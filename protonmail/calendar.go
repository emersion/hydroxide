package protonmail

import (
	"encoding/base64"
	"errors"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/emersion/go-ical"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const calendarPath = "/calendar/v1"

type CalendarFlags int

type Calendar struct {
	ID         string
	Type       int
	CreateTime Timestamp
	Members    []CalendarMemberView
}

type CalendarBootstrap struct {
	Keys       []CalendarKey
	Passphrase CalendarPassphrase
	Members    []CalendarMemberView
	// ... CalendarSettings
}

type CalendarKey struct {
	ID           string
	PrivateKey   string
	PassphraseID string
	Flags        int
	CalendarID   string
}

type CalendarPassphrase struct {
	Flags             int
	ID                string
	MemberPassphrases []CalendarMemberPassphrase
	CalendarID        string
}

type CalendarMemberView struct {
	ID          string
	Permissions int
	Email       string
	AddressID   string
	CalendarID  string
	Name        string
	Description string
	Color       string
	Display     int
	Priority    int
	Flags       int
}

type CalendarMemberPassphrase struct {
	MemberID   string
	Passphrase string
	Signature  string
}

type CalendarEventPermissions int

const (
	CalendarEventAvailability CalendarEventPermissions = 1 << iota
	CalendarEventRead
	CalendarEventReadMemberList
	CalendarEventWrite
	CalendarEventAdmin
	CalendarEventOwner
)

type CalendarEvent struct {
	ID                         string
	CalendarID                 string
	SharedEventID              string
	CalendarKeyPacket          string
	CreateTime, ModifyTime     Timestamp
	LastEditTime               Timestamp
	StartTime, EndTime         Timestamp
	StartTimezone, EndTimezone string
	FullDay                    int
	UID                        string
	IsOrganizer                int
	RecurrenceID               string
	Exdates                    []interface{}
	RRule                      interface{}
	Author                     string
	Permissions                CalendarEventPermissions
	SharedKeyPacket            string
	SharedEvents               []CalendarEventCard
	CalendarEvents             []CalendarEventCard
	PersonalEvents             []CalendarEventCard
	AttendeesEvents            []CalendarEventCard
	Attendees                  []interface{}
}

type CalendarEventCardType int

const (
	CalendarEventCardClear CalendarEventCardType = iota
	CalendarEventCardEncrypted
	CalendarEventCardSigned
	CalendarEventCardEncryptedAndSigned
)

func (t CalendarEventCardType) Signed() bool {
	switch t {
	case CalendarEventCardSigned, CalendarEventCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

func (t CalendarEventCardType) Encrypted() bool {
	switch t {
	case CalendarEventCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

type CalendarEventCard struct {
	Type      CalendarEventCardType
	Data      string
	Signature string
	MemberID  string
	Author    string
}

func FindMemberViewFromKeyring(members []CalendarMemberView, kr openpgp.KeyRing) (*CalendarMemberView, error) {
	for _, _member := range members {
		for _, userKey := range kr.DecryptionKeys() {
			for _, identity := range userKey.Entity.Identities {
				if _member.Email == identity.UserId.Email {
					return &_member, nil
				}
			}
		}
	}
	return nil, errors.New("could not find a CalendarMemberView for keyring")
}

func (bootstrap *CalendarBootstrap) DecryptKeyring(userKr openpgp.KeyRing) (openpgp.KeyRing, error) {
	var calKr openpgp.EntityList
	for _, key := range bootstrap.Keys {
		var passphrase *CalendarMemberPassphrase

		member, err := FindMemberViewFromKeyring(bootstrap.Members, userKr)
		if err != nil {
			return nil, err
		}

		for _, _passphrase := range bootstrap.Passphrase.MemberPassphrases {
			if _passphrase.MemberID == member.ID {
				passphrase = &_passphrase
				break
			}
		}
		if passphrase == nil {
			return nil, errors.New("could not find a MemberPassphrase for MemberID")
		}

		passphraseEnc, err := armor.Decode(strings.NewReader(passphrase.Passphrase))
		if err != nil {
			return nil, err
		}

		md, err := openpgp.ReadMessage(passphraseEnc.Body, userKr, nil, nil)
		if err != nil {
			return nil, err
		}

		passphraseBytes, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			return nil, err
		}

		/*		signatureData, err := armor.Decode(strings.NewReader(passphrase.Signature))
				if err != nil {
					return nil, err
				}
				_, err = openpgp.CheckArmoredDetachedSignature(userKr, bytes.NewReader(passphraseBytes), signatureData.Body, nil)
				if err != nil {
					return nil, err
				}*/

		keyKr, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key.PrivateKey))
		if err != nil {
			return nil, err
		}

		for _, decKey := range keyKr.DecryptionKeys() {
			err = decKey.PrivateKey.Decrypt(passphraseBytes)
			if err != nil {
				return nil, err
			}
		}

		calKr = append(calKr, keyKr...)
	}
	return calKr, nil
}

func (card *CalendarEventCard) Read(userKr openpgp.KeyRing, calKr openpgp.KeyRing, keyPacket string) (*openpgp.MessageDetails, error) {
	if !card.Type.Encrypted() {
		md := &openpgp.MessageDetails{
			IsEncrypted:    false,
			IsSigned:       false,
			UnverifiedBody: strings.NewReader(card.Data),
		}

		if !card.Type.Signed() {
			return md, nil
		}

		signed := strings.NewReader(card.Data)
		signature := strings.NewReader(card.Signature)
		signer, err := openpgp.CheckArmoredDetachedSignature(userKr, signed, signature, nil)
		md.IsSigned = true
		md.SignatureError = err
		if signer != nil {
			md.SignedByKeyId = signer.PrimaryKey.KeyId
			md.SignedBy = entityPrimaryKey(signer)
		}
		return md, nil
	}

	keyPacketData := base64.NewDecoder(base64.StdEncoding, strings.NewReader(keyPacket))
	ciphertext := base64.NewDecoder(base64.StdEncoding, strings.NewReader(card.Data))
	msg := io.MultiReader(keyPacketData, ciphertext)
	md, err := openpgp.ReadMessage(msg, calKr, nil, nil)
	if err != nil {
		return nil, err
	}

	if card.Type.Signed() {
		r := &detachedSignatureReader{
			md:        md,
			signature: strings.NewReader(card.Signature),
			keyring:   userKr,
		}
		r.body = io.TeeReader(md.UnverifiedBody, &r.signed)

		md.UnverifiedBody = r
	}

	return md, nil
}

func (c *Client) ListCalendars() ([]*Calendar, error) {
	req, err := c.newRequest(http.MethodGet, calendarPath, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Calendars []*Calendar
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Calendars, nil
}

func (c *Client) BootstrapCalendar(id string) (*CalendarBootstrap, error) {
	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+id+"/bootstrap", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		*CalendarBootstrap
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.CalendarBootstrap, nil
}

type CalendarEventFilter struct {
	Start, End     Timestamp
	Timezone       string
	Page, PageSize int
}

func (c *Client) ListCalendarEvents(calendarID string, filter *CalendarEventFilter) ([]*CalendarEvent, error) {
	v := url.Values{}

	if filter != nil {
		v.Set("Start", strconv.FormatInt(int64(filter.Start), 10))
		v.Set("End", strconv.FormatInt(int64(filter.End), 10))
		v.Set("Timezone", filter.Timezone)
		v.Set("Page", strconv.Itoa(filter.Page))
		if filter.PageSize > 0 {
			v.Set("PageSize", strconv.Itoa(filter.PageSize))
		}
	}

	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+calendarID+"/events?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Events []*CalendarEvent
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Events, nil
}

func (c *Client) GetCalendarEvent(calendarID string, eventID string) (*CalendarEvent, error) {
	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+calendarID+"/events/"+eventID, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Event *CalendarEvent
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Event, nil
}

func concat(slices [][]string) []string {
	var totalLen int
	for _, s := range slices {
		totalLen += len(s)
	}
	tmp := make([]string, totalLen)
	var i int
	for _, s := range slices {
		i += copy(tmp[i:], s)
	}
	return tmp
}

var sharedSignedFields = []string{
	"uid",
	"dtstamp",
	"dtstart",
	"dtend",
	"recurrence-id",
	"rrule",
	"exdate",
	"organizer",
	"sequence",
}
var sharedEncryptedFields = []string{
	"uid",
	"dtstamp",
	"created",
	"description",
	"summary",
	"location",
}

var calendarSignedFields = []string{
	"uid",
	"dtstamp",
	"exdate",
	"status",
	"transp",
}
var calendarEncryptedFields = []string{
	"uid",
	"dtstamp",
	"comment",
}

var personalSignedFields = []string{
	"uid",
	"dtstamp",
}
var personalEncryptedFields = []string{}

var usedFields = concat([][]string{
	sharedSignedFields,
	sharedEncryptedFields,

	calendarSignedFields,
	calendarEncryptedFields,

	personalSignedFields,
	personalEncryptedFields,
})

// ... attendeesSigned/EncryptedFields
func pickProps(event *ical.Event, propNames []string) *ical.Event {
	evt := ical.NewEvent()
	for _, propName := range propNames {
		props := event.Props.Values(propName)
		if props != nil && len(props) > 0 {
			evt.Props[props[0].Name] = props
		}
	}

	return evt
}

func getEventParts(event *ical.Event) (map[CalendarEventCardType]*ical.Event, map[CalendarEventCardType]*ical.Event, map[CalendarEventCardType]*ical.Event) {
	sharedPart := make(map[CalendarEventCardType]*ical.Event)
	sharedPart[CalendarEventCardSigned] = pickProps(event, sharedSignedFields)
	sharedPart[CalendarEventCardEncryptedAndSigned] = pickProps(event, sharedEncryptedFields)

	calendarPart := make(map[CalendarEventCardType]*ical.Event)
	calendarPart[CalendarEventCardSigned] = pickProps(event, calendarSignedFields)
	calendarPart[CalendarEventCardEncryptedAndSigned] = pickProps(event, calendarEncryptedFields)

	personalPart := make(map[CalendarEventCardType]*ical.Event)
	personalPart[CalendarEventCardSigned] = pickProps(event, personalSignedFields)
	personalPart[CalendarEventCardEncryptedAndSigned] = pickProps(event, personalEncryptedFields)

	for _, propName := range usedFields {
		event.Props.Del(propName)
	}
	for name, props := range event.Props {
		sharedPart[CalendarEventCardEncryptedAndSigned].Props[strings.ToUpper(name)] = append(sharedPart[CalendarEventCardEncryptedAndSigned].Props[strings.ToUpper(name)], props...)
	}

	return sharedPart, calendarPart, personalPart
}

func decryptSessionKey(sessionKey string, calKr openpgp.KeyRing) (*packet.EncryptedKey, error) {
	if sessionKey == "" {
		return nil, nil
	}

	sharedKeyPacket := base64.NewDecoder(base64.StdEncoding, strings.NewReader(sessionKey))
	packetReader := packet.NewReader(sharedKeyPacket)

	pkt, err := packetReader.Next()
	if err != nil {
		return nil, err
	}

	switch pkt.(type) {
	case *packet.EncryptedKey:
		for _, pKey := range calKr.DecryptionKeys() {
			if !pKey.PrivateKey.Encrypted {
				keyPacket := pkt.(*packet.EncryptedKey)
				err := keyPacket.Decrypt(pKey.PrivateKey, nil)
				if err != nil {
					return nil, err
				}

				return keyPacket, nil
			}
		}
	}

	return nil, errors.New("Could not decrypt session key")
}

func getOrGenerateSessionKey(oldEvent *CalendarEvent, calKr openpgp.KeyRing, config *packet.Config) (*packet.EncryptedKey, string, error) {
	var sessionKey *packet.EncryptedKey
	var encryptedSessionKey string
	if oldEvent != nil {
		encryptedSessionKey = oldEvent.SharedKeyPacket

		var err error
		sessionKey, err = decryptSessionKey(encryptedSessionKey, calKr)
		if err != nil {
			return nil, "", err
		}
	}

	if sessionKey == nil {
		var err error
		sessionKey, err = generateUnencryptedKey(packet.CipherAES256, config)
		if err != nil {
			return nil, "", err
		}

		calEncryptionKey, ok := encryptionKey(calKr.DecryptionKeys()[0].Entity, time.Now())
		if !ok {
			return nil, "", errors.New("Could not find encryption key for calKr")
		}
		encryptedSessionKey, err = serializeEncryptedKey(sessionKey, calEncryptionKey.PublicKey, config)
	}

	return sessionKey, encryptedSessionKey, nil
}

type CreateOrUpdateCalendarEventData struct {
	CalendarKeyPacket        string
	CalendarEventContent     []CalendarEventCard
	SharedKeyPacket          string
	SharedEventContent       []CalendarEventCard
	Color                    string
	Permissions              int
	IsOrganizer              bool
	IsPersonalSingleEdit     bool
	RemovedAttendeeAddresses []string
	AddedProtonAttendees     []AddedProtonAttendee
	// Notifications, AttendeesEventContent, Attendees, CancelledOccurrenceContent ...
}

type AddedProtonAttendee struct {
	Email            string
	AddressKeyPacket string
}

type CalendarEventSyncReq struct {
	Events []interface{}
}

func (c *Client) UpdateCalendarEvent(calID string, eventID string, event ical.Event, userKr openpgp.KeyRing) error {
	oldEvent, err := c.GetCalendarEvent(calID, eventID)
	isCreate := false
	if apiErr, ok := err.(*APIError); ok && apiErr.Code == 2061 {
		isCreate = true
	} else if err != nil {
		return err
	}

	bootstrap, err := c.BootstrapCalendar(calID)
	if err != nil {
		return err
	}

	calKr, err := bootstrap.DecryptKeyring(userKr)
	if err != nil {
		return err
	}

	sharedPart, calendarPart, _ := getEventParts(&event)

	config := &packet.Config{}
	sharedSessionKey, encryptedSharedSessionKey, err := getOrGenerateSessionKey(oldEvent, calKr, config)
	if err != nil {
		return err
	}

	calendarSessionKey, encryptedCalendarSessionKey, err := getOrGenerateSessionKey(oldEvent, calKr, config)
	if err != nil {
		return err
	}

	body := CreateOrUpdateCalendarEventData{}
	color := event.Props.Get("color")
	if color != nil && color.Value != "" {
		body.Color = color.Value
	}

	if isCreate {
		body.SharedKeyPacket = encryptedSharedSessionKey
	}

	_ = sharedPart
	_ = calendarPart
	_ = sharedSessionKey
	_ = calendarSessionKey
	_ = encryptedCalendarSessionKey

	return nil
}

type CalendarEventDeletionSyncEntry struct {
	ID             string
	DeletionReason int
}

func (c *Client) DeleteCalendarEvent(calendarID string, eventID string) error {
	body := CalendarEventSyncReq{
		Events: []interface{}{
			CalendarEventDeletionSyncEntry{
				ID:             eventID,
				DeletionReason: 0,
			},
		},
	}

	req, err := c.newJSONRequest(http.MethodPut, calendarPath+"/"+calendarID+"/events/sync", body)
	if err != nil {
		return err
	}

	if _, err := c.do(req); err != nil {
		return err
	}

	return nil
}
