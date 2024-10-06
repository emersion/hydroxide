package protonmail

import (
	"encoding/base64"
	"errors"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	CalendarEventCardClear CalendarEventCardType = 1 + iota
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

type CalendarEventDeletionReq struct {
	Events []CalendarEventDeletionEntry
}

type CalendarEventDeletionEntry struct {
	ID             string
	DeletionReason int
}

func (c *Client) DeleteCalendarEvent(calendarID string, eventID string) error {
	body := CalendarEventDeletionReq{
		Events: []CalendarEventDeletionEntry{
			{
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
