package protonmail

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

const calendarPath = "/calendar/v1"

type CalendarFlags int

type Calendar struct {
	ID          string
	Name        string
	Description string
	Color       string
	Display     int
	Flags       CalendarFlags
}

type CalendarEventPermissions int

type CalendarEvent struct {
	ID                string
	CalendarID        string
	CalendarKeyPacket string
	CreateTime        Timestamp
	LastEditTime      Timestamp
	Author            string
	Permissions       CalendarEventPermissions
	SharedKeyPacket   string
	SharedEvents      []CalendarEventCard
	CalendarEvents    interface{}
	PersonalEvent     []CalendarEventCard
}

type CalendarEventCardType int

const (
	CalendarEventCardCleartext CalendarEventCardType = iota
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
	case CalendarEventCardEncrypted, CalendarEventCardEncryptedAndSigned:
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
}

func (card *CalendarEventCard) Read(keyring openpgp.KeyRing) (*openpgp.MessageDetails, error) {
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
		signer, err := openpgp.CheckArmoredDetachedSignature(keyring, signed, signature, nil)
		md.IsSigned = true
		md.SignatureError = err
		if signer != nil {
			md.SignedByKeyId = signer.PrimaryKey.KeyId
			md.SignedBy = entityPrimaryKey(signer)
		}
		return md, nil
	}

	ciphertextBlock, err := armor.Decode(strings.NewReader(card.Data))
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(ciphertextBlock.Body, keyring, nil, nil)
	if err != nil {
		return nil, err
	}

	if card.Type.Signed() {
		r := &detachedSignatureReader{
			md:        md,
			signature: strings.NewReader(card.Signature),
			keyring:   keyring,
		}
		r.body = io.TeeReader(md.UnverifiedBody, &r.signed)
		md.UnverifiedBody = r
	}

	return md, nil
}

func NewEncryptedCalendarEventCard(r io.Reader, to []*openpgp.Entity, signer *openpgp.Entity) (*CalendarEventCard, error) {
	var msg, armored bytes.Buffer
	if signer != nil {
		r = io.TeeReader(r, &msg)
	}

	ciphertext, err := armor.Encode(&armored, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}

	cleartext, err := openpgp.Encrypt(ciphertext, to, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(cleartext, r); err != nil {
		return nil, err
	}
	if err := cleartext.Close(); err != nil {
		return nil, err
	}
	if err := ciphertext.Close(); err != nil {
		return nil, err
	}

	card := &CalendarEventCard{
		Type: CalendarEventCardEncrypted,
		Data: armored.String(),
	}

	if signer != nil {
		var sig bytes.Buffer
		if err := openpgp.ArmoredDetachSignText(&sig, signer, &msg, nil); err != nil {
			return nil, err
		}
		card.Type = CalendarEventCardEncryptedAndSigned
		card.Signature = sig.String()
	}

	return card, nil
}

func NewSignedCalendarEventCard(r io.Reader, signer *openpgp.Entity) (*CalendarEventCard, error) {
	var msg, sig bytes.Buffer
	r = io.TeeReader(r, &msg)
	if err := openpgp.ArmoredDetachSignText(&sig, signer, r, nil); err != nil {
		return nil, err
	}

	return &CalendarEventCard{
		Type:      CalendarEventCardSigned,
		Data:      msg.String(),
		Signature: sig.String(),
	}, nil
}

type CalendarEventImport struct {
	Event *CalendarEventCardSet
}

type CalendarEventCardSet struct {
	Shared *CalendarEventCard
	CalendarEvent   *CalendarEventCard
	PersonalEvent *CalendarEventCard
}

func (c *Client) ListCalendars(page, pageSize int) ([]*Calendar, error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, calendarPath+"?"+v.Encode(), nil)
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

func (c *Client) GetCalendar(id string) (*Calendar, error) {
	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Calendar *Calendar
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Calendar, nil
}

func (c *Client) CreateCalendar(calendar *Calendar) (*Calendar, error) {
	req, err := c.newJSONRequest(http.MethodPost, calendarPath, calendar)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Calendar *Calendar
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Calendar, nil
}

func (c *Client) DeleteCalendar(id string) error {
	req, err := c.newRequest(http.MethodDelete, calendarPath+"/"+id, nil)
	if err != nil {
		return err
	}

	var respData resp
	if err := c.doJSON(req, &respData); err != nil {
		return err
	}

	return nil
}

type CalendarEventFilter struct {
	Start, End     int64
	Timezone       string
	Page, PageSize int
}

func (c *Client) ListCalendarEvents(calendarID string, filter *CalendarEventFilter) ([]*CalendarEvent, error) {
	v := url.Values{}
	v.Set("Start", strconv.FormatInt(filter.Start, 10))
	v.Set("End", strconv.FormatInt(filter.End, 10))
	v.Set("Timezone", filter.Timezone)
	v.Set("Page", strconv.Itoa(filter.Page))
	if filter.PageSize > 0 {
		v.Set("PageSize", strconv.Itoa(filter.PageSize))
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

func (c *Client) GetCalendarEvent(calendarID, eventID string) (*CalendarEvent, error) {
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

func (c *Client) CreateCalendarEvent(calendarID string, event *CalendarEventImport) (*CalendarEvent, error) {
	req, err := c.newJSONRequest(http.MethodPost, calendarPath+"/"+calendarID+"/events", event)
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

func (c *Client) UpdateCalendarEvent(calendarID, eventID string, event *CalendarEventImport) (*CalendarEvent, error) {
	req, err := c.newJSONRequest(http.MethodPut, calendarPath+"/"+calendarID+"/events/"+eventID, event)
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

func (c *Client) DeleteCalendarEvent(calendarID, eventID string) error {
	req, err := c.newRequest(http.MethodDelete, calendarPath+"/"+calendarID+"/events/"+eventID, nil)
	if err != nil {
		return err
	}

	var respData resp
	if err := c.doJSON(req, &respData); err != nil {
		return err
	}

	return nil
}