package protonmail

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/openpgp"
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

	// TODO: read using SharedKeyPacket if any

	ciphertext := base64.NewDecoder(base64.StdEncoding, strings.NewReader(card.Data))
	md, err := openpgp.ReadMessage(ciphertext, keyring, nil, nil)
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

type CalendarEventFilter struct {
	Start, End     Timestamp
	Timezone       string
	Page, PageSize int
}

func (c *Client) ListCalendarEvents(calendarID string, filter *CalendarEventFilter) ([]*CalendarEvent, error) {
	v := url.Values{}
	v.Set("Start", strconv.FormatInt(int64(filter.Start), 10))
	v.Set("End", strconv.FormatInt(int64(filter.End), 10))
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
