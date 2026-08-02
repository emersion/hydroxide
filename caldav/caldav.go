package caldav

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/emersion/hydroxide/protonmail"
)

// TODO: use a HTTP error
var errNotFound = errors.New("caldav: not found")

// Calendar paths look like: /calendar/<calendarID>/
// Calendar object paths look like: /calendar/<calendarID>/<eventID>.ics

const calendarPrefix = "/calendar"

func formatCalendarPath(id string) string {
	return calendarPrefix + "/" + id
}

func formatCalendarObjectPath(calendarID, eventID string) string {
	return calendarPrefix + "/" + calendarID + "/" + eventID + ".ics"
}

func parseCalendarPath(p string) (string, error) {
	p = strings.TrimSuffix(p, "/")
	if !strings.HasPrefix(p, calendarPrefix+"/") {
		return "", errNotFound
	}
	id := strings.TrimPrefix(p, calendarPrefix+"/")
	if id == "" || strings.Contains(id, "/") {
		return "", errNotFound
	}
	return id, nil
}

func parseCalendarObjectPath(p string) (calendarID, eventID string, err error) {
	p = strings.TrimSuffix(p, "/")
	if !strings.HasPrefix(p, calendarPrefix+"/") {
		return "", "", errNotFound
	}
	rest := strings.TrimPrefix(p, calendarPrefix+"/")
	// rest should be <calendarID>/<eventID>.ics
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errNotFound
	}
	calendarID = parts[0]
	filename := parts[1]
	if strings.Contains(filename, "/") {
		return "", "", errNotFound
	}
	ext := path.Ext(filename)
	if ext != ".ics" {
		return "", "", errNotFound
	}
	return calendarID, strings.TrimSuffix(filename, ext), nil
}

// decryptCalendarEventCard decrypts a single Proton CalendarEventCard.
//
// Proton Calendar encrypts event data with a symmetric session key. The
// session key itself is encrypted with the user's PGP key and shipped in
// CalendarEvent.CalendarKeyPacket (for the owner's personal copy) or
// CalendarEvent.SharedKeyPacket (for shared events). The encrypted event
// payload is base64-encoded in CalendarEventCard.Data.
//
// This function:
//  1. Base64-decodes the key packet.
//  2. Feeds it through openpgp.ReadMessage using the user's private keyring,
//     which performs the asymmetric PGP decryption and yields the session key.
//  3. Base64-decodes the card Data, treats it as a PGP message encrypted with
//     that session key, and decrypts.
//
// Returns the cleartext iCalendar fragment on success.
//
// Note: This mirrors the encryption pattern documented in
// protonmail/contacts.go for ContactCard.Read, adapted to the calendar
// scheme where the key packet is detached from the data packet. If Proton
// has changed their wire format, this will need to be updated; a clear
// error is returned in that case so the maintainer can patch it.
func decryptCalendarEventCard(card *protonmail.CalendarEventCard, keyPacket string, privateKeys openpgp.KeyRing) ([]byte, error) {
	if card == nil {
		return nil, errors.New("caldav: nil event card")
	}

	// Decode the key packet (base64 → binary OpenPGP message containing the session key).
	keyPacketBytes, err := base64.StdEncoding.DecodeString(keyPacket)
	if err != nil {
		return nil, fmt.Errorf("caldav: failed to decode key packet: %v", err)
	}

	// Read it as an OpenPGP message. ReadMessage will use the private keyring
	// to perform public-key decryption of the session key.
	keyMd, err := openpgp.ReadMessage(bytes.NewReader(keyPacketBytes), privateKeys, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("caldav: failed to read key packet: %v", err)
	}
	sessionKeyBytes, err := ioutil.ReadAll(keyMd.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("caldav: failed to decrypt session key: %v", err)
	}

	// Decode the card data (base64 → binary OpenPGP message encrypted with the session key).
	dataBytes, err := base64.StdEncoding.DecodeString(card.Data)
	if err != nil {
		return nil, fmt.Errorf("caldav: failed to decode card data: %v", err)
	}

	// Re-armour the data so we can use openpgp.ReadMessage. The session key
	// needs to be supplied via a custom prompt function.
	armored := &bytes.Buffer{}
	w, err := armor.Encode(armored, "PGP MESSAGE", nil)
	if err != nil {
		return nil, fmt.Errorf("caldav: failed to armor-encode data: %v", err)
	}
	if _, err := w.Write(dataBytes); err != nil {
		return nil, fmt.Errorf("caldav: failed to write armored data: %v", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("caldav: failed to close armored data: %v", err)
	}

	block, err := armor.Decode(armored)
	if err != nil {
		return nil, fmt.Errorf("caldav: failed to decode armored data: %v", err)
	}

	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if !symmetric {
			return nil, errors.New("caldav: expected symmetric encryption for calendar event data")
		}
		return sessionKeyBytes, nil
	}

	dataMd, err := openpgp.ReadMessage(block.Body, nil, prompt, nil)
	if err != nil {
		return nil, fmt.Errorf("caldav: failed to read encrypted card data: %v", err)
	}
	return ioutil.ReadAll(dataMd.UnverifiedBody)
}

// eventToICal builds a go-ical Calendar from a Proton CalendarEvent.
//
// The Proton event carries one or more CalendarEventCards:
//   - SharedEvents: visible to all attendees (encrypted with the shared key packet)
//   - PersonalEvent: visible only to the owner (encrypted with the calendar key packet)
//
// We prefer SharedEvents for the canonical representation, falling back to
// PersonalEvent if no shared card is present. The decrypted payload is a
// fragment of iCalendar data (typically a VEVENT block) which we wrap in a
// full VCALENDAR object.
func (b *backend) eventToICal(event *protonmail.CalendarEvent) (*ical.Calendar, error) {
	var cards []protonmail.CalendarEventCard
	var keyPacket string

	if len(event.SharedEvents) > 0 {
		cards = event.SharedEvents
		keyPacket = event.SharedKeyPacket
	} else if len(event.PersonalEvent) > 0 {
		cards = event.PersonalEvent
		keyPacket = event.CalendarKeyPacket
	} else {
		return nil, errNotFound
	}

	var plaintext []byte
	var lastErr error
	for i := range cards {
		pt, err := decryptCalendarEventCard(&cards[i], keyPacket, b.privateKeys)
		if err != nil {
			lastErr = err
			continue
		}
		plaintext = pt
		break
	}
	if plaintext == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errNotFound
	}

	// Parse the decrypted fragment as iCalendar.
	// Proton typically sends a full VCALENDAR object; if it's just a VEVENT,
	// wrap it ourselves.
	dec := ical.NewDecoder(bytes.NewReader(plaintext))
	parsed, err := dec.Decode()
	if err != nil {
		// Maybe it's a bare VEVENT. Wrap it.
		wrapped := append([]byte("BEGIN:VCALENDAR\r\n"), plaintext...)
		wrapped = append(wrapped, []byte("\r\nEND:VCALENDAR\r\n")...)
		dec2 := ical.NewDecoder(bytes.NewReader(wrapped))
		parsed, err = dec2.Decode()
		if err != nil {
			return nil, fmt.Errorf("caldav: failed to parse decrypted iCal: %v", err)
		}
		return parsed, nil
	}
	return parsed, nil
}

func (b *backend) toCalendarObject(calendarID string, event *protonmail.CalendarEvent) (*caldav.CalendarObject, error) {
	cal, err := b.eventToICal(event)
	if err != nil {
		return nil, err
	}

	return &caldav.CalendarObject{
		Path:    formatCalendarObjectPath(calendarID, event.ID),
		ModTime: event.LastEditTime.Time(),
		// ETag derived from LastEditTime; weaker than ideal but sufficient
		// for clients that just need change detection.
		ETag: fmt.Sprintf("\"%x\"", event.LastEditTime),
		Data: cal,
	}, nil
}

type backend struct {
	c           *protonmail.Client
	privateKeys openpgp.EntityList

	mu        sync.Mutex
	calendars map[string]*protonmail.Calendar // cached by ID
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/", nil
}

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	return calendarPrefix, nil
}

func (b *backend) CreateCalendar(ctx context.Context, cal *caldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("caldav: creating calendars is not supported"))
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	protonCals, err := b.c.ListCalendars(0, 0)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	for _, pc := range protonCals {
		b.calendars[pc.ID] = pc
	}
	b.mu.Unlock()

	result := make([]caldav.Calendar, 0, len(protonCals))
	for _, pc := range protonCals {
		result = append(result, caldav.Calendar{
			Path:                  formatCalendarPath(pc.ID),
			Name:                  pc.Name,
			Description:           pc.Description,
			MaxResourceSize:       100 * 1024, // 100 KiB, matches CardDAV cap
			SupportedComponentSet: []string{ical.CompEvent},
		})
	}
	return result, nil
}

func (b *backend) GetCalendar(ctx context.Context, p string) (*caldav.Calendar, error) {
	id, err := parseCalendarPath(p)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	pc, ok := b.calendars[id]
	b.mu.Unlock()

	if !ok {
		// Refresh the cache once.
		protonCals, err := b.c.ListCalendars(0, 0)
		if err != nil {
			return nil, err
		}
		b.mu.Lock()
		for _, c := range protonCals {
			b.calendars[c.ID] = c
		}
		pc, ok = b.calendars[id]
		b.mu.Unlock()
		if !ok {
			return nil, webdav.NewHTTPError(http.StatusNotFound, errNotFound)
		}
	}

	return &caldav.Calendar{
		Path:                  formatCalendarPath(pc.ID),
		Name:                  pc.Name,
		Description:           pc.Description,
		MaxResourceSize:       100 * 1024,
		SupportedComponentSet: []string{ical.CompEvent},
	}, nil
}

// listAllEvents enumerates all events in a calendar across a generous time
// range. The Proton API requires Start/End; we use a 10-year window centred
// on now which should cover virtually every real calendar's active events.
func (b *backend) listAllEvents(calendarID string) ([]*protonmail.CalendarEvent, error) {
	now := time.Now()
	filter := &protonmail.CalendarEventFilter{
		Start:    now.AddDate(-5, 0, 0).Unix(),
		End:      now.AddDate(5, 0, 0).Unix(),
		Timezone: "UTC",
		Page:     0,
		PageSize: 0,
	}

	var all []*protonmail.CalendarEvent
	for {
		events, err := b.c.ListCalendarEvents(calendarID, filter)
		if err != nil {
			return nil, err
		}
		all = append(all, events...)
		if len(events) == 0 || (filter.PageSize > 0 && len(events) < filter.PageSize) {
			break
		}
		filter.Page++
		if filter.Page > 100 {
			// Safety valve: 100 pages × PageSize (default ~100) = ~10K events.
			break
		}
	}
	return all, nil
}

func (b *backend) ListCalendarObjects(ctx context.Context, p string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	calendarID, err := parseCalendarPath(p)
	if err != nil {
		return nil, err
	}

	events, err := b.listAllEvents(calendarID)
	if err != nil {
		return nil, err
	}

	result := make([]caldav.CalendarObject, 0, len(events))
	for _, ev := range events {
		co, err := b.toCalendarObject(calendarID, ev)
		if err != nil {
			// Skip events that fail to decrypt rather than failing the whole
			// listing. This matches how CardDAV handles corrupt contact cards.
			continue
		}
		result = append(result, *co)
	}
	return result, nil
}

func (b *backend) GetCalendarObject(ctx context.Context, p string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	calendarID, eventID, err := parseCalendarObjectPath(p)
	if err != nil {
		return nil, err
	}

	events, err := b.listAllEvents(calendarID)
	if err != nil {
		return nil, err
	}

	for _, ev := range events {
		if ev.ID == eventID {
			return b.toCalendarObject(calendarID, ev)
		}
	}
	return nil, webdav.NewHTTPError(http.StatusNotFound, errNotFound)
}

func (b *backend) QueryCalendarObjects(ctx context.Context, p string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	req := caldav.CalendarCompRequest{AllProps: true}
	if query != nil {
		req = query.CompRequest
	}

	all, err := b.ListCalendarObjects(ctx, p, &req)
	if err != nil {
		return nil, err
	}

	if query == nil {
		return all, nil
	}
	return caldav.Filter(query, all)
}

func (b *backend) PutCalendarObject(ctx context.Context, p string, cal *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	return nil, webdav.NewHTTPError(http.StatusForbidden, errors.New("caldav: creating/updating events is not yet supported"))
}

func (b *backend) DeleteCalendarObject(ctx context.Context, p string) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("caldav: deleting events is not yet supported"))
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList) http.Handler {
	if len(privateKeys) == 0 {
		panic("hydroxide/caldav: no private key available")
	}

	b := &backend{
		c:           c,
		privateKeys: privateKeys,
		calendars:   make(map[string]*protonmail.Calendar),
	}

	return &caldav.Handler{Backend: b}
}
