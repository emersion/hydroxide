package caldav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"

	"github.com/emersion/hydroxide/protonmail"
)

// TODO: use a HTTP error
var errNotFound = errors.New("caldav: not found")

var errMultipleCalendarsNotSupported = errors.New("caldav: multiple calendars not supported yet")

var calendarHomeSet = "/calendars"

var defaultCalendar = &caldav.Calendar{
	Path:        "/calendars/default",
	Name:        "ProtonMail",
	Description: "ProtonMail calendar",
	// MaxResourceSize: 100 * 1024, // TODO: what's the actual limit?
	SupportedComponentSet: []string{ical.CompEvent},
}

func formatCalendarObjectPath(id string) string {
	return "/calendars/default/" + id + ".ics"
}

func parseCalendarObjectPath(p string) (string, error) {
	dirname, filename := path.Split(p)
	ext := path.Ext(filename)
	if dirname != "/calendars/default/" || ext != ".ics" {
		return "", errNotFound
	}
	return strings.TrimSuffix(filename, ext), nil
}

func (b *backend) toCalendarObject(event *protonmail.CalendarEvent, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	merged := ical.NewEvent()

	// Handle SharedEvents, CalendarEvents, PersonalEvents, AttendeesEvents
	allCards := append(event.SharedEvents, event.CalendarEvents...)
	allCards = append(allCards, event.PersonalEvents...)
	allCards = append(allCards, event.AttendeesEvents...)

	for _, c := range allCards {
		md, err := c.Read(b.privateKeys)
		if err != nil {
			return nil, err
		}

		decoded, err := ical.NewDecoder(md.UnverifiedBody).Decode()
		if err != nil {
			return nil, err
		}

		// The signature can be checked only if md.UnverifiedBody is consumed until EOF
		io.Copy(ioutil.Discard, md.UnverifiedBody)
		if err := md.SignatureError; err != nil {
			return nil, err
		}

		children := decoded.Events()
		if len(children) != 1 {
			return nil, fmt.Errorf("hydroxide/caldav: expected VCALENDAR to have exactly one VEVENT")
		}
		decodedEvent := &children[0]

		for _, props := range decodedEvent.Props {
			for _, p := range props {
				merged.Props.Add(&p)
			}
		}
	}

	// Set UID from event if not already set
	if _, ok := merged.Props["UID"]; !ok {
		uid := event.UID
		if uid == "" {
			uid = event.ID
		}
		merged.Props.Set(&ical.Prop{Name: "UID", Value: uid})
	}

	// Set DTSTART and DTEND from event fields if not already in the cards
	if _, ok := merged.Props["DTSTART"]; !ok {
		dtstart := ical.NewProp("DTSTART")
		dtstart.SetDateTime(event.StartTime.Time())
		merged.Props.Set(dtstart)
	}
	if _, ok := merged.Props["DTEND"]; !ok {
		dtend := ical.NewProp("DTEND")
		dtend.SetDateTime(event.EndTime.Time())
		merged.Props.Set(dtend)
	}

	data := ical.NewCalendar()
	data.Children = append(data.Children, merged.Component)

	modTime := event.LastEditTime.Time()
	if modTime.IsZero() {
		modTime = event.CreateTime.Time()
	}

	return &caldav.CalendarObject{
		Path:    formatCalendarObjectPath(event.ID),
		ModTime: modTime,
		ETag:    fmt.Sprintf("\"%x\"", modTime.Unix()),
		Data:    data,
	}, nil
}

type backend struct {
	c           *protonmail.Client
	cache       map[string]*protonmail.CalendarEvent
	locker      sync.Mutex
	privateKeys openpgp.EntityList
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/", nil
}

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	return calendarHomeSet, nil
}

func (b *backend) CreateCalendar(ctx context.Context, calendar *caldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot create new calendar"))
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	return []caldav.Calendar{*defaultCalendar}, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	if path != defaultCalendar.Path {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar not found"))
	}
	return defaultCalendar, nil
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	id, err := parseCalendarObjectPath(path)
	if err != nil {
		return nil, err
	}

	// First check cache
	b.locker.Lock()
	event, ok := b.cache[id]
	b.locker.Unlock()

	if !ok {
		// Fetch from API - we need the calendar ID. Since we use a single calendar,
		// list calendars to get the first one
		calendars, err := b.c.ListCalendars(0, 1)
		if err != nil {
			return nil, err
		}
		if len(calendars) == 0 {
			return nil, errNotFound
		}

		event, err = b.c.GetCalendarEvent(calendars[0].ID, id)
		if err != nil {
			return nil, err
		}

		b.locker.Lock()
		b.cache[id] = event
		b.locker.Unlock()
	}

	return b.toCalendarObject(event, req)
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	calendars, err := b.c.ListCalendars(0, 1)
	if err != nil {
		return nil, err
	}
	if len(calendars) == 0 {
		return nil, nil
	}
	cal := calendars[0]

	// Use a broad time range to get all events
	now := time.Now()
	filter := &protonmail.CalendarEventFilter{
		Start:    now.AddDate(-1, 0, 0).Unix(),
		End:      now.AddDate(1, 0, 0).Unix(),
		Timezone: "UTC",
	}

	events, err := b.c.ListCalendarEvents(cal.ID, filter)
	if err != nil {
		return nil, err
	}

	cos := make([]caldav.CalendarObject, 0, len(events))
	for _, event := range events {
		// Cache the event
		b.locker.Lock()
		b.cache[event.ID] = event
		b.locker.Unlock()

		co, err := b.toCalendarObject(event, req)
		if err != nil {
			continue // skip events we can't decode
		}
		cos = append(cos, *co)
	}

	return cos, nil
}

func (b *backend) QueryCalendarObjects(ctx context.Context, path string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	calendars, err := b.c.ListCalendars(0, 1)
	if err != nil {
		return nil, err
	}
	if len(calendars) == 0 {
		return nil, nil
	}
	cal := calendars[0]

	filter := &protonmail.CalendarEventFilter{
		Timezone: "UTC",
	}

	// Parse time range from query filter
	if len(query.CompFilter.Comps) > 0 {
		cf := &query.CompFilter.Comps[0]
		if !cf.Start.IsZero() {
			filter.Start = cf.Start.Unix()
		}
		if !cf.End.IsZero() {
			filter.End = cf.End.Unix()
		}
	}

	// If no time range specified, use a broad range
	if filter.Start == 0 && filter.End == 0 {
		now := time.Now()
		filter.Start = now.AddDate(-1, 0, 0).Unix()
		filter.End = now.AddDate(1, 0, 0).Unix()
	}

	events, err := b.c.ListCalendarEvents(cal.ID, filter)
	if err != nil {
		return nil, err
	}

	cos := make([]caldav.CalendarObject, 0, len(events))
	for _, event := range events {
		b.locker.Lock()
		b.cache[event.ID] = event
		b.locker.Unlock()

		co, err := b.toCalendarObject(event, &query.CompRequest)
		if err != nil {
			continue
		}
		cos = append(cos, *co)
	}

	return cos, nil
}

func (b *backend) PutCalendarObject(ctx context.Context, path string, calendar *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	id, err := parseCalendarObjectPath(path)
	if err != nil {
		return nil, err
	}

	calendars, err := b.c.ListCalendars(0, 1)
	if err != nil {
		return nil, err
	}
	if len(calendars) == 0 {
		return nil, errNotFound
	}
	cal := calendars[0]

	// Check if this is an update or create
	existingEvent, lookupErr := b.c.GetCalendarEvent(cal.ID, id)

	// Build calendar event cards from the iCalendar data
	// For now, create cleartext shared events
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(calendar); err != nil {
		return nil, err
	}

	card := protonmail.CalendarEventCard{
		Type: protonmail.CalendarEventCardClear,
		Data: buf.String(),
	}

	eventImport := &protonmail.CalendarEventImport{
		SharedEvents: []protonmail.CalendarEventCard{card},
	}

	var updatedEvent *protonmail.CalendarEvent
	if lookupErr == nil && existingEvent != nil {
		updatedEvent, err = b.c.UpdateCalendarEvent(cal.ID, id, eventImport)
	} else {
		updatedEvent, err = b.c.CreateCalendarEvent(cal.ID, eventImport)
	}
	if err != nil {
		return nil, err
	}

	b.locker.Lock()
	b.cache[updatedEvent.ID] = updatedEvent
	b.locker.Unlock()

	return b.toCalendarObject(updatedEvent, &caldav.CalendarCompRequest{AllProps: true, AllComps: true})
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	id, err := parseCalendarObjectPath(path)
	if err != nil {
		return err
	}

	calendars, err := b.c.ListCalendars(0, 1)
	if err != nil {
		return err
	}
	if len(calendars) == 0 {
		return errNotFound
	}
	cal := calendars[0]

	if err := b.c.DeleteCalendarEvent(cal.ID, id); err != nil {
		return err
	}

	b.locker.Lock()
	delete(b.cache, id)
	b.locker.Unlock()

	return nil
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	for event := range events {
		b.locker.Lock()
		// Calendar events are not yet supported in the event stream,
		// so just clear the cache on any refresh
		if event.Refresh != 0 {
			b.cache = make(map[string]*protonmail.CalendarEvent)
		}
		b.locker.Unlock()
	}
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, events <-chan *protonmail.Event) http.Handler {
	if len(privateKeys) == 0 {
		panic("hydroxide/caldav: no private key available")
	}

	b := &backend{
		c:           c,
		cache:       make(map[string]*protonmail.CalendarEvent),
		privateKeys: privateKeys,
	}

	if events != nil {
		go b.receiveEvents(events)
	}

	return &caldav.Handler{Backend: b}
}