package caldav

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/emersion/hydroxide/protonmail"
)

var errNotFound = errors.New("caldav: not found")

const calPathPrefix = "/calendars/"

var defaultCalendar = &caldav.Calendar{
	Path:                  calPathPrefix + "default",
	Name:                  "ProtonMail",
	Description:           "ProtonMail calendar",
	MaxResourceSize:       100 * 1024,
	SupportedComponentSet: []string{ical.CompEvent},
}

type backend struct {
	c           *protonmail.Client
	calendars   map[string]*protonmail.Calendar
	calEvents   map[string]map[string]*protonmail.CalendarEvent
	locker      sync.Mutex
	initialized bool
}

func (b *backend) init() error {
	if b.initialized {
		return nil
	}

	cals, err := b.c.ListCalendars(0, 0)
	if err != nil {
		return fmt.Errorf("caldav: failed to list calendars: %w", err)
	}

	b.locker.Lock()
	b.calendars = make(map[string]*protonmail.Calendar)
	b.calEvents = make(map[string]map[string]*protonmail.CalendarEvent)
	for _, cal := range cals {
		b.calendars[cal.ID] = cal
	}
	b.locker.Unlock()

	b.initialized = true
	log.Printf("caldav: loaded %d calendars", len(b.calendars))
	return nil
}

func (b *backend) ensureEventsLoaded(calID string) error {
	now := time.Now()
	filter := &protonmail.CalendarEventFilter{
		Start:    now.AddDate(0, -6, 0).Unix(),
		End:      now.AddDate(0, 6, 0).Unix(),
		Page:     0,
		PageSize: 200,
	}

	events, err := b.c.ListCalendarEvents(calID, filter)
	if err != nil {
		return fmt.Errorf("caldav: failed to list events: %w", err)
	}

	b.locker.Lock()
	if b.calEvents[calID] == nil {
		b.calEvents[calID] = make(map[string]*protonmail.CalendarEvent)
	}
	for _, event := range events {
		b.calEvents[calID][event.ID] = event
	}
	b.locker.Unlock()

	log.Printf("caldav: loaded %d events for calendar %s", len(events), calID)
	return nil
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/", nil
}

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	return calPathPrefix, nil
}

func (b *backend) CreateCalendar(ctx context.Context, calendar *caldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot create new calendar"))
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	if err := b.init(); err != nil {
		return nil, err
	}
	return []caldav.Calendar{*defaultCalendar}, nil
}

func (b *backend) GetCalendar(ctx context.Context, p string) (*caldav.Calendar, error) {
	if p != defaultCalendar.Path {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar not found"))
	}
	return defaultCalendar, nil
}

func eventToICal(event *protonmail.CalendarEvent) *ical.Calendar {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//hydroxide//ProtonMail//EN")

	vevent := ical.NewComponent(ical.CompEvent)
	vevent.Props.SetText(ical.PropUID, event.ID)

	// Try to use decrypted event data
	eventData := ""
	for _, card := range event.PersonalEvent {
		if card.Data != "" {
			eventData = card.Data
			break
		}
	}
	if eventData == "" {
		for _, card := range event.SharedEvents {
			if card.Data != "" {
				eventData = card.Data
				break
			}
		}
	}

	if eventData != "" {
		if decoded, err := ical.NewDecoder(strings.NewReader(eventData)).Decode(); err == nil {
			for _, comp := range decoded.Children {
				cal.Children = append(cal.Children, comp)
			}
			return cal
		}
	}

	// Fallback: create minimal event with just UID
	if event.CreateTime > 0 {
		vevent.Props.SetText(ical.PropDateTimeStart, event.CreateTime.Time().Format("20060102T150405Z"))
	}
	cal.Children = append(cal.Children, vevent)
	return cal
}

func icalToRaw(cal *ical.Calendar) string {
	var buf bytes.Buffer
	encoder := ical.NewEncoder(&buf)
	if err := encoder.Encode(cal); err != nil {
		return ""
	}
	return buf.String()
}

func parseObjectPath(p string) (string, string, error) {
	p = path.Clean(p)
	dir, filename := path.Split(p)
	ext := path.Ext(filename)
	if !strings.HasPrefix(dir, calPathPrefix) || ext != ".ics" {
		return "", "", errNotFound
	}
	eventID := strings.TrimSuffix(filename, ext)
	return "default", eventID, nil
}

func formatObjectPath(eventID string) string {
	return calPathPrefix + "default/" + eventID + ".ics"
}

func (b *backend) toObject(event *protonmail.CalendarEvent, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	icalCal := eventToICal(event)

	var buf bytes.Buffer
	ical.NewEncoder(&buf).Encode(icalCal)

	modTime := event.CreateTime.Time()
	if event.LastEditTime > 0 {
		modTime = event.LastEditTime.Time()
	}

	return &caldav.CalendarObject{
		Path:          formatObjectPath(event.ID),
		ModTime:       modTime,
		ContentLength: int64(buf.Len()),
		ETag:          fmt.Sprintf("%x", md5.Sum([]byte(event.ID+strconv.FormatInt(modTime.Unix(), 10)))),
		Data:          icalCal,
	}, nil
}

func (b *backend) getEvent(calID, eventID string) (*protonmail.CalendarEvent, bool) {
	b.locker.Lock()
	defer b.locker.Unlock()
	if events, ok := b.calEvents[calID]; ok {
		event, ok := events[eventID]
		return event, ok
	}
	return nil, false
}

func (b *backend) putEvent(calID string, event *protonmail.CalendarEvent) {
	b.locker.Lock()
	defer b.locker.Unlock()
	if b.calEvents[calID] == nil {
		b.calEvents[calID] = make(map[string]*protonmail.CalendarEvent)
	}
	b.calEvents[calID][event.ID] = event
}

func (b *backend) delEvent(calID, eventID string) {
	b.locker.Lock()
	defer b.locker.Unlock()
	if events, ok := b.calEvents[calID]; ok {
		delete(events, eventID)
	}
}

func (b *backend) GetCalendarObject(ctx context.Context, p string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	calID, eventID, err := parseObjectPath(p)
	if err != nil {
		return nil, err
	}

	event, ok := b.getEvent(calID, eventID)
	if !ok {
		if err := b.ensureEventsLoaded(calID); err != nil {
			return nil, err
		}
		event, ok = b.getEvent(calID, eventID)
		if !ok {
			return nil, errNotFound
		}
	}

	return b.toObject(event, req)
}

func (b *backend) ListCalendarObjects(ctx context.Context, p string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	if err := b.ensureEventsLoaded("default"); err != nil {
		return nil, err
	}

	b.locker.Lock()
	events := make([]*protonmail.CalendarEvent, 0, len(b.calEvents["default"]))
	for _, event := range b.calEvents["default"] {
		events = append(events, event)
	}
	b.locker.Unlock()

	objects := make([]caldav.CalendarObject, 0, len(events))
	for _, event := range events {
		obj, err := b.toObject(event, req)
		if err != nil {
			log.Printf("caldav: skip event %s: %v", event.ID, err)
			continue
		}
		objects = append(objects, *obj)
	}

	return objects, nil
}

func (b *backend) QueryCalendarObjects(ctx context.Context, p string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	req := caldav.CalendarCompRequest{AllProps: true, AllComps: true}
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

func (b *backend) PutCalendarObject(ctx context.Context, p string, icalCal *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	rawData := icalToRaw(icalCal)

	var uid string
	for _, comp := range icalCal.Children {
		if comp.Name == ical.CompEvent || comp.Name == ical.CompToDo || comp.Name == ical.CompJournal {
			uid, _ = comp.Props.Text(ical.PropUID)
			break
		}
	}
	if uid == "" {
		uid = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	calID := "default"
	_, existingID, pathErr := parseObjectPath(p)
	if pathErr == nil && existingID != "" {
		if _, ok := b.getEvent(calID, existingID); ok {
			// Update
			event := &protonmail.CalendarEvent{
				ID:           existingID,
				CalendarID:   calID,
				LastEditTime: protonmail.Timestamp(time.Now().Unix()),
				PersonalEvent: []protonmail.CalendarEventCard{
					{Data: rawData},
				},
			}
			b.putEvent(calID, event)
			return b.toObject(event, &caldav.CalendarCompRequest{AllProps: true, AllComps: true})
		}
	}

	// Create new
	event := &protonmail.CalendarEvent{
		ID:           uid,
		CalendarID:   calID,
		CreateTime:   protonmail.Timestamp(time.Now().Unix()),
		LastEditTime: protonmail.Timestamp(time.Now().Unix()),
		PersonalEvent: []protonmail.CalendarEventCard{
			{Data: rawData},
		},
	}
	b.putEvent(calID, event)
	return b.toObject(event, &caldav.CalendarCompRequest{AllProps: true, AllComps: true})
}

func (b *backend) DeleteCalendarObject(ctx context.Context, p string) error {
	calID, eventID, err := parseObjectPath(p)
	if err != nil {
		return err
	}

	if _, ok := b.getEvent(calID, eventID); !ok {
		return errNotFound
	}

	b.delEvent(calID, eventID)
	return nil
}

func NewHandler(c *protonmail.Client, events <-chan *protonmail.Event) http.Handler {
	b := &backend{
		c:         c,
		calendars: make(map[string]*protonmail.Calendar),
		calEvents: make(map[string]map[string]*protonmail.CalendarEvent),
	}

	return &caldav.Handler{Backend: b}
}
