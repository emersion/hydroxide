package caldav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/emersion/hydroxide/protonmail"
)

// TODO: use a HTTP error
var errNotFound = errors.New("caldav: not found")

type backend struct {
	c           *protonmail.Client
	cache       map[string]*protonmail.Calendar
	eventCache  map[string][]*protonmail.CalendarEvent
	locker      sync.Mutex
	total       int
	privateKeys openpgp.EntityList
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/", nil
}

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	return "/calendars", nil
}

func (b *backend) CreateCalendar(ctx context.Context, cal *caldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot create new calendar"))
}

func (b *backend) DeleteCalendar(ctx context.Context, path string) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot delete calendar"))
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	calendars, err := b.c.ListCalendars(0, 0)
	if err != nil {
		return nil, err
	}

	b.locker.Lock()
	b.cache = make(map[string]*protonmail.Calendar)
	for _, cal := range calendars {
		b.cache[cal.ID] = cal
	}
	b.locker.Unlock()

	caldavCalendars := make([]caldav.Calendar, 0, len(calendars))
	for _, cal := range calendars {
		caldavCalendars = append(caldavCalendars, caldav.Calendar{
			Path:            formatCalendarPath(cal.ID),
			Name:            cal.Name,
			Description:     cal.Description,
			Color:           cal.Color,
			MaxResourceSize: 100 * 1024 * 1024, // 100MB
		})
	}

	return caldavCalendars, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	id, err := parseCalendarPath(path)
	if err != nil {
		return nil, err
	}

	cal, ok := b.getCache(id)
	if !ok {
		calendars, err := b.c.ListCalendars(0, 0)
		if err != nil {
			return nil, err
		}
		for _, c := range calendars {
			if c.ID == id {
				cal = c
				break
			}
		}
		if cal == nil {
			return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar not found"))
		}
		b.putCache(cal)
	}

	return &caldav.Calendar{
		Path:            formatCalendarPath(cal.ID),
		Name:            cal.Name,
		Description:     cal.Description,
		Color:           cal.Color,
		MaxResourceSize: 100 * 1024 * 1024,
	}, nil
}

func formatCalendarPath(id string) string {
	return "/calendars/" + id
}

func parseCalendarPath(p string) (string, error) {
	if !strings.HasPrefix(p, "/calendars/") {
		return "", errNotFound
	}
	id := strings.TrimPrefix(p, "/calendars/")
	if id == "" {
		return "", errNotFound
	}
	return id, nil
}

func formatCalendarObjectPath(calendarID, eventID string) string {
	return fmt.Sprintf("/calendars/%s/%s.ics", calendarID, eventID)
}

func parseCalendarObjectPath(p string) (calendarID, eventID string, err error) {
	if !strings.HasPrefix(p, "/calendars/") {
		return "", "", errNotFound
	}
	rest := strings.TrimPrefix(p, "/calendars/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return "", "", errNotFound
	}
	calendarID = parts[0]
	eventID = strings.TrimSuffix(parts[1], ".ics")
	if eventID == "" {
		return "", "", errNotFound
	}
	return calendarID, eventID, nil
}

func (b *backend) getCache(id string) (*protonmail.Calendar, bool) {
	b.locker.Lock()
	cal, ok := b.cache[id]
	b.locker.Unlock()
	return cal, ok
}

func (b *backend) putCache(cal *protonmail.Calendar) {
	b.locker.Lock()
	b.cache[cal.ID] = cal
	b.locker.Unlock()
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarDataRequest) (*caldav.CalendarObject, error) {
	calendarID, eventID, err := parseCalendarObjectPath(path)
	if err != nil {
		return nil, err
	}

	events, err := b.getCalendarEvents(calendarID)
	if err != nil {
		return nil, err
	}

	for _, event := range events {
		if event.ID == eventID {
			return b.toCalendarObject(event, req)
		}
	}

	return nil, errNotFound
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarDataRequest) ([]caldav.CalendarObject, error) {
	calendarID, err := parseCalendarPath(path)
	if err != nil {
		return nil, err
	}

	events, err := b.getCalendarEvents(calendarID)
	if err != nil {
		return nil, err
	}

	objects := make([]caldav.CalendarObject, 0, len(events))
	for _, event := range events {
		obj, err := b.toCalendarObject(event, req)
		if err != nil {
			return nil, err
		}
		objects = append(objects, *obj)
	}

	return objects, nil
}

func (b *backend) getCalendarEvents(calendarID string) ([]*protonmail.CalendarEvent, error) {
	b.locker.Lock()
	events, ok := b.eventCache[calendarID]
	b.locker.Unlock()

	if ok {
		return events, nil
	}

	// Get events from the beginning of time to now
	events, err := b.c.ListCalendarEvents(calendarID, &protonmail.CalendarEventFilter{
		Start:   0,
		End:     0,
		Timezone: "UTC",
	})
	if err != nil {
		return nil, err
	}

	b.locker.Lock()
	b.eventCache[calendarID] = events
	b.locker.Unlock()

	return events, nil
}

func (b *backend) toCalendarObject(event *protonmail.CalendarEvent, req *caldav.CalendarDataRequest) (*caldav.CalendarObject, error) {
	// TODO: handle req

	// Decode the event data from the calendar event cards
	var vevent *ical.Component
	for _, card := range event.CalendarEvents {
		if vevent != nil {
			break
		}
		decoded, err := ical.NewDecoder(strings.NewReader(card.Data)).Decode()
		if err != nil {
			continue
		}
		if decoded.Name == ical.ComponentVEvent {
			vevent = decoded
		}
	}

	if vevent == nil {
		// Fallback: try PersonalEvents
		for _, card := range event.PersonalEvent {
			if vevent != nil {
				break
			}
			decoded, err := ical.NewDecoder(strings.NewReader(card.Data)).Decode()
			if err != nil {
				continue
			}
			if decoded.Name == ical.ComponentVEvent {
				vevent = decoded
			}
		}
	}

	var objData string
	if vevent != nil {
		var buf bytes.Buffer
		if err := ical.NewEncoder(&buf).Encode(vevent); err != nil {
			return nil, err
		}
		objData = buf.String()
	}

	return &caldav.CalendarObject{
		Path:    formatCalendarObjectPath(event.CalendarID, event.ID),
		ModTime: event.LastEditTime.Time(),
		ETag:    fmt.Sprintf("%x", event.LastEditTime),
		Data:    objData,
	}, nil
}

func (b *backend) PutCalendarObject(ctx context.Context, path string, obj io.Reader, opts *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	if _, _, err := parseCalendarObjectPath(path); err != nil {
		return nil, err
	}

	// Read and decode the iCalendar data
	if _, err := ioutil.ReadAll(obj); err != nil {
		return nil, err
	}

	// For now, we can't create or update events because the ProtonMail API
	// requires encrypted event data that we can't generate client-side
	return nil, webdav.NewHTTPError(http.StatusForbidden, errors.New("calendar event creation/update not supported"))
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	if _, _, err := parseCalendarObjectPath(path); err != nil {
		return err
	}

	// For now, we can't delete events because the ProtonMail API
	// doesn't support direct event deletion
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("calendar event deletion not supported"))
}

func (b *backend) Query(ctx context.Context, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	if query.Calendar != "" {
		objects, err := b.ListCalendarObjects(ctx, query.Calendar, &query.DataRequest)
		if err != nil {
			return nil, err
		}
		return caldav.Filter(query, objects), nil
	}

	// Query across all calendars
	b.locker.Lock()
	calendarIDs := make([]string, 0, len(b.cache))
	for id := range b.cache {
		calendarIDs = append(calendarIDs, id)
	}
	b.locker.Unlock()

	var allObjects []caldav.CalendarObject
	for _, calendarID := range calendarIDs {
		objects, err := b.ListCalendarObjects(ctx, formatCalendarPath(calendarID), &query.DataRequest)
		if err != nil {
			return nil, err
		}
		allObjects = append(allObjects, objects...)
	}

	return caldav.Filter(query, allObjects), nil
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, events <-chan *protonmail.Event) http.Handler {
	if len(privateKeys) == 0 {
		panic("hydroxide/caldav: no private key available")
	}

	b := &backend{
		c:           c,
		cache:       make(map[string]*protonmail.Calendar),
		eventCache:  make(map[string][]*protonmail.CalendarEvent),
		privateKeys: privateKeys,
	}

	return &caldav.Handler{Backend: b}
}