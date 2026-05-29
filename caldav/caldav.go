package caldav

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/emersion/hydroxide/protonmail"
)

var errNotFound = errors.New("caldav: not found")

var defaultCalendar = &caldav.Calendar{
	Path:        "/calendars/default",
	Name:        "ProtonMail",
	Description: "ProtonMail calendar",
}

func parseCalendarObjectPath(p string) (string, error) {
	dirname, filename := path.Split(p)
	ext := path.Ext(filename)
	if dirname != "/calendars/default/" || ext != ".ics" {
		return "", errNotFound
	}
	return strings.TrimSuffix(filename, ext), nil
}

func formatCalendarObjectPath(id string) string {
	return "/calendars/default/" + id + ".ics"
}

func timestampToTime(ts protonmail.Timestamp) time.Time {
	return ts.Time()
}

func calendarEventToIcal(event *protonmail.CalendarEvent) (*ical.Calendar, error) {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.ProdID, "-//hydroxide//EN")

	// Decode shared events
	for _, sharedEvent := range event.SharedEvents {
		comp := ical.NewComponent(ical.CompEvent)
		comp.Props.SetText(ical.PropUID, event.ID)

		// Parse the event data (iCal format stored by ProtonMail)
		if sharedEvent.Data != "" {
			// ProtonMail stores event data as iCal, parse and copy properties
			parser := ical.NewDecoder(strings.NewReader(sharedEvent.Data))
			parsed, err := parser.Decode()
			if err == nil {
				for _, child := range parsed.Children {
					for propName, props := range child.Props {
						for _, prop := range props {
							comp.Props.Add(propName, prop)
						}
					}
				}
			}
		}

		// Set timestamps
		if !event.CreateTime.Time().IsZero() {
			comp.Props.SetDateTime(ical.PropCreated, event.CreateTime.Time())
		}
		if !event.LastEditTime.Time().IsZero() {
			comp.Props.SetDateTime(ical.PropLastModified, event.LastEditTime.Time())
		}

		cal.Children = append(cal.Children, comp)
	}

	return cal, nil
}

type backend struct {
	c      *protonmail.Client
	cache  map[string]*protonmail.CalendarEvent
	locker sync.Mutex
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/", nil
}

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	return "/calendars", nil
}

func (b *backend) CreateCalendar(ctx context.Context, calendar *caldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot create new calendar"))
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	return []caldav.Calendar{*defaultCalendar}, nil
}

func (b *backend) GetCalendar(ctx context.Context, calendarPath string) (*caldav.Calendar, error) {
	if calendarPath != defaultCalendar.Path {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar not found"))
	}
	return defaultCalendar, nil
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	id, err := parseCalendarObjectPath(path)
	if err != nil {
		return nil, err
	}

	b.locker.Lock()
	event, ok := b.cache[id]
	b.locker.Unlock()

	if !ok {
		return nil, errNotFound
	}

	cal, err := calendarEventToIcal(event)
	if err != nil {
		return nil, err
	}

	return &caldav.CalendarObject{
		Path:    formatCalendarObjectPath(event.ID),
		ModTime: timestampToTime(event.LastEditTime),
		ETag:    fmt.Sprintf("%x", event.LastEditTime),
		Data:    cal,
	}, nil
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	if path != defaultCalendar.Path {
		return nil, errNotFound
	}

	// Get calendars from ProtonMail
	calendars, err := b.c.ListCalendars(0, 0)
	if err != nil {
		return nil, err
	}

	var objs []caldav.CalendarObject
	for _, cal := range calendars {
		// Get events for each calendar
		filter := &protonmail.CalendarEventFilter{
			Start:    time.Now().AddDate(-1, 0, 0).Unix(),
			End:      time.Now().AddDate(1, 0, 0).Unix(),
			Timezone: "UTC",
			Page:     0,
			PageSize: 100,
		}

		events, err := b.c.ListCalendarEvents(cal.ID, filter)
		if err != nil {
			continue
		}

		for _, event := range events {
			b.locker.Lock()
			b.cache[event.ID] = event
			b.locker.Unlock()

			ical, err := calendarEventToIcal(event)
			if err != nil {
				continue
			}

			objs = append(objs, caldav.CalendarObject{
				Path:    formatCalendarObjectPath(event.ID),
				ModTime: timestampToTime(event.LastEditTime),
				ETag:    fmt.Sprintf("%x", event.LastEditTime),
				Data:    ical,
			})
		}
	}

	return objs, nil
}

func (b *backend) QueryCalendarObjects(ctx context.Context, path string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	req := caldav.CalendarCompRequest{AllProp: true}
	if query != nil {
		req = query.CompRequest
	}
	return b.ListCalendarObjects(ctx, path, &req)
}

func (b *backend) PutCalendarObject(ctx context.Context, path string, calendar *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	return nil, webdav.NewHTTPError(http.StatusNotImplemented, errors.New("put calendar object not implemented"))
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	return webdav.NewHTTPError(http.StatusNotImplemented, errors.New("delete calendar object not implemented"))
}

func NewHandler(c *protonmail.Client) http.Handler {
	b := &backend{
		c:     c,
		cache: make(map[string]*protonmail.CalendarEvent),
	}
	return &caldav.Handler{Backend: b}
}
