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

var errNotFound = errors.New("caldav: not found")

func formatCalendarObjectPath(calendarID, eventID string) string {
	return "/calendars/" + calendarID + "/" + eventID + ".ics"
}

func parseCalendarObjectPath(p string) (calendarID, eventID string, err error) {
	dirname, filename := path.Split(p)
	ext := path.Ext(filename)
	if dirname == "" || ext != ".ics" {
		return "", "", errNotFound
	}
	parts := strings.Split(strings.TrimSuffix(dirname, "/"), "/")
	if len(parts) != 3 || parts[0] != "" || parts[1] != "calendars" {
		return "", "", errNotFound
	}
	calendarID = parts[2]
	eventID = strings.TrimSuffix(filename, ext)
	return calendarID, eventID, nil
}

func formatCalendarPath(id string) string {
	return "/calendars/" + id + "/"
}

func parseCalendarPath(p string) (id string, err error) {
	p = strings.TrimSuffix(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) != 3 || parts[0] != "" || parts[1] != "calendars" {
		return "", errNotFound
	}
	return parts[2], nil
}

func (b *backend) toCalendarObject(event *protonmail.CalendarEvent, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//ProtonMail//ProtonMail Calendar//EN")

	var allCards []protonmail.CalendarEventCard
	if len(event.PersonalEvent) > 0 {
		allCards = append(allCards, event.PersonalEvent...)
	}
	if len(event.SharedEvents) > 0 {
		allCards = append(allCards, event.SharedEvents...)
	}

	for _, card := range allCards {
		md, err := card.Read(b.privateKeys)
		if err != nil {
			return nil, fmt.Errorf("caldav: failed to decrypt calendar event card: %v", err)
		}

		decoded, err := ical.NewDecoder(md.UnverifiedBody).Decode()
		if err != nil {
			return nil, fmt.Errorf("caldav: failed to parse iCal data: %v", err)
		}

		io.Copy(ioutil.Discard, md.UnverifiedBody)

		for _, comp := range decoded.Children {
			cal.Children = append(cal.Children, comp)
		}
	}

	etag := fmt.Sprintf("%x-%x", event.LastEditTime.Unix(), event.ID)

	return &caldav.CalendarObject{
		Path:    formatCalendarObjectPath(event.CalendarID, event.ID),
		ModTime: event.LastEditTime.Time(),
		ETag:    etag,
		Data:    cal,
	}, nil
}

type backend struct {
	c           *protonmail.Client
	locker      sync.Mutex
	calendars   []*protonmail.Calendar
	cache       map[string]map[string]*protonmail.CalendarEvent
	privateKeys openpgp.EntityList
}

func (b *backend) refreshCalendars() error {
	cals, err := b.c.ListCalendars(0, 0)
	if err != nil {
		return err
	}
	b.locker.Lock()
	b.calendars = cals
	b.locker.Unlock()
	return nil
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
	if err := b.refreshCalendars(); err != nil {
		return nil, err
	}

	b.locker.Lock()
	defer b.locker.Unlock()

	cals := make([]caldav.Calendar, len(b.calendars))
	for i, cal := range b.calendars {
		cals[i] = caldav.Calendar{
			Path:                  formatCalendarPath(cal.ID),
			Name:                  cal.Name,
			Description:           cal.Description,
			MaxResourceSize:       100 * 1024,
			SupportedComponentSet: []string{ical.CompEvent},
		}
	}
	return cals, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	id, err := parseCalendarPath(path)
	if err != nil {
		return nil, err
	}

	if err := b.refreshCalendars(); err != nil {
		return nil, err
	}

	b.locker.Lock()
	defer b.locker.Unlock()

	for _, cal := range b.calendars {
		if cal.ID == id {
			return &caldav.Calendar{
				Path:                  formatCalendarPath(cal.ID),
				Name:                  cal.Name,
				Description:           cal.Description,
				MaxResourceSize:       100 * 1024,
				SupportedComponentSet: []string{ical.CompEvent},
			}, nil
		}
	}

	return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar not found"))
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	id, err := parseCalendarPath(path)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	start := now.Add(-7 * 24 * time.Hour).Unix()
	end := now.Add(30 * 24 * time.Hour).Unix()

	events, err := b.c.ListCalendarEvents(id, &protonmail.CalendarEventFilter{
		Start:    start,
		End:      end,
		Timezone: "UTC",
	})
	if err != nil {
		return nil, err
	}

	objects := make([]caldav.CalendarObject, 0, len(events))
	for _, event := range events {
		obj, err := b.toCalendarObject(event, req)
		if err != nil {
			continue
		}
		objects = append(objects, *obj)
	}
	return objects, nil
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	calendarID, eventID, err := parseCalendarObjectPath(path)
	if err != nil {
		return nil, err
	}

	events, err := b.c.ListCalendarEvents(calendarID, &protonmail.CalendarEventFilter{
		Start: 0,
		End:   time.Now().Add(365 * 24 * time.Hour).Unix(),
	})
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

func (b *backend) QueryCalendarObjects(ctx context.Context, path string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	all, err := b.ListCalendarObjects(ctx, path, &caldav.CalendarCompRequest{AllProp: true})
	if err != nil {
		return nil, err
	}

	if query == nil {
		return all, nil
	}

	return caldav.Filter(query, all)
}

func (b *backend) CreateCalendarObject(ctx context.Context, path string, cal *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (obj *caldav.CalendarObject, err error) {
	return nil, webdav.NewHTTPError(http.StatusNotImplemented, errors.New("creating calendar objects not yet supported"))
}

func (b *backend) UpdateCalendarObject(ctx context.Context, path string, cal *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (obj *caldav.CalendarObject, err error) {
	return nil, webdav.NewHTTPError(http.StatusNotImplemented, errors.New("updating calendar objects not yet supported"))
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	return webdav.NewHTTPError(http.StatusNotImplemented, errors.New("deleting calendar objects not yet supported"))
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList) http.Handler {
	if len(privateKeys) == 0 {
		panic("hydroxide/caldav: no private key available")
	}

	b := &backend{
		c:           c,
		cache:       make(map[string]map[string]*protonmail.CalendarEvent),
		privateKeys: privateKeys,
	}

	return &caldav.Handler{Backend: b}
}
