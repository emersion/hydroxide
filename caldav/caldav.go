package caldav

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/emersion/hydroxide/protonmail"
)

// TODO: use a HTTP error
var errNotFound = errors.New("caldav: not found")

var calendar = &caldav.Calendar{
	Path:            "/calendar",
	Name:            "ProtonMail",
	Description:     "ProtonMail calendars",
	MaxResourceSize: 100 * 1024 * 1024, // 100MB
}

type backend struct {
	c           *protonmail.Client
	cache       map[string]*protonmail.Calendar
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

func (b *backend) CreateCalendar(ctx context.Context, ab *caldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot create new calendar"))
}

func (b *backend) DeleteCalendar(ctx context.Context, path string) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot delete calendar"))
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	return []caldav.Calendar{*calendar}, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	if path != calendar.Path {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar not found"))
	}
	return calendar, nil
}

func (b *backend) cacheComplete() bool {
	b.locker.Lock()
	defer b.locker.Unlock()
	return b.total >= 0 && len(b.cache) == b.total
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

func (b *backend) deleteCache(id string) {
	b.locker.Lock()
	delete(b.cache, id)
	b.locker.Unlock()
}

func formatCalendarObjectPath(id string) string {
	return "/calendar/" + id + ".ics"
}

func parseCalendarObjectPath(p string) (string, error) {
	dirname, filename := path.Split(p)
	ext := path.Ext(filename)
	if dirname != "/calendar/" || ext != ".ics" {
		return "", errNotFound
	}
	return strings.TrimSuffix(filename, ext), nil
}

func (b *backend) toCalendarObject(event *protonmail.CalendarEvent, req *caldav.CalendarDataRequest) (*caldav.CalendarObject, error) {
	// TODO: handle req

	var buf bytes.Buffer
	for _, card := range event.CalendarEvents {
		data, err := base64.StdEncoding.DecodeString(card.Data)
		if err != nil {
			return nil, err
		}
		buf.Write(data)
		if card.Signature != "" {
			sig, err := base64.StdEncoding.DecodeString(card.Signature)
			if err != nil {
				return nil, err
			}
			buf.Write(sig)
		}
	}

	return &caldav.CalendarObject{
		Path:    formatCalendarObjectPath(event.ID),
		ModTime: event.CreateTime.Time(),
		// TODO: stronger ETag
		ETag: fmt.Sprintf("%x%x", event.CreateTime, event.Author),
		Data: buf.Bytes(),
	}, nil
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarDataRequest) ([]caldav.CalendarObject, error) {
	if path != calendar.Path {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar not found"))
	}

	if b.cacheComplete() {
		b.locker.Lock()
		defer b.locker.Unlock()

		cos := make([]caldav.CalendarObject, 0)
		for _, cal := range b.cache {
			objs, err := b.listCalendarEvents(cal.ID, req)
			if err != nil {
				return nil, err
			}
			cos = append(cos, objs...)
		}
		return cos, nil
	}

	// Get a list of all calendars
	calendars, err := b.c.ListCalendars(0, 0)
	if err != nil {
		return nil, err
	}
	b.locker.Lock()
	b.total = len(calendars)
	b.locker.Unlock()

	for _, cal := range calendars {
		b.putCache(cal)
	}

	// Get all calendar events
	cos := make([]caldav.CalendarObject, 0)
	now := time.Now().Unix()
	start := now - 90*24*60*60 // 90 days ago
	end := now + 365*24*60*60  // 1 year ahead

	for _, cal := range calendars {
		events, err := b.c.ListCalendarEvents(cal.ID, &protonmail.CalendarEventFilter{
			Start:    start,
			End:      end,
			Timezone: "UTC",
			Page:     0,
			PageSize: 0,
		})
		if err != nil {
			return nil, err
		}

		for _, event := range events {
			co, err := b.toCalendarObject(event, req)
			if err != nil {
				return nil, err
			}
			cos = append(cos, *co)
		}
	}

	return cos, nil
}

func (b *backend) listCalendarEvents(calendarID string, req *caldav.CalendarDataRequest) ([]caldav.CalendarObject, error) {
	now := time.Now().Unix()
	start := now - 90*24*60*60
	end := now + 365*24*60*60

	events, err := b.c.ListCalendarEvents(calendarID, &protonmail.CalendarEventFilter{
		Start:    start,
		End:      end,
		Timezone: "UTC",
		Page:     0,
		PageSize: 0,
	})
	if err != nil {
		return nil, err
	}

	cos := make([]caldav.CalendarObject, 0, len(events))
	for _, event := range events {
		co, err := b.toCalendarObject(event, req)
		if err != nil {
			return nil, err
		}
		cos = append(cos, *co)
	}

	return cos, nil
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarDataRequest) (*caldav.CalendarObject, error) {
	id, err := parseCalendarObjectPath(path)
	if err != nil {
		return nil, err
	}

	// Search for the event in all calendars
	b.locker.Lock()
	cals := make([]*protonmail.Calendar, 0, len(b.cache))
	for _, cal := range b.cache {
		cals = append(cals, cal)
	}
	b.locker.Unlock()

	for _, cal := range cals {
		events, err := b.c.ListCalendarEvents(cal.ID, &protonmail.CalendarEventFilter{
			Start:    0,
			End:      time.Now().Unix() + 365*24*60*60,
			Timezone: "UTC",
			Page:     0,
			PageSize: 0,
		})
		if err != nil {
			return nil, err
		}

		for _, event := range events {
			if event.ID == id {
				return b.toCalendarObject(event, req)
			}
		}
	}

	return nil, errNotFound
}

func (b *backend) QueryCalendarObjects(ctx context.Context, path string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	req := caldav.CalendarDataRequest{AllProp: true}
	if query != nil {
		req = query.DataRequest
	}

	all, err := b.ListCalendarObjects(ctx, path, &req)
	if err != nil {
		return nil, err
	}

	return caldav.Filter(query, all), nil
}

func (b *backend) PutCalendarObject(ctx context.Context, path string, calendarData []byte, opts *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	// TODO: implement
	return nil, webdav.NewHTTPError(http.StatusForbidden, errors.New("creating/updating calendar events not supported"))
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	// TODO: implement
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("deleting calendar events not supported"))
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	for event := range events {
		b.locker.Lock()
		if event.Refresh&protonmail.EventRefreshCalendar != 0 {
			b.cache = make(map[string]*protonmail.Calendar)
			b.total = -1
		} else if len(event.Calendars) > 0 {
			for _, eventCal := range event.Calendars {
				switch eventCal.Action {
				case protonmail.EventCreate:
					if b.total >= 0 {
						b.total++
					}
					fallthrough
				case protonmail.EventUpdate:
					b.cache[eventCal.ID] = eventCal.Calendar
				case protonmail.EventDelete:
					delete(b.cache, eventCal.ID)
					if b.total >= 0 {
						b.total--
					}
				}
			}
		}
		b.locker.Unlock()
	}
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, events <-chan *protonmail.Event) http.Handler {
	b := &backend{
		c:           c,
		cache:       make(map[string]*protonmail.Calendar),
		total:       -1,
		privateKeys: privateKeys,
	}

	if events != nil {
		go b.receiveEvents(events)
	}

	return &caldav.Handler{Backend: b}
}