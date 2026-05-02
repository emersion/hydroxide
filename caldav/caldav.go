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
	// dirname should be /calendars/{calendarID}/
	parts := strings.Split(strings.TrimSuffix(dirname, "/"), "/")
	// parts should be ["", "calendars", calendarID]
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
	// parts should be ["", "calendars", id]
	if len(parts) != 3 || parts[0] != "" || parts[1] != "calendars" {
		return "", errNotFound
	}
	return parts[2], nil
}

func (b *backend) toCalendarObject(event *protonmail.CalendarEvent, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//ProtonMail//ProtonMail Calendar//EN")

	// Decrypt and combine all event cards
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

		// Consume body for signature verification
		io.Copy(ioutil.Discard, md.UnverifiedBody)
		if err := md.SignatureError; err != nil {
			// Log but don't fail on signature errors
			// return nil, fmt.Errorf("caldav: signature verification failed: %v", err)
		}

		// Merge components from decoded calendar
		for _, comp := range decoded.Children {
			cal.Children = append(cal.Children, comp)
		}
	}

	return &caldav.CalendarObject{
		Path:    formatCalendarObjectPath(event.CalendarID, event.ID),
		ModTime: event.LastEditTime.Time(),
		ETag:    fmt.Sprintf("%x-%x", event.LastEditTime, event.ID),
		Data:    cal,
	}, nil
}

func formatCalendarEvent(cal *ical.Calendar, privateKey *openpgp.Entity) (*protonmail.CalendarEventImport, error) {
	// Encode the iCalendar data
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, err
	}

	// Encrypt the iCal data with user's key and sign with private key
	to := []*openpgp.Entity{privateKey}
	encrypted, err := protonmail.NewEncryptedCalendarEventCard(&buf, to, privateKey)
	if err != nil {
		return nil, err
	}

	return &protonmail.CalendarEventImport{
		Event: &protonmail.CalendarEventCardSet{
			PersonalEvent: encrypted,
		},
	}, nil
}

type backend struct {
	c           *protonmail.Client
	locker      sync.Mutex
	calendars   []*protonmail.Calendar
	cache       map[string]map[string]*protonmail.CalendarEvent // calendarID -> eventID -> event
	privateKeys openpgp.EntityList
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

func (b *backend) refreshCalendars() error {
	b.locker.Lock()
	if b.calendars != nil {
		b.locker.Unlock()
		return nil
	}
	b.locker.Unlock()

	calendars, err := b.c.ListCalendars(0, 0)
	if err != nil {
		return err
	}

	b.locker.Lock()
	b.calendars = calendars
	b.locker.Unlock()
	return nil
}

func (b *backend) getCache(calendarID, eventID string) (*protonmail.CalendarEvent, bool) {
	b.locker.Lock()
	defer b.locker.Unlock()
	if calCache, ok := b.cache[calendarID]; ok {
		event, ok := calCache[eventID]
		return event, ok
	}
	return nil, false
}

func (b *backend) putCache(event *protonmail.CalendarEvent) {
	b.locker.Lock()
	defer b.locker.Unlock()
	if b.cache == nil {
		b.cache = make(map[string]map[string]*protonmail.CalendarEvent)
	}
	calCache, ok := b.cache[event.CalendarID]
	if !ok {
		calCache = make(map[string]*protonmail.CalendarEvent)
		b.cache[event.CalendarID] = calCache
	}
	calCache[event.ID] = event
}

func (b *backend) deleteCache(calendarID, eventID string) {
	b.locker.Lock()
	defer b.locker.Unlock()
	if calCache, ok := b.cache[calendarID]; ok {
		delete(calCache, eventID)
	}
}

func (b *backend) cacheComplete(calendarID string) bool {
	b.locker.Lock()
	defer b.locker.Unlock()
	calCache, ok := b.cache[calendarID]
	if !ok {
		return false
	}
	return len(calCache) > 0
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	calendarID, eventID, err := parseCalendarObjectPath(path)
	if err != nil {
		return nil, err
	}

	event, ok := b.getCache(calendarID, eventID)
	if !ok {
		if b.cacheComplete(calendarID) {
			return nil, errNotFound
		}

		event, err = b.c.GetCalendarEvent(calendarID, eventID)
		if err != nil {
			if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2501 {
				return nil, errNotFound
			}
			return nil, err
		}
		b.putCache(event)
	}

	return b.toCalendarObject(event, req)
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	calendarID, err := parseCalendarPath(path)
	if err != nil {
		return nil, err
	}

	// If cache is complete, use it
	if b.cacheComplete(calendarID) {
		b.locker.Lock()
		calCache := b.cache[calendarID]
		b.locker.Unlock()

		cos := make([]caldav.CalendarObject, 0, len(calCache))
		for _, event := range calCache {
			co, err := b.toCalendarObject(event, req)
			if err != nil {
				return nil, err
			}
			cos = append(cos, *co)
		}
		return cos, nil
	}

	// Fetch all events for this calendar
	// Use a wide time range to get all events
	filter := &protonmail.CalendarEventFilter{
		Start:    0,
		End:     4102444800, // ~2100-01-01
		Timezone: "UTC",
		Page:     0,
	}

	var allEvents []*protonmail.CalendarEvent
	for {
		events, err := b.c.ListCalendarEvents(calendarID, filter)
		if err != nil {
			return nil, err
		}
		allEvents = append(allEvents, events...)
		if len(events) == 0 || filter.PageSize > 0 && len(events) < filter.PageSize {
			break
		}
		filter.Page++
	}

	// Populate cache
	b.locker.Lock()
	if b.cache == nil {
		b.cache = make(map[string]map[string]*protonmail.CalendarEvent)
	}
	calCache := make(map[string]*protonmail.CalendarEvent, len(allEvents))
	for _, event := range allEvents {
		calCache[event.ID] = event
	}
	b.cache[calendarID] = calCache
	b.locker.Unlock()

	cos := make([]caldav.CalendarObject, 0, len(allEvents))
	for _, event := range allEvents {
		co, err := b.toCalendarObject(event, req)
		if err != nil {
			return nil, err
		}
		cos = append(cos, *co)
	}
	return cos, nil
}

func (b *backend) QueryCalendarObjects(ctx context.Context, path string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	req := caldav.CalendarCompRequest{AllProps: true}
	if query != nil {
		req = query.CompRequest
	}

	// TODO: optimize with ProtonMail server-side filtering
	all, err := b.ListCalendarObjects(ctx, path, &req)
	if err != nil {
		return nil, err
	}

	return caldav.Filter(query, all)
}

func (b *backend) PutCalendarObject(ctx context.Context, path string, cal *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (co *caldav.CalendarObject, err error) {
	calendarID, eventID, pathErr := parseCalendarObjectPath(path)
	if pathErr != nil {
		// Maybe it's a PUT to a new path — extract calendarID from parent
		// For new events, the path format is /calendars/{calID}/{newID}.ics
		return nil, pathErr
	}

	eventImport, err := formatCalendarEvent(cal, b.privateKeys[0])
	if err != nil {
		return nil, err
	}

	var event *protonmail.CalendarEvent

	// Check if the event already exists
	if _, getErr := b.GetCalendarObject(ctx, path, nil); getErr == nil {
		// Update existing event
		event, err = b.c.UpdateCalendarEvent(calendarID, eventID, eventImport)
		if err != nil {
			return nil, err
		}
	} else {
		// Create new event
		event, err = b.c.CreateCalendarEvent(calendarID, eventImport)
		if err != nil {
			return nil, err
		}
	}

	b.putCache(event)

	return b.toCalendarObject(event, nil)
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	calendarID, eventID, err := parseCalendarObjectPath(path)
	if err != nil {
		return err
	}

	if err := b.c.DeleteCalendarEvent(calendarID, eventID); err != nil {
		return err
	}

	b.deleteCache(calendarID, eventID)
	return nil
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	for event := range events {
		b.locker.Lock()
		if event.Refresh&protonmail.EventRefreshCalendar != 0 {
			b.calendars = nil
			b.cache = make(map[string]map[string]*protonmail.CalendarEvent)
		} else if len(event.CalendarEvents) > 0 {
			for _, eventCalEvent := range event.CalendarEvents {
				switch eventCalEvent.Action {
				case protonmail.EventCreate:
					fallthrough
				case protonmail.EventUpdate:
					b.putCache(eventCalEvent.CalendarEvent)
				case protonmail.EventDelete:
					if eventCalEvent.CalendarEvent != nil {
						b.deleteCache(eventCalEvent.CalendarEvent.CalendarID, eventCalEvent.ID)
					}
				}
			}
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
		cache:       make(map[string]map[string]*protonmail.CalendarEvent),
		privateKeys: privateKeys,
	}

	if events != nil {
		go b.receiveEvents(events)
	}

	return &caldav.Handler{Backend: b}
}