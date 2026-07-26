package caldav

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/emersion/go-webdav"
)

var errNotFound = errors.New("caldav: not found")

// Calendar represents a CalDAV calendar collection.
type Calendar struct {
	Path        string
	Name        string
	Description string
}

// CalendarObject represents a single calendar event (VEVENT).
type CalendarObject struct {
	Path      string
	Data      []byte
	ETag      string
	ModTime   time.Time
	ContentType string
}

// Backend describes the ProtonMail calendar backend.
type Backend interface {
	// ListCalendars returns all available calendars.
	ListCalendars(ctx context.Context) ([]Calendar, error)
	// GetCalendarObject returns a calendar object by path.
	GetCalendarObject(ctx context.Context, path string) (*CalendarObject, error)
	// ListCalendarObjects returns all objects in a calendar.
	ListCalendarObjects(ctx context.Context, calendarPath string) ([]CalendarObject, error)
}

// Handler implements a basic CalDAV server.
type Handler struct {
	backend Backend
	prefix  string
	mu      sync.RWMutex
}

func NewHandler(backend Backend, prefix string) *Handler {
	return &Handler{backend: backend, prefix: prefix}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("DAV", "1, calendar-access")
		w.Header().Set("Allow", "OPTIONS, PROPFIND, REPORT, GET")
		w.WriteHeader(http.StatusOK)

	case "PROPFIND":
		h.handlePropfind(w, r, ctx)

	case "REPORT":
		h.handleReport(w, r, ctx)

	case http.MethodGet:
		h.handleGet(w, r, ctx)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handlePropfind(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	calendars, err := h.backend.ListCalendars(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var responses []webdav.PropfindResponse
	for _, cal := range calendars {
		responses = append(responses, webdav.PropfindResponse{
			Href: h.prefix + cal.Path,
			Propstat: []webdav.Propstat{{
				Status: "HTTP/1.1 200 OK",
				Props: map[string]interface{}{
					"DAV::resourcetype":    []string{"collection", "calendar"},
					"DAV::displayname":     cal.Name,
					"CALDAV::calendar-description": cal.Description,
					"CALDAV::supported-calendar-component-set": []string{"VEVENT"},
				},
			}},
		})
	}

	body, _ := webdav.MarshalPropfind(&webdav.MultiStatus{Responses: responses})
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	w.Write(body)
}

func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	// calendar-query: list events in a calendar
	objects, err := h.backend.ListCalendarObjects(ctx, r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var responses []webdav.PropfindResponse
	for _, obj := range objects {
		responses = append(responses, webdav.PropfindResponse{
			Href: h.prefix + obj.Path,
			Propstat: []webdav.Propstat{{
				Status: "HTTP/1.1 200 OK",
				Props: map[string]interface{}{
					"DAV::getetag":       obj.ETag,
					"DAV::getlastmodified": obj.ModTime,
					"DAV::getcontenttype":  obj.ContentType,
				},
			}},
		})
	}

	body, _ := webdav.MarshalPropfind(&webdav.MultiStatus{Responses: responses})
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	w.Write(body)
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	obj, err := h.backend.GetCalendarObject(ctx, r.URL.Path)
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", obj.ContentType)
	w.Header().Set("ETag", obj.ETag)
	w.Write(obj.Data)
}

// ProtonMail adapter
type ProtonMailBackend struct {
	calendars []Calendar
	events    map[string][]CalendarObject
}

func NewProtonMailBackend() *ProtonMailBackend {
	return &ProtonMailBackend{
		calendars: []Calendar{{
			Path:        "/calendar/default",
			Name:        "ProtonMail",
			Description: "ProtonMail calendar",
		}},
		events: make(map[string][]CalendarObject),
	}
}

func (b *ProtonMailBackend) ListCalendars(ctx context.Context) ([]Calendar, error) {
	return b.calendars, nil
}

func (b *ProtonMailBackend) GetCalendarObject(ctx context.Context, path string) (*CalendarObject, error) {
	for _, cal := range b.calendars {
		for _, obj := range b.events[cal.Path] {
			if obj.Path == path {
				return &obj, nil
			}
		}
	}
	return nil, errNotFound
}

func (b *ProtonMailBackend) ListCalendarObjects(ctx context.Context, calendarPath string) ([]CalendarObject, error) {
	return b.events[calendarPath], nil
}

func (b *ProtonMailBackend) AddEvent(calendarPath string, obj CalendarObject) {
	b.events[calendarPath] = append(b.events[calendarPath], obj)
}

// Ensure Handler implements http.Handler
var _ http.Handler = (*Handler)(nil)
var _ Backend = (*ProtonMailBackend)(nil)
var _ = fmt.Sprintf
var _ = io.ReadAll
