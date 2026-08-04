package caldav

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strings"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/emersion/hydroxide/protonmail"
)

// TODO: support multiple calendars

type backend struct {
	c           *protonmail.Client
	cal         *protonmail.Calendar
	privateKeys openpgp.EntityList
}

func (b *backend) calendar() (*protonmail.Calendar, error) {
	if b.cal != nil {
		return b.cal, nil
	}

	calendars, err := b.c.ListCalendars(0, 150)
	if err != nil {
		return nil, err
	} else if len(calendars) == 0 {
		return nil, fmt.Errorf("hydroxide/caldav: no calendar available")
	}

	return calendars[0], nil
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
	cal, err := b.calendar()
	if err != nil {
		return nil, err
	}
	return []caldav.Calendar{{
		Path:        "/",
		Name:        cal.Name,
		Description: cal.Description,
	}}, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	if path != "/" {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar not found"))
	}
	cal, err := b.calendar()
	if err != nil {
		return nil, err
	}
	return &caldav.Calendar{
		Path:        "/",
		Name:        cal.Name,
		Description: cal.Description,
	}, nil
}

func formatCalendarObjectPath(id string) string {
	return "/" + id + ".ics"
}

func (b *backend) toCalendarObject(event *protonmail.CalendarEvent, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	// TODO: handle req

	merged := ical.NewEvent()

	// TODO: handle CalendarEvents, AttendeesEvents and PersonalEvents
	for _, c := range event.SharedEvents {
		md, err := c.Read(b.privateKeys)
		if err != nil {
			return nil, err
		}

		decoded, err := ical.NewDecoder(md.UnverifiedBody).Decode()
		if err != nil {
			return nil, err
		}

		// The signature can be checked only if md.UnverifiedBody is consumed until
		// EOF
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

	data := ical.NewCalendar()
	data.Children = append(data.Children, merged.Component)

	return &caldav.CalendarObject{
		Path:    formatCalendarObjectPath(event.ID),
		ModTime: event.ModifyTime.Time(),
		// TODO: ETag
		Data: data,
	}, nil
}

func parseCalendarObjectPath(p string) (string, error) {
	dirname, filename := path.Split(p)
	ext := path.Ext(filename)
	if dirname != "/" || ext != ".ics" {
		return "", fmt.Errorf("caldav: not found")
	}
	return strings.TrimSuffix(filename, ext), nil
}

func (b *backend) GetCalendarObject(ctx context.Context, reqPath string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	id, err := parseCalendarObjectPath(reqPath)
	if err != nil {
		return nil, err
	}

	cal, err := b.calendar()
	if err != nil {
		return nil, err
	}

	event, err := b.c.GetCalendarEvent(cal.ID, id)
	if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 13051 {
		return nil, fmt.Errorf("caldav: not found")
	} else if err != nil {
		return nil, err
	}

	return b.toCalendarObject(event, req)
}

func (b *backend) ListCalendarObjects(ctx context.Context, reqPath string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	cal, err := b.calendar()
	if err != nil {
		return nil, err
	}

	events, err := b.c.ListCalendarEvents(cal.ID, nil)
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

func (b *backend) QueryCalendarObjects(ctx context.Context, reqPath string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	if query.CompFilter.Name != ical.CompCalendar {
		return nil, fmt.Errorf("hydroxide/caldav: expected toplevel comp to be VCALENDAR")
	}
	if len(query.CompFilter.Comps) != 1 || query.CompFilter.Comps[0].Name != ical.CompEvent {
		return nil, fmt.Errorf("hydroxide/caldav: expected exactly one nested VEVENT comp")
	}
	cf := &query.CompFilter.Comps[0]

	cal, err := b.calendar()
	if err != nil {
		return nil, err
	}

	filter := protonmail.CalendarEventFilter{}
	filter.Start = protonmail.NewTimestamp(cf.Start)
	filter.End = protonmail.NewTimestamp(cf.End)
	filter.Timezone = cf.Start.Location().String()
	events, err := b.c.ListCalendarEvents(cal.ID, &filter)
	if err != nil {
		return nil, err
	}

	cos := make([]caldav.CalendarObject, len(events))
	for i, event := range events {
		co, err := b.toCalendarObject(event, &query.CompRequest)
		if err != nil {
			return nil, err
		}
		cos[i] = *co
	}

	return cos, nil
}

func (b *backend) PutCalendarObject(ctx context.Context, reqPath string, calendar *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	return nil, fmt.Errorf("hydroxide/caldav: PutCalendarObject not implemented")
}

func (b *backend) DeleteCalendarObject(ctx context.Context, reqPath string) error {
	return fmt.Errorf("hydroxide/caldav: DeleteCalendarObject not implemented")
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	// TODO
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, events <-chan *protonmail.Event) http.Handler {
	if len(privateKeys) == 0 {
		panic("hydroxide/caldav: no private key available")
	}

	b := &backend{
		c:           c,
		privateKeys: privateKeys,
	}

	if events != nil {
		go b.receiveEvents(events)
	}

	return &caldav.Handler{Backend: b}
}
