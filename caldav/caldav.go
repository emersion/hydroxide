package caldav

import (
	"context"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
	"io"
	"net/http"

	"github.com/emersion/hydroxide/protonmail"
)

// TODO: support multiple calendars

type backend struct {
	c           *protonmail.Client
	cal         *protonmail.Calendar
	calKr       openpgp.KeyRing
	privateKeys openpgp.EntityList
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	// TODO
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

func (b *backend) Calendar() (*caldav.Calendar, error) {
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

func toCalendarObject(event *protonmail.CalendarEvent, calKr openpgp.KeyRing, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	// TODO: handle req

	merged := ical.NewEvent()
	// TODO: handle CalendarEvents, AttendeesEvents and PersonalEvents
	for _, c := range event.SharedEvents {
		md, err := c.Read(userKr, calKr, event.SharedKeyPacket)
		if err != nil {
			return nil, err
		}

		decoded, err := ical.NewDecoder(md.UnverifiedBody).Decode()
		if err != nil {
			return nil, err
		}

		// The signature can be checked only if md.UnverifiedBody is consumed until
		// EOF
		_, err = io.Copy(io.Discard, md.UnverifiedBody)
		if err != nil {
			return nil, err
		}

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

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	return "", nil
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	return nil, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	return nil, nil
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	cal, err := b.calendar()
	if err != nil {
		return nil, err
	}

	bootstrap, err := b.c.BootstrapCalendar(cal.ID)
	if err != nil {
		return nil, err
	}
	calKr, err := bootstrap.DecryptKeyring(b.privateKeys)
	if err != nil {
		return nil, err
	}
	_ = calKr

	events, err := b.c.ListCalendarEvents(cal.ID, nil)
	if err != nil {
		return nil, err
	}

	co, err := toCalendarObject(events[0], nil) // todo calkr
	if err != nil {
		return nil, err
	}

	return co, nil
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	return nil, nil
}

func (b *backend) QueryCalendarObjects(ctx context.Context, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
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

func (b *backend) PutCalendarObject(ctx context.Context, path string, calendar *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (loc string, err error) {
	return "", nil
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	return nil
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/", nil
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
