package caldav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
	"github.com/emersion/hydroxide/protonmail"
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type backend struct {
	c           *protonmail.Client
	privateKeys openpgp.EntityList
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	// TODO
}

func makeIcal(props ical.Props, components ...*ical.Component) *ical.Calendar {
	cal := ical.NewCalendar()

	if props != nil {
		maps.Copy(cal.Props, props)
	}
	cal.Props.SetText("VERSION", "2.0")
	cal.Props.SetText("PRODID", "-//hydroxide//ProtonMail calendar//EN")

	if components != nil {
		cal.Children = append(cal.Children, components...)
	}

	return cal
}

func toIcalEvent(event *protonmail.CalendarEvent, userKr openpgp.KeyRing, calKr openpgp.KeyRing) (*ical.Event, error) {
	merged := ical.NewEvent()
	// TODO: handle CalendarEvents, AttendeesEvents and PersonalEvents
	for _, c := range event.SharedEvents {
		md, err := c.Read(userKr, calKr, event.SharedKeyPacket)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			return nil, err
		}

		decoded, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
		if err != nil {
			return nil, err
		}

		// The signature can be checked only if md.UnverifiedBody is consumed until
		// EOF
		// TODO: mdc hash mismatch (?)
		/*_, err = io.Copy(io.Discard, md.UnverifiedBody)
		if err != nil {
			return nil, err
		}*/

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
				merged.Props.Set(&p)
			}
		}
	}
	return merged, nil
}

func toIcalCalendar(events []*protonmail.CalendarEvent, userKr openpgp.KeyRing, calKr openpgp.KeyRing) (*ical.Calendar, error) {
	ces := make([]*ical.Component, len(events))
	for i, event := range events {
		ce, err := toIcalEvent(event, userKr, calKr)
		if err != nil {
			return nil, err
		}

		ces[i] = ce.Component
	}

	cal := makeIcal(nil, ces...)
	return cal, nil
}

func getCalendarObject(b *backend, cal *protonmail.Calendar, filter *protonmail.CalendarEventFilter) (*caldav.CalendarObject, error) {
	bootstrap, err := b.c.BootstrapCalendar(cal.ID)
	if err != nil {
		return nil, err
	}

	calKr, err := bootstrap.DecryptKeyring(b.privateKeys)
	if err != nil {
		return nil, err
	}

	events, err := b.c.ListCalendarEvents(cal.ID, filter)
	if err != nil {
		return nil, err
	}

	data, err := toIcalCalendar(events, b.privateKeys, calKr)
	if err != nil {
		return nil, err
	}

	lastEditTime := getLastEditTime(events)
	co := &caldav.CalendarObject{
		Path:    "/caldav/calendars/" + cal.ID,
		ModTime: lastEditTime,
		// TODO: ETag
		ETag: strconv.FormatInt(lastEditTime.Unix(), 10),
		Data: data,
	}
	return co, nil
}

func getLastEditTime(events []*protonmail.CalendarEvent) time.Time {
	var lastEditTime time.Time
	for _, event := range events {
		stamp := time.Unix(int64(event.LastEditTime), 0)
		if stamp.After(lastEditTime) {
			lastEditTime = stamp
		}
	}
	return lastEditTime
}

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	userPrincipal, err := b.CurrentUserPrincipal(ctx)
	if err != nil {
		return "", err
	}
	return userPrincipal + "calendars/", nil
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	protonCals, err := b.c.ListCalendars()
	if err != nil {
		return nil, err
	}

	cals := make([]caldav.Calendar, len(protonCals))
	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, err
	}

	for i, cal := range protonCals {
		calView, err := protonmail.FindMemberViewFromKeyring(cal.Members, b.privateKeys)
		if err != nil {
			return nil, err
		}

		caldavCal := caldav.Calendar{
			Path:        homeSetPath + cal.ID,
			Name:        calView.Name,
			Description: calView.Description,
		}
		cals[i] = caldavCal
	}
	return cals, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	protonCals, err := b.c.ListCalendars()
	if err != nil {
		return nil, err
	}

	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, err
	}

	id, _ := strings.CutSuffix(path, "/")
	id, _ = strings.CutPrefix(id, homeSetPath)
	for _, cal := range protonCals {
		if cal.ID != id {
			continue
		}

		calView, err := protonmail.FindMemberViewFromKeyring(cal.Members, b.privateKeys)
		if err != nil {
			return nil, err
		}

		caldavCal := caldav.Calendar{
			Path:        homeSetPath + cal.ID,
			Name:        calView.Name,
			Description: calView.Description,
		}

		return &caldavCal, nil
	}
	return nil, errors.New("could not find calendar with path")
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	protonCals, err := b.c.ListCalendars()
	if err != nil {
		return nil, err
	}

	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, err
	}

	id, _ := strings.CutSuffix(path, "/")
	id, _ = strings.CutPrefix(id, homeSetPath)
	for _, cal := range protonCals {
		if cal.ID != id {
			continue
		}

		co, err := getCalendarObject(b, cal, nil)
		if err != nil {
			return nil, err
		}

		return co, nil
	}
	return nil, errors.New("could not find calendar with path")
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

	protonCals, err := b.c.ListCalendars()
	if err != nil {
		return nil, err
	}

	cos := make([]caldav.CalendarObject, len(protonCals))
	for i, protonCal := range protonCals {
		filter := protonmail.CalendarEventFilter{}
		filter.Start = protonmail.NewTimestamp(cf.Start)
		filter.End = protonmail.NewTimestamp(cf.End)
		filter.Timezone = cf.Start.Location().String()

		co, err := getCalendarObject(b, protonCal, &filter)
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
	return "/caldav/", nil
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
