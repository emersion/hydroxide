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
	"sync"
	"time"
)

type backend struct {
	c           *protonmail.Client
	privateKeys openpgp.EntityList
	keyCache    map[string]openpgp.EntityList
	locker      sync.Mutex
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	// TODO
}

func readEventCard(event *ical.Event, eventCard protonmail.CalendarEventCard, userKr openpgp.KeyRing, calKr openpgp.KeyRing, keyPacket string) (ical.Props, error) {
	md, err := eventCard.Read(userKr, calKr, keyPacket)
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
			event.Props.Set(&p)
		}
	}

	return decoded.Props, nil
}

func toIcalCalendar(event *protonmail.CalendarEvent, userKr openpgp.KeyRing, calKr openpgp.KeyRing) (*ical.Calendar, error) {
	merged := ical.NewEvent()
	calProps := ical.Props{}
	// TODO: handle AttendeesEvents and PersonalEvents
	for _, card := range event.CalendarEvents {
		if propsMap, err := readEventCard(merged, card, userKr, calKr, ""); err != nil {
			return nil, err
		} else {
			for name, props := range propsMap {
				calProps[name] = append(calProps[name], props...)
			}
		}
	}

	for _, card := range event.SharedEvents {
		if propsMap, err := readEventCard(merged, card, userKr, calKr, event.SharedKeyPacket); err != nil {
			return nil, err
		} else {
			for name, props := range propsMap {
				name = strings.ToUpper(name)
				calProps[name] = append(calProps[name], props...)
			}
		}
	}

	cal := ical.NewCalendar()

	if calProps != nil {
		maps.Copy(cal.Props, calProps)
	}
	cal.Children = append(cal.Children, merged.Component)

	return cal, nil
}

func getCalendarObject(b *backend, calId string, calKr openpgp.KeyRing, event *protonmail.CalendarEvent) (*caldav.CalendarObject, error) {
	userKr, exists := b.keyCache[event.Author]
	if !exists {
		userKeys, err := b.c.GetPublicKeys(event.Author)
		if err != nil {
			return nil, err
		}

		for _, userKey := range userKeys.Keys {
			userKeyEntity, err := userKey.Entity()
			if err != nil {
				return nil, err
			}

			userKr = append(userKr, userKeyEntity)
		}

		b.locker.Lock()
		b.keyCache[event.Author] = userKr
		b.locker.Unlock()
	}

	data, err := toIcalCalendar(event, userKr, calKr)
	if err != nil {
		return nil, err
	}

	homeSetPath, err := b.CalendarHomeSetPath(nil)
	if err != nil {
		return nil, err
	}

	co := &caldav.CalendarObject{
		Path:    homeSetPath + calId + formatCalendarObjectPath(event.ID),
		ModTime: time.Unix(int64(event.LastEditTime), 0),
		// TODO: ETag
		ETag: strconv.FormatInt(int64(event.LastEditTime), 10),
		Data: data,
	}
	return co, nil
}

func formatCalendarObjectPath(id string) string {
	return "/" + id + ".ics"
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
	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, err
	}

	calEvtId, _ := strings.CutSuffix(path, "/")
	calEvtId, _ = strings.CutSuffix(calEvtId, ".ics")
	calEvtId, _ = strings.CutPrefix(calEvtId, homeSetPath)
	splitIds := strings.Split(calEvtId, "/")

	calId, evtId := splitIds[0], splitIds[1]
	event, err := b.c.GetCalendarEvent(calId, evtId)
	if err != nil {
		return nil, err
	}

	bootstrap, err := b.c.BootstrapCalendar(calId)
	if err != nil {
		return nil, err
	}

	calKr, err := bootstrap.DecryptKeyring(b.privateKeys)
	if err != nil {
		return nil, err
	}

	co, err := getCalendarObject(b, calId, calKr, event)
	if err != nil {
		return nil, err
	}

	return co, nil
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	protonCals, err := b.c.ListCalendars()
	if err != nil {
		return nil, err
	}

	var cos []caldav.CalendarObject
	for _, protonCal := range protonCals {
		events, err := b.c.ListCalendarEvents(protonCal.ID, nil)
		if err != nil {
			return nil, err
		}

		bootstrap, err := b.c.BootstrapCalendar(protonCal.ID)
		if err != nil {
			return nil, err
		}

		calKr, err := bootstrap.DecryptKeyring(b.privateKeys)
		if err != nil {
			return nil, err
		}

		calCos := make([]caldav.CalendarObject, len(events))
		for i, event := range events {
			co, err := getCalendarObject(b, protonCal.ID, calKr, event)
			if err != nil {
				return nil, err
			}

			calCos[i] = *co
		}

		cos = append(cos, calCos...)
	}

	return cos, nil
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

	var cos []caldav.CalendarObject
	for _, protonCal := range protonCals {
		filter := protonmail.CalendarEventFilter{}
		filter.Start = protonmail.NewTimestamp(cf.Start)
		filter.End = protonmail.NewTimestamp(cf.End)
		filter.Timezone = cf.Start.Location().String()

		events, err := b.c.ListCalendarEvents(protonCal.ID, &filter)
		if err != nil {
			return nil, err
		}

		bootstrap, err := b.c.BootstrapCalendar(protonCal.ID)
		if err != nil {
			return nil, err
		}

		calKr, err := bootstrap.DecryptKeyring(b.privateKeys)
		if err != nil {
			return nil, err
		}

		calCos := make([]caldav.CalendarObject, len(events))
		for i, event := range events {
			co, err := getCalendarObject(b, protonCal.ID, calKr, event)
			if err != nil {
				return nil, err
			}

			calCos[i] = *co
		}

		cos = append(cos, calCos...)
	}

	return cos, nil
}

func (b *backend) PutCalendarObject(ctx context.Context, path string, calendar *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (loc string, err error) {
	//TODO: maybe impl opts?
	homeSetPath, err := b.CalendarHomeSetPath(nil)
	if err != nil {
		return "", err
	}

	calEvtId, _ := strings.CutSuffix(path, "/")
	calEvtId, _ = strings.CutSuffix(calEvtId, ".ics")
	calEvtId, _ = strings.CutPrefix(calEvtId, homeSetPath)
	splitIds := strings.Split(calEvtId, "/")

	calId, evtId := splitIds[0], splitIds[1]

	events := calendar.Events()
	if len(events) != 1 {
		return "", errors.New("hydroxide/caldav: expected PUT VCALENDAR to have exactly one VEVENT")
	}
	event := events[0]

	err = b.c.UpdateCalendarEvent(calId, evtId, event, b.privateKeys)
	if err != nil {
		return "", err
	}

	//TODO: write functionality
	return "", nil
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	homeSetPath, err := b.CalendarHomeSetPath(nil)
	if err != nil {
		return err
	}

	calEvtId, _ := strings.CutSuffix(path, "/")
	calEvtId, _ = strings.CutSuffix(calEvtId, ".ics")
	calEvtId, _ = strings.CutPrefix(calEvtId, homeSetPath)
	splitIds := strings.Split(calEvtId, "/")

	calId, evtId := splitIds[0], splitIds[1]

	return b.c.DeleteCalendarEvent(calId, evtId)
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/caldav/", nil
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, username string, events <-chan *protonmail.Event) http.Handler {
	if len(privateKeys) == 0 {
		panic("hydroxide/caldav: no private key available")
	}

	keyCache := map[string]openpgp.EntityList{username: privateKeys}
	b := &backend{
		c:           c,
		privateKeys: privateKeys,
		keyCache:    keyCache,
	}

	if events != nil {
		go b.receiveEvents(events)
	}

	return &caldav.Handler{Backend: b}
}
