package caldav

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
	"github.com/emersion/hydroxide/protonmail"
)

var errNotFound = errors.New("caldav: not found")

const calendarHomePath = "/calendars"

func defaultCalendarPath(calID string) string {
	return calendarHomePath + "/" + calID
}

func parseCalendarPath(p string) (string, error) {
	p = strings.TrimSuffix(p, "/")
	if !strings.HasPrefix(p, calendarHomePath+"/") {
		return "", errNotFound
	}
	id := strings.TrimPrefix(p, calendarHomePath+"/")
	if id == "" {
		return "", errNotFound
	}
	return id, nil
}

func parseEventObjectPath(p string) (calID, eventID string, err error) {
	p = strings.TrimSuffix(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) != 4 || parts[1] != "calendars" {
		return "", "", errNotFound
	}
	calID = parts[2]
	eventID = strings.TrimSuffix(parts[3], ".ics")
	if calID == "" || eventID == "" {
		return "", "", errNotFound
	}
	return calID, eventID, nil
}

type backend struct {
	client      *protonmail.Client
	privateKeys openpgp.EntityList
}

// NewBackend initializes a new caldav.Backend implementation wrapper.
func NewBackend(client *protonmail.Client, privateKeys openpgp.EntityList) caldav.Backend {
	return &backend{
		client:      client,
		privateKeys: privateKeys,
	}
}

// NewHandler wraps the backend interface within an HTTP Handler matching the call signature in main.go
func NewHandler(client *protonmail.Client, privateKeys openpgp.EntityList, eventsChan chan *protonmail.Event) http.Handler {
	b := NewBackend(client, privateKeys)
	return &caldav.Handler{Backend: b}
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	user, err := b.client.GetCurrentUser()
	if err != nil {
		return "", err
	}
	return "/principals/" + user.Name, nil
}

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	return calendarHomePath, nil
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	rawCals, err := b.client.ListCalendars(1, 100)
	if err != nil {
		return nil, err
	}

	var cals []caldav.Calendar
	for _, rc := range rawCals {
		cals = append(cals, caldav.Calendar{
			Path:                  defaultCalendarPath(rc.ID),
			Name:                  rc.Name,
			Description:           rc.Description,
			SupportedComponentSet: []string{ical.CompEvent},
		})
	}
	return cals, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	calID, err := parseCalendarPath(path)
	if err != nil {
		return nil, err
	}

	rc, err := b.client.GetCalendar(calID)
	if err != nil {
		return nil, err
	}

	return &caldav.Calendar{
		Path:                  defaultCalendarPath(rc.ID),
		Name:                  rc.Name,
		Description:           rc.Description,
		SupportedComponentSet: []string{ical.CompEvent},
	}, nil
}

func (b *backend) CreateCalendar(ctx context.Context, calendar *caldav.Calendar) error {
	return fmt.Errorf("action forbidden")
}

func (b *backend) DeleteCalendar(ctx context.Context, path string) error {
	return fmt.Errorf("action forbidden")
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	calID, err := parseCalendarPath(path)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	filter := &protonmail.CalendarEventFilter{
		Start:    protonmail.Timestamp(now.AddDate(-1, 0, 0).Unix()),
		End:      protonmail.Timestamp(now.AddDate(1, 0, 0).Unix()),
		PageSize: 100,
	}

	_, exports, err := b.client.ListCalendarEventsExport(calID, filter)
	if err != nil {
		return nil, err
	}

	var objs []caldav.CalendarObject
	for _, exp := range exports {
		var cardData []byte
		if len(exp.Cards) > 0 {
			cardData, _ = b.decryptCardData(exp.Cards[0], b.privateKeys)
		}

		calComp := ical.NewCalendar()
		calComp.Props.SetText(ical.PropVersion, "2.0")
		calComp.Props.SetText(ical.PropProductID, "-//emersion//hydroxide//EN")

		eventComp := ical.NewComponent(ical.CompEvent)
		b.populateEventFromRaw(eventComp, exp.Event, cardData)
		calComp.Children = append(calComp.Children, eventComp)

		objs = append(objs, caldav.CalendarObject{
			Path: path + "/" + exp.ID + ".ics",
			Data: calComp,
		})
	}

	return objs, nil
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	calID, eventID, err := parseEventObjectPath(path)
	if err != nil {
		return nil, err
	}

	rawEvent, err := b.client.GetCalendarEvent(calID, eventID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	filter := &protonmail.CalendarEventFilter{
		Start:    protonmail.Timestamp(now.AddDate(-5, 0, 0).Unix()),
		End:      protonmail.Timestamp(now.AddDate(5, 0, 0).Unix()),
		PageSize: 100,
	}
	_, exports, err := b.client.ListCalendarEventsExport(calID, filter)
	if err != nil {
		return nil, err
	}

	var cardData []byte
	for _, exp := range exports {
		if exp.ID == eventID && len(exp.Cards) > 0 {
			cardData, _ = b.decryptCardData(exp.Cards[0], b.privateKeys)
			break
		}
	}

	calComp := ical.NewCalendar()
	calComp.Props.SetText(ical.PropVersion, "2.0")
	calComp.Props.SetText(ical.PropProductID, "-//emersion//hydroxide//EN")

	eventComp := ical.NewComponent(ical.CompEvent)
	b.populateEventFromRaw(eventComp, rawEvent, cardData)
	calComp.Children = append(calComp.Children, eventComp)

	return &caldav.CalendarObject{
		Path: path,
		Data: calComp,
	}, nil
}

func (b *backend) PutCalendarObject(ctx context.Context, path string, calendar *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	calID, eventID, err := parseEventObjectPath(path)
	if err != nil {
		return nil, err
	}

	var eventComp *ical.Component
	for _, child := range calendar.Children {
		if child.Name == ical.CompEvent {
			eventComp = child
			break
		}
	}
	if eventComp == nil {
		return nil, fmt.Errorf("caldav: missing VEVENT component")
	}

	if len(b.privateKeys) == 0 {
		return nil, fmt.Errorf("caldav: no private keys available for signing")
	}

	eventImport, err := b.icalToEventImport(eventComp, b.privateKeys[0])
	if err != nil {
		return nil, err
	}

	_, err = b.client.GetCalendarEvent(calID, eventID)
	if err == nil {
		_, err = b.client.UpdateCalendarEvent(calID, eventID, eventImport)
	} else {
		_, err = b.client.CreateCalendarEvent(calID, eventImport)
	}
	if err != nil {
		return nil, err
	}

	return &caldav.CalendarObject{
		Path: path,
		Data: calendar,
	}, nil
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	calID, eventID, err := parseEventObjectPath(path)
	if err != nil {
		return err
	}

	return b.client.DeleteCalendarEvent(calID, eventID)
}

func (b *backend) QueryCalendarObjects(ctx context.Context, path string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	return b.ListCalendarObjects(ctx, path, nil)
}

func (b *backend) decryptCardData(card *protonmail.CalendarEventCard, keys openpgp.EntityList) ([]byte, error) {
	cc := &protonmail.ContactCard{
		Type: protonmail.ContactCardType(card.Type),
		Data: card.Data,
	}
	md, err := cc.Read(keys)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, md.UnverifiedBody)
	return buf.Bytes(), err
}

func (b *backend) populateEventFromRaw(event *ical.Component, raw *protonmail.CalendarEvent, data []byte) {
	event.Props.SetText(ical.PropUID, raw.ID)

	var (
		summary, desc, loc string
		start, end         time.Time
	)

	if len(data) > 0 {
		var rawData struct {
			Summary     string
			Description string
			Location    string
			Start       int64
			End         int64
		}
		if err := json.Unmarshal(data, &rawData); err == nil {
			summary = rawData.Summary
			desc = rawData.Description
			loc = rawData.Location
			start = time.Unix(rawData.Start, 0)
			end = time.Unix(rawData.End, 0)
		}
	}

	if summary != "" {
		event.Props.SetText(ical.PropSummary, summary)
	}
	if desc != "" {
		event.Props.SetText(ical.PropDescription, desc)
	}
	if loc != "" {
		event.Props.SetText(ical.PropLocation, loc)
	}

	if !start.IsZero() {
		event.Props.SetDateTime(ical.PropDateTimeStart, start)
	}
	if !end.IsZero() {
		event.Props.SetDateTime(ical.PropDateTimeEnd, end)
	}

	if len(data) > 0 && !strings.HasPrefix(string(data), "{") {
		subCal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
		if err == nil {
			var subEvent *ical.Component
			for _, child := range subCal.Children {
				if child.Name == ical.CompEvent {
					subEvent = child
					break
				}
			}
			if subEvent != nil {
				for name, props := range subEvent.Props {
					if len(props) > 0 {
						event.Props.SetText(name, props[0].Value)
					}
				}
			}
		}
	}
}

func (b *backend) icalToEventImport(eventComp *ical.Component, signer *openpgp.Entity) (*protonmail.CalendarEventImport, error) {
	var buf bytes.Buffer
	subCal := ical.NewCalendar()
	subCal.Children = append(subCal.Children, eventComp)
	if err := ical.NewEncoder(&buf).Encode(subCal); err != nil {
		return nil, err
	}

	to := []*openpgp.Entity{signer}
	encrypted, err := protonmail.NewEncryptedContactCard(&buf, to, signer)
	if err != nil {
		return nil, err
	}

	return &protonmail.CalendarEventImport{
		Cards: []*protonmail.CalendarEventCard{
			{
				Type: protonmail.CalendarEventCardType(encrypted.Type),
				Data: encrypted.Data,
			},
		},
	}, nil
}
