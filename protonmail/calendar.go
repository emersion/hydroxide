package protonmail

import (
	"net/http"
	"net/url"
	"strconv"
)

const calendarPath = "/calendar/v1"

type CalendarFlags int

type Calendar struct {
	ID          string
	Name        string
	Description string
	Color       string
	Display     int
	Flags       CalendarFlags
}

type CalendarEventPermissions int

type CalendarEvent struct {
	ID                string
	CalendarID        string
	CalendarKeyPacket string
	CreateTime        Timestamp
	LastEditTime      Timestamp
	Author            string
	Permissions       CalendarEventPermissions
	SharedKeyPacket   string
	SharedEvents      []CalendarEventCard
	CalendarEvents    interface{}
	PersonalEvent     []CalendarEventCard
}

type CalendarEventCardType int

type CalendarEventCard struct {
	Type      CalendarEventCardType
	Data      string
	Signature string
	MemberID  string
}

func (c *Client) ListCalendars(page, pageSize int) ([]*Calendar, error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, calendarPath+"?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Calendars []*Calendar
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Calendars, nil
}

type CalendarEventFilter struct {
	Start, End     int64
	Timezone       string
	Page, PageSize int
}

func (c *Client) ListCalendarEvents(calendarID string, filter *CalendarEventFilter) ([]*CalendarEvent, error) {
	v := url.Values{}
	v.Set("Start", strconv.FormatInt(filter.Start, 10))
	v.Set("End", strconv.FormatInt(filter.End, 10))
	v.Set("Timezone", filter.Timezone)
	v.Set("Page", strconv.Itoa(filter.Page))
	if filter.PageSize > 0 {
		v.Set("PageSize", strconv.Itoa(filter.PageSize))
	}

	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+calendarID+"/events?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Events []*CalendarEvent
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Events, nil
}

func (c *Client) CreateCalendarEvent(calendarID string, event *CalendarEvent) (*CalendarEvent, error) {
	req, err := c.newJSONRequest(http.MethodPost, calendarPath+"/"+calendarID+"/events", event)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Event *CalendarEvent
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Event, nil
}

func (c *Client) UpdateCalendarEvent(calendarID, eventID string, event *CalendarEvent) (*CalendarEvent, error) {
	req, err := c.newJSONRequest(http.MethodPut, calendarPath+"/"+calendarID+"/events/"+eventID, event)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Event *CalendarEvent
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Event, nil
}

func (c *Client) DeleteCalendarEvent(calendarID, eventID string) error {
	req, err := c.newRequest(http.MethodDelete, calendarPath+"/"+calendarID+"/events/"+eventID, nil)
	if err != nil {
		return err
	}

	var respData resp
	if err := c.doJSON(req, &respData); err != nil {
		return err
	}

	return nil
}
