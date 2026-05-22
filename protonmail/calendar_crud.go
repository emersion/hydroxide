package protonmail

import (
	"net/http"
	"net/url"
	"strconv"
)

// CalendarEventFilter is removed from here because it is already 
// declared in the existing internal protonmail/calendar.go file.

func (c *Client) GetCalendar(id string) (*Calendar, error) {
	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Calendar *Calendar
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Calendar, nil
}

func (c *Client) GetCalendarEvent(calendarID, eventID string) (*CalendarEvent, error) {
	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+calendarID+"/events/"+eventID, nil)
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

type CalendarEventExport struct {
	ID    string
	Event *CalendarEvent
	Cards []*CalendarEventCard
}

func (c *Client) ListCalendarEventsExport(calendarID string, filter *CalendarEventFilter) (total int, events []*CalendarEventExport, err error) {
	v := url.Values{}
    v.Set("Start", strconv.FormatInt(int64(filter.Start), 10))
    v.Set("End", strconv.FormatInt(int64(filter.End), 10))
	if filter.Timezone != "" {
		v.Set("Timezone", filter.Timezone)
	}
	if filter.Page > 0 {
		v.Set("Page", strconv.Itoa(filter.Page))
	}
	if filter.PageSize > 0 {
		v.Set("PageSize", strconv.Itoa(filter.PageSize))
	}

	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+calendarID+"/events/export?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		Events []*CalendarEventExport
		Total  int
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.Events, nil
}

type CalendarEventImport struct {
	Cards []*CalendarEventCard
}

func (c *Client) CreateCalendarEvent(calendarID string, event *CalendarEventImport) (*CalendarEvent, error) {
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

func (c *Client) UpdateCalendarEvent(calendarID, eventID string, event *CalendarEventImport) (*CalendarEvent, error) {
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

	return c.doJSON(req, nil)
}