package protonmail

import (
	"net/http"
)

type EventRefresh int

const (
	EventRefreshMail EventRefresh = 1 << iota
	EventRefreshContacts
)

type Event struct {
	ID      string `json:"EventID"`
	Refresh EventRefresh
	Messages []*EventMessage
	Contacts []*EventContact
	//ContactEmails
	//Labels
	//User
	//Members
	//Domains
	//Organization
	MessageCounts []*MessageCount
	//ConversationCounts
	//UsedSpace
	Notices []string
}

type EventAction int

const (
	EventDelete EventAction = iota
	EventCreate
	EventUpdate

	// For messages
	EventUpdateFlags
)

type EventMessage struct {
	ID      string
	Action  EventAction
	Message *Message
}

type EventContact struct {
	ID      string
	Action  EventAction
	Contact *Contact
}

func (c *Client) GetEvent(last string) (*Event, error) {
	if last == "" {
		last = "latest"
	}

	req, err := c.newRequest(http.MethodGet, "/events/"+last, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		*Event
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Event, nil
}
