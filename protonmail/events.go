package protonmail

import (
	"net/http"
)

type Event struct {
	ID string `json:"EventID"`
	Refresh int
	//Messages
	Contacts []*EventContact
	//ContactEmails
	//Labels
	//User
	//Members
	//Domains
	//Organization
	//MessageCounts
	//ConversationCounts
	//UsedSpace
	Notices []string
}

type EventAction int

const (
	EventDelete EventAction = iota
	EventCreate
	EventUpdate
)

type EventContact struct {
	ID string
	Action EventAction
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
