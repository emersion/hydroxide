package protonmail

import (
	"encoding/json"
	"net/http"
)

type EventRefresh int

const (
	EventRefreshMail EventRefresh = 1 << iota
	EventRefreshContacts
)

type Event struct {
	ID       string `json:"EventID"`
	Refresh  EventRefresh
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
	ID     string
	Action EventAction

	// Only populated for EventCreate
	Created *Message
	// Only populated for EventUpdate or EventUpdateFlags
	Updated *EventMessageUpdate
}

type EventMessageUpdate struct {
	Unread       *int
	Type         *MessageType
	Time         Timestamp
	IsReplied    *int
	IsRepliedAll *int
	IsForwarded  *int

	// Only populated for EventUpdateFlags
	LabelIDs        []string
	LabelIDsAdded   []string
	LabelIDsRemoved []string
}

func buildLabelsSet(labelIDs []string) map[string]struct{} {
	set := make(map[string]struct{}, len(labelIDs))
	for _, labelID := range labelIDs {
		set[labelID] = struct{}{}
	}
	return set
}

func (update *EventMessageUpdate) DiffLabelIDs(current []string) (added, removed []string) {
	if update.LabelIDsAdded != nil && update.LabelIDsRemoved != nil {
		return update.LabelIDsAdded, update.LabelIDsRemoved
	}
	if update.LabelIDs == nil {
		return
	}

	currentSet := buildLabelsSet(current)
	updateSet := buildLabelsSet(update.LabelIDs)
	for labelID := range currentSet {
		if _, ok := updateSet[labelID]; !ok {
			removed = append(removed, labelID)
		}
	}
	for labelID := range updateSet {
		if _, ok := currentSet[labelID]; !ok {
			added = append(added, labelID)
		}
	}
	return
}

func (update *EventMessageUpdate) Patch(msg *Message) {
	msg.Time = update.Time
	if update.Unread != nil {
		msg.Unread = *update.Unread
	}
	if update.Type != nil {
		msg.Type = *update.Type
	}
	if update.IsReplied != nil {
		msg.IsReplied = *update.IsReplied
	}
	if update.IsRepliedAll != nil {
		msg.IsRepliedAll = *update.IsRepliedAll
	}
	if update.IsForwarded != nil {
		msg.IsForwarded = *update.IsForwarded
	}

	if update.LabelIDs != nil {
		msg.LabelIDs = update.LabelIDs
	} else if update.LabelIDsAdded != nil && update.LabelIDsRemoved != nil {
		set := buildLabelsSet(msg.LabelIDs)
		for _, labelID := range update.LabelIDsAdded {
			set[labelID] = struct{}{}
		}
		for _, labelID := range update.LabelIDsRemoved {
			delete(set, labelID)
		}
		msg.LabelIDs = make([]string, 0, len(set))
		for labelID := range set {
			msg.LabelIDs = append(msg.LabelIDs, labelID)
		}
	}
}

type rawEventMessage struct {
	ID      string
	Action  EventAction
	Message json.RawMessage `json:",omitempty"`
}

func (em *EventMessage) UnmarshalJSON(b []byte) error {
	var raw rawEventMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	em.ID = raw.ID
	em.Action = raw.Action
	switch raw.Action {
	case EventCreate:
		em.Created = new(Message)
		return json.Unmarshal(raw.Message, em.Created)
	case EventUpdate, EventUpdateFlags:
		em.Updated = new(EventMessageUpdate)
		return json.Unmarshal(raw.Message, em.Updated)
	}
	return nil
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
