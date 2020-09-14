package protonmail

import (
	"net/http"
	"net/url"
)

type Conversation struct {
	ID             string
	Order          int64
	Subject        string
	Senders        []*MessageAddress
	Recipients     []*MessageAddress
	NumMessages    int
	NumUnread      int
	NumAttachments int
	ExpirationTime Timestamp
	TotalSize      int64
	AddressID      string
	LabelIDs       []string
}

func (c *Client) GetConversation(id, msgID string) (*Conversation, []*Message, error) {
	v := url.Values{}
	if msgID != "" {
		v.Set("MessageID", msgID)
	}

	req, err := c.newRequest(http.MethodGet, "/conversations/"+id+"?"+v.Encode(), nil)
	if err != nil {
		return nil, nil, err
	}

	var respData struct {
		resp
		Conversation *Conversation
		Messages     []*Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, nil, err
	}

	return respData.Conversation, respData.Messages, nil
}
