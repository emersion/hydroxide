package protonmail

import (
	"net/http"
)

type MessageType int

const (
	MessageInbox MessageType = iota
	MessageDraft
	MessageSent
	MessageInboxAndSent
)

type MessageEncryption int

type MessageAddress struct {
	Address string
	Name    string
}

type Message struct {
	ID             string
	Order          int64
	Subject        string
	IsRead         int
	Type           MessageType
	Sender         *MessageAddress
	ReplyTo        *MessageAddress
	ToList         []*MessageAddress
	Time           int64
	Size           int64
	IsEncrypted    MessageEncryption
	ExpirationTime int64
	IsReplied      int
	IsRepliedAll   int
	IsForwarded    int
	SpamScore      int
	AddressID      string
	Body           string
	MIMEType       string
	CCList         []*MessageAddress
	BCCList        []*MessageAddress
	Header         string
	Attachments    []*Attachment
	LabelIDs       []string
	ExternalID     string
}

func (c *Client) GetMessage(id string) (*Message, error) {
	req, err := c.newRequest(http.MethodGet, "/messages/"+id, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Message *Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Message, nil
}

func (c *Client) CreateDraftMessage(msg *Message, parentID string) (*Message, error) {
	reqData := struct {
		Message  *Message
		ParentID string `json:",omitempty"`
		Action   *int   `json:",omitempty"`
	}{msg, parentID, nil}
	req, err := c.newJSONRequest(http.MethodPost, "/messages", &reqData)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Message *Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Message, nil
}

func (c *Client) UpdateDraftMessage(msg *Message) (*Message, error) {
	reqData := struct {
		Message *Message
	}{msg}
	req, err := c.newJSONRequest(http.MethodPut, "/messages/"+msg.ID, &reqData)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Message *Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Message, nil
}

type MessageKeyPacket struct {
	ID         string
	KeyPackets string
}

type MessagePackageType int

type MessagePackage struct {
	Address    string
	Type       MessagePackageType
	Body       string
	KeyPackets []*MessageKeyPacket

	Token        string
	EncToken     string
	PasswordHint string `json:",omitempty"`
}

type MessageOutgoing struct {
	ID string

	ClearBody      string
	ExpirationTime int64
	AttachmentKeys []*AttachmentKey
	Packages       []*MessagePackage
}

func (c *Client) SendMessage(msg *MessageOutgoing) (sent, parent *Message, err error) {
	req, err := c.newJSONRequest(http.MethodPut, "/messages/"+msg.ID, msg)
	if err != nil {
		return nil, nil, err
	}

	var respData struct {
		resp
		Sent, Parent *Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, nil, err
	}

	return respData.Sent, respData.Parent, nil
}
