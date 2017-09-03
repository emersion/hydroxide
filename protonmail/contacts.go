package protonmail

import (
	"net/http"
	"net/url"
	"strconv"
)

type Contact struct {
	ID       string
	Name     string
	UID      string
	Size     int
	CreateTime int
	ModifyTime int
	LabelIDs []string

	// Not when using ListContacts
	ContactEmails []*ContactEmail
	Cards         []*ContactCard
}

type ContactEmailDefaults int

type ContactEmail struct {
	ID        string
	Email     string
	Type      []string
	Defaults  ContactEmailDefaults
	Order     int
	ContactID string
	LabelIDs  []string

	// Only when using ListContactsEmails
	Name string
}

type ContactCardType int

const (
	ContactCardCleartext ContactCardType = iota
	ContactCardEncrypted
	ContactCardSigned
	ContactCardEncryptedAndSigned
)

func (t ContactCardType) Signed() bool {
	switch t {
	case ContactCardSigned, ContactCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

func (t ContactCardType) Encrypted() bool {
	switch t {
	case ContactCardEncrypted, ContactCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

type ContactCard struct {
	Type      ContactCardType
	Data      string
	Signature string
}

type ContactExport struct {
	ID    string
	Cards []*ContactCard
}

func (c *Client) ListContacts() ([]*Contact, error) {
	req, err := c.newRequest(http.MethodGet, "/contacts", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Contacts []*Contact
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Contacts, nil
}

func (c *Client) ListContactsEmails(page, pageSize int) (total int, emails []*ContactEmail, err error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, "/contacts/emails?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		ContactEmails []*ContactEmail
		Total         int
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.ContactEmails, nil
}

func (c *Client) ListContactsExport(page, pageSize int) (total int, contacts []*ContactExport, err error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, "/contacts/export?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		Contacts []*ContactExport
		Total    int
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.Contacts, nil
}

func (c *Client) GetContact(id string) (*Contact, error) {
	req, err := c.newRequest(http.MethodGet, "/contacts/"+id, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Contact *Contact
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Contact, nil
}

type CreateContactResp struct {
	Input    *Contact
	Response struct {
		resp
		Contact *Contact
	}
}

func (c *Client) CreateContacts(contacts []*Contact) ([]*CreateContactResp, error) {
	reqData := struct {
		Contacts []*Contact
	}{contacts}

	req, err := c.newJSONRequest(http.MethodPost, "/contacts", &reqData)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Responses []*CreateContactResp
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Responses, nil
}
