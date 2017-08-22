package protonmail

import (
	"net/http"
)

type Contact struct {
	ID       string
	Name     string
	LabelIDs []string

	Emails []*ContactEmail
	Data   []*ContactData
}

type ContactEmail struct {
	ID        string
	Name      string
	Email     string
	Type      string
	Encrypt   int
	Order     int
	ContactID string
	LabelIDs  []string
}

type ContactDataType int

const (
	ContactDataEncrypted ContactDataType = 1
)

type ContactData struct {
	Type ContactDataType
	Data string
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

func (c *Client) ListContactsEmails() ([]*ContactEmail, error) {
	req, err := c.newRequest(http.MethodGet, "/contacts/emails", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Contacts []*ContactEmail
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Contacts, nil
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
