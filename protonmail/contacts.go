package protonmail

import (
	"net/http"
)

type Contact struct {
	ID string
	Name string
	LabelIDs []string

	Emails []*ContactEmail
	Data []*ContactData
}

type ContactEmail struct {
	ID string
	Name string
	Email string
	Type string
	Encrypt int
	Order int
	ContactID string
	LabelIDs []string
}

type ContactDataType int

type ContactData struct {
	Type ContactDataType
	Data string
}

type contactsResp struct {
	resp
	Contacts []*Contact
}

func (c *Client) Contacts() ([]*Contact, error) {
	req, err := c.newRequest(http.MethodGet, "/contacts", nil)
	if err != nil {
		return nil, err
	}

	var respData contactsResp
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Contacts, nil
}
