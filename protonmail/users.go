package protonmail

import (
	"net/http"
)

type User struct {
	ID         string
	Name       string
	UsedSpace  int
	Currency   string // e.g. EUR
	Credit     int
	MaxSpace   int
	MaxUpload  int
	Role       int // TODO
	Private    int
	Subscribed int // TODO
	Services   int // TODO
	Delinquent int
	Keys       []*PrivateKey
}

func (c *Client) GetCurrentUser() (*User, error) {
	req, err := c.newRequest(http.MethodGet, "/users", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		User *User
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.User, nil
}
