package protonmail

import (
	"net/http"
)

type (
	LogAuth        int
	ComposerMode   int
	MessageButtons int
	ImagesMode     int
	ViewMode       int
	ViewLayout     int
	SwipeAction    int
)

type User struct {
	ID                 string
	Name               string
	NotificationEmail  string
	Signature          string // HTML
	NumMessagePerPage  int
	UsedSpace          int
	Notify             int
	AutoSaveContacts   int
	Language           string // e.g. en_US
	LogAuth            LogAuth
	ComposerMode       ComposerMode
	MessageButtons     MessageButtons
	Images             ImagesMode
	Moved              int
	ShowImages         int
	ShowEmbedded       int
	ViewMode           ViewMode
	ViewLayout         ViewLayout
	SwipeLeft          SwipeAction
	SwipeRight         SwipeAction
	Theme              string
	Currency           string // e.g. EUR
	Credit             int
	InvoiceText        string
	AlsoArchive        int
	Hotkeys            int
	PMSignature        int
	TwoFactor          int
	PasswordReset      int
	PasswordMode       PasswordMode
	News               int
	AutoResponder      interface{} // TODO
	AutoWildcardSearch int
	DraftMIMEType      string
	ReceiveMIMEType    string
	ImageProxy         int
	DisplayName        string
	MaxSpace           int
	MaxUpload          int
	Subscribed         int // TODO
	Services           int // TODO
	Role               int // TODO
	Private            int
	VPN                interface{} // TODO
	Delinquent         int
	Addresses          []*Address
	Keys               []*PrivateKey
}

func (c *Client) GetCurrentUser() (*User, error) {
	req, err := c.newRequest(http.MethodGet, "/users", nil)
	if err != nil {
		return nil, err
	}

	var userData struct {
		resp
		User *User
	}
	if err := c.doJSON(req, &userData); err != nil {
		return nil, err
	}

	req, err = c.newRequest(http.MethodGet, "/addresses", nil)
	if err != nil {
		return nil, err
	}

	var addrData struct {
		resp
		Addresses []*Address
	}
	if err := c.doJSON(req, &addrData); err != nil {
		return nil, err
	}

	userData.User.Addresses = addrData.Addresses

	return userData.User, nil
}
