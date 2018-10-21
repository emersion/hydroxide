package protonmail

import (
	"net/http"
)

type (
	AddressSend   int
	AddressStatus int
	AddressType   int
)

const (
	AddressSendDisabled AddressSend = iota
	AddressSendPrimary
	AddressSendSecondary
)

const (
	AddressDisabled AddressStatus = iota
	AddressEnabled
)

const (
	AddressOriginal AddressType = iota
	AddressAlias
	AddressCustom
)

type Address struct {
	ID          string
	DomainID    string
	Email       string
	Send        AddressSend
	Receive     int
	Status      AddressStatus
	Type        AddressType
	Order       int
	DisplayName string
	Signature   string // HTML
	HasKeys     int
	Keys        []*PrivateKey
}

func (c *Client) ListAddresses() ([]*Address, error) {
	// TODO: Page, PageSize
	req, err := c.newRequest(http.MethodGet, "/addresses", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Addresses []*Address
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Addresses, nil
}
