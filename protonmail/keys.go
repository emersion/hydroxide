package protonmail

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/openpgp"
)

type Key struct {
	ID          string
	Version     int
	PublicKey   string
	PrivateKey  string
	Fingerprint string
	Activation  interface{} // TODO
}

type RecipientType int

const (
	RecipientInternal RecipientType = 1
	RecipientExternal               = 2
)

type PublicKeyResp struct {
	RecipientType RecipientType
	MIMEType      string
	Keys          []*PublicKey
}

type PublicKey struct {
	Send      int
	PublicKey string
}

func (pub *PublicKey) Entity() (*openpgp.Entity, error) {
	keyRing, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pub.PublicKey))
	if err != nil {
		return nil, err
	}
	if len(keyRing) == 0 {
		return nil, errors.New("public key is empty")
	}
	return keyRing[0], nil
}

// GetPublicKeys retrieves public keys for a user. The first key in
// PublicKeyResp.Keys can be used for sending.
func (c *Client) GetPublicKeys(email string) (*PublicKeyResp, error) {
	v := url.Values{}
	v.Set("Email", email)
	// TODO: Fingerprint

	req, err := c.newRequest(http.MethodGet, "/keys?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		*PublicKeyResp
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.PublicKeyResp, nil
}
