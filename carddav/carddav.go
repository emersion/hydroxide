package carddav

import (
	"net/http"
	"strings"

	"github.com/emersion/hydroxide/protonmail"
	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav/carddav"

	"log"
)

type addressObject struct {
	c *protonmail.Client
	contact *protonmail.ContactExport
}

func (ao *addressObject) ID() string {
	return ao.contact.ID
}

func (ao *addressObject) Card() (vcard.Card, error) {
	card := make(vcard.Card)

	for _, c := range ao.contact.Cards {
		if c.Type.Encrypted() {
			// TODO: decrypt
			continue
		}
		if c.Type.Signed() {
			// TODO: check signature
		}

		decoded, err := vcard.NewDecoder(strings.NewReader(c.Data)).Decode()
		if err != nil {
			return nil, err
		}

		for k, fields := range decoded {
			for _, f := range fields {
				card.Add(k, f)
			}
		}
	}

	return card, nil
}

type addressBook struct {
	c *protonmail.Client
}

func (ab *addressBook) ListAddressObjects() ([]carddav.AddressObject, error) {
	// TODO: cache this
	// TODO: paging support
	_, contacts, err := ab.c.ListContactsExport(0, 0)
log.Println(contacts, err)
	if err != nil {
		return nil, err
	}

	aos := make([]carddav.AddressObject, len(contacts))
	for i, contact := range contacts {
		aos[i] = &addressObject{c: ab.c, contact: contact}
	}

	return aos, nil
}

func (ab *addressBook) GetAddressObject(id string) (carddav.AddressObject, error) {
	contact, err := ab.c.GetContact(id)
	if err != nil {
		return nil, err
	}

	return &addressObject{
		c: ab.c,
		contact: &protonmail.ContactExport{
			ID: contact.ID,
			Cards: contact.Cards,
		},
	}, nil
}

func NewHandler(c *protonmail.Client) http.Handler {
	return carddav.NewHandler(&addressBook{c})
}
