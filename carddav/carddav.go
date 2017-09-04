package carddav

import (
	"net/http"
	"os"
	"strings"

	"github.com/emersion/hydroxide/protonmail"
	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav/carddav"
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

func (ao *addressObject) Stat() (os.FileInfo, error) {
	return nil, nil
}

type addressBook struct {
	c     *protonmail.Client
	cache map[string]carddav.AddressObject
	total int
}

func (ab *addressBook) cacheComplete() bool {
	return ab.total >= 0 && len(ab.cache) == ab.total
}

func (ab *addressBook) ListAddressObjects() ([]carddav.AddressObject, error) {
	if ab.cacheComplete() {
		aos := make([]carddav.AddressObject, 0, len(ab.cache))
		for _, ao := range ab.cache {
			aos = append(aos, ao)
		}
		return aos, nil
	}

	var aos []carddav.AddressObject
	page := 0
	for {
		total, contacts, err := ab.c.ListContactsExport(page, 0)
		if err != nil {
			return nil, err
		}
		ab.total = total

		if aos == nil {
			aos = make([]carddav.AddressObject, 0, total)
		}

		for _, contact := range contacts {
			ao := &addressObject{c: ab.c, contact: contact}
			ab.cache[contact.ID] = ao
			aos = append(aos, ao)
		}

		if len(aos) == total || len(contacts) == 0 {
			break
		}
		page++
	}

	return aos, nil
}

func (ab *addressBook) GetAddressObject(id string) (carddav.AddressObject, error) {
	if ao, ok := ab.cache[id]; ok {
		return ao, nil
	} else if ab.cacheComplete() {
		return nil, carddav.ErrNotFound
	}

	contact, err := ab.c.GetContact(id)
	if err != nil {
		return nil, err
	}

	ao := &addressObject{
		c: ab.c,
		contact: &protonmail.ContactExport{
			ID: contact.ID,
			Cards: contact.Cards,
		},
	}
	ab.cache[id] = ao
	return ao, nil
}

func NewHandler(c *protonmail.Client) http.Handler {
	return carddav.NewHandler(&addressBook{
		c: c,
		cache: make(map[string]carddav.AddressObject),
		total: -1,
	})
}
