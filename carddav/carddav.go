package carddav

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav/carddav"
	"github.com/emersion/hydroxide/protonmail"
	"github.com/keybase/go-crypto/openpgp"
)

type contextKey string

const ClientContextKey = contextKey("client")

var (
	cleartextCardProps = []string{vcard.FieldVersion, vcard.FieldProductID, "X-PM-LABEL", "X-PM-GROUP"}
	signedCardProps    = []string{vcard.FieldVersion, vcard.FieldProductID, vcard.FieldFormattedName, vcard.FieldUID, vcard.FieldEmail}
)

func formatCard(card vcard.Card, privateKey *openpgp.Entity) (*protonmail.ContactImport, error) {
	vcard.ToV4(card)

	// Add groups to emails
	i := 1
	for _, email := range card[vcard.FieldEmail] {
		if email.Group == "" {
			email.Group = "item" + strconv.Itoa(i)
			i++
		}
	}

	toEncrypt := card
	toSign := make(vcard.Card)
	for _, k := range signedCardProps {
		if fields, ok := toEncrypt[k]; ok {
			toSign[k] = fields
			if k != vcard.FieldVersion {
				delete(toEncrypt, k)
			}
		}
	}

	var contactImport protonmail.ContactImport
	var b bytes.Buffer

	if len(toSign) > 0 {
		if err := vcard.NewEncoder(&b).Encode(toSign); err != nil {
			return nil, err
		}
		signed, err := protonmail.NewSignedContactCard(&b, privateKey)
		if err != nil {
			return nil, err
		}
		contactImport.Cards = append(contactImport.Cards, signed)
		b.Reset()
	}

	if len(toEncrypt) > 0 {
		if err := vcard.NewEncoder(&b).Encode(toEncrypt); err != nil {
			return nil, err
		}
		to := []*openpgp.Entity{privateKey}
		encrypted, err := protonmail.NewEncryptedContactCard(&b, to, privateKey)
		if err != nil {
			return nil, err
		}
		contactImport.Cards = append(contactImport.Cards, encrypted)
		b.Reset()
	}

	return &contactImport, nil
}

type addressFileInfo struct {
	contact *protonmail.Contact
}

func (fi *addressFileInfo) Name() string {
	return fi.contact.ID
}

func (fi *addressFileInfo) Size() int64 {
	return int64(fi.contact.Size)
}

func (fi *addressFileInfo) Mode() os.FileMode {
	return os.ModePerm
}

func (fi *addressFileInfo) ModTime() time.Time {
	return time.Unix(fi.contact.ModifyTime, 0)
}

func (fi *addressFileInfo) IsDir() bool {
	return false
}

func (fi *addressFileInfo) Sys() interface{} {
	return nil
}

type addressObject struct {
	ab      *addressBook
	contact *protonmail.Contact
}

func (ao *addressObject) ID() string {
	return ao.contact.ID
}

func (ao *addressObject) Stat() (os.FileInfo, error) {
	return &addressFileInfo{ao.contact}, nil
}

func (ao *addressObject) Card() (vcard.Card, error) {
	card := make(vcard.Card)

	for _, c := range ao.contact.Cards {
		md, err := c.Read(ao.ab.privateKeys)
		if err != nil {
			return nil, err
		}

		decoded, err := vcard.NewDecoder(md.UnverifiedBody).Decode()
		if err != nil {
			return nil, err
		}

		// The signature can be checked only if md.UnverifiedBody is consumed until
		// EOF
		io.Copy(ioutil.Discard, md.UnverifiedBody)
		if err := md.SignatureError; err != nil {
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

func (ao *addressObject) SetCard(card vcard.Card) error {
	contactImport, err := formatCard(card, ao.ab.privateKeys[0])
	if err != nil {
		return err
	}

	contact, err := ao.ab.c.UpdateContact(ao.contact.ID, contactImport)
	if err != nil {
		return err
	}
	contact.Cards = contactImport.Cards // Not returned by the server

	ao.contact = contact
	return nil
}

func (ao *addressObject) Remove() error {
	resps, err := ao.ab.c.DeleteContacts([]string{ao.contact.ID})
	if err != nil {
		return err
	}
	if len(resps) != 1 {
		return errors.New("hydroxide/carddav: expected exactly one response when deleting contact")
	}
	resp := resps[0]
	return resp.Err()
}

type addressBook struct {
	c           *protonmail.Client
	cache       map[string]*addressObject
	locker      sync.Mutex
	total       int
	privateKeys openpgp.EntityList
}

func (ab *addressBook) Info() (*carddav.AddressBookInfo, error) {
	return &carddav.AddressBookInfo{
		Name:            "ProtonMail",
		Description:     "ProtonMail contacts",
		MaxResourceSize: 100 * 1024,
	}, nil
}

func (ab *addressBook) cacheComplete() bool {
	ab.locker.Lock()
	defer ab.locker.Unlock()
	return ab.total >= 0 && len(ab.cache) == ab.total
}

func (ab *addressBook) addressObject(id string) (*addressObject, bool) {
	ab.locker.Lock()
	defer ab.locker.Unlock()
	ao, ok := ab.cache[id]
	return ao, ok
}

func (ab *addressBook) cacheAddressObject(ao *addressObject) {
	ab.locker.Lock()
	defer ab.locker.Unlock()
	ab.cache[ao.contact.ID] = ao
}

func (ab *addressBook) ListAddressObjects() ([]carddav.AddressObject, error) {
	if ab.cacheComplete() {
		ab.locker.Lock()
		defer ab.locker.Unlock()

		aos := make([]carddav.AddressObject, 0, len(ab.cache))
		for _, ao := range ab.cache {
			aos = append(aos, ao)
		}

		return aos, nil
	}

	// Get a list of all contacts
	// TODO: paging support
	total, contacts, err := ab.c.ListContacts(0, 0)
	if err != nil {
		return nil, err
	}
	ab.locker.Lock()
	ab.total = total
	ab.locker.Unlock()

	for _, contact := range contacts {
		if _, ok := ab.addressObject(contact.ID); !ok {
			ab.cacheAddressObject(&addressObject{
				ab:      ab,
				contact: contact,
			})
		}
	}

	// Get all contacts cards
	var aos []carddav.AddressObject
	page := 0
	for {
		_, contacts, err := ab.c.ListContactsExport(page, 0)
		if err != nil {
			return nil, err
		}

		if aos == nil {
			aos = make([]carddav.AddressObject, 0, total)
		}

		for _, contact := range contacts {
			ao, ok := ab.addressObject(contact.ID)
			if !ok {
				ao = &addressObject{
					ab:      ab,
					contact: &protonmail.Contact{ID: contact.ID},
				}
				ab.cacheAddressObject(ao)
			}

			ao.contact.Cards = contact.Cards
			aos = append(aos, ao)
		}

		if len(aos) >= total || len(contacts) == 0 {
			break
		}
		page++
	}

	return aos, nil
}

func (ab *addressBook) GetAddressObject(id string) (carddav.AddressObject, error) {
	if ao, ok := ab.addressObject(id); ok {
		return ao, nil
	} else if ab.cacheComplete() {
		return nil, carddav.ErrNotFound
	}

	contact, err := ab.c.GetContact(id)
	if err != nil {
		// TODO: return carddav.ErrNotFound if appropriate
		return nil, err
	}

	ao := &addressObject{
		ab:      ab,
		contact: contact,
	}
	ab.cacheAddressObject(ao)
	return ao, nil
}

func (ab *addressBook) CreateAddressObject(card vcard.Card) (carddav.AddressObject, error) {
	contactImport, err := formatCard(card, ab.privateKeys[0])
	if err != nil {
		return nil, err
	}

	resps, err := ab.c.CreateContacts([]*protonmail.ContactImport{contactImport})
	if err != nil {
		return nil, err
	}
	if len(resps) != 1 {
		return nil, errors.New("hydroxide/carddav: expected exactly one response when creating contact")
	}
	resp := resps[0]
	if err := resp.Err(); err != nil {
		return nil, err
	}
	contact := resp.Response.Contact
	contact.Cards = contactImport.Cards // Not returned by the server

	ao := &addressObject{
		ab:      ab,
		contact: contact,
	}
	ab.cacheAddressObject(ao)
	return ao, nil
}

func (ab *addressBook) receiveEvents(events <-chan *protonmail.Event) {
	for event := range events {
		ab.locker.Lock()
		if event.Refresh&protonmail.EventRefreshContacts != 0 {
			ab.cache = make(map[string]*addressObject)
			ab.total = -1
		} else if len(event.Contacts) > 0 {
			for _, eventContact := range event.Contacts {
				switch eventContact.Action {
				case protonmail.EventCreate:
					ab.total++
					fallthrough
				case protonmail.EventUpdate:
					ab.cache[eventContact.ID] = &addressObject{
						ab:      ab,
						contact: eventContact.Contact,
					}
				case protonmail.EventDelete:
					delete(ab.cache, eventContact.ID)
					ab.total--
				}
			}
		}
		ab.locker.Unlock()
	}
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, events <-chan *protonmail.Event) http.Handler {
	if len(privateKeys) == 0 {
		panic("hydroxide/carddav: no private key available")
	}

	ab := &addressBook{
		c:           c,
		cache:       make(map[string]*addressObject),
		total:       -1,
		privateKeys: privateKeys,
	}

	if events != nil {
		go ab.receiveEvents(events)
	}

	return carddav.NewHandler(ab)
}
