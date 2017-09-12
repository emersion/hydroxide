package carddav

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/emersion/hydroxide/protonmail"
	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav/carddav"
)

type contextKey string

const ClientContextKey = contextKey("client")

type addressFileInfo struct {
	contact *protonmail.Contact
}

func (fi *addressFileInfo) Name() string {
	return fi.contact.ID + ".vcf"
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
	c *protonmail.Client
	contact *protonmail.Contact
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
	return &addressFileInfo{ao.contact}, nil
}

type addressBook struct {
	c     *protonmail.Client
	cache map[string]*addressObject
	locker sync.Mutex
	total int
}

func (ab *addressBook) Info() (*carddav.AddressBookInfo, error) {
	return &carddav.AddressBookInfo{
		Name: "ProtonMail",
		Description: "ProtonMail contacts",
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
				c: ab.c,
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
					c: ab.c,
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
		c: ab.c,
		contact: contact,
	}
	ab.cacheAddressObject(ao)
	return ao, nil
}

func (ab *addressBook) receiveEvents(events <-chan *protonmail.Event) {
	for event := range events {
		ab.locker.Lock()
		if event.Refresh == 1 {
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
						c: ab.c,
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

func NewHandler(c *protonmail.Client, events <-chan *protonmail.Event) http.Handler {
	ab := &addressBook{
		c: c,
		cache: make(map[string]*addressObject),
		total: -1,
	}

	if events != nil {
		go ab.receiveEvents(events)
	}

	return carddav.NewHandler(ab)
}
