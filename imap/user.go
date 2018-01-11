package imap

import (
	"log"
	"sync"

	"golang.org/x/crypto/openpgp"
	"github.com/emersion/go-imap"
	imapbackend "github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap-specialuse"

	"github.com/emersion/hydroxide/imap/database"
	"github.com/emersion/hydroxide/protonmail"
)

var systemMailboxes = []struct{
	name string
	label string
	flags []string
}{
	{imap.InboxName, protonmail.LabelInbox, nil},
	{"All Mail", protonmail.LabelAllMail, []string{specialuse.All}},
	{"Archive", protonmail.LabelArchive, []string{specialuse.Archive}},
	{"Drafts", protonmail.LabelDraft, []string{specialuse.Drafts}},
	{"Starred", protonmail.LabelStarred, []string{specialuse.Flagged}},
	{"Spam", protonmail.LabelSpam, []string{specialuse.Junk}},
	{"Sent", protonmail.LabelSent, []string{specialuse.Sent}},
	{"Trash", protonmail.LabelTrash, []string{specialuse.Trash}},
}

type user struct {
	c           *protonmail.Client
	u           *protonmail.User
	privateKeys openpgp.EntityList

	db *database.User

	locker sync.Mutex
	mailboxes map[string]*mailbox
}

func newUser(c *protonmail.Client, u *protonmail.User, privateKeys openpgp.EntityList) (*user, error) {
	uu := &user{
		c: c,
		u: u,
		privateKeys: privateKeys,
	}

	db, err := database.Open(u.Name+".db")
	if err != nil {
		return nil, err
	}
	uu.db = db

	if err := uu.initMailboxes(); err != nil {
		return nil, err
	}

	// TODO: go uu.receiveEvents(events)

	return uu, nil
}

func (u *user) initMailboxes() error {
	u.locker.Lock()
	defer u.locker.Unlock()

	u.mailboxes = make(map[string]*mailbox)

	for _, data := range systemMailboxes {
		mboxDB, err := u.db.Mailbox(data.label)
		if err != nil {
			return err
		}

		u.mailboxes[data.label] = &mailbox{
			name: data.name,
			label: data.label,
			flags: data.flags,
			u: u,
			db: mboxDB,
		}
	}

	counts, err := u.c.CountMessages("")
	if err != nil {
		return err
	}

	for _, count := range counts {
		if mbox, ok := u.mailboxes[count.LabelID]; ok {
			mbox.total = count.Total
			mbox.unread = count.Unread
		}
	}

	return nil
}

func (u *user) Username() string {
	return u.u.Name
}

func (u *user) ListMailboxes(subscribed bool) ([]imapbackend.Mailbox, error) {
	u.locker.Lock()
	defer u.locker.Unlock()

	list := make([]imapbackend.Mailbox, 0, len(u.mailboxes))
	for _, mbox := range u.mailboxes {
		list = append(list, mbox)
	}
	return list, nil
}

func (u *user) GetMailbox(name string) (imapbackend.Mailbox, error) {
	u.locker.Lock()
	defer u.locker.Unlock()

	for _, mbox := range u.mailboxes {
		if mbox.name == name {
			return mbox, nil
		}
	}
	return nil, imapbackend.ErrNoSuchMailbox
}

func (u *user) CreateMailbox(name string) error {
	return errNotYetImplemented // TODO
}

func (u *user) DeleteMailbox(name string) error {
	return errNotYetImplemented // TODO
}

func (u *user) RenameMailbox(existingName, newName string) error {
	return errNotYetImplemented // TODO
}

func (u *user) Logout() error {
	if err := u.db.Close(); err != nil {
		return err
	}

	u.c = nil
	u.u = nil
	u.privateKeys = nil
	return nil
}

func (u *user) receiveEvents(events <-chan *protonmail.Event) {
	for event := range events {
		if event.Refresh&protonmail.EventRefreshMail != 0 {
			log.Println("Reinitializing the whole IMAP database")

			u.locker.Lock()
			for _, mbox := range u.mailboxes {
				if err := mbox.reset(); err != nil {
					log.Printf("cannot reset mailbox %s: %v", mbox.name, err)
				}
			}
			u.locker.Unlock()

			if err := u.db.ResetMessages(); err != nil {
				log.Printf("cannot reset user: %v", err)
			}

			if err := u.initMailboxes(); err != nil {
				log.Printf("cannot reinitialize mailboxes: %v", err)
			}
		} else {
			for _, eventMessage := range event.Messages {
				switch eventMessage.Action {
				case protonmail.EventCreate:
					if err := u.db.CreateMessage(eventMessage.Created); err != nil {
						log.Printf("cannot handle create event for message %s: cannot create message in local DB: %v", eventMessage.ID, err)
						break
					}

					// TODO: send updates
				case protonmail.EventUpdate:
					// No-op
				case protonmail.EventUpdateFlags:
					if err := u.db.UpdateMessage(eventMessage.Updated); err != nil {
						log.Printf("cannot handle update event for message %s: cannot update message in local DB: %v", eventMessage.ID, err)
						break
					}

					// TODO: send updates
				case protonmail.EventDelete:
					if err := u.db.DeleteMessage(eventMessage.ID); err != nil {
						log.Printf("cannot handle delete event for message %s: cannot delete message from local DB: %v", eventMessage.ID, err)
						break
					}

					// TODO: send updates
				}
			}

			u.locker.Lock()
			for _, count := range event.MessageCounts {
				if mbox, ok := u.mailboxes[count.LabelID]; ok {
					mbox.total = count.Total
					mbox.unread = count.Unread
				}
			}
			u.locker.Unlock()
		}
	}
}
