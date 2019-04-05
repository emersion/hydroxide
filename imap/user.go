package imap

import (
	"log"
	"sync"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap-specialuse"
	imapbackend "github.com/emersion/go-imap/backend"
	"github.com/keybase/go-crypto/openpgp"

	"github.com/emersion/hydroxide/events"
	"github.com/emersion/hydroxide/imap/database"
	"github.com/emersion/hydroxide/protonmail"
)

var systemMailboxes = []struct {
	name  string
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
	addrs       []*protonmail.Address

	db             *database.User
	eventsReceiver *events.Receiver

	locker    sync.Mutex
	mailboxes map[string]*mailbox

	done      chan<- struct{}
	eventSent chan struct{}
}

func newUser(be *backend, c *protonmail.Client, u *protonmail.User, privateKeys openpgp.EntityList, addrs []*protonmail.Address) (*user, error) {
	uu := &user{
		c:           c,
		u:           u,
		privateKeys: privateKeys,
		addrs:       addrs,
		eventSent:   make(chan struct{}),
	}

	db, err := database.Open(u.Name + ".db")
	if err != nil {
		return nil, err
	}
	uu.db = db

	if err := uu.initMailboxes(); err != nil {
		return nil, err
	}

	done := make(chan struct{})
	uu.done = done
	ch := make(chan *protonmail.Event)
	go uu.receiveEvents(be.updates, ch)
	uu.eventsReceiver = be.eventsManager.Register(c, u.Name, ch, done)

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
			name:    data.name,
			label:   data.label,
			flags:   data.flags,
			u:       u,
			db:      mboxDB,
			deleted: make(map[string]struct{}),
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

func (u *user) getMailboxByLabel(labelID string) *mailbox {
	u.locker.Lock()
	defer u.locker.Unlock()
	return u.mailboxes[labelID]
}

func (u *user) getMailbox(name string) *mailbox {
	u.locker.Lock()
	defer u.locker.Unlock()

	for _, mbox := range u.mailboxes {
		if mbox.name == name {
			return mbox
		}
	}
	return nil
}

func (u *user) GetMailbox(name string) (imapbackend.Mailbox, error) {
	mbox := u.getMailbox(name)
	if mbox == nil {
		return nil, imapbackend.ErrNoSuchMailbox
	}
	return mbox, nil
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
	close(u.done)

	if err := u.db.Close(); err != nil {
		return err
	}

	u.c = nil
	u.u = nil
	u.privateKeys = nil
	return nil
}

func (u *user) poll() {
	go u.eventsReceiver.Poll()
	<-u.eventSent
}

func (u *user) receiveEvents(updates chan<- imapbackend.Update, events <-chan *protonmail.Event) {
	for event := range events {
		var eventUpdates []imapbackend.Update

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
					log.Println("Received create event for message", eventMessage.ID)
					seqNums, err := u.db.CreateMessage(eventMessage.Created)
					if err != nil {
						log.Printf("cannot handle create event for message %s: cannot create message in local DB: %v", eventMessage.ID, err)
						break
					}

					// TODO: what if the message was already in the local DB?
					for labelID, seqNum := range seqNums {
						if mbox := u.getMailboxByLabel(labelID); mbox != nil {
							update := new(imapbackend.MailboxUpdate)
							update.Update = imapbackend.NewUpdate(u.u.Name, mbox.name)
							update.MailboxStatus = imap.NewMailboxStatus(mbox.name, []imap.StatusItem{imap.StatusMessages})
							update.MailboxStatus.Messages = seqNum
							eventUpdates = append(eventUpdates, update)
						}
					}
				case protonmail.EventUpdate, protonmail.EventUpdateFlags:
					log.Println("Received update event for message", eventMessage.ID)
					createdSeqNums, deletedSeqNums, err := u.db.UpdateMessage(eventMessage.ID, eventMessage.Updated)
					if err != nil {
						log.Printf("cannot handle update event for message %s: cannot update message in local DB: %v", eventMessage.ID, err)
						break
					}

					for labelID, seqNum := range createdSeqNums {
						if mbox := u.getMailboxByLabel(labelID); mbox != nil {
							update := new(imapbackend.MailboxUpdate)
							update.Update = imapbackend.NewUpdate(u.u.Name, mbox.name)
							update.MailboxStatus = imap.NewMailboxStatus(mbox.name, []imap.StatusItem{imap.StatusMessages})
							update.MailboxStatus.Messages = seqNum
							eventUpdates = append(eventUpdates, update)
						}
					}
					for labelID, seqNum := range deletedSeqNums {
						if mbox := u.getMailboxByLabel(labelID); mbox != nil {
							update := new(imapbackend.ExpungeUpdate)
							update.Update = imapbackend.NewUpdate(u.u.Name, mbox.name)
							update.SeqNum = seqNum
							eventUpdates = append(eventUpdates, update)
						}
					}

					// Send message updates
					msg, err := u.db.Message(eventMessage.ID)
					if err != nil {
						log.Printf("cannot handle update event for message %s: cannot get updated message from local DB: %v", eventMessage.ID, err)
						break
					}
					for _, labelID := range msg.LabelIDs {
						if _, created := createdSeqNums[labelID]; created {
							// This message has been added to the label's mailbox
							// No need to send a message update
							continue
						}

						if mbox := u.getMailboxByLabel(labelID); mbox != nil {
							seqNum, _, err := mbox.db.FromApiID(eventMessage.ID)
							if err != nil {
								log.Printf("cannot handle update event for message %s: cannot get message sequence number in %s: %v", eventMessage.ID, mbox.name, err)
								continue
							}

							update := new(imapbackend.MessageUpdate)
							update.Update = imapbackend.NewUpdate(u.u.Name, mbox.name)
							update.Message = imap.NewMessage(seqNum, []imap.FetchItem{imap.FetchFlags})
							update.Message.Flags = fetchFlags(msg)
							eventUpdates = append(eventUpdates, update)
						}
					}
				case protonmail.EventDelete:
					log.Println("Received delete event for message", eventMessage.ID)
					seqNums, err := u.db.DeleteMessage(eventMessage.ID)
					if err != nil {
						log.Printf("cannot handle delete event for message %s: cannot delete message from local DB: %v", eventMessage.ID, err)
						break
					}

					for labelID, seqNum := range seqNums {
						if mbox := u.getMailboxByLabel(labelID); mbox != nil {
							update := new(imapbackend.ExpungeUpdate)
							update.Update = imapbackend.NewUpdate(u.u.Name, mbox.name)
							update.SeqNum = seqNum
							eventUpdates = append(eventUpdates, update)
						}
					}
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

		for _, update := range eventUpdates {
			updates <- update
		}
		go func() {
			for _, update := range eventUpdates {
				<-update.Done()
			}

			select {
			case u.eventSent <- struct{}{}:
			default:
			}
		}()
	}
}
