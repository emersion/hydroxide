package imap

import (
	"log"
	"strings"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-imap"
	imapbackend "github.com/emersion/go-imap/backend"
	"github.com/emersion/hydroxide/events"
	"github.com/emersion/hydroxide/imap/database"
	"github.com/emersion/hydroxide/protonmail"
)

var systemMailboxes = []struct {
	name  string
	label string
	attrs []string
}{
	{imap.InboxName, protonmail.LabelInbox, nil},
	{"All Mail", protonmail.LabelAllMail, []string{imap.AllAttr}},
	{"Archive", protonmail.LabelArchive, []string{imap.ArchiveAttr}},
	{"Drafts", protonmail.LabelDraft, []string{imap.DraftsAttr}},
	{"Starred", protonmail.LabelStarred, []string{imap.FlaggedAttr}},
	{"Spam", protonmail.LabelSpam, []string{imap.JunkAttr}},
	{"Sent", protonmail.LabelSent, []string{imap.SentAttr}},
	{"Trash", protonmail.LabelTrash, []string{imap.TrashAttr}},
}

var systemFlags = []struct {
	name  string
	label string
}{
	{imap.FlaggedFlag, protonmail.LabelStarred},
	{imap.DraftFlag, protonmail.LabelDraft},
}

type user struct {
	username    string
	backend     *backend
	c           *protonmail.Client
	u           *protonmail.User
	privateKeys openpgp.EntityList
	addrs       []*protonmail.Address

	db             *database.User
	eventsReceiver *events.Receiver

	done      chan<- struct{}
	eventSent chan struct{}

	sync.Mutex // protects everything below

	numClients int
	mailboxes  map[string]*mailbox // indexed by label ID
	flags      map[string]string   // indexed by label ID
}

func getUser(be *backend, username string, c *protonmail.Client, privateKeys openpgp.EntityList) (*user, error) {
	// TODO: logging a user in may take some time, find a way not to lock all
	// other logins during this time
	be.Lock()
	defer be.Unlock()

	if u, ok := be.users[username]; ok {
		u.Lock()
		u.numClients++
		u.Unlock()
		return u, nil
	} else {
		u, err := newUser(be, username, c, privateKeys)
		if err != nil {
			return nil, err
		}

		be.users[username] = u
		return u, nil
	}
}

func newUser(be *backend, username string, c *protonmail.Client, privateKeys openpgp.EntityList) (*user, error) {
	u, err := c.GetCurrentUser()
	if err != nil {
		return nil, err
	}

	addrs, err := c.ListAddresses()
	if err != nil {
		return nil, err
	}

	uu := &user{
		username:    username,
		backend:     be,
		c:           c,
		u:           u,
		privateKeys: privateKeys,
		addrs:       addrs,
		eventSent:   make(chan struct{}),
		numClients:  1,
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

	log.Printf("User %q logged in via IMAP", u.Name)
	return uu, nil
}

func labelNameToFlag(s string) string {
	var sb strings.Builder
	var lastValid bool
	for _, r := range s {
		// See atom-specials in RFC 3501
		var valid bool
		switch r {
		case '(', ')', '{':
		case ' ', '\t': // SP
		case '%', '*': // list-wildcards
		case '"', '\\': // quoted-specials
		case ']': // resp-specials
		default:
			valid = r <= '~' && r > 31
		}
		if !valid {
			if !lastValid {
				continue
			}
			r = '_'
		}
		sb.WriteRune(r)
		lastValid = valid
	}
	return sb.String()
}

func (u *user) initMailboxes() error {
	u.Lock()
	defer u.Unlock()

	u.mailboxes = make(map[string]*mailbox)
	for _, data := range systemMailboxes {
		var err error
		u.mailboxes[data.label], err = newMailbox(data.name, data.label, data.attrs, u)
		if err != nil {
			return err
		}
	}

	u.flags = make(map[string]string)
	for _, data := range systemFlags {
		u.flags[data.label] = data.name
	}

	labels, err := u.c.ListLabels()
	if err != nil {
		return err
	}

	for _, label := range labels {
		if label.Exclusive == 1 {
			if _, ok := u.mailboxes[label.ID]; ok {
				continue
			}

			u.mailboxes[label.ID], err = newMailbox(label.Name, label.ID, nil, u)
			if err != nil {
				return err
			}
		} else {
			if _, ok := u.flags[label.ID]; ok {
				continue
			}

			u.flags[label.ID] = labelNameToFlag(label.Name)
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
	u.Lock()
	defer u.Unlock()

	list := make([]imapbackend.Mailbox, 0, len(u.mailboxes))
	for _, mbox := range u.mailboxes {
		list = append(list, mbox)
	}
	return list, nil
}

func (u *user) getMailboxByLabel(labelID string) *mailbox {
	u.Lock()
	defer u.Unlock()
	return u.mailboxes[labelID]
}

func (u *user) getMailbox(name string) *mailbox {
	u.Lock()
	defer u.Unlock()

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

func (u *user) getFlag(name string) string {
	u.Lock()
	defer u.Unlock()

	for label, flag := range u.flags {
		if flag == name {
			return label
		}
	}
	return ""
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
	u.backend.Lock()
	defer u.backend.Unlock()
	u.Lock()
	defer u.Unlock()

	if u.numClients <= 0 {
		panic("unreachable")
	}
	u.numClients--
	if u.numClients > 0 {
		return nil
	}

	delete(u.backend.users, u.username)

	close(u.done)

	if err := u.db.Close(); err != nil {
		return err
	}

	log.Printf("User %q logged out via IMAP", u.u.Name)
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

			u.Lock()
			for _, mbox := range u.mailboxes {
				if err := mbox.reset(); err != nil {
					log.Printf("cannot reset mailbox %s: %v", mbox.name, err)
				}
			}
			u.Unlock()

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
							update.Message.Flags = mbox.fetchFlags(msg)
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

			u.Lock()
			for _, count := range event.MessageCounts {
				if mbox, ok := u.mailboxes[count.LabelID]; ok {
					mbox.total = count.Total
					mbox.unread = count.Unread
				}
			}
			u.Unlock()
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
