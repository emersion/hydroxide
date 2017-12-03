package imap

import (
	"golang.org/x/crypto/openpgp"
	"github.com/emersion/go-imap"
	imapbackend "github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap-specialuse"

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

	mailboxes map[string]*mailbox
}

func newUser(c *protonmail.Client, u *protonmail.User, privateKeys openpgp.EntityList) (*user, error) {
	uu := &user{
		c: c,
		u: u,
		privateKeys: privateKeys,
		mailboxes: make(map[string]*mailbox),
	}

	for _, data := range systemMailboxes {
		uu.mailboxes[data.name] = &mailbox{
			name: data.name,
			label: data.label,
			flags: data.flags,
		}
	}

	return uu, nil
}

func (u *user) Username() string {
	return u.u.Name
}

func (u *user) ListMailboxes(subscribed bool) ([]imapbackend.Mailbox, error) {
	list := make([]imapbackend.Mailbox, 0, len(u.mailboxes))
	for _, mbox := range u.mailboxes {
		list = append(list, mbox)
	}
	return list, nil
}

func (u *user) GetMailbox(name string) (imapbackend.Mailbox, error) {
	if mbox, ok := u.mailboxes[name]; ok {
		return mbox, nil
	} else {
		return nil, imapbackend.ErrNoSuchMailbox
	}
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
	u.c = nil
	u.u = nil
	u.privateKeys = nil
	return nil
}
