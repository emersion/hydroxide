package imap

import (
	"golang.org/x/crypto/openpgp"
	imapbackend "github.com/emersion/go-imap/backend"

	"github.com/emersion/hydroxide/protonmail"
)

type user struct {
	username    string
	c           *protonmail.Client
	u           *protonmail.User
	privateKeys openpgp.EntityList
}

func (u *user) Username() string {
	return u.username
}

func (u *user) ListMailboxes(subscribed bool) ([]imapbackend.Mailbox, error) {
	return nil, errNotYetImplemented // TODO
}

func (u *user) GetMailbox(name string) (imapbackend.Mailbox, error) {
	return &mailbox{}, errNotYetImplemented // TODO
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
