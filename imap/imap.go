package imap

import (
	"errors"

	imapbackend "github.com/emersion/go-imap/backend"
	"golang.org/x/crypto/openpgp"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/protonmail"
)

var errNotYetImplemented = errors.New("not yet implemented")

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
	return nil, errNotYetImplemented // TODO
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

type backend struct {
	sessions *auth.Manager
}

func (be *backend) Login(username, password string) (imapbackend.User, error) {
	c, privateKeys, err := be.sessions.Auth(username, password)
	if err != nil {
		return nil, err
	}

	u, err := c.GetCurrentUser()
	if err != nil {
		return nil, err
	}

	// TODO: decrypt private keys in u.Addresses

	return &user{
		username: username,
		c: c,
		u: u,
		privateKeys: privateKeys,
	}, nil
}

func New(sessions *auth.Manager) imapbackend.Backend {
	return &backend{sessions}
}
