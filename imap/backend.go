package imap

import (
	"errors"

	imapbackend "github.com/emersion/go-imap/backend"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/events"
)

var errNotYetImplemented = errors.New("not yet implemented")

type backend struct {
	sessions      *auth.Manager
	eventsManager *events.Manager
	updates       chan imapbackend.Update
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

	addrs, err := c.ListAddresses()
	if err != nil {
		return nil, err
	}

	return newUser(be, c, u, privateKeys, addrs)
}

func (be *backend) Updates() <-chan imapbackend.Update {
	return be.updates
}

func New(sessions *auth.Manager, eventsManager *events.Manager) imapbackend.Backend {
	return &backend{sessions, eventsManager, make(chan imapbackend.Update, 50)}
}
