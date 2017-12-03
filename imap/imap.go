package imap

import (
	"errors"

	imapbackend "github.com/emersion/go-imap/backend"

	"github.com/emersion/hydroxide/auth"
)

var errNotYetImplemented = errors.New("not yet implemented")

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

	return newUser(c, u, privateKeys)
}

func New(sessions *auth.Manager) imapbackend.Backend {
	return &backend{sessions}
}
