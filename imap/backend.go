package imap

import (
	"errors"
	"sync"

	"github.com/emersion/go-imap"
	imapbackend "github.com/emersion/go-imap/backend"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/events"
)

var errNotYetImplemented = errors.New("not yet implemented")

type backend struct {
	sessions      *auth.Manager
	eventsManager *events.Manager
	updates       chan imapbackend.Update

	sync.Mutex // protects everything below

	users map[string]*user
}

func (be *backend) Login(info *imap.ConnInfo, username, password string) (imapbackend.User, error) {
	c, privateKeys, err := be.sessions.Auth(username, password)
	if err != nil {
		return nil, err
	}

	return getUser(be, username, c, privateKeys)
}

func (be *backend) Updates() <-chan imapbackend.Update {
	return be.updates
}

func New(sessions *auth.Manager, eventsManager *events.Manager) imapbackend.Backend {
	return &backend{
		sessions:      sessions,
		eventsManager: eventsManager,
		updates:       make(chan imapbackend.Update, 50),
		users:         make(map[string]*user),
	}
}
