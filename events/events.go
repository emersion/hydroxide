package events

import (
	"log"
	"sync"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

const pollInterval = time.Minute

type receiver struct {
	channels []chan<- *protonmail.Event
	locker sync.Mutex
}

func (r *receiver) receiveEvents(c *protonmail.Client, last string) {
	t := time.NewTicker(pollInterval)
	defer t.Stop()

	for range t.C {
		event, err := c.GetEvent(last)
		if err != nil {
			log.Println("cannot receive event:", err)
			continue
		}

		if event.ID == last {
			continue
		}
		last = event.ID

		r.locker.Lock()
		for _, ch := range r.channels {
			ch <- event
		}
		r.locker.Unlock()
	}
}

type Manager struct {
	receivers map[string]*receiver
	locker sync.Mutex
}

func NewManager() *Manager {
	return &Manager{
		receivers: make(map[string]*receiver),
	}
}

func (m *Manager) Register(c *protonmail.Client, username string, ch chan<- *protonmail.Event) {
	m.locker.Lock()
	defer m.locker.Unlock()

	if r, ok := m.receivers[username]; ok {
		r.locker.Lock()
		r.channels = append(r.channels, ch)
		r.locker.Unlock()
	} else {
		r = &receiver{
			channels: []chan<- *protonmail.Event{ch},
		}
		go r.receiveEvents(c, "")
		m.receivers[username] = r
	}
}
