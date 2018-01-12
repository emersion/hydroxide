package events

import (
	"log"
	"sync"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

const pollInterval = 30 * time.Second

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
		n := len(r.channels)
		for _, ch := range r.channels {
			ch <- event
		}
		r.locker.Unlock()

		if n == 0 {
			break
		}
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

func (m *Manager) Register(c *protonmail.Client, username string, ch chan<- *protonmail.Event, done <-chan struct{}) {
	m.locker.Lock()
	defer m.locker.Unlock()

	r, ok := m.receivers[username]
	if ok {
		r.locker.Lock()
		r.channels = append(r.channels, ch)
		r.locker.Unlock()
	} else {
		r = &receiver{
			channels: []chan<- *protonmail.Event{ch},
		}

		go func() {
			r.receiveEvents(c, "")

			m.locker.Lock()
			delete(m.receivers, username)
			m.locker.Unlock()
		}()

		m.receivers[username] = r
	}

	if done != nil {
		go func() {
			<-done

			r.locker.Lock()
			for i, c := range r.channels {
				if c == ch {
					r.channels = append(r.channels[:i], r.channels[i+1:]...)
				}
			}
			r.locker.Unlock()

			close(ch)
		}()
	}
}
