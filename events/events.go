package events

import (
	"log"
	"sync"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

const pollInterval = 30 * time.Second

type Receiver struct {
	c *protonmail.Client

	locker   sync.Mutex
	channels []chan<- *protonmail.Event

	poll chan struct{}
}

func (r *Receiver) receiveEvents() {
	t := time.NewTicker(pollInterval)
	defer t.Stop()

	var last string
	for {
		event, err := r.c.GetEvent(last)
		if err != nil {
			log.Println("cannot receive event:", err)
			select {
			case <-t.C:
			case <-r.poll:
			}
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

		select {
		case <-t.C:
		case <-r.poll:
		}
	}
}

func (r *Receiver) Poll() {
	r.poll <- struct{}{}
}

type Manager struct {
	receivers map[string]*Receiver
	locker    sync.Mutex
}

func NewManager() *Manager {
	return &Manager{
		receivers: make(map[string]*Receiver),
	}
}

func (m *Manager) Register(c *protonmail.Client, username string, ch chan<- *protonmail.Event, done <-chan struct{}) *Receiver {
	m.locker.Lock()
	defer m.locker.Unlock()

	r, ok := m.receivers[username]
	if ok {
		r.locker.Lock()
		r.channels = append(r.channels, ch)
		r.locker.Unlock()
	} else {
		r = &Receiver{
			c:        c,
			channels: []chan<- *protonmail.Event{ch},
			poll:     make(chan struct{}),
		}

		go func() {
			r.receiveEvents()

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

	return r
}
