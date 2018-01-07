package database

import (
	"encoding/json"
	"errors"

	"github.com/boltdb/bolt"

	"github.com/emersion/hydroxide/protonmail"
)

var ErrNotFound = errors.New("message not found in local database")

var (
	mailboxesBucket = []byte("mailboxes")
	messagesBucket = []byte("messages")
)

type User struct {
	db *bolt.DB
}

func (u *User) Mailbox(name string) (*Mailbox, error) {
	err := u.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(mailboxesBucket)
		if err != nil {
			return err
		}
		_, err = b.CreateBucketIfNotExists([]byte(name))
		return err
	})
	if err != nil {
		return nil, err
	}

	return &Mailbox{name, u}, nil
}

func (u *User) sync(messages []*protonmail.Message) error {
	return u.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(messagesBucket)
		if err != nil {
			return err
		}

		for _, msg := range messages {
			k := []byte(msg.ID)
			v, err := json.Marshal(msg)
			if err != nil{
				return err
			}
			if err := b.Put(k, v); err != nil {
				return err
			}
		}

		return nil
	})
}

func (u *User) Message(apiID string) (*protonmail.Message, error) {
	var msg *protonmail.Message
	err := u.db.View(func (tx *bolt.Tx) error {
		b := tx.Bucket(messagesBucket)
		if b == nil {
			return ErrNotFound
		}

		k := []byte(apiID)
		v := b.Get(k)
		if v == nil {
			return ErrNotFound
		}

		return json.Unmarshal(v, msg)
	})
	return msg, err
}

func Open(path string) (*User, error) {
	db, err := bolt.Open(path, 0700, nil)
	if err != nil {
		return nil, err
	}

	return &User{db}, nil
}
