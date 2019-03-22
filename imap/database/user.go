package database

import (
	"encoding/json"
	"errors"

	"github.com/boltdb/bolt"

	"github.com/emersion/hydroxide/config"
	"github.com/emersion/hydroxide/protonmail"
)

var ErrNotFound = errors.New("message not found in local database")

var (
	mailboxesBucket = []byte("mailboxes")
	messagesBucket  = []byte("messages")
)

func userMessage(b *bolt.Bucket, apiID string) (*protonmail.Message, error) {
	k := []byte(apiID)
	v := b.Get(k)
	if v == nil {
		return nil, ErrNotFound
	}

	msg := &protonmail.Message{}
	err := json.Unmarshal(v, msg)
	return msg, err
}

func userCreateMessage(b *bolt.Bucket, msg *protonmail.Message) error {
	k := []byte(msg.ID)
	v, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return b.Put(k, v)
}

func userSync(tx *bolt.Tx, messages []*protonmail.Message) error {
	b, err := tx.CreateBucketIfNotExists(messagesBucket)
	if err != nil {
		return err
	}

	for _, msg := range messages {
		if err := userCreateMessage(b, msg); err != nil {
			return err
		}
	}

	return nil
}

type User struct {
	db *bolt.DB
}

func (u *User) Mailbox(labelID string) (*Mailbox, error) {
	err := u.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(mailboxesBucket)
		if err != nil {
			return err
		}
		_, err = b.CreateBucketIfNotExists([]byte(labelID))
		return err
	})
	if err != nil {
		return nil, err
	}

	return &Mailbox{labelID, u}, nil
}

func (u *User) Message(apiID string) (*protonmail.Message, error) {
	var msg *protonmail.Message
	err := u.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(messagesBucket)
		if b == nil {
			return ErrNotFound
		}

		var err error
		msg, err = userMessage(b, apiID)
		return err
	})
	return msg, err
}

func (u *User) ResetMessages() error {
	return u.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket(messagesBucket)
	})
}

func (u *User) CreateMessage(msg *protonmail.Message) (seqNums map[string]uint32, err error) {
	seqNums = make(map[string]uint32)
	err = u.db.Update(func(tx *bolt.Tx) error {
		messages, err := tx.CreateBucketIfNotExists(messagesBucket)
		if err != nil {
			return err
		}

		if err := userCreateMessage(messages, msg); err != nil {
			return err
		}

		mailboxes, err := tx.CreateBucketIfNotExists(mailboxesBucket)
		if err != nil {
			return err
		}
		for _, labelID := range msg.LabelIDs {
			mbox, err := mailboxes.CreateBucketIfNotExists([]byte(labelID))
			if err != nil {
				return err
			}

			seqNum, err := mailboxCreateMessage(mbox, msg.ID)
			if err != nil {
				return err
			}
			seqNums[labelID] = seqNum
		}

		return nil
	})
	return
}

func (u *User) UpdateMessage(apiID string, update *protonmail.EventMessageUpdate) (createdSeqNums map[string]uint32, deletedSeqNums map[string]uint32, err error) {
	createdSeqNums = make(map[string]uint32)
	deletedSeqNums = make(map[string]uint32)
	err = u.db.Update(func(tx *bolt.Tx) error {
		messages := tx.Bucket(messagesBucket)
		if messages == nil {
			return errors.New("cannot update message in local DB: messages bucket doesn't exist")
		}

		msg, err := userMessage(messages, apiID)
		if err != nil {
			return err
		}

		addedLabels, removedLabels := update.DiffLabelIDs(msg.LabelIDs)

		mailboxes, err := tx.CreateBucketIfNotExists(mailboxesBucket)
		if err != nil {
			return err
		}
		for _, labelID := range addedLabels {
			mbox, err := mailboxes.CreateBucketIfNotExists([]byte(labelID))
			if err != nil {
				return err
			}

			seqNum, err := mailboxCreateMessage(mbox, apiID)
			if err != nil {
				return err
			}
			createdSeqNums[labelID] = seqNum
		}
		for _, labelID := range removedLabels {
			mbox := mailboxes.Bucket([]byte(labelID))
			if mbox == nil {
				continue
			}

			seqNum, err := mailboxDeleteMessage(mbox, apiID)
			if err != nil {
				return err
			}
			deletedSeqNums[labelID] = seqNum
		}

		update.Patch(msg)
		return userCreateMessage(messages, msg)
	})
	return
}

func (u *User) DeleteMessage(apiID string) (seqNums map[string]uint32, err error) {
	seqNums = make(map[string]uint32)
	err = u.db.Update(func(tx *bolt.Tx) error {
		messages := tx.Bucket(messagesBucket)
		if messages == nil {
			return nil
		}

		msg, err := userMessage(messages, apiID)
		if err == ErrNotFound {
			return nil
		} else if err != nil {
			return err
		}

		if err := messages.Delete([]byte(apiID)); err != nil {
			return err
		}

		mailboxes := tx.Bucket(mailboxesBucket)
		if mailboxes == nil {
			return nil
		}
		for _, labelID := range msg.LabelIDs {
			mbox := mailboxes.Bucket([]byte(labelID))
			if mbox == nil {
				continue
			}

			seqNum, err := mailboxDeleteMessage(mbox, msg.ID)
			if err != nil {
				return err
			}
			seqNums[labelID] = seqNum
		}

		return nil
	})
	return
}

func (u *User) Close() error {
	return u.db.Close()
}

func Open(filename string) (*User, error) {
	p, err := config.Path(filename)
	if err != nil {
		return nil, err
	}

	db, err := bolt.Open(p, 0700, nil)
	if err != nil {
		return nil, err
	}

	return &User{db}, nil
}
