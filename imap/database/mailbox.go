package database

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/boltdb/bolt"

	"github.com/emersion/hydroxide/protonmail"
)

func serializeUID(uid uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uid)
	return b
}

func unserializeUID(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func mailboxCreateMessage(b *bolt.Bucket, apiID string) (seqNum uint32, err error) {
	want := []byte(apiID)
	c := b.Cursor()
	var n uint32 = 1
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if bytes.Equal(v, want) {
			return n, nil
		}
		n++
	}

	id, _ := b.NextSequence()
	uid := uint32(id)
	return n, b.Put(serializeUID(uid), want)
}

func mailboxDeleteMessage(b *bolt.Bucket, apiID string) (seqNum uint32, err error) {
	want := []byte(apiID)
	c := b.Cursor()
	var n uint32 = 1
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if bytes.Equal(v, want) {
			return n, b.Delete(k)
		}
		n++
	}
	return 0, nil
}

type Mailbox struct {
	labelID string
	u       *User
}

func (mbox *Mailbox) bucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	b := tx.Bucket(mailboxesBucket)
	if b == nil {
		return nil, errors.New("cannot find mailboxes bucket")
	}
	b = b.Bucket([]byte(mbox.labelID))
	if b == nil {
		return nil, errors.New("cannot find mailbox bucket")
	}
	return b, nil
}

func (mbox *Mailbox) Sync(messages []*protonmail.Message) error {
	return mbox.u.db.Update(func(tx *bolt.Tx) error {
		b, err := mbox.bucket(tx)
		if err != nil {
			return err
		}

		for _, msg := range messages {
			if _, err := mailboxCreateMessage(b, msg.ID); err != nil {
				return err
			}
		}

		return userSync(tx, messages)
	})
}

func (mbox *Mailbox) UidNext() (uint32, error) {
	var uid uint32
	err := mbox.u.db.View(func(tx *bolt.Tx) error {
		b, err := mbox.bucket(tx)
		if err != nil {
			return err
		}

		uid = uint32(b.Sequence() + 1)
		return nil
	})
	return uid, err
}

func (mbox *Mailbox) FromUid(uid uint32) (apiID string, err error) {
	err = mbox.u.db.View(func(tx *bolt.Tx) error {
		b, err := mbox.bucket(tx)
		if err != nil {
			return err
		}

		k := serializeUID(uid)
		v := b.Get(k)
		if v == nil {
			return ErrNotFound
		}
		apiID = string(v)
		return nil
	})
	return
}

func (mbox *Mailbox) FromSeqNum(seqNum uint32) (apiID string, err error) {
	err = mbox.u.db.View(func(tx *bolt.Tx) error {
		b, err := mbox.bucket(tx)
		if err != nil {
			return err
		}

		c := b.Cursor()
		var n uint32 = 1
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if seqNum == n {
				apiID = string(v)
				return nil
			}
			n++
		}

		return ErrNotFound
	})
	return
}

func (mbox *Mailbox) FromApiID(apiID string) (seqNum uint32, uid uint32, err error) {
	err = mbox.u.db.View(func(tx *bolt.Tx) error {
		b, err := mbox.bucket(tx)
		if err != nil {
			return err
		}

		want := []byte(apiID)
		c := b.Cursor()
		var n uint32 = 1
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if bytes.Equal(v, want) {
				seqNum = n
				uid = unserializeUID(k)
				return nil
			}
			n++
		}

		return ErrNotFound
	})
	return
}

func (mbox *Mailbox) ForEach(f func(seqNum, uid uint32, apiID string) error) error {
	return mbox.u.db.View(func(tx *bolt.Tx) error {
		b, err := mbox.bucket(tx)
		if err != nil {
			return err
		}

		c := b.Cursor()
		var n uint32 = 1
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if err := f(n, unserializeUID(k), string(v)); err != nil {
				return err
			}
			n++
		}

		return nil
	})
}

func (mbox *Mailbox) Reset() error {
	return mbox.u.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(mailboxesBucket)
		if b == nil {
			return errors.New("cannot find mailboxes bucket")
		}
		k := []byte(mbox.labelID)
		if err := b.DeleteBucket(k); err != nil {
			return err
		}
		_, err := b.CreateBucket(k)
		return err
	})
}
