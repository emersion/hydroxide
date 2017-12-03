package imap

import (
	"time"

	"github.com/emersion/go-imap"
)

type mailbox struct {
	name string
}

func (mbox *mailbox) Name() string {
	return mbox.name
}

func (mbox *mailbox) Info() (*imap.MailboxInfo, error) {
	return nil, errNotYetImplemented // TODO
}

func (mbox *mailbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	return nil, errNotYetImplemented // TODO
}

func (mbox *mailbox) SetSubscribed(subscribed bool) error {
	return errNotYetImplemented // TODO
}

func (mbox *mailbox) Check() error {
	return nil
}

func (mbox *mailbox) ListMessages(uid bool, seqset *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	return errNotYetImplemented // TODO
}

func (mbox *mailbox) SearchMessages(uid bool, criteria *imap.SearchCriteria) ([]uint32, error) {
	return nil, errNotYetImplemented // TODO
}

func (mbox *mailbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	return errNotYetImplemented // TODO
}

func (mbox *mailbox) UpdateMessagesFlags(uid bool, seqset *imap.SeqSet, operation imap.FlagsOp, flags []string) error {
	return errNotYetImplemented // TODO
}

func (mbox *mailbox) CopyMessages(uid bool, seqset *imap.SeqSet, dest string) error {
	return errNotYetImplemented // TODO
}

func (mbox *mailbox) Expunge() error {
	return errNotYetImplemented // TODO
}
