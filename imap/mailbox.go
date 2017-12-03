package imap

import (
	"time"

	"github.com/emersion/go-imap"
)

const delimiter = "/"

type mailbox struct {
	name string
	label string
	flags []string
}

func (mbox *mailbox) Name() string {
	return mbox.name
}

func (mbox *mailbox) Info() (*imap.MailboxInfo, error) {
	return &imap.MailboxInfo{
		Attributes: append(mbox.flags, imap.NoInferiorsAttr),
		Delimiter: delimiter,
		Name: mbox.name,
	}, nil
}

func (mbox *mailbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	status := imap.NewMailboxStatus(mbox.name, items)
	status.Flags = mbox.flags
	status.PermanentFlags = []string{imap.SeenFlag, imap.AnsweredFlag, imap.FlaggedFlag, imap.DeletedFlag, imap.DraftFlag}
	status.UnseenSeqNum = 0 // TODO

	for _, name := range items {
		switch name {
		case imap.StatusMessages:
			status.Messages = 0 // TODO
		case imap.StatusUidNext:
			status.UidNext = 1 // TODO
		case imap.StatusUidValidity:
			status.UidValidity = 1
		case imap.StatusRecent:
			status.Recent = 0 // TODO
		case imap.StatusUnseen:
			status.Unseen = 0 // TODO
		}
	}

	return status, nil
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
