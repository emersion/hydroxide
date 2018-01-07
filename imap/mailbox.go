package imap

import (
	"strings"
	"time"

	"github.com/emersion/go-imap"

	"github.com/emersion/hydroxide/imap/database"
	"github.com/emersion/hydroxide/protonmail"
)

const delimiter = "/"

type mailbox struct {
	name string
	label string
	flags []string

	u *user
	db *database.Mailbox

	total, unread int
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
			status.Messages = uint32(mbox.total)
		case imap.StatusUidNext:
			uidNext, err := mbox.db.UidNext()
			if err != nil {
				return nil, err
			}
			status.UidNext = uidNext
		case imap.StatusUidValidity:
			status.UidValidity = 1
		case imap.StatusRecent:
			status.Recent = 0
		case imap.StatusUnseen:
			status.Unseen = uint32(mbox.unread)
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

func (mbox *mailbox) sync() error {
	filter := &protonmail.MessageFilter{
		PageSize: 150,
		Label: mbox.label,
		Sort: "ID",
		Asc: true,
	}

	total := -1
	for {
		offset := filter.PageSize * filter.Page
		if total >= 0 && offset > total {
			break
		}

		var page []*protonmail.Message
		var err error
		total, page, err = mbox.u.c.ListMessages(filter)
		if err != nil {
			return err
		}

		if err := mbox.db.Sync(page); err != nil {
			return err
		}

		filter.Page++
	}

	return nil
}

func getMessageID(id string) string {
	return id + "@protonmail.com"
}

func getAddress(addr *protonmail.MessageAddress) *imap.Address {
	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) < 2 {
		parts = append(parts, "")
	}

	return &imap.Address{
		PersonalName: addr.Name,
		MailboxName: parts[0],
		HostName: parts[1],
	}
}

func getAddressList(addresses []*protonmail.MessageAddress) []*imap.Address {
	l := make([]*imap.Address, len(addresses))
	for i, addr := range addresses {
		l[i] = getAddress(addr)
	}
	return l
}

func getEnvelope(msg *protonmail.Message) *imap.Envelope {
	return &imap.Envelope{
		Date: time.Unix(msg.Time, 0),
		Subject: msg.Subject,
		From: []*imap.Address{getAddress(msg.Sender)},
		Sender: []*imap.Address{getAddress(msg.Sender)},
		ReplyTo: []*imap.Address{getAddress(msg.ReplyTo)},
		To: getAddressList(msg.ToList),
		Cc: getAddressList(msg.CCList),
		Bcc: getAddressList(msg.BCCList),
		// TODO: InReplyTo
		MessageId: getMessageID(msg.ID),
	}
}

func hasLabel(msg *protonmail.Message, labelID string) bool {
	for _, id := range msg.LabelIDs {
		if labelID == id {
			return true
		}
	}
	return false
}

func getFlags(msg *protonmail.Message) []string {
	var flags []string
	if msg.IsRead != 0 {
		flags = append(flags, imap.SeenFlag)
	}
	if msg.IsReplied != 0 || msg.IsRepliedAll != 0 {
		flags = append(flags, imap.AnsweredFlag)
	}
	for _, label := range msg.LabelIDs {
		switch label {
		case protonmail.LabelStarred:
			flags = append(flags, imap.FlaggedFlag)
		case protonmail.LabelDraft:
			flags = append(flags, imap.DraftFlag)
		}
	}
	// TODO: DeletedFlag
	return flags
}

func (mbox *mailbox) getBodyStructure(id string, extended bool) (*imap.BodyStructure, error) {
	// TODO
}

func (mbox *mailbox) getBodySection(id string, section *imap.BodySectionName) (imap.Literal, error) {
	// TODO
}

func (mbox *mailbox) getMessage(isUid bool, id uint32, items []imap.FetchItem) (*imap.Message, error) {
	var apiID string
	var err error
	if isUid {
		apiID, err = mbox.db.FromUid(id)
	} else {
		apiID, err = mbox.db.FromSeqNum(id)
	}
	if err != nil {
		return nil, err
	}

	seqNum, uid, err := mbox.db.FromApiID(apiID)
	if err != nil {
		return nil, err
	}

	msg, err := mbox.u.db.Message(apiID)
	if err != nil {
		return nil, err
	}

	fetched := imap.NewMessage(seqNum, items)
	for _, item := range items {
		switch item {
		case imap.FetchEnvelope:
			fetched.Envelope = getEnvelope(msg)
		case imap.FetchBody, imap.FetchBodyStructure:
			bs, err := mbox.getBodyStructure(msg.ID, item == imap.FetchBodyStructure)
			if err != nil {
				return nil, err
			}
			fetched.BodyStructure = bs
		case imap.FetchFlags:
			fetched.Flags = getFlags(msg)
		case imap.FetchInternalDate:
			fetched.InternalDate = time.Unix(msg.Time, 0)
		case imap.FetchRFC822Size:
			fetched.Size = uint32(msg.Size)
		case imap.FetchUid:
			fetched.Uid = uid
		default:
			section, err := imap.ParseBodySectionName(item)
			if err != nil {
				break
			}

			l, err := mbox.getBodySection(msg.ID, section)
			if err != nil {
				return nil, err
			}
			fetched.Body[section] = l
		}
	}

	return fetched, nil
}

func (mbox *mailbox) ListMessages(uid bool, seqSet *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	defer close(ch)

	for _, seq := range seqSet.Set {
		start := seq.Start
		if start == 0 {
			start = 1
		}

		stop := seq.Stop
		if stop == 0 {
			if uid {
				uidNext, err := mbox.db.UidNext()
				if err != nil {
					return err
				}
				stop = uidNext - 1
			} else {
				stop = uint32(mbox.total)
			}
		}

		for i := start; i <= stop; i++ {
			msg, err := mbox.getMessage(uid, i, items)
			if err != nil {
				return err
			}
			if msg != nil {
				ch <- msg
			}
		}
	}

	return nil
}

func (mbox *mailbox) SearchMessages(uid bool, criteria *imap.SearchCriteria) ([]uint32, error) {
	return nil, errNotYetImplemented // TODO
}

func (mbox *mailbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	return errNotYetImplemented // TODO
}

func (mbox *mailbox) UpdateMessagesFlags(uid bool, seqSet *imap.SeqSet, operation imap.FlagsOp, flags []string) error {
	return errNotYetImplemented // TODO
}

func (mbox *mailbox) CopyMessages(uid bool, seqSet *imap.SeqSet, dest string) error {
	return errNotYetImplemented // TODO
}

func (mbox *mailbox) Expunge() error {
	return errNotYetImplemented // TODO
}
