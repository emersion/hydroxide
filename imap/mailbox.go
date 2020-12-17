package imap

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap"
	imapbackend "github.com/emersion/go-imap/backend"

	"github.com/emersion/hydroxide/imap/database"
	"github.com/emersion/hydroxide/protonmail"
)

const delimiter = "/"

type mailbox struct {
	name  string
	label string
	attrs []string

	u  *user
	db *database.Mailbox

	sync.Mutex // protects everything below

	initialized   bool
	total, unread int
	deleted       map[string]struct{}
}

func newMailbox(name string, label string, attrs []string, u *user) (*mailbox, error) {
	mboxDB, err := u.db.Mailbox(label)
	if err != nil {
		return nil, err
	}

	return &mailbox{
		name:    name,
		label:   label,
		attrs:   attrs,
		u:       u,
		db:      mboxDB,
		deleted: make(map[string]struct{}),
	}, nil
}

func (mbox *mailbox) Name() string {
	return mbox.name
}

func (mbox *mailbox) Info() (*imap.MailboxInfo, error) {
	return &imap.MailboxInfo{
		Attributes: append([]string{imap.NoInferiorsAttr}, mbox.attrs...),
		Delimiter:  delimiter,
		Name:       mbox.name,
	}, nil
}

func (mbox *mailbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	mbox.u.Lock()
	flags := []string{imap.SeenFlag, imap.DeletedFlag}
	permFlags := []string{imap.SeenFlag, imap.DeletedFlag}
	for _, flag := range mbox.u.flags {
		flags = append(flags, flag)
		permFlags = append(permFlags, flag)
	}
	mbox.u.Unlock()

	status := imap.NewMailboxStatus(mbox.name, items)
	status.Flags = flags
	status.PermanentFlags = permFlags
	status.UnseenSeqNum = 0 // TODO

	mbox.Lock()
	defer mbox.Unlock()

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
	log.Printf("Synchronizing mailbox %v...", mbox.name)

	// TODO: don't do this without incrementing UIDVALIDITY
	if err := mbox.db.Reset(); err != nil {
		return err
	}

	filter := &protonmail.MessageFilter{
		PageSize: 150,
		Label:    mbox.label,
		Sort:     "ID",
		Asc:      true,
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

	log.Printf("Synchronizing mailbox %v: done.", mbox.name)
	return nil
}

func (mbox *mailbox) init() error {
	mbox.Lock()
	defer mbox.Unlock()

	if mbox.initialized {
		return nil
	}

	// TODO: sync only the first time
	if err := mbox.sync(); err != nil {
		return err
	}

	mbox.initialized = true
	return nil
}

func (mbox *mailbox) reset() error {
	mbox.Lock()
	defer mbox.Unlock()

	mbox.initialized = false
	return mbox.db.Reset()
}

func (mbox *mailbox) fetchFlags(msg *protonmail.Message) []string {
	var flags []string
	if msg.Unread != 1 {
		flags = append(flags, imap.SeenFlag)
	}
	if msg.IsReplied != 0 || msg.IsRepliedAll != 0 {
		flags = append(flags, imap.AnsweredFlag)
	}

	mbox.Lock()
	if _, ok := mbox.deleted[msg.ID]; ok {
		flags = append(flags, imap.DeletedFlag)
	}
	mbox.Unlock()

	mbox.u.Lock()
	for _, label := range msg.LabelIDs {
		if flag, ok := mbox.u.flags[label]; ok {
			flags = append(flags, flag)
		}
	}
	mbox.u.Unlock()

	return flags
}

func (mbox *mailbox) fetchMessage(isUid bool, id uint32, items []imap.FetchItem) (*imap.Message, error) {
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
			fetched.Envelope = fetchEnvelope(msg)
		case imap.FetchBody, imap.FetchBodyStructure:
			bs, err := mbox.fetchBodyStructure(msg, item == imap.FetchBodyStructure)
			if err != nil {
				return nil, err
			}
			fetched.BodyStructure = bs
		case imap.FetchFlags:
			fetched.Flags = mbox.fetchFlags(msg)
		case imap.FetchInternalDate:
			fetched.InternalDate = msg.Time.Time()
		case imap.FetchRFC822Size:
			fetched.Size = uint32(msg.Size)
		case imap.FetchUid:
			fetched.Uid = uid
		default:
			section, err := imap.ParseBodySectionName(item)
			if err != nil {
				break
			}

			l, err := mbox.fetchBodySection(msg, section)
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

	if err := mbox.init(); err != nil {
		return err
	}

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
			msg, err := mbox.fetchMessage(uid, i, items)
			if err == database.ErrNotFound {
				continue
			} else if err != nil {
				return err
			}
			if msg != nil {
				ch <- msg
			}
		}
	}

	return nil
}

func matchString(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func (mbox *mailbox) SearchMessages(isUID bool, c *imap.SearchCriteria) ([]uint32, error) {
	if err := mbox.init(); err != nil {
		return nil, err
	}

	// TODO: c.Not, c.Or
	if c.Not != nil || c.Or != nil {
		return nil, errors.New("search queries with NOT or OR clauses are not yet implemented")
	}

	var results []uint32
	err := mbox.db.ForEach(func(seqNum, uid uint32, apiID string) error {
		if c.SeqNum != nil && !c.SeqNum.Contains(seqNum) {
			return nil
		}
		if c.Uid != nil && !c.Uid.Contains(uid) {
			return nil
		}

		// TODO: fetch message from local DB only if needed
		msg, err := mbox.u.db.Message(apiID)
		if err != nil {
			return err
		}

		flags := make(map[string]bool)
		for _, flag := range mbox.fetchFlags(msg) {
			flags[flag] = true
		}
		for _, f := range c.WithFlags {
			if !flags[f] {
				return nil
			}
		}
		for _, f := range c.WithoutFlags {
			if flags[f] {
				return nil
			}
		}

		date := msg.Time.Time().Round(24 * time.Hour)
		if !c.Since.IsZero() && !date.After(c.Since) {
			return nil
		}
		if !c.Before.IsZero() && !date.Before(c.Before) {
			return nil
		}
		// TODO: this date should be from the Date MIME header
		if !c.SentBefore.IsZero() && !date.Before(c.SentBefore) {
			return nil
		}
		if !c.SentSince.IsZero() && !date.After(c.SentSince) {
			return nil
		}

		h := messageHeader(msg)
		for key, wantValues := range c.Header {
			fields := h.FieldsByKey(key)
			var values []string
			for fields.Next() {
				values = append(values, fields.Value())
			}

			for _, wantValue := range wantValues {
				if wantValue == "" && len(values) == 0 {
					return nil
				}
				if wantValue != "" {
					ok := false
					for _, v := range values {
						if matchString(v, wantValue) {
							ok = true
							break
						}
					}
					if !ok {
						return nil
					}
				}
			}
		}

		// TODO: c.Body, c.Text

		if c.Larger > 0 && uint32(msg.Size) < c.Larger {
			return nil
		}
		if c.Smaller > 0 && uint32(msg.Size) > c.Smaller {
			return nil
		}

		if isUID {
			results = append(results, uid)
		} else {
			results = append(results, seqNum)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (mbox *mailbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	if mbox.label != protonmail.LabelDraft {
		return errors.New("cannot create messages outside the Drafts mailbox")
	}

	if err := mbox.init(); err != nil {
		return err
	}

	_, err := createMessage(mbox.u.c, mbox.u.u, mbox.u.privateKeys, mbox.u.addrs, body)
	if err != nil {
		return err
	}

	return mbox.Poll()
}

func (mbox *mailbox) fromSeqSet(isUID bool, seqSet *imap.SeqSet) ([]string, error) {
	var apiIDs []string
	err := mbox.db.ForEach(func(seqNum, uid uint32, apiID string) error {
		var id uint32
		if isUID {
			id = uid
		} else {
			id = seqNum
		}

		if seqSet.Contains(id) {
			apiIDs = append(apiIDs, apiID)
		}
		return nil
	})
	return apiIDs, err
}

func (mbox *mailbox) UpdateMessagesFlags(uid bool, seqSet *imap.SeqSet, op imap.FlagsOp, flags []string) error {
	if err := mbox.init(); err != nil {
		return err
	}

	apiIDs, err := mbox.fromSeqSet(uid, seqSet)
	if err != nil {
		return err
	}

	// TODO: imap.SetFlags should remove currently set flags

	for _, flag := range flags {
		var err error
		switch flag {
		case imap.SeenFlag:
			switch op {
			case imap.SetFlags, imap.AddFlags:
				err = mbox.u.c.MarkMessagesRead(apiIDs)
			case imap.RemoveFlags:
				err = mbox.u.c.MarkMessagesUnread(apiIDs)
			}
		case imap.DeletedFlag:
			// TODO: send updates
			mbox.Lock()
			switch op {
			case imap.SetFlags, imap.AddFlags:
				for _, apiID := range apiIDs {
					mbox.deleted[apiID] = struct{}{}
				}
			case imap.RemoveFlags:
				for _, apiID := range apiIDs {
					delete(mbox.deleted, apiID)
				}
			}
			mbox.Unlock()
		case imap.DraftFlag:
			// No-op
		default:
			label := mbox.u.getFlag(flag)
			if label == "" {
				break
			}

			switch op {
			case imap.SetFlags, imap.AddFlags:
				err = mbox.u.c.LabelMessages(label, apiIDs)
			case imap.RemoveFlags:
				err = mbox.u.c.UnlabelMessages(label, apiIDs)
			}
		}
		if err != nil {
			return err
		}
	}

	return mbox.Poll()
}

func (mbox *mailbox) CopyMessages(uid bool, seqSet *imap.SeqSet, destName string) error {
	if err := mbox.init(); err != nil {
		return err
	}

	apiIDs, err := mbox.fromSeqSet(uid, seqSet)
	if err != nil {
		return err
	}

	dest := mbox.u.getMailbox(destName)
	if dest == nil {
		return imapbackend.ErrNoSuchMailbox
	}

	if err := mbox.u.c.LabelMessages(dest.label, apiIDs); err != nil {
		return err
	}
	return mbox.Poll()
}

func (mbox *mailbox) MoveMessages(uid bool, seqSet *imap.SeqSet, destName string) error {
	if err := mbox.init(); err != nil {
		return err
	}

	apiIDs, err := mbox.fromSeqSet(uid, seqSet)
	if err != nil {
		return err
	}

	dest := mbox.u.getMailbox(destName)
	if dest == nil {
		return imapbackend.ErrNoSuchMailbox
	}

	if err := mbox.u.c.LabelMessages(dest.label, apiIDs); err != nil {
		return err
	}
	if err := mbox.u.c.UnlabelMessages(mbox.label, apiIDs); err != nil {
		return err
	}
	return mbox.Poll()
}

func (mbox *mailbox) Expunge() error {
	if err := mbox.init(); err != nil {
		return err
	}

	mbox.Lock()
	if len(mbox.deleted) == 0 {
		mbox.Unlock()
		return nil // Nothing to do
	}

	apiIDs := make([]string, 0, len(mbox.deleted))

	for apiID := range mbox.deleted {
		apiIDs = append(apiIDs, apiID)
	}
	mbox.Unlock()

	if err := mbox.u.c.DeleteMessages(apiIDs); err != nil {
		return err
	}

	return mbox.Poll()
}

func (mbox *mailbox) Poll() error {
	mbox.u.poll()
	return nil
}
