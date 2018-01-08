package imap

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"

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

func getMessageID(msg *protonmail.Message) string {
	if msg.ExternalID != "" {
		return msg.ExternalID
	} else {
		return msg.ID + "@protonmail.com"
	}
}

func imapAddress(addr *protonmail.MessageAddress) *imap.Address {
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

func imapAddressList(addresses []*protonmail.MessageAddress) []*imap.Address {
	l := make([]*imap.Address, len(addresses))
	for i, addr := range addresses {
		l[i] = imapAddress(addr)
	}
	return l
}

func getEnvelope(msg *protonmail.Message) *imap.Envelope {
	var replyTo []*imap.Address
	if msg.ReplyTo != nil {
		replyTo = []*imap.Address{imapAddress(msg.ReplyTo)}
	}

	return &imap.Envelope{
		Date: time.Unix(msg.Time, 0),
		Subject: msg.Subject,
		From: []*imap.Address{imapAddress(msg.Sender)},
		// TODO: Sender
		ReplyTo: replyTo,
		To: imapAddressList(msg.ToList),
		Cc: imapAddressList(msg.CCList),
		Bcc: imapAddressList(msg.BCCList),
		// TODO: InReplyTo
		MessageId: getMessageID(msg),
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

func splitMIMEType(t string) (string, string) {
	parts := strings.SplitN(t, "/", 2)
	if len(parts) < 2 {
		return "text", "plain"
	}
	return parts[0], parts[1]
}

func (mbox *mailbox) getBodyStructure(msg *protonmail.Message, extended bool) (*imap.BodyStructure, error) {
	if msg.NumAttachments > 0 {
		var err error
		msg, err = mbox.u.c.GetMessage(msg.ID)
		if err != nil {
			return nil, err
		}
	}

	inlineType, inlineSubType := splitMIMEType(msg.MIMEType)
	parts := []*imap.BodyStructure{
		&imap.BodyStructure{
			MIMEType: inlineType,
			MIMESubType: inlineSubType,
			Encoding: "quoted-printable",
			Size: uint32(len(msg.Body)),
			Extended: extended,
			Disposition: "inline",
		},
	}

	for _, att := range msg.Attachments {
		attType, attSubType := splitMIMEType(att.MIMEType)
		parts = append(parts, &imap.BodyStructure{
			MIMEType: attType,
			MIMESubType: attSubType,
			Id: att.ContentID,
			Encoding: "base64",
			Size: uint32(att.Size),
			Extended: extended,
			Disposition: "attachment",
			DispositionParams: map[string]string{"filename": att.Name},
		})
	}

	return &imap.BodyStructure{
		MIMEType: "multipart",
		MIMESubType: "mixed",
		// TODO: Params: map[string]string{"boundary": ...},
		// TODO: Size
		Parts: parts,
		Extended: extended,
	}, nil
}

func (mbox *mailbox) getInlineSection(msg *protonmail.Message) (message.Header, io.Reader, error) {
	h := mail.NewTextHeader()
	h.SetContentType(msg.MIMEType, nil)

	md, err := msg.Read(mbox.u.privateKeys, nil)
	if err != nil {
		return nil, nil, err
	}

	// TODO: check signature
	return h.Header, md.UnverifiedBody, nil
}

func (mbox *mailbox) getAttachmentSection(att *protonmail.Attachment) (message.Header, io.Reader, error) {
	h := mail.NewAttachmentHeader()
	h.SetContentType(att.MIMEType, nil)
	h.SetFilename(att.Name)
	if att.ContentID != "" {
		h.Set("Content-Id", att.ContentID)
	}

	rc, err := mbox.u.c.GetAttachment(att.ID)
	if err != nil {
		return nil, nil, err
	}

	md, err := att.Read(rc, mbox.u.privateKeys, nil)
	if err != nil {
		return nil, nil, err
	}

	// TODO: check signature
	return h.Header, md.UnverifiedBody, nil
}

func mailAddress(addr *protonmail.MessageAddress) *mail.Address {
	return &mail.Address{
		Name: addr.Name,
		Address: addr.Address,
	}
}

func mailAddressList(addresses []*protonmail.MessageAddress) []*mail.Address {
	l := make([]*mail.Address, len(addresses))
	for i, addr := range addresses {
		l[i] = mailAddress(addr)
	}
	return l
}

func (mbox *mailbox) getBodySection(msg *protonmail.Message, section *imap.BodySectionName) (imap.Literal, error) {
	// TODO: section.Peek
	// TODO: section.Partial
	// TODO: section.Specifier

	// TODO: only fetch if needed
	msg, err := mbox.u.c.GetMessage(msg.ID)
	if err != nil {
		return nil, err
	}

	b := new(bytes.Buffer)

	if len(section.Path) == 0 {
		h := mail.NewHeader()
		h.SetDate(time.Unix(msg.Time, 0))
		h.SetSubject(msg.Subject)
		h.SetAddressList("From", []*mail.Address{mailAddress(msg.Sender)})
		if msg.ReplyTo != nil {
			h.SetAddressList("Reply-To", []*mail.Address{mailAddress(msg.ReplyTo)})
		}
		h.SetAddressList("To", mailAddressList(msg.ToList))
		h.SetAddressList("Cc", mailAddressList(msg.CCList))
		h.SetAddressList("Bcc", mailAddressList(msg.BCCList))
		// TODO: In-Reply-To
		h.Set("Message-Id", getMessageID(msg))

		w, err := message.CreateWriter(b, h.Header)
		if err != nil {
			return nil, err
		}

		ph, pr, err := mbox.getInlineSection(msg)
		if err != nil {
			return nil, err
		}
		pw, err := w.CreatePart(ph)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(pw, pr); err != nil {
			return nil, err
		}
		pw.Close()

		for _, att := range msg.Attachments {
			ph, pr, err := mbox.getAttachmentSection(att)
			if err != nil {
				return nil, err
			}

			pw, err := w.CreatePart(ph)
			if err != nil {
				return nil, err
			}
			if _, err := io.Copy(pw, pr); err != nil {
				return nil, err
			}
			pw.Close()
		}

		w.Close()
	} else {
		if len(section.Path) > 1 {
			return nil, errors.New("invalid body section path length")
		}

		var h message.Header
		var r io.Reader
		var err error
		part := section.Path[0]
		if part == 1 {
			h, r, err = mbox.getInlineSection(msg)
		} else {
			i := part - 2
			if i >= msg.NumAttachments {
				return nil, errors.New("invalid attachment section path")
			}
			h, r, err = mbox.getAttachmentSection(msg.Attachments[i])
		}
		if err != nil {
			return nil, err
		}

		w, err := message.CreateWriter(b, h)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(w, r); err != nil {
			return nil, err
		}
		w.Close()
	}

	return b, nil
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
			bs, err := mbox.getBodyStructure(msg, item == imap.FetchBodyStructure)
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

			l, err := mbox.getBodySection(msg, section)
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
