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

	"github.com/emersion/hydroxide/protonmail"
)

func messageID(msg *protonmail.Message) string {
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

func fetchEnvelope(msg *protonmail.Message) *imap.Envelope {
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
		MessageId: messageID(msg),
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

func fetchFlags(msg *protonmail.Message) []string {
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

func (mbox *mailbox) fetchBodyStructure(msg *protonmail.Message, extended bool) (*imap.BodyStructure, error) {
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

func (mbox *mailbox) inlineBody(msg *protonmail.Message) (io.Reader, error) {
	h := mail.NewTextHeader()
	h.SetContentType(msg.MIMEType, nil)

	md, err := msg.Read(mbox.u.privateKeys, nil)
	if err != nil {
		return nil, err
	}

	// TODO: check signature
	return md.UnverifiedBody, nil
}

func (mbox *mailbox) attachmentBody(att *protonmail.Attachment) (io.Reader, error) {
	rc, err := mbox.u.c.GetAttachment(att.ID)
	if err != nil {
		return nil, err
	}

	md, err := att.Read(rc, mbox.u.privateKeys, nil)
	if err != nil {
		return nil, err
	}

	// TODO: check signature
	return md.UnverifiedBody, nil
}

func inlineHeader(msg *protonmail.Message) message.Header {
	h := mail.NewTextHeader()
	h.SetContentType(msg.MIMEType, nil)
	return h.Header
}

func attachmentHeader(att *protonmail.Attachment) message.Header {
	h := mail.NewAttachmentHeader()
	h.SetContentType(att.MIMEType, nil)
	h.SetFilename(att.Name)
	if att.ContentID != "" {
		h.Set("Content-Id", att.ContentID)
	}
	return h.Header
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

func messageHeader(msg *protonmail.Message) message.Header {
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
	h.Set("Message-Id", messageID(msg))
	return h.Header
}

func (mbox *mailbox) fetchBodySection(msg *protonmail.Message, section *imap.BodySectionName) (imap.Literal, error) {
	// TODO: section.Peek

	b := new(bytes.Buffer)

	if len(section.Path) == 0 {
		w, err := message.CreateWriter(b, messageHeader(msg))
		if err != nil {
			return nil, err
		}

		if section.Specifier == imap.TextSpecifier {
			b.Reset()
		}

		switch section.Specifier {
		case imap.EntireSpecifier, imap.TextSpecifier:
			msg, err := mbox.u.c.GetMessage(msg.ID)
			if err != nil {
				return nil, err
			}

			pw, err := w.CreatePart(inlineHeader(msg))
			if err != nil {
				return nil, err
			}
			pr, err := mbox.inlineBody(msg)
			if err != nil {
				return nil, err
			}
			if _, err := io.Copy(pw, pr); err != nil {
				return nil, err
			}
			pw.Close()

			for _, att := range msg.Attachments {
				pw, err := w.CreatePart(attachmentHeader(att))
				if err != nil {
					return nil, err
				}
				pr, err := mbox.attachmentBody(att)
				if err != nil {
					return nil, err
				}
				if _, err := io.Copy(pw, pr); err != nil {
					return nil, err
				}
				pw.Close()
			}
		}

		w.Close()
	} else {
		if len(section.Path) > 1 {
			return nil, errors.New("invalid body section path length")
		}

		var h message.Header
		var getBody func() (io.Reader, error)
		if part := section.Path[0]; part == 1 {
			h = inlineHeader(msg)
			getBody = func() (io.Reader, error) {
				msg, err := mbox.u.c.GetMessage(msg.ID)
				if err != nil {
					return nil, err
				}

				return mbox.inlineBody(msg)
			}
		} else {
			i := part - 2
			if i >= msg.NumAttachments {
				return nil, errors.New("invalid attachment section path")
			}

			msg, err := mbox.u.c.GetMessage(msg.ID)
			if err != nil {
				return nil, err
			}

			att := msg.Attachments[i]
			h = attachmentHeader(att)
			getBody = func() (io.Reader, error) {
				return mbox.attachmentBody(att)
			}
		}

		w, err := message.CreateWriter(b, h)
		if err != nil {
			return nil, err
		}

		if section.Specifier == imap.TextSpecifier {
			b.Reset()
		}

		switch section.Specifier {
		case imap.EntireSpecifier, imap.TextSpecifier:
			r, err := getBody()
			if err != nil {
				return nil, err
			}

			if _, err := io.Copy(w, r); err != nil {
				return nil, err
			}
		}

		w.Close()
	}

	var l imap.Literal = b
	if section.Partial != nil {
		l = bytes.NewReader(section.ExtractPartial(b.Bytes()))
	}

	return l, nil
}
