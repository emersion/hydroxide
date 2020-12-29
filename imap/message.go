package imap

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
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

func formatHeader(h mail.Header) string {
	var b bytes.Buffer
	fields := h.Fields()
	for fields.Next() {
		b.WriteString(fmt.Sprintf("%s: %s\r\n", fields.Key(), fields.Value()))
	}
	return b.String()
}

func protonmailAddressList(addresses []*mail.Address) []*protonmail.MessageAddress {
	l := make([]*protonmail.MessageAddress, len(addresses))
	for i, addr := range addresses {
		l[i] = &protonmail.MessageAddress{
			Name:    addr.Name,
			Address: addr.Address,
		}
	}
	return l
}

func imapAddress(addr *protonmail.MessageAddress) *imap.Address {
	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) < 2 {
		parts = append(parts, "")
	}

	return &imap.Address{
		PersonalName: addr.Name,
		MailboxName:  parts[0],
		HostName:     parts[1],
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
	return &imap.Envelope{
		Date:    msg.Time.Time(),
		Subject: msg.Subject,
		From:    []*imap.Address{imapAddress(msg.Sender)},
		// TODO: Sender
		To:      imapAddressList(msg.ToList),
		Cc:      imapAddressList(msg.CCList),
		Bcc:     imapAddressList(msg.BCCList),
		ReplyTo: imapAddressList(msg.ReplyTos),
		// TODO: InReplyTo
		MessageId: messageID(msg),
	}
}

func msgBoundary(msg *protonmail.Message) string {
	h := sha1.Sum([]byte(msg.ID))
	return hex.EncodeToString(h[:])
}

func hasLabel(msg *protonmail.Message, labelID string) bool {
	for _, id := range msg.LabelIDs {
		if labelID == id {
			return true
		}
	}
	return false
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

	inlineType := "text"
	inlineSubType := "html"
	if msg.MIMEType != "" {
		inlineType, inlineSubType = splitMIMEType(msg.MIMEType)
	}
	parts := []*imap.BodyStructure{
		&imap.BodyStructure{
			MIMEType:    inlineType,
			MIMESubType: inlineSubType,
			Encoding:    "quoted-printable",
			Size:        uint32(len(msg.Body)),
			Extended:    extended,
			Disposition: "inline",
		},
	}

	for _, att := range msg.Attachments {
		attType, attSubType := splitMIMEType(att.MIMEType)
		parts = append(parts, &imap.BodyStructure{
			MIMEType:          attType,
			MIMESubType:       attSubType,
			Id:                att.ContentID,
			Encoding:          "base64",
			Size:              uint32(att.Size),
			Extended:          extended,
			Disposition:       "attachment",
			DispositionParams: map[string]string{"filename": att.Name},
		})
	}

	return &imap.BodyStructure{
		MIMEType:    "multipart",
		MIMESubType: "mixed",
		Params:      map[string]string{"boundary": msgBoundary(msg)},
		// TODO: Size
		Parts:    parts,
		Extended: extended,
	}, nil
}

func (mbox *mailbox) inlineBody(msg *protonmail.Message) (io.Reader, error) {
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
	var h mail.InlineHeader
	if msg.MIMEType != "" {
		h.SetContentType(msg.MIMEType, map[string]string{"charset": "utf-8"})
	} else {
		log.Println("Sending an inline header without its proper MIME type")
	}
	h.Set("Content-Transfer-Encoding", "quoted-printable")
	return h.Header
}

func attachmentHeader(att *protonmail.Attachment) message.Header {
	var h mail.AttachmentHeader
	h.SetContentType(att.MIMEType, nil)
	h.Set("Content-Transfer-Encoding", "base64")
	h.SetFilename(att.Name)
	if att.ContentID != "" {
		h.Set("Content-Id", att.ContentID)
	}
	return h.Header
}

func mailAddress(addr *protonmail.MessageAddress) *mail.Address {
	return &mail.Address{
		Name:    addr.Name,
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
	typeParams := map[string]string{"boundary": msgBoundary(msg)}

	var h mail.Header
	h.SetContentType("multipart/mixed", typeParams)
	h.SetDate(msg.Time.Time())
	h.SetSubject(msg.Subject)
	h.SetAddressList("From", []*mail.Address{mailAddress(msg.Sender)})
	if len(msg.ReplyTos) > 0 {
		h.SetAddressList("Reply-To", mailAddressList(msg.ReplyTos))
	}
	if len(msg.ToList) > 0 {
		h.SetAddressList("To", mailAddressList(msg.ToList))
	}
	if len(msg.CCList) > 0 {
		h.SetAddressList("Cc", mailAddressList(msg.CCList))
	}
	if len(msg.BCCList) > 0 {
		h.SetAddressList("Bcc", mailAddressList(msg.BCCList))
	}
	// TODO: In-Reply-To
	h.Set("Message-Id", fmt.Sprintf("<%s>", messageID(msg)))
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
			// TODO: only fetch the message if the body is needed
			// For now we fetch it in all cases because the MIME type is not included
			// in the cached message, and inlineHeader needs it
			msg, err := mbox.u.c.GetMessage(msg.ID)
			if err != nil {
				return nil, err
			}

			h = inlineHeader(msg)
			getBody = func() (io.Reader, error) {
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

		switch section.Specifier {
		case imap.TextSpecifier:
			// The header hasn't been requested. Discard it.
			b.Reset()
		case imap.EntireSpecifier:
			if len(section.Path) > 0 {
				// When selecting a specific part by index, IMAP servers
				// return only the text, not the associated MIME header.
				b.Reset()
			}
		}

		// Write the body, if requested
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

func createMessage(c *protonmail.Client, u *protonmail.User, privateKeys openpgp.EntityList, addrs []*protonmail.Address, r io.Reader) (*protonmail.Message, error) {
	// Parse the incoming MIME message header
	mr, err := mail.CreateReader(r)
	if err != nil {
		return nil, err
	}

	subject, _ := mr.Header.Subject()
	fromList, _ := mr.Header.AddressList("From")
	toList, _ := mr.Header.AddressList("To")
	ccList, _ := mr.Header.AddressList("Cc")
	bccList, _ := mr.Header.AddressList("Bcc")

	if len(fromList) != 1 {
		return nil, errors.New("the From field must contain exactly one address")
	}
	if len(toList) == 0 && len(ccList) == 0 && len(bccList) == 0 {
		return nil, errors.New("no recipient specified")
	}

	fromAddrStr := fromList[0].Address
	var fromAddr *protonmail.Address
	for _, addr := range addrs {
		if strings.EqualFold(addr.Email, fromAddrStr) {
			fromAddr = addr
			break
		}
	}
	if fromAddr == nil {
		return nil, errors.New("unknown sender address")
	}
	if len(fromAddr.Keys) == 0 {
		return nil, errors.New("sender address has no private key")
	}

	// TODO: get appropriate private key
	encryptedPrivateKey, err := fromAddr.Keys[0].Entity()
	if err != nil {
		return nil, fmt.Errorf("cannot parse sender private key: %v", err)
	}

	var privateKey *openpgp.Entity
	for _, e := range privateKeys {
		if e.PrimaryKey.KeyId == encryptedPrivateKey.PrimaryKey.KeyId {
			privateKey = e
			break
		}
	}
	if privateKey == nil {
		return nil, errors.New("sender address key hasn't been decrypted")
	}

	msg := &protonmail.Message{
		ToList:    protonmailAddressList(toList),
		CCList:    protonmailAddressList(ccList),
		BCCList:   protonmailAddressList(bccList),
		Subject:   subject,
		Header:    formatHeader(mr.Header),
		AddressID: fromAddr.ID,
	}

	// Create an empty draft
	plaintext, err := msg.Encrypt([]*openpgp.Entity{privateKey}, privateKey)
	if err != nil {
		return nil, err
	}
	if err := plaintext.Close(); err != nil {
		return nil, err
	}

	// TODO: parentID from In-Reply-To
	msg, err = c.CreateDraftMessage(msg, "")
	if err != nil {
		return nil, fmt.Errorf("cannot create draft message: %v", err)
	}

	var body *bytes.Buffer
	var bodyType string

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		switch h := p.Header.(type) {
		case *mail.InlineHeader:
			t, _, err := h.ContentType()
			if err != nil {
				break
			}

			if body != nil && t != "text/html" {
				break
			}

			body = &bytes.Buffer{}
			bodyType = t
			if _, err := io.Copy(body, p.Body); err != nil {
				return nil, err
			}
		case *mail.AttachmentHeader:
			t, _, err := h.ContentType()
			if err != nil {
				break
			}

			filename, err := h.Filename()
			if err != nil {
				break
			}

			att := &protonmail.Attachment{
				MessageID: msg.ID,
				Name:      filename,
				MIMEType:  t,
				ContentID: h.Get("Content-Id"),
				// TODO: Header
			}

			_, err = att.GenerateKey([]*openpgp.Entity{privateKey})
			if err != nil {
				return nil, fmt.Errorf("cannot generate attachment key: %v", err)
			}

			pr, pw := io.Pipe()

			go func() {
				cleartext, err := att.Encrypt(pw, privateKey)
				if err != nil {
					pw.CloseWithError(err)
					return
				}
				if _, err := io.Copy(cleartext, p.Body); err != nil {
					pw.CloseWithError(err)
					return
				}
				pw.CloseWithError(cleartext.Close())
			}()

			att, err = c.CreateAttachment(att, pr)
			if err != nil {
				return nil, fmt.Errorf("cannot upload attachment: %v", err)
			}

			msg.Attachments = append(msg.Attachments, att)
		}
	}

	if body == nil {
		return nil, errors.New("message doesn't contain a body part")
	}

	// Encrypt the body and update the draft
	msg.MIMEType = bodyType
	plaintext, err = msg.Encrypt([]*openpgp.Entity{privateKey}, privateKey)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(plaintext, body); err != nil {
		return nil, err
	}
	if err := plaintext.Close(); err != nil {
		return nil, err
	}

	if _, err := c.UpdateDraftMessage(msg); err != nil {
		return nil, fmt.Errorf("cannot update draft message: %v", err)
	}

	return msg, nil
}
