package smtp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-smtp"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/protonmail"
)

func toPMAddressList(addresses []*mail.Address) []*protonmail.MessageAddress {
	l := make([]*protonmail.MessageAddress, len(addresses))
	for i, addr := range addresses {
		l[i] = &protonmail.MessageAddress{
			Name:    addr.Name,
			Address: addr.Address,
		}
	}
	return l
}

func formatHeader(h mail.Header) string {
	var b bytes.Buffer
	for k, values := range h.Header {
		for _, v := range values {
			b.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	return b.String()
}

type user struct {
	c           *protonmail.Client
	u           *protonmail.User
	privateKeys openpgp.EntityList
}

func (u *user) Send(from string, to []string, r io.Reader) error {
	// Parse the incoming MIME message header
	mr, err := mail.CreateReader(r)
	if err != nil {
		return err
	}

	subject, _ := mr.Header.Subject()
	fromList, _ := mr.Header.AddressList("From")
	toList, _ := mr.Header.AddressList("To")
	ccList, _ := mr.Header.AddressList("Cc")
	bccList, _ := mr.Header.AddressList("Bcc")

	if len(fromList) != 1 {
		return errors.New("the From field must contain exactly one address")
	}
	if len(toList) == 0 && len(ccList) == 0 && len(bccList) == 0 {
		return errors.New("no recipient specified")
	}

	fromAddrStr := fromList[0].Address
	var fromAddr *protonmail.Address
	for _, addr := range u.u.Addresses {
		if strings.EqualFold(addr.Email, fromAddrStr) {
			fromAddr = addr
			break
		}
	}
	if fromAddr == nil {
		return errors.New("unknown sender address")
	}
	if len(fromAddr.Keys) == 0 {
		return errors.New("sender address has no private key")
	}

	// TODO: get appropriate private key
	encryptedPrivateKey, err := fromAddr.Keys[0].Entity()
	if err != nil {
		return fmt.Errorf("cannot parse sender private key: %v", err)
	}

	var privateKey *openpgp.Entity
	for _, e := range u.privateKeys {
		if e.PrimaryKey.KeyId == encryptedPrivateKey.PrimaryKey.KeyId {
			privateKey = e
			break
		}
	}
	if privateKey == nil {
		return errors.New("sender address key hasn't been decrypted")
	}

	msg := &protonmail.Message{
		ToList:    toPMAddressList(toList),
		CCList:    toPMAddressList(ccList),
		BCCList:   toPMAddressList(bccList),
		Subject:   subject,
		Header:    formatHeader(mr.Header),
		AddressID: fromAddr.ID,
	}

	// Create an empty draft
	plaintext, err := msg.Encrypt([]*openpgp.Entity{privateKey}, privateKey)
	if err != nil {
		return err
	}
	if err := plaintext.Close(); err != nil {
		return err
	}

	parentID := ""
	inReplyToList, _ := mr.Header.AddressList("In-Reply-To")
	if len(inReplyToList) == 1 {
		inReplyTo := inReplyToList[0].Address

		filter := protonmail.MessageFilter{
			Limit: 1,
			ExternalID: inReplyTo,
			AddressID: fromAddr.ID,
		}
		total, msgs, err := u.c.ListMessages(&filter)
		if err != nil {
			return err
		}
		if total == 1 {
			parentID = msgs[0].ID
		}
	}

	msg, err = u.c.CreateDraftMessage(msg, parentID)
	if err != nil {
		return fmt.Errorf("cannot create draft message: %v", err)
	}

	// Parse the incoming MIME message body
	// Save the message text into a buffer
	// Upload attachments

	var body *bytes.Buffer
	var bodyType string
	attachmentKeys := make(map[string]*packet.EncryptedKey)

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		switch h := p.Header.(type) {
		case mail.TextHeader:
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
				return err
			}
		case mail.AttachmentHeader:
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

			attKey, err := att.GenerateKey([]*openpgp.Entity{privateKey})
			if err != nil {
				return fmt.Errorf("cannot generate attachment key: %v", err)
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

			att, err = u.c.CreateAttachment(att, pr)
			if err != nil {
				return fmt.Errorf("cannot upload attachment: %v", err)
			}

			attachmentKeys[att.ID] = attKey
		}
	}

	if body == nil {
		return errors.New("message doesn't contain a body part")
	}

	// Encrypt the body and update the draft
	msg.MIMEType = bodyType
	plaintext, err = msg.Encrypt([]*openpgp.Entity{privateKey}, privateKey)
	if err != nil {
		return err
	}
	if _, err := io.Copy(plaintext, bytes.NewReader(body.Bytes())); err != nil {
		return err
	}
	if err := plaintext.Close(); err != nil {
		return err
	}

	msg, err = u.c.UpdateDraftMessage(msg)
	if err != nil {
		return fmt.Errorf("cannot update draft message: %v", err)
	}

	// Split internal recipients and plaintext recipients

	recipients := make([]*mail.Address, 0, len(toList)+len(ccList)+len(bccList))
	recipients = append(recipients, toList...)
	recipients = append(recipients, ccList...)
	recipients = append(recipients, bccList...)

	var plaintextRecipients []string
	encryptedRecipients := make(map[string]*openpgp.Entity)
	for _, rcpt := range recipients {
		resp, err := u.c.GetPublicKeys(rcpt.Address)
		if err != nil {
			return fmt.Errorf("cannot get public key for address %q: %v", rcpt.Address, err)
		}

		if len(resp.Keys) == 0 {
			plaintextRecipients = append(plaintextRecipients, rcpt.Address)
			continue
		}

		// TODO: only keys with Send == 1
		pub, err := resp.Keys[0].Entity()
		if err != nil {
			return err
		}

		encryptedRecipients[rcpt.Address] = pub
	}

	// Create and send the outgoing message
	outgoing := &protonmail.OutgoingMessage{ID: msg.ID}

	if len(plaintextRecipients) > 0 {
		plaintextSet := protonmail.NewMessagePackageSet(attachmentKeys)

		plaintext, err := plaintextSet.Encrypt(bodyType, privateKey)
		if err != nil {
			return err
		}
		if _, err := io.Copy(plaintext, bytes.NewReader(body.Bytes())); err != nil {
			plaintext.Close()
			return err
		}
		if err := plaintext.Close(); err != nil {
			return err
		}

		for _, rcpt := range plaintextRecipients {
			pkg, err := plaintextSet.AddCleartext(rcpt)
			if err != nil {
				return err
			}

			// Don't sign plaintext messages by default
			// TODO: send inline singnature to opt-in contacts
			pkg.Signature = 0
		}

		outgoing.Packages = append(outgoing.Packages, plaintextSet)
	}

	if len(encryptedRecipients) > 0 {
		encryptedSet := protonmail.NewMessagePackageSet(attachmentKeys)

		plaintext, err := encryptedSet.Encrypt(bodyType, privateKey)
		if err != nil {
			return err
		}
		if _, err := io.Copy(plaintext, bytes.NewReader(body.Bytes())); err != nil {
			plaintext.Close()
			return err
		}
		if err := plaintext.Close(); err != nil {
			return err
		}

		for rcpt, pub := range encryptedRecipients {
			if _, err := encryptedSet.AddInternal(rcpt, pub); err != nil {
				return err
			}
		}

		outgoing.Packages = append(outgoing.Packages, encryptedSet)
	}

	_, _, err = u.c.SendMessage(outgoing)
	if err != nil {
		return fmt.Errorf("cannot send message: %v", err)
	}

	return nil
}

func (u *user) Logout() error {
	u.c = nil
	u.u = nil
	u.privateKeys = nil
	return nil
}

type backend struct {
	sessions *auth.Manager
}

func (be *backend) Login(username, password string) (smtp.User, error) {
	c, privateKeys, err := be.sessions.Auth(username, password)
	if err != nil {
		return nil, err
	}

	u, err := c.GetCurrentUser()
	if err != nil {
		return nil, err
	}

	// TODO: decrypt private keys in u.Addresses

	return &user{c, u, privateKeys}, nil
}

func (be *backend) AnonymousLogin() (smtp.User, error) {
	return nil, smtp.ErrAuthRequired
}

func New(sessions *auth.Manager) smtp.Backend {
	return &backend{sessions}
}
