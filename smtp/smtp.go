package smtp

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-smtp"
	"golang.org/x/crypto/openpgp"

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
		if addr.Email == fromAddrStr {
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

	var body *bytes.Buffer
	var bodyType string

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
			// TODO
		}
	}

	if body == nil {
		return errors.New("message doesn't contain a body part")
	}

	msg.MIMEType = bodyType

	plaintext, err := msg.Encrypt([]*openpgp.Entity{privateKey}, privateKey)
	if err != nil {
		return err
	}
	if _, err := io.Copy(plaintext, bytes.NewReader(body.Bytes())); err != nil {
		return err
	}
	if err := plaintext.Close(); err != nil {
		return err
	}

	// TODO: parentID from In-Reply-To
	msg, err = u.c.CreateDraftMessage(msg, "")
	if err != nil {
		return fmt.Errorf("cannot create draft message: %v", err)
	}

	outgoing := &protonmail.OutgoingMessage{ID: msg.ID}

	recipients := make([]*mail.Address, 0, len(toList) + len(ccList) + len(bccList))
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
			break
		}

		// TODO: only keys with Send == 1
		pub, err := resp.Keys[0].Entity()
		if err != nil {
			return err
		}

		encryptedRecipients[rcpt.Address] = pub
	}

	if len(plaintextRecipients) > 0 {
		plaintextSet := protonmail.NewMessagePackageSet(nil)

		plaintext, err := plaintextSet.Encrypt(bodyType)
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
			if err := plaintextSet.AddCleartext(rcpt); err != nil {
				return err
			}
		}

		outgoing.Packages = append(outgoing.Packages, plaintextSet)
	}

	if len(encryptedRecipients) > 0 {
		encryptedSet := protonmail.NewMessagePackageSet(nil)

		plaintext, err := encryptedSet.Encrypt(bodyType)
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
			if err := encryptedSet.AddInternal(rcpt, pub); err != nil {
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

func New(sessions *auth.Manager) smtp.Backend {
	return &backend{sessions}
}
