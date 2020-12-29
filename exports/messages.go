package exports

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-mbox"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"

	"github.com/emersion/hydroxide/protonmail"
)

func writeMessage(c *protonmail.Client, privateKeys openpgp.KeyRing, w io.Writer, msg *protonmail.Message) error {
	mimeType := msg.MIMEType
	if mimeType == "" {
		mimeType = "text/html"
	}

	br := bufio.NewReader(strings.NewReader(msg.Header))
	th, err := textproto.ReadHeader(br)
	if err != nil {
		return fmt.Errorf("failed to read message header: %v", err)
	}

	mh := mail.Header{message.Header{th}}
	mh.SetContentType(mimeType, map[string]string{"charset": "utf-8"})
	mh.Set("Content-Transfer-Encoding", "quoted-printable")

	// TODO: add support for attachments
	mw, err := mail.CreateSingleInlineWriter(w, mh)
	if err != nil {
		return fmt.Errorf("failed to create message writer: %v", err)
	}

	md, err := msg.Read(privateKeys, nil)
	if err != nil {
		return err
	}

	// TODO: check signature
	if _, err := io.Copy(mw, md.UnverifiedBody); err != nil {
		return err
	}

	return mw.Close()
}

func ExportMessage(c *protonmail.Client, privateKeys openpgp.KeyRing, w io.Writer, id string) error {
	msg, err := c.GetMessage(id)
	if err != nil {
		return fmt.Errorf("failed to fetch message: %v", err)
	}

	return writeMessage(c, privateKeys, w, msg)
}

func ExportMessageMbox(c *protonmail.Client, privateKeys openpgp.KeyRing, mbox *mbox.Writer, id string) error {
	msg, err := c.GetMessage(id)
	if err != nil {
		return fmt.Errorf("failed to fetch message: %v", err)
	}

	w, err := mbox.CreateMessage(msg.Sender.Address, msg.Time.Time())
	if err != nil {
		return fmt.Errorf("failed to create mbox message: %v", err)
	}

	return writeMessage(c, privateKeys, w, msg)
}

func ExportConversationMbox(c *protonmail.Client, privateKeys openpgp.KeyRing, mbox *mbox.Writer, id string) error {
	_, msgs, err := c.GetConversation(id, "")
	if err != nil {
		return fmt.Errorf("failed to fetch conversation: %v", err)
	}

	for _, msg := range msgs {
		if err := ExportMessageMbox(c, privateKeys, mbox, msg.ID); err != nil {
			return fmt.Errorf("failed to export conversation message: %v", err)
		}
	}

	return nil
}
