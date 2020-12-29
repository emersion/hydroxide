package imports

import (
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/emersion/go-message/mail"

	"github.com/emersion/hydroxide/protonmail"
)

func ImportMessage(c *protonmail.Client, r io.Reader) error {
	mr, err := mail.CreateReader(r)
	if err != nil {
		return err
	}
	defer mr.Close()

	// TODO: support attachments
	hdr := mr.Header
	var body io.Reader
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if _, ok := p.Header.(*mail.InlineHeader); ok {
			if t := p.Header.Get("Content-Type"); t != "" {
				hdr.Set("Content-Type", t)
			}
			body = p.Body
			break
		}
	}
	if body == nil {
		return fmt.Errorf("message has no body")
	}

	addrs, err := c.ListAddresses()
	if err != nil {
		return err
	}
	// TODO: choose address depending on message header
	var importAddr *protonmail.Address
	for _, addr := range addrs {
		if addr.Send == protonmail.AddressSendPrimary {
			importAddr = addr
			break
		}
	}
	if importAddr == nil {
		return fmt.Errorf("no primary address found")
	}

	publicKey, err := importAddr.Keys[0].Entity()
	if err != nil {
		return err
	}

	key := "0"
	metadata := map[string]*protonmail.Message{
		key: {
			Unread:    1,
			LabelIDs:  []string{protonmail.LabelInbox},
			Type:      protonmail.MessageInbox,
			AddressID: importAddr.ID,
		},
	}
	importer, err := c.Import(metadata)
	if err != nil {
		return err
	}

	w, err := importer.ImportMessage(key)
	if err != nil {
		return err
	}

	var ihdr mail.InlineHeader
	ihdr.Set("Content-Type", hdr.Get("Content-Type"))
	ihdr.Set("Content-Transfer-Encoding", "8bit")

	hdr.Del("Content-Type")
	hdr.Del("Content-Transfer-Encoding")
	hdr.Del("Content-Disposition")
	mwc, err := mail.CreateWriter(w, hdr)
	if err != nil {
		return err
	}
	defer mwc.Close()

	iwc, err := mwc.CreateSingleInline(ihdr)
	if err != nil {
		return err
	}

	awc, err := armor.Encode(iwc, "PGP MESSAGE", nil)
	if err != nil {
		return err
	}
	defer awc.Close()
	ewc, err := openpgp.Encrypt(awc, []*openpgp.Entity{publicKey}, nil, nil, nil)
	if err != nil {
		return err
	}
	defer ewc.Close()

	if _, err := io.Copy(ewc, body); err != nil {
		return err
	}
	if err := ewc.Close(); err != nil {
		return err
	}
	if err := awc.Close(); err != nil {
		return err
	}
	if err := iwc.Close(); err != nil {
		return err
	}
	if err := mwc.Close(); err != nil {
		return err
	}

	if result, err := importer.Commit(); err != nil {
		return err
	} else if err := result.Err(); err != nil {
		return err
	}

	return nil
}
