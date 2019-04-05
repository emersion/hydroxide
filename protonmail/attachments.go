package protonmail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/packet"
)

type AttachmentKey struct {
	ID   string
	Key  string
	Algo string
}

type Attachment struct {
	ID         string
	MessageID  string
	Name       string
	Size       int
	MIMEType   string
	ContentID  string
	KeyPackets string // encrypted with the user's key, base64-encoded
	//Headers    map[string]string
	Signature string

	unencryptedKey *packet.EncryptedKey
}

// GenerateKey generates an encrypted key and encrypts it to the provided
// recipients. Usually, the recipient is the user himself.
//
// The returned key is NOT encrypted.
func (att *Attachment) GenerateKey(to []*openpgp.Entity) (*packet.EncryptedKey, error) {
	config := &packet.Config{}

	var encodedKeyPackets bytes.Buffer
	keyPackets := base64.NewEncoder(base64.StdEncoding, &encodedKeyPackets)

	unencryptedKey, err := generateUnencryptedKey(packet.CipherAES256, config)
	if err != nil {
		return nil, err
	}

	for _, pub := range to {
		encKey, ok := encryptionKey(pub, config.Now())
		if !ok {
			return nil, errors.New("cannot encrypt an attachment to key id " + strconv.FormatUint(pub.PrimaryKey.KeyId, 16) + " because it has no encryption keys")
		}

		err := packet.SerializeEncryptedKey(keyPackets, encKey.PublicKey, unencryptedKey.CipherFunc, unencryptedKey.Key, config)
		if err != nil {
			return nil, err
		}
	}

	keyPackets.Close()
	att.unencryptedKey = unencryptedKey
	att.KeyPackets = encodedKeyPackets.String()
	return unencryptedKey, nil
}

// Encrypt encrypts to w the data that will be written to the returned
// io.WriteCloser.
//
// Prior to calling Encrypt, an attachment key must have been generated with
// GenerateKey.
//
// signed is ignored for now.
func (att *Attachment) Encrypt(ciphertext io.Writer, signed *openpgp.Entity) (cleartext io.WriteCloser, err error) {
	config := &packet.Config{}

	if att.unencryptedKey == nil {
		return nil, errors.New("cannot encrypt attachment: no attachment key available")
	}

	// TODO: sign and store signature in att.Signature

	hints := &openpgp.FileHints{
		IsBinary: true,
		FileName: att.Name,
	}
	return symetricallyEncrypt(ciphertext, att.unencryptedKey, nil, hints, config)
}

func (att *Attachment) Read(ciphertext io.Reader, keyring openpgp.KeyRing, prompt openpgp.PromptFunction) (*openpgp.MessageDetails, error) {
	if len(att.KeyPackets) == 0 {
		return &openpgp.MessageDetails{
			IsEncrypted:    false,
			IsSigned:       false,
			UnverifiedBody: ciphertext,
		}, nil
	} else {
		kpr := base64.NewDecoder(base64.StdEncoding, strings.NewReader(att.KeyPackets))
		r := io.MultiReader(kpr, ciphertext)
		return openpgp.ReadMessage(r, keyring, prompt, nil)
	}
}

// GetAttachment downloads an attachment's payload. The returned io.ReadCloser
// may be encrypted, use Attachment.Read to decrypt it.
func (c *Client) GetAttachment(id string) (io.ReadCloser, error) {
	req, err := c.newRequest(http.MethodGet, "/attachments/"+id, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("cannot get attachment %q: %v %v", id, resp.Status, resp.StatusCode)
	}

	return resp.Body, nil
}

// CreateAttachment uploads a new attachment. r must be an PGP data packet
// encrypted with att.KeyPackets.
func (c *Client) CreateAttachment(att *Attachment, r io.Reader) (created *Attachment, err error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	go func() {
		if err := mw.WriteField("Filename", att.Name); err != nil {
			pw.CloseWithError(err)
			return
		}

		if err := mw.WriteField("MessageID", att.MessageID); err != nil {
			pw.CloseWithError(err)
			return
		}

		if err := mw.WriteField("MIMEType", att.MIMEType); err != nil {
			pw.CloseWithError(err)
			return
		}

		if att.ContentID != "" {
			if err := mw.WriteField("ContentID", att.ContentID); err != nil {
				pw.CloseWithError(err)
				return
			}
		}

		if w, err := mw.CreateFormFile("KeyPackets", "KeyPackets.pgp"); err != nil {
			pw.CloseWithError(err)
			return
		} else {
			kpr := base64.NewDecoder(base64.StdEncoding, strings.NewReader(att.KeyPackets))
			if _, err := io.Copy(w, kpr); err != nil {
				pw.CloseWithError(err)
				return
			}
		}

		if w, err := mw.CreateFormFile("DataPacket", "DataPacket.pgp"); err != nil {
			pw.CloseWithError(err)
			return
		} else if _, err := io.Copy(w, r); err != nil {
			pw.CloseWithError(err)
			return
		}

		// TODO: Signature

		pw.CloseWithError(mw.Close())
	}()

	req, err := c.newRequest(http.MethodPost, "/attachments", pr)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", mw.FormDataContentType())

	var respData struct {
		resp
		Attachment *Attachment
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Attachment, nil
}
