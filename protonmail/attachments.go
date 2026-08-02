package protonmail

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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
// If signed is not nil, a detached signature of the plaintext is generated
// and stored in att.Signature (base64-encoded).
func (att *Attachment) Encrypt(ciphertext io.Writer, signed *openpgp.Entity) (cleartext io.WriteCloser, err error) {
	config := &packet.Config{}

	if att.unencryptedKey == nil {
		return nil, errors.New("cannot encrypt attachment: no attachment key available")
	}

	var signer *packet.PrivateKey
	if signed != nil {
		signKey, ok := signingKey(signed, config.Now())
		if !ok {
			return nil, errors.New("no valid signing keys")
		}
		signer = signKey.PrivateKey
		if signer == nil {
			return nil, errors.New("no private key in signing key")
		}
		if signer.Encrypted {
			return nil, errors.New("signing key must be decrypted")
		}
	}

	hints := &openpgp.FileHints{
		IsBinary: true,
		FileName: att.Name,
	}
	inner, err := symetricallyEncrypt(ciphertext, att.unencryptedKey, signer, hints, config)
	if err != nil {
		return nil, err
	}

	if signer == nil {
		return inner, nil
	}

	// Wrap the writer to also compute a detached signature over the plaintext.
	hashType := crypto.SHA512
	h := hashType.New()
	return &attachmentSignWriter{
		inner:    inner,
		h:        h,
		hashType: hashType,
		signer:   signer,
		att:      att,
		config:   config,
	}, nil
}

// attachmentSignWriter wraps the inner encrypted writer and tees plaintext
// into a hash. On Close, it generates a detached signature and stores it
// base64-encoded in att.Signature.
type attachmentSignWriter struct {
	inner    io.WriteCloser
	h        hash.Hash
	hashType crypto.Hash
	signer   *packet.PrivateKey
	att      *Attachment
	config   *packet.Config
}

func (w *attachmentSignWriter) Write(data []byte) (int, error) {
	w.h.Write(data)
	return w.inner.Write(data)
}

func (w *attachmentSignWriter) Close() error {
	if err := w.inner.Close(); err != nil {
		return err
	}

	sigLifetimeSecs := w.config.SigLifetime()
	sig := &packet.Signature{
		Version:           3,
		SigType:           packet.SigTypeBinary,
		PubKeyAlgo:        w.signer.PubKeyAlgo,
		Hash:              w.hashType,
		CreationTime:      w.config.Now(),
		IssuerKeyId:       &w.signer.KeyId,
		IssuerFingerprint: w.signer.Fingerprint,
		SigLifetimeSecs:   &sigLifetimeSecs,
	}

	if err := sig.Sign(w.h, w.signer, w.config); err != nil {
		return fmt.Errorf("cannot sign attachment: %v", err)
	}

	var buf bytes.Buffer
	if err := sig.Serialize(&buf); err != nil {
		return fmt.Errorf("cannot serialize attachment signature: %v", err)
	}

	w.att.Signature = base64.StdEncoding.EncodeToString(buf.Bytes())
	return nil
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

		// Upload detached signature if present
		if att.Signature != "" {
			if w, err := mw.CreateFormFile("Signature", "Signature.pgp"); err != nil {
				pw.CloseWithError(err)
				return
			} else {
				sigReader := base64.NewDecoder(base64.StdEncoding, strings.NewReader(att.Signature))
				if _, err := io.Copy(w, sigReader); err != nil {
					pw.CloseWithError(err)
					return
				}
			}
		}

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
