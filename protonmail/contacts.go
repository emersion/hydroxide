package protonmail

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type Contact struct {
	ID         string
	Name       string
	UID        string
	Size       int
	CreateTime Timestamp
	ModifyTime Timestamp
	LabelIDs   []string

	// Not when using ListContacts
	ContactEmails []*ContactEmail
	Cards         []*ContactCard
}

type ContactEmailDefaults int

type ContactEmail struct {
	ID        string
	Email     string
	Type      []string
	Defaults  ContactEmailDefaults
	Order     int
	ContactID string
	LabelIDs  []string

	// Only when using ListContactsEmails
	Name string
}

type ContactCardType int

const (
	ContactCardCleartext ContactCardType = iota
	ContactCardEncrypted
	ContactCardSigned
	ContactCardEncryptedAndSigned
)

func (t ContactCardType) Signed() bool {
	switch t {
	case ContactCardSigned, ContactCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

func (t ContactCardType) Encrypted() bool {
	switch t {
	case ContactCardEncrypted, ContactCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

type ContactCard struct {
	Type      ContactCardType
	Data      string
	Signature string
}

func NewEncryptedContactCard(r io.Reader, to []*openpgp.Entity, signer *openpgp.Entity) (*ContactCard, error) {
	// TODO: sign and encrypt at the same time

	var msg, armored bytes.Buffer
	if signer != nil {
		// We'll sign the message later, keep a copy of it
		r = io.TeeReader(r, &msg)
	}

	ciphertext, err := armor.Encode(&armored, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}

	cleartext, err := openpgp.Encrypt(ciphertext, to, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(cleartext, r); err != nil {
		return nil, err
	}
	if err := cleartext.Close(); err != nil {
		return nil, err
	}

	if err := ciphertext.Close(); err != nil {
		return nil, err
	}

	card := &ContactCard{
		Type: ContactCardEncrypted,
		Data: armored.String(),
	}

	if signer != nil {
		var sig bytes.Buffer
		if err := openpgp.ArmoredDetachSignText(&sig, signer, &msg, nil); err != nil {
			return nil, err
		}

		card.Type = ContactCardEncryptedAndSigned
		card.Signature = sig.String()
	}

	return card, nil
}

func NewSignedContactCard(r io.Reader, signer *openpgp.Entity) (*ContactCard, error) {
	var msg, sig bytes.Buffer
	r = io.TeeReader(r, &msg)
	if err := openpgp.ArmoredDetachSignText(&sig, signer, r, nil); err != nil {
		return nil, err
	}

	return &ContactCard{
		Type:      ContactCardSigned,
		Data:      msg.String(),
		Signature: sig.String(),
	}, nil
}

func entityPrimaryKey(e *openpgp.Entity) *openpgp.Key {
	var selfSig *packet.Signature
	for _, ident := range e.Identities {
		if selfSig == nil {
			selfSig = ident.SelfSignature
		} else if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			selfSig = ident.SelfSignature
			break
		}
	}
	return &openpgp.Key{e, e.PrimaryKey, e.PrivateKey, selfSig}
}

type detachedSignatureReader struct {
	md        *openpgp.MessageDetails
	body      io.Reader
	signed    bytes.Buffer
	signature io.Reader
	keyring   openpgp.KeyRing
	eof       bool
}

func (r *detachedSignatureReader) Read(p []byte) (n int, err error) {
	// TODO: check signature and decrypt at the same time

	n, err = r.body.Read(p)
	if err == io.EOF && !r.eof {
		// Check signature
		signer, signatureError := openpgp.CheckArmoredDetachedSignature(r.keyring, &r.signed, r.signature, nil)
		r.md.IsSigned = true
		r.md.SignatureError = signatureError
		if signer != nil {
			r.md.SignedByKeyId = signer.PrimaryKey.KeyId
			r.md.SignedBy = entityPrimaryKey(signer)
		}
		r.eof = true
	}
	return
}

func (card *ContactCard) Read(keyring openpgp.KeyRing) (*openpgp.MessageDetails, error) {
	if !card.Type.Encrypted() {
		md := &openpgp.MessageDetails{
			IsEncrypted:    false,
			IsSigned:       false,
			UnverifiedBody: strings.NewReader(card.Data),
		}

		if !card.Type.Signed() {
			return md, nil
		}

		signed := strings.NewReader(card.Data)
		signature := strings.NewReader(card.Signature)
		signer, err := openpgp.CheckArmoredDetachedSignature(keyring, signed, signature, nil)
		md.IsSigned = true
		md.SignatureError = err
		if signer != nil {
			md.SignedByKeyId = signer.PrimaryKey.KeyId
			md.SignedBy = entityPrimaryKey(signer)
		}
		return md, nil
	}

	ciphertextBlock, err := armor.Decode(strings.NewReader(card.Data))
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(ciphertextBlock.Body, keyring, nil, nil)
	if err != nil {
		return nil, err
	}

	if card.Type.Signed() {
		r := &detachedSignatureReader{
			md:        md,
			signature: strings.NewReader(card.Signature),
			keyring:   keyring,
		}
		r.body = io.TeeReader(md.UnverifiedBody, &r.signed)

		md.UnverifiedBody = r
	}

	return md, nil
}

type ContactExport struct {
	ID    string
	Cards []*ContactCard
}

type ContactImport struct {
	Cards []*ContactCard
}

func (c *Client) ListContacts(page, pageSize int) (total int, contacts []*Contact, err error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, "/contacts?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		Contacts []*Contact
		Total    int
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.Contacts, nil
}

func (c *Client) ListContactsEmails(page, pageSize int) (total int, emails []*ContactEmail, err error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, "/contacts/emails?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		ContactEmails []*ContactEmail
		Total         int
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.ContactEmails, nil
}

func (c *Client) ListContactsExport(page, pageSize int) (total int, contacts []*ContactExport, err error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, "/contacts/export?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		Contacts []*ContactExport
		Total    int
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.Contacts, nil
}

func (c *Client) GetContact(id string) (*Contact, error) {
	req, err := c.newRequest(http.MethodGet, "/contacts/"+id, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Contact *Contact
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Contact, nil
}

type CreateContactResp struct {
	Index    int
	Response struct {
		resp
		Contact *Contact
	}
}

func (resp *CreateContactResp) Err() error {
	return resp.Response.Err()
}

func (c *Client) CreateContacts(contacts []*ContactImport) ([]*CreateContactResp, error) {
	reqData := struct {
		Contacts                  []*ContactImport
		Overwrite, Groups, Labels int
	}{contacts, 0, 0, 0}
	req, err := c.newJSONRequest(http.MethodPost, "/contacts", &reqData)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Responses []*CreateContactResp
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Responses, nil
}

func (c *Client) UpdateContact(id string, contact *ContactImport) (*Contact, error) {
	req, err := c.newJSONRequest(http.MethodPut, "/contacts/"+id, contact)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Contact *Contact
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Contact, nil
}

type DeleteContactResp struct {
	ID       string
	Response struct {
		resp
	}
}

func (resp *DeleteContactResp) Err() error {
	return resp.Response.Err()
}

func (c *Client) DeleteContacts(ids []string) ([]*DeleteContactResp, error) {
	reqData := struct {
		IDs []string
	}{ids}
	req, err := c.newJSONRequest(http.MethodPut, "/contacts/delete", &reqData)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Responses []*DeleteContactResp
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Responses, nil
}

func (c *Client) DeleteAllContacts() error {
	req, err := c.newRequest(http.MethodDelete, "/contacts", nil)
	if err != nil {
		return err
	}

	var respData resp
	if err := c.doJSON(req, &respData); err != nil {
		return err
	}

	return nil
}
