package protonmail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/keybase/go-crypto/openpgp/packet"
)

type MessageType int

const (
	MessageInbox MessageType = iota
	MessageDraft
	MessageSent
	MessageInboxAndSent
)

type MessageEncryption int

const (
	MessageUnencrypted MessageEncryption = iota
	MessageEncryptedInternal
	MessageEncryptedExternal
	MessageEncryptedOutside
	_
	_
	_
	MessageEncryptedInlinePGP
	MessageEncryptedPGPMIME
	_
	_
)

type MessageAction int

const (
	MessageReply MessageAction = iota
	MessageReplyAll
	MessageForward
)

type MessageAddress struct {
	Address string
	Name    string
}

type Message struct {
	ID             string
	Order          int64
	Subject        string
	Unread         int
	Type           MessageType
	Sender         *MessageAddress
	ReplyTo        *MessageAddress
	ToList         []*MessageAddress
	Time           int64
	Size           int64
	NumAttachments int
	IsEncrypted    MessageEncryption
	ExpirationTime int64
	IsReplied      int
	IsRepliedAll   int
	IsForwarded    int
	SpamScore      int
	AddressID      string
	Body           string
	MIMEType       string `json:",omitempty"`
	CCList         []*MessageAddress
	BCCList        []*MessageAddress
	Header         string
	Attachments    []*Attachment
	LabelIDs       []string
	ExternalID     string
}

func (msg *Message) Read(keyring openpgp.KeyRing, prompt openpgp.PromptFunction) (*openpgp.MessageDetails, error) {
	switch msg.IsEncrypted {
	case MessageUnencrypted:
		return &openpgp.MessageDetails{
			IsEncrypted:    false,
			IsSigned:       false,
			UnverifiedBody: strings.NewReader(msg.Body),
		}, nil
	default:
		block, err := armor.Decode(strings.NewReader(msg.Body))
		if err != nil {
			return nil, err
		}

		return openpgp.ReadMessage(block.Body, keyring, prompt, nil)
	}
}

type messageWriter struct {
	plaintext  io.WriteCloser
	ciphertext io.WriteCloser
	b          *bytes.Buffer
	msg        *Message
}

func (w *messageWriter) Write(p []byte) (n int, err error) {
	return w.plaintext.Write(p)
}

func (w *messageWriter) Close() error {
	if err := w.plaintext.Close(); err != nil {
		return err
	}
	if err := w.ciphertext.Close(); err != nil {
		return err
	}
	w.msg.Body = w.b.String()
	return nil
}

func (msg *Message) Encrypt(to []*openpgp.Entity, signed *openpgp.Entity) (plaintext io.WriteCloser, err error) {
	var b bytes.Buffer
	ciphertext, err := armor.Encode(&b, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}

	plaintext, err = openpgp.Encrypt(ciphertext, to, signed, nil, nil)
	if err != nil {
		return nil, err
	}

	return &messageWriter{
		plaintext:  plaintext,
		ciphertext: ciphertext,
		b:          &b,
		msg:        msg,
	}, nil
}

type MessageFilter struct {
	Page     int
	PageSize int
	Limit    int

	Label        string
	Sort         string
	Asc          bool
	Begin        int64
	End          int64
	Keyword      string
	To           string
	From         string
	Subject      string
	Attachments  *bool
	Starred      *bool
	Unread       *bool
	Conversation string
	AddressID    string
	ID           []string
	ExternalID   string
}

func (c *Client) ListMessages(filter *MessageFilter) (total int, messages []*Message, err error) {
	v := url.Values{}
	if filter.Page != 0 {
		v.Set("Page", strconv.Itoa(filter.Page))
	}
	if filter.PageSize != 0 {
		v.Set("PageSize", strconv.Itoa(filter.PageSize))
	}
	if filter.Limit != 0 {
		v.Set("Limit", strconv.Itoa(filter.Limit))
	}
	if filter.Label != "" {
		v.Set("Label", filter.Label)
	}
	if filter.Sort != "" {
		v.Set("Sort", filter.Sort)
	}
	if filter.Asc {
		v.Set("Desc", "0")
	}
	if filter.Conversation != "" {
		v.Set("Conversation", filter.Conversation)
	}
	if filter.AddressID != "" {
		v.Set("AddressID", filter.AddressID)
	}
	if filter.ExternalID != "" {
		v.Set("ExternalID", filter.ExternalID)
	}

	req, err := c.newRequest(http.MethodGet, "/messages?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		Total    int
		Messages []*Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.Messages, nil
}

type MessageCount struct {
	LabelID string
	Total   int
	Unread  int
}

func (c *Client) CountMessages(address string) ([]*MessageCount, error) {
	v := url.Values{}
	if address != "" {
		v.Set("Address", address)
	}
	req, err := c.newRequest(http.MethodGet, "/messages/count?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Counts []*MessageCount
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Counts, nil
}

func (c *Client) GetMessage(id string) (*Message, error) {
	req, err := c.newRequest(http.MethodGet, "/messages/"+id, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Message *Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Message, nil
}

// CreateDraftMessage creates a new draft message. ToList, CCList, BCCList,
// Subject, Body and AddressID are required in msg.
func (c *Client) CreateDraftMessage(msg *Message, parentID string) (*Message, error) {
	var actionPtr *MessageAction
	if parentID != "" {
		// TODO: support other actions
		action := MessageReply
		actionPtr = &action
	}

	reqData := struct {
		Message  *Message
		ParentID string         `json:",omitempty"`
		Action   *MessageAction `json:",omitempty"`
	}{msg, parentID, actionPtr}
	req, err := c.newJSONRequest(http.MethodPost, "/messages", &reqData)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Message *Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Message, nil
}

func (c *Client) UpdateDraftMessage(msg *Message) (*Message, error) {
	reqData := struct {
		Message *Message
	}{msg}
	req, err := c.newJSONRequest(http.MethodPut, "/messages/"+msg.ID, &reqData)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Message *Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Message, nil
}

func (c *Client) doMessages(action string, ids []string) error {
	reqData := struct {
		IDs []string
	}{ids}
	req, err := c.newJSONRequest(http.MethodPut, "/messages/"+action, &reqData)
	if err != nil {
		return err
	}

	// TODO: the response contains one response per message
	return c.doJSON(req, nil)
}

func (c *Client) MarkMessagesRead(ids []string) error {
	return c.doMessages("read", ids)
}

func (c *Client) MarkMessagesUnread(ids []string) error {
	return c.doMessages("unread", ids)
}

func (c *Client) DeleteMessages(ids []string) error {
	return c.doMessages("delete", ids)
}

func (c *Client) UndeleteMessages(ids []string) error {
	return c.doMessages("undelete", ids)
}

func (c *Client) LabelMessages(labelID string, ids []string) error {
	reqData := struct {
		LabelID string
		IDs     []string
	}{labelID, ids}
	req, err := c.newJSONRequest(http.MethodPut, "/messages/label", &reqData)
	if err != nil {
		return err
	}

	// TODO: the response contains one response per message
	return c.doJSON(req, nil)
}

func (c *Client) UnlabelMessages(labelID string, ids []string) error {
	reqData := struct {
		LabelID string
		IDs     []string
	}{labelID, ids}
	req, err := c.newJSONRequest(http.MethodPut, "/messages/unlabel", &reqData)
	if err != nil {
		return err
	}

	// TODO: the response contains one response per message
	return c.doJSON(req, nil)
}

type MessageKeyPacket struct {
	ID         string
	KeyPackets string
}

type MessagePackageType int

const (
	MessagePackageInternal         MessagePackageType = 1
	MessagePackageEncryptedOutside                    = 2
	MessagePackageCleartext                           = 4
	MessagePackageInlinePGP                           = 8
	MessagePackagePGPMIME                             = 16
	MessagePackageMIME                                = 32
)

// From https://github.com/ProtonMail/WebClient/blob/public/src/app/composer/services/encryptMessage.js

type MessagePackage struct {
	Type MessagePackageType

	BodyKeyPacket        string
	AttachmentKeyPackets map[string]string
	Signature            int

	// Only if encrypted for outside
	PasswordHint string
	Auth         interface{} // TODO
	Token        string
	EncToken     string
}

type MessagePackageSet struct {
	Type      MessagePackageType // OR of each Type
	Addresses map[string]*MessagePackage
	MIMEType  string
	Body      string // Encrypted body data packet

	// Only if cleartext is sent
	BodyKey        *MessageBodyKey `json:",omitempty"`
	AttachmentKeys map[string]string

	bodyKey        *packet.EncryptedKey
	attachmentKeys map[string]*packet.EncryptedKey
	signature      int
}

type MessageBodyKey struct {
	Algorithm string
	Key       string
}

func NewMessagePackageSet(attachmentKeys map[string]*packet.EncryptedKey) *MessagePackageSet {
	return &MessagePackageSet{
		Addresses:      make(map[string]*MessagePackage),
		attachmentKeys: attachmentKeys,
	}
}

type outgoingMessageWriter struct {
	cleartext  io.WriteCloser
	ciphertext io.WriteCloser
	encoded    *bytes.Buffer
	set        *MessagePackageSet
}

func (w *outgoingMessageWriter) Write(p []byte) (int, error) {
	return w.cleartext.Write(p)
}

func (w *outgoingMessageWriter) Close() error {
	if err := w.cleartext.Close(); err != nil {
		return err
	}
	if err := w.ciphertext.Close(); err != nil {
		return err
	}
	w.set.Body = w.encoded.String()
	w.encoded = nil
	return nil
}

// Encrypt encrypts the data that will be written to the returned
// io.WriteCloser, and optionally signs it.
func (set *MessagePackageSet) Encrypt(mimeType string, signed *openpgp.Entity) (io.WriteCloser, error) {
	set.MIMEType = mimeType

	config := &packet.Config{}

	key, err := generateUnencryptedKey(packet.CipherAES256, config)
	if err != nil {
		return nil, err
	}
	set.bodyKey = key

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
		set.signature = 1
	}

	encoded := new(bytes.Buffer)
	ciphertext := base64.NewEncoder(base64.StdEncoding, encoded)

	cleartext, err := symetricallyEncrypt(ciphertext, key, signer, nil, config)
	if err != nil {
		return nil, err
	}

	return &outgoingMessageWriter{
		cleartext:  cleartext,
		ciphertext: ciphertext,
		encoded:    encoded,
		set:        set,
	}, nil
}

func cipherFunctionString(cipherFunc packet.CipherFunction) string {
	switch cipherFunc {
	case packet.CipherAES128:
		return "aes128"
	case packet.CipherAES192:
		return "aes192"
	case packet.CipherAES256:
		return "aes256"
	default:
		panic("protonmail: unsupported cipher function")
	}
}

func (set *MessagePackageSet) AddCleartext(addr string) (*MessagePackage, error) {
	pkg := &MessagePackage{
		Type:      MessagePackageCleartext,
		Signature: set.signature,
	}
	set.Addresses[addr] = pkg
	set.Type |= MessagePackageCleartext

	if set.BodyKey == nil || set.AttachmentKeys == nil {
		set.BodyKey = &MessageBodyKey{
			Algorithm: cipherFunctionString(set.bodyKey.CipherFunc),
			Key:       base64.StdEncoding.EncodeToString(set.bodyKey.Key),
		}

		set.AttachmentKeys = make(map[string]string, len(set.attachmentKeys))
		for att, key := range set.attachmentKeys {
			set.AttachmentKeys[att] = base64.StdEncoding.EncodeToString(key.Key)
		}
	}

	return pkg, nil
}

func serializeEncryptedKey(symKey *packet.EncryptedKey, pub *packet.PublicKey, config *packet.Config) (string, error) {
	var encoded bytes.Buffer
	ciphertext := base64.NewEncoder(base64.StdEncoding, &encoded)

	err := packet.SerializeEncryptedKey(ciphertext, pub, symKey.CipherFunc, symKey.Key, config)
	if err != nil {
		return "", err
	}

	ciphertext.Close()

	return encoded.String(), nil
}

func (set *MessagePackageSet) AddInternal(addr string, pub *openpgp.Entity) (*MessagePackage, error) {
	config := &packet.Config{}

	encKey, ok := encryptionKey(pub, config.Now())
	if !ok {
		return nil, errors.New("cannot encrypt a message to key id " + strconv.FormatUint(pub.PrimaryKey.KeyId, 16) + " because it has no encryption keys")
	}

	bodyKey, err := serializeEncryptedKey(set.bodyKey, encKey.PublicKey, config)
	if err != nil {
		return nil, err
	}

	attachmentKeys := make(map[string]string, len(set.attachmentKeys))
	for att, key := range set.attachmentKeys {
		attKey, err := serializeEncryptedKey(key, encKey.PublicKey, config)
		if err != nil {
			return nil, err
		}
		attachmentKeys[att] = attKey
	}

	set.Type |= MessagePackageInternal
	pkg := &MessagePackage{
		Type:                 MessagePackageInternal,
		BodyKeyPacket:        bodyKey,
		AttachmentKeyPackets: attachmentKeys,
		Signature:            set.signature,
	}
	set.Addresses[addr] = pkg
	return pkg, nil
}

type OutgoingMessage struct {
	ID string

	// Only if message expires
	ExpirationTime int // Duration in seconds

	Packages []*MessagePackageSet
}

func (c *Client) SendMessage(msg *OutgoingMessage) (sent, parent *Message, err error) {
	req, err := c.newJSONRequest(http.MethodPost, "/messages/"+msg.ID, msg)
	if err != nil {
		return nil, nil, err
	}

	var respData struct {
		resp
		Sent, Parent *Message
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, nil, err
	}

	return respData.Sent, respData.Parent, nil
}
