package protonmail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
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

type MessageAddress struct {
	Address string
	Name    string
}

type Message struct {
	ID             string
	Order          int64
	Subject        string
	IsRead         int
	Type           MessageType
	Sender         *MessageAddress
	ReplyTo        *MessageAddress
	ToList         []*MessageAddress
	Time           int64
	Size           int64
	IsEncrypted    MessageEncryption
	ExpirationTime int64
	IsReplied      int
	IsRepliedAll   int
	IsForwarded    int
	SpamScore      int
	AddressID      string
	Body           string
	MIMEType       string
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
	reqData := struct {
		Message  *Message
		ParentID string `json:",omitempty"`
		Action   *int   `json:",omitempty"`
	}{msg, parentID, nil}
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

// From https://github.com/ProtonMail/Angular/blob/v3/src/app/composer/controllers/composeMessage.js#L656

type MessagePackage struct {
	Type MessagePackageType

	BodyKeyPacket string
	AttachmentKeyPackets map[string]string
	Signature int

	// Only if encrypted for outside
	PasswordHint string
	Auth interface{} // TODO
	Token string
	EncToken string
}

type MessagePackageSet struct {
	Type MessagePackageType // OR of each Type
	Addresses map[string]*MessagePackage
	MIMEType string
	Body string // Body data packet

	// Only if cleartext is sent
	BodyKey string
	AttachmentKeys map[string]string

	bodyKey *packet.EncryptedKey
	attachmentKeys map[string]*packet.EncryptedKey
}

func NewMessagePackageSet(attachmentKeys map[string]*packet.EncryptedKey) *MessagePackageSet {
	return &MessagePackageSet{
		attachmentKeys: attachmentKeys,
	}
}

func (set *MessagePackageSet) generateBodyKey(cipher packet.CipherFunction, config *packet.Config) error {
	symKey := make([]byte, cipher.KeySize())
	if _, err := io.ReadFull(config.Random(), symKey); err != nil {
		return err
	}

	set.bodyKey = &packet.EncryptedKey{
		CipherFunc: cipher,
		Key: symKey,
	}
	return nil
}

type outgoingMessageWriter struct {
	cleartext io.WriteCloser
	ciphertext io.WriteCloser
	armored *bytes.Buffer
	set *MessagePackageSet
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
	w.set.Body = w.armored.String()
	w.armored = nil
	return nil
}

func (set *MessagePackageSet) Encrypt() (io.WriteCloser, error) {
	config := &packet.Config{}

	if err := set.generateBodyKey(packet.CipherAES256, config); err != nil {
		return nil, err
	}

	var armored bytes.Buffer
	ciphertext, err := armor.Encode(&armored, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}

	encryptedData, err := packet.SerializeSymmetricallyEncrypted(ciphertext, set.bodyKey.CipherFunc, set.bodyKey.Key, config)
	if err != nil {
		return nil, err
	}

	// TODO: sign, see https://github.com/golang/crypto/blob/master/openpgp/write.go#L287

	literalData, err := packet.SerializeLiteral(encryptedData, false, "", 0)
	if err != nil {
		return nil, err
	}

	return &outgoingMessageWriter{
		cleartext: literalData,
		ciphertext: ciphertext,
		armored: &armored,
		set: set,
	}, nil
}

func (set *MessagePackageSet) AddCleartext(addr string) error {
	set.Addresses[addr] = &MessagePackage{Type: MessagePackageCleartext}

	if set.BodyKey == "" || set.AttachmentKeys == nil {
		set.BodyKey = base64.StdEncoding.EncodeToString(set.bodyKey.Key)

		set.AttachmentKeys = make(map[string]string, len(set.attachmentKeys))
		for att, key := range set.attachmentKeys {
			set.AttachmentKeys[att] = base64.StdEncoding.EncodeToString(key.Key)
		}
	}

	return nil
}

func serializeEncryptedKey(symKey *packet.EncryptedKey, pub *packet.PublicKey, config *packet.Config) (string, error) {
	var armored bytes.Buffer
	ciphertext, err := armor.Encode(&armored, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}

	err = packet.SerializeEncryptedKey(ciphertext, pub, symKey.CipherFunc, symKey.Key, config)
	if err != nil {
		return "", err
	}

	return armored.String(), nil
}

func (set *MessagePackageSet) AddInternal(addr string, pub *openpgp.Entity) error {
	config := &packet.Config{}

	encKey, ok := encryptionKey(pub, config.Now())
	if !ok {
		return errors.New("cannot encrypt a message to key id " + strconv.FormatUint(pub.PrimaryKey.KeyId, 16) + " because it has no encryption keys")
	}

	bodyKey, err := serializeEncryptedKey(set.bodyKey, encKey.PublicKey, config)
	if err != nil {
		return err
	}

	attachmentKeys := make(map[string]string, len(set.attachmentKeys))
	for att, key := range set.attachmentKeys {
		attKey, err := serializeEncryptedKey(key, encKey.PublicKey, config)
		if err != nil {
			return err
		}
		attachmentKeys[att] = attKey
	}

	set.Addresses[addr] = &MessagePackage{
		Type: MessagePackageInternal,
		BodyKeyPacket: bodyKey,
		AttachmentKeyPackets: attachmentKeys,
	}
	return nil
}

type OutgoingMessage struct {
	ID string

	// Only if message expires
	ExpirationTime int // Duration in seconds

	Packages []*MessagePackageSet
}

func (c *Client) SendMessage(msg *OutgoingMessage) (sent, parent *Message, err error) {
	req, err := c.newJSONRequest(http.MethodPut, "/messages/"+msg.ID, msg)
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
