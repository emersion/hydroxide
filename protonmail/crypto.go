package protonmail

import (
	"crypto"
	"hash"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// primaryIdentity returns the Identity marked as primary or the first identity
// if none are so marked.
func primaryIdentity(e *openpgp.Entity) *openpgp.Identity {
	var firstIdentity *openpgp.Identity
	for _, ident := range e.Identities {
		if firstIdentity == nil {
			firstIdentity = ident
		}
		if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			return ident
		}
	}
	return firstIdentity
}

func entityToKey(e *openpgp.Entity, ident *openpgp.Identity) *openpgp.Key {
	return &openpgp.Key{
		Entity:        e,
		PublicKey:     e.PrimaryKey,
		PrivateKey:    e.PrivateKey,
		SelfSignature: ident.SelfSignature,
		Revocations:   e.Revocations,
	}
}

func entityPrimaryKey(e *openpgp.Entity) *openpgp.Key {
	return entityToKey(e, primaryIdentity(e))
}

func entitySubkeyToKey(e *openpgp.Entity, subkey *openpgp.Subkey) *openpgp.Key {
	return &openpgp.Key{
		Entity:        e,
		PublicKey:     subkey.PublicKey,
		PrivateKey:    subkey.PrivateKey,
		SelfSignature: subkey.Sig,
		Revocations:   subkey.Revocations,
	}
}

// encryptionKey returns the best candidate Key for encrypting a message to the
// given Entity.
func encryptionKey(e *openpgp.Entity, now time.Time) (openpgp.Key, bool) {
	candidateSubkey := -1

	// Iterate the keys to find the newest key
	var maxTime time.Time
	for i, subkey := range e.Subkeys {
		if subkey.Sig.FlagsValid &&
			subkey.Sig.FlagEncryptCommunications &&
			subkey.PublicKey.PubKeyAlgo.CanEncrypt() &&
			!subkey.PublicKey.KeyExpired(subkey.Sig, now) &&
			(maxTime.IsZero() || subkey.Sig.CreationTime.After(maxTime)) {
			candidateSubkey = i
			maxTime = subkey.Sig.CreationTime
		}
	}

	if candidateSubkey != -1 {
		subkey := e.Subkeys[candidateSubkey]
		return *entitySubkeyToKey(e, &subkey), true
	}

	// If we don't have any candidate subkeys for encryption and
	// the primary key doesn't have any usage metadata then we
	// assume that the primary key is ok. Or, if the primary key is
	// marked as ok to encrypt to, then we can obviously use it.
	i := primaryIdentity(e)
	if !i.SelfSignature.FlagsValid || i.SelfSignature.FlagEncryptCommunications && e.PrimaryKey.PubKeyAlgo.CanEncrypt() && !i.SelfSignature.SigExpired(now) {
		return *entityToKey(e, i), true
	}

	// This Entity appears to be signing only.
	return openpgp.Key{}, false
}

// signingKey return the best candidate Key for signing a message with this
// Entity.
func signingKey(e *openpgp.Entity, now time.Time) (openpgp.Key, bool) {
	candidateSubkey := -1

	for i, subkey := range e.Subkeys {
		if subkey.Sig.FlagsValid &&
			subkey.Sig.FlagSign &&
			subkey.PublicKey.PubKeyAlgo.CanSign() &&
			!subkey.PublicKey.KeyExpired(subkey.Sig, now) {
			candidateSubkey = i
			break
		}
	}

	if candidateSubkey != -1 {
		subkey := e.Subkeys[candidateSubkey]
		return *entitySubkeyToKey(e, &subkey), true
	}

	// If we have no candidate subkey then we assume that it's ok to sign
	// with the primary key.
	i := primaryIdentity(e)
	if !i.SelfSignature.FlagsValid || i.SelfSignature.FlagSign && !i.SelfSignature.SigExpired(now) {
		return *entityToKey(e, i), true
	}

	return openpgp.Key{}, false
}

func generateUnencryptedKey(cipher packet.CipherFunction, config *packet.Config) (*packet.EncryptedKey, error) {
	symKey := make([]byte, cipher.KeySize())
	if _, err := io.ReadFull(config.Random(), symKey); err != nil {
		return nil, err
	}

	return &packet.EncryptedKey{
		CipherFunc: cipher,
		Key:        symKey,
	}, nil
}

func symetricallyEncrypt(ciphertext io.Writer, symKey *packet.EncryptedKey, signer *packet.PrivateKey, hints *openpgp.FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	// From https://github.com/golang/crypto/blob/master/openpgp/write.go#L172

	cipherSuite := packet.CipherSuite{
		Cipher: config.Cipher(),
		Mode:   config.AEAD().Mode(),
	}
	encryptedData, err := packet.SerializeSymmetricallyEncrypted(ciphertext, symKey.CipherFunc, config.AEAD() != nil, cipherSuite, symKey.Key, config)
	if err != nil {
		return nil, err
	}

	hash := crypto.SHA256

	if signer != nil {
		ops := &packet.OnePassSignature{
			SigType:    packet.SigTypeBinary,
			Hash:       hash,
			PubKeyAlgo: signer.PubKeyAlgo,
			KeyId:      signer.KeyId,
			IsLast:     true,
		}
		if err := ops.Serialize(encryptedData); err != nil {
			return nil, err
		}
	}

	if hints == nil {
		hints = &openpgp.FileHints{}
	}

	w := encryptedData
	if signer != nil {
		// If we need to write a signature packet after the literal
		// data then we need to stop literalData from closing
		// encryptedData.
		w = noOpCloser{encryptedData}
	}
	var epochSeconds uint32
	if !hints.ModTime.IsZero() {
		epochSeconds = uint32(hints.ModTime.Unix())
	}
	literalData, err := packet.SerializeLiteral(w, hints.IsBinary, hints.FileName, epochSeconds)
	if err != nil {
		return nil, err
	}

	if signer != nil {
		return signatureWriter{encryptedData, literalData, hash, hash.New(), signer, config}, nil
	}
	return literalData, nil
}

// signatureWriter hashes the contents of a message while passing it along to
// literalData. When closed, it closes literalData, writes a signature packet
// to encryptedData and then also closes encryptedData.
type signatureWriter struct {
	encryptedData io.WriteCloser
	literalData   io.WriteCloser
	hashType      crypto.Hash
	h             hash.Hash
	signer        *packet.PrivateKey
	config        *packet.Config
}

func (s signatureWriter) Write(data []byte) (int, error) {
	s.h.Write(data)
	return s.literalData.Write(data)
}

func (s signatureWriter) Close() error {
	sig := &packet.Signature{
		SigType:      packet.SigTypeBinary,
		PubKeyAlgo:   s.signer.PubKeyAlgo,
		Hash:         s.hashType,
		CreationTime: s.config.Now(),
		IssuerKeyId:  &s.signer.KeyId,
	}

	if err := sig.Sign(s.h, s.signer, s.config); err != nil {
		return err
	}
	if err := s.literalData.Close(); err != nil {
		return err
	}
	if err := sig.Serialize(s.encryptedData); err != nil {
		return err
	}
	return s.encryptedData.Close()
}

// noOpCloser is like an ioutil.NopCloser, but for an io.Writer.
type noOpCloser struct {
	w io.Writer
}

func (c noOpCloser) Write(data []byte) (n int, err error) {
	return c.w.Write(data)
}

func (c noOpCloser) Close() error {
	return nil
}
