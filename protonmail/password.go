package protonmail

import (
	"bytes"
	"crypto/sha512"
	"errors"

	"github.com/emersion/go-bcrypt"
)

const bcryptCost = 10

func hashBcrypt(password, salt []byte) ([]byte, error) {
	hashed, err := bcrypt.GenerateFromPasswordAndSalt(password, bcryptCost, salt)
	if err != nil {
		return nil, err
	}
	hashed = bytes.Replace(hashed, []byte("$2a$"), []byte("$2y$"), 1)
	return hashed, nil
}

func expandHash(b []byte) []byte {
	var expanded []byte
	var part [64]byte

	part = sha512.Sum512(append(b, 0))
	expanded = append(expanded, part[:]...)

	part = sha512.Sum512(append(b, 1))
	expanded = append(expanded, part[:]...)

	part = sha512.Sum512(append(b, 2))
	expanded = append(expanded, part[:]...)

	part = sha512.Sum512(append(b, 3))
	expanded = append(expanded, part[:]...)

	return expanded
}

func hashPassword(version int, password, salt, modulus []byte) ([]byte, error) {
	switch version {
	case 3, 4:
		salt = append(salt, []byte("proton")...)
		hashed, err := hashBcrypt(password, salt)
		if err != nil {
			return nil, err
		}
		return expandHash(append([]byte(hashed), modulus...)), nil
	default:
		return nil, errors.New("unsupported auth version")
	}
}

func computeKeyPassword(password, salt []byte) ([]byte, error) {
	hashed, err := hashBcrypt(password, salt)
	if err != nil {
		return nil, err
	}

	// Remove bcrypt prefix and salt (first 29 characters)
	return hashed[29:], nil
}
