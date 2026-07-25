package protonmail

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

var randReader io.Reader = rand.Reader

// Public key for SRP verification
// From https://github.com/ProtonMail/proton-bridge/blob/99721b6577fe9079ac7547f11fc77e5090cdd31b/pkg/srp/srp.go#L41-L52
const modulusPubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----`

func decodeModulus(msg string) ([]byte, error) {
	block, _ := clearsign.Decode([]byte(msg))
	if block == nil {
		return nil, errors.New("invalid SRP modulus signed PGP block")
	}

	modulusKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(modulusPubkey)))
	if err != nil {
		return nil, fmt.Errorf("cannot read modulus pubkey: %v", err)
	}

	_, err = openpgp.CheckDetachedSignature(modulusKeyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to check modulus signature: %v", err)
	}

	b, err := base64.StdEncoding.DecodeString(string(block.Plaintext))
	if err != nil {
		return nil, fmt.Errorf("malformed SRP modulus: %v", err)
	}

	return b, nil
}

func reverse(b []byte) {
	for i := 0; i < len(b)/2; i++ {
		j := len(b) - 1 - i
		b[i], b[j] = b[j], b[i]
	}
}

func itoa(i *big.Int, l int) []byte {
	b := i.Bytes()
	reverse(b)
	padding := make([]byte, l/8-len(b))
	b = append(b, padding...)
	return b
}

func atoi(b []byte) *big.Int {
	reverse(b)
	return big.NewInt(0).SetBytes(b)
}

type proofs struct {
	clientEphemeral     []byte
	clientProof         []byte
	expectedServerProof []byte
}

// From https://github.com/ProtonMail/WebClient/blob/public/src/app/authentication/services/srp.js#L13
func generateProofs(l int, hash func([]byte) []byte, modulusBytes, hashedBytes, serverEphemeralBytes []byte) (*proofs, error) {
	generator := big.NewInt(2)

	multiplier := atoi(hash(append(itoa(generator, l), modulusBytes...)))
	modulus := atoi(modulusBytes)
	hashed := atoi(hashedBytes)
	serverEphemeral := atoi(serverEphemeralBytes)

	modulusMinusOne := big.NewInt(0).Sub(modulus, big.NewInt(1))
	if modulus.BitLen() != l {
		return nil, errors.New("SRP modulus has incorrect size")
	}

	multiplier = multiplier.Mod(multiplier, modulus)

	if multiplier.Cmp(big.NewInt(1)) <= 0 || multiplier.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("SRP multiplier is out of bounds")
	}
	if generator.Cmp(big.NewInt(1)) <= 0 || generator.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("SRP generator is out of bounds")
	}
	if serverEphemeral.Cmp(big.NewInt(1)) <= 0 || serverEphemeral.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("SRP server ephemeral is out of bounds")
	}

	// TODO: Check primality
	// TODO: Check safe primality

	var clientSecret, clientEphemeral, scramblingParam *big.Int
	for {
		for {
			var err error
			clientSecret, err = rand.Int(randReader, modulusMinusOne)
			if err != nil {
				return nil, err
			}

			if clientSecret.Cmp(big.NewInt(int64(l)*2)) <= 0 { // Very unlikely
				continue
			}
			break
		}

		clientEphemeral = big.NewInt(0).Exp(generator, clientSecret, modulus)
		scramblingParam = atoi(hash(append(itoa(clientEphemeral, l), itoa(serverEphemeral, l)...)))
		if scramblingParam.Cmp(big.NewInt(0)) == 0 { // Very unlikely
			continue
		}
		break
	}

	subtracted := big.NewInt(0).Sub(serverEphemeral, big.NewInt(0).Mod(big.NewInt(0).Mul(big.NewInt(0).Exp(generator, hashed, modulus), multiplier), modulus))
	if subtracted.Cmp(big.NewInt(0)) < 0 {
		subtracted.Add(subtracted, modulus)
	}
	exponent := big.NewInt(0).Mod(big.NewInt(0).Add(big.NewInt(0).Mul(scramblingParam, hashed), clientSecret), modulusMinusOne)
	sharedSession := big.NewInt(0).Exp(subtracted, exponent, modulus)

	var clientProof []byte
	clientProof = append(clientProof, itoa(clientEphemeral, l)...)
	clientProof = append(clientProof, itoa(serverEphemeral, l)...)
	clientProof = append(clientProof, itoa(sharedSession, l)...)
	clientProof = hash(clientProof)

	var serverProof []byte
	serverProof = append(serverProof, itoa(clientEphemeral, l)...)
	serverProof = append(serverProof, clientProof...)
	serverProof = append(serverProof, itoa(sharedSession, l)...)
	serverProof = hash(serverProof)

	return &proofs{
		clientEphemeral:     itoa(clientEphemeral, l),
		clientProof:         clientProof,
		expectedServerProof: serverProof,
	}, nil
}

func (p *proofs) VerifyServerProof(serverProofString string) error {
	serverProof, err := base64.StdEncoding.DecodeString(serverProofString)
	if err != nil {
		return fmt.Errorf("malformed SRP server proof: %v", err)
	}

	if subtle.ConstantTimeCompare(p.expectedServerProof, serverProof) != 1 {
		return errors.New("invalid SRP server proof")
	}
	return nil
}

// From https://github.com/ProtonMail/WebClient/blob/public/src/app/authentication/services/srp.js#L135
func srp(password []byte, info *AuthInfo) (*proofs, error) {
	modulus, err := decodeModulus(info.modulus)
	if err != nil {
		return nil, err
	}

	serverEphemeral, err := base64.StdEncoding.DecodeString(info.serverEphemeral)
	if err != nil {
		return nil, fmt.Errorf("malformed SRP server ephemeral: %v", err)
	}

	salt, err := base64.StdEncoding.DecodeString(info.salt)
	if err != nil {
		return nil, fmt.Errorf("malformed SRP salt: %v", err)
	}

	hashed, err := hashPassword(info.version, password, salt, modulus)
	if err != nil {
		return nil, err
	}

	proofs, err := generateProofs(2048, expandHash, modulus, hashed, serverEphemeral)
	if err != nil {
		return nil, err
	}

	return proofs, nil
}
