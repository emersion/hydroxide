package protonmail

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type authInfoReq struct {
	Username string
}

type AuthInfo struct {
	version         int
	modulus         string
	serverEphemeral string
	salt            string
	srpSession      string
}

type AuthInfoResp struct {
	resp
	AuthInfo
	Version         int
	Modulus         string
	ServerEphemeral string
	Salt            string
	SRPSession      string
}

func (resp *AuthInfoResp) authInfo() *AuthInfo {
	info := &resp.AuthInfo
	info.version = resp.Version
	info.modulus = resp.Modulus
	info.serverEphemeral = resp.ServerEphemeral
	info.salt = resp.Salt
	info.srpSession = resp.SRPSession
	return info
}

func (c *Client) AuthInfo(username string) (*AuthInfo, error) {
	reqData := &authInfoReq{
		Username: username,
	}

	req, err := c.newJSONRequest(http.MethodPost, "/auth/info", reqData)
	if err != nil {
		return nil, err
	}

	var respData AuthInfoResp
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.authInfo(), nil
}

type authReq struct {
	Username        string
	SRPSession      string
	ClientEphemeral string
	ClientProof     string
}

type PasswordMode int

const (
	PasswordSingle PasswordMode = 1
	PasswordTwo                 = 2
)

type Auth struct {
	ExpiresAt    time.Time
	Scope        string
	UID          string
	AccessToken  string
	RefreshToken string
	UserID       string
	EventID      string
	PasswordMode PasswordMode
	TwoFactor    struct {
		Enabled int
		U2F     interface{} // TODO
		TOTP    int
	} `json:"2FA"`
}

type authResp struct {
	resp
	Auth
	ExpiresIn   int
	TokenType   string
	ServerProof string
}

func (resp *authResp) auth() *Auth {
	auth := &resp.Auth
	auth.ExpiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	return auth
}

func (c *Client) Auth(username, password string, info *AuthInfo) (*Auth, error) {
	if info == nil {
		var err error
		if info, err = c.AuthInfo(username); err != nil {
			return nil, err
		}
	}

	proofs, err := srp([]byte(password), info)
	if err != nil {
		return nil, fmt.Errorf("SRP failed during auth: %v", err)
	}

	reqData := &authReq{
		Username:        username,
		SRPSession:      info.srpSession,
		ClientEphemeral: base64.StdEncoding.EncodeToString(proofs.clientEphemeral),
		ClientProof:     base64.StdEncoding.EncodeToString(proofs.clientProof),
	}

	req, err := c.newJSONRequest(http.MethodPost, "/auth", reqData)
	if err != nil {
		return nil, err
	}

	var respData authResp
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	if err := proofs.VerifyServerProof(respData.ServerProof); err != nil {
		return nil, err
	}

	auth := respData.auth()
	c.uid = auth.UID
	c.accessToken = auth.AccessToken
	return auth, nil
}

func (c *Client) AuthTOTP(code string) (scope string, err error) {
	reqData := struct {
		TwoFactorCode string
	}{
		TwoFactorCode: code,
	}

	req, err := c.newJSONRequest(http.MethodPost, "/auth/2fa", reqData)
	if err != nil {
		return "", err
	}

	respData := struct {
		resp
		Scope string
	}{}
	if err := c.doJSON(req, &respData); err != nil {
		return "", err
	}

	return respData.Scope, nil
}

type authRefreshReq struct {
	RefreshToken string

	// Unused but required
	ResponseType string
	GrantType    string
	RedirectURI  string
}

func (c *Client) AuthRefresh(expiredAuth *Auth) (*Auth, error) {
	reqData := &authRefreshReq{
		RefreshToken: expiredAuth.RefreshToken,
		ResponseType: "token",
		GrantType:    "refresh_token",
		RedirectURI:  "http://www.protonmail.ch",
	}

	req, err := c.newJSONRequest(http.MethodPost, "/auth/refresh", reqData)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Pm-Uid", expiredAuth.UID)

	var respData authResp
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	auth := respData.auth()
	//auth.EventID = expiredAuth.EventID
	auth.PasswordMode = expiredAuth.PasswordMode
	return auth, nil
}

func (c *Client) ListKeySalts() (map[string][]byte, error) {
	req, err := c.newRequest(http.MethodGet, "/keys/salts", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		KeySalts []struct {
			ID      string
			KeySalt string
		}
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	salts := make(map[string][]byte, len(respData.KeySalts))
	for _, salt := range respData.KeySalts {
		if salt.KeySalt == "" {
			salts[salt.ID] = nil
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(salt.KeySalt)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key salt payload: %v", err)
		}
		salts[salt.ID] = payload
	}

	return salts, nil
}

func unlockKey(e *openpgp.Entity, passphraseBytes []byte) error {
	var privateKeys []*packet.PrivateKey

	// e.PrivateKey is a signing key
	if e.PrivateKey != nil {
		privateKeys = append(privateKeys, e.PrivateKey)
	}

	// e.Subkeys are encryption keys
	for _, subkey := range e.Subkeys {
		if subkey.PrivateKey != nil {
			privateKeys = append(privateKeys, subkey.PrivateKey)
		}
	}

	for _, priv := range privateKeys {
		if err := priv.Decrypt(passphraseBytes); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) Unlock(auth *Auth, keySalts map[string][]byte, passphrase string) (openpgp.EntityList, error) {
	c.uid = auth.UID
	c.accessToken = auth.AccessToken

	addrs, err := c.ListAddresses()
	if err != nil {
		return nil, err
	}

	var keyRing openpgp.EntityList
	for _, addr := range addrs {
		for _, key := range addr.Keys {
			entity, err := key.Entity()
			if err != nil {
				log.Printf("warning: failed to read key %q: %v", addr.Email, err)
				continue
			}

			passphraseBytes := []byte(passphrase)
			if keySalt, ok := keySalts[key.ID]; ok && keySalt != nil {
				passphraseBytes, err = computeKeyPassword(passphraseBytes, keySalt)
				if err != nil {
					return nil, err
				}
			}

			if err := unlockKey(entity, passphraseBytes); err != nil {
				log.Printf("warning: failed to unlock key %q %v: %v", addr.Email, entity.PrimaryKey.KeyIdString(), err)
				continue
			}

			keyRing = append(keyRing, entity)
		}
	}

	if len(keyRing) == 0 {
		return nil, fmt.Errorf("failed to unlock any key")
	}

	c.keyRing = keyRing

	return keyRing, nil
}

func (c *Client) Logout() error {
	req, err := c.newRequest(http.MethodDelete, "/auth", nil)
	if err != nil {
		return err
	}

	if err := c.doJSON(req, nil); err != nil {
		return err
	}

	c.uid = ""
	c.accessToken = ""
	c.keyRing = nil
	return nil
}
