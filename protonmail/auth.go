package protonmail

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type authInfoReq struct {
	ClientID     string
	ClientSecret string
	Username     string
}

type AuthInfo struct {
	TwoFactor       int
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
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Username:     username,
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
	ClientID        string
	ClientSecret    string
	Username        string
	SRPSession      string
	ClientEphemeral string
	ClientProof     string
	TwoFactorCode   string
}

type PasswordMode int

const (
	PasswordSingle PasswordMode = 1
	PasswordTwo                 = 2
)

type Auth struct {
	ExpiresAt    time.Time
	Scope        string
	UID          string `json:"Uid"`
	RefreshToken string
	EventID      string
	PasswordMode PasswordMode

	accessToken string
	privateKey  string
	keySalt     string
}

type authResp struct {
	resp
	Auth
	ExpiresIn   int
	AccessToken string
	TokenType   string
	ServerProof string
	PrivateKey  string
	KeySalt     string
}

func (resp *authResp) auth() *Auth {
	auth := &resp.Auth
	auth.ExpiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	auth.accessToken = resp.AccessToken
	auth.privateKey = resp.PrivateKey
	auth.keySalt = resp.KeySalt
	return auth
}

func (c *Client) Auth(username, password, twoFactorCode string, info *AuthInfo) (*Auth, error) {
	if info == nil {
		var err error
		if info, err = c.AuthInfo(username); err != nil {
			return nil, err
		}
	}

	proofs, err := srp([]byte(password), info)
	if err != nil {
		return nil, err
	}

	reqData := &authReq{
		ClientID:        c.ClientID,
		ClientSecret:    c.ClientSecret,
		Username:        username,
		SRPSession:      info.srpSession,
		ClientEphemeral: base64.StdEncoding.EncodeToString(proofs.clientEphemeral),
		ClientProof:     base64.StdEncoding.EncodeToString(proofs.clientProof),
		TwoFactorCode:   twoFactorCode,
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

	return respData.auth(), nil
}

type authRefreshReq struct {
	ClientID     string
	UID          string `json:"Uid"`
	RefreshToken string

	// Unused but required
	ResponseType string
	GrantType    string
	RedirectURI  string
	State        string
}

func (c *Client) AuthRefresh(expiredAuth *Auth) (*Auth, error) {
	reqData := &authRefreshReq{
		ClientID:     c.ClientID,
		UID:          expiredAuth.UID,
		RefreshToken: expiredAuth.RefreshToken,
	}

	req, err := c.newJSONRequest(http.MethodPost, "/auth/refresh", reqData)
	if err != nil {
		return nil, err
	}

	var respData authResp
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	auth := respData.auth()
	//auth.EventID = expiredAuth.EventID
	auth.PasswordMode = expiredAuth.PasswordMode
	return auth, nil
}

func (c *Client) Unlock(auth *Auth, passphrase string) (openpgp.EntityList, error) {
	passphraseBytes := []byte(passphrase)
	if auth.keySalt != "" {
		keySalt, err := base64.StdEncoding.DecodeString(auth.keySalt)
		if err != nil {
			return nil, err
		}

		passphraseBytes, err = computeKeyPassword(passphraseBytes, keySalt)
		if err != nil {
			return nil, err
		}
	}

	// Read private keys and unlock them

	keyRing, err := openpgp.ReadArmoredKeyRing(strings.NewReader(auth.privateKey))
	if err != nil {
		return nil, err
	}
	if len(keyRing) == 0 {
		return nil, errors.New("auth key ring is empty")
	}

	for _, e := range keyRing {
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
				return nil, err
			}
		}
	}

	// Decrypt access token

	block, err := armor.Decode(strings.NewReader(auth.accessToken))
	if err != nil {
		return nil, err
	}

	msg, err := openpgp.ReadMessage(block.Body, keyRing, nil, nil)
	if err != nil {
		return nil, err
	}

	// TODO: maybe check signature
	accessTokenBytes, err := ioutil.ReadAll(msg.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	c.uid = auth.UID
	c.accessToken = string(accessTokenBytes)
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
