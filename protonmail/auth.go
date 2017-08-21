package protonmail

import (
	"encoding/base64"
	"net/http"

	"log"
)

type authInfoReq struct {
	ClientID string
	ClientSecret string
	Username string
}

type AuthInfoResp struct {
	resp
	Version int
	TwoFactor int
	Modulus string
	ServerEphemeral string
	Salt string
	SRPSession string
}

type AuthInfo struct {
	TwoFactor int
	version int
	modulus string
	serverEphemeral string
	salt string
	srpSession string
}

func (c *Client) AuthInfo(username string) (*AuthInfo, error) {
	reqData := &authInfoReq{
		ClientID: c.ClientID,
		ClientSecret: c.ClientSecret,
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

	return &AuthInfo{
		TwoFactor: respData.TwoFactor,
		version: respData.Version,
		modulus: respData.Modulus,
		serverEphemeral: respData.ServerEphemeral,
		salt: respData.Salt,
		srpSession: respData.SRPSession,
	}, nil
}

type authReq struct {
	ClientID string
	ClientSecret string
	Username string
	SRPSession string
	ClientEphemeral string
	ClientProof string
	TwoFactorCode string
}

type PasswordMode int

const (
	PasswordSingle PasswordMode = 1
	PasswordTwo = 2
)

type authResp struct {
	resp
	AccessToken string
	ExpiresIn int
	TokenType string
	Scope string
	UID string `json:"Uid"`
	RefreshToken string
	EventID string
	ServerProof string
	PasswordMode PasswordMode
	PrivateKey string
	KeySalt string
}

func (c *Client) Auth(username, password, twoFactorCode string, info *AuthInfo) error {
	if info == nil {
		var err error
		if info, err = c.AuthInfo(username); err != nil {
			return err
		}
	}

	log.Printf("%#v\n", info)

	proofs, err := srp([]byte(password), info)
	if err != nil {
		return err
	}

	reqData := &authReq{
		ClientID: c.ClientID,
		ClientSecret: c.ClientSecret,
		Username: username,
		SRPSession: info.srpSession,
		ClientEphemeral: base64.StdEncoding.EncodeToString(proofs.clientEphemeral),
		ClientProof: base64.StdEncoding.EncodeToString(proofs.clientProof),
		TwoFactorCode: twoFactorCode,
	}
	log.Printf("%#v\n", reqData)

	req, err := c.newJSONRequest(http.MethodPost, "/auth", reqData)
	if err != nil {
		return err
	}

	var respData authResp
	if err := c.doJSON(req, &respData); err != nil {
		return err
	}

	log.Printf("%#v\n", respData)

	if err := proofs.VerifyServerProof(respData.ServerProof); err != nil {
		return err
	}

	return nil
}
