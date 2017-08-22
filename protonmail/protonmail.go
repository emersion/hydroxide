// Package protonmail implements a ProtonMail API client.
package protonmail

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/crypto/openpgp"
)

const Version = 3

const headerAPIVersion = "X-Pm-Apiversion"

type resp struct {
	Code int
	*apiError
}

func (r *resp) Err() error {
	if err := r.apiError; err != nil {
		return r.apiError
	}
	return nil
}

type maybeError interface {
	Err() error
}

type apiError struct {
	Message string `json:"Error"`
}

func (err apiError) Error() string {
	return err.Message
}

// Client is a ProtonMail API client.
type Client struct {
	RootURL    string
	AppVersion string

	ClientID     string
	ClientSecret string

	HTTPClient *http.Client

	uid string
	accessToken string
	keyRing openpgp.EntityList
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.RootURL+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Pm-Appversion", c.AppVersion)
	req.Header.Set(headerAPIVersion, strconv.Itoa(Version))

	if c.uid != "" && c.accessToken != "" {
		req.Header.Set("X-Pm-Uid", c.uid)
		req.Header.Set("Authorization", "Bearer " + c.accessToken)
	}

	return req, nil
}

func (c *Client) newJSONRequest(method, path string, body interface{}) (*http.Request, error) {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(body); err != nil {
		return nil, err
	}
	req, err := c.newRequest(method, path, &b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return httpClient.Do(req)
}

func (c *Client) doJSON(req *http.Request, respData interface{}) error {
	req.Header.Set("Accept", "application/json")

	if respData == nil {
		respData = new(resp)
	}

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
		return err
	}

	if maybeError, ok := respData.(maybeError); ok {
		if err := maybeError.Err(); err != nil {
			return err
		}
	}
	return nil
}
