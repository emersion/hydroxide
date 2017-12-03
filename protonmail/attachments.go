package protonmail

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

type AttachmentKey struct {
	ID   string
	Key  string
	Algo string
}

type Attachment struct {
	ID         string
	MessageID  string
	Name       string
	Size       int
	MIMEType   string
	ContentID  string
	KeyPackets string // encrypted with the user's key, base64-encoded
	//Headers    map[string]string
	Signature  string
}

// GetAttachment downloads an attachment's payload. The returned io.ReadCloser
// may be encrypted.
func (c *Client) GetAttachment(id string) (io.ReadCloser, error) {
	req, err := c.newRequest(http.MethodGet, "/attachments/"+id, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("cannot get attachment %q: %v %v", id, resp.Status, resp.StatusCode)
	}

	return resp.Body, nil
}

// CreateAttachment uploads a new attachment. r must be an PGP data packet
// encrypted with att.KeyPackets.
func (c *Client) CreateAttachment(att *Attachment, r io.Reader) (created *Attachment, err error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	go func() {
		if err := mw.WriteField("Filename", att.Name); err != nil {
			pw.CloseWithError(err)
			return
		}

		if err := mw.WriteField("MessageID", att.MessageID); err != nil {
			pw.CloseWithError(err)
			return
		}

		if err := mw.WriteField("MIMEType", att.MIMEType); err != nil {
			pw.CloseWithError(err)
			return
		}

		if att.ContentID != "" {
			if err := mw.WriteField("ContentID", att.ContentID); err != nil {
				pw.CloseWithError(err)
				return
			}
		}

		if w, err := mw.CreateFormFile("KeyPackets", "KeyPackets.pgp"); err != nil {
			pw.CloseWithError(err)
			return
		} else {
			kpr := base64.NewDecoder(base64.StdEncoding, strings.NewReader(att.KeyPackets))
			if _, err := io.Copy(w, kpr); err != nil {
				pw.CloseWithError(err)
				return
			}
		}

		if w, err := mw.CreateFormFile("DataPackets", "DataPackets.pgp"); err != nil {
			pw.CloseWithError(err)
			return
		} else if _, err := io.Copy(w, r); err != nil {
			pw.CloseWithError(err)
			return
		}

		// TODO: Signature

		if err := mw.Close(); err != nil {
			pw.CloseWithError(err)
		}
		pw.Close()
	}()

	req, err := c.newRequest(http.MethodPost, "/attachments", pr)
	if err != nil {
		return nil, err
	}

	params := map[string]string{"boundary": mw.Boundary()}
	req.Header.Set("Content-Type", mime.FormatMediaType("multipart/form-data", params))

	var respData struct {
		resp
		Attachment *Attachment
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Attachment, nil
}
