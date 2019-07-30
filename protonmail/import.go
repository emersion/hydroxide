package protonmail

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
)

type ImportResult map[string]ImportMessageResult

func (res ImportResult) Err() error {
	for _, msgRes := range res {
		if msgRes.Err != nil {
			return msgRes.Err
		}
	}
	return nil
}

type ImportMessageResult struct {
	Err       error
	MessageID string
}

type Importer struct {
	pw       *io.PipeWriter
	mw       *multipart.Writer
	uploaded map[string]bool
	closed   bool
	done     <-chan error
	result   <-chan ImportResult
}

func (imp *Importer) ImportMessage(key string) (io.Writer, error) {
	if uploaded, ok := imp.uploaded[key]; !ok {
		return nil, fmt.Errorf("protonmail: unknown import message %q", key)
	} else if uploaded {
		return nil, fmt.Errorf("protonmail: message %q already imported", key)
	}
	imp.uploaded[key] = true

	hdr := make(textproto.MIMEHeader)
	params := map[string]string{
		"name":     key,
		"filename": key + ".eml",
	}
	hdr.Set("Content-Disposition", mime.FormatMediaType("form-data", params))
	hdr.Set("Content-Type", "message/rfc822")
	return imp.mw.CreatePart(hdr)
}

func (imp *Importer) close() error {
	if imp.closed {
		return fmt.Errorf("protonmail: importer already closed")
	}
	imp.closed = true

	if err := imp.mw.Close(); err != nil {
		return err
	}

	return imp.pw.Close()
}

func (imp *Importer) Commit() (ImportResult, error) {
	if err := imp.close(); err != nil {
		return nil, err
	}

	for key, ok := range imp.uploaded {
		if !ok {
			return nil, fmt.Errorf("protonmail: message %q has not been imported", key)
		}
	}

	if err := <-imp.done; err != nil {
		return nil, err
	}

	return <-imp.result, nil
}

func (c *Client) Import(metadata map[string]*Message) (*Importer, error) {
	pr, pw := io.Pipe()

	mw := multipart.NewWriter(pw)

	done := make(chan error, 1)
	result := make(chan ImportResult, 1)
	go func() {
		defer close(done)
		defer close(result)

		req, err := c.newRequest(http.MethodPost, "/import", pr)
		if err != nil {
			done <- err
			return
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())

		type messageResp struct {
			Name     string
			Response struct {
				resp
				MessageID string
			}
		}
		var respData struct {
			resp
			Responses []messageResp
		}
		err = c.doJSON(req, &respData)
		done <- err
		if err != nil {
			return
		}

		res := make(ImportResult, len(respData.Responses))
		for _, msgData := range respData.Responses {
			res[msgData.Name] = ImportMessageResult{
				Err:       msgData.Response.Err(),
				MessageID: msgData.Response.MessageID,
			}
		}
		result <- res
	}()

	// Send metadata
	hdr := make(textproto.MIMEHeader)
	params := map[string]string{"name": "Metadata"}
	hdr.Set("Content-Disposition", mime.FormatMediaType("form-data", params))
	hdr.Set("Content-Type", "application/json")
	metadataWriter, err := mw.CreatePart(hdr)
	if err != nil {
		pw.CloseWithError(fmt.Errorf("protonmail: failed to write metadata"))
		return nil, err
	}
	if err := json.NewEncoder(metadataWriter).Encode(metadata); err != nil {
		pw.CloseWithError(fmt.Errorf("protonmail: failed to write metadata"))
		return nil, err
	}

	uploaded := make(map[string]bool, len(metadata))
	for key := range metadata {
		uploaded[key] = false
	}

	return &Importer{
		pw:       pw,
		mw:       mw,
		uploaded: uploaded,
		done:     done,
		result:   result,
	}, nil
}
