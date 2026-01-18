package protonmail

import (
	"net/http"
)

const (
	LabelInbox    = "0"
	LabelAllDraft = "1"
	LabelAllSent  = "2"
	LabelTrash    = "3"
	LabelSpam     = "4"
	LabelAllMail  = "5"
	LabelArchive  = "6"
	LabelSent     = "7"
	LabelDraft    = "8"
	LabelStarred  = "10"
)

type LabelType int

const (
	LabelMessage LabelType = 1
	LabelContact LabelType = 2
)

type Label struct {
	ID        string
	Name      string
	Path      string
	Color     string
	Display   int
	Type      LabelType
	Exclusive int
	Notify    int
	Order     int
}

func (c *Client) ListLabels() ([]*Label, error) {
	req, err := c.newRequest(http.MethodGet, "/labels", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Labels []*Label
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Labels, nil
}
