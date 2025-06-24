package protonmail

import (
	"encoding/json"
	"net/http"
	"strings"
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

// LabelPath is a custom type that can unmarshal both string and []string
type LabelPath []string

func (lp *LabelPath) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as []string first
	var slice []string
	if err := json.Unmarshal(data, &slice); err == nil {
		*lp = LabelPath(slice)
		return nil
	}
	
	// If that fails, try to unmarshal as string
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	
	// Convert string to slice, handling different possible formats
	if str == "" {
		*lp = LabelPath([]string{})
	} else {
		// Split by common delimiters that might be used in paths
		parts := strings.Split(str, "/")
		*lp = LabelPath(parts)
	}
	
	return nil
}

type Label struct {
	ID        string
	ParentID  string    `json:"ParentID,omitempty"`
	Path      LabelPath `json:"Path,omitempty"`
	Name      string
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
