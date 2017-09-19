package protonmail

type Attachment struct {
	ID         string
	Name       string
	Size       int
	MIMEType   string
	KeyPackets string
	//Headers map[string]string
}

type AttachmentKey struct {
	ID   string
	Key  string
	Algo string
}
