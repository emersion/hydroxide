package protonmail

type (
	AddressSend   int
	AddressStatus int
	AddressType   int
)

const (
	AddressSendDisabled AddressSend = iota
	AddressSendPrimary
	AddressSendSecondary
)

const (
	AddressDisabled AddressStatus = iota
	AddressEnabled
)

const (
	AddressOriginal AddressType = iota
	AddressAlias
	AddressCustom
)

type Address struct {
	ID          string
	DomainID    string
	Email       string
	Send        AddressSend
	Receive     int
	Status      AddressStatus
	Type        AddressType
	Order       int
	DisplayName string
	Signature   string // HTML
	HasKeys     int
	Keys        []*PrivateKey
}
