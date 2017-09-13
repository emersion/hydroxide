package protonmail

type (
	AddressSend   int
	AddressStatus int
	AddressType   int
)

type Address struct {
	ID          string
	DomainID    string
	Email       string
	Send        AddressSend
	Receive     int
	Status      AddressStatus
	Type        AddressType
	DisplayName string
	Signature   string // HTML
	HasKeys     int
	Keys        []*Key
}
