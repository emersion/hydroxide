package protonmail

type Key struct {
	ID string
	Version int
	PublicKey string
	PrivateKey string
	Fingerprint string
	Activation interface{} // TODO
}
