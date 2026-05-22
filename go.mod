module github.com/emersion/hydroxide

go 1.23.0

require (
	github.com/boltdb/bolt v1.3.1
	github.com/emersion/go-bcrypt v0.0.0-20170822072041-6e724a1baa63
	github.com/emersion/go-ical v0.0.0-20240127095438-fc1c9d8fb2b6
	github.com/emersion/go-imap v1.0.5
	github.com/emersion/go-imap-move v0.0.0-20190710073258-6e5a51a5b342
	github.com/emersion/go-imap-specialuse v0.0.0-20200722111535-598ff00e4075
	github.com/emersion/go-mbox v1.0.1
	github.com/emersion/go-message v0.12.0
	github.com/emersion/go-smtp v0.14.0
	github.com/emersion/go-vcard v0.0.0-20230815062825-8fda7d206ec9
	github.com/emersion/go-webdav v0.7.0
	github.com/howeyc/gopass v0.0.0-20190910152052-7cb4b85ec19c
	golang.org/x/crypto v0.41.0
)

require (
	github.com/emersion/go-sasl v0.0.0-20200509203442-7bfe0ed36a21 // indirect
	github.com/emersion/go-textwrapper v0.0.0-20200911093747-65d896831594 // indirect
	github.com/martinlindhe/base36 v1.1.0 // indirect
	github.com/stretchr/testify v1.4.0 // indirect
	github.com/teambition/rrule-go v1.8.2 // indirect
	golang.org/x/sys v0.0.0-20190412213103-97732733099d // indirect
	golang.org/x/text v0.3.3 // indirect
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20200605105621-11f6ee2dd602
