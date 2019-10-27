package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	imapmove "github.com/emersion/go-imap-move"
	imapspacialuse "github.com/emersion/go-imap-specialuse"
	imapserver "github.com/emersion/go-imap/server"
	"github.com/emersion/go-smtp"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/carddav"
	"github.com/emersion/hydroxide/events"
	imapbackend "github.com/emersion/hydroxide/imap"
	"github.com/emersion/hydroxide/imports"
	"github.com/emersion/hydroxide/protonmail"
	smtpbackend "github.com/emersion/hydroxide/smtp"
)

func newClient() *protonmail.Client {
	return &protonmail.Client{
		RootURL:      "https://mail.protonmail.com/api",
		AppVersion:   "Web_3.16.6",
	}
}

func listenAndServeSMTP(addr string, authManager *auth.Manager) error {
	be := smtpbackend.New(authManager)
	s := smtp.NewServer(be)
	s.Addr = addr
	s.Domain = "localhost"     // TODO: make this configurable
	s.AllowInsecureAuth = true // TODO: remove this
	//s.Debug = os.Stdout

	log.Println("SMTP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeIMAP(addr string, authManager *auth.Manager, eventsManager *events.Manager) error {
	be := imapbackend.New(authManager, eventsManager)
	s := imapserver.New(be)
	s.Addr = addr
	s.AllowInsecureAuth = true // TODO: remove this
	//s.Debug = os.Stdout

	s.Enable(imapspacialuse.NewExtension())
	s.Enable(imapmove.NewExtension())

	log.Println("IMAP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeCardDAV(addr string, authManager *auth.Manager, eventsManager *events.Manager) error {
	handlers := make(map[string]http.Handler)

	s := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("WWW-Authenticate", "Basic")

			username, password, ok := req.BasicAuth()
			if !ok {
				resp.WriteHeader(http.StatusUnauthorized)
				io.WriteString(resp, "Credentials are required")
				return
			}

			c, privateKeys, err := authManager.Auth(username, password)
			if err != nil {
				if err == auth.ErrUnauthorized {
					resp.WriteHeader(http.StatusUnauthorized)
				} else {
					resp.WriteHeader(http.StatusInternalServerError)
				}
				io.WriteString(resp, err.Error())
				return
			}

			h, ok := handlers[username]
			if !ok {
				ch := make(chan *protonmail.Event)
				eventsManager.Register(c, username, ch, nil)
				h = carddav.NewHandler(c, privateKeys, ch)

				handlers[username] = h
			}

			h.ServeHTTP(resp, req)
		}),
	}

	log.Println("CardDAV server listening on", s.Addr)
	return s.ListenAndServe()
}

func main() {
	smtpHost := flag.String("smtp-host", "127.0.0.1", "Allowed SMTP email hostname on which hydroxide listens, defaults to 127.0.0.1")
	smtpPort := flag.String("smtp-port", "1025", "SMTP port on which hydroxide listens, defaults to 1025")

	imapHost := flag.String("imap-host", "127.0.0.1", "Allowed IMAP email hostname on which hydroxide listens, defaults to 127.0.0.1")
	imapPort := flag.String("imap-port", "1143", "IMAP port on which hydroxide listens, defaults to 1143")

	carddavHost := flag.String("carddav-host", "127.0.0.1", "Allowed CardDAV email hostname on which hydroxide listens, defaults to 127.0.0.1")
	carddavPort := flag.String("carddav-port", "8080", "CardDAV port on which hydroxide listens, defaults to 8080")

	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	exportSecretKeysCmd := flag.NewFlagSet("export-secret-keys", flag.ExitOnError)
	importMessagesCmd := flag.NewFlagSet("import-messages", flag.ExitOnError)

	flag.Parse()

	cmd := flag.Arg(0)
	switch cmd {
	case "auth":
		authCmd.Parse(os.Args[2:])
		username := authCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: hydroxide auth <username>")
		}

		c := newClient()

		var a *protonmail.Auth
		/*if cachedAuth, ok := auths[username]; ok {
			var err error
			a, err = c.AuthRefresh(a)
			if err != nil {
				// TODO: handle expired token error
				log.Fatal(err)
			}
		}*/

		var loginPassword string
		if a == nil {
			fmt.Printf("Password: ")
			if pass, err := gopass.GetPasswd(); err != nil {
				log.Fatal(err)
			} else {
				loginPassword = string(pass)
			}

			authInfo, err := c.AuthInfo(username)
			if err != nil {
				log.Fatal(err)
			}

			var twoFactorCode string
			if authInfo.TwoFactor == 1 {
				scanner := bufio.NewScanner(os.Stdin)
				fmt.Printf("2FA code: ")
				scanner.Scan()
				twoFactorCode = scanner.Text()
			}

			a, err = c.Auth(username, loginPassword, twoFactorCode, authInfo)
			if err != nil {
				log.Fatal(err)
			}
		}

		var mailboxPassword string
		if a.PasswordMode == protonmail.PasswordSingle {
			mailboxPassword = loginPassword
		}
		if mailboxPassword == "" {
			if a.PasswordMode == protonmail.PasswordTwo {
				fmt.Printf("Mailbox password: ")
			} else {
				fmt.Printf("Password: ")
			}
			if pass, err := gopass.GetPasswd(); err != nil {
				log.Fatal(err)
			} else {
				mailboxPassword = string(pass)
			}
		}

		keySalts, err := c.ListKeySalts()
		if err != nil {
			log.Fatal(err)
		}

		_, err = c.Unlock(a, keySalts, mailboxPassword)
		if err != nil {
			log.Fatal(err)
		}

		secretKey, bridgePassword, err := auth.GeneratePassword()
		if err != nil {
			log.Fatal(err)
		}

		err = auth.EncryptAndSave(&auth.CachedAuth{
			Auth: *a,
			LoginPassword: loginPassword,
			MailboxPassword: mailboxPassword,
			KeySalts: keySalts,
		}, username, secretKey)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Bridge password:", bridgePassword)
	case "status":
		usernames, err := auth.ListUsernames()
		if err != nil {
			log.Fatal(err)
		}

		if len(usernames) == 0 {
			fmt.Printf("No logged in user.\n")
		} else {
			fmt.Printf("%v logged in user(s):\n", len(usernames))
			for _, u := range usernames {
				fmt.Printf("- %v\n", u)
			}
		}
	case "export-secret-keys":
		exportSecretKeysCmd.Parse(os.Args[2:])
		username := exportSecretKeysCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: hydroxide export-secret-keys <username>")
		}

		var bridgePassword string
		fmt.Printf("Bridge password: ")
		if pass, err := gopass.GetPasswd(); err != nil {
			log.Fatal(err)
		} else {
			bridgePassword = string(pass)
		}

		_, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		wc, err := armor.Encode(os.Stdout, openpgp.PrivateKeyType, nil)
		if err != nil {
			log.Fatal(err)
		}

		for _, key := range privateKeys {
			if err := key.SerializePrivate(wc, nil); err != nil {
				log.Fatal(err)
			}
		}

		if err := wc.Close(); err != nil {
			log.Fatal(err)
		}
	case "import-messages":
		// TODO: support for mbox

		importMessagesCmd.Parse(os.Args[2:])
		username := importMessagesCmd.Arg(0)
		archivePath := importMessagesCmd.Arg(1)
		if username == "" || archivePath == "" {
			log.Fatal("usage: hydroxide import-messages <username> <file>")
		}

		f, err := os.Open(archivePath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		var bridgePassword string
		fmt.Printf("Bridge password: ")
		if pass, err := gopass.GetPasswd(); err != nil {
			log.Fatal(err)
		} else {
			bridgePassword = string(pass)
		}

		c, _, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		if err := imports.ImportMessage(c, f); err != nil {
			log.Fatal(err)
		}
	case "smtp":
		addr := *smtpHost + ":" + *smtpPort
		authManager := auth.NewManager(newClient)
		log.Fatal(listenAndServeSMTP(addr, authManager))
	case "imap":
		addr := *imapHost + ":" + *imapPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeIMAP(addr, authManager, eventsManager))
	case "carddav":
		addr := *carddavHost + ":" + *carddavPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCardDAV(addr, authManager, eventsManager))
	case "serve":
		smtpAddr := *smtpHost + ":" + *smtpPort
		imapAddr := *imapHost + ":" + *imapPort
		carddavAddr := *carddavHost + ":" + *carddavPort

		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()

		done := make(chan error, 3)
		go func() {
			done <- listenAndServeSMTP(smtpAddr, authManager)
		}()
		go func() {
			done <- listenAndServeIMAP(imapAddr, authManager, eventsManager)
		}()
		go func() {
			done <- listenAndServeCardDAV(carddavAddr, authManager, eventsManager)
		}()
		log.Fatal(<-done)
	default:
		log.Println(`usage: hydroxide <command> <flags>
Commands:
	auth <username>		Login to ProtonMail via hydroxide
	carddav			Run hydroxide as a CardDAV server
	export-secret-keys <username> Export secret keys
	imap			Run hydroxide as an IMAP server
	import-messages <username> <file>	Import messages
	serve			Run all servers
	smtp			Run hydroxide as an SMTP server
	status			View hydroxide status

Flags:
	-smtp-host example.com
		Allowed SMTP email hostname on which hydroxide listens, defaults to 127.0.0.1
	-imap-host example.com
		Allowed IMAP email hostname on which hydroxide listens, defaults to 127.0.0.1
	-carddav-host example.com
		Allowed SMTP email hostname on which hydroxide listens, defaults to 127.0.0.1
	-smtp-port example.com
		SMTP port on which hydroxide listens, defaults to 1025
	-imap-port example.com
		IMAP port on which hydroxide listens, defaults to 1143
	-carddav-port example.com
		CardDAV port on which hydroxide listens, defaults to 8080`)
		if cmd != "help" {
			log.Fatal("Unrecognized command")
		}
	}
}
