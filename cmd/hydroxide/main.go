package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	imapmove "github.com/emersion/go-imap-move"
	imapspacialuse "github.com/emersion/go-imap-specialuse"
	imapserver "github.com/emersion/go-imap/server"
	"github.com/emersion/go-mbox"
	"github.com/emersion/go-smtp"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/carddav"
	"github.com/emersion/hydroxide/events"
	"github.com/emersion/hydroxide/exports"
	imapbackend "github.com/emersion/hydroxide/imap"
	"github.com/emersion/hydroxide/imports"
	"github.com/emersion/hydroxide/protonmail"
	smtpbackend "github.com/emersion/hydroxide/smtp"
)

var debug bool

func newClient() *protonmail.Client {
	return &protonmail.Client{
		RootURL:    "https://mail.protonmail.com/api",
		AppVersion: "Web_3.16.6",
		Debug:      debug,
	}
}

func listenAndServeSMTP(addr string, debug bool, authManager *auth.Manager) error {
	be := smtpbackend.New(authManager)
	s := smtp.NewServer(be)
	s.Addr = addr
	s.Domain = "localhost"     // TODO: make this configurable
	s.AllowInsecureAuth = true // TODO: remove this
	if debug {
		s.Debug = os.Stdout
	}

	log.Println("SMTP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeIMAP(addr string, debug bool, authManager *auth.Manager, eventsManager *events.Manager) error {
	be := imapbackend.New(authManager, eventsManager)
	s := imapserver.New(be)
	s.Addr = addr
	s.AllowInsecureAuth = true // TODO: remove this
	if debug {
		s.Debug = os.Stdout
	}

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

func isMbox(br *bufio.Reader) (bool, error) {
	prefix := []byte("From ")
	b, err := br.Peek(len(prefix))
	if err != nil {
		return false, err
	}
	return bytes.Equal(b, prefix), nil
}

const usage = `usage: hydroxide [options...] <command>
Commands:
	auth <username>		Login to ProtonMail via hydroxide
	carddav			Run hydroxide as a CardDAV server
	export-secret-keys <username> Export secret keys
	imap			Run hydroxide as an IMAP server
	import-messages <username> <file>	Import messages
	export-messages [options...] <username>	Export messages
	serve			Run all servers
	smtp			Run hydroxide as an SMTP server
	status			View hydroxide status

Global options:
	-debug
		Enable debug logs
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
		CardDAV port on which hydroxide listens, defaults to 8080`

func main() {
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")

	smtpHost := flag.String("smtp-host", "127.0.0.1", "Allowed SMTP email hostname on which hydroxide listens, defaults to 127.0.0.1")
	smtpPort := flag.String("smtp-port", "1025", "SMTP port on which hydroxide listens, defaults to 1025")

	imapHost := flag.String("imap-host", "127.0.0.1", "Allowed IMAP email hostname on which hydroxide listens, defaults to 127.0.0.1")
	imapPort := flag.String("imap-port", "1143", "IMAP port on which hydroxide listens, defaults to 1143")

	carddavHost := flag.String("carddav-host", "127.0.0.1", "Allowed CardDAV email hostname on which hydroxide listens, defaults to 127.0.0.1")
	carddavPort := flag.String("carddav-port", "8080", "CardDAV port on which hydroxide listens, defaults to 8080")

	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	exportSecretKeysCmd := flag.NewFlagSet("export-secret-keys", flag.ExitOnError)
	importMessagesCmd := flag.NewFlagSet("import-messages", flag.ExitOnError)
	exportMessagesCmd := flag.NewFlagSet("export-messages", flag.ExitOnError)

	flag.Parse()

	cmd := flag.Arg(0)
	switch cmd {
	case "auth":
		authCmd.Parse(flag.Args()[1:])
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

			a, err = c.Auth(username, loginPassword, authInfo)
			if err != nil {
				log.Fatal(err)
			}

			if a.TwoFactor.Enabled == 1 {
				if a.TwoFactor.TOTP != 1 {
					log.Fatal("Only TOTP is supported as a 2FA method")
				}

				scanner := bufio.NewScanner(os.Stdin)
				fmt.Printf("2FA TOTP code: ")
				scanner.Scan()
				code := scanner.Text()

				scope, err := c.AuthTOTP(code)
				if err != nil {
					log.Fatal(err)
				}
				a.Scope = scope
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
			Auth:            *a,
			LoginPassword:   loginPassword,
			MailboxPassword: mailboxPassword,
			KeySalts:        keySalts,
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
		exportSecretKeysCmd.Parse(flag.Args()[1:])
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
		importMessagesCmd.Parse(flag.Args()[1:])
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

		br := bufio.NewReader(f)
		if ok, err := isMbox(br); err != nil {
			log.Fatal(err)
		} else if ok {
			mr := mbox.NewReader(br)
			for {
				r, err := mr.NextMessage()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Fatal(err)
				}
				if err := imports.ImportMessage(c, r); err != nil {
					log.Fatal(err)
				}
			}
		} else {
			if err := imports.ImportMessage(c, br); err != nil {
				log.Fatal(err)
			}
		}
	case "export-messages":
		// TODO: allow specifying multiple IDs
		var convID, msgID string
		exportMessagesCmd.StringVar(&convID, "conversation-id", "", "conversation ID")
		exportMessagesCmd.StringVar(&msgID, "message-id", "", "message ID")
		exportMessagesCmd.Parse(flag.Args()[1:])
		username := exportMessagesCmd.Arg(0)
		if (convID == "" && msgID == "") || username == "" {
			log.Fatal("usage: hydroxide export-messages [-conversation-id <id>] [-message-id <id>] <username>")
		}

		var bridgePassword string
		fmt.Fprintf(os.Stderr, "Bridge password: ")
		if pass, err := gopass.GetPasswd(); err != nil {
			log.Fatal(err)
		} else {
			bridgePassword = string(pass)
		}

		c, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		mboxWriter := mbox.NewWriter(os.Stdout)

		if convID != "" {
			if err := exports.ExportConversationMbox(c, privateKeys, mboxWriter, convID); err != nil {
				log.Fatal(err)
			}
		}
		if msgID != "" {
			if err := exports.ExportMessageMbox(c, privateKeys, mboxWriter, msgID); err != nil {
				log.Fatal(err)
			}
		}

		if err := mboxWriter.Close(); err != nil {
			log.Fatal(err)
		}
	case "smtp":
		addr := *smtpHost + ":" + *smtpPort
		authManager := auth.NewManager(newClient)
		log.Fatal(listenAndServeSMTP(addr, debug, authManager))
	case "imap":
		addr := *imapHost + ":" + *imapPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeIMAP(addr, debug, authManager, eventsManager))
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
			done <- listenAndServeSMTP(smtpAddr, debug, authManager)
		}()
		go func() {
			done <- listenAndServeIMAP(imapAddr, debug, authManager, eventsManager)
		}()
		go func() {
			done <- listenAndServeCardDAV(carddavAddr, authManager, eventsManager)
		}()
		log.Fatal(<-done)
	default:
		log.Println(usage)
		if cmd != "help" {
			log.Fatal("Unrecognized command")
		}
	}
}
