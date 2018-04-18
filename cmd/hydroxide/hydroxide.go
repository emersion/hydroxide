package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	imapmove "github.com/emersion/go-imap-move"
	imapserver "github.com/emersion/go-imap/server"
	imapspacialuse "github.com/emersion/go-imap-specialuse"
	"github.com/emersion/go-smtp"
	"github.com/howeyc/gopass"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/carddav"
	"github.com/emersion/hydroxide/events"
	"github.com/emersion/hydroxide/protonmail"
	imapbackend "github.com/emersion/hydroxide/imap"
	smtpbackend "github.com/emersion/hydroxide/smtp"
)

func newClient() *protonmail.Client {
	return &protonmail.Client{
		RootURL:      "https://dev.protonmail.com/api",
		AppVersion:   "Web_3.12.45",
		ClientID:     "Web",
		ClientSecret: "4957cc9a2e0a2a49d02475c9d013478d",
	}
}

func receiveEvents(c *protonmail.Client, ch chan<- *protonmail.Event) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()

	var last string
	for range t.C {
		event, err := c.GetEvent(last)
		if err != nil {
			log.Println("Cannot receive event:", err)
			continue
		}

		if event.ID == last {
			continue
		}
		last = event.ID

		ch <- event
	}
}

func main() {
	flag.Parse()

	switch flag.Arg(0) {
	case "auth":
		username := flag.Arg(1)

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

		_, err := c.Unlock(a, mailboxPassword)
		if err != nil {
			log.Fatal(err)
		}

		secretKey, bridgePassword, err := auth.GeneratePassword()
		if err != nil {
			log.Fatal(err)
		}

		err = auth.EncryptAndSave(&auth.CachedAuth{
			*a,
			loginPassword,
			mailboxPassword,
		}, username, secretKey)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Bridge password:", bridgePassword)
	case "smtp":
		port := os.Getenv("PORT")
		if port == "" {
			port = "1025"
		}

		sessions := auth.NewManager(newClient)

		be := smtpbackend.New(sessions)
		s := smtp.NewServer(be)
		s.Addr = "127.0.0.1:" + port
		s.Domain = "localhost"     // TODO: make this configurable
		s.AllowInsecureAuth = true // TODO: remove this
		//s.Debug = os.Stdout

		log.Println("Starting SMTP server at", s.Addr)
		log.Fatal(s.ListenAndServe())
	case "imap":
		port := os.Getenv("PORT")
		if port == "" {
			port = "1143"
		}

		sessions := auth.NewManager(newClient)
		eventsManager := events.NewManager()

		be := imapbackend.New(sessions, eventsManager)
		s := imapserver.New(be)
		s.Addr = "127.0.0.1:" + port
		s.AllowInsecureAuth = true // TODO: remove this
		//s.Debug = os.Stdout
		s.Enable(imapspacialuse.NewExtension())
		s.Enable(imapmove.NewExtension())

		log.Println("Starting IMAP server at", s.Addr)
		log.Fatal(s.ListenAndServe())
	case "carddav":
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}

		sessions := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		handlers := make(map[string]http.Handler)

		s := &http.Server{
			Addr: "127.0.0.1:" + port,
			Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
				resp.Header().Set("WWW-Authenticate", "Basic")

				username, password, ok := req.BasicAuth()
				if !ok {
					resp.WriteHeader(http.StatusUnauthorized)
					io.WriteString(resp, "Credentials are required")
					return
				}

				c, privateKeys, err := sessions.Auth(username, password)
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

		log.Println("Starting CardDAV server at", s.Addr)
		log.Fatal(s.ListenAndServe())
	default:
		log.Fatal("usage: hydroxide carddav")
		log.Fatal("usage: hydroxide smtp")
		log.Fatal("usage: hydroxide auth <username>")
	}
}
