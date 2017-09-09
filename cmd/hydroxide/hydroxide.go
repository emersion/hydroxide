package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/emersion/hydroxide/carddav"
	"github.com/emersion/hydroxide/protonmail"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"
)

const authFile = "auth.json"

type cachedAuth struct {
	protonmail.Auth
	LoginPassword string
	MailboxPassword string
	// TODO: add padding
}

func readCachedAuths() (map[string]string, error) {
	f, err := os.Open(authFile)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()

	auths := make(map[string]string)
	err = json.NewDecoder(f).Decode(&auths)
	return auths, err
}

func saveAuths(auths map[string]string) error {
	f, err := os.Create(authFile)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(auths)
}

func encrypt(msg []byte, secretKey *[32]byte) (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}

	encrypted := secretbox.Seal(nonce[:], msg, &nonce, secretKey)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func decrypt(encryptedString string, secretKey *[32]byte) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encryptedString)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &nonce, secretKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}

func encryptAndSaveAuth(auth *cachedAuth, username string, secretKey *[32]byte) error {
	cleartext, err := json.Marshal(auth)
	if err != nil {
		return err
	}

	encrypted, err := encrypt(cleartext, secretKey)
	if err != nil {
		return err
	}

	auths, err := readCachedAuths()
	if err != nil {
		return err
	}

	if auths == nil {
		auths = make(map[string]string)
	}
	auths[username] = encrypted

	return saveAuths(auths)
}

func newClient() *protonmail.Client {
	return &protonmail.Client{
		RootURL:      "https://dev.protonmail.com/api",
		AppVersion:   "Web_3.11.1",
		ClientID:     "Web",
		ClientSecret: "4957cc9a2e0a2a49d02475c9d013478d",
	}
}

func authenticate(c *protonmail.Client, cachedAuth *cachedAuth) error {
	auth, err := c.AuthRefresh(&cachedAuth.Auth)
	if err != nil {
		// TODO: handle expired token, re-authenticate
		return err
	}
	cachedAuth.Auth = *auth

	_, err = c.Unlock(auth, cachedAuth.MailboxPassword)
	return err
}

type session struct {
	h http.Handler
	hashedSecretKey []byte
}

func main() {
	flag.Parse()

	switch flag.Arg(0) {
	case "auth":
		username := flag.Arg(1)
		scanner := bufio.NewScanner(os.Stdin)

		c := newClient()

		var auth *protonmail.Auth
		/*if cachedAuth, ok := auths[username]; ok {
			var err error
			auth, err = c.AuthRefresh(auth)
			if err != nil {
				// TODO: handle expired token error
				log.Fatal(err)
			}
		}*/

		var loginPassword string
		if auth == nil {
			fmt.Printf("Password: ")
			scanner.Scan()
			loginPassword = scanner.Text()

			authInfo, err := c.AuthInfo(username)
			if err != nil {
				log.Fatal(err)
			}

			var twoFactorCode string
			if authInfo.TwoFactor == 1 {
				fmt.Printf("2FA code: ")
				scanner.Scan()
				twoFactorCode = scanner.Text()
			}

			auth, err = c.Auth(username, loginPassword, twoFactorCode, authInfo)
			if err != nil {
				log.Fatal(err)
			}
		}

		var mailboxPassword string
		if auth.PasswordMode == protonmail.PasswordSingle {
			mailboxPassword = loginPassword
		}
		if mailboxPassword == "" {
			if auth.PasswordMode == protonmail.PasswordTwo {
				fmt.Printf("Mailbox password: ")
			} else {
				fmt.Printf("Password: ")
			}
			scanner.Scan()
			mailboxPassword = scanner.Text()
		}

		_, err := c.Unlock(auth, mailboxPassword)
		if err != nil {
			log.Fatal(err)
		}

		var secretKey [32]byte
		if _, err := io.ReadFull(rand.Reader, secretKey[:]); err != nil {
			log.Fatal(err)
		}
		bridgePassword := base64.StdEncoding.EncodeToString(secretKey[:])

		err = encryptAndSaveAuth(&cachedAuth{
			*auth,
			loginPassword,
			mailboxPassword,
		}, username, &secretKey)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Bridge password:", bridgePassword)
	case "":
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}

		sessions := make(map[string]*session)

		s := &http.Server{
			Addr: "127.0.0.1:"+port,
			Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
				resp.Header().Set("WWW-Authenticate", "Basic")

				username, password, ok := req.BasicAuth()
				if !ok {
					resp.WriteHeader(http.StatusUnauthorized)
					return
				}

				var secretKey [32]byte
				passwordBytes, err := base64.StdEncoding.DecodeString(password)
				if err != nil || len(passwordBytes) != len(secretKey) {
					resp.WriteHeader(http.StatusUnauthorized)
					return
				}
				copy(secretKey[:], passwordBytes)

				var h http.Handler
				s, ok := sessions[username]
				if ok {
					err := bcrypt.CompareHashAndPassword(s.hashedSecretKey, secretKey[:])
					if err != nil {
						resp.WriteHeader(http.StatusUnauthorized)
						return
					}

					h = s.h
				} else {
					auths, err := readCachedAuths()
					if err != nil && !os.IsNotExist(err) {
						resp.WriteHeader(http.StatusInternalServerError)
						return
					}

					encrypted, ok := auths[username]
					if !ok {
						resp.WriteHeader(http.StatusUnauthorized)
						return
					}

					decrypted, err := decrypt(encrypted, &secretKey)
					if err != nil {
						resp.WriteHeader(http.StatusUnauthorized)
						return
					}

					var cachedAuth cachedAuth
					if err := json.Unmarshal(decrypted, &cachedAuth); err != nil {
						resp.WriteHeader(http.StatusInternalServerError)
						return
					}

					// authenticate updates cachedAuth with the new refresh token
					c := newClient()
					if err := authenticate(c, &cachedAuth); err != nil {
						resp.WriteHeader(http.StatusInternalServerError)
						return
					}

					if err := encryptAndSaveAuth(&cachedAuth, username, &secretKey); err != nil {
						resp.WriteHeader(http.StatusInternalServerError)
						return
					}

					hashed, err := bcrypt.GenerateFromPassword(secretKey[:], bcrypt.DefaultCost)
					if err != nil {
						resp.WriteHeader(http.StatusInternalServerError)
						return
					}

					h = carddav.NewHandler(c)

					sessions[username] = &session{
						h: h,
						hashedSecretKey: hashed,
					}
				}

				h.ServeHTTP(resp, req)
			}),
		}

		log.Println("Starting server at", s.Addr)
		log.Fatal(s.ListenAndServe())
	default:
		log.Fatal("usage: hydroxide")
		log.Fatal("usage: hydroxide auth <username>")
	}
}
