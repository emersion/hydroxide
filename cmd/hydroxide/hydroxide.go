package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/emersion/hydroxide/carddav"
	"github.com/emersion/hydroxide/protonmail"
)

const authFile = "auth.json"

func readCachedAuth() (*protonmail.Auth, error) {
	f, err := os.Open(authFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	auth := new(protonmail.Auth)
	err = json.NewDecoder(f).Decode(auth)
	return auth, err
}

func saveAuth(auth *protonmail.Auth) error {
	f, err := os.Create(authFile)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(auth)
}

func main() {
	c := &protonmail.Client{
		RootURL:      "https://dev.protonmail.com/api",
		AppVersion:   "Web_3.11.1",
		ClientID:     "Web",
		ClientSecret: "4957cc9a2e0a2a49d02475c9d013478d",
	}

	scanner := bufio.NewScanner(os.Stdin)

	var password string
	auth, err := readCachedAuth()
	if err == nil {
		var err error
		auth, err = c.AuthRefresh(auth)
		if err != nil {
			log.Fatal(err)
		}
	} else if os.IsNotExist(err) {
		fmt.Printf("Username: ")
		scanner.Scan()
		username := scanner.Text()

		fmt.Printf("Password: ")
		scanner.Scan()
		password = scanner.Text()

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

		auth, err = c.Auth(username, password, twoFactorCode, authInfo)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatal(err)
	}

	if err := saveAuth(auth); err != nil {
		log.Fatal(err)
	}

	if auth.PasswordMode == protonmail.PasswordTwo || password == "" {
		if auth.PasswordMode == protonmail.PasswordTwo {
			fmt.Printf("Mailbox password: ")
		} else {
			fmt.Printf("Password: ")
		}
		scanner.Scan()
		password = scanner.Text()
	}

	_, err = c.Unlock(auth, password)
	if err != nil {
		log.Fatal(err)
	}

	h := carddav.NewHandler(c)

	s := &http.Server{
		Addr: "127.0.0.1:8080",
		Handler: h,
	}

	log.Println("Starting server at", s.Addr)
	log.Fatal(s.ListenAndServe())
}
