package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/emersion/hydroxide/protonmail"
)

func main() {
	c := &protonmail.Client{
		RootURL:      "https://dev.protonmail.com/api",
		AppVersion:   "Web_3.11.1",
		ClientID:     "Web",
		ClientSecret: "4957cc9a2e0a2a49d02475c9d013478d",
	}

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("Username: ")
	scanner.Scan()
	username := scanner.Text()

	fmt.Printf("Password: ")
	scanner.Scan()
	password := scanner.Text()

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

	auth, err := c.Auth(username, password, twoFactorCode, authInfo)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(auth)

	var mailboxPassword string
	if auth.PasswordMode == protonmail.PasswordTwo {
		fmt.Printf("Mailbox password: ")
		scanner.Scan()
		mailboxPassword = scanner.Text()
	}

	_, err = c.Unlock(auth, mailboxPassword)
	if err != nil {
		log.Fatal(err)
	}
}
