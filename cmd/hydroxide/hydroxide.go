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
		RootURL: "https://dev.protonmail.com/api",
		AppVersion: "Web_3.11.1",
		ClientID: "Web",
		ClientSecret: "4957cc9a2e0a2a49d02475c9d013478d",
	}

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("Username: ")
	scanner.Scan()
	username := scanner.Text()

	fmt.Printf("Password: ")
	scanner.Scan()
	password := scanner.Text()

	fmt.Printf("2FA code: ")
	scanner.Scan()
	code := scanner.Text()

	err := c.Auth(username, password, code, nil)
	if err != nil {
		log.Fatal(err)
	}
}
