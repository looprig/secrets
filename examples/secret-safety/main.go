package main

import (
	"fmt"
	"log"

	"github.com/looprig/secrets"
)

func main() {
	secret, err := secrets.New([]byte("private-value"))
	if err != nil {
		log.Fatal(err)
	}

	exposed := secret.Bytes()
	exposed[0] = 'X'

	fmt.Printf("formatted=%v\n", secret)
	fmt.Printf("valid=%t\n", secret.Valid())
	fmt.Printf("explicit-bytes=%d\n", len(secret.Bytes()))
	fmt.Printf("copy-isolated=%t\n", secret.Bytes()[0] == 'p')
}
