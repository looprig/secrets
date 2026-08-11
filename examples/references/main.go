package main

import (
	"fmt"
	"log"

	"github.com/looprig/secrets"
)

func main() {
	reference, err := secrets.ParseReference("LOCAL://service/production/token")
	if err != nil {
		log.Fatal(err)
	}
	namespace, err := secrets.NewNamespace("local", "service/production/")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("canonical=%s\n", reference.Canonical())
	fmt.Printf("scheme=%s\n", reference.Scheme())
	fmt.Printf("path=%s\n", reference.Path())
	fmt.Printf("contained=%t\n", namespace.Contains(reference))
}
