package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/looprig/secrets"
	"github.com/looprig/secrets/local"
)

func main() {
	root, err := os.MkdirTemp("", "looprig-secrets-example-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(root)

	store, err := local.New(root)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	reference, err := secrets.ParseReference("local://service/token")
	if err != nil {
		log.Fatal(err)
	}
	namespace, err := secrets.ParseNamespace("local://service")
	if err != nil {
		log.Fatal(err)
	}
	initial, err := secrets.New([]byte("initial-value"))
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	created, err := store.Put(ctx, reference, initial, secrets.CreateOnlyPut())
	if err != nil {
		log.Fatal(err)
	}
	resolved, err := store.Resolve(ctx, reference)
	if err != nil {
		log.Fatal(err)
	}
	updatedValue, err := secrets.New([]byte("updated-value"))
	if err != nil {
		log.Fatal(err)
	}
	updated, err := store.Put(ctx, reference, updatedValue, secrets.CompareAndSwapPut(created.Version))
	if err != nil {
		log.Fatal(err)
	}
	page, err := store.List(ctx, namespace, secrets.PageToken{}, 10)
	if err != nil {
		log.Fatal(err)
	}
	deleted, err := store.Delete(ctx, reference, secrets.CompareAndSwapDelete(updated.Version))
	if err != nil {
		log.Fatal(err)
	}
	absent, err := store.Delete(ctx, reference, secrets.UnconditionalDelete())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("created=%t\n", created.Value.Valid())
	fmt.Printf("resolved=%t\n", string(resolved.Value.Bytes()) == "initial-value")
	fmt.Printf("updated=%t\n", updated.Version != created.Version)
	fmt.Printf("listed=%d\n", len(page.Items))
	fmt.Printf("deleted=%s\n", deleted.Status)
	fmt.Printf("absent=%s\n", absent.Status)
}
