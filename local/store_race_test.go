package local

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/looprig/secrets"
)

func TestLocalStoreConcurrentPutResolveDelete(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://race/token")
	ctx := context.Background()
	const workers = 8
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value := mustSecret(t, string(rune('a'+i)))
			for j := 0; j < 30; j++ {
				_, _ = store.Put(ctx, ref, value, secrets.UnconditionalPut())
				_, _ = store.Resolve(ctx, ref)
			}
		}(i)
	}
	wg.Wait()
	_, _ = store.Delete(ctx, ref, secrets.UnconditionalDelete())
}

func TestLocalStoresShareCrossProcessStyleFileLock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	first, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ref := mustReference(t, "local://locks/shared")
	ctx := context.Background()
	var wg sync.WaitGroup
	for i, store := range []*Store{first, second} {
		wg.Add(1)
		go func(i int, store *Store) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, err := store.Put(ctx, ref, mustSecret(t, string(rune('a'+i))), secrets.UnconditionalPut())
				if err != nil {
					t.Errorf("store %d Put: %v", i, err)
					return
				}
			}
		}(i, store)
	}
	wg.Wait()
	if _, err := first.Resolve(ctx, ref); err != nil {
		t.Fatal(err)
	}
}

func TestLocalStoreLockWaitHonorsCancellation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	entered := make(chan struct{})
	release := make(chan struct{})
	first, err := NewWithOptions(root, Options{Hooks: Hooks{BeforeRename: func() error {
		close(entered)
		<-release
		return nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ref := mustReference(t, "local://locks/cancel")
	firstDone := make(chan error, 1)
	go func() {
		_, err := first.Put(context.Background(), ref, mustSecret(t, "first"), secrets.UnconditionalPut())
		firstDone <- err
	}()
	<-entered
	var releaseOnce sync.Once
	releaseHook := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseHook()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := second.Put(ctx, ref, mustSecret(t, "second"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrCanceled) {
		t.Fatalf("lock-wait Put error = %v, want ErrCanceled", err)
	}
	releaseHook()
	if err := <-firstDone; err != nil {
		t.Fatalf("first Put: %v", err)
	}
}

func TestLocalStoreMutationWaitHonorsCancellation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	entered := make(chan struct{})
	release := make(chan struct{})
	store, err := NewWithOptions(root, Options{Hooks: Hooks{BeforeRename: func() error {
		close(entered)
		<-release
		return nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://mutation/cancel")
	firstDone := make(chan error, 1)
	go func() {
		_, err := store.Put(context.Background(), ref, mustSecret(t, "first"), secrets.UnconditionalPut())
		firstDone <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := store.Put(ctx, mustReference(t, "local://mutation/other"), mustSecret(t, "second"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrCanceled) {
		t.Fatalf("same-store mutation wait error = %v, want ErrCanceled", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Put: %v", err)
	}
}
