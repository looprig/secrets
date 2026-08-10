// Package contracttest contains reusable contract checks for secrets.Store
// implementations. It intentionally inspects only the public secrets API.
package contracttest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/looprig/secrets"
)

// StoreFactory constructs a fresh store for one contract run. The factory is
// responsible for registering cleanup with t.
type StoreFactory func(t *testing.T) secrets.Store

// StoreContractOptions identifies safe, backend-specific references used by
// the contract. The runner deliberately has no default scheme or path: each
// backend must provide references that it can actually resolve and list.
type StoreContractOptions struct {
	Reference        secrets.Reference
	Namespace        secrets.Namespace
	OtherReference   secrets.Reference
	OutsideReference secrets.Reference

	RequireCreateOnly     bool
	RequireCompareAndSwap bool
	RequireVersion        bool
	RequireListing        bool
}

// StoreContractConfig is a descriptive alias for callers that prefer the
// word “config” at the call site.
type StoreContractConfig = StoreContractOptions

// ContractOptions is a short alias retained for adapters that use a generic
// contract-options name in their test harness.
type ContractOptions = StoreContractOptions

// RunStore runs resolver/store behavior shared by local and future backends.
// Exactly one options value is required so this reusable runner cannot smuggle
// in a backend-specific reference or capability assumption.
func RunStore(t *testing.T, factory StoreFactory, options ...StoreContractOptions) {
	t.Helper()
	if len(options) != 1 {
		t.Fatal("RunStore requires one StoreContractOptions value")
	}
	config := options[0]
	validateStoreContractOptions(t, config)
	store := factory(t)
	if store == nil {
		t.Fatal("store factory returned nil")
	}
	ref := config.Reference
	caps, hasCaps := store.(secrets.PreconditionCapabilities)
	if config.RequireCreateOnly && (!hasCaps || !caps.SupportsCreateOnly()) {
		t.Fatal("store did not affirm create-only support")
	}
	if config.RequireCompareAndSwap && (!hasCaps || !caps.SupportsCompareAndSwap()) {
		t.Fatal("store did not affirm compare-and-swap support")
	}
	value, err := secrets.New([]byte("contract-secret"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := store.Resolve(ctx, ref); err == nil || !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing Resolve error = %v, want ErrNotFound", err)
	}
	created, err := store.Put(ctx, ref, value, secrets.UnconditionalPut())
	if err != nil {
		t.Fatalf("unconditional Put: %v", err)
	}
	if err := created.Validate(); err != nil {
		t.Fatalf("created record invalid: %v", err)
	}
	versioned := !created.Version.IsUnsupported()
	if config.RequireVersion && !versioned {
		t.Fatal("store returned VersionUnsupported but contract requires backend-issued versions")
	}
	if got := string(created.Value.Bytes()); got != "contract-secret" {
		t.Fatalf("created value = %q", got)
	}
	if config.RequireCreateOnly {
		if _, err := store.Put(ctx, ref, value, secrets.CreateOnlyPut()); err == nil || !errors.Is(err, secrets.ErrConflict) {
			t.Fatalf("duplicate create-only Put error = %v, want ErrConflict", err)
		}
	}
	resolved, err := store.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Version != created.Version || string(resolved.Value.Bytes()) != "contract-secret" {
		t.Fatalf("resolved = %#v, want created version/value", resolved)
	}

	updatedValue, err := secrets.New([]byte("updated-secret"))
	if err != nil {
		t.Fatal(err)
	}
	var updated secrets.Record
	if config.RequireCompareAndSwap {
		updated, err = store.Put(ctx, ref, updatedValue, secrets.CompareAndSwapPut(created.Version))
		if err != nil {
			t.Fatalf("CAS Put: %v", err)
		}
		if _, err := store.Put(ctx, ref, value, secrets.CompareAndSwapPut(created.Version)); err == nil || !errors.Is(err, secrets.ErrConflict) {
			t.Fatalf("stale CAS Put error = %v, want ErrConflict", err)
		}
	} else {
		updated, err = store.Put(ctx, ref, updatedValue, secrets.UnconditionalPut())
		if err != nil {
			t.Fatalf("unconditional update Put: %v", err)
		}
	}
	if versioned && updated.Version == created.Version {
		t.Fatal("update Put did not issue a new version")
	}

	if config.RequireListing {
		otherValue, err := secrets.New([]byte("other-secret"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Put(ctx, config.OtherReference, otherValue, secrets.UnconditionalPut()); err != nil {
			t.Fatalf("listing companion Put: %v", err)
		}
		outsideValue, err := secrets.New([]byte("outside-secret"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Put(ctx, config.OutsideReference, outsideValue, secrets.UnconditionalPut()); err != nil {
			t.Fatalf("outside-namespace Put: %v", err)
		}
		lister, ok := store.(secrets.Lister)
		if !ok {
			t.Fatal("store does not implement Lister")
		}
		RunList(t, lister, config)
	}

	var deleted secrets.DeleteResult
	if config.RequireCompareAndSwap {
		deleted, err = store.Delete(ctx, ref, secrets.CompareAndSwapDelete(updated.Version))
		if err != nil {
			t.Fatalf("CAS Delete: %v", err)
		}
	} else {
		deleted, err = store.Delete(ctx, ref, secrets.UnconditionalDelete())
		if err != nil {
			t.Fatalf("unconditional Delete: %v", err)
		}
	}
	if deleted.Status != secrets.DeleteStatusDeleted || deleted.Version != updated.Version {
		t.Fatalf("delete result = %#v", deleted)
	}
	absent, err := store.Delete(ctx, ref, secrets.UnconditionalDelete())
	if err != nil {
		t.Fatalf("idempotent Delete: %v", err)
	}
	if absent.Status != secrets.DeleteStatusAbsent || !absent.Version.IsUnsupported() {
		t.Fatalf("absent delete result = %#v", absent)
	}
	if config.RequireCompareAndSwap {
		if _, err := store.Delete(ctx, ref, secrets.CompareAndSwapDelete(updated.Version)); err == nil || !errors.Is(err, secrets.ErrConflict) {
			t.Fatalf("CAS Delete against absent error = %v, want ErrConflict", err)
		}
	}
}

func validateStoreContractOptions(t *testing.T, config StoreContractOptions) {
	t.Helper()
	if config.Reference.IsZero() {
		t.Fatal("contract reference is required")
	}
	if config.RequireListing {
		if config.Namespace.IsZero() || !config.Namespace.Contains(config.Reference) {
			t.Fatal("contract namespace must contain the primary reference")
		}
		if config.OtherReference.IsZero() || !config.Namespace.Contains(config.OtherReference) || config.OtherReference == config.Reference {
			t.Fatal("listing contract requires a distinct in-namespace reference")
		}
		if config.OutsideReference.IsZero() || config.OutsideReference.Scheme() != config.Namespace.Scheme() || config.Namespace.Contains(config.OutsideReference) {
			t.Fatal("listing contract requires an outside-namespace reference")
		}
	}
}

// RunList exercises the optional metadata-only listing contract, including
// page boundaries and namespace isolation. Values are inserted by RunStore;
// this function only observes Metadata results.
func RunList(t *testing.T, lister secrets.Lister, config StoreContractOptions) {
	t.Helper()
	if lister == nil {
		t.Fatal("store does not implement Lister")
	}
	token := secrets.PageToken{}
	seen := make(map[string]struct{})
	pages := 0
	for {
		page, err := lister.List(context.Background(), config.Namespace, token, 1)
		if err != nil {
			t.Fatalf("List page %d: %v", pages, err)
		}
		if err := page.Validate(1); err != nil {
			t.Fatalf("List page %d invalid: %v", pages, err)
		}
		pages++
		for _, item := range page.Items {
			if err := item.Validate(); err != nil {
				t.Fatalf("List metadata invalid: %v", err)
			}
			if !config.Namespace.Contains(item.Reference) {
				t.Fatalf("List returned outside-namespace reference %q", item.Reference.Canonical())
			}
			if item.Reference == config.OutsideReference {
				t.Fatalf("List returned outside-namespace reference")
			}
			key := item.Reference.Canonical()
			if _, duplicate := seen[key]; duplicate {
				t.Fatalf("List repeated reference %q across pages", key)
			}
			seen[key] = struct{}{}
		}
		if page.NextToken.IsZero() {
			break
		}
		token = page.NextToken
		if pages > 4 {
			t.Fatal("List did not terminate within bounded pages")
		}
	}
	if pages < 2 {
		t.Fatal("List did not exercise pagination")
	}
	want := map[string]struct{}{
		config.Reference.Canonical():      {},
		config.OtherReference.Canonical(): {},
	}
	if len(seen) != len(want) {
		t.Fatalf("List returned %d references, want %d", len(seen), len(want))
	}
	for key := range want {
		if _, ok := seen[key]; !ok {
			t.Fatalf("List omitted in-namespace reference %q", key)
		}
	}
}

// AssertListMetadata confirms that a lister does not expose a value field
// through the public metadata type and honors bounded pages.
func AssertListMetadata(t *testing.T, lister secrets.Lister, namespace secrets.Namespace) {
	t.Helper()
	if lister == nil {
		t.Fatal("store does not implement Lister")
	}
	page, err := lister.List(context.Background(), namespace, secrets.PageToken{}, 1)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := page.Validate(1); err != nil {
		t.Fatalf("invalid list page: %v", err)
	}
	for _, item := range page.Items {
		if err := item.Validate(); err != nil {
			t.Fatalf("invalid metadata item: %v", err)
		}
	}
}

// ErrorText is a helper for callers checking that an error remains bounded.
func ErrorText(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v|%#v", err, err)
}
