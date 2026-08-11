package contracttest_test

import (
	"path/filepath"
	"testing"

	"github.com/looprig/secrets"
	"github.com/looprig/secrets/contracttest"
	"github.com/looprig/secrets/local"
)

func TestLocalStoreContract(t *testing.T) {
	contracttest.RunStore(t, func(t *testing.T) secrets.Store {
		store, err := local.New(filepath.Join(t.TempDir(), "secrets"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return store
	}, contracttest.StoreContractOptions{
		Reference:             mustReference(t, "local://contract/primary"),
		Namespace:             mustNamespace(t, "local://contract"),
		OtherReference:        mustReference(t, "local://contract/other"),
		OutsideReference:      mustReference(t, "local://outside/value"),
		RequireCreateOnly:     true,
		RequireCompareAndSwap: true,
		RequireVersion:        true,
		RequireListing:        true,
	})
}

func mustReference(t *testing.T, raw string) secrets.Reference {
	t.Helper()
	reference, err := secrets.ParseReference(raw)
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func mustNamespace(t *testing.T, raw string) secrets.Namespace {
	t.Helper()
	namespace, err := secrets.ParseNamespace(raw)
	if err != nil {
		t.Fatal(err)
	}
	return namespace
}
