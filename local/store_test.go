package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/looprig/secrets"
	"github.com/looprig/secrets/contracttest"
)

func TestNewRequiresExplicitAbsoluteCleanRoot(t *testing.T) {
	if _, err := New("relative-root"); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("relative root error = %v, want ErrInsecurePath", err)
	}
	root := filepath.Join(t.TempDir(), "store")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if got := store.Root(); got != filepath.Clean(root) {
		t.Fatalf("Root() = %q, want %q", got, filepath.Clean(root))
	}
}

func TestNilLocalStoreReturnsSafeUnavailableErrors(t *testing.T) {
	var store *Store
	ref := mustReference(t, "local://nil/token")
	if _, err := store.Resolve(context.Background(), ref); err == nil || !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("nil Resolve error = %v, want ErrUnavailable", err)
	}
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("nil Put error = %v, want ErrUnavailable", err)
	}
	if _, err := store.Delete(context.Background(), ref, secrets.UnconditionalDelete()); err == nil || !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("nil Delete error = %v, want ErrUnavailable", err)
	}
	if _, err := store.List(context.Background(), mustNamespace(t, "local://nil"), secrets.PageToken{}, 1); err == nil || !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("nil List error = %v, want ErrUnavailable", err)
	}
}

func TestLocalStoreRejectsUnsupportedReferenceScheme(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "vault://openai/token")
	if _, err := store.Resolve(context.Background(), ref); err == nil || !errors.Is(err, secrets.ErrUnsupportedScheme) {
		t.Fatalf("Resolve unsupported scheme error = %v, want ErrUnsupportedScheme", err)
	}
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrUnsupportedScheme) {
		t.Fatalf("Put unsupported scheme error = %v, want ErrUnsupportedScheme", err)
	}
}

func TestLocalStoreSatisfiesReusableContract(t *testing.T) {
	contracttest.RunStore(t, func(t *testing.T) secrets.Store {
		store, err := New(filepath.Join(t.TempDir(), "secrets"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return store
	}, contracttest.StoreContractOptions{
		Reference:             mustReference(t, "local://contract/token"),
		Namespace:             mustNamespace(t, "local://contract"),
		OtherReference:        mustReference(t, "local://contract/other"),
		OutsideReference:      mustReference(t, "local://different/token"),
		RequireCreateOnly:     true,
		RequireCompareAndSwap: true,
		RequireVersion:        true,
		RequireListing:        true,
	})
}

func TestLocalStoreReportsConditionalCapabilities(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	caps, ok := any(store).(secrets.PreconditionCapabilities)
	if !ok || !caps.SupportsCreateOnly() || !caps.SupportsCompareAndSwap() {
		t.Fatal("local store did not affirm create-only and CAS support")
	}
}

func TestLocalStoreCreatesOwnerOnlyRecordFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://permissions/file")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, store.Filename(ref)))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("record mode = %v, want regular 0600", info.Mode())
	}
	lockInfo, err := os.Stat(filepath.Join(root, lockName))
	if err != nil {
		t.Fatal(err)
	}
	if lockInfo.Mode().Perm() != 0o600 || !lockInfo.Mode().IsRegular() {
		t.Fatalf("lock mode = %v, want regular 0600", lockInfo.Mode())
	}
}

func TestLocalStoreDoesNotPersistVersionHistory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://versions/no-history")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".store.history")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("version history stat error = %v, want absent", err)
	}
}

func TestLocalStoreListsMetadataByNamespaceWithBoundedPages(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	for _, raw := range []string{
		"local://openai/personal/a",
		"local://openai/personal/b",
		"local://openai/other/c",
		"local://other/personal/d",
	} {
		ref := mustReference(t, raw)
		if _, err := store.Put(ctx, ref, mustSecret(t, "value-"+raw), secrets.UnconditionalPut()); err != nil {
			t.Fatalf("Put(%q): %v", raw, err)
		}
	}
	ns, err := secrets.NewNamespace("local", "openai/personal")
	if err != nil {
		t.Fatal(err)
	}
	lister := any(store).(secrets.Lister)
	token := secrets.PageToken{}
	var got []string
	for {
		page, err := lister.List(ctx, ns, token, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := page.Validate(1); err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			got = append(got, item.Reference.Canonical())
			if item.Reference.Canonical() == "local://openai/personal/a" {
				if _, ok := any(item).(struct{ Value secrets.Secret }); ok {
					t.Fatal("metadata unexpectedly exposes secret value")
				}
			}
		}
		if page.NextToken.IsZero() {
			break
		}
		token = page.NextToken
	}
	want := []string{"local://openai/personal/a", "local://openai/personal/b"}
	if len(got) != len(want) {
		t.Fatalf("listed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("listed %v, want %v", got, want)
		}
	}
	for _, raw := range []string{"i:01", "i:-1", "cursor"} {
		token, err := secrets.NewPageToken(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lister.List(ctx, ns, token, 1); err == nil || !errors.Is(err, secrets.ErrInvalidPageToken) {
			t.Fatalf("token %q List error = %v, want ErrInvalidPageToken", raw, err)
		}
	}
}

func TestLocalStoreRejectsMalformedEnvelopeVariants(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://malformed/token")
	name := store.Filename(ref)
	variants := []struct {
		name string
		data []byte
	}{
		{"unknown", []byte(`{"schema":1,"reference":"local://malformed/token","value":"dmFsdWU=","version":"v1","updated_at":"2026-01-01T00:00:00Z","extra":1}`)},
		{"duplicate", []byte(`{"schema":1,"reference":"local://malformed/token","reference":"local://malformed/token","value":"dmFsdWU=","version":"v1","updated_at":"2026-01-01T00:00:00Z"}`)},
		{"trailing", []byte(`{"schema":1,"reference":"local://malformed/token","value":"dmFsdWU=","version":"v1","updated_at":"2026-01-01T00:00:00Z"}{}`)},
		{"schema", []byte(`{"schema":2,"reference":"local://malformed/token","value":"dmFsdWU=","version":"v1","updated_at":"2026-01-01T00:00:00Z"}`)},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(root, name), variant.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Resolve(context.Background(), ref); err == nil || !errors.Is(err, secrets.ErrCorruptRecord) {
				t.Fatalf("Resolve error = %v, want ErrCorruptRecord", err)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(root, name), []byte("{\xff"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(context.Background(), ref); err == nil || !errors.Is(err, secrets.ErrCorruptRecord) {
		t.Fatalf("invalid UTF-8 Resolve error = %v, want ErrCorruptRecord", err)
	}
	if err := os.WriteFile(filepath.Join(root, name), make([]byte, maxEnvelopeBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(context.Background(), ref); err == nil || !errors.Is(err, secrets.ErrCorruptRecord) {
		t.Fatalf("oversized Resolve error = %v, want ErrCorruptRecord", err)
	}
}

func TestLocalStoreRejectsEnvelopeCopiedToAnotherEncodedFilename(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://filename/original")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, store.Filename(ref)))
	if err != nil {
		t.Fatal(err)
	}
	other := mustReference(t, "local://filename/copied")
	if err := os.WriteFile(filepath.Join(root, store.Filename(other)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	ns := mustNamespace(t, "local://filename")
	if _, err := store.List(context.Background(), ns, secrets.PageToken{}, 10); err == nil || !errors.Is(err, secrets.ErrCorruptRecord) {
		t.Fatalf("copied filename List error = %v, want ErrCorruptRecord", err)
	}
}

func TestLocalStoreListTreatsEncodedFilenameAsAuthoritative(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	target := mustReference(t, "local://filename/authoritative")
	outside := mustReference(t, "local://other/outside")
	if _, err := store.Put(ctx, target, mustSecret(t, "value"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, store.Filename(target)))
	if err != nil {
		t.Fatal(err)
	}
	var envelope diskEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Reference = outside.Canonical()
	data, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, store.Filename(target)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(ctx, mustNamespace(t, "local://filename"), secrets.PageToken{}, 10); err == nil || !errors.Is(err, secrets.ErrCorruptRecord) {
		t.Fatalf("filename-authoritative List error = %v, want ErrCorruptRecord", err)
	}
}

func TestLocalStoreListBoundsAggregateReadWork(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	large := mustSecret(t, strings.Repeat("x", secrets.MaxSecretSize))
	for i := 0; i < 9; i++ {
		ref := mustReference(t, fmt.Sprintf("local://budget/%d", i))
		if _, err := store.Put(ctx, ref, large, secrets.UnconditionalPut()); err != nil {
			t.Fatalf("Put(%d): %v", i, err)
		}
	}
	if _, err := store.List(ctx, mustNamespace(t, "local://budget"), secrets.PageToken{}, 1); err == nil || !errors.Is(err, ErrListTooLarge) {
		t.Fatalf("aggregate-budget List error = %v, want ErrListTooLarge", err)
	}
}

func TestLocalStoreCancellationBeforeMutationPreservesPriorValue(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://cancel/token")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "old"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Put(ctx, ref, mustSecret(t, "new"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrCanceled) {
		t.Fatalf("canceled Put error = %v, want ErrCanceled", err)
	}
	got, err := store.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Value.Bytes()) != "old" {
		t.Fatalf("canceled Put changed value to %q", got.Value.Bytes())
	}
}

func TestLocalStoreReportsVisibleDurabilityUnknownAfterRenameAndUnlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := NewWithOptions(root, Options{Hooks: Hooks{SyncDir: func() error { return errors.New("injected") }}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://durability/token")
	record, err := store.Put(context.Background(), ref, mustSecret(t, "new"), secrets.UnconditionalPut())
	var durabilityErr *CommitVisibleDurabilityUnknownError
	if err == nil || !errors.As(err, &durabilityErr) || !durabilityErr.Visible() {
		t.Fatalf("Put error = %v, want visible durability-unknown error", err)
	}
	if record.Reference != ref {
		t.Fatalf("Put record = %#v, want committed record", record)
	}
	if got, err := store.Resolve(context.Background(), ref); err != nil || string(got.Value.Bytes()) != "new" {
		t.Fatalf("visible Put state = %#v, %v", got, err)
	}
	store.ops.Hooks.SyncDir = func() error { return errors.New("injected") }
	result, err := store.Delete(context.Background(), ref, secrets.UnconditionalDelete())
	if err == nil || !errors.As(err, &durabilityErr) || result.Status != secrets.DeleteStatusDeleted {
		t.Fatalf("Delete = %#v, %v, want visible durability-unknown", result, err)
	}
	if _, err := store.Resolve(context.Background(), ref); err == nil || !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("post-unlink Resolve = %v, want ErrNotFound", err)
	}
}

func TestLocalStoreCancellationAfterLinearizationReturnsCommittedResult(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	ctx, cancel := context.WithCancel(context.Background())
	store, err := NewWithOptions(root, Options{Hooks: Hooks{AfterRename: func() error { cancel(); return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://cancel/after-rename")
	record, err := store.Put(ctx, ref, mustSecret(t, "committed"), secrets.UnconditionalPut())
	if err != nil {
		t.Fatalf("post-rename cancellation Put error = %v, want committed success", err)
	}
	if record.Reference != ref {
		t.Fatalf("committed record reference = %v, want %v", record.Reference, ref)
	}
	got, err := store.Resolve(context.Background(), ref)
	if err != nil || string(got.Value.Bytes()) != "committed" {
		t.Fatalf("post-rename state = %#v, %v", got, err)
	}

	deleteCtx, deleteCancel := context.WithCancel(context.Background())
	store.ops.Hooks.AfterRename = nil
	store.ops.Hooks.AfterUnlink = func() error { deleteCancel(); return nil }
	result, err := store.Delete(deleteCtx, ref, secrets.UnconditionalDelete())
	if err != nil || result.Status != secrets.DeleteStatusDeleted {
		t.Fatalf("post-unlink cancellation Delete = %#v, %v", result, err)
	}
}

func TestLocalStoreRejectsSymlinkRecordAndRootReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics are covered by the Windows unsupported test")
	}
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://openai/personal/token")
	value := mustSecret(t, "first")
	if _, err := store.Put(context.Background(), ref, value, secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	name := store.filenameFor(ref)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, name)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, name)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(context.Background(), ref); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("symlink resolve error = %v, want ErrInsecurePath", err)
	}
}

func TestLocalStoreRejectsRootPathRecreation(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.Rename(root, filepath.Join(parent, "old-root")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ref := mustReference(t, "local://root-swap/reject")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("recreated root Put error = %v, want ErrInsecurePath", err)
	}
	if _, err := os.Stat(filepath.Join(root, store.Filename(ref))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recreated root unexpectedly received record, stat error=%v", err)
	}
}

func TestNewRejectsIntermediateRootSymlink(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(parent, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(link, "secrets")
	if _, err := New(root); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("intermediate symlink root error = %v, want ErrInsecurePath", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "secrets")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("intermediate symlink traversal created outside root, stat error=%v", err)
	}
}

func TestLocalStoreRechecksRootBeforeRenameAndUnlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := NewWithOptions(root, Options{Hooks: Hooks{BeforeRename: func() error {
		return os.Chmod(root, 0o755)
	}}})
	if err != nil {
		t.Fatal(err)
	}
	ref := mustReference(t, "local://root-check/rename")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("root mode change before rename error = %v, want ErrInsecurePath", err)
	}
	store.ops.Hooks.BeforeRename = nil
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	store.ops.Hooks.BeforeRename = nil
	store.ops.Hooks.BeforeUnlink = func() error { return os.Chmod(root, 0o755) }
	if _, err := store.Delete(context.Background(), ref, secrets.UnconditionalDelete()); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("root mode change before unlink error = %v, want ErrInsecurePath", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
}

func TestLocalStoreDeleteReportsAbsentWhenUnlinkRaceFindsNoFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://delete/race")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	store.ops.Hooks.BeforeUnlink = func() error {
		return os.Remove(filepath.Join(root, store.Filename(ref)))
	}
	result, err := store.Delete(context.Background(), ref, secrets.UnconditionalDelete())
	if err != nil {
		t.Fatalf("racing Delete error = %v", err)
	}
	if result.Status != secrets.DeleteStatusAbsent {
		t.Fatalf("racing Delete status = %v, want absent", result.Status)
	}
}

func TestLocalStoreCASDeleteRaceRemainsConflictWhenUnlinkDoesNotOccur(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://delete/cas-race")
	record, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut())
	if err != nil {
		t.Fatal(err)
	}
	store.ops.Hooks.BeforeUnlink = func() error {
		return os.Remove(filepath.Join(root, store.Filename(ref)))
	}
	if _, err := store.Delete(context.Background(), ref, secrets.CompareAndSwapDelete(record.Version)); err == nil || !errors.Is(err, secrets.ErrConflict) {
		t.Fatalf("racing CAS Delete error = %v, want ErrConflict", err)
	}
}

func TestLocalStoreListPaginationUsesStableSnapshotCursor(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	for _, raw := range []string{"local://snapshot/a", "local://snapshot/b"} {
		if _, err := store.Put(ctx, mustReference(t, raw), mustSecret(t, raw), secrets.UnconditionalPut()); err != nil {
			t.Fatal(err)
		}
	}
	ns := mustNamespace(t, "local://snapshot")
	first, err := store.List(ctx, ns, secrets.PageToken{}, 1)
	if err != nil || len(first.Items) != 1 || first.NextToken.IsZero() {
		t.Fatalf("first snapshot page = %#v, %v", first, err)
	}
	if _, err := store.Put(ctx, mustReference(t, "local://snapshot/aa"), mustSecret(t, "inserted"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	otherNS := mustNamespace(t, "local://other-snapshot")
	if _, err := store.Put(ctx, mustReference(t, "local://other-snapshot/x"), mustSecret(t, "other"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(ctx, otherNS, first.NextToken, 1); err == nil || !errors.Is(err, secrets.ErrInvalidPageToken) {
		t.Fatalf("cross-namespace token error = %v, want ErrInvalidPageToken", err)
	}
	otherStore, err := New(store.Root())
	if err != nil {
		t.Fatal(err)
	}
	defer otherStore.Close()
	if _, err := otherStore.List(ctx, ns, first.NextToken, 1); err == nil || (!errors.Is(err, secrets.ErrInvalidPageToken) && !errors.Is(err, ErrPageTokenExpired)) {
		t.Fatalf("cross-store token error = %v, want invalid/expired token", err)
	}
	second, err := store.List(ctx, ns, first.NextToken, 1)
	if err != nil || len(second.Items) != 1 || second.Items[0].Reference.Canonical() != "local://snapshot/b" {
		t.Fatalf("second snapshot page = %#v, %v, want b", second, err)
	}
	var expired *PageTokenExpiredError
	if _, err := store.List(ctx, ns, first.NextToken, 1); err == nil || !errors.As(err, &expired) {
		t.Fatalf("replayed snapshot token error = %v, want PageTokenExpiredError", err)
	}
	tampered, err := secrets.NewPageToken(first.NextToken.String()[:len(first.NextToken.String())-1] + "0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(ctx, ns, tampered, 1); err == nil || (!errors.Is(err, secrets.ErrInvalidPageToken) && !errors.As(err, &expired)) {
		t.Fatalf("tampered snapshot token error = %v, want invalid/expired token", err)
	}
}

func TestLocalStoreListContinuationRevalidatesRootAndCancellationFirst(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	for _, raw := range []string{"local://continuation/a", "local://continuation/b"} {
		if _, err := store.Put(ctx, mustReference(t, raw), mustSecret(t, raw), secrets.UnconditionalPut()); err != nil {
			t.Fatal(err)
		}
	}
	ns := mustNamespace(t, "local://continuation")
	first, err := store.List(ctx, ns, secrets.PageToken{}, 1)
	if err != nil || first.NextToken.IsZero() {
		t.Fatalf("first continuation page = %#v, %v", first, err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(ctx, ns, first.NextToken, 1); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("continuation root mode error = %v, want ErrInsecurePath", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.List(canceled, ns, first.NextToken, 1); err == nil || !errors.Is(err, secrets.ErrCanceled) {
		t.Fatalf("canceled continuation error = %v, want ErrCanceled", err)
	}
}

func TestLocalStoreCloseReleasesListSnapshots(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, raw := range []string{"local://snapshot-release/a", "local://snapshot-release/b"} {
		if _, err := store.Put(ctx, mustReference(t, raw), mustSecret(t, raw), secrets.UnconditionalPut()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.List(ctx, mustNamespace(t, "local://snapshot-release"), secrets.PageToken{}, 1); err != nil {
		t.Fatal(err)
	}
	store.snapshotMu.Lock()
	countBefore := len(store.snapshots)
	store.snapshotMu.Unlock()
	if countBefore == 0 {
		t.Fatal("List did not retain a continuation snapshot")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store.snapshotMu.Lock()
	countAfter := len(store.snapshots)
	store.snapshotMu.Unlock()
	if countAfter != 0 {
		t.Fatalf("closed store retained %d list snapshots", countAfter)
	}
}

func TestLocalStoreBoundsDirectoryScanWork(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for i := 0; i <= maxListRecords; i++ {
		name := filepath.Join(root, fmt.Sprintf(".junk-%05d", i))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.List(context.Background(), mustNamespace(t, "local://bounded"), secrets.PageToken{}, 1); err == nil || !errors.Is(err, ErrListTooLarge) {
		t.Fatalf("oversized directory List error = %v, want ErrListTooLarge", err)
	}
}

func TestLocalStoreRetriesGeneratedVersionCollisions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	versions := []string{"v1", "v1", "v2", "v1", "v3"}
	var calls int
	store, err := NewWithOptions(root, Options{Hooks: Hooks{NewVersion: func() (secrets.Version, error) {
		if calls >= len(versions) {
			return secrets.NewVersion("fallback")
		}
		raw := versions[calls]
		calls++
		return secrets.NewVersion(raw)
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://versions/collision")
	first, err := store.Put(context.Background(), ref, mustSecret(t, "one"), secrets.UnconditionalPut())
	if err != nil || first.Version.String() != "v1" {
		t.Fatalf("first Put = %#v, %v, want v1", first, err)
	}
	second, err := store.Put(context.Background(), ref, mustSecret(t, "two"), secrets.UnconditionalPut())
	if err != nil || second.Version.String() != "v2" {
		t.Fatalf("collision retry Put = %#v, %v, want v2", second, err)
	}
	third, err := store.Put(context.Background(), ref, mustSecret(t, "three"), secrets.UnconditionalPut())
	if err != nil || third.Version.String() != "v1" {
		t.Fatalf("current-version collision retry Put = %#v, %v, want v1", third, err)
	}
}

func TestLocalStoreVersionGenerationDoesNotRetainAllHistory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	versions := []string{"v1", "v2"}
	calls := 0
	store, err := NewWithOptions(root, Options{Hooks: Hooks{NewVersion: func() (secrets.Version, error) {
		raw := versions[calls%len(versions)]
		calls++
		return secrets.NewVersion(raw)
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://versions/bounded-state")
	for i := 0; i < 32; i++ {
		record, err := store.Put(context.Background(), ref, mustSecret(t, fmt.Sprintf("value-%d", i)), secrets.UnconditionalPut())
		if err != nil {
			t.Fatalf("Put(%d): %v", i, err)
		}
		if got, want := record.Version.String(), versions[i%len(versions)]; got != want {
			t.Fatalf("Put(%d) version = %q, want %q", i, got, want)
		}
	}
}

func TestLocalStoreCancellationPrecedesFilesystemValidation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ref := mustReference(t, "local://cancel/validation")
	if _, err := store.Resolve(ctx, ref); err == nil || !errors.Is(err, secrets.ErrCanceled) {
		t.Fatalf("canceled Resolve with insecure root error = %v, want ErrCanceled", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestLocalStoreCancellationDuringPreLinearizationIOStopsMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	ctx, cancel := context.WithCancel(context.Background())
	store, err := NewWithOptions(root, Options{Hooks: Hooks{BeforeWrite: func() error {
		cancel()
		return nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://cancel/pre-linearization")
	if _, err := store.Put(ctx, ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrCanceled) {
		t.Fatalf("pre-linearization canceled Put error = %v, want ErrCanceled", err)
	}
	if _, err := os.Stat(filepath.Join(root, store.Filename(ref))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-linearization canceled Put left a record, stat error = %v", err)
	}
}

func TestLocalStoreCancellationHooksCoverReadVersionAndTempWrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://cancel/phases")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "old"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	phases := []struct {
		name  string
		set   func(*Store, context.CancelFunc)
		clear func(*Store)
	}{
		{name: "existing read", set: func(s *Store, cancel context.CancelFunc) {
			s.ops.Hooks.BeforeExistingRead = func() error { cancel(); return nil }
		}, clear: func(s *Store) { s.ops.Hooks.BeforeExistingRead = nil }},
		{name: "version generation", set: func(s *Store, cancel context.CancelFunc) {
			s.ops.Hooks.BeforeVersion = func() error { cancel(); return nil }
		}, clear: func(s *Store) { s.ops.Hooks.BeforeVersion = nil }},
		{name: "temporary write", set: func(s *Store, cancel context.CancelFunc) {
			s.ops.Hooks.BeforeTempWrite = func() error { cancel(); return nil }
		}, clear: func(s *Store) { s.ops.Hooks.BeforeTempWrite = nil }},
	}
	for _, phase := range phases {
		t.Run(phase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			phase.set(store, cancel)
			defer func() {
				cancel()
				phase.clear(store)
			}()
			if _, err := store.Put(ctx, ref, mustSecret(t, "new"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrCanceled) {
				t.Fatalf("canceled %s Put error = %v, want ErrCanceled", phase.name, err)
			}
		})
	}
	got, err := store.Resolve(context.Background(), ref)
	if err != nil || string(got.Value.Bytes()) != "old" {
		t.Fatalf("canceled phase state = %#v, %v, want old", got, err)
	}
}

func TestLocalStoreListIgnoresCorruptValuesOutsideNamespace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	target := mustReference(t, "local://visible/target")
	other := mustReference(t, "local://hidden/other")
	malformed := mustReference(t, "local://hidden/malformed")
	if _, err := store.Put(ctx, target, mustSecret(t, "target"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte(`{"schema":1,"reference":"local://hidden/other","value":"not-base64!!!","version":"v1","updated_at":"2026-01-01T00:00:00Z"}`)
	if err := os.WriteFile(filepath.Join(root, store.Filename(other)), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, store.Filename(malformed)), []byte(`{"schema":1,"reference":"local://hidden/malformed","value":%%%`), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidUTF8 := mustReference(t, "local://hidden/invalid-utf8")
	invalidData := append([]byte(`{"schema":1,"reference":"local://hidden/invalid-utf8","value":"`), 0xff)
	invalidData = append(invalidData, []byte(`"}`)...)
	if err := os.WriteFile(filepath.Join(root, store.Filename(invalidUTF8)), invalidData, 0o600); err != nil {
		t.Fatal(err)
	}
	nested := mustReference(t, "local://hidden/nested")
	if err := os.WriteFile(filepath.Join(root, store.Filename(nested)), []byte(`{"schema":1,"value":{"reference":"local://visible/fake"},"reference":%%%}`), 0o600); err != nil {
		t.Fatal(err)
	}
	longHidden := mustReference(t, "local://hidden/"+strings.Repeat("x", 220))
	longCorrupt := []byte(`{"schema":1,"reference":` + fmt.Sprintf("%q", longHidden.Canonical()) + `,"value":%%%}`)
	if err := os.WriteFile(filepath.Join(root, store.Filename(longHidden)), longCorrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	page, err := store.List(ctx, mustNamespace(t, "local://visible"), secrets.PageToken{}, 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].Reference != target {
		t.Fatalf("namespace List with unrelated corrupt value = %#v, %v", page, err)
	}
}

func TestLocalStoreListIgnoresLargeUnrelatedHashedValues(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	large := mustSecret(t, strings.Repeat("x", secrets.MaxSecretSize))
	for i := 0; i < 8; i++ {
		ref := mustReference(t, fmt.Sprintf("local://hidden/%s%d", strings.Repeat("x", 220), i))
		if _, err := store.Put(ctx, ref, large, secrets.UnconditionalPut()); err != nil {
			t.Fatalf("Put(%d): %v", i, err)
		}
	}
	target := mustReference(t, "local://visible/target")
	if _, err := store.Put(ctx, target, mustSecret(t, "target"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	page, err := store.List(ctx, mustNamespace(t, "local://visible"), secrets.PageToken{}, 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].Reference != target {
		t.Fatalf("namespace List with large unrelated values = %#v, %v", page, err)
	}
}

func TestLocalStoreListRejectsCopiedHashedFilename(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	target := mustReference(t, "local://hidden/"+strings.Repeat("x", 220)+"target")
	if _, err := store.Put(ctx, target, mustSecret(t, "value"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, store.Filename(target)))
	if err != nil {
		t.Fatal(err)
	}
	other := mustReference(t, "local://hidden/"+strings.Repeat("y", 220)+"other")
	if err := os.WriteFile(filepath.Join(root, store.Filename(other)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(ctx, mustNamespace(t, "local://hidden"), secrets.PageToken{}, 10); err == nil || !errors.Is(err, secrets.ErrCorruptRecord) {
		t.Fatalf("copied hashed filename List error = %v, want ErrCorruptRecord", err)
	}
}

func TestLocalStoreListRejectsUnrelatedRecordSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics are covered by the Windows unsupported test")
	}
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	other := mustReference(t, "local://hidden/symlink")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, store.Filename(other))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(context.Background(), mustNamespace(t, "local://visible"), secrets.PageToken{}, 1); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("unrelated record symlink List error = %v, want ErrInsecurePath", err)
	}
}

func TestLocalStoreRejectsLockReplacementAndInsecureModes(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "secrets")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("insecure root mode error = %v, want ErrInsecurePath", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://permissions/token")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(context.Background(), ref); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("changed root mode Resolve error = %v, want ErrInsecurePath", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, lockName)
	lockHandle, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockHandle.WriteString("unexpected metadata"); err != nil {
		_ = lockHandle.Close()
		t.Fatal(err)
	}
	if err := lockHandle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), mustReference(t, "local://lock/nonempty"), mustSecret(t, "value"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("non-empty lock Put error = %v, want ErrInsecurePath", err)
	}
	if err := os.Truncate(lockPath, 0); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(parent, "lock-backup")
	if err := os.Rename(lockPath, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ref = mustReference(t, "local://lock/token")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("lock replacement Put error = %v, want ErrInsecurePath", err)
	}

	// A replacement racing with the pre-linearization window is rejected too.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(parent, "racing")
	store, err = NewWithOptions(root, Options{Hooks: Hooks{BeforeRename: func() error {
		lockPath := filepath.Join(root, lockName)
		if err := os.Rename(lockPath, filepath.Join(parent, "racing-lock-backup")); err != nil {
			return err
		}
		return os.WriteFile(lockPath, nil, 0o600)
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Put(context.Background(), mustReference(t, "local://lock/race"), mustSecret(t, "value"), secrets.UnconditionalPut()); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("racing lock replacement Put error = %v, want ErrInsecurePath", err)
	}
}

func TestNewRejectsNonRegularLock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, lockName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
		t.Fatalf("non-regular lock error = %v, want ErrInsecurePath", err)
	}
}

func mustReference(t *testing.T, raw string) secrets.Reference {
	t.Helper()
	ref, err := secrets.ParseReference(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func mustSecret(t *testing.T, raw string) secrets.Secret {
	t.Helper()
	value, err := secrets.New([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustNamespace(t *testing.T, raw string) secrets.Namespace {
	t.Helper()
	ns, err := secrets.ParseNamespace(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ns
}
