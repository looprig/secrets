//go:build darwin || linux

package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/looprig/secrets"
)

func TestIdentityPreservesNativeStatFields(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin's signed dev_t is the conversion regression")
	}
	stat := &unix.Stat_t{Dev: 42, Ino: 99}
	got := identity(stat)
	if !reflect.DeepEqual(got.dev, stat.Dev) {
		t.Fatalf("identity device = %#v (%T), want native %#v (%T)", got.dev, got.dev, stat.Dev, stat.Dev)
	}
	if !reflect.DeepEqual(got.ino, stat.Ino) {
		t.Fatalf("identity inode = %#v (%T), want native %#v (%T)", got.ino, got.ino, stat.Ino, stat.Ino)
	}
}

func TestUIDMatchesPreserves32BitPattern(t *testing.T) {
	tests := []struct {
		name       string
		statUID    uint32
		processUID int
		want       bool
	}{
		{name: "ordinary uid", statUID: 1000, processUID: 1000, want: true},
		{name: "high bit uid sign extended", statUID: 0x80000000, processUID: -2147483648, want: true},
		{name: "all bits uid sign extended", statUID: 0xffffffff, processUID: -1, want: true},
		{name: "different high bit uid", statUID: 0x80000000, processUID: -1, want: false},
		{name: "negative uid is not ordinary uid", statUID: 1000, processUID: -1, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := uidMatches(tc.statUID, tc.processUID); got != tc.want {
				t.Fatalf("uidMatches(%#x, %d) = %t, want %t", tc.statUID, tc.processUID, got, tc.want)
			}
		})
	}
}

func TestUnixReadPermissionErrorClosesOpenedDescriptor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := mustReference(t, "local://fd-errors/token")
	if _, err := store.Put(context.Background(), ref, mustSecret(t, "value"), secrets.UnconditionalPut()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, store.Filename(ref))
	platform, ok := store.impl.(*unixPlatform)
	if !ok {
		t.Fatal("store is not backed by unixPlatform")
	}
	platform.beforeReadFstat = func(fd int) error {
		return unix.Fchmod(fd, 0o644)
	}
	fdBefore := countOpenDescriptors(t)
	for i := 0; i < 64; i++ {
		_, err := platform.read(store.Filename(ref))
		if err == nil || !errors.Is(err, errInsecure) {
			t.Fatalf("permission read error = %v, want errInsecure", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fdAfter := countOpenDescriptors(t)
	if fdAfter > fdBefore+2 {
		t.Fatalf("open descriptor count grew from %d to %d after read errors", fdBefore, fdAfter)
	}
}

func TestUnixRejectingRootClosesDescriptor(t *testing.T) {
	fdBefore := countOpenDescriptors(t)
	for i := 0; i < 64; i++ {
		if _, err := New("/"); err == nil || !errors.Is(err, secrets.ErrInsecurePath) {
			t.Fatalf("New(/) error = %v, want ErrInsecurePath", err)
		}
	}
	fdAfter := countOpenDescriptors(t)
	if fdAfter > fdBefore+2 {
		t.Fatalf("open descriptor count grew from %d to %d after rejecting roots", fdBefore, fdAfter)
	}
}

func countOpenDescriptors(t *testing.T) int {
	t.Helper()
	var lastErr error
	for _, path := range []string{"/proc/self/fd", "/dev/fd"} {
		dir, err := os.Open(path)
		if err == nil {
			names, readErr := dir.Readdirnames(-1)
			_ = dir.Close()
			if readErr == nil {
				return len(names)
			}
			err = readErr
		}
		lastErr = err
	}
	t.Skipf("descriptor enumeration unavailable: %v", lastErr)
	return 0
}
