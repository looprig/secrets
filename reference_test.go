package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestParseReferenceCanonicalizesSchemeAndPreservesOpaquePath(t *testing.T) {
	ref, err := ParseReference("LOCAL://OpenAI/personal/refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ref.String(), "local://OpenAI/personal/refresh-token"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if got, want := ref.Canonical(), "local://OpenAI/personal/refresh-token"; got != want {
		t.Fatalf("Canonical() = %q, want %q", got, want)
	}
	if got, want := ref.Scheme(), "local"; got != want {
		t.Fatalf("Scheme() = %q, want %q", got, want)
	}
	if got, want := ref.Path(), "OpenAI/personal/refresh-token"; got != want {
		t.Fatalf("Path() = %q, want %q", got, want)
	}
}

func TestParseReferenceRejectsUnsafeOrNonCanonicalContent(t *testing.T) {
	unsafe := []string{
		"",
		"local:",
		"local:/openai/token",
		"local://",
		"local://openai/token?query=secret",
		"local://openai/token#fragment",
		"local://openai//token",
		"local://openai/./token",
		"local://openai/../token",
		"local://../token",
		"local:///tmp/token",
		"local://C:/Users/token",
		"local://C:\\Users\\token",
		"file://etc/passwd",
		"https://example.invalid/token",
		"local://openai/token%2Fother",
		"local://openai/token with spaces",
		"local://openai/token\x00",
	}
	for _, raw := range unsafe {
		t.Run(raw, func(t *testing.T) {
			ref, err := ParseReference(raw)
			if err == nil || !ref.IsZero() {
				t.Fatalf("ParseReference(%q) = (%q, %v), want zero value and error", raw, ref, err)
			}
			var invalid *InvalidReferenceError
			if !errors.As(err, &invalid) {
				t.Fatalf("ParseReference(%q) error type = %T, want InvalidReferenceError", raw, err)
			}
			if strings.Contains(err.Error(), "top-secret") || strings.Contains(err.Error(), "query=secret") {
				t.Fatalf("error may disclose input: %q", err)
			}
		})
	}
}

func TestReferenceCanonicalizationIsBounded(t *testing.T) {
	if _, err := ParseReference("local://" + strings.Repeat("a", MaxReferenceLength)); err == nil {
		t.Fatal("oversized reference was accepted")
	}
	if _, err := NewReference("local", strings.Repeat("a", MaxReferencePathLength+1)); err == nil {
		t.Fatal("oversized reference path was accepted")
	}
	ref, err := NewReference("LOCAL", "openai/personal/token")
	if err != nil {
		t.Fatal(err)
	}
	if len(ref.Canonical()) > MaxReferenceLength {
		t.Fatalf("canonical reference exceeded bound: %d", len(ref.Canonical()))
	}
}

func TestReferenceUnmarshalRejectsOversizedBytesBeforeParsing(t *testing.T) {
	input := make([]byte, MaxReferenceLength+1)
	copy(input, "local://")
	for i := len("local://"); i < len(input); i++ {
		input[i] = 'r'
	}
	var ref Reference
	if err := ref.UnmarshalText(input); err == nil {
		t.Fatal("oversized reference unexpectedly accepted")
	} else if typed, ok := err.(*InvalidReferenceError); !ok || typed.Reason() != "length" {
		t.Fatalf("oversized reference error = %T %v, want length reason", err, err)
	}
}

func TestNamespaceContainsOnlyItsCanonicalPathPrefix(t *testing.T) {
	ns, err := NewNamespace("local", "openai/personal")
	if err != nil {
		t.Fatal(err)
	}
	inside, err := ParseReference("local://openai/personal/refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	exact, err := ParseReference("local://openai/personal")
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseReference("local://openai/personally/refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	differentScheme, err := ParseReference("vault://openai/personal/refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if !ns.Contains(inside) || !ns.Contains(exact) {
		t.Fatal("namespace did not contain its exact or descendant reference")
	}
	if ns.Contains(out) || ns.Contains(differentScheme) {
		t.Fatal("namespace widened beyond its scheme/path boundary")
	}
}

func TestParseNamespaceCanonicalizesTrailingPrefixSeparator(t *testing.T) {
	ns, err := ParseNamespace("LOCAL://openai/personal/")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ns.String(), "local://openai/personal"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestVersionUnsupportedTextIsReserved(t *testing.T) {
	got, err := NewVersion(VersionUnsupported.String())
	if err == nil || !got.IsZero() {
		t.Fatalf("NewVersion(%q) = (%q, %v), want zero version and error", VersionUnsupported, got, err)
	}
	if !VersionUnsupported.Valid() || !VersionUnsupported.IsUnsupported() {
		t.Fatalf("explicit VersionUnsupported must remain a valid unsupported marker: %#v", VersionUnsupported)
	}
	ref, err := ParseReference("local://openai/personal/token")
	if err != nil {
		t.Fatal(err)
	}
	value, err := New([]byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	if err := (Record{Reference: ref, Value: value, Version: VersionUnsupported}).Validate(); err != nil {
		t.Fatalf("record with explicit unsupported version rejected: %v", err)
	}
}
