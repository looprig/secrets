package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

func TestPutOptionsValidatePreconditions(t *testing.T) {
	version, err := NewVersion("backend-v1")
	if err != nil {
		t.Fatal(err)
	}
	valid := []PutOptions{
		{},
		{Precondition: PreconditionCreateOnly},
		{Precondition: PreconditionCompareAndSwap, ExpectedVersion: version},
	}
	for _, options := range valid {
		if err := options.Validate(); err != nil {
			t.Errorf("PutOptions %#v rejected: %v", options, err)
		}
	}
	invalid := []PutOptions{
		{Precondition: PreconditionCompareAndSwap},
		{Precondition: PreconditionCompareAndSwap, ExpectedVersion: VersionUnsupported},
		{ExpectedVersion: version},
		{Precondition: Precondition(255)},
	}
	for _, options := range invalid {
		if err := options.Validate(); err == nil {
			t.Errorf("PutOptions %#v unexpectedly accepted", options)
		} else if !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("PutOptions %#v error = %v, want ErrInvalidOptions", options, err)
		}
	}
}

func TestDeleteOptionsValidatePreconditions(t *testing.T) {
	version, err := NewVersion("backend-v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range []DeleteOptions{{}, {Precondition: PreconditionCompareAndSwap, ExpectedVersion: version}} {
		if err := options.Validate(); err != nil {
			t.Errorf("DeleteOptions %#v rejected: %v", options, err)
		}
	}
	for _, options := range []DeleteOptions{
		{Precondition: PreconditionCompareAndSwap},
		{Precondition: PreconditionCompareAndSwap, ExpectedVersion: VersionUnsupported},
		{ExpectedVersion: version},
		{Precondition: Precondition(255)},
	} {
		if err := options.Validate(); err == nil {
			t.Errorf("DeleteOptions %#v unexpectedly accepted", options)
		} else if !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("DeleteOptions %#v error = %v, want ErrInvalidOptions", options, err)
		}
	}
}

func TestVersionAndMetadataValidation(t *testing.T) {
	ref, err := ParseReference("local://openai/personal/token")
	if err != nil {
		t.Fatal(err)
	}
	value, err := New([]byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	version, err := NewVersion("backend-v1")
	if err != nil {
		t.Fatal(err)
	}
	record := Record{Reference: ref, Value: value, Version: version}
	if err := record.Validate(); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	metadata := record.Metadata()
	if err := metadata.Validate(); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}
	if metadata.Reference != ref || metadata.Version != version {
		t.Fatalf("metadata did not preserve safe coordination fields: %#v", metadata)
	}
	if err := (Record{Reference: ref, Version: version}).Validate(); !errors.Is(err, ErrZeroSecret) {
		t.Fatalf("zero-value record error = %v, want ErrZeroSecret", err)
	}
	if err := (Record{Reference: ref, Value: value}).Validate(); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("unversioned record error = %v, want ErrInvalidVersion", err)
	}
	if err := (Metadata{Reference: ref}).Validate(); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("unversioned metadata error = %v, want ErrInvalidVersion", err)
	}
	if _, err := NewVersion(VersionUnsupported.String()); err == nil || !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("reserved version error = %v, want ErrInvalidVersion", err)
	}
}

func TestPageTokenAndPageValidationCopiesItems(t *testing.T) {
	token, err := NewPageToken("cursor-1")
	if err != nil {
		t.Fatal(err)
	}
	items := []Metadata{{Reference: mustReference(t, "local://openai/personal/token"), Version: VersionUnsupported}}
	page, err := NewPage(items, token)
	if err != nil {
		t.Fatal(err)
	}
	items[0] = Metadata{}
	if page.Items[0].Reference.IsZero() {
		t.Fatal("NewPage did not copy items")
	}
	if err := page.Validate(1); err != nil {
		t.Fatalf("valid page rejected: %v", err)
	}
	for _, limit := range []int{0, MaxPageItems + 1} {
		if err := page.Validate(limit); err == nil {
			t.Errorf("page accepted invalid limit %d", limit)
		}
	}
	if _, err := NewPage(make([]Metadata, MaxPageItems+1), token); err == nil || !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("oversized page error = %v, want ErrInvalidOptions", err)
	}
	if _, err := NewPage([]Metadata{{}}, PageToken{value: "\n"}); err == nil || !errors.Is(err, ErrInvalidPageToken) {
		t.Fatalf("invalid token error = %v, want ErrInvalidPageToken", err)
	}
	for _, raw := range []string{"\n", strings.Repeat("x", MaxPageTokenLength+1)} {
		if token, err := NewPageToken(raw); err == nil || !token.IsZero() {
			t.Fatalf("NewPageToken(%q) = (%q, %v), want zero token and error", raw, token, err)
		}
	}
	if _, ok := reflect.TypeOf(Metadata{}).FieldByName("Value"); ok {
		t.Fatal("Metadata exposes a secret value field")
	}
}

func TestDeleteResultUsesOneValidatedStatus(t *testing.T) {
	ref := mustReference(t, "local://openai/personal/token")
	version, err := NewVersion("backend-v1")
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := NewDeleteResult(ref, DeleteStatusDeleted, version)
	if err != nil || deleted.Status != DeleteStatusDeleted {
		t.Fatalf("deleted result = %#v, %v", deleted, err)
	}
	absent, err := NewDeleteResult(ref, DeleteStatusAbsent, VersionUnsupported)
	if err != nil || absent.Status != DeleteStatusAbsent {
		t.Fatalf("absent result = %#v, %v", absent, err)
	}
	for _, result := range []DeleteResult{
		{Reference: ref, Status: DeleteStatusDeleted},
		{Reference: ref, Status: DeleteStatusAbsent, Version: version},
		{Reference: ref, Status: DeleteStatus(255), Version: VersionUnsupported},
	} {
		if err := result.Validate(); err == nil {
			t.Errorf("invalid delete result accepted: %#v", result)
		}
	}
	typ := reflect.TypeOf(DeleteResult{})
	if _, ok := typ.FieldByName("Deleted"); ok {
		t.Fatal("DeleteResult retains ambiguous Deleted field")
	}
	if _, ok := typ.FieldByName("Existed"); ok {
		t.Fatal("DeleteResult retains ambiguous Existed field")
	}
	if _, ok := typ.FieldByName("Found"); ok {
		t.Fatal("DeleteResult retains ambiguous Found field")
	}
}

func TestVersionAndPageTokenUseOpaqueComparableRepresentations(t *testing.T) {
	if got := reflect.TypeOf(Version{}).Kind(); got != reflect.Struct {
		t.Fatalf("Version underlying kind = %v, want struct", got)
	}
	if got := reflect.TypeOf(PageToken{}).Kind(); got != reflect.Struct {
		t.Fatalf("PageToken underlying kind = %v, want struct", got)
	}
	version, err := NewVersion("backend-v1")
	if err != nil {
		t.Fatal(err)
	}
	if version == VersionUnsupported || version.IsUnsupported() {
		t.Fatal("supported Version collided with VersionUnsupported")
	}
	token, err := NewPageToken("cursor-1")
	if err != nil {
		t.Fatal(err)
	}
	if token.IsZero() || !token.Valid() || token.String() != "cursor-1" {
		t.Fatalf("constructed PageToken is invalid: %#v", token)
	}
}

func TestVersionAndPageTokenConstructorsEnforceBounds(t *testing.T) {
	for _, raw := range []string{"", "\n", strings.Repeat("v", MaxVersionLength+1), VersionUnsupported.String()} {
		version, err := NewVersion(raw)
		if err == nil || !version.IsZero() {
			t.Fatalf("NewVersion(%q) = (%#v, %v), want zero value and error", raw, version, err)
		}
	}
	version, err := NewVersion("backend-v1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := version.MarshalText()
	if err != nil || string(encoded) != "backend-v1" {
		t.Fatalf("Version.MarshalText() = (%q, %v)", encoded, err)
	}
	var decoded Version
	if err := decoded.UnmarshalText(encoded); err != nil || decoded != version {
		t.Fatalf("Version.UnmarshalText() = (%#v, %v), want %#v", decoded, err, version)
	}

	for _, raw := range []string{"\n", strings.Repeat("t", MaxPageTokenLength+1)} {
		token, err := NewPageToken(raw)
		if err == nil || !token.IsZero() {
			t.Fatalf("NewPageToken(%q) = (%#v, %v), want zero value and error", raw, token, err)
		}
	}
	token, err := NewPageToken("cursor-1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = token.MarshalText()
	if err != nil || string(encoded) != "cursor-1" {
		t.Fatalf("PageToken.MarshalText() = (%q, %v)", encoded, err)
	}
	var decodedToken PageToken
	if err := decodedToken.UnmarshalText(encoded); err != nil || decodedToken != token {
		t.Fatalf("PageToken.UnmarshalText() = (%#v, %v), want %#v", decodedToken, err, token)
	}
}

func TestVersionAndPageTokenErrorsUseClosedReasonLabels(t *testing.T) {
	if got := NewInvalidVersionError("version").Reason(); got != "version" {
		t.Fatalf("version reason = %q, want version", got)
	}
	if got := NewInvalidPageTokenError("token").Reason(); got != "token" {
		t.Fatalf("token reason = %q, want token", got)
	}
}

func TestVersionAndPageTokenUnmarshalRejectOversizedBytesBeforeParsing(t *testing.T) {
	versionInput := make([]byte, MaxVersionLength+1)
	for i := range versionInput {
		versionInput[i] = 'v'
	}
	var version Version
	if err := version.UnmarshalText(versionInput); err == nil {
		t.Fatal("oversized version unexpectedly accepted")
	} else if typed, ok := err.(*InvalidVersionError); !ok || typed.Reason() != "length" {
		t.Fatalf("oversized version error = %T %v, want length reason", err, err)
	}

	tokenInput := make([]byte, MaxPageTokenLength+1)
	for i := range tokenInput {
		tokenInput[i] = 't'
	}
	var token PageToken
	if err := token.UnmarshalText(tokenInput); err == nil {
		t.Fatal("oversized page token unexpectedly accepted")
	} else if typed, ok := err.(*InvalidPageTokenError); !ok || typed.Reason() != "length" {
		t.Fatalf("oversized page token error = %T %v, want length reason", err, err)
	}
}

func TestDeleteResultUnsupportedVersionIsExplicitlyNonCAS(t *testing.T) {
	ref := mustReference(t, "local://openai/personal/token")
	result, err := NewDeleteResult(ref, DeleteStatusDeleted, VersionUnsupported)
	if err != nil {
		t.Fatalf("unconditional delete without comparable versions rejected: %v", err)
	}
	if !result.Version.IsUnsupported() || result.Version == (Version{}) {
		t.Fatalf("delete result did not preserve explicit unsupported marker: %#v", result)
	}
	if err := (DeleteOptions{Precondition: PreconditionCompareAndSwap, ExpectedVersion: VersionUnsupported}).Validate(); err == nil {
		t.Fatal("VersionUnsupported incorrectly permitted as a CAS precondition")
	}
}

func TestProviderErrorConstructorsDoNotAcceptDiscardedPayloads(t *testing.T) {
	constructors := []struct {
		name string
		fn   any
	}{
		{"unsupported scheme", NewUnsupportedSchemeError},
		{"unsupported capability", NewUnsupportedCapabilityError},
		{"corrupt record", NewCorruptRecordError},
		{"conflict", NewConflictError},
		{"unavailable", NewUnavailableError},
	}
	for _, tc := range constructors {
		t.Run(tc.name, func(t *testing.T) {
			if reflect.TypeOf(tc.fn).IsVariadic() {
				t.Fatal("constructor accepts discarded provider payloads")
			}
		})
	}
}

func mustReference(t *testing.T, raw string) Reference {
	t.Helper()
	ref, err := ParseReference(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestPublicErrorsNeverFormatSecretBearingPayloads(t *testing.T) {
	const secret = "top-secret-provider-response"
	ref, err := ParseReference("local://openai/personal/token")
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New(secret)
	wrappedCanceled := fmt.Errorf("request failed: %w", context.Canceled)
	errs := []error{
		&EmptySecretError{},
		&SecretSizeError{Limit: MaxSecretSize, Got: MaxSecretSize + 1},
		&ZeroSecretError{},
		NewInvalidReferenceError(secret),
		NewInvalidNamespaceError(secret),
		NewInvalidVersionError(secret),
		NewInvalidPageTokenError(secret),
		NewInvalidOptionsError(secret),
		NewNotFoundError(ref),
		NewUnsupportedSchemeError(),
		NewUnsupportedCapabilityError(),
		NewInsecurePathError(secret),
		NewCorruptRecordError(ref),
		NewConflictError(ref),
		NewUnavailableError("resolve", ref),
		NewCanceledError(secret, wrappedCanceled),
	}
	for _, publicErr := range errs {
		t.Run(fmt.Sprintf("%T", publicErr), func(t *testing.T) {
			for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
				got := fmt.Sprintf(format, publicErr)
				if strings.Contains(got, secret) {
					t.Errorf("format %q leaked %q: %q", format, secret, got)
				}
			}
			var output strings.Builder
			slog.New(slog.NewTextHandler(&output, nil)).Info("error event", "error", publicErr)
			if strings.Contains(output.String(), secret) {
				t.Errorf("slog leaked %q: %q", secret, output.String())
			}
		})
	}

	if errors.Is(NewUnavailableError("resolve", ref), cause) {
		t.Fatal("unavailable error retained arbitrary cause for errors.Is")
	}
	if errors.Is(NewCanceledError(secret, wrappedCanceled), wrappedCanceled) {
		t.Fatal("canceled error retained arbitrary cause for errors.Is")
	}
	if !errors.Is(NewCanceledError("resolve", wrappedCanceled), context.Canceled) {
		t.Fatal("canceled error lost normalized context.Canceled identity")
	}
}

func TestPublicErrorsPreserveOnlyKnownSentinels(t *testing.T) {
	ref := mustReference(t, "local://openai/personal/token")
	secretCause := errors.New("provider response: top-secret")
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"empty secret", &EmptySecretError{}, ErrEmptySecret},
		{"oversized secret", &SecretSizeError{Limit: MaxSecretSize, Got: MaxSecretSize + 1}, ErrSecretTooLarge},
		{"zero secret", &ZeroSecretError{}, ErrZeroSecret},
		{"invalid reference", NewInvalidReferenceError("secret"), ErrInvalidReference},
		{"invalid namespace", NewInvalidNamespaceError("secret"), ErrInvalidNamespace},
		{"invalid version", NewInvalidVersionError("secret"), ErrInvalidVersion},
		{"invalid page token", NewInvalidPageTokenError("secret"), ErrInvalidPageToken},
		{"invalid options", NewInvalidOptionsError("secret"), ErrInvalidOptions},
		{"not found", NewNotFoundError(ref), ErrNotFound},
		{"unsupported scheme", NewUnsupportedSchemeError(), ErrUnsupportedScheme},
		{"unsupported capability", NewUnsupportedCapabilityError(), ErrUnsupportedCapability},
		{"insecure path", NewInsecurePathError("secret"), ErrInsecurePath},
		{"corrupt record", NewCorruptRecordError(ref), ErrCorruptRecord},
		{"conflict", NewConflictError(ref), ErrConflict},
		{"unavailable", NewUnavailableError("resolve", ref), ErrUnavailable},
		{"canceled", NewCanceledError("secret", secretCause), ErrCanceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.want) {
				t.Fatalf("errors.Is(%v, %v) = false", tc.err, tc.want)
			}
			if errors.Is(tc.err, secretCause) {
				t.Fatal("error retained arbitrary provider cause")
			}
		})
	}
	if !errors.Is(NewCanceledError("resolve", fmt.Errorf("wrapped: %w", context.Canceled)), context.Canceled) {
		t.Fatal("normalized cancellation no longer matches context.Canceled")
	}
	if !errors.Is(NewCanceledError("resolve", fmt.Errorf("wrapped: %w", context.DeadlineExceeded)), context.DeadlineExceeded) {
		t.Fatal("normalized cancellation no longer matches context.DeadlineExceeded")
	}
}

func TestVisibleCommitClassificationIsGenericAndSafe(t *testing.T) {
	if !IsVisibleCommit(visibleCommitTestError{}) {
		t.Fatal("visible commit error was not classified")
	}
	if IsVisibleCommit(errors.New("pre-linearization failure")) {
		t.Fatal("pre-linearization failure was classified as visible")
	}
}

type visibleCommitTestError struct{}

func (visibleCommitTestError) Error() string { return "visible commit" }
func (visibleCommitTestError) Visible() bool { return true }
