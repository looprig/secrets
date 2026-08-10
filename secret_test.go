package secrets

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretCopiesInputAndOutput(t *testing.T) {
	input := []byte("top-secret")
	value, err := New(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	if got := string(value.Bytes()); got != "top-secret" {
		t.Fatalf("input mutation changed secret: got %q", got)
	}

	output := value.Bytes()
	output[0] = 'X'
	if got := string(value.Bytes()); got != "top-secret" {
		t.Fatalf("output mutation changed secret: got %q", got)
	}
	if !value.Valid() || value.IsZero() {
		t.Fatal("constructed secret should be valid and non-zero")
	}
}

func TestSecretRejectsZeroAndOversizedValues(t *testing.T) {
	for _, input := range [][]byte{nil, {}, []byte{}} {
		if value, err := New(input); err == nil || !value.IsZero() {
			t.Fatalf("New(%#v) = (%v, %v), want zero value and error", input, value, err)
		}
	}
	if value, err := New(bytes.Repeat([]byte{'x'}, MaxSecretSize+1)); err == nil || !value.IsZero() {
		t.Fatalf("oversized New returned (%v, %v), want zero value and error", value, err)
	}

	var zero Secret
	if zero.Valid() || !zero.IsZero() || zero.Bytes() != nil {
		t.Fatalf("zero Secret has discloseable state: valid=%v zero=%v bytes=%#v", zero.Valid(), zero.IsZero(), zero.Bytes())
	}
}

func TestSecretRedactsEveryFormattingVerb(t *testing.T) {
	value, err := New([]byte("top-secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		got := fmt.Sprintf(format, value)
		if strings.Contains(got, "top-secret") {
			t.Fatalf("format %q leaked secret: %q", format, got)
		}
		if got == "" {
			t.Fatalf("format %q produced an empty redaction", format)
		}
	}

	if got := value.String(); strings.Contains(got, "top-secret") || got == "" {
		t.Fatalf("String leaked or omitted redaction: %q", got)
	}
	if got := value.GoString(); strings.Contains(got, "top-secret") || got == "" {
		t.Fatalf("GoString leaked or omitted redaction: %q", got)
	}
	if got := value.LogValue(); got.Kind() != slog.KindString || strings.Contains(got.String(), "top-secret") {
		t.Fatalf("LogValue leaked or used unexpected value: kind=%v value=%q", got.Kind(), got.String())
	}
}

func TestSecretRedactsThroughSlog(t *testing.T) {
	value, err := New([]byte("top-secret"))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	logger.Info("secret event", "secret", value)
	if strings.Contains(output.String(), "top-secret") {
		t.Fatalf("slog output leaked secret: %q", output.String())
	}
}

func TestSecretFormatterRedactsAllVerbsFlagsAndNesting(t *testing.T) {
	value, err := New([]byte("top-secret"))
	if err != nil {
		t.Fatal(err)
	}
	formats := []string{
		"%s", "%v", "%+v", "%#v", "%d", "%+d", "%#d", "%b", "%#b",
		"%x", "%#x", "%X", "%q", "%20s", "%.3s", "%020d", "%#20x",
	}
	for _, format := range formats {
		if got := fmt.Sprintf(format, value); got != redactedSecret {
			t.Errorf("format %q = %q, want fixed redaction %q", format, got, redactedSecret)
		}
		if got := fmt.Sprintf(format, &value); got != redactedSecret {
			t.Errorf("pointer format %q = %q, want fixed redaction %q", format, got, redactedSecret)
		}
	}
	record := Record{Value: value}
	for _, format := range formats {
		got := fmt.Sprintf(format, record)
		if strings.Contains(got, "top-secret") || !strings.Contains(got, redactedSecret) {
			t.Errorf("nested record format %q leaked or omitted redaction: %q", format, got)
		}
	}
	var output bytes.Buffer
	slog.New(slog.NewTextHandler(&output, nil)).Info("secret event", "value", &value, "record", record)
	if strings.Contains(output.String(), "top-secret") || !strings.Contains(output.String(), redactedSecret) {
		t.Fatalf("slog formatting leaked or omitted redaction: %q", output.String())
	}
}
