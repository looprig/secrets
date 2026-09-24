# secrets

`github.com/looprig/secrets` defines Looprig's secret-value and secret-storage
contracts, plus an owner-only local store. A `Secret` is an immutable opaque
value whose bytes are redacted from every ordinary formatting and structured
logging path; callers opt in to `Bytes()` only at the point where the value is
consumed. Secrets are addressed by a validated `Reference` (`scheme://path`),
never by a filesystem path or environment variable.

The module depends only on the Go standard library and `golang.org/x/sys`.

## Status

Released and in use by `credentials`, `inference` and `llm`.

- The root package provides `Secret`, `Reference`, `Namespace`, `Version`, the
  `Resolver` / `Store` / `Lister` interfaces, put and delete preconditions
  (unconditional, create-only, compare-and-swap), bounded paging and a typed
  error vocabulary.
- `local` is the only bundled store. It uses the `local://` scheme and needs an
  explicit absolute, clean root directory. It keeps owner-only files (`0600` in
  `0700` directories) and does descriptor-relative I/O.

Known limits:

- `local` works on Linux and macOS only. On Windows and other platforms
  `local.New` fails with `*local.UnsupportedPlatformError`.
- A value is limited to `MaxSecretSize` (1 MiB).
- A write whose commit is visible but whose durability could not be confirmed
  is reported as `local.ErrDurabilityUnknown`, not as success. Use
  `secrets.IsVisibleCommit(err)` to tell it apart from a write that never
  landed.

## Install

```sh
go get github.com/looprig/secrets@latest
```

## Packages

| Package | Purpose |
|---|---|
| `secrets` | Opaque `Secret` values, references, namespaces, versions, store contracts and errors. |
| `secrets/local` | Owner-only local filesystem `Store` and `Lister` rooted at a caller-supplied directory. |
| `secrets/contracttest` | Reusable contract checks (`RunStore`, `RunList`) for any `secrets.Store` implementation. |

## Usage

```go
store, err := local.New(root) // root must be absolute and clean
if err != nil {
	return err
}
defer store.Close()

ref, err := secrets.ParseReference("local://service/token")
if err != nil {
	return err
}
value, err := secrets.New([]byte("initial-value"))
if err != nil {
	return err
}

created, err := store.Put(ctx, ref, value, secrets.CreateOnlyPut())
if err != nil {
	return err
}
record, err := store.Resolve(ctx, ref)
if err != nil {
	return err
}
_ = record.Value.Bytes() // explicit consumption boundary

_, err = store.Delete(ctx, ref, secrets.CompareAndSwapDelete(created.Version))
```

Runnable programs live in `examples/`: `secret-safety`, `references`,
`local-store`, and `contracttest` (which runs the contract suite against the
local store).

## Where it sits

Tier 0 in the Looprig workspace: it has no Looprig dependencies. Direct
dependents are `credentials`, `inference` and `llm`.

## Development

The Go baseline is 1.26.8. Verify the module standalone:

```sh
GOWORK=off go test ./...
make check   # gofmt check, vet, staticcheck, gosec, govulncheck, race tests, build
```

Individual targets: `fmt`, `fmt-check`, `vet`, `test`, `check-staticcheck`,
`check-gosec`, `check-vuln`, `build`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
