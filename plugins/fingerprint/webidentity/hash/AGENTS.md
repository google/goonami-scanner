# Package `hash`

Package `hash` computes HTTP response hashes and matches them against known web
application signatures for the `fp/webidentity` fingerprinter and downstream
detectors such as `dt/adkweakcreds`. It hashes an HTTP response's status code,
`Content-Type` header, and body using 128-bit Murmur3 to produce a deterministic
hex digest. It also provides an in-memory `Registry` that indexes `Fingerprints`
protobuf definitions by 64-bit Murmur3 keys to resolve observed page hashes and
URLs into software names, candidate application roots, and version sets.

## Services

-   **`Hash`, `New(resp)`, `(*Hash).Update(buffer)`, and `(*Hash).Hex()`**:
    Streaming 128-bit Murmur3 HTTP response hasher seeded by `New` with the
    little-endian `uint32` status code and `Content-Type` header of `resp`.
    `Update` writes response body chunks into the digest, and `Hex` encodes the
    128-bit sum in little-endian byte order as a 32-character lowercase hex
    string.
-   **`FromResponse(resp, content)`**: Convenience helper that calls `New(resp)`
    and `Update(content)` to compute the `*Hash` for a complete HTTP response
    and body slice in one call.
-   **`Identity`**: Represents a matched web application with exported
    `Software` (product name), `PotentialRoots` (candidate application root URLs
    or registered content paths), and `Versions` (candidate version strings)
    fields.
-   **`(*Identity).IntersectVersions(newmatch)`**: Narrows `Versions` on the
    receiver in place to the set intersection with `newmatch` when `newmatch` is
    non-nil and has the same `Software` name. Leaves the receiver unchanged when
    `newmatch` is `nil`, targets different software, or shares no common
    versions.
-   **`Registry`, `NewRegistry()`, and `(*Registry).Count()`**: In-memory lookup
    table initialized by `NewRegistry` that maps 64-bit Murmur3 keys of hex
    signature hashes to `*Identity` entries (populate before concurrent reads,
    as mutations are not synchronized). `Count` returns the total number of hash
    keys stored in the registry, including entries invalidated by cross-software
    collisions.
-   **`(*Registry).Load(fingerprints)`**: Indexes `HashVersions` and
    `ContentHashes` from a `*fpb.Fingerprints` protobuf message under its
    software name while deduplicating version strings and content paths. If a
    hash key collides across two different software names, the entry is
    invalidated so subsequent loads and lookups ignore it.
-   **`(*Registry).Find(hash, path)`**: Looks up a hex response `hash` and
    observed URL or request `path`, returning a new `*Identity` whose
    `PotentialRoots` are derived by trimming matching content-path suffixes from
    `path`. Returns `nil` if the hash is absent, invalidated, or associated with
    content paths none of which match `path` as a suffix.

## Usage

```go
import (
  "net/http"

  "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
  fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprints_go_proto"
)

func newSignatureRegistry(sigs []*fpb.Fingerprints) (*hash.Registry, error) {
  reg := hash.NewRegistry()
  for _, fp := range sigs {
    if err := reg.Load(fp); err != nil {
      return nil, err
    }
  }
  return reg, nil
}

func matchPage(
    reg *hash.Registry,
    known *hash.Identity,
    pageURL string,
    resp *http.Response,
    body []byte,
) (*hash.Identity, error) {
  h, err := hash.FromResponse(resp, body)
  if err != nil {
    return nil, err
  }
  match := reg.Find(h.Hex(), pageURL)
  if known != nil && match != nil {
    known.IntersectVersions(match)
    return known, nil
  }
  return match, nil
}
```
