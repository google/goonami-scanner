# Package `hash`

Package `hash` computes deterministic 128-bit Murmur3 hashes of HTTP
responses for the `fp/webidentity` fingerprinter, declarative matcher, and
downstream detectors such as `dt/adkweakcreds`. It digests the response status
code, `Content-Type` header, and response body into a 32-character lowercase hex
string.

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

## Usage

```go
import (
  "net/http"

  "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
)

func hashResponse(resp *http.Response, body []byte) (string, error) {
  h, err := hash.FromResponse(resp, body)
  if err != nil {
    return "", err
  }
  return h.Hex(), nil
}
```
