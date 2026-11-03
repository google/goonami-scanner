# Package `netutils`

Package `netutils` provides URL and domain formatting and parsing utilities for
Goonami's out-of-band callback server. Callback server clients use it to
construct HTTP callback URLs and DNS callback domains that embed a callback
identifier (CBID). Callback server HTTP and DNS recording handlers use it to
extract and validate CBIDs from incoming requests and queries.

## Services

-   **`CallbackURL(uri string, cbid string) string`**: Constructs an HTTP
    callback URL by trimming a trailing slash from `uri` and appending `cbid` as
    the path segment (`<uri>/<cbid>`).
-   **`CallbackDomain(domain string, cbid string) (string, error)`**: Constructs
    a DNS callback domain by prepending `cbid` as a subdomain label
    (`<cbid>.<domain>`), preserving any trailing dot on FQDNs.
-   **`IdentifierFromURL(httpURL string) (string, error)`**: Parses an HTTP URL
    or path, extracts its single path segment while ignoring query parameters
    and fragments, and validates it with `cbid.Validate`. Returns
    `ErrFailedToParseURL` on URL parse errors, `ErrInvalidURL` if the path is
    empty or contains multiple segments, or `cbid.ErrInvalidCBID` if validation
    fails.
-   **`IdentifierFromDomain(domain string) (string, error)`**: Extracts the
    leading dot-separated label from a DNS domain name and validates it with
    `cbid.Validate`. Returns `ErrInvalidDomain` for IP addresses, empty strings,
    single-label names, or leading dots, and `cbid.ErrInvalidCBID` if validation
    fails.
-   **Sentinel Errors (`ErrInvalidDomain`, `ErrInvalidURL`,
    `ErrFailedToParseURL`)**: Package-level errors returned by
    `IdentifierFromDomain` and `IdentifierFromURL` for `errors.Is` inspection
    when callback domains or URLs are malformed.

## Usage

```go
import (
    "github.com/google/goonami-scanner/common/callbackserver/cbid"
    "github.com/google/goonami-scanner/common/callbackserver/netutils"
)

func example(secret string) error {
    id, err := cbid.Generate(secret)
    if err != nil {
        return err
    }

    // Client-side: build HTTP and DNS callback targets.
    httpTarget := netutils.CallbackURL("http://cb.example.com:8080", id)
    dnsTarget, err := netutils.CallbackDomain("cb.example.com", id)
    if err != nil {
        return err
    }

    // Server-side: extract and validate CBIDs from incoming callbacks.
    httpID, err := netutils.IdentifierFromURL(httpTarget)
    if err != nil {
        return err
    }
    dnsID, err := netutils.IdentifierFromDomain(dnsTarget)
    if err != nil {
        return err
    }
    _, _ = httpID, dnsID
    return nil
}
```
