# Package `cbid`

Package `cbid` generates and validates callback identifiers (CBIDs) used for
out-of-band interaction tracking in the Goonami callback server ecosystem. It
deterministically hashes caller secrets with SHA3-224 into 56-character
lowercase hexadecimal identifiers so raw secrets are never exposed in outbound
HTTP callback URLs or DNS queries. Both the callback server client and server
packages use `cbid` to construct callback endpoints, validate incoming
interaction identifiers, and correlate polling requests with recorded
interactions.

## Services

-   **`Generate(secret string) (string, error)`**: Computes the SHA3-224 digest
    of `secret` and returns it as a 56-character lowercase hexadecimal CBID
    string.
-   **`Validate(cbid string) error`**: Verifies that `cbid` is a 56-character
    lowercase hexadecimal string matching `^[a-f0-9]{56}$`, returning
    `ErrInvalidCBID` on mismatch.
-   **`ErrInvalidCBID`**: Sentinel error returned by `Validate` when an
    identifier has an invalid length or contains non-lowercase-hexadecimal
    characters.

## Usage

```go
import (
    "errors"

    "github.com/google/goonami-scanner/common/callbackserver/cbid"
)

// Outbound or polling path: derive a deterministic CBID from a secret.
id, err := cbid.Generate(secret)
if err != nil {
    return err
}

// Inbound callback path: verify an untrusted identifier from HTTP or DNS.
if err := cbid.Validate(candidateID); errors.Is(err, cbid.ErrInvalidCBID) {
    return err
}
```
