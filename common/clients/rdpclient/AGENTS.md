# Package `rdpclient`

Package `rdpclient` provides a reusable pure-Go Remote Desktop Protocol (RDP)
client for service probing, NLA/CredSSP (NTLMv2) credential verification,
non-NLA TLS inline authentication verification, and canonical sentinel error
classification in Goonami plugins.

## Services

-   **`Client` and `New(cfg *config.Config) *Client`**: Manages bounded TCP/TLS
    RDP connections using per-request timeout settings from `config.Config`,
    defaulting to `DefaultTimeout` (`5s`).
-   **`(*Client).Probe(ctx, addr, canaryUser, canaryPass)`**: Performs X.224
    protocol negotiation and negative-canary authentication verification to
    classify targets into `AuthModeCredSSP`, `AuthModeCredSSPSPNEGO`,
    `AuthModeTLSInline`, or `AuthModeNoAuth`, while short-circuiting non-RDP
    peers (`ErrNotRDPService`) and interactive graphical login greeters
    (`ErrAuthUnsupported`).
-   **`(*Client).Authenticate(ctx, addr, mode, username, password)`**: Verifies
    a single credential pair (including empty passwords) under the probed
    `AuthMode`. For CredSSP/NLA (versions 2 through 6), performs cryptographic
    server `pubKeyAuth` binding hash and NTLM MAC verification.
-   **Sentinel Errors (`ErrAuthFailed`, `ErrAccountUnavailable`,
    `ErrAuthUnsupported`, `ErrNotRDPService`)**: Distinguish rejected
    credentials, locked/disabled/expired accounts, unsupported interactive
    login modes, and unreachable or non-RDP endpoints.

## Usage

```go
package example

import (
    "context"
    "errors"

    "github.com/google/goonami-scanner/common/clients/rdpclient"
    "github.com/google/goonami-scanner/core/config"
)

func checkRDP(ctx context.Context, cfg *config.Config, addr, user, pass string) (bool, error) {
    client := rdpclient.New(cfg)
    probe, err := client.Probe(ctx, addr, "probe-user", "probe-invalid-password")
    if err != nil {
        return false, err
    }
    err = client.Authenticate(ctx, addr, probe.Mode, user, pass)
    if err != nil {
        if errors.Is(err, rdpclient.ErrAuthFailed) || errors.Is(err, rdpclient.ErrAccountUnavailable) {
            return false, nil
        }
        return false, err
    }
    return true, nil
}
```
