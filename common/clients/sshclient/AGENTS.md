# Package `sshclient`

Package `sshclient` provides a reusable SSH client for network service probing,
password authentication, and canonical error classification in Goonami plugins.
It wraps Go's `ssh` package with configurable per-attempt timeouts derived from
client-specific or global performance settings in `config.Config`. Connection
and handshake failures are normalized into sentinel errors so callers can
distinguish invalid credentials, unsupported password authentication, and
non-SSH endpoints.

## Services

-   **`Client` and `New(cfg *config.Config) *Client`**: Manages SSH TCP dialing
    and password authentication using timeout settings from
    `cfg.ClientsConfig().GetSsh()`, falling back to
    `cfg.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds()` or
    `DefaultTimeout`. Passing `nil` initializes a client configured with
    `DefaultTimeout`.
-   **`(*Client).Connect(ctx, addr, username, password)`**: Dials `addr` within
    `Timeout()`, skips host key verification, and attempts a single password
    login for `username`. Returns an established `*ssh.Client` (which the caller
    must close) on success, or an error classified via `ClassifyError` on
    failure.
-   **`(*Client).ConnectWithPasswords(ctx, addr, username, passwords...)`**:
    Dials `addr` within `Timeout()`, skips host key verification, and tries each
    password sequentially within a single SSH connection handshake for
    `username`. Returns an established `*ssh.Client` on success, or an error
    classified via `ClassifyError` on failure.
-   **`(*Client).ConnectWithBannerPrefix(ctx, addr, username, bannerPrefix,
    passwords...)`**: Behaves like `ConnectWithPasswords`, and additionally
    requires the server's `SSH-` identification banner to start with
    `bannerPrefix` when non-empty (aborting before key exchange with
    `ErrNotSSHService` on mismatch).
-   **`(*Client).Timeout()` and `DefaultTimeout`**: `Timeout()` returns the
    active connection and authentication `time.Duration`, defaulting to
    `DefaultTimeout` (`5s`) when no positive timeout is configured.
-   **`ClassifyError(err error) error`**: Wraps raw network, EOF, banner, and
    SSH authentication errors with canonical sentinel errors while returning
    `nil`, context errors, and unrecognized errors unchanged.
-   **Sentinel Errors (`ErrAuthFailed`, `ErrPasswordAuthUnsupported`,
    `ErrNotSSHService`, `ErrConnectionDropped`)**: Classify connection outcomes
    via `errors.Is` into rejected credentials (`ErrAuthFailed`), servers
    disallowing password login (`ErrPasswordAuthUnsupported`),
    unreachable/non-SSH targets (`ErrNotSSHService`), or TCP connections dropped
    before sending an SSH banner (`ErrConnectionDropped`, wrapped alongside
    `ErrNotSSHService`).
-   **`SSHClientConfig` (`ssh_client_config.proto`)**: Protobuf configuration
    message (`goonami.proto.configs.clients.SSHClientConfig`) defining
    `timeout_seconds` (default `5`) for SSH connection and authentication
    attempts.

## Usage

```go
package example

import (
    "context"
    "errors"

    "github.com/google/goonami-scanner/common/clients/sshclient"
    "github.com/google/goonami-scanner/core/config"
)

func checkCredentials(
    ctx context.Context, cfg *config.Config, addr, user, pass string,
) (bool, error) {
    client := sshclient.New(cfg)
    conn, err := client.Connect(ctx, addr, user, pass)
    if err != nil {
        if errors.Is(err, sshclient.ErrAuthFailed) {
            return false, nil
        }
        // E.g. ErrPasswordAuthUnsupported or ErrNotSSHService.
        return false, err
    }
    _ = conn.Close()
    return true, nil
}
```
