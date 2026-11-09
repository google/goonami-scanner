# Package `mysqlclient`

Package `mysqlclient` provides a reusable MySQL client for network service
probing, password authentication, and canonical error classification in Goonami
plugins. It wraps Go's `database/sql` and `github.com/go-sql-driver/mysql` with
configurable per-attempt timeouts derived from client-specific or global
performance settings in `config.Config`. Connection and handshake failures are
normalized into sentinel errors so callers can distinguish invalid credentials,
unsupported password authentication or host restrictions, and non-MySQL
endpoints.

## Services

-   **`Client` and `New(cfg *config.Config) *Client`**: Manages MySQL TCP
    dialing and password authentication using timeout settings from
    `cfg.ClientsConfig().GetMysql()`, falling back to
    `cfg.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds()` or
    `DefaultTimeout`. Passing `nil` initializes a client configured with
    `DefaultTimeout`.
-   **`(*Client).Connect(ctx, addr, username, password)`**: Dials `addr` within
    `Timeout()`, allows native, cleartext, and old password authentication, and
    verifies authentication via `db.PingContext`. Returns an established
    `*sql.DB` (which the caller must close) on success, or an error classified
    via `ClassifyError` on failure.
-   **`(*Client).Timeout()` and `DefaultTimeout`**: `Timeout()` returns the
    active connection and authentication `time.Duration`, defaulting to
    `DefaultTimeout` (`5s`) when no positive timeout is configured.
-   **`ClassifyError(err error) error`**: Wraps raw network, EOF, protocol, and
    MySQL authentication errors with canonical sentinel errors while returning
    `nil`, context errors, and unrecognized errors unchanged.
-   **Sentinel Errors (`ErrAuthFailed`, `ErrPasswordAuthUnsupported`,
    `ErrNotMySQLService`)**: Classify connection outcomes via `errors.Is` into
    rejected credentials (`ErrAuthFailed`), servers disabling password login
    or blocking the scanner host (`ErrPasswordAuthUnsupported`), or
    unreachable/non-MySQL targets (`ErrNotMySQLService`).
-   **`MySQLClientConfig` (`mysql_client_config.proto`)**: Protobuf
    configuration message (`goonami.proto.configs.clients.MySQLClientConfig`)
    defining `timeout_seconds` (default `5`) for MySQL connection and
    authentication attempts.

## Usage

```go
package example

import (
    "context"
    "errors"

    "github.com/google/goonami-scanner/common/clients/mysqlclient"
    "github.com/google/goonami-scanner/core/config"
)

func checkCredentials(
    ctx context.Context, cfg *config.Config, addr, user, pass string,
) (bool, error) {
    client := mysqlclient.New(cfg)
    db, err := client.Connect(ctx, addr, user, pass)
    if err != nil {
        if errors.Is(err, mysqlclient.ErrAuthFailed) {
            return false, nil
        }
        // E.g. ErrPasswordAuthUnsupported or ErrNotMySQLService.
        return false, err
    }
    _ = db.Close()
    return true, nil
}
```
