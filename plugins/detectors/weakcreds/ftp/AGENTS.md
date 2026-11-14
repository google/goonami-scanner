# Package `ftp`

Package `ftp` provides a Goonami weak-credentials vulnerability detector
(`dt/wk/ftp`) that tests FTP and FTPS servers for weak, default, empty, or
anonymous credentials using `common/bruteforce`.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/wk/ftp"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new FTP weak-credentials detector backed by
    `bruteforce.New` with FTP default credentials and an empty password (`""`)
    prepended for every user in the default credential store.
-   **`NewWithOptions(ctx context.Context, cfg *config.Config, opts
    *bruteforce.Options) (*bruteforce.Detector, error)`**: Constructs an FTP
    weak-credentials detector with custom `bruteforce.Options`.
-   **`DefaultCredentials() []bruteforce.Credential`**: Returns the FTP-specific
    default credentials tested prior to generic dictionary entries.
-   **`Handler`**: Implements `bruteforce.Handler` and spawns sequential
    `bruteforce.Worker` instances supporting cleartext FTP (RFC 959), explicit
    FTPS (`AUTH TLS`, RFC 4217), and implicit FTPS, verifying active session
    state after login before reporting a finding.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/weakcreds/ftp"
)
```
