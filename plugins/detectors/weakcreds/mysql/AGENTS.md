# Package `mysql`

Package `mysql` provides a Goonami weak-credentials vulnerability detector
(`dt/wk/mysql`) that tests MySQL and MariaDB servers for weak or default
credentials using `common/bruteforce` and `common/clients/mysqlclient`.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/wk/mysql"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new MySQL weak-credentials detector backed by
    `bruteforce.New` and `mysqlclient.New(cfg)` with the default credential
    store and default MySQL credential (`root:""`).
-   **`NewWithOptions(ctx context.Context, cfg *config.Config, opts
    *bruteforce.Options) (*bruteforce.Detector, error)`**: Constructs a MySQL
    weak-credentials detector with custom `bruteforce.Options`.
-   **`Handler`**: Implements `bruteforce.Handler` and `bruteforce.Worker` for
    MySQL password authentication, fingerprinting candidate TCP MySQL/MariaDB
    services to confirm they support password authentication before testing
    credentials.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/weakcreds/mysql"
)
```
