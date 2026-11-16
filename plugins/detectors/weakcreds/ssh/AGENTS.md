# Package `ssh`

Package `ssh` provides a Goonami weak-credentials vulnerability detector
(`dt/wk/ssh`) that tests SSH servers for weak or default credentials using
`common/bruteforce` and `common/clients/sshclient`.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/wk/ssh"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new SSH weak-credentials detector backed by
    `bruteforce.New` and `sshclient.New(cfg)` with common Linux and container
    SSH accounts, default passwords, and prioritized empty/username-matching
    passwords.
-   **`NewWithOptions(ctx context.Context, cfg *config.Config, opts
    *bruteforce.Options) (*bruteforce.Detector, error)`**: Constructs an SSH
    weak-credentials detector with custom `bruteforce.Options` (when `opts` is
    `nil`, initializes the default SSH credential store).
-   **`Handler`**: Implements `bruteforce.Handler` (spawning per-worker
    `bruteforce.Worker` instances via `NewWorker`) for SSH password and
    keyboard-interactive authentication, fingerprinting TCP SSH services on any
    port and applying a bounded per-service cooldown retry budget when
    pre-banner rate-limit connection drops occur on wire-confirmed SSH
    endpoints.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/weakcreds/ssh"
)
```
