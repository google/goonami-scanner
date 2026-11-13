# Package `ssh`

Package `ssh` provides a Goonami weak-credentials vulnerability detector
(`dt/wk/ssh`) that tests SSH servers for weak or default credentials using
`common/bruteforce` and `common/clients/sshclient`.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/wk/ssh"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new SSH weak-credentials detector backed by
    `bruteforce.New` and `sshclient.New(cfg)` with the default credential store
    and an empty password (`""`) prepended for every user.
-   **`NewWithOptions(ctx context.Context, cfg *config.Config, opts
    *bruteforce.Options) (*bruteforce.Detector, error)`**: Constructs an SSH
    weak-credentials detector with custom `bruteforce.Options` (when `opts` is
    `nil`, loads the default store with an empty password prepended per user).
-   **`Handler`**: Implements `bruteforce.Handler` and `bruteforce.Worker` for
    SSH password and keyboard-interactive authentication, fingerprinting
    candidate TCP SSH services to confirm they support password or
    keyboard-interactive authentication before testing credentials.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/weakcreds/ssh"
)
```
