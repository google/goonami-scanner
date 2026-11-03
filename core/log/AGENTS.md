# Package `log`

Package `log` provides Goonami's context-aware logging interface and global
logging helpers across error, warning, info, vulnerability, and tiered debug
levels. By default, package-level logging functions delegate to a
`DefaultLogger` backed by the Go standard library logger, while `SetLogger`
allows callers to swap in a custom `Logger` implementation. Callers can enrich
`context.Context` values with module names and target network service ports so
log output automatically includes structured prefixes.

## Services

-   **`Logger` and `SetLogger`**: `Logger` defines Goonami's context-aware
    logging interface with formatted (`*Contextf`) and unformatted (`*Context`)
    methods for error, warning, info, vulnerability, and leveled debug messages.
    `SetLogger(l)` replaces the active package-level `Logger` (initialized to
    `&DefaultLogger{}`) with a caller-supplied implementation.
-   **`DefaultLogger`**: Default `Logger` implementation that writes via the
    standard library `log.Print` with level tags (`ERR`, `WARN`, `INFO`, `VULN`,
    `DBG<n>`) and any `[ <port> ]` or `[ <module> ]` prefixes present in `ctx`.
    Its `VerboseLevel` field gates debug output (`VerboseLevel >= level`), and
    `UseColors` enables ANSI color formatting for level tags, context prefixes,
    and vulnerability messages.
-   **`DebugLevel` (`DebugLevelSession`, `DebugLevelService`,
    `DebugLevelRequest`)**: `DebugLevel` (`int32`) specifies debug verbosity
    where higher numbers represent more granular output. `DebugLevelSession`
    (`1`) is for once-per-scan events, `DebugLevelService` (`2`) is for
    once-per-service events, and `DebugLevelRequest` (`3`) is for high-frequency
    per-request events.
-   **Package-Level Logging Functions (`ErrorContext`/`ErrorContextf`,
    `WarnContext`/`WarnContextf`, `InfoContext`/`InfoContextf`,
    `VulnContext`/`VulnContextf`, `DebugContext`/`DebugContextf`)**: Static
    convenience functions that forward formatted or unformatted log calls
    directly to the active package-level `Logger`. `DebugContext` and
    `DebugContextf` additionally take a `DebugLevel` argument to classify
    verbosity.
-   **`ContextForModule`, `ContextForService`, and
    `ContextForModuleAndService`**: Attach a module name (`string`), the port
    number extracted from a `*nspb.NetworkService`, or both to a
    `context.Context`. `DefaultLogger` reads these context values to prepend
    `[ <port> ]` and `[ <module> ]` prefixes to log entries.

## Usage

```go
package example

import (
    "context"

    "github.com/google/goonami-scanner/core/log"

    nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func scanService(ctx context.Context, svc *nspb.NetworkService) {
    log.SetLogger(&log.DefaultLogger{
        VerboseLevel: log.DebugLevelService,
        UseColors:    true,
    })

    ctx = log.ContextForModuleAndService(ctx, "plugin/example", svc)
    log.DebugContextf(ctx, log.DebugLevelService, "probing target service")
    log.VulnContext(ctx, "detected exposed administrative endpoint")
}
```
