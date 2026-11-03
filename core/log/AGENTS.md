# Package `log`

Package `log` provides Goonami's context-aware logging interface and global
logging helpers across error, warning, info, vulnerability, and tiered debug
levels. By default, package-level logging functions delegate to a
`DefaultLogger` backed by the Go standard library logger, while `SetLogger`
allows callers to swap in a custom `Logger` implementation. Callers can enrich
`context.Context` values with target hosts, target network services (host and
port), and module names so log output automatically includes structured prefixes
and downstream consumers (such as per-target metrics and scan runners) can
inspect the active host via `HostFromContext`.

## Services

-   **`Logger` and `SetLogger`**: `Logger` defines Goonami's context-aware
    logging interface with formatted (`*Contextf`) and unformatted (`*Context`)
    methods for error, warning, info, vulnerability, and leveled debug messages.
    `SetLogger(l)` replaces the active package-level `Logger` (initialized to
    `&DefaultLogger{}`) with a caller-supplied implementation.
-   **`DefaultLogger`**: Default `Logger` implementation that writes via the
    standard library `log.Print` with level tags (`ERR`, `WARN`, `INFO`, `VULN`,
    `DBG<n>`) followed by any `[ <host> ]` (split via `netendpoint.SplitHost`
    into separate `[ <ip> ] [ <hostname> ]` tags for composite `"<ip>_<hostname>"`
    hosts), `[ <port> ]`, and `[ <module> ]` prefixes present in `ctx`. Its
    `VerboseLevel` field gates debug output (`VerboseLevel >= level`), and
    `UseColors` enables ANSI color formatting for level tags, context prefixes
    (purple for hosts, green for ports, cyan for modules, with uncolored
    brackets), and vulnerability messages.
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
-   **`ContextForHost` and `HostFromContext`**: `ContextForHost(ctx, host)`
    attaches a canonical target `host` string to `ctx` (passing `""` clears any
    previously attached host), and `HostFromContext(ctx)` returns the attached
    host string or `""` when none is present.
-   **`ContextForModule` and `ContextForModuleAndHost`**: Attach a module name
    (`string`), or both a target `host` and module `name`, to a
    `context.Context`.
-   **`ContextForService` and `ContextForModuleAndService`**: Extract the
    canonical host (via `netendpoint.ToHost`) and port number from a
    `*nspb.NetworkService` and attach them—optionally alongside a module
    `name`—to `ctx`. If `service` is `nil` or its endpoint lacks a valid host
    address, `ContextForService` clears any prior host attached to `ctx` so
    subsequent logs and metrics do not inherit a stale host.

## Usage

```go
package example

import (
    "context"

    "github.com/google/goonami-scanner/core/log"

    nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func scanService(ctx context.Context, host string, svc *nspb.NetworkService) {
    log.SetLogger(&log.DefaultLogger{
        VerboseLevel: log.DebugLevelService,
        UseColors:    true,
    })

    // Host-scoped logging: prefixes output with "[ <host> ] [ core/runner ]".
    hostCtx := log.ContextForModuleAndHost(ctx, "core/runner", host)
    log.InfoContextf(hostCtx, "starting checks for %s", log.HostFromContext(hostCtx))

    // Service-scoped logging: prefixes output with "[ <host> ] [ <port> ] [ plugin/example ]"
    // (or "[ <ip> ] [ <hostname> ] [ <port> ] [ plugin/example ]" when both are set).
    svcCtx := log.ContextForModuleAndService(ctx, "plugin/example", svc)
    log.DebugContextf(svcCtx, log.DebugLevelService, "probing target service")
    log.VulnContext(svcCtx, "detected exposed administrative endpoint")
}
```
