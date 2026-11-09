# Package `config`

Package `config` loads, validates, and manages runtime configuration and working
directories for the Goonami scanner. It wraps the root `goonami.proto.Config`
protocol buffer—covering global engine performance settings, module workflow
selection, shared client configurations, and plugin-specific options—and
supports mutating fields at startup via key-value CLI overrides. Core engine
components, clients, and plugins receive `*config.Config` to read typed settings
and allocate per-module artifact and cache directories.

## Services

-   **`Config`**: Central configuration handle holding the parsed
    `goonami.proto.Config` message alongside paths for the scan's working,
    temporary, artifacts, and cache directories.
-   **`FromFile` / `FromProto` / `Default`**: Constructors that initialize a
    `*Config` from a textproto file path, an existing `*cpb.Config` proto
    (`nil`-safe), or empty proto defaults respectively. Callers that need
    filesystem storage must still invoke `CreateDirectories` before using
    directory-dependent methods.
-   **`(*Config).CreateDirectories` / `(*Config).Close`**:
    `CreateDirectories(workdir)` validates an existing working directory and
    creates the `tempfiles`, `artifacts`, and `cache` subdirectories (`0700`).
    `Close(ctx)` removes `TempDirectory()` at the end of a scan and returns
    `ErrUninitialized` if `CreateDirectories` was not called.
-   **Directory Accessors (`WorkingDirectory`, `TempDirectory`,
    `ArtifactsDirectory`, `CacheDirectory`, `ArtifactsForModule`,
    `GetCacheForModule`)**: Return the configured runtime directory paths for
    scan outputs and temporary files. `ArtifactsForModule` and
    `GetCacheForModule` lazily create (`0700`) and return module-scoped
    subdirectories under `artifacts/` and `cache/`, returning `ErrUninitialized`
    if directories were not initialized.
-   **Section Accessors & Helpers (`GlobalConfig`, `ClientsConfig`,
    `PluginsConfig`, `WorkflowConfig`, `TimeoutPerRequest`)**: Return the typed
    sub-messages of the underlying `Config` proto for engine, client, plugin,
    and workflow settings. `TimeoutPerRequest()` converts
    `GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds()` into a
    `time.Duration`.
-   **`(*Config).ApplyOverrides`**: Mutates fields in the underlying `Config`
    proto via protobuf reflection using `"key=value"` dot-separated proto field
    paths, supporting strings, booleans, 32/64-bit signed and unsigned integers,
    enums (by name or number), and comma-separated repeated fields (replacing
    prior elements, or clearing on `"key="`). Also resolves shorthand key
    aliases (`ports`, `http_client`, `portscan`, `fingerprinters.require`,
    `fingerprinters.ignore`, `detectors.require`, and `detectors.ignore`).
-   **Configuration Proto (`config_go_proto`)**: Defines the root `Config`
    message composed of `GlobalConfig` (concurrency, request timeouts,
    packet/HTTP rate limits, HTTP redirect/429 retry bounds, `ports_to_scan`,
    `user_agent`, and `http_client`), `WorkflowConfiguration` (`portscan` name
    plus ordered `ModuleFilter` `require`/`ignore` regex lists for
    `fingerprinters` and `detectors`), `ClientsConfig` (`nmap`, `http_crawler`,
    `llm`, `callback_server`, `ssh`, `mysql`), and `PluginsConfig`
    (`webidentity`, `httpscan`, `templatedweakcredentials`).
-   **Sentinel Errors**: Exports `ErrUninitialized`, `ErrWorkDirEmpty`,
    `ErrWorkDirAccess`, and `ErrCreateDir` for directory lifecycle failures;
    `ErrConfigRead` and `ErrConfigUnmarshal` for file I/O, textproto parsing,
    and override value conversion errors; and `ErrInvalidOverrideFormat`,
    `ErrFieldNotFound`, `ErrFieldNotMessage`, and `ErrUnsupportedFieldKind` for
    invalid override paths or unsupported proto field kinds.

## Usage

Load a configuration file, apply CLI overrides, initialize scan directories, and
allocate a per-module artifact directory:

```go
import (
    "context"

    "github.com/google/goonami-scanner/core/config"
)

func initScannerConfig(ctx context.Context, cfgPath, outputDir string) error {
    cfg, err := config.FromFile(cfgPath)
    if err != nil {
        return err
    }

    overrides := []string{
        "ports=80,443",
        "globalcfg.performance.max_concurrency=10",
    }
    if err := cfg.ApplyOverrides(ctx, overrides); err != nil {
        return err
    }

    if err := cfg.CreateDirectories(outputDir); err != nil {
        return err
    }
    defer cfg.Close(ctx)

    timeout := cfg.TimeoutPerRequest()
    _ = timeout

    moduleArtifacts, err := cfg.ArtifactsForModule("fp/webidentity")
    if err != nil {
        return err
    }
    _ = moduleArtifacts
    return nil
}
```

Construct a `*config.Config` programmatically from a proto builder (commonly
used in tests and embedded callers):

```go
import (
    "google.golang.org/protobuf/proto"
    "github.com/google/goonami-scanner/core/config"
    cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func buildCustomConfig(workDir string) (*config.Config, error) {
    cfg := config.FromProto(cpb.Config_builder{
        Globalcfg: cpb.GlobalConfig_builder{
            UserAgent: proto.String("custom-scanner"),
        }.Build(),
        Workflowcfg: cpb.WorkflowConfiguration_builder{
            Portscan: proto.String("ps/nmap"),
        }.Build(),
    }.Build())

    if err := cfg.CreateDirectories(workDir); err != nil {
        return nil, err
    }
    return cfg, nil
}
```
