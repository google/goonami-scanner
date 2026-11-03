# Package `templatedengine`

Package `templatedengine` provides the core execution engine and plugin loaders
for Goonami's textproto-defined (`TemplatedPlugin`) vulnerability detectors. It
validates plugin workflows and action phase ordering, initializes per-service
variable environments, and dispatches HTTP, callback server, and utility actions
with deferred cleanup execution. Detector modules such as `templated` and
`templatedweakcredentials` use `TemplatedDetector` and the filesystem loader
helpers to register and run full or phase-targeted detection workflows against
`NetworkService` targets.

## Services

-   **`TemplatedDetector` (`New`, `NewForTesting`, `Name`)**: Implements
    `module.VulnDetector` to execute workflows defined in a
    `*tpb.TemplatedPlugin` protocol buffer, reporting its module name with the
    `"dt/tpl/"` prefix via `Name()`. `New` indexes the plugin's actions by name
    and runs `Validate()`, while `NewForTesting` additionally injects a fixed
    `*environment.Environment` to override per-workflow environment
    initialization.
-   **`(*TemplatedDetector).Validate`**: Verifies that every defined action maps
    to a supported runner (HTTP request, utility, or callback server), all
    referenced workflow and cleanup actions exist, and action phases within each
    workflow never decrease (treating `ACTION_PHASE_UNDEFINED` as
    `ACTION_PHASE_DETECTION`). Returns wrapped `actions.ErrInvalidAction` or
    `actions.ErrActionNotFound` when validation fails.
-   **`(*TemplatedDetector).Detect`**: Selects the first workflow whose runtime
    condition (such as `REQUIRES_CALLBACK_SERVER`) is satisfied, runs all
    workflow actions against the target `*nspb.NetworkService` (scheduling
    registered cleanup actions via `defer`), and returns a
    `VULNERABILITY_VERIFIED` `DetectionReportList` on success. Suppresses
    non-fatal `actions.ErrActionFailed` and `ErrNoCompatibleWorkflow` outcomes
    by returning `(nil, nil)` while propagating engine or plugin errors.
-   **`(*TemplatedDetector).DetectWithVariables` /
    `(*TemplatedDetector).DetectForPhase`**: Execute the first compatible
    workflow after injecting `extraVars` into the service environment prior to
    workflow variable substitution, returning `actions.ErrActionFailed` and
    `ErrNoCompatibleWorkflow` directly to the caller. `DetectWithVariables` runs
    all phases (`ACTION_PHASE_UNDEFINED`), whereas `DetectForPhase` skips
    actions below `targetPhase` and stops early returning `(nil, nil)` upon
    reaching an action above `targetPhase`.
-   **`LoadPluginsFromFS` / `LoadPlugins` / `Registry`**: `LoadPluginsFromFS`
    recursively walks an `fs.FS` to unmarshal `.textproto` plugin definitions
    into `[]*tpb.TemplatedPlugin`, skipping `*_test.textproto` files and plugins
    with `config.disabled` set to `true`. `LoadPlugins` deduplicates plugins by
    `info.name` into `[]module.InitVulnDetectorFn` callbacks, and `Registry`
    provides a struct holding a `Detectors` slice of those initializers.
-   **`ErrNoCompatibleWorkflow`**: Sentinel error returned by
    `DetectWithVariables` and `DetectForPhase` when none of a plugin's workflows
    satisfy the active scanner configuration.

## Usage

Load embedded `.textproto` plugins from an `embed.FS` and register each as a
`module.VulnDetector`:

```go
import (
    "context"
    "embed"

    "github.com/google/goonami-scanner/common/templatedengine"
    "github.com/google/goonami-scanner/core/config"
    "github.com/google/goonami-scanner/core/module"
)

//go:embed detections
var pluginFilesFS embed.FS

func registerDetectors(ctx context.Context) error {
    plugins, err := templatedengine.LoadPluginsFromFS(ctx, pluginFilesFS)
    if err != nil {
        return err
    }

    for _, p := range plugins {
        proto := p
        name := "dt/tpl/" + proto.GetInfo().GetName()
        module.RegisterDetector(name, func(
            ctx context.Context, cfg *config.Config,
        ) (module.VulnDetector, error) {
            return templatedengine.New(ctx, cfg, proto)
        })
    }
    return nil
}
```

Execute a `TemplatedDetector` with injected runtime variables and handle
non-fatal workflow or action outcomes:

```go
import (
    "context"
    "errors"

    "github.com/google/goonami-scanner/common/templatedengine/actions"
    "github.com/google/goonami-scanner/common/templatedengine"
    dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
    nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func runWithCredentials(
    ctx context.Context,
    detector *templatedengine.TemplatedDetector,
    service *nspb.NetworkService,
    user, pass string,
) (*dpb.DetectionReportList, error) {
    vars := map[string]string{
        "T_USERNAME": user,
        "T_PASSWORD": pass,
    }
    reports, err := detector.DetectWithVariables(ctx, service, vars)
    if errors.Is(err, actions.ErrActionFailed) ||
        errors.Is(err, templatedengine.ErrNoCompatibleWorkflow) {
        return nil, nil
    }
    return reports, err
}
```
