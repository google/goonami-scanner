# Package `templatedweakcredentials`

Package `templatedweakcredentials` loads and executes templated weak-credential
detector plugins in Goonami. At initialization, it embeds `TemplatedPlugin`
definitions from `detections/`, creates a shared default
`credentialstore.CredentialStore`, and registers each detector under the
`dt/wktpl/` module prefix. During detection, each plugin fingerprints the target
service once and then tests service-specific default credentials followed by
generic wordlists via the templated engine.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package loads all
    embedded `TemplatedPlugin` definitions under `detections/` with a shared
    default `credentialstore.CredentialStore` and registers each with
    `module.RegisterDetector` as `"dt/wktpl/<PluginName>"`.
-   **`NewFromProto`**: Constructs a `*Detector` (returned as
    `module.VulnDetector`) from a `*config.Config`, `*tpb.TemplatedPlugin`, and
    `*credentialstore.CredentialStore`. It deep-copies the store and prepends
    any `default_credentials` from `ServiceInformation` (using an empty username
    for `AUTHENTICATION_TYPE_PASSWORD_ONLY`) so service defaults are tried
    before generic wordlists.
-   **`Detector` / `(*Detector).Name`**: Implements `module.VulnDetector` around
    a `*templatedengine.TemplatedDetector` and a per-plugin credential store.
    `Name` returns `"dt/wktpl/"` concatenated with
    `pluginProto.GetInfo().GetName()`.
-   **`(*Detector).Detect`**: Executes `ACTION_PHASE_FINGERPRINT` once against
    the target `NetworkService` (returning `nil, nil` on fingerprint or workflow
    mismatch) and then runs `ACTION_PHASE_DETECTION` per credential pair with
    `T_PASSWORD` (plus `T_USERNAME` unless password-only). Returns on the first
    valid credential after appending `"<username>:<password>"` to each
    vulnerability's `AdditionalDetails`, or aborts and increments
    `metrics.BudgetExhausted` when `max_attempts_per_service` is reached.
-   **`TemplatedWeakCredentialsConfig`
    (`templatedweakcredentials_config_go_proto`)**: Protobuf configuration
    message (`PluginsConfig.templatedweakcredentials`) defining
    `max_attempts_per_service` (`0` for unlimited) along with `username_file`
    and `passwords_file` wordlist path fields.

## Usage

Blank-import the package to register all embedded `dt/wktpl/` detectors and cap
per-service login attempts in the scanner configuration:

```go
import (
    "google.golang.org/protobuf/proto"
    "github.com/google/goonami-scanner/core/config"
    cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
    _ "github.com/google/goonami-scanner/plugins/detectors/templatedweakcredentials"
    twcpb "github.com/google/goonami-scanner/plugins/detectors/templatedweakcredentials/templatedweakcredentials_config_go_proto"
)

twcCfg := twcpb.TemplatedWeakCredentialsConfig_builder{
    MaxAttemptsPerService: proto.Int32(25),
}.Build()
cfg := config.FromProto(cpb.Config_builder{
    Plugins: cpb.PluginsConfig_builder{
        Templatedweakcredentials: twcCfg,
    }.Build(),
}.Build())
```

Construct and invoke a weak-credential detector directly from a
`TemplatedPlugin` definition and credential store:

```go
import (
    "context"

    "github.com/google/goonami-scanner/common/credentialstore"
    "github.com/google/goonami-scanner/core/config"
    "github.com/google/goonami-scanner/plugins/detectors/templatedweakcredentials"
    dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
    nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
    tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

func runDetector(
    ctx context.Context,
    cfg *config.Config,
    plugin *tpb.TemplatedPlugin,
    service *nspb.NetworkService,
) (*dpb.DetectionReportList, error) {
    store, err := credentialstore.NewWithDefaults()
    if err != nil {
        return nil, err
    }

    detector, err := templatedweakcredentials.NewFromProto(
        ctx, cfg, plugin, store,
    )
    if err != nil {
        return nil, err
    }
    return detector.Detect(ctx, service)
}
```
