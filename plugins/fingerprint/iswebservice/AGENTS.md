# Package `iswebservice`

Package `iswebservice` implements the `"fp/iswebservice"` fingerprinter plugin,
which determines whether a discovered network service responds to HTTP(S). It
probes the service's web root with an HTTP `GET` request via Goonami's shared
HTTP client and appends `"GET"` to `SupportedHttpMethods` on the target
`*nspb.NetworkService` when a response is received. Populating
`SupportedHttpMethods` marks the endpoint as a web service (via
`netservice.IsWebService`) for downstream fingerprinters and vulnerability
detectors.

## Services

-   **`Module` (`New`)**: Fingerprinter implementation embedding
    `*module.BaseModule` (`Name()` returns `"fp/iswebservice"`).
    `New(ctx, config)` constructs a `*Module` bound to `*config.Config` and
    returns it as a `module.Fingerprinter`.
-   **`(*Module).Fingerprint`**: Queries the URL from
    `netservice.BuildWebRoot(service)` with an HTTP `GET` via
    `http.SharedClient`, appending `"GET"` in place to
    `service.SupportedHttpMethods` (if not already present) when a response is
    received and returning `[]*nspb.NetworkService{service}`. Non-canceled HTTP
    transport errors (such as timeouts or non-HTTP protocols) return the
    unmodified service with a `nil` error, whereas invalid endpoints, request
    creation failures, or `context.Canceled` return an error.
-   **Plugin Registration (`"fp/iswebservice"`)**: Importing the package
    registers `New` under `"fp/iswebservice"` on `module.DefaultRegistry` via
    `module.RegisterFingerprinter` in `init()`.

## Usage

Register the fingerprinter with `module.DefaultRegistry` in a scanner binary:

```go
import (
  _ "github.com/google/goonami-scanner/plugins/fingerprint/iswebservice"
)
```

Instantiate and run the fingerprinter directly against a `NetworkService`:

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  _ "github.com/google/goonami-scanner/core/net/http/simpleclient"
  "github.com/google/goonami-scanner/plugins/fingerprint/iswebservice"

  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func probeService(
    ctx context.Context, cfg *config.Config, svc *nspb.NetworkService,
) ([]*nspb.NetworkService, error) {
  fp, err := iswebservice.New(ctx, cfg)
  if err != nil {
    return nil, err
  }
  return fp.Fingerprint(ctx, svc)
}
```
