# Package `sslsupport`

Package `sslsupport` implements the `"fp/sslsupport"` fingerprinter plugin for
detecting whether a network service supports SSL/TLS. In Goonami's scanning
pipeline, it probes discovered `*nspb.NetworkService` endpoints that do not yet
have SSL/TLS version metadata and records the negotiated TLS version so
downstream modules know whether to use TLS. Importing the package self-registers
its constructor on `module.DefaultRegistry` under `"fp/sslsupport"`.

## Services

-   **`Module`**: Fingerprinter struct that embeds `*module.BaseModule`
    (`Name()` returns `"fp/sslsupport"`) and implements `module.Fingerprinter`.
-   **`New`**: `module.InitFingerprinterFn` constructor
    (`New(ctx, config) (module.Fingerprinter, error)`) that returns a `*Module`
    configured with `config`. Automatically registered on
    `module.DefaultRegistry` under `"fp/sslsupport"` by package `init()`.
-   **`(*Module).Fingerprint`**: Connects to `service.GetNetworkEndpoint()` over
    TCP via `tls.Dialer` (skipping certificate verification and enforcing
    `config.TimeoutPerRequest()`) unless `netservice.HasTLS(service)` is already
    true, appending `tls.VersionName` of the negotiated connection to
    `supported_ssl_versions` on success. Returns `(nil, err)` on invalid
    endpoints or `context.Canceled`, while non-TLS connections, handshake
    failures, and per-request timeouts return `[]*nspb.NetworkService{service}`
    unchanged with a `nil` error.

## Usage

Blank-import the package to register `"fp/sslsupport"` with
`module.DefaultRegistry`:

```go
import (
  _ "github.com/google/goonami-scanner/plugins/fingerprint/sslsupport"
)
```

Instantiate and run the fingerprinter directly against a `*nspb.NetworkService`:

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/plugins/fingerprint/sslsupport"

  nepb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func checkSSL(
    ctx context.Context, cfg *config.Config,
) ([]*nspb.NetworkService, error) {
  fp, err := sslsupport.New(ctx, cfg)
  if err != nil {
    return nil, err
  }

  svc := nspb.NetworkService_builder{
      NetworkEndpoint: nepb.NetworkEndpoint_builder{
          Type: nepb.NetworkEndpoint_IP_PORT,
          IpAddress: nepb.IpAddress_builder{
              Address:       "127.0.0.1",
              AddressFamily: nepb.AddressFamily_IPV4,
          }.Build(),
          Port: nepb.Port_builder{PortNumber: 443}.Build(),
      }.Build(),
  }.Build()

  return fp.Fingerprint(ctx, svc)
}
```
