# Package `fakecallbackserver`

Package `fakecallbackserver` provides an in-memory HTTP fake of the Tsunami
Callback Server (TCS) polling endpoint for unit testing in Goonami. Backed by
`net/http/httptest`, it simulates HTTP and DNS out-of-band interaction responses
(or custom HTTP status codes and payloads) while recording the most recent
`secret` query parameter polled. It also builds ready-to-use
`CallbackserverConfig` and `ClientsConfig` protobuf messages so detector,
templated engine, and callback client tests can wire up
`callbackserver.Initialize` without external network dependencies.

## Services

-   **`Server` (`Close`, `URL`)**: Wraps an `httptest.Server` to simulate the
    callback polling server in tests while tracking its enabled state and
    received polling secrets. `URL()` returns the server's base HTTP address,
    and `Close()` shuts down the underlying listener.
-   **`NewServer`**: `NewServer(enabled, hasHTTPInteraction, hasDNSInteraction)`
    starts a `*Server` that responds with `200 OK` and a JSON interaction
    payload when `enabled` is `true` and at least one interaction flag is set.
    When `enabled` is `false` or both interaction flags are `false`, polling
    requests receive `404 Not Found`.
-   **`NewServerWithResponse`**: `NewServerWithResponse(enabled, status, body)`
    starts a `*Server` that serves a custom HTTP `status` and `body` when
    `enabled` is `true`, or `404 Not Found` with an empty body when `enabled` is
    `false`. Tests use it to exercise malformed JSON responses or custom HTTP
    status codes.
-   **`Server.LastSecret`**: Thread-safely returns the `secret` query parameter
    from the most recent HTTP request received by the server, even when the
    server is disabled.
-   **`Server.ClientConfig` / `Server.ClientsConfig` & `DefaultDNSDomain`**:
    When enabled, `ClientConfig()` returns a `*cbpb.CallbackserverConfig`
    pointing HTTP poll and record endpoints to `URL()` and the DNS record
    endpoint to `DefaultDNSDomain` (`"cb.localhost.lan"`), or an empty config
    when disabled. `ClientsConfig()` wraps `ClientConfig()` in a
    `*cpb.ClientsConfig` ready to attach to a scanner `Config` proto.

## Usage

```go
package detector_test

import (
    "testing"

    "github.com/google/goonami-scanner/common/clients/callbackserver"
    "github.com/google/goonami-scanner/common/testfakes/fakecallbackserver"
    "github.com/google/goonami-scanner/core/config"
    _ "github.com/google/goonami-scanner/core/net/http/simpleclient"

    cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func TestCallbackInteraction(t *testing.T) {
    cbs := fakecallbackserver.NewServer(true, true, false)
    defer cbs.Close()

    cfgProto := cpb.Config_builder{
        Clients: cbs.ClientsConfig(),
    }.Build()
    cfg := config.FromProto(cfgProto)

    ctx := t.Context()
    if err := callbackserver.Initialize(ctx, cfg); err != nil {
        t.Fatalf("callbackserver.Initialize() unexpected error: %v", err)
    }

    got, err := callbackserver.DefaultClient().HasInteraction(ctx, "sec1")
    if err != nil || !got {
        t.Errorf("HasInteraction() = (%v, %v), want (true, nil)", got, err)
    }
    if cbs.LastSecret() != "sec1" {
        t.Errorf("LastSecret() = %q, want %q", cbs.LastSecret(), "sec1")
    }
}
```
