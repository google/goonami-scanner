# Package `callbackserver`

Package `callbackserver` implements Goonami's out-of-band interaction callback
server, orchestrating local HTTP recording, DNS recording, and HTTP polling
endpoints over a shared in-memory interaction store. Both the main Goonami
scanner entrypoint and the standalone callback server binary use it to start
local listeners when endpoints are configured in `MODE_START_LOCAL_SERVER`,
while skipping endpoints that are omitted or delegated to a remote server. It
also defines the `CallbackserverConfig` protobuf schema shared by the server
runtime and the scanner's callback client.

## Services

-   **`Server` and `New`**: `New(ctx, cfg)` validates `cfg` via `ValidateConfig`
    (defaulting `nil` to an empty proto) and returns a `*Server` backed by an
    expiring in-memory interaction store
    (`storage.NewInMemoryInteractionStore`). `Server` manages the lifecycle of
    the underlying HTTP recording, UDP DNS recording, and HTTP polling
    listeners.
-   **`Server.StartPolling` / `Server.StartRecordingHTTP` /
    `Server.StartRecordingDNS`**: Start the respective HTTP polling, HTTP
    recording, or UDP DNS recording listener in a background goroutine when its
    `EndpointConfig` is present and set to `MODE_START_LOCAL_SERVER`. If an
    endpoint config is omitted or uses `MODE_USE_REMOTE_SERVER`, the method logs
    a warning and returns `nil` without binding a socket.
-   **`Server.Shutdown`**: `Shutdown(ctx)` gracefully stops any active HTTP
    recording and polling servers via `http.Server.Shutdown` and closes the
    active UDP DNS recording connection.
-   **`ConfigFromFile`**: `ConfigFromFile(ctx, path)` reads a textproto file
    from `path` and unmarshals it into a `*cbpb.CallbackserverConfig` for
    standalone server binaries, wrapping `ErrConfigRead` or `ErrConfigUnmarshal`
    on failure.
-   **`ValidateConfig`**: `ValidateConfig(cfg)` verifies that `http_poll_config`
    is set, `interaction_ttl_seconds` and `cleanup_interval_seconds` are greater
    than zero, and any local HTTP or DNS recording endpoint specifies a
    `bind_port` in `1..65535`, wrapping `ErrInvalidConfig` otherwise.
-   **`CallbackserverConfig`, `EndpointConfig`, and `CallbackEndpointMode`
    (`callbackserver_config.proto`)**: Protobuf configuration types in
    `callbackserver_config_go_proto` defining the HTTP polling, HTTP recording,
    and DNS recording endpoints alongside interaction TTL (default `60`s) and
    cleanup interval (default `10`s). Each `EndpointConfig` pairs a
    `CallbackEndpointMode` (`MODE_START_LOCAL_SERVER` or
    `MODE_USE_REMOTE_SERVER`) with a `public_uri` and local
    `bind_address`/`bind_port`.
-   **Sentinel Errors (`ErrConfigRead`, `ErrConfigUnmarshal`,
    `ErrInvalidConfig`)**: `ErrConfigRead` and `ErrConfigUnmarshal` wrap file
    I/O and textproto parsing errors in `ConfigFromFile`. `ErrInvalidConfig`
    wraps configuration validation failures returned by `ValidateConfig` and
    `New`.

## Usage

```go
package example

import (
    "context"

    "google.golang.org/protobuf/proto"
    "github.com/google/goonami-scanner/tools/callbackserver"

    cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
)

func runServer(ctx context.Context) error {
    localMode := cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER.Enum()
    cfg := cbpb.CallbackserverConfig_builder{
        HttpPollConfig: cbpb.EndpointConfig_builder{
            Mode:        localMode,
            PublicUri:   proto.String("http://127.0.0.1:8081"),
            BindAddress: proto.String("127.0.0.1"),
            BindPort:    proto.Uint32(8081),
        }.Build(),
        HttpRecordConfig: cbpb.EndpointConfig_builder{
            Mode:        localMode,
            PublicUri:   proto.String("http://127.0.0.1:8080"),
            BindAddress: proto.String("127.0.0.1"),
            BindPort:    proto.Uint32(8080),
        }.Build(),
    }.Build()

    srv, err := callbackserver.New(ctx, cfg)
    if err != nil {
        return err
    }
    defer srv.Shutdown(ctx)

    if err := srv.StartPolling(ctx); err != nil {
        return err
    }
    if err := srv.StartRecordingHTTP(ctx); err != nil {
        return err
    }
    if err := srv.StartRecordingDNS(ctx); err != nil {
        return err
    }

    <-ctx.Done()
    return nil
}
```
