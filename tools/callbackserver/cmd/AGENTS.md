# Package `main` (`tools/callbackserver/cmd`)

Package `main` is the standalone `callbackserver` CLI binary entrypoint for
running Goonami's out-of-band callback server outside the main scanner process.
It parses command-line flags, configures logging, loads a textproto
`CallbackserverConfig` from disk, and starts the HTTP recording and HTTP polling
endpoints. The binary blocks until `SIGINT` or `SIGTERM` is received, then
cancels its context and shuts down the server gracefully.

## Services

-   **`callbackserver` CLI entrypoint (`main`)**: Configures a
    `log.DefaultLogger`, reads a `CallbackserverConfig` via
    `callbackserver.ConfigFromFile`, creates a `callbackserver.Server`, and
    starts its HTTP recording (`StartRecordingHTTP`) and HTTP polling
    (`StartPolling`) servers. Exits with status `1` on startup errors and calls
    `Server.Shutdown` upon receiving `SIGINT` or `SIGTERM`.
-   **CLI flags (`-config`, `-colors`, `-debug`)**: `-config` sets the path to
    the textproto configuration file (default `""`, required for startup to
    succeed). `-colors` toggles ANSI log colors (default `true`), and `-debug`
    sets the numeric log verbosity level (default `0`).
-   **Sample configuration (`config.textproto`)**: Defines a local
    `MODE_START_LOCAL_SERVER` configuration with a 300-second interaction TTL
    and 10-second cleanup interval. Configures endpoints on `127.0.0.1:8080` for
    HTTP recording, `127.0.0.1:8081` for HTTP polling, and `127.0.0.1:5353`
    (`cb.localhost.lan`) for DNS recording.

## Usage

```sh
go run ./tools/callbackserver/cmd \
  -config=tools/callbackserver/cmd/config.textproto \
  -debug=1 \
  -colors=false
```
