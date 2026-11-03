# Package `faketemplated`

Package `faketemplated` provides an `httptest`-backed mock HTTP server and test
harness helpers for unit testing textproto-defined templated plugins in Goonami.
It loads `TemplatedPlugin` and `TemplatedPluginTests` definitions from an
`fs.FS`, serves conditional mock HTTP responses with runtime variable
substitution from an `environment.Environment`, and builds `NetworkService`
descriptors targeting local test servers. Detector test suites such as
`templated` and `templatedweakcredentials` use it to execute declarative
`*_test.textproto` scenarios against simulated HTTP endpoints without external
network dependencies.

## Services

-   **`LoadPluginsAndTests`**: `LoadPluginsAndTests(fsys)` recursively walks
    `fsys` from `"."` and unmarshals `.textproto` files into maps of
    `*tpb.TemplatedPlugin` (keyed by `info.name`) and
    `*ttpb.TemplatedPluginTests` (for `*_test.textproto` files, keyed by file
    path). Non-`.textproto` entries are ignored, and directory walk or
    `prototext` unmarshaling failures return an error.
-   **`NewHTTPServer`**: `NewHTTPServer(ctx, mockServer, env)` starts an
    `*httptest.Server` that evaluates `mockServer.GetMockResponses()` in order,
    substituting template variables from `env` into each mock URI (prepending
    `"/"` when relative unless prefixed with
    `environment.VarTestingMagicPrefix`) and matching against
    `environment.VarTestingMagicAnyURI`, `r.URL.String()`, or `r.URL.Path`. For
    the first URI match where `MatchesConditions` succeeds, it writes the
    variable-substituted response headers, status code, and body, or responds
    with `404 Not Found` if none match.
-   **`MatchesConditions`**: `MatchesConditions(ctx, r, cond, env)` reports
    whether an `*http.Request` satisfies all header, `GET` query parameter, HTTP
    method (`request_type`), and body substring checks in `cond` after variable
    substitution via `env`, returning `true` when `cond` is `nil`. When body
    substring checks are present, it reads and restores `r.Body` so subsequent
    readers can still consume the payload.
-   **`ServiceForServer`**: `ServiceForServer(server)` parses the `host:port`
    address from `server.URL` and returns an HTTP `*nspb.NetworkService` with an
    `IP_HOSTNAME_PORT` IPv4 endpoint supporting `GET`, `POST`, `PUT`, `DELETE`,
    and `HEAD`. It returns an error if `server.URL` cannot be split into a host
    and port.

## Usage

```go
package detector_test

import (
  "embed"
  "testing"

  "github.com/google/goonami-scanner/common/templatedengine/environment"
  "github.com/google/goonami-scanner/common/templatedengine"
  "github.com/google/goonami-scanner/common/testfakes/faketemplated"
  "github.com/google/goonami-scanner/core/config"
  _ "github.com/google/goonami-scanner/core/net/http/simpleclient"
)

//go:embed detections
var pluginFilesFS embed.FS

func TestTemplatedPlugins(t *testing.T) {
  plugins, tests, err := faketemplated.LoadPluginsAndTests(pluginFilesFS)
  if err != nil {
    t.Fatalf("LoadPluginsAndTests() unexpected error: %v", err)
  }

  cfg := config.Default()
  for _, suite := range tests {
    plugin := plugins[suite.GetConfig().GetTestedPlugin()]
    for _, tc := range suite.GetTests() {
      t.Run(tc.GetName(), func(t *testing.T) {
        ctx := t.Context()
        env := environment.New(cfg)
        env.Set(environment.VarTestingDisableSleep, "true")

        srv := faketemplated.NewHTTPServer(ctx, tc.GetMockHttpServer(), env)
        defer srv.Close()

        svc, err := faketemplated.ServiceForServer(srv)
        if err != nil {
          t.Fatalf("ServiceForServer() unexpected error: %v", err)
        }
        if err := env.InitializeFor(ctx, svc); err != nil {
          t.Fatalf("InitializeFor() unexpected error: %v", err)
        }

        det, err := templatedengine.NewForTesting(ctx, cfg, plugin, env)
        if err != nil {
          t.Fatalf("NewForTesting() unexpected error: %v", err)
        }
        reports, err := det.Detect(ctx, svc)
        if err != nil {
          t.Fatalf("Detect() unexpected error: %v", err)
        }
        got := len(reports.GetDetectionReports()) > 0
        if got != tc.GetExpectVulnerability() {
          t.Errorf("got vuln = %v, want %v", got, tc.GetExpectVulnerability())
        }
      })
    }
  }
}
```
