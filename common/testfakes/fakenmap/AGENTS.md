# Package `fakenmap`

Package `fakenmap` provides a fake implementation of the `nmap.Client` interface
for unit testing components that consume `nmap` scan results without executing
the `nmap` binary. Callers can construct a `Client` directly from an in-memory
`*nmap.OutputXML` and `error`, or load canned `nmap` XML (`-oX`) test fixtures
from disk. Reconnaissance plugins such as the `ps/nmap` port scanner use
`fakenmap` in unit tests to replay saved XML scan reports and simulate scanner
errors.

## Services

-   **`Client`**: Fake implementation of `nmap.Client` that stores a
    preconfigured `*nmap.OutputXML` and `error` to return during tests.
-   **`New`**: Constructs a `*Client`
    (`New(output *nmap.OutputXML, err error) *Client`) configured to return the
    given parsed output and error, including both simultaneously when non-nil.
-   **`FromFile`**: Reads an `nmap` XML file from `path`
    (`FromFile(path string) (*Client, error)`) and parses it via
    `nmap.ParseXMLOutput` into a `*Client` with a `nil` run error. Returns any
    file read error (such as `os.ErrNotExist`) or XML unmarshalling error
    wrapping `nmap.ErrNmapXMLUnmarshal`.
-   **`(*Client).Run`**: Implements `nmap.Client`
    (`Run(ctx context.Context, target string) (*nmap.OutputXML, error)`) by
    returning the configured `*nmap.OutputXML` and `error` verbatim without
    inspecting `ctx` or `target`.

## Usage

Load a canned `nmap` XML fixture from `testdata`:

```go
import (
    "path/filepath"
    "testing"

    "github.com/google/goonami-scanner/common/testfakes/fakenmap"
)

func TestScannerWithXMLFixture(t *testing.T) {
    xmlPath := filepath.Join("testdata", "service_is_ip_port_tcp.xml")
    client, err := fakenmap.FromFile(xmlPath)
    if err != nil {
        t.Fatalf("FromFile(%q) failed: %v", xmlPath, err)
    }

    out, err := client.Run(t.Context(), "127.0.0.1")
    if err != nil {
        t.Fatalf("Run() unexpected error: %v", err)
    }
    _ = out
}
```

Simulate an `nmap` execution error or return an in-memory `*nmap.OutputXML`:

```go
import (
    "errors"
    "testing"

    "github.com/google/goonami-scanner/common/clients/nmap"
    "github.com/google/goonami-scanner/common/testfakes/fakenmap"
)

func TestScannerErrorHandling(t *testing.T) {
    wantErr := errors.New("nmap execution failed")
    var client nmap.Client = fakenmap.New(nil, wantErr)

    _, err := client.Run(t.Context(), "127.0.0.1")
    if !errors.Is(err, wantErr) {
        t.Errorf("Run() error = %v, want %v", err, wantErr)
    }
}
```
