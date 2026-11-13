# Package `fakessh`

Package `fakessh` provides an in-process fake SSH server listening on
`127.0.0.1` for unit and integration testing of SSH clients and plugins in
Goonami. It performs real SSH protocol handshakes backed by a static Ed25519
host key, supporting custom `ssh.ServerConfig` setups as well as preconfigured
password and public-key-only authentication modes. Accepted connections complete
authentication and immediately close opened channels while discarding requests,
and helper accessors expose the bound address, port, and a Tsunami
`NetworkService` protobuf descriptor.

## Services

-   **`Server` and `New(cfg *ssh.ServerConfig) (*Server, error)`**: Starts a
    local TCP listener on `127.0.0.1:0` and serves SSH handshakes in a
    background goroutine using `cfg` (or an empty `ssh.ServerConfig` if `nil`)
    with a static Ed25519 host key attached. Accepted connections discard global
    and channel requests and immediately close any opened SSH channels.
-   **`NewWithPasswordAuth(user, password string) (*Server, error)`**: Starts a
    `Server` configured with password authentication that accepts only the exact
    `user` and `password` pair and rejects all other credentials.
-   **`NewWithKeyboardInteractiveAuth(user, password string) (*Server,
    error)`**: Starts a `Server` configured with only keyboard-interactive
    authentication that accepts only the exact `user` and `password` pair and
    rejects all other credentials.
-   **`NewPublicKeyOnly() (*Server, error)`**: Starts a `Server` configured with
    only a rejecting `PublicKeyCallback` so password authentication is
    advertised as unsupported during SSH handshakes.
-   **`GenerateSigner() (ssh.Signer, error)`**: Parses and returns an
    `ssh.Signer` from the built-in static Ed25519 OpenSSH test private key used
    to sign server host keys.
-   **`(*Server).Addr() string` and `(*Server).Port() int`**: Return the bound
    `127.0.0.1:<port>` TCP address string and integer port number that the
    server is listening on.
-   **`(*Server).NetworkService() *nspb.NetworkService`**: Constructs a Tsunami
    `NetworkService` protobuf message (`service_name: "ssh"`, IPv4 `127.0.0.1`,
    and `Port()`) targeting the running fake server for plugin tests.
-   **`(*Server).Close() error`**: Stops the server by closing its underlying
    TCP listener, ignoring `nil` listeners and `net.ErrClosed` errors for
    idempotent cleanup.

## Usage

```go
package example_test

import (
    "testing"

    "github.com/google/goonami-scanner/common/clients/sshclient"
    "github.com/google/goonami-scanner/common/testfakes/fakessh"
)

func TestSSHProbe(t *testing.T) {
    srv, err := fakessh.NewWithPasswordAuth("admin", "secret")
    if err != nil {
        t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
    }
    defer func() { _ = srv.Close() }()

    svc := srv.NetworkService() // Endpoint for plugin Detect() calls.
    _ = svc

    client := sshclient.New(nil)
    conn, err := client.Connect(t.Context(), srv.Addr(), "admin", "secret")
    if err != nil {
        t.Fatalf("Connect(%q) unexpected error: %v", srv.Addr(), err)
    }
    _ = conn.Close()
}
```
