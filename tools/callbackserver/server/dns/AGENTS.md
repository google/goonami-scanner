# Package `dns`

Package `dns` implements the UDP DNS interaction recording endpoint for the
Goonami callback server. It inspects incoming DNS queries targeting a configured
callback domain, extracts the embedded callback identifier (CBID), and records
out-of-band `DNSInteraction` entries in a `storage.InteractionStore`. Security
scanner plugins rely on these recorded DNS lookups to detect blind out-of-band
vulnerabilities when targets resolve unique callback subdomains.

## Services

-   **`RecordingHandler`**: Struct holding `Store` (`storage.InteractionStore`)
    and `Domain` (`string`) to configure where valid DNS interactions are stored
    and which base callback domain (and its subdomains) the handler answers.
-   **`(*RecordingHandler).HandleDNS`**: Unpacks a raw UDP DNS query packet,
    verifies case-insensitively that the first question targets `Domain` or one
    of its subdomains, extracts the CBID, and registers a
    `storage.DNSInteraction` in `Store`. Replies with `RCodeNameError`
    (`NXDOMAIN`) after recording, `RCodeRefused` (`REFUSED`) on domain mismatch,
    invalid CBID, or storage error, and silently drops malformed or questionless
    packets.
-   **`ServeDNS`**: Reads UDP datagrams up to 512 bytes from a `*net.UDPConn` in
    a loop and dispatches each packet concurrently to `handler.HandleDNS` until
    the context is canceled, closing `conn` on return.

## Usage

```go
package main

import (
    "context"
    "net"
    "time"

    "github.com/google/goonami-scanner/tools/callbackserver/server/dns"
    "github.com/google/goonami-scanner/tools/callbackserver/storage"
)

func startDNSRecorder(ctx context.Context) (*net.UDPConn, error) {
    store := storage.NewInMemoryInteractionStore(
        ctx, 10*time.Minute, 1*time.Minute,
    )
    handler := &dns.RecordingHandler{
        Store:  store,
        Domain: "cb.example.com",
    }

    addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8053")
    if err != nil {
        return nil, err
    }
    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        return nil, err
    }

    go dns.ServeDNS(ctx, conn, handler)
    return conn, nil
}
```
