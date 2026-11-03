# Package `netendpoint`

Package `netendpoint` provides helper functions for constructing Tsunami
`NetworkEndpoint` protocol buffers and formatting them as URI authority strings.
It parses bare IPv4, IPv6, or hostname strings into `NetworkEndpoint` messages
and formats endpoints into `host` or `host:port` authorities (with bracketed
IPv6 literals) while prioritizing hostnames for HTTP virtual-host matching.
Goonami networking libraries, scan runners, and plugins use it to build dial
addresses, web roots, and redirect allowlists, and to identify endpoints missing
a usable address.

## Services

-   **`FromString(endpoint string) *npb.NetworkEndpoint`**: Builds a
    `NetworkEndpoint` from an address string, setting `Type` to
    `NetworkEndpoint_IP` (`AddressFamily_IPV4` or `AddressFamily_IPV6`) when
    `iputils.IsIP` succeeds, or `NetworkEndpoint_HOSTNAME` otherwise. Inputs
    must not include a port, as port-suffixed strings fail IP parsing and are
    stored verbatim as hostnames.
-   **`ToURIAuthority(endpoint *npb.NetworkEndpoint) (string, error)`**: Formats
    `endpoint` as its primary URI authority (`host` or `host:port`, enclosing
    `AddressFamily_IPV6` addresses in square brackets), preferring the hostname
    over the IP address when both are present so HTTP virtual-host matching
    succeeds. Returns `ErrEndpointMissingAddress` if neither a hostname nor an
    IP address is populated.
-   **`ToURIAuthorities(endpoint *npb.NetworkEndpoint) ([]string, error)`**:
    Returns all URI authority strings (`host` or `host:port`, with bracketed
    `AddressFamily_IPV6` addresses) available on `endpoint`, placing the
    hostname-based authority before the IP-based authority when both are set.
    Returns `ErrEndpointMissingAddress` if `endpoint` has neither a hostname nor
    an IP address.
-   **`ErrEndpointMissingAddress`**: Sentinel error returned by `ToURIAuthority`
    and `ToURIAuthorities` when a `NetworkEndpoint` lacks both a hostname and an
    IP address. Callers such as `SimpleRunner` match it with `errors.Is` to drop
    unusable services during scanning.

## Usage

```go
import (
    "errors"
    "net"

    "github.com/google/goonami-scanner/core/net/netendpoint"
    npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
)

// Construct a NetworkEndpoint from a bare IPv4, IPv6, or hostname string.
ipEndpoint := netendpoint.FromString("2001:db8::1")

// Format a service endpoint into URI authorities (hostname prioritized).
svcEndpoint := npb.NetworkEndpoint_builder{
    IpAddress: ipEndpoint.GetIpAddress(),
    Hostname:  npb.Hostname_builder{Name: "app.example.com"}.Build(),
    Port:      npb.Port_builder{PortNumber: 443}.Build(),
}.Build()

authority, err := netendpoint.ToURIAuthority(svcEndpoint)
if err != nil {
    if errors.Is(err, netendpoint.ErrEndpointMissingAddress) {
        // Endpoint lacks both hostname and IP address.
    }
    return err
}
// authority == "app.example.com:443"
conn, err := net.Dial("tcp", authority)

allAuths, err := netendpoint.ToURIAuthorities(svcEndpoint)
// allAuths == []string{"app.example.com:443", "[2001:db8::1]:443"}
```
