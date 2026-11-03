# Package `netendpoint`

Package `netendpoint` provides helper functions for constructing, expanding, and
formatting Tsunami `NetworkEndpoint` protocol buffers. It parses bare IPv4,
IPv6, hostname, or CIDR target strings into `NetworkEndpoint` messages, promotes
host endpoints to port-bearing service endpoints, formats and splits canonical
portless host identifiers, and formats URI authority strings (`host` or
`host:port` with bracketed IPv6 literals) while prioritizing hostnames for HTTP
virtual-host matching. Goonami networking libraries, scan runners, and plugins
use it for target expansion, dial addresses, web roots, redirect allowlists, and
host-scoped logging, metrics, and result grouping.

## Services

-   **`FromString(endpoint string) *npb.NetworkEndpoint`**: Builds a
    `NetworkEndpoint` from an address string, setting `Type` to
    `NetworkEndpoint_IP` (`AddressFamily_IPV4` or `AddressFamily_IPV6`) when
    `iputils.IsIP` succeeds, or `NetworkEndpoint_HOSTNAME` otherwise. Inputs
    must not include a port, as port-suffixed strings fail IP parsing and are
    stored verbatim as hostnames.
-   **`FromTarget(target string) ([]*npb.NetworkEndpoint, error)`**: Converts a
    scan target (a CIDR range, IP address, or hostname) into one or more
    portless `NetworkEndpoint` messages. Non-CIDR inputs without `'/'` are
    converted directly via `FromString`, whereas slash-containing inputs are
    expanded via `iputils.ExpandCIDR`. Returns `ErrEndpointMissingAddress` if
    `target` is empty, or an error wrapping `iputils.ErrInvalidCIDR` or
    `iputils.ErrCIDRTooLarge` if the CIDR prefix is malformed or exceeds the
    expansion limit.
-   **`WithPort(endpoint *npb.NetworkEndpoint, port uint32) (*npb.NetworkEndpoint, error)`**:
    Returns a copy of `endpoint` with `port` attached and `Type` promoted from
    `NetworkEndpoint_IP`, `NetworkEndpoint_HOSTNAME`, or
    `NetworkEndpoint_IP_HOSTNAME` to the corresponding `*_PORT` variant
    (`IP_PORT`, `HOSTNAME_PORT`, or `IP_HOSTNAME_PORT`). Returns an error
    wrapping `ErrInvalidEndpointType` for `nil`, unspecified, or already
    port-bearing endpoints.
-   **`ToHost(endpoint *npb.NetworkEndpoint) (string, error)`**: Formats
    `endpoint` as a canonical host identifier without a port (`"<ip>"`,
    `"<hostname>"`, or `"<ip>_<hostname>"` when both non-empty IP address and
    hostname strings are present). Returns `ErrEndpointMissingAddress` when
    `endpoint` is `nil` or lacks both a non-empty IP address and hostname.
-   **`SplitHost(host string) []string`**: Splits a canonical host string
    produced by `ToHost` into `[ip, hostname]` for composite `"<ip>_<hostname>"`
    values (preserving underscores inside hostnames because IP literals never
    contain `'_'`), `[host]` for single IP or hostname values, or `nil` when
    `host` is empty.
-   **`ToURIAuthority(endpoint *npb.NetworkEndpoint) (string, error)`**: Formats
    `endpoint` as its primary URI authority (`host` or `host:port`, enclosing
    `AddressFamily_IPV6` addresses in square brackets), preferring a non-empty
    hostname over a non-empty IP address when both are present so HTTP
    virtual-host matching succeeds. Returns `ErrEndpointMissingAddress` if
    `endpoint` is `nil` or neither a non-empty hostname nor a non-empty IP
    address is populated.
-   **`ToURIAuthorities(endpoint *npb.NetworkEndpoint) ([]string, error)`**:
    Returns all URI authority strings (`host` or `host:port`, with bracketed
    `AddressFamily_IPV6` addresses) available on `endpoint`, placing the
    hostname-based authority before the IP-based authority when both are set.
    Returns `ErrEndpointMissingAddress` if `endpoint` has neither a hostname nor
    an IP address.
-   **`ErrEndpointMissingAddress`**: Sentinel error returned by `FromTarget`,
    `ToHost`, `ToURIAuthority`, and `ToURIAuthorities` when a target is empty or
    a `NetworkEndpoint` lacks both a hostname and an IP address. Callers such as
    `SimpleRunner` match it with `errors.Is` to reject or drop unusable targets
    and services during scanning.
-   **`ErrInvalidEndpointType`**: Sentinel error wrapped and returned by
    `WithPort` when an endpoint's `Type` cannot be promoted to a port-bearing
    endpoint type (matchable with `errors.Is`).

## Usage

```go
import (
    "errors"
    "net"

    "github.com/google/goonami-scanner/core/net/netendpoint"
    npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
)

// Expand a CIDR or single host target into portless NetworkEndpoints.
endpoints, err := netendpoint.FromTarget("2001:db8::/127")
if err != nil {
    return err
}

// Promote a host endpoint to a port-bearing endpoint.
portEndpoint, err := netendpoint.WithPort(endpoints[0], 443)
if err != nil {
    if errors.Is(err, netendpoint.ErrInvalidEndpointType) {
        // Endpoint type cannot be promoted to *_PORT.
    }
    return err
}

// Format a composite IP + hostname service endpoint into host and URI forms.
svcEndpoint := npb.NetworkEndpoint_builder{
    Type:      npb.NetworkEndpoint_IP_HOSTNAME_PORT,
    IpAddress: portEndpoint.GetIpAddress(),
    Hostname:  npb.Hostname_builder{Name: "app.example.com"}.Build(),
    Port:      portEndpoint.GetPort(),
}.Build()

host, err := netendpoint.ToHost(svcEndpoint)
if err != nil {
    return err
}
// host == "2001:db8::_app.example.com"
// netendpoint.SplitHost(host) == []string{"2001:db8::", "app.example.com"}

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
// allAuths == []string{"app.example.com:443", "[2001:db8::]:443"}
```
