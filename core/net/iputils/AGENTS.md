# Package `iputils`

Package `iputils` provides lightweight helper functions for validating IP
address strings and CIDR prefixes, distinguishing between IPv4 and IPv6 formats,
and expanding or counting addresses in CIDR ranges. IP literal checks wrap
`net.ParseIP` and `net.IP.To4`, and CIDR helpers wrap `netip.ParsePrefix` from
the Go standard library without performing DNS resolution. Goonami networking
packages, scanner clients, entrypoint target parsers, and callback server
utilities use it to differentiate IP literals and CIDR blocks from hostnames,
select IPv4 or IPv6 handling, and expand or count scan targets.

## Services

-   **`IsIP(ip string) bool`**: Reports whether `ip` can be parsed by
    `net.ParseIP` as a valid IPv4 or IPv6 address literal, returning `false` for
    hostnames, empty strings, or unparseable inputs.
-   **`IsIPv4(ip string) bool`**: Parses `ip` with `net.ParseIP` and reports
    whether `addr.To4() != nil`. Returns `false` for IPv6 addresses, hostnames,
    and invalid strings.
-   **`IsIPv6(ip string) bool`**: Parses `ip` with `net.ParseIP` and reports
    whether `addr.To4() == nil`. Returns `false` for IPv4 addresses, hostnames,
    and invalid strings.
-   **`IsCIDR(cidr string) bool`**: Reports whether `cidr` can be parsed by
    `netip.ParsePrefix` as a valid IPv4 or IPv6 CIDR prefix.
-   **`IsIPv4CIDR(cidr string) bool`**: Parses `cidr` with `netip.ParsePrefix`
    and reports whether `p.Addr().Is4()` is `true`. Returns `false` for IPv6
    CIDR prefixes, bare IP addresses, hostnames, and invalid strings.
-   **`IsIPv6CIDR(cidr string) bool`**: Parses `cidr` with `netip.ParsePrefix`
    and reports whether `p.Addr().Is6()` is `true`. Returns `false` for IPv4
    CIDR prefixes, bare IP addresses, hostnames, and invalid strings.
-   **`ExpandCIDR(cidr string) ([]string, error)`**: Masks `cidr` to its
    canonical network prefix (`p.Masked()`) and expands it into a slice of all
    IP address strings in the range. Caps in-memory expansion at 20 host bits
    (`2^20` = 1,048,576 addresses); returns `ErrInvalidCIDR` (wrapped) if `cidr`
    cannot be parsed, or `ErrCIDRTooLarge` (wrapped) if the prefix exceeds 20
    host bits.
-   **`CountCIDR(cidr string) (int64, error)`**: Computes the number of IP
    addresses in `cidr` (`int64(1) << hostBits`) without expanding the range.
    Caps counting at 62 host bits (`2^62` addresses) so the result fits in a
    positive `int64`; returns `ErrInvalidCIDR` (wrapped) if `cidr` cannot be
    parsed, or `ErrCIDRTooLarge` (wrapped) if the prefix exceeds 62 host bits.
-   **`ErrInvalidCIDR`**: Sentinel error wrapped and returned by `ExpandCIDR`
    and `CountCIDR` when the input cannot be parsed as a CIDR range (matchable
    with `errors.Is`).
-   **`ErrCIDRTooLarge`**: Sentinel error wrapped and returned by `ExpandCIDR`
    (above 20 host bits) and `CountCIDR` (above 62 host bits) when the CIDR
    range exceeds the supported size bound (matchable with `errors.Is`).

## Usage

```go
import (
    "errors"

    "github.com/google/goonami-scanner/core/net/iputils"
)

func validateDomain(domain string) error {
    if iputils.IsIP(domain) || iputils.IsCIDR(domain) {
        return errors.New("expected domain name, got IP address or CIDR range")
    }
    return nil
}

func ipVersionFlag(target string) string {
    switch {
    case iputils.IsIPv4(target), iputils.IsIPv4CIDR(target):
        return "-4"
    case iputils.IsIPv6(target), iputils.IsIPv6CIDR(target):
        return "-6"
    default:
        return ""
    }
}

func expandAndCountTargets(target string) ([]string, int64, error) {
    if !iputils.IsCIDR(target) {
        return []string{target}, 1, nil
    }
    count, err := iputils.CountCIDR(target)
    if err != nil {
        return nil, 0, err
    }
    ips, err := iputils.ExpandCIDR(target)
    if err != nil {
        if errors.Is(err, iputils.ErrCIDRTooLarge) {
            // CIDR exceeds 2^20 addresses for in-memory expansion.
        }
        return nil, 0, err
    }
    return ips, count, nil
}
```
