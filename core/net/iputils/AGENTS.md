# Package `iputils`

Package `iputils` provides lightweight helper functions for validating IP
address strings and distinguishing between IPv4 and IPv6 formats. All checks
wrap `net.ParseIP` and `net.IP.To4` from the Go standard library without
performing DNS resolution. Goonami networking packages, scanner clients, and
callback server utilities use it to differentiate IP literals from hostnames and
select IPv4 or IPv6 handling.

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

## Usage

```go
import (
    "errors"

    "github.com/google/goonami-scanner/core/net/iputils"
)

func validateDomain(domain string) error {
    if iputils.IsIP(domain) {
        return errors.New("expected domain name, got IP address")
    }
    return nil
}

func ipVersionFlag(target string) string {
    switch {
    case iputils.IsIPv4(target):
        return "-4"
    case iputils.IsIPv6(target):
        return "-6"
    default:
        return ""
    }
}
```
