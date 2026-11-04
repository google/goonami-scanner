# Package `parser`

Package `parser` parses HTML documents to extract and resolve candidate target
URLs for Goonami's HTTP web crawler (`httpcrawler`). It traverses the HTML DOM
tree to inspect standard HTML4 and HTML5 link-bearing attributes as well as
`<meta>` refresh directives. Relative links are resolved against the page's root
URL, non-crawlable prefixes (`data:`, `javascript:`, `mailto:`, and `tel:`) are
ignored case-insensitively, and other non-HTTP(S) schemes return an error.

## Services

-   **`ExtractLinksFromHTML`**: Parses raw HTML bytes (`content`), inspects
    HTML4 and HTML5 link attributes such as `href`, `src`, `action`,
    `formaction`, and `<meta>` refresh `content` across all nodes, and returns
    extracted URLs (`[]string`) resolved against `rootURL`. Attributes starting
    with `data:`, `javascript:`, `mailto:`, or `tel:` (case-insensitively) are
    silently skipped.
-   **`ErrParseURL`**: Sentinel error wrapped and returned when an extracted
    link attribute or `rootURL` cannot be parsed as a valid URL.
-   **`ErrUnsupportedScheme`**: Sentinel error wrapped and returned when a
    non-ignored link specifies a URL scheme other than `http` or `https`.

## Usage

```go
package example

import (
    "errors"

    "github.com/google/goonami-scanner/common/clients/httpcrawler/parser"
)

func discoverLinks(pageURL string, htmlContent []byte) ([]string, error) {
    links, err := parser.ExtractLinksFromHTML(pageURL, htmlContent)
    if err != nil {
        if errors.Is(err, parser.ErrParseURL) ||
            errors.Is(err, parser.ErrUnsupportedScheme) {
            return nil, nil
        }
        return nil, err
    }
    return links, nil
}
```
