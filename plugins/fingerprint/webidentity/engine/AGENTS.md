# Package `engine`

Package `engine` orchestrates two-pass declarative web application
fingerprinting for the `fp/webidentity` plugin. Pass 1 evaluates passively
crawled responses already in the HTTP cache, and Pass 2 issues targeted active
HTTP probes for remaining workflows and version extraction while coalescing
duplicate requests.

## Services

-   **`CompiledFingerprint`, `CompileFingerprint(fp)`**: Compiles a
    `WebFingerprint` proto (metadata, named steps, and workflows) into an
    in-memory executable representation, rejecting missing software identifiers
    or duplicate step names.
-   **`Engine`, `New(fps)`, and `(*Engine).Fingerprints()`**: Filters active
    compiled fingerprints (skipping disabled definitions) and exposes the loaded
    catalog.
-   **`(*Engine).Run(ctx, c, baseURL)`**: Executes passive cache evaluation and
    active probing against `baseURL` using `cache.Cache`, returning sorted
    `*IdentificationResult` entries with `Software`, `ApplicationRoot`, and
    deduplicated `Versions`.
-   **Sentinel errors (`ErrNilFingerprint`, `ErrMissingSoftware`,
    `ErrDuplicateStep`)**: Returned by `CompileFingerprint` for invalid
    fingerprint definitions.

## Usage

```go
import (
  "context"

  "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/cache"
  "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/engine"
  fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
)

func detectApps(
    ctx context.Context,
    fps []*fpb.WebFingerprint,
    c *cache.Cache,
    baseURL string,
) ([]*engine.IdentificationResult, error) {
  var compiled []*engine.CompiledFingerprint
  for _, fp := range fps {
    cf, err := engine.CompileFingerprint(fp)
    if err != nil {
      return nil, err
    }
    compiled = append(compiled, cf)
  }
  return engine.New(compiled).Run(ctx, c, baseURL)
}
```
