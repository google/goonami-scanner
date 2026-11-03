# Package `storage`

Package `storage` provides a concurrency-safe byte quota tracker for the
`webidentity` fingerprinter plugin. When the plugin is configured to persist
crawled HTML responses as artifacts on disk, `Storage` tracks cumulative bytes
reserved and prevents writes from exceeding a configured maximum storage budget.
Enforcement can be toggled at construction time so callers can use a single code
path whether artifact persistence is enabled or disabled.

## Services

-   **`Storage`**: Thread-safe storage quota manager that tracks cumulative
    reserved space in bytes against a configured maximum limit.
-   **`New(enforce bool, maxSize int64) *Storage`**: Constructs a new `Storage`
    manager initialized with zero used space. When `enforce` is `false`, quota
    checks and usage tracking are bypassed.
-   **`(*Storage).Reserve(size int64) bool`**: Attempts to allocate `size` bytes
    against the maximum quota, returning `true` if `used + size <= maxSize` (or
    whenever enforcement is disabled) and `false` otherwise.
-   **`(*Storage).Release(size int64)`**: Returns `size` bytes of previously
    reserved capacity back to the quota when enforcement is enabled, clamping
    tracked usage at `0` if `size` exceeds current usage.

## Usage

```go
import (
  "os"

  "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/storage"
)

// Enforce a 10 MiB total budget when persisting crawled HTML artifacts.
quota := storage.New(true, 10*1024*1024)

size := int64(len(content))
if quota.Reserve(size) {
  if err := os.WriteFile(artifactPath, content, 0644); err != nil {
    quota.Release(size)
    return err
  }
}
```
