# Package `testrunner`

Package `testrunner` provides a hermetic mock-HTTP test harness for validating
declarative `WebFingerprint` definitions against `WebFingerprintTests` test
suites without network access.

## Services

-   **`RunTestCase(ctx, fp, tc)`**: Seeds an in-memory `cache.Cache` with the
    mock HTTP responses from `tc`, executes `engine.Engine` against the
    compiled fingerprint `fp`, and verifies detected application roots and
    expected versions.
-   **`RunSuite(t, fpProto, suite)`**: Compiles `fpProto` once and runs
    every `TestCase` in `suite` as a Go subtest under `t` (skipping the
    suite when `disabled` is set).

## Usage

```go
import (
  "testing"

  fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
  ftpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_test_go_proto"
  "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/testrunner"
)

func runFingerprintTests(
    t *testing.T,
    fp *fpb.WebFingerprint,
    suite *ftpb.WebFingerprintTests,
) {
  testrunner.RunSuite(t, fp, suite)
}
```
