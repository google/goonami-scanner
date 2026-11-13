# Package `metrics`

Package `metrics` provides Goonami's bounded telemetry declaration, recording,
in-memory aggregation, and protobuf export framework. All scan, module, HTTP,
budget, and LLM metrics are pre-declared in a central catalog with bounded label
keys so target-controlled inputs cannot cause unbounded series cardinality.
Observations default to a zero-overhead `NoopRecorder` until a `Recorder` such
as `Collector` is installed via `SetRecorder` or `entrypoint.Options`. At scan
completion or in tests, `Collector` supports deterministic series queries and
exports aggregated `ScanMetrics` protobuf or textproto summaries.

## Services

-   **`Metric`, `Unit`, and `Declared`**: `Metric` is a sealed read-only
    interface (`Name`, `Description`, `Unit`, `LabelKeys`) implemented
    exclusively by `*Counter` and `*Distribution`, using `Unit` constants
    (`UnitCount`, `UnitSeconds`, `UnitBytes`). `Declared` returns all registered
    metrics in the catalog sorted by name.
-   **`Counter` and `NewCounter`**: Declares and registers a monotonically
    increasing `UnitCount` metric at initialization time, panicking on malformed
    or duplicate names, empty descriptions, or invalid label keys. `Counter.Add`
    increments the series on the active `Recorder`, logging an error and
    dropping negative deltas.
-   **`Distribution` and `NewDistribution`**: Declares and registers a sample
    distribution metric with a `Unit` and allowed `LabelKey` list, panicking
    under the same validation rules as `NewCounter`. `Distribution.Observe`
    records a `float64` sample on the active `Recorder`.
-   **`Label`, `LabelKey`, `LimitNameValue`, and Label Constructors**: `Label`
    pairs a declared `LabelKey` (`LabelModule`, `LabelErrorClass`,
    `LabelLimitName`, `LabelModel`, `LabelFingerprint`, `LabelRule`) with a
    sanitized string value, while metrics drop undeclared or duplicate keys
    automatically. Constructors `Module`, `LLMModel`, `Fingerprint`,
    `FingerprintRule`, `LimitName` (`LimitMaxAttemptsPerService`,
    `LimitMaxRequestsPerService`, `LimitMaxHTTPRedirects`, `LimitMaxAttempts`),
    and `ErrorClass` build normalized labels with bounded values.
-   **Catalog Metric Handles**: Pre-declared handles record scan phase latencies
    (`ScanDuration`, `PortScanDuration`, `FingerprintDuration`,
    `DetectDuration`), module execution, fingerprints, and findings
    (`ServicesDiscovered`, `ModuleDuration`, `ModuleErrors`, `Findings`,
    `FingerprintIdentifications`, `BudgetExhausted`), and HTTP traffic
    (`HTTPRequests`, `HTTPRequestErrors`). LLM telemetry is tracked via
    `LLMDuration` and token counters (`LLMTokens`, `LLMInputTokens`,
    `LLMCachedTokens`, `LLMOutputTokens`, `LLMThoughtTokens`,
    `LLMToolInputTokens`).
-   **`Recorder`, `NoopRecorder`, `SetRecorder`, and `CurrentRecorder`**:
    `Recorder` defines the concurrency-safe observation sink (`Add` and
    `Observe`), defaulting globally to `NoopRecorder` so uninstrumented callers
    incur no overhead. `SetRecorder` installs the active global `Recorder` (or
    restores `NoopRecorder` when passed `nil`), and `CurrentRecorder` retrieves
    it.
-   **`Collector`, `NewCollector`, and `CollectorOption`**: Concurrency-safe
    `Recorder` (`Add`, `Observe`) and test double that aggregates observations
    in memory while capping series per metric at `DefaultMaxSeriesPerMetric`
    (200), configurable via `WithMaxSeriesPerMetric`. Callers inspect collected
    data through `Series`, `Value`, `Stats`, and `DroppedObservations`.
-   **`Series` and `Stats`**: `Series` pairs a `Metric` and its normalized
    `Labels` with either a counter total via `Value` or a distribution `Stats`
    summary (`Count`, `Sum`, `Min`, `Max`) via `Stats`.
-   **`Collector.Export`, `Collector.WriteFile`, and Sentinel Errors**: `Export`
    converts collected series and cap-dropped counts into a `ScanMetrics`
    protobuf message, and `WriteFile` writes it to disk as a multiline
    textproto. `WriteFile` wraps marshaling and filesystem failures with
    `ErrMarshalMetrics` and `ErrWriteMetrics`.
-   **`ScanMetrics` Protobuf Messages (`scan_metrics.proto`)**: Defines
    `ScanMetrics`, `Series`, `Label`, `Distribution`, and `DroppedSeries` for
    serializing end-of-scan counter totals, distribution summaries, and dropped
    observation counts.

## Usage

```go
package example

import (
  "context"
  "time"

  "github.com/google/goonami-scanner/core/metrics"
)

func recordDetectorRun(
    ctx context.Context,
    moduleName string,
    run func(context.Context) (int64, error),
) error {
  start := time.Now()
  findings, err := run(ctx)
  elapsed := time.Since(start).Seconds()

  mod := metrics.Module(moduleName)
  metrics.ModuleDuration.Observe(ctx, elapsed, mod)
  if err != nil {
    metrics.ModuleErrors.Add(ctx, 1, mod, metrics.ErrorClass(err))
    return err
  }
  if findings > 0 {
    metrics.Findings.Add(ctx, findings, mod)
  }
  return nil
}

func collectAndWrite(ctx context.Context, outPath string) (int64, error) {
  collector := metrics.NewCollector()
  metrics.SetRecorder(collector)
  defer metrics.SetRecorder(nil)

  metrics.ServicesDiscovered.Add(ctx, 3)
  count := collector.Value(ctx, metrics.ServicesDiscovered)
  return count, collector.WriteFile(outPath)
}
```
