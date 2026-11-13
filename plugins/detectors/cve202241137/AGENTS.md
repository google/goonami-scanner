# Package `cve202241137`

Package `cve202241137` provides a Goonami vulnerability detector
(`dt/cve202241137`) that identifies Apache Hive Metastore servers vulnerable to
unauthenticated remote code execution via insecure Kryo deserialization in the
Thrift `get_partitions_by_expr` RPC (`CVE-2022-41137` / `HIVE-26539`).

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/cve202241137"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module`.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `APACHE_HIVE_METASTORE_CVE_2022_41137`, `CVE-2022-41137`,
    `Severity_CRITICAL`) supported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Skips web, non-TCP, and non-candidate services,
    sends a negative-control Thrift `get_partitions_by_expr` call with a
    56-byte truncated `ExprNodeGenericFuncDesc` Kryo header (falling back to
    `get_all_databases` / `get_all_tables` discovery when Hive 2.x/3.x requires
    an existing table name), and then sends a benign nested `java.util.TreeMap`
    gadget inside `ExprNodeGenericFuncDesc.chidren` using both Hive 2.x/3.x
    (`readObject(ExprNodeGenericFuncDesc.class)`, 101 bytes) and Hive 4.x
    (`readClassAndObject()`, 156 bytes) Kryo wire formats. When the target
    instantiates `java.util.TreeMap` at `classCounter > 0` and returns a Thrift
    `MetaException` containing `java.lang.ClassCastException:
    java.util.ArrayList cannot be cast to java.lang.Comparable` and
    `ExprNodeGenericFuncDesc`, returns a `*dpb.DetectionReportList` with
    `DetectionStatus_VULNERABILITY_VERIFIED`.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/cve202241137"
)
```
