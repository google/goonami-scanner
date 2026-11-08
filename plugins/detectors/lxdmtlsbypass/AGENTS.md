# Package `lxdmtlsbypass`

Package `lxdmtlsbypass` provides a Goonami vulnerability detector
(`dt/lxdmtlsbypass`) for **CVE-2026-112816** (`GHSA-xg75-xf37-cph9` /
`LXD_INCUS_MTLS_CERT_CHAIN_AUTH_BYPASS`) affecting Canonical LXD, Linux
Containers Incus, and Canonical MicroCloud.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/lxdmtlsbypass"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module` configured with a per-probe timeout.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `LXD_INCUS_MTLS_CERT_CHAIN_AUTH_BYPASS`, `CVE-2026-112816`,
    `Severity_CRITICAL`) supported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Filters for candidate TCP/HTTPS/LXD services,
    generates an ephemeral self-signed ECDSA P-256 leaf certificate in memory,
    and executes a non-destructive 2-step differential mTLS probe against
    `GET /1.0`:
    1.  **Probe 1 (Negative Control & Server Certificate Harvest)**: Connects
        with a 1-certificate client chain `[ephemeralLeaf]`, verifies that
        `GET /1.0` returns an LXD/Incus sync response with
        `"auth": "untrusted"`, and harvests the daemon's X.509 server
        certificate (`PeerCertificates[0]`).
    2.  **Probe 2 (Differential Chain Probe)**: Opens a fresh TLS session
        presenting the 2-certificate chain
        `[ephemeralLeaf, harvestedServerCert]` signed only with the ephemeral
        leaf key, and reports `DetectionStatus_VULNERABILITY_VERIFIED` if and
        only if `"auth"` transitions from `"untrusted"` to `"trusted"`.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/lxdmtlsbypass"
)
```
