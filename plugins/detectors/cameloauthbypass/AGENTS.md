# Package `cameloauthbypass`

Package `cameloauthbypass` provides a Goonami vulnerability detector
(`dt/cameloauthbypass`) that identifies Apache Camel applications using
`camel-oauth` (versions `4.11.0` to `4.18.4` and `4.19.0` to `4.22.0`) that are
vulnerable to fail-open authentication bypass (`CVE-2026-80312` /
`CAMEL-24411`).

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/cameloauthbypass"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module` backed by a non-redirect-following
    Goonami HTTP client (`DisableFollowRedirects: true`).
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `APACHE_CAMEL_OAUTH_AUTH_BYPASS`, `CVE-2026-80312`,
    `Severity_CRITICAL`) supported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Skips non-TCP and non-HTTP/unknown services,
    gathers crawled and default OAuth route paths, and probes for fail-open
    downstream route execution across `OAuthCodeFlowProcessor` (HTTP 302 with
    `camel.oauth.session` cookie, OIDC authorization `Location` redirect, and
    non-empty downstream route body), `OAuthCodeFlowCallback` (HTTP 400 with
    downstream route body when `code` is omitted and `camel.oauth.session`
    cookie when `code` is provided), and `OAuthBearerTokenProcessor` (HTTP 400
    with identical downstream route body on missing, `Basic`, and two-space
    `Bearer  <token>` `Authorization` headers vs. HTTP 500 empty body on a
    single-space invalid `Bearer <token>` header).

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/cameloauthbypass"
)
```
