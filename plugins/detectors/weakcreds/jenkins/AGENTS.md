# Package `jenkins`

Package `jenkins` provides a Goonami weak password detector (`dt/wk/jenkins`)
that detects Jenkins instances configured with weak administrator passwords,
testing at most 10 common weak passwords (`MaxPasswordAttempts = 10`) and
stopping on the first verified credential.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/wk/jenkins"` via `module.RegisterDetector`.
-   **`New` and `NewWithOptions`**: Construct a `*Module` backed by a
    redirect-disabled `goohttp.Client` and a weak password list capped at
    `MaxPasswordAttempts` (defaulting to `admin`, `password`, `jenkins`,
    `123456`, `admin123`, `12345678`, `password1`, `qwerty`, `letmein`,
    `welcome`).
-   **`(*Module).Advisories`**: Returns the `GOOGLE` /
    `WEAK_CREDENTIALS_FOR_JENKINS` (`Severity_CRITICAL`) advisory metadata.
-   **`(*Module).Detect`**: Performs a 3-step active check on candidate TCP web
    services:
    1.  Sends `GET /login` to confirm both Jenkins identity (`X-Jenkins` /
        `X-Hudson` header or `[Jenkins]` title) and a local password login form
        (`j_spring_security_check`, `j_acegi_security_check`, or
        `name="j_password"`), short-circuiting non-Jenkins and OAuth/SSO-only
        instances in a single request.
    2.  Sends an unauthenticated `GET /whoAmI/api/json` negative control to
        verify the endpoint rejects unauthenticated access (`401`/`403`) or
        resolves strictly to `"anonymous": true`, preventing false positives on
        unauthenticated Jenkins instances.
    3.  Tests up to 10 candidate passwords for `"admin"` via HTTP Basic
        authentication against `/whoAmI/api/json`, verifying `HTTP 200` JSON
        with `authenticated == true`, `anonymous == false`, and `name ==
        "admin"`, stopping immediately upon the first valid match or unexpected
        non-`401`/`403` status.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/weakcreds/jenkins"
)
```
