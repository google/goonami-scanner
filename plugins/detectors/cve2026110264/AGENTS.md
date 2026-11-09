# Package `cve2026110264`

Package `cve2026110264` provides a Goonami vulnerability detector
(`dt/cve2026110264`) for **CVE-2026-110264** (**CVE-2026-97229**), an
unauthenticated Remote Code Execution vulnerability in GitLab Community Edition
(CE) and Enterprise Edition (EE) (`< 19.3.6`, `>= 19.4.0 < 19.4.3`, `>= 19.5.0 <
19.5.1`) caused by a 16-bit signed integer overflow in Ruby's Onigmo regular
expression range-repeat compilation reachable via `org-ruby` (`<= 0.9.12`)
Org-mode `#+TODO:` keyword rendering.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/cve2026110264"` in `module.DefaultRegistry` via
    `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module` instance bound to the scan
    configuration.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `CVE-2026-110264`, related `CVE-2026-110264` and
    `CVE-2026-97229`, `Severity_CRITICAL`) supported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Evaluates web services (`netservice.IsWebService`)
    using a three-step non-destructive differential probe:
    1.  **GitLab Fingerprinting & CSRF Token Extraction**: Requests `GET
        /users/sign_in`, verifies GitLab markers (`_gitlab_session=` cookie,
        `content="GitLab"`, `gon.gitlab_url`, or `Sign in · GitLab`), and
        extracts the `<meta name="csrf-token">` value along with session cookies
        stored in the client cookie jar.
    2.  **Public Project Discovery**: Queries `GET
        /api/v4/projects?simple=true&per_page=5` for public projects
        (`path_with_namespace` and `default_branch`), falling back to parsing
        project links from `GET /explore/projects` across `main` and `master`
        branches.
    3.  **32,768-Range-Repeat Org-Mode Preview Probe**: Sends `POST
        /<namespace>/<project>/-/preview/<branch>/README.org?file_path=README.org`
        containing an Org-mode document with `#+TODO:
        .+:|a{,9}...[32,768 times]:TSUNAMI_VERIFIED`. On vulnerable targets
        (unpatched Onigmo + `org-ruby <= 0.9.12`), Onigmo overflows the signed
        16-bit `MemNumType` counter (`> 32,767` range repeats) without raising
        `ONIGERR_TOO_MANY_RANGE_REPEAT`, and the leading `.+:` alternation
        branch strips the prefix without executing `OP_REPEAT`, rendering
        `<h1>TSUNAMI_VERIFIED HeadingEnd</h1>`. Patched Onigmo rejects the regex
        at compile time (`RegexpError: too many range repeat`), and patched
        `org-ruby >= 0.10.0` escapes `@keyword` with `Regexp.escape`.

## Usage

Register `"dt/cve2026110264"` with `module.DefaultRegistry` via a blank import:

```go
import (
  _ "github.com/google/goonami-scanner/core/net/http/simpleclient"
  _ "github.com/google/goonami-scanner/plugins/detectors/cve2026110264"
)
```
