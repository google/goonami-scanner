# Package `adkweakcreds`

Package `adkweakcreds` implements the `"dt/adkweakcreds"` vulnerability detector
plugin, using ADK Gemini agents to discover web authentication endpoints and
test them for weak or default credentials. For each target web service, a
fast-tier discovery agent probes the application (or reuses a cached strategy)
to synthesize candidate credentials, optional CSRF token extraction, and a
templated login request verified against an invalid-credential probe. The
detector then executes candidate login attempts and confirms potential matches
through mutated-password negative validation and a pro-tier LLM judge agent
before reporting `GENERIC_AGENTIC_WEAK_CREDENTIALS` findings.

## Services

-   **`"dt/adkweakcreds"` Registration**: Importing the package registers `New`
    under `"dt/adkweakcreds"` in `module.DefaultRegistry` via `init()`. Workflow
    configurations match `"dt/adkweakcreds"` to enable or filter out this
    detector.
-   **`Module` & `New`**: `Module` embeds `*module.BaseModule` and implements
    `module.VulnDetector` for agentic weak-credential scanning.
    `New(ctx, config)` returns an initialized `*Module` wired with the default
    discovery and judge ADK agent builders and loads the `"dt/adkweakcreds"`
    strategy cache via `config.GetCacheForModule` (disabling caching on lookup
    failure).
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `GENERIC_AGENTIC_WEAK_CREDENTIALS`, `Severity: HIGH`) supported
    by the detector.
-   **`(*Module).Detect`**: Evaluates a `*nspb.NetworkService` by obtaining an
    authentication strategy and testing its candidate credentials, returning
    `(nil, nil)` for non-web services or services without password/secret
    authentication. Confirmed credentials produce a verified `HIGH`-severity
    `*dpb.DetectionReportList` (`GOOGLE` / `GENERIC_AGENTIC_WEAK_CREDENTIALS`)
    with JSON-serialized `valid_credentials`, `login_request`, and
    `csrf_request` in `AdditionalDetails`.
-   **Authentication Strategy Discovery & Caching**: On a cache miss, `Detect`
    runs the `authentication-agent` (`llm.ModelTierFast`, `prompt.md`, and the
    `httpclient` tool) via `llm.Client.RunWithFeedbackLoop` to synthesize a JSON
    strategy supporting `[[username]]`, `[[password]]`, `[[basic_auth]]`, and
    `[[csrftoken]]` placeholders. A feedback verifier tests the strategy with
    deterministically mutated invalid credentials to confirm `extraction_regex`
    matches failure responses (aborting with `llm.ErrAbort` if rate-limited),
    then caches verified strategies per service.
-   **Brute-Force Execution & LLM Judge Adjudication**: Each login attempt runs
    in an isolated cookie-storing HTTP client that fetches any required CSRF
    token, restricts redirects to the target authority, records the
    post-redirect `FinalURI` and raw `SetCookies` across redirects, and treats
    `extraction_regex` matches or HTTP 401/403 statuses as failures. Candidate
    responses that do not fail must pass a mutated-password negative baseline
    check and receive `{"authenticated": true}` from the stateless
    `authentication-judge-agent` (`llm.ModelTierPro`, `judge_prompt.md`), which
    evaluates the response status, `final_uri`, `set_cookies`, and body against
    the negative baseline while preserving already-confirmed credentials if a
    later attempt errors.

## Usage

Register `"dt/adkweakcreds"` with `module.DefaultRegistry` via a blank import:

```go
import (
  _ "github.com/google/goonami-scanner/core/net/http/simpleclient"
  _ "github.com/google/goonami-scanner/plugins/detectors/adkweakcreds"
)
```

Instantiate the detector directly and scan a web `NetworkService`:

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  _ "github.com/google/goonami-scanner/core/net/http/simpleclient"
  "github.com/google/goonami-scanner/plugins/detectors/adkweakcreds"

  dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
  npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func detectWeakCreds(
    ctx context.Context, cfg *config.Config,
) (*dpb.DetectionReportList, error) {
  detector, err := adkweakcreds.New(ctx, cfg)
  if err != nil {
    return nil, err
  }

  svc := nspb.NetworkService_builder{
      ServiceName:          "http",
      SupportedHttpMethods: []string{"GET", "POST"},
      NetworkEndpoint: npb.NetworkEndpoint_builder{
          Type:      npb.NetworkEndpoint_IP_PORT,
          IpAddress: npb.IpAddress_builder{Address: "192.0.2.10"}.Build(),
          Port:      npb.Port_builder{PortNumber: 8080}.Build(),
      }.Build(),
  }.Build()

  return detector.Detect(ctx, svc)
}
```
