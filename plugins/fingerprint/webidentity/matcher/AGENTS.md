# Package `matcher`

Package `matcher` compiles and evaluates declarative HTTP response matchers,
steps, and multi-step workflows for the `fp/webidentity` fingerprinter. It
supports status code checks, header/body/hash conditions (`expect_all`,
`expect_any`, `expect_none`), variable and version extraction, root-path
inference, and template variable substitution.

## Services

-   **`CompiledResponseMatcher`, `CompileResponseMatcher(r)`, and
    `(*CompiledResponseMatcher).Match(resp, body)`**: Pre-compiles status
    codes, regexps, and hash expectations from an `HttpResponse` proto and
    evaluates them against a live or cached HTTP response, returning a
    `*MatchResult` with extracted variables and versions.
-   **`CompiledStep`, `CompileStep(s)`, and `(*CompiledStep).Match(resp,
    body)`**: Wraps a named `Step` proto with its compiled `path_regexp` and
    `*CompiledResponseMatcher`.
-   **`CompiledWorkflow` and `CompileWorkflow(w, stepMap)`**: Resolves an
    ordered sequence of step names from a `Workflow` proto against compiled
    steps.
-   **`InferRootFromSuffix(crawledPath, suffix)` and
    `InferRootFromRegexp(crawledPath, re)`**: Derive candidate application root
    subpaths from crawled URL paths using suffix stripping or RE2 capture
    groups.
-   **`SubstituteVariables(template, vars)`**: Replaces `{{ var_name }}`
    placeholders in request path templates using variables extracted by earlier
    steps.
-   **Sentinel errors (`ErrNilResponse`, `ErrNilStep`, `ErrMissingStepName`,
    `ErrNilWorkflow`, `ErrEmptyWorkflow`, `ErrUnknownStep`)**: Returned on nil
    responses or invalid step/workflow definitions.

## Usage

```go
import (
  "net/http"

  fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
  "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/matcher"
)

func matchStep(
    step *fpb.Step,
    resp *http.Response,
    body []byte,
) (*matcher.MatchResult, error) {
  cs, err := matcher.CompileStep(step)
  if err != nil {
    return nil, err
  }
  return cs.Match(resp, body)
}
```
