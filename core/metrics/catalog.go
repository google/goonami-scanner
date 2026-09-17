/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package metrics

import (
	"context"
	"errors"
	"io"
	"net"
)

// The label keys Goonami uses. Every key is declared here and a metric only
// accepts the keys it lists in its declaration.
const (
	// LabelModule identifies the module that produced the observation.
	LabelModule LabelKey = "module"

	// LabelErrorClass identifies a bounded classification of an error.
	LabelErrorClass LabelKey = "error_class"

	// LabelLimitName identifies the configured limit that stopped work early.
	LabelLimitName LabelKey = "limit_name"

	// LabelModel identifies the model that served a response, as reported by the
	// backend.
	LabelModel LabelKey = "model"
)

// LimitNameValue is the name of a configured limit that can stop work early.
type LimitNameValue string

const (
	// LimitMaxAttemptsPerService is the weak credential attempt budget.
	LimitMaxAttemptsPerService LimitNameValue = "max_attempts_per_service"

	// LimitMaxRequestsPerService is the per-service HTTP request budget.
	LimitMaxRequestsPerService LimitNameValue = "max_requests_per_service"

	// LimitMaxHTTPRedirects is the redirect following budget.
	LimitMaxHTTPRedirects LimitNameValue = "max_http_redirects"

	// LimitMaxAttempts is the LLM agent retry budget.
	LimitMaxAttempts LimitNameValue = "max_attempts"
)

// Bounded classifications of an error, used by ErrorClass.
const (
	errorClassNone             = "none"
	errorClassDeadlineExceeded = "deadline_exceeded"
	errorClassCanceled         = "canceled"
	errorClassTimeout          = "timeout"
	errorClassNetwork          = "network"
	errorClassEOF              = "eof"
	errorClassOther            = "other"
)

// The metrics Goonami records. This is the complete catalog: recording is only
// possible through one of these handles, so the set of series Goonami can emit
// is reviewable in one place.
var (
	// ScanDuration is the wall time of a whole scan, end to end. It is the parent
	// of the per phase durations below, which partition it.
	ScanDuration = NewDistribution("scan/duration",
		"Wall time of a scan, end to end.", UnitSeconds)

	// PortScanDuration is the wall time of the port scanning phase.
	PortScanDuration = NewDistribution("scan/duration/portscan",
		"Wall time of the port scanning phase.", UnitSeconds)

	// FingerprintDuration is the wall time of the fingerprinting phase.
	FingerprintDuration = NewDistribution("scan/duration/fingerprint",
		"Wall time of the fingerprinting phase.", UnitSeconds)

	// DetectDuration is the wall time of the vulnerability detection phase.
	DetectDuration = NewDistribution("scan/duration/detect",
		"Wall time of the vulnerability detection phase.", UnitSeconds)

	// ServicesDiscovered counts the network services found by the port scanner.
	ServicesDiscovered = NewCounter("services/discovered",
		"Network services discovered by the port scanner.")

	// ModuleErrors counts module invocations that returned an error.
	//
	// Successes are not counted on their own: they are the invocation count in
	// ModuleDuration minus these errors.
	ModuleErrors = NewCounter("module/errors",
		"Module invocations that returned an error.", LabelModule, LabelErrorClass)

	// ModuleDuration is the latency of a single module invocation.
	// It is observed on every invocation, including the ones that fail.
	ModuleDuration = NewDistribution("module/duration",
		"Latency of a module invocation.", UnitSeconds, LabelModule)

	// Findings counts the vulnerabilities reported by detectors.
	Findings = NewCounter("findings",
		"Vulnerabilities reported by detectors.", LabelModule)

	// BudgetExhausted counts the times a configured limit stopped work early.
	BudgetExhausted = NewCounter("budget/exhausted",
		"Times a configured limit stopped work early.", LabelModule, LabelLimitName)

	// HTTPRequests counts outbound HTTP requests. It is the parent of the error
	// counter below.
	HTTPRequests = NewCounter("http/requests",
		"Outbound HTTP requests.")

	// HTTPRequestErrors counts outbound HTTP requests that never produced a
	// response. This is the subset of HTTPRequests that failed in transport.
	HTTPRequestErrors = NewCounter("http/requests/error",
		"Outbound HTTP requests that failed before a response.", LabelErrorClass)

	// LLMTokens counts the tokens consumed by the LLM client, attributed to the
	// model that served the response. This is the billable total and the parent
	// of the breakdown below.
	//
	// The backend reports the total as the sum of the prompt, the generated
	// candidates, the tool results fed back in and the thinking tokens, so the
	// four children partition it. The total is recorded rather than derived
	// because it is the one field every backend populates: the parts are
	// conditional on the model (thinking) and on the request (tool use).
	LLMTokens = NewCounter("llm/tokens",
		"Tokens consumed by the LLM client.", LabelModel)

	// LLMInputTokens counts the prompt tokens sent to the model.
	//
	// This is the full effective prompt of each request, so across a multi turn
	// run it includes the history resent every turn. That is the billed
	// quantity, not the size of the conversation.
	LLMInputTokens = NewCounter("llm/tokens/input",
		"Prompt tokens sent to the model.", LabelModel)

	// LLMCachedTokens counts the prompt tokens that were served from cached
	// content. Caching applies to the prompt only, which is why this is a child
	// of llm/tokens/input rather than a sibling of it.
	LLMCachedTokens = NewCounter("llm/tokens/input/cached",
		"Prompt tokens served from cached content, a subset of llm/tokens/input.", LabelModel)

	// LLMOutputTokens counts the tokens generated by the model. Thinking tokens
	// are reported separately by the backend and are not included here.
	LLMOutputTokens = NewCounter("llm/tokens/output",
		"Tokens generated by the model.", LabelModel)

	// LLMThoughtTokens counts the tokens spent on the model's internal
	// reasoning. Zero for models that do not think.
	LLMThoughtTokens = NewCounter("llm/tokens/thoughts",
		"Tokens spent on the model's internal reasoning.", LabelModel)

	// LLMToolInputTokens counts the tokens of tool results fed back to the model
	// as input. The backend reports these separately from the prompt.
	LLMToolInputTokens = NewCounter("llm/tokens/tool_input",
		"Tokens of tool results fed back to the model as input.", LabelModel)

	// LLMDuration is the wall time of a single LLM agent run.
	// It carries no model label: a run is a feedback loop that may involve
	// several models, so attributing its latency to one of them would be wrong.
	// Per-model cost is answered by LLMTokens.
	LLMDuration = NewDistribution("llm/duration",
		"Wall time of an LLM agent run.", UnitSeconds, LabelErrorClass)
)

// Module returns the label identifying the module that produced an observation.
func Module(name string) Label {
	return Label{Key: LabelModule, Value: name}
}

// LimitName returns the label identifying a configured limit.
func LimitName(limit LimitNameValue) Label {
	return Label{Key: LabelLimitName, Value: string(limit)}
}

// LLMModel returns the label identifying the model that served a response.
func LLMModel(name string) Label {
	return Label{Key: LabelModel, Value: name}
}

// ErrorClass returns the label identifying a bounded classification of err.
func ErrorClass(err error) Label {
	return Label{Key: LabelErrorClass, Value: classifyError(err)}
}

func classifyError(err error) string {
	if err == nil {
		return errorClassNone
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errorClassDeadlineExceeded
	case errors.Is(err, context.Canceled):
		return errorClassCanceled
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return errorClassEOF
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return errorClassTimeout
		}
		return errorClassNetwork
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errorClassNetwork
	}

	return errorClassOther
}
