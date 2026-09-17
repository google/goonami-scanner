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
