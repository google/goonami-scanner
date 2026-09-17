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
	"fmt"
	"io"
	"net"
	"testing"
)

func TestClassifyError(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "when_there_is_no_error_it_is_none",
			err:  nil,
			want: errorClassNone,
		},
		{
			name: "when_the_deadline_was_exceeded_it_is_deadline_exceeded",
			err:  context.DeadlineExceeded,
			want: errorClassDeadlineExceeded,
		},
		{
			name: "when_the_deadline_error_is_wrapped_it_is_still_deadline_exceeded",
			err:  fmt.Errorf("running detector: %w", context.DeadlineExceeded),
			want: errorClassDeadlineExceeded,
		},
		{
			name: "when_the_context_was_canceled_it_is_canceled",
			err:  context.Canceled,
			want: errorClassCanceled,
		},
		{
			name: "when_the_stream_ended_early_it_is_eof",
			err:  io.ErrUnexpectedEOF,
			want: errorClassEOF,
		},
		{
			name: "when_the_network_timed_out_it_is_timeout",
			err:  &net.DNSError{IsTimeout: true},
			want: errorClassTimeout,
		},
		{
			name: "when_the_network_failed_it_is_network",
			err:  &net.DNSError{Err: "no such host"},
			want: errorClassNetwork,
		},
		{
			name: "when_the_error_is_unrecognized_it_is_other",
			err:  errors.New("something specific to the target that must not become a label"),
			want: errorClassOther,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyError(tc.err); got != tc.want {
				t.Errorf("classifyError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestErrorClassLabel(t *testing.T) {
	got := ErrorClass(context.Canceled)
	want := Label{Key: LabelErrorClass, Value: errorClassCanceled}

	if got != want {
		t.Errorf("ErrorClass() = %v, want %v", got, want)
	}
}

func TestSimpleLabelConstructors(t *testing.T) {
	testCases := []struct {
		name  string
		label Label
		want  Label
	}{
		{
			name:  "module",
			label: Module("webidentity"),
			want:  Label{Key: LabelModule, Value: "webidentity"},
		},
		{
			name:  "limit_name",
			label: LimitName(LimitMaxAttemptsPerService),
			want:  Label{Key: LabelLimitName, Value: "max_attempts_per_service"},
		},
		{
			name:  "model",
			label: LLMModel("gemini-3.6-flash"),
			want:  Label{Key: LabelModel, Value: "gemini-3.6-flash"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.label != tc.want {
				t.Errorf("label = %v, want %v", tc.label, tc.want)
			}
		})
	}
}
