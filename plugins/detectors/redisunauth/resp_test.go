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

package redisunauth

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestEncodeCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "when_two_arguments_passed_encodes_resp2_array",
			args: []string{"INFO", "server"},
			want: "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n",
		},
		{
			name: "when_empty_argument_passed_encodes_zero_length_bulk_string",
			args: []string{"MODULE", "LOADEX", "", "CONFIG"},
			want: "*4\r\n$6\r\nMODULE\r\n$6\r\nLOADEX\r\n$0\r\n\r\n$6\r\nCONFIG\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(encodeCommand(tc.args...))
			if got != tc.want {
				t.Errorf("encodeCommand(%v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

func TestRespReader_Success(t *testing.T) {
	maxValidBulk := strings.Repeat("a", maxBulkBytes)
	maxLine := strings.Repeat("b", maxLineBytes)
	tests := []struct {
		name string
		wire string
		want respValue
	}{
		{
			name: "when_simple_string_read_returns_text",
			wire: "+PONG\r\n",
			want: respValue{kind: respSimpleString, text: "PONG"},
		},
		{
			name: "when_exact_max_line_bytes_read_returns_text",
			wire: "+" + maxLine + "\r\n",
			want: respValue{kind: respSimpleString, text: maxLine},
		},
		{
			name: "when_error_frame_read_returns_error_text",
			wire: "-NOAUTH Authentication required.\r\n",
			want: respValue{kind: respError, text: "NOAUTH Authentication required."},
		},
		{
			name: "when_integer_frame_read_returns_int64",
			wire: ":-42\r\n",
			want: respValue{kind: respInteger, integer: -42},
		},
		{
			name: "when_bulk_string_read_returns_payload",
			wire: "$18\r\nredis_version:7.2\n\r\n",
			want: respValue{kind: respBulkString, text: "redis_version:7.2\n"},
		},
		{
			name: "when_null_bulk_string_read_returns_null_bulk",
			wire: "$-1\r\n",
			want: respValue{kind: respNullBulk},
		},
		{
			name: "when_exact_max_session_bulk_read_returns_payload",
			wire: "$65526\r\n" + maxValidBulk + "\r\n",
			want: respValue{kind: respBulkString, text: maxValidBulk},
		},
		{
			name: "when_config_get_array_read_returns_elements",
			wire: "*2\r\n$24\r\nenable-protected-configs\r\n$2\r\nno\r\n",
			want: respValue{
				kind: respArray,
				elements: []respValue{
					{kind: respBulkString, text: "enable-protected-configs"},
					{kind: respBulkString, text: "no"},
				},
			},
		},
		{
			name: "when_depth_four_nested_array_read_drains_cleanly",
			wire: "*1\r\n*1\r\n*1\r\n*1\r\n+OK\r\n",
			want: respValue{
				kind: respArray,
				elements: []respValue{{
					kind: respArray,
					elements: []respValue{{
						kind: respArray,
						elements: []respValue{{
							kind:     respArray,
							elements: []respValue{{kind: respSimpleString, text: "OK"}},
						}},
					}},
				}},
			},
		},
		{
			name: "when_empty_array_read_returns_zero_elements",
			wire: "*0\r\n",
			want: respValue{kind: respArray, elements: []respValue{}},
		},
		{
			name: "when_null_array_read_returns_null_array",
			wire: "*-1\r\n",
			want: respValue{kind: respNullArray},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newRespReader(strings.NewReader(tc.wire)).readFrame()
			if err != nil {
				t.Fatalf("readFrame() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(respValue{})); diff != "" {
				t.Errorf("readFrame() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRespReader_EmptyStreamReturnsEOF(t *testing.T) {
	if _, err := newRespReader(strings.NewReader("")).readFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("readFrame(\"\") error = %v, want io.EOF", err)
	}
}

func TestRespReader_Errors(t *testing.T) {
	tests := []struct {
		name string
		wire string
	}{
		{
			name: "when_unknown_prefix_byte_returns_protocol_error",
			wire: "HTTP/1.1 200 OK\r\n",
		},
		{
			name: "when_bare_lf_without_cr_returns_protocol_error",
			wire: "+OK\n",
		},
		{
			name: "when_interior_cr_without_lf_returns_protocol_error",
			wire: "+OK\rX\r\n",
		},
		{
			name: "when_line_exceeds_max_line_bytes_returns_protocol_error",
			wire: "+" + strings.Repeat("x", maxLineBytes+1) + "\r\n",
		},
		{
			name: "when_invalid_integer_returns_protocol_error",
			wire: ":notanumber\r\n",
		},
		{
			name: "when_plus_prefixed_integer_returns_protocol_error",
			wire: ":+42\r\n",
		},
		{
			name: "when_non_numeric_bulk_length_returns_protocol_error",
			wire: "$abc\r\n",
		},
		{
			name: "when_plus_prefixed_bulk_length_returns_protocol_error",
			wire: "$+2\r\nOK\r\n",
		},
		{
			name: "when_negative_bulk_length_below_minus_one_returns_protocol_error",
			wire: "$-2\r\n",
		},
		{
			name: "when_oversized_bulk_length_returns_protocol_error",
			wire: "$65527\r\n",
		},
		{
			name: "when_truncated_bulk_payload_returns_protocol_error",
			wire: "$10\r\nabc\r\n",
		},
		{
			name: "when_missing_trailing_crlf_after_bulk_returns_protocol_error",
			wire: "$3\r\nabcXX",
		},
		{
			name: "when_non_numeric_array_count_returns_protocol_error",
			wire: "*abc\r\n",
		},
		{
			name: "when_plus_prefixed_array_count_returns_protocol_error",
			wire: "*+1\r\n+OK\r\n",
		},
		{
			name: "when_oversized_array_count_returns_protocol_error",
			wire: "*1025\r\n",
		},
		{
			name: "when_truncated_array_element_returns_protocol_error",
			wire: "*2\r\n+OK\r\n",
		},
		{
			name: "when_nesting_depth_exceeds_four_returns_protocol_error",
			wire: "*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n+OK\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newRespReader(strings.NewReader(tc.wire)).readFrame(); !errors.Is(err, errRespProtocol) {
				t.Errorf("readFrame(%q) error = %v, want errRespProtocol", tc.wire, err)
			}
		})
	}
}

func TestRespReader_CumulativeSessionBudget(t *testing.T) {
	frame1 := "$40000\r\n" + strings.Repeat("a", 40000) + "\r\n"
	frame2 := "$30000\r\n" + strings.Repeat("b", 30000) + "\r\n"
	rr := newRespReader(strings.NewReader(frame1 + frame2))

	got, err := rr.readFrame()
	if err != nil {
		t.Fatalf("first readFrame() unexpected error: %v", err)
	}
	if len(got.text) != 40000 {
		t.Errorf("len(first readFrame().text) = %d, want 40000", len(got.text))
	}
	if _, err := rr.readFrame(); !errors.Is(err, errRespProtocol) {
		t.Errorf("second readFrame() error = %v, want errRespProtocol", err)
	}
}
