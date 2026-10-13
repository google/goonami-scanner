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

package fakelog

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/log"
)

func TestLogger(t *testing.T) {
	tests := []struct {
		name   string
		action func(ctx context.Context, l *Logger)
		get    func(l *Logger) []string
		want   []string
	}{
		{
			name: "when_error_logged_records_error_messages",
			action: func(ctx context.Context, l *Logger) {
				l.ErrorContext(ctx, "err1")
				l.ErrorContextf(ctx, "err%d", 2)
			},
			get:  (*Logger).Errors,
			want: []string{"err1", "err2"},
		},
		{
			name: "when_warn_logged_records_warn_messages",
			action: func(ctx context.Context, l *Logger) {
				l.WarnContext(ctx, "warn1")
				l.WarnContextf(ctx, "warn%d", 2)
			},
			get:  (*Logger).Warns,
			want: []string{"warn1", "warn2"},
		},
		{
			name: "when_info_logged_records_info_messages",
			action: func(ctx context.Context, l *Logger) {
				l.InfoContext(ctx, "info1")
				l.InfoContextf(ctx, "info%d", 2)
			},
			get:  (*Logger).Infos,
			want: []string{"info1", "info2"},
		},
		{
			name: "when_vuln_logged_records_vuln_messages",
			action: func(ctx context.Context, l *Logger) {
				l.VulnContext(ctx, "vuln1")
				l.VulnContextf(ctx, "vuln%d", 2)
			},
			get:  (*Logger).Vulns,
			want: []string{"vuln1", "vuln2"},
		},
		{
			name: "when_debug_logged_records_debug_messages",
			action: func(ctx context.Context, l *Logger) {
				l.DebugContext(ctx, log.DebugLevelSession, "dbg1")
				l.DebugContextf(ctx, log.DebugLevelRequest, "dbg%d", 2)
			},
			get:  (*Logger).Debugs,
			want: []string{"dbg1", "dbg2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := New()
			tc.action(t.Context(), l)
			if diff := cmp.Diff(tc.want, tc.get(l)); diff != "" {
				t.Errorf("recorded messages diff (-want +got):\n%s", diff)
			}
		})
	}
}
