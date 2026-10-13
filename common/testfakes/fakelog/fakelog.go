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

// Package fakelog provides a fake implementation of the Goonami Logger interface.
package fakelog

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/goonami-scanner/core/log"
)

// Logger is a fake implementation of log.Logger that records logged messages in memory.
type Logger struct {
	mu     sync.Mutex
	errors []string
	warns  []string
	infos  []string
	vulns  []string
	debugs []string
}

// New creates a new fake logger.
func New() *Logger {
	return &Logger{}
}

// ErrorContextf records a formatted error message.
func (l *Logger) ErrorContextf(ctx context.Context, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, fmt.Sprintf(format, args...))
}

// ErrorContext records an unformatted error message.
func (l *Logger) ErrorContext(ctx context.Context, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, fmt.Sprint(args...))
}

// WarnContextf records a formatted warning message.
func (l *Logger) WarnContextf(ctx context.Context, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, fmt.Sprintf(format, args...))
}

// WarnContext records an unformatted warning message.
func (l *Logger) WarnContext(ctx context.Context, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, fmt.Sprint(args...))
}

// InfoContextf records a formatted info message.
func (l *Logger) InfoContextf(ctx context.Context, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, fmt.Sprintf(format, args...))
}

// InfoContext records an unformatted info message.
func (l *Logger) InfoContext(ctx context.Context, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, fmt.Sprint(args...))
}

// VulnContextf records a formatted vulnerability message.
func (l *Logger) VulnContextf(ctx context.Context, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.vulns = append(l.vulns, fmt.Sprintf(format, args...))
}

// VulnContext records an unformatted vulnerability message.
func (l *Logger) VulnContext(ctx context.Context, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.vulns = append(l.vulns, fmt.Sprint(args...))
}

// DebugContextf records a formatted debug message.
func (l *Logger) DebugContextf(ctx context.Context, level log.DebugLevel, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugs = append(l.debugs, fmt.Sprintf(format, args...))
}

// DebugContext records an unformatted debug message.
func (l *Logger) DebugContext(ctx context.Context, level log.DebugLevel, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugs = append(l.debugs, fmt.Sprint(args...))
}

// Errors returns a copy of all recorded error messages.
func (l *Logger) Errors() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.errors...)
}

// Warns returns a copy of all recorded warning messages.
func (l *Logger) Warns() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.warns...)
}

// Infos returns a copy of all recorded info messages.
func (l *Logger) Infos() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.infos...)
}

// Vulns returns a copy of all recorded vulnerability messages.
func (l *Logger) Vulns() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.vulns...)
}

// Debugs returns a copy of all recorded debug messages.
func (l *Logger) Debugs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.debugs...)
}
