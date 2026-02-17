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

// Package log provides the logging interface.
// By default, it uses the default Go logger, but it can be replaced with user-defined loggers.
package log

import (
	"context"
	"fmt"
	"log"
)

// Logger is Goonami's logging interface.
type Logger interface {
	// Logs in different log levels, either formatted or unformatted.
	ErrorContextf(ctx context.Context, format string, args ...any)
	ErrorContext(ctx context.Context, args ...any)
	WarnContextf(ctx context.Context, format string, args ...any)
	WarnContext(ctx context.Context, args ...any)
	InfoContextf(ctx context.Context, format string, args ...any)
	InfoContext(ctx context.Context, args ...any)
	DebugContextf(ctx context.Context, level DebugLevel, format string, args ...any)
	DebugContext(ctx context.Context, level DebugLevel, args ...any)
}

// DebugLevel represents the level of a debug log (the higher the number, the more verbose).
type DebugLevel int32

const (
	// DebugLevelSession can be used by debug logs that are expected to only happen once per run of the
	// scanner (e.g. "the scanner was initialized").
	DebugLevelSession = 1

	// DebugLevelService is the debug level for logs that are expected to happen once per network service
	// (e.g. "port 8080 supports SSL").
	DebugLevelService = 2

	// DebugLevelRequest is the last level of debugging, it might log every single request.
	DebugLevelRequest = 3
)

type contextKey int

const (
	moduleKey contextKey = iota
	serviceKey
)

// ContextForModule returns a new context with the module name attached.
func ContextForModule(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, moduleKey, name)
}

// ContextForService returns a new context with the service information (port) attached.
func ContextForService(ctx context.Context, port int) context.Context {
	return context.WithValue(ctx, serviceKey, port)
}

// ContextForModuleAndService returns a new context with both the module name and the service
// information (port) attached.
func ContextForModuleAndService(ctx context.Context, name string, port int) context.Context {
	return ContextForModule(ContextForService(ctx, port), name)
}

var logger Logger = &DefaultLogger{}

// SetLogger overwrites the default logger with a user specified one.
func SetLogger(l Logger) { logger = l }

// ErrorContextf is the static formatted error logging function.
func ErrorContextf(ctx context.Context, format string, args ...any) {
	logger.ErrorContextf(ctx, format, args...)
}

// WarnContextf is the static formatted warning logging function.
func WarnContextf(ctx context.Context, format string, args ...any) {
	logger.WarnContextf(ctx, format, args...)
}

// InfoContextf is the static formatted info logging function.
func InfoContextf(ctx context.Context, format string, args ...any) {
	logger.InfoContextf(ctx, format, args...)
}

// DebugContextf is the static formatted debug logging function.
func DebugContextf(ctx context.Context, level DebugLevel, format string, args ...any) {
	logger.DebugContextf(ctx, level, format, args...)
}

// ErrorContext is the static error logging function.
func ErrorContext(ctx context.Context, args ...any) {
	logger.ErrorContext(ctx, args...)
}

// WarnContext is the static warning logging function.
func WarnContext(ctx context.Context, args ...any) {
	logger.WarnContext(ctx, args...)
}

// InfoContext is the static info logging function.
func InfoContext(ctx context.Context, args ...any) {
	logger.InfoContext(ctx, args...)
}

// DebugContext is the static debug logging function.
// Note that there is no perfect rule to select the right debug level, but the rule of thumb is:
//   - level 1: logs that will be displayed once per session (e.g. "the scanner is initialized")
//   - level 2: logs that will be displayed once per service (e.g. "port 8080 supports SSL")
//   - level 3: logs that will be displayed multiple times per service (e.g. "crawling page A of service on port 8080")
func DebugContext(ctx context.Context, level DebugLevel, args ...any) {
	logger.DebugContext(ctx, level, args...)
}

// DefaultLogger is the Logger implementation used by default.
// It just logs to stderr using the default Go logger.
type DefaultLogger struct {
	VerboseLevel DebugLevel // Whether debug logs should be shown.
	UseColors    bool       // Whether colors should be used in the logs.
}

func (l *DefaultLogger) log(ctx context.Context, level string, msg string) {
	prefix := level + " "

	if port, ok := ctx.Value(serviceKey).(int); ok {
		portVal := colorize(fmt.Sprintf("%5d", port), ansiGreen, l.UseColors)
		prefix += "[ " + portVal + " ] "
	}
	if module, ok := ctx.Value(moduleKey).(string); ok {
		moduleVal := colorize(module, ansiCyan, l.UseColors)
		prefix += "[ " + moduleVal + " ] "
	}
	log.Print(prefix + msg)
}

// ErrorContextf is the formatted error logging function.
func (l *DefaultLogger) ErrorContextf(ctx context.Context, format string, args ...any) {
	level := colorize(fmt.Sprintf("%-4s", "ERR"), ansiBoldRed, l.UseColors)
	l.log(ctx, level, fmt.Sprintf(format, args...))
}

// WarnContextf is the formatted warning logging function.
func (l *DefaultLogger) WarnContextf(ctx context.Context, format string, args ...any) {
	level := colorize(fmt.Sprintf("%-4s", "WARN"), ansiBoldYellow, l.UseColors)
	l.log(ctx, level, fmt.Sprintf(format, args...))
}

// InfoContextf is the formatted info logging function.
func (l *DefaultLogger) InfoContextf(ctx context.Context, format string, args ...any) {
	level := colorize(fmt.Sprintf("%-4s", "INFO"), ansiBoldBlue, l.UseColors)
	l.log(ctx, level, fmt.Sprintf(format, args...))
}

// DebugContextf is the formatted debug logging function.
func (l *DefaultLogger) DebugContextf(ctx context.Context, level DebugLevel, format string, args ...any) {
	if l.VerboseLevel >= level {
		level := fmt.Sprintf("DBG%d", level)
		levelStr := colorize(fmt.Sprintf("%-4s", level), ansiBoldGray, l.UseColors)
		l.log(ctx, levelStr, fmt.Sprintf(format, args...))
	}
}

// ErrorContext is the error logging function.
func (l *DefaultLogger) ErrorContext(ctx context.Context, args ...any) {
	level := colorize(fmt.Sprintf("%-4s", "ERR"), ansiBoldRed, l.UseColors)
	l.log(ctx, level, fmt.Sprint(args...))
}

// WarnContext is the warning logging function.
func (l *DefaultLogger) WarnContext(ctx context.Context, args ...any) {
	level := colorize(fmt.Sprintf("%-4s", "WARN"), ansiBoldYellow, l.UseColors)
	l.log(ctx, level, fmt.Sprint(args...))
}

// InfoContext is the info logging function.
func (l *DefaultLogger) InfoContext(ctx context.Context, args ...any) {
	level := colorize(fmt.Sprintf("%-4s", "INFO"), ansiBoldBlue, l.UseColors)
	l.log(ctx, level, fmt.Sprint(args...))
}

// DebugContext is the debug logging function.
func (l *DefaultLogger) DebugContext(ctx context.Context, level DebugLevel, args ...any) {
	if l.VerboseLevel >= level {
		levelStr := colorize(fmt.Sprintf("%-4s", fmt.Sprintf("DBG%d", level)), ansiBoldGray, l.UseColors)
		l.log(ctx, levelStr, fmt.Sprint(args...))
	}
}
