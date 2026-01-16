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

import "log"

// Logger is Goonami's logging interface.
type Logger interface {
	// Logs in different log levels, either formatted or unformatted.
	Errorf(format string, args ...any)
	Error(args ...any)
	Warnf(format string, args ...any)
	Warn(args ...any)
	Infof(format string, args ...any)
	Info(args ...any)
	Debugf(level DebugLevel, format string, args ...any)
	Debug(level DebugLevel, args ...any)
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

var logger Logger = &DefaultLogger{}

// SetLogger overwrites the default logger with a user specified one.
func SetLogger(l Logger) { logger = l }

// Errorf is the static formatted error logging function.
func Errorf(format string, args ...any) {
	logger.Errorf(format, args...)
}

// Warnf is the static formatted warning logging function.
func Warnf(format string, args ...any) {
	logger.Warnf(format, args...)
}

// Infof is the static formatted info logging function.
func Infof(format string, args ...any) {
	logger.Infof(format, args...)
}

// Debugf is the static formatted debug logging function.
func Debugf(level DebugLevel, format string, args ...any) {
	logger.Debugf(level, format, args...)
}

// Error is the static error logging function.
func Error(args ...any) {
	logger.Error(args...)
}

// Warn is the static warning logging function.
func Warn(args ...any) {
	logger.Warn(args...)
}

// Info is the static info logging function.
func Info(args ...any) {
	logger.Info(args...)
}

// Debug is the static debug logging function.
// Note that there is no perfect rule to select the right debug level, but the rule of thumb is:
//   - level 1: logs that will be displayed once per session (e.g. "the scanner is initialized")
//   - level 2: logs that will be displayed once per service (e.g. "port 8080 supports SSL")
//   - level 3: logs that will be displayed multiple times per service (e.g. "crawling page A of service on port 8080")
func Debug(level DebugLevel, args ...any) {
	logger.Debug(level, args...)
}

// DefaultLogger is the Logger implementation used by default.
// It just logs to stderr using the default Go logger.
type DefaultLogger struct {
	VerboseLevel DebugLevel // Whether debug logs should be shown.
}

// Errorf is the formatted error logging function.
func (DefaultLogger) Errorf(format string, args ...any) {
	log.Printf(format, args...)
}

// Warnf is the formatted warning logging function.
func (DefaultLogger) Warnf(format string, args ...any) {
	log.Printf(format, args...)
}

// Infof is the formatted info logging function.
func (DefaultLogger) Infof(format string, args ...any) {
	log.Printf(format, args...)
}

// Debugf is the formatted debug logging function.
func (l *DefaultLogger) Debugf(level DebugLevel, format string, args ...any) {
	if l.VerboseLevel >= level {
		log.Printf(format, args...)
	}
}

// Error is the error logging function.
func (DefaultLogger) Error(args ...any) {
	log.Println(args...)
}

// Warn is the warning logging function.
func (DefaultLogger) Warn(args ...any) {
	log.Println(args...)
}

// Info is the info logging function.
func (DefaultLogger) Info(args ...any) {
	log.Println(args...)
}

// Debug is the debug logging function.
func (l *DefaultLogger) Debug(level DebugLevel, args ...any) {
	if l.VerboseLevel >= level {
		log.Println(args...)
	}
}
