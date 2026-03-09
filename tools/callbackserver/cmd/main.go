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

// Package main is the entry point for the callback server when running as a standalone binary.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/tools/callbackserver"
)

func main() {
	config := flag.String("config", "", "Path to the config file")
	colors := flag.Bool("colors", true, "Whether to use colors in logs")
	debug := flag.Int("debug", 0, "Verbosity level")

	flag.Parse()

	level := log.DebugLevel(*debug)
	l := &log.DefaultLogger{UseColors: *colors, VerboseLevel: level}
	log.SetLogger(l)

	// We associate our context to a signal channel that will cancel it if a signal is received.
	ctx := log.ContextForModule(context.Background(), "main")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	cfg, err := callbackserver.ConfigFromFile(ctx, *config)
	if err != nil {
		log.ErrorContextf(ctx, "failed to read config: %v", err)
		os.Exit(1)
	}

	go func() {
		<-sigChan
		log.InfoContext(ctx, "shutting down callback server standalone")
		cancel()
	}()

	server, err := callbackserver.New(ctx, cfg)
	if err != nil {
		log.ErrorContextf(ctx, "failed to create server: %v", err)
		os.Exit(1)
	}
	if err := server.StartRecordingHTTP(ctx); err != nil {
		log.ErrorContextf(ctx, "failed to start HTTP recording server: %v", err)
		os.Exit(1)
	}

	if err := server.StartPolling(ctx); err != nil {
		log.ErrorContextf(ctx, "failed to start HTTP polling server: %v", err)
		os.Exit(1)
	}

	<-ctx.Done()
	server.Shutdown(ctx)
}
