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

// Package callbackserver provides a callback server for goonami-scanner.
package callbackserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/goonami-scanner/core/log"
	tcs_http "github.com/google/goonami-scanner/tools/callbackserver/server/http"
	"github.com/google/goonami-scanner/tools/callbackserver/storage"
	"google.golang.org/protobuf/encoding/prototext"

	ctpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_tool_config_go_proto"
)

var (
	// ErrConfigRead is returned when the config file cannot be read.
	ErrConfigRead = errors.New("failed to read config file")

	// ErrConfigUnmarshal is returned when the config file cannot be unmarshalled.
	ErrConfigUnmarshal = errors.New("failed to unmarshal config file")

	// ErrInvalidConfig is returned when the config file is invalid.
	ErrInvalidConfig = errors.New("invalid config")
)

// ConfigFromFile reads and validates the config from the given file.
func ConfigFromFile(ctx context.Context, path string) (*ctpb.CallbackserverToolConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigRead, err)
	}

	cfg := &ctpb.CallbackserverToolConfig{}
	if err := prototext.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigUnmarshal, err)
	}

	if !cfg.HasPollConfig() || !cfg.HasRecordConfig() {
		return nil, fmt.Errorf("%w: poll_config and record_config are required", ErrInvalidConfig)
	}

	if cfg.GetPollConfig().GetPort() > 65535 {
		return nil, fmt.Errorf("%w: poll_config.port is out of range", ErrInvalidConfig)
	}

	if cfg.GetRecordConfig().GetPort() > 65535 {
		return nil, fmt.Errorf("%w: record_config.port is out of range", ErrInvalidConfig)
	}

	return cfg, nil
}

// Server represents a callback server.
type Server struct {
	cfg   *ctpb.CallbackserverToolConfig
	store storage.InteractionStore

	recordingServer *http.Server
	pollingServer   *http.Server
}

// New creates a new callback server.
func New(ctx context.Context, cfg *ctpb.CallbackserverToolConfig) *Server {
	ttl := time.Duration(cfg.GetInteractionTtlSeconds()) * time.Second
	cleanupInterval := time.Duration(cfg.GetCleanupIntervalSeconds()) * time.Second
	store := storage.NewInMemoryInteractionStore(ctx, ttl, cleanupInterval)

	return &Server{
		store: store,
		cfg:   cfg,
	}
}

// Shutdown shuts down the callback server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.recordingServer != nil {
		s.recordingServer.Shutdown(ctx)
	}

	if s.pollingServer != nil {
		s.pollingServer.Shutdown(ctx)
	}

	return nil
}

// StartPolling starts the polling server in a new goroutine.
func (s *Server) StartPolling(ctx context.Context) {
	ctx = log.ContextForModule(ctx, "callbackserver")
	listenAddr := s.cfg.GetPollConfig().GetAddress()
	listenPort := s.cfg.GetPollConfig().GetPort()
	pollHandler := &tcs_http.PollingHandler{Store: s.store}
	bindAddr := fmt.Sprintf("%s:%d", listenAddr, listenPort)
	log.InfoContextf(ctx, "starting polling server %q", bindAddr)
	s.pollingServer = serveHTTP(ctx, "polling", bindAddr, pollHandler)
}

// StartRecordingHTTP starts the HTTP interactions recording server in a new goroutine.
func (s *Server) StartRecordingHTTP(ctx context.Context) {
	ctx = log.ContextForModule(ctx, "callbackserver")
	listenAddr := s.cfg.GetRecordConfig().GetAddress()
	listenPort := s.cfg.GetRecordConfig().GetPort()
	recordHandler := &tcs_http.RecordingHandler{Store: s.store}
	bindAddr := fmt.Sprintf("%s:%d", listenAddr, listenPort)
	log.InfoContextf(ctx, "starting recording server %q", bindAddr)
	s.recordingServer = serveHTTP(ctx, "recording", bindAddr, recordHandler)
}

func serveHTTP(ctx context.Context, usage string, bindaddr string, handler http.Handler) *http.Server {
	ctx = log.ContextForModule(ctx, fmt.Sprintf("callbackserver/%s", usage))
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	server := &http.Server{
		Addr:    bindaddr,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.ErrorContextf(ctx, "HTTP server error: %v", err)
		}
	}()

	return server
}
