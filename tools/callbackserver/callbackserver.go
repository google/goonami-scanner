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
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/goonami-scanner/core/log"
	tcsdns "github.com/google/goonami-scanner/tools/callbackserver/server/dns"
	tcshttp "github.com/google/goonami-scanner/tools/callbackserver/server/http"
	"github.com/google/goonami-scanner/tools/callbackserver/storage"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
)

var (
	// ErrConfigRead is returned when the config file cannot be read.
	ErrConfigRead = errors.New("failed to read config file")

	// ErrConfigUnmarshal is returned when the config file cannot be unmarshalled.
	ErrConfigUnmarshal = errors.New("failed to unmarshal config file")

	// ErrInvalidConfig is returned when the config file is invalid.
	ErrInvalidConfig = errors.New("invalid config")
)

// DefaultConfig returns the default config for the callback server.
func DefaultConfig() *cbpb.CallbackserverConfig {
	return cbpb.CallbackserverConfig_builder{
		InteractionTtlSeconds:  proto.Uint32(60),
		CleanupIntervalSeconds: proto.Uint32(10),
	}.Build()
}

// ConfigFromFile reads and validates the config from the given file. This is used only by the
// standalone callback server binary.
func ConfigFromFile(ctx context.Context, path string) (*cbpb.CallbackserverConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigRead, err)
	}

	cfg := &cbpb.CallbackserverConfig{}
	if err := prototext.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigUnmarshal, err)
	}

	return cfg, nil
}

// ValidateConfig for the callback server. Note that this is a server perspective, so we need to
// ensure that all ports are set and valid only if the server is going to be started locally.
func ValidateConfig(cfg *cbpb.CallbackserverConfig) error {
	if !cfg.HasHttpPollConfig() {
		return fmt.Errorf("%w: http_poll_config is required", ErrInvalidConfig)
	}

	if cfg.GetInteractionTtlSeconds() == 0 {
		return fmt.Errorf("%w: interaction_ttl_seconds must be greater than 0", ErrInvalidConfig)
	}

	if cfg.GetCleanupIntervalSeconds() == 0 {
		return fmt.Errorf("%w: cleanup_interval_seconds must be greater than 0", ErrInvalidConfig)
	}

	if cfg.GetHttpRecordConfig().GetMode() == cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER {
		port := cfg.GetHttpRecordConfig().GetBindPort()
		if port <= 0 || port > 65535 {
			return fmt.Errorf("%w: http_record_config.port must be between 1 and 65535", ErrInvalidConfig)
		}
	}

	if cfg.GetDnsRecordConfig().GetMode() == cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER {
		port := cfg.GetDnsRecordConfig().GetBindPort()
		if port <= 0 || port > 65535 {
			return fmt.Errorf("%w: dns_record_config.port must be between 1 and 65535", ErrInvalidConfig)
		}
	}

	return nil
}

// Server represents a callback server.
type Server struct {
	cfg   *cbpb.CallbackserverConfig
	store storage.InteractionStore

	httpRecordingSrv *http.Server
	dnsRecordingSrv  *net.UDPConn
	httpPollingSrv   *http.Server
}

// New creates a new callback server.
func New(ctx context.Context, cfg *cbpb.CallbackserverConfig) (*Server, error) {
	clientCfg := DefaultConfig()

	if cfg != nil {
		proto.Merge(clientCfg, cfg)
	}

	if err := ValidateConfig(clientCfg); err != nil {
		return nil, err
	}

	ttl := time.Duration(clientCfg.GetInteractionTtlSeconds()) * time.Second
	cleanupInterval := time.Duration(clientCfg.GetCleanupIntervalSeconds()) * time.Second
	store := storage.NewInMemoryInteractionStore(ctx, ttl, cleanupInterval)

	return &Server{
		store: store,
		cfg:   clientCfg,
	}, nil
}

// Shutdown shuts down the callback server.
func (s *Server) Shutdown(ctx context.Context) error {
	ctx = log.ContextForModule(ctx, "callbackserver")
	if s.httpRecordingSrv != nil {
		log.InfoContextf(ctx, "shutting down HTTP recording server")
		s.httpRecordingSrv.Shutdown(ctx)
	}

	if s.httpPollingSrv != nil {
		log.InfoContextf(ctx, "shutting down HTTP polling server")
		s.httpPollingSrv.Shutdown(ctx)
	}

	if s.dnsRecordingSrv != nil {
		log.InfoContextf(ctx, "shutting down DNS recording server")
		s.dnsRecordingSrv.Close()
	}

	return nil
}

// StartRecordingDNS interactions with the callback server.
func (s *Server) StartRecordingDNS(ctx context.Context) error {
	ctx = log.ContextForModule(ctx, "callbackserver/rec/dns")
	if !s.cfg.HasDnsRecordConfig() {
		log.WarnContextf(ctx, "DNS recording server is disabled, not starting")
		return nil
	}

	if s.cfg.GetDnsRecordConfig().GetMode() != cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER {
		log.WarnContextf(ctx, "DNS recording server set to remote (%s), not starting", s.cfg.GetDnsRecordConfig().GetPublicUri())
		return nil
	}

	bindaddr := s.cfg.GetDnsRecordConfig().GetBindAddress()
	port := s.cfg.GetDnsRecordConfig().GetBindPort()
	bindaddr = fmt.Sprintf("%s:%d", bindaddr, port)
	handler := &tcsdns.RecordingHandler{
		Domain: s.cfg.GetDnsRecordConfig().GetPublicUri(),
		Store:  s.store,
	}

	dnsAddr, err := net.ResolveUDPAddr("udp", bindaddr)
	if err != nil {
		log.ErrorContextf(ctx, "failed to resolve UDP address %q: %v", bindaddr, err)
		return err
	}

	log.InfoContextf(ctx, "binding DNS server to %q", bindaddr)
	dnsConn, err := net.ListenUDP("udp", dnsAddr)
	if err != nil {
		log.ErrorContextf(ctx, "failed to listen on UDP address %q: %v", bindaddr, err)
		return err
	}

	go tcsdns.ServeDNS(ctx, dnsConn, handler)
	s.dnsRecordingSrv = dnsConn
	return nil
}

// StartPolling starts the polling server in a new goroutine.
func (s *Server) StartPolling(ctx context.Context) error {
	ctx = log.ContextForModule(ctx, "callbackserver/poll")
	if !s.cfg.HasHttpPollConfig() {
		log.WarnContextf(ctx, "HTTP polling server is disabled, not starting")
		return nil
	}

	if s.cfg.GetHttpPollConfig().GetMode() != cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER {
		log.WarnContextf(ctx, "HTTP polling server set to remote (%s), not starting", s.cfg.GetHttpPollConfig().GetPublicUri())
		return nil
	}

	listenAddr := s.cfg.GetHttpPollConfig().GetBindAddress()
	listenPort := s.cfg.GetHttpPollConfig().GetBindPort()
	pollHandler := &tcshttp.PollingHandler{Store: s.store}
	bindAddr := fmt.Sprintf("%s:%d", listenAddr, listenPort)
	log.InfoContextf(ctx, "binding polling server to %q", bindAddr)

	srv, err := serveHTTP(ctx, bindAddr, pollHandler)
	if err != nil {
		return err
	}

	s.httpPollingSrv = srv
	return nil
}

// StartRecordingHTTP starts the HTTP interactions recording server in a new goroutine.
func (s *Server) StartRecordingHTTP(ctx context.Context) error {
	ctx = log.ContextForModule(ctx, "callbackserver/rec/http")
	if !s.cfg.HasHttpRecordConfig() {
		log.WarnContextf(ctx, "HTTP recording server is disabled, not starting")
		return nil
	}

	if s.cfg.GetHttpRecordConfig().GetMode() != cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER {
		log.WarnContextf(ctx, "HTTP recording server set to remote (%s), not starting", s.cfg.GetHttpRecordConfig().GetPublicUri())
		return nil
	}

	listenAddr := s.cfg.GetHttpRecordConfig().GetBindAddress()
	listenPort := s.cfg.GetHttpRecordConfig().GetBindPort()
	recordHandler := &tcshttp.RecordingHandler{Store: s.store}
	bindAddr := fmt.Sprintf("%s:%d", listenAddr, listenPort)
	log.InfoContextf(ctx, "binding recording server to %q", bindAddr)

	srv, err := serveHTTP(ctx, bindAddr, recordHandler)
	if err != nil {
		return err
	}

	s.httpRecordingSrv = srv
	return nil
}

func serveHTTP(ctx context.Context, bindaddr string, handler http.Handler) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	server := &http.Server{
		Addr:    bindaddr,
		Handler: mux,
	}

	listener, err := net.Listen("tcp", bindaddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %q: %w", bindaddr, err)
	}

	go func() {
		if err := server.Serve(listener); err != nil {
			if err != http.ErrServerClosed {
				log.ErrorContextf(ctx, "HTTP server error: %v", err)
			}
		}
	}()

	return server, nil
}
