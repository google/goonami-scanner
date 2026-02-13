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

// Package sslsupport checks if a network service supports SSL.
package sslsupport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"github.com/google/goonami-scanner/core/net/netservice"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

const (
	moduleName = "fp/sslsupport"
)

var (
	errNotTLSConn = errors.New("connection is not an SSL/TLS connection")
)

// Module is the fingerprinter to detect if a network service supports SSL.
type Module struct {
	*module.BaseModule
	config *config.Config
}

// New returns a new instance of the module.
func New(ctx context.Context, config *config.Config) (module.Fingerprinter, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		config:     config,
	}, nil
}

// Fingerprint connects to the network service and checks if it supports SSL.
func (m *Module) Fingerprint(ctx context.Context, service *nspb.NetworkService) ([]*nspb.NetworkService, error) {
	result := []*nspb.NetworkService{service}

	// The fingerprinting was already performed, probably by a port scanner.
	if netservice.HasTLS(service) {
		return result, nil
	}

	ctx, cancel := context.WithTimeout(ctx, m.config.TimeoutPerRequest())
	defer cancel()

	authority, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return nil, err
	}

	// Note: If SSL connection fails, we consider that the service does not support SSL.
	tlsConn, err := m.connect(ctx, "tcp", authority)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}

		return result, nil
	}
	defer tlsConn.Close()

	log.DebugContextf(ctx, log.DebugLevelService, "service supports SSL")
	version := tls.VersionName(tlsConn.ConnectionState().Version)
	tlsversions := append(service.GetSupportedSslVersions(), version)
	service.SetSupportedSslVersions(tlsversions)
	return result, nil
}

func (m *Module) connect(ctx context.Context, protocol string, addr string) (*tls.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout:   m.config.TimeoutPerRequest(),
			KeepAlive: m.config.TimeoutPerRequest() / 2,
		},
		Config: &tls.Config{InsecureSkipVerify: true}, // NOLINT
	}

	conn, err := dialer.DialContext(ctx, protocol, addr)
	if err != nil {
		return nil, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, errNotTLSConn
	}

	return tlsConn, nil
}
