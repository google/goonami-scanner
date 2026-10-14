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

// Package fakessh provides a fake SSH server for unit and integration testing.
package fakessh

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

const (
	// testHostKey is a static Ed25519 private key in OpenSSH format used for test host signing.
	// Generated with:
	//   ssh-keygen -t ed25519 -N "" -C "test host key for fakessh" -f /tmp/test_key
	testHostKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBgcvsu3k5ZwGP21DnJnseSa0lv/+TxTFG/4G1Qt1urQwAAAKCfX/bBn1/2
wQAAAAtzc2gtZWQyNTUxOQAAACBgcvsu3k5ZwGP21DnJnseSa0lv/+TxTFG/4G1Qt1urQw
AAAEDvWpgQ3/AZ3eKfLQOG9lhF0sbr7sFqQhCNuraAGH6BkmBy+y7eTlnAY/bUOcmex5Jr
SW//5PFMUb/gbVC3W6tDAAAAGXRlc3QgaG9zdCBrZXkgZm9yIGZha2Vzc2gBAgME
-----END OPENSSH PRIVATE KEY-----`
)

// Server is a test SSH server.
type Server struct {
	listener net.Listener
	addr     string
	port     int
	config   *ssh.ServerConfig
}

// GenerateSigner returns a test SSH host key signer parsed from a static test key.
func GenerateSigner() (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey([]byte(testHostKey))
	if err != nil {
		return nil, fmt.Errorf("ssh.ParsePrivateKey failed: %w", err)
	}
	return signer, nil
}

// New creates and starts a test SSH server using the provided ssh.ServerConfig.
// An Ed25519 host key signer is added automatically if none was configured.
func New(cfg *ssh.ServerConfig) (*Server, error) {
	if cfg == nil {
		cfg = &ssh.ServerConfig{}
	}

	signer, err := GenerateSigner()
	if err != nil {
		return nil, err
	}
	cfg.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("net.Listen failed: %w", err)
	}

	addr := listener.Addr().String()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("net.SplitHostPort failed: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("strconv.Atoi failed: %w", err)
	}

	server := &Server{
		listener: listener,
		addr:     addr,
		port:     port,
		config:   cfg,
	}

	go server.serve()

	return server, nil
}

func (s *Server) serve() {
	for {
		tcpConn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(tcpConn)
	}
}

func (s *Server) handleConnection(c net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.config)
	if err != nil {
		_ = c.Close()
		return
	}
	defer func() {
		_ = sshConn.Close()
	}()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		ch, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(requests)
		_ = ch.Close()
	}
}

// NewWithPasswordAuth starts a fake SSH server that accepts the given username and password.
func NewWithPasswordAuth(user, password string) (*Server, error) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
	}
	return New(cfg)
}

// NewPublicKeyOnly starts a fake SSH server that only supports public key authentication.
func NewPublicKeyOnly() (*Server, error) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("publickey only")
		},
	}
	return New(cfg)
}

// Close terminates the test SSH server listener.
func (s *Server) Close() error {
	if s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Addr returns the TCP address (host:port) the fake SSH server is listening on.
func (s *Server) Addr() string {
	return s.addr
}

// Port returns the TCP port the fake SSH server is listening on.
func (s *Server) Port() int {
	return s.port
}

// NetworkService creates a NetworkService proto pointing to this fake SSH server.
func (s *Server) NetworkService() *nspb.NetworkService {
	return nspb.NetworkService_builder{
		ServiceName: "ssh",
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       "127.0.0.1",
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(s.port),
			}.Build(),
		}.Build(),
	}.Build()
}
