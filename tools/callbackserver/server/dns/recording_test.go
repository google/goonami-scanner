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

package dns

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/tools/callbackserver/storage"
	"golang.org/x/net/dns/dnsmessage"
)

func TestHandleDNS(t *testing.T) {
	validCBID, err := cbid.Generate("test")
	if err != nil {
		t.Fatalf("failed to generate CBID: %v", err)
	}
	domain := "cb.example.com"
	validQuery := fmt.Sprintf("%s.%s", validCBID, domain)

	tests := []struct {
		name                 string
		queryName            string
		expectedRCode        dnsmessage.RCode
		expectedInteractions int
	}{
		{
			name:                 "when_valid_query_records_interaction",
			queryName:            validQuery,
			expectedRCode:        dnsmessage.RCodeNameError,
			expectedInteractions: 1,
		},
		{
			name:                 "when_wrong_domain_refuses",
			queryName:            fmt.Sprintf("%s.wrong.com", validCBID),
			expectedRCode:        dnsmessage.RCodeRefused,
			expectedInteractions: 0,
		},
		{
			name:                 "when_invalid_cbid_refuses",
			queryName:            fmt.Sprintf("invalid-cbid.%s", domain),
			expectedRCode:        dnsmessage.RCodeRefused,
			expectedInteractions: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 1*time.Minute)
			handler := &RecordingHandler{
				Store:  store,
				Domain: domain,
			}

			// Setup a real UDP connection to test HandleDNS's ability to write responses.
			udpaddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
			conn, err := net.ListenUDP("udp", udpaddr)
			if err != nil {
				t.Fatalf("failed to listen on UDP: %v", err)
			}
			defer conn.Close()

			clientConn, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatalf("failed to dial UDP: %v", err)
			}
			defer clientConn.Close()

			// Prepare DNS query
			queryName, err := dnsmessage.NewName(tt.queryName + ".")
			if err != nil {
				t.Fatalf("failed to create DNS name: %v", err)
			}
			query := dnsmessage.Message{
				Header: dnsmessage.Header{ID: 1234},
				Questions: []dnsmessage.Question{
					{
						Name:  queryName,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			}
			packed, err := query.Pack()
			if err != nil {
				t.Fatalf("failed to pack DNS query: %v", err)
			}

			clientAddr := clientConn.LocalAddr().(*net.UDPAddr)
			handler.HandleDNS(t.Context(), conn, clientAddr, packed)

			// Read response from client connection
			respBuf := make([]byte, 512)
			clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := clientConn.Read(respBuf)
			if err != nil {
				t.Fatalf("failed to read DNS response: %v", err)
			}

			var resp dnsmessage.Message
			if err := resp.Unpack(respBuf[:n]); err != nil {
				t.Fatalf("failed to unpack DNS response: %v", err)
			}

			if resp.Header.RCode != tt.expectedRCode {
				t.Errorf("HandleDNS() RCode = %v, want %v", resp.Header.RCode, tt.expectedRCode)
			}

			interactions := store.Get(validCBID)
			if len(interactions) != tt.expectedInteractions {
				t.Errorf("HandleDNS() interactions count = %v, want %v", len(interactions), tt.expectedInteractions)
			}
		})
	}
}

func TestShouldAnswer(t *testing.T) {
	tests := []struct {
		name       string
		handlerDom string
		queryName  string
		want       bool
	}{
		{
			name:       "exact_match",
			handlerDom: "cb.example.com",
			queryName:  "cb.example.com.",
			want:       true,
		},
		{
			name:       "subdomain_match",
			handlerDom: "cb.example.com",
			queryName:  "abc.cb.example.com.",
			want:       true,
		},
		{
			name:       "deep_subdomain_match",
			handlerDom: "cb.example.com",
			queryName:  "x.y.z.cb.example.com.",
			want:       true,
		},
		{
			name:       "case_insensitive_match",
			handlerDom: "CB.Example.COM",
			queryName:  "abc.cb.EXAMPLE.com.",
			want:       true,
		},
		{
			name:       "no_match",
			handlerDom: "cb.example.com",
			queryName:  "example.com.",
			want:       false,
		},
		{
			name:       "different_domain",
			handlerDom: "cb.example.com",
			queryName:  "cb.other.com.",
			want:       false,
		},
		{
			name:       "suffix_match_but_not_subdomain",
			handlerDom: "example.com",
			queryName:  "myexample.com.",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &RecordingHandler{Domain: tt.handlerDom}
			if got := h.shouldAnswer(tt.queryName); got != tt.want {
				t.Errorf("shouldAnswer(%q) = %v, want %v", tt.queryName, got, tt.want)
			}
		})
	}
}

func TestServeDNS(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen on UDP: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	handler := &RecordingHandler{}

	done := make(chan struct{})
	go func() {
		ServeDNS(ctx, conn, handler)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("ServeDNS did not stop after context cancellation")
	}
}
