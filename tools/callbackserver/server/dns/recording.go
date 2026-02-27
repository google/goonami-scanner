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

// Package dns handles incoming DNS requests to record interactions.
package dns

import (
	"context"
	"net"
	"strings"

	"github.com/google/goonami-scanner/common/callbackserver/netutils"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/tools/callbackserver/storage"
	"golang.org/x/net/dns/dnsmessage"
)

// RecordingHandler handles incoming DNS requests to record interactions.
type RecordingHandler struct {
	Store  storage.InteractionStore
	Domain string
}

// ServeDNS starts handling incoming DNS requests on the given connection.
func ServeDNS(ctx context.Context, conn *net.UDPConn, handler *RecordingHandler) {
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}

			go handler.HandleDNS(ctx, conn, addr, buf[:n])
		}
	}
}

// HandleDNS processes a DNS query and returns a response.
func (h *RecordingHandler) HandleDNS(ctx context.Context, conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	var msg dnsmessage.Message
	if err := msg.Unpack(data); err != nil {
		return
	}

	if len(msg.Questions) == 0 {
		return
	}

	question := msg.Questions[0]
	questionName := question.Name.String()

	if !h.shouldAnswer(questionName) {
		log.DebugContextf(ctx, log.DebugLevelSession, "refusing DNS query for %q from IP %q", questionName, addr.String())
		h.sendErrorResponse(conn, addr, msg, dnsmessage.RCodeRefused)
		return
	}

	cbid, err := netutils.IdentifierFromDomain(questionName)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelSession, "failed to extract identifier from %q: %v", questionName, err)
		h.sendErrorResponse(conn, addr, msg, dnsmessage.RCodeRefused)
		return
	}

	if err := h.Store.Register(cbid, storage.DNSInteraction); err != nil {
		log.ErrorContextf(ctx, "failed to register DNS interaction for %q: %v", questionName, err)
		h.sendErrorResponse(conn, addr, msg, dnsmessage.RCodeRefused)
		return
	}

	// We have recorded the interaction, but the client does not have to handle a specific type of
	// response. We send a different error type for differentiation.
	log.DebugContextf(ctx, log.DebugLevelSession, "DNS interaction with CBID %q recorded from IP %q", cbid, addr.String())
	h.sendErrorResponse(conn, addr, msg, dnsmessage.RCodeNameError)
}

func (h *RecordingHandler) shouldAnswer(name string) bool {
	n := strings.ToLower(name)
	n = strings.TrimSuffix(n, ".")
	domain := strings.ToLower(h.Domain)
	domain = strings.TrimSuffix(domain, ".")

	return n == domain || strings.HasSuffix(n, "."+domain)
}

func (h *RecordingHandler) sendErrorResponse(conn *net.UDPConn, addr *net.UDPAddr, query dnsmessage.Message, rcode dnsmessage.RCode) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       query.ID,
			Response: true,
			RCode:    rcode,
		},
		Questions: query.Questions,
	}

	packed, err := resp.Pack()
	if err != nil {
		return
	}

	conn.WriteToUDP(packed, addr)
}
