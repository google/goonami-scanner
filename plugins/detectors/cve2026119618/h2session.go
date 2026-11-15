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

package cve2026119618

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	h2ClientPreface       = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	maxH2FrameSize        = 16384
	maxContinuationFrames = 16
	maxH2HeaderListSize   = 32768
	maxHpackFields        = 128
	maxHpackStringLen     = 8192
	hpackDynTableSize     = 4096
	maxResponseBodyLen    = 65536
	maxFramesPerStream    = 64
	maxHeadersPerStream   = 9
)

var (
	errNotH2Peer       = errors.New("target did not negotiate or speak HTTP/2")
	errGoAwayReconnect = errors.New("peer closed HTTP/2 session with GOAWAY or EOF")
	errTooManyHeaders  = errors.New("outbound header count exceeds <10 safety ceiling")
)

type transportMode string

const (
	transportH2TLS transportMode = "h2"
	transportH2C   transportMode = "h2c"
)

type dialFunc func(ctx context.Context, mode transportMode, dialAddr, sniHost string, timeout time.Duration) (net.Conn, error)

func defaultDial(ctx context.Context, mode transportMode, dialAddr, sniHost string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, err
	}

	if mode == transportH2C {
		return rawConn, nil
	}

	tlsCfg := &tls.Config{
		// Scanner probes arbitrary network endpoints that frequently serve self-signed or IP-bound certificates.
		InsecureSkipVerify: true, // NOLINT
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	}
	if sniHost != "" {
		tlsCfg.ServerName = sniHost
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	_ = rawConn.SetDeadline(time.Now().Add(timeout)) // NOMUTANTS -- defensive handshake deadline
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close() // NOMUTANTS(SBR): Resource cleanup on failed TLS handshake; unobservable on returned error.
		return nil, err
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = tlsConn.Close() // NOMUTANTS(SBR): Resource cleanup on ALPN mismatch; unobservable on returned error.
		return nil, errNotH2Peer
	}
	return tlsConn, nil
}

type h2Response struct {
	status      string
	contentType string
	body        []byte
}

// h2ProbeSession encapsulates a single sequential HTTP/2 connection (including
// its connection-scoped HPACK encoder/decoder dynamic tables and transparent
// GOAWAY reconnection between sequential streams).
type h2ProbeSession struct {
	mode       transportMode
	dialAddr   string
	sniHost    string
	timeout    time.Duration
	dial       dialFunc
	conn       net.Conn
	framer     *http2.Framer
	hpackDec   *hpack.Decoder
	hpackEnc   *hpack.Encoder
	hpackBuf   bytes.Buffer
	nextStream uint32
	peerGoAway bool
}

func openH2ProbeSession(ctx context.Context, dial dialFunc, mode transportMode, target endpointTarget, timeout time.Duration) (*h2ProbeSession, error) {
	s := &h2ProbeSession{
		mode:     mode,
		dialAddr: target.dialAddr,
		sniHost:  target.sniHost,
		timeout:  timeout,
		dial:     dial,
	}
	if err := s.connect(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *h2ProbeSession) connect(ctx context.Context) error {
	s.closeConn() // NOMUTANTS(SBR): Closes prior socket before re-dialing to prevent file descriptor leaks.
	conn, err := s.dial(ctx, s.mode, s.dialAddr, s.sniHost, s.timeout)
	if err != nil {
		return err
	}
	connected := false
	defer func() {
		if !connected {
			_ = conn.Close() // NOMUTANTS(SBR): Best-effort socket cleanup on failed HTTP/2 preface exchange.
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(s.timeout)) // NOMUTANTS -- defensive connection deadline

	// Send client connection preface and empty initial SETTINGS frame (9 bytes) together.
	if _, err := io.WriteString(conn, h2ClientPreface+"\x00\x00\x00\x04\x00\x00\x00\x00\x00"); err != nil {
		return err
	}

	fr := http2.NewFramer(conn, conn)
	hdec := hpack.NewDecoder(hpackDynTableSize, nil)
	hdec.SetMaxStringLength(maxHpackStringLen)

	// Pre-allocation 9-byte frame header gate: reject HTTP/1.1 responses (e.g.
	// "HTTP/1.1 400...", whose first 3 bytes 0x485454 encode a 4.74 MiB length)
	// immediately before reading any frame payload.
	fh, err := fr.ReadFrameHeader()
	if err != nil {
		return fmt.Errorf("%w: %v", errNotH2Peer, err)
	}
	if fh.Type != http2.FrameSettings || fh.Flags.Has(http2.FlagSettingsAck) || fh.StreamID != 0 || fh.Length%6 != 0 {
		return errNotH2Peer
	}
	if _, err := fr.ReadFrameForHeader(fh); err != nil {
		return errNotH2Peer
	}
	if err := fr.WriteSettingsAck(); err != nil {
		return err
	}

	connected = true
	s.conn = conn
	s.framer = fr
	s.hpackDec = hdec
	s.hpackEnc = hpack.NewEncoder(&s.hpackBuf)
	s.nextStream = 1
	s.peerGoAway = false
	return nil
}

func (s *h2ProbeSession) closeConn() {
	if s.conn != nil {
		_ = s.conn.Close() // NOMUTANTS(SBR): Closing the active socket is resource cleanup.
		s.conn = nil
	}
}

func (s *h2ProbeSession) close() {
	s.closeConn()
}

// roundTrip executes a single sequential HTTP/2 request stream, reconnecting
// once with fresh HPACK state and stream ID 1 if the peer sent GOAWAY or closed
// the idle connection after a previous stream.
func (s *h2ProbeSession) roundTrip(ctx context.Context, headers []hpack.HeaderField, body []byte) (h2Response, error) {
	if len(headers) > maxHeadersPerStream {
		return h2Response{}, errTooManyHeaders
	}
	if s.conn == nil || s.peerGoAway {
		if err := s.connect(ctx); err != nil {
			return h2Response{}, err
		}
	}

	canRetry := s.nextStream > 1
	resp, err := s.exchangeOnce(headers, body)
	if err != nil && canRetry && errors.Is(err, errGoAwayReconnect) {
		if reconnErr := s.connect(ctx); reconnErr != nil {
			return h2Response{}, reconnErr
		}
		return s.exchangeOnce(headers, body)
	}
	return resp, err
}

func (s *h2ProbeSession) exchangeOnce(headers []hpack.HeaderField, body []byte) (h2Response, error) {
	_ = s.conn.SetDeadline(time.Now().Add(s.timeout)) // NOMUTANTS -- per-stream socket deadline

	streamID := s.nextStream
	s.nextStream += 2

	s.hpackBuf.Reset()
	for _, hf := range headers {
		hf.Sensitive = true
		if err := s.hpackEnc.WriteField(hf); err != nil {
			return h2Response{}, err
		}
	}

	err := s.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: s.hpackBuf.Bytes(),
		EndStream:     len(body) == 0,
		EndHeaders:    true,
	})
	if err != nil {
		return h2Response{}, fmt.Errorf("%w: %v", errGoAwayReconnect, err)
	}
	if len(body) > 0 {
		if err := s.framer.WriteData(streamID, true, body); err != nil {
			return h2Response{}, fmt.Errorf("%w: %v", errGoAwayReconnect, err)
		}
	}

	var (
		status      string
		contentType string
		bodyBuf     bytes.Buffer
	)

	for frameCount := 0; frameCount < maxFramesPerStream; frameCount++ {
		fh, err := s.framer.ReadFrameHeader()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if status != "" {
					return h2Response{status: status, contentType: contentType, body: bodyBuf.Bytes()}, nil
				}
				return h2Response{}, fmt.Errorf("%w: %v", errGoAwayReconnect, err)
			}
			if status == "" && isRetryableReadErr(err) {
				return h2Response{}, fmt.Errorf("%w: %v", errGoAwayReconnect, err)
			}
			return h2Response{}, err
		}
		frame, err := s.framer.ReadFrameForHeader(fh)
		if err != nil {
			return h2Response{}, err
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if ackErr := s.framer.WriteSettingsAck(); ackErr != nil {
					return h2Response{}, ackErr
				}
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				if pingErr := s.framer.WritePing(true, f.Data); pingErr != nil {
					return h2Response{}, pingErr
				}
			}
		case *http2.WindowUpdateFrame:
			// Ignore peer flow-control increments on our small 1-byte probes.
		case *http2.HeadersFrame:
			decoded, decErr := s.decodeHeadersBlock(f)
			if decErr != nil {
				return h2Response{}, decErr
			}
			if f.StreamID != streamID {
				continue
			}
			if status == "" {
				var hdrStatus, hdrContentType string
				for _, hf := range decoded {
					if hf.Name == ":status" {
						hdrStatus = hf.Value
					} else if strings.EqualFold(hf.Name, "content-type") {
						hdrContentType = hf.Value
					}
				}
				// Ignore non-END_STREAM 1xx interim informational HEADERS frames
				// (such as 103 Early Hints from Apache H2EarlyHints on) so the
				// final >= 200 response HEADERS frame is captured.
				if !f.StreamEnded() && len(hdrStatus) == 3 && hdrStatus[0] == '1' {
					continue
				}
				status = hdrStatus
				contentType = hdrContentType
			}
			if f.StreamEnded() {
				return h2Response{status: status, contentType: contentType, body: bodyBuf.Bytes()}, nil
			}
		case *http2.DataFrame:
			if f.StreamID != streamID {
				continue
			}
			data := f.Data()
			if bodyBuf.Len()+len(data) > maxResponseBodyLen {
				return h2Response{}, errors.New("response body exceeds maximum allowed size")
			}
			bodyBuf.Write(data)
			if f.StreamEnded() {
				return h2Response{status: status, contentType: contentType, body: bodyBuf.Bytes()}, nil
			}
			if fh.Length > 0 {
				_ = s.framer.WriteWindowUpdate(0, fh.Length)
				_ = s.framer.WriteWindowUpdate(streamID, fh.Length)
			}
		case *http2.RSTStreamFrame:
			if f.StreamID != streamID {
				continue
			}
			// When ap_send_http_trace rejects a 1-byte TRACE body with 413 without
			// draining the request stream, nghttp2 sends HEADERS(:status=413) +
			// DATA(END_STREAM) followed by RST_STREAM(NO_ERROR). Preserve completed
			// response headers if already received.
			if status != "" {
				return h2Response{status: status, contentType: contentType, body: bodyBuf.Bytes()}, nil
			}
			return h2Response{}, fmt.Errorf("stream %d reset with %v", streamID, f.ErrCode)
		case *http2.GoAwayFrame:
			s.peerGoAway = true
			if f.LastStreamID < streamID {
				return h2Response{}, errGoAwayReconnect
			}
		}
	}

	return h2Response{}, errors.New("exceeded maximum HTTP/2 frames per stream")
}

func (s *h2ProbeSession) decodeHeadersBlock(hf *http2.HeadersFrame) ([]hpack.HeaderField, error) {
	var (
		decoded     []hpack.HeaderField
		limitErr    error
		remainBytes = maxH2HeaderListSize
	)
	s.hpackDec.SetEmitFunc(func(field hpack.HeaderField) {
		if len(decoded) >= maxHpackFields || int(field.Size()) > remainBytes {
			limitErr = errors.New("response header list exceeds maximum allowed size")
			return
		}
		remainBytes -= int(field.Size())
		decoded = append(decoded, field)
	})
	defer s.hpackDec.SetEmitFunc(func(hpack.HeaderField) {})

	if _, err := s.hpackDec.Write(hf.HeaderBlockFragment()); err != nil {
		return nil, err
	}
	if limitErr != nil {
		return nil, limitErr
	}

	if !hf.HeadersEnded() {
		ended := false
		for i := 0; i < maxContinuationFrames; i++ {
			nextFrame, err := s.framer.ReadFrame()
			if err != nil {
				return nil, err
			}
			cf, ok := nextFrame.(*http2.ContinuationFrame)
			if !ok || cf.StreamID != hf.StreamID {
				return nil, errors.New("expected contiguous CONTINUATION frame")
			}
			if _, err := s.hpackDec.Write(cf.HeaderBlockFragment()); err != nil {
				return nil, err
			}
			if limitErr != nil {
				return nil, limitErr
			}
			if cf.HeadersEnded() {
				ended = true
				break
			}
		}
		if !ended {
			return nil, errors.New("exceeded maximum HTTP/2 CONTINUATION frame count")
		}
	}

	if err := s.hpackDec.Close(); err != nil {
		return nil, err
	}
	return decoded, nil
}

func isRetryableReadErr(err error) bool {
	if errors.Is(err, http2.ErrFrameTooLarge) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	var connErr http2.ConnectionError
	if errors.As(err, &connErr) {
		return false
	}
	var streamErr http2.StreamError
	if errors.As(err, &streamErr) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return true
}
