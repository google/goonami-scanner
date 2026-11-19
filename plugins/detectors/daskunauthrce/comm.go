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

package daskunauthrce

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxFrameBytes         = 512 * 1024
	maxFramesCount        = 16
	maxWSFramesPerMessage = 64
	maxMsgPackDepth       = 16
	maxCollectionSize     = 4096
)

var (
	errInvalidDaskProtocol = errors.New("not a valid unauthenticated Dask Distributed Comm endpoint")

	// commHandshakeFrame encodes {"compression": nil, "python": [3, 10, 0], "pickle-protocol": 4}.
	commHandshakeFrame = []byte{
		0x83,
		0xab, 'c', 'o', 'm', 'p', 'r', 'e', 's', 's', 'i', 'o', 'n', 0xc0,
		0xa6, 'p', 'y', 't', 'h', 'o', 'n', 0x93, 0x03, 0x0a, 0x00,
		0xaf, 'p', 'i', 'c', 'k', 'l', 'e', '-', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l', 0x04,
	}

	// identityRequestFrame encodes {"op": "identity", "reply": true}.
	identityRequestFrame = []byte{
		0x82,
		0xa2, 'o', 'p', 0xa8, 'i', 'd', 'e', 'n', 't', 'i', 't', 'y',
		0xa5, 'r', 'e', 'p', 'l', 'y', 0xc3,
	}

	// operatorAddPickle is Pickle protocol 2 for stdlib operator.add.
	operatorAddPickle = []byte("\x80\x02coperator\nadd\nq\x00.")

	// emptyKwargsPickle is Pickle protocol 2 for an empty dict {}.
	emptyKwargsPickle = []byte("\x80\x02}q\x00.")
)

type commResult struct {
	commAddr    string
	daemonType  string
	daemonID    string
	handler     string
	operandA    int32
	operandB    int32
	computedSum int64
}

type frameReadWriter interface {
	writeFrames(frames [][]byte) error
	readFrames() ([][]byte, error)
}

func probeCommTCP(ctx context.Context, authority string, useTLS bool, timeout time.Duration, a, b int32) (*commResult, error) {
	conn, err := dialCommSocket(ctx, authority, useTLS, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	rw := &tcpFrameRW{r: bufio.NewReaderSize(conn, 8192), w: conn}
	return runCommSession(rw, authority, a, b)
}

func probeCommWebSocket(ctx context.Context, authority string, useTLS bool, timeout time.Duration, a, b int32) (*commResult, error) {
	conn, err := dialCommSocket(ctx, authority, useTLS, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	br := bufio.NewReaderSize(conn, 8192)
	if err := performWebSocketUpgrade(br, conn, authority); err != nil {
		return nil, err
	}

	rw := &wsFrameRW{r: br, w: conn}
	return runCommSession(rw, authority, a, b)
}

func dialCommSocket(ctx context.Context, authority string, useTLS bool, timeout time.Duration) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var (
		dialer net.Dialer
		conn   net.Conn
		err    error
	)
	if useTLS {
		tlsDialer := &tls.Dialer{
			NetDialer: &dialer,
			Config: &tls.Config{
				// Probed Dask clusters commonly use self-signed or internal-CA certs;
				// skipping server-cert verification tests whether mTLS client auth is enforced.
				InsecureSkipVerify: true, // NOLINT
			},
		}
		conn, err = tlsDialer.DialContext(dialCtx, "tcp", authority)
	} else {
		conn, err = dialer.DialContext(dialCtx, "tcp", authority)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	deadline := time.Now().Add(timeout) // NOMUTANTS -- defensive socket deadline
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline // NOMUTANTS -- defensive socket deadline
	}
	_ = conn.SetDeadline(deadline) // NOMUTANTS -- defensive socket deadline
	return conn, nil
}

func hasUnsafeHTTPByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return true
		}
	}
	return false
}

func performWebSocketUpgrade(br *bufio.Reader, w io.Writer, authority string) error {
	if authority == "" || hasUnsafeHTTPByte(authority) {
		return errInvalidDaskProtocol
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil { // NOMUTANTS -- OS CSPRNG failure
		return err // NOMUTANTS -- OS CSPRNG failure
	}
	wsKey := base64.StdEncoding.EncodeToString(nonce[:])

	reqStr := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		authority, wsKey,
	)
	if _, err := io.WriteString(w, reqStr); err != nil {
		return err
	}

	dummyReq := &http.Request{Method: http.MethodGet}
	resp, err := http.ReadResponse(br, dummyReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return errInvalidDaskProtocol
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Header.Get("Upgrade")), "websocket") {
		return errInvalidDaskProtocol
	}
	if !headerContainsToken(resp.Header.Get("Connection"), "upgrade") {
		return errInvalidDaskProtocol
	}
	if strings.TrimSpace(resp.Header.Get("Sec-WebSocket-Accept")) == "" {
		return errInvalidDaskProtocol
	}
	return nil
}

func headerContainsToken(headerVal, wantToken string) bool {
	for _, part := range strings.Split(headerVal, ",") {
		if strings.EqualFold(strings.TrimSpace(part), wantToken) {
			return true
		}
	}
	return false
}

func runCommSession(rw frameReadWriter, commAddr string, a, b int32) (*commResult, error) {
	// Step 1: Exchange Dask Comm binary handshake.
	if err := rw.writeFrames([][]byte{commHandshakeFrame}); err != nil {
		return nil, err
	}
	hsFrames, err := rw.readFrames()
	if err != nil {
		return nil, err
	}
	if len(hsFrames) != 1 || !isValidHandshakeReply(hsFrames[0]) {
		return nil, errInvalidDaskProtocol
	}

	// Step 2: Query {"op": "identity", "reply": true} to verify a live Dask Scheduler or Worker
	// and immediately reject echo servers (which lack "type" and "id").
	if err := rw.writeFrames([][]byte{identityRequestFrame}); err != nil {
		return nil, err
	}
	idFrames, err := rw.readFrames()
	if err != nil {
		return nil, err
	}
	daemonType, daemonID, ok := parseIdentityReply(idFrames)
	if !ok {
		return nil, errInvalidDaskProtocol
	}

	// Step 3: Non-destructive active arithmetic evaluation via operator.add(a, b).
	expectedSum := int64(a) + int64(b)
	argsPickle := buildArgsTuplePickle(a, b)

	type rpcProbe struct {
		handler string
		frame   []byte
		verify  func([][]byte, int64) bool
	}
	probes := []rpcProbe{
		{"run", buildRunOpFrame("run", operatorAddPickle, argsPickle, emptyKwargsPickle), verifyDirectRunReply},
	}
	if daemonType == "Scheduler" {
		probes = []rpcProbe{
			{"run_function", buildRunOpFrame("run_function", operatorAddPickle, argsPickle, emptyKwargsPickle), verifyDirectRunReply},
			{"broadcast(run)", buildBroadcastRunFrame(operatorAddPickle, argsPickle, emptyKwargsPickle, false), verifyBroadcastRunReply},
			{"broadcast(nanny_run)", buildBroadcastRunFrame(operatorAddPickle, argsPickle, emptyKwargsPickle, true), verifyBroadcastRunReply},
		}
	}
	for _, p := range probes {
		if err := rw.writeFrames([][]byte{p.frame}); err != nil {
			return nil, err
		}
		replyFrames, err := rw.readFrames()
		if err != nil {
			return nil, err
		}
		if p.verify(replyFrames, expectedSum) {
			return &commResult{
				commAddr:    commAddr,
				daemonType:  daemonType,
				daemonID:    daemonID,
				handler:     p.handler,
				operandA:    a,
				operandB:    b,
				computedSum: expectedSum,
			}, nil
		}
	}
	return nil, errInvalidDaskProtocol
}

type tcpFrameRW struct {
	r io.Reader
	w io.Writer
}

func (t *tcpFrameRW) writeFrames(frames [][]byte) error {
	var totalPayload int
	for _, f := range frames {
		totalPayload += len(f)
	}
	nFrames := uint64(len(frames))
	nosplitLen := 8*(1+nFrames) + uint64(totalPayload)

	var buf bytes.Buffer
	buf.Grow(int(8 + nosplitLen)) // NOMUTANTS(AOR): Preallocation hint only; serialized frame bytes match.
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], nosplitLen)
	buf.Write(tmp[:])
	binary.LittleEndian.PutUint64(tmp[:], nFrames)
	buf.Write(tmp[:])
	for _, f := range frames {
		binary.LittleEndian.PutUint64(tmp[:], uint64(len(f)))
		buf.Write(tmp[:])
	}
	for _, f := range frames {
		buf.Write(f)
	}
	_, err := t.w.Write(buf.Bytes())
	return err
}

func (t *tcpFrameRW) readFrames() ([][]byte, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(t.r, hdr[:]); err != nil {
		return nil, err
	}
	nosplitBytes := binary.LittleEndian.Uint64(hdr[0:8])
	nFrames := binary.LittleEndian.Uint64(hdr[8:16])
	if nFrames == 0 || nFrames > maxFramesCount || nosplitBytes > maxFrameBytes*maxFramesCount {
		return nil, errInvalidDaskProtocol
	}

	lensBuf := make([]byte, nFrames*8)
	if _, err := io.ReadFull(t.r, lensBuf); err != nil {
		return nil, err
	}
	lengths := make([]uint64, nFrames)
	var sumLengths uint64
	for i := uint64(0); i < nFrames; i++ {
		fLen := binary.LittleEndian.Uint64(lensBuf[i*8 : (i+1)*8])
		if fLen > maxFrameBytes {
			return nil, errInvalidDaskProtocol
		}
		lengths[i] = fLen
		sumLengths += fLen
	}
	if nosplitBytes != 8*(1+nFrames)+sumLengths {
		return nil, errInvalidDaskProtocol
	}

	frames := make([][]byte, nFrames)
	for i, fLen := range lengths {
		frame := make([]byte, fLen)
		if _, err := io.ReadFull(t.r, frame); err != nil {
			return nil, err
		}
		frames[i] = frame
	}
	return frames, nil
}

type wsFrameRW struct {
	r io.Reader
	w io.Writer
}

func (ws *wsFrameRW) writeFrames(frames [][]byte) error {
	var countBuf [8]byte
	binary.LittleEndian.PutUint64(countBuf[:], uint64(len(frames)))
	if err := writeWSBinaryMessage(ws.w, countBuf[:]); err != nil {
		return err
	}
	for _, frame := range frames {
		if err := writeWSBinaryMessage(ws.w, frame); err != nil {
			return err
		}
	}
	return nil
}

func (ws *wsFrameRW) readFrames() ([][]byte, error) {
	countMsg, err := readWSBinaryMessage(ws.r)
	if err != nil {
		return nil, err
	}
	if len(countMsg) != 8 {
		return nil, errInvalidDaskProtocol
	}
	nFrames := binary.LittleEndian.Uint64(countMsg)
	if nFrames == 0 || nFrames > maxFramesCount {
		return nil, errInvalidDaskProtocol
	}

	frames := make([][]byte, nFrames)
	for i := uint64(0); i < nFrames; i++ {
		frame, err := readWSBinaryMessage(ws.r)
		if err != nil {
			return nil, err
		}
		frames[i] = frame
	}
	return frames, nil
}

func writeWSBinaryMessage(w io.Writer, payload []byte) error {
	var maskKey [4]byte
	if _, err := io.ReadFull(rand.Reader, maskKey[:]); err != nil { // NOMUTANTS -- OS CSPRNG failure
		return err // NOMUTANTS -- OS CSPRNG failure
	}

	var buf bytes.Buffer
	buf.WriteByte(0x82) // FIN=1, opcode=0x2 (binary)
	n := len(payload)
	if n < 126 {
		buf.WriteByte(0x80 | byte(n))
	} else {
		buf.WriteByte(0x80 | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		buf.Write(ext[:])
	}
	buf.Write(maskKey[:])
	for i := 0; i < n; i++ {
		buf.WriteByte(payload[i] ^ maskKey[i&3])
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func readWSBinaryMessage(r io.Reader) ([]byte, error) {
	var assembled []byte
	expectingContinuation := false

	for frameCount := 0; frameCount < maxWSFramesPerMessage; frameCount++ {
		var hdr [2]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		fin := (hdr[0] & 0x80) != 0
		opcode := hdr[0] & 0x0f
		masked := (hdr[1] & 0x80) != 0
		payLen := uint64(hdr[1] & 0x7f)

		switch payLen {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(r, ext[:]); err != nil {
				return nil, err
			}
			payLen = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(r, ext[:]); err != nil {
				return nil, err
			}
			payLen = binary.BigEndian.Uint64(ext[:])
		}
		if payLen > maxFrameBytes-uint64(len(assembled)) {
			return nil, errInvalidDaskProtocol
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(r, maskKey[:]); err != nil {
				return nil, err
			}
		}

		chunk := make([]byte, payLen)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, err
		}
		if masked {
			for i := range chunk {
				chunk[i] ^= maskKey[i&3]
			}
		}

		switch opcode {
		case 0x09, 0x0a: // ping / pong control frame
			continue
		case 0x08: // close
			return nil, errInvalidDaskProtocol
		case 0x02:
			if expectingContinuation {
				return nil, errInvalidDaskProtocol
			}
			assembled = append(assembled, chunk...)
			if fin {
				return assembled, nil
			}
			expectingContinuation = true
		case 0x00:
			if !expectingContinuation {
				return nil, errInvalidDaskProtocol
			}
			assembled = append(assembled, chunk...)
			if fin {
				return assembled, nil
			}
		default:
			return nil, errInvalidDaskProtocol
		}
	}
	return nil, errInvalidDaskProtocol
}

func buildArgsTuplePickle(a, b int32) []byte {
	var out []byte
	out = append(out, 0x80, 0x02, 'J')
	out = binary.LittleEndian.AppendUint32(out, uint32(a))
	out = append(out, 'J')
	out = binary.LittleEndian.AppendUint32(out, uint32(b))
	return append(out, 0x86, 'q', 0x00, '.')
}

func buildRunOpFrame(op string, fnPkl, argsPkl, kwargsPkl []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x86) // fixmap(6)
	writeMPFixStr(&buf, "op")
	writeMPFixStr(&buf, op)
	writeMPFixStr(&buf, "function")
	writeMPBin8(&buf, fnPkl)
	writeMPFixStr(&buf, "args")
	writeMPBin8(&buf, argsPkl)
	writeMPFixStr(&buf, "kwargs")
	writeMPBin8(&buf, kwargsPkl)
	writeMPFixStr(&buf, "wait")
	buf.WriteByte(0xc3)
	writeMPFixStr(&buf, "reply")
	buf.WriteByte(0xc3)
	return buf.Bytes()
}

func buildBroadcastRunFrame(fnPkl, argsPkl, kwargsPkl []byte, targetNanny bool) []byte {
	var buf bytes.Buffer
	if targetNanny {
		buf.WriteByte(0x84) // fixmap(4)
	} else {
		buf.WriteByte(0x83) // fixmap(3)
	}
	writeMPFixStr(&buf, "op")
	writeMPFixStr(&buf, "broadcast")
	writeMPFixStr(&buf, "msg")
	buf.WriteByte(0x85) // fixmap(5)
	writeMPFixStr(&buf, "op")
	writeMPFixStr(&buf, "run")
	writeMPFixStr(&buf, "function")
	writeMPBin8(&buf, fnPkl)
	writeMPFixStr(&buf, "args")
	writeMPBin8(&buf, argsPkl)
	writeMPFixStr(&buf, "kwargs")
	writeMPBin8(&buf, kwargsPkl)
	writeMPFixStr(&buf, "wait")
	buf.WriteByte(0xc3)
	if targetNanny {
		writeMPFixStr(&buf, "nanny")
		buf.WriteByte(0xc3)
	}
	writeMPFixStr(&buf, "reply")
	buf.WriteByte(0xc3)
	return buf.Bytes()
}

func writeMPFixStr(buf *bytes.Buffer, s string) {
	buf.WriteByte(0xa0 | byte(len(s)))
	buf.WriteString(s)
}

func writeMPBin8(buf *bytes.Buffer, b []byte) {
	buf.WriteByte(0xc4)
	buf.WriteByte(byte(len(b)))
	buf.Write(b)
}

func isValidHandshakeReply(frame []byte) bool {
	val, err := decodeMsgPack(frame)
	if err != nil {
		return false
	}
	m, ok := val.(map[string]any)
	if !ok {
		return false
	}
	_, hasPickleProto := m["pickle-protocol"].(int64)
	return hasPickleProto
}

func parseIdentityReply(frames [][]byte) (string, string, bool) {
	if len(frames) == 0 {
		return "", "", false
	}
	val, err := decodeMsgPack(frames[0])
	if err != nil {
		return "", "", false
	}
	m, ok := val.(map[string]any)
	if !ok {
		return "", "", false
	}
	daemonType, _ := m["type"].(string)
	daemonID, _ := m["id"].(string)
	if strings.TrimSpace(daemonID) == "" {
		return "", "", false
	}
	switch daemonType {
	case "Scheduler", "Worker", "CUDAWorker", "Nanny":
		return daemonType, daemonID, true
	default:
		return "", "", false
	}
}

func verifyDirectRunReply(frames [][]byte, expectedSum int64) bool {
	if len(frames) == 0 {
		return false
	}
	val, err := decodeMsgPack(frames[0])
	if err != nil {
		return false
	}
	m, ok := val.(map[string]any)
	if !ok {
		return false
	}
	return matchesWorkerStatusMap(m, frames[1:], expectedSum)
}

func verifyBroadcastRunReply(frames [][]byte, expectedSum int64) bool {
	if len(frames) == 0 {
		return false
	}
	val, err := decodeMsgPack(frames[0])
	if err != nil {
		return false
	}
	outer, ok := val.(map[string]any)
	if !ok {
		return false
	}
	for _, entry := range outer {
		workerMap, ok := entry.(map[string]any)
		if ok && matchesWorkerStatusMap(workerMap, frames[1:], expectedSum) {
			return true
		}
	}
	return false
}

func matchesWorkerStatusMap(m map[string]any, subFrames [][]byte, expectedSum int64) bool {
	status, _ := m["status"].(string)
	if status != "OK" {
		return false
	}
	resVal, exists := m["result"]
	if !exists {
		return false
	}
	if directInt, ok := resVal.(int64); ok {
		return directInt == expectedSum
	}
	if directBytes, ok := resVal.([]byte); ok {
		got, ok := parsePickleInt64(directBytes)
		return ok && got == expectedSum
	}
	resMap, ok := resVal.(map[string]any)
	if !ok {
		return false
	}
	if pickledBytes, ok := resMap["__Pickled__"].([]byte); ok {
		got, ok := parsePickleInt64(pickledBytes)
		return ok && got == expectedSum
	}
	_, isSerialized := resMap["__Serialized__"]
	_, hasPickledOffset := resMap["__Pickled__"]
	if isSerialized || hasPickledOffset {
		for _, sf := range subFrames {
			if got, ok := extractSubFramePickleInt64(sf); ok && got == expectedSum {
				return true
			}
		}
	}
	return false
}

func extractSubFramePickleInt64(sf []byte) (int64, bool) {
	if got, ok := parsePickleInt64(sf); ok {
		return got, true
	}
	decoded, err := decodeMsgPack(sf)
	if err != nil {
		return 0, false
	}
	subHeader, ok := decoded.(map[string]any)
	if !ok {
		return 0, false
	}
	pickledObj, ok := subHeader["pickled-obj"].([]byte)
	if !ok {
		return 0, false
	}
	return parsePickleInt64(pickledObj)
}

func parsePickleInt64(data []byte) (int64, bool) {
	pos := 0
	if pos < len(data) && data[pos] == 0x80 { // PROTO
		pos += 2
		if pos > len(data) {
			return 0, false
		}
	}
	if pos < len(data) && data[pos] == 0x95 { // FRAME (protocol >= 4)
		pos += 9
		if pos > len(data) {
			return 0, false
		}
	}
	if pos >= len(data) {
		return 0, false
	}

	var val int64
	switch data[pos] {
	case 'J': // BININT (signed int32 little-endian)
		if pos+5 > len(data) {
			return 0, false
		}
		val = int64(int32(binary.LittleEndian.Uint32(data[pos+1 : pos+5])))
		pos += 5
	case 'I': // INT (ASCII decimal terminated by \n)
		nl := bytes.IndexByte(data[pos+1:], '\n')
		if nl <= 0 {
			return 0, false
		}
		parsed, err := strconv.ParseInt(strings.TrimSuffix(string(data[pos+1:pos+1+nl]), "L"), 10, 64)
		if err != nil {
			return 0, false
		}
		val = parsed
		pos += 2 + nl
	case 0x8a: // LONG1
		if pos+2 > len(data) {
			return 0, false
		}
		n := int(data[pos+1])
		if n <= 0 || n > 8 || pos+2+n > len(data) {
			return 0, false
		}
		var u uint64
		for i := 0; i < n; i++ {
			u |= uint64(data[pos+2+i]) << (8 * i)
		}
		val = int64(u)
		pos += 2 + n
	default:
		return 0, false
	}

	// Skip optional memoize opcodes (MEMOIZE 0x94, BINPUT 'q'<u8>, LONG_BINPUT 'r'<u32>).
	for pos < len(data) {
		switch data[pos] {
		case 0x94:
			pos++
		case 'q':
			pos += 2
		case 'r':
			pos += 5
		case '.':
			return val, pos+1 == len(data)
		default:
			return 0, false
		}
	}
	return 0, false
}

type mpDecoder struct {
	data []byte
	pos  int
}

func decodeMsgPack(data []byte) (any, error) {
	dec := &mpDecoder{data: data}
	return dec.readValue(0)
}

func (d *mpDecoder) readByte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, io.ErrUnexpectedEOF
	}
	b := d.data[d.pos]
	d.pos++
	return b, nil
}

func (d *mpDecoder) readN(n int) ([]byte, error) {
	if d.pos+n > len(d.data) {
		return nil, io.ErrUnexpectedEOF
	}
	slice := d.data[d.pos : d.pos+n]
	d.pos += n
	return slice, nil
}

func (d *mpDecoder) readValue(depth int) (any, error) {
	if depth > maxMsgPackDepth {
		return nil, errInvalidDaskProtocol
	}
	tag, err := d.readByte()
	if err != nil {
		return nil, err
	}

	switch {
	case tag <= 0x7f:
		return int64(tag), nil
	case tag >= 0xe0:
		return int64(int8(tag)), nil
	case tag >= 0x80 && tag <= 0x8f:
		return d.readMap(int(tag&0x0f), depth)
	case tag >= 0x90 && tag <= 0x9f:
		return d.readArray(int(tag&0x0f), depth)
	case tag >= 0xa0 && tag <= 0xbf:
		raw, err := d.readN(int(tag & 0x1f))
		if err != nil {
			return nil, err
		}
		return string(raw), nil
	}

	switch tag {
	case 0xc0:
		return nil, nil
	case 0xc2:
		return false, nil
	case 0xc3:
		return true, nil
	case 0xc4, 0xd9: // bin8, str8
		n, err := d.readByte()
		if err != nil {
			return nil, err
		}
		raw, err := d.readN(int(n))
		if err != nil {
			return nil, err
		}
		if tag == 0xd9 {
			return string(raw), nil
		}
		return bytes.Clone(raw), nil
	case 0xc5, 0xda: // bin16, str16
		b, err := d.readN(2)
		if err != nil {
			return nil, err
		}
		raw, err := d.readN(int(binary.BigEndian.Uint16(b)))
		if err != nil {
			return nil, err
		}
		if tag == 0xda {
			return string(raw), nil
		}
		return bytes.Clone(raw), nil
	case 0xc6, 0xdb: // bin32, str32
		b, err := d.readN(4)
		if err != nil {
			return nil, err
		}
		ln := binary.BigEndian.Uint32(b)
		if ln > maxFrameBytes {
			return nil, errInvalidDaskProtocol
		}
		raw, err := d.readN(int(ln))
		if err != nil {
			return nil, err
		}
		if tag == 0xdb {
			return string(raw), nil
		}
		return bytes.Clone(raw), nil
	case 0xca: // float32
		_, err := d.readN(4)
		return 0.0, err
	case 0xcb: // float64
		_, err := d.readN(8)
		return 0.0, err
	case 0xcc: // uint8
		b, err := d.readByte()
		return int64(b), err
	case 0xcd: // uint16
		b, err := d.readN(2)
		if err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint16(b)), nil
	case 0xce: // uint32
		b, err := d.readN(4)
		if err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint32(b)), nil
	case 0xcf: // uint64
		b, err := d.readN(8)
		if err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint64(b)), nil
	case 0xd0: // int8
		b, err := d.readByte()
		return int64(int8(b)), err
	case 0xd1: // int16
		b, err := d.readN(2)
		if err != nil {
			return nil, err
		}
		return int64(int16(binary.BigEndian.Uint16(b))), nil
	case 0xd2: // int32
		b, err := d.readN(4)
		if err != nil {
			return nil, err
		}
		return int64(int32(binary.BigEndian.Uint32(b))), nil
	case 0xd3: // int64
		b, err := d.readN(8)
		if err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint64(b)), nil
	case 0xdc: // array16
		b, err := d.readN(2)
		if err != nil {
			return nil, err
		}
		return d.readArray(int(binary.BigEndian.Uint16(b)), depth)
	case 0xdd: // array32
		b, err := d.readN(4)
		if err != nil {
			return nil, err
		}
		ln := binary.BigEndian.Uint32(b)
		if ln > maxCollectionSize {
			return nil, errInvalidDaskProtocol
		}
		return d.readArray(int(ln), depth)
	case 0xde: // map16
		b, err := d.readN(2)
		if err != nil {
			return nil, err
		}
		return d.readMap(int(binary.BigEndian.Uint16(b)), depth)
	case 0xdf: // map32
		b, err := d.readN(4)
		if err != nil {
			return nil, err
		}
		ln := binary.BigEndian.Uint32(b)
		if ln > maxCollectionSize {
			return nil, errInvalidDaskProtocol
		}
		return d.readMap(int(ln), depth)
	case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8: // fixext 1, 2, 4, 8, 16
		extSize := 1 << (tag - 0xd4)
		_, err := d.readN(1 + extSize)
		return nil, err
	case 0xc7, 0xc8, 0xc9: // ext 8, 16, 32
		return d.skipVarExt(tag)
	default:
		return nil, errInvalidDaskProtocol
	}
}

func (d *mpDecoder) skipVarExt(tag byte) (any, error) {
	var ln uint32
	switch tag {
	case 0xc7:
		b, err := d.readByte()
		if err != nil {
			return nil, err
		}
		ln = uint32(b)
	case 0xc8:
		b, err := d.readN(2)
		if err != nil {
			return nil, err
		}
		ln = uint32(binary.BigEndian.Uint16(b))
	default:
		b, err := d.readN(4)
		if err != nil {
			return nil, err
		}
		ln = binary.BigEndian.Uint32(b)
	}
	if ln > maxFrameBytes {
		return nil, errInvalidDaskProtocol
	}
	_, err := d.readN(1 + int(ln))
	return nil, err
}

func (d *mpDecoder) readArray(count, depth int) ([]any, error) {
	if count > maxCollectionSize {
		return nil, errInvalidDaskProtocol
	}
	arr := make([]any, count)
	for i := 0; i < count; i++ {
		v, err := d.readValue(depth + 1)
		if err != nil {
			return nil, err
		}
		arr[i] = v
	}
	return arr, nil
}

func (d *mpDecoder) readMap(count, depth int) (map[string]any, error) {
	if count > maxCollectionSize {
		return nil, errInvalidDaskProtocol
	}
	m := make(map[string]any, count)
	for i := 0; i < count; i++ {
		k, err := d.readValue(depth + 1)
		if err != nil {
			return nil, err
		}
		v, err := d.readValue(depth + 1)
		if err != nil {
			return nil, err
		}
		m[fmt.Sprint(k)] = v
	}
	return m, nil
}
