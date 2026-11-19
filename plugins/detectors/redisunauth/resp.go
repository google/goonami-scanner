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

package redisunauth

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	maxSessionBytes = 65536
	// Largest single bulk payload whose "$<5-digit-len>\r\n...payload...\r\n" frame fits in maxSessionBytes.
	maxBulkBytes     = maxSessionBytes - len("$65526\r\n\r\n")
	maxLineBytes     = 4096
	maxArrayElements = 1024
	maxNestingDepth  = 4
)

var errRespProtocol = errors.New("invalid or out-of-bounds RESP2 frame")

type respKind int

const (
	respSimpleString respKind = iota
	respError
	respInteger
	respBulkString
	respNullBulk
	respArray
	respNullArray
)

type respValue struct {
	kind     respKind
	text     string
	integer  int64
	elements []respValue
}

type respReader struct {
	br       *bufio.Reader
	consumed int
}

func newRespReader(r io.Reader) *respReader {
	// Read up to maxSessionBytes + 1 so exceeding the 64 KiB session budget is
	// deterministically surfaced as errRespProtocol rather than clean io.EOF.
	limited := io.LimitReader(r, maxSessionBytes+1) // NOMUTANTS -- defensive session cap
	return &respReader{br: bufio.NewReader(limited)}
}

func encodeCommand(args ...string) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&out, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return out.Bytes()
}

func (rr *respReader) readFrame() (respValue, error) {
	return rr.readFrameAtDepth(0, true)
}

func (rr *respReader) readFrameAtDepth(depth int, atFrameStart bool) (respValue, error) {
	if depth > maxNestingDepth {
		return respValue{}, fmt.Errorf("%w: array nesting depth exceeded %d", errRespProtocol, maxNestingDepth)
	}
	prefix, err := rr.readByte(atFrameStart)
	if err != nil {
		return respValue{}, err
	}
	switch prefix {
	case '+':
		line, err := rr.readCrLfLine()
		if err != nil {
			return respValue{}, err
		}
		return respValue{kind: respSimpleString, text: line}, nil
	case '-':
		line, err := rr.readCrLfLine()
		if err != nil {
			return respValue{}, err
		}
		return respValue{kind: respError, text: line}, nil
	case ':':
		line, err := rr.readCrLfLine()
		if err != nil {
			return respValue{}, err
		}
		val, err := parseStrictInt64(line)
		if err != nil {
			return respValue{}, fmt.Errorf("%w: invalid integer %q", errRespProtocol, line)
		}
		return respValue{kind: respInteger, integer: val}, nil
	case '$':
		return rr.readBulkString()
	case '*':
		return rr.readArray(depth)
	default:
		return respValue{}, fmt.Errorf("%w: unexpected prefix byte %d", errRespProtocol, prefix)
	}
}

func (rr *respReader) readBulkString() (respValue, error) {
	line, err := rr.readCrLfLine()
	if err != nil {
		return respValue{}, err
	}
	declaredLen, err := parseStrictInt64(line)
	if err != nil {
		return respValue{}, fmt.Errorf("%w: invalid bulk length %q", errRespProtocol, line)
	}
	if declaredLen == -1 {
		return respValue{kind: respNullBulk}, nil
	}
	if declaredLen < -1 || declaredLen > int64(maxBulkBytes) {
		return respValue{}, fmt.Errorf("%w: out-of-bounds bulk length %d", errRespProtocol, declaredLen)
	}
	length := int(declaredLen)
	if rr.consumed+length+2 > maxSessionBytes {
		return respValue{}, fmt.Errorf("%w: bulk payload exceeds session byte budget", errRespProtocol)
	}
	buf := make([]byte, length+2)
	if _, err := io.ReadFull(rr.br, buf); err != nil {
		return respValue{}, fmt.Errorf("%w: truncated bulk payload: %v", errRespProtocol, err)
	}
	if err := rr.consume(length + 2); err != nil {
		return respValue{}, err
	}
	if buf[length] != '\r' || buf[length+1] != '\n' {
		return respValue{}, fmt.Errorf("%w: missing trailing CRLF after bulk string", errRespProtocol)
	}
	return respValue{kind: respBulkString, text: strings.ToValidUTF8(string(buf[:length]), "\uFFFD")}, nil
}

func (rr *respReader) readArray(depth int) (respValue, error) {
	line, err := rr.readCrLfLine()
	if err != nil {
		return respValue{}, err
	}
	declaredCount, err := parseStrictInt64(line)
	if err != nil {
		return respValue{}, fmt.Errorf("%w: invalid array count %q", errRespProtocol, line)
	}
	if declaredCount == -1 {
		return respValue{kind: respNullArray}, nil
	}
	if declaredCount < -1 || declaredCount > maxArrayElements {
		return respValue{}, fmt.Errorf("%w: out-of-bounds array count %d", errRespProtocol, declaredCount)
	}
	count := int(declaredCount)
	elements := make([]respValue, 0, min(count, 64))
	for range count {
		elem, err := rr.readFrameAtDepth(depth+1, false)
		if err != nil {
			return respValue{}, err
		}
		elements = append(elements, elem)
	}
	return respValue{kind: respArray, elements: elements}, nil
}

func (rr *respReader) readCrLfLine() (string, error) {
	var line []byte
	for {
		b, err := rr.readByte(false)
		if err != nil {
			return "", err
		}
		if b == '\r' {
			lf, err := rr.readByte(false)
			if err != nil {
				return "", err
			}
			if lf != '\n' {
				return "", fmt.Errorf("%w: expected LF after CR", errRespProtocol)
			}
			return strings.ToValidUTF8(string(line), "\uFFFD"), nil
		}
		if b == '\n' {
			return "", fmt.Errorf("%w: missing CR before LF", errRespProtocol)
		}
		if len(line) >= maxLineBytes {
			return "", fmt.Errorf("%w: line exceeded %d bytes", errRespProtocol, maxLineBytes)
		}
		line = append(line, b)
	}
}

func (rr *respReader) readByte(cleanEOFAllowed bool) (byte, error) {
	b, err := rr.br.ReadByte()
	if err != nil {
		if cleanEOFAllowed && errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("%w: truncated frame: %v", errRespProtocol, err)
	}
	if err := rr.consume(1); err != nil {
		return 0, err
	}
	return b, nil
}

func (rr *respReader) consume(n int) error {
	rr.consumed += n
	if rr.consumed > maxSessionBytes {
		return fmt.Errorf("%w: session exceeded byte budget of %d", errRespProtocol, maxSessionBytes)
	}
	return nil
}

func parseStrictInt64(raw string) (int64, error) {
	if raw == "" {
		return 0, errRespProtocol
	}
	for i := range len(raw) {
		c := raw[i]
		if !(i == 0 && c == '-' && len(raw) > 1) && (c < '0' || c > '9') {
			return 0, errRespProtocol
		}
	}
	return strconv.ParseInt(raw, 10, 64)
}
