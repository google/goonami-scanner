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

package rdpclient

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	credSSPClientVersion = 6
	maxDERMessageBytes   = 65536

	// NTSTATUS codes returned in TSRequest.errorCode (MS-CSSP).
	ntStatusLogonFailure       uint32 = 0xc000006d
	ntStatusAccountRestriction uint32 = 0xc000006e
	ntStatusPasswordExpired    uint32 = 0xc0000071
	ntStatusAccountDisabled    uint32 = 0xc0000072
	ntStatusAccountExpired     uint32 = 0xc0000193
	ntStatusPasswordMustChange uint32 = 0xc0000224
	ntStatusAccountLockedOut   uint32 = 0xc0000234
)

var (
	credSSPC2SMagic = []byte("CredSSP Client-To-Server Binding Hash\x00")
	credSSPS2CMagic = []byte("CredSSP Server-To-Client Binding Hash\x00")

	spnegoOID              = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmsspOID             = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	tlsServerEndPointLabel = []byte("tls-server-end-point:")
)

func derEncodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var buf [4]byte
	var start int
	switch {
	case n <= 0xff:
		buf[3] = byte(n)
		start = 3
	case n <= 0xffff:
		buf[2] = byte(n >> 8)
		buf[3] = byte(n)
		start = 2
	case n <= 0xffffff:
		buf[1] = byte(n >> 16)
		buf[2] = byte(n >> 8)
		buf[3] = byte(n)
		start = 1
	default:
		buf[0] = byte(n >> 24)
		buf[1] = byte(n >> 16)
		buf[2] = byte(n >> 8)
		buf[3] = byte(n)
		start = 0
	}
	numBytes := 4 - start
	out := make([]byte, 1+numBytes)
	out[0] = byte(0x80 | numBytes)
	copy(out[1:], buf[start:])
	return out
}

func derTLV(tag byte, value []byte) []byte {
	l := derEncodeLength(len(value))
	out := make([]byte, 0, 1+len(l)+len(value))
	out = append(out, tag)
	out = append(out, l...)
	out = append(out, value...)
	return out
}

func derInt(v int) []byte {
	if v == 0 {
		return derTLV(0x02, []byte{0})
	}
	var raw []byte
	for tmp := v; tmp > 0; tmp >>= 8 {
		raw = append([]byte{byte(tmp & 0xff)}, raw...)
	}
	if raw[0]&0x80 != 0 {
		raw = append([]byte{0x00}, raw...)
	}
	return derTLV(0x02, raw)
}

func derReadTLV(data []byte, offset int) (byte, []byte, int, error) {
	if offset+2 > len(data) {
		return 0, nil, 0, errors.New("der: truncated header")
	}
	tag := data[offset]
	l0 := data[offset+1]
	offset += 2

	var length int
	if l0 < 0x80 {
		length = int(l0)
	} else {
		nBytes := int(l0 & 0x7f)
		if nBytes == 0 || nBytes > 4 || offset+nBytes > len(data) {
			return 0, nil, 0, errors.New("der: invalid length encoding")
		}
		for i := range nBytes {
			length = (length << 8) | int(data[offset+i])
		}
		offset += nBytes
	}
	if offset+length > len(data) {
		return 0, nil, 0, errors.New("der: value exceeds buffer")
	}
	return tag, data[offset : offset+length], offset + length, nil
}

func readDERMessage(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	var (
		length   int
		lenBytes []byte
	)
	if hdr[1] < 0x80 {
		length = int(hdr[1])
		lenBytes = []byte{hdr[1]}
	} else {
		nBytes := int(hdr[1] & 0x7f)
		if nBytes == 0 || nBytes > 4 {
			return nil, fmt.Errorf("%w: invalid DER length prefix 0x%02x", ErrNotRDPService, hdr[1])
		}
		extra := make([]byte, nBytes)
		if _, err := io.ReadFull(r, extra); err != nil {
			return nil, err
		}
		for _, b := range extra {
			length = (length << 8) | int(b)
		}
		lenBytes = append([]byte{hdr[1]}, extra...)
	}
	if length <= 0 || length > maxDERMessageBytes {
		return nil, fmt.Errorf("%w: invalid DER payload length %d", ErrNotRDPService, length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(lenBytes)+len(body))
	out = append(out, hdr[0])
	out = append(out, lenBytes...)
	out = append(out, body...)
	return out, nil
}

// extractSubjectPublicKey parses an X.509 SubjectPublicKeyInfo SEQUENCE in DER
// form and returns the raw SubjectPublicKey BIT STRING payload (excluding the
// unused-bits byte) required by MS-CSSP pubKeyAuth verification.
func extractSubjectPublicKey(spkiDER []byte) ([]byte, error) {
	t, spkiBody, _, err := derReadTLV(spkiDER, 0)
	if err != nil || t != 0x30 {
		return nil, errors.New("x509: missing SubjectPublicKeyInfo")
	}
	// Skip algorithm SEQUENCE.
	_, _, spkiOff, err := derReadTLV(spkiBody, 0)
	if err != nil {
		return nil, err
	}
	// Read subjectPublicKey BIT STRING.
	t, bitString, _, err := derReadTLV(spkiBody, spkiOff)
	if err != nil || t != 0x03 || len(bitString) < 2 {
		return nil, errors.New("x509: missing SubjectPublicKey BIT STRING")
	}
	return bitString[1:], nil
}

type tsRequest struct {
	version      int
	negoToken    []byte
	pubKeyAuth   []byte
	hasErrorCode bool
	errorCode    uint32
	clientNonce  []byte
}

func buildTSRequest(version int, negoToken, pubKeyAuth, clientNonce []byte) []byte {
	var fields []byte
	fields = append(fields, derTLV(0xa0, derInt(version))...)
	if len(negoToken) > 0 {
		negoDataItem := derTLV(0x30, derTLV(0xa0, derTLV(0x04, negoToken)))
		fields = append(fields, derTLV(0xa1, derTLV(0x30, negoDataItem))...)
	}
	if len(pubKeyAuth) > 0 {
		fields = append(fields, derTLV(0xa3, derTLV(0x04, pubKeyAuth))...)
	}
	if len(clientNonce) > 0 {
		fields = append(fields, derTLV(0xa5, derTLV(0x04, clientNonce))...)
	}
	return derTLV(0x30, fields)
}

func parseTSRequest(data []byte) (tsRequest, error) {
	var req tsRequest
	tag, body, _, err := derReadTLV(data, 0)
	if err != nil || tag != 0x30 {
		return req, errors.New("credssp: expected TSRequest SEQUENCE")
	}
	for off := 0; off < len(body); {
		t, v, nextOff, err := derReadTLV(body, off)
		if err != nil {
			return req, err
		}
		off = nextOff
		switch t {
		case 0xa0:
			ivTag, iv, _, err := derReadTLV(v, 0)
			if err != nil || ivTag != 0x02 || len(iv) == 0 {
				return req, errors.New("credssp: invalid version")
			}
			ver := 0
			for _, b := range iv {
				ver = (ver << 8) | int(b)
			}
			req.version = ver
		case 0xa1:
			seqTag, seqOf, _, err := derReadTLV(v, 0)
			if err != nil || seqTag != 0x30 {
				return req, errors.New("credssp: invalid negoTokens")
			}
			itemTag, item, _, err := derReadTLV(seqOf, 0)
			if err != nil || itemTag != 0x30 {
				return req, errors.New("credssp: invalid NegoDataItem")
			}
			ctxTag, ctx0, _, err := derReadTLV(item, 0)
			if err != nil || ctxTag != 0xa0 {
				return req, errors.New("credssp: invalid negoToken tag")
			}
			octTag, octets, _, err := derReadTLV(ctx0, 0)
			if err != nil || octTag != 0x04 {
				return req, errors.New("credssp: invalid negoToken OCTET STRING")
			}
			req.negoToken = octets
		case 0xa3:
			octTag, octets, _, err := derReadTLV(v, 0)
			if err != nil || octTag != 0x04 {
				return req, errors.New("credssp: invalid pubKeyAuth")
			}
			req.pubKeyAuth = octets
		case 0xa4:
			intTag, iv, _, err := derReadTLV(v, 0)
			if err != nil || intTag != 0x02 || len(iv) == 0 {
				return req, errors.New("credssp: invalid errorCode")
			}
			var code uint32
			for _, b := range iv {
				code = (code << 8) | uint32(b)
			}
			req.hasErrorCode = true
			req.errorCode = code
		case 0xa5:
			octTag, octets, _, err := derReadTLV(v, 0)
			if err != nil || octTag != 0x04 {
				return req, errors.New("credssp: invalid clientNonce")
			}
			req.clientNonce = octets
		}
	}
	return req, nil
}

func classifyNTStatus(code uint32) error {
	switch code {
	case ntStatusAccountLockedOut,
		ntStatusAccountDisabled,
		ntStatusAccountExpired,
		ntStatusAccountRestriction,
		ntStatusPasswordExpired,
		ntStatusPasswordMustChange:
		return fmt.Errorf("%w: NTSTATUS 0x%08x", ErrAccountUnavailable, code)
	default:
		return fmt.Errorf("%w: NTSTATUS 0x%08x", ErrAuthFailed, code)
	}
}

// computeTLSChannelBindingsHash computes the 16-byte MS-NLMP MsvAvChannelBindings
// MD5 digest over SEC_CHANNEL_BINDINGS + RFC 5929 "tls-server-end-point:" hash
// of the server's leaf X.509 certificate.
func computeTLSChannelBindingsHash(cert *x509.Certificate) []byte {
	var certDigest []byte
	switch cert.SignatureAlgorithm {
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		sum := sha512.Sum512(cert.Raw)
		certDigest = sum[:]
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		sum := sha512.Sum384(cert.Raw)
		certDigest = sum[:]
	default:
		sum := sha256.Sum256(cert.Raw)
		certDigest = sum[:]
	}

	var gssHeader [20]byte
	binary.LittleEndian.PutUint32(gssHeader[16:20], uint32(len(tlsServerEndPointLabel)+len(certDigest)))
	cbt := md5Sum(gssHeader[:], tlsServerEndPointLabel, certDigest)
	return append([]byte(nil), cbt[:]...)
}

func wrapSPNEGONegTokenInit(ntlmNeg []byte) []byte {
	mechTypes := derTLV(0xa0, derTLV(0x30, ntlmsspOID))
	mechToken := derTLV(0xa2, derTLV(0x04, ntlmNeg))
	seqBody := append(mechTypes, mechToken...)
	choice := derTLV(0xa0, derTLV(0x30, seqBody))
	appBody := append(append([]byte(nil), spnegoOID...), choice...)
	return derTLV(0x60, appBody)
}

func wrapSPNEGONegTokenResp(ntlmAuth []byte) []byte {
	return derTLV(0xa1, derTLV(0x30, derTLV(0xa2, derTLV(0x04, ntlmAuth))))
}

func extractNTLMFromNegoToken(raw []byte) ([]byte, bool, bool) {
	if bytes.HasPrefix(raw, ntlmSignature) {
		return raw, false, true
	}
	if inner, ok := findNTLMOctetString(raw, 0); ok {
		return inner, true, true
	}
	return nil, false, false
}

func findNTLMOctetString(data []byte, depth int) ([]byte, bool) {
	if depth > 8 {
		return nil, false
	}
	for off := 0; off < len(data); {
		tag, val, nextOff, err := derReadTLV(data, off)
		if err != nil {
			return nil, false
		}
		off = nextOff
		if tag == 0x04 && bytes.HasPrefix(val, ntlmSignature) {
			return val, true
		}
		if tag == 0x60 {
			_, _, oidNext, err := derReadTLV(val, 0)
			if err == nil && oidNext < len(val) {
				if found, ok := findNTLMOctetString(val[oidNext:], depth+1); ok {
					return found, true
				}
			}
		} else if tag&0x20 != 0 {
			if found, ok := findNTLMOctetString(val, depth+1); ok {
				return found, true
			}
		}
	}
	return nil, false
}

func authenticateCredSSP(tlsConn *tls.Conn, targetHost, username, password, domain string, spnegoInit bool) error {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("%w: server presented no TLS certificate", ErrNotRDPService)
	}
	leafCert := state.PeerCertificates[0]
	serverPubKey, err := extractSubjectPublicKey(leafCert.RawSubjectPublicKeyInfo)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotRDPService, err)
	}
	cbtHash := computeTLSChannelBindingsHash(leafCert)

	// Step 1: Send TSRequest with NTLM NEGOTIATE token (raw or SPNEGO NegTokenInit).
	negMsg := buildNTLMNegotiate()
	step1Token := negMsg
	if spnegoInit {
		step1Token = wrapSPNEGONegTokenInit(negMsg)
	}
	tsReq1 := buildTSRequest(credSSPClientVersion, step1Token, nil, nil)
	if _, err := tlsConn.Write(tsReq1); err != nil {
		return fmt.Errorf("%w: writing CredSSP negotiate: %w", ErrNotRDPService, err)
	}

	// Step 2: Receive TSRequest with NTLM CHALLENGE token (raw or SPNEGO NegTokenResp).
	rawResp1, err := readDERMessage(tlsConn)
	if err != nil {
		return fmt.Errorf("%w: reading CredSSP challenge: %w", ErrNotRDPService, err)
	}
	resp1, err := parseTSRequest(rawResp1)
	if err != nil {
		return fmt.Errorf("%w: parsing CredSSP challenge: %w", ErrNotRDPService, err)
	}
	if resp1.hasErrorCode {
		return classifyNTStatus(resp1.errorCode)
	}
	ntlmChallenge, spnegoWrapped, ok := extractNTLMFromNegoToken(resp1.negoToken)
	if !ok {
		return fmt.Errorf("%w: unrecognized CredSSP negotiation token", ErrAuthUnsupported)
	}

	serverVersion := resp1.version
	if serverVersion <= 0 {
		serverVersion = 2
	}
	effVersion := min(credSSPClientVersion, serverVersion)

	authMsg, sess, err := buildNTLMAuthenticate(negMsg, ntlmChallenge, username, password, domain, targetHost, cbtHash)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthUnsupported, err)
	}

	// Step 3: Send NTLM AUTHENTICATE + sealed pubKeyAuth binding.
	var (
		clientNonce []byte
		pubKeyAuth  []byte
	)
	if effVersion >= 5 {
		clientNonce = make([]byte, 32)
		if _, err := rand.Read(clientNonce); err != nil { // NOMUTANTS -- CSPRNG entropy cannot be distinguished from fixed bytes by peers
			return fmt.Errorf("credssp: generating clientNonce: %w", err)
		}
		h := sha256.New()
		h.Write(credSSPC2SMagic)
		h.Write(clientNonce)
		h.Write(serverPubKey)
		pubKeyAuth = sess.seal(h.Sum(nil))
	} else {
		pubKeyAuth = sess.seal(serverPubKey)
	}

	step3Token := authMsg
	if spnegoInit || spnegoWrapped {
		step3Token = wrapSPNEGONegTokenResp(authMsg)
	}
	tsReq3 := buildTSRequest(effVersion, step3Token, pubKeyAuth, clientNonce)
	if _, err := tlsConn.Write(tsReq3); err != nil {
		return fmt.Errorf("%w: writing CredSSP authenticate: %w", ErrAuthFailed, err)
	}

	// Step 4: Read server's pubKeyAuth verification or errorCode/EOF rejection.
	rawResp2, err := readDERMessage(tlsConn)
	if err != nil {
		if !isDisconnectError(err) {
			return fmt.Errorf("%w: reading CredSSP auth response: %w", ErrNotRDPService, err)
		}
		// Standard CredSSP servers (including FreeRDP and older Windows) close
		// the TLS session immediately on invalid NTLMv2 credentials.
		return fmt.Errorf("%w: server rejected CredSSP authenticate: %w", ErrAuthFailed, err)
	}
	resp2, err := parseTSRequest(rawResp2)
	if err != nil {
		return fmt.Errorf("%w: parsing CredSSP auth response: %w", ErrAuthFailed, err)
	}
	if resp2.hasErrorCode {
		return classifyNTStatus(resp2.errorCode)
	}

	decrypted, macOK := sess.verifyAndUnseal(resp2.pubKeyAuth)
	if !macOK {
		return fmt.Errorf("%w: server pubKeyAuth MAC verification failed", ErrAuthFailed)
	}

	var expected []byte
	if effVersion >= 5 {
		h := sha256.New()
		h.Write(credSSPS2CMagic)
		h.Write(clientNonce)
		h.Write(serverPubKey)
		expected = h.Sum(nil)
	} else {
		expected = append([]byte(nil), serverPubKey...)
		expected[0]++
	}

	if subtle.ConstantTimeCompare(decrypted, expected) != 1 {
		return fmt.Errorf("%w: server pubKeyAuth binding hash mismatch", ErrAuthFailed)
	}
	return nil
}
