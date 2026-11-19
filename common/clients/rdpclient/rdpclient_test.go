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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/google/goonami-scanner/core/config"
	"google.golang.org/protobuf/proto"

	configpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func selfSignedTLSConfig(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() failed: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake-rdp.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() failed: %v", err)
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	pubKey, err := extractSubjectPublicKey(parsedCert.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatalf("extractSubjectPublicKey() failed: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, pubKey
}

func startFakeTCPServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				handler(conn)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func readClientX224ConnReq(conn net.Conn) error {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x03 || hdr[1] != 0x00 {
		return errors.New("invalid TPKT header")
	}
	pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if pktLen < 19 {
		return errors.New("TPKT too short")
	}
	body := make([]byte, pktLen-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return err
	}
	if int(body[0])+1 != len(body) || (body[1]&0xf0) != 0xe0 {
		return errors.New("invalid X.224 CR TPDU")
	}
	neg := body[len(body)-8:]
	if neg[0] != rdpNegReq || neg[1] != 0x00 || binary.LittleEndian.Uint16(neg[2:4]) != 8 || binary.LittleEndian.Uint32(neg[4:8]) == 0 {
		return errors.New("invalid RDP_NEG_REQ")
	}
	return nil
}

func sendX224Confirm(conn net.Conn, respType byte, val uint32) error {
	var body [15]byte
	body[0] = 14
	body[1] = 0xd0
	body[7] = respType
	body[8] = 0x00
	binary.LittleEndian.PutUint16(body[9:11], 8)
	binary.LittleEndian.PutUint32(body[11:15], val)

	var pkt [19]byte
	pkt[0] = 0x03
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 19)
	copy(pkt[4:], body[:])
	_, err := conn.Write(pkt[:])
	return err
}

func decodeUTF16LE(b []byte) string {
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}

type fakeCredSSPOpts struct {
	version                int
	protocol               uint32
	validCreds             map[string]string
	errorCodes             map[string]uint32
	tamperPubKey           bool
	tamperMAC              bool
	dropOnFail             bool
	noKeyExch              bool
	noRequestTarget        bool
	emptyChallenge         bool
	challengeErrorCode     uint32
	requireSPNEGO          bool
	spnegoChallengeOnly    bool
	requireEPA             bool
	omitServerVersion      bool
	omitChallengeTimestamp bool
	truncateChallengeTI    bool
	stallBeforeStep4       bool
}

func countAVPairs(ntResp []byte, wantID uint16) int {
	if len(ntResp) < 44 {
		return 0
	}
	ti := ntResp[44:]
	count := 0
	for off := 0; off+4 <= len(ti); {
		id := binary.LittleEndian.Uint16(ti[off : off+2])
		l := int(binary.LittleEndian.Uint16(ti[off+2 : off+4]))
		off += 4
		if off+l > len(ti) {
			return count
		}
		off += l
		if id == 0 {
			return count
		}
		if id == wantID {
			count++
		}
	}
	return count
}

func validateNTLMv2ClientBlob(blob []byte) bool {
	if len(blob) < 36 {
		return false
	}
	if !bytes.Equal(blob[0:8], []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0}) {
		return false
	}
	if !bytes.Equal(blob[24:28], []byte{0, 0, 0, 0}) {
		return false
	}
	ti := blob[28:]
	for off := 0; off+4 <= len(ti); {
		id := binary.LittleEndian.Uint16(ti[off : off+2])
		l := int(binary.LittleEndian.Uint16(ti[off+2 : off+4]))
		off += 4
		if off+l > len(ti) {
			return false
		}
		off += l
		if id == avIDEOL {
			return l == 0 && off+4 == len(ti) && bytes.Equal(ti[off:], []byte{0, 0, 0, 0})
		}
	}
	return false
}

func ntRespContainsAVPair(ntResp []byte, wantID uint16, wantVal []byte) bool {
	if len(ntResp) < 44 {
		return false
	}
	ti := ntResp[44:]
	for off := 0; off+4 <= len(ti); {
		id := binary.LittleEndian.Uint16(ti[off : off+2])
		l := int(binary.LittleEndian.Uint16(ti[off+2 : off+4]))
		off += 4
		if off+l > len(ti) {
			return false
		}
		val := ti[off : off+l]
		off += l
		if id == 0 {
			return false
		}
		if id == wantID && bytes.Equal(val, wantVal) {
			return true
		}
	}
	return false
}

func startFakeCredSSPServer(t *testing.T, opts fakeCredSSPOpts) string {
	t.Helper()
	tlsCfg, serverPubKey := selfSignedTLSConfig(t)
	certDER := tlsCfg.Certificates[0].Certificate[0]
	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	if opts.version == 0 {
		opts.version = 6
	}
	if opts.protocol == 0 {
		opts.protocol = protocolHybrid
	}

	return startFakeTCPServer(t, func(conn net.Conn) {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := readClientX224ConnReq(conn); err != nil {
			return
		}
		if err := sendX224Confirm(conn, rdpNegRsp, opts.protocol); err != nil {
			return
		}
		tlsConn := tls.Server(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		if tlsConn.ConnectionState().Version != tls.VersionTLS12 {
			return
		}
		raw1, err := readDERMessage(tlsConn)
		if err != nil {
			return
		}
		req1, err := parseTSRequest(raw1)
		if err != nil || len(req1.negoToken) < 12 || req1.pubKeyAuth != nil || req1.clientNonce != nil {
			return
		}
		if opts.requireSPNEGO && req1.negoToken[0] != 0x60 {
			return
		}
		neg1, _, negOK := extractNTLMFromNegoToken(req1.negoToken)
		if !negOK || len(neg1) < 40 || !bytes.Equal(neg1[0:8], ntlmSignature) || binary.LittleEndian.Uint32(neg1[8:12]) != 1 || binary.LittleEndian.Uint32(neg1[12:16]) == 0 || !bytes.Equal(neg1[32:40], ntlmVersion) {
			return
		}
		if opts.emptyChallenge {
			_, _ = tlsConn.Write(buildTSRequest(opts.version, nil, nil, nil))
			return
		}
		if opts.challengeErrorCode != 0 {
			var errInt [4]byte
			binary.BigEndian.PutUint32(errInt[:], opts.challengeErrorCode)
			fields := append(derTLV(0xa0, derInt(opts.version)), derTLV(0xa4, derTLV(0x02, append([]byte{0x00}, errInt[:]...)))...)
			_, _ = tlsConn.Write(derTLV(0x30, fields))
			return
		}

		// Build NTLM Type 2 CHALLENGE target info.
		srvChal := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
		const fixedSrvTimestamp uint64 = 133500000000000000
		var ti []byte
		switch {
		case opts.truncateChallengeTI:
			// Malformed AV_PAIR claiming length 100 inside an 8-byte buffer (no timestamp).
			ti = []byte{0x01, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00}
		case opts.omitChallengeTimestamp:
			// Valid AV_ID_FLAGS without AV_ID_TIMESTAMP, terminated by EOL.
			ti = []byte{0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		default:
			ti = make([]byte, 16)
			binary.LittleEndian.PutUint16(ti[0:2], avIDTimestamp)
			binary.LittleEndian.PutUint16(ti[2:4], 8)
			binary.LittleEndian.PutUint64(ti[4:12], fixedSrvTimestamp)
		}

		flags := ntlmNegotiateUnicode | ntlmNegotiateNTLM | ntlmNegotiateExtendedSessionSecurity |
			ntlmNegotiateSign | ntlmNegotiateSeal | ntlmNegotiate128
		if !opts.noRequestTarget {
			flags |= ntlmRequestTarget
		}
		if !opts.noKeyExch {
			flags |= ntlmNegotiateKeyExch
		}
		chal := make([]byte, 56+len(ti))
		copy(chal[0:8], ntlmSignature)
		binary.LittleEndian.PutUint32(chal[8:12], 2)
		binary.LittleEndian.PutUint32(chal[20:24], flags)
		copy(chal[24:32], srvChal)
		binary.LittleEndian.PutUint16(chal[40:42], uint16(len(ti)))
		binary.LittleEndian.PutUint16(chal[42:44], uint16(len(ti)))
		binary.LittleEndian.PutUint32(chal[44:48], 56)
		copy(chal[56:], ti)

		chalToken := chal
		if opts.spnegoChallengeOnly {
			chalToken = wrapSPNEGONegTokenResp(chal)
		}
		var tsChal []byte
		if opts.omitServerVersion {
			negoDataItem := derTLV(0x30, derTLV(0xa0, derTLV(0x04, chalToken)))
			tsChal = derTLV(0x30, derTLV(0xa1, derTLV(0x30, negoDataItem)))
		} else {
			tsChal = buildTSRequest(opts.version, chalToken, nil, nil)
		}
		if _, err := tlsConn.Write(tsChal); err != nil {
			return
		}

		raw2, err := readDERMessage(tlsConn)
		if err != nil {
			return
		}
		req2, err := parseTSRequest(raw2)
		wantVer := min(credSSPClientVersion, opts.version)
		if opts.omitServerVersion {
			wantVer = 2
		}
		if err != nil || len(req2.negoToken) == 0 || req2.version != wantVer {
			return
		}
		auth := req2.negoToken
		if opts.requireSPNEGO || opts.spnegoChallengeOnly {
			if auth[0] != 0xa1 {
				return
			}
			unwrapped, spnego, ok := extractNTLMFromNegoToken(auth)
			if !ok || !spnego {
				return
			}
			auth = unwrapped
		}
		if len(auth) < 88 ||
			!bytes.Equal(auth[0:8], ntlmSignature) ||
			binary.LittleEndian.Uint32(auth[8:12]) != 3 ||
			!bytes.Equal(auth[64:72], ntlmVersion) {
			return
		}
		wantAuthFlags := ntlmNegotiateUnicode | ntlmNegotiateSign | ntlmNegotiateSeal |
			ntlmNegotiateNTLM | ntlmNegotiateAlwaysSign | ntlmNegotiateExtendedSessionSecurity |
			ntlmNegotiateVersion | ntlmNegotiate128 | ntlmNegotiate56
		if !opts.noKeyExch {
			wantAuthFlags |= ntlmNegotiateKeyExch
		}
		if !opts.noRequestTarget {
			wantAuthFlags |= ntlmRequestTarget
		}
		if binary.LittleEndian.Uint32(auth[60:64]) != wantAuthFlags {
			return
		}
		readField := func(off int) []byte {
			l := int(binary.LittleEndian.Uint16(auth[off : off+2]))
			o := int(binary.LittleEndian.Uint32(auth[off+4 : off+8]))
			if o+l > len(auth) {
				return nil
			}
			return auth[o : o+l]
		}
		lmResp := readField(12)
		ntResp := readField(20)
		domBytes := readField(28)
		usrBytes := readField(36)
		wsBytes := readField(44)
		domStr := decodeUTF16LE(domBytes)
		userStr := decodeUTF16LE(usrBytes)
		wsStr := decodeUTF16LE(wsBytes)
		encKey := readField(52)
		wantAuthLen := 88 + len(lmResp) + len(ntResp) + len(domBytes) + len(usrBytes) + len(wsBytes) + len(encKey)
		wantKeyLen := 16
		if opts.noKeyExch {
			wantKeyLen = 0
		}
		if len(auth) != wantAuthLen || len(encKey) != wantKeyLen || len(lmResp) != 24 || wsStr != "GOONAMI" || len(ntResp) < 52 || !validateNTLMv2ClientBlob(ntResp[16:]) {
			return
		}

		if !opts.omitChallengeTimestamp && !opts.truncateChallengeTI {
			if len(ntResp) < 32 || binary.LittleEndian.Uint64(ntResp[24:32]) != fixedSrvTimestamp {
				return
			}
		}

		wantAVFlags := []byte{0x02, 0x00, 0x00, 0x00}
		if opts.omitChallengeTimestamp {
			wantAVFlags = []byte{0x03, 0x00, 0x00, 0x00}
		}
		if !ntRespContainsAVPair(ntResp, avIDFlags, wantAVFlags) {
			return
		}

		if opts.requireEPA {
			wantCBT := computeTLSChannelBindingsHash(leafCert)
			if domStr != "" ||
				!ntRespContainsAVPair(ntResp, avIDChannelBindings, wantCBT) ||
				!ntRespContainsAVPair(ntResp, avIDTargetName, encodeUTF16LE("TERMSRV/127.0.0.1")) {
				return
			}
		}

		if opts.stallBeforeStep4 {
			time.Sleep(400 * time.Millisecond)
			return
		}
		if code, ok := opts.errorCodes[userStr]; ok {
			var errInt [4]byte
			binary.BigEndian.PutUint32(errInt[:], code)
			fields := append(derTLV(0xa0, derInt(opts.version)), derTLV(0xa4, derTLV(0x02, append([]byte{0x00}, errInt[:]...)))...)
			_, _ = tlsConn.Write(derTLV(0x30, fields))
			return
		}

		wantPass, ok := opts.validCreds[userStr]
		if !ok || len(ntResp) < 16 {
			if !opts.dropOnFail {
				var errInt [4]byte
				binary.BigEndian.PutUint32(errInt[:], ntStatusLogonFailure)
				fields := append(derTLV(0xa0, derInt(opts.version)), derTLV(0xa4, derTLV(0x02, append([]byte{0x00}, errInt[:]...)))...)
				_, _ = tlsConn.Write(derTLV(0x30, fields))
			}
			return
		}

		// Verify NTLMv2 proof against wantPass.
		ntHash := md4Sum(encodeUTF16LE(wantPass))
		respKeyNT := hmacMD5(ntHash[:], encodeUTF16LE(strings.ToUpper(userStr)+domStr))
		ntProof := ntResp[:16]
		clientBlob := ntResp[16:]
		expectedProof := hmacMD5(respKeyNT[:], srvChal, clientBlob)
		if subtle.ConstantTimeCompare(ntProof, expectedProof[:]) != 1 {
			if !opts.dropOnFail {
				var errInt [4]byte
				binary.BigEndian.PutUint32(errInt[:], ntStatusLogonFailure)
				fields := append(derTLV(0xa0, derInt(opts.version)), derTLV(0xa4, derTLV(0x02, append([]byte{0x00}, errInt[:]...)))...)
				_, _ = tlsConn.Write(derTLV(0x30, fields))
			}
			return
		}

		sessionBaseKey := hmacMD5(respKeyNT[:], ntProof)
		var exportedKey []byte
		if !opts.noKeyExch {
			exportedKey = newRC4(sessionBaseKey[:]).xorKeyStream(encKey)
		} else {
			exportedKey = sessionBaseKey[:]
		}

		// Verify NTLMv2 MIC over (NEGOTIATE || CHALLENGE || AUTHENTICATE_zero_mic).
		authZero := append([]byte(nil), auth...)
		clear(authZero[72:88])
		wantMIC := hmacMD5(exportedKey, neg1, chal, authZero)
		if subtle.ConstantTimeCompare(auth[72:88], wantMIC[:]) != 1 {
			return
		}

		// Verify Client-To-Server pubKeyAuth binding under client NTLMv2 session keys.
		cSign := md5Sum(exportedKey, clientSignMagic)
		cSeal := md5Sum(exportedKey, clientSealMagic)
		cCipher := newRC4(cSeal[:])
		if len(req2.pubKeyAuth) < 16 {
			return
		}
		cPlain := cCipher.xorKeyStream(req2.pubKeyAuth[16:])
		var cSeq [4]byte
		cMAC := hmacMD5(cSign[:], cSeq[:], cPlain)
		cChk := cMAC[:8]
		if !opts.noKeyExch {
			cChk = cCipher.xorKeyStream(cChk)
		}
		var wantCSig [16]byte
		binary.LittleEndian.PutUint32(wantCSig[0:4], 1)
		copy(wantCSig[4:12], cChk)
		if subtle.ConstantTimeCompare(req2.pubKeyAuth[:16], wantCSig[:]) != 1 {
			return
		}

		sSign := md5Sum(exportedKey, serverSignMagic)
		sSeal := md5Sum(exportedKey, serverSealMagic)
		sCipher := newRC4(sSeal[:])

		effVer := min(opts.version, req2.version)
		var wantCPlain, respPlain []byte
		if effVer >= 5 {
			if len(req2.clientNonce) != 32 {
				return
			}
			hc := sha256.New()
			hc.Write(credSSPC2SMagic)
			hc.Write(req2.clientNonce)
			hc.Write(serverPubKey)
			wantCPlain = hc.Sum(nil)

			h := sha256.New()
			h.Write(credSSPS2CMagic)
			h.Write(req2.clientNonce)
			h.Write(serverPubKey)
			respPlain = h.Sum(nil)
		} else {
			if req2.clientNonce != nil {
				return
			}
			wantCPlain = serverPubKey
			respPlain = append([]byte(nil), serverPubKey...)
			respPlain[0]++
		}
		if subtle.ConstantTimeCompare(cPlain, wantCPlain) != 1 {
			return
		}
		if opts.tamperPubKey {
			respPlain[0] ^= 0xff
		}

		ct := sCipher.xorKeyStream(respPlain)
		var seq [4]byte
		mac := hmacMD5(sSign[:], seq[:], respPlain)
		chk := mac[:8]
		if !opts.noKeyExch {
			chk = sCipher.xorKeyStream(chk)
		}
		if opts.tamperMAC {
			chk[0] ^= 0xff
		}
		sealed := make([]byte, 16+len(ct))
		binary.LittleEndian.PutUint32(sealed[0:4], 1)
		copy(sealed[4:12], chk)
		copy(sealed[16:], ct)

		_, _ = tlsConn.Write(buildTSRequest(opts.version, nil, sealed, nil))
	})
}

type fakeTLSServerMode int

const (
	fakeTLSInlineAuth fakeTLSServerMode = iota
	fakeTLSNoAuthSaveSessionInfo
	fakeTLSLoginScreenGreeter
	fakeTLSXrdpLicenseRequest
	fakeTLSFastPathThenSaveSessionInfo
	fakeTLSFastPathThenLogonError
)

func sendMCSIndication(conn net.Conn, payload []byte) error {
	var buf bytes.Buffer
	buf.WriteByte(0x68) // SendDataIndication
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1003))
	buf.WriteByte(0x70)
	buf.Write(encodePERLength(len(payload)))
	buf.Write(payload)
	return writeTPKT(conn, buf.Bytes())
}

func startFakeNonNLATLSServer(t *testing.T, mode fakeTLSServerMode, validCreds map[string]string) string {
	t.Helper()
	tlsCfg, _ := selfSignedTLSConfig(t)

	return startFakeTCPServer(t, func(conn net.Conn) {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := readClientX224ConnReq(conn); err != nil {
			return
		}
		if err := sendX224Confirm(conn, rdpNegRsp, protocolSSL); err != nil {
			return
		}
		tlsConn := tls.Server(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		if tlsConn.ConnectionState().Version != tls.VersionTLS12 {
			return
		}
		// Read MCS Connect-Initial.
		if _, err := readTPKT(tlsConn); err != nil {
			return
		}
		// Exercise SC_NET ioChannel=1007 (0x03ef), missing SC_NET fallback (1003), and truncated SC_NET fallback (1003).
		expectedIOCh := uint16(1007)
		cr := []byte{0x7f, 0x66, 0x08, 0x03, 0x0c, 0x08, 0x00, 0xef, 0x03, 0x00, 0x00}
		switch mode {
		case fakeTLSNoAuthSaveSessionInfo:
			expectedIOCh = 1003
			cr = []byte{0x7f, 0x66, 0x03, 0x03, 0x0c}
		case fakeTLSFastPathThenSaveSessionInfo:
			expectedIOCh = 1003
			cr = []byte{0x7f, 0x66, 0x01, 0x00}
		}
		if err := writeTPKT(tlsConn, cr); err != nil {
			return
		}
		// Read Erect Domain + Attach User and verify exact wire bytes.
		edBody, err := readTPKT(tlsConn)
		if err != nil || !bytes.Equal(edBody, []byte{0x02, 0xf0, 0x80, 0x04, 0x01, 0x00, 0x01, 0x00}) {
			return
		}
		auBody, err := readTPKT(tlsConn)
		if err != nil || !bytes.Equal(auBody, []byte{0x02, 0xf0, 0x80, 0x28}) {
			return
		}
		// Attach User Confirm: userId = 1004 (initiator=3).
		if err := writeTPKT(tlsConn, []byte{0x2e, 0x00, 0x00, 0x03}); err != nil {
			return
		}
		// Channel Join Requests (userId=1004 -> initiator=3, ioChannel=expectedIOCh).
		wantChannels := []uint16{1004, expectedIOCh}
		for _, wantCh := range wantChannels {
			cjBody, err := readTPKT(tlsConn)
			wantCJ := []byte{0x02, 0xf0, 0x80, 0x38, 0x00, 0x03, byte(wantCh >> 8), byte(wantCh)}
			if err != nil || !bytes.Equal(cjBody, wantCJ) {
				return
			}
			if err := writeTPKT(tlsConn, []byte{0x3e, 0x00, 0x00, 0x03, byte(wantCh >> 8), byte(wantCh), byte(wantCh >> 8), byte(wantCh)}); err != nil {
				return
			}
		}
		// Read Client Info PDU and parse username + password from TS_INFO_PACKET.
		infoBody, err := readTPKT(tlsConn)
		if err != nil || len(infoBody) < 12 || infoBody[3] != 0x64 ||
			binary.BigEndian.Uint16(infoBody[4:6]) != 3 ||
			binary.BigEndian.Uint16(infoBody[6:8]) != expectedIOCh {
			return
		}
		// MCS SendDataRequest (0x64) offset: 3(x224) + 1(0x64) + 2(init) + 2(ch) + 1(0x70) + perLen
		off := 9
		if infoBody[off]&0x80 != 0 {
			off += 2
		} else {
			off++
		}
		rdpInfo := infoBody[off:]
		if len(rdpInfo) < 22 {
			return
		}
		// Skip 4-byte security header + 8-byte codePage/flags.
		cbDom := int(binary.LittleEndian.Uint16(rdpInfo[12:14]))
		cbUsr := int(binary.LittleEndian.Uint16(rdpInfo[14:16]))
		cbPwd := int(binary.LittleEndian.Uint16(rdpInfo[16:18]))
		cur := 22 + cbDom + 2
		userStr := decodeUTF16LE(rdpInfo[cur : cur+cbUsr])
		cur += cbUsr + 2
		passStr := decodeUTF16LE(rdpInfo[cur : cur+cbPwd])

		if mode == fakeTLSXrdpLicenseRequest {
			licReq := []byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x10, 0x00}
			_ = sendMCSIndication(tlsConn, licReq)
			return
		}

		// Send STATUS_VALID_CLIENT license alert, an ignored non-DemandActive PDU, and a 140-byte
		// (0x008c, bit 0x0080 set) Demand Active PDU so totalLength & secLicensePkt != 0 never
		// collides with TS_SECURITY_HEADER (flagsHi == 0).
		validClient := []byte{0x80, 0x00, 0x00, 0x00, 0xff, 0x03, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00}
		if err := sendMCSIndication(tlsConn, validClient); err != nil {
			return
		}
		preData := make([]byte, 18)
		binary.LittleEndian.PutUint16(preData[0:2], 18)
		binary.LittleEndian.PutUint16(preData[2:4], pduTypeData|(1<<4))
		binary.LittleEndian.PutUint16(preData[4:6], 1002)
		binary.LittleEndian.PutUint32(preData[6:10], 0xdeadbeef)
		if err := sendMCSIndication(tlsConn, preData); err != nil {
			return
		}
		demandActive := make([]byte, 140)
		binary.LittleEndian.PutUint16(demandActive[0:2], 140)
		binary.LittleEndian.PutUint16(demandActive[2:4], pduTypeDemandActive|(1<<4))
		binary.LittleEndian.PutUint16(demandActive[4:6], 1002)
		binary.LittleEndian.PutUint32(demandActive[6:10], 0x103ec)
		if err := sendMCSIndication(tlsConn, demandActive); err != nil {
			return
		}

		// Read Confirm Active + Synchronize + Control(2) + Font List (5 PDUs) and verify PDU types & shareID.
		wantPostDemand := []byte{
			byte(pduTypeConfirmActive),
			pduType2Synchronize,
			pduType2Control,
			pduType2Control,
			pduType2FontList,
		}
		for idx, wantType := range wantPostDemand {
			pkt, err := readTPKT(tlsConn)
			if err != nil || len(pkt) < 16 || pkt[3] != 0x64 {
				return
			}
			pOff := 9
			if pkt[pOff]&0x80 != 0 {
				pOff += 2
			} else {
				pOff++
			}
			rdp := pkt[pOff:]
			if idx == 0 {
				if len(rdp) < 10 || (binary.LittleEndian.Uint16(rdp[2:4])&0x000f) != uint16(wantType) ||
					binary.LittleEndian.Uint32(rdp[6:10]) != 0x103ec {
					return
				}
			} else {
				if len(rdp) < 19 || (binary.LittleEndian.Uint16(rdp[2:4])&0x000f) != pduTypeData ||
					binary.LittleEndian.Uint32(rdp[6:10]) != 0x103ec || rdp[14] != wantType {
					return
				}
			}
		}

		// Send Font Map PDU (0x28).
		fontMap := make([]byte, 18)
		binary.LittleEndian.PutUint16(fontMap[0:2], 18)
		binary.LittleEndian.PutUint16(fontMap[2:4], pduTypeData|(1<<4))
		binary.LittleEndian.PutUint16(fontMap[4:6], 1002)
		binary.LittleEndian.PutUint32(fontMap[6:10], 0x103ec)
		fontMap[14] = pduType2FontMap
		if err := sendMCSIndication(tlsConn, fontMap); err != nil {
			return
		}

		switch mode {
		case fakeTLSInlineAuth:
			if wantPass, ok := validCreds[userStr]; ok && wantPass == passStr {
				// Emit benign ERRINFO_NONE (0x00000000) SetErrorInfo PDU followed by FastPath Output.
				errNone := make([]byte, 22)
				binary.LittleEndian.PutUint16(errNone[0:2], 22)
				binary.LittleEndian.PutUint16(errNone[2:4], pduTypeData|(1<<4))
				binary.LittleEndian.PutUint16(errNone[4:6], 1002)
				binary.LittleEndian.PutUint32(errNone[6:10], 0x103ec)
				errNone[14] = pduType2SetErrorInfo
				_ = sendMCSIndication(tlsConn, errNone)
				_, _ = tlsConn.Write([]byte{0x00, 0x06, 0x01, 0x00, 0x00, 0x00})
			}
			// Rejected: close connection immediately after Font Map.
		case fakeTLSNoAuthSaveSessionInfo:
			// Emit PDUTYPE2_SAVE_SESSION_INFO with INFOTYPE_LOGON_PLAINNOTIFY (0x02).
			ssi := make([]byte, 22)
			binary.LittleEndian.PutUint16(ssi[0:2], 22)
			binary.LittleEndian.PutUint16(ssi[2:4], pduTypeData|(1<<4))
			binary.LittleEndian.PutUint16(ssi[4:6], 1002)
			binary.LittleEndian.PutUint32(ssi[6:10], 0x103ec)
			ssi[14] = pduType2SaveSessionInfo
			binary.LittleEndian.PutUint32(ssi[18:22], infoTypeLogonPlainNotify)
			_ = sendMCSIndication(tlsConn, ssi)
		case fakeTLSLoginScreenGreeter:
			// Emit FastPath Output login box even for invalid credentials (no SaveSessionInfo).
			_, _ = tlsConn.Write([]byte{0x00, 0x06, 0x01, 0x00, 0x00, 0x00})
		case fakeTLSFastPathThenSaveSessionInfo:
			// Use 2-byte FastPath length header (l1 = 0x80 | 0, l2 = 7).
			_, _ = tlsConn.Write([]byte{0x00, 0x80, 0x07, 0x01, 0x00, 0x00, 0x00})
			ssi := make([]byte, 22)
			binary.LittleEndian.PutUint16(ssi[0:2], 22)
			binary.LittleEndian.PutUint16(ssi[2:4], pduTypeData|(1<<4))
			binary.LittleEndian.PutUint16(ssi[4:6], 1002)
			binary.LittleEndian.PutUint32(ssi[6:10], 0x103ec)
			ssi[14] = pduType2SaveSessionInfo
			binary.LittleEndian.PutUint32(ssi[18:22], infoTypeLogonPlainNotify)
			_ = sendMCSIndication(tlsConn, ssi)
		case fakeTLSFastPathThenLogonError:
			_, _ = tlsConn.Write([]byte{0x00, 0x06, 0x01, 0x00, 0x00, 0x00})
			if wantPass, ok := validCreds[userStr]; !ok || wantPass != passStr {
				errPDU := make([]byte, 22)
				binary.LittleEndian.PutUint16(errPDU[0:2], 22)
				binary.LittleEndian.PutUint16(errPDU[2:4], pduTypeData|(1<<4))
				binary.LittleEndian.PutUint16(errPDU[4:6], 1002)
				binary.LittleEndian.PutUint32(errPDU[6:10], 0x103ec)
				errPDU[14] = pduType2SetErrorInfo
				binary.LittleEndian.PutUint32(errPDU[18:22], 0x00000009)
				_ = sendMCSIndication(tlsConn, errPDU)
			}
		}
	})
}

func fastClient() *Client {
	return New(config.FromProto(configpb.Config_builder{
		Globalcfg: configpb.GlobalConfig_builder{
			Performance: configpb.GlobalConfig_Performance_builder{
				TimeoutPerRequestSeconds: proto.Int32(2),
			}.Build(),
		}.Build(),
	}.Build()))
}

func TestCryptoVectors(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "when_md4_empty_utf16le_matches_nt_empty_hash",
			got:  hex.EncodeToString(func() []byte { s := md4Sum(encodeUTF16LE("")); return s[:] }()),
			want: "31d6cfe0d16ae931b73c59d7e0c089c0",
		},
		{
			name: "when_md4_password_utf16le_matches_nt_hash",
			got:  hex.EncodeToString(func() []byte { s := md4Sum(encodeUTF16LE("password")); return s[:] }()),
			want: "8846f7eaee8fb117ad06bdd830b7586c",
		},
		{
			name: "when_md5_rfc1321_abc_matches_vector",
			got:  hex.EncodeToString(func() []byte { s := md5Sum([]byte("abc")); return s[:] }()),
			want: "900150983cd24fb0d6963f7d28e17f72",
		},
		{
			name: "when_hmac_md5_rfc2202_vector_matches",
			got:  hex.EncodeToString(func() []byte { s := hmacMD5([]byte("Jefe"), []byte("what do ya want for nothing?")); return s[:] }()),
			want: "750c783e6ab0b503eaa86e310a5db738",
		},
		{
			name: "when_hmac_md5_long_key_hashes_key_first",
			got: hex.EncodeToString(func() []byte {
				key := bytes.Repeat([]byte{0xaa}, 80)
				s := hmacMD5(key, []byte("Test Using Larger Than Block-Size Key - Hash Key First"))
				return s[:]
			}()),
			want: "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
		},
		{
			name: "when_der_encode_length_three_bytes_encodes_big_endian",
			got:  hex.EncodeToString(derEncodeLength(0x010203)),
			want: "83010203",
		},
		{
			name: "when_der_encode_length_boundaries_preserve_minimal_byte_widths",
			got: hex.EncodeToString(bytes.Join([][]byte{
				derEncodeLength(0x7f),
				derEncodeLength(0x80),
				derEncodeLength(0xff),
				derEncodeLength(0x0100),
				derEncodeLength(0xffff),
				derEncodeLength(0xffffff),
			}, nil)),
			want: "7f818081ff82010082ffff83ffffff",
		},
		{
			name: "when_der_encode_length_four_bytes_encodes_big_endian",
			got:  hex.EncodeToString(derEncodeLength(0x01020304)),
			want: "8401020304",
		},
		{
			name: "when_der_int_positive_msb_clear_omits_leading_zero",
			got:  hex.EncodeToString(derInt(0x7f)),
			want: "02017f",
		},
		{
			name: "when_der_int_positive_msb_set_prepends_leading_zero",
			got:  hex.EncodeToString(derInt(0x80)),
			want: "02020080",
		},
		{
			name: "when_build_ts_request_omits_nil_nego_token_and_nonce",
			got:  hex.EncodeToString(buildTSRequest(6, nil, []byte{0xaa}, nil)),
			want: "300aa003020106a3030401aa",
		},
		{
			name: "when_build_ts_request_omits_nil_pubkey_auth",
			got:  hex.EncodeToString(buildTSRequest(6, []byte{0xbb}, nil, []byte{0xcc})),
			want: "3015a003020106a10930073005a0030401bba5030401cc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("digest = %s, want %s", tc.got, tc.want)
			}
		})
	}
}

func TestNewAndTimeout(t *testing.T) {
	tests := []struct {
		name string
		c    *Client
		want time.Duration
	}{
		{
			name: "when_config_is_nil_uses_default_timeout",
			c:    New(nil),
			want: DefaultTimeout,
		},
		{
			name: "when_client_is_nil_uses_default_timeout",
			c:    nil,
			want: DefaultTimeout,
		},
		{
			name: "when_client_has_zero_timeout_uses_default_timeout",
			c:    &Client{},
			want: DefaultTimeout,
		},
		{
			name: "when_global_timeout_configured_uses_configured_timeout",
			c:    fastClient(),
			want: 2 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.Timeout(); got != tc.want {
				t.Errorf("Timeout() = %v, want %v", got, tc.want)
			}
		})
	}

	if got := targetHostFromAddr("rdp-host.internal"); got != "rdp-host.internal" {
		t.Errorf("targetHostFromAddr(bare) = %q, want rdp-host.internal", got)
	}
	if got := targetHostFromAddr("127.0.0.1:3389"); got != "127.0.0.1" {
		t.Errorf("targetHostFromAddr(hostport) = %q, want 127.0.0.1", got)
	}

	if u, d := splitUserDomain("admin"); u != "admin" || d != "" {
		t.Errorf("splitUserDomain(bare) = (%q, %q), want (admin, \"\")", u, d)
	}
	if u, d := splitUserDomain(".\\admin"); u != "admin" || d != "" {
		t.Errorf("splitUserDomain(local) = (%q, %q), want (admin, \"\")", u, d)
	}
	if u, d := splitUserDomain("CORP\\admin"); u != "admin" || d != "CORP" {
		t.Errorf("splitUserDomain(domain) = (%q, %q), want (admin, CORP)", u, d)
	}

	// Verify exact RFC 5929 + SEC_CHANNEL_BINDINGS MD5 digests across SHA-256, SHA-384, and SHA-512.
	c256 := hex.EncodeToString(computeTLSChannelBindingsHash(&x509.Certificate{Raw: []byte("cert-der"), SignatureAlgorithm: x509.ECDSAWithSHA256}))
	c384 := hex.EncodeToString(computeTLSChannelBindingsHash(&x509.Certificate{Raw: []byte("cert-der"), SignatureAlgorithm: x509.ECDSAWithSHA384}))
	c512 := hex.EncodeToString(computeTLSChannelBindingsHash(&x509.Certificate{Raw: []byte("cert-der"), SignatureAlgorithm: x509.ECDSAWithSHA512}))
	if c256 != "6590a2d957ea153ffed9ee611c656a64" || c384 != "cc80b0632f5f2a00e2e647fa3a28814a" || c512 != "af9ca4c1dc2f5d03729279790ee6daae" {
		t.Errorf("computeTLSChannelBindingsHash vectors = (%s, %s, %s)", c256, c384, c512)
	}

	// Verify NTSTATUS classification across all account restriction/expiry/lockout codes.
	for _, code := range []uint32{
		ntStatusAccountLockedOut,
		ntStatusAccountDisabled,
		ntStatusAccountExpired,
		ntStatusAccountRestriction,
		ntStatusPasswordExpired,
		ntStatusPasswordMustChange,
	} {
		if err := classifyNTStatus(code); !errors.Is(err, ErrAccountUnavailable) {
			t.Errorf("classifyNTStatus(0x%08x) = %v, want %v", code, err, ErrAccountUnavailable)
		}
	}
	if err := classifyNTStatus(ntStatusLogonFailure); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("classifyNTStatus(logonFailure) = %v, want %v", err, ErrAuthFailed)
	}
}

func TestProtocolEdgeCases(t *testing.T) {
	t.Run("when_write_tpkt_frames_x224_data_emits_exact_header_and_length", func(t *testing.T) {
		var buf bytes.Buffer
		if err := writeTPKT(&buf, []byte{0xaa, 0xbb}); err != nil {
			t.Fatalf("writeTPKT() error: %v", err)
		}
		want := []byte{0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0xaa, 0xbb}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("writeTPKT() = %x, want %x", buf.Bytes(), want)
		}
		if _, err := readTPKT(bytes.NewReader([]byte{0x04, 0x00, 0x00, 0x04})); err == nil {
			t.Errorf("readTPKT(version=4, len=4) = nil, want error")
		}
		if _, err := readTPKT(bytes.NewReader([]byte{0x03, 0x00, 0x00, 0x03})); err == nil {
			t.Errorf("readTPKT(len=3) = nil, want error")
		}
		eofC, eofS := net.Pipe()
		go func() {
			_, _ = readTPKT(eofS)
			_ = eofS.Close()
		}()
		_, x224Err := x224Negotiate(eofC, protocolSSL|protocolHybrid)
		_ = eofC.Close()
		if !errors.Is(x224Err, ErrNotRDPService) || !errors.Is(x224Err, io.EOF) {
			t.Errorf("x224Negotiate(EOF) = %v, want ErrNotRDPService + io.EOF", x224Err)
		}
	})

	t.Run("when_x224_confirm_violates_each_header_invariant_rejects_independently", func(t *testing.T) {
		invalidTPKTs := [][]byte{
			// Clause 1: len(body) == 6 (< 7), valid 0xd0 and LI=5.
			{0x03, 0x00, 0x00, 0x0a, 0x05, 0xd0, 0, 0, 0, 0},
			// Clause 2: len(body) == 8 (>= 7), invalid TPDU code 0xe0 (!= 0xd0), LI=7.
			{0x03, 0x00, 0x00, 0x0c, 0x07, 0xe0, 0, 0, 0, 0, 0, 0},
			// Clause 3: len(body) == 8 (>= 7), valid 0xd0, invalid LI=20 (20+1 > 8).
			{0x03, 0x00, 0x00, 0x0c, 0x14, 0xd0, 0, 0, 0, 0, 0, 0},
			// rdpNegData length != 8 (9 instead of 8).
			{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0, 0, 0, 0x02, 0, 0x09, 0, 0x02, 0, 0, 0},
		}
		for i, resp := range invalidTPKTs {
			cConn, sConn := net.Pipe()
			go func(pkt []byte) {
				defer sConn.Close()
				_, _ = readTPKT(sConn)
				_, _ = sConn.Write(pkt)
			}(resp)
			_, err := x224Negotiate(cConn, protocolSSL|protocolHybrid)
			_ = cConn.Close()
			if !errors.Is(err, ErrNotRDPService) {
				t.Errorf("case %d: x224Negotiate() = %v, want %v", i, err, ErrNotRDPService)
			}
		}
	})

	t.Run("when_ntlm_challenge_has_empty_or_exact_target_info_parses_bounds_accurately", func(t *testing.T) {
		neg := buildNTLMNegotiate()
		// Reject truncated or invalid challenge headers and out-of-bounds targetInfo.
		if _, _, err := buildNTLMAuthenticate(neg, make([]byte, 47), "admin", "p", "", "h", nil); err == nil {
			t.Errorf("buildNTLMAuthenticate(len=47) = nil, want error")
		}
		badSig := make([]byte, 48)
		binary.LittleEndian.PutUint32(badSig[8:12], 2)
		if _, _, err := buildNTLMAuthenticate(neg, badSig, "admin", "p", "", "h", nil); err == nil {
			t.Errorf("buildNTLMAuthenticate(bad sig) = nil, want error")
		}
		badType := make([]byte, 48)
		copy(badType[0:8], ntlmSignature)
		binary.LittleEndian.PutUint32(badType[8:12], 3)
		if _, _, err := buildNTLMAuthenticate(neg, badType, "admin", "p", "", "h", nil); err == nil {
			t.Errorf("buildNTLMAuthenticate(type=3) = nil, want error")
		}
		oobTI := make([]byte, 48)
		copy(oobTI[0:8], ntlmSignature)
		binary.LittleEndian.PutUint32(oobTI[8:12], 2)
		binary.LittleEndian.PutUint16(oobTI[40:42], 16)
		binary.LittleEndian.PutUint32(oobTI[44:48], 40)
		if _, _, err := buildNTLMAuthenticate(neg, oobTI, "admin", "p", "", "h", nil); err == nil {
			t.Errorf("buildNTLMAuthenticate(oob TI) = nil, want error")
		}

		// Case A: tiLen == 0 with arbitrary non-zero tiOff (9999) and targetHost == "" must omit MsvAvTargetName.
		chalEmptyTI := make([]byte, 56)
		copy(chalEmptyTI[0:8], ntlmSignature)
		binary.LittleEndian.PutUint32(chalEmptyTI[8:12], 2)
		binary.LittleEndian.PutUint16(chalEmptyTI[40:42], 0)
		binary.LittleEndian.PutUint32(chalEmptyTI[44:48], 9999)
		authEmptyHost, _, err := buildNTLMAuthenticate(neg, chalEmptyTI, "admin", "pass", "", "", nil)
		if err != nil {
			t.Fatalf("buildNTLMAuthenticate(tiLen=0, targetHost=\"\") unexpected error: %v", err)
		}
		ntLenA := binary.LittleEndian.Uint16(authEmptyHost[20:22])
		ntOffA := binary.LittleEndian.Uint32(authEmptyHost[24:28])
		if countAVPairs(authEmptyHost[ntOffA:ntOffA+uint32(ntLenA)], avIDTargetName) != 0 {
			t.Errorf("buildNTLMAuthenticate(targetHost=\"\") emitted unexpected MsvAvTargetName")
		}

		// Case B: server TI already has MsvAvTargetName + placeholder MsvAvChannelBindings + 4-byte timestamp + 8-byte non-timestamp AV_PAIR ("SRVR").
		nbVal := encodeUTF16LE("SRVR")
		existingSPN := encodeUTF16LE("TERMSRV/existing.local")
		var tiExact []byte
		tiExact = append(tiExact, 0x09, 0x00, byte(len(existingSPN)), 0x00)
		tiExact = append(tiExact, existingSPN...)
		tiExact = append(tiExact, 0x0a, 0x00, 16, 0x00)
		tiExact = append(tiExact, make([]byte, 16)...)
		tiExact = append(tiExact, 0x07, 0x00, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44)
		tiExact = append(tiExact, 0x01, 0x00, byte(len(nbVal)), 0x00)
		tiExact = append(tiExact, nbVal...)

		chalExact := make([]byte, 56+len(tiExact))
		copy(chalExact[0:8], ntlmSignature)
		binary.LittleEndian.PutUint32(chalExact[8:12], 2)
		binary.LittleEndian.PutUint16(chalExact[40:42], uint16(len(tiExact)))
		binary.LittleEndian.PutUint32(chalExact[44:48], 56)
		copy(chalExact[56:], tiExact)

		cbt := bytes.Repeat([]byte{0xab}, 16)
		auth, _, err := buildNTLMAuthenticate(neg, chalExact, "admin", "pass", "", "other.local", cbt)
		if err != nil {
			t.Fatalf("buildNTLMAuthenticate(exact TI) error: %v", err)
		}
		ntLen := binary.LittleEndian.Uint16(auth[20:22])
		ntOff := binary.LittleEndian.Uint32(auth[24:28])
		ntField := auth[ntOff : ntOff+uint32(ntLen)]
		if !ntRespContainsAVPair(ntField, 0x0001, nbVal) ||
			binary.LittleEndian.Uint64(ntField[24:32]) < 130000000000000000 ||
			countAVPairs(ntField, avIDTargetName) != 1 ||
			!ntRespContainsAVPair(ntField, avIDTargetName, existingSPN) ||
			countAVPairs(ntField, avIDChannelBindings) != 1 ||
			!ntRespContainsAVPair(ntField, avIDChannelBindings, cbt) ||
			!validateNTLMv2ClientBlob(ntField[16:]) {
			t.Errorf("buildNTLMAuthenticate(exact TI) failed AV_PAIR deduplication or client blob validation")
		}
	})

	t.Run("when_rdp_per_and_mcs_pdu_builders_encode_frames_match_wire_vectors", func(t *testing.T) {
		if !bytes.Equal(encodePERLength(0x7f), []byte{0x7f}) ||
			!bytes.Equal(encodePERLength(0x80), []byte{0x80, 0x80}) ||
			!bytes.Equal(encodePERLength(0x0105), []byte{0x81, 0x05}) {
			t.Errorf("encodePERLength boundary mismatch")
		}

		shaHex := func(b []byte) string {
			s := sha256.Sum256(b)
			return hex.EncodeToString(s[:])
		}
		if got := shaHex(buildMCSConnectInitial(protocolSSL)); got != "b71da87efb42ec04a5218827b7b7bfd59d0e43d28399b8065bb055991919d61f" {
			t.Errorf("buildMCSConnectInitial digest = %s", got)
		}
		if got := shaHex(buildClientInfoPDU("admin", "password", "CORP")); got != "ac9c3f1df2cb8e07b5bd01b07c018281cfb6b1582ea5afb0385a81989c238225" {
			t.Errorf("buildClientInfoPDU(auth) digest = %s", got)
		}
		if got := shaHex(buildClientInfoPDU("", "", "")); got != "7711b451bf5598c9b2097163ca784ca30472fea20c5a6c79f444ccf5a7bb8d1f" {
			t.Errorf("buildClientInfoPDU(empty) digest = %s", got)
		}
		ciUserOnly := buildClientInfoPDU("admin", "", "")
		ciPassOnly := buildClientInfoPDU("", "password", "")
		ciNeither := buildClientInfoPDU("", "", "")
		if binary.LittleEndian.Uint32(ciUserOnly[8:12])&infoAutoLogon == 0 ||
			binary.LittleEndian.Uint32(ciPassOnly[8:12])&infoAutoLogon == 0 ||
			binary.LittleEndian.Uint32(ciNeither[8:12])&infoAutoLogon != 0 {
			t.Errorf("buildClientInfoPDU infoAutoLogon flag mismatch")
		}
		if got := shaHex(buildConfirmActivePDU(1004, 0x103ec)); got != "8541e7cc8cdaea5467f4a3aca5616f8118f823dc1a61d1a0003497306a25ae04" {
			t.Errorf("buildConfirmActivePDU digest = %s", got)
		}

		var shareBuf bytes.Buffer
		if err := sendShareDataPDU(&shareBuf, 1004, 1007, 0x103ec, pduType2Synchronize, []byte{0x01, 0x00, 0xea, 0x03}); err != nil {
			t.Fatalf("sendShareDataPDU() error: %v", err)
		}
		wantShare := []byte{
			0x03, 0x00, 0x00, 0x24, 0x02, 0xf0, 0x80,
			0x64, 0x00, 0x03, 0x03, 0xef, 0x70, 0x16,
			0x16, 0x00, 0x17, 0x00, 0xec, 0x03, 0xec, 0x03, 0x01, 0x00,
			0x00, 0x01, 0x08, 0x00, 0x1f, 0x00, 0x00, 0x00,
			0x01, 0x00, 0xea, 0x03,
		}
		if !bytes.Equal(shareBuf.Bytes(), wantShare) {
			t.Errorf("sendShareDataPDU() = %x, want %x", shareBuf.Bytes(), wantShare)
		}

		var ssi [22]byte
		binary.LittleEndian.PutUint32(ssi[18:], infoTypeLogonExtendedInf)
		if !isLogonSaveSessionInfo(ssi[:]) || isLogonSaveSessionInfo(ssi[:21]) {
			t.Errorf("isLogonSaveSessionInfo(infoType=3) failed")
		}
		binary.LittleEndian.PutUint32(ssi[18:], infoTypeLogonExtendedInf+1)
		if isLogonSaveSessionInfo(ssi[:]) {
			t.Errorf("isLogonSaveSessionInfo(infoType=4) = true, want false")
		}
	})
}

func TestCredSSPProbeAndAuthenticate(t *testing.T) {
	tests := []struct {
		name     string
		opts     fakeCredSSPOpts
		user     string
		pass     string
		wantMode AuthMode
		wantErr  error
	}{
		{
			name:     "when_credssp_v6_weak_password_valid_returns_nil",
			opts:     fakeCredSSPOpts{version: 6, validCreds: map[string]string{"admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSP,
		},
		{
			name:     "when_credssp_v6_empty_password_valid_returns_nil",
			opts:     fakeCredSSPOpts{version: 6, validCreds: map[string]string{"admin": ""}},
			user:     "admin",
			pass:     "",
			wantMode: AuthModeCredSSP,
		},
		{
			name:     "when_credssp_local_dot_domain_shorthand_and_epa_cbt_returns_nil",
			opts:     fakeCredSSPOpts{version: 6, requireEPA: true, validCreds: map[string]string{"admin": "password"}},
			user:     ".\\admin",
			pass:     "password",
			wantMode: AuthModeCredSSP,
		},
		{
			name:     "when_credssp_requires_spnego_and_epa_falls_back_and_returns_nil",
			opts:     fakeCredSSPOpts{version: 6, requireSPNEGO: true, requireEPA: true, errorCodes: map[string]uint32{"canary-user": ntStatusAccountLockedOut}, validCreds: map[string]string{"admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSPSPNEGO,
		},
		{
			name:     "when_credssp_spnego_fallback_canary_succeeds_returns_spnego_mode",
			opts:     fakeCredSSPOpts{version: 6, requireSPNEGO: true, validCreds: map[string]string{"canary-user": "canary-invalid-pass", "admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSPSPNEGO,
		},
		{
			name:     "when_credssp_spnego_fallback_canary_rejected_returns_spnego_mode",
			opts:     fakeCredSSPOpts{version: 6, requireSPNEGO: true, validCreds: map[string]string{"admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSPSPNEGO,
		},
		{
			name:     "when_credssp_wraps_only_challenge_in_spnego_and_canary_valid_returns_nil",
			opts:     fakeCredSSPOpts{version: 6, spnegoChallengeOnly: true, noRequestTarget: true, validCreds: map[string]string{"canary-user": "canary-invalid-pass", "admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSP,
		},
		{
			name:     "when_credssp_challenge_returns_error_code_on_step2_classifies_auth_failed",
			opts:     fakeCredSSPOpts{version: 6, challengeErrorCode: ntStatusLogonFailure},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSP,
			wantErr:  ErrAuthFailed,
		},
		{
			name:     "when_credssp_v3_legacy_valid_returns_nil",
			opts:     fakeCredSSPOpts{version: 2, omitServerVersion: true, omitChallengeTimestamp: true, validCreds: map[string]string{"Administrator": "Password1"}},
			user:     "CORP\\Administrator",
			pass:     "Password1",
			wantMode: AuthModeCredSSP,
		},
		{
			name:     "when_credssp_v4_boundary_and_v5_boundary_valid_returns_nil",
			opts:     fakeCredSSPOpts{version: 4, validCreds: map[string]string{"admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSP,
		},
		{
			name:     "when_credssp_v5_exact_boundary_valid_returns_nil",
			opts:     fakeCredSSPOpts{version: 5, validCreds: map[string]string{"admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSP,
		},
		{
			name:     "when_credssp_hybrid_ex_without_key_exch_valid_returns_nil",
			opts:     fakeCredSSPOpts{version: 6, protocol: protocolHybridEx, noKeyExch: true, truncateChallengeTI: true, validCreds: map[string]string{"admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSP,
		},
		{
			name:     "when_credssp_password_wrong_error_code_returns_err_auth_failed",
			opts:     fakeCredSSPOpts{version: 6, validCreds: map[string]string{"admin": "secret"}},
			user:     "admin",
			pass:     "wrong",
			wantMode: AuthModeCredSSP,
			wantErr:  ErrAuthFailed,
		},
		{
			name:     "when_credssp_password_wrong_tls_drop_returns_err_auth_failed",
			opts:     fakeCredSSPOpts{version: 6, dropOnFail: true, validCreds: map[string]string{"admin": "secret"}},
			user:     "admin",
			pass:     "wrong",
			wantMode: AuthModeCredSSP,
			wantErr:  ErrAuthFailed,
		},
		{
			name:     "when_credssp_account_locked_returns_err_account_unavailable",
			opts:     fakeCredSSPOpts{version: 6, errorCodes: map[string]uint32{"canary-user": ntStatusAccountLockedOut, "locked": ntStatusAccountLockedOut}},
			user:     "locked",
			pass:     "password",
			wantMode: AuthModeCredSSP,
			wantErr:  ErrAccountUnavailable,
		},
		{
			name:     "when_credssp_account_disabled_returns_err_account_unavailable",
			opts:     fakeCredSSPOpts{version: 6, errorCodes: map[string]uint32{"guest": ntStatusAccountDisabled}},
			user:     "guest",
			pass:     "",
			wantMode: AuthModeCredSSP,
			wantErr:  ErrAccountUnavailable,
		},
		{
			name:     "when_credssp_pubkey_binding_tampered_returns_err_auth_failed",
			opts:     fakeCredSSPOpts{version: 6, tamperPubKey: true, validCreds: map[string]string{"admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSP,
			wantErr:  ErrAuthFailed,
		},
		{
			name:     "when_credssp_mac_tampered_returns_err_auth_failed",
			opts:     fakeCredSSPOpts{version: 6, tamperMAC: true, validCreds: map[string]string{"admin": "password"}},
			user:     "admin",
			pass:     "password",
			wantMode: AuthModeCredSSP,
			wantErr:  ErrAuthFailed,
		},
	}

	c := fastClient()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := startFakeCredSSPServer(t, tc.opts)
			probe, err := c.Probe(t.Context(), addr, "canary-user", "canary-invalid-pass")
			if err != nil {
				t.Fatalf("Probe(%s) unexpected error: %v", addr, err)
			}
			if probe.Mode != tc.wantMode {
				t.Fatalf("Probe(%s).Mode = %v, want %v", addr, probe.Mode, tc.wantMode)
			}

			err = c.Authenticate(t.Context(), addr, probe.Mode, tc.user, tc.pass)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Authenticate(%q, %q) error = %v, want %v", tc.user, tc.pass, err, tc.wantErr)
			}
		})
	}
}

func TestNonNLATLSProbeAndAuthenticate(t *testing.T) {
	c := fastClient()

	t.Run("when_tls_inline_auth_accepts_weak_and_rejects_wrong_password", func(t *testing.T) {
		addr := startFakeNonNLATLSServer(t, fakeTLSInlineAuth, map[string]string{"admin": "password"})
		probe, err := c.Probe(t.Context(), addr, "canary-user", "canary-invalid-pass")
		if err != nil {
			t.Fatalf("Probe() unexpected error: %v", err)
		}
		if probe.Mode != AuthModeTLSInline {
			t.Fatalf("Probe().Mode = %v, want %v", probe.Mode, AuthModeTLSInline)
		}
		if err := c.Authenticate(t.Context(), addr, probe.Mode, "admin", "wrong"); !errors.Is(err, ErrAuthFailed) {
			t.Errorf("Authenticate(wrong) = %v, want %v", err, ErrAuthFailed)
		}
		if err := c.Authenticate(t.Context(), addr, probe.Mode, "admin", "password"); err != nil {
			t.Errorf("Authenticate(valid) = %v, want nil", err)
		}
	})

	t.Run("when_tls_noauth_emits_save_session_info_returns_auth_mode_no_auth", func(t *testing.T) {
		addr := startFakeNonNLATLSServer(t, fakeTLSNoAuthSaveSessionInfo, nil)
		probe, err := c.Probe(t.Context(), addr, "canary-user", "canary-invalid-pass")
		if err != nil {
			t.Fatalf("Probe() unexpected error: %v", err)
		}
		if probe.Mode != AuthModeNoAuth {
			t.Fatalf("Probe().Mode = %v, want %v", probe.Mode, AuthModeNoAuth)
		}
		if err := c.Authenticate(t.Context(), addr, probe.Mode, "", ""); err != nil {
			t.Errorf("Authenticate(empty) = %v, want nil", err)
		}
	})

	t.Run("when_tls_login_screen_greeter_returns_err_auth_unsupported", func(t *testing.T) {
		addr := startFakeNonNLATLSServer(t, fakeTLSLoginScreenGreeter, nil)
		_, err := c.Probe(t.Context(), addr, "canary-user", "canary-invalid-pass")
		if !errors.Is(err, ErrAuthUnsupported) {
			t.Errorf("Probe() error = %v, want %v", err, ErrAuthUnsupported)
		}
	})

	t.Run("when_xrdp_license_request_greeter_returns_err_auth_unsupported", func(t *testing.T) {
		addr := startFakeNonNLATLSServer(t, fakeTLSXrdpLicenseRequest, nil)
		_, err := c.Probe(t.Context(), addr, "canary-user", "canary-invalid-pass")
		if !errors.Is(err, ErrAuthUnsupported) {
			t.Errorf("Probe() error = %v, want %v", err, ErrAuthUnsupported)
		}
	})

	t.Run("when_fastpath_followed_by_save_session_info_returns_auth_mode_no_auth", func(t *testing.T) {
		addr := startFakeNonNLATLSServer(t, fakeTLSFastPathThenSaveSessionInfo, nil)
		probe, err := c.Probe(t.Context(), addr, "canary-user", "canary-invalid-pass")
		if err != nil {
			t.Fatalf("Probe() unexpected error: %v", err)
		}
		if probe.Mode != AuthModeNoAuth {
			t.Fatalf("Probe().Mode = %v, want %v", probe.Mode, AuthModeNoAuth)
		}
	})

	t.Run("when_fastpath_followed_by_set_error_info_rejects_wrong_password", func(t *testing.T) {
		addr := startFakeNonNLATLSServer(t, fakeTLSFastPathThenLogonError, map[string]string{"admin": "password"})
		probe, err := c.Probe(t.Context(), addr, "canary-user", "canary-invalid-pass")
		if err != nil {
			t.Fatalf("Probe() unexpected error: %v", err)
		}
		if probe.Mode != AuthModeTLSInline {
			t.Fatalf("Probe().Mode = %v, want %v", probe.Mode, AuthModeTLSInline)
		}
		if err := c.Authenticate(t.Context(), addr, probe.Mode, "admin", "wrong"); !errors.Is(err, ErrAuthFailed) {
			t.Errorf("Authenticate(wrong) = %v, want %v", err, ErrAuthFailed)
		}
		if err := c.Authenticate(t.Context(), addr, probe.Mode, "admin", "password"); err != nil {
			t.Errorf("Authenticate(valid) = %v, want nil", err)
		}
	})
}

func TestProbe_NonRDPAndFailureCases(t *testing.T) {
	c := fastClient()

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	closedAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr error
	}{
		{
			name:    "when_port_closed_returns_err_not_rdp_service",
			setup:   func(t *testing.T) string { return closedAddr },
			wantErr: ErrNotRDPService,
		},
		{
			name: "when_http_banner_returned_returns_err_not_rdp_service",
			setup: func(t *testing.T) string {
				return startFakeTCPServer(t, func(conn net.Conn) {
					_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				})
			},
			wantErr: ErrNotRDPService,
		},
		{
			name: "when_x224_negotiation_failure_returns_err_auth_unsupported",
			setup: func(t *testing.T) string {
				return startFakeTCPServer(t, func(conn net.Conn) {
					_, _ = readTPKT(conn)
					_ = sendX224Confirm(conn, rdpNegFailure, 0x00000002)
				})
			},
			wantErr: ErrAuthUnsupported,
		},
		{
			name: "when_standard_rdp_protocol_only_returns_err_auth_unsupported",
			setup: func(t *testing.T) string {
				return startFakeTCPServer(t, func(conn net.Conn) {
					_, _ = readTPKT(conn)
					_ = sendX224Confirm(conn, rdpNegRsp, protocolRDP)
				})
			},
			wantErr: ErrAuthUnsupported,
		},
		{
			name: "when_legacy_short_x224_confirm_without_neg_data_returns_err_auth_unsupported",
			setup: func(t *testing.T) string {
				return startFakeTCPServer(t, func(conn net.Conn) {
					_, _ = readTPKT(conn)
					_, _ = conn.Write([]byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0, 0, 0, 0, 0})
				})
			},
			wantErr: ErrAuthUnsupported,
		},
		{
			name: "when_tls_handshake_fails_after_x224_confirm_returns_err_not_rdp_service",
			setup: func(t *testing.T) string {
				return startFakeTCPServer(t, func(conn net.Conn) {
					_, _ = readTPKT(conn)
					_ = sendX224Confirm(conn, rdpNegRsp, protocolHybrid)
					_, _ = conn.Write([]byte("PLAIN-NOT-TLS\r\n"))
				})
			},
			wantErr: ErrNotRDPService,
		},
		{
			name: "when_credssp_returns_empty_challenge_returns_err_auth_unsupported",
			setup: func(t *testing.T) string {
				return startFakeCredSSPServer(t, fakeCredSSPOpts{emptyChallenge: true})
			},
			wantErr: ErrAuthUnsupported,
		},
		{
			name: "when_tcp_echo_server_reflects_x224_request_returns_err_not_rdp_service",
			setup: func(t *testing.T) string {
				return startFakeTCPServer(t, func(conn net.Conn) {
					buf := make([]byte, 512)
					n, err := conn.Read(buf)
					if err == nil && n > 0 {
						_, _ = conn.Write(buf[:n])
					}
				})
			},
			wantErr: ErrNotRDPService,
		},
		{
			name: "when_tls_echo_server_reflects_credssp_negotiate_returns_err_auth_unsupported",
			setup: func(t *testing.T) string {
				tlsCfg, _ := selfSignedTLSConfig(t)
				return startFakeTCPServer(t, func(conn net.Conn) {
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					_, _ = readTPKT(conn)
					_ = sendX224Confirm(conn, rdpNegRsp, protocolHybrid)
					tlsConn := tls.Server(conn, tlsCfg)
					if err := tlsConn.Handshake(); err != nil {
						return
					}
					if msg, err := readDERMessage(tlsConn); err == nil {
						_, _ = tlsConn.Write(msg)
					}
				})
			},
			wantErr: ErrAuthUnsupported,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.setup(t)
			_, err := c.Probe(t.Context(), addr, "canary", "canary-pass")
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Probe() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestContextCancellationAndOversizedDER(t *testing.T) {
	c := fastClient()

	t.Run("when_context_canceled_before_probe_returns_context_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := c.Probe(ctx, "127.0.0.1:1", "u", "p")
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Probe() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("when_context_canceled_before_authenticate_returns_context_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		err := c.Authenticate(ctx, "127.0.0.1:1", AuthModeCredSSP, "u", "p")
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Authenticate() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("when_der_message_exceeds_max_length_returns_err_not_rdp_service", func(t *testing.T) {
		for _, badDER := range [][]byte{
			{0x30, 0x80},                   // indefinite length nBytes == 0
			{0x30, 0x85, 0, 0, 0, 0, 1},    // nBytes == 5 (> 4)
			{0x30, 0x00},                   // length == 0 (<= 0)
			{0x30, 0x83, 0x10, 0x00, 0x00}, // 1 MiB > maxDERMessageBytes
		} {
			if _, err := readDERMessage(bytes.NewReader(badDER)); !errors.Is(err, ErrNotRDPService) {
				t.Errorf("readDERMessage(%x) = %v, want %v", badDER, err, ErrNotRDPService)
			}
		}

		// Verify SPNEGO NegTokenInit extraction at exact depth == 8 and rejection at depth > 8.
		neg := buildNTLMNegotiate()
		depth8SPNEGO := wrapSPNEGONegTokenInit(neg)
		for range 4 {
			depth8SPNEGO = derTLV(0x30, depth8SPNEGO)
		}
		gotNeg, wrapped, ok := extractNTLMFromNegoToken(depth8SPNEGO)
		if !ok || !wrapped || !bytes.Equal(gotNeg, neg) {
			t.Errorf("extractNTLMFromNegoToken(depth8 NegTokenInit) = (%v, %v)", wrapped, ok)
		}
		if _, _, ok := extractNTLMFromNegoToken(derTLV(0x30, depth8SPNEGO)); ok {
			t.Errorf("extractNTLMFromNegoToken(depth9 NegTokenInit) = true, want false")
		}
		if _, _, ok := extractNTLMFromNegoToken(derTLV(0x04, []byte("KERBEROS"))); ok {
			t.Errorf("extractNTLMFromNegoToken(non-NTLM 0x04) = true, want false")
		}
		if _, _, ok := extractNTLMFromNegoToken(derTLV(0x30, append([]byte("NTLMSSP\x00"), 1, 2))); ok {
			t.Errorf("extractNTLMFromNegoToken(0x30 with NTLMSSP prefix) = true, want false")
		}
		if _, _, ok := extractNTLMFromNegoToken(derTLV(0xa0, derTLV(0x0a, derTLV(0x04, neg)))); ok {
			t.Errorf("extractNTLMFromNegoToken(primitive 0x0a wrapper) = true, want false")
		}

		// Verify Step 2 EOF wraps io.EOF alongside ErrNotRDPService.
		tlsCfg, _ := selfSignedTLSConfig(t)
		pClient, pServer := net.Pipe()
		go func() {
			sTLS := tls.Server(pServer, tlsCfg)
			if sTLS.Handshake() == nil {
				var reqBuf [128]byte
				_, _ = sTLS.Read(reqBuf[:])
			}
			_ = sTLS.Close()
		}()
		cTLS := tls.Client(pClient, &tls.Config{
			InsecureSkipVerify: true, // NOLINT
			MaxVersion:         tls.VersionTLS12,
		})
		if err := cTLS.Handshake(); err != nil {
			t.Fatalf("cTLS.Handshake() error: %v", err)
		}
		step2Err := authenticateCredSSP(cTLS, "127.0.0.1", "u", "p", "", false)
		_ = cTLS.Close()
		if !errors.Is(step2Err, ErrNotRDPService) || !errors.Is(step2Err, io.EOF) {
			t.Errorf("authenticateCredSSP(step2 EOF) = %v, want ErrNotRDPService + io.EOF", step2Err)
		}

		// Verify extractMCSIndicationPayload & isDisconnectError boundaries.
		if _, ok := extractMCSIndicationPayload([]byte{1, 2, 3}); ok {
			t.Errorf("extractMCSIndicationPayload(short) = true, want false")
		}
		if _, ok := extractMCSIndicationPayload([]byte{0x02, 0xf0, 0x80, 0x68, 0, 1, 0x03, 0xeb, 0x70, 0x80}); ok {
			t.Errorf("extractMCSIndicationPayload(truncated 2B PER) = true, want false")
		}
		if isDisconnectError(nil) || isDisconnectError(net.ErrClosed) ||
			!isDisconnectError(io.EOF) || !isDisconnectError(io.ErrUnexpectedEOF) ||
			isDisconnectError(&net.DNSError{IsTimeout: true}) || !isDisconnectError(errors.New("reset")) {
			t.Errorf("isDisconnectError classification mismatch")
		}
	})

	t.Run("when_authenticate_unknown_mode_returns_err_auth_unsupported", func(t *testing.T) {
		credSSPAddr := startFakeCredSSPServer(t, fakeCredSSPOpts{})
		tlsAddr := startFakeNonNLATLSServer(t, fakeTLSInlineAuth, nil)
		if err := c.Authenticate(t.Context(), credSSPAddr, AuthModeUnknown, "admin", "password"); !errors.Is(err, ErrAuthUnsupported) {
			t.Errorf("Authenticate(AuthModeUnknown) = %v, want %v", err, ErrAuthUnsupported)
		}
		if err := c.Authenticate(t.Context(), tlsAddr, AuthModeCredSSP, "admin", "password"); !errors.Is(err, ErrAuthUnsupported) {
			t.Errorf("Authenticate(CredSSP on TLS) = %v, want %v", err, ErrAuthUnsupported)
		}
		if err := c.Authenticate(t.Context(), credSSPAddr, AuthModeTLSInline, "admin", "password"); !errors.Is(err, ErrAuthUnsupported) {
			t.Errorf("Authenticate(TLSInline on CredSSP) = %v, want %v", err, ErrAuthUnsupported)
		}
		if err := c.Authenticate(t.Context(), credSSPAddr, AuthModeNoAuth, "", ""); !errors.Is(err, ErrAuthUnsupported) {
			t.Errorf("Authenticate(NoAuth on CredSSP) = %v, want %v", err, ErrAuthUnsupported)
		}
		if err := c.Authenticate(t.Context(), tlsAddr, AuthModeNoAuth, "", ""); !errors.Is(err, ErrAuthFailed) {
			t.Errorf("Authenticate(NoAuth rejected) = %v, want %v", err, ErrAuthFailed)
		}
		xrdpAddr := startFakeNonNLATLSServer(t, fakeTLSXrdpLicenseRequest, nil)
		if err := c.Authenticate(t.Context(), xrdpAddr, AuthModeTLSInline, "admin", "password"); !errors.Is(err, ErrAuthUnsupported) {
			t.Errorf("Authenticate(TLSInline on xrdp license greeter) = %v, want %v", err, ErrAuthUnsupported)
		}
		shortClient := &Client{timeout: 100 * time.Millisecond}
		stallAddr := startFakeCredSSPServer(t, fakeCredSSPOpts{stallBeforeStep4: true})
		if _, err := shortClient.Probe(t.Context(), stallAddr, "canary", "pass"); !errors.Is(err, ErrNotRDPService) {
			t.Errorf("Probe(stallBeforeStep4) = %v, want %v", err, ErrNotRDPService)
		}
	})
}

func TestReadDERMessage_EOF(t *testing.T) {
	_, err := readDERMessage(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Errorf("readDERMessage(empty) = %v, want io.EOF", err)
	}
}
