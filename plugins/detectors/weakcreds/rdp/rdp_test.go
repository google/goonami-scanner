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

package rdp

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
	"errors"
	"io"
	"math/big"
	"math/bits"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"google.golang.org/protobuf/proto"

	bruteforceconfigpb "github.com/google/goonami-scanner/common/bruteforce/bruteforce_config_go_proto"
	configpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	detectionpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	networkpb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	networkservicepb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vulnerabilitypb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

// Minimal self-contained crypto & DER helpers for fake RDP test servers.
func testUTF16LE(s string) []byte {
	r := utf16.Encode([]rune(s))
	out := make([]byte, len(r)*2)
	for i, v := range r {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func testDecodeUTF16LE(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func testMD4(data []byte) [16]byte {
	padLen := (56 - (len(data)+1)%64 + 64) % 64
	msg := make([]byte, len(data)+1+padLen+8)
	copy(msg, data)
	msg[len(data)] = 0x80
	binary.LittleEndian.PutUint64(msg[len(msg)-8:], uint64(len(data))*8)
	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)
	s1 := [4]int{3, 7, 11, 19}
	s2 := [4]int{3, 5, 9, 13}
	s3 := [4]int{3, 9, 11, 15}
	ord := [16]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
	var x [16]uint32
	for off := 0; off < len(msg); off += 64 {
		for i := range 16 {
			x[i] = binary.LittleEndian.Uint32(msg[off+i*4:])
		}
		aa, bb, cc, dd := a, b, c, d
		for k := range 16 {
			a = bits.RotateLeft32(a+((b&c)|(^b&d))+x[k], s1[k%4])
			a, b, c, d = d, a, b, c
		}
		for k := range 16 {
			idx := (k%4)*4 + (k / 4)
			a = bits.RotateLeft32(a+((b&c)|(b&d)|(c&d))+x[idx]+0x5a827999, s2[k%4])
			a, b, c, d = d, a, b, c
		}
		for k := range 16 {
			a = bits.RotateLeft32(a+(b^c^d)+x[ord[k]]+0x6ed9eba1, s3[k%4])
			a, b, c, d = d, a, b, c
		}
		a, b, c, d = a+aa, b+bb, c+cc, d+dd
	}
	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint32(out[4:8], b)
	binary.LittleEndian.PutUint32(out[8:12], c)
	binary.LittleEndian.PutUint32(out[12:16], d)
	return out
}

var testMD5Tbl = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

var testMD5Shifts = [64]int{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

func testMD5(parts ...[]byte) [16]byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}
	padLen := (56 - (total+1)%64 + 64) % 64
	msg := make([]byte, total+1+padLen+8)
	pos := 0
	for _, p := range parts {
		pos += copy(msg[pos:], p)
	}
	msg[total] = 0x80
	binary.LittleEndian.PutUint64(msg[len(msg)-8:], uint64(total)*8)
	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)
	var m [16]uint32
	for off := 0; off < len(msg); off += 64 {
		for i := range 16 {
			m[i] = binary.LittleEndian.Uint32(msg[off+i*4:])
		}
		aa, bb, cc, dd := a, b, c, d
		for i := range 64 {
			var f, g uint32
			switch {
			case i < 16:
				f, g = (b&c)|(^b&d), uint32(i)
			case i < 32:
				f, g = (d&b)|(^d&c), uint32((5*i+1)%16)
			case i < 48:
				f, g = b^c^d, uint32((3*i+5)%16)
			default:
				f, g = c^(b|^d), uint32((7*i)%16)
			}
			f = f + a + testMD5Tbl[i] + m[g]
			a, d, c = d, c, b
			b += bits.RotateLeft32(f, testMD5Shifts[i])
		}
		a, b, c, d = a+aa, b+bb, c+cc, d+dd
	}
	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint32(out[4:8], b)
	binary.LittleEndian.PutUint32(out[8:12], c)
	binary.LittleEndian.PutUint32(out[12:16], d)
	return out
}

func testHMACMD5(key []byte, parts ...[]byte) [16]byte {
	var k [64]byte
	copy(k[:], key)
	var ipad, opad [64]byte
	for i := range 64 {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}
	in := append([][]byte{ipad[:]}, parts...)
	inner := testMD5(in...)
	return testMD5(opad[:], inner[:])
}

func testRC4(key, src []byte) ([]byte, *[256]byte, uint8, uint8) {
	var s [256]byte
	for i := range 256 {
		s[i] = byte(i)
	}
	var j uint8
	for i := range 256 {
		j += s[i] + key[i%len(key)]
		s[i], s[j] = s[j], s[i]
	}
	dst := make([]byte, len(src))
	var x, y uint8
	for idx, b := range src {
		x++
		y += s[x]
		s[x], s[y] = s[y], s[x]
		dst[idx] = b ^ s[s[x]+s[y]]
	}
	return dst, &s, x, y
}

func testRC4Continue(s *[256]byte, x, y uint8, src []byte) []byte {
	dst := make([]byte, len(src))
	for idx, b := range src {
		x++
		y += s[x]
		s[x], s[y] = s[y], s[x]
		dst[idx] = b ^ s[s[x]+s[y]]
	}
	return dst
}

func testDERTLV(tag byte, v []byte) []byte {
	var lb []byte
	n := len(v)
	switch {
	case n < 0x80:
		lb = []byte{byte(n)}
	case n <= 0xff:
		lb = []byte{0x81, byte(n)}
	default:
		lb = []byte{0x82, byte(n >> 8), byte(n)}
	}
	out := make([]byte, 0, 1+len(lb)+len(v))
	out = append(out, tag)
	out = append(out, lb...)
	out = append(out, v...)
	return out
}

func testDERRead(data []byte, off int) (byte, []byte, int) {
	tag := data[off]
	l0 := data[off+1]
	off += 2
	var l int
	if l0 < 0x80 {
		l = int(l0)
	} else {
		n := int(l0 & 0x7f)
		for i := range n {
			l = (l << 8) | int(data[off+i])
		}
		off += n
	}
	return tag, data[off : off+l], off + l
}

func testReadDER(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	var l int
	var lb []byte
	if h[1] < 0x80 {
		l = int(h[1])
		lb = []byte{h[1]}
	} else {
		n := int(h[1] & 0x7f)
		ex := make([]byte, n)
		if _, err := io.ReadFull(r, ex); err != nil {
			return nil, err
		}
		for _, b := range ex {
			l = (l << 8) | int(b)
		}
		lb = append([]byte{h[1]}, ex...)
	}
	body := make([]byte, l)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(append([]byte{h[0]}, lb...), body...), nil
}

func testExtractPubKey(certDER []byte) []byte {
	_, cb, _ := testDERRead(certDER, 0)
	_, tbs, _ := testDERRead(cb, 0)
	off := 0
	t, _, next := testDERRead(tbs, off)
	if t == 0xa0 {
		off = next
	}
	for range 5 {
		_, _, off = testDERRead(tbs, off)
	}
	_, spki, _ := testDERRead(tbs, off)
	_, _, spkiOff := testDERRead(spki, 0)
	_, bs, _ := testDERRead(spki, spkiOff)
	return bs[1:]
}

func testSelfSignedTLS(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() failed: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rdp-test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() failed: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}, testExtractPubKey(der)
}

func serviceFromAddr(addr string) *networkservicepb.NetworkService {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := net.LookupPort("tcp", portStr)
	return networkservicepb.NetworkService_builder{
		ServiceName:       "ms-wbt-server",
		TransportProtocol: networkpb.TransportProtocol_TCP,
		NetworkEndpoint: networkpb.NetworkEndpoint_builder{
			Type: networkpb.NetworkEndpoint_IP_PORT,
			IpAddress: networkpb.IpAddress_builder{
				Address:       host,
				AddressFamily: networkpb.AddressFamily_IPV4,
			}.Build(),
			Port: networkpb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
	}.Build()
}

type fakeRDPServerOpts struct {
	validCreds  map[string]string
	errorCodes  map[string]uint32
	onAttempt   func(user string)
	onConnect   func()
	noAuthTLS   bool
	xrdpGreeter bool
}

func startFakeRDPServer(t *testing.T, opts fakeRDPServerOpts) *networkservicepb.NetworkService {
	t.Helper()
	tlsCfg, pubKey := testSelfSignedTLS(t)

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
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if opts.onConnect != nil {
					opts.onConnect()
				}
				// Read X.224 TPKT.
				var h [4]byte
				if _, err := io.ReadFull(conn, h[:]); err != nil {
					return
				}
				l := int(binary.BigEndian.Uint16(h[2:4]))
				if l < 4 {
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(l-4)); err != nil {
					return
				}

				selectedProto := uint32(0x02) // PROTOCOL_HYBRID
				if opts.noAuthTLS || opts.xrdpGreeter {
					selectedProto = 0x01 // PROTOCOL_SSL
				}
				var cc [19]byte
				cc[0], cc[3] = 3, 19
				cc[4], cc[5] = 14, 0xd0
				cc[11], cc[13] = 0x02, 8
				binary.LittleEndian.PutUint32(cc[15:19], selectedProto)
				if _, err := conn.Write(cc[:]); err != nil {
					return
				}

				tlsConn := tls.Server(conn, tlsCfg)
				if err := tlsConn.Handshake(); err != nil {
					return
				}

				if opts.xrdpGreeter || opts.noAuthTLS {
					handleFakeNonNLATLS(tlsConn, opts.noAuthTLS)
					return
				}

				// CredSSP v6 NTLMv2 flow.
				if _, err := testReadDER(tlsConn); err != nil {
					return
				}
				srvChal := []byte{1, 2, 3, 4, 5, 6, 7, 8}
				ti := make([]byte, 16)
				binary.LittleEndian.PutUint16(ti[0:2], 7)
				binary.LittleEndian.PutUint16(ti[2:4], 8)
				binary.LittleEndian.PutUint64(ti[4:12], uint64(time.Now().Unix()+11644473600)*10000000)
				chal := make([]byte, 56+len(ti))
				copy(chal[0:8], "NTLMSSP\x00")
				binary.LittleEndian.PutUint32(chal[8:12], 2)
				binary.LittleEndian.PutUint32(chal[20:24], 0x60088235)
				copy(chal[24:32], srvChal)
				binary.LittleEndian.PutUint16(chal[40:42], uint16(len(ti)))
				binary.LittleEndian.PutUint16(chal[42:44], uint16(len(ti)))
				binary.LittleEndian.PutUint32(chal[44:48], 56)
				copy(chal[56:], ti)

				negoItem := testDERTLV(0x30, testDERTLV(0xa0, testDERTLV(0x04, chal)))
				tsChal := testDERTLV(0x30, append(testDERTLV(0xa0, testDERTLV(0x02, []byte{6})), testDERTLV(0xa1, testDERTLV(0x30, negoItem))...))
				if _, err := tlsConn.Write(tsChal); err != nil {
					return
				}

				rawAuth, err := testReadDER(tlsConn)
				if err != nil {
					return
				}
				_, body, _ := testDERRead(rawAuth, 0)
				var authMsg, nonce []byte
				for off := 0; off < len(body); {
					t, v, next := testDERRead(body, off)
					off = next
					switch t {
					case 0xa1:
						_, seq, _ := testDERRead(v, 0)
						_, item, _ := testDERRead(seq, 0)
						_, c0, _ := testDERRead(item, 0)
						_, authMsg, _ = testDERRead(c0, 0)
					case 0xa5:
						_, nonce, _ = testDERRead(v, 0)
					}
				}
				readField := func(off int) []byte {
					fl := int(binary.LittleEndian.Uint16(authMsg[off : off+2]))
					fo := int(binary.LittleEndian.Uint32(authMsg[off+4 : off+8]))
					return authMsg[fo : fo+fl]
				}
				ntResp := readField(20)
				dom := testDecodeUTF16LE(readField(28))
				user := testDecodeUTF16LE(readField(36))
				encKey := readField(52)

				if user == "" {
					t.Errorf("unexpected CredSSP authentication attempt with empty username")
					return
				}
				if opts.onAttempt != nil {
					opts.onAttempt(user)
				}
				if code, ok := opts.errorCodes[user]; ok {
					var b [5]byte
					binary.BigEndian.PutUint32(b[1:5], code)
					resp := testDERTLV(0x30, append(testDERTLV(0xa0, testDERTLV(0x02, []byte{6})), testDERTLV(0xa4, testDERTLV(0x02, b[:]))...))
					_, _ = tlsConn.Write(resp)
					return
				}
				wantPass, ok := opts.validCreds[user]
				if !ok || len(ntResp) < 16 {
					return
				}
				ntHash := testMD4(testUTF16LE(wantPass))
				rk := testHMACMD5(ntHash[:], testUTF16LE(strings.ToUpper(user)+dom))
				wantProof := testHMACMD5(rk[:], srvChal, ntResp[16:])
				if subtle.ConstantTimeCompare(ntResp[:16], wantProof[:]) != 1 {
					return
				}
				sbk := testHMACMD5(rk[:], ntResp[:16])
				expKey, _, _, _ := testRC4(sbk[:], encKey)
				sSign := testMD5(expKey, []byte("session key to server-to-client signing key magic constant\x00"))
				sSeal := testMD5(expKey, []byte("session key to server-to-client sealing key magic constant\x00"))
				hasher := sha256.New()
				hasher.Write([]byte("CredSSP Server-To-Client Binding Hash\x00"))
				hasher.Write(nonce)
				hasher.Write(pubKey)
				plain := hasher.Sum(nil)
				ct, s, rx, ry := testRC4(sSeal[:], plain)
				var seq [4]byte
				mac := testHMACMD5(sSign[:], seq[:], plain)
				chk := testRC4Continue(s, rx, ry, mac[:8])
				sealed := make([]byte, 16+len(ct))
				binary.LittleEndian.PutUint32(sealed[0:4], 1)
				copy(sealed[4:12], chk)
				copy(sealed[16:], ct)
				okResp := testDERTLV(0x30, append(testDERTLV(0xa0, testDERTLV(0x02, []byte{6})), testDERTLV(0xa3, testDERTLV(0x04, sealed))...))
				_, _ = tlsConn.Write(okResp)
			}(c)
		}
	}()

	return serviceFromAddr(ln.Addr().String())
}

func handleFakeNonNLATLS(tlsConn *tls.Conn, noAuth bool) {
	readPkt := func() error {
		var h [4]byte
		if _, err := io.ReadFull(tlsConn, h[:]); err != nil {
			return err
		}
		l := int(binary.BigEndian.Uint16(h[2:4]))
		if l < 4 {
			return io.ErrUnexpectedEOF
		}
		_, err := io.CopyN(io.Discard, tlsConn, int64(l-4))
		return err
	}
	writePkt := func(data []byte) error {
		p := make([]byte, 7+len(data))
		p[0] = 3
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		p[4], p[5], p[6] = 0x02, 0xf0, 0x80
		copy(p[7:], data)
		_, err := tlsConn.Write(p)
		return err
	}
	sendInd := func(payload []byte) error {
		var b bytes.Buffer
		b.WriteByte(0x68)
		_ = binary.Write(&b, binary.BigEndian, uint16(1))
		_ = binary.Write(&b, binary.BigEndian, uint16(1003))
		b.WriteByte(0x70)
		b.WriteByte(byte(len(payload)))
		b.Write(payload)
		return writePkt(b.Bytes())
	}

	if err := readPkt(); err != nil {
		return
	}
	_ = writePkt([]byte{0x7f, 0x66, 0x08, 0x03, 0x0c, 0x08, 0x00, 0xeb, 0x03, 0x00, 0x00})
	if err := readPkt(); err != nil {
		return
	}
	if err := readPkt(); err != nil {
		return
	}
	_ = writePkt([]byte{0x2e, 0x00, 0x00, 0x03})
	for range 2 {
		if err := readPkt(); err != nil {
			return
		}
		_ = writePkt([]byte{0x3e, 0x00, 0x00, 0x03, 0x03, 0xeb, 0x03, 0xeb})
	}
	if err := readPkt(); err != nil {
		return
	}
	if !noAuth {
		// xrdp-style LICENSE_REQUEST (bMsgType=0x01).
		_ = sendInd([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x10, 0x00})
		return
	}
	_ = sendInd([]byte{0x80, 0x00, 0x00, 0x00, 0xff, 0x03, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00})
	da := make([]byte, 14)
	binary.LittleEndian.PutUint16(da[0:2], 14)
	binary.LittleEndian.PutUint16(da[2:4], 0x0011)
	binary.LittleEndian.PutUint32(da[6:10], 0x103ec)
	_ = sendInd(da)
	for range 5 {
		if err := readPkt(); err != nil {
			return
		}
	}
	ssi := make([]byte, 22)
	binary.LittleEndian.PutUint16(ssi[0:2], 22)
	binary.LittleEndian.PutUint16(ssi[2:4], 0x0017)
	binary.LittleEndian.PutUint32(ssi[6:10], 0x103ec)
	ssi[14] = 0x26 // PDUTYPE2_SAVE_SESSION_INFO
	binary.LittleEndian.PutUint32(ssi[18:22], 0x02)
	_ = sendInd(ssi)
}

func fastConfig(stopAtFirst bool) *config.Config {
	return config.FromProto(configpb.Config_builder{
		Globalcfg: configpb.GlobalConfig_builder{
			Performance: configpb.GlobalConfig_Performance_builder{
				TimeoutPerRequestSeconds: proto.Int32(2),
			}.Build(),
		}.Build(),
		Plugins: configpb.PluginsConfig_builder{
			Bruteforce: bruteforceconfigpb.BruteForceConfig_builder{
				MaxRequestsPerSecond:        proto.Int32(0),
				MaxConcurrency:              proto.Int32(1),
				StopAtFirstValidCredentials: proto.Bool(stopAtFirst),
			}.Build(),
		}.Build(),
	}.Build())
}

func smallStore(users, passes []string) *credentialstore.CredentialStore {
	s := credentialstore.New()
	for _, u := range users {
		_ = s.AddUser(u)
		for _, p := range passes {
			_ = s.AddPasswordForUser(u, p)
		}
	}
	return s
}

func extractFoundCredentials(reports *detectionpb.DetectionReportList) []string {
	var creds []string
	for _, r := range reports.GetDetectionReports() {
		for _, ad := range r.GetVulnerability().GetAdditionalDetails() {
			creds = append(creds, ad.GetTextData().GetText())
		}
	}
	return creds
}

func TestRegistrationAndNew(t *testing.T) {
	t.Run("when_init_runs_registers_detector_in_module_registry", func(t *testing.T) {
		detectors, err := module.AllDetectors(t.Context(), config.Default())
		if err != nil {
			t.Fatalf("module.AllDetectors() error: %v", err)
		}
		found := false
		for _, d := range detectors {
			if d.Name() == ModuleName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("module.AllDetectors() did not include %q", ModuleName)
		}
	})

	t.Run("when_config_is_nil_returns_err_config_nil", func(t *testing.T) {
		if _, err := New(t.Context(), nil); !errors.Is(err, bruteforce.ErrConfigNil) {
			t.Errorf("New(nil) error = %v, want %v", err, bruteforce.ErrConfigNil)
		}
	})

	t.Run("when_default_store_built_includes_empty_password_first_for_every_user", func(t *testing.T) {
		if len(DefaultCredentials()) != 30 {
			t.Errorf("len(DefaultCredentials()) = %d, want 30", len(DefaultCredentials()))
		}
		d, err := New(t.Context(), config.Default())
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		bf := d.(*bruteforce.Detector)
		store := bf.CredentialStore()
		if len(store.Usernames()) != 9 {
			t.Errorf("len(store.Usernames()) = %d, want 9", len(store.Usernames()))
		}
		for _, u := range store.Usernames() {
			passes := store.Passwords(u)
			if len(passes) == 0 || passes[0] != "" {
				t.Errorf("Passwords(%q) = %v, want empty password first", u, passes)
			}
		}
		h := NewHandler(config.Default())
		if got := h.Name(); got != ModuleName {
			t.Errorf("Handler.Name() = %q, want %q", got, ModuleName)
		}
		if err := h.NewWorker().Close(); err != nil {
			t.Errorf("Worker.Close() = %v, want nil", err)
		}
		vuln := h.Vulnerability()
		if got := vuln.GetMainId().GetPublisher(); got != "GOOGLE" {
			t.Errorf("Publisher = %q, want GOOGLE", got)
		}
		if got := vuln.GetMainId().GetValue(); got != "WEAK_CREDENTIALS_FOR_RDP" {
			t.Errorf("MainId = %q, want WEAK_CREDENTIALS_FOR_RDP", got)
		}
		if got := vuln.GetSeverity(); got != vulnerabilitypb.Severity_CRITICAL {
			t.Errorf("Severity = %v, want CRITICAL", got)
		}
		if vuln.GetTitle() == "" || vuln.GetDescription() == "" || vuln.GetRecommendation() == "" {
			t.Errorf("Vulnerability text fields must be non-empty: %+v", vuln)
		}
	})
}

func TestDetect_WeakAndBlankCredentials(t *testing.T) {
	tests := []struct {
		name        string
		opts        fakeRDPServerOpts
		bfOpts      *bruteforce.Options
		stopAtFirst bool
		wantCreds   []string
	}{
		{
			name:        "when_nla_weak_password_matches_returns_verified_finding",
			opts:        fakeRDPServerOpts{validCreds: map[string]string{"admin": "password"}},
			bfOpts:      &bruteforce.Options{CredentialStore: smallStore([]string{"admin"}, []string{"", "password"})},
			stopAtFirst: true,
			wantCreds:   []string{"admin:password"},
		},
		{
			name:        "when_nla_empty_password_matches_default_store_returns_verified_finding",
			opts:        fakeRDPServerOpts{validCreds: map[string]string{"admin": ""}},
			bfOpts:      nil,
			stopAtFirst: true,
			wantCreds:   []string{"admin:"},
		},
		{
			name:        "when_transport_protocol_unspecified_matches_valid_cred",
			opts:        fakeRDPServerOpts{validCreds: map[string]string{"admin": "password"}},
			bfOpts:      &bruteforce.Options{CredentialStore: smallStore([]string{"admin"}, []string{"password"})},
			stopAtFirst: true,
			wantCreds:   []string{"admin:password"},
		},
		{
			name:        "when_tls_noauth_save_session_info_matches_empty_cred",
			opts:        fakeRDPServerOpts{noAuthTLS: true},
			bfOpts:      nil,
			stopAtFirst: true,
			wantCreds:   []string{":"},
		},
		{
			name:        "when_stop_at_first_disabled_reports_all_valid_creds",
			opts:        fakeRDPServerOpts{validCreds: map[string]string{"Administrator": "", "admin": "password"}},
			bfOpts:      &bruteforce.Options{CredentialStore: smallStore([]string{"Administrator", "admin"}, []string{"", "password"})},
			stopAtFirst: false,
			wantCreds:   []string{"Administrator:", "admin:password"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := startFakeRDPServer(t, tc.opts)
			if strings.Contains(tc.name, "unspecified") {
				svc.SetTransportProtocol(networkpb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED)
			}
			d, err := NewWithOptions(t.Context(), fastConfig(tc.stopAtFirst), tc.bfOpts)
			if err != nil {
				t.Fatalf("NewWithOptions() error: %v", err)
			}
			reports, err := d.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}
			if len(reports.GetDetectionReports()) != 1 {
				t.Fatalf("len(DetectionReports) = %d, want 1", len(reports.GetDetectionReports()))
			}
			if got := reports.GetDetectionReports()[0].GetDetectionStatus(); got != detectionpb.DetectionStatus_VULNERABILITY_VERIFIED {
				t.Errorf("DetectionStatus = %v, want VULNERABILITY_VERIFIED", got)
			}
			if diff := cmp.Diff(tc.wantCreds, extractFoundCredentials(reports)); diff != "" {
				t.Errorf("credentials diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetect_NoFindingsAndFilters(t *testing.T) {
	tests := []struct {
		name        string
		opts        fakeRDPServerOpts
		protocol    networkpb.TransportProtocol
		httpMethods []string
		clearPort   bool
	}{
		{
			name:     "when_password_is_strong_returns_no_findings",
			opts:     fakeRDPServerOpts{validCreds: map[string]string{"admin": "S3cure!Random#2026"}},
			protocol: networkpb.TransportProtocol_TCP,
		},
		{
			name:     "when_xrdp_interactive_greeter_returns_no_findings",
			opts:     fakeRDPServerOpts{xrdpGreeter: true},
			protocol: networkpb.TransportProtocol_TCP,
		},
		{
			name:        "when_service_is_web_service_skips_without_findings",
			opts:        fakeRDPServerOpts{validCreds: map[string]string{"admin": "password"}},
			protocol:    networkpb.TransportProtocol_TCP,
			httpMethods: []string{"GET"},
		},
		{
			name:     "when_transport_protocol_is_udp_skips_without_findings",
			opts:     fakeRDPServerOpts{validCreds: map[string]string{"admin": "password"}},
			protocol: networkpb.TransportProtocol_UDP,
		},
		{
			name:      "when_endpoint_missing_port_skips_without_findings",
			opts:      fakeRDPServerOpts{validCreds: map[string]string{"admin": "password"}},
			protocol:  networkpb.TransportProtocol_TCP,
			clearPort: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := startFakeRDPServer(t, tc.opts)
			svc.SetTransportProtocol(tc.protocol)
			if len(tc.httpMethods) > 0 {
				svc.SetSupportedHttpMethods(tc.httpMethods)
			}
			if tc.clearPort {
				svc.GetNetworkEndpoint().ClearPort()
			}
			d, err := NewWithOptions(t.Context(), fastConfig(true), &bruteforce.Options{
				CredentialStore: smallStore([]string{"admin"}, []string{"", "password"}),
			})
			if err != nil {
				t.Fatalf("NewWithOptions() error: %v", err)
			}
			reports, err := d.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}
			if len(reports.GetDetectionReports()) != 0 {
				t.Errorf("Detect() returned %d reports, want 0", len(reports.GetDetectionReports()))
			}
		})
	}
}

func TestDetect_SkipsLockedAccountRemainingPasswords(t *testing.T) {
	var lockedAttempts atomic.Int32
	svc := startFakeRDPServer(t, fakeRDPServerOpts{
		errorCodes: map[string]uint32{"locked": 0xc0000234},
		validCreds: map[string]string{"admin": "password"},
		onAttempt: func(user string) {
			if user == "locked" {
				lockedAttempts.Add(1)
			}
		},
	})

	store := smallStore([]string{"locked", "admin"}, []string{"", "p1", "p2", "password"})
	d, err := NewWithOptions(t.Context(), fastConfig(true), &bruteforce.Options{CredentialStore: store})
	if err != nil {
		t.Fatalf("NewWithOptions() error: %v", err)
	}
	reports, err := d.Detect(t.Context(), svc)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if got := lockedAttempts.Load(); got != 1 {
		t.Errorf("locked account attempts = %d, want 1 (subsequent passwords skipped)", got)
	}
	if diff := cmp.Diff([]string{"admin:password"}, extractFoundCredentials(reports)); diff != "" {
		t.Errorf("credentials diff (-want +got):\n%s", diff)
	}
}

func TestDetect_StopsCleanlyOnConsecutiveTransportErrors(t *testing.T) {
	targetSvc := startFakeRDPServer(t, fakeRDPServerOpts{validCreds: map[string]string{"admin": "other"}})
	targetAddr, err := netendpoint.ToURIAuthority(targetSvc.GetNetworkEndpoint())
	if err != nil {
		t.Fatalf("ToURIAuthority() error: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var connCount atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if connCount.Add(1) > 1 {
				_ = c.Close()
				continue
			}
			go func(client net.Conn) {
				defer client.Close()
				up, err := net.Dial("tcp", targetAddr)
				if err != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(up, client)
					_ = up.Close()
					close(done)
				}()
				_, _ = io.Copy(client, up)
				_ = client.Close()
				<-done
			}(c)
		}
	}()

	proxySvc := serviceFromAddr(ln.Addr().String())
	d, err := NewWithOptions(t.Context(), fastConfig(true), &bruteforce.Options{
		CredentialStore: smallStore([]string{"admin", "user", "root"}, []string{"p1", "p2", "p3"}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions() error: %v", err)
	}
	reports, err := d.Detect(t.Context(), proxySvc)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(reports.GetDetectionReports()) != 0 {
		t.Errorf("Detect() returned %d reports, want 0", len(reports.GetDetectionReports()))
	}
	if got, want := connCount.Load(), int32(1+maxConsecutiveTransportErrors); got != want {
		t.Errorf("connection count = %d, want %d", got, want)
	}
}

func TestHandler_ErrorPropagationAndEndpointSelection(t *testing.T) {
	h := NewHandler(fastConfig(true))
	invalidSvc := networkservicepb.NetworkService_builder{
		ServiceName:     "ms-wbt-server",
		NetworkEndpoint: &networkpb.NetworkEndpoint{},
	}.Build()

	t.Run("when_fingerprint_missing_address_returns_error", func(t *testing.T) {
		if _, err := h.Fingerprint(t.Context(), invalidSvc); !errors.Is(err, netendpoint.ErrEndpointMissingAddress) {
			t.Errorf("Fingerprint() error = %v, want %v", err, netendpoint.ErrEndpointMissingAddress)
		}
	})

	t.Run("when_fingerprint_context_canceled_returns_context_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := h.Fingerprint(ctx, invalidSvc); !errors.Is(err, context.Canceled) {
			t.Errorf("Fingerprint() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("when_test_credential_context_canceled_returns_context_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := h.TestCredential(ctx, invalidSvc, bruteforce.Credential{Username: "admin", Password: "password"}); !errors.Is(err, context.Canceled) {
			t.Errorf("TestCredential() error = %v, want %v", err, context.Canceled)
		}
		w := h.NewWorker()
		defer w.Close()
		if _, err := w.TestCredential(ctx, invalidSvc, bruteforce.Credential{Username: "admin", Password: "password"}); !errors.Is(err, context.Canceled) {
			t.Errorf("Worker.TestCredential(canceled) error = %v, want %v", err, context.Canceled)
		}
		if _, err := h.TestCredential(t.Context(), invalidSvc, bruteforce.Credential{Username: "admin", Password: "password"}); !errors.Is(err, netendpoint.ErrEndpointMissingAddress) {
			t.Errorf("TestCredential(missing address) error = %v, want %v", err, netendpoint.ErrEndpointMissingAddress)
		}
		portlessSvc := networkservicepb.NetworkService_builder{
			NetworkEndpoint: networkpb.NetworkEndpoint_builder{
				Type: networkpb.NetworkEndpoint_IP,
				IpAddress: networkpb.IpAddress_builder{
					Address:       "127.0.0.1",
					AddressFamily: networkpb.AddressFamily_IPV4,
				}.Build(),
			}.Build(),
		}.Build()
		if _, err := w.TestCredential(t.Context(), portlessSvc, bruteforce.Credential{Username: "admin", Password: "password"}); !errors.Is(err, bruteforce.ErrStopBruteForce) {
			t.Errorf("Worker.TestCredential(missing port) error = %v, want %v", err, bruteforce.ErrStopBruteForce)
		}
	})

	t.Run("when_ip_and_hostname_present_prefers_ip_authority", func(t *testing.T) {
		svc := networkservicepb.NetworkService_builder{
			NetworkEndpoint: networkpb.NetworkEndpoint_builder{
				Type: networkpb.NetworkEndpoint_IP_HOSTNAME_PORT,
				Hostname: networkpb.Hostname_builder{
					Name: "nonexistent.invalid",
				}.Build(),
				IpAddress: networkpb.IpAddress_builder{
					Address:       "127.0.0.1",
					AddressFamily: networkpb.AddressFamily_IPV4,
				}.Build(),
				Port: networkpb.Port_builder{
					PortNumber: 3389,
				}.Build(),
			}.Build(),
		}.Build()
		addr, ok, err := resolveAddr(svc)
		if err != nil || !ok || addr != "127.0.0.1:3389" {
			t.Errorf("resolveAddr() = (%q, %v, %v), want (\"127.0.0.1:3389\", true, nil)", addr, ok, err)
		}
	})

	t.Run("when_only_hostname_present_uses_hostname_authority", func(t *testing.T) {
		svc := networkservicepb.NetworkService_builder{
			NetworkEndpoint: networkpb.NetworkEndpoint_builder{
				Type: networkpb.NetworkEndpoint_HOSTNAME_PORT,
				Hostname: networkpb.Hostname_builder{
					Name: "rdp-host.example",
				}.Build(),
				Port: networkpb.Port_builder{
					PortNumber: 3389,
				}.Build(),
			}.Build(),
		}.Build()
		addr, ok, err := resolveAddr(svc)
		if err != nil || !ok || addr != "rdp-host.example:3389" {
			t.Errorf("resolveAddr() = (%q, %v, %v), want (\"rdp-host.example:3389\", true, nil)", addr, ok, err)
		}
	})

	t.Run("when_test_credential_called_without_prior_fingerprint_defaults_to_credssp", func(t *testing.T) {
		svc := startFakeRDPServer(t, fakeRDPServerOpts{validCreds: map[string]string{"admin": "password"}})
		unprobed := NewHandler(fastConfig(true))
		ok, err := unprobed.TestCredential(t.Context(), svc, bruteforce.Credential{Username: "admin", Password: "password"})
		if err != nil || !ok {
			t.Errorf("TestCredential() = (%v, %v), want (true, nil)", ok, err)
		}
	})

	t.Run("when_set_mode_recalled_resets_previously_skipped_users", func(t *testing.T) {
		hReset := NewHandler(fastConfig(true))
		hReset.markUserSkipped("127.0.0.1:3389", "locked")
		if !hReset.isUserSkipped("127.0.0.1:3389", "locked") {
			t.Fatalf("isUserSkipped() = false before reset, want true")
		}
		hReset.setMode("127.0.0.1:3389", 1)
		if hReset.isUserSkipped("127.0.0.1:3389", "locked") {
			t.Errorf("isUserSkipped() = true after setMode reset, want false")
		}
	})

	t.Run("when_context_canceled_mid_flight_propagates_context_canceled", func(t *testing.T) {
		ctxFp, cancelFp := context.WithCancel(t.Context())
		lnFp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() error: %v", err)
		}
		t.Cleanup(func() { _ = lnFp.Close() })
		go func() {
			c, err := lnFp.Accept()
			if err != nil {
				return
			}
			cancelFp()
			_ = c.Close()
		}()
		if _, err := h.Fingerprint(ctxFp, serviceFromAddr(lnFp.Addr().String())); !errors.Is(err, context.Canceled) {
			t.Errorf("Fingerprint(mid-flight cancel) = %v, want %v", err, context.Canceled)
		}

		ctxTc, cancelTc := context.WithCancel(t.Context())
		lnTc, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() error: %v", err)
		}
		t.Cleanup(func() { _ = lnTc.Close() })
		go func() {
			c, err := lnTc.Accept()
			if err != nil {
				return
			}
			cancelTc()
			_ = c.Close()
		}()
		if _, err := h.TestCredential(ctxTc, serviceFromAddr(lnTc.Addr().String()), bruteforce.Credential{Username: "admin", Password: "p"}); !errors.Is(err, context.Canceled) {
			t.Errorf("TestCredential(mid-flight cancel) = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("when_server_returns_x224_neg_failure_during_test_credential_stops_brute_force", func(t *testing.T) {
		lnFail, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() error: %v", err)
		}
		t.Cleanup(func() { _ = lnFail.Close() })
		go func() {
			c, err := lnFail.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			var buf [64]byte
			_, _ = c.Read(buf[:])
			var cc [19]byte
			cc[0], cc[3] = 3, 19
			cc[4], cc[5] = 14, 0xd0
			cc[11], cc[13] = 0x03, 8 // rdpNegFailure
			binary.LittleEndian.PutUint32(cc[15:19], 2)
			_, _ = c.Write(cc[:])
		}()
		_, err = h.TestCredential(t.Context(), serviceFromAddr(lnFail.Addr().String()), bruteforce.Credential{Username: "admin", Password: "p"})
		if !errors.Is(err, bruteforce.ErrStopBruteForce) {
			t.Errorf("TestCredential(negFailure) = %v, want %v", err, bruteforce.ErrStopBruteForce)
		}
	})

	t.Run("when_worker_encounters_valid_attempt_between_transport_errors_resets_counter", func(t *testing.T) {
		realSvc := startFakeRDPServer(t, fakeRDPServerOpts{validCreds: map[string]string{"admin": "password"}})
		realAddr, err := netendpoint.ToURIAuthority(realSvc.GetNetworkEndpoint())
		if err != nil {
			t.Fatalf("ToURIAuthority() error: %v", err)
		}

		lnProxy, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() error: %v", err)
		}
		t.Cleanup(func() { _ = lnProxy.Close() })

		var seq atomic.Int32
		go func() {
			for {
				c, err := lnProxy.Accept()
				if err != nil {
					return
				}
				n := seq.Add(1)
				if n == 2 || n == 3 || n == 5 || n == 6 {
					_ = c.Close()
					continue
				}
				go func(client net.Conn) {
					defer client.Close()
					up, err := net.Dial("tcp", realAddr)
					if err != nil {
						return
					}
					defer up.Close()
					done := make(chan struct{})
					go func() {
						_, _ = io.Copy(up, client)
						_ = up.Close()
						close(done)
					}()
					_, _ = io.Copy(client, up)
					_ = client.Close()
					<-done
				}(c)
			}
		}()

		proxySvc := serviceFromAddr(lnProxy.Addr().String())
		hWorker := NewHandler(fastConfig(true))
		fpOK, err := hWorker.Fingerprint(t.Context(), proxySvc)
		if err != nil || !fpOK {
			t.Fatalf("Fingerprint() = (%v, %v), want (true, nil)", fpOK, err)
		}
		w := hWorker.NewWorker()
		defer w.Close()

		for range 5 {
			ok, err := w.TestCredential(t.Context(), proxySvc, bruteforce.Credential{Username: "admin", Password: "wrong"})
			if err != nil || ok {
				t.Fatalf("intermediate TestCredential() = (%v, %v), want (false, nil)", ok, err)
			}
		}
		ok, err := w.TestCredential(t.Context(), proxySvc, bruteforce.Credential{Username: "admin", Password: "password"})
		if err != nil || !ok {
			t.Errorf("final TestCredential() = (%v, %v), want (true, nil)", ok, err)
		}
	})
}
