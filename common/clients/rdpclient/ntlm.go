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

// Package rdpclient provides a reusable pure-Go RDP client supporting
// NLA/CredSSP (NTLMv2) and non-NLA TLS authentication probing with canonical
// sentinel error classification.
package rdpclient

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	ntlmNegotiateUnicode                 uint32 = 0x00000001
	ntlmRequestTarget                    uint32 = 0x00000004
	ntlmNegotiateSign                    uint32 = 0x00000010
	ntlmNegotiateSeal                    uint32 = 0x00000020
	ntlmNegotiateNTLM                    uint32 = 0x00000200
	ntlmNegotiateAlwaysSign              uint32 = 0x00008000
	ntlmNegotiateExtendedSessionSecurity uint32 = 0x00080000
	ntlmNegotiateVersion                 uint32 = 0x02000000
	ntlmNegotiate128                     uint32 = 0x20000000
	ntlmNegotiateKeyExch                 uint32 = 0x40000000
	ntlmNegotiate56                      uint32 = 0x80000000

	avIDEOL             uint16 = 0x0000
	avIDFlags           uint16 = 0x0006
	avIDTimestamp       uint16 = 0x0007
	avIDTargetName      uint16 = 0x0009
	avIDChannelBindings uint16 = 0x000a

	avFlagMICPresent uint32 = 0x00000002

	// Windows FILETIME epoch offset (1601-01-01 to 1970-01-01) in seconds.
	filetimeEpochOffsetSec = 11644473600
)

var (
	ntlmSignature = []byte("NTLMSSP\x00")
	ntlmVersion   = []byte{10, 0, 0x61, 0x4a, 0, 0, 0, 15} // Windows 10 build 19041, NTLMSSP_REVISION_W2K3

	clientSignMagic = []byte("session key to client-to-server signing key magic constant\x00")
	serverSignMagic = []byte("session key to server-to-client signing key magic constant\x00")
	clientSealMagic = []byte("session key to client-to-server sealing key magic constant\x00")
	serverSealMagic = []byte("session key to server-to-client sealing key magic constant\x00")
)

// encodeUTF16LE encodes s as little-endian UTF-16 bytes.
func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}

// md4Sum computes the RFC 1320 MD4 digest required for NTLMv2 NT hashes.
func md4Sum(data []byte) [16]byte {
	origBitLen := uint64(len(data)) * 8
	padLen := (56 - (len(data)+1)%64 + 64) % 64
	msg := make([]byte, len(data)+1+padLen+8)
	copy(msg, data)
	msg[len(data)] = 0x80
	binary.LittleEndian.PutUint64(msg[len(msg)-8:], origBitLen)

	a := uint32(0x67452301)
	b := uint32(0xefcdab89)
	c := uint32(0x98badcfe)
	d := uint32(0x10325476)

	s1 := [4]int{3, 7, 11, 19}
	s2 := [4]int{3, 5, 9, 13}
	s3 := [4]int{3, 9, 11, 15}
	order3 := [16]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}

	var x [16]uint32
	for off := 0; off < len(msg); off += 64 {
		for i := range 16 {
			x[i] = binary.LittleEndian.Uint32(msg[off+i*4:])
		}
		aa, bb, cc, dd := a, b, c, d

		for k := range 16 {
			f := (b & c) | (^b & d)
			a = bits.RotateLeft32(a+f+x[k], s1[k%4])
			a, b, c, d = d, a, b, c
		}
		for k := range 16 {
			idx := (k%4)*4 + (k / 4)
			g := (b & c) | (b & d) | (c & d)
			a = bits.RotateLeft32(a+g+x[idx]+0x5a827999, s2[k%4])
			a, b, c, d = d, a, b, c
		}
		for k := range 16 {
			h := b ^ c ^ d
			a = bits.RotateLeft32(a+h+x[order3[k]]+0x6ed9eba1, s3[k%4])
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd
	}

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint32(out[4:8], b)
	binary.LittleEndian.PutUint32(out[8:12], c)
	binary.LittleEndian.PutUint32(out[12:16], d)
	return out
}

var md5Table = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

var md5Shifts = [64]int{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

// md5Sum computes the RFC 1321 MD5 digest required by MS-NLMP key derivation
// and HMAC-MD5 signatures.
func md5Sum(parts ...[]byte) [16]byte {
	var totalLen int
	for _, p := range parts {
		totalLen += len(p)
	}
	padLen := (56 - (totalLen+1)%64 + 64) % 64
	msg := make([]byte, totalLen+1+padLen+8)
	pos := 0
	for _, p := range parts {
		pos += copy(msg[pos:], p)
	}
	msg[totalLen] = 0x80
	binary.LittleEndian.PutUint64(msg[len(msg)-8:], uint64(totalLen)*8)

	a := uint32(0x67452301)
	b := uint32(0xefcdab89)
	c := uint32(0x98badcfe)
	d := uint32(0x10325476)

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
				f = (b & c) | (^b & d)
				g = uint32(i)
			case i < 32:
				f = (d & b) | (^d & c)
				g = uint32((5*i + 1) % 16)
			case i < 48:
				f = b ^ c ^ d
				g = uint32((3*i + 5) % 16)
			default:
				f = c ^ (b | ^d)
				g = uint32((7 * i) % 16)
			}
			f = f + a + md5Table[i] + m[g]
			a = d
			d = c
			c = b
			b += bits.RotateLeft32(f, md5Shifts[i])
		}
		a += aa
		b += bb
		c += cc
		d += dd
	}

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint32(out[4:8], b)
	binary.LittleEndian.PutUint32(out[8:12], c)
	binary.LittleEndian.PutUint32(out[12:16], d)
	return out
}

// hmacMD5 computes RFC 2104 HMAC-MD5 required by MS-NLMP (NTLMv2).
func hmacMD5(key []byte, parts ...[]byte) [16]byte {
	var k [64]byte
	if len(key) > 64 {
		sum := md5Sum(key)
		copy(k[:], sum[:])
	} else {
		copy(k[:], key)
	}
	var ipad, opad [64]byte
	for i := range 64 {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}
	innerArgs := make([][]byte, 0, len(parts)+1)
	innerArgs = append(innerArgs, ipad[:])
	innerArgs = append(innerArgs, parts...)
	inner := md5Sum(innerArgs...)
	return md5Sum(opad[:], inner[:])
}

// rc4Cipher implements the stateful stream cipher required by MS-NLMP sealing.
type rc4Cipher struct {
	s    [256]byte
	i, j uint8
}

func newRC4(key []byte) *rc4Cipher {
	c := &rc4Cipher{}
	for i := range 256 {
		c.s[i] = byte(i)
	}
	var j uint8
	for i := range 256 {
		j += c.s[i] + key[i%len(key)]
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return c
}

func (c *rc4Cipher) xorKeyStream(src []byte) []byte {
	dst := make([]byte, len(src))
	i, j := c.i, c.j
	for k, b := range src {
		i++
		j += c.s[i]
		c.s[i], c.s[j] = c.s[j], c.s[i]
		dst[k] = b ^ c.s[c.s[i]+c.s[j]]
	}
	c.i, c.j = i, j
	return dst
}

type ntlmSession struct {
	clientSignKey []byte
	serverSignKey []byte
	clientSeal    *rc4Cipher
	serverSeal    *rc4Cipher
	keyExch       bool
}

func buildNTLMNegotiate() []byte {
	flags := ntlmNegotiateUnicode |
		ntlmRequestTarget |
		ntlmNegotiateSign |
		ntlmNegotiateSeal |
		ntlmNegotiateNTLM |
		ntlmNegotiateAlwaysSign |
		ntlmNegotiateExtendedSessionSecurity |
		ntlmNegotiateVersion |
		ntlmNegotiate128 |
		ntlmNegotiateKeyExch |
		ntlmNegotiate56

	msg := make([]byte, 40)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], 1) // NtLmNegotiate
	binary.LittleEndian.PutUint32(msg[12:16], flags)
	// DomainNameFields (16..24) and WorkstationFields (24..32) left zero.
	copy(msg[32:40], ntlmVersion)
	return msg
}

type avPair struct {
	id  uint16
	val []byte
}

func buildNTLMAuthenticate(negotiateMsg, challengeMsg []byte, username, password, domain, targetHost string, channelBindingsHash []byte) ([]byte, *ntlmSession, error) {
	if len(challengeMsg) < 48 {
		return nil, nil, errors.New("ntlm: challenge message truncated")
	}
	if subtle.ConstantTimeCompare(challengeMsg[0:8], ntlmSignature) != 1 || binary.LittleEndian.Uint32(challengeMsg[8:12]) != 2 {
		return nil, nil, errors.New("ntlm: invalid challenge header")
	}

	serverFlags := binary.LittleEndian.Uint32(challengeMsg[20:24])
	serverChallenge := challengeMsg[24:32]

	tiLen := uint64(binary.LittleEndian.Uint16(challengeMsg[40:42]))
	tiOff := uint64(binary.LittleEndian.Uint32(challengeMsg[44:48]))
	var targetInfo []byte
	if tiLen > 0 {
		if tiOff+tiLen > uint64(len(challengeMsg)) {
			return nil, nil, errors.New("ntlm: target info out of bounds")
		}
		targetInfo = challengeMsg[tiOff : tiOff+tiLen]
	}

	var (
		timestamp     []byte
		pairs         []avPair
		hasAVFlags    bool
		hasTargetName bool
	)
	for off := 0; off+4 <= len(targetInfo); {
		id := binary.LittleEndian.Uint16(targetInfo[off:])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[off+2:]))
		off += 4
		if off+avLen > len(targetInfo) {
			break
		}
		val := append([]byte(nil), targetInfo[off:off+avLen]...)
		off += avLen
		if id == avIDEOL {
			break
		}
		if id == avIDChannelBindings {
			continue
		}
		if id == avIDTargetName {
			hasTargetName = true
		}
		if id == avIDTimestamp && avLen == 8 {
			timestamp = val
		}
		if id == avIDFlags && avLen == 4 {
			hasAVFlags = true
			flagsVal := binary.LittleEndian.Uint32(val) | avFlagMICPresent
			binary.LittleEndian.PutUint32(val, flagsVal)
		}
		pairs = append(pairs, avPair{id: id, val: val})
	}

	if !hasAVFlags {
		f := make([]byte, 4)
		binary.LittleEndian.PutUint32(f, avFlagMICPresent)
		pairs = append(pairs, avPair{id: avIDFlags, val: f})
	}
	if timestamp == nil {
		ft := uint64(time.Now().Unix()+filetimeEpochOffsetSec) * 10000000
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
		pairs = append(pairs, avPair{id: avIDTimestamp, val: timestamp})
	}
	if !hasTargetName && targetHost != "" {
		pairs = append(pairs, avPair{id: avIDTargetName, val: encodeUTF16LE("TERMSRV/" + targetHost)})
	}
	if len(channelBindingsHash) == 16 {
		pairs = append(pairs, avPair{id: avIDChannelBindings, val: channelBindingsHash})
	}

	var encodedTI []byte
	for _, p := range pairs {
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint16(hdr[0:2], p.id)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(p.val)))
		encodedTI = append(encodedTI, hdr...)
		encodedTI = append(encodedTI, p.val...)
	}
	encodedTI = append(encodedTI, 0, 0, 0, 0) // MsvAvEOL

	ntHash := md4Sum(encodeUTF16LE(password))
	userDom := encodeUTF16LE(strings.ToUpper(username) + domain)
	responseKeyNT := hmacMD5(ntHash[:], userDom)

	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil { // NOMUTANTS -- CSPRNG entropy cannot be distinguished from fixed bytes by peers
		return nil, nil, fmt.Errorf("ntlm: generating client challenge: %w", err)
	}

	temp := make([]byte, 0, 28+len(encodedTI)+4)
	temp = append(temp, 0x01, 0x01, 0, 0, 0, 0, 0, 0)
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, encodedTI...)
	temp = append(temp, 0, 0, 0, 0)

	ntProofStr := hmacMD5(responseKeyNT[:], serverChallenge, temp)
	ntResponse := make([]byte, 0, 16+len(temp))
	ntResponse = append(ntResponse, ntProofStr[:]...)
	ntResponse = append(ntResponse, temp...)
	lmResponse := make([]byte, 24)

	sessionBaseKey := hmacMD5(responseKeyNT[:], ntProofStr[:])

	keyExch := (serverFlags & ntlmNegotiateKeyExch) != 0
	var (
		exportedSessionKey []byte
		encRandomKey       []byte
	)
	if keyExch {
		exportedSessionKey = make([]byte, 16)
		if _, err := rand.Read(exportedSessionKey); err != nil { // NOMUTANTS -- CSPRNG entropy cannot be distinguished from fixed bytes by peers
			return nil, nil, fmt.Errorf("ntlm: generating session key: %w", err)
		}
		encRandomKey = newRC4(sessionBaseKey[:]).xorKeyStream(exportedSessionKey)
	} else {
		exportedSessionKey = append([]byte(nil), sessionBaseKey[:]...)
	}

	authFlags := ntlmNegotiateUnicode |
		ntlmNegotiateSign |
		ntlmNegotiateSeal |
		ntlmNegotiateNTLM |
		ntlmNegotiateAlwaysSign |
		ntlmNegotiateExtendedSessionSecurity |
		ntlmNegotiateVersion |
		ntlmNegotiate128 |
		ntlmNegotiate56
	if keyExch {
		authFlags |= ntlmNegotiateKeyExch
	}
	if (serverFlags & ntlmRequestTarget) != 0 {
		authFlags |= ntlmRequestTarget
	}

	domBytes := encodeUTF16LE(domain)
	usrBytes := encodeUTF16LE(username)
	wsBytes := encodeUTF16LE("GOONAMI")

	const headerLen = 88 // 64 fixed + 8 version + 16 MIC
	off := headerLen
	putSecBuf := func(dst []byte, field []byte) {
		binary.LittleEndian.PutUint16(dst[0:2], uint16(len(field)))
		binary.LittleEndian.PutUint16(dst[2:4], uint16(len(field)))
		binary.LittleEndian.PutUint32(dst[4:8], uint32(off))
		off += len(field)
	}

	totalLen := headerLen + len(lmResponse) + len(ntResponse) + len(domBytes) + len(usrBytes) + len(wsBytes) + len(encRandomKey)
	authMsg := make([]byte, totalLen)
	copy(authMsg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(authMsg[8:12], 3) // NtLmAuthenticate
	putSecBuf(authMsg[12:20], lmResponse)
	putSecBuf(authMsg[20:28], ntResponse)
	putSecBuf(authMsg[28:36], domBytes)
	putSecBuf(authMsg[36:44], usrBytes)
	putSecBuf(authMsg[44:52], wsBytes)
	putSecBuf(authMsg[52:60], encRandomKey)
	binary.LittleEndian.PutUint32(authMsg[60:64], authFlags)
	copy(authMsg[64:72], ntlmVersion)
	// Bytes 72..88 are zeroed for MIC calculation.

	pos := headerLen
	pos += copy(authMsg[pos:], lmResponse)
	pos += copy(authMsg[pos:], ntResponse)
	pos += copy(authMsg[pos:], domBytes)
	pos += copy(authMsg[pos:], usrBytes)
	pos += copy(authMsg[pos:], wsBytes)
	copy(authMsg[pos:], encRandomKey)

	mic := hmacMD5(exportedSessionKey, negotiateMsg, challengeMsg, authMsg)
	copy(authMsg[72:88], mic[:])

	cSign := md5Sum(exportedSessionKey, clientSignMagic)
	sSign := md5Sum(exportedSessionKey, serverSignMagic)
	cSeal := md5Sum(exportedSessionKey, clientSealMagic)
	sSeal := md5Sum(exportedSessionKey, serverSealMagic)

	sess := &ntlmSession{
		clientSignKey: append([]byte(nil), cSign[:]...),
		serverSignKey: append([]byte(nil), sSign[:]...),
		clientSeal:    newRC4(cSeal[:]),
		serverSeal:    newRC4(sSeal[:]),
		keyExch:       keyExch,
	}
	return authMsg, sess, nil
}

func (s *ntlmSession) seal(plaintext []byte) []byte {
	ciphertext := s.clientSeal.xorKeyStream(plaintext)
	var seqBytes [4]byte
	mac := hmacMD5(s.clientSignKey, seqBytes[:], plaintext)
	checksum := mac[:8]
	if s.keyExch {
		checksum = s.clientSeal.xorKeyStream(checksum)
	}
	out := make([]byte, 16+len(ciphertext)) // out[12:16] = seqNum 0
	binary.LittleEndian.PutUint32(out[0:4], 1)
	copy(out[4:12], checksum)
	copy(out[16:], ciphertext)
	return out
}

func (s *ntlmSession) verifyAndUnseal(sealed []byte) ([]byte, bool) {
	if len(sealed) < 16 {
		return nil, false
	}
	sig := sealed[:16]
	plaintext := s.serverSeal.xorKeyStream(sealed[16:])
	var seqBytes [4]byte
	mac := hmacMD5(s.serverSignKey, seqBytes[:], plaintext)
	checksum := mac[:8]
	if s.keyExch {
		checksum = s.serverSeal.xorKeyStream(checksum)
	}
	var expectedSig [16]byte // expectedSig[12:16] = seqNum 0
	binary.LittleEndian.PutUint32(expectedSig[0:4], 1)
	copy(expectedSig[4:12], checksum)
	return plaintext, subtle.ConstantTimeCompare(sig, expectedSig[:]) == 1
}
