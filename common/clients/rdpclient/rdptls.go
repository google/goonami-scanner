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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1 requested & selected security protocols.
	protocolRDP      uint32 = 0x00000000
	protocolSSL      uint32 = 0x00000001
	protocolHybrid   uint32 = 0x00000002
	protocolHybridEx uint32 = 0x00000008

	rdpNegReq     byte = 0x01
	rdpNegRsp     byte = 0x02
	rdpNegFailure byte = 0x03

	postActivationDrainTimeout = 150 * time.Millisecond

	// TS_INFO_PACKET flags (MS-RDPBCGR 2.2.1.11.1.1).
	infoMouse             uint32 = 0x00000001
	infoDisableCtrlAltDel uint32 = 0x00000002
	infoAutoLogon         uint32 = 0x00000008
	infoUnicode           uint32 = 0x00000010
	infoMaximizeShell     uint32 = 0x00000020
	infoLogonNotify       uint32 = 0x00000040

	secInfoPkt    uint16 = 0x0040
	secLicensePkt uint16 = 0x0080

	licenseErrorAlert byte = 0xff

	pduTypeDemandActive  uint16 = 0x0001
	pduTypeConfirmActive uint16 = 0x0003
	pduTypeDeactivateAll uint16 = 0x0006
	pduTypeData          uint16 = 0x0007

	pduType2Update          byte = 0x02
	pduType2Control         byte = 0x14
	pduType2Synchronize     byte = 0x1f
	pduType2SaveSessionInfo byte = 0x26
	pduType2FontList        byte = 0x27
	pduType2FontMap         byte = 0x28
	pduType2SetErrorInfo    byte = 0x2f

	// TS_SAVE_SESSION_INFO_PDU_DATA infoType values confirming logon.
	infoTypeLogon            uint32 = 0x00000000
	infoTypeLogonLong        uint32 = 0x00000001
	infoTypeLogonPlainNotify uint32 = 0x00000002
	infoTypeLogonExtendedInf uint32 = 0x00000003
)

type x224Result struct {
	responseType     byte
	selectedProtocol uint32
	failureCode      uint32
}

// x224Negotiate sends an RDP X.224 Connection Request over TPKT and parses the
// X.224 Connection Confirm.
func x224Negotiate(conn net.Conn, requestedProtocols uint32) (x224Result, error) {
	var negReq [8]byte // negReq[1] flags = 0x00
	negReq[0] = rdpNegReq
	binary.LittleEndian.PutUint16(negReq[2:4], 8)
	binary.LittleEndian.PutUint32(negReq[4:8], requestedProtocols)

	cookie := []byte("Cookie: mstshash=goonami\r\n")
	li := byte(6 + len(cookie) + len(negReq))
	x224Payload := make([]byte, 0, int(li)+1)
	x224Payload = append(x224Payload, li, 0xe0, 0, 0, 0, 0, 0)
	x224Payload = append(x224Payload, cookie...)
	x224Payload = append(x224Payload, negReq[:]...)

	tpkt := make([]byte, 4+len(x224Payload)) // tpkt[1] reserved = 0x00
	tpkt[0] = 0x03
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(len(tpkt)))
	copy(tpkt[4:], x224Payload)

	if _, err := conn.Write(tpkt); err != nil {
		return x224Result{}, fmt.Errorf("%w: writing X.224 request: %w", ErrNotRDPService, err)
	}

	body, err := readTPKT(conn)
	if err != nil {
		return x224Result{}, fmt.Errorf("%w: reading X.224 confirm: %w", ErrNotRDPService, err)
	}
	if len(body) < 7 || (body[1]&0xf0) != 0xd0 || int(body[0])+1 > len(body) {
		return x224Result{}, fmt.Errorf("%w: invalid X.224 connection confirm", ErrNotRDPService)
	}
	if len(body) < 15 {
		return x224Result{responseType: rdpNegRsp, selectedProtocol: protocolRDP}, nil
	}
	if binary.LittleEndian.Uint16(body[9:11]) != 8 {
		return x224Result{}, fmt.Errorf("%w: invalid rdpNegData length", ErrNotRDPService)
	}

	res := x224Result{responseType: body[7]}
	val := binary.LittleEndian.Uint32(body[11:15])
	switch res.responseType {
	case rdpNegRsp:
		res.selectedProtocol = val
	case rdpNegFailure:
		res.failureCode = val
	default:
		return x224Result{}, fmt.Errorf("%w: unexpected RDP negotiation type 0x%02x", ErrNotRDPService, res.responseType)
	}
	return res, nil
}

func readTPKT(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x03 {
		return nil, fmt.Errorf("tpkt: invalid version 0x%02x", hdr[0])
	}
	pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if pktLen < 4 {
		return nil, fmt.Errorf("tpkt: invalid length %d", pktLen)
	}
	body := make([]byte, pktLen-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeTPKT(w io.Writer, x224Data []byte) error {
	pkt := make([]byte, 4+3+len(x224Data)) // pkt[1] reserved = 0x00
	pkt[0] = 0x03
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[4] = 0x02
	pkt[5] = 0xf0
	pkt[6] = 0x80
	copy(pkt[7:], x224Data)
	_, err := w.Write(pkt)
	return err
}

func encodePERLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	return []byte{byte(0x80 | (n >> 8)), byte(n & 0xff)}
}

func buildMCSConnectInitial(selectedProtocol uint32) []byte {
	clientName := make([]byte, 32)
	copy(clientName, encodeUTF16LE("goonami"))

	var csCoreData bytes.Buffer
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint32(0x00080004)) // version RDP 5.0+
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint16(800))        // desktopWidth
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint16(600))        // desktopHeight
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint16(0xca01))     // colorDepth
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint16(0xaa03))     // SASSequence
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint32(0x0409))     // keyboardLayout
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint32(2600))       // clientBuild
	csCoreData.Write(clientName)
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint32(4))  // keyboardType
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint32(0))  // keyboardSubType
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint32(12)) // keyboardFunctionKey
	csCoreData.Write(make([]byte, 64))                             // imeFileName
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint16(0xca01))
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint16(1))
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint32(0))
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint16(0x0018)) // highColorDepth
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint16(0x0007)) // supportedColorDepths
	_ = binary.Write(&csCoreData, binary.LittleEndian, uint16(0x0001)) // earlyCapabilityFlags
	csCoreData.Write(make([]byte, 64))                                 // clientDigProductId
	csCoreData.Write([]byte{0, 0})                                     // connectionType, pad1Octet
	_ = binary.Write(&csCoreData, binary.LittleEndian, selectedProtocol)

	var userData bytes.Buffer
	_ = binary.Write(&userData, binary.LittleEndian, uint16(0xc001))
	_ = binary.Write(&userData, binary.LittleEndian, uint16(4+csCoreData.Len()))
	userData.Write(csCoreData.Bytes())
	_ = binary.Write(&userData, binary.LittleEndian, uint16(0xc002))
	_ = binary.Write(&userData, binary.LittleEndian, uint16(12))
	_ = binary.Write(&userData, binary.LittleEndian, uint32(0))
	_ = binary.Write(&userData, binary.LittleEndian, uint32(0))
	_ = binary.Write(&userData, binary.LittleEndian, uint16(0xc003))
	_ = binary.Write(&userData, binary.LittleEndian, uint16(8))
	_ = binary.Write(&userData, binary.LittleEndian, uint32(0))

	udBytes := userData.Bytes()
	var gccInner []byte
	gccInner = append(gccInner, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75, 0x63, 0x61)
	gccInner = append(gccInner, encodePERLength(len(udBytes))...)
	gccInner = append(gccInner, udBytes...)

	var gccReq []byte
	gccReq = append(gccReq, 0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01)
	gccReq = append(gccReq, encodePERLength(len(gccInner))...)
	gccReq = append(gccReq, gccInner...)

	berDomainParams := func(maxCh, maxUsers, maxTok, maxPDU int) []byte {
		var p []byte
		p = append(p, derInt(maxCh)...)
		p = append(p, derInt(maxUsers)...)
		p = append(p, derInt(maxTok)...)
		p = append(p, derInt(1)...)
		p = append(p, derInt(0)...)
		p = append(p, derInt(1)...)
		p = append(p, derInt(maxPDU)...)
		p = append(p, derInt(2)...)
		return derTLV(0x30, p)
	}

	var mcsBody []byte
	mcsBody = append(mcsBody, derTLV(0x04, []byte{0x01})...)
	mcsBody = append(mcsBody, derTLV(0x04, []byte{0x01})...)
	mcsBody = append(mcsBody, derTLV(0x01, []byte{0xff})...)
	mcsBody = append(mcsBody, berDomainParams(34, 2, 0, 65535)...)
	mcsBody = append(mcsBody, berDomainParams(1, 1, 1, 1056)...)
	mcsBody = append(mcsBody, berDomainParams(65535, 64535, 65535, 65535)...)
	mcsBody = append(mcsBody, derTLV(0x04, gccReq)...)

	out := make([]byte, 0, 2+4+len(mcsBody))
	out = append(out, 0x7f, 0x65)
	out = append(out, derEncodeLength(len(mcsBody))...)
	out = append(out, mcsBody...)
	return out
}

func sendMCSData(w io.Writer, userID, channelID uint16, payload []byte) error {
	var buf bytes.Buffer
	buf.WriteByte(0x64) // SendDataRequest
	_ = binary.Write(&buf, binary.BigEndian, userID-1001)
	_ = binary.Write(&buf, binary.BigEndian, channelID)
	buf.WriteByte(0x70)
	buf.Write(encodePERLength(len(payload)))
	buf.Write(payload)
	return writeTPKT(w, buf.Bytes())
}

func buildClientInfoPDU(username, password, domain string) []byte {
	domBytes := encodeUTF16LE(domain)
	usrBytes := encodeUTF16LE(username)
	pwdBytes := encodeUTF16LE(password)

	flags := infoMouse | infoDisableCtrlAltDel | infoUnicode | infoMaximizeShell | infoLogonNotify
	if username != "" || password != "" {
		flags |= infoAutoLogon
	}

	clientAddr := encodeUTF16LE("127.0.0.1\x00")
	clientDir := encodeUTF16LE("\x00")

	var buf bytes.Buffer
	// Basic Security Header: SEC_INFO_PKT (0x0040)
	_ = binary.Write(&buf, binary.LittleEndian, secInfoPkt)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	// TS_INFO_PACKET
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // codePage
	_ = binary.Write(&buf, binary.LittleEndian, flags)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(domBytes)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(usrBytes)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(pwdBytes)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // cbAlternateShell
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // cbWorkingDir
	buf.Write(domBytes)
	buf.Write([]byte{0, 0})
	buf.Write(usrBytes)
	buf.Write([]byte{0, 0})
	buf.Write(pwdBytes)
	buf.Write([]byte{0, 0})
	buf.Write([]byte{0, 0, 0, 0}) // AlternateShell + WorkingDir null terminators
	// TS_EXTENDED_INFO_PACKET
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0002)) // AF_INET
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(clientAddr)))
	buf.Write(clientAddr)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(clientDir)))
	buf.Write(clientDir)
	buf.Write(make([]byte, 172)) // TS_TIME_ZONE_INFORMATION
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

func buildConfirmActivePDU(userID uint16, shareID uint32) []byte {
	srcDesc := []byte("MSTSC\x00")

	// TS_GENERAL_CAPABILITYSET (24 bytes) with FASTPATH_OUTPUT_SUPPORTED (0x0001).
	var capGeneral bytes.Buffer
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(0x0001)) // CAPSTYPE_GENERAL
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(24))
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(1))      // osMajorType Windows
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(3))      // osMinorType NT
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(0x0200)) // protocolVersion
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(0))      // pad2octetsA
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(0))      // generalCompressionTypes
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(0x0001)) // extraFlags: FASTPATH_OUTPUT_SUPPORTED
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(0))      // updateCapabilityFlag
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(0))      // remoteUnshareFlag
	_ = binary.Write(&capGeneral, binary.LittleEndian, uint16(0))      // generalCompressionLevel
	capGeneral.Write([]byte{0, 0})                                     // refreshRectSupport, suppressOutputSupport

	// TS_BITMAP_CAPABILITYSET (28 bytes).
	var capBitmap bytes.Buffer
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(0x0002)) // CAPSTYPE_BITMAP
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(28))
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(16))  // preferredBitsPerPixel
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(1))   // receive1BitPerPixel
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(1))   // receive4BitsPerPixel
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(1))   // receive8BitsPerPixel
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(800)) // desktopWidth
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(600)) // desktopHeight
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(0))   // pad2octets
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(1))   // desktopResizeFlag
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(1))   // bitmapCompressionFlag
	capBitmap.Write([]byte{0, 0})                                  // highColorFlags, drawingFlags
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(1))   // multipleRectangleSupport
	_ = binary.Write(&capBitmap, binary.LittleEndian, uint16(0))   // pad2octetsB

	var caps bytes.Buffer
	_ = binary.Write(&caps, binary.LittleEndian, uint16(2)) // numberCapabilities
	_ = binary.Write(&caps, binary.LittleEndian, uint16(0)) // pad2Octets
	caps.Write(capGeneral.Bytes())
	caps.Write(capBitmap.Bytes())

	var body bytes.Buffer
	_ = binary.Write(&body, binary.LittleEndian, shareID)
	_ = binary.Write(&body, binary.LittleEndian, uint16(0x03ea)) // originatorId
	_ = binary.Write(&body, binary.LittleEndian, uint16(len(srcDesc)))
	_ = binary.Write(&body, binary.LittleEndian, uint16(caps.Len()))
	body.Write(srcDesc)
	body.Write(caps.Bytes())

	var pdu bytes.Buffer
	_ = binary.Write(&pdu, binary.LittleEndian, uint16(6+body.Len()))
	_ = binary.Write(&pdu, binary.LittleEndian, uint16(pduTypeConfirmActive|(1<<4)))
	_ = binary.Write(&pdu, binary.LittleEndian, userID)
	pdu.Write(body.Bytes())
	return pdu.Bytes()
}

func sendShareDataPDU(w io.Writer, userID, channelID uint16, shareID uint32, pduType2 byte, data []byte) error {
	var pdu bytes.Buffer
	totalLen := uint16(6 + 12 + len(data))
	_ = binary.Write(&pdu, binary.LittleEndian, totalLen)
	_ = binary.Write(&pdu, binary.LittleEndian, uint16(pduTypeData|(1<<4)))
	_ = binary.Write(&pdu, binary.LittleEndian, userID)
	_ = binary.Write(&pdu, binary.LittleEndian, shareID)
	pdu.WriteByte(0) // pad1
	pdu.WriteByte(1) // streamId = STREAM_LOW
	_ = binary.Write(&pdu, binary.LittleEndian, uint16(len(data)+4))
	pdu.WriteByte(pduType2)
	pdu.WriteByte(0) // compressedType
	_ = binary.Write(&pdu, binary.LittleEndian, uint16(0))
	pdu.Write(data)
	return sendMCSData(w, userID, channelID, pdu.Bytes())
}

type tlsExchangeOutcome int

const (
	tlsOutcomeUnsupported tlsExchangeOutcome = iota
	tlsOutcomeRejected
	tlsOutcomeDesktopActive
	tlsOutcomeSaveSessionInfo
)

// extractMCSIndicationPayload returns the RDP payload inside an MCS
// SendDataIndication (0x68) TPKT body.
func extractMCSIndicationPayload(tpktBody []byte) ([]byte, bool) {
	// X.224 DT (3) + 0x68 (1) + initiator (2) + channelId (2) + dataPriority (1) = 9 bytes before PER length.
	if len(tpktBody) < 10 || tpktBody[3] != 0x68 {
		return nil, false
	}
	off := 9
	if tpktBody[off]&0x80 != 0 {
		off += 2
	} else {
		off++
	}
	if off > len(tpktBody) {
		return nil, false
	}
	return tpktBody[off:], true
}

func isLogonSaveSessionInfo(rdpData []byte) bool {
	// ShareControlHeader (6) + ShareDataHeader (12) + infoType (4) = 22 bytes.
	if len(rdpData) < 22 {
		return false
	}
	infoType := binary.LittleEndian.Uint32(rdpData[18:])
	return infoType <= infoTypeLogonExtendedInf
}

// runTLSExchange performs an MS-RDPBCGR MCS + ClientInfo + Activation sequence
// over an established PROTOCOL_SSL TLS connection and classifies the post-auth
// server outcome.
func runTLSExchange(conn net.Conn, username, password, domain string) (tlsExchangeOutcome, error) {
	if err := writeTPKT(conn, buildMCSConnectInitial(protocolSSL)); err != nil {
		return tlsOutcomeUnsupported, fmt.Errorf("%w: writing MCS Connect-Initial: %w", ErrNotRDPService, err)
	}
	cr, err := readTPKT(conn)
	if err != nil {
		return tlsOutcomeUnsupported, fmt.Errorf("%w: reading MCS Connect-Response: %w", ErrNotRDPService, err)
	}

	ioChannel := uint16(1003)
	if idx := bytes.Index(cr, []byte{0x03, 0x0c}); idx != -1 && idx+8 <= len(cr) {
		ioChannel = binary.LittleEndian.Uint16(cr[idx+4 : idx+6])
	}

	// Erect Domain Request + Attach User Request.
	if err := writeTPKT(conn, []byte{0x04, 0x01, 0x00, 0x01, 0x00}); err != nil {
		return tlsOutcomeUnsupported, fmt.Errorf("%w: writing Erect Domain: %w", ErrNotRDPService, err)
	}
	if err := writeTPKT(conn, []byte{0x28}); err != nil {
		return tlsOutcomeUnsupported, fmt.Errorf("%w: writing Attach User: %w", ErrNotRDPService, err)
	}
	auc, err := readTPKT(conn)
	if err != nil || len(auc) < 7 {
		return tlsOutcomeUnsupported, fmt.Errorf("%w: reading Attach User Confirm", ErrNotRDPService)
	}
	userID := binary.BigEndian.Uint16(auc[5:7]) + 1001

	for _, ch := range []uint16{userID, ioChannel} {
		var cj [5]byte
		cj[0] = 0x38
		binary.BigEndian.PutUint16(cj[1:3], userID-1001)
		binary.BigEndian.PutUint16(cj[3:5], ch)
		if err := writeTPKT(conn, cj[:]); err != nil {
			return tlsOutcomeUnsupported, fmt.Errorf("%w: writing Channel Join: %w", ErrNotRDPService, err)
		}
		if _, err := readTPKT(conn); err != nil {
			return tlsOutcomeUnsupported, fmt.Errorf("%w: reading Channel Join Confirm: %w", ErrNotRDPService, err)
		}
	}

	// Send Client Info PDU carrying candidate credentials.
	if err := sendMCSData(conn, userID, ioChannel, buildClientInfoPDU(username, password, domain)); err != nil {
		return tlsOutcomeUnsupported, fmt.Errorf("%w: writing Client Info PDU: %w", ErrNotRDPService, err)
	}

	// Read Server Licensing / Demand Active PDUs.
	var (
		shareID      uint32
		gotDemandAct bool
	)
	for range 6 {
		body, err := readTPKT(conn)
		if err != nil {
			if isDisconnectError(err) {
				return tlsOutcomeRejected, nil
			}
			return tlsOutcomeUnsupported, nil
		}
		if len(body) >= 4 && (body[3]&0xfc) == 0x20 { // DisconnectProviderUltimatum
			return tlsOutcomeRejected, nil
		}
		rdpData, ok := extractMCSIndicationPayload(body)
		if !ok || len(rdpData) < 6 {
			continue
		}
		flagsOrLen := binary.LittleEndian.Uint16(rdpData[0:2])
		flagsHiOrType := binary.LittleEndian.Uint16(rdpData[2:4])
		if flagsHiOrType == 0 && (flagsOrLen&secLicensePkt) != 0 {
			if rdpData[4] != licenseErrorAlert {
				// Server initiated interactive RDPELE license negotiation (e.g. xrdp);
				// short-circuit immediately rather than waiting for timeout.
				return tlsOutcomeUnsupported, nil
			}
			continue
		}
		if (flagsHiOrType&0x000f) == pduTypeDemandActive && len(rdpData) >= 10 {
			shareID = binary.LittleEndian.Uint32(rdpData[6:10])
			gotDemandAct = true
			break
		}
	}
	if !gotDemandAct {
		return tlsOutcomeUnsupported, nil
	}

	// Complete Capabilities Exchange & Connection Finalization.
	if err := sendMCSData(conn, userID, ioChannel, buildConfirmActivePDU(userID, shareID)); err != nil {
		return tlsOutcomeRejected, nil
	}
	if err := sendShareDataPDU(conn, userID, ioChannel, shareID, pduType2Synchronize, []byte{0x01, 0x00, 0xea, 0x03}); err != nil {
		return tlsOutcomeRejected, nil
	}
	if err := sendShareDataPDU(conn, userID, ioChannel, shareID, pduType2Control, []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return tlsOutcomeRejected, nil
	}
	if err := sendShareDataPDU(conn, userID, ioChannel, shareID, pduType2Control, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return tlsOutcomeRejected, nil
	}
	if err := sendShareDataPDU(conn, userID, ioChannel, shareID, pduType2FontList, []byte{0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x32, 0x00}); err != nil {
		return tlsOutcomeRejected, nil
	}

	// Read post-activation PDUs (both TPKT ShareData and FastPath output).
	sawDesktopOutput := false
	for range 12 {
		var hdr0 [1]byte
		if _, err := io.ReadFull(conn, hdr0[:]); err != nil {
			if sawDesktopOutput {
				return tlsOutcomeDesktopActive, nil
			}
			if isDisconnectError(err) {
				return tlsOutcomeRejected, nil
			}
			return tlsOutcomeUnsupported, nil
		}

		if hdr0[0] == 0x03 {
			var rest [3]byte
			if _, err := io.ReadFull(conn, rest[:]); err != nil {
				if isDisconnectError(err) {
					return tlsOutcomeRejected, nil
				}
				return tlsOutcomeUnsupported, nil
			}
			pktLen := int(binary.BigEndian.Uint16(rest[1:3]))
			if pktLen < 4 {
				return tlsOutcomeUnsupported, nil
			}
			body := make([]byte, pktLen-4)
			if _, err := io.ReadFull(conn, body); err != nil {
				if isDisconnectError(err) {
					return tlsOutcomeRejected, nil
				}
				return tlsOutcomeUnsupported, nil
			}
			if len(body) >= 4 && (body[3]&0xfc) == 0x20 { // DisconnectProviderUltimatum
				return tlsOutcomeRejected, nil
			}
			rdpData, ok := extractMCSIndicationPayload(body)
			if !ok || len(rdpData) < 6 {
				continue
			}
			pduType := binary.LittleEndian.Uint16(rdpData[2:4]) & 0x000f
			if pduType == pduTypeDeactivateAll {
				return tlsOutcomeRejected, nil
			}
			if pduType != pduTypeData || len(rdpData) < 15 {
				continue
			}
			pduType2 := rdpData[14]
			switch pduType2 {
			case pduType2SaveSessionInfo:
				if isLogonSaveSessionInfo(rdpData) {
					return tlsOutcomeSaveSessionInfo, nil
				}
			case pduType2SetErrorInfo:
				if len(rdpData) >= 22 && binary.LittleEndian.Uint32(rdpData[18:22]) != 0 {
					return tlsOutcomeRejected, nil
				}
			case pduType2Update:
				if !sawDesktopOutput {
					sawDesktopOutput = true
					_ = conn.SetReadDeadline(time.Now().Add(postActivationDrainTimeout)) // NOMUTANTS -- bounded post-frame drain deadline
				}
			case pduType2FontMap:
				// Continue reading to observe either PAM/PostConnect disconnect or desktop output / SaveSessionInfo.
			}
			continue
		}

		if (hdr0[0] & 0x03) == 0x00 {
			// MS-RDPBCGR FastPath Output Update PDU; drain briefly for trailing SaveSessionInfo or error PDUs.
			var l1 [1]byte
			if _, err := io.ReadFull(conn, l1[:]); err != nil {
				if isDisconnectError(err) {
					return tlsOutcomeRejected, nil
				}
				return tlsOutcomeUnsupported, nil
			}
			var fpLen, hdrLen int
			if l1[0]&0x80 != 0 {
				var l2 [1]byte
				if _, err := io.ReadFull(conn, l2[:]); err != nil {
					return tlsOutcomeUnsupported, nil
				}
				fpLen = (int(l1[0]&0x7f) << 8) | int(l2[0])
				hdrLen = 3
			} else {
				fpLen = int(l1[0])
				hdrLen = 2
			}
			if fpLen > hdrLen {
				if _, err := io.CopyN(io.Discard, conn, int64(fpLen-hdrLen)); err != nil {
					if isDisconnectError(err) {
						return tlsOutcomeRejected, nil
					}
					return tlsOutcomeUnsupported, nil
				}
			}
			if !sawDesktopOutput {
				sawDesktopOutput = true
				_ = conn.SetReadDeadline(time.Now().Add(postActivationDrainTimeout)) // NOMUTANTS -- bounded post-frame drain deadline
			}
			continue
		}

		return tlsOutcomeUnsupported, nil
	}

	if sawDesktopOutput {
		return tlsOutcomeDesktopActive, nil
	}
	return tlsOutcomeUnsupported, nil
}

func isDisconnectError(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return true
}
