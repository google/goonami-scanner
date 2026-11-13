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

// Package cve202241137 detects the Apache Hive Metastore insecure Kryo
// deserialization vulnerability (CVE-2022-41137 / HIVE-26539) over the Thrift
// TBinaryProtocol get_partitions_by_expr RPC.
package cve202241137

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"github.com/google/goonami-scanner/core/net/netservice"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/cve202241137"

	defaultMetastorePort = 9083
	defaultTimeout       = 5 * time.Second
	maxMetaExceptionLen  = 8192

	thriftVersion1Call  uint32 = 0x80010001
	thriftVersion1Reply uint32 = 0x80010002
	thriftTypeStop      byte   = 0x00
	thriftTypeString    byte   = 0x0b
	thriftTypeStruct    byte   = 0x0c
	thriftTypeList      byte   = 0x0f

	thriftMethodName       = "get_partitions_by_expr"
	thriftGetAllDBsMethod  = "get_all_databases"
	thriftGetAllTblsMethod = "get_all_tables"
	probeDBName            = "default"
	probeTableName         = "tsunami_probe"
	maxDiscoveredItems     = 32
	tableNotFoundSubstring = "table not found"

	controlSeqID  uint32 = 1
	vulnSeqID     uint32 = 2
	listDBsSeqID  uint32 = 3
	listTblsSeqID uint32 = 4

	controlExpectedExprNode = "org.apache.hadoop.hive.ql.plan.ExprNode"
	controlHive23Marker     = "genericUDF (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)"
	patchedMarkerSubstring  = "The object to be deserialized must be an ExprNodeDesc"
	patchedNotAllowedMarker = "is not allowed"
	vulnCastClass           = "java.util.ArrayList"
	vulnCastSubstring       = "cannot be cast to"
	vulnTargetClass         = "java.lang.Comparable"
	vulnTraceExprNode       = "org.apache.hadoop.hive.ql.plan.ExprNode"
)

var (
	// controlExprNodeProbe is a 56-byte truncated Kryo header for
	// org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc with no field bytes.
	// On Hive 4.x (readClassAndObject), Kryo instantiates root ExprNodeGenericFuncDesc
	// and hits EOF on chidren; on Hive 2.x/3.1.x (readObject), Kryo sets chidren=null,
	// reads funcText, and fails on genericUDF. Both return a MetaException containing
	// "Serialization trace:" and "org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc".
	controlExprNodeProbe = []byte{
		0x01, 0x00,
		'o', 'r', 'g', '.', 'a', 'p', 'a', 'c', 'h', 'e', '.', 'h', 'a', 'd', 'o', 'o', 'p', '.',
		'h', 'i', 'v', 'e', '.', 'q', 'l', '.', 'p', 'l', 'a', 'n', '.',
		'E', 'x', 'p', 'r', 'N', 'o', 'd', 'e', 'G', 'e', 'n', 'e', 'r', 'i', 'c', 'F', 'u', 'n', 'c', 'D', 'e', 's', 0xe3,
		0x01,
	}

	// hive23NestedTreeMapExpr is a 54-byte Kryo payload for Hive 2.x/3.1.x
	// (SerializationUtilities.deserializeExpressionFromKryo -> kryo.readObject(input, ExprNodeGenericFuncDesc.class)).
	// It encodes an ExprNodeGenericFuncDesc whose chidren list (classCounter > 0) contains a
	// java.util.TreeMap (comparator = null) with 1 java.util.ArrayList key.
	hive23NestedTreeMapExpr = []byte{
		0x01, 0x01, 0x00,
		'j', 'a', 'v', 'a', '.', 'u', 't', 'i', 'l', '.', 'A', 'r', 'r', 'a', 'y', 'L', 'i', 's', 0xf4,
		0x01, 0x01, 0x01, 0x01,
		'j', 'a', 'v', 'a', '.', 'u', 't', 'i', 'l', '.', 'T', 'r', 'e', 'e', 'M', 'a', 0xf0,
		0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// hive4NestedTreeMapExpr is a 111-byte Kryo payload for Hive 4.x
	// (SerializationUtilities.deserializeObjectWithTypeInformation -> kryo.readClassAndObject(input)).
	// Root class is org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc (passing HIVE-26539's
	// classCounter == 0 check), and chidren (classCounter > 0) is an ArrayList containing a
	// java.util.TreeMap (comparator = null) with 1 java.util.ArrayList key.
	hive4NestedTreeMapExpr = []byte{
		0x01, 0x00,
		'o', 'r', 'g', '.', 'a', 'p', 'a', 'c', 'h', 'e', '.', 'h', 'a', 'd', 'o', 'o', 'p', '.',
		'h', 'i', 'v', 'e', '.', 'q', 'l', '.', 'p', 'l', 'a', 'n', '.',
		'E', 'x', 'p', 'r', 'N', 'o', 'd', 'e', 'G', 'e', 'n', 'e', 'r', 'i', 'c', 'F', 'u', 'n', 'c', 'D', 'e', 's', 0xe3,
		0x01, 0x01, 0x01,
		'j', 'a', 'v', 'a', '.', 'u', 't', 'i', 'l', '.', 'A', 'r', 'r', 'a', 'y', 'L', 'i', 's', 0xf4,
		0x01, 0x82, 0x01, 0x02,
		'j', 'a', 'v', 'a', '.', 'u', 't', 'i', 'l', '.', 'T', 'r', 'e', 'e', 'M', 'a', 0xf0,
		0x00, 0x01, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
	}

	errNotHiveMetastore = errors.New("not an Apache Hive Metastore Thrift service")
)

// Module implements the module.VulnDetector interface for CVE-2022-41137.
type Module struct {
	*module.BaseModule
	timeout time.Duration
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the CVE-2022-41137 detector.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	timeout := defaultTimeout
	if cfg != nil {
		if secs := cfg.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds(); secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		timeout:    timeout,
	}, nil
}

// Advisories returns the vulnerability metadata reported by this module.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "APACHE_HIVE_METASTORE_CVE_2022_41137",
		}.Build(),
		RelatedId: []*vpb.VulnerabilityId{
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     "CVE-2022-41137",
			}.Build(),
		},
		Severity:       vpb.Severity_CRITICAL,
		Title:          "Apache Hive Metastore Insecure Kryo Deserialization RCE (CVE-2022-41137)",
		Description:    "The Apache Hive Metastore Thrift service is vulnerable to unauthenticated remote code execution via insecure Kryo deserialization in the get_partitions_by_expr RPC (CVE-2022-41137 / HIVE-26539). PartitionExpressionForMetastore.deserializeExpr deserializes caller-supplied expr bytes before checking whether the target database or table exists, allowing arbitrary gadget classes (such as java.util.TreeMap nested inside ExprNodeGenericFuncDesc.chidren at classCounter > 0) to be instantiated across Hive 2.x, 3.x, and unpatched or root-only-validated 4.x builds.",
		Recommendation: "Apply depth-all Kryo class allowlist validation in SerializationUtilities$KryoWithHooks.getRegistration across all classCounter depths (blocking non-ExprNodeDesc and Map gadget classes at classCounter >= 0), and restrict network access to the Metastore Thrift port (9083) to trusted clients.",
	}.Build()
}

// Detect probes the target network service for CVE-2022-41137.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if netservice.IsWebService(service) {
		return nil, nil
	}

	if proto := service.GetTransportProtocol(); proto != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && proto != npb.TransportProtocol_TCP {
		return nil, nil
	}

	if !isCandidateService(service) {
		return nil, nil
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return nil, err
	}

	metaMsg, vulnerable, err := m.probeTarget(ctx, addr)
	if err != nil || !vulnerable {
		return nil, err
	}

	return buildDetectionReport(service, metaMsg), nil
}

func isCandidateService(service *nspb.NetworkService) bool {
	name := strings.ToLower(strings.TrimSpace(service.GetServiceName()))
	switch name {
	case "", "thrift", "apache-thrift", "hive", "hive-metastore", "metastore", "emc-pp-mgmtsvc", "unknown":
		return true
	case "tcpwrapped":
		port := service.GetNetworkEndpoint().GetPort().GetPortNumber()
		return port == defaultMetastorePort
	default:
		return false
	}
}

func (m *Module) probeTarget(ctx context.Context, addr string) (string, bool, error) {
	dbName := probeDBName
	tblName := probeTableName

	// Step 1 (Negative Control & Wire-Format Fingerprint): Send a 56-byte truncated
	// ExprNodeGenericFuncDesc Kryo header and verify that the target responds with a
	// valid Thrift TBinaryProtocol get_partitions_by_expr MetaException referencing
	// ExprNodeGenericFuncDesc. On Hive 2.x/3.x where fireReadTablePreEvent checks
	// table existence before Kryo deserialization, discover an existing table via
	// get_all_databases / get_all_tables if default.tsunami_probe returns
	// NoSuchObjectException ("table not found").
	controlMsg, err := m.sendGetPartitionsByExpr(ctx, addr, controlSeqID, dbName, tblName, controlExprNodeProbe)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", false, err
		}
		return "", false, nil
	}
	if strings.Contains(controlMsg, tableNotFoundSubstring) {
		foundDB, foundTbl, findErr := m.discoverExistingTable(ctx, addr)
		if findErr != nil {
			if errors.Is(findErr, context.Canceled) || errors.Is(findErr, context.DeadlineExceeded) {
				return "", false, findErr
			}
			return "", false, nil
		}
		if foundDB == "" || foundTbl == "" {
			return "", false, nil
		}
		dbName = foundDB
		tblName = foundTbl
		controlMsg, err = m.sendGetPartitionsByExpr(ctx, addr, controlSeqID, dbName, tblName, controlExprNodeProbe)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", false, err
			}
			return "", false, nil
		}
	}
	if !strings.Contains(controlMsg, controlExpectedExprNode) || strings.Contains(controlMsg, vulnCastSubstring) {
		return "", false, nil
	}

	// Step 2 (Active Nested Kryo Deserialization Probe): Select the Hive 2.x/3.1.x
	// (readObject) or Hive 4.x (readClassAndObject) nested TreeMap payload based on
	// Step 1's serialization trace. Vulnerable instances instantiate java.util.TreeMap
	// inside ExprNodeGenericFuncDesc.chidren (classCounter > 0) and fail in
	// TreeMap.put(ArrayList, null) with ClassCastException.
	probePayload := hive4NestedTreeMapExpr
	if strings.Contains(controlMsg, controlHive23Marker) {
		probePayload = hive23NestedTreeMapExpr
	}

	vulnMsg, err := m.sendGetPartitionsByExpr(ctx, addr, vulnSeqID, dbName, tblName, probePayload)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", false, err
		}
		return "", false, nil
	}

	if strings.Contains(vulnMsg, patchedMarkerSubstring) || strings.Contains(vulnMsg, patchedNotAllowedMarker) {
		return "", false, nil
	}

	if strings.Contains(vulnMsg, vulnCastClass) &&
		strings.Contains(vulnMsg, vulnCastSubstring) &&
		strings.Contains(vulnMsg, vulnTargetClass) &&
		strings.Contains(vulnMsg, vulnTraceExprNode) {
		return vulnMsg, true, nil
	}

	return "", false, nil
}

func (m *Module) discoverExistingTable(ctx context.Context, addr string) (string, string, error) {
	dbs, err := m.sendGetAllDatabases(ctx, addr)
	if err != nil {
		return "", "", err
	}
	if len(dbs) == 0 {
		dbs = []string{probeDBName}
	}
	for _, db := range dbs {
		tbls, err := m.sendGetAllTables(ctx, addr, db)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", "", err
			}
			continue
		}
		if len(tbls) > 0 && tbls[0] != "" {
			return db, tbls[0], nil
		}
	}
	return "", "", nil
}

func (m *Module) sendGetAllDatabases(ctx context.Context, addr string) ([]string, error) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, thriftVersion1Call)
	writeThriftString(&buf, []byte(thriftGetAllDBsMethod))
	_ = binary.Write(&buf, binary.BigEndian, listDBsSeqID)
	buf.WriteByte(thriftTypeStop)
	return m.sendThriftStringListRPC(ctx, addr, thriftGetAllDBsMethod, listDBsSeqID, buf.Bytes())
}

func (m *Module) sendGetAllTables(ctx context.Context, addr, dbName string) ([]string, error) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, thriftVersion1Call)
	writeThriftString(&buf, []byte(thriftGetAllTblsMethod))
	_ = binary.Write(&buf, binary.BigEndian, listTblsSeqID)
	buf.WriteByte(thriftTypeString)
	_ = binary.Write(&buf, binary.BigEndian, int16(1))
	writeThriftString(&buf, []byte(dbName))
	buf.WriteByte(thriftTypeStop)
	return m.sendThriftStringListRPC(ctx, addr, thriftGetAllTblsMethod, listTblsSeqID, buf.Bytes())
}

func (m *Module) sendThriftStringListRPC(ctx context.Context, addr, methodName string, seqID uint32, req []byte) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	dialer := net.Dialer{Timeout: m.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(m.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if _, err := conn.Write(req); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	items, err := readStringListReply(conn, methodName, seqID)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return items, nil
}

func (m *Module) sendGetPartitionsByExpr(ctx context.Context, addr string, seqID uint32, dbName, tblName string, exprBytes []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	dialer := net.Dialer{Timeout: m.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(m.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}

	req := buildGetPartitionsByExprRequest(seqID, dbName, tblName, exprBytes)
	if _, err := conn.Write(req); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", err
	}

	msg, err := readMetaExceptionReply(conn, seqID)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", err
	}
	return msg, nil
}

func buildGetPartitionsByExprRequest(seqID uint32, dbName, tblName string, exprBytes []byte) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, thriftVersion1Call)
	writeThriftString(&buf, []byte(thriftMethodName))
	_ = binary.Write(&buf, binary.BigEndian, seqID)

	// Field 1 of get_partitions_by_expr_args: PartitionsByExprRequest (STRUCT, id=1)
	buf.WriteByte(thriftTypeStruct)
	_ = binary.Write(&buf, binary.BigEndian, int16(1))

	// Field 1: dbName (STRING, id=1)
	buf.WriteByte(thriftTypeString)
	_ = binary.Write(&buf, binary.BigEndian, int16(1))
	writeThriftString(&buf, []byte(dbName))

	// Field 2: tblName (STRING, id=2)
	buf.WriteByte(thriftTypeString)
	_ = binary.Write(&buf, binary.BigEndian, int16(2))
	writeThriftString(&buf, []byte(tblName))

	// Field 3: expr (BINARY/STRING, id=3)
	buf.WriteByte(thriftTypeString)
	_ = binary.Write(&buf, binary.BigEndian, int16(3))
	writeThriftString(&buf, exprBytes)

	// End of PartitionsByExprRequest struct + End of get_partitions_by_expr_args struct
	buf.WriteByte(thriftTypeStop)
	buf.WriteByte(thriftTypeStop)
	return buf.Bytes()
}

func writeThriftString(buf *bytes.Buffer, data []byte) {
	_ = binary.Write(buf, binary.BigEndian, uint32(len(data)))
	buf.Write(data)
}

func readMetaExceptionReply(r io.Reader, wantSeqID uint32) (string, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", err
	}
	versionAndType := binary.BigEndian.Uint32(hdr[0:4])
	methodLen := binary.BigEndian.Uint32(hdr[4:8])
	if versionAndType != thriftVersion1Reply || methodLen != uint32(len(thriftMethodName)) {
		return "", errNotHiveMetastore
	}

	methodAndSeq := make([]byte, len(thriftMethodName)+4)
	if _, err := io.ReadFull(r, methodAndSeq); err != nil {
		return "", err
	}
	if string(methodAndSeq[:len(thriftMethodName)]) != thriftMethodName {
		return "", errNotHiveMetastore
	}
	gotSeqID := binary.BigEndian.Uint32(methodAndSeq[len(thriftMethodName):])
	if gotSeqID != wantSeqID {
		return "", errNotHiveMetastore
	}

	// Read outer struct field header: MetaException (TType.STRUCT=12, fieldID=1) or
	// NoSuchObjectException (TType.STRUCT=12, fieldID=2).
	var outerField [3]byte
	if _, err := io.ReadFull(r, outerField[:]); err != nil {
		return "", err
	}
	outerType := outerField[0]
	outerID := binary.BigEndian.Uint16(outerField[1:3])
	if outerType != thriftTypeStruct || (outerID != 1 && outerID != 2) {
		return "", errNotHiveMetastore
	}

	// Read exception message field header (TType.STRING=11, fieldID=1, 4-byte length)
	var innerField [7]byte
	if _, err := io.ReadFull(r, innerField[:]); err != nil {
		return "", err
	}
	innerType := innerField[0]
	innerID := binary.BigEndian.Uint16(innerField[1:3])
	msgLen := binary.BigEndian.Uint32(innerField[3:7])
	if innerType != thriftTypeString || innerID != 1 || msgLen > maxMetaExceptionLen {
		return "", errNotHiveMetastore
	}

	msgAndStops := make([]byte, msgLen+2)
	if _, err := io.ReadFull(r, msgAndStops); err != nil {
		return "", err
	}
	return string(msgAndStops[:msgLen]), nil
}

func readStringListReply(r io.Reader, wantMethod string, wantSeqID uint32) ([]string, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	versionAndType := binary.BigEndian.Uint32(hdr[0:4])
	methodLen := binary.BigEndian.Uint32(hdr[4:8])
	if versionAndType != thriftVersion1Reply || methodLen != uint32(len(wantMethod)) {
		return nil, errNotHiveMetastore
	}

	methodAndSeq := make([]byte, len(wantMethod)+4)
	if _, err := io.ReadFull(r, methodAndSeq); err != nil {
		return nil, err
	}
	if string(methodAndSeq[:len(wantMethod)]) != wantMethod {
		return nil, errNotHiveMetastore
	}
	gotSeqID := binary.BigEndian.Uint32(methodAndSeq[len(wantMethod):])
	if gotSeqID != wantSeqID {
		return nil, errNotHiveMetastore
	}

	// Read field 0: LIST<STRING> (type=0x0f, fieldID=0, elemType=0x0b, count=uint32)
	var listHdr [8]byte
	if _, err := io.ReadFull(r, listHdr[:]); err != nil {
		return nil, err
	}
	fieldType := listHdr[0]
	fieldID := binary.BigEndian.Uint16(listHdr[1:3])
	elemType := listHdr[3]
	count := binary.BigEndian.Uint32(listHdr[4:8])
	if fieldType != thriftTypeList || fieldID != 0 || elemType != thriftTypeString {
		return nil, errNotHiveMetastore
	}
	if count > maxDiscoveredItems {
		count = maxDiscoveredItems
	}

	items := make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, err
		}
		strLen := binary.BigEndian.Uint32(lenBuf[:])
		if strLen > maxMetaExceptionLen {
			return nil, errNotHiveMetastore
		}
		strBytes := make([]byte, strLen)
		if _, err := io.ReadFull(r, strBytes); err != nil {
			return nil, err
		}
		items = append(items, string(strBytes))
	}
	return items, nil
}

func buildDetectionReport(service *nspb.NetworkService, metaExceptionMsg string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Verified unvalidated Kryo deserialization via Thrift get_partitions_by_expr",
			TextData: vpb.TextData_builder{
				Text: fmt.Sprintf("Thrift get_partitions_by_expr deserialized nested non-ExprNodeDesc class java.util.TreeMap and returned MetaException: %q", metaExceptionMsg),
			}.Build(),
		}.Build(),
	})

	return dpb.DetectionReportList_builder{
		DetectionReports: []*dpb.DetectionReport{
			dpb.DetectionReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						service.GetNetworkEndpoint(),
					},
				}.Build(),
				NetworkService:     service,
				DetectionTimestamp: tspb.Now(),
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      vuln,
			}.Build(),
		},
	}.Build()
}
