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

// Package redisunauthrce detects unauthenticated Redis instances that permit
// command execution over the Redis Serialization Protocol (RESP).
package redisunauthrce

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
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
	moduleName = "dt/redisunauthrce"

	defaultTimeout   = 5 * time.Second
	maxRESPBulkBytes = 64 * 1024
	maxRESPLineBytes = 4096
	maxRESPArrayLen  = 16

	// evalProbeExpr computes 41327 * 23 = 950521 server-side in Lua with zero
	// keys touched and without embedding the expected product in the request.
	evalProbeExpr       = "return 41327 * 23"
	evalExpectedProduct = int64(950521)

	vulnDescription = "The scanner detected that this Redis instance does not require authentication " +
		"and permits unauthenticated command execution over RESP. Anyone with network access to this " +
		"Redis service can execute commands, read or modify stored data, and potentially escalate to " +
		"operating-system code execution via Lua scripting, module loading, replication, or arbitrary " +
		"file writes."

	vulnRecommendation = "Restrict network access so only trusted clients can reach Redis, enable " +
		"authentication via requirepass or Redis ACLs (disabling nopass on the default user), keep " +
		"protected-mode enabled, and enable TLS encryption when traffic traverses untrusted networks."
)

var (
	errInvalidRESP = errors.New("invalid or unexpected RESP message")
	errRESPCommand = errors.New("redis returned a RESP error reply")
)

// Module implements module.VulnDetector for unauthenticated Redis command execution.
type Module struct {
	*module.BaseModule
	timeout time.Duration
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the unauthenticated Redis command execution detector.
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

// Advisories returns the vulnerability metadata reported by this detector.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "REDIS_UNAUTHENTICATED_COMMAND_EXECUTION",
		}.Build(),
		Severity:       vpb.Severity_CRITICAL,
		Title:          "Redis unauthenticated command execution",
		Description:    vulnDescription,
		Recommendation: vulnRecommendation,
	}.Build()
}

// Detect probes the target network service over RESP to verify unauthenticated
// Redis command execution.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- diagnostic log context enrichment
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if netservice.IsWebService(service) {
		return nil, nil
	}

	proto := service.GetTransportProtocol()
	if proto != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && proto != npb.TransportProtocol_TCP {
		return nil, nil
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return nil, err
	}

	evidence, vulnerable, err := m.probeRedis(ctx, addr, netservice.HasTLS(service))
	if err != nil {
		return nil, err
	}
	if !vulnerable {
		return nil, nil
	}

	return buildDetectionReport(service, evidence), nil
}

func (m *Module) probeRedis(ctx context.Context, addr string, useTLS bool) (string, bool, error) {
	conn, err := m.dial(ctx, addr, useTLS)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "connection to %q failed: %v", addr, err) // NOMUTANTS -- diagnostic logging
		return "", false, nil
	}
	defer conn.Close()

	deadline := time.Now().Add(m.timeout)                                      // NOMUTANTS -- defensive socket deadline bound
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) { // NOMUTANTS -- defensive context deadline bound
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline) // NOMUTANTS -- defensive socket deadline bound

	reader := bufio.NewReaderSize(conn, 8192) // NOMUTANTS -- buffer sizing optimization

	// Step 1: Execute "INFO server" and parse the structured RESP bulk string.
	// Password-protected instances fail immediately with "-NOAUTH", and
	// protected-mode instances fail with "-DENIED".
	version, err := queryServerVersion(conn, reader)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", false, ctxErr
		}
		return "", false, nil
	}

	// Step 2: Negative control — send a randomized unknown command and verify
	// that the daemon actively parses RESP commands and returns a "-" error
	// reply, ruling out static banner replay servers and accept-all honeypots.
	if err := verifyUnknownCommandRejected(conn, reader); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", false, ctxErr
		}
		return "", false, nil
	}

	// Step 3: Verify active command execution beyond read-only INFO telemetry
	// ( ruling out locked-down monitoring ACLs such as "-@all +info +ping").
	proof, ok, err := verifyActiveCommandExecution(conn, reader)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", false, ctxErr
		}
		return "", false, nil
	}
	if !ok {
		return "", false, nil
	}

	return fmt.Sprintf("Unauthenticated Redis %s verified (%s).", version, proof), true, nil
}

func (m *Module) dial(ctx context.Context, addr string, useTLS bool) (net.Conn, error) {
	netDialer := &net.Dialer{Timeout: m.timeout} // NOMUTANTS -- defensive dial timeout
	if !useTLS {
		return netDialer.DialContext(ctx, "tcp", addr)
	}
	tlsDialer := &tls.Dialer{
		NetDialer: netDialer,
		Config: &tls.Config{
			InsecureSkipVerify: true, // NOLINT
		},
	}
	return tlsDialer.DialContext(ctx, "tcp", addr)
}

func queryServerVersion(w io.Writer, r *bufio.Reader) (string, error) {
	if err := writeRESPCommand(w, "INFO", "server"); err != nil {
		return "", err
	}
	infoPayload, err := readRESPBulkOrVerbatimString(r)
	if err != nil {
		return "", err
	}
	version, ok := parseRedisServerInfo(infoPayload)
	if !ok {
		return "", errInvalidRESP
	}
	return version, nil
}

func verifyUnknownCommandRejected(w io.Writer, r *bufio.Reader) error {
	var nonce [6]byte
	_, _ = rand.Read(nonce[:])
	unknownCmd := "GOONAMI_PROBE_" + hex.EncodeToString(nonce[:])
	if err := writeRESPCommand(w, unknownCmd); err != nil {
		return err
	}
	prefix, line, err := readRESPLine(r)
	if err != nil {
		return err
	}
	if prefix != '-' {
		return errInvalidRESP
	}
	upper := strings.ToUpper(line)
	if strings.HasPrefix(upper, "NOAUTH") || strings.HasPrefix(upper, "DENIED") {
		return errInvalidRESP
	}
	return nil
}

func verifyActiveCommandExecution(w io.Writer, r *bufio.Reader) (string, bool, error) {
	// Primary check: zero-side-effect Lua arithmetic evaluation.
	if err := writeRESPCommand(w, "EVAL", evalProbeExpr, "0"); err != nil {
		return "", false, err
	}
	val, err := readRESPInteger(r)
	if err == nil {
		if val == evalExpectedProduct {
			return fmt.Sprintf("EVAL computed %d", val), true, nil
		}
		return "", false, nil
	}
	if !errors.Is(err, errRESPCommand) {
		return "", false, err
	}

	// Fallback 1 (when EVAL is disabled via rename-command or ACL): read-only CONFIG GET dir.
	// If CONFIG GET dir returns an empty array (e.g., on Redis-compatible engines without a
	// "dir" parameter), fall through to the DBSIZE + ROLE check.
	if err := writeRESPCommand(w, "CONFIG", "GET", "dir"); err != nil {
		return "", false, err
	}
	items, err := readRESPStringArray(r)
	if err == nil {
		if len(items) >= 2 && strings.EqualFold(items[0], "dir") {
			return "CONFIG GET dir succeeded", true, nil
		}
	} else if !errors.Is(err, errRESPCommand) {
		return "", false, err
	}

	// Fallback 2 (when both EVAL and CONFIG are renamed on an unauthenticated
	// instance, while excluding INFO-only monitoring ACLs): DBSIZE + ROLE.
	if err := writeRESPCommand(w, "DBSIZE"); err != nil {
		return "", false, err
	}
	dbSize, err := readRESPInteger(r)
	if err != nil {
		if errors.Is(err, errRESPCommand) {
			return "", false, nil
		}
		return "", false, err
	}
	if dbSize < 0 {
		return "", false, nil
	}

	if err := writeRESPCommand(w, "ROLE"); err != nil {
		return "", false, err
	}
	role, err := readRESPRole(r)
	if err != nil {
		if errors.Is(err, errRESPCommand) {
			return "", false, nil
		}
		return "", false, err
	}
	return fmt.Sprintf("DBSIZE=%d and ROLE=%s succeeded", dbSize, role), true, nil
}

func parseRedisServerInfo(info string) (string, bool) {
	var version string
	hasRuntimeField := false
	for _, rawLine := range strings.Split(info, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		key, val, ok := strings.Cut(line, ":")
		if !ok || val == "" {
			continue
		}
		switch key {
		case "redis_version", "valkey_version":
			if version == "" {
				version = val
			}
		case "redis_mode", "server_mode", "os", "tcp_port", "process_id", "arch_bits":
			hasRuntimeField = true
		}
	}
	if version == "" || !hasRuntimeField {
		return "", false
	}
	return version, true
}

func writeRESPCommand(w io.Writer, args ...string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(arg), arg)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func readRESPLine(r *bufio.Reader) (byte, string, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return 0, "", err
	}
	var line []byte
	for len(line) < maxRESPLineBytes { // NOMUTANTS -- defensive line length cap
		b, err := r.ReadByte()
		if err != nil {
			return 0, "", err
		}
		if b == '\n' {
			if len(line) == 0 || line[len(line)-1] != '\r' {
				return 0, "", errInvalidRESP
			}
			return prefix, string(line[:len(line)-1]), nil
		}
		line = append(line, b)
	}
	return 0, "", errInvalidRESP
}

func readRESPBulkOrVerbatimString(r *bufio.Reader) (string, error) {
	prefix, header, err := readRESPLine(r)
	if err != nil {
		return "", err
	}
	if prefix == '-' {
		return "", errRESPCommand
	}
	if prefix != '$' && prefix != '=' {
		return "", errInvalidRESP
	}
	n, err := strconv.Atoi(header)
	if err != nil || n < 0 || n > maxRESPBulkBytes {
		return "", errInvalidRESP
	}
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	if buf[n] != '\r' || buf[n+1] != '\n' {
		return "", errInvalidRESP
	}
	payload := string(buf[:n])
	if prefix == '=' && len(payload) >= 4 && payload[3] == ':' {
		payload = payload[4:]
	}
	return payload, nil
}

func readRESPInteger(r *bufio.Reader) (int64, error) {
	prefix, line, err := readRESPLine(r)
	if err != nil {
		return 0, err
	}
	if prefix == '-' {
		return 0, errRESPCommand
	}
	if prefix != ':' {
		return 0, errInvalidRESP
	}
	val, err := strconv.ParseInt(line, 10, 64)
	if err != nil {
		return 0, errInvalidRESP
	}
	return val, nil
}

func readRESPStringArray(r *bufio.Reader) ([]string, error) {
	prefix, line, err := readRESPLine(r)
	if err != nil {
		return nil, err
	}
	if prefix == '-' {
		return nil, errRESPCommand
	}
	if prefix != '*' {
		return nil, errInvalidRESP
	}
	count, err := strconv.Atoi(line)
	if err != nil || count < 0 || count > maxRESPArrayLen {
		return nil, errInvalidRESP
	}
	items := make([]string, 0, count)
	for range count {
		elem, err := readRESPBulkOrVerbatimString(r)
		if err != nil {
			return nil, err
		}
		items = append(items, elem)
	}
	return items, nil
}

func readRESPRole(r *bufio.Reader) (string, error) {
	prefix, line, err := readRESPLine(r)
	if err != nil {
		return "", err
	}
	if prefix == '-' {
		return "", errRESPCommand
	}
	if prefix != '*' {
		return "", errInvalidRESP
	}
	count, err := strconv.Atoi(line)
	if err != nil || count < 1 || count > maxRESPArrayLen {
		return "", errInvalidRESP
	}
	role, err := readRESPBulkOrVerbatimString(r)
	if err != nil {
		return "", err
	}
	switch role {
	case "master", "slave", "sentinel":
		return role, nil
	default:
		return "", errInvalidRESP
	}
}

func buildDetectionReport(service *nspb.NetworkService, evidence string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Verified unauthenticated RESP command execution",
			TextData: vpb.TextData_builder{
				Text: evidence,
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
