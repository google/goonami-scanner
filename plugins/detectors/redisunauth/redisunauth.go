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

// Package redisunauth detects unauthenticated Redis and Valkey services,
// reporting unauthenticated database read/write access (HIGH) unless live
// server setup and configuration permit direct OS command execution (CRITICAL).
package redisunauth

import (
	"context"
	"crypto/tls"
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
	// ModuleName is the registered Goonami detector name for unauthenticated
	// Redis and Valkey detection.
	ModuleName = "dt/redisunauth"

	defaultTimeout        = 5 * time.Second
	maxInfoExcerptBytes   = 512
	probeName             = "__tsunami_ro_probe__"
	dbfilenameInvalidPath = "a/b"

	rceVulnID       = "REDIS_UNAUTHENTICATED_COMMAND_EXECUTION"
	readWriteVulnID = "REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS"

	rceDescription = `The scanner verified that this Redis/Valkey instance accepts unauthenticated RESP2 commands and is configured in a state that permits direct OS remote code execution (RCE) on the Redis host:
1. Unprotected runtime file-write configuration (` + "`CONFIG SET dir`" + ` / ` + "`dbfilename`" + ` unlocked — default on Redis < 7.0, or when ` + "`enable-protected-configs`" + ` is set to ` + "`yes`" + ` / reachable ` + "`local`" + ` on Redis >= 7.0 and Valkey), allowing attackers to write arbitrary files (cron jobs, SSH ` + "`authorized_keys`" + `, or web shells).
2. Unprotected dynamic module loading (` + "`MODULE LOAD`" + ` / ` + "`MODULE LOADEX`" + ` unlocked — default on Redis 4.0–6.2, or when ` + "`enable-module-command`" + ` is set to ` + "`yes`" + ` / reachable ` + "`local`" + ` on Redis >= 7.0 and Valkey), allowing execution of native shared libraries (for example, staged into ` + "`./dump.rdb`" + ` via ` + "`REPLICAOF`" + ` / ` + "`SLAVEOF`" + ` full-resync).

Verified using strictly non-destructive RESP2 probes (` + "`INFO server`" + `, ` + "`CONFIG GET`" + `, path-rejected ` + "`CONFIG SET dbfilename \"a/b\"`" + `, and syntax-rejected ` + "`MODULE LOADEX \"\" CONFIG`" + ` / nonexistent ` + "`MODULE UNLOAD`" + `) without mutating keys, configuration, working directory, or loaded modules.`

	readWriteDescription = `The scanner verified that this Redis/Valkey instance accepts unauthenticated RESP2 commands (` + "`INFO server`" + `) without confirming unlocked direct OS file-write (` + "`CONFIG SET dir`" + ` / ` + "`dbfilename`" + `) or dynamic module loading (` + "`MODULE LOAD`" + ` / ` + "`MODULE LOADEX`" + `).

Security impact and escalation paths:
1. Unauthenticated data read/write and tampering: any network-reachable client can read, exfiltrate, modify, or delete keys (` + "`FLUSHALL`" + `), session tokens, and cached credentials, or capture live traffic via ` + "`MONITOR`" + `.
2. Downstream application RCE via unsafe deserialization: overwriting keys or task-queue payloads consumed by workers using Python ` + "`pickle`" + ` (Celery, RQ, Django), Ruby ` + "`Marshal`" + ` (Sidekiq, Rails), Java serialization/Kryo, or PHP session handlers can achieve remote code execution on connected application hosts.
3. Internal network SSRF: when ` + "`REPLICAOF`" + ` / ` + "`SLAVEOF`" + ` or ` + "`MIGRATE`" + ` is permitted, attackers can trigger outbound TCP connections from the Redis host to internal VPC endpoints.`

	vulnRecommendation = `1. Restrict network reachability using VPC firewall rules and bind Redis/Valkey to private or loopback interfaces (` + "`bind 127.0.0.1 -::1`" + `, ` + "`protected-mode yes`" + `): https://redis.io/docs/latest/operate/oss_and_stack/management/security/
2. Require strong authentication via Redis ACLs (` + "`ACL SETUSER`" + ` disabling ` + "`nopass`" + ` on ` + "`default`" + ` and restricting ` + "`@admin`" + ` / ` + "`@dangerous`" + `) or ` + "`requirepass`" + `, and enable TLS (` + "`tls-port`" + `) on untrusted networks.
3. Keep ` + "`enable-protected-configs no`" + ` and ` + "`enable-module-command no`" + ` (the defaults in Redis >= 7.0 and Valkey), and avoid unsafe deserialization formats (` + "`pickle`" + `, ` + "`Marshal`" + `) for Redis-backed caches and queues.`
)

// Module implements module.VulnDetector for unauthenticated Redis and Valkey detection.
type Module struct {
	*module.BaseModule
	timeout time.Duration
}

type configProbeMode int

const (
	configProbeNone configProbeMode = iota
	configProbeDbfilenamePath
	configProbeSyntheticParam
)

type serverBanner struct {
	engine      string
	version     string
	infoExcerpt string
	configMode  configProbeMode
}

type probeOutcome struct {
	banner         serverBanner
	rceVectors     []string
	probesComplete bool
}

func init() {
	module.RegisterDetector(ModuleName, New)
}

// New returns a new instance of the unauthenticated Redis/Valkey detector.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	timeout := defaultTimeout
	if cfg != nil {
		if d := cfg.TimeoutPerRequest(); d > 0 {
			timeout = d
		}
	}
	return &Module{
		BaseModule: module.NewBaseModule(ModuleName),
		timeout:    timeout,
	}, nil
}

// Advisories returns the CRITICAL RCE and HIGH read/write advisories reported by this detector.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{
		baseRCEVulnerability(),
		baseReadWriteVulnerability(),
	}
}

// Detect probes non-web TCP/TLS services for unauthenticated Redis or Valkey exposure.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- diagnostic logging
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if netservice.IsWebService(service) {
		return nil, nil
	}
	if tp := service.GetTransportProtocol(); tp != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && tp != npb.TransportProtocol_TCP {
		return nil, nil
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return nil, err
	}

	outcome, ok, err := m.probeTarget(ctx, addr, netservice.HasTLS(service))
	if err != nil || !ok {
		return nil, err
	}
	return buildDetectionReport(service, outcome), nil
}

func baseRCEVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     rceVulnID,
		}.Build(),
		Severity:       vpb.Severity_CRITICAL,
		Title:          "Redis unauthenticated command execution",
		Description:    rceDescription,
		Recommendation: vulnRecommendation,
	}.Build()
}

func baseReadWriteVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     readWriteVulnID,
		}.Build(),
		Severity:       vpb.Severity_HIGH,
		Title:          "Redis unauthenticated read/write and command access",
		Description:    readWriteDescription,
		Recommendation: vulnRecommendation,
	}.Build()
}

func (m *Module) probeTarget(ctx context.Context, addr string, useTLS bool) (probeOutcome, bool, error) {
	if err := ctx.Err(); err != nil {
		return probeOutcome{}, false, err
	}

	conn, err := m.openConn(ctx, addr, useTLS)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return probeOutcome{}, false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "Failed to connect to %s: %v", addr, err) // NOMUTANTS -- diagnostic logging
		return probeOutcome{}, false, nil
	}
	defer conn.Close()

	reader := newRespReader(conn)
	infoResp, err := sendProbe(conn, reader, "INFO", "server")
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return probeOutcome{}, false, ctxErr
		}
		return probeOutcome{}, false, nil
	}

	banner, ok := parseServerBanner(infoResp)
	if !ok {
		log.DebugContextf(ctx, log.DebugLevelService, "Service at %s did not return a valid Redis/Valkey INFO server reply", addr) // NOMUTANTS -- diagnostic logging
		return probeOutcome{}, false, nil
	}

	vectors, err := probeRCEConfig(conn, reader, banner)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return probeOutcome{}, false, ctxErr
		}
		// Preserve any already-verified RCE vectors; otherwise fall back to HIGH
		// read/write access because unauthenticated INFO server access was verified.
		return probeOutcome{banner: banner, rceVectors: vectors, probesComplete: false}, true, nil
	}
	return probeOutcome{banner: banner, rceVectors: vectors, probesComplete: true}, true, nil
}

func (m *Module) openConn(ctx context.Context, addr string, useTLS bool) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	var (
		dialer net.Dialer
		conn   net.Conn
		err    error
	)
	if useTLS {
		tlsDialer := &tls.Dialer{
			NetDialer: &dialer,
			Config:    &tls.Config{InsecureSkipVerify: true}, // NOLINT
		}
		conn, err = tlsDialer.DialContext(dialCtx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(dialCtx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(m.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil { // NOMUTANTS -- defensive deadline
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func parseServerBanner(resp respValue) (serverBanner, bool) {
	if resp.kind != respBulkString {
		return serverBanner{}, false
	}
	var redisVer, valkeyVer, compatEngine, compatVer, serverName string
	for line := range strings.SplitSeq(resp.text, "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "redis_version":
			redisVer = val
		case "valkey_version":
			valkeyVer = val
		case "server_name":
			serverName = strings.ToLower(val)
		case "dragonfly_version", "kvrocks_version", "garnet_version", "keydb_version":
			compatEngine, _, _ = strings.Cut(key, "_")
			compatVer = val
		}
	}

	excerpt := resp.text
	if len(excerpt) > maxInfoExcerptBytes {
		excerpt = strings.ToValidUTF8(excerpt[:maxInfoExcerptBytes], "")
	}

	if hasLeadingDigit(valkeyVer) {
		return serverBanner{
			engine:      "valkey",
			version:     valkeyVer,
			infoExcerpt: excerpt,
			configMode:  configProbeDbfilenamePath,
		}, true
	}
	if containsASCIIDigit(compatVer) {
		// Third-party RESP2 engines (Dragonfly, Kvrocks, Garnet, KeyDB) do not
		// guarantee C Redis's pathIsBaseName check on runtime CONFIG SET dbfilename.
		return serverBanner{
			engine:      compatEngine,
			version:     compatVer,
			infoExcerpt: excerpt,
			configMode:  configProbeNone,
		}, true
	}
	if !hasLeadingDigit(redisVer) {
		return serverBanner{}, false
	}
	if serverName != "" && serverName != "redis" && serverName != "valkey" {
		return serverBanner{
			engine:      serverName,
			version:     redisVer,
			infoExcerpt: excerpt,
			configMode:  configProbeNone,
		}, true
	}
	// Redis < 3.2 lacks pathIsBaseName validation on runtime CONFIG SET dbfilename;
	// probe an unknown synthetic parameter instead so rdb_filename is never mutated.
	mode := configProbeDbfilenamePath
	if isLegacyRedisPreThreeTwo(redisVer) {
		mode = configProbeSyntheticParam
	}
	return serverBanner{
		engine:      "redis",
		version:     redisVer,
		infoExcerpt: excerpt,
		configMode:  mode,
	}, true
}

func isLegacyRedisPreThreeTwo(ver string) bool {
	return strings.HasPrefix(ver, "0.") ||
		strings.HasPrefix(ver, "1.") ||
		strings.HasPrefix(ver, "2.") ||
		ver == "3.0" || strings.HasPrefix(ver, "3.0.") ||
		ver == "3.1" || strings.HasPrefix(ver, "3.1.")
}

func hasLeadingDigit(s string) bool {
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
}

func containsASCIIDigit(s string) bool {
	for i := range len(s) {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

func probeRCEConfig(w io.Writer, reader *respReader, banner serverBanner) ([]string, error) {
	var vectors []string

	// 1. Check runtime file-write configuration (CONFIG SET dir / dbfilename).
	protectedCfg, err := getConfigOption(w, reader, "enable-protected-configs")
	if err != nil {
		return vectors, err
	}
	if protectedCfg != "no" {
		switch banner.configMode {
		case configProbeDbfilenamePath:
			resp, err := sendProbe(w, reader, "CONFIG", "SET", "dbfilename", dbfilenameInvalidPath)
			if err != nil {
				return vectors, err
			}
			if isErrorContaining(resp, "just a filename") {
				vectors = append(vectors, "CONFIG SET dir/dbfilename permitted (protected configs unlocked)")
			}
		case configProbeSyntheticParam:
			resp, err := sendProbe(w, reader, "CONFIG", "SET", probeName, "")
			if err != nil {
				return vectors, err
			}
			if isErrorContaining(resp, "unsupported config parameter") || isErrorContaining(resp, "unknown option") {
				vectors = append(vectors, "CONFIG SET dir/dbfilename permitted")
			}
		}
	}

	// 2. Check dynamic shared-library module loading (MODULE LOAD / MODULE LOADEX).
	moduleCfg, err := getConfigOption(w, reader, "enable-module-command")
	if err != nil {
		return vectors, err
	}
	if moduleCfg != "no" {
		loadexResp, err := sendProbe(w, reader, "MODULE", "LOADEX", "", "CONFIG")
		if err != nil {
			return vectors, err
		}
		if isErrorContaining(loadexResp, "error loading the extension") {
			vectors = append(vectors, "MODULE LOADEX permitted (module loading unlocked)")
		} else if isUnknownSubcommandError(loadexResp) {
			unloadResp, err := sendProbe(w, reader, "MODULE", "UNLOAD", probeName)
			if err != nil {
				return vectors, err
			}
			if isErrorContaining(unloadResp, "no such module") {
				vectors = append(vectors, "MODULE LOAD/UNLOAD permitted (module commands unlocked)")
			}
		}
	}

	return vectors, nil
}

func isUnknownSubcommandError(resp respValue) bool {
	return isErrorContaining(resp, "unknown subcommand") ||
		isErrorContaining(resp, "wrong number of arguments") ||
		isErrorContaining(resp, "syntax")
}

func getConfigOption(w io.Writer, reader *respReader, option string) (string, error) {
	resp, err := sendProbe(w, reader, "CONFIG", "GET", option)
	if err != nil {
		return "", err
	}
	if resp.kind == respArray && len(resp.elements) == 2 &&
		resp.elements[0].kind == respBulkString &&
		resp.elements[1].kind == respBulkString &&
		strings.EqualFold(resp.elements[0].text, option) {
		return strings.ToLower(strings.TrimSpace(resp.elements[1].text)), nil
	}
	return "", nil
}

func isErrorContaining(resp respValue, needle string) bool {
	return resp.kind == respError && strings.Contains(strings.ToLower(resp.text), needle)
}

func sendProbe(w io.Writer, reader *respReader, args ...string) (respValue, error) {
	if _, err := w.Write(encodeCommand(args...)); err != nil {
		return respValue{}, err
	}
	return reader.readFrame()
}

func buildDetectionReport(service *nspb.NetworkService, outcome probeOutcome) *dpb.DetectionReportList {
	var (
		vuln    *vpb.Vulnerability
		summary string
	)
	if len(outcome.rceVectors) > 0 {
		vuln = baseRCEVulnerability()
		summary = fmt.Sprintf(
			"Engine: %s %s; verified OS RCE misconfiguration(s): %s.",
			outcome.banner.engine, outcome.banner.version, strings.Join(outcome.rceVectors, "; "),
		)
	} else {
		vuln = baseReadWriteVulnerability()
		gateStatus := "direct OS RCE gates (protected configs and module loading) are locked"
		if !outcome.probesComplete {
			gateStatus = "follow-up OS RCE configuration probes were interrupted before completion"
		} else if outcome.banner.configMode == configProbeNone {
			gateStatus = "runtime CONFIG SET probe skipped for compatibility engine; module loading gate is locked"
		}
		summary = fmt.Sprintf(
			"Engine: %s %s; unauthenticated command access confirmed via INFO server; %s.",
			outcome.banner.engine, outcome.banner.version, gateStatus,
		)
	}
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Configuration assessment",
			TextData: vpb.TextData_builder{
				Text: summary,
			}.Build(),
		}.Build(),
		vpb.AdditionalDetail_builder{
			Description: "INFO server excerpt",
			TextData: vpb.TextData_builder{
				Text: outcome.banner.infoExcerpt,
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
