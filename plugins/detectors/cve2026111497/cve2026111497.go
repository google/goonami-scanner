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

// Package cve2026111497 provides a Goonami detector for CVE-2026-111497
// (Google Brotli Decoder 25-bit block_length_2 bit-field truncation out-of-bounds write RCE).
package cve2026111497

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tpb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/cve2026111497"

	// decompressedCanary is the unique canary token embedded inside the decompressed JSON payload of
	// both validBrotliControl and the CVE-2026-111497 probe stream. It never appears as a raw ASCII
	// substring in the compressed bytes because Brotli uncompressed metablocks split the repeated
	// string.
	decompressedCanary = "tsunami_brotli_check_7f9a2b"

	// validBrotliControlHex is a standard RFC 7932 Brotli stream (191 bytes) with block_length < 2^24
	// that decompresses to the 175-byte JSON canary document on both vulnerable and patched Brotli
	// decoders.
	validBrotliControlHex = "5001107b0d0a200a09227473756e616d695f62726f746c695f080108636865636b5f" +
		"376639613262223a20202020227473756e616d695f62726f746c695f200108636865636b5f37663961326222" +
		"2c227175657279223a227b7473756e616d695f62726f746c080208695f636865636b5f3766396132627d222c" +
		"226a736f6e727063223a22322e30222c226964223a20312c2020226d6574686f64223a227473756e616d695f" +
		"62726f746c780008695f636865636b5f376639613262227d03"

	// probeHeaderHex (17 bytes) encodes the initial metadata metablock and compressed metablock
	// header with NBLTYPESD == 1 (implicit block_length[2] = 16,777,216) and NBLTYPESI == 2
	// (block_length[1] = 16,777,217).
	probeHeaderHex = "0c28002082c8ffffff260880102404896f"

	// probeTailHex (221 bytes) completes the 16,777,217th command, encodes a 32-byte zero-filled
	// metadata metablock, and reconstructs the 175-byte JSON canary document across split
	// uncompressed metablocks.
	probeTailHex = "61b13e000000000000000000000000000000000000000000000000000000000000000000780008" +
		"227473756e616d695f62726f746c695f080108636865636b5f376639613262223a20202020227473756e616d" +
		"695f62726f746c695f200108636865636b5f376639613262222c227175657279223a227b7473756e616d695f" +
		"62726f746c080208695f636865636b5f3766396132627d222c226a736f6e727063223a22322e30222c226964" +
		"223a20312c2020226d6574686f64223a227473756e616d695f62726f746c780008695f636865636b5f376639" +
		"613262227d03"

	maxConsecutiveStep1IOErrors = 3
	maxProbesPerService         = 2
)

var (
	// candidatePaths are the 21 HTTP POST routes probed for automatic Content-Encoding: br
	// request-body decompression, matching Tsunami's Cve2026111497Detector.
	candidatePaths = []string{
		"",
		"graphql",
		"api",
		"api/v1",
		"api/graphql",
		"rpc",
		"jsonrpc",
		"rest",
		"redfish/v1",
		"trpc",
		"login",
		"api/login",
		"auth/login",
		"webhook",
		"mcp",
		"messages?session_id=00000000-0000-0000-0000-000000000000&sessionId=00000000-0000-0000-0000-000000000000",
		"v1",
		"api/v2",
		"invocations",
		"predict",
		"index.php",
	}

	// probeMiddleZeroLen is the number of zero bytes (23,068,672) between probeHeader and probeTail
	// encoding 16,777,216 distance commands that output 0 bytes while decrementing block_length[2]
	// down to 0. Exposed as a variable so unit tests can override it for fast in-memory runs.
	probeMiddleZeroLen = 23_068_672

	validBrotliControl   = mustDecodeHex(validBrotliControlHex)
	invalidBrotliControl = buildInvalidBrotliControl(len(validBrotliControl))
	probeHeader          = mustDecodeHex(probeHeaderHex)
	probeTail            = mustDecodeHex(probeTailHex)
)

type controlPairOrder int

const (
	invalidFirst controlPairOrder = iota
	validFirst
)

var (
	preProbeControlPairOrders    = []controlPairOrder{invalidFirst, validFirst}
	postProbeCanaryControlOrders = []controlPairOrder{validFirst}
	postProbeStatusControlOrders = []controlPairOrder{
		invalidFirst,
		validFirst,
		invalidFirst,
		invalidFirst,
		validFirst,
	}
)

type httpResult struct {
	statusCode int
	body       string
}

type endpointCheckOutcome struct {
	step1IOError bool
	probeSent    bool
	vulnerable   bool
}

// Module implements the dt/cve2026111497 vulnerability detector.
type Module struct {
	*module.BaseModule
	coreConfig *config.Config
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the CVE-2026-111497 detector module.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		coreConfig: cfg,
	}, nil
}

// Advisories returns the vulnerability advisory detected by this module.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "CVE-2026-111497",
		}.Build(),
		RelatedId: []*vpb.VulnerabilityId{
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     "CVE-2026-111497",
			}.Build(),
		},
		Severity: vpb.Severity_CRITICAL,
		Title:    "Google Brotli Decoder Out-of-Bounds Write Remote Code Execution (CVE-2026-111497)",
		Description: "The target HTTP service automatically decompresses Brotli-encoded " +
			"(Content-Encoding: br) request bodies using an unpatched version of the Google " +
			"Brotli decoder (versions 1.0.3 through 1.0.9, 1.1.0, or 1.2.0) vulnerable to " +
			"CVE-2026-111497. In ReadBlockLength(), a 24-bit integer addition (val + (1U << 24)) " +
			"can reach 1 << 25 (33,554,432), which overflows to 0 when truncated to a 25-bit " +
			"unsigned bit-field (uint32_t block_length_2 : 25) in BrotliDecoderState. This " +
			"causes a premature block-type switch without re-evaluating context modes, leading " +
			"to an out-of-bounds write in ProcessCommandsInternal() and remote code execution.",
		Recommendation: "Upgrade the Brotli library (libbrotli / brotli package) to version " +
			"1.0.10, 1.1.1, 1.2.1, or later, which narrows the maximum block-length prefix code " +
			"range to 24 bits and clamps decoded block lengths to 1 << 24.",
	}.Build()
}

// Detect probes the target web service for CVE-2026-111497 using a 5-step zero-side-effect
// differential Brotli decompression protocol.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	if !netservice.IsWebService(service) {
		return nil, nil
	}

	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return nil, nil
	}
	rootURL := webRoot + "/"

	opts := goohttp.DefaultClientOptions()
	opts.DisableFollowRedirects = true
	client, err := goohttp.NewClient(m.coreConfig, opts)
	if err != nil {
		return nil, err
	}

	consecutiveStep1IOErrors := 0
	probesSent := 0
	for _, candidatePath := range candidatePaths {
		targetURL := rootURL + candidatePath
		outcome := m.checkEndpoint(ctx, client, targetURL)
		if outcome.vulnerable {
			return m.buildDetectionReport(service, targetURL), nil
		}
		if outcome.step1IOError {
			consecutiveStep1IOErrors++
			if consecutiveStep1IOErrors >= maxConsecutiveStep1IOErrors {
				break
			}
			continue
		}
		consecutiveStep1IOErrors = 0
		if outcome.probeSent {
			probesSent++
			if probesSent >= maxProbesPerService {
				break
			}
		}
	}

	return nil, nil
}

func (m *Module) checkEndpoint(ctx context.Context, client goohttp.Client, targetURL string) endpointCheckOutcome {
	// Step 1: Send valid RFC 7932 Brotli control stream (block_length < 2^24).
	validResp, err := sendPostRequest(ctx, client, targetURL, validBrotliControl, true)
	if err != nil {
		return endpointCheckOutcome{step1IOError: true}
	}

	canaryReflected := containsCanary(validResp.body)
	validStatusAccepted := isPostDecompressionStatus(validResp.statusCode)
	if !canaryReflected && !validStatusAccepted {
		return endpointCheckOutcome{}
	}

	// Step 2: Send invalid Brotli control stream of the exact same length (191 bytes).
	invalidResp, err := sendPostRequest(ctx, client, targetURL, invalidBrotliControl, true)
	if err != nil {
		return endpointCheckOutcome{}
	}

	canaryDiff := canaryReflected && !containsCanary(invalidResp.body)
	statusDiff := validStatusAccepted && isDecompressionFailureStatus(invalidResp.statusCode)
	if !canaryDiff && !statusDiff {
		return endpointCheckOutcome{}
	}

	// In status-differential mode, verify pre-probe control pairs in both orders to rule out
	// non-deterministic or alternating responses before sending the probe.
	if !canaryDiff && !verifyControlPairs(ctx, client, targetURL, validResp.statusCode, invalidResp.statusCode, false, preProbeControlPairOrders) {
		return endpointCheckOutcome{}
	}

	// Step 3: Send the CVE-2026-111497 zero-side-effect probe.
	probeResp, err := sendPostRequest(ctx, client, targetURL, buildCve2026111497Probe(), true)
	if err != nil || probeResp.statusCode != validResp.statusCode || (canaryDiff && !containsCanary(probeResp.body)) {
		return endpointCheckOutcome{probeSent: true}
	}

	// Step 4: Re-verify post-probe control pairs so stateful, round-robin, or sticky servers
	// cannot match the expected response sequence.
	postOrders := postProbeStatusControlOrders
	if canaryDiff {
		postOrders = postProbeCanaryControlOrders
	}
	if !verifyControlPairs(ctx, client, targetURL, validResp.statusCode, invalidResp.statusCode, canaryDiff, postOrders) {
		return endpointCheckOutcome{probeSent: true}
	}

	// Step 5: Unencoded baseline check without Content-Encoding: br to confirm that the server
	// genuinely acts on the Content-Encoding: br header rather than echoing or matching raw bytes.
	if !verifyUnencodedBaseline(ctx, client, targetURL, canaryDiff) {
		return endpointCheckOutcome{probeSent: true}
	}

	return endpointCheckOutcome{probeSent: true, vulnerable: true}
}

func verifyUnencodedBaseline(
	ctx context.Context,
	client goohttp.Client,
	targetURL string,
	canaryDiff bool,
) bool {
	unencodedValid, err := sendPostRequest(ctx, client, targetURL, validBrotliControl, false)
	if err != nil {
		return false
	}
	if canaryDiff {
		return !containsCanary(unencodedValid.body)
	}
	return isUnencodedRejectionStatus(unencodedValid.statusCode)
}

func verifyControlPairs(
	ctx context.Context,
	client goohttp.Client,
	targetURL string,
	expectedValidStatus int,
	expectedInvalidStatus int,
	requireCanary bool,
	orders []controlPairOrder,
) bool {
	for _, order := range orders {
		if order == invalidFirst {
			if !verifyControlRequest(ctx, client, targetURL, invalidBrotliControl, expectedInvalidStatus, requireCanary, false) ||
				!verifyControlRequest(ctx, client, targetURL, validBrotliControl, expectedValidStatus, requireCanary, true) {
				return false
			}
		} else {
			if !verifyControlRequest(ctx, client, targetURL, validBrotliControl, expectedValidStatus, requireCanary, true) ||
				!verifyControlRequest(ctx, client, targetURL, invalidBrotliControl, expectedInvalidStatus, requireCanary, false) {
				return false
			}
		}
	}
	return true
}

func verifyControlRequest(
	ctx context.Context,
	client goohttp.Client,
	targetURL string,
	payload []byte,
	expectedStatus int,
	checkCanary bool,
	wantCanary bool,
) bool {
	resp, err := sendPostRequest(ctx, client, targetURL, payload, true)
	if err != nil || resp.statusCode != expectedStatus {
		return false
	}
	return !checkCanary || containsCanary(resp.body) == wantCanary
}

func sendPostRequest(
	ctx context.Context,
	client goohttp.Client,
	targetURL string,
	body []byte,
	includeBrotliHeader bool,
) (*httpResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream, text/plain, */*")
	if includeBrotliHeader {
		req.Header.Set("Content-Encoding", "br")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &httpResult{
		statusCode: resp.StatusCode,
		body:       string(respBytes),
	}, nil
}

func containsCanary(body string) bool {
	return strings.Contains(body, decompressedCanary)
}

func isPostDecompressionStatus(code int) bool {
	return (code >= 200 && code < 300) ||
		code == http.StatusFound ||
		code == http.StatusSeeOther ||
		code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect ||
		code == http.StatusUnauthorized ||
		code == http.StatusForbidden ||
		code == http.StatusNotFound ||
		code == http.StatusMethodNotAllowed ||
		code == http.StatusNotAcceptable
}

func isDecompressionFailureStatus(code int) bool {
	return code == http.StatusBadRequest ||
		code == http.StatusUnprocessableEntity ||
		code == http.StatusInternalServerError
}

func isUnencodedRejectionStatus(code int) bool {
	return isDecompressionFailureStatus(code) || code == http.StatusUnsupportedMediaType
}

func (m *Module) buildDetectionReport(service *nspb.NetworkService, verifiedURL string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			TextData: vpb.TextData_builder{
				Text: fmt.Sprintf(
					"Verified CVE-2026-111497 on endpoint %s via differential Brotli Content-Encoding: br "+
						"decompression of a 25-bit block_length_2 (1 << 25) stream.",
					verifiedURL,
				),
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
				DetectionTimestamp: tpb.Now(),
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      vuln,
			}.Build(),
		},
	}.Build()
}

func buildCve2026111497Probe() []byte {
	totalLen := len(probeHeader) + probeMiddleZeroLen + len(probeTail)
	buf := make([]byte, totalLen)
	copy(buf, probeHeader)
	copy(buf[len(probeHeader)+probeMiddleZeroLen:], probeTail)
	return buf
}

func buildInvalidBrotliControl(targetLength int) []byte {
	const prefix = "Vtsunami_brotli_invalid_control_"
	buf := bytes.Repeat([]byte{'_'}, targetLength)
	copy(buf, prefix)
	return buf
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex constant: %v", err))
	}
	return b
}
