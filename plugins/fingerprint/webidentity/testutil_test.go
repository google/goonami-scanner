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

package webidentity

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/engine"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	wfpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/webidentity_fp_config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

func newHostAwareTestServer(hostPages, ipPages map[string]string) *httptest.Server {
	handler := func(w http.ResponseWriter, r *http.Request) {
		pages := ipPages
		if strings.HasPrefix(r.Host, "localhost") {
			pages = hostPages
		}

		p, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, p)
	}

	return httptest.NewServer(http.HandlerFunc(handler))
}

func newTestServer(pages map[string]string) *httptest.Server {
	return newHostAwareTestServer(pages, pages)
}

func serverInfo(t *testing.T, server *httptest.Server) (string, uint32, *nspb.NetworkService) {
	t.Helper()

	hostname, portStr, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) failed: %v", server.Listener.Addr().String(), err)
	}

	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) failed: %v", portStr, err)
	}

	port := uint32(p)
	service := nspb.NetworkService_builder{
		NetworkEndpoint:      buildTestEndpoint(npb.NetworkEndpoint_IP_PORT, hostname, port),
		SupportedHttpMethods: []string{"GET"},
	}.Build()

	return hostname, port, service
}

func buildTestEndpoint(epType npb.NetworkEndpoint_Type, ip string, port uint32) *npb.NetworkEndpoint {
	b := npb.NetworkEndpoint_builder{
		Type: epType,
		Port: npb.Port_builder{PortNumber: port}.Build(),
	}
	if epType == npb.NetworkEndpoint_HOSTNAME_PORT || epType == npb.NetworkEndpoint_IP_HOSTNAME_PORT {
		b.Hostname = npb.Hostname_builder{Name: "localhost"}.Build()
	}
	if epType == npb.NetworkEndpoint_IP_PORT || epType == npb.NetworkEndpoint_IP_HOSTNAME_PORT {
		b.IpAddress = npb.IpAddress_builder{AddressFamily: npb.AddressFamily_IPV4, Address: ip}.Build()
	}
	return b.Build()
}

func buildTestService(epType npb.NetworkEndpoint_Type, appRoot, software string, crawls ...*wcpb.CrawlResult) *nspb.NetworkService {
	wsc := nspb.WebServiceContext_builder{
		ApplicationRoot: appRoot,
		CrawlResults:    crawls,
	}
	if software != "" {
		wsc.Software = spb.Software_builder{Name: software}.Build()
		wsc.VersionSet = &spb.VersionSet{}
	}
	return nspb.NetworkService_builder{
		NetworkEndpoint:      npb.NetworkEndpoint_builder{Type: epType}.Build(),
		SupportedHttpMethods: []string{"GET"},
		ServiceContext: nspb.ServiceContext_builder{
			WebServiceContext: wsc.Build(),
		}.Build(),
	}.Build()
}

func buildTestCrawl(rawURL string, depth int32, hexHash string) *wcpb.CrawlResult {
	return wcpb.CrawlResult_builder{
		CrawlTarget:      wcpb.CrawlTarget_builder{Url: rawURL}.Build(),
		CrawlDepth:       depth,
		ResponseCode:     http.StatusOK,
		Content:          []byte(hexHash),
		CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
	}.Build()
}

func pageHash(t *testing.T, page string) string {
	t.Helper()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	h, err := hash.FromResponse(resp, []byte(page+"\n"))
	if err != nil {
		t.Fatalf("hash.FromResponse(%q) failed: %v", page, err)
	}
	return h.Hex()
}

func buildConfig(t *testing.T, modConfig *wfpb.WebIdentityFpConfig, workdir string) *config.Config {
	t.Helper()

	cfg := config.FromProto(cpb.Config_builder{
		Plugins: cpb.PluginsConfig_builder{
			Webidentity: modConfig,
		}.Build(),
	}.Build())

	if workdir != "" {
		cfg.CreateDirectories(workdir)
	}

	return cfg
}

func newTestModuleWithFingerprints(t *testing.T, fps []*fpb.WebFingerprint, modConfig *wfpb.WebIdentityFpConfig, workdir string) module.Fingerprinter {
	t.Helper()

	var compiled []*engine.CompiledFingerprint
	for _, fp := range fps {
		c, err := engine.CompileFingerprint(fp)
		if err != nil {
			t.Fatalf("engine.CompileFingerprint() failed: %v", err)
		}
		compiled = append(compiled, c)
	}

	if modConfig == nil {
		modConfig = wfpb.WebIdentityFpConfig_builder{WriteHtmlToFile: proto.Bool(false)}.Build()
	}
	cfg := buildConfig(t, modConfig, workdir)

	mod, err := newWithEngine(t.Context(), modConfig, cfg, engine.New(compiled))
	if err != nil {
		t.Fatalf("newWithEngine() failed: %v", err)
	}
	return mod
}

func replaceURIPlaceholders(contexts []*nspb.ServiceContext, uri string) []*nspb.ServiceContext {
	var out []*nspb.ServiceContext
	for _, sc := range contexts {
		cloned := proto.CloneOf(sc)
		wsc := cloned.GetWebServiceContext()
		if wsc.GetApplicationRoot() != "" {
			wsc.SetApplicationRoot(strings.ReplaceAll(wsc.GetApplicationRoot(), "{uri}", uri))
		}
		for _, crawlResult := range wsc.GetCrawlResults() {
			newURL := strings.ReplaceAll(crawlResult.GetCrawlTarget().GetUrl(), "{uri}", uri)
			crawlResult.GetCrawlTarget().SetUrl(newURL)
		}
		out = append(out, cloned)
	}
	return out
}
