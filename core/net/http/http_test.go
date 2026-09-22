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

package http

import (
	"net/http"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func TestRegisterAndNewClient(t *testing.T) {
	cfg := config.Default()
	_, err := NewClient(cfg, DefaultClientOptions())
	if err == nil {
		t.Errorf("NewClient(default) with no simpleclient registered did not return error")
	}

	Register("simpleclient", func(cfg *config.Config, options *ClientOptions) (Client, error) {
		return &fakeClient{}, nil
	})

	client, err := NewClient(cfg, DefaultClientOptions())
	if err != nil {
		t.Fatalf("NewClient(default) returned error: %v", err)
	}
	if client == nil {
		t.Errorf("NewClient(default) returned nil client")
	}

	customCfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			HttpClient: proto.String("unknown-client"),
		}.Build(),
	}.Build())
	_, err = NewClient(customCfg, DefaultClientOptions())
	if err == nil {
		t.Errorf("NewClient with unknown client did not return error")
	}

	Register("custom", func(cfg *config.Config, options *ClientOptions) (Client, error) {
		return &fakeClient{}, nil
	})
	customCfg = config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			HttpClient: proto.String("custom"),
		}.Build(),
	}.Build())
	client, err = NewClient(customCfg, DefaultClientOptions())
	if err != nil {
		t.Fatalf("NewClient(custom) returned error: %v", err)
	}
	instrumented, ok := client.(*metricsClient)
	if !ok {
		t.Fatalf("NewClient(custom) returned %T, want *instrumentedClient", client)
	}
	if _, ok := instrumented.wrapped.(*fakeClient); !ok {
		t.Errorf("NewClient(custom) wrapped %T, want *fakeClient", instrumented.wrapped)
	}
}

type fakeClient struct {
	statusCode int
	err        error
}

func (f *fakeClient) Do(req *http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.statusCode == 0 {
		return nil, nil
	}
	return &http.Response{StatusCode: f.statusCode}, nil
}

// totalRequestErrors sums every http/requests/error series.
func totalRequestErrors(collector *metrics.Collector) int64 {
	var total int64
	for _, series := range collector.Series() {
		if series.Metric == metrics.HTTPRequestErrors {
			total += series.Value()
		}
	}
	return total
}
