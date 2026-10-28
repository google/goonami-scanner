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

package bruteforce

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/protobuf/proto"

	bfpb "github.com/google/goonami-scanner/common/bruteforce/bruteforce_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

type fakeHandler struct {
	name          string
	fingerprintFn func(ctx context.Context, service *nspb.NetworkService) (bool, error)
	newWorkerFn   func() Worker
	testCredFn    func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error)
	closeFn       func() error
	vulnFn        func() *vpb.Vulnerability
	vuln          *vpb.Vulnerability
}

func (h *fakeHandler) Name() string {
	if h.name == "" {
		return "dt/fake_bruteforce"
	}
	return h.name
}

func (h *fakeHandler) Fingerprint(ctx context.Context, service *nspb.NetworkService) (bool, error) {
	if h.fingerprintFn != nil {
		return h.fingerprintFn(ctx, service)
	}
	return true, nil
}

func (h *fakeHandler) NewWorker() Worker {
	if h.newWorkerFn != nil {
		return h.newWorkerFn()
	}
	return h
}

func (h *fakeHandler) TestCredential(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
	if h.testCredFn != nil {
		return h.testCredFn(ctx, service, cred)
	}
	return false, nil
}

func (h *fakeHandler) Close() error {
	if h.closeFn != nil {
		return h.closeFn()
	}
	return nil
}

func (h *fakeHandler) Vulnerability() *vpb.Vulnerability {
	if h.vulnFn != nil {
		return h.vulnFn()
	}
	if h.vuln != nil {
		return h.vuln
	}
	return &vpb.Vulnerability{}
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

func testService() *nspb.NetworkService {
	return nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
			Port:     npb.Port_builder{PortNumber: 8080}.Build(),
		}.Build(),
	}.Build()
}

func additionalDetailTexts(reports *dpb.DetectionReportList) []string {
	var details []string
	for _, r := range reports.GetDetectionReports() {
		for _, ad := range r.GetVulnerability().GetAdditionalDetails() {
			details = append(details, ad.GetTextData().GetText())
		}
	}
	return details
}

func TestNew(t *testing.T) {
	tests := []struct {
		name               string
		cfg                *config.Config
		handler            Handler
		opts               *Options
		wantErr            error
		wantName           string
		wantNonEmptyStore  bool
		wantUsernames      []string
		wantPasswords      map[string][]string
		wantMaxAttempts    int32
		wantMaxConcurrency int32
		wantMaxQPS         int32
	}{
		{
			name:    "when_config_is_nil_returns_error",
			cfg:     nil,
			handler: &fakeHandler{},
			wantErr: ErrConfigNil,
		},
		{
			name:    "when_handler_is_nil_returns_error",
			cfg:     config.Default(),
			handler: nil,
			wantErr: ErrHandlerNil,
		},
		{
			name: "when_handler_vulnerability_is_nil_returns_error",
			cfg:  config.Default(),
			handler: &fakeHandler{
				vulnFn: func() *vpb.Vulnerability { return nil },
			},
			wantErr: ErrVulnerabilityNil,
		},
		{
			name:               "when_default_config_used_loads_default_credentials",
			cfg:                config.Default(),
			handler:            &fakeHandler{name: "dt/test"},
			wantName:           "dt/test",
			wantNonEmptyStore:  true,
			wantMaxAttempts:    2000,
			wantMaxConcurrency: 1,
			wantMaxQPS:         10,
		},
		{
			name:    "when_default_credentials_provided_prepends_in_order",
			cfg:     config.Default(),
			handler: &fakeHandler{},
			opts: &Options{
				CredentialStore: smallStore([]string{"user1"}, []string{"pass1"}),
				DefaultCredentials: []Credential{
					{Username: "def1", Password: "def_p1"},
					{Username: "def2", Password: "def_p2"},
				},
			},
			wantUsernames: []string{"def1", "def2", "user1"},
			wantPasswords: map[string][]string{
				"def1": {"def_p1"},
				"def2": {"def_p2"},
			},
		},
		{
			name:    "when_password_only_enabled_collapses_store_to_empty_username",
			cfg:     config.Default(),
			handler: &fakeHandler{},
			opts: &Options{
				CredentialStore:    smallStore([]string{"u1", "u2"}, []string{"p1", "p2"}),
				DefaultCredentials: []Credential{{Username: "ignored", Password: "p0"}},
				PasswordOnly:       true,
			},
			wantUsernames: []string{""},
			wantPasswords: map[string][]string{
				"": {"p0", "p1", "p2"},
			},
		},
		{
			name: "when_max_concurrency_is_non_positive_defaults_to_one",
			cfg: config.FromProto(cpb.Config_builder{
				Plugins: cpb.PluginsConfig_builder{
					Bruteforce: bfpb.BruteForceConfig_builder{
						MaxConcurrency: proto.Int32(-5),
					}.Build(),
				}.Build(),
			}.Build()),
			handler:            &fakeHandler{},
			opts:               &Options{CredentialStore: smallStore([]string{"u"}, []string{"p"})},
			wantMaxConcurrency: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(t.Context(), tc.cfg, tc.handler, tc.opts)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("New() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if tc.wantName != "" && d.Name() != tc.wantName {
				t.Errorf("Detector.Name() = %q, want %q", d.Name(), tc.wantName)
			}
			store := d.CredentialStore()
			if tc.wantNonEmptyStore && store.Count() == 0 {
				t.Errorf("Detector.CredentialStore().Count() = 0, want > 0")
			}
			if tc.wantUsernames != nil {
				if diff := cmp.Diff(tc.wantUsernames, store.Usernames()); diff != "" {
					t.Errorf("store.Usernames() mismatch (-want +got):\n%s", diff)
				}
			}
			for user, wantPasses := range tc.wantPasswords {
				if diff := cmp.Diff(wantPasses, store.Passwords(user)); diff != "" {
					t.Errorf("store.Passwords(%q) mismatch (-want +got):\n%s", user, diff)
				}
			}
			if tc.wantMaxAttempts != 0 && d.config.GetMaxAttemptsPerService() != tc.wantMaxAttempts {
				t.Errorf("d.config.GetMaxAttemptsPerService() = %d, want %d", d.config.GetMaxAttemptsPerService(), tc.wantMaxAttempts)
			}
			if tc.wantMaxConcurrency != 0 && d.config.GetMaxConcurrency() != tc.wantMaxConcurrency {
				t.Errorf("d.config.GetMaxConcurrency() = %d, want %d", d.config.GetMaxConcurrency(), tc.wantMaxConcurrency)
			}
			if tc.wantMaxQPS != 0 && d.config.GetMaxRequestsPerSecond() != tc.wantMaxQPS {
				t.Errorf("d.config.GetMaxRequestsPerSecond() = %d, want %d", d.config.GetMaxRequestsPerSecond(), tc.wantMaxQPS)
			}
		})
	}
}

func TestNew_DoesNotMutateOriginalStore(t *testing.T) {
	orig := smallStore([]string{"u1"}, []string{"p1"})
	_, err := New(
		t.Context(),
		config.Default(),
		&fakeHandler{},
		&Options{
			CredentialStore:    orig,
			DefaultCredentials: []Credential{{Username: "admin", Password: "admin"}},
		},
	)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if diff := cmp.Diff([]string{"u1"}, orig.Usernames()); diff != "" {
		t.Errorf("original store usernames mutated (-want +got):\n%s", diff)
	}
}

func TestDetector_Detect(t *testing.T) {
	errUnexpected := errors.New("unexpected protocol failure")

	baseVuln := vpb.Vulnerability_builder{
		Title: "Weak Credentials",
	}.Build()

	var stopFirstWG sync.WaitGroup
	stopFirstWG.Add(2)

	var sameUserWG sync.WaitGroup
	sameUserWG.Add(2)

	var cancelCurrentRun context.CancelFunc

	tests := []struct {
		name                string
		bfCfg               *bfpb.BruteForceConfig
		store               *credentialstore.CredentialStore
		handler             *fakeHandler
		cancelCtx           bool
		ignoreDetailOrder   bool
		wantErr             error
		wantDetails         []string
		wantBudgetExhausted int64
	}{
		{
			name:      "when_context_already_canceled_returns_error",
			store:     smallStore([]string{"admin"}, []string{"pass"}),
			handler:   &fakeHandler{},
			cancelCtx: true,
			wantErr:   context.Canceled,
		},
		{
			name:  "when_fingerprinting_returns_false_skips_brute_forcing",
			store: smallStore([]string{"admin"}, []string{"pass"}),
			handler: &fakeHandler{
				fingerprintFn: func(ctx context.Context, service *nspb.NetworkService) (bool, error) {
					return false, nil
				},
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					t.Errorf("TestCredential() called after Fingerprint returned false")
					return true, nil
				},
			},
			wantDetails: nil,
		},
		{
			name:  "when_fingerprinting_returns_error_aborts_and_returns_error",
			store: smallStore([]string{"admin"}, []string{"pass"}),
			handler: &fakeHandler{
				fingerprintFn: func(ctx context.Context, service *nspb.NetworkService) (bool, error) {
					return false, errUnexpected
				},
			},
			wantErr: errUnexpected,
		},
		{
			name:  "when_no_credentials_match_returns_no_reports",
			store: smallStore([]string{"admin", "root"}, []string{"123", "password"}),
			handler: &fakeHandler{
				vuln: baseVuln,
			},
			wantDetails: nil,
		},
		{
			name:  "when_single_credential_matches_returns_report_with_detail",
			store: smallStore([]string{"admin", "root"}, []string{"123", "password"}),
			handler: &fakeHandler{
				vuln: baseVuln,
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					return cred.Username == "root" && cred.Password == "123", nil
				},
			},
			wantDetails: []string{"root:123"},
		},
		{
			name:  "when_multiple_credentials_match_stops_at_first_valid_credential_by_default",
			store: smallStore([]string{"admin", "root"}, []string{"123", "password"}),
			handler: &fakeHandler{
				vuln: baseVuln,
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					if cred.Username == "root" {
						t.Errorf("TestCredential() called for %s after first valid credential was already found", cred)
					}
					return (cred.Username == "admin" && cred.Password == "password") ||
						(cred.Username == "root" && cred.Password == "123"), nil
				},
			},
			wantDetails: []string{"admin:password"},
		},
		{
			name: "when_stop_at_first_valid_credentials_is_false_collects_all_valid_credentials_in_order",
			bfCfg: bfpb.BruteForceConfig_builder{
				StopAtFirstValidCredentials: proto.Bool(false),
			}.Build(),
			store: smallStore([]string{"admin", "root"}, []string{"123", "password"}),
			handler: &fakeHandler{
				vuln: baseVuln,
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					return (cred.Username == "admin" && cred.Password == "password") ||
						(cred.Username == "root" && cred.Password == "123"), nil
				},
			},
			wantDetails: []string{"admin:password", "root:123"},
		},
		{
			name: "when_user_password_found_skips_remaining_passwords_for_that_user",
			bfCfg: bfpb.BruteForceConfig_builder{
				StopAtFirstValidCredentials: proto.Bool(false),
			}.Build(),
			store: smallStore([]string{"admin", "root"}, []string{"123", "password", "secret"}),
			handler: &fakeHandler{
				vuln: baseVuln,
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					if cred.Username == "admin" && cred.Password != "123" {
						t.Errorf("TestCredential() called for %s after valid password was already found for admin", cred)
					}
					return (cred.Username == "admin" && cred.Password == "123") ||
						(cred.Username == "root" && cred.Password == "password"), nil
				},
			},
			wantDetails: []string{"admin:123", "root:password"},
		},
		{
			name:  "when_test_credential_returns_error_aborts_and_returns_error",
			store: smallStore([]string{"admin", "root"}, []string{"123", "password"}),
			handler: &fakeHandler{
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					return false, errUnexpected
				},
			},
			wantErr: errUnexpected,
		},
		{
			name: "when_max_attempts_reached_records_budget_exhausted_and_stops",
			bfCfg: bfpb.BruteForceConfig_builder{
				MaxAttemptsPerService: proto.Int32(2),
			}.Build(),
			store: smallStore([]string{"admin", "root"}, []string{"123", "password"}),
			handler: &fakeHandler{
				vuln: baseVuln,
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					// Would match on 3rd attempt (root:123), which is beyond budget of 2.
					return cred.Username == "root" && cred.Password == "123", nil
				},
			},
			wantDetails:         nil,
			wantBudgetExhausted: 1,
		},
		{
			name: "when_candidates_exceed_max_attempts_and_valid_credential_found_records_budget_exhausted",
			bfCfg: bfpb.BruteForceConfig_builder{
				MaxAttemptsPerService: proto.Int32(2),
			}.Build(),
			store: smallStore([]string{"admin", "root"}, []string{"123", "password"}),
			handler: &fakeHandler{
				vuln: baseVuln,
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					return cred.Password == "123", nil
				},
			},
			wantDetails:         []string{"admin:123"},
			wantBudgetExhausted: 1,
		},
		{
			name: "when_max_attempts_equals_total_credentials_does_not_record_budget_exhausted",
			bfCfg: bfpb.BruteForceConfig_builder{
				MaxAttemptsPerService: proto.Int32(4),
			}.Build(),
			store: smallStore([]string{"admin", "root"}, []string{"123", "password"}),
			handler: &fakeHandler{
				vuln: baseVuln,
			},
			wantDetails:         nil,
			wantBudgetExhausted: 0,
		},
		{
			name: "when_context_canceled_during_match_takes_priority_over_done",
			bfCfg: bfpb.BruteForceConfig_builder{
				MaxRequestsPerSecond:        proto.Int32(0),
				StopAtFirstValidCredentials: proto.Bool(true),
			}.Build(),
			store: smallStore([]string{"u1", "u2"}, []string{"p1"}),
			handler: &fakeHandler{
				vuln: baseVuln,
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					cancelCurrentRun()
					return true, nil
				},
			},
			wantErr: context.Canceled,
		},
		{
			name: "when_concurrent_workers_find_multiple_passwords_for_same_user_reports_all_found_and_skips_queued",
			bfCfg: bfpb.BruteForceConfig_builder{
				MaxConcurrency:              proto.Int32(2),
				MaxRequestsPerSecond:        proto.Int32(0),
				StopAtFirstValidCredentials: proto.Bool(false),
			}.Build(),
			store: smallStore([]string{"u1"}, []string{"p1", "p2", "p3"}),
			handler: &fakeHandler{
				vuln: baseVuln,
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					if cred.Password == "p3" {
						t.Errorf("TestCredential() called for %s after user was already done", cred)
					}
					sameUserWG.Done()
					sameUserWG.Wait()
					return true, nil
				},
			},
			ignoreDetailOrder: true,
			wantDetails:       []string{"u1:p1", "u1:p2"},
		},
		{
			name: "when_concurrent_workers_find_multiple_credentials_with_stop_at_first_reports_all_found_and_skips_queued",
			bfCfg: bfpb.BruteForceConfig_builder{
				MaxConcurrency:              proto.Int32(2),
				MaxRequestsPerSecond:        proto.Int32(0),
				StopAtFirstValidCredentials: proto.Bool(true),
			}.Build(),
			store: smallStore([]string{"u1", "u2", "u3"}, []string{"p1"}),
			handler: &fakeHandler{
				vuln: baseVuln,
				testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
					if cred.Username == "u3" {
						t.Errorf("TestCredential() called for %s after pool was already done", cred)
					}
					stopFirstWG.Done()
					stopFirstWG.Wait()
					return true, nil
				},
			},
			ignoreDetailOrder: true,
			wantDetails:       []string{"u1:p1", "u2:p1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			collector := metrics.NewCollector()
			metrics.SetRecorder(collector)
			t.Cleanup(func() { metrics.SetRecorder(nil) })

			cfgProto := &cpb.Config{}
			if tc.bfCfg != nil {
				cfgProto.SetPlugins(cpb.PluginsConfig_builder{
					Bruteforce: tc.bfCfg,
				}.Build())
			}
			cfg := config.FromProto(cfgProto)

			d, err := New(t.Context(), cfg, tc.handler, &Options{CredentialStore: tc.store})
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			cancelCurrentRun = cancel
			defer cancel()
			if tc.cancelCtx {
				cancel()
			}

			reports, err := d.Detect(ctx, testService())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Detect() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}

			gotDetails := additionalDetailTexts(reports)
			if tc.ignoreDetailOrder {
				slices.Sort(gotDetails)
			}
			if diff := cmp.Diff(tc.wantDetails, gotDetails); diff != "" {
				t.Errorf("Detect() AdditionalDetails mismatch (-want +got):\n%s", diff)
			}

			if len(baseVuln.GetAdditionalDetails()) != 0 {
				t.Errorf("baseVuln was mutated during Detect()")
			}

			budget := collector.Value(t.Context(), metrics.BudgetExhausted,
				metrics.Module(d.Name()),
				metrics.LimitName(metrics.LimitMaxAttemptsPerService))
			if budget != tc.wantBudgetExhausted {
				t.Errorf("budget/exhausted = %d, want %d", budget, tc.wantBudgetExhausted)
			}
		})
	}
}

func TestDetector_Detect_RateLimiting(t *testing.T) {
	store := smallStore([]string{"u1"}, []string{"p1", "p2", "p3"})
	cfg := config.FromProto(cpb.Config_builder{
		Plugins: cpb.PluginsConfig_builder{
			Bruteforce: bfpb.BruteForceConfig_builder{
				MaxRequestsPerSecond: proto.Int32(25), // 40ms between requests -> ~80ms for 3 requests
				MaxConcurrency:       proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())

	var attempts atomic.Int32
	handler := &fakeHandler{
		testCredFn: func(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
			attempts.Add(1)
			return false, nil
		},
	}

	d, err := New(t.Context(), cfg, handler, &Options{CredentialStore: store})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	start := time.Now()
	if _, err := d.Detect(t.Context(), testService()); err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}
	elapsed := time.Since(start)

	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
	// With burst=1 and 25 QPS (40ms interval), 3 attempts require 2 intervals (~80ms).
	if elapsed < 60*time.Millisecond {
		t.Errorf("Detect() elapsed = %v, want >= 60ms for 3 requests at 25 QPS", elapsed)
	}
}

type statefulRenegotiatingWorker struct {
	connID         int
	attemptsOnConn int
	closed         bool
	closeErr       error
}

func (w *statefulRenegotiatingWorker) TestCredential(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error) {
	if w.connID == 0 || w.attemptsOnConn >= 2 {
		w.connID++
		w.attemptsOnConn = 0
	}
	w.attemptsOnConn++

	// Only succeeds on connection 3 (5th attempt).
	if w.connID == 3 && cred.Password == "p5" {
		return true, nil
	}
	return false, nil
}

func (w *statefulRenegotiatingWorker) Close() error {
	w.closed = true
	return w.closeErr
}

func TestDetector_Detect_StatefulWorkerRenegotiation(t *testing.T) {
	store := smallStore([]string{"u1"}, []string{"p1", "p2", "p3", "p4", "p5"})
	worker := &statefulRenegotiatingWorker{
		closeErr: errors.New("simulated close failure for log coverage"),
	}

	handler := &fakeHandler{
		newWorkerFn: func() Worker {
			return worker
		},
	}

	d, err := New(t.Context(), config.Default(), handler, &Options{CredentialStore: store})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	reports, err := d.Detect(t.Context(), testService())
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}

	if !worker.closed {
		t.Errorf("worker.closed = false, want true")
	}

	gotDetails := additionalDetailTexts(reports)
	wantDetails := []string{"u1:p5"}
	if diff := cmp.Diff(wantDetails, gotDetails); diff != "" {
		t.Errorf("Detect() AdditionalDetails mismatch (-want +got):\n%s", diff)
	}
}

func TestWorkerPool_DoneAndUserDone(t *testing.T) {
	creds := []Credential{
		{Username: "admin", Password: "123"},
		{Username: "root", Password: "password"},
	}

	tests := []struct {
		name         string
		stopAtFirst  bool
		matched      []int
		checkUser    string
		wantDone     bool
		wantUserDone bool
	}{
		{
			name:         "when_no_matches_returns_false",
			stopAtFirst:  true,
			matched:      nil,
			checkUser:    "admin",
			wantDone:     false,
			wantUserDone: false,
		},
		{
			name:         "when_matched_and_stop_at_first_true_returns_done_true",
			stopAtFirst:  true,
			matched:      []int{0},
			checkUser:    "admin",
			wantDone:     true,
			wantUserDone: true,
		},
		{
			name:         "when_matched_and_stop_at_first_false_returns_done_false_and_user_done_for_matched_user",
			stopAtFirst:  false,
			matched:      []int{0},
			checkUser:    "admin",
			wantDone:     false,
			wantUserDone: true,
		},
		{
			name:         "when_other_user_matched_returns_user_done_false",
			stopAtFirst:  false,
			matched:      []int{0},
			checkUser:    "root",
			wantDone:     false,
			wantUserDone: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pool := &workerPool{
				cfg: bfpb.BruteForceConfig_builder{
					StopAtFirstValidCredentials: proto.Bool(tc.stopAtFirst),
				}.Build(),
				creds:   creds,
				matched: tc.matched,
			}
			if got := pool.Done(); got != tc.wantDone {
				t.Errorf("pool.Done() = %v, want %v", got, tc.wantDone)
			}
			if got := pool.UserDone(tc.checkUser); got != tc.wantUserDone {
				t.Errorf("pool.UserDone(%q) = %v, want %v", tc.checkUser, got, tc.wantUserDone)
			}
		})
	}
}
