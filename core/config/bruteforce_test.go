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

package config

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	bfpb "github.com/google/goonami-scanner/common/bruteforce/bruteforce_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

type fakeTimer struct {
	clock   *fakeClock
	fireAt  time.Time
	fn      func()
	stopped bool
}

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.stopped {
		return false
	}
	t.stopped = true
	return true
}

type fakeClock struct {
	mu     sync.Mutex
	cur    time.Time
	timers []*fakeTimer
}

func newFakeClock() *fakeClock {
	return &fakeClock{
		cur: time.Unix(1_700_000_000, 0),
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}

func (c *fakeClock) AfterFunc(d time.Duration, fn func()) bruteForceTimer {
	c.mu.Lock()
	timer := &fakeTimer{
		clock:  c,
		fireAt: c.cur.Add(d),
		fn:     fn,
	}
	if d <= 0 {
		timer.stopped = true
		c.mu.Unlock()
		go fn()
		return timer
	}
	c.timers = append(c.timers, timer)
	c.mu.Unlock()
	return timer
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.cur = c.cur.Add(d)
	var due []func()
	var remaining []*fakeTimer
	for _, timer := range c.timers {
		if timer.stopped {
			continue
		}
		if !timer.fireAt.After(c.cur) {
			timer.stopped = true
			due = append(due, timer.fn)
		} else {
			remaining = append(remaining, timer)
		}
	}
	c.timers = remaining
	c.mu.Unlock()

	for _, fn := range due {
		fn()
	}
}

func (c *fakeClock) ActiveTimerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for _, timer := range c.timers {
		if !timer.stopped {
			count++
		}
	}
	return count
}

func newBudgetConfig(timeoutSeconds int32, clock *fakeClock) *Config {
	cfg := FromProto(cpb.Config_builder{
		Plugins: cpb.PluginsConfig_builder{
			Bruteforce: bfpb.BruteForceConfig_builder{
				TimeoutSeconds: new(timeoutSeconds),
			}.Build(),
		}.Build(),
	}.Build())
	cfg.bfBudget.nowFn = clock.Now
	cfg.bfBudget.afterFunc = clock.AfterFunc
	return cfg
}

func TestBruteForceTimeout(t *testing.T) {
	tests := []struct {
		name      string
		cfg       func(t *testing.T) *Config
		overrides []string
		want      time.Duration
	}{
		{
			name: "when_default_config_returns_30_minutes",
			cfg: func(t *testing.T) *Config {
				t.Helper()
				return Default()
			},
			want: 20 * time.Minute,
		},
		{
			name: "when_explicit_timeout_returns_configured_duration",
			cfg: func(t *testing.T) *Config {
				t.Helper()
				return FromProto(cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Bruteforce: bfpb.BruteForceConfig_builder{
							TimeoutSeconds: new(int32(120)),
						}.Build(),
					}.Build(),
				}.Build())
			},
			want: 2 * time.Minute,
		},
		{
			name: "when_timeout_is_zero_returns_zero",
			cfg: func(t *testing.T) *Config {
				t.Helper()
				return FromProto(cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Bruteforce: bfpb.BruteForceConfig_builder{
							TimeoutSeconds: new(int32(0)),
						}.Build(),
					}.Build(),
				}.Build())
			},
			want: 0,
		},
		{
			name: "when_timeout_is_negative_returns_zero",
			cfg: func(t *testing.T) *Config {
				t.Helper()
				return FromProto(cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Bruteforce: bfpb.BruteForceConfig_builder{
							TimeoutSeconds: new(int32(-10)),
						}.Build(),
					}.Build(),
				}.Build())
			},
			want: 0,
		},
		{
			name: "when_overridden_via_apply_overrides_returns_overridden_duration",
			cfg: func(t *testing.T) *Config {
				t.Helper()
				return Default()
			},
			overrides: []string{"plugins.bruteforce.timeout_seconds=45"},
			want:      45 * time.Second,
		},
		{
			name: "when_config_is_nil_returns_zero",
			cfg: func(t *testing.T) *Config {
				t.Helper()
				return nil
			},
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg(t)
			if len(tc.overrides) > 0 {
				if err := cfg.ApplyOverrides(t.Context(), tc.overrides); err != nil {
					t.Fatalf("ApplyOverrides(%v) unexpected error: %v", tc.overrides, err)
				}
			}

			if got := cfg.BruteForceTimeout(); got != tc.want {
				t.Errorf("BruteForceTimeout() = %v, want %v", got, tc.want)
			}
		})
	}
}

type budgetStep struct {
	idleBefore    time.Duration
	preCancel     bool
	activeAdvance time.Duration
	cancelDuring  bool
	wantCalled    bool
	wantErrs      []error
	wantNotErrs   []error
}

func TestRunBruteForce(t *testing.T) {
	tests := []struct {
		name           string
		nilConfig      bool
		timeoutSeconds int32
		steps          []budgetStep
	}{
		{
			name:           "when_timeout_disabled_allows_unlimited_execution",
			timeoutSeconds: 0,
			steps: []budgetStep{
				{
					activeAdvance: time.Hour,
					wantCalled:    true,
				},
				{
					activeAdvance: time.Hour,
					wantCalled:    true,
				},
			},
		},
		{
			name:      "when_config_is_nil_runs_without_budget",
			nilConfig: true,
			steps: []budgetStep{
				{
					activeAdvance: time.Hour,
					wantCalled:    true,
				},
			},
		},
		{
			name:           "when_caller_context_already_canceled_returns_context_canceled",
			timeoutSeconds: 10,
			steps: []budgetStep{
				{
					preCancel:   true,
					wantCalled:  false,
					wantErrs:    []error{context.Canceled},
					wantNotErrs: []error{ErrBruteForceTimeout, context.DeadlineExceeded},
				},
			},
		},
		{
			name:           "when_caller_context_canceled_mid_run_returns_context_canceled_and_deducts_elapsed",
			timeoutSeconds: 10,
			steps: []budgetStep{
				{
					activeAdvance: 6 * time.Second,
					cancelDuring:  true,
					wantCalled:    true,
					wantErrs:      []error{context.Canceled},
					wantNotErrs:   []error{ErrBruteForceTimeout, context.DeadlineExceeded},
				},
				{
					activeAdvance: 4 * time.Second,
					wantCalled:    true,
					wantErrs:      []error{ErrBruteForceTimeout, context.DeadlineExceeded},
					wantNotErrs:   []error{context.Canceled},
				},
			},
		},
		{
			name:           "when_budget_expires_mid_run_cancels_context_and_returns_brute_force_timeout",
			timeoutSeconds: 10,
			steps: []budgetStep{
				{
					activeAdvance: 10 * time.Second,
					wantCalled:    true,
					wantErrs:      []error{ErrBruteForceTimeout, context.DeadlineExceeded},
					wantNotErrs:   []error{context.Canceled},
				},
			},
		},
		{
			name:           "when_budget_already_exhausted_skips_fn_and_returns_brute_force_timeout",
			timeoutSeconds: 10,
			steps: []budgetStep{
				{
					activeAdvance: 10 * time.Second,
					wantCalled:    true,
					wantErrs:      []error{ErrBruteForceTimeout, context.DeadlineExceeded},
					wantNotErrs:   []error{context.Canceled},
				},
				{
					wantCalled:  false,
					wantErrs:    []error{ErrBruteForceTimeout, context.DeadlineExceeded},
					wantNotErrs: []error{context.Canceled},
				},
			},
		},
		{
			name:           "when_idle_between_runs_pauses_timer_and_accumulates_only_active_time",
			timeoutSeconds: 10,
			steps: []budgetStep{
				{
					activeAdvance: 6 * time.Second,
					wantCalled:    true,
				},
				{
					// Long non-bruteforce phase must not consume brute-force budget.
					idleBefore:    time.Hour,
					activeAdvance: 3 * time.Second,
					wantCalled:    true,
				},
				{
					idleBefore:    time.Hour,
					activeAdvance: 1 * time.Second,
					wantCalled:    true,
					wantErrs:      []error{ErrBruteForceTimeout, context.DeadlineExceeded},
					wantNotErrs:   []error{context.Canceled},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock()
			var cfg *Config
			if !tc.nilConfig {
				cfg = newBudgetConfig(tc.timeoutSeconds, clock)
			}

			for i, step := range tc.steps {
				if step.idleBefore > 0 {
					clock.Advance(step.idleBefore)
				}

				stepCtx, cancel := context.WithCancel(t.Context())
				if step.preCancel {
					cancel()
				}

				called := false
				err := cfg.RunBruteForce(stepCtx, func(bfCtx context.Context) error {
					called = true
					if _, hasDeadline := bfCtx.Deadline(); hasDeadline {
						t.Errorf("step %d: bfCtx has a deadline, want no synthetic deadline", i)
					}
					if step.activeAdvance > 0 {
						clock.Advance(step.activeAdvance)
					}
					if step.cancelDuring {
						cancel()
					}
					return bfCtx.Err()
				})
				cancel()

				if called != step.wantCalled {
					t.Errorf("step %d: RunBruteForce() called = %t, want %t", i, called, step.wantCalled)
				}
				if len(step.wantErrs) == 0 && err != nil {
					t.Errorf("step %d: RunBruteForce() error = %v, want nil", i, err)
				}
				for _, wantErr := range step.wantErrs {
					if !errors.Is(err, wantErr) {
						t.Errorf("step %d: RunBruteForce() error = %v, want errors.Is(_, %v) = true", i, err, wantErr)
					}
				}
				for _, notErr := range step.wantNotErrs {
					if errors.Is(err, notErr) {
						t.Errorf("step %d: RunBruteForce() error = %v, want errors.Is(_, %v) = false", i, err, notErr)
					}
				}
			}

			if got := clock.ActiveTimerCount(); got != 0 {
				t.Errorf("ActiveTimerCount() = %d, want 0 after RunBruteForce steps finish", got)
			}
		})
	}
}

func TestRunBruteForce_ConcurrentOverlap(t *testing.T) {
	tests := []struct {
		name              string
		timeoutSeconds    int32
		secondStartDelay  time.Duration
		firstFinishAfter  time.Duration
		secondFinishAfter time.Duration
		wantFirstErrs     []error
		wantSecondErrs    []error
		wantFollowUpErrs  []error
	}{
		{
			name:              "when_concurrent_runs_finish_within_budget_counts_shared_wall_clock",
			timeoutSeconds:    10,
			secondStartDelay:  2 * time.Second,
			firstFinishAfter:  3 * time.Second, // ends at t=5s
			secondFinishAfter: 2 * time.Second, // ends at t=7s -> 3s left
			wantFollowUpErrs:  nil,             // 3s remain, so an instant follow-up succeeds
		},
		{
			name:              "when_concurrent_runs_overlap_shares_wall_clock_budget_and_cancels_all_on_expiry",
			timeoutSeconds:    10,
			secondStartDelay:  4 * time.Second,
			firstFinishAfter:  6 * time.Second, // t=10s -> expires both
			secondFinishAfter: 0,
			wantFirstErrs:     []error{ErrBruteForceTimeout, context.DeadlineExceeded},
			wantSecondErrs:    []error{ErrBruteForceTimeout, context.DeadlineExceeded},
			wantFollowUpErrs:  []error{ErrBruteForceTimeout, context.DeadlineExceeded},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock()
			cfg := newBudgetConfig(tc.timeoutSeconds, clock)

			firstEntered := make(chan struct{})
			proceedFirst := make(chan struct{})
			secondEntered := make(chan struct{})
			proceedSecond := make(chan struct{})

			var wg sync.WaitGroup
			var firstErr, secondErr error

			wg.Add(1)
			go func() {
				defer wg.Done()
				firstErr = cfg.RunBruteForce(t.Context(), func(bfCtx context.Context) error {
					close(firstEntered)
					select {
					case <-proceedFirst:
					case <-bfCtx.Done():
					}
					return bfCtx.Err()
				})
			}()

			<-firstEntered
			clock.Advance(tc.secondStartDelay)

			wg.Add(1)
			go func() {
				defer wg.Done()
				secondErr = cfg.RunBruteForce(t.Context(), func(bfCtx context.Context) error {
					close(secondEntered)
					select {
					case <-proceedSecond:
					case <-bfCtx.Done():
					}
					return bfCtx.Err()
				})
			}()

			<-secondEntered
			if tc.firstFinishAfter > 0 {
				clock.Advance(tc.firstFinishAfter)
			}
			close(proceedFirst)

			if tc.secondFinishAfter > 0 {
				clock.Advance(tc.secondFinishAfter)
			}
			close(proceedSecond)

			wg.Wait()

			if len(tc.wantFirstErrs) == 0 && firstErr != nil {
				t.Errorf("first RunBruteForce() error = %v, want nil", firstErr)
			}
			for _, wantErr := range tc.wantFirstErrs {
				if !errors.Is(firstErr, wantErr) {
					t.Errorf("first RunBruteForce() error = %v, want %v", firstErr, wantErr)
				}
			}

			if len(tc.wantSecondErrs) == 0 && secondErr != nil {
				t.Errorf("second RunBruteForce() error = %v, want nil", secondErr)
			}
			for _, wantErr := range tc.wantSecondErrs {
				if !errors.Is(secondErr, wantErr) {
					t.Errorf("second RunBruteForce() error = %v, want %v", secondErr, wantErr)
				}
			}

			followUpErr := cfg.RunBruteForce(t.Context(), func(bfCtx context.Context) error {
				return bfCtx.Err()
			})
			if len(tc.wantFollowUpErrs) == 0 && followUpErr != nil {
				t.Errorf("follow-up RunBruteForce() error = %v, want nil", followUpErr)
			}
			for _, wantErr := range tc.wantFollowUpErrs {
				if !errors.Is(followUpErr, wantErr) {
					t.Errorf("follow-up RunBruteForce() error = %v, want %v", followUpErr, wantErr)
				}
			}

			if got := clock.ActiveTimerCount(); got != 0 {
				t.Errorf("ActiveTimerCount() = %d, want 0", got)
			}
		})
	}
}

func TestRunBruteForce_CloseStopsActiveTimer(t *testing.T) {
	clock := newFakeClock()
	cfg := newBudgetConfig(1800, clock)
	if err := cfg.CreateDirectories(t.TempDir()); err != nil {
		t.Fatalf("CreateDirectories() unexpected error: %v", err)
	}

	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- cfg.RunBruteForce(t.Context(), func(bfCtx context.Context) error {
			close(entered)
			<-bfCtx.Done()
			return bfCtx.Err()
		})
	}()

	<-entered
	if got := clock.ActiveTimerCount(); got != 1 {
		t.Fatalf("ActiveTimerCount() = %d, want 1 while active", got)
	}

	if err := cfg.Close(t.Context()); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}
	if got := clock.ActiveTimerCount(); got != 0 {
		t.Errorf("ActiveTimerCount() after Close() = %d, want 0", got)
	}

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("RunBruteForce() error after Close() = %v, want %v", err, context.Canceled)
	}
}
