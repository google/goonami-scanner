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
	"fmt"
	"sync"
	"time"
)

var errBruteForceDeadline = fmt.Errorf("%w: %w", ErrBruteForceTimeout, context.DeadlineExceeded)

// BruteForceTimeout returns the scan-wide active brute-force time limit from the
// configuration. A duration <= 0 indicates no limit.
func (c *Config) BruteForceTimeout() time.Duration {
	if c == nil {
		return 0
	}
	secs := c.PluginsConfig().GetBruteforce().GetTimeoutSeconds()
	if secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// RunBruteForce executes fn under this Config's shared active brute-force wall-clock
// time budget. Only wall-clock time while at least one RunBruteForce call is active
// counts toward the budget. If the budget is already exhausted, RunBruteForce returns
// an error wrapping ErrBruteForceTimeout and context.DeadlineExceeded without calling fn.
// If the budget expires while fn is running, the context passed to fn is canceled and
// RunBruteForce wraps ErrBruteForceTimeout and context.DeadlineExceeded on return.
func (c *Config) RunBruteForce(ctx context.Context, fn func(context.Context) error) error {
	if c == nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(ctx)
	}

	bfCtx, release, err := c.bfBudget.acquire(ctx, c)
	if err != nil {
		return err
	}
	defer release()

	err = fn(bfCtx)
	if err != nil && errors.Is(context.Cause(bfCtx), ErrBruteForceTimeout) {
		return fmt.Errorf("%w: %v", errBruteForceDeadline, err)
	}
	return err
}

type bruteForceTimer interface {
	Stop() bool
}

type bruteForceBudget struct {
	mu          sync.Mutex
	initialized bool
	unlimited   bool
	expired     bool
	remaining   time.Duration
	startedAt   time.Time
	active      int
	nextID      uint64
	cancels     map[uint64]context.CancelCauseFunc
	timer       bruteForceTimer
	timerGen    uint64

	nowFn     func() time.Time
	afterFunc func(time.Duration, func()) bruteForceTimer
}

func (b *bruteForceBudget) now() time.Time {
	if b.nowFn != nil {
		return b.nowFn()
	}
	return time.Now()
}

func (b *bruteForceBudget) startTimer(d time.Duration, fn func()) bruteForceTimer {
	if b.afterFunc != nil {
		return b.afterFunc(d, fn)
	}
	return time.AfterFunc(d, fn)
}

func (b *bruteForceBudget) acquire(ctx context.Context, cfg *Config) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	b.mu.Lock()
	if !b.initialized {
		b.initialized = true
		timeout := cfg.BruteForceTimeout()
		if timeout <= 0 {
			b.unlimited = true
		} else {
			b.remaining = timeout
			b.cancels = make(map[uint64]context.CancelCauseFunc)
		}
	}

	if b.unlimited {
		b.mu.Unlock()
		return ctx, func() {}, nil
	}

	now := b.now()
	if !b.expired && b.active > 0 && now.Sub(b.startedAt) >= b.remaining {
		cancels := b.expireLocked()
		b.mu.Unlock()
		for _, cancel := range cancels {
			cancel(errBruteForceDeadline)
		}
		return nil, nil, errBruteForceDeadline
	}

	if b.expired {
		b.mu.Unlock()
		return nil, nil, errBruteForceDeadline
	}

	b.nextID++
	id := b.nextID
	bfCtx, cancel := context.WithCancelCause(ctx)
	b.cancels[id] = cancel

	if b.active == 0 {
		b.startedAt = now
		b.timerGen++
		gen := b.timerGen
		b.timer = b.startTimer(b.remaining, func() {
			b.onExpire(gen)
		})
	}
	b.active++
	b.mu.Unlock()

	release := sync.OnceFunc(func() {
		b.release(id)
		cancel(nil)
	})
	return bfCtx, release, nil
}

func (b *bruteForceBudget) release(id uint64) {
	b.mu.Lock()
	delete(b.cancels, id)
	var cancels []context.CancelCauseFunc
	if !b.expired && b.active > 0 {
		b.active--
		if b.active == 0 {
			if b.timer != nil {
				b.timer.Stop()
				b.timer = nil
			}
			b.timerGen++
			elapsed := b.now().Sub(b.startedAt)
			if elapsed >= b.remaining {
				cancels = b.expireLocked()
			} else if elapsed > 0 {
				b.remaining -= elapsed
			}
		}
	}
	b.mu.Unlock()

	for _, cancel := range cancels {
		cancel(errBruteForceDeadline)
	}
}

func (b *bruteForceBudget) onExpire(gen uint64) {
	b.mu.Lock()
	if b.expired || b.active == 0 || gen != b.timerGen {
		b.mu.Unlock()
		return
	}

	now := b.now()
	elapsed := now.Sub(b.startedAt)
	if elapsed < b.remaining {
		if elapsed > 0 {
			b.remaining -= elapsed
		}
		b.startedAt = now
		b.timerGen++
		nextGen := b.timerGen
		b.timer = b.startTimer(b.remaining, func() {
			b.onExpire(nextGen)
		})
		b.mu.Unlock()
		return
	}

	cancels := b.expireLocked()
	b.mu.Unlock()

	for _, cancel := range cancels {
		cancel(errBruteForceDeadline)
	}
}

func (b *bruteForceBudget) expireLocked() []context.CancelCauseFunc {
	b.expired = true
	b.active = 0
	b.remaining = 0
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.timerGen++
	if len(b.cancels) == 0 {
		return nil
	}
	cancels := make([]context.CancelCauseFunc, 0, len(b.cancels))
	for _, cancel := range b.cancels {
		cancels = append(cancels, cancel)
	}
	clear(b.cancels)
	return cancels
}

func (b *bruteForceBudget) stop() {
	b.mu.Lock()
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.timerGen++
	b.active = 0
	var cancels []context.CancelCauseFunc
	if len(b.cancels) > 0 {
		cancels = make([]context.CancelCauseFunc, 0, len(b.cancels))
		for _, cancel := range b.cancels {
			cancels = append(cancels, cancel)
		}
		clear(b.cancels)
	}
	b.mu.Unlock()

	for _, cancel := range cancels {
		cancel(nil)
	}
}
