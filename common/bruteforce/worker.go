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
	"io"
	"sync"

	"github.com/google/goonami-scanner/core/log"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	bfpb "github.com/google/goonami-scanner/common/bruteforce/bruteforce_config_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// Worker executes credential attempts sequentially within a single brute-force
// goroutine. Because each Worker instance is used by a single goroutine,
// implementations for stateful protocols (e.g. SSH, RDP) can maintain and
// renegotiate connection state across attempts without synchronization.
//
// Detector calls Close when the worker goroutine finishes.
type Worker interface {
	io.Closer

	// TestCredential attempts to authenticate against the service using the
	// provided credential.
	// Returning (true, nil) indicates the credential is valid.
	// Returning (false, nil) indicates the credential is invalid (normal authentication failure).
	// Returning (false, err) indicates an unexpected error that should abort brute-forcing.
	TestCredential(ctx context.Context, service *nspb.NetworkService, cred Credential) (bool, error)
}

type workerPool struct {
	cfg     *bfpb.BruteForceConfig
	service *nspb.NetworkService
	creds   []Credential
	workCh  chan int
	limiter *rate.Limiter

	mu      sync.Mutex
	matched []int
}

func testCredentials(ctx context.Context, cfg *bfpb.BruteForceConfig, newWorker func() Worker, service *nspb.NetworkService, creds []Credential) ([]Credential, error) {
	workCh := make(chan int, len(creds))
	for i := range creds {
		workCh <- i
	}
	close(workCh)

	pool := &workerPool{
		cfg:     cfg,
		service: service,
		creds:   creds,
		workCh:  workCh,
		limiter: newLimiter(cfg.GetMaxRequestsPerSecond()),
	}

	numWorkers := min(int(cfg.GetMaxConcurrency()), len(creds))
	group, grpctx := errgroup.WithContext(ctx)
	for range numWorkers {
		group.Go(func() error {
			return pool.runWorker(grpctx, newWorker())
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return pool.validCredentials(), nil
}

func (p *workerPool) runWorker(ctx context.Context, worker Worker) error {
	defer func() {
		if err := worker.Close(); err != nil {
			log.DebugContextf(ctx, log.DebugLevelRequest, "closing brute-force worker: %v", err)
		}
	}()

	for idx := range p.workCh {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p.Done() {
			return nil
		}

		cred := p.creds[idx]
		if p.UserDone(cred.Username) {
			continue
		}

		if err := p.limiter.Wait(ctx); err != nil {
			return err
		}

		log.DebugContextf(ctx, log.DebugLevelRequest, "attempting detection with credentials %s", cred)
		valid, err := worker.TestCredential(ctx, p.service, cred)
		if err != nil {
			return err
		}

		if valid {
			log.DebugContextf(ctx, log.DebugLevelService, "valid credentials identified: %s", cred)
			p.recordMatch(idx)
		}
	}
	return nil
}

func (p *workerPool) recordMatch(idx int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.matched = append(p.matched, idx)
}

// Done reports whether the pool has found a valid credential and is configured
// to stop at the first match.
func (p *workerPool) Done() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.GetStopAtFirstValidCredentials() && len(p.matched) > 0
}

// UserDone reports whether a valid credential has already been found for user.
func (p *workerPool) UserDone(user string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, idx := range p.matched {
		if p.creds[idx].Username == user {
			return true
		}
	}
	return false
}

func (p *workerPool) validCredentials() []Credential {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.matched) == 0 {
		return nil
	}

	creds := make([]Credential, len(p.matched))
	for i, idx := range p.matched {
		creds[i] = p.creds[idx]
	}
	return creds
}

func newLimiter(qps int32) *rate.Limiter {
	if qps <= 0 {
		return rate.NewLimiter(rate.Inf, 0)
	}
	return rate.NewLimiter(rate.Limit(qps), 1)
}
