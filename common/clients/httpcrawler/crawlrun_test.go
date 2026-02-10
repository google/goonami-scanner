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

package httpcrawler

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestCrawlRun_Callback(t *testing.T) {
	errCallback := errors.New("callback error")
	tests := []struct {
		name     string
		callback PageCallback
		wantErr  error
	}{
		{
			name: "when_callback_is_successful_returns_no_error",
			callback: func(info *PageInfo, _ *http.Response, _ []byte) error {
				return nil
			},
			wantErr: nil,
		},
		{
			name: "when_callback_fails_it_propagates_error",
			callback: func(info *PageInfo, _ *http.Response, _ []byte) error {
				return errCallback
			},
			wantErr: errCallback,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &crawlRun{callback: tc.callback}
			pi := &PageInfo{}
			err := r.Callback(pi, nil, nil)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Callback() error: got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCrawlRun_AlreadyVisited(t *testing.T) {
	tests := []struct {
		name    string
		visited map[string]bool
		url     string
		want    bool
	}{
		{
			name:    "when_url_is_not_visited_returns_false",
			visited: map[string]bool{},
			url:     "/test1",
			want:    false,
		},
		{
			name:    "when_url_is_visited_returns_true",
			visited: map[string]bool{"/test1": true},
			url:     "/test1",
			want:    true,
		},
		{
			name: "when_url_with_trailing_slash_is_visited_returns_true",
			visited: map[string]bool{
				"/test1": true,
			},
			url:  "/test1/",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &crawlRun{visited: tc.visited}
			if got := r.AlreadyVisited(tc.url); got != tc.want {
				t.Errorf("AlreadyVisited(%q): got %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

func TestCrawlRun_AddToVisited(t *testing.T) {
	tests := []struct {
		name      string
		add       []string
		want      map[string]bool
		wantCount int32
	}{
		{
			name:      "when_adding_one_url_it_is_marked_as_visited",
			add:       []string{"/test1"},
			want:      map[string]bool{"/test1": true},
			wantCount: 1,
		},
		{
			name:      "when_adding_one_url_with_trailing_slash_it_is_marked_as_visited_without_slash",
			add:       []string{"/test1/"},
			want:      map[string]bool{"/test1": true},
			wantCount: 1,
		},
		{
			name:      "when_adding_two_urls_both_are_marked_as_visited",
			add:       []string{"/test1", "/test2/"},
			want:      map[string]bool{"/test1": true, "/test2": true},
			wantCount: 2,
		},
		{
			name:      "when_adding_duplicate_urls_only_one_is_marked_as_visited",
			add:       []string{"/test1", "/test1/"},
			want:      map[string]bool{"/test1": true},
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &crawlRun{visited: make(map[string]bool)}
			for _, url := range tc.add {
				r.AddToVisited(url)
			}
			if got := r.CountVisited(); got != tc.wantCount {
				t.Errorf("CountVisited(): got %d, want %d", got, tc.wantCount)
			}
			if diff := cmp.Diff(tc.want, r.visited); diff != "" {
				t.Errorf("visited map differs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCrawlRun_QueuePage(t *testing.T) {
	r := &crawlRun{
		queue:   make(chan *PageInfo, 10),
		visited: make(map[string]bool),
	}

	if got := r.CountPending(); got != 0 {
		t.Errorf("PendingCount at start: got %d, want 0", got)
	}

	r.QueuePage("url1", 0)
	if got := r.CountPending(); got != 1 {
		t.Errorf("PendingCount after QueuePage: got %d, want 1", got)
	}
}

func TestCrawlRun_PageDone(t *testing.T) {
	r := &crawlRun{
		queue:     make(chan *PageInfo, 10),
		visited:   make(map[string]bool),
		workCount: 1,
	}

	r.PageDone()
	if got := r.CountPending(); got != 0 {
		t.Errorf("PendingCount after PageDone: got %d, want 0", got)
	}
}

func TestCrawlRun_StartWatcher(t *testing.T) {
	r := &crawlRun{
		queue:   make(chan *PageInfo, 10),
		visited: make(map[string]bool),
	}
	r.workCount = 1
	r.StartWatcher()

	// If watcher is working, it should eventually see PendingCount() == 0 and close queue.
	r.PageDone()

	select {
	case _, ok := <-r.queue:
		if ok {
			t.Errorf("channel should be closed by watcher")
		}
	case <-time.After(1 * time.Second):
		t.Errorf("watcher did not close channel within timeout")
	}
}
