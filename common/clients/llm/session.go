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

package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/google/goonami-scanner/core/log"
	"github.com/pborman/uuid"
	"google.golang.org/adk/v2/session"
)

// For most of Goonami's use cases, the in-memory session service is sufficient.
var defaultSessionService session.Service = session.InMemoryService()

type sessionDump struct {
	ID        string           `json:"id"`
	AppName   string           `json:"appName"`
	UserID    string           `json:"userId"`
	UpdatedAt time.Time        `json:"lastUpdateTime"`
	State     map[string]any   `json:"state,omitempty"`
	Events    []*session.Event `json:"events"`
}

// createSession creates a new unique session with the configured session service.
func (c *Client) createSession(ctx context.Context) (string, error) {
	if c.sessionService == nil {
		return "", ErrSessionService
	}

	sessionID := uuid.New()
	_, err := c.sessionService.Create(ctx, &session.CreateRequest{
		SessionID: sessionID,
		UserID:    c.userID,
		AppName:   c.appName,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSessionService, err)
	}
	return sessionID, nil
}

// dumpSession writes the full state and trajectory of the given session to the
// module's artifacts directory if trajectory dumping is enabled.
func (c *Client) dumpSession(ctx context.Context, sessionID string) {
	if !c.config.GetDumpTrajectories() || c.coreConfig == nil || sessionID == "" || c.sessionService == nil {
		return
	}

	artifactsDir, err := c.coreConfig.ArtifactsForModule(llmMetricsModule)
	if err != nil {
		log.WarnContextf(ctx, "Failed to get artifacts directory for dumping session %q: %v", sessionID, err)
		return
	}

	resp, err := c.sessionService.Get(context.WithoutCancel(ctx), &session.GetRequest{
		AppName:   c.appName,
		UserID:    c.userID,
		SessionID: sessionID,
	})
	if err != nil || resp == nil || resp.Session == nil {
		log.WarnContextf(ctx, "Failed to retrieve session %q for dumping: %v", sessionID, err)
		return
	}

	sess := resp.Session
	dump := sessionDump{
		ID:        sess.ID(),
		AppName:   sess.AppName(),
		UserID:    sess.UserID(),
		UpdatedAt: sess.LastUpdateTime(),
		State:     maps.Collect(sess.State().All()),
		Events:    slices.Collect(sess.Events().All()),
	}

	data, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		log.WarnContextf(ctx, "Failed to marshal session %q for dumping: %v", sessionID, err)
		return
	}

	filePath := filepath.Join(artifactsDir, fmt.Sprintf("session_%s.json", sessionID))
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		log.WarnContextf(ctx, "Failed to write session dump to %q: %v", filePath, err)
	}
}
