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

// Package callbackserver provides a client for the Tsunami Callback Server.
package callbackserver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	cscpb "github.com/google/goonami-scanner/common/clients/callbackserver/callbackserver_client_config_go_proto"
	ppb "github.com/google/goonami-scanner/common/clients/callbackserver/polling_go_proto"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/iputils"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrPollingRequest is returned when the polling request fails.
	ErrPollingRequest = errors.New("polling request failed")

	// ErrInvalidConfig is returned when the callback server configuration is invalid.
	ErrInvalidConfig = errors.New("invalid callback server configuration")
)

// Client is a client for the Tsunami Callback Server.
type Client struct {
	config     *cscpb.CallbackServerClientConfig
	coreConfig *config.Config
}

// New creates a new Client.
func New(ctx context.Context, config *config.Config) *Client {
	ctx = log.ContextForModule(ctx, "client/callbackserver")
	clientConfig := &cscpb.CallbackServerClientConfig{}
	if config.ClientsConfig().HasCallbackServer() {
		proto.Merge(clientConfig, config.ClientsConfig().GetCallbackServer())
	} else {
		log.WarnContextf(ctx, "no callback server config: callbacks will be disabled")
	}

	return &Client{
		config:     clientConfig,
		coreConfig: config,
	}
}

// IsCallbackServerEnabled returns true if the callback server is enabled.
func (c *Client) IsCallbackServerEnabled() bool {
	if !(c.config.GetCallbackPort() > 0 && c.config.GetCallbackPort() < 65536) {
		return false
	}

	if c.config.GetCallbackAddress() == "" {
		return false
	}

	if c.config.GetPollingBaseUrl() == "" {
		return false
	}

	return true
}

// GetCallbackURI returns the callback URI for a given secret string.
func (c *Client) GetCallbackURI(secret string) (string, error) {
	if !c.IsCallbackServerEnabled() {
		return "", ErrInvalidConfig
	}

	cbid, err := GenerateCBID(secret)
	if err != nil {
		return "", err
	}

	address := c.config.GetCallbackAddress()
	port := c.config.GetCallbackPort()

	// For IPs, we use the HTTP format.
	if iputils.IsIP(address) {
		return fmt.Sprintf("http://%s:%d/%s", address, port, cbid), nil
	}

	// For domains, we use it as a subdomain.
	return fmt.Sprintf("%s.%s:%d", cbid, address, port), nil
}

// HasInteraction checks whether the callback server has recorded any interaction for the given secret.
func (c *Client) HasInteraction(ctx context.Context, secret string) (bool, error) {
	if !c.IsCallbackServerEnabled() {
		return false, ErrInvalidConfig
	}

	result, err := c.poll(ctx, secret)
	if err != nil || result == nil {
		return false, err
	}

	hasInteraction := result.GetHasDnsInteraction() || result.GetHasHttpInteraction()
	return hasInteraction, nil
}

func (c *Client) poll(ctx context.Context, secret string) (*ppb.PollingResult, error) {
	pollingURL := strings.TrimSuffix(c.config.GetPollingBaseUrl(), "/")
	url := fmt.Sprintf("%s/?secret=%s", pollingURL, secret)

	ctx, cancel := context.WithTimeout(ctx, c.coreConfig.TimeoutPerRequest())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPollingRequest, err)
	}

	resp, err := goohttp.DefaultClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPollingRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.DebugContextf(ctx, log.DebugLevelService, "secret not found")
		return nil, nil
	}

	// Note: the callback server answer should be relatively small.
	body, err := goohttp.ReadBody(resp, 1024)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response from callback server: %v", ErrPollingRequest, err)
	}

	result := &ppb.PollingResult{}
	if err := protojson.Unmarshal(body, result); err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal JSON: %v", ErrPollingRequest, err)
	}

	return result, nil
}

// GenerateCBID generates a CBID from a secret string using SHA3-224.
func GenerateCBID(secret string) (string, error) {
	d := sha3.New224()
	if _, err := d.Write([]byte(secret)); err != nil {
		return "", err
	}

	return hex.EncodeToString(d.Sum(nil)), nil
}
