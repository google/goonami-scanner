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
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/common/callbackserver/netutils"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"google.golang.org/protobuf/encoding/protojson"

	ppb "github.com/google/goonami-scanner/common/clients/callbackserver/polling_go_proto"
	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
)

var (
	// ErrPollingRequest is returned when the polling request fails.
	ErrPollingRequest = errors.New("polling request failed")

	// ErrDomainCallbackWithIP is returned when the callback server address is an IP address.
	ErrDomainCallbackWithIP = errors.New("domain callback with IP address is not supported, please use a hostname")

	// ErrInvalidConfig is returned when the callback server configuration is invalid.
	ErrInvalidConfig = errors.New("invalid callback server configuration")
)

var defaultClient *Client = nil

// Client is a client for the Tsunami Callback Server.
type Client struct {
	coreConfig *config.Config
	config     *cbpb.CallbackserverConfig
}

// Initialize the default callback server client.
func Initialize(ctx context.Context, config *config.Config) error {
	var err error
	defaultClient, err = new(ctx, config)
	return err
}

// DefaultClient returns the default callback server client.
func DefaultClient() *Client {
	if defaultClient == nil {
		panic("fatal error: callack server client was never initialized")
	}

	return defaultClient
}

// new creates a new Client.
func new(ctx context.Context, config *config.Config) (*Client, error) {
	ctx = log.ContextForModule(ctx, "client/callbackserver")
	clientConfig := &cbpb.CallbackserverConfig{}

	if config.ClientsConfig().HasCallbackServer() {
		clientConfig = config.ClientsConfig().GetCallbackServer()
	}

	return &Client{
		config:     clientConfig,
		coreConfig: config,
	}, nil
}

// IsCallbackServerEnabled returns true if the callback server is enabled. Note that this is a
// client perspective, so we only need the public URIs.
func (c *Client) IsCallbackServerEnabled() bool {
	if c.config.GetHttpPollConfig().GetPublicUri() == "" {
		return false
	}

	if c.config.GetHttpRecordConfig().GetPublicUri() == "" {
		return false
	}

	if c.config.GetDnsRecordConfig().GetPublicUri() == "" {
		return false
	}

	return true
}

// GetHTTPCallbackURI returns the callback URI for a given secret string. This is the HTTP URI used to
// record the interaction.
func (c *Client) GetHTTPCallbackURI(secret string) (string, error) {
	if !c.IsCallbackServerEnabled() {
		return "", ErrInvalidConfig
	}

	id, err := cbid.Generate(secret)
	if err != nil {
		return "", err
	}

	publicURI := c.config.GetHttpRecordConfig().GetPublicUri()
	return netutils.CallbackURL(publicURI, id), nil
}

// HasInteraction checks whether the callback server has recorded any interaction for the given
// secret. Expects caller to have called IsCallbackServerEnabled first.
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
	pollingURL := strings.TrimSuffix(c.config.GetHttpPollConfig().GetPublicUri(), "/")
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
