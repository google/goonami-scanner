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

// Package fakenmap provides a fake implementation of the nmap client.
package fakenmap

import (
	"context"
	"os"

	"github.com/google/goonami-scanner/common/clients/nmap"
)

// Client is a fake implementation of the nmap client.
type Client struct {
	output *nmap.OutputXML
	err    error
}

// New creates a new fake nmap client.
func New(output *nmap.OutputXML, err error) *Client {
	return &Client{
		output: output,
		err:    err,
	}
}

// FromFile creates a fake nmap client but directly loads the output to be provided from a file.
func FromFile(path string) (*Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	output, err := nmap.ParseXMLOutput(data)
	if err != nil {
		return nil, err
	}

	return &Client{
		output: output,
	}, nil
}

// Run returns the fake nmap output and error.
func (c *Client) Run(ctx context.Context, target string) (*nmap.OutputXML, error) {
	return c.output, c.err
}
