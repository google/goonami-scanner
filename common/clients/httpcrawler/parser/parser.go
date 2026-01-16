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

// Package parser provides functions to parse HTML content and extract potentially new crawling
// targets.
package parser

import (
	"bytes"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

var (
	knownLinkAttributes = []string{
		// HTML 4 link attributes.
		"action",
		"archive",
		"background",
		"cite",
		"codebase",
		"data",
		"href",
		"longdesc",
		"profile",
		"src",

		// HTML 5 link attributes.
		"formaction",
		"manifest",
		"poster",
		"srcdoc",
		"ping",
	}
)

// ExtractLinksFromHTML extracts all potentially new crawling targets from the given HTML content.
func ExtractLinksFromHTML(rootURL string, content []byte) ([]string, error) {
	r := bytes.NewReader(content)
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}

	var results []string
	for node := range doc.ChildNodes() {
		links, err := processHTMLNode(rootURL, node)
		if err != nil {
			return nil, err
		}

		results = append(results, links...)
	}

	return results, nil
}

func processHTMLNode(rootURL string, node *html.Node) ([]string, error) {
	var results []string

	for child := range node.ChildNodes() {
		links, err := processHTMLNode(rootURL, child)
		if err != nil {
			return nil, err
		}
		results = append(results, links...)
	}

	for _, attr := range node.Attr {
		if !slices.Contains(knownLinkAttributes, attr.Key) {
			continue
		}

		link, err := parseURL(rootURL, attr.Val)
		if err != nil {
			return nil, err
		}

		results = append(results, link)
	}

	return results, nil
}

func parseURL(base string, redirect string) (string, error) {
	if strings.HasPrefix(redirect, "javascript:") || strings.HasPrefix(redirect, "mailto:") {
		return "", fmt.Errorf("unsupported URL type: %q", redirect)
	}

	redirurl, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}

	if redirurl.Scheme != "" {
		if redirurl.Scheme != "http" && redirurl.Scheme != "https" {
			return "", fmt.Errorf("unsupported scheme: %q", redirurl.Scheme)
		}
	}

	if redirurl.IsAbs() {
		return redirurl.String(), nil
	}

	rooturl, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	if len(redirurl.Path) == 0 {
		return rooturl.String(), nil
	}

	newurl := *rooturl

	if redirurl.Path[0] == '/' {
		newurl.Path = redirurl.Path
		return newurl.String(), nil
	}

	rootDir := path.Dir(rooturl.Path)
	newpath, err := url.JoinPath(rootDir, redirurl.String())
	if err != nil {
		return "", err
	}

	newurl.Path = newpath
	return newurl.String(), nil
}
