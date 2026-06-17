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
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

var (
	// ErrParseURL is returned when the URL fails to parse.
	ErrParseURL = errors.New("failed to parse URL")
	// ErrUnsupportedScheme is returned when the URL scheme is not supported.
	ErrUnsupportedScheme = errors.New("unsupported scheme")

	unsupportedPrefixes = []string{
		"data:",
		"javascript:",
		"mailto:",
	}

	knownLinkAttributes = []string{
		// HTML 4 link attributes.
		"action",
		"archive",
		"background",
		"cite",
		"codebase",
		"content",
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

		link, err := dispatch(node, attr.Key, rootURL, attr.Val)
		if err != nil {
			return nil, err
		}

		if link == "" {
			continue
		}

		results = append(results, link)
	}

	return results, nil
}

func dispatch(node *html.Node, key, base, redirect string) (string, error) {
	switch key {
	case "content":
		return parseContent(node, base, redirect)
	default:
		return parseURL(base, redirect)
	}
}

func parseContent(node *html.Node, base, content string) (string, error) {
	if strings.ToLower(node.Data) != "meta" {
		return "", nil
	}

	cleanContent := strings.ToLower(strings.ReplaceAll(content, " ", ""))
	splitContent := strings.Split(cleanContent, "url=")
	if len(splitContent) != 2 {
		return "", nil
	}

	return parseURL(base, splitContent[1])
}

func parseURL(base string, redirect string) (string, error) {
	redirect = strings.TrimSpace(redirect)

	for _, prefix := range unsupportedPrefixes {
		if strings.HasPrefix(redirect, prefix) {
			return "", nil
		}
	}

	redirurl, err := url.Parse(redirect)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrParseURL, err)
	}

	if redirurl.Scheme != "" {
		if redirurl.Scheme != "http" && redirurl.Scheme != "https" {
			return "", fmt.Errorf("%w: %q", ErrUnsupportedScheme, redirurl.Scheme)
		}
	}

	if redirurl.IsAbs() {
		return redirurl.String(), nil
	}

	rooturl, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrParseURL, err)
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
