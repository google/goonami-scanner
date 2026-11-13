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

package webidentity

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/engine"
	"google.golang.org/protobuf/encoding/prototext"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	wfpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/webidentity_fp_config_go_proto"
)

var (
	// ErrSignaturesRead is returned when reading a signature file fails.
	ErrSignaturesRead = errors.New("reading signature file")

	// ErrSignaturesUnmarshal is returned when unmarshaling a signature fails.
	ErrSignaturesUnmarshal = errors.New("unmarshaling signature")
)

//go:embed fingerprints/*.textproto
var embeddedFingerprintsFS embed.FS

// resolveSignaturesDirectory returns the directory containing the signatures.
func resolveSignaturesDirectory(config *wfpb.WebIdentityFpConfig) (string, error) {
	dir := config.GetSignaturesDirectory()
	return filepath.Clean(dir), nil
}

// loadAllFingerprints loads all signatures from the embedded catalog or configured directory.
func loadAllFingerprints(ctx context.Context, config *wfpb.WebIdentityFpConfig) ([]*engine.CompiledFingerprint, error) {
	var fsys fs.FS
	if config.GetSignaturesDirectory() == "" {
		subFS, err := fs.Sub(embeddedFingerprintsFS, "fingerprints")
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSignaturesRead, err)
		}
		if _, err := fs.ReadDir(subFS, "."); errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		fsys = subFS
	} else {
		dirPath, err := resolveSignaturesDirectory(config)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSignaturesRead, err)
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "signatures directory is: %q", dirPath)
		fsys = os.DirFS(dirPath)
	}

	rawDataList, err := readSignatureFiles(fsys)
	if err != nil {
		return nil, err
	}

	var compiled []*engine.CompiledFingerprint
	for _, data := range rawDataList {
		c, err := compileSignatureData(ctx, data)
		if err != nil {
			return nil, err
		}
		if c != nil {
			compiled = append(compiled, c)
		}
	}

	return compiled, nil
}

func readSignatureFiles(fsys fs.FS) ([][]byte, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignaturesRead, err)
	}

	var rawDataList [][]byte
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".textproto") || strings.HasSuffix(name, "_test.textproto") {
			continue
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSignaturesRead, err)
		}
		rawDataList = append(rawDataList, data)
	}

	return rawDataList, nil
}

func compileSignatureData(ctx context.Context, data []byte) (*engine.CompiledFingerprint, error) {
	fp := &fpb.WebFingerprint{}
	if err := prototext.Unmarshal(data, fp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignaturesUnmarshal, err)
	}
	if fp.GetConfig().GetDisabled() {
		log.InfoContextf(ctx, "fingerprint %q is disabled, skipping", fp.GetInfo().GetName())
		return nil, nil
	}
	return engine.CompileFingerprint(fp)
}
