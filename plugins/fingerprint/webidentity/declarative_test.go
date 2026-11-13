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
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/testrunner"
	"google.golang.org/protobuf/encoding/prototext"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	ftpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_test_go_proto"
)

func TestDeclarativeFingerprints(t *testing.T) {
	log.SetLogger(&log.DefaultLogger{VerboseLevel: log.DebugLevelRequest})

	entries, err := embeddedFingerprintsFS.ReadDir("fingerprints")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			t.Skip("no embedded fingerprints catalog available")
		}
		t.Fatalf("embeddedFingerprintsFS.ReadDir(\"fingerprints\") returned unexpected error: %v", err)
	}

	foundSuites := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.textproto") {
			continue
		}

		foundSuites++
		testName := strings.TrimSuffix(entry.Name(), "_test.textproto")
		fpFileName := "fingerprints/" + testName + ".textproto"
		testSuiteFileName := "fingerprints/" + entry.Name()

		fpData, err := embeddedFingerprintsFS.ReadFile(fpFileName)
		if err != nil {
			t.Fatalf("missing companion fingerprint %q for test %q: %v", fpFileName, entry.Name(), err)
		}
		fp := &fpb.WebFingerprint{}
		if err := prototext.Unmarshal(fpData, fp); err != nil {
			t.Fatalf("prototext.Unmarshal(%q) returned unexpected error: %v", fpFileName, err)
		}

		suiteData, err := embeddedFingerprintsFS.ReadFile(testSuiteFileName)
		if err != nil {
			t.Fatalf("embeddedFingerprintsFS.ReadFile(%q) returned unexpected error: %v", testSuiteFileName, err)
		}
		suite := &ftpb.WebFingerprintTests{}
		if err := prototext.Unmarshal(suiteData, suite); err != nil {
			t.Fatalf("prototext.Unmarshal(%q) returned unexpected error: %v", testSuiteFileName, err)
		}

		t.Run(testName, func(t *testing.T) {
			testrunner.RunSuite(t, fp, suite)
		})
	}

	if foundSuites == 0 {
		t.Skip("no declarative test suites found in embedded fingerprints")
	}
}
