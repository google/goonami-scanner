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

	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/log"
)

// Options are the parameters that control the behavior of a brute-force Detector.
type Options struct {
	// CredentialStore is the base credential store to use (a copy is made).
	// When nil, the default credential store is loaded.
	CredentialStore *credentialstore.CredentialStore

	// DefaultCredentials are service-specific default credentials to be prepended
	// to the credential store so they are tested before generic credentials.
	DefaultCredentials []Credential

	// PasswordOnly configures the detector for password-only authentication,
	// where credentials have an empty username.
	PasswordOnly bool
}

func (o *Options) prepareCredentialStore(ctx context.Context) (*credentialstore.CredentialStore, error) {
	var store *credentialstore.CredentialStore
	if o.CredentialStore != nil {
		store = o.CredentialStore.Copy()
	} else {
		var err error
		store, err = credentialstore.NewWithDefaults()
		if err != nil {
			return nil, err
		}
	}

	if o.PasswordOnly {
		store.CollapseToPasswordOnly()
	}

	o.prependDefaultCredentials(ctx, store)
	return store, nil
}

func (o *Options) prependDefaultCredentials(ctx context.Context, store *credentialstore.CredentialStore) {
	if len(o.DefaultCredentials) == 0 {
		return
	}

	log.DebugContextf(ctx, log.DebugLevelSession, "loading default credentials into credential store")
	for i := len(o.DefaultCredentials) - 1; i >= 0; i-- {
		cred := o.DefaultCredentials[i]
		user := cred.Username
		if o.PasswordOnly {
			user = ""
		}
		if err := store.PrependUser(user); err != nil {
			log.WarnContextf(ctx, "failed to prepend user: %v", err)
		}
		if err := store.PrependPasswordForUser(user, cred.Password); err != nil {
			log.WarnContextf(ctx, "failed to prepend password: %v", err)
		}
	}
}
