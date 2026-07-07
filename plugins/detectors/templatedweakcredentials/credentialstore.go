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

package templatedweakcredentials

import (
	"bufio"
	"context"
	"os"
	"slices"
	"sync"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
)

// CredentialStore is a store of credentials (username associated with a list of passwords).
// Note that it keeps track of the order in which username are added.
type CredentialStore struct {
	mu          sync.RWMutex
	usernames   []string
	credentials map[string][]string
	loadOnce    sync.Once
	loadErr     error
}

// NewCredentialStore creates a new CredentialStore.
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		mu:          sync.RWMutex{},
		usernames:   []string{},
		credentials: make(map[string][]string),
	}
}

// Copy returns a deep copy of the credential store.
func (c *CredentialStore) Copy() *CredentialStore {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cp := NewCredentialStore()
	cp.usernames = make([]string, len(c.usernames))
	copy(cp.usernames, c.usernames)

	for user, passes := range c.credentials {
		cp.credentials[user] = make([]string, len(passes))
		copy(cp.credentials[user], passes)
	}

	return cp
}

// AddMultiplePasswordsForUser adds multiple passwords for a given username.
func (c *CredentialStore) AddMultiplePasswordsForUser(username string, passwords []string) {
	for _, password := range passwords {
		c.AddPasswordForUser(username, password)
	}
}

// AddPasswordForUser adds a password for a given username.
func (c *CredentialStore) AddPasswordForUser(username string, password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.credentials[username]; ok {
		knownPasses := c.credentials[username]
		if slices.Contains(knownPasses, password) {
			return nil
		}
	}

	c.credentials[username] = append(c.credentials[username], password)
	return nil
}

// AddPassword adds a password for all users in the store.
func (c *CredentialStore) AddPassword(password string) error {
	for username := range c.credentials {
		if err := c.AddPasswordForUser(username, password); err != nil {
			return err
		}
	}

	return nil
}

// AddUser adds a user to the store.
func (c *CredentialStore) AddUser(username string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.credentials[username]; ok {
		return nil
	}

	c.usernames = append(c.usernames, username)
	c.credentials[username] = []string{}
	return nil
}

// PrependUser adds a user at the beginning of the store's usernames list. If the user already exists, it is moved to the front.
func (c *CredentialStore) PrependUser(username string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.credentials[username]; ok {
		idx := slices.Index(c.usernames, username)
		if idx != -1 {
			c.usernames = slices.Delete(c.usernames, idx, idx+1)
		}
		c.usernames = append([]string{username}, c.usernames...)
		return nil
	}

	c.usernames = append([]string{username}, c.usernames...)
	c.credentials[username] = []string{}
	return nil
}

// PrependPasswordForUser adds a password at the beginning of the password list for a given username. If the password already exists, it is moved to the front.
func (c *CredentialStore) PrependPasswordForUser(username string, password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.credentials[username]; ok {
		knownPasses := c.credentials[username]
		if idx := slices.Index(knownPasses, password); idx != -1 {
			c.credentials[username] = slices.Delete(knownPasses, idx, idx+1)
		}
	}

	c.credentials[username] = append([]string{password}, c.credentials[username]...)
	return nil
}

// UsersFromFile reads a list of users from a file and adds them to the store. Each user should be
// on a separate line.
func (c *CredentialStore) UsersFromFile(path string) error {
	users, err := fromFile(path)
	if err != nil {
		return err
	}

	for _, user := range users {
		if err := c.AddUser(user); err != nil {
			return err
		}
	}

	return nil
}

// PasswordsFromFile reads a list of passwords from a file and adds them to the store. Each password
// should be on a separate line. Each password is added to every user in the store.
func (c *CredentialStore) PasswordsFromFile(path string) error {
	passwords, err := fromFile(path)
	if err != nil {
		return err
	}

	for _, pass := range passwords {
		if err := c.AddPassword(pass); err != nil {
			return err
		}
	}

	return nil
}

// Count the number of credentials in the store.
func (c *CredentialStore) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var count int

	for _, passwords := range c.credentials {
		count += len(passwords)
	}

	return count
}

// Usernames returns a list of all usernames in the store.
func (c *CredentialStore) Usernames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.usernames
}

// Passwords returns a list of all passwords for a given username.
func (c *CredentialStore) Passwords(username string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.credentials[username]
}

func fromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		results = append(results, line)
	}

	return results, nil
}

// LoadFromConfigOnce loads usernames and passwords from config files (only once).
func (c *CredentialStore) LoadFromConfigOnce(ctx context.Context, cfg *config.Config) error {
	c.loadOnce.Do(func() {
		c.loadErr = c.fromConfig(ctx, cfg)
	})
	return c.loadErr
}

func (c *CredentialStore) fromConfig(ctx context.Context, cfg *config.Config) error {
	if cfg.PluginsConfig().GetTemplatedweakcredentials().HasUsernameFile() {
		userFile := cfg.PluginsConfig().GetTemplatedweakcredentials().GetUsernameFile()
		log.DebugContextf(ctx, log.DebugLevelSession, "loading all usernames from %q", userFile)
		if err := c.UsersFromFile(userFile); err != nil {
			return err
		}
	}

	if cfg.PluginsConfig().GetTemplatedweakcredentials().HasPasswordsFile() {
		passFile := cfg.PluginsConfig().GetTemplatedweakcredentials().GetPasswordsFile()
		log.DebugContextf(ctx, log.DebugLevelSession, "loading passwords from %q", passFile)
		if err := c.PasswordsFromFile(passFile); err != nil {
			return err
		}
	}

	return nil
}
