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

// Package credentialstore provides a store and loader for credential wordlists.
package credentialstore

import (
	"bufio"
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"sync"
)

//go:embed data/*
var defaultDataFS embed.FS

// UsernamesFilename is the required filename for usernames.
const UsernamesFilename = "usernames.txt"

// PasswordsFilename is the required filename for passwords.
const PasswordsFilename = "passwords.txt"

// CredentialStore is a store of credentials (username associated with a list of passwords).
// Note that it keeps track of the order in which usernames are added.
type CredentialStore struct {
	mu          sync.RWMutex
	usernames   []string
	credentials map[string][]string
	loadOnce    sync.Once
	loadErr     error
}

// New creates a new CredentialStore.
func New() *CredentialStore {
	return &CredentialStore{
		usernames:   []string{},
		credentials: make(map[string][]string),
	}
}

// NewWithDefaults creates a new CredentialStore populated with default embedded credentials.
func NewWithDefaults() (*CredentialStore, error) {
	store := New()
	if err := store.LoadDefaults(); err != nil {
		return nil, err
	}

	return store, nil
}

// Copy returns a deep copy of the credential store.
func (c *CredentialStore) Copy() *CredentialStore {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cp := New()
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
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, username := range c.usernames {
		knownPasses := c.credentials[username]
		if !slices.Contains(knownPasses, password) {
			c.credentials[username] = append(c.credentials[username], password)
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

// PrependUser adds a user at the beginning of the store's usernames list. If the user already
// exists, it is moved to the front.
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

// PrependPasswordForUser adds a password at the beginning of the password list for a given
// username. If the password already exists, it is moved to the front.
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

// UsersFromFS reads a list of users from a file in the given filesystem and adds them to the store.
// Each user should be on a separate line.
func (c *CredentialStore) UsersFromFS(fsys fs.FS, path string) error {
	users, err := readLines(fsys, path)
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

// PasswordsFromFS reads a list of passwords from a file in the given filesystem and adds them to
// the store. Each password should be on a separate line. Each password is added to every user in
// the store.
func (c *CredentialStore) PasswordsFromFS(fsys fs.FS, path string) error {
	passwords, err := readLines(fsys, path)
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

// LoadFromFS walks the provided filesystem and loads the required usernames.txt and passwords.txt files.
// It verifies that exactly one usernames.txt and one passwords.txt exist in the filesystem, returning
// an error if either is missing or if duplicates are found.
func (c *CredentialStore) LoadFromFS(fsys fs.FS) error {
	var userPath, passPath string

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		switch d.Name() {
		case UsernamesFilename:
			if userPath != "" {
				return fmt.Errorf("multiple %s files found: %q and %q", UsernamesFilename, userPath, path)
			}
			userPath = path
		case PasswordsFilename:
			if passPath != "" {
				return fmt.Errorf("multiple %s files found: %q and %q", PasswordsFilename, passPath, path)
			}
			passPath = path
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk credentials filesystem: %w", err)
	}

	if userPath == "" {
		return fmt.Errorf("missing required credential file: %s", UsernamesFilename)
	}
	if passPath == "" {
		return fmt.Errorf("missing required credential file: %s", PasswordsFilename)
	}

	if err := c.UsersFromFS(fsys, userPath); err != nil {
		return fmt.Errorf("failed to load users from %s: %w", userPath, err)
	}

	if err := c.PasswordsFromFS(fsys, passPath); err != nil {
		return fmt.Errorf("failed to load passwords from %s: %w", passPath, err)
	}

	return nil
}

// LoadDefaults loads the default embedded credentials into the store.
func (c *CredentialStore) LoadDefaults() error {
	return c.LoadFromFS(defaultDataFS)
}

// LoadDefaultsOnce loads the default embedded credentials into the store (only once).
func (c *CredentialStore) LoadDefaultsOnce() error {
	c.loadOnce.Do(func() {
		c.loadErr = c.LoadDefaults()
	})
	return c.loadErr
}

// Count returns the total number of credentials across all users in the store.
func (c *CredentialStore) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var count int
	for _, passwords := range c.credentials {
		count += len(passwords)
	}
	return count
}

// Usernames returns a list of all usernames in the store in insertion order.
func (c *CredentialStore) Usernames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]string, len(c.usernames))
	copy(result, c.usernames)
	return result
}

// Passwords returns a list of all passwords for a given username.
func (c *CredentialStore) Passwords(username string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	passes, ok := c.credentials[username]
	if !ok {
		return nil
	}
	result := make([]string, len(passes))
	copy(result, passes)
	return result
}

func readLines(fsys fs.FS, path string) ([]string, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		results = append(results, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}
