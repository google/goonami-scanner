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

package credentialstore

import (
	"slices"
	"testing"
	"testing/fstest"
)

func TestCredentialStore_New(t *testing.T) {
	store := New()
	if store == nil {
		t.Fatal("New() returned nil")
	}
	if store.Count() != 0 {
		t.Errorf("expected count 0, got %d", store.Count())
	}
	if len(store.Usernames()) != 0 {
		t.Errorf("expected 0 users, got %d", len(store.Usernames()))
	}
}

func TestCredentialStore_NewWithDefaults(t *testing.T) {
	store, err := NewWithDefaults()
	if err != nil {
		t.Fatalf("NewWithDefaults() failed: %v", err)
	}
	if store == nil {
		t.Fatal("NewWithDefaults() returned nil store")
	}
	if len(store.Usernames()) == 0 {
		t.Errorf("expected default usernames, got 0")
	}
	if store.Count() == 0 {
		t.Errorf("expected default credentials, got 0")
	}
	if !slices.Contains(store.Usernames(), "root") {
		t.Errorf("expected 'root' in default usernames, got %v", store.Usernames())
	}
	if !slices.Contains(store.Usernames(), "admin") {
		t.Errorf("expected 'admin' in default usernames, got %v", store.Usernames())
	}
	rootPasses := store.Passwords("root")
	if !slices.Contains(rootPasses, "password") {
		t.Errorf("expected 'password' in root passwords, got %v", rootPasses)
	}
}

func TestCredentialStore_Copy(t *testing.T) {
	store := New()
	store.AddUser("user1")
	store.AddPasswordForUser("user1", "pass1")
	store.AddUser("user2")
	store.AddPasswordForUser("user2", "pass2")

	cp := store.Copy()

	if len(cp.Usernames()) != 2 {
		t.Errorf("expected 2 users, got %d", len(cp.Usernames()))
	}
	if cp.Count() != 2 {
		t.Errorf("expected 2 passwords, got %d", cp.Count())
	}

	// modify copy
	cp.AddUser("user3")
	cp.AddPasswordForUser("user1", "pass3")

	if len(store.Usernames()) != 2 {
		t.Errorf("expected original users unchanged, got %d", len(store.Usernames()))
	}
	if len(store.Passwords("user1")) != 1 {
		t.Errorf("expected original passwords unchanged, got %d", len(store.Passwords("user1")))
	}
}

func TestCredentialStore_AddUser(t *testing.T) {
	tests := []struct {
		name         string
		initialUsers []string
		userToAdd    string
		wantUsers    int
		wantErr      bool
	}{
		{
			name:      "when_adding_new_user_adds_user",
			userToAdd: "user1",
			wantUsers: 1,
			wantErr:   false,
		},
		{
			name:         "when_adding_existing_user_does_not_error",
			initialUsers: []string{"user1"},
			userToAdd:    "user1",
			wantUsers:    1,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			for _, u := range tt.initialUsers {
				store.AddUser(u)
			}
			err := store.AddUser(tt.userToAdd)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AddUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(store.Usernames()) != tt.wantUsers {
				t.Errorf("expected %d user, got %d", tt.wantUsers, len(store.Usernames()))
			}
			if !tt.wantErr && !slices.Contains(store.Usernames(), tt.userToAdd) {
				t.Errorf("expected %s in credentials", tt.userToAdd)
			}
		})
	}
}

func TestCredentialStore_PrependUser(t *testing.T) {
	tests := []struct {
		name         string
		initialUsers []string
		userToAdd    string
		wantUsers    []string
		wantErr      bool
	}{
		{
			name:         "when_prepending_new_user_adds_to_front",
			initialUsers: []string{"user1", "user2"},
			userToAdd:    "user3",
			wantUsers:    []string{"user3", "user1", "user2"},
			wantErr:      false,
		},
		{
			name:         "when_prepending_existing_user_moves_to_front",
			initialUsers: []string{"user1", "user2", "user3"},
			userToAdd:    "user2",
			wantUsers:    []string{"user2", "user1", "user3"},
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			for _, u := range tt.initialUsers {
				store.AddUser(u)
			}
			err := store.PrependUser(tt.userToAdd)
			if (err != nil) != tt.wantErr {
				t.Fatalf("PrependUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			users := store.Usernames()
			if len(users) != len(tt.wantUsers) {
				t.Errorf("expected %d user, got %d", len(tt.wantUsers), len(users))
			}
			for i, u := range users {
				if u != tt.wantUsers[i] {
					t.Errorf("expected users[%d] to be %q, got %q", i, tt.wantUsers[i], u)
				}
			}
		})
	}
}

func TestCredentialStore_AddPasswordForUser(t *testing.T) {
	tests := []struct {
		name             string
		initialPasswords map[string][]string
		userToAdd        string
		passToAdd        string
		wantPasswords    int
		wantErr          bool
	}{
		{
			name:          "when_adding_password_for_new_user_adds_password",
			userToAdd:     "user1",
			passToAdd:     "pass1",
			wantPasswords: 1,
			wantErr:       false,
		},
		{
			name:             "when_adding_duplicate_password_for_user_does_not_add_again",
			initialPasswords: map[string][]string{"user1": {"pass1"}},
			userToAdd:        "user1",
			passToAdd:        "pass1",
			wantPasswords:    1,
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			for u, passes := range tt.initialPasswords {
				for _, p := range passes {
					store.AddPasswordForUser(u, p)
				}
			}
			err := store.AddPasswordForUser(tt.userToAdd, tt.passToAdd)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AddPasswordForUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			creds := store.Passwords(tt.userToAdd)
			if len(creds) != tt.wantPasswords {
				t.Errorf("expected %s to have %d passwords, got %v", tt.userToAdd, tt.wantPasswords, creds)
			}
			if !tt.wantErr && !slices.Contains(creds, tt.passToAdd) {
				t.Errorf("expected %s to have %s", tt.userToAdd, tt.passToAdd)
			}
		})
	}
}

func TestCredentialStore_PrependPasswordForUser(t *testing.T) {
	tests := []struct {
		name             string
		initialPasswords map[string][]string
		userToAdd        string
		passToAdd        string
		wantPasswords    []string
		wantErr          bool
	}{
		{
			name:             "when_prepending_new_password_adds_to_front",
			initialPasswords: map[string][]string{"user1": {"pass1", "pass2"}},
			userToAdd:        "user1",
			passToAdd:        "pass3",
			wantPasswords:    []string{"pass3", "pass1", "pass2"},
			wantErr:          false,
		},
		{
			name:             "when_prepending_existing_password_moves_to_front",
			initialPasswords: map[string][]string{"user1": {"pass1", "pass2", "pass3"}},
			userToAdd:        "user1",
			passToAdd:        "pass2",
			wantPasswords:    []string{"pass2", "pass1", "pass3"},
			wantErr:          false,
		},
		{
			name:             "when_prepending_password_for_new_user_adds_user_and_password",
			initialPasswords: map[string][]string{},
			userToAdd:        "user1",
			passToAdd:        "pass1",
			wantPasswords:    []string{"pass1"},
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			for u, passes := range tt.initialPasswords {
				for _, p := range passes {
					store.AddPasswordForUser(u, p)
				}
			}
			err := store.PrependPasswordForUser(tt.userToAdd, tt.passToAdd)
			if (err != nil) != tt.wantErr {
				t.Fatalf("PrependPasswordForUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			creds := store.Passwords(tt.userToAdd)
			if len(creds) != len(tt.wantPasswords) {
				t.Errorf("expected %s to have %d passwords, got %v", tt.userToAdd, len(tt.wantPasswords), creds)
			}
			for i, p := range creds {
				if p != tt.wantPasswords[i] {
					t.Errorf("expected passwords[%d] to be %q, got %q", i, tt.wantPasswords[i], p)
				}
			}
		})
	}
}

func TestCredentialStore_AddMultiplePasswordsForUser(t *testing.T) {
	tests := []struct {
		name          string
		user          string
		passwords     []string
		wantPasswords []string
	}{
		{
			name:          "when_adding_multiple_passwords_adds_all",
			user:          "user1",
			passwords:     []string{"pass1", "pass2"},
			wantPasswords: []string{"pass1", "pass2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			store.AddMultiplePasswordsForUser(tt.user, tt.passwords)

			creds := store.Passwords(tt.user)
			if len(creds) != len(tt.wantPasswords) {
				t.Errorf("expected %d passwords, got %d", len(tt.wantPasswords), len(creds))
			}
			for _, p := range tt.wantPasswords {
				if !slices.Contains(creds, p) {
					t.Errorf("missing password, expected: %s, got: %v", p, creds)
				}
			}
		})
	}
}

func TestCredentialStore_AddPassword(t *testing.T) {
	tests := []struct {
		name         string
		initialUsers []string
		passToAdd    string
		wantErr      bool
	}{
		{
			name:         "when_adding_password_adds_to_all_users",
			initialUsers: []string{"user1", "user2"},
			passToAdd:    "pass1",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			for _, u := range tt.initialUsers {
				store.AddUser(u)
			}

			err := store.AddPassword(tt.passToAdd)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AddPassword() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				for _, u := range tt.initialUsers {
					if !slices.Contains(store.Passwords(u), tt.passToAdd) {
						t.Errorf("expected %s to have %s", u, tt.passToAdd)
					}
				}
			}
		})
	}
}

func TestCredentialStore_Count(t *testing.T) {
	tests := []struct {
		name             string
		initialPasswords map[string][]string
		wantCount        int
	}{
		{
			name: "when_calculating_count_returns_total_passwords",
			initialPasswords: map[string][]string{
				"user1": {"pass1", "pass2"},
				"user2": {"pass3"},
			},
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			for u, passes := range tt.initialPasswords {
				for _, p := range passes {
					store.AddPasswordForUser(u, p)
				}
			}

			if store.Count() != tt.wantCount {
				t.Errorf("expected count %d, got %d", tt.wantCount, store.Count())
			}
		})
	}
}

func TestCredentialStore_UsersFromFS(t *testing.T) {
	mockFS := fstest.MapFS{
		"users.txt":       &fstest.MapFile{Data: []byte("testuser1\ntestuser2\n")},
		"empty/users.txt": &fstest.MapFile{Data: []byte("")},
	}

	tests := []struct {
		name      string
		path      string
		wantUsers []string
		wantErr   bool
	}{
		{
			name:      "when_reading_valid_users_file_adds_users",
			path:      "users.txt",
			wantUsers: []string{"testuser1", "testuser2"},
			wantErr:   false,
		},
		{
			name:      "when_reading_empty_users_file_adds_no_users",
			path:      "empty/users.txt",
			wantUsers: []string{},
			wantErr:   false,
		},
		{
			name:    "when_reading_nonexistent_file_returns_error",
			path:    "nonexistent.txt",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()

			err := store.UsersFromFS(mockFS, tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UsersFromFS() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				usernames := store.Usernames()
				if len(usernames) != len(tt.wantUsers) {
					t.Errorf("expected %d users, got %d", len(tt.wantUsers), len(usernames))
				}
				for _, u := range tt.wantUsers {
					if !slices.Contains(usernames, u) {
						t.Errorf("expected %s in credentials", u)
					}
				}
			}
		})
	}
}

func TestCredentialStore_PasswordsFromFS(t *testing.T) {
	mockFS := fstest.MapFS{
		"passwords.txt": &fstest.MapFile{Data: []byte("testpassword1\ntestpassword2\n")},
	}

	tests := []struct {
		name          string
		initialUsers  []string
		path          string
		wantPasswords []string
		wantErr       bool
	}{
		{
			name:          "when_reading_valid_passwords_file_adds_passwords_to_all_users",
			initialUsers:  []string{"user1"},
			path:          "passwords.txt",
			wantPasswords: []string{"testpassword1", "testpassword2"},
			wantErr:       false,
		},
		{
			name:         "when_reading_nonexistent_file_returns_error",
			initialUsers: []string{"user1"},
			path:         "nonexistent.txt",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			for _, u := range tt.initialUsers {
				store.AddUser(u)
			}

			err := store.PasswordsFromFS(mockFS, tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("PasswordsFromFS() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				for _, u := range tt.initialUsers {
					creds := store.Passwords(u)
					if len(creds) != len(tt.wantPasswords) {
						t.Errorf("expected %d passwords, got %d", len(tt.wantPasswords), len(creds))
					}
					for _, p := range tt.wantPasswords {
						if !slices.Contains(creds, p) {
							t.Errorf("expected %s", p)
						}
					}
				}
			}
		})
	}
}

func TestCredentialStore_LoadFromFS(t *testing.T) {
	tests := []struct {
		name          string
		fsys          fstest.MapFS
		wantUsers     []string
		wantPasswords []string
		wantCount     int
		wantErr       bool
	}{
		{
			name: "when_valid_usernames_and_passwords_present_loads_successfully",
			fsys: fstest.MapFS{
				"data/usernames.txt": &fstest.MapFile{Data: []byte("admin\nroot\n")},
				"data/passwords.txt": &fstest.MapFile{Data: []byte("pass1\npass2\n")},
			},
			wantUsers:     []string{"admin", "root"},
			wantPasswords: []string{"pass1", "pass2"},
			wantCount:     4,
			wantErr:       false,
		},
		{
			name: "when_usernames_missing_returns_error",
			fsys: fstest.MapFS{
				"data/passwords.txt": &fstest.MapFile{Data: []byte("pass1\npass2\n")},
			},
			wantErr: true,
		},
		{
			name: "when_passwords_missing_returns_error",
			fsys: fstest.MapFS{
				"data/usernames.txt": &fstest.MapFile{Data: []byte("admin\nroot\n")},
			},
			wantErr: true,
		},
		{
			name: "when_multiple_usernames_files_present_returns_error",
			fsys: fstest.MapFS{
				"dir1/usernames.txt": &fstest.MapFile{Data: []byte("admin\n")},
				"dir2/usernames.txt": &fstest.MapFile{Data: []byte("root\n")},
				"data/passwords.txt": &fstest.MapFile{Data: []byte("pass1\n")},
			},
			wantErr: true,
		},
		{
			name: "when_multiple_passwords_files_present_returns_error",
			fsys: fstest.MapFS{
				"data/usernames.txt": &fstest.MapFile{Data: []byte("admin\n")},
				"dir1/passwords.txt": &fstest.MapFile{Data: []byte("pass1\n")},
				"dir2/passwords.txt": &fstest.MapFile{Data: []byte("pass2\n")},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			err := store.LoadFromFS(tt.fsys)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadFromFS() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if len(store.Usernames()) != len(tt.wantUsers) {
					t.Errorf("expected %d users, got %d: %v", len(tt.wantUsers), len(store.Usernames()), store.Usernames())
				}
				for _, u := range tt.wantUsers {
					if !slices.Contains(store.Usernames(), u) {
						t.Errorf("expected user %s in store", u)
					}
					passes := store.Passwords(u)
					if len(passes) != len(tt.wantPasswords) {
						t.Errorf("expected %d passwords for %s, got %d: %v", len(tt.wantPasswords), u, len(passes), passes)
					}
					for _, p := range tt.wantPasswords {
						if !slices.Contains(passes, p) {
							t.Errorf("expected password %s for %s", p, u)
						}
					}
				}
				if store.Count() != tt.wantCount {
					t.Errorf("expected %d credentials, got %d", tt.wantCount, store.Count())
				}
			}
		})
	}
}

func TestCredentialStore_LoadDefaults(t *testing.T) {
	store := New()
	if err := store.LoadDefaults(); err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}
	if store.Count() == 0 {
		t.Errorf("expected non-zero count after LoadDefaults(), got 0")
	}
}

func TestCredentialStore_LoadDefaultsOnce(t *testing.T) {
	store := New()
	if err := store.LoadDefaultsOnce(); err != nil {
		t.Fatalf("LoadDefaultsOnce() error = %v", err)
	}
	count1 := store.Count()
	if count1 == 0 {
		t.Errorf("expected non-zero count, got 0")
	}

	// Calling second time should be a no-op and not duplicate entries
	if err := store.LoadDefaultsOnce(); err != nil {
		t.Fatalf("Second LoadDefaultsOnce() error = %v", err)
	}
	if store.Count() != count1 {
		t.Errorf("expected count to remain %d, got %d", count1, store.Count())
	}
}
