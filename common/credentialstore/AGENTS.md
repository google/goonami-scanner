# Package `credentialstore`

Package `credentialstore` provides a concurrency-safe store and loader for
ordered username and password wordlists used by weak-credential detectors in
Goonami. It maps usernames to deduplicated password lists while preserving
insertion and prepend order so service-specific default credentials can be
tested before generic wordlists. Stores can be populated programmatically,
loaded from any `io/fs.FS`, or initialized from embedded default `usernames.txt`
and `passwords.txt` files.

## Services

-   **`CredentialStore`**: Concurrency-safe store associating ordered usernames
    with deduplicated, ordered password slices.
-   **`New` / `NewWithDefaults` / `CredentialStore.Copy`**: Construct an empty
    store, initialize a store preloaded with embedded default wordlists, or
    deep-copy an existing store to customize per-detector credentials without
    mutating a shared baseline.
-   **`CredentialStore.AddUser` / `CredentialStore.PrependUser`**: Append a
    username to the ordered list if absent, or insert/move a username to the
    front so it is tested first.
-   **`CredentialStore.AddPassword` / `CredentialStore.AddPasswordForUser` /
    `CredentialStore.AddMultiplePasswordsForUser` /
    `CredentialStore.PrependPasswordForUser`**: Append deduplicated passwords
    across all registered users or for a specific username, or insert/move a
    password to the front of a user's list (pair user-specific password methods
    with `AddUser` or `PrependUser` so the user appears in `Usernames()`).
-   **`CredentialStore.LoadFromFS` / `CredentialStore.UsersFromFS` /
    `CredentialStore.PasswordsFromFS`**: Walk an `fs.FS` to load a single pair
    of `UsernamesFilename` (`"usernames.txt"`) and `PasswordsFilename`
    (`"passwords.txt"`) files, or load line-delimited user and password files
    individually from explicit paths.
-   **`CredentialStore.LoadDefaults` / `CredentialStore.LoadDefaultsOnce`**:
    Populate an existing store with the package's embedded default usernames and
    passwords, with `LoadDefaultsOnce` ensuring idempotent single-time loading.
-   **`CredentialStore.Usernames` / `CredentialStore.Passwords` /
    `CredentialStore.Count`**: Return defensive copies of the ordered username
    slice and a given user's password slice, or count the total number of stored
    credential pairs.

## Usage

Clone a shared default store, prepend service-specific credentials so they are
tried first, and iterate in priority order:

```go
import (
    "github.com/google/goonami-scanner/common/credentialstore"
)

shared, err := credentialstore.NewWithDefaults()
if err != nil {
    return err
}

store := shared.Copy()
if err := store.PrependUser("admin"); err != nil {
    return err
}
if err := store.PrependPasswordForUser("admin", "changeme"); err != nil {
    return err
}

for _, user := range store.Usernames() {
    for _, pass := range store.Passwords(user) {
        // Test user and pass against the target service.
    }
}
```

Load custom wordlists from an `io/fs.FS` containing `usernames.txt` and
`passwords.txt`:

```go
custom := credentialstore.New()
if err := custom.LoadFromFS(wordlistsFS); err != nil {
    return err
}
```
