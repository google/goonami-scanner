# Package `storage`

Package `storage` defines the backend storage abstraction and default in-memory
store for Goonami's out-of-band callback server. HTTP and DNS recording handlers
register observed callback identifiers (`cbid`) against an `InteractionStore`,
while HTTP polling handlers query recorded interactions to confirm vulnerability
callbacks. Its built-in `InMemoryInteractionStore` provides concurrency-safe
storage with per-type timestamp refreshing and background TTL-based expiration.

## Services

-   **`InteractionStore`**: Backend interface for recording and querying
    callback interactions keyed by callback identifier (`cbid`). Implementations
    provide `Register(cbid, interactionType)` to record an interaction,
    `Get(cbid)` to retrieve recorded interactions, and `Delete(cbid)` to remove
    entries for a `cbid`.
-   **`Interaction` and `InteractionType` (`UnknownInteraction`,
    `HTTPInteraction`, `DNSInteraction`)**: `Interaction` pairs a recorded
    `Type` (`InteractionType`) with its `RecordTime` (`time.Time`).
    `InteractionType` distinguishes `HTTPInteraction` and `DNSInteraction`
    callbacks from the invalid zero value `UnknownInteraction`.
-   **`InMemoryInteractionStore` and `NewInMemoryInteractionStore`**:
    `NewInMemoryInteractionStore(ctx, ttl, cleanupInterval)` initializes a
    concurrency-safe (`sync.RWMutex`) in-memory `InteractionStore` and starts a
    background cleanup loop ticking every `cleanupInterval` until `ctx` is
    canceled. Interactions whose `RecordTime` age exceeds `ttl` are evicted on
    each cleanup pass.
-   **`InMemoryInteractionStore.Register` / `Get` / `Delete`**:
    `Register(cbid, interactionType)` records the interaction at the current
    time, refreshing `RecordTime` in place if an entry of the same
    `InteractionType` already exists for `cbid`. `Get(cbid)` returns a copy of
    the recorded interactions slice for `cbid`, and `Delete(cbid)` removes all
    interactions associated with `cbid`.
-   **`ErrUnknownInteractionType`**: Sentinel error returned by
    `InMemoryInteractionStore.Register` when `UnknownInteraction` is provided.

## Usage

```go
package example

import (
    "context"
    "time"

    "github.com/google/goonami-scanner/tools/callbackserver/storage"
)

func trackInteraction(ctx context.Context, cbid string) (bool, error) {
    store := storage.NewInMemoryInteractionStore(
        ctx,
        60*time.Second,
        10*time.Second,
    )

    if err := store.Register(cbid, storage.HTTPInteraction); err != nil {
        return false, err
    }

    var hasHTTP bool
    for _, interaction := range store.Get(cbid) {
        if interaction.Type == storage.HTTPInteraction {
            hasHTTP = true
        }
    }

    store.Delete(cbid)
    return hasHTTP, nil
}
```
