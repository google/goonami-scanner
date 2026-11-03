# Package `http`

Package `http` provides standard `net/http` handlers for Goonami's callback
server to record incoming out-of-band HTTP callbacks and serve client polling
queries. It connects HTTP endpoints to a `storage.InteractionStore` backend,
recording HTTP hits by callback identifier (CBID) and returning JSON-encoded
`PollingResult` payloads for recorded DNS and HTTP interactions.
`callbackserver.Server` mounts these handlers on separate listeners for the
local HTTP recording and polling endpoints.

## Services

-   **`RecordingHandler`**: Implements `http.Handler`
    (`ServeHTTP(w http.ResponseWriter, r *http.Request)`) backed by `Store`
    (`storage.InteractionStore`) to record incoming HTTP callbacks. It extracts
    the CBID from the request URL via `netutils.IdentifierFromURL` and registers
    a `storage.HTTPInteraction`, responding with `200 OK` (`{"status":"OK"}`) or
    `500 Internal Server Error` if extraction or registration fails.
-   **`PollingHandler`**: Implements `http.Handler`
    (`ServeHTTP(w http.ResponseWriter, r *http.Request)`) backed by `Store`
    (`storage.InteractionStore`) to derive a CBID from the `secret` query
    parameter via `cbid.Generate` and return a `protojson`-marshaled
    `PollingResult` indicating recorded DNS and HTTP interactions. Requests
    omitting `secret` return `200 OK` (`{}`) for health checks, empty `secret`
    values return `400 Bad Request`, unrecorded secrets return `404 Not Found`,
    and CBID or JSON errors return `500 Internal Server Error`.

## Usage

```go
import (
  "context"
  "net/http"
  "time"

  tcshttp "github.com/google/goonami-scanner/tools/callbackserver/server/http"
  "github.com/google/goonami-scanner/tools/callbackserver/storage"
)

store := storage.NewInMemoryInteractionStore(ctx, time.Hour, time.Minute)

// Mount the HTTP callback recording handler.
recordMux := http.NewServeMux()
recordMux.Handle("/", &tcshttp.RecordingHandler{Store: store})

// Mount the interaction polling handler ("/?secret=..." and "/" health).
pollMux := http.NewServeMux()
pollMux.Handle("/", &tcshttp.PollingHandler{Store: store})
```
