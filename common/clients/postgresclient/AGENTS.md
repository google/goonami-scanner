# Package `postgresclient`

Package `postgresclient` provides a shared PostgreSQL client wrapper around
`database/sql` and `lib/pq` for Goonami plugins.

## Key Symbols

-   `DefaultDatabase`: Default PostgreSQL database name (`"postgres"`) used when
    no database is specified.
-   `Client`: Configured PostgreSQL client that opens and verifies connections
    to target endpoints.
    -   `New(cfg *config.Config) *Client`: Creates a new client using
        `ClientsConfig().GetPostgres()` settings from `cfg`.
    -   `(*Client).Timeout() time.Duration`: Returns the configured connection
        and authentication timeout (defaults to 5s).
    -   `(*Client).Connect(ctx context.Context, addr, username, password,
        database string) (*sql.DB, error)`: Opens a PostgreSQL connection to
        `addr` (`"host:port"`), verifies the session via `PingContext`, and
        returns the active `*sql.DB` handle or a classified error.
-   `ClassifyError(err error) error`: Maps `lib/pq` and network errors to
    Goonami sentinel errors:
    -   `ErrAuthFailed`: The server is a PostgreSQL instance that rejected the
        supplied credentials or role (`28P01`, `28000` role errors).
    -   `ErrPasswordAuthUnsupported`: The server does not allow password
        authentication for the connection (`0A000`, `pg_hba.conf` rejection, or
        unsupported authentication mechanisms such as Kerberos/GSS).
    -   `ErrNotPostgresService`: The target is unreachable or did not respond as
        a valid PostgreSQL server.
