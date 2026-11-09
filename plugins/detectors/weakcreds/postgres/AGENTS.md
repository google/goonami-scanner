# Package `postgres` (`dt/wk/postgres`)

Package `postgres` implements a Goonami weak credentials detector plugin for
PostgreSQL database servers, migrated from Tsunami's `PostgresCredentialTester`.

## Key Symbols

-   `ModuleName`: `"dt/wk/postgres"` — unique module identifier registered with
    the Goonami scanner.
-   `New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error)`:
    Constructs a `module.VulnDetector` backed by `common/bruteforce`, seeded
    with `DefaultCredentials()`.
-   `NewWithOptions(ctx context.Context, cfg *config.Config, opts
    *bruteforce.Options) (*bruteforce.Detector, error)`: Constructs the detector
    with custom brute-force options.
-   `DefaultCredentials() []bruteforce.Credential`: Returns the default
    PostgreSQL credentials to test (`postgres:<empty>` and `postgres:postgres`).
-   `BaseVulnerability() *vpb.Vulnerability`: Returns the base vulnerability
    metadata (`POSTGRES_WEAK_CREDENTIALS`, `CRITICAL`) reported when weak
    credentials are found.
-   `Handler` / `NewHandler(cfg *config.Config) *Handler`: Implements
    `bruteforce.Handler` and `bruteforce.Worker` for TCP PostgreSQL services
    using `common/clients/postgresclient`.
