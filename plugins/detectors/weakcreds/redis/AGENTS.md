# Package `redis` (`dt/wk/redis`)

Package `redis` implements a Goonami weak credentials detector plugin for Redis
and RESP-compatible database servers, migrated from Tsunami's Ncrack Redis
credential tester.

## Key Symbols

-   `ModuleName`: `"dt/wk/redis"` — unique module identifier registered with
    the Goonami scanner.
-   `New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error)`:
    Constructs a `module.VulnDetector` backed by `common/bruteforce`, seeded
    with `DefaultCredentials()`, common passwords for the `"default"` account,
    and targeted Redis 6+ ACL credentials.
-   `NewWithOptions(ctx context.Context, cfg *config.Config, opts
    *bruteforce.Options) (*bruteforce.Detector, error)`: Constructs the detector
    with custom brute-force options.
-   `DefaultCredentials() []bruteforce.Credential`: Returns the default Redis
    credentials to test first.
-   `BaseVulnerability() *vpb.Vulnerability`: Returns the base vulnerability
    metadata (`WEAK_CREDENTIALS_FOR_REDIS`, `CRITICAL`) reported when weak
    credentials are found.
-   `Handler` / `NewHandler(cfg *config.Config) *Handler`: Implements
    `bruteforce.Handler` for TCP and TLS Redis RESP services.
