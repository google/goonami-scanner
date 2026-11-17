# Goonami Plugin Development Guidelines

These instructions apply to all Goonami plugins under `plugins/`
(`plugins/detectors/`, `plugins/fingerprint/`, and `plugins/portscan/`),
alongside any repository-wide rules in the root `AGENTS.md` when present.

## 1. Understand Goonami's Pipeline Before Filtering Services

Goonami's default scan workflow (`ps/nmap` -> `fp/sslsupport` ->
`fp/iswebservice` -> `fp/webidentity` -> `dt/*`) differs fundamentally from
scanners that rely on Nmap `-sV` banner scripts:

-   **Port discovery does not run version/banner scripts by default**: `ps/nmap`
    performs port discovery with `enable_version_detection`,
    `enable_http_methods_detection`, and `enable_ssl_detection` disabled by
    default. Consequently, `service.GetServiceName()` is typically `"unknown"`,
    empty, or an unverified `/etc/services` port-table guess.
-   **Goonami's fingerprinters enrich every open port before detectors run**:
    -   `fp/sslsupport` probes TLS on every open port and populates
        `service.SupportedSslVersions` (`netservice.HasTLS(service)`).
    -   `fp/iswebservice` sends an HTTP `GET` to every open port and populates
        `service.SupportedHttpMethods` (`netservice.IsWebService(service)`).
    -   `fp/webidentity` crawls web services via `common/clients/httpcrawler`,
        stores `CONTENT_TYPE_HASH` `CrawlResults` (crawled URLs, status codes,
        and content hashes—not raw bodies or headers) in `WebServiceContext`
        (`netservice.WasCrawled` / `netservice.GetCrawlContent`), and populates
        `ApplicationRoot`, `Software`, and `VersionSet` entries.

Plugins must rely on these fingerprinted `NetworkService` properties and the
core engine's shared utilities rather than port numbers, service-name strings,
or custom networking boilerplate.

## 2. Prefer Declarative & Shared Frameworks Before Custom Go Code

Before creating a standalone Go detector package, check whether existing plugin
engines cover the vulnerability class:

1.  **Templated Detectors (`dt/tpl/*`)**: If detection can be expressed via
    HTTP(S) requests, callback-server checks, status/header/body assertions, and
    variable extraction, author a `.textproto` definition and companion
    `*_test.textproto` suite under `plugins/detectors/templated/detections/`
    (powered by
    [common/templatedengine](/common/templatedengine/AGENTS.md))
    instead of custom Go code.
2.  **Weak or Default Credentials (`dt/wktpl/*` & `dt/wk/*`)**:
    -   For web/HTTP credential checks, add a templated plugin under
        `plugins/detectors/templatedweakcredentials/detections/` or extend
        [common/credentialstore](/common/credentialstore/AGENTS.md).
    -   For non-HTTP network protocols, implement `bruteforce.Handler` on top of
        `common/bruteforce` and a shared protocol client in `common/clients/`
        (such as `sshclient`, `postgresclient`, or `mysqlclient`) so
        concurrency, QPS limits, per-service attempt budgets
        (`metrics.BudgetExhausted`), and credential lists stay consistent across
        plugins.
3.  **Custom Go Plugins**: Write custom Go code under
    `plugins/detectors/<name>/` only when stateful multi-step handshakes, binary
    framing, or protocol semantics cannot be expressed declaratively. When
    multiple plugins speak the same non-HTTP protocol, place the reusable
    protocol client and sentinel error classification under
    `common/clients/<protocol>client/` instead of duplicating wire code inside
    individual detectors.

## 3. Port-Agnostic, Service-Driven Triggering

**Never gate detection on hardcoded default port numbers or `service_name`
strings.** Real-world services routinely listen on custom, high, or
reverse-proxied ports. Detectors that check `port == 8080` or
`service.GetServiceName() == "http-alt"` pass synthetic lab tests while missing
vulnerable deployments in the wild—and falsely probe unrelated services that
happen to occupy another product's default port.

Follow these triggering patterns instead:

-   **Web / HTTP(S) Detectors**:
    -   Gate exclusively with `netservice.IsWebService(service)`. Do **not**
        maintain custom `knownWebServiceNames` maps (`"http"`, `"https"`,
        `"ssl/http"`, etc.) or inspect `strings.HasPrefix(name, "ssl/")`.
    -   Construct base URLs via `netservice.BuildWebRoot(service)` or
        `netservice.BuildAllWebRoots(service)`, which automatically select
        `http://` vs. `https://` via `netservice.HasTLS(service)` and prioritize
        hostnames so virtual-host routing succeeds.
    -   Inspect existing crawl data in `WebServiceContext`
        (`netservice.WasCrawled` or
        `service.GetServiceContext().GetWebServiceContext().GetCrawlResults()`
        for discovered URLs and status codes, checking
        `CrawlContentType == CONTENT_TYPE_RAW` when reading
        `netservice.GetCrawlContent`) before issuing redundant discovery
        requests.
-   **Non-HTTP TCP / Binary-Protocol Detectors**:
    -   Skip web services when probing a non-HTTP protocol
        (`if netservice.IsWebService(service) { return nil, nil }`) and verify
        transport compatibility (`TCP` or `TRANSPORT_PROTOCOL_UNSPECIFIED`).
    -   Resolve the dial address strictly via
        `netendpoint.ToURIAuthority(service.GetNetworkEndpoint())` and check TLS
        via `netservice.HasTLS(service)`. Never synthesize fallback ports
        (`"80"`, `"443"`, or a product's default port) with `net.JoinHostPort`
        when `!endpoint.HasPort()`.
    -   Identify the target service on **any** port using a lightweight,
        bounded, non-destructive protocol handshake or banner check, returning
        `(nil, nil)` immediately if the peer does not speak the expected
        protocol.
-   **Multi-Surface Services (Exposing Both an HTTP API/UI and a Binary/RPC
    Port)**:
    -   Route `netservice.IsWebService(service)` endpoints through the HTTP
        probe path and `!netservice.IsWebService(service)` TCP endpoints through
        the bounded binary/RPC handshake path on any port—never branch on
        `port == defaultUIPort` vs. `port == defaultRPCPort`.

## 4. Reuse Core & Common Utilities (Do Not Reinvent Shared Helpers)

Re-implementing endpoint formatting, TLS detection, HTTP clients, timeouts, or
test mocks causes behavior divergence across plugins and introduces subtle bugs
(broken IPv6 bracketing, missed virtual hosts, bypassed rate limiters or proxy
transports, ignored CLI overrides, and unbounded memory reads). Always use
Goonami's built-in packages:

Capability                       | Canonical Package & Helpers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Anti-Patterns to Avoid
:------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------
Web & TLS service traits         | [core/net/netservice](/core/net/netservice/AGENTS.md): `IsWebService`, `HasTLS`, `BuildWebRoot`, `BuildAllWebRoots`, `GetCrawlContent`, `WasCrawled`, `AddCrawlResults`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Checking `service.GetServiceName()`, `"ssl/"` prefixes, port `443`/`8443`, or hand-building `"http://" + host`
Endpoint & authority formatting  | [core/net/netendpoint](/core/net/netendpoint/AGENTS.md), [core/net/iputils](/core/net/iputils/AGENTS.md): `ToURIAuthority`, `ToURIAuthorities`, `ToHost`, `SplitHost`, `WithPort`, `ErrEndpointMissingAddress`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Manual `net.JoinHostPort`, manual `[ipv6]` string manipulation, or injecting default port numbers
HTTP requests & bounded reads    | [core/net/http](/core/net/http/AGENTS.md): `SharedClient(cfg)`, `NewClient(cfg, opts)`, `DefaultClientOptions()`, `opts.LoadAuthorities(service)`, `ReadBody(resp, maxsize)`, `ErrPageTooBig`, `ErrRateLimited`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Constructing `&http.Client{}` directly (bypasses timeouts, QPS limits, `User-Agent`, metrics, forbidden-path filters, and registered HTTP backends) or calling unbounded `io.ReadAll`
Timeouts, cache & runtime config | [core/config](/core/config/AGENTS.md): `cfg.TimeoutPerRequest()`, `cfg.ClientsConfig()`, `cfg.PluginsConfig()`, `cfg.GetCacheForModule(name)`, `cfg.ArtifactsForModule(name)`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Hardcoding timeouts instead of honoring `cfg.TimeoutPerRequest()` and `-o` overrides
Context-aware logging            | [core/log](/core/log/AGENTS.md): `ContextForModuleAndService`, `DebugContextf` (`DebugLevelSession`, `DebugLevelService`, `DebugLevelRequest`), `InfoContextf`, `WarnContextf`, `ErrorContextf`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Calling standard library `log.Printf` / `fmt.Printf` or omitting `log.ContextForModuleAndService`
Module lifecycle & registry      | [core/module](/core/module/AGENTS.md): `BaseModule`, `NewBaseModule`, `RegisterDetector`, `RegisterFingerprinter`, `RegisterPortScanner`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Custom `Name()` boilerplate instead of embedding `*module.BaseModule`
Out-of-band callbacks (TCS)      | [common/clients/callbackserver](/common/clients/callbackserver/AGENTS.md), [common/callbackserver/cbid](/common/callbackserver/cbid/AGENTS.md), [common/callbackserver/netutils](/common/callbackserver/netutils/AGENTS.md): `DefaultClient()`, `IsCallbackServerEnabled()`, `GetHTTPCallbackURI`, `GetDNSCallbackDomain`, `HasInteraction`                                                                                                                                                                                                                                                                                                                                                                                                                                  | Hand-rolling TCS polling URLs, secret hashing, or custom callback HTTP requests
Web crawling                     | [common/clients/httpcrawler](/common/clients/httpcrawler/AGENTS.md): `NewSimpleCrawler(ctx, cfg)`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Custom HTML link scrapers or unscoped redirect followers
Protocol clients & brute-forcing | `common/bruteforce`, [common/credentialstore](/common/credentialstore/AGENTS.md), [common/clients/sshclient](/common/clients/sshclient/AGENTS.md), [common/clients/postgresclient](/common/clients/postgresclient/AGENTS.md), [common/clients/mysqlclient](/common/clients/mysqlclient/AGENTS.md), [common/clients/llm](/common/clients/llm/AGENTS.md)                                                                                                                                                                                                                                                                                                                                                   | Custom worker pools, bespoke credential lists, or raw driver dials when a shared client exists
Unit-test doubles                | [common/testfakes/fakehttp](/common/testfakes/fakehttp/AGENTS.md), [common/testfakes/fakecallbackserver](/common/testfakes/fakecallbackserver/AGENTS.md), [common/testfakes/faketemplated](/common/testfakes/faketemplated/AGENTS.md), [common/testfakes/fakemodule](/common/testfakes/fakemodule/AGENTS.md), [common/testfakes/fakerunner](/common/testfakes/fakerunner/AGENTS.md), [common/testfakes/fakenmap](/common/testfakes/fakenmap/AGENTS.md), [common/testfakes/fakessh](/common/testfakes/fakessh/AGENTS.md), [common/testfakes/fakellmagent](/common/testfakes/fakellmagent/AGENTS.md) | Re-implementing mock `goohttp.Client` structs, fake TCS servers, or fake module wrappers in plugin `_test.go` files

Similarly, prefer standard library packages (`net/http`, `net/url`,
`encoding/json`, `encoding/binary`) and vetted protocol libraries over
hand-rolled wire parsers or `fmt.Sprintf` protocol frames.

## 5. Network Safety, Deadlines, & Error Semantics

-   **Bound every network operation—including TLS handshakes**: `main.go` runs
    scans with a background `context.Context` that carries **no** deadline. When
    dialing raw TCP/TLS sockets (`net.Dialer` / `tls.Dialer`),
    `net.Dialer{Timeout: timeout}` bounds only TCP connection setup, **not** the
    TLS handshake. Always wrap raw/TLS dials and protocol exchanges in
    `reqCtx, cancel := context.WithTimeout(ctx, m.config.TimeoutPerRequest())`
    (with `defer cancel()`) and set `conn.SetDeadline` so tarpits or non-TLS
    listeners cannot stall `SimpleRunner` workers indefinitely.
-   **Return stage-appropriate non-match values on target/protocol mismatches,
    not `error`**: Any non-nil error from `Detect` or `Fingerprint` records a
    module error metric and degrades `ScanStatus` to `PARTIALLY_SUCCEEDED` (and
    any non-nil error from `PortScanner.Scan` aborts the scan). Treat connection
    refusals, per-request timeouts (`ctx.Err() == nil`), TLS/handshake failures,
    and unexpected protocol responses as non-matching targets logged via
    `log.DebugContextf`: return `(nil, nil)` from `Detect` (and from `Scan` when
    a host is unreachable), and return `([]*nspb.NetworkService{service}, nil)`
    from `Fingerprint`—returning `(nil, nil)` from `Fingerprint` drops `service`
    from `SimpleRunner`'s pipeline. Propagate non-nil errors only when the
    caller's `ctx` is canceled (`ctx.Err() != nil`) or when the input
    endpoint/configuration is invalid (such as
    `netendpoint.ErrEndpointMissingAddress`).
-   **Keep probes strictly on-target and treat peer data as untrusted**:
    -   Scope custom HTTP clients to the scanned service via
        `opts.LoadAuthorities(service)` when following redirects, and never dial
        arbitrary external hosts returned in target payloads.
    -   Treat `NetworkEndpoint.Hostname` (which may originate from untrusted PTR
        records) and target response fields (`ApplicationRoot`, headers, JSON
        values) as untrusted input. Build URLs via `net/url` and `net/http`
        rather than `fmt.Sprintf` wire strings; if raw wire framing is required,
        reject CR/LF, whitespace, and control bytes (`b <= 0x20 || b >= 0x7f`).
    -   Bound every response read (`goohttp.ReadBody` or `io.LimitReader`) and
        close all sockets and response bodies deterministically.
    -   Verification payloads must be 100% deterministic and non-destructive
        (`DetectionStatus_VULNERABILITY_VERIFIED`), using harmless computation,
        causal-ablation differentials, or TCS out-of-band callbacks—never shell
        commands that mutate state, drop files, or disrupt service availability.

## 6. Plugin Package Checklist

1.  Embed `*module.BaseModule` (`"dt/<name>"`, `"fp/<name>"`, or `"ps/<name>"`),
    self-register in `init()`, and add the blank import in alphabetical order in
    `main.go`.
2.  Include a concise `AGENTS.md` inside the new plugin directory using the
    standard `# Package <name>`, `## Services`, and `## Usage` sections to
    document its module name, exported constructors/methods/errors, detection
    mechanism, and blank-import usage.
3.  Write hermetic table-driven unit tests using `common/testfakes/` (such as
    `fakehttp` and `fakecallbackserver`) or `127.0.0.1:0` ephemeral loopback
    listeners—never external network dependencies—covering non-default ports,
    TLS vs. plaintext, non-matching services, malformed/oversized responses,
    per-request timeouts, and canceled contexts.
