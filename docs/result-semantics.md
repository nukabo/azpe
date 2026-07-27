# AZPE Result Semantics & Schema Specification

This document defines the vocabulary, assessment logic, target normalization rules, schema versioning, and exit code contracts used by AZPE.

---

## Operating-System DNS Resolution Semantics

AZPE uses Go's platform resolver behavior (`dns.OSResolver`).

> [!NOTE]
> **DNS Resolver Mode (`GO_BUILTIN`)**:
> In statically compiled Unix releases (`CGO_ENABLED=0`), name resolution uses Go's built-in pure-Go DNS resolver (which parses system configuration files such as `/etc/resolv.conf`, `/etc/hosts`, and `/etc/nsswitch.conf`) rather than invoking C/libc functions like `getaddrinfo`.
>
> In `--details` terminal output, AZPE reports:
> `Resolver mode        Go built-in`
> In JSON output (`schemaVersion: 1`), `dns` includes:
> `"resolverMode": "GO_BUILTIN"`
>
> In typical workload environments (e.g. Linux containers, VMs, Kubernetes pods), Go's pure resolver produces identical DNS resolution results to standard system tools. In environments relying on custom C/NSS dynamic library modules or platform-specific macOS split-DNS, results should be compared against native system tools during initial workload validation.

---

## Target Normalization

AZPE normalizes input target strings into a consistent `Target` model containing:
- `originalInput`: Raw user input string
- `scheme`: `http` or `https` (default: `https`)
- `hostname`: Target FQDN or IP literal (without brackets)
- `port`: TCP port (default: `443` for https, `80` for http)
- `requestPath`: Path and query string (default: `/`)
- `targetType`: `RECOGNIZED_AZURE_SERVICE`, `POSSIBLE_AZURE_SERVICE`, `UNRECOGNIZED_TARGET`, or `IP_LITERAL`
- `azureServiceFamily`: Identified Azure service family (e.g. `KEY_VAULT`, `STORAGE_BLOB`, `SQL`, `COSMOS_DB`, `AI_SEARCH`, `AZURE_OPENAI`, `CONTAINER_REGISTRY`, `APP_CONFIGURATION`, `SERVICE_BUS`, `OTHER_AZURE`, `NONE`)

### IP Literals
When the target hostname is an IPv4 or IPv6 literal (e.g. `10.0.0.1`, `[fd00::1]`), AZPE bypasses OS hostname DNS resolution.
- `dns.status`: `NOT_APPLICABLE`
- `dns.isIpLiteral`: `true`
- The IP address is classified directly without implying private DNS was tested.
- Human output state: `The Azure service hostname is required` (`An IP address cannot test Private Endpoint DNS`).
- Exit code: `8`

---

## Address Classification

Each resolved IP address is classified independently with explicit precedence rules:

| Category | Description | Precedence |
| -------- | ----------- | ---------- |
| `UNSPECIFIED` | `0.0.0.0`, `::` | 1 (Highest) |
| `LOOPBACK` | `127.0.0.0/8`, `::1` | 2 |
| `MULTICAST` | `224.0.0.0/4`, `ff00::/8` | 3 |
| `LINK_LOCAL` | `169.254.0.0/16`, `fe80::/10` | 4 |
| `DOCUMENTATION` | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` | 5 |
| `BENCHMARK` | `198.18.0.0/15` | 6 |
| `RESERVED` | `240.0.0.0/4`, `100.64.0.0/10` (CGNAT), `192.0.0.0/24`, `192.88.99.0/24` | 7 |
| `PRIVATE` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` (RFC 1918 / RFC 4193) | 8 |
| `PUBLIC` | All other global unicast IP addresses | 9 |

---

## Direct HTTPS Probing (Phase 5)

When direct TCP probing and TLS validation succeed for private IP addresses (`VALID`), AZPE sends a single unauthenticated HTTPS GET request to `captured IP + port` using the original Azure service hostname as `Host` header and `ServerName` (SNI).

- **Central Product Insight**: Any syntactically valid HTTP response (2xx, 3xx, 400, 401, 403, 404, 405, 409, 429, 5xx) proves that end-to-end network, TCP, TLS, and HTTP transport reached the Azure service.
- **HTTP 401 & 403**: Categorized as `AUTHENTICATION_REQUIRED` and `ACCESS_DENIED`. They return Exit Code `0` (`The Azure service responded`) because network transport is fully functional.
- **No Second DNS Lookup**: Direct socket connection dials `net.JoinHostPort(capturedIP, port)`.
- **Proxy Bypass**: Environment proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are explicitly ignored (`Proxy: nil`).
- **Redirects Not Followed**: Redirects (3xx) are returned directly to AZPE without following target URLs.
- **Bounded Body & Query Redaction**: Reads up to 4 KiB limit, discards content, and redacts query parameter values in output (e.g. `/path?sig=REDACTED`).

---

## Assessment Rules & Exit Codes

| Case | Human Title | Overall State (JSON) | Exit Code | Description |
| ---- | ----------- | ------------------- | --------- | ----------- |
| Recognized Private Only + TCP + TLS + HTTP Response (2xx, 3xx, 4xx, 429, 5xx) or `--no-http` | `The Azure service responded` / `Secure private connection looks correct` | `WORKING` | `0` | End-to-end HTTPS transport succeeded and an HTTP response was received. |
| Recognized Private Only + TCP + TLS + HTTP Response Timeout / Malformed / Transport Error | `The Azure service did not respond in time` / `The destination did not return a valid HTTP response` / `The HTTPS request could not be completed` | `BROKEN` | `7` | DNS, TCP, and TLS valid, but NO valid HTTP response was received. |
| Recognized Private Only + TCP + TLS + Partial HTTP Response | `The Azure service responded on only some private addresses` | `UNKNOWN` | `8` | At least one address returned an HTTP response and at least one timed out or failed. |
| Recognized Private Only + TCP Success + TLS Failure | `The certificate does not match the Azure service name` / `The certificate is not trusted by this workload` / `The certificate has expired` | `BROKEN` | `6` | TCP connected, but ALL TLS validations failed. |
| Recognized Private Only + TCP Failure | `The private address cannot be reached` | `BROKEN` | `5` | Resolved to private IP address(es), but ALL TCP connection probes failed. |
| Recognized Public Only | `This workload is not using private DNS` | `NOT_PRIVATE` | `4` | Resolved to public IP address(es). TCP/TLS/HTTP probes not attempted. |
| DNS Lookup Failed | `The Azure service name cannot be resolved` | `BROKEN` | `3` | DNS resolution failed (NXDOMAIN, timeout, or server failure). |
| Inconclusive / Not Applicable | `DNS is returning both private and public addresses` / `Cannot test this target` / `The Azure service hostname is required` | `UNKNOWN` | `8` | Mixed private/public DNS, special-purpose addresses, IP literal input, generic non-Azure target, or unsupported Azure target. |
| Invalid Usage/Target | N/A | N/A | `2` | Malformed target syntax, unsupported scheme, invalid port, or invalid CLI flag. |
| Unexpected Internal Error | N/A | N/A | `10` | Internal unexpected runtime error. |

---

## JSON Schema Versioning

All machine-readable output generated with `--json` contains top-level field `schemaVersion`.
Current schema version: `1`.

Key schema conventions in `schemaVersion: 1`:
- `engine` object includes `name` (`NATIVE` or `POWERSHELL_COMPAT`), `version` (`0.1.0`), and engine-specific runtime capability metadata (`powerShellVersion`, `powerShellEdition`, `languageMode`).
- `dns` object includes `status`, `resolverMode` (`GO_BUILTIN`), `queryHostname`, `durationMs`, `addresses`, `aggregateClassification`, `isIpLiteral`.
- `http` object includes `status`, `aggregateStatus`, `method`, `path`, `durationMs`, and `results` slice containing per-address observations.
- Unobserved/skipped phases omit optional fields or serialize `results: []`.
- Slice properties (`errors`, `warnings`, `privateIps`, `publicIps`, `addresses`, `tcp.results`, `tls.results`, `http.results`) serialize as `[]` rather than `null`.
- Machine enums (`WORKING`, `BROKEN`, `NOT_PRIVATE`, `UNKNOWN`, `ALL_RESPONDED`, `NONE_RESPONDED`, `PARTIALLY_RESPONDED`, `NOT_ATTEMPTED`, `GO_BUILTIN`) are preserved in JSON for automation.
