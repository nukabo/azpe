# AZPE Result Semantics & Schema Specification

This document defines the vocabulary, assessment logic, target normalization rules, schema versioning, and exit code contracts used by AZPE.

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

## Direct TLS Validation (Phase 4)

When direct TCP probing succeeds for private IP addresses (`CONNECTED`), AZPE establishes a direct TLS connection (`crypto/tls`) to `captured IP + port` using the original Azure service hostname as `ServerName` (SNI) and validating certificate chains against the system trust store.

- **No Second DNS Lookup**: TLS connects directly to captured IP addresses using `net.JoinHostPort` without re-resolving hostnames.
- **Strict Verification**: Certificate validation is **never** disabled (`InsecureSkipVerify: false`).
- **Per-Address Observations**: Each TCP-reachable address receives a TLS status (`VALID`, `HOSTNAME_MISMATCH`, `UNTRUSTED_CERTIFICATE`, `EXPIRED_CERTIFICATE`, `NOT_YET_VALID`, `HANDSHAKE_TIMEOUT`, `HANDSHAKE_FAILED`, `CONNECTION_CLOSED`).
- **Aggregate TLS Status**:
  - `ALL_VALID`: All attempted private addresses completed trusted, hostname-validated TLS.
  - `NONE_VALID`: All attempted private addresses failed TLS validation or handshake.
  - `PARTIALLY_VALID`: At least one private address completed valid TLS and at least one failed.
  - `NOT_ATTEMPTED`: TLS was not attempted because DNS was non-private, DNS failed, or TCP connection failed.

---

## Assessment Rules & Exit Codes

| Case | Human Title | Overall State (JSON) | Exit Code | Description |
| ---- | ----------- | ------------------- | --------- | ----------- |
| Recognized Private Only + TCP Success + TLS Valid | `Secure private connection looks correct` | `WORKING` | `0` | Resolved to private IP address(es), TCP connected, and all TLS validations succeeded. |
| Recognized Private Only + TCP Success + TLS Failure | `The certificate does not match the Azure service name` / `The certificate is not trusted by this workload` / `The certificate has expired` | `BROKEN` | `6` | TCP connected, but ALL TLS validations failed (hostname mismatch, untrusted CA, expired, TLS timeout). |
| Recognized Private Only + TCP Success + Partial TLS | `TLS works for only some private addresses` | `UNKNOWN` | `8` | TCP connected; at least one address validated TLS and at least one failed. |
| Recognized Private Only + TCP Failure | `The private address cannot be reached` | `BROKEN` | `5` | Resolved to private IP address(es), but ALL TCP connection probes failed. |
| Recognized Public Only | `This workload is not using private DNS` | `NOT_PRIVATE` | `4` | Resolved to public IP address(es). TCP/TLS probes not attempted. |
| DNS Lookup Failed | `The Azure service name cannot be resolved` | `BROKEN` | `3` | DNS resolution failed (NXDOMAIN, timeout, or server failure). TCP/TLS probes not attempted. |
| Inconclusive / Not Applicable | `DNS is returning both private and public addresses` / `Cannot test this target` / `The Azure service hostname is required` | `UNKNOWN` | `8` | Mixed private/public DNS, special-purpose addresses, IP literal input, generic non-Azure target, or unsupported Azure target. |
| Invalid Usage/Target | N/A | N/A | `2` | Malformed target syntax, unsupported scheme, invalid port, or invalid CLI flag. |
| Unexpected Internal Error | N/A | N/A | `10` | Internal unexpected runtime error. |

---

## JSON Schema Versioning

All machine-readable output generated with `--json` contains top-level field `schemaVersion`.
Current schema version: `1`.

Key schema conventions in `schemaVersion: 1`:
- `tls` object includes `aggregateStatus`, `serverName`, `durationMs`, and `results` slice containing per-address observations (`address`, `version`, `classification`, `destination`, `port`, `serverName`, `status`, `stage`, `durationMs`, `tlsVersion`, `cipherSuite`, `hostnameValid`, `certificateTrusted`, `peerCertificateCount`, `verifiedChainCount`, `leafCertificate`, `errorCategory`, `error`).
- Unobserved/skipped phases omit optional fields or serialize `results: []`.
- Slice properties (`errors`, `warnings`, `privateIps`, `publicIps`, `addresses`, `tcp.results`, `tls.results`) serialize as `[]` rather than `null`.
- Machine enums (`WORKING`, `BROKEN`, `NOT_PRIVATE`, `UNKNOWN`, `ALL_VALID`, `NONE_VALID`, `PARTIALLY_VALID`, `NOT_ATTEMPTED`) are preserved in JSON for automation.
- `assessment` object contains structured fields: `scenario`, `state`, `title`, `explanation`, `impact`, `summary`, `likelyOwner`, `nextAction`.
