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

## Aggregate Address Classification

| Aggregate State | Meaning |
| --------------- | ------- |
| `PRIVATE_ONLY` | All resolved IP addresses are `PRIVATE`. |
| `PUBLIC_ONLY` | All resolved IP addresses are `PUBLIC`. |
| `MIXED_PRIVATE_PUBLIC` | Target returned a mixture of `PRIVATE` and `PUBLIC` IP addresses. |
| `SPECIAL_ONLY` | All resolved IP addresses belong to special-purpose ranges (loopback, link-local, documentation, etc.). |
| `MIXED` | Other mixtures of special and private/public IPs. |
| `NONE` | No IP addresses were returned (DNS resolution failed). |

---

## Assessment Rules & Exit Codes

| Case | Human Title | Overall State (JSON) | Exit Code | Description |
| ---- | ----------- | ------------------- | --------- | ----------- |
| Recognized Private Only | `Private DNS looks correct` | `UNKNOWN` | `0` | Resolved to private IP address(es). Evidence of private DNS, but network connectivity is untested. |
| Recognized Public Only | `This workload is not using private DNS` | `NOT_PRIVATE` | `4` | Resolved to public IP address(es). The application will attempt to use a public Azure endpoint. |
| DNS Lookup Failed | `The Azure service name cannot be resolved` | `BROKEN` | `3` | DNS resolution failed (NXDOMAIN, timeout, or temporary server failure). |
| Inconclusive / Not Applicable | `DNS is returning both private and public addresses` / `Cannot test this target` / `The Azure service hostname is required` | `UNKNOWN` | `8` | Mixed private/public DNS, special-purpose addresses, IP literal input, generic non-Azure target, or unsupported Azure target. |
| Invalid Usage/Target | N/A | N/A | `2` | Malformed target syntax, unsupported scheme, invalid port, or invalid CLI flag. |
| Unexpected Internal Error | N/A | N/A | `10` | Internal unexpected runtime error. |

---

## JSON Schema Versioning

All machine-readable output generated with `--json` contains top-level field `schemaVersion`.
Current schema version: `1`.

Key schema conventions in `schemaVersion: 1`:
- Unobserved/skipped phases (e.g. TLS certificate validation in Phase 2) omit `certValid` instead of serializing `certValid: false`.
- Slice properties (`errors`, `warnings`, `privateIps`, `publicIps`, `addresses`) serialize as `[]` rather than `null`.
- Machine enums (`NOT_PRIVATE`, `BROKEN`, `UNKNOWN`, `DNS_OR_NETWORK`, `PRIVATE_ONLY`, `PUBLIC_ONLY`) are preserved in JSON for automation.
- `assessment` object contains structured fields: `scenario`, `state`, `title`, `explanation`, `impact`, `summary`, `likelyOwner`, `nextAction`.
