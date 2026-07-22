# AZPE (Azure Private Endpoint Connectivity Diagnostic Utility)

`azpe` is a small, portable, zero-runtime command-line utility for diagnosing Azure Private Endpoint connectivity directly from a workload's actual execution environment (e.g. application container, pod, VM, serverless instance).

## Primary Command

```bash
azpe probe myvault.vault.azure.net
```

## The Problem

Application teams in large enterprises often rely on centrally managed Azure Private Endpoints to access cloud services securely. However, these teams frequently lack access or visibility into:
- Azure Private DNS zones
- Endpoint Network Interfaces (NICs)
- Virtual Networks (VNets) and Subnets
- Network Security Groups (NSGs)
- Route tables & VNet peerings
- Firewalls & Azure Network Watcher

When an application cannot reach an Azure service, engineers commonly cannot distinguish between:
1. Local or corporate DNS resolution failures
2. Public IP resolution instead of Private IP resolution
3. Network path & routing failures (TCP timeout / connection refused)
4. TLS / certificate handshake failures (hostname mismatch / untrusted CA / expired certificate)
5. Application authentication or authorization failures (HTTP 401/403)
6. Upstream service outages (HTTP 5xx)

`azpe` combines DNS resolution, IP classification, TCP connectivity, TLS validation, and a minimal HTTP health probe into a single plain-language diagnostic assessment.

## Target User

- Application Engineers & DevOps Practitioners
- Cloud Reliability Engineers
- Enterprise Network & Security Operations Teams

`azpe` requires **zero Azure permissions**, **no Azure CLI**, **no Azure SDK**, and **no Go runtime** on the target host.

## Critical Product Semantics & Security Policy

> [!IMPORTANT]
> **No Control-Plane Claims**: AZPE observes connectivity from the workload's current execution environment without Azure control-plane access.
> - An approved Azure Private Endpoint configuration in the Azure portal **does not prove workload connectivity** from your environment.
> - Observing resolution to a private IP address is **evidence**, not formal proof, that the target is using private DNS.
> - A valid TLS connection proves that the certificate chain is trusted and matches the hostname.
> - An HTTP 401 or 403 status response **proves end-to-end HTTPS transport works**, but that the request lacks valid credentials or authorization.
> - Certificate validation is **NEVER** disabled (`InsecureSkipVerify: false`).
> 
> Therefore, AZPE will never claim `Private Endpoint verified`. It states: *The Azure service responded*, *Secure private connection looks correct*, *Private connection is reachable*, or *This workload is not using private DNS*.

> [!WARNING]
> **Target URL Recommendation**: Avoid placing secrets, tokens, or credentials directly in the target URL. AZPE redacts query parameter values in all terminal and JSON output (e.g. `/path?sig=REDACTED`), but the raw query parameter values are still sent over the network to the target service as part of the requested HTTP URL.

## Current Status (Phase 5)

Phase 5 implements:
- Operating-system DNS resolution using Go's standard library resolver.
- Azure service hostname recognition catalogue (Key Vault, Storage, SQL, Cosmos DB, AI Search, OpenAI, ACR, App Configuration, Service Bus).
- IP address classification across 10 categories (`PRIVATE`, `PUBLIC`, `LOOPBACK`, `LINK_LOCAL`, `UNSPECIFIED`, `MULTICAST`, `DOCUMENTATION`, `BENCHMARK`, `RESERVED`, `UNKNOWN`).
- Direct TCP connectivity probing (`net.Dialer.DialContext`) directly against captured IP addresses and target ports without secondary DNS lookups.
- Direct TLS validation (`crypto/tls`) against captured private IPs using original Azure service hostname for SNI and system trust store certificate verification.
- Minimal unauthenticated HTTPS GET probing against TLS-valid private IP addresses.
- Direct-IP HTTPS transport ignoring environment proxies (`HTTP_PROXY`, etc.) and redirect prevention.
- Bounded response body reading (4 KiB max) and safe response-header allowlisting (`Content-Type`, `Date`, `Server`, `Location`, `Retry-After`, `WWW-Authenticate`, request IDs).
- Universal query parameter value redaction (e.g. `/path?sig=REDACTED`) across simple, detailed, and JSON outputs.
- Plain-language diagnostic assessments and exit code contracts:
  - Exit `0`: Recognized Azure service, private DNS active, TCP connected, TLS valid, and HTTP response received (2xx, 3xx, 4xx, 429, 5xx) or `--no-http` specified (`✓ The Azure service responded`).
  - Exit `2`: Invalid CLI usage or target syntax error.
  - Exit `3`: DNS lookup failed for a recognized Azure service hostname (`✗ The Azure service name cannot be resolved`).
  - Exit `4`: Recognized Azure service hostname resolved exclusively to public addresses (`✗ This workload is not using private DNS`).
  - Exit `5`: Recognized Azure service hostname resolved privately, but ALL TCP connection probes failed (`✗ The private address cannot be reached`).
  - Exit `6`: Recognized Azure service hostname resolved privately, TCP succeeded, but ALL TLS validations failed (`✗ The certificate does not match the Azure service name`, `✗ The certificate is not trusted by this workload`, `✗ The certificate has expired`).
  - Exit `7`: DNS, TCP, and TLS succeeded, but NO valid HTTP response was received before timeout / transport error (`✗ The Azure service did not respond in time`).
  - Exit `8`: Inconclusive / Partial (mixed DNS, partial TCP reachability, partial TLS validity, partial HTTP response, special-purpose IPs, IP literal, unrecognized non-Azure target).
  - Exit `10`: Unexpected internal error.

## Completed v0.1 Roadmap

- [x] Target parsing, result modeling, CLI routing, JSON & terminal rendering (Phase 1)
- [x] Operating-system DNS resolution, target recognition & IP address classification (Phase 2)
- [x] Direct TCP connectivity probing & per-address latency measurement (Phase 3)
- [x] Direct TLS validation, SNI & system trust store certificate verification (Phase 4)
- [x] Minimal unauthenticated HTTPS GET probe & HTTP status code classification (Phase 5)

## Building from Source

### Prerequisites
- Go 1.22 or higher

### Build

```bash
go build -o azpe ./cmd/azpe
```

### Run Tests

```bash
go test -v ./...
go vet ./...
go test -race ./...
```

### Cross-Compilation

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o dist/azpe-linux-amd64 ./cmd/azpe

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o dist/azpe-linux-arm64 ./cmd/azpe

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o dist/azpe-windows-amd64.exe ./cmd/azpe

# macOS AMD64
GOOS=darwin GOARCH=amd64 go build -o dist/azpe-darwin-amd64 ./cmd/azpe

# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -o dist/azpe-darwin-arm64 ./cmd/azpe
```

## License

This project is licensed under the [MIT License](LICENSE).
