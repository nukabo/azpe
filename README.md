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
4. TLS / certificate handshake failures
5. Application authentication or authorization failures (HTTP 401/403)
6. Upstream service outages (HTTP 5xx)

`azpe` combines DNS resolution, IP classification, TCP connectivity, TLS validation, and a minimal HTTP request into a single plain-language diagnostic assessment.

## Target User

- Application Engineers & DevOps Practitioners
- Cloud Reliability Engineers
- Enterprise Network & Security Operations Teams

`azpe` requires **zero Azure permissions**, **no Azure CLI**, **no Azure SDK**, and **no Go runtime** on the target host.

## Critical Product Semantics & Disclaimers

> [!IMPORTANT]
> **No Control-Plane Claims**: AZPE observes connectivity from the workload's current execution environment without Azure control-plane access.
> - An approved Azure Private Endpoint configuration in the Azure portal **does not prove workload connectivity** from your environment.
> - Observing resolution to a private IP address is **evidence**, not formal proof, that the target is using private DNS.
> 
> Therefore, AZPE will never claim `Private Endpoint verified`. It states: *Private DNS looks correct* or *This workload is not using private DNS*.

## Current Status (Phase 2)

Phase 2 implements:
- Operating-system DNS resolution using Go's standard library resolver.
- Azure service hostname recognition catalogue (Key Vault, Storage, SQL, Cosmos DB, AI Search, OpenAI, ACR, App Configuration, Service Bus).
- IP address classification across 10 categories (`PRIVATE`, `PUBLIC`, `LOOPBACK`, `LINK_LOCAL`, `UNSPECIFIED`, `MULTICAST`, `DOCUMENTATION`, `BENCHMARK`, `RESERVED`, `UNKNOWN`).
- Address deduplication and deterministic IP ordering.
- Plain-language diagnostic assessments and exit code contracts:
  - Exit `0`: Recognized Azure service hostname resolved exclusively to private addresses (`Private DNS looks correct`).
  - Exit `2`: Invalid CLI usage or target syntax error.
  - Exit `3`: DNS lookup failed for a recognized Azure service hostname (`The Azure service name cannot be resolved`).
  - Exit `4`: Recognized Azure service hostname resolved exclusively to public addresses (`This workload is not using private DNS`).
  - Exit `8`: Inconclusive / Not applicable (mixed DNS, special-purpose IPs, IP literal, unrecognized non-Azure target).
  - Exit `10`: Unexpected internal error.

*Note: TCP connectivity, TLS validation, and HTTP health probes remain untested in Phase 2 and are planned for subsequent phases.*

## Planned v0.1 Roadmap

- [x] Target parsing, result modeling, CLI routing, JSON & terminal rendering (Phase 1)
- [x] Operating-system DNS resolution, target recognition & IP address classification (Phase 2)
- [ ] TCP port probe & latency measurement (Phase 3)
- [ ] TLS certificate verification & SNI validation (Phase 4)
- [ ] Minimal HTTP HEAD/GET request & status code classification (Phase 5)

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
