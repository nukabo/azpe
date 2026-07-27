# AZPE (Azure Private Endpoint Connectivity Diagnostic Utility)

[![CI](https://github.com/nukabo/azpe/actions/workflows/ci.yml/badge.svg)](https://github.com/nukabo/azpe/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/nukabo/azpe)](https://goreportcard.com/report/github.com/nukabo/azpe)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`azpe` is a small, portable, zero-login, single-binary command-line utility for diagnosing Azure Private Endpoint connectivity directly from a workload's actual execution environment (e.g. application container, pod, VM, serverless instance).

---

## Quick Start

```bash
# 1. Download and run directly (no installation or Azure login required)
azpe probe myvault.vault.azure.net
```

### Example Terminal Output

```text
AZPE

✓ The Azure service responded

myvault.vault.azure.net → 10.42.3.7:443
HTTP 403 Forbidden

Private DNS     Looks correct
Connection      Working
TLS             Valid
Azure service   Access denied

The private connection is working. The service denied this unauthenticated request.

What to do:
If the application still fails, check its identity and Azure permissions.
```

---

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

> **Key Diagnostic Fact**: An `HTTP 403 Forbidden` or `HTTP 401 Unauthorized` response means **the private connection and HTTPS transport work perfectly**. The issue is purely application identity, credentials, or RBAC roles.

---

## Target User & Requirements

- Application Engineers & DevOps Practitioners
- Cloud Reliability Engineers
- Enterprise Network & Security Operations Teams

**Zero Prerequisites**: Ordinary users do **not** need Go, Docker, Python, Node.js, .NET, Azure CLI, Azure login, or administrator privileges (unless placing the binary in a system-wide `PATH` directory).

---

## Download & Installation Guide

Download the appropriate release archive from [GitHub Releases](https://github.com/nukabo/azpe/releases):

| Environment / Platform | Download Asset | What to Use It For |
| ---------------------- | -------------- | ------------------ |
| **Windows (Restricted / AVD / AppLocker)** | `azpe-powershell_0.1.1.zip` | Restricted Windows workstations, Azure Virtual Desktop (AVD), or hosts blocking `.exe` files |
| **Windows (Native Binary)** | `azpe_0.1.1_windows_amd64.zip` | Standard Windows workstations & servers |
| **Linux (AMD64)** | `azpe_0.1.1_linux_amd64.tar.gz` | Linux VMs, Kubernetes pods, CI/CD runners, container instances |
| **Linux (ARM64)** | `azpe_0.1.1_linux_arm64.tar.gz` | Linux ARM64 VMs & servers |
| **macOS (Apple Silicon)** | `azpe_0.1.1_darwin_arm64.tar.gz` | macOS M1/M2/M3/M4 workstations |
| **macOS (Intel)** | `azpe_0.1.1_darwin_amd64.tar.gz` | macOS Intel workstations |

---

### Option A: Windows (PowerShell Client — Restricted / AVD / AppLocker) ⭐ *Recommended for Enterprise*

If your Windows laptop or Azure Virtual Desktop host blocks running unsigned `.exe` files:

1. Download **`azpe-powershell_0.1.1.zip`** from [GitHub Releases](https://github.com/nukabo/azpe/releases).
2. Right-click the `.zip` file → **Extract All...**
3. Open PowerShell in the extracted folder and run:

```powershell
# Load the script
. .\Invoke-AzpeProbe.ps1

# Run diagnostic probe
Invoke-AzpeProbe myvault.vault.azure.net
```

---

### Option B: Windows (Native Executable)

1. Download **`azpe_0.1.1_windows_amd64.zip`** from [GitHub Releases](https://github.com/nukabo/azpe/releases).
2. Right-click → **Extract All...**
3. Open PowerShell in the extracted folder:

```powershell
# Remove web download block if necessary
Unblock-File .\azpe.exe

# Run diagnostic probe
.\azpe.exe probe myvault.vault.azure.net
```

> **Note**: If Windows shows `Access is denied` due to AppLocker policies, switch to **Option A (PowerShell Client)** above.

---

### Option C: Linux / macOS

```bash
# Download and extract (example for Linux AMD64)
tar -xzf azpe_0.1.1_linux_amd64.tar.gz

# Run probe
./azpe probe myvault.vault.azure.net
```

---

## Verifying Release Artifacts

### 1. SHA-256 Checksum Verification

Every release includes a `checksums.txt` file containing SHA-256 hashes for all native release archives. Verify downloaded archives before extraction:

**Linux / macOS**:
```bash
sha256sum --check checksums.txt
# Or macOS shasum:
shasum -a 256 -c checksums.txt
```

**Windows (PowerShell)**:
```powershell
Get-FileHash .\azpe_0.1.0_windows_amd64.zip -Algorithm SHA256
```
Compare the output with the corresponding hash in `checksums.txt`.

### 2. GitHub Artifact Provenance Attestations

AZPE releases publish GitHub OIDC build provenance attestations. You can verify that downloaded binaries were produced by official GitHub Actions workflows:

```bash
gh attestation verify azpe_0.1.0_linux_amd64.tar.gz --repo nukabo/azpe
```

---

## Upgrade & Uninstall

### Upgrading AZPE
To upgrade AZPE, download the new release archive from [GitHub Releases](https://github.com/nukabo/azpe/releases) and replace your existing `azpe` / `azpe.exe` executable file.

### Uninstalling AZPE
To uninstall AZPE, simply delete the `azpe` / `azpe.exe` executable file from your system:

```bash
# Linux / macOS
sudo rm /usr/local/bin/azpe

# Windows (PowerShell)
Remove-Item C:\Path\To\azpe.exe
```

---

## Critical Security Policies & Disclaimers

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

---

## Usage Guide & Command Options

```bash
azpe probe <azure-service-hostname-or-url> [flags]
```

### Flags

| Flag | Description |
| ---- | ----------- |
| `--json` | Output machine-readable JSON (`schemaVersion: 1`) |
| `--details` | Multi-section terminal output (Target, DNS, Connection, TLS, HTTP, Tests, Assessment) |
| `--timeout <duration>` | Operation deadline timeout (default: `5s`) |
| `--no-http` | Skip minimal HTTP probe phase and return Phase 4 TLS results |
| `--no-color` | Disable ANSI colorized terminal output |

---

## Building & Contributing (For Maintainers & Developers)

### Prerequisites
- Go 1.22 or higher
- Git

### Local Build & Test

```bash
# Clone repository
git clone https://github.com/nukabo/azpe.git
cd azpe

# Build host binary
go build -o azpe ./cmd/azpe

# Run test suite
go test -v -count=1 ./...
go vet ./...
go test -v -race ./...

# Validate GoReleaser v2 configuration locally
goreleaser check
goreleaser release --snapshot --clean
```

---

## License

This project is licensed under the [MIT License](LICENSE).
