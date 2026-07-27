# Changelog

All notable changes to `azpe` (Azure Private Endpoint Connectivity Diagnostic Utility) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Official PowerShell Compatibility Client (Phase 7)**:
  - Enterprise PowerShell module `Azpe` (`Azpe.psd1`, `Azpe.psm1`) and standalone script `Invoke-AzpeProbe.ps1`.
  - Full support for Windows PowerShell 5.1 and PowerShell 7 on Windows / AVD.
  - Strict compliance with enterprise application controls (AppLocker, WDAC, Constrained Language Mode, Execution Policies). Zero security bypass techniques implemented or documented.
  - Capability detection (`Get-AzpeCapability`) reporting PowerShell version, edition, language mode, `Resolve-DnsName`, `Test-NetConnection`, and `curl.exe`.
  - High-fidelity target parsing, boundary-safe Azure service suffix catalogue, DNS address classification, TCP probing against captured IPs, and direct-IP `--resolve` HTTPS validation via native `curl.exe`.
  - Full terminal rendering (`-Detailed`) and machine-readable JSON (`-Json`) schema compatibility with engine metadata (`"engine": { "name": "POWERSHELL_COMPAT", "version": "0.1.0" }`).
  - GitHub Actions CI workflow (`powershell-ci.yml`) and deterministic packaging script (`powershell/build.ps1`).

## [v0.1.0] - 2026-07-22

### Added
- **Target Normalization & Recognition (Phase 1 & 2)**:
  - Target FQDN and URL normalization (`https://myvault.vault.azure.net:443/`).
  - Catalogue recognition for Azure service families (Key Vault, Storage Blob, SQL, Cosmos DB, AI Search, OpenAI, ACR, App Configuration, Service Bus).
  - Operating-system DNS resolution (`dns.OSResolver`).
  - IP address classification across 10 categories (`PRIVATE`, `PUBLIC`, `LOOPBACK`, `LINK_LOCAL`, `UNSPECIFIED`, `MULTICAST`, `DOCUMENTATION`, `BENCHMARK`, `RESERVED`, `UNKNOWN`).
- **Direct TCP Connectivity Probing (Phase 3)**:
  - Direct socket connectivity probing (`net.Dialer.DialContext`) without secondary DNS lookups.
  - Per-address connection latency measurement and TCP error categorization (`TIMEOUT`, `CONNECTION_REFUSED`, `UNREACHABLE`).
- **Direct TLS Validation (Phase 4)**:
  - Direct TLS handshake against captured private IP addresses.
  - SNI and certificate validation enforced using original Azure hostname.
  - System trust store verification with zero bypass options (`InsecureSkipVerify: false`).
- **Minimal Unauthenticated HTTPS GET Probing (Phase 5)**:
  - Unauthenticated HTTPS GET request to captured private IP + port.
  - HTTP status code mapping (2xx, 3xx, 4xx, 429, 5xx) yielding Exit Code `0` (`✓ The Azure service responded`).
  - HTTP 401 & 403 mapped to `AUTHENTICATION_REQUIRED` and `ACCESS_DENIED` with Exit Code `0` (confirming connectivity works).
  - Explicit proxy bypass (`Proxy: nil`) and redirect prevention (`CheckRedirect: ErrUseLastResponse`).
  - Bounded 4 KiB response body reading and safe response header allowlisting (`Content-Type`, `Date`, `Server`, `Location`, `Retry-After`, `WWW-Authenticate`, request IDs).
  - Universal query parameter value redaction (`/path?sig=REDACTED`).
  - `--no-http` flag to skip HTTP probing phase.
- **Release Engineering & Automation (Phase 6)**:
  - Linker flag build-time version injection (`Version`, `Commit`, `Date`, `SchemaVersion`).
  - GoReleaser v2 configuration for 5 native cross-platform binaries (`linux/amd64`, `linux/arm64`, `windows/amd64`, `darwin/amd64`, `darwin/arm64`).
  - SHA-256 `checksums.txt` generation.
  - GitHub Actions CI (`ci.yml`) and Release (`release.yml`) workflows with minimal permissions.
  - GitHub Artifact Attestations for native release archives via GitHub OIDC.
