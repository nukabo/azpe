# Contributing to AZPE

Thank you for your interest in contributing to AZPE! We welcome pull requests, bug reports, feature suggestions, and documentation improvements.

---

## Code of conduct

All contributors and community members are expected to keep discussions civil, constructive, and inclusive.

---

## Development setup

### Prerequisites
- Go 1.22 or higher
- PowerShell 5.1 / PowerShell 7 (if testing the PowerShell compatibility client)
- Git

### Building locally

```bash
# 1. Clone repository
git clone https://github.com/nukabo/azpe.git
cd azpe

# 2. Build host binary
go build -o azpe ./cmd/azpe

# 3. Test execution
./azpe probe myvault.vault.azure.net
```

---

## Workflow & quality standards

Before submitting a pull request, verify that all quality gates pass locally:

### 1. Go native client quality gates

```bash
# Format code
gofmt -s -w .

# Run static analysis
go vet ./...

# Run test suite and race detector
go test -v -count=1 ./...
go test -v -race ./...

# Validate GoReleaser v2 configuration
goreleaser check
```

### 2. PowerShell compatibility client quality gates

```powershell
# Rebuild standalone script and run Pester tests
./powershell/build.ps1
Invoke-Pester -Path ./powershell/Tests -Output Detailed
```

---

## Azure service catalogue maintenance

AZPE relies on a shared Azure service catalogue to recognize official Azure Private Link domain suffixes (e.g. `.vault.azure.net`, `.blob.core.windows.net`, `.redis.cache.windows.net`).

When proposing new Azure service suffixes or updated private domain patterns:

1. **Update `internal/catalog/azure-services.json`**: Add the new pattern with its `suffix`, `family`, and human-friendly `displayName`.
2. **Update Go target classifier (`internal/target/recognize.go`)**: Ensure the `AzureServiceFamily` enum and pattern slice include the new service family.
3. **Update PowerShell target classifier (`powershell/Azpe/Private/Catalogue.ps1`)**: Keep the PowerShell catalogue and display names 100% synchronized with `azure-services.json`.
4. **Add Unit & Parity Tests**: Add test cases in `internal/target/recognize_test.go` and `powershell/Tests/Parity.Tests.ps1` verifying target classification across both clients.

---

## Core product principles

> [!NOTE]
> When proposing architectural changes or new CLI features, adhere to the core product principles detailed in [docs/product-principles.md](docs/product-principles.md).

Key guidelines:
- **Zero Azure login/credentials**: Never introduce mandatory Azure CLI, Azure SDK, or Azure credential requirements.
- **No security policy bypass**: Never implement or document execution policy bypasses, AMSI bypasses, or certificate validation bypasses (`InsecureSkipVerify: false`).
- **Separation of concerns**: Keep diagnostic observation logic cleanly separated from human terminal rendering and JSON output formatters.
- **Accuracy**: Never claim more certainty than empirical evidence supports (e.g., state *The Azure service responded*, never *Private Endpoint verified*).
