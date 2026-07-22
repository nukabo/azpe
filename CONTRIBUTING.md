# Contributing to AZPE

Thank you for your interest in contributing to AZPE!

## Code of Conduct

All contributors are expected to keep discussions civil, constructive, and inclusive.

## Development Setup

1. Install Go 1.22+.
2. Clone the repository.
3. Build the binary locally:
   ```bash
   go build -o azpe ./cmd/azpe
   ```

## Workflow & Quality Standards

Before submitting a pull request:
1. Ensure code is formatted with `gofmt`:
   ```bash
   gofmt -s -w .
   ```
2. Run unit and integration tests:
   ```bash
   go test -v ./...
   ```
3. Run `go vet`:
   ```bash
   go vet ./...
   ```
4. Verify cross-compilation targets succeed:
   ```bash
   GOOS=linux GOARCH=amd64 go build ./cmd/azpe
   GOOS=windows GOARCH=amd64 go build ./cmd/azpe
   GOOS=darwin GOARCH=arm64 go build ./cmd/azpe
   ```

## Design Principles

When proposing changes, adhere to the 10 Core Product Principles detailed in [docs/product-principles.md](docs/product-principles.md). Key rules include:
- Do not introduce runtime dependencies on Azure SDK/CLI or mandatory Azure authentication.
- Keep business logic cleanly separated from CLI rendering and output formatting.
- Never declare network success when an application or authorization error occurs.
