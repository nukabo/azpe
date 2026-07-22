## Description

Provide a clear, concise summary of the changes introduced in this pull request and the problem they solve.

## Type of Change

- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] Feature / Enhancement (non-breaking change introducing new capability)
- [ ] Documentation update
- [ ] Release engineering / CI update

## Verification & Testing

Describe how these changes were tested:
- [ ] `go test -count=1 ./...` passed cleanly
- [ ] `go test -race ./...` passed with zero race conditions
- [ ] `go vet ./...` passed without warnings
- [ ] `gofmt -l .` returned zero unformatted files

## Security & Principles Check

- [ ] Does NOT expose or log unredacted credentials or query secrets.
- [ ] Does NOT bypass TLS certificate verification (`InsecureSkipVerify: false`).
- [ ] Does NOT perform secondary DNS lookups during TCP or HTTP probing.
- [ ] Does NOT require Azure authentication, Azure CLI, or Azure SDK permissions.
