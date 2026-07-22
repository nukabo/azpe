# Stage 1: Build static Linux binary
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Copy module files first for layer caching
COPY go.mod ./
RUN go mod download

# Copy source files
COPY . .

# Build static binary with CGO disabled and trimpath
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=v0.1.0-dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags "-s -w -X github.com/azpe/azpe/internal/version.Version=${VERSION} -X github.com/azpe/azpe/internal/version.Commit=${COMMIT} -X github.com/azpe/azpe/internal/version.Date=${DATE}" \
    -o /bin/azpe ./cmd/azpe

# Stage 2: Minimal non-root runtime container
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="AZPE" \
      org.opencontainers.image.description="Azure Private Endpoint Connectivity Diagnostic Utility" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/nukabo/azpe"

# Copy binary from builder
COPY --from=builder /bin/azpe /azpe

USER 65534:65534

ENTRYPOINT ["/azpe"]
