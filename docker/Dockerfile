# ============================================================
# Stage 1: Build the picoclaw binary
# ============================================================
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN make build

# ============================================================
# Stage 2: Minimal runtime image
# ============================================================
FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata curl

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:18790/health || exit 1

# Copy binary and first-run entrypoint (same as release image).
COPY --from=builder /src/build/picoclaw /usr/local/bin/picoclaw

# Copy the canonical original SOUL.md to a non-PVC path so the init
# container can prepend it to the per-employee Role prompt when first
# writing the workspace SOUL.md. The PVC mount at /root/.picoclaw hides
# any SOUL.md baked under the workspace path, so we expose it here too.
COPY workspace/SOUL.md /opt/picoclaw/SOUL.md.original

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
