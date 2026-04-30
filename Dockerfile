# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

# Install git (needed by go mod to fetch private/public deps)
RUN apk add --no-cache git

WORKDIR /app

# Copy source and initialise the module
COPY main.go .
COPY redis_pipeline.go .

# Bootstrap go.mod + go.sum, then tidy to pull all dependencies
RUN go mod init dealer && \
    go mod tidy

# Build a fully static binary (CGO disabled for scratch/alpine compatibility)
RUN CGO_ENABLED=0 GOOS=linux go build -o dealer .

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates is needed for any outbound TLS calls
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy only the compiled binary from the builder stage
COPY --from=builder /app/dealer .

# ── Ports ────────────────────────────────────────────────────────────────────
# 8000 → HTTP REST API (overridable via HTTP_PORT)
# 8080 → TCP agent listener  (overridable via TCP_PORT)
EXPOSE 8000 8080

# ── Environment defaults ─────────────────────────────────────────────────────
ENV HTTP_PORT=8000 \
    TCP_PORT=8080 \
    DB_URL="" \
    REDIS_HOST="my_rihno_redis" \
    REDIS_PORT="6379" \
    REDIS_PASS="" \
    REDIS_DB="0"

# ── Entrypoint ───────────────────────────────────────────────────────────────
ENTRYPOINT ["./dealer"]