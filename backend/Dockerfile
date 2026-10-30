# Multi-stage build for High-Performance Go SIEM Server
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/bin/siem-server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/bin/siem-agent ./cmd/agent

# Minimal, secure production container
FROM alpine:3.21

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/bin/siem-server /app/siem-server
COPY --from=builder /app/bin/siem-agent /app/siem-agent

ENV PORT=8000
ENV DATABASE_DIR=/app/siem_data

VOLUME ["/app/siem_data"]

EXPOSE 8000

CMD ["/app/siem-server"]
