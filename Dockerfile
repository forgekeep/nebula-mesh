# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.3

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.versionStr=${VERSION}" \
        -o /out/nebula-mgmt ./cmd/nebula-mgmt

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S -g 10001 nebula && \
    adduser  -S -u 10001 -G nebula nebula && \
    mkdir -p /var/lib/nebula-mgmt /etc/nebula-mgmt && \
    chown -R nebula:nebula /var/lib/nebula-mgmt /etc/nebula-mgmt

COPY --from=build /out/nebula-mgmt /usr/local/bin/nebula-mgmt

USER nebula:nebula
WORKDIR /var/lib/nebula-mgmt

EXPOSE 8080
VOLUME ["/var/lib/nebula-mgmt", "/etc/nebula-mgmt"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/nebula-mgmt"]
# Containers bind 0.0.0.0 and terminate TLS at the ingress/reverse proxy, so the
# app layer serves plaintext to the container network by design. --insecure-http
# opts past the loopback-only guard (#179); put TLS in front at your ingress.
CMD ["serve", "--config", "/etc/nebula-mgmt/server.yml", "--insecure-http"]
