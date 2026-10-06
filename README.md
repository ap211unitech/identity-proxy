# Identity-Aware mTLS Reverse Proxy (Rust)

A small reverse proxy that sits in front of an existing HTTP API, authenticates non-human
identities (NHIs) with mTLS, authorizes them against a YAML policy, writes a structured
audit event for every request, and forwards allowed traffic to the upstream.

```
Client --TLS/mTLS--> [ Intercept -> Identify -> Authorize -> Observe ] --HTTP--> Upstream API
```

## Code layout

| File                                            | Purpose                                                                          |
| ----------------------------------------------- | -------------------------------------------------------------------------------- |
| `src/main.rs`                                   | Startup, accept loop, TLS handshake, graceful shutdown, health endpoints         |
| `src/tls.rs`                                    | Builds the rustls server config; hot-reloads the trusted CA bundle               |
| `src/identity.rs`                               | Parses the verified client cert, extracts/validates the identity (SPIFFE)        |
| `src/policy.rs`                                 | YAML policy engine, path matching and path-safety checks                         |
| `src/proxy.rs`                                  | Request pipeline: loop check, authz, limits, header rewriting, forwarding, audit |
| `src/audit.rs`, `src/config.rs`                 | JSON audit/log output; env-var configuration                                     |
| `examples/mock_upstream.rs`                     | Tiny upstream that echoes what the proxy sent (for testing)                      |
| `scripts/gen-certs.sh`, `scripts/smoke-test.sh` | Test certificates; end-to-end checks                                             |

## Build, run, test

Needs Rust >= 1.85 (tested with 1.91) and `openssl`/`curl` for the scripts.

```bash
cargo test                       # unit tests (policy matching, SPIFFE validation)
./scripts/gen-certs.sh           # test CAs + client certs into ./certs (git-ignored)

# terminal 1: mock upstream on 127.0.0.1:8080
cargo run --release --example mock_upstream

# terminal 2: the proxy on https://localhost:8443
UPSTREAM_URL=http://127.0.0.1:8080 LISTEN_ADDR=127.0.0.1:8443 ADMIN_ADDR=127.0.0.1:8081 \
TLS_CERT=certs/server.pem TLS_KEY=certs/server.key CLIENT_CA=certs/client-ca.pem \
POLICY_FILE=config/policy.yaml cargo run --release

# terminal 3: 16 end-to-end checks (allow/deny, TLS-layer vs app-layer rejections, limits, loop)
./scripts/smoke-test.sh
```

### Container image

```bash
docker build -t identity-proxy .

# upstream running on the host (listening on all interfaces so the container can reach it)
MOCK_ADDR=0.0.0.0:8080 cargo run --release --example mock_upstream &

docker run --rm -p 8443:8443 -p 8081:8081 \
  --add-host host.docker.internal:host-gateway \
  -e UPSTREAM_URL=http://host.docker.internal:8080 \
  -e POLICY_FILE=/etc/policy/policy.yaml \
  -v "$PWD/certs:/etc/proxy:ro" \
  -v "$PWD/config:/etc/policy:ro" \
  identity-proxy

curl --cacert certs/ca.pem --cert certs/client-reporting.pem --key certs/client-reporting.key \
  https://localhost:8443/reports/q1
```

### Configuration (environment variables)

| Variable                | Default                       | Meaning                                           |
| ----------------------- | ----------------------------- | ------------------------------------------------- |
| `UPSTREAM_URL`          | `http://backend:8080`         | Upstream (plain `http://host:port`)               |
| `LISTEN_ADDR`           | `0.0.0.0:8443`                | mTLS listener                                     |
| `ADMIN_ADDR`            | `0.0.0.0:8081`                | Plain-HTTP `/healthz`, `/readyz`                  |
| `TLS_CERT`, `TLS_KEY`   | `/etc/proxy/server.{pem,key}` | Server certificate + key                          |
| `CLIENT_CA`             | `/etc/proxy/client-ca.pem`    | Trusted CA bundle for client certs (hot-reloaded) |
| `POLICY_FILE`           | `/etc/proxy/policy.yaml`      | Authorization policy                              |
| `MAX_BODY_BYTES`        | `1048576`                     | Request body limit                                |
| `UPSTREAM_TIMEOUT_SECS` | `10`                          | Upstream timeout                                  |
| `MAX_CONCURRENCY`       | `1024`                        | Max in-flight requests                            |
| `RELOAD_INTERVAL_SECS`  | `5`                           | Trust-store poll interval                         |

## Resilience

| Capability         | Behavior                                                                                                                                     |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Upstream timeout   | `UPSTREAM_TIMEOUT_SECS`, returns 504                                                                                                         |
| Request body limit | `MAX_BODY_BYTES`, returns 413                                                                                                                |
| Concurrency limit  | Semaphore, excess requests are shed with 503 (counted until response headers are sent)                                                       |
| Graceful shutdown  | On SIGTERM/Ctrl-C: `/readyz` -> 503, stop accepting, HTTP/2 GOAWAY / `Connection: close`, drain in-flight requests (max 30 s)                |
| Health / readiness | `GET :8081/healthz` (liveness), `GET :8081/readyz` (fails while draining); separate plain-HTTP port so orchestrators don't need client certs |

## Performance

Tested with:

```
oha -z 10s -c 200 --no-tui \
  --cacert certs/ca.pem \
  --cert certs/client-reporting.pem --key certs/client-reporting.key \
  https://localhost:8443/reports/q1
```

| Scenario (c=200, 100,000 requests, keep-alive) | Req/s       | p50       | p95        | p99        | Errors |
| ---------------------------------------------- | ----------- | --------- | ---------- | ---------- | ------ |
| Direct to upstream (HTTP)                      | 101,880     | 2 ms      | 2 ms       | 7 ms       | 0%     |
| Through proxy (mTLS, TLS 1.3)                  | 81,474      | 10 ms     | 14 ms      | 19 ms      | 0%     |
| **Added by proxy**                             | **-20,406** | **+8 ms** | **+12 ms** | **+12 ms** |        |

## Assumptions

- The proxy runs next to the upstream on a trusted network; the upstream only accepts traffic from the proxy,
  so it can trust `X-Authenticated-Identity`.
- Clients are workloads with certs from a private CA (SPIFFE-style IDs). Certificate revocation (CRL/OCSP) is
  not checked; short-lived certs plus trust rotation are the expected control.
- Policy changes are rare and deployed with the service.
