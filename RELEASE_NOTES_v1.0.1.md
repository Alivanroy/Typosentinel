# TypoSentinel v1.0.1

## Highlights
- Webhook signature verification hardened with replay protection
- Distributed rate limiting with Redis backend (env or config driven)
- Prometheus metrics integration and `/metrics` endpoint (plus `/metrics.json`)
- SSE stream endpoint `/v1/stream` for real‑time monitoring
- Vulnerability database refresh scheduler (configurable)
- Slack and SMTP email notifications for high‑risk analysis
- `/ready` enhanced with Redis connectivity and webhook provider readiness
- Loader reads provider secrets from config/env for readiness and metrics

## Installation
- Binaries and artifacts attached to the release (see Assets)
- Docker image available after CI publish

## Changes Since v1.0.0
- Internal metrics: request counters, latency histograms, rate limit hits, Redis connectivity, webhook signature failure/replay counters
- API: input validators for Go/Maven; metrics/stream endpoints; readiness checks
- Middleware: local and Redis limiters; instrumentation
- Webhook: replay protection, signature failure metrics, provider loaders

## Known Notes
- Redis DSN preferred from internal config; fallback to `RATE_LIMIT_REDIS_URL`
- Provider secrets can be set via `webhooks.providers.<provider>.secret/token` in config or env

## How to Upgrade
- Update configuration for Redis and provider secrets as needed
- Deploy and validate `/ready` and `/metrics` endpoints

---
See CHANGELOG.md for full details.
