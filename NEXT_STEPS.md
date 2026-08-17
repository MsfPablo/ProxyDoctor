# Next Steps

Follow-up work intentionally outside the current delivery scope.

## High priority

- Add CI jobs that run `gofmt`, `go test ./...` and `go vet ./...` on every pull request.
- Add timeout and cancellation tests across all built-in checks.
- Add end-to-end tests for the HTTP server API (`/api/diagnose`, `/api/local-proxy/*`).
- Add PAC file support (#45): serve `http://127.0.0.1:8081/proxy.pac` from the local proxy so users can configure their whole system in one step.

## Open feature requests

| Issue | Feature | Difficulty |
|---|---|---|
| #47 | Geolocation & exit node identity | Easy |
| #48 | IP reputation & blacklist check | Easy-Medium |
| #49 | HTTP header leak detection | Easy |
| #50 | Speed & latency benchmarking | Easy-Medium |
| #51 | Subscription link import & batch testing | Medium |
| #52 | Proxy protocol auto-detection | Easy |
| #53 | DNS-over-HTTPS / DNS-over-TLS verification | Medium |
| #54 | Connection stability / long-lived test | Easy-Medium |
| #55 | Kill switch / reconnection leak test | Medium-Hard |

## Medium priority

- Add golden-file tests for text, JSON, Markdown and HTML output.
- Add structured logging around adapter creation and check execution.
- Add configuration examples for authenticated proxies.
- Improve documentation for common corporate proxy troubleshooting scenarios.

## Recently completed

- **DNS leak detection** (`core/checks/dns_leak/`): compares DNS through proxy vs direct, detects bypass. Closes #5.
- **WebRTC leak detection** (`core/checks/webrtc_leak/`): STUN probing via UDP, detects IP exposure through ICE. Closes #6.
- **Hermetic proxy integration tests** (`internal/testproxy` + `core/adapters/adapters_integration_test.go` + `core/plugins/localproxy/plugin_test.go`). Closes #35.
- **Local forward proxy plugin** (`core/plugins/localproxy/`). Closes #44.
- **Installation methods**: `go install`, Homebrew cask, release binaries. Closes #21.

## Documentation rules

- `ARCHITECTURE.md` describes only implemented behavior.
- Planned or speculative work belongs in this file.

## Issue hygiene

Every open issue should point to at least one concrete starting point in the codebase. Keep `docs/ISSUE_STARTING_POINTS.md` updated whenever roadmap issues are added, closed, or substantially rewritten.
