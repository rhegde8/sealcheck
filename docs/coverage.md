# Coverage and validation

| Channel or failure | Implemented measurement | Validation |
|---|---|---|
| TCP IPv4/IPv6 | Connection plus synthetic canary write | Portable TCP control; IPv6 regression; Linux leak/remediation profile |
| UDP IPv4/IPv6 | Synthetic datagram plus independent receipt | UDP integration; no-ack regression; Linux profile |
| Direct DNS | Synthetic labels at controlled authoritative server | NXDOMAIN receiver and correlated receipt |
| System-configured DNS | Go resolver using sandbox resolver configuration | NXDOMAIN integration and Linux profile |
| DNS tunneling primitive | Synthetic information carried in query labels | Demonstrates query-label delivery, not arbitrary tunneling throughput |
| Direct HTTP(S) | Explicit direct transport | Proxy-environment regression; Linux direct HTTP profile; normal TLS verification |
| HTTP forward proxy | Explicit transport through selected proxy | Portable allow/deny fixture |
| HTTPS CONNECT | Go transport support | Fixture rejects CONNECT; no dedicated CONNECT success fixture yet |
| Package proxy SSRF behavior | Terraform/Cargo/Ansible-named synthetic handlers | Deny/forward pairs and redirect revalidation |
| Forward then fail | Receiver logs a canary before returning 500 | Regression verifies FAIL despite local error |
| Registry upload | Synthetic PUT and external GET of exact bytes | Demo confirms external readback; not a production registry protocol |
| Missing receiver / overflow / restart | Health and instance continuity | Evaluator prevents PASS |
| Report tampering / wrong key / wrong run / wrong policy | Pinned-key signature and context verification | Cryptographic regression suite |
| Stale observations / reports | Observation and consumption windows | Regression suite |
| Periodic drift | Serialized checks, diffs, deadline and exit handling | CLI checks; external supervisor required for liveness |

## Reproduction levels

1. **Unit and loopback integration:** `go test -race ./...`. These exercise sockets, observers, proxy fixtures, verdict rules, and signed evidence.
2. **Portable fixture demonstration:** `sealcheck demo`. Transport controls are intentionally reachable. This is not an OS isolation test.
3. **Linux container lab:** `make lab`. Real route prohibitions, unprivileged execution, and controlled network leaks. Requires Docker/Compose and IPv6 networking.
4. **Vendor reproduction:** not implemented or claimed. A successful synthetic fixture test is not evidence about an Artifactory release.

Docker was unavailable in the initial development environment. The Linux lab's scripts and configuration were checked locally; execution is delegated to the included Linux CI gate or a user's Docker environment. Do not label that level validated until it has actually run successfully.

## Explicit omissions

Real Artifactory incident paths and authenticated package-manager flows, native libc/NSS resolver variations, DNS-over-TCP, DoH/DoT, QUIC semantics, custom TLS certificate/oracle experiments, timing channels, ICMP/raw sockets, Unix-socket brokers, cloud metadata probes, kernel escapes, and resistance to an actively compromised runner are outside v0.1 coverage. Unsupported required coverage must remain an error or INCONCLUSIVE, never a green check.

The profile does not enumerate every destination or port. IPv4 success or denial does not imply the same result for IPv6; each family needs an explicit probe. The lab uses a fixed controlled destination set and makes no Internet-wide reachability claim.
