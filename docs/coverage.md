# Coverage and validation

| Channel or failure | Implemented measurement | Validation |
|---|---|---|
| TCP IPv4/IPv6 | Connection plus synthetic canary write | Portable TCP control; IPv6 regression; Linux leak/remediation profile |
| UDP IPv4/IPv6 | Three synthetic datagrams plus independent receipt | UDP integration; no-ack regression; Linux profile |
| Direct DNS | Synthetic labels at controlled authoritative server | Authoritative NODATA receiver and correlated receipt |
| System-configured DNS | Go resolver using sandbox resolver configuration | Negative-answer integration and Linux profile |
| DNS via minimizing recursive resolver | Receiver answers in-zone names with authoritative NODATA, so RFC 9156 resolvers continue to the full canary name instead of stopping at an NXDOMAIN cut | Label-by-label recursive stub regression |
| DNS tunneling primitive | Synthetic information carried in query labels | Demonstrates query-label delivery, not arbitrary tunneling throughput |
| Direct HTTP(S) | Explicit direct transport | Proxy-environment regression; Linux direct HTTP profile; normal TLS verification |
| HTTP forward proxy | Explicit transport through selected proxy | Portable allow/deny fixture |
| HTTPS CONNECT | Go transport support | Fixture rejects CONNECT; no dedicated CONNECT success fixture yet |
| Package proxy SSRF behavior | Terraform/Cargo/Ansible-named synthetic handlers | Deny/forward pairs and redirect revalidation |
| Forward then fail | Receiver logs a canary before returning 500 | Regression verifies FAIL despite local error |
| Registry upload | Synthetic PUT and external GET of exact bytes | Demo confirms external readback; not a production registry protocol |
| Missing receiver / overflow / restart | Health, instance continuity, and per-run overflow | Evaluator prevents PASS |
| Canary flood for unregistered runs | Witnesses retain only controller-registered runs | Regression keeps PASS after 10,001 foreign canaries |
| Report tampering / wrong key / wrong run / wrong policy | Pinned-key signature and context verification | Cryptographic regression suite |
| Stale observations / reports | Observation and consumption windows | Regression suite |
| Periodic drift | Serialized checks, diffs, deadline and exit handling | CLI checks; external supervisor required for liveness |

## Reproduction levels

1. **Unit and loopback integration:** `go test -race ./...`. These exercise sockets, observers, proxy fixtures, verdict rules, and signed evidence.
2. **Portable fixture demonstration:** `sealcheck demo`. Transport controls are intentionally reachable. This is not an OS isolation test.
3. **Linux container lab:** `make lab`. Real route prohibitions, unprivileged execution, and controlled network leaks. Requires Docker/Compose/Buildx and IPv6 networking.
4. **Vendor reproduction:** not implemented or claimed. A successful synthetic fixture test is not evidence about an Artifactory release.

Docker was unavailable in the initial development environment. The complete Linux lab has since run successfully in the local Colima environment described below. GitHub's Linux CI remains an independent gate; local validation does not establish that a workflow has passed on its runner.

## Local Linux lab validation

Validated on 2026-10-01 with `DOCKER_CONTEXT=colima-sealcheck make lab`. The host was macOS 27.0 on Apple Silicon. The Colima VM used native ARM64, Apple's VZ backend, 2 CPUs, 4 GiB RAM, and a 30 GiB data disk, running Ubuntu 24.04.4 LTS with Linux kernel `6.8.0-117-generic`.

| Tool | Tested version |
|---|---|
| Colima | 0.10.3 |
| Lima | 2.2.0 |
| Docker CLI | 29.8.2 |
| Docker Engine in VM | 29.5.2 |
| Docker Compose | 5.5.1 |
| Docker Buildx | 0.37.2 |
| Host Go | 1.27.1 |

| Phase | Observed verdict |
|---|---|
| Baseline | PASS |
| Proxy leak | FAIL |
| Remediated proxy | PASS |
| Direct IPv4/IPv6 leaks | FAIL |
| Restored routes | PASS |

The direct-leak report independently recorded forbidden canary delivery for TCP and UDP over both IPv4 and IPv6, direct and system-configured DNS, and direct HTTP. Every phase reported UID/EUID/GID 10001, effective capabilities `0000000000000000`, `NoNewPrivs: 1`, and seccomp mode 2; these remain runner-reported identity observations.

All five bundles passed `sealcheck verify --historical` with the controller's separately generated public key. Historical verification establishes signature validity and evidence consistency; it does not authorize a current evaluation. Containers and lab networks were removed, and Colima is run on demand. Reports and keys are retained locally under `out/lab-20261001T044855Z/`, which is ignored by Git.

The first executions exposed three lab startup issues, now fixed: protocol-name lookup in the minimal Debian image, writes to the read-only resolver file, and host port publishing on internal-only witness networks. The initializer uses TCP protocol number 6, Compose mounts the controlled resolver configuration read-only, and trusted witnesses join a separate management bridge. The sandbox retains its internal data network and IPv4/IPv6 prohibit routes.

## Explicit omissions

Real Artifactory incident paths and authenticated package-manager flows, native libc/NSS resolver variations, DNS-over-TCP, DoH/DoT, QUIC semantics, custom TLS certificate/oracle experiments, timing channels, ICMP/raw sockets, Unix-socket brokers, cloud metadata probes, kernel escapes, and resistance to an actively compromised runner are outside v0.1 coverage. Unsupported required coverage must remain an error or INCONCLUSIVE, never a green check.

The profile does not enumerate every destination or port. IPv4 success or denial does not imply the same result for IPv6; each family needs an explicit probe. The lab uses a fixed controlled destination set and makes no Internet-wide reachability claim.
