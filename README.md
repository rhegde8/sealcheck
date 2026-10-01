# Sealcheck

**Verify a sandbox's egress policy from the workload's security context, with signed evidence.**

Sealcheck runs synthetic probes inside a sandbox, correlates their results with controlled receivers outside the boundary, and signs a report from an external controller. It is an early security engineering tool, with a reproducible portable demo and a Linux isolation lab.

```mermaid
flowchart LR
    C[Trusted controller and signing key] -->|Launch through workload harness| R
    subgraph Sandbox boundary
        R[Probe runner with workload restrictions]
    end
    R -->|Direct canaries| W[Controlled receivers]
    R -->|Package requests| P[Package proxy]
    P -->|Upstream canaries| W
    C -->|Management evidence| W
    C -->|Boundary evidence| P
```

Reports answer **what was observed for this policy, probe set, identity, and time window**. They do not prove that every possible channel is closed. The project does not implement hardware remote attestation.

## Try the portable demo

Requirements: Go 1.24 or later. The core uses only the Go standard library. The demo opens loopback listeners; it needs no Docker or Internet access.

```sh
make test
make build
./bin/sealcheck demo --out out/demo
```

The demonstration produces:

1. **PASS:** the package proxy fixture denies forwarding and uploads while allowed controls work.
2. **FAIL:** a deliberately leaky fixture forwards canaries, follows redirects, and accepts a registry upload that an external reader retrieves.
3. **PASS:** restoring the proxy policy closes those tested paths.

The demo deliberately **allows its direct TCP, UDP, and DNS controls**. It demonstrates evidence collection and proxy behavior; it does not create an OS sandbox. Use the Linux lab for actual network isolation.

Each run gets `plan.json`, `results.json`, `witnesses.json`, `report.json`, `bundle.json`, and `summary.txt`. The signed bundle embeds all report evidence. `demo.json` identifies the three runs; private demo keys are ignored by Git.

Verify an archived demo report with an independently obtained public key:

```sh
./bin/sealcheck verify \
  --bundle out/demo/baseline/REPLACE_WITH_RUN_ID/bundle.json \
  --public-key out/demo/demo.pub.pem --historical
```

Historical verification checks the signature and internal consistency. To authorize a current evaluation, omit `--historical` and supply `--run-id`, `--policy`, and optionally `--max-age`. Obtain the expected run ID from the trusted controller, not from an untrusted report.

## Verdicts

| Verdict | Exit | Meaning |
|---|---:|---|
| PASS | 0 | Every required check has sufficient evidence that the tested policy held. |
| FAIL | 1 | A forbidden operation succeeded or an independent witness observed its canary. |
| INCONCLUSIVE | 2 | Required evidence is missing, a control failed, or execution was incomplete. Configuration errors also exit 2. |

A UDP send, a timeout, or an HTTP 403 does not establish denial by default. Kernel `EACCES`/`EPERM` and configured boundary witnesses can corroborate denials. A correlated external receipt takes precedence over an error or denial reported by the runner. Missing witnesses, restarted witnesses, and event-buffer overflow prevent PASS. Optional missing coverage is reported as SKIP; optional probes that demonstrate a leak still fail the run.

Sandboxes that fail ambiguously (unreachable networks, silent drops) can opt into `min_deny_evidence: non-receipt`. Direct deny probes can then pass with grade `non-receipt` when an unrestricted reference context, supplied with `--reference-launcher`, delivers the same probes during the check. This proves each target was live. Proxy probes still need explicit denials. See [evidence grades](docs/interfaces.md#evidence-grades).

The `probe` command only emits observations; its exit code is not an evaluation verdict. Use `check`, `evaluate`, or current-context `verify` as the gate.

## Linux isolation lab

Requirements: Docker with Compose and Buildx, IPv6-capable Linux container networking, Go, `curl`, and `openssl`. Docker Desktop and Colima provide a Linux VM on macOS. The lab reserves `172.30.56.0/24`, `172.30.57.0/24`, `fd53:ea1:56::/64`, and loopback ports 18080–18082.

```sh
make lab
```

The script builds the container image, creates an external signing key, runs baseline → proxy leak → remediation → direct IPv4/IPv6 leaks → restoration → non-receipt grading under `unreachable` routes, and removes the containers. Reports remain under `out/lab-TIMESTAMP/`.

The sandbox's trusted initializer configures Linux `prohibit` routes and blocks management port 8081. The workload and runner then run as UID 10001 with capabilities dropped and `no_new_privs`. A `prohibit` route supplies explicit kernel denial evidence; silent packet dropping would produce INCONCLUSIVE without additional telemetry. The signing key and witness tokens stay on the controller side.

The sandbox joins only the internal data network. The trusted receiver and proxy also join a separate management bridge so the controller can reach their loopback-published ports. The sandbox's controlled resolver configuration is mounted read-only, bypassing Docker's DNS stub.

The Docker lab is a reference integration. Adapting it to another harness requires matching that harness's actual namespace, credentials, syscall filters, and process restrictions. `docker exec` by itself does not recreate a process's self-applied Landlock or seccomp restrictions.

### macOS with Colima

On an Apple Silicon Mac with Homebrew, install the VM runtime and Docker tools:

```sh
brew install colima docker docker-compose docker-buildx
```

Merge `cliPluginsExtraDirs` into `~/.docker/config.json`, preserving existing settings. For the standard Apple Silicon Homebrew prefix:

```json
{
  "cliPluginsExtraDirs": ["/opt/homebrew/lib/docker/cli-plugins"]
}
```

For another Homebrew prefix, use its `lib/docker/cli-plugins` directory. See the [Homebrew Compose instructions](https://formulae.brew.sh/formula/docker-compose).

Start a dedicated native ARM64 VM and run the lab with its Docker context:

```sh
colima start sealcheck --runtime docker --vm-type vz \
  --arch aarch64 --cpus 2 --memory 4 --disk 30 --activate=false
docker --context colima-sealcheck info
docker compose version
docker buildx version
DOCKER_CONTEXT=colima-sealcheck make lab
colima stop sealcheck
```

Start it again when needed with `colima start sealcheck --activate=false`. This setup uses Colima on demand and selects the project context explicitly. See [Colima profiles](https://colima.run/docs/profiles/).

The full lab was validated locally on 2026-10-01 with **PASS → FAIL → PASS → FAIL → PASS → INCONCLUSIVE → PASS (non-receipt) → FAIL → PASS**, including direct IPv4/IPv6 leaks, proxy-side DNS resolution, and all nine historical signature checks. Tested versions and evidence details are recorded in [the coverage document](docs/coverage.md#local-linux-lab-validation).

## Use with a sandbox

Start controlled witnesses outside the sandbox, set their management tokens on the controller, and create a policy using [lab/policy.json](lab/policy.json) as the example. Then:

```sh
./bin/sealcheck keygen \
  --private-key out/controller.key.pem --public-key out/controller.pub.pem

./bin/sealcheck check --policy policy.json \
  --private-key out/controller.key.pem --out out/checks -- \
  your-trusted-launcher sealcheck probe
```

The launcher receives the run plan on stdin and must return runner JSON on stdout. Sealcheck never shell-interpolates the plan. It removes the configured witness-token variables from the launcher's environment. The launcher must supply workload credentials deliberately and keep the controller's files and management services outside the workload's reach.

For periodic checks:

```sh
./bin/sealcheck watch --policy policy.json \
  --private-key out/controller.key.pem --out out/watch \
  --interval 5m -- your-trusted-launcher sealcheck probe
```

`watch` writes verdict diffs and the next due time, and exits on FAIL, INCONCLUSIVE, an overdue iteration, or interruption. Your evaluation supervisor must stop the evaluation when that process exits unsuccessfully. An external supervisor must also detect a killed or stalled watcher; a process cannot attest its own continued liveness. Validate report age at consumption time.

For manual integrations, `plan`, `probe`, and `evaluate` expose the stages separately. Only feed `evaluate` witness files collected over a trusted external path. A signature cannot repair fabricated inputs. Run any command with `-h` for its flags.

## Coverage and project status

Implemented: TCP/UDP IPv4 and IPv6, direct and system-configured DNS canaries (including through QNAME-minimizing resolvers), direct HTTP(S), explicit HTTP forward proxy use, proxy-side resolution of canary hostnames, templated proxy-fetch probes with the workload's own credentials, synthetic package-proxy fetch/redirect fixtures, private registry upload/readback, signed reports, offline verification, pre-flight gates, and periodic checks.

The Terraform, Cargo, and Ansible routes in this repository are **synthetic fixture routes**. To probe a real proxy, describe its handler with a [templated `proxy-fetch`](docs/interfaces.md#http-probe-templates-and-credentials) and supply the workload's credential through `credential_env`. They are not Artifactory exploit paths, and passing them does not attest an Artifactory deployment. Real Artifactory adapters require version-specific reproductions. Timing/certificate oracles, DoH/DoT, QUIC, production registry protocols, and native libc/NSS resolver behavior are not claimed as covered.

- [Threat model and trust boundaries](docs/threat-model.md)
- [Policy, commands, and report contract](docs/interfaces.md)
- [Coverage and validation matrix](docs/coverage.md)
- [Research and expansion criteria](docs/research.md)

## Development

```sh
make test  # race detector and integration tests using loopback sockets
make vet
```

CI runs tests, the portable demo, and the Linux lab. It uploads report evidence and public keys, excluding private signing keys. A successful workflow run is required before claiming the Linux lab has been validated on that runner.
