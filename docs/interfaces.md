# Interfaces

## Policy v1

Policies are JSON, parsed with unknown-field rejection. See `lab/policy.json` for a complete example.

| Field | Contract |
|---|---|
| `version`, `name` | Version `1` and a nonempty profile name. |
| `timeout_ms` | Per-probe deadline, 10–30000 ms. |
| `observation_ms` | External observation grace period, 0–30000 ms. |
| `max_age_seconds` | Maximum age when consuming a report, 1–86400 seconds. |
| `probes` | 1–128 probes; at least one required. |
| `witnesses` | 1–8 externally managed witnesses. |

Probe IDs use lowercase letters, digits, and hyphens, with a maximum of 32 characters. IDs must be unique. `expect` is `allow` or `deny`. `optional` defaults to false. Optional missing coverage is SKIP, never an implicit pass. A demonstrated forbidden operation always fails, including optional probes.

| Kind | Inputs and behavior |
|---|---|
| `tcp` | Literal-IP `target` with port; optional `network` is `4` or `6`. Establish a connection and write a canary. |
| `udp` | Literal-IP `target` with port; write a canary without assuming an acknowledgement. |
| `dns` | Literal-IP resolver `target` with port and controlled `zone`; UDP A query carrying a canary in labels. |
| `dns-system` | Controlled `zone`; empty `target`. Go's resolver reads system resolver configuration and submits canary queries. Native libc/NSS behavior is not measured. |
| `http` | HTTP(S) `target`; GET with `canary` query parameter. Ignores environment proxy settings. |
| `http-proxy` | HTTP(S) `target` plus explicit `proxy`; normal Go HTTP transport, including HTTPS CONNECT when supported by the configured proxy. |
| `proxy-fetch` | Synthetic fixture `target` plus controlled `callback`; the fixture receives a `url` parameter. This is not a generic Artifactory adapter. |
| `registry-upload` | Controlled fixture `target`, typically `/registry`; PUT the synthetic body under the run/probe path. |

HTTP probes do not follow redirects themselves. The package-proxy fixture follows controlled upstream redirects to test that boundary. TLS uses normal platform certificate verification; there is no insecure-skip-verification option. Direct probes have explicit proxy isolation; inherited `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` do not silently change their transport.

Witness fields are `id`, `url`, `token_env`, and `role` (`receiver` or `boundary`). The URL is a management base URL. The credential value exists only in the controller environment variable named by `token_env`. `registry_url` optionally enables the controller's independent registry reader on a receiver witness. Management redirects are rejected to avoid forwarding credentials.

## Command stages

`check` is the recommended orchestrator. It checks witness health, constructs a fresh plan, passes the plan to the configured launcher over stdin, parses results from stdout, waits for observations, performs optional registry readbacks, collects witnesses, evaluates, and signs.

`plan` creates a plan JSON independently. `probe --plan - --out -` reads stdin and writes JSON to stdout. A probe execution can contain errors yet exit 0 because it successfully produced observations; evaluation is external.

`evaluate` takes `--plan`, `--results`, `--witnesses`, `--private-key`, and `--out`. Its witness input is an array of the `Witness` records embedded in a report. It must come from a trusted controller, including pre-run health times, instance continuity, and post-run snapshots. The command does not authenticate arbitrary imported witness files. The Go `Check` function exposes the orchestrated version to harness adapters.

`watch` runs `check` repeatedly. Checks never overlap. It stops on a non-PASS verdict, an overdue iteration, or interruption. `--count` is useful for bounded integration tests. `diff.json` compares consecutive probe verdicts; `schedule.json` records the next due time. These convenience files are unsigned; use signed bundles for authoritative gate decisions.

## Report and bundle v1

The Go types in `internal/seal/model.go` are the authoritative schema. A report contains:

- Format and tool versions, controller issuance time, and the full plan.
- Plan run ID, nonce, per-probe canaries, creation/deadline times, policy, and SHA-256 of its normalized typed JSON representation. Whitespace and object-key order in the input do not affect the policy hash.
- Runner identity and per-probe timestamps, outcomes, and HTTP status when available.
- Witness health, observation windows, instance IDs, receipt arrays, and verified registry readbacks.
- Findings with verdicts, reasons, evidence references, global errors, and explicit limitations.

Evidence reference strings such as `witnesses/receiver/events/0` are logical identifiers within the embedded report, not filesystem paths or JSON pointers. Ordinary errors are reduced to fixed descriptions so network error strings cannot accidentally serialize proxy credentials.

The bundle has `version`, `key_id`, `payload` (base64 report bytes), and `signature` (base64 Ed25519 signature). The signature input is `sealcheck/report/v1`, a NUL byte, then the exact report bytes. The key ID is SHA-256 of the raw Ed25519 public key. Public/private key files use PKIX/PKCS#8 PEM respectively.

`verify` requires `--public-key`, `--bundle`, `--run-id`, and `--policy` for current use. Its exit code reflects the verified verdict. `--historical` verifies archived integrity and consistency only; its success is not an authorization to start an evaluation. Never use that mode as a pre-flight gate.

## Compatibility

This is a v0.1 interface. Format changes require a new version rather than silently changing signed semantics. New probes must define required evidence and include negative controls and an independent delivery test before becoming supported coverage. The CLI rejects unknown probe kinds and unknown policy fields with exit 2.
