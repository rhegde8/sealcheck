# Interfaces

## Policy v1

Policies are JSON, parsed with unknown-field rejection. See `lab/policy.json` for a complete example.

| Field | Contract |
|---|---|
| `version`, `name` | Version `1` and a nonempty profile name. |
| `timeout_ms` | Per-probe deadline, 10–30000 ms. |
| `observation_ms` | External observation grace period, 0–30000 ms. |
| `max_age_seconds` | Maximum age when consuming a report, 1–86400 seconds. |
| `min_deny_evidence` | Optional. `explicit-denial` (the default) or `non-receipt`. See [evidence grades](#evidence-grades). `non-receipt` requires `observation_ms` of at least 100. |
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

### HTTP probe templates and credentials

HTTP probes accept optional fields. Each is omitted from the policy hash when unset, so existing policies keep their hashes.

| Field | Contract |
|---|---|
| `zone` | Required when a URL uses `{canary_host}`. |
| `headers` | Up to 16 extra request headers. Names match `[A-Za-z0-9-]{1,64}`. Framing and connection headers, `Authorization`, `Cookie`, and `Proxy-*` are rejected; credentials belong in `credential_env`. Values are at most 1,024 bytes. |
| `method` | `GET`, `HEAD`, `POST`, or `PUT`; only for a templated `proxy-fetch`. |
| `credential_env` | Names a variable the runner reads **inside the sandbox**, so the probe uses the workload's own identity. If it is unset, the result is `unsupported` (INCONCLUSIVE, or SKIP when optional), never an anonymous attempt. The value never appears in results, errors, or reports. It cannot name a witness token variable. |
| `credential_header` | Header that carries the credential. Defaults to `Authorization`, or `Proxy-Authorization` for `http-proxy`. For an HTTPS `http-proxy` target, `Proxy-Authorization` goes only on the CONNECT request. |

| Placeholder | Expands to | Allowed in |
|---|---|---|
| `{canary_host}` | `sc1.<run>.<probe>.<token>.<zone>` | The entire host of an `http` or `http-proxy` target, or of a `proxy-fetch` callback |
| `{callback}` | The query-escaped callback URL, including its `canary` parameter | `proxy-fetch` target or header values |
| `{canary}` | The canary string | `proxy-fetch` target or header values |

A `proxy-fetch` probe is *templated* when its target contains a placeholder or a header contains `{callback}`. A templated probe must place `{callback}` itself, and the runner adds no `url` or `canary` parameters. Templates let a policy describe the handler under test, such as a remote-repository endpoint and its injection point, without this repository shipping vendor request shapes. Unknown placeholders and stray braces are rejected.

A `{canary_host}` probe also accepts DNS receipts for its canary. Resolving a denied name already delivers its labels to the zone's authoritative receiver, so a proxy that resolves before applying its policy FAILs even when it returns 403. Production use needs the zone delegated to the receiver.

HTTP probes do not follow redirects themselves. The package-proxy fixture follows controlled upstream redirects to test that boundary. TLS uses normal platform certificate verification; there is no insecure-skip-verification option. Direct probes have explicit proxy isolation; inherited `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` do not silently change their transport.

Witness fields are `id`, `url`, `token_env`, and `role` (`receiver` or `boundary`). The URL is a management base URL. The credential value exists only in the controller environment variable named by `token_env`. `registry_url` optionally enables the controller's independent registry reader on a receiver witness. Management redirects are rejected to avoid forwarding credentials.

## Witness management API

All management requests carry `Authorization: Bearer <token>`.

| Request | Purpose |
|---|---|
| `POST /runs` | Body `{"run_id", "expires_at"}`. Registers a run so the witness retains its evidence. `expires_at` must fall within the next two hours. Idempotent; re-registration can extend but never shorten retention. Returns 204, 400 for an invalid body, or 503 when 1,024 runs are active. |
| `GET /health` | Instance ID and time; never reports events. |
| `GET /events?run_id=` | That run's events and per-run overflow flag. |

`check` registers every run before launching probes. Witnesses discard evidence for unregistered runs, so a manual `plan` → `probe` flow collects no live witness evidence unless its run is registered first.

## Evidence grades

By default, a `deny` probe passes only on an explicit kernel `EACCES`/`EPERM` or a boundary-witness denial. Many correctly sealed sandboxes instead fail ambiguously: `ENETUNREACH`, `EHOSTUNREACH`, a refused connection, or a silent drop. With `min_deny_evidence: non-receipt`, a direct deny probe (`tcp`, `udp`, `dns`, `dns-system`, `http`) can also pass with grade `non-receipt` when all of the following hold:

- The runner attempted the probe (outcome `error` or `sent`) and no witness observed its canary.
- A **reference run** delivered the same probe, with an identical definition but its own run ID and canary, from an unrestricted context during the same check.
- The witness that recorded the reference delivery is the same instance that watched the measured run, with no overflow.

The reference proves each target was live and correctly addressed, so an absent canary means something. Proxy kinds never pass on non-receipt, because a wrong handler path or proxy address looks the same as a denial. Leak precedence is unchanged: any receipt still FAILs.

`check` and `watch` accept `--reference-launcher` as a JSON argv array, for example `'["docker","exec","-i","reference","sealcheck","probe"]'`. The reference runs after the measured launcher, inside the measured plan's deadline, and receives only the eligible probes. A failed reference leaves the affected findings INCONCLUSIVE.

A finding's `grade` is `non-receipt` only for that kind of pass. An absent grade on a deny PASS means an explicit denial, so earlier reports verify unchanged. The report's `reference` holds the reference plan, its runner results, and each witness's snapshot for the reference run. The verifier recomputes grades from that evidence, so a grade cannot be added or removed after signing.

## Command stages

`check` is the recommended orchestrator. It checks witness health, constructs a fresh plan, registers the run with each witness, passes the plan to the configured launcher over stdin, parses results from stdout, waits for observations, performs optional registry readbacks, collects witnesses, evaluates, and signs.

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
