# Handoff

Status as of 2026-10-01: tool 0.2.0. The policy and report formats are at version 1, but the 1.0 release has not been tagged. Read [threat-model.md](threat-model.md) and [interfaces.md](interfaces.md) before you change any evidence rules.

## What sealcheck is

The runner probes egress from inside a sandbox. Witnesses outside the sandbox record which synthetic canaries got through. A trusted controller collects that evidence, evaluates it, and signs a report: PASS, FAIL, or INCONCLUSIVE, with exit codes 0, 1, and 2.

Its distinguishing property: a FAIL comes from an independent receiver's evidence, not from the sandbox reporting on itself.

## Done

- **0.1:** TCP/UDP (IPv4 and IPv6), DNS (direct and system resolver), direct HTTP and forward-proxy HTTP probes. Synthetic package-proxy fixtures and registry upload/readback. Ed25519-signed reports and a verifier that recomputes the verdict. `check`, `watch`, the portable demo, and the Docker lab.
- **0.2 (PR #1):**
  - The DNS receiver answers NODATA instead of NXDOMAIN, so leaks through QNAME-minimizing resolvers are caught.
  - Witnesses keep evidence only for runs the controller registered (`POST /runs`), and overflow is per run. Floods can no longer block the gate.
  - Templated `proxy-fetch` with `{callback}`, `{canary}`, and `{canary_host}`. Workload credentials via `credential_env`, read inside the sandbox and never serialized.
  - Opt-in `non-receipt` evidence grade for direct deny probes, backed by a reference-context positive control (`--reference-launcher`).
- **Validated:** `go test -race`, fuzzing, the demo, GitHub CI, and the Colima lab (9 phases). The lab sequence is in [coverage.md](coverage.md#local-linux-lab-validation).

## Rules for changes

- Evidence must never be weakened. A leak always wins over a denial. Ambiguous errors and timeouts are not denials. Anything unsupported must yield INCONCLUSIVE or SKIP, never PASS.
- New probe kinds need required evidence, negative controls, and an independent delivery test (see `docs/interfaces.md` → Compatibility).
- New format fields use `omitempty`. Old bundles must still verify. Check against `out/lab-*/` bundles if you have them.
- Tests open loopback ports. In a restricted sandbox, allow local binding.

## TODO toward 1.0

Order matters. Item 1 changes signed formats, so do it before anything depends on them.

1. **Breaking cleanups before the format freeze**
   - [ ] Always emit a finding `grade`, including `explicit-denial`, instead of leaving it absent.
   - [ ] Give `verify` a distinct exit code for verification failure, separate from INCONCLUSIVE (both are 2 today).
   - [ ] Record controller-attested subject information in the signed report: the launcher argv plus an optional `--subject` (container ID, pod, image digest).
   - [ ] Pass an allowlist environment to the launcher instead of stripping a denylist (`internal/seal/controller.go`, `CommandLauncher`).
   - [ ] Decide on a DSSE/in-toto envelope. If adopted, it must land before 1.0.
2. **Deployable witnesses**
   - [ ] TLS for the management API, with a pinned certificate or CA. Bearer tokens over plain HTTP are lab-only.
   - [ ] A deployment guide covering zone delegation to the receiver, public receiver addresses, and where the reference launcher runs.
   - [ ] Release binaries and a container image with checksums.
3. **Real-world validation** (see the rig plan below)
   - [ ] Run templated probes against a real proxy (Squid, Nexus, or Artifactory) in a real sandbox runtime, and record the results in `coverage.md`.
4. **Cheap coverage gaps**
   - [ ] Cloud metadata probes (`169.254.169.254`, `fd00:ec2::254`), possibly as a built-in hazard profile.
   - [ ] A successful HTTPS CONNECT fixture.
   - [ ] DNS over TCP.
   - [ ] A documented DoH-through-proxy recipe, using templates only.
5. **Positioning**
   - [ ] Make the pitch match the build. Remove "exact Artifactory paths" and "timing/cert oracles", or mark them as roadmap.

Deferred until after 1.0: timing and certificate oracles (they need a channel model first, see `research.md`), QUIC, durable witness storage, key rotation and hardware-backed keys, and vendor adapters, which need version-specific reproductions.

## Rig plan: Arch Linux with an RTX 4090 (TODO 3)

Run the lab and the experiments natively on Linux, without Colima:

1. **Native lab.** Run `make lab` with Docker and Compose. Confirm that IPv6 works on user-defined networks, because the lab needs it. Record the kernel and Docker versions in `coverage.md`.
2. **Real sandbox runtimes.** Write a launcher for each runtime: Docker `--network none` plus a proxy sidecar, gVisor (`runsc`), and bubblewrap or Landlock. Each runtime fails differently (EACCES, ENETUNREACH, or a silent drop), which exercises both explicit and `non-receipt` grading.
3. **Real proxy.** Put Squid with `dst` ACLs in front of the sandbox. Point `{canary_host}` probes at it, and confirm that DNS-before-deny is caught. Optionally run a Nexus or Artifactory OSS instance with templated `proxy-fetch` probes.
4. **Local-LLM agent experiment.**
   - Serve a small instruct model that supports tool calling on the host GPU: a 7–14B model through Ollama, llama.cpp, or vLLM.
   - Run the agent harness inside the sandbox. Its only allowed paths are the inference endpoint and the proxy.
   - Gate the run with `sealcheck check` as a pre-flight, and keep `sealcheck watch` running for the whole session.
   - Optionally give the agent a red-team task: get the synthetic canary to the receiver. Any path the agent finds that sealcheck did not probe is a coverage gap; turn it into a probe and a test.
   - Use synthetic canaries only, and keep receivers on networks you control.
