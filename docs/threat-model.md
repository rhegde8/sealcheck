# Threat model

## Claim

Sealcheck measures an explicit egress policy over a bounded interval. PASS means sufficient evidence exists for the required probes in that policy. It does not mean universal noninterference, absence of undiscovered vulnerabilities, or continuous enforcement.

The intended threat is a workload that can attempt to send information through permitted and prohibited network paths. Initial validation assumes a trusted probe executable and launcher. An actively compromised runtime can recognize probes, tamper with observations, hide behavior between checks, or selectively permit/deny traffic. Sealcheck does not solve that problem through signing.

## Trusted components

The host, sandbox launcher, controller, signing key, and configured witnesses are trusted. A witness marked `boundary` is authorized by policy to testify to explicit denials. A plain receiver cannot establish policy denial. Compromised witnesses can lie, and a compromised controller can sign false reports.

The runner reports its UID/EUID/GID, hostname, available namespace links, Linux capability mask, seccomp mode, and `no_new_privs` state. These are labelled `runner-reported`. Namespace links identify contexts within a host; they are not global workload identities. Credential labels in probe specifications are declarations, not authentication evidence. Receiver source addresses may identify a proxy, NAT gateway, or resolver rather than the original workload.

The trusted launcher must reproduce the workload's security context. A new sibling process might have different per-process restrictions even if its UID and network namespace match. The reference lab has a deliberately simple shared route policy and starts both workload and probes with the same capability restrictions. Production harness adapters need their own equivalence tests.

## Evidence

Each plan has independent random run and nonce values, one random canary per probe, a policy hash, and a deadline. The wire canary contains only synthetic identifiers. External receipts bind the run, probe, token, protocol, observation time, and canary hash.

The controller checks witness health before launching and collects evidence afterward, with an observation grace period. Witness restarts, missing health, and bounded-buffer overflow prevent PASS. Foreign, stale, wrong-protocol, and wrong-token events do not corroborate a result. Evidence that a canary escaped takes precedence over a locally reported error or denial. A failed evaluation remains FAIL even if other observations are incomplete.

TCP establishment and successful forbidden HTTP operations establish reachability under the trusted-runner assumption. UDP socket creation/send does not establish remote receipt. DNS NXDOMAIN and application error responses do not imply that no query or payload left the boundary. Registry readback is performed by the controller and compares the exact synthetic bytes.

Denials require an explicit kernel `EACCES`/`EPERM` or a trusted boundary event. `ECONNREFUSED`, `ENETUNREACH`, NXDOMAIN, HTTP error status, and timeouts alone remain ambiguous. Positive allowed-traffic controls help identify broken environments.

## Cryptographic boundaries

The controller signs exact report bytes with Ed25519, prefixed by a format-specific domain separator. The JSON bundle base64-encodes those bytes so whitespace formatting cannot change them. The public-key fingerprint identifies the signer, but verification requires a separately trusted public key. Reports embed evidence rather than referencing mutable external files.

Current-context verification requires the expected run ID and policy, validates age against both the caller's maximum and the signed policy maximum, and checks verdict consistency. Signing keys are never generated inside or passed to the sandbox. Private keys require owner-only file permissions and key generation refuses to overwrite existing keys.

Signatures do not authenticate the runner's identity claims or the underlying wall clock. This release assumes synchronized clocks with at most two seconds of observation skew. The issuance timestamp comes from the controller; event timestamps come from witnesses. Long-term signing-key distribution, rotation, revocation, and hardware-backed keys are integration responsibilities.

## Deployment boundaries

The lab sends synthetic bytes only to its controlled fixtures. The registry fixture is a bounded temporary object store, not OCI/npm/Cargo protocol coverage. The deliberately leaky proxy remains restricted to its configured lab origin.

Management listeners require bearer tokens and are separate from data listeners. The Linux lab also blocks management port 8081 from the workload. HTTP management transport is intended for the isolated local lab; remote deployment requires an authenticated protected transport such as a TLS-terminating management network. Do not place bearer credentials into policy URLs.

Receivers retain up to 10,000 events and 10,000 registry objects in memory. A run snapshot is capped at 1,024 events; serialized report payloads are capped at 4 MiB. Overflow is explicit and prevents PASS. Restart between completed runs to clear a full fixture; do not restart during a measurement. Durable retention and automatic rotation are future operational work.

Periodic checks sample conditions. The supervisor must enforce nonzero gate exits, missed check deadlines, watcher liveness, and report freshness. Reports do not themselves stop a workload or enforce firewall policy.
