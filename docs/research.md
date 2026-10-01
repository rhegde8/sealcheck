# Research and expansion

## Positioning

Existing work includes [EgressCheck](https://github.com/stufus/egresscheck-framework), [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench), [Pipelock](https://github.com/luckyPipewrench/pipelock), and [OpenParallax sandbox probes](https://docs.openparallax.dev/sandbox/). Sealcheck focuses on workload-context probing, package-proxy behavior, independent observations, and a portable signed report. The existence of a signed report alone is not a novel claim.

## Real Artifactory adapters

[JFrog's advisories](https://docs.jfrog.com/releases/docs/jfrog-security-advisories) describe Terraform (CVE-2026-65924), Cargo (CVE-2026-65925), and Ansible (CVE-2026-65923) remote-repository SSRF classes. Those descriptions do not by themselves establish the exact requests used in an incident.

The repository's `/fixtures/terraform/module`, `/fixtures/cargo/download`, and `/fixtures/ansible/archive` routes are synthetic. They deliberately exercise a common trusted-proxy failure mode without presenting an invented path as a vendor exploit.

Before adding an adapter:

1. Obtain a suitable isolated Artifactory edition/version and record its provenance and configuration.
2. Source the actual handler/request shape from authoritative documentation or a reproducible disclosure. Record authentication, repository type, permissions, and version prerequisites.
3. Reproduce forwarding to a controlled canary receiver on the affected configuration and denial on the fixed or hardened configuration.
4. Capture request/response metadata with secrets redacted, receiver receipts, timing, and the exact version pair.
5. Add an adapter and integration test. Publish coverage only for the reproduced versions and preconditions.

Until those conditions are met, unsupported Artifactory coverage stays out of a passing required profile. The portable demo remains usable independently of vendor licensing or version availability.

## Timing and certificate-related oracles

These are experimental research tracks, not implemented probe kinds. They need a precise channel model before a meaningful verdict is possible.

For each experiment, specify the sender, observer, controllable input, observable output, information direction, and trust boundary. Distinguish outbound exfiltration from inbound information or reachability oracles. Readable time or certificate information alone does not establish an egress channel.

Use randomly generated synthetic bits, randomized trial ordering, baseline/control groups, independently collected observations, and a prespecified decoding threshold. Measure false positives and reproducibility across repetitions. A noisy statistical difference alone must not become a FAIL labelled proven exfiltration. Promote a channel only after an independent observer repeatedly reconstructs the intended synthetic information under the stated threat model.

## Next engineering milestones

- Add actual vendor adapters after successful version-specific reproduction.
- Add DNS-over-TCP and encrypted DNS with explicit transport evidence.
- Add a successful TLS CONNECT fixture and normal certificate-chain tests.
- Add production registry protocols with scoped disposable repositories and independent readers.
- Add stronger host/launcher identity evidence, durable witness storage, key rotation, and supervisor integrations.

Each expansion should preserve the core rule: absence of an observed leak is not enough to manufacture a corroborated denial.
