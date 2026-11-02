# Security audit — 2026-11-02 UTC

Scope: the Go controller, runner, verifier, witness services, DNS parser, proxy
fixture, Linux lab, Docker build, GitHub workflows, and repository security
settings. This was a source review and automated vulnerability check, not a
penetration test of a production deployment.

## GitHub inventory

- No open pull requests, Dependabot alerts, or secret-scanning alerts at the
  initial inspection.
- Dependency vulnerability alerts, secret scanning, and secret push protection
  are enabled. Dependabot security updates were disabled and are now enabled.
- Code scanning has no analysis configured. The new security workflow runs the
  Go vulnerability scanner; it does not claim CodeQL coverage.
- The main branch has no branch protection. Requiring successful `test` and
  `vulnerabilities` checks remains a repository governance recommendation.

## Remediations

| Finding | Assessment | Resolution |
| --- | --- | --- |
| Go 1.24 build baseline is outside the supported release window | Medium: standard-library security fixes were not guaranteed by the build configuration | Require Go 1.27.3 in `go.mod`, CI, and Docker |
| Mutable Action tags and Docker base tags | Low: upstream tag movement could change build inputs | Pin official Action commits and multi-platform Docker manifest digests |
| Dependency maintenance and vulnerability checking were absent | Medium: newly disclosed vulnerabilities could remain unnoticed | Enable Dependabot security updates; add weekly Go, Docker, and Action updates; run `govulncheck` on pushes, PRs, and weekly |
| Checkout persisted its repository credential | Low: later build steps unnecessarily retained the checkout credential | Set `persist-credentials: false` in both workflows |

Go supports the two most recent major release lines. Release and toolchain
selection were verified against the [official Go downloads](https://go.dev/dl/)
and [release history](https://go.dev/doc/devel/release). Scanner behavior and
limits are described in [Go vulnerability management](https://go.dev/doc/security/vuln/).
Action commit IDs were resolved from their official repositories and Docker
digests from the Docker Hub registry API.

## Code review and remaining deployment limits

No new exploitable application vulnerability was identified within the stated
[trust model](threat-model.md). The review checked signature and run/policy
binding, freshness, fail-closed evidence evaluation, leak precedence, token
scrubbing and credential serialization, witness authentication and retention,
request limits and deadlines, redirect restrictions, DNS parsing, file writes,
and container privileges. This is a bounded review, not proof of absence.

- Management bearer tokens use HTTP in the isolated lab. A remote deployment
  must supply authenticated protected transport and isolate management access.
- `CommandLauncher` removes configured witness-token variables, but inherits
  other controller environment variables. A trusted launcher must supply a
  deliberately limited workload environment; run the controller without
  unrelated cloud, registry, or application secrets. A default environment
  allowlist remains a pre-1.0 design task because launchers may require Docker
  context, SSH, and workload authentication variables.
- The host, controller, launcher, witnesses, and probe executable remain trusted.
  Signing cannot establish the integrity of a compromised runtime. Non-receipt
  evidence is weaker than explicit denial and requires its positive control.
- The container's Debian packages were not vulnerability-scanned locally.
  A complete production image assessment needs an image/SBOM scanner. Pinned
  base digests do not pin packages fetched by `apt-get` during the build.
- Pattern inspection found no private PEM keys, GitHub tokens, or AWS access-key
  identifiers in tracked source. This was not a full-history secret scan.

## Validation

- `go test -race ./...`: passed with Go 1.27.3 on macOS arm64.
- `go vet ./...`: passed.
- CLI build and portable demo: passed, with expected PASS → FAIL → PASS.
- `govulncheck ./...` v1.9.0 on macOS arm64 and Linux amd64: no vulnerabilities
  found for the scanned code and standard library at audit time.
- DNS parser fuzzing: a bounded 20-second run supplements the regression corpus.
- Docker is unavailable locally. The Linux lab must pass GitHub CI before this
  toolchain/container change is merged; the PR checks provide that evidence.

Keep the scanner version current separately from the application's Go module:
the scanner is installed as CI tooling and is not an application dependency.
