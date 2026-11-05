<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🐹 Go Workflows

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![Source Code](https://img.shields.io/badge/GitHub-100000?logo=github&logoColor=white&color=blue)](https://github.com/lfreleng-actions/go-workflows) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![pre-commit.ci status badge]][pre-commit.ci results page] [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lfreleng-actions/go-workflows/badge)](https://scorecard.dev/viewer/?uri=github.com/lfreleng-actions/go-workflows)
<!-- prettier-ignore-end -->

Reusable GitHub Actions workflows for Go projects, following the Linux
Foundation release engineering pipeline shape. Thin caller workflows in
consuming repositories invoke these reusable workflows for pull-request
verification and for tag-driven releases, on both GitHub-native and
Gerrit-sourced projects.

## Workflows

<!-- markdownlint-disable MD013 -->

| Workflow                                    | Purpose                                                                                     |
| ------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `.github/workflows/build-test.yaml`         | Build, test, lint, audit and scan a Go project on pull requests                             |
| `.github/workflows/build-test-release.yaml` | Tag-driven release: multi-platform binaries, checksums, signing, attestation and publishing |

<!-- markdownlint-enable MD013 -->

Both workflows share the same scaffolding:

- Dual checkout: a standard GitHub checkout, or a Gerrit change
  checkout when the caller passes `gerrit_refspec`
- Step-security harden-runner in every job that touches the network,
  with a blocked egress
  policy and an out-of-band allow-list by default (the gerrit-validate
  job runs pure input validation with no checkout or network access,
  so it carries none)
- Explicit per-job permissions, top-level `permissions: {}`, and
  `timeout-minutes` on every job
- The NO_BLOCK/soft-fail pattern: setting a `*_permit_fail` input, or
  the `NO_BLOCK_AUDIT_FAIL` repository variable (an org/repo-wide
  override that soft-fails these checks even when a caller passes
  false), turns failures
  into warnings

Neither workflow declares secrets: jobs use the calling workflow's
`GITHUB_TOKEN` for metadata queries and release operations.

## Build/Test Workflow

Job graph (`->` denotes sequence; jobs in `{ }` run in parallel):

```text
go-metadata -> build -> { tests | go-lint | audit | sbom -> grype | cbom }
```

- `go-metadata` derives the Go version matrix from `go.mod` via
  build-metadata-action, or takes it from the `go_version_matrix` input
- `build` compiles the project across the version matrix with
  go-build-action
- `tests` runs `go test` across the version matrix with go-test-action;
  coverage and the race detector default to on
- `go-lint` runs golangci-lint
- `audit` runs govulncheck (plus optional gosec and staticcheck) with
  go-audit-action
- `sbom` generates a CycloneDX SBOM with sbom-action, then `grype`
  scans it for known vulnerabilities; with `grype_gate_when:
  dependencies-changed` the gate arms when the change touched the
  dependency chain (see
  [Change-Scoped Grype Gating](#change-scoped-grype-gating))
- `cbom` generates a CycloneDX Cryptography Bill of Materials with
  cbom-action; informational, and it never fails the run (see below)

The `repository-metadata` job runs in parallel; it reports repository
metadata and, under `grype_gate_when: dependencies-changed`, detects
whether the change touched the dependency chain for the `grype` job.
The `gerrit-validate` job fails fast on inconsistent Gerrit inputs and
on an invalid Grype gating policy.

### Change-Scoped Grype Gating

By default the Grype scan gates on every run (`grype_gate_when:
always`). Setting `grype_gate_when: dependencies-changed` makes the
gate opt-in per change: the `repository-metadata` job runs
[repository-metadata-action][]'s dependency change detection against
the change under test and exports its verdict, and the `grype` job
passes it to `grype-scan-action` as `dependencies-changed`. A change
that left every dependency file alone then reports findings as
warnings instead of failing. The action's
[Dependency Change Detection][dependency-change-detection] section
defines the file list per preset, how it picks the base commit and
the fail-closed contract; this workflow adds no rules of its own.

Detection checks every preset unless `grype_dependency_ecosystems`
narrows it to a comma-separated subset (`go` for a pure Go module);
`grype_dependency_patterns` adds file patterns, one per line, and
`path_prefix` scopes the check to the module's directory.
`gerrit-validate` rejects an empty entry or an unknown preset name in
that list, and a bypass repository not in `owner/name` form.

The detection fails closed. When the action cannot resolve a base,
the verdict is empty, and `grype-scan-action` then gates as on an
`always` run. The `grype` job reads the verdict when the
`repository-metadata` job succeeded and treats it as empty otherwise.
It still runs when that job fails or skips, so a metadata failure
gates too and never loosens the gate. `tests/test-grype-gating.sh` guards that wiring.

`grype_bypass_repository` names the repository holding the approved
`BYPASS:` issues `grype-scan-action` honours; empty reads them from
the calling repository.

Two inputs shape what an armed gate blocks on. `grype_only_fixed`
defaults to `true`: the gate blocks on CVEs with a known, published
fix version and nothing else, so a finding nobody can act on appears
in the report without blocking. `grype_dependency_policy: declared`
(the default) holds transitive findings to `grype_transitive_fail_on`
(default `critical`) rather than `grype_fail_on`. Syft emits no
dependency graph for Go yet,
so for a Go module every finding counts as declared until
[sbom-action#45][] lands; on this family the relief comes from
`grype_gate_when`.

The remediation window bounds that relief in time. With
`grype_remediation_window_days` set and a change that left the
dependency chain alone, a finding stays a warning for that number of
days after its fix became available, then gates as on an armed run.
The days value alone turns the window on: empty (the default) keeps it
off. `grype_remediation_window_start` is an optional floor on the
start of the count: a fix published before that date counts from the
date instead; empty (the default) sets no floor and counts every fix
from publication, so it does not turn the window off. Neither does
anything on `always` runs; `gerrit-validate` checks the days value is
a whole number and the start value is a real `YYYY-MM-DD` date, and
leaves "not in the future" to the action.

The release workflow always gates: it accepts the policy inputs and
`grype_bypass_repository` but not `grype_gate_when` or the detection
inputs, and runs no detection.

[repository-metadata-action]: https://github.com/lfreleng-actions/repository-metadata-action
[dependency-change-detection]: https://github.com/lfreleng-actions/repository-metadata-action#dependency-change-detection
[sbom-action#45]: https://github.com/lfreleng-actions/sbom-action/issues/45

### CBOM (informational)

The `cbom` job records the algorithms, key sizes, modes, protocols and
certificates the code actually calls. An SBOM cannot express that, and
a CBOM is what post-quantum readiness assessments read. For Go the
scanner covers the `crypto` standard library (bar `crypto/x509`) plus
`hkdf`, `pbkdf2` and `sha3` from `golang.org/x/crypto`.

**It never fails the workflow run.** The job sets `continue-on-error`
and pins the action's `fail_on_error` to `false`, so a scanner error, a
rejected input, or the job timeout all leave the run green. That covers
the whole leg on purpose — there is no `cbom_permit_fail` input,
because the report is advisory by contract rather than by configuration.
Set `cbom_enabled: false` to drop the job entirely.

It runs in parallel with the test, lint, audit and SBOM legs and gates
nothing, so it never delays another job. The run as a whole still waits
for it, as it does for every job, so a scan that outlasts every other
branch extends the total; `cbom_timeout_minutes` bounds that. In the
self-test it takes 34–41 seconds, well inside the build. `needs: build`
orders it after the build; it does its own checkout and reads no build
output.

In the release workflow this leg sits outside the gating inversion:
it neither gates `tests` nor joins the release assets, because a job
permitted to fail would attach its output at random.

CBOM files upload as the `cbom-files` artefact with 45-day retention,
matching the SBOM. The job writes reports under `RUNNER_TEMP`, never the
workspace, so a project that tracks its own `cbom.json` keeps it. The
scanner image is a digest pinned inside `cbom-action`, so it moves when
the action pin moves rather than through a workflow input.

**Known limitation.** The CBOM's metadata block (repository URL, branch,
commit) comes from the workflow run's own context, so it names the
*calling* repository and commit. Where `repository` or `ref` points at a
different tree, and on a Gerrit-sourced run where the checked-out change
is not the mirror commit, that metadata describes the caller rather than
the source scanned. This does not touch the cryptographic findings themselves.
Fixing it needs explicit metadata inputs on `cbom-action`.

### Build/Test Inputs

<!-- markdownlint-disable MD013 -->

| Name                                   | Type    | Default            | Description                                                                                                  |
| -------------------------------------- | ------- | ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `repository`                           | string  | `''`               | Repository to check out (owner/name); empty = calling repository                                             |
| `ref`                                  | string  | `''`               | Branch/tag/SHA to check out (empty = event ref; other repos: default branch)                                 |
| `path_prefix`                          | string  | `'.'`              | Path to the project root directory                                                                           |
| `go_version_matrix`                    | string  | `''`               | JSON array of Go versions, e.g. `["1.26", "1.27"]`; empty derives from go.mod                                |
| `build_target`                         | string  | `'./...'`          | Package(s) passed to `go build`                                                                              |
| `build_flags`                          | string  | `''`               | Extra flags passed to `go build`                                                                             |
| `cgo_enabled`                          | string  | `'0'`              | CGO_ENABLED for the build job (`'0'`/`'1'`); set `'1'` for cgo modules such as confluent-kafka-go            |
| `tests_enabled`                        | boolean | `true`             | Run the tests job (set false to skip tests)                                                                  |
| `test_args`                            | string  | `''`               | Extra arguments passed to `go test`                                                                          |
| `test_make_args`                       | string  | `''`               | Run the project Makefile via make-action instead of `go test` (e.g. `test`); ignores coverage/race/test_args |
| `coverage`                             | boolean | `true`             | Collect and report test coverage                                                                             |
| `race`                                 | boolean | `true`             | Run tests with the Go race detector                                                                          |
| `test_permit_fail`                     | boolean | `false`            | Permit test failures without failing the workflow                                                            |
| `test_artifact_path`                   | string  | `''`               | Test output/reports path (relative to path_prefix) to upload; empty disables                                 |
| `lint_version`                         | string  | `'v2.12.2'`        | golangci-lint version to install (pinned for reproducibility)                                                |
| `lint_permit_fail`                     | boolean | `false`            | Permit golangci-lint failures (the NO_BLOCK pattern)                                                         |
| `audit_enabled`                        | boolean | `true`             | Run the dependency audit job (set false to skip)                                                             |
| `gosec`                                | boolean | `false`            | Run the gosec security scanner during the audit                                                              |
| `staticcheck`                          | boolean | `false`            | Run staticcheck during the audit                                                                             |
| `audit_permit_fail`                    | boolean | `false`            | Permit dependency audit failures (the NO_BLOCK pattern)                                                      |
| `sbom_enabled`                         | boolean | `true`             | Generate an SBOM (set false to skip; Grype then has nothing to scan)                                         |
| `grype_enabled`                        | boolean | `true`             | Run the Grype scan (set false to keep the SBOM but skip the scan)                                            |
| `grype_fail_on`                        | string  | `'medium'`         | Severity that fails the scan (`negligible` … `critical`), or `none` to report without gating                 |
| `grype_permit_fail`                    | boolean | `false`            | Permit Grype findings without failing the job                                                                |
| `grype_gate_when`                      | string  | `'always'`         | When the scan gates: `always`, or `dependencies-changed` (gate when the change touched the dependency chain) |
| `grype_dependency_ecosystems`          | string  | `''`               | Comma-separated presets checked under `dependencies-changed` (`go`, `node`, …); empty checks every preset    |
| `grype_dependency_patterns`            | string  | `''`               | Extra dependency file patterns, one per line, checked under `dependencies-changed`                           |
| `grype_bypass_repository`              | string  | `''`               | Repository (`owner/name`) holding approved `BYPASS:` issues; empty uses the calling repository               |
| `grype_dependency_policy`              | string  | `'declared'`       | Findings that gate: `all`, or `declared` (transitive findings held to `grype_transitive_fail_on`)            |
| `grype_transitive_fail_on`             | string  | `'critical'`       | Severity threshold for transitive findings under `declared` (`none`, `negligible`, `low` … `critical`)       |
| `grype_only_fixed`                     | boolean | `true`             | Gate on findings with a published fix version and report the rest                                            |
| `grype_remediation_window_days`        | string  | `''`               | Days a finding stays a warning after its fix on an unarmed `dependencies-changed` run; empty disables        |
| `grype_remediation_window_start`       | string  | `''`               | Optional floor (`YYYY-MM-DD`) the window counts earlier fixes from; empty counts from publication            |
| `cbom_enabled`                         | boolean | `true`             | Generate a CBOM (set false to skip the job); the job never fails the run                                     |
| `cbom_languages`                       | string  | `''`               | Comma-separated languages to scan (`java`, `python`, `go`, `csharp`); empty auto-detects                     |
| `cbom_exclude`                         | string  | `''`               | Comma-separated Java regex patterns to exclude; empty skips test sources                                     |
| `cbom_module_cboms`                    | boolean | `true`             | Emit a per-module CBOM alongside the consolidated one                                                        |
| `cbom_empty_cboms`                     | boolean | `true`             | Write CBOM files even when the scan finds no cryptographic assets                                            |
| `artifact_suffix`                      | string  | `''`               | Appended as `-<value>` to SBOM, Grype, CBOM and test artefact names; distinct per call in one run            |
| `build_timeout_minutes`                | number  | `10`               | Timeout (minutes) for the build job (release workflow default: `12`)                                         |
| `test_timeout_minutes`                 | number  | `15`               | Timeout (minutes) for the tests job                                                                          |
| `audit_timeout_minutes`                | number  | `10`               | Timeout (minutes) for the audit, SBOM and Grype jobs                                                         |
| `cbom_timeout_minutes`                 | number  | `15`               | Timeout (minutes) for the CBOM job; covers the container image pull as well as the scan                      |
| `harden_runner_egress`                 | string  | `'block'`          | Harden-runner egress policy: `block` or `audit`                                                              |
| `harden_runner_allowlist`              | string  | (pinned reference) | Out-of-band harden-runner allow-list configuration; see [Egress Allow-List](#egress-allow-list)              |
| `harden_runner_supplemental_allowlist` | string  | `''`               | Extra allow-list merged with `harden_runner_allowlist`; empty adds nothing                                   |
| `harden_runner_supplemental_unpinned`  | boolean | `false`            | Let the supplemental list omit `@ref` and follow its default branch (lists in the caller's own organisation) |
| `harden_runner_extra_endpoints`        | string  | `''`               | Inline `host[:port]` endpoints merged into the allow-list for short-lived fixes                              |
| `gerrit_refspec`                       | string  | `''`               | Gerrit refspec of the change under test                                                                      |
| `gerrit_project`                       | string  | `''`               | Gerrit project name                                                                                          |
| `gerrit_branch`                        | string  | `''`               | Gerrit target branch                                                                                         |
| `gerrit_url`                           | string  | `''`               | Gerrit server URL; empty falls back to the `GERRIT_URL` variable                                             |

<!-- markdownlint-enable MD013 -->

### Build/Test Outputs

<!-- markdownlint-disable MD013 -->

| Name                         | Description                                                                                          |
| ---------------------------- | ---------------------------------------------------------------------------------------------------- |
| `grype_gate_active`          | Whether the Grype gate armed (`true`/`false`); empty when the scan did not run. Not matrix-safe.     |
| `grype_dependencies_changed` | Verdict Grype received (`true`/`false`); empty when unresolved, off, failed or not scanned.          |

<!-- markdownlint-enable MD013 -->

### Egress Allow-List

Both workflows run step-security harden-runner with a blocked egress
policy. Each job loads its allow-list through
`lfreleng-actions/harden-runner-block-action`, and five inputs, shared
by both workflows, shape that list:

- `harden_runner_egress`: `block` (the default) or `audit`.
- `harden_runner_allowlist`: the baseline list, by default the
  organisation list pinned to a release.
- `harden_runner_supplemental_allowlist`: a second list, in the same
  coordinate grammar as `harden_runner_allowlist`, merged with the
  baseline.
- `harden_runner_supplemental_unpinned`: lets the supplemental list
  omit `@ref` and follow its default branch.
- `harden_runner_extra_endpoints`: `host[:port]` tokens, separated by
  spaces or newlines, merged into the list.

An organisation that needs endpoints beyond the baseline keeps them in
its own list. An ONAP caller, for example, follows its own list on its
default branch:

```yaml
    with:
      harden_runner_supplemental_allowlist: 'onap//'
      harden_runner_supplemental_unpinned: true
```

A list may go unpinned when it lives in the caller's own
organisation. A list from another organisation must carry an `@ref`
pin, even with `harden_runner_supplemental_unpinned` set.

Naming a supplemental list makes it a dependency: the workflows set
the action's `supplemental_required` whenever
`harden_runner_supplemental_allowlist` is non-empty, so a list that
does not resolve fails the job at load time, not at the first blocked
connection.

For an unpinned list, the action's `supplemental_source` and
`supplemental_sha` outputs record which list and which commit each job
loaded. They are the audit trail for a list that moves between runs.

`harden_runner_extra_endpoints` suits a short-lived fix, such as
unblocking a build while an endpoint waits to join a list:

```yaml
    with:
      harden_runner_extra_endpoints: 'registry.nordix.org:443'
```

The lasting fix is adding the endpoint to the organisation's list,
after which the caller drops the inline entry.

### Build/Test Usage (GitHub)

<!-- markdownlint-disable MD013 -->

```yaml
jobs:
  build-test:
    permissions:
      contents: read
      pull-requests: read
    # yamllint disable-line rule:line-length
    uses: lfreleng-actions/go-workflows/.github/workflows/build-test.yaml@<SHA>  # vX.Y.Z
    # with:
    #   go_version_matrix: '["1.26", "1.27"]'
    #   gosec: true
    #   staticcheck: true
```

<!-- markdownlint-enable MD013 -->

See `examples/build-test/github.yaml` for a complete caller triggered
on pull requests.

### Build/Test Usage (Gerrit)

For projects where Gerrit is the source of truth, copy
`examples/build-test/gerrit.yaml` into `.github/workflows/` with a
filename containing both `gerrit` and `verify` (for example
`gerrit-verify.yaml`). gerrit_to_platform dispatches the workflow per
patchset with the nine `GERRIT_*` inputs, and the wrapper votes
Verified +/-1 back on the change.

## Build/Test/Release Workflow

The release model is tag-driven (Model A): a signed semver tag push
drives every release, with no snapshot or merge-based publishing model.
The Go module proxy serves module versions straight from repository
tags (and untagged commits as pseudo-versions), so no separate registry
publish step exists.

Job graph:

```text
tag-validate -> release-matrix -> build (GOOS x GOARCH)
build -> { audit | sbom -> grype } -> tests
build -> cbom
build -> checksums -> sign-artefacts
build -> attest
{ tests | checksums | sign-artefacts | attest }
  -> attach-artefacts -> promote-release
```

- `tag-validate` verifies the pushed tag (signed semver) and ensures a
  draft release exists
- `release-matrix` expands `release_goos`/`release_goarch` into a
  GOOS×GOARCH build matrix, excluding `windows/arm64`
- `build` produces one static binary per platform
  (`<name>-<tag>-<goos>-<goarch>[.exe]`, CGO off, `-trimpath`,
  stripped, with `main.version` set to the tag); projects without a
  buildable main package get a compile check and no binary artefacts
- `checksums` generates a SHA-256 `checksums.txt` over the binaries
- `sign-artefacts` signs `checksums.txt` with cosign (keyless/OIDC),
  producing `checksums.txt.sigstore.json`
- `attest` generates SLSA build provenance for the binaries
- `audit`, `sbom` and `grype` mirror the build-test workflow; `tests`
  gate on the audits (gating inversion: audits gate tests on releases);
  jobs skipped via the `*_enabled` toggles never block the release,
  while genuine failures always do
- `cbom` mirrors the build-test workflow and stays outside that
  inversion: it gates nothing, cannot fail the run, and uploads as a
  workflow artefact rather than a release asset
- `attach-artefacts` uploads binaries, checksums, the signature bundle
  and SBOM files to the draft release; `promote-release` publishes it

### Release Inputs

The release workflow accepts the shared inputs from the build-test
table above (except the matrix/lint inputs `go_version_matrix`,
`lint_version` and `lint_permit_fail` — the release pipeline runs no
lint job — and `grype_gate_when`, `grype_dependency_ecosystems` and
`grype_dependency_patterns`, because a release always gates),
plus:

<!-- markdownlint-disable MD013 -->

| Name             | Type    | Default                  | Description                                                          |
| ---------------- | ------- | ------------------------ | -------------------------------------------------------------------- |
| `go_version`     | string  | `''`                     | Explicit Go version for release builds; empty derives from go.mod    |
| `release_goos`   | string  | `'linux,darwin,windows'` | Comma-separated GOOS values for release binaries                     |
| `release_goarch` | string  | `'amd64,arm64'`          | Comma-separated GOARCH values for release binaries                   |
| `build_target`   | string  | `'./...'`                | Package to build; the default probes the module root and `cmd/`      |
| `output_name`    | string  | `''`                     | Base name for release binaries; empty uses the repository name       |
| `cgo_enabled`    | string  | `'0'`                    | CGO_ENABLED for release builds; `'1'` needs a per-target C toolchain |
| `attestations`   | boolean | `true`                   | Generate SLSA build provenance attestations for the release binaries |
| `sigstore_sign`  | boolean | `true`                   | Sign the release checksums file with Sigstore (keyless/OIDC)         |

<!-- markdownlint-enable MD013 -->

### Release Outputs

<!-- markdownlint-disable MD013 -->

| Name  | Description                          |
| ----- | ------------------------------------ |
| `tag` | Validated release tag/version string |

<!-- markdownlint-enable MD013 -->

### Release Usage

<!-- markdownlint-disable MD013 -->

```yaml
on:
  push:
    tags:
      - '**'

jobs:
  release:
    if: "!github.event.deleted"
    permissions:
      contents: write
      id-token: write
      attestations: write
    # yamllint disable-line rule:line-length
    uses: lfreleng-actions/go-workflows/.github/workflows/build-test-release.yaml@<SHA>  # vX.Y.Z
```

<!-- markdownlint-enable MD013 -->

See `examples/build-test-release/` for complete GitHub-native and
Gerrit-sourced callers. Gerrit projects push the release tag to Gerrit;
replication to the GitHub mirror fires the standard tag-push event, so
the release caller stays tag-triggered with no `workflow_dispatch`.

## Verifying Release Artefacts

The attestation and the signature both come from jobs inside this
reusable workflow, so the Sigstore certificate behind each one names
the reusable workflow as the signer. The calling run's repository and
tag appear in the GitHub extensions of the certificate, not in its
identity:

<!-- markdownlint-disable MD013 -->

| Certificate field                             | Binds                                       | Value                                                                                              |
| --------------------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Subject Alternative Name (identity)           | This workflow, at the ref the caller pinned | `https://github.com/lfreleng-actions/go-workflows/.github/workflows/build-test-release.yaml@<ref>` |
| GitHub Workflow Repository                    | The calling repository                      | `<owner>/<repo>`                                                                                   |
| GitHub Workflow Ref and Source Repository Ref | The tag the caller ran on                   | `refs/tags/<tag>`                                                                                  |
| GitHub Workflow Trigger                       | The triggering event                        | `push`                                                                                             |

<!-- markdownlint-enable MD013 -->

`<ref>` is whatever follows `@` in the caller's `uses:` line,
typically a go-workflows commit SHA. Check the identity and the
extensions together: the identity alone accepts an artefact that any
project released through this workflow, and the extensions alone
accept one from any workflow that ran on that tag.

The extensions describe the calling run, not the checkout. The
`repository` and `ref` inputs can point the build at other source, so
the extensions identify the packaged source when the caller leaves
both inputs empty, as the examples do, and not otherwise.

Verify the build provenance attestation of each binary with GitHub
CLI v2.102.0 or later; earlier releases matched `--signer-workflow` as
a prefix ([GHSA-wjmr-j3rp-mh2g]) and `--source-ref` without regard to
case ([GHSA-4mq3-hpgx-9cx8]). `--signer-workflow` is mandatory: without
it `gh` expects a signer in the project repository and rejects every
release:

<!-- markdownlint-disable MD013 -->

```bash
gh attestation verify <binary> \
  --repo <owner>/<repo> \
  --signer-workflow lfreleng-actions/go-workflows/.github/workflows/build-test-release.yaml \
  --source-ref refs/tags/<tag>
```

<!-- markdownlint-enable MD013 -->

Verify the checksums signature bundle with cosign v3 or later. The
workflow emits a v0.3 Sigstore bundle, which cosign v2.2 cannot read:

<!-- markdownlint-disable MD013 -->

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp \
  '^https://github\.com/lfreleng-actions/go-workflows/\.github/workflows/build-test-release\.yaml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository <owner>/<repo> \
  --certificate-github-workflow-ref refs/tags/<tag> \
  --certificate-github-workflow-trigger push \
  checksums.txt
```

<!-- markdownlint-enable MD013 -->

Both commands accept any revision of this workflow. To pin the
revision as well, take the commit SHA from the project's caller at the
release tag, add `--signer-digest <sha>` to the `gh` command, and
replace cosign's `--certificate-identity-regexp` with
`--certificate-identity` and the full SAN ending in `@<sha>`.

[GHSA-wjmr-j3rp-mh2g]: https://github.com/cli/cli/security/advisories/GHSA-wjmr-j3rp-mh2g
[GHSA-4mq3-hpgx-9cx8]: https://github.com/cli/cli/security/advisories/GHSA-4mq3-hpgx-9cx8

Then check each downloaded binary against the signed checksums:

```bash
sha256sum --check checksums.txt
```

## Self-Testing

`.github/workflows/testing.yaml` exercises the build-test workflow on
pull requests against pinned fixture repositories (a Go fixture project
and an ONAP monorepo subdirectory). The release workflow needs a signed
tag-push context, so consuming repositories exercise it through their
own release cycles.

`.github/workflows/testing-gate.yaml` runs build-test with
`grype_gate_when: dependencies-changed` in two lanes, each with its
own `artifact_suffix`. The first runs the external Go fixture, which
pins a commit of another repository, so the pull request's base cannot
resolve against it: the lane proves the unresolved path gates by
asserting an empty `grype_dependencies_changed` output and a
`grype_gate_active` output of `true`. The second runs the in-repository
module under `tests/fixtures/go-module`, checked out at the run's own
commit: on a pull request it asserts a `true` or `false` verdict that
`grype_gate_active` follows, proving a resolved verdict reaches Grype;
on a manual run no base exists and it asserts the gate arms. That lane
sets `grype_permit_fail`, because a pull request that changes no
dependency file never arms its gate, while one that does arms it
against whatever the scan finds.

The `testing.yaml` legs call build-test in one run, so each passes its
matrix name as `artifact_suffix`. Without it the legs share the
`sbom-files` name and `upload-artifact` rejects the second upload. The
`grype` job does not rely on the name either way: the `sbom` job
exports its upload's `artifact-id` as the `sbom_artifact_id` output
and `grype` downloads by `artifact-ids`, so a same-named artefact from
another call of the workflow in the same run is never the one scanned.

Each leg also passes the [egress allow-list](#egress-allow-list)
inputs in a form that grants nothing new: `lfreleng-actions//`
unpinned resolves to the organisation list the baseline already loads,
and `github.com:443` already sits on that list.

`bash tests/test-harden-runner-inputs.sh` checks that both reusable
workflows expose the five `harden_runner_*` inputs and pass each one
through to every block-action step; a prek hook runs it on every
workflow change.

`bash tests/test-grype-gating.sh` checks the Grype gating wiring: the
inputs and their defaults in both workflows, the pinned detection step
in the `repository-metadata` job and the job output carrying its
verdict, the `grype` job's guarded read of that output, the absence of
the retired sidecar wiring, every policy input reaching
`grype-scan-action`, and the `gerrit-validate` step rejecting each
invalid value by running the step's own script. A prek hook and a
`testing.yaml` job both run it.

`bash tests/test-artifact-suffix.sh` checks that both reusable
workflows take `artifact_suffix`, append it at every upload and
download of the SBOM, Grype, CBOM and test artefacts, bind the `grype`
job's SBOM download to the `sbom` job's upload by artefact ID rather
than by name, and reject an invalid suffix in `gerrit-validate`, and
that each `testing.yaml` leg passes a distinct suffix. A prek hook and
a `testing.yaml` job both run it.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/go-workflows/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/go-workflows/main.svg
