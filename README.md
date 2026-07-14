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
go-metadata -> build -> { tests | go-lint | audit | sbom -> grype }
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
  scans it for known vulnerabilities

The `repository-metadata` job runs in parallel as an informational
step, and the `gerrit-validate` job fails fast on inconsistent Gerrit
inputs.

### Build/Test Inputs

<!-- markdownlint-disable MD013 -->

| Name                      | Type    | Default            | Description                                                                                                  |
| ------------------------- | ------- | ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `repository`              | string  | `''`               | Repository to check out (owner/name); empty = calling repository                                             |
| `ref`                     | string  | `''`               | Branch/tag/SHA to check out (empty = event ref; other repos: default branch)                                 |
| `path_prefix`             | string  | `'.'`              | Path to the project root directory                                                                           |
| `go_version_matrix`       | string  | `''`               | JSON array of Go versions, e.g. `["1.25", "1.26"]`; empty derives from go.mod                                |
| `build_target`            | string  | `'./...'`          | Package(s) passed to `go build`                                                                              |
| `build_flags`             | string  | `''`               | Extra flags passed to `go build`                                                                             |
| `cgo_enabled`             | string  | `'0'`              | CGO_ENABLED for the build job (`'0'`/`'1'`); set `'1'` for cgo modules such as confluent-kafka-go            |
| `tests_enabled`           | boolean | `true`             | Run the tests job (set false to skip tests)                                                                  |
| `test_args`               | string  | `''`               | Extra arguments passed to `go test`                                                                          |
| `test_make_args`          | string  | `''`               | Run the project Makefile via make-action instead of `go test` (e.g. `test`); ignores coverage/race/test_args |
| `coverage`                | boolean | `true`             | Collect and report test coverage                                                                             |
| `race`                    | boolean | `true`             | Run tests with the Go race detector                                                                          |
| `test_permit_fail`        | boolean | `false`            | Permit test failures without failing the workflow                                                            |
| `test_artifact_path`      | string  | `''`               | Test output/reports path (relative to path_prefix) to upload; empty disables                                 |
| `lint_version`            | string  | `'v2.12.2'`        | golangci-lint version to install (pinned for reproducibility)                                                |
| `lint_permit_fail`        | boolean | `false`            | Permit golangci-lint failures (the NO_BLOCK pattern)                                                         |
| `audit_enabled`           | boolean | `true`             | Run the dependency audit job (set false to skip)                                                             |
| `gosec`                   | boolean | `false`            | Run the gosec security scanner during the audit                                                              |
| `staticcheck`             | boolean | `false`            | Run staticcheck during the audit                                                                             |
| `audit_permit_fail`       | boolean | `false`            | Permit dependency audit failures (the NO_BLOCK pattern)                                                      |
| `sbom_enabled`            | boolean | `true`             | Generate an SBOM (set false to skip; also skips the dependent Grype scan)                                    |
| `grype_fail_on`           | string  | `'medium'`         | Severity threshold that fails the Grype scan                                                                 |
| `grype_permit_fail`       | boolean | `false`            | Permit Grype findings without failing the job                                                                |
| `build_timeout_minutes`   | number  | `10`               | Timeout (minutes) for the build job (release workflow default: `12`)                                         |
| `test_timeout_minutes`    | number  | `15`               | Timeout (minutes) for the tests job                                                                          |
| `audit_timeout_minutes`   | number  | `10`               | Timeout (minutes) for the audit, SBOM and Grype jobs                                                         |
| `harden_runner_egress`    | string  | `'block'`          | Harden-runner egress policy: `block` or `audit`                                                              |
| `harden_runner_allowlist` | string  | (pinned reference) | Out-of-band harden-runner allow-list configuration                                                           |
| `gerrit_refspec`          | string  | `''`               | Gerrit refspec of the change under test                                                                      |
| `gerrit_project`          | string  | `''`               | Gerrit project name                                                                                          |
| `gerrit_branch`           | string  | `''`               | Gerrit target branch                                                                                         |
| `gerrit_url`              | string  | `''`               | Gerrit server URL; empty falls back to the `GERRIT_URL` variable                                             |

<!-- markdownlint-enable MD013 -->

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
    #   go_version_matrix: '["1.25", "1.26"]'
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
- `attach-artefacts` uploads binaries, checksums, the signature bundle
  and SBOM files to the draft release; `promote-release` publishes it

### Release Inputs

The release workflow accepts the shared inputs from the build-test
table above (except the matrix/lint inputs `go_version_matrix`,
`lint_version` and `lint_permit_fail` — the release pipeline runs no
lint job), plus:

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

Verify build provenance attestations with the GitHub CLI:

```bash
gh attestation verify <binary> --repo <owner>/<repo>
```

Verify the checksums signature bundle with cosign:

<!-- markdownlint-disable MD013 -->

```bash
# Pin the identity to this reusable workflow and the release tag so
# signatures from unrelated workflows or refs get rejected; replace
# <tag> with the release tag under verification
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp \
  'https://github.com/lfreleng-actions/go-workflows/.github/workflows/build-test-release.yaml@refs/tags/<tag>' \
  --certificate-oidc-issuer \
  https://token.actions.githubusercontent.com \
  checksums.txt
```

<!-- markdownlint-enable MD013 -->

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

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/go-workflows/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/go-workflows/main.svg
