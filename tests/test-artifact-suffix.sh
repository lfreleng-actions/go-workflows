#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Checks that the reusable workflows name their per-call artefacts
# with the artifact_suffix input, so a caller that runs a workflow
# more than once in one run (a matrix) gets distinct names, and that
# each grype job downloads the SBOM its own sbom job uploaded, by
# artefact ID, so no call scans another call's SBOM even when the
# suffix is omitted and the names collide.
#
# Static, from the parsed YAML:
#   - both reusable workflows take artifact_suffix (string, default
#     empty) and derive the workflow-level ARTIFACT_SUFFIX env from it,
#     empty when the input is unset so existing names stay unchanged;
#   - every upload and download of a per-call artefact (sbom-files,
#     cbom-files, go-test-results, test-coverage-go,
#     grype-scan-results) appends ${{ env.ARTIFACT_SUFFIX }}, and the
#     expected sites are all present;
#   - the sbom job exports its upload step's artifact-id output as
#     sbom_artifact_id, and every download-artifact step in the grype
#     job passes it as artifact-ids, with no name or pattern;
#   - testing.yaml passes a distinct, valid suffix on each matrix leg.
#
# Dynamic: the 'Validate artifact_suffix input' step of gerrit-validate
# is extracted from each workflow and run under bash with valid and
# invalid values.
#
# It then mutates copies of the workflows in each way the check must
# catch and expects every mutant to fail.
#
# Usage: bash tests/test-artifact-suffix.sh [<workflows-dir>]
#
# Needs python3 with PyYAML visible under 'python3 -I' (not the user site).

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
workflows="${1:-${repo_root}/.github/workflows}"

if [ ! -d "${workflows}" ]; then
  echo "ERROR: workflows directory not found: ${workflows}" >&2
  exit 1
fi

if ! python3 -I -c 'import yaml' 2>/dev/null; then
  echo "ERROR: python3 -I cannot import yaml; install PyYAML where" \
    "the interpreter on PATH sees it (a virtual environment)" >&2
  exit 1
fi

python3 -I - "${workflows}" <<'PYEOF'
import copy
import os
import pathlib
import re
import subprocess
import sys

import yaml

INPUT = "artifact_suffix"
ENV_NAME = "ARTIFACT_SUFFIX"
ENV_VALUE = (
    "${{ inputs.artifact_suffix != '' && "
    "format('-{0}', inputs.artifact_suffix) || '' }}"
)
SUFFIX = "${{ env.ARTIFACT_SUFFIX }}"
VALIDATE_STEP = "Validate artifact_suffix input"
UPLOAD = "actions/upload-artifact"
DOWNLOAD = "actions/download-artifact"
GRYPE = "lfreleng-actions/grype-scan-action"
GO_TEST = "lfreleng-actions/go-test-action"
PER_CALL = (
    "sbom-files", "cbom-files", "go-test-results", "test-coverage-go",
    "grype-scan-results",
)
SBOM_JOB = "sbom"
GRYPE_JOB = "grype"
SBOM_OUTPUT = "sbom_artifact_id"
SBOM_ID = "${{ needs.%s.outputs.%s }}" % (SBOM_JOB, SBOM_OUTPUT)
# download-artifact selects by exactly one of these; a grype job may
# use only artifact-ids.
SELECTORS = ("name", "pattern", "artifact-ids")

# workflow -> [(job, action, with-key, expected name)]
SITES = {
    "build-test.yaml": [
        ("tests", GO_TEST, "artifact_name",
         "test-coverage-go-${{ matrix.go-version }}" + SUFFIX),
        ("tests", UPLOAD, "name",
         "go-test-results-${{ matrix.go-version }}" + SUFFIX),
        ("sbom", UPLOAD, "name", "sbom-files" + SUFFIX),
        ("grype", GRYPE, "artifact-name", "grype-scan-results" + SUFFIX),
        ("cbom", UPLOAD, "name", "cbom-files" + SUFFIX),
    ],
    "build-test-release.yaml": [
        ("tests", UPLOAD, "name", "go-test-results" + SUFFIX),
        ("sbom", UPLOAD, "name", "sbom-files" + SUFFIX),
        ("grype", GRYPE, "artifact-name", "grype-scan-results" + SUFFIX),
        ("cbom", UPLOAD, "name", "cbom-files" + SUFFIX),
        ("attach-artefacts", DOWNLOAD, "name", "sbom-files" + SUFFIX),
    ],
}
CALLER = "testing.yaml"
CALLER_JOB = "build-test"

ACCEPTED = [
    "", "a", "test-go-project", "multicloud-k8s", "v1.2_3", "A.B-c_d",
]
REJECTED = [
    "a/b", "a b", "a:b", "../x", "a*", "$(id)", "a\nb", "ä", "a;b",
    "a\"b", "a\\b",
]


def triggers(doc):
    # PyYAML reads a bare 'on' key as the boolean True.
    on = doc.get("on", doc.get(True))
    return on if isinstance(on, dict) else {}


def inputs_of(doc):
    return (triggers(doc).get("workflow_call") or {}).get("inputs") or {}


def jobs_of(doc):
    return doc.get("jobs") or {}


def action_of(step):
    return str((step or {}).get("uses", "")).split("@", 1)[0]


def validate_step(doc):
    job = jobs_of(doc).get("gerrit-validate") or {}
    for step in job.get("steps") or []:
        if (step or {}).get("name") == VALIDATE_STEP:
            return step
    return None


def sbom_upload(doc):
    """Return the sbom job's upload step for the SBOM artefact."""
    job = jobs_of(doc).get(SBOM_JOB) or {}
    for step in job.get("steps") or []:
        if action_of(step) == UPLOAD and \
                ((step or {}).get("with") or {}).get("name") == \
                "sbom-files" + SUFFIX:
            return step
    return None


def check_binding(doc, problems):
    """The grype job must download the SBOM its sbom job uploaded."""
    upload = sbom_upload(doc)
    if upload is None:
        return  # SITES already reports the missing upload
    step_id = upload.get("id")
    wanted = "${{ steps.%s.outputs.artifact-id }}" % step_id
    outputs = (jobs_of(doc).get(SBOM_JOB) or {}).get("outputs") or {}
    if not step_id or outputs.get(SBOM_OUTPUT) != wanted:
        problems.append(
            f"jobs.{SBOM_JOB}.outputs.{SBOM_OUTPUT} is not the upload"
            " step's artifact-id"
        )
    job = jobs_of(doc).get(GRYPE_JOB) or {}
    needs = job.get("needs") or []
    if SBOM_JOB not in ([needs] if isinstance(needs, str) else needs):
        problems.append(f"jobs.{GRYPE_JOB} does not need {SBOM_JOB}")
    downloads = 0
    for index, step in enumerate(job.get("steps") or []):
        if action_of(step) != DOWNLOAD:
            continue
        downloads += 1
        where = f"jobs.{GRYPE_JOB}.steps[{index}].with"
        given = (step or {}).get("with") or {}
        for key in SELECTORS:
            if key != "artifact-ids" and key in given:
                problems.append(f"{where}.{key} selects by {key}, not by ID")
        if given.get("artifact-ids") != SBOM_ID:
            problems.append(f"{where}.artifact-ids is not {SBOM_ID}")
    if not downloads:
        problems.append(f"jobs.{GRYPE_JOB} has no {DOWNLOAD} step")


def check_doc(name, doc):
    """Return the list of problems in one reusable workflow."""
    problems = []
    spec = inputs_of(doc).get(INPUT)
    if not isinstance(spec, dict):
        problems.append(f"input {INPUT} is missing")
    else:
        if spec.get("type") != "string":
            problems.append(f"input {INPUT} is not type string")
        if spec.get("default") != "":
            problems.append(f"input {INPUT} default is not ''")
    if (doc.get("env") or {}).get(ENV_NAME) != ENV_VALUE:
        problems.append(f"workflow env {ENV_NAME} is not {ENV_VALUE}")

    found = set()
    for job_id, job in jobs_of(doc).items():
        for index, step in enumerate((job or {}).get("steps") or []):
            action = action_of(step)
            given = (step or {}).get("with") or {}
            for key in ("name", "artifact_name", "artifact-name"):
                value = given.get(key)
                if not isinstance(value, str):
                    continue
                if not value.startswith(PER_CALL):
                    continue
                where = f"jobs.{job_id}.steps[{index}].with.{key}"
                if not value.endswith(SUFFIX):
                    problems.append(f"{where} lacks {SUFFIX}: {value!r}")
                found.add((job_id, action, key, value))
    for site in SITES[name]:
        if site not in found:
            job_id, action, key, value = site
            problems.append(
                f"jobs.{job_id} has no {action} step with {key}: {value!r}"
            )
    check_binding(doc, problems)

    step = validate_step(doc)
    if step is None:
        problems.append(f"jobs.gerrit-validate has no '{VALIDATE_STEP}' step")
    else:
        if "if" in step:
            problems.append(f"'{VALIDATE_STEP}' must run unconditionally")
        env = step.get("env") or {}
        if "${{ inputs.%s }}" % INPUT not in env.values():
            problems.append(f"'{VALIDATE_STEP}' does not read {INPUT}")
        if not isinstance(step.get("run"), str) or not step["run"].strip():
            problems.append(f"'{VALIDATE_STEP}' has no run script")
    return problems


def check_caller(doc):
    """Return the list of problems in the testing.yaml caller."""
    problems = []
    job = jobs_of(doc).get(CALLER_JOB) or {}
    given = job.get("with") or {}
    if given.get(INPUT) != "${{ matrix.name }}":
        problems.append(
            f"jobs.{CALLER_JOB} does not pass {INPUT}: ${{{{ matrix.name }}}}"
        )
    legs = ((job.get("strategy") or {}).get("matrix") or {}).get("include")
    names = [str((leg or {}).get("name", "")) for leg in legs or []]
    if len(names) != len(set(names)):
        problems.append(f"jobs.{CALLER_JOB} matrix names are not distinct")
    for leg in names:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", leg):
            problems.append(f"matrix name {leg!r} is not a valid suffix")
    return problems


def run_validate(doc, value):
    step = validate_step(doc)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    for var, ref in (step.get("env") or {}).items():
        if ref == "${{ inputs.%s }}" % INPUT:
            env[var] = value
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        env=env, capture_output=True, text=True, check=False,
    )
    return result.returncode, result.stdout + result.stderr


def exercise_validation(name, doc):
    wrong = 0
    for value in ACCEPTED:
        code, output = run_validate(doc, value)
        if code != 0:
            wrong += 1
            print(f"::error file={name}::{value!r} rejected: {output.strip()}")
    for value in REJECTED:
        code, output = run_validate(doc, value)
        if code == 0:
            wrong += 1
            print(f"::error file={name}::{value!r} accepted")
        elif f"Invalid {INPUT} input" not in output:
            wrong += 1
            print(
                f"::error file={name}::{value!r} rejected without naming"
                f" the input: {output.strip()}"
            )
    total = len(ACCEPTED) + len(REJECTED)
    print(f"{name}: validate step right on {total - wrong}/{total} values")
    return wrong


def mutants(name, doc):
    """Yield (label, mutated doc) for each drift the check must catch."""
    on_key = "on" if "on" in doc else True

    def find(d, job_id, action, key, value):
        for step in d["jobs"][job_id]["steps"]:
            if action_of(step) == action and \
                    (step.get("with") or {}).get(key) == value:
                return step
        raise LookupError((job_id, action, key, value))

    d = copy.deepcopy(doc)
    del d[on_key]["workflow_call"]["inputs"][INPUT]
    yield "drop the input", d
    d = copy.deepcopy(doc)
    d[on_key]["workflow_call"]["inputs"][INPUT]["default"] = "x"
    yield "non-empty default", d
    d = copy.deepcopy(doc)
    del d["env"][ENV_NAME]
    yield "drop the env", d
    d = copy.deepcopy(doc)
    d["env"][ENV_NAME] = "-${{ inputs.artifact_suffix }}"
    yield "env adds a hyphen when unset", d
    for job_id, action, key, value in SITES[name]:
        d = copy.deepcopy(doc)
        step = find(d, job_id, action, key, value)
        step["with"][key] = value[: -len(SUFFIX)]
        yield f"{job_id} {key} without the suffix", d
        d = copy.deepcopy(doc)
        d["jobs"][job_id]["steps"].remove(find(d, job_id, action, key, value))
        yield f"{job_id} {key} site removed", d

    def download(d):
        for step in d["jobs"][GRYPE_JOB]["steps"]:
            if action_of(step) == DOWNLOAD:
                return step
        raise LookupError((GRYPE_JOB, DOWNLOAD))

    d = copy.deepcopy(doc)
    del d["jobs"][SBOM_JOB]["outputs"][SBOM_OUTPUT]
    yield "sbom job drops the artefact ID output", d
    d = copy.deepcopy(doc)
    d["jobs"][SBOM_JOB]["outputs"][SBOM_OUTPUT] = \
        "${{ steps.sbom.outputs.artifact-id }}"
    yield "sbom job reads the ID from another step", d
    d = copy.deepcopy(doc)
    del sbom_upload(d)["id"]
    yield "sbom upload step loses its id", d
    d = copy.deepcopy(doc)
    d["jobs"][GRYPE_JOB]["needs"] = "build"
    yield "grype job no longer needs sbom", d
    d = copy.deepcopy(doc)
    download(d)["with"] = {"name": "sbom-files" + SUFFIX}
    yield "grype downloads by name", d
    d = copy.deepcopy(doc)
    download(d)["with"]["name"] = "sbom-files" + SUFFIX
    yield "grype downloads by name and ID", d
    d = copy.deepcopy(doc)
    download(d)["with"] = {"pattern": "sbom-files*"}
    yield "grype downloads by pattern", d
    d = copy.deepcopy(doc)
    download(d)["with"]["artifact-ids"] = "${{ needs.sbom.outputs.id }}"
    yield "grype downloads another output", d
    d = copy.deepcopy(doc)
    del download(d)["with"]["artifact-ids"]
    yield "grype downloads every artefact", d
    d = copy.deepcopy(doc)
    d["jobs"][GRYPE_JOB]["steps"].remove(download(d))
    yield "grype download removed", d
    d = copy.deepcopy(doc)
    validate_step(d)["if"] = "inputs.artifact_suffix != ''"
    yield "validate step conditional", d
    d = copy.deepcopy(doc)
    d["jobs"]["gerrit-validate"]["steps"].remove(validate_step(d))
    yield "validate step missing", d


def caller_mutants(doc):
    d = copy.deepcopy(doc)
    del d["jobs"][CALLER_JOB]["with"][INPUT]
    yield "caller drops the suffix", d
    d = copy.deepcopy(doc)
    d["jobs"][CALLER_JOB]["with"][INPUT] = "fixed"
    yield "caller passes one suffix to every leg", d
    d = copy.deepcopy(doc)
    legs = d["jobs"][CALLER_JOB]["strategy"]["matrix"]["include"]
    legs[1]["name"] = legs[0]["name"]
    yield "caller legs share a name", d


def self_test(name, doc, check):
    escaped = 0
    total = 0
    generator = caller_mutants(doc) if name == CALLER else mutants(name, doc)
    for label, mutant in generator:
        total += 1
        if not check(yaml.safe_load(yaml.safe_dump(mutant))):
            escaped += 1
            print(f"::error::mutant of {name} not caught: {label}")
    print(f"Mutants of {name} caught: {total - escaped}/{total}")
    return escaped


root = pathlib.Path(sys.argv[1])
failures = 0
docs = {}
for name in sorted(list(SITES) + [CALLER]):
    path = root / name
    if not path.is_file():
        print(f"::error::workflow not found: {path}")
        failures += 1
        continue
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    docs[name] = doc
    problems = check_caller(doc) if name == CALLER else check_doc(name, doc)
    for problem in problems:
        failures += 1
        print(f"::error file={path}::{problem}")
if failures:
    print(f"{failures} problem(s) in the artefact suffix wiring ❌")
    sys.exit(1)
print(f"{len(docs)} workflow(s) wire the artefact suffix ✅")
for name in SITES:
    failures += exercise_validation(name, docs[name])
for name in SITES:
    failures += self_test(
        name, docs[name], lambda d, n=name: check_doc(n, d),
    )
failures += self_test(CALLER, docs[CALLER], check_caller)
if failures:
    sys.exit(1)
PYEOF
