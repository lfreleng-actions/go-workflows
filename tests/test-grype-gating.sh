#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Checks the change-scoped Grype gating wiring in the reusable
# workflows.
#
# Static, from the parsed YAML:
#   - build-test exposes the six grype_* policy inputs and the release
#     workflow the five it takes (a release always gates), each with
#     the agreed type and default;
#   - the sbom job of build-test runs dependency-change-action at the
#     agreed pin, after the checkout and before the SBOM upload, and
#     that checkout fetches depth 2 (at depth 1 every pull request
#     would be unresolved and gate);
#   - dependency-change.json rides in the sbom-files artefact and the
#     grype job names it through dependency-change-manifest;
#   - every policy input reaches grype-scan-action, and the workflow
#     surfaces the gate-active output the self-test asserts.
#
# Dynamic: the 'Validate Grype policy inputs' step of gerrit-validate
# is extracted from each workflow and run under bash with each valid
# and invalid value, so a typo that the step would let through fails
# here.
#
# It then mutates a copy of build-test in each way the static check
# must catch and expects every mutant to fail, so a check that passes
# everything fails here too.
#
# Usage: bash tests/test-grype-gating.sh [<workflows-dir>]
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

# '-I' keeps the working directory and the user site off sys.path, so
# the check runs in the same mode as the parser below: a PyYAML only
# the user site holds would pass a plain import and fail the parse.
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

DETECT_ACTION = "lfreleng-actions/dependency-change-action"
DETECT_PIN = "257928b15e4e6a5cc5a888435be59b058055c4e1"  # v0.0.1
GRYPE_ACTION = "lfreleng-actions/grype-scan-action"
GRYPE_PIN = "5c81b23afb2ea771b2d247807a12d90783328675"  # v0.5.0
CHECKOUT_ACTION = "actions/checkout"
UPLOAD_ACTION = "actions/upload-artifact"
DOWNLOAD_ACTION = "actions/download-artifact"
SIDECAR = "dependency-change.json"
ARTEFACT = "sbom-files"
VALIDATE_STEP = "Validate Grype policy inputs"

# name -> (type, default, grype-scan-action input)
POLICY_INPUTS = {
    "grype_dependency_policy": ("string", "declared", "dependency-policy"),
    "grype_transitive_fail_on": ("string", "critical", "transitive-fail-on"),
    "grype_only_fixed": ("boolean", True, "only-fixed"),
    "grype_remediation_window_days": ("string", "", "remediation-window-days"),
    "grype_remediation_window_start": (
        "string", "", "remediation-window-start",
    ),
}
GATE_WHEN = "grype_gate_when"

# Every workflow_call workflow that calls grype-scan-action; 'verify'
# ones take grype_gate_when and run detection, the rest always gate.
VERIFY = {"build-test.yaml"}
RELEASE = {"build-test-release.yaml"}

# input -> ([accepted], [rejected]) for the extracted validate step.
CASES = {
    GATE_WHEN: (
        ["always", "dependencies-changed"],
        ["", "sometimes", "Always", "dependencies_changed"],
    ),
    "grype_dependency_policy": (
        ["all", "declared"],
        ["", "direct", "Declared", "all "],
    ),
    "grype_transitive_fail_on": (
        ["none", "negligible", "low", "medium", "high", "critical"],
        ["", "severe", "Critical", "critical,high"],
    ),
    "grype_remediation_window_days": (
        ["", "0", "7", "30", "365"],
        ["7d", "-1", "1.5", "seven", " 7"],
    ),
    "grype_remediation_window_start": (
        ["", "2026-01-01", "2026-11-03", "2024-02-29"],
        [
            "2026-1-1", "20260101", "yesterday", "2026-01-01T00:00:00Z",
            # Right shape, impossible on the calendar.
            "2026-02-31", "2025-02-29", "2026-13-01", "2026-00-10",
            "2026-11-31",
        ],
    ),
}


def triggers(doc):
    # PyYAML reads a bare 'on' key as the boolean True.
    on = doc.get("on", doc.get(True))
    return on if isinstance(on, dict) else {}


def inputs_of(doc):
    return (triggers(doc).get("workflow_call") or {}).get("inputs") or {}


def steps_of(doc, job_id):
    job = (doc.get("jobs") or {}).get(job_id) or {}
    return list(job.get("steps") or [])


def find_step(steps, action):
    """Return (index, step) of the first step using the action."""
    for index, step in enumerate(steps):
        uses = str((step or {}).get("uses", ""))
        if uses.split("@", 1)[0] == action:
            return index, step
    return None, None


def check_input(inputs, name, kind, default, problems):
    spec = inputs.get(name)
    if not isinstance(spec, dict):
        problems.append(f"input {name} is missing")
        return
    if spec.get("type") != kind:
        problems.append(f"input {name} is not type {kind}")
    value = spec.get("default")
    if value != default or type(value) is not type(default):
        problems.append(f"input {name} default is not {default!r}")


def check_grype_step(doc, verify, problems):
    steps = steps_of(doc, "grype")
    _, download = find_step(steps, DOWNLOAD_ACTION)
    if download is None or (download.get("with") or {}).get("name") != ARTEFACT:
        problems.append(f"jobs.grype does not download {ARTEFACT}")
    index, step = find_step(steps, GRYPE_ACTION)
    if step is None:
        problems.append(f"jobs.grype does not call {GRYPE_ACTION}")
        return
    where = f"jobs.grype.steps[{index}]"
    if step["uses"].partition("@")[2] != GRYPE_PIN:
        problems.append(f"{where} does not pin {GRYPE_ACTION}@{GRYPE_PIN}")
    given = step.get("with") or {}
    for name, (_, _, key) in POLICY_INPUTS.items():
        expected = "${{ inputs.%s }}" % name
        if given.get(key) != expected:
            problems.append(f"{where} does not pass {key} as {expected}")
    if verify:
        if given.get("gate-when") != "${{ inputs.%s }}" % GATE_WHEN:
            problems.append(f"{where} does not pass gate-when from the input")
        if given.get("dependency-change-manifest") != SIDECAR:
            problems.append(f"{where} does not name {SIDECAR}")
        outputs = (doc["jobs"]["grype"].get("outputs") or {})
        step_id = step.get("id")
        wanted = "${{ steps.%s.outputs.gate-active }}" % step_id
        if not step_id or outputs.get("gate_active") != wanted:
            problems.append("jobs.grype.outputs.gate_active is not gate-active")
        call = triggers(doc).get("workflow_call") or {}
        exposed = ((call.get("outputs") or {}).get("grype_gate_active") or {})
        if exposed.get("value") != "${{ jobs.grype.outputs.gate_active }}":
            problems.append("output grype_gate_active is missing")
    else:
        if given.get("gate-when") != "always":
            problems.append(f"{where} must fix gate-when to always")
        if "dependency-change-manifest" in given:
            problems.append(f"{where} must not read a sidecar on a release")


def check_detection(doc, problems):
    steps = steps_of(doc, "sbom")
    checkout_index, checkout = find_step(steps, CHECKOUT_ACTION)
    if checkout is None:
        problems.append("jobs.sbom has no actions/checkout step")
        return
    depth = (checkout.get("with") or {}).get("fetch-depth")
    # Depth 0 is a full clone and also serves; 1 cannot diff a parent.
    if not isinstance(depth, int) or isinstance(depth, bool) or depth == 1 \
            or depth < 0:
        problems.append(
            f"jobs.sbom.steps[{checkout_index}] fetch-depth must be 0 or"
            f" >= 2, is {depth!r}"
        )
    detect_index, detect = find_step(steps, DETECT_ACTION)
    if detect is None:
        problems.append(f"jobs.sbom does not call {DETECT_ACTION}")
        return
    where = f"jobs.sbom.steps[{detect_index}]"
    if detect["uses"].partition("@")[2] != DETECT_PIN:
        problems.append(f"{where} does not pin {DETECT_ACTION}@{DETECT_PIN}")
    if detect.get("id") != "dependency-change":
        problems.append(f"{where} id is not dependency-change")
    wanted_if = (
        "inputs.grype_enabled && inputs.%s == 'dependencies-changed'"
        % GATE_WHEN
    )
    if detect.get("if") != wanted_if:
        problems.append(f"{where} does not run on {wanted_if}")
    given = detect.get("with") or {}
    for key, expected in {
        "ecosystems": "go",
        "path-prefix": "${{ inputs.path_prefix }}",
        "gerrit-refspec": "${{ inputs.gerrit_refspec }}",
        "output": SIDECAR,
    }.items():
        if given.get(key) != expected:
            problems.append(f"{where} does not pass {key} as {expected!r}")
    upload_index, upload = find_step(steps, UPLOAD_ACTION)
    if upload is None:
        problems.append("jobs.sbom has no upload-artifact step")
        return
    if not checkout_index < detect_index < upload_index:
        problems.append(
            f"{where} must follow the checkout and precede the upload"
        )
    given = upload.get("with") or {}
    paths = str(given.get("path", "")).split()
    if given.get("name") != ARTEFACT or SIDECAR not in paths:
        problems.append(
            f"jobs.sbom.steps[{upload_index}] does not carry {SIDECAR}"
            f" in {ARTEFACT}"
        )
    if given.get("if-no-files-found") != "error":
        problems.append(
            f"jobs.sbom.steps[{upload_index}] must still fail on a missing"
            " SBOM"
        )


def check_release_has_no_detection(doc, problems):
    for job_id in doc.get("jobs") or {}:
        index, step = find_step(steps_of(doc, job_id), DETECT_ACTION)
        if step is not None:
            problems.append(
                f"jobs.{job_id}.steps[{index}] runs detection on a release"
            )


def validate_step(doc):
    for step in steps_of(doc, "gerrit-validate"):
        if (step or {}).get("name") == VALIDATE_STEP:
            return step
    return None


def check_validate_step(doc, verify, problems):
    step = validate_step(doc)
    if step is None:
        problems.append(f"jobs.gerrit-validate has no '{VALIDATE_STEP}' step")
        return
    if "if" in step:
        problems.append(f"'{VALIDATE_STEP}' must run unconditionally")
    env = step.get("env") or {}
    referenced = set()
    for value in env.values():
        match = re.fullmatch(r"\$\{\{ inputs\.([a-z_]+) \}\}", str(value))
        if match:
            referenced.add(match.group(1))
    expected = {
        name for name, (kind, _, _) in POLICY_INPUTS.items() if kind == "string"
    }
    if verify:
        expected.add(GATE_WHEN)
    for name in sorted(expected - referenced):
        problems.append(f"'{VALIDATE_STEP}' does not read {name}")
    if not isinstance(step.get("run"), str) or not step["run"].strip():
        problems.append(f"'{VALIDATE_STEP}' has no run script")


def check_doc(name, doc):
    """Return the list of problems in one parsed workflow."""
    verify = name in VERIFY
    problems = []
    inputs = inputs_of(doc)
    for input_name, (kind, default, _) in POLICY_INPUTS.items():
        check_input(inputs, input_name, kind, default, problems)
    if verify:
        check_input(inputs, GATE_WHEN, "string", "always", problems)
        check_detection(doc, problems)
    else:
        if GATE_WHEN in inputs:
            problems.append(f"input {GATE_WHEN} is not a release input")
        check_release_has_no_detection(doc, problems)
    check_grype_step(doc, verify, problems)
    check_validate_step(doc, verify, problems)
    return problems


def run_validate(doc, overrides):
    """Run the extracted validate step; return its exit code."""
    step = validate_step(doc)
    inputs = inputs_of(doc)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    for var, value in (step.get("env") or {}).items():
        match = re.fullmatch(r"\$\{\{ inputs\.([a-z_]+) \}\}", str(value))
        name = match.group(1)
        default = inputs[name].get("default", "")
        env[var] = str(overrides.get(name, default))
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        env=env, capture_output=True, text=True, check=False,
    )
    return result.returncode, result.stdout + result.stderr


def exercise_validation(name, doc):
    """Return the number of cases the validate step got wrong."""
    verify = name in VERIFY
    wrong = 0
    total = 0
    code, output = run_validate(doc, {})
    total += 1
    if code != 0:
        wrong += 1
        print(f"::error file={name}::defaults rejected: {output.strip()}")
    for input_name, (accepted, rejected) in CASES.items():
        if input_name == GATE_WHEN and not verify:
            continue
        for value in accepted:
            total += 1
            code, output = run_validate(doc, {input_name: value})
            if code != 0:
                wrong += 1
                print(
                    f"::error file={name}::{input_name}={value!r} rejected:"
                    f" {output.strip()}"
                )
        for value in rejected:
            total += 1
            code, output = run_validate(doc, {input_name: value})
            if code == 0:
                wrong += 1
                print(f"::error file={name}::{input_name}={value!r} accepted")
            elif f"Invalid {input_name} input" not in output:
                wrong += 1
                print(
                    f"::error file={name}::{input_name}={value!r} rejected"
                    f" without naming the input: {output.strip()}"
                )
    print(f"{name}: validate step right on {total - wrong}/{total} values")
    return wrong


def pin_comment(path, action, pin, tag):
    """The pinned 'uses:' line must carry its version comment."""
    pattern = re.compile(
        r"uses:\s+%s@%s\s+#\s+%s\b" % (
            re.escape(action), re.escape(pin), re.escape(tag),
        )
    )
    if not pattern.search(path.read_text(encoding="utf-8")):
        return [f"{action}@{pin} lacks its '# {tag}' comment"]
    return []


def mutants(doc):
    """Yield (label, mutated doc) for each drift the check must catch."""
    on_key = "on" if "on" in doc else True

    def inputs(d):
        return d[on_key]["workflow_call"]["inputs"]

    def step(d, job, action):
        return find_step(steps_of(d, job), action)[1]

    for name in list(POLICY_INPUTS) + [GATE_WHEN]:
        d = copy.deepcopy(doc)
        del inputs(d)[name]
        yield f"drop input {name}", d
    d = copy.deepcopy(doc)
    inputs(d)[GATE_WHEN]["default"] = "dependencies-changed"
    yield "gate_when defaults to dependencies-changed", d
    d = copy.deepcopy(doc)
    inputs(d)["grype_only_fixed"]["default"] = False
    yield "only_fixed defaults to false", d
    d = copy.deepcopy(doc)
    inputs(d)["grype_remediation_window_days"]["default"] = "30"
    yield "remediation window on by default", d
    d = copy.deepcopy(doc)
    del step(d, "sbom", CHECKOUT_ACTION)["with"]["fetch-depth"]
    yield "sbom checkout at default depth", d
    d = copy.deepcopy(doc)
    step(d, "sbom", CHECKOUT_ACTION)["with"]["fetch-depth"] = 1
    yield "sbom checkout at depth 1", d
    d = copy.deepcopy(doc)
    step(d, "sbom", DETECT_ACTION)["uses"] = f"{DETECT_ACTION}@{'0' * 40}"
    yield "detection pinned elsewhere", d
    d = copy.deepcopy(doc)
    step(d, "sbom", DETECT_ACTION)["if"] = "inputs.grype_enabled"
    yield "detection runs on always", d
    d = copy.deepcopy(doc)
    step(d, "sbom", DETECT_ACTION)["with"]["ecosystems"] = "python"
    yield "detection preset not go", d
    d = copy.deepcopy(doc)
    steps = d["jobs"]["sbom"]["steps"]
    index, detect = find_step(steps, DETECT_ACTION)
    steps.append(steps.pop(index))
    yield "detection after the upload", d
    d = copy.deepcopy(doc)
    step(d, "sbom", UPLOAD_ACTION)["with"]["path"] = "sbom-cyclonedx.*"
    yield "sidecar left out of the artefact", d
    d = copy.deepcopy(doc)
    step(d, "sbom", UPLOAD_ACTION)["with"]["if-no-files-found"] = "ignore"
    yield "upload ignores a missing SBOM", d
    for _, _, key in POLICY_INPUTS.values():
        d = copy.deepcopy(doc)
        del step(d, "grype", GRYPE_ACTION)["with"][key]
        yield f"grype step drops {key}", d
    d = copy.deepcopy(doc)
    del step(d, "grype", GRYPE_ACTION)["with"]["dependency-change-manifest"]
    yield "grype step drops the manifest", d
    d = copy.deepcopy(doc)
    step(d, "grype", GRYPE_ACTION)["with"]["gate-when"] = "always"
    yield "grype step fixes gate-when", d
    d = copy.deepcopy(doc)
    del d["jobs"]["grype"]["outputs"]
    yield "grype job drops gate_active", d
    d = copy.deepcopy(doc)
    del d[on_key]["workflow_call"]["outputs"]["grype_gate_active"]
    yield "workflow drops grype_gate_active", d
    d = copy.deepcopy(doc)
    validate = validate_step(d)
    validate["env"].pop(
        next(k for k, v in validate["env"].items() if GATE_WHEN in v)
    )
    yield "validate step ignores gate_when", d
    d = copy.deepcopy(doc)
    validate_step(d)["if"] = "inputs.grype_enabled"
    yield "validate step conditional", d
    d = copy.deepcopy(doc)
    d["jobs"]["gerrit-validate"]["steps"].remove(validate_step(d))
    yield "validate step missing", d


def self_test(name, doc):
    """Expect every mutant of the verify workflow to fail."""
    escaped = 0
    total = 0
    for label, mutant in mutants(doc):
        total += 1
        # Round-trip through YAML as the real check does.
        if not check_doc(name, yaml.safe_load(yaml.safe_dump(mutant))):
            escaped += 1
            print(f"::error::mutant not caught: {label}")
    print(f"Mutants of {name} caught: {total - escaped}/{total}")
    return escaped


root = pathlib.Path(sys.argv[1])
failures = 0
docs = {}
for workflow in sorted(root.glob("*.y*ml")):
    if workflow.name not in VERIFY | RELEASE:
        continue
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    docs[workflow.name] = doc
    problems = check_doc(workflow.name, doc)
    problems += pin_comment(workflow, GRYPE_ACTION, GRYPE_PIN, "v0.5.0")
    if workflow.name in VERIFY:
        problems += pin_comment(workflow, DETECT_ACTION, DETECT_PIN, "v0.0.1")
    for problem in problems:
        failures += 1
        print(f"::error file={workflow}::{problem}")
missing = (VERIFY | RELEASE) - set(docs)
if missing:
    print(f"::error::workflows not found in {root}: {sorted(missing)}")
    sys.exit(1)
if failures:
    print(f"{failures} problem(s) across {len(docs)} workflow(s) ❌")
    sys.exit(1)
print(f"{len(docs)} workflow(s) wire the Grype gating inputs ✅")
for name, doc in docs.items():
    failures += exercise_validation(name, doc)
if failures:
    sys.exit(1)
for name in sorted(VERIFY):
    failures += self_test(name, docs[name])
if failures:
    sys.exit(1)
PYEOF
