#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Checks the change-scoped Grype gating wiring in the reusable
# workflows.
#
# Static, from the parsed YAML:
#   - build-test exposes the grype_* policy, detection and bypass
#     inputs and the release workflow the ones it takes (a release
#     always gates and detects nothing), each with the agreed type and
#     default;
#   - every workflow pins repository-metadata-action at v0.4.0, and in
#     build-test its step detects only when grype_gate_when is
#     'dependencies-changed', with the refspec, presets, patterns and
#     path prefix passed through, and its job exports the verdict as
#     dependencies_changed;
#   - the grype job needs repository-metadata yet still runs when it
#     fails or skips (!cancelled(), no result requirement), and passes
#     the verdict only when that job succeeded;
#   - no dependency-change-action call, sidecar file, manifest input or
#     detection-only sbom checkout depth remains;
#   - every policy input reaches grype-scan-action, and the workflow
#     surfaces the gate-active and verdict outputs the self-test
#     asserts.
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

METADATA_ACTION = "lfreleng-actions/repository-metadata-action"
METADATA_PIN = "18e5b7c5b16423b0e734891d103513826b324858"  # v0.4.0
METADATA_TAG = "v0.4.0"
METADATA_JOB = "repository-metadata"
# Detection moved into repository-metadata-action; no workflow may
# call the detector itself or carry its sidecar any more.
DETECT_ACTION = "lfreleng-actions/dependency-change-action"
RETIRED = ("dependency-change.json", "dependency-change-manifest")
GRYPE_ACTION = "lfreleng-actions/grype-scan-action"
GRYPE_PIN = "5c81b23afb2ea771b2d247807a12d90783328675"  # v0.5.0
CHECKOUT_ACTION = "actions/checkout"
DOWNLOAD_ACTION = "actions/download-artifact"
# The per-call suffix and the download's binding to the upload by ID
# are checked in tests/test-artifact-suffix.sh.
ARTEFACT_ID = "${{ needs.sbom.outputs.sbom_artifact_id }}"
VALIDATE_STEP = "Validate Grype policy inputs"

DETECT_ON = (
    "${{ inputs.grype_enabled"
    " && inputs.grype_gate_when == 'dependencies-changed' }}"
)
# Runs whatever repository-metadata's result; the verdict below is
# empty unless that job succeeded, and empty gates.
GRYPE_IF = (
    "${{ !cancelled() && needs.sbom.result == 'success'"
    " && inputs.grype_enabled }}"
)
VERDICT = (
    "${{ needs.%s.result == 'success'"
    " && needs.%s.outputs.dependencies_changed || '' }}"
    % (METADATA_JOB, METADATA_JOB)
)
# A workflow_call output cannot read a job's result, so the grype job
# re-exports the guarded verdict it received and the workflow surfaces
# that.
VERDICT_OUTPUT = "${{ jobs.grype.outputs.dependencies_changed }}"

# name -> (type, default, grype-scan-action input); both workflows.
POLICY_INPUTS = {
    "grype_dependency_policy": ("string", "declared", "dependency-policy"),
    "grype_transitive_fail_on": ("string", "critical", "transitive-fail-on"),
    "grype_only_fixed": ("boolean", True, "only-fixed"),
    "grype_remediation_window_days": ("string", "", "remediation-window-days"),
    "grype_remediation_window_start": (
        "string", "", "remediation-window-start",
    ),
    "grype_bypass_repository": ("string", "", "bypass-repository"),
}
FAIL_ON = "grype_fail_on"
GATE_WHEN = "grype_gate_when"
# name -> repository-metadata-action input; verify workflows only.
DETECTION_INPUTS = {
    "grype_dependency_ecosystems": "dependency_ecosystems",
    "grype_dependency_patterns": "dependency_patterns",
}
# Validated in gerrit-validate; the patterns are left to the detector.
VALIDATED = {FAIL_ON, "grype_bypass_repository"} | {
    name for name, (kind, _, _) in POLICY_INPUTS.items() if kind == "string"
}
VALIDATED_VERIFY = {GATE_WHEN, "grype_dependency_ecosystems"}

# Every workflow_call workflow that calls grype-scan-action; 'verify'
# ones take grype_gate_when and detect, the rest always gate.
VERIFY = {"build-test.yaml"}
RELEASE = {"build-test-release.yaml"}

# input -> ([accepted], [rejected]) for the extracted validate step.
CASES = {
    FAIL_ON: (
        ["negligible", "low", "medium", "high", "critical", "none"],
        ["", "severe", "Medium", "medium,high", " high"],
    ),
    GATE_WHEN: (
        ["always", "dependencies-changed"],
        ["", "sometimes", "Always", "dependencies_changed"],
    ),
    "grype_dependency_ecosystems": (
        [
            "", "go", "go,node", " go , python ",
            "node,python,go,maven,gradle,rust,docker",
        ],
        [
            "golang", "Go", "go,", ",go", "go,,node", "go;node", "go node",
            "go\nnode", "npm",
        ],
    ),
    "grype_bypass_repository": (
        ["", "lfreleng-actions/.github", "Owner_1/repo-name.x"],
        [
            "owner", "owner/", "/name", "owner/name/extra", "owner name/x",
            "https://github.com/o/n", "o/n;x", "o/n\n",
        ],
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
VERIFY_ONLY_CASES = {GATE_WHEN, "grype_dependency_ecosystems"}


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


def check_metadata(doc, verify, problems):
    job = (doc.get("jobs") or {}).get(METADATA_JOB) or {}
    index, step = find_step(steps_of(doc, METADATA_JOB), METADATA_ACTION)
    if step is None:
        problems.append(f"jobs.{METADATA_JOB} does not call {METADATA_ACTION}")
        return
    where = f"jobs.{METADATA_JOB}.steps[{index}]"
    if step["uses"].partition("@")[2] != METADATA_PIN:
        problems.append(
            f"{where} does not pin {METADATA_ACTION}@{METADATA_PIN}"
        )
    given = step.get("with") or {}
    if not verify:
        if "dependency_change" in given:
            problems.append(f"{where} must not detect on a release")
        return
    wanted = {
        "dependency_change": DETECT_ON,
        "gerrit_refspec": "${{ inputs.gerrit_refspec }}",
        "dependency_path_prefix": "${{ inputs.path_prefix }}",
    }
    for name, key in DETECTION_INPUTS.items():
        wanted[key] = "${{ inputs.%s }}" % name
    for key, expected in wanted.items():
        if given.get(key) != expected:
            problems.append(f"{where} does not pass {key} as {expected}")
    step_id = step.get("id")
    expected = "${{ steps.%s.outputs.dependencies_changed }}" % step_id
    if not step_id or \
            (job.get("outputs") or {}).get("dependencies_changed") != expected:
        problems.append(
            f"jobs.{METADATA_JOB}.outputs.dependencies_changed is not"
            " the step's verdict"
        )


def check_grype_step(doc, verify, problems):
    job = (doc.get("jobs") or {}).get("grype") or {}
    steps = steps_of(doc, "grype")
    _, download = find_step(steps, DOWNLOAD_ACTION)
    if download is None or \
            (download.get("with") or {}).get("artifact-ids") != ARTEFACT_ID:
        problems.append(f"jobs.grype does not download {ARTEFACT_ID}")
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
    for key in RETIRED:
        if key in given:
            problems.append(f"{where} still passes {key}")
    if verify:
        needs = job.get("needs")
        needs = [needs] if isinstance(needs, str) else list(needs or [])
        if "sbom" not in needs or METADATA_JOB not in needs:
            problems.append(f"jobs.grype must need sbom and {METADATA_JOB}")
        # Exact, so the job cannot come to require the metadata job's
        # success (which would skip the scan) or lose !cancelled().
        if job.get("if") != GRYPE_IF:
            problems.append(f"jobs.grype must run on {GRYPE_IF}")
        if given.get("gate-when") != "${{ inputs.%s }}" % GATE_WHEN:
            problems.append(f"{where} does not pass gate-when from the input")
        if given.get("dependencies-changed") != VERDICT:
            problems.append(
                f"{where} does not pass dependencies-changed as {VERDICT}"
            )
        outputs = job.get("outputs") or {}
        step_id = step.get("id")
        wanted = "${{ steps.%s.outputs.gate-active }}" % step_id
        if not step_id or outputs.get("gate_active") != wanted:
            problems.append("jobs.grype.outputs.gate_active is not gate-active")
        if outputs.get("dependencies_changed") != VERDICT:
            problems.append(
                f"jobs.grype.outputs.dependencies_changed is not {VERDICT}"
            )
        call = triggers(doc).get("workflow_call") or {}
        exposed = call.get("outputs") or {}
        if (exposed.get("grype_gate_active") or {}).get("value") != \
                "${{ jobs.grype.outputs.gate_active }}":
            problems.append("output grype_gate_active is missing")
        if (exposed.get("grype_dependencies_changed") or {}).get("value") \
                != VERDICT_OUTPUT:
            problems.append(
                f"output grype_dependencies_changed is not {VERDICT_OUTPUT}"
            )
    else:
        if given.get("gate-when") != "always":
            problems.append(f"{where} must fix gate-when to always")
        if "dependencies-changed" in given:
            problems.append(f"{where} must not read a verdict on a release")


def check_retired(doc, problems):
    """No detector call, sidecar or detection-only depth remains."""
    for job_id in doc.get("jobs") or {}:
        index, step = find_step(steps_of(doc, job_id), DETECT_ACTION)
        if step is not None:
            problems.append(
                f"jobs.{job_id}.steps[{index}] still calls {DETECT_ACTION}"
            )
    # Values only: the raw text check in main() covers comments too.
    dumped = yaml.safe_dump(doc)
    for word in RETIRED:
        if word in dumped:
            problems.append(f"{word} still appears in the workflow")
    index, checkout = find_step(steps_of(doc, "sbom"), CHECKOUT_ACTION)
    if checkout is not None and \
            "fetch-depth" in (checkout.get("with") or {}):
        problems.append(
            f"jobs.sbom.steps[{index}] keeps a fetch-depth the sbom job"
            " no longer needs"
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
    expected = set(VALIDATED)
    if verify:
        expected |= VALIDATED_VERIFY
    for name in sorted(expected - referenced):
        problems.append(f"'{VALIDATE_STEP}' does not read {name}")
    if not isinstance(step.get("run"), str) or not step["run"].strip():
        problems.append(f"'{VALIDATE_STEP}' has no run script")


def check_doc(name, doc):
    """Return the list of problems in one parsed workflow."""
    verify = name in VERIFY
    problems = []
    inputs = inputs_of(doc)
    check_input(inputs, FAIL_ON, "string", "medium", problems)
    for input_name, (kind, default, _) in POLICY_INPUTS.items():
        check_input(inputs, input_name, kind, default, problems)
    if verify:
        check_input(inputs, GATE_WHEN, "string", "always", problems)
        for input_name in DETECTION_INPUTS:
            check_input(inputs, input_name, "string", "", problems)
    else:
        for input_name in [GATE_WHEN] + list(DETECTION_INPUTS):
            if input_name in inputs:
                problems.append(f"input {input_name} is not a release input")
    check_metadata(doc, verify, problems)
    check_retired(doc, problems)
    check_grype_step(doc, verify, problems)
    check_validate_step(doc, verify, problems)
    return problems


def check_text(path):
    """Checks on the raw file: pins and their comments, retired words."""
    text = path.read_text(encoding="utf-8")
    problems = []
    for action, pin, tag in (
        (GRYPE_ACTION, GRYPE_PIN, "v0.5.0"),
        (METADATA_ACTION, METADATA_PIN, METADATA_TAG),
    ):
        for line in re.findall(
            r"uses:\s+%s@\S+.*" % re.escape(action), text,
        ):
            if not re.fullmatch(
                r"uses:\s+%s@%s\s+#\s+%s\b.*"
                % (re.escape(action), re.escape(pin), re.escape(tag)),
                line,
            ):
                problems.append(f"'{line.strip()}' is not {action}@{pin}"
                                f" # {tag}")
    for word in RETIRED:
        if word in text:
            problems.append(f"{word} still appears in {path.name}")
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
        if input_name in VERIFY_ONLY_CASES and not verify:
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


def mutants(doc):
    """Yield (label, mutated doc) for each drift the check must catch."""
    on_key = "on" if "on" in doc else True

    def inputs(d):
        return d[on_key]["workflow_call"]["inputs"]

    def step(d, job, action):
        return find_step(steps_of(d, job), action)[1]

    def metadata(d):
        return step(d, METADATA_JOB, METADATA_ACTION)

    def grype(d):
        return step(d, "grype", GRYPE_ACTION)

    for name in [FAIL_ON, GATE_WHEN] + list(POLICY_INPUTS) + \
            list(DETECTION_INPUTS):
        d = copy.deepcopy(doc)
        del inputs(d)[name]
        yield f"drop input {name}", d
    d = copy.deepcopy(doc)
    inputs(d)[GATE_WHEN]["default"] = "dependencies-changed"
    yield "gate_when defaults to dependencies-changed", d
    d = copy.deepcopy(doc)
    inputs(d)[FAIL_ON]["default"] = "high"
    yield "fail_on default changed", d
    d = copy.deepcopy(doc)
    inputs(d)["grype_only_fixed"]["default"] = False
    yield "only_fixed defaults to false", d
    d = copy.deepcopy(doc)
    inputs(d)["grype_remediation_window_days"]["default"] = "30"
    yield "remediation window on by default", d
    d = copy.deepcopy(doc)
    inputs(d)["grype_dependency_ecosystems"]["default"] = "go"
    yield "ecosystems narrowed by default", d
    d = copy.deepcopy(doc)
    metadata(d)["uses"] = f"{METADATA_ACTION}@{'0' * 40}"
    yield "metadata action pinned elsewhere", d
    d = copy.deepcopy(doc)
    metadata(d)["with"]["dependency_change"] = "true"
    yield "detection runs on always", d
    for key in ["dependency_change", "gerrit_refspec",
                "dependency_path_prefix"] + list(DETECTION_INPUTS.values()):
        d = copy.deepcopy(doc)
        del metadata(d)["with"][key]
        yield f"metadata step drops {key}", d
    d = copy.deepcopy(doc)
    del d["jobs"][METADATA_JOB]["outputs"]
    yield "metadata job drops dependencies_changed", d
    d = copy.deepcopy(doc)
    d["jobs"]["grype"]["needs"] = "sbom"
    yield "grype job does not need the metadata job", d
    d = copy.deepcopy(doc)
    d["jobs"]["grype"]["if"] = GRYPE_IF.replace(
        " }}", f" && needs.{METADATA_JOB}.result == 'success' }}}}"
    )
    yield "grype job skips when metadata fails", d
    d = copy.deepcopy(doc)
    d["jobs"]["grype"]["if"] = GRYPE_IF.replace("!cancelled() && ", "")
    yield "grype job drops !cancelled()", d
    d = copy.deepcopy(doc)
    grype(d)["with"]["dependencies-changed"] = (
        "${{ needs.%s.outputs.dependencies_changed }}" % METADATA_JOB
    )
    yield "verdict not guarded by the job result", d
    d = copy.deepcopy(doc)
    grype(d)["with"]["dependency-change-manifest"] = RETIRED[0]
    yield "grype step reads the sidecar again", d
    d = copy.deepcopy(doc)
    d["jobs"]["sbom"]["steps"].insert(0, {
        "uses": f"{DETECT_ACTION}@{'0' * 40}", "with": {"ecosystems": "go"},
    })
    yield "sbom job runs the detector again", d
    d = copy.deepcopy(doc)
    step(d, "sbom", CHECKOUT_ACTION)["with"]["fetch-depth"] = 2
    yield "sbom checkout keeps depth 2", d
    for _, _, key in POLICY_INPUTS.values():
        d = copy.deepcopy(doc)
        del grype(d)["with"][key]
        yield f"grype step drops {key}", d
    d = copy.deepcopy(doc)
    grype(d)["with"]["gate-when"] = "always"
    yield "grype step fixes gate-when", d
    d = copy.deepcopy(doc)
    del d["jobs"]["grype"]["outputs"]
    yield "grype job drops gate_active", d
    d = copy.deepcopy(doc)
    d["jobs"]["grype"]["outputs"]["dependencies_changed"] = (
        "${{ needs.%s.outputs.dependencies_changed }}" % METADATA_JOB
    )
    yield "grype job exports an unguarded verdict", d
    for output in ("grype_gate_active", "grype_dependencies_changed"):
        d = copy.deepcopy(doc)
        del d[on_key]["workflow_call"]["outputs"][output]
        yield f"workflow drops {output}", d
    for name in sorted(VALIDATED | VALIDATED_VERIFY):
        d = copy.deepcopy(doc)
        validate = validate_step(d)
        validate["env"].pop(
            next(k for k, v in validate["env"].items()
                 if v == "${{ inputs.%s }}" % name)
        )
        yield f"validate step ignores {name}", d
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
    # The single pin covers every workflow that calls the action.
    problems = [p for p in check_text(workflow)
                if workflow.name in VERIFY | RELEASE or METADATA_ACTION in p]
    if workflow.name in VERIFY | RELEASE:
        doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        docs[workflow.name] = doc
        problems += check_doc(workflow.name, doc)
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
