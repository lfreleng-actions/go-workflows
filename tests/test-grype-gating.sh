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
#     asserts;
#   - gerrit-validate validates the Grype inputs through
#     grype-scan-action itself, in validate-only mode, at the scan
#     step's pin and with the scan step's own expressions for every
#     input it passes (read from the scan step, less the ones only a
#     scan has, so an input added to the scan and not to the validator
#     fails here) and nothing else: no sbom, no target; the job runs no
#     other action and no shell check of a grype-scan-action input;
#   - testing.yaml's check job runs that validation at the same pin
#     with build-test's defaults and a gate-when the action rejects,
#     under continue-on-error, and asserts the rejection.
#
# Dynamic: the 'Validate grype_dependency_ecosystems input' step of
# build-test's gerrit-validate, the one Grype-adjacent input the
# action does not own, is extracted and run under bash with each valid
# and invalid value. The grype-scan-action inputs themselves are
# checked by the action's own suite, not re-tested here.
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
GRYPE_PIN = "f65dca2762823cfc8f376e32fee9baa6f3292696"  # v0.6.2
GRYPE_TAG = "v0.6.2"
GRYPE_USES = f"{GRYPE_ACTION}@{GRYPE_PIN}"
CHECKOUT_ACTION = "actions/checkout"
DOWNLOAD_ACTION = "actions/download-artifact"
# The per-call suffix and the download's binding to the upload by ID
# are checked in tests/test-artifact-suffix.sh.
ARTEFACT_ID = "${{ needs.sbom.outputs.sbom_artifact_id }}"
VALIDATE_JOB = "gerrit-validate"
VALIDATE_STEP = "Validate Grype inputs"
ECOSYSTEMS_STEP = "Validate grype_dependency_ecosystems input"
ECOSYSTEMS_INPUT = "grype_dependency_ecosystems"
# The scan step's inputs that only a scan has, so the validator
# must not mirror them: the SBOM (validate-only has nothing to scan
# and rejects one), the soft-fail switch applied after evaluation,
# the verdict of a job that runs after this one, the report artefact
# and the token that reads bypass issues. Everything else the scan
# passes, the validator passes as the same expression.
SCAN_ONLY = frozenset({
    "sbom", "target", "permit-fail", "dependencies-changed",
    "artifact-name", "github-token",
})
# testing.yaml proves the rejection end to end: a job calling the
# workflow cannot set continue-on-error, so it runs the validation
# step itself, with build-test's defaults and a gate-when the action
# does not know.
CALLER = "testing.yaml"
CHECK_JOB = "grype-validate-check"
GATE_WHEN_VALUES = {"always", "dependencies-changed"}

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

# Every workflow_call workflow that calls grype-scan-action; 'verify'
# ones take grype_gate_when and detect, the rest always gate.
VERIFY = {"build-test.yaml"}
RELEASE = {"build-test-release.yaml"}

# ([accepted], [rejected]) for the extracted ecosystems step: the one
# Grype-adjacent rule still written in shell, as an input of
# repository-metadata-action rather than of grype-scan-action.
ECOSYSTEMS_CASES = (
    [
        "", "go", "go,node", " go , python ",
        "node,python,go,maven,gradle,rust,docker",
    ],
    [
        "golang", "Go", "go,", ",go", "go,,node", "go;node", "go node",
        "go\nnode", "npm",
    ],
)


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


def steps_named(steps, name):
    """Return every step carrying the name, so a duplicate shows."""
    return [step for step in steps if (step or {}).get("name") == name]


def steps_using(steps, action):
    """Return every step using the action, so a duplicate shows."""
    return [
        step for step in steps
        if str((step or {}).get("uses", "")).split("@", 1)[0] == action
    ]


def the_one(found, what, problems):
    """Return the single match, or record why there is none."""
    if len(found) == 1:
        return found[0]
    if not found:
        problems.append(f"{what} is missing")
    else:
        problems.append(f"{what} matches {len(found)} steps")
    return None


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


def mirrored(scan):
    """The validator's with: block the scan step calls for."""
    given = scan.get("with") or {}
    return {"validate-only": "true", **{
        key: value for key, value in given.items() if key not in SCAN_ONLY
    }}


def validate_step(doc, problems=None):
    """The one validation step of gerrit-validate, or None."""
    return the_one(
        steps_named(steps_of(doc, VALIDATE_JOB), VALIDATE_STEP),
        f"jobs.{VALIDATE_JOB} step '{VALIDATE_STEP}'",
        [] if problems is None else problems,
    )


def ecosystems_step(doc, problems=None):
    """The one ecosystems step of gerrit-validate, or None."""
    return the_one(
        steps_named(steps_of(doc, VALIDATE_JOB), ECOSYSTEMS_STEP),
        f"jobs.{VALIDATE_JOB} step '{ECOSYSTEMS_STEP}'",
        [] if problems is None else problems,
    )


def grype_inputs_read(step):
    """The grype_* inputs a run: step reads through its env."""
    read = set()
    for value in (step.get("env") or {}).values():
        read |= set(re.findall(r"inputs\.(grype_[a-z_]+)", str(value)))
    return read


def check_validate_step(doc, verify, problems):
    """gerrit-validate validates through the action, as the scan does.

    The validator is the action at the scan step's pin, in validate-only
    mode, with the scan step's own expression for every input the scan
    passes less the scan-only ones, and nothing else: so no sbom and no
    target. The job runs no other action (no checkout, no harden-runner)
    and no shell check of a grype-scan-action input; the ecosystems
    preset list, an input of repository-metadata-action, keeps its shell
    step on the verify workflows.
    """
    steps = steps_of(doc, VALIDATE_JOB)
    step = validate_step(doc, problems)
    scan = the_one(
        steps_using(steps_of(doc, "grype"), GRYPE_ACTION),
        f"jobs.grype step using {GRYPE_ACTION}", problems,
    )
    if step is None or scan is None:
        return
    where = f"'{VALIDATE_STEP}'"
    if "if" in step:
        problems.append(f"{where} must run unconditionally")
    if step.get("uses") != GRYPE_USES:
        problems.append(f"{where} does not use {GRYPE_USES}")
    if step.get("uses") != scan.get("uses"):
        problems.append(f"{where} and the scan step must share one pin")
    expected = mirrored(scan)
    given = step.get("with") or {}
    if given != expected:
        for key in sorted(set(expected) | set(given)):
            if key not in given:
                problems.append(f"{where} does not pass {key}")
            elif key not in expected:
                problems.append(f"{where} must not pass {key}")
            elif given[key] != expected[key]:
                problems.append(
                    f"{where} passes {key} as {given[key]!r}, the scan"
                    f" as {expected[key]!r}"
                )
    for key in ("run", "env"):
        if key in step:
            problems.append(f"{where} must not carry {key}")
    actions = [s.get("uses") for s in steps if (s or {}).get("uses")]
    if actions != [GRYPE_USES]:
        problems.append(
            f"jobs.{VALIDATE_JOB} must run no action but the validator:"
            f" no checkout, no harden-runner; runs {actions}"
        )
    allowed = {ECOSYSTEMS_INPUT} if verify else set()
    for index, shell in enumerate(steps):
        if not (shell or {}).get("run"):
            continue
        for name in sorted(grype_inputs_read(shell) - allowed):
            problems.append(
                f"jobs.{VALIDATE_JOB}.steps[{index}] still checks {name}"
                " in shell"
            )
    if not verify:
        if steps_named(steps, ECOSYSTEMS_STEP):
            problems.append(f"'{ECOSYSTEMS_STEP}' is not a release step")
        return
    shell = ecosystems_step(doc, problems)
    if shell is None:
        return
    where = f"'{ECOSYSTEMS_STEP}'"
    if "if" in shell:
        problems.append(f"{where} must run unconditionally")
    if "${{ inputs.%s }}" % ECOSYSTEMS_INPUT not in \
            (shell.get("env") or {}).values():
        problems.append(f"{where} does not read {ECOSYSTEMS_INPUT}")
    if not isinstance(shell.get("run"), str) or not shell["run"].strip():
        problems.append(f"{where} has no run script")


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
        (GRYPE_ACTION, GRYPE_PIN, GRYPE_TAG),
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


def input_default(doc, name):
    """A workflow input's default as the action receives it."""
    value = inputs_of(doc)[name].get("default", "")
    return str(value).lower() if isinstance(value, bool) else str(value)


def check_caller(caller, verify_doc):
    """testing.yaml's check job rejects a bad gate-when at the pin.

    The job runs the validation step itself, since a job calling the
    workflow cannot set continue-on-error: the same with: keys as
    build-test's validator, each with build-test's default, but a
    gate-when the action does not know, and asserts the step failed.
    """
    problems = []
    job = (caller.get("jobs") or {}).get(CHECK_JOB)
    if not isinstance(job, dict):
        return [f"jobs.{CHECK_JOB} is missing"]
    steps = list(job.get("steps") or [])
    step = the_one(
        steps_named(steps, VALIDATE_STEP),
        f"jobs.{CHECK_JOB} step '{VALIDATE_STEP}'", problems,
    )
    validator = validate_step(verify_doc, problems)
    scan = the_one(
        steps_using(steps_of(verify_doc, "grype"), GRYPE_ACTION),
        f"jobs.grype step using {GRYPE_ACTION}", problems,
    )
    if step is None or validator is None or scan is None:
        return problems
    where = f"jobs.{CHECK_JOB} '{VALIDATE_STEP}'"
    if step.get("uses") != GRYPE_USES:
        problems.append(f"{where} does not use {GRYPE_USES}")
    if step.get("continue-on-error") is not True:
        problems.append(f"{where} must set continue-on-error: true")
    given = step.get("with") or {}
    expected = {}
    for key, expression in mirrored(scan).items():
        match = re.fullmatch(
            r"\$\{\{ inputs\.([a-z_]+) \}\}", str(expression),
        )
        expected[key] = (
            input_default(verify_doc, match.group(1)) if match
            else expression
        )
    expected["validate-only"] = "true"
    expected["gate-when"] = None
    if set(given) != set(expected):
        problems.append(
            f"{where} passes {sorted(given)}; build-test's validator"
            f" passes {sorted(expected)}"
        )
    for key, value in expected.items():
        if key == "gate-when":
            if given.get(key) in GATE_WHEN_VALUES | {None}:
                problems.append(
                    f"{where} must pass a gate-when the action rejects"
                )
        elif key in given and given[key] != value:
            problems.append(
                f"{where} passes {key} as {given[key]!r}, build-test's"
                f" default is {value!r}"
            )
    step_id = step.get("id")
    index = steps.index(step)
    assertion = [
        s for s in steps[index + 1:]
        if step_id and f"steps.{step_id}.outcome" in yaml.safe_dump(s)
    ]
    if not assertion:
        problems.append(f"{where} has no later step reading its outcome")
    actions = [s.get("uses") for s in steps if (s or {}).get("uses")]
    if actions != [GRYPE_USES]:
        problems.append(
            f"jobs.{CHECK_JOB} must run no action but the validator;"
            f" runs {actions}"
        )
    return problems


def run_ecosystems(doc, value):
    """Run the extracted ecosystems step; return (exit code, output)."""
    step = ecosystems_step(doc)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    for var, expression in (step.get("env") or {}).items():
        if expression == "${{ inputs.%s }}" % ECOSYSTEMS_INPUT:
            env[var] = value
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        env=env, capture_output=True, text=True, check=False,
    )
    return result.returncode, result.stdout + result.stderr


def exercise_ecosystems(name, doc):
    """Return the number of values the ecosystems step got wrong."""
    wrong = 0
    accepted, rejected = ECOSYSTEMS_CASES
    for value in accepted:
        code, output = run_ecosystems(doc, value)
        if code != 0:
            wrong += 1
            print(
                f"::error file={name}::{ECOSYSTEMS_INPUT}={value!r}"
                f" rejected: {output.strip()}"
            )
    for value in rejected:
        code, output = run_ecosystems(doc, value)
        if code == 0:
            wrong += 1
            print(f"::error file={name}::{ECOSYSTEMS_INPUT}={value!r} accepted")
        elif f"Invalid {ECOSYSTEMS_INPUT} input" not in output:
            wrong += 1
            print(
                f"::error file={name}::{ECOSYSTEMS_INPUT}={value!r} rejected"
                f" without naming the input: {output.strip()}"
            )
    total = len(accepted) + len(rejected)
    print(f"{name}: ecosystems step right on {total - wrong}/{total} values")
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
    # The validator: its pin, its mode, and its mirror of the scan.
    d = copy.deepcopy(doc)
    validate_step(d)["uses"] = f"{GRYPE_ACTION}@{'0' * 40}"
    yield "validator pinned elsewhere", d
    d = copy.deepcopy(doc)
    grype(d)["uses"] = f"{GRYPE_ACTION}@{'0' * 40}"
    yield "scan pinned elsewhere", d
    d = copy.deepcopy(doc)
    for s in (validate_step(d), grype(d)):
        s["uses"] = f"{GRYPE_ACTION}@{'0' * 40}"
    yield "validator and scan pinned elsewhere together", d
    d = copy.deepcopy(doc)
    del validate_step(d)["with"]["validate-only"]
    yield "validator drops validate-only", d
    d = copy.deepcopy(doc)
    validate_step(d)["with"]["validate-only"] = True
    yield "validator passes validate-only as a YAML boolean", d
    d = copy.deepcopy(doc)
    validate_step(d)["with"]["validate-only"] = "false"
    yield "validator passes validate-only false", d
    for key in sorted(set(mirrored(grype(doc))) - {"validate-only"}):
        d = copy.deepcopy(doc)
        del validate_step(d)["with"][key]
        yield f"validator drops {key}", d
        d = copy.deepcopy(doc)
        validate_step(d)["with"][key] = "${{ inputs.grype_enabled }}"
        yield f"validator passes {key} as another expression", d
        d = copy.deepcopy(doc)
        validate_step(d)["with"][key] = str(grype(doc)["with"][key]) + " "
        yield f"validator passes {key} with trailing whitespace", d
    d = copy.deepcopy(doc)
    grype(d)["with"]["cache-db"] = "restore-only"
    yield "scan gains an input the validator lacks", d
    d = copy.deepcopy(doc)
    grype(d)["with"]["fail-on"] = "${{ inputs.grype_transitive_fail_on }}"
    yield "scan changes an expression the validator keeps", d
    for key, value in (
        ("sbom", "sbom-cyclonedx.json"),
        ("target", "dir:."),
        ("permit-fail", grype(doc)["with"]["permit-fail"]),
        ("github-token", "${{ secrets.GITHUB_TOKEN }}"),
    ):
        d = copy.deepcopy(doc)
        validate_step(d)["with"][key] = value
        yield f"validator passes {key}", d
    d = copy.deepcopy(doc)
    validate_step(d)["if"] = "inputs.grype_enabled"
    yield "validator conditional", d
    d = copy.deepcopy(doc)
    d["jobs"][VALIDATE_JOB]["steps"].remove(validate_step(d))
    yield "validator missing", d
    d = copy.deepcopy(doc)
    d["jobs"][VALIDATE_JOB]["steps"].append(
        copy.deepcopy(validate_step(d))
    )
    yield "validator duplicated", d
    d = copy.deepcopy(doc)
    d["jobs"]["grype"]["steps"].append(copy.deepcopy(grype(d)))
    yield "scan step duplicated", d
    # The job's shape: the validator alone, no checkout, no
    # harden-runner, and no shell check of a Grype input.
    d = copy.deepcopy(doc)
    d["jobs"][VALIDATE_JOB]["steps"].insert(0, {
        "name": "Checkout", "uses": f"{CHECKOUT_ACTION}@{'0' * 40}",
    })
    yield "validation job checks out", d
    d = copy.deepcopy(doc)
    d["jobs"][VALIDATE_JOB]["steps"].insert(0, {
        "name": "Harden runner",
        "uses": f"step-security/harden-runner@{'0' * 40}",
    })
    yield "validation job hardens the runner", d
    d = copy.deepcopy(doc)
    d["jobs"][VALIDATE_JOB]["steps"].append({
        "name": "Validate grype_fail_on input",
        "shell": "bash",
        "env": {"GRYPE_FAIL_ON": "${{ inputs.grype_fail_on }}"},
        "run": "test -n \"${GRYPE_FAIL_ON}\"",
    })
    yield "shell check of a Grype input returns", d
    d = copy.deepcopy(doc)
    ecosystems_step(d)["env"]["GRYPE_FAIL_ON"] = "${{ inputs.grype_fail_on }}"
    yield "ecosystems step reads a Grype input", d
    # The ecosystems step, the one shell check kept.
    d = copy.deepcopy(doc)
    ecosystems_step(d)["env"] = {"ECOSYSTEMS": "go"}
    yield "ecosystems step ignores the input", d
    d = copy.deepcopy(doc)
    ecosystems_step(d)["if"] = "inputs.grype_enabled"
    yield "ecosystems step conditional", d
    d = copy.deepcopy(doc)
    d["jobs"][VALIDATE_JOB]["steps"].remove(ecosystems_step(d))
    yield "ecosystems step missing", d


def caller_mutants(caller):
    """Yield (label, mutated caller) for each drift check_caller must catch."""
    def step(d):
        return steps_named(d["jobs"][CHECK_JOB]["steps"], VALIDATE_STEP)[0]

    d = copy.deepcopy(caller)
    del d["jobs"][CHECK_JOB]
    yield "check job missing", d
    d = copy.deepcopy(caller)
    step(d)["uses"] = f"{GRYPE_ACTION}@{'0' * 40}"
    yield "check job pinned elsewhere", d
    d = copy.deepcopy(caller)
    del step(d)["continue-on-error"]
    yield "check job would fail on the rejection", d
    d = copy.deepcopy(caller)
    step(d)["with"]["gate-when"] = "always"
    yield "check job passes a gate-when the action accepts", d
    d = copy.deepcopy(caller)
    del step(d)["with"]["gate-when"]
    yield "check job passes no gate-when", d
    d = copy.deepcopy(caller)
    step(d)["with"]["validate-only"] = "false"
    yield "check job scans for real", d
    d = copy.deepcopy(caller)
    step(d)["with"]["fail-on"] = "high"
    yield "check job departs from build-test's default", d
    d = copy.deepcopy(caller)
    del step(d)["with"]["bypass-repository"]
    yield "check job drops an input the validator passes", d
    d = copy.deepcopy(caller)
    step(d)["with"]["sbom"] = "sbom-cyclonedx.json"
    yield "check job passes an sbom", d
    d = copy.deepcopy(caller)
    step(d)["id"] = "renamed"
    yield "check job's assertion reads another step", d
    d = copy.deepcopy(caller)
    d["jobs"][CHECK_JOB]["steps"].insert(0, {
        "name": "Checkout", "uses": f"{CHECKOUT_ACTION}@{'0' * 40}",
    })
    yield "check job checks out", d


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
    if workflow.name in VERIFY | RELEASE | {CALLER}:
        doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        docs[workflow.name] = doc
    if workflow.name in VERIFY | RELEASE:
        problems += check_doc(workflow.name, doc)
    for problem in problems:
        failures += 1
        print(f"::error file={workflow}::{problem}")
missing = (VERIFY | RELEASE | {CALLER}) - set(docs)
if missing:
    print(f"::error::workflows not found in {root}: {sorted(missing)}")
    sys.exit(1)
verify_doc = docs[sorted(VERIFY)[0]]
for problem in check_caller(docs[CALLER], verify_doc):
    failures += 1
    print(f"::error file={root / CALLER}::{problem}")
if failures:
    print(f"{failures} problem(s) across {len(docs)} workflow(s) ❌")
    sys.exit(1)
print(f"{len(docs)} workflow(s) wire the Grype gating inputs ✅")
for name in sorted(VERIFY):
    failures += exercise_ecosystems(name, docs[name])
if failures:
    sys.exit(1)
for name in sorted(VERIFY):
    failures += self_test(name, docs[name])
escaped = 0
total = 0
for label, mutant in caller_mutants(docs[CALLER]):
    total += 1
    if not check_caller(yaml.safe_load(yaml.safe_dump(mutant)), verify_doc):
        escaped += 1
        print(f"::error::caller mutant not caught: {label}")
print(f"Mutants of {CALLER} caught: {total - escaped}/{total}")
failures += escaped
if failures:
    sys.exit(1)
PYEOF
