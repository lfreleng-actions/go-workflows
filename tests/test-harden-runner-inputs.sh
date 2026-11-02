#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Drift check for the harden-runner allow-list inputs.
#
# Every reusable (workflow_call) workflow that loads its egress
# allow-list through lfreleng-actions/harden-runner-block-action must
# expose the same five harden_runner_* inputs, pass every one of them
# through on each block-action step in one fixed form, and pin the
# action at the same release. The set is rolled out to every
# '*-workflows' repository, so this script names nothing specific to
# any one of them: copy it unchanged.
#
# It first checks the real workflows, then mutates a copy of one of
# them in each way the check must catch and expects each mutant to
# fail, so a check that silently passes everything fails here too.
#
# Usage: bash tests/test-harden-runner-inputs.sh [<workflows-dir>]
#
# Needs python3 with PyYAML.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
workflows="${1:-${repo_root}/.github/workflows}"

if [ ! -d "${workflows}" ]; then
  echo "ERROR: workflows directory not found: ${workflows}" >&2
  exit 1
fi

if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "ERROR: python3 cannot import yaml; install PyYAML" >&2
  exit 1
fi

# '-I' keeps the working directory off sys.path.
python3 -I - "${workflows}" <<'PYEOF'
import copy
import pathlib
import sys
import tempfile

import yaml

ACTION = "lfreleng-actions/harden-runner-block-action"
# v0.15.0, the first release with extra_endpoints.
PIN = "2fed66c9c36c4687c31ca349b925b81ec629673f"

# name -> (type, required default; None accepts any non-empty value)
INPUTS = {
    "harden_runner_egress": ("string", None),
    "harden_runner_allowlist": ("string", None),
    "harden_runner_supplemental_allowlist": ("string", ""),
    "harden_runner_supplemental_unpinned": ("boolean", False),
    "harden_runner_extra_endpoints": ("string", ""),
}

PASS_THROUGH = {
    "config": "${{ inputs.harden_runner_allowlist }}",
    "supplemental_config": (
        "${{ inputs.harden_runner_supplemental_allowlist }}"
    ),
    "supplemental_required": (
        "${{ inputs.harden_runner_supplemental_allowlist != ''"
        " && 'true' || 'false' }}"
    ),
    "supplemental_unpinned": (
        "${{ inputs.harden_runner_supplemental_unpinned"
        " && 'true' || 'false' }}"
    ),
    "extra_endpoints": "${{ inputs.harden_runner_extra_endpoints }}",
}


def triggers(doc):
    # PyYAML reads a bare 'on' key as the boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    return on if isinstance(on, dict) else {}


def block_steps(doc):
    for job_id, job in (doc.get("jobs") or {}).items():
        for index, step in enumerate((job or {}).get("steps") or []):
            uses = str((step or {}).get("uses", ""))
            if uses.split("@", 1)[0] == ACTION:
                where = f"jobs.{job_id}.steps[{index}]"
                yield where, step, uses


def check_doc(doc):
    """Return the list of problems in one parsed workflow."""
    on = triggers(doc)
    if "workflow_call" not in on:
        return []
    steps = list(block_steps(doc))
    if not steps:
        return []
    problems = []
    inputs = (on.get("workflow_call") or {}).get("inputs") or {}
    for name, (kind, default) in INPUTS.items():
        spec = inputs.get(name)
        if not isinstance(spec, dict):
            problems.append(f"input {name} is missing")
            continue
        if spec.get("type") != kind:
            problems.append(f"input {name} is not type {kind}")
        value = spec.get("default")
        if default is None:
            if not isinstance(value, str) or not value:
                problems.append(f"input {name} has no default")
        elif value != default or type(value) is not type(default):
            problems.append(f"input {name} default is not {default!r}")
    for where, step, uses in steps:
        if uses.partition("@")[2] != PIN:
            problems.append(f"{where} does not pin {ACTION}@{PIN}")
        given = step.get("with") or {}
        for key, expected in PASS_THROUGH.items():
            if key not in given:
                problems.append(f"{where} does not pass {key}")
            elif given[key] != expected:
                problems.append(f"{where} passes {key} as {given[key]!r}")
    return problems


def check_dir(path):
    checked = 0
    failures = 0
    for workflow in sorted(path.glob("*.y*ml")):
        doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            continue
        problems = check_doc(doc)
        on = triggers(doc)
        if "workflow_call" in on and list(block_steps(doc)):
            checked += 1
        for problem in problems:
            failures += 1
            print(f"::error file={workflow}::{problem}")
    return checked, failures


def mutants(doc):
    """Yield (label, mutated doc) for each drift the check must catch."""
    on_key = "on" if "on" in doc else True

    def inputs(d):
        return d[on_key]["workflow_call"]["inputs"]

    def first_with(d):
        for _, step, _ in block_steps(d):
            return step.setdefault("with", {})
        raise AssertionError("no block-action step")

    for name in INPUTS:
        d = copy.deepcopy(doc)
        del inputs(d)[name]
        yield f"drop input {name}", d
    d = copy.deepcopy(doc)
    inputs(d)["harden_runner_supplemental_unpinned"]["type"] = "string"
    yield "unpinned input typed string", d
    d = copy.deepcopy(doc)
    inputs(d)["harden_runner_extra_endpoints"]["default"] = "x.org:443"
    yield "non-empty extra_endpoints default", d
    d = copy.deepcopy(doc)
    inputs(d)["harden_runner_supplemental_allowlist"]["default"] = "o//"
    yield "non-empty supplemental default", d
    for key in PASS_THROUGH:
        d = copy.deepcopy(doc)
        first_with(d).pop(key, None)
        yield f"drop {key}", d
    d = copy.deepcopy(doc)
    first_with(d)["supplemental_unpinned"] = (
        "${{ inputs.harden_runner_supplemental_unpinned }}"
    )
    yield "supplemental_unpinned in another form", d
    d = copy.deepcopy(doc)
    for _, step, _ in block_steps(d):
        step["uses"] = f"{ACTION}@{'0' * 40}"
        break
    yield "block-action pinned elsewhere", d


def self_test(path):
    """Expect every mutant of the first checked workflow to fail."""
    for workflow in sorted(path.glob("*.y*ml")):
        doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and not check_doc(doc) and (
            "workflow_call" in triggers(doc) and list(block_steps(doc))
        ):
            break
    else:
        print("::error::no clean workflow to mutate")
        return 1
    escaped = 0
    total = 0
    with tempfile.TemporaryDirectory() as scratch:
        target = pathlib.Path(scratch) / workflow.name
        for label, mutant in mutants(doc):
            total += 1
            target.write_text(yaml.safe_dump(mutant), encoding="utf-8")
            if not check_doc(yaml.safe_load(target.read_text())):
                escaped += 1
                print(f"::error::mutant not caught: {label}")
    print(f"Mutants of {workflow.name} caught: {total - escaped}/{total}")
    return escaped


root = pathlib.Path(sys.argv[1])
checked, failures = check_dir(root)
if not checked:
    print(f"::error::no workflow_call workflow uses {ACTION} in {root}")
    sys.exit(1)
if failures:
    print(f"{failures} problem(s) across {checked} workflow(s) ❌")
    sys.exit(1)
print(f"{checked} workflow(s) expose and pass every input ✅")
if self_test(root):
    sys.exit(1)
PYEOF
