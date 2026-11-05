#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Drift check for the harden-runner allow-list inputs.
#
# Every reusable (workflow_call) workflow that loads its egress
# allow-list through lfreleng-actions/harden-runner-block-action must
# expose the same five harden_runner_* inputs and pass every one of
# them through on each block-action step in one fixed form. Every
# block-action step in the directory pins the same commit SHA, with a
# '# vX.Y.Z' comment naming the same release on each line, at or above
# MIN_VERSION; the comments come from the raw text, on the line each
# step's 'uses:' value starts on, since the YAML parser drops them.
# extra_endpoints alone has a second form: one earlier job's output
# followed by the caller's input, for an endpoint the workflow
# resolves at run time and wants DNS-checked.
# The output comes first because the loader strips a '#' comment to
# the end of its line, and a comment ending the caller's value would
# swallow an output placed after it. Each input's description must
# be the reference wording held below, whitespace aside, optionally
# followed by '.' or by '. ' and a note about the workflow. A
# block-action step may tolerate its own failure only under 'audit'
# with no supplemental list named, so a caller's missing list fails
# the job as supplemental_required says. The set is rolled out to
# every '*-workflows' repository, so this script names nothing
# specific to any one of them: copy it unchanged.
#
# It first checks the real workflows, then mutates a copy of one of
# them in each way the check must catch and expects each mutant to
# fail, so a check that silently passes everything fails here too. It
# also expects positive controls, such as a description with a note,
# to pass, and runs text fixtures through the pin rules, which the
# parsed mutants cannot carry.
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
import collections
import copy
import pathlib
import re
import sys
import tempfile

import yaml

ACTION = "lfreleng-actions/harden-runner-block-action"
# v0.15.0, the first release with extra_endpoints, which the
# five-input pass-through needs.
MIN_VERSION = (0, 15, 0)

# One block-action 'uses:' line of the raw file text, optionally a
# '- ' list item, quoted or not, with any trailing comment.
USES_LINE = re.compile(
    r"^(?P<lead>[ \t]*(?:-[ \t]+)?)uses:[ \t]*(?P<quote>['\"]?)"
    + re.escape(ACTION)
    + r"@(?P<sha>[^\s'\"#]+)(?P=quote)"
    r"(?:[ \t]+#[ \t]*(?P<comment>[^\n]*?))?[ \t]*$",
    re.MULTILINE,
)
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
VERSION_COMMENT = re.compile(r"v(\d+)\.(\d+)\.(\d+)\Z", re.ASCII)

# name -> (type, required default; None accepts any non-empty value)
INPUTS = {
    "harden_runner_egress": ("string", None),
    "harden_runner_allowlist": ("string", None),
    "harden_runner_supplemental_allowlist": ("string", ""),
    "harden_runner_supplemental_unpinned": ("boolean", False),
    "harden_runner_extra_endpoints": ("string", ""),
}

# The reference wording, from rust-workflows' build-test.yaml. Once
# whitespace is normalised, so line breaks in a folded scalar do not
# count, each input's description must be this wording alone, the
# wording and '.', or the wording, '. ' and a note.
DESCRIPTIONS = {
    "harden_runner_egress": (
        "Harden-runner egress policy: 'block' or 'audit'"
    ),
    "harden_runner_allowlist": (
        "Out-of-band harden-runner allow-list configuration"
    ),
    "harden_runner_supplemental_allowlist": (
        "Extra harden-runner allow-list merged with"
        " harden_runner_allowlist, in the same coordinate grammar."
        " Empty adds nothing"
    ),
    "harden_runner_supplemental_unpinned": (
        "Let harden_runner_supplemental_allowlist omit '@ref' and"
        " follow its default branch; only a list in the caller's own"
        " organisation qualifies"
    ),
    "harden_runner_extra_endpoints": (
        "Extra egress endpoints written inline, host[:port] tokens"
        " separated by spaces or newlines, merged into the allow-list"
        " for short-lived fixes. Empty adds nothing"
    ),
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

# extra_endpoints may also carry one endpoint the workflow resolved in
# an earlier job, ahead of the caller's input, so the loader's DNS
# check covers it as well: one job output first, then the caller's
# input unchanged, nothing else. The output goes first because the
# loader strips a '#' comment to the end of its line: a caller's value
# ending in one would swallow an output appended after it.
EXTRA_MERGED = re.compile(
    r"\$\{\{ format\('\{0\} \{1\}',"
    r" needs\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\.[A-Za-z_][A-Za-z0-9_-]*,"
    r" inputs\.harden_runner_extra_endpoints\) \}\}\Z",
    re.ASCII,
)

# The one continue-on-error a block-action step may carry, besides none
# or false: a step that tolerates any other failure would swallow the
# failure supplemental_required raises for a missing named list.
CONTINUE_ON_ERROR = (
    "${{ inputs.harden_runner_egress != 'block'"
    " && inputs.harden_runner_supplemental_allowlist == '' }}"
)


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


def inspected(doc):
    """Whether the check applies: a reusable workflow using the action."""
    return "workflow_call" in triggers(doc) and any(block_steps(doc))


def description_ok(name, text):
    """Whether text is the reference wording, optionally with a note."""
    if not isinstance(text, str):
        return False
    text = " ".join(text.split())
    ref = DESCRIPTIONS[name]
    return text in (ref, f"{ref}.") or text.startswith(f"{ref}. ")


def check_doc(doc):
    """Return the list of problems in one parsed workflow.

    The pin rules need the raw text and every workflow in the
    directory, so read_pins and check_pins apply them instead.
    """
    if not inspected(doc):
        return []
    on = triggers(doc)
    steps = list(block_steps(doc))
    problems = []
    inputs = (on.get("workflow_call") or {}).get("inputs") or {}
    for name, (kind, default) in INPUTS.items():
        spec = inputs.get(name)
        if not isinstance(spec, dict):
            problems.append(f"input {name} is missing")
            continue
        if not description_ok(name, spec.get("description")):
            problems.append(
                f"input {name} description is not the reference wording,"
                " alone or followed by '.' and an optional note"
            )
        if spec.get("type") != kind:
            problems.append(f"input {name} is not type {kind}")
        value = spec.get("default")
        if default is None:
            if not isinstance(value, str) or not value:
                problems.append(f"input {name} has no default")
        elif value != default or type(value) is not type(default):
            problems.append(f"input {name} default is not {default!r}")
    for where, step, _ in steps:
        tolerate = step.get("continue-on-error", False)
        if tolerate is not False and tolerate != CONTINUE_ON_ERROR:
            problems.append(
                f"{where} sets continue-on-error as {tolerate!r}"
            )
        given = step.get("with") or {}
        for key, expected in PASS_THROUGH.items():
            if key not in given:
                problems.append(f"{where} does not pass {key}")
            elif key == "extra_endpoints" and isinstance(
                given[key], str
            ) and EXTRA_MERGED.match(given[key]):
                continue
            elif given[key] != expected:
                problems.append(f"{where} passes {key} as {given[key]!r}")
    return problems


def show(version):
    return "v" + ".".join(map(str, version))


def uses_lines(text):
    """Map each step's location to the source line of its 'uses:' value.

    The location matches what block_steps yields. Taking the line from
    the composed node, not from a scan of the text, keeps a 'uses:'
    example inside a block scalar from standing in for a real step.
    """
    loader = yaml.SafeLoader(text)
    try:
        root = loader.get_single_node()

        def value(node, key):
            found = None
            if isinstance(node, yaml.MappingNode):
                for k, v in node.value:
                    if loader.construct_object(k, deep=True) == key:
                        found = v
            return found

        def line_of(node):
            at = node.start_mark.index
            start = text.rfind("\n", 0, at) + 1
            end = text.find("\n", at)
            return text[start:end if end >= 0 else None].rstrip("\r")

        located = {}
        jobs = value(root, "jobs")
        if not isinstance(jobs, yaml.MappingNode):
            return located
        for key, job in jobs.value:
            job_id = loader.construct_object(key, deep=True)
            steps = value(job, "steps")
            if not isinstance(steps, yaml.SequenceNode):
                continue
            for index, step in enumerate(steps.value):
                uses = value(step, "uses")
                if isinstance(uses, yaml.ScalarNode):
                    where = f"jobs.{job_id}.steps[{index}]"
                    located[where] = line_of(uses)
        return located
    finally:
        loader.dispose()


def read_pins(text, doc):
    """Read the version comment on each block-action step's own line.

    The parsed document has lost the comments, so each step's 'uses:'
    line comes from the raw text at the position its node starts.
    Return (pins, problems): one (where, sha, version) per step with a
    commit SHA, version None when its line carries no valid '# vX.Y.Z'
    comment, and the problems found.
    """
    located = uses_lines(text)
    pins = []
    problems = []
    for where, _, uses in block_steps(doc):
        sha = uses.partition("@")[2]
        if not COMMIT_SHA.match(sha):
            problems.append(
                f"{where} pins {uses!r}, not a 40-character commit SHA"
            )
            continue
        match = USES_LINE.match(located.get(where, ""))
        if not match or match["sha"] != sha:
            problems.append(
                f"{where} has no readable 'uses: {ACTION}@{sha}' line"
            )
            pins.append((where, sha, None))
            continue
        comment = match["comment"]
        version = VERSION_COMMENT.match(comment or "")
        if comment is None:
            problems.append(f"{where} has no '# vX.Y.Z' comment on its pin")
        elif not version:
            problems.append(
                f"{where} has a malformed version comment {comment!r},"
                " not '# vX.Y.Z'"
            )
        parsed = tuple(map(int, version.groups())) if version else None
        pins.append((where, sha, parsed))
    return pins, problems


def check_pins(pins):
    """Return (workflow, problem) for each step off the common pin.

    pins holds (workflow, where, sha, version) for every block-action
    step in the directory: all must share one SHA and one version, at
    or above MIN_VERSION.
    """
    problems = []
    if not pins:
        return problems
    sha_common = collections.Counter(
        sha for _, _, sha, _ in pins
    ).most_common(1)[0][0]
    versions = collections.Counter(v for *_, v in pins if v is not None)
    version_common = versions.most_common(1)[0][0] if versions else None
    for workflow, where, sha, version in pins:
        if sha != sha_common:
            problems.append((
                workflow,
                f"{where} pins {ACTION}@{sha}, but most steps pin"
                f" {sha_common}",
            ))
        if version is None:
            continue
        if version < MIN_VERSION:
            problems.append((
                workflow,
                f"{where} pins {show(version)}, below the"
                f" {show(MIN_VERSION)} floor",
            ))
        if version != version_common:
            problems.append((
                workflow,
                f"{where} has comment {show(version)}, but most steps"
                f" have {show(version_common)}",
            ))
    return problems


def check_dir(path):
    """Return (workflows checked, [(workflow, problem)]) for path."""
    checked = 0
    problems = []
    pins = []
    for workflow in sorted(path.glob("*.y*ml")):
        text = workflow.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict) or not inspected(doc):
            continue
        checked += 1
        problems.extend((workflow, p) for p in check_doc(doc))
        found, unread = read_pins(text, doc)
        problems.extend((workflow, p) for p in unread)
        pins.extend((workflow, *pin) for pin in found)
    problems.extend(check_pins(pins))
    return checked, problems


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
    for name, ref in DESCRIPTIONS.items():
        words = ref.split()
        changed = list(words)
        changed[len(words) // 2] = "altered"
        for label, text in (
            ("one word changed", " ".join(changed)),
            ("cut short", " ".join(words[:-1])),
            ("joined with no boundary", f"{ref}s"),
            ("joined by ';'", f"{ref}; local note"),
        ):
            d = copy.deepcopy(doc)
            inputs(d)[name]["description"] = text
            yield f"{name} description {label}", d
    d = copy.deepcopy(doc)
    del inputs(d)["harden_runner_extra_endpoints"]["description"]
    yield "extra_endpoints description missing", d
    for key in PASS_THROUGH:
        d = copy.deepcopy(doc)
        first_with(d).pop(key, None)
        yield f"drop {key}", d
    d = copy.deepcopy(doc)
    first_with(d)["supplemental_unpinned"] = (
        "${{ inputs.harden_runner_supplemental_unpinned }}"
    )
    yield "supplemental_unpinned in another form", d
    for label, value in (
        ("extra_endpoints drops the caller's input",
         "${{ needs.gerrit.outputs.endpoint }}"),
        ("extra_endpoints merges another input",
         "${{ format('{0} {1}', inputs.other,"
         " inputs.harden_runner_extra_endpoints) }}"),
        ("extra_endpoints puts the caller's input first",
         "${{ format('{0} {1}', inputs.harden_runner_extra_endpoints,"
         " needs.gerrit.outputs.endpoint) }}"),
        ("extra_endpoints merges two outputs",
         "${{ format('{0} {1} {2}', needs.a.outputs.b, needs.c.outputs.d,"
         " inputs.harden_runner_extra_endpoints) }}"),
    ):
        d = copy.deepcopy(doc)
        first_with(d)["extra_endpoints"] = value
        yield label, d
    for value in (True, "${{ inputs.harden_runner_egress != 'block' }}"):
        d = copy.deepcopy(doc)
        for _, step, _ in block_steps(d):
            step["continue-on-error"] = value
            break
        yield f"continue-on-error {value!r}", d


def controls(doc):
    """Yield (label, varied doc) for each form the check must accept."""
    on_key = "on" if "on" in doc else True
    for name, ref in DESCRIPTIONS.items():
        for label, text in (
            ("with a note", f"{ref}. A note about this workflow."),
            ("with a full stop", f"{ref}."),
        ):
            d = copy.deepcopy(doc)
            d[on_key]["workflow_call"]["inputs"][name]["description"] = text
            yield f"{name} description {label}", d


# Text fixtures for the pin rules: (label, passes, the pin of each of
# two copies of the workflow as (sha, comment, quote), and an optional
# (sha, comment) for a 'uses:' example in a block scalar ahead of the
# jobs, which must not stand in for a real step's line).
NEW_SHA = "36a02f4a61b27e7a0a91e1df2134abe9545cf54e"
PIN_FIXTURES = (
    ("all steps on v0.16.1", True,
     ((NEW_SHA, "v0.16.1", ""), (NEW_SHA, "v0.16.1", '"'))),
    ("two different SHAs", False,
     ((NEW_SHA, "v0.16.1", ""), ("f" * 40, "v0.16.1", ""))),
    ("versions that disagree", False,
     ((NEW_SHA, "v0.16.1", ""), (NEW_SHA, "v0.16.0", ""))),
    ("a version below the floor", False,
     ((NEW_SHA, "v0.14.0", ""), (NEW_SHA, "v0.14.0", ""))),
    ("no version comment", False,
     ((NEW_SHA, None, ""), (NEW_SHA, None, ""))),
    ("a malformed version comment", False,
     ((NEW_SHA, "0.16.1", ""), (NEW_SHA, "0.16.1", ""))),
    ("a tag in place of a SHA", False,
     (("v0.16.1", "v0.16.1", ""), ("v0.16.1", "v0.16.1", ""))),
    ("a missing comment behind a commented example", False,
     ((NEW_SHA, None, ""), (NEW_SHA, None, "")), (NEW_SHA, "v0.16.1")),
    ("a version below the floor behind a newer example", False,
     ((NEW_SHA, "v0.14.0", ""), (NEW_SHA, "v0.14.0", "")),
     (NEW_SHA, "v0.16.1")),
    ("valid pins behind an outdated example", True,
     ((NEW_SHA, "v0.16.1", ""), (NEW_SHA, "v0.16.1", "")),
     (NEW_SHA, "v0.14.0")),
)


def repin(text, sha, comment, quote):
    """Rewrite every block-action 'uses:' line of text to one pin."""
    tail = "" if comment is None else f"  # {comment}"
    return USES_LINE.sub(
        lambda m: f"{m['lead']}uses: {quote}{ACTION}@{sha}{quote}{tail}",
        text,
    )


def with_example(text, sha, comment):
    """Put a block-scalar 'uses:' example ahead of the jobs in text."""
    example = (
        "x-example: |\n"
        f"  - uses: {ACTION}@{sha}  # {comment}\n"
    )
    return re.sub(r"^(?=jobs:)", lambda _: example, text, count=1,
                  flags=re.MULTILINE)


def self_test(path):
    """Mutate the first clean workflow; expect each result as stated."""
    for workflow in sorted(path.glob("*.y*ml")):
        text = workflow.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        if isinstance(doc, dict) and inspected(doc) and not check_doc(doc):
            break
    else:
        print("::error::no clean workflow to mutate")
        return 1
    if not USES_LINE.search(text):
        print(f"::error::no readable block-action line in {workflow.name}")
        return 1
    wrong = 0

    def run(kind, cases, expect_pass):
        nonlocal wrong
        total = 0
        right = 0
        with tempfile.TemporaryDirectory() as scratch:
            target = pathlib.Path(scratch) / workflow.name
            for label, variant in cases:
                total += 1
                target.write_text(yaml.safe_dump(variant), encoding="utf-8")
                passed = not check_doc(yaml.safe_load(target.read_text()))
                if passed == expect_pass:
                    right += 1
                else:
                    print(f"::error::{kind} {label}: wrong result")
        wrong += total - right
        verb = "accepted" if expect_pass else "caught"
        print(f"{kind}s of {workflow.name} {verb}: {right}/{total}")

    run("Mutant", mutants(doc), False)
    run("Positive control", controls(doc), True)
    right = 0
    for label, expect_pass, copies, *example in PIN_FIXTURES:
        with tempfile.TemporaryDirectory() as scratch:
            for prefix, pin in zip("ab", copies):
                copy_path = pathlib.Path(scratch) / f"{prefix}-{workflow.name}"
                pinned = repin(text, *pin)
                fixture = pinned
                if example:
                    fixture = with_example(pinned, *example[0])
                    if fixture == pinned:
                        print(f"::error::no jobs key for fixture {label}")
                        wrong += 1
                copy_path.write_text(fixture, encoding="utf-8")
            checked, problems = check_dir(pathlib.Path(scratch))
        if checked == 2 and (not problems) == expect_pass:
            right += 1
        else:
            print(f"::error::pin fixture with {label}: wrong result")
            wrong += 1
    print(f"Pin fixtures as expected: {right}/{len(PIN_FIXTURES)}")
    return wrong


root = pathlib.Path(sys.argv[1])
checked, problems = check_dir(root)
if not checked:
    print(f"::error::no workflow_call workflow uses {ACTION} in {root}")
    sys.exit(1)
for workflow, problem in problems:
    print(f"::error file={workflow}::{problem}")
if problems:
    print(f"{len(problems)} problem(s) across {checked} workflow(s) ❌")
    sys.exit(1)
print(f"{checked} workflow(s) expose and pass every input ✅")
if self_test(root):
    sys.exit(1)
PYEOF
