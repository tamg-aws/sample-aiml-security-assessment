#!/usr/bin/env python3
"""Generate the per-module AISF compliance maps from the parity work ledger.

Phase 2 of the AISF parity work tags *existing* producer findings with the AISF
control they contribute to, so a reader of `bedrock_security_report_*.csv` can
trace a row to a framework control. That is a different mechanism from phase 1,
which derives eight standalone `AISF-NN` rows at consolidation time. Phase 1
publishes a verdict under an AISF control id and therefore may only ever restate
a `covered` control; phase 2 publishes no new verdict at all, only a reference on
a row whose verdict the incumbent already earned. That is why phase 2 may tag a
`tighten` control and phase 1 may not.

One map per producer module, written into the module's own directory. The four
producer Lambdas are packaged separately (each has its own `CodeUri` in
template.yaml), so a single shared module would not be importable at runtime.
The copies are generated rather than hand-maintained for exactly that reason.

The tag vocabulary is load-bearing. Writing an unqualified control id on a check
that only partly asserts the control is the same overclaim `check_ledger.py`
gate 11 refuses in phase 1, so the qualifier carries the ledger verdict:

    AISF <control>                  this check alone asserts the whole control
    AISF <control> (1 of N checks)  the control is fully asserted, by this check
                                    together with N-1 others
    AISF <control> (partial)        this check asserts less than the control
                                    requires; the tightening is still outstanding

Run:  python3 aisf-parity/gen_compliance_maps.py          # write the maps
      python3 aisf-parity/gen_compliance_maps.py --check   # exit 1 on drift
"""

import argparse
import collections
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
MODULES = os.path.join(REPO, "aiml-security-assessment", "functions", "security")
LEDGER = os.path.join(HERE, "aisf-work-ledger.json")


def generated_name(module):
    """The map module's filename, which must be unique across the four producers.

    Not a shared `aisf_compliance.py`. The producers are packaged separately, but
    the test suite loads several of them into one interpreter and puts each module
    directory on sys.path so that `from schema import create_finding` resolves
    (tests/test_sagemaker_checks.py:22-31). A shared name is therefore cached in
    sys.modules under its bare name and the first loader wins. Measured: with
    both directories on sys.path, `aisf_compliance` resolves to whichever was
    inserted last, and `aisf_frameworks("BR-10")` returns "" inside the bedrock
    module. The failure is an empty tag, not an ImportError, so nothing raises.
    The three producer schema.py files are byte-identical, which is why the
    existing `schema` collision is harmless and this one would not be.
    """
    return f"aisf_compliance_{module.removesuffix('_assessments')}.py"


# Only these two verdicts name an incumbent that already ships a verdict.
#   new              - no incumbent exists to tag.
#   not_implementable - nothing to tag, and nothing will be built.
#   unassessed       - the 11 FND rows have not had their dedup pass, so their
#                      "incumbents" are candidates and not yet findings. Tagging
#                      them would publish a mapping the ledger has not settled.
TAGGABLE = ("covered", "tighten")


def load_rows():
    with open(LEDGER) as f:
        return json.load(f)["rows"]


def check_owners():
    """check_id -> set of module dirs whose app.py emits it.

    Two spellings, because the producers disagree: bedrock, sagemaker and
    agentcore pass `check_id=` as a keyword, agent_registry passes it
    positionally. A keyword-only scan silently resolves zero checks for
    agent_registry, which would drop that module's map entirely while every
    other gate still passed.
    """
    out = collections.defaultdict(set)
    for path in sorted(glob.glob(os.path.join(MODULES, "*", "app.py"))):
        mod = os.path.basename(os.path.dirname(path))
        with open(path) as f:
            src = f.read()
        for pattern in (
            r'check_id=["\']([A-Z]{2,3}-\d{2})["\']',
            r'["\']([A-Z]{2,3}-\d{2})["\']\s*,',
        ):
            for cid in re.findall(pattern, src):
                out[cid].add(mod)
    return out


def build_maps(rows, owners):
    """(module -> {check_id: tag}), plus the pairs that went into them."""
    per_check = collections.defaultdict(list)  # check_id -> [(control, tag)]
    pairs = []
    unresolved = []
    for row in rows:
        verdict = row.get("verdict")
        if verdict not in TAGGABLE:
            continue
        incumbents = row.get("incumbents") or []
        control = row["control"]
        for cid in incumbents:
            if verdict == "covered":
                # A covered control asserted by several checks is fully covered,
                # but not by any one of them alone. An unqualified tag on one leg
                # would read as a complete assertion.
                tag = (
                    f"AISF {control}"
                    if len(incumbents) == 1
                    else f"AISF {control} (1 of {len(incumbents)} checks)"
                )
            else:
                tag = f"AISF {control} (partial)"
            mods = owners.get(cid) or set()
            if len(mods) != 1:
                unresolved.append((cid, sorted(mods)))
                continue
            per_check[cid].append((control, tag))
            pairs.append((next(iter(mods)), cid, control, verdict))

    if unresolved:
        raise SystemExit(
            "ERROR: cannot place these incumbents in exactly one module, so the "
            "map they belong to is undecidable: "
            + ", ".join(f"{c} -> {m}" for c, m in unresolved)
        )

    maps = collections.defaultdict(dict)
    for cid, entries in per_check.items():
        mod = next(iter(owners[cid]))
        # Sort by control id so the generated file is byte-stable across runs.
        maps[mod][cid] = " | ".join(tag for _, tag in sorted(entries))
    return maps, pairs


def render(module, mapping):
    body = "".join(f'    "{cid}": "{mapping[cid]}",\n' for cid in sorted(mapping))
    return f'''"""AISF control tags for {module} findings.

GENERATED by aisf-parity/gen_compliance_maps.py from aisf-parity/aisf-work-ledger.json.
Do not hand-edit: change the ledger, re-run the generator, and re-run
aisf-parity/check_ledger.py, whose gate 14 compares this file against the ledger
in both directions.

The filename carries the module name because the test suite loads several
producers into one interpreter with each module directory on sys.path. A shared
`aisf_compliance.py` would be cached under that bare name and the first loader
would win, silently returning "" for every other module's check ids.

Qualifier vocabulary:
    AISF <control>                  this check alone asserts the whole control
    AISF <control> (1 of N checks)  the control is fully asserted, by this check
                                    together with N-1 others
    AISF <control> (partial)        this check asserts less than the control
                                    requires; the tightening is still outstanding

A tag is a traceability reference, not a statement that the control passed. The
row's own Status column carries the verdict.
"""

AISF_COMPLIANCE_MAP = {{
{body}}}


def aisf_frameworks(check_id: str) -> str:
    """The AISF tag for a check id, or "" when the ledger maps none to it."""
    return AISF_COMPLIANCE_MAP.get(check_id, "")
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--check",
        action="store_true",
        help="compare the on-disk maps against a fresh render; exit 1 on drift",
    )
    args = ap.parse_args()

    rows = load_rows()
    owners = check_owners()
    maps, pairs = build_maps(rows, owners)

    drift = []
    for module in sorted(maps):
        name = generated_name(module)
        path = os.path.join(MODULES, module, name)
        want = render(module, maps[module])
        have = None
        if os.path.exists(path):
            with open(path) as f:
                have = f.read()
        if args.check:
            if have is None:
                drift.append(f"{module}/{name} is missing")
            elif have != want:
                drift.append(f"{module}/{name} differs from the ledger")
        elif have != want:
            with open(path, "w") as f:
                f.write(want)
            print(f"wrote {module}/{name} ({len(maps[module])} checks)")
        else:
            print(f"unchanged {module}/{name} ({len(maps[module])} checks)")

    total_checks = sum(len(m) for m in maps.values())
    print(
        f"{len(maps)} modules, {total_checks} checks, {len(pairs)} check-control pairs, "
        f"{len({p[2] for p in pairs})} distinct controls"
    )
    if args.check:
        if drift:
            print("DRIFT: " + "; ".join(drift))
            return 1
        print("maps match the ledger")
    return 0


if __name__ == "__main__":
    sys.exit(main())
