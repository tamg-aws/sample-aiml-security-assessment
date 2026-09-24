#!/usr/bin/env python3
"""Gate the AISF parity work ledger against the two repos it makes claims about.

Every check here can fail. A check that cannot fail is not a gate, so each one
prints its denominator beside its verdict.

Run:  python3 aisf-parity/check_ledger.py
Exit 0 = all gates pass. Exit 1 = at least one gate failed.
"""

import glob
import json
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
AISF_REPO = os.path.expanduser(
    "~/WorkDocs/Builder/aws-ai-security-framework-assessment"
)
MODULES = os.path.join(REPO, "aiml-security-assessment", "functions", "security")
TEMPLATE = os.path.join(REPO, "aiml-security-assessment", "template.yaml")

# target_module directory -> the SAM function logical id that runs it
MODULE_TO_FUNCTION = {
    "bedrock_assessments": "BedrockSecurityAssessmentFunction",
    "sagemaker_assessments": "SagemakerSecurityAssessmentFunction",
    "agentcore_assessments": "AgentCoreSecurityAssessmentFunction",
    "agent_registry_assessments": "AgentRegistrySecurityAssessmentFunction",
    "responsible_ai_grc_assessments": "ResponsibleAIGRCAssessmentFunction",
    "owasp_assessments": "OWASPSecurityAssessmentFunction",
}

results = []


def gate(name, ok, detail):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def load_ledger():
    with open(os.path.join(HERE, "aisf-work-ledger.json")) as f:
        return json.load(f)


def load_aisf_classification():
    path = os.path.join(AISF_REPO, "crosswalk", "classification-ledger.json")
    with open(path) as f:
        return json.load(f)["controls"]


def load_granted_actions():
    """logical function id -> set of iam actions granted in template.yaml."""

    class Loader(yaml.SafeLoader):
        pass

    def multi(loader, suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    Loader.add_multi_constructor("!", multi)
    with open(TEMPLATE) as f:
        tpl = yaml.load(f, Loader=Loader)
    out = {}
    for name, res in tpl["Resources"].items():
        if res.get("Type") != "AWS::Serverless::Function":
            continue
        blob = json.dumps(res.get("Properties", {}).get("Policies") or [])
        out[name] = set(re.findall(r'"([a-z0-9-]{2,30}:[A-Za-z0-9*]{1,60})"', blob))
    return out


def emitted_check_ids():
    """check_id -> set of module dirs that emit it."""
    out = {}
    for path in glob.glob(os.path.join(MODULES, "*", "app.py")):
        mod = os.path.basename(os.path.dirname(path))
        with open(path) as f:
            src = f.read()
        for cid in re.findall(r'check_id=["\']([A-Z]{2,3}-\d{2})["\']', src):
            out.setdefault(cid, set()).add(mod)
        for cid in re.findall(r'["\']([A-Z]{2,3}-\d{2})["\']\s*,', src):
            out.setdefault(cid, set()).add(mod)
    return out


def main():
    doc = load_ledger()
    rows = doc["rows"]
    summary = doc["summary"]
    classification = load_aisf_classification()
    granted = load_granted_actions()
    emitted = emitted_check_ids()

    # ---- gate 1: forward. every row is a real machine-checkable AISF control.
    bad = [
        r["control"]
        for r in rows
        if not classification.get(r["control"], {}).get("machine_checkable")
    ]
    gate(
        "rows are machine-checkable AISF controls",
        not bad,
        f"{len(rows) - len(bad)}/{len(rows)} valid" + (f", bad={bad}" if bad else ""),
    )

    # ---- gate 2: backward. no machine-checkable hosted control is missing a row.
    # This is the check a scan over the ledger's own rows cannot perform.
    hosted_areas = ("BDR", "SGM", "ACR")
    expected = {
        cid
        for cid, flags in classification.items()
        if flags.get("machine_checkable") and cid.split("-")[1] in hosted_areas
    }
    present = {r["control"] for r in rows if r["area"] in hosted_areas}
    missing = sorted(expected - present)
    extra = sorted(present - expected)
    gate(
        "every machine-checkable hosted control has a row",
        not missing and not extra,
        f"{len(present)}/{len(expected)} covered"
        + (f", missing={missing}" if missing else "")
        + (f", not-in-ledger={extra}" if extra else ""),
    )

    # ---- gate 3: the FND tier is machine-checkable AND workload-agnostic.
    fnd = [r for r in rows if r["area"] == "FND"]
    wrong = [
        r["control"]
        for r in fnd
        if not classification[r["control"]].get("workload_agnostic")
    ]
    gate(
        "FND tier is workload-agnostic",
        not wrong,
        f"{len(fnd) - len(wrong)}/{len(fnd)} agnostic"
        + (f", workload-specific={wrong}" if wrong else ""),
    )

    # ---- gate 4: every incumbent named actually exists in the codebase.
    named = sorted({i for r in rows for i in r["incumbents"]})
    absent = [i for i in named if i not in emitted]
    gate(
        "every incumbent check_id exists in a module",
        not absent,
        f"{len(named) - len(absent)}/{len(named)} found"
        + (f", absent={absent}" if absent else ""),
    )

    # ---- gate 5: an incumbent must live in the row's target module.
    # Catches filing a row against a check that runs somewhere else.
    misfiled = []
    for r in rows:
        if not r["target_modules"]:
            continue
        for i in r["incumbents"]:
            mods = emitted.get(i, set())
            if mods and not (mods & set(r["target_modules"])):
                misfiled.append(f"{r['control']}:{i} in {sorted(mods)}")
    gate(
        "incumbents live in the row's target module",
        not misfiled,
        f"{len(named)} incumbents checked"
        + (f", misfiled={misfiled}" if misfiled else ""),
    )

    # ---- gate 6: a claimed new IAM action must not already be granted to that
    # row's own function. Granted-to-some-other-function does not help.
    overstated = []
    checked = 0
    for r in rows:
        fns = [
            MODULE_TO_FUNCTION[m]
            for m in r["target_modules"]
            if m in MODULE_TO_FUNCTION
        ]
        if not fns:
            continue
        for action in r["extra_iam"]:
            checked += 1
            holders = [fn for fn in fns if action in granted.get(fn, set())]
            if len(holders) == len(fns):
                overstated.append(f"{r['control']}:{action} already on {holders}")
    gate(
        "claimed new IAM actions are not already granted to that function",
        not overstated,
        f"{checked} action-claims checked"
        + (f", overstated={overstated}" if overstated else ""),
    )

    # ---- gate 7: TIGHTEN rows carry a disposition and an incumbent; NEW rows do not.
    shape = []
    for r in rows:
        if r["verdict"] == "tighten":
            if r["disposition"] not in ("extend", "new_id"):
                shape.append(f"{r['control']}: tighten without disposition")
            if not r["incumbents"]:
                shape.append(f"{r['control']}: tighten without an incumbent")
        if r["verdict"] == "new" and r["incumbents"]:
            shape.append(f"{r['control']}: new but names an incumbent")
        if r["verdict"] == "covered" and not r["incumbents"]:
            shape.append(f"{r['control']}: covered without an incumbent")
    gate(
        "verdict and disposition shapes agree",
        not shape,
        f"{len(rows)} rows checked" + (f", bad={shape}" if shape else ""),
    )

    # ---- gate 8: a new_id disposition must quote the incumbent's real name.
    # The claim is about the name, so the name must be the published one.
    unquoted = []
    for r in rows:
        if r["disposition"] != "new_id":
            continue
        if not any(
            n.split()[-2:] and " ".join(n.split()[-2:]).lower() in r["gap"].lower()
            for n in r["incumbent_names"]
        ):
            unquoted.append(r["control"])
    n_newid = sum(1 for r in rows if r["disposition"] == "new_id")
    gate(
        "new_id rows quote the incumbent's published name",
        not unquoted,
        f"{n_newid - len(unquoted)}/{n_newid} quote it"
        + (f", unquoted={unquoted}" if unquoted else ""),
    )

    # ---- gate 9: the partition sums, and the published totals match the rows.
    hosted = [r for r in rows if r["area"] in hosted_areas]
    part = (
        summary["covered"]
        + summary["tighten"]
        + summary["new"]
        + summary["not_implementable"]
    )
    ok = (
        part == len(hosted) == 67
        and summary["tighten_extend"] + summary["tighten_new_id"] == summary["tighten"]
        and summary["total"] == len(rows)
        and summary["new_check_functions"]
        == summary["new"] + summary["tighten_new_id"] + summary["unassessed"]
    )
    gate(
        "published totals reconcile against the rows",
        ok,
        f"hosted partition {part}/{len(hosted)}, "
        f"tighten {summary['tighten_extend']}+{summary['tighten_new_id']}"
        f"={summary['tighten']}, "
        f"new functions {summary['new_check_functions']}",
    )

    # ---- gate 10: the markdown view is current with the JSON.
    md = os.path.join(HERE, "AISF-WORK-LEDGER.md")
    stale = not os.path.exists(md) or os.path.getmtime(md) < os.path.getmtime(
        os.path.join(HERE, "aisf-work-ledger.json")
    )
    gate(
        "markdown view is not older than the json",
        not stale,
        "regenerate with build_ledger.py" if stale else "current",
    )

    failed = [n for n, ok, _ in results if not ok]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} gates passed")
    if failed:
        print("FAILED: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
