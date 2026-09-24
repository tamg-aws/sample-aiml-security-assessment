#!/usr/bin/env python3
"""Gate the AISF parity work ledger against the two repos it makes claims about.

Every check here can fail. A check that cannot fail is not a gate, so each one
prints its denominator beside its verdict.

Run:  python3 aisf-parity/check_ledger.py
Exit 0 = all gates pass. Exit 1 = at least one gate failed.
"""

import glob
import importlib.util
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
REPORT_APP_DIR = os.path.join(MODULES, "generate_consolidated_report")
SECURITY_CHECKS_DOC = os.path.join(REPO, "docs", "SECURITY_CHECKS.md")
AISF_DOC = os.path.join(REPO, "docs", "SECURITY_CHECKS_AISF.md")

# Gates 11 and 12 read the shipped derived-standard map directly, not a copy of
# it, so a drift between the map and the ledger cannot hide behind a transcription.
#
# Read it from source on every run. The platform python3 on macOS keeps its
# bytecode cache outside the tree (sys.pycache_prefix points into
# ~/Library/Caches/com.apple.python), and a stale entry there whose recorded
# mtime and size match the edited file has already been observed serving the
# previous text of report_template.py: gate 12 reported the old figure and
# passed while the file on disk carried the new one. A gate that reads a stale
# copy of the thing it is gating fails open, so drop any cache entry for these
# two modules and write none.
sys.dont_write_bytecode = True
for _name in ("report_template", "aisf_mappings"):
    _cached = importlib.util.cache_from_source(
        os.path.join(REPORT_APP_DIR, _name + ".py")
    )
    if os.path.exists(_cached):
        os.remove(_cached)

sys.path.insert(0, REPORT_APP_DIR)

from aisf_mappings import (  # noqa: E402
    AISF_COVERAGE_CHECK_ID,
    AISF_DERIVED_MAP,
    AISF_RISK_TO_SEVERITY,
)
from report_template import COMPLIANCE_STANDARDS  # noqa: E402

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


def scope_figures(text):
    """The AISF coverage figures a piece of prose publishes.

    The same three coverage figures are published twice, in the report section's
    scope_text and in docs/SECURITY_CHECKS_AISF.md, so both are read with one
    set of patterns and compared. A figure the patterns cannot find comes back
    as None, which gate 12 treats as a failure: a reworded sentence that drops a
    figure also drops it from the gate.
    """
    out = {}
    for label, pattern in (
        ("derivable", r"(\d+) of the \d+ in-scope AISF controls"),
        ("in_scope", r"\d+ of the (\d+) in-scope AISF controls"),
        ("remaining", r"remaining (\d+) are not yet"),
        ("catalog", r"framework's (\d+)-check total"),
    ):
        found = re.search(pattern, text)
        out[label] = int(found.group(1)) if found else None
    return out


def load_aisf_control(rel_path, control_id):
    """One control item as authored in the AISF repository, or None."""
    with open(os.path.join(AISF_REPO, rel_path)) as f:
        doc = yaml.safe_load(f)
    for item in doc.get("items", []):
        if item.get("id") == control_id:
            return item
    return None


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

    # ---- gate 11: the shipped AISF framework view restates covered controls only,
    # and names the same incumbents the ledger names.
    # A `tighten` control must never reach the map: its incumbent asserts only part
    # of the control, so republishing that incumbent's `Passed` under the AISF
    # control id publishes a pass the assessment never earned.
    by_control = {r["control"]: r for r in rows}
    bad_map = []
    bad_ids = set()
    for m in AISF_DERIVED_MAP:
        row = by_control.get(m["control"])
        if row is None:
            bad_map.append(f"{m['check_id']}:{m['control']} has no ledger row")
            bad_ids.add(m["check_id"])
            continue
        if row["verdict"] != "covered":
            bad_map.append(f"{m['check_id']}:{m['control']} verdict={row['verdict']}")
            bad_ids.add(m["check_id"])
        if len(set(m["sources"])) != len(m["sources"]) or set(m["sources"]) != set(
            row["incumbents"]
        ):
            bad_map.append(
                f"{m['check_id']}:{m['control']} sources={m['sources']} "
                f"incumbents={row['incumbents']}"
            )
            bad_ids.add(m["check_id"])
    n_covered = sum(1 for r in rows if r["verdict"] == "covered")
    gate(
        "derived AISF map restates covered controls only",
        not bad_map,
        f"{len(AISF_DERIVED_MAP) - len(bad_ids)}/{len(AISF_DERIVED_MAP)} mappings "
        f"agree with the ledger, {len(AISF_DERIVED_MAP)}/{n_covered} covered "
        "controls mapped" + (f", bad={bad_map}" if bad_map else ""),
    )

    # ---- gate 12: the control text baked into the map, and every figure the AISF
    # report section publishes, still match the source they were taken from.
    # The text is baked because the AISF repo is not on the Lambda's filesystem at
    # runtime, so nothing at runtime can notice that it has drifted.
    drift = []
    for m in AISF_DERIVED_MAP:
        row = by_control.get(m["control"])
        if row is None:
            continue  # already reported by gate 11
        item = load_aisf_control(row["source"], m["control"])
        if item is None:
            drift.append(f"{m['check_id']}: control absent from {row['source']}")
            continue
        # Severity is the documented collapse of AISF's five risk bands onto this
        # repository's four-level SeverityEnum, not an identity match: there is no
        # `Critical` here (see the note on AISF_RISK_TO_SEVERITY).
        expected_severity = AISF_RISK_TO_SEVERITY.get(item["risk"])
        if expected_severity is None:
            drift.append(f"{m['check_id']}: risk={item['risk']} has no severity band")
        elif m["severity"] != expected_severity:
            drift.append(
                f"{m['check_id']}: severity={m['severity']} but risk="
                f"{item['risk']} maps to {expected_severity}"
            )
        if m["resolution"] != item["rec"]:
            drift.append(f"{m['check_id']}: resolution drifted from the control's rec")
        if m["reference"] != item["src"][0]["u"]:
            drift.append(
                f"{m['check_id']}: reference={m['reference']} != {item['src'][0]['u']}"
            )

    aisf_entry = next((s for s in COMPLIANCE_STANDARDS if s["slug"] == "aisf"), None)
    figures = scope_figures((aisf_entry or {}).get("scope_text", ""))
    with open(AISF_DOC) as f:
        doc_figures = scope_figures(f.read())
    # AI-00 is the coverage marker row, never a control, so it is not in the map
    # and must not be counted among the derivable controls.
    allocated = [m["check_id"] for m in AISF_DERIVED_MAP]
    if AISF_COVERAGE_CHECK_ID in allocated:
        drift.append(f"{AISF_COVERAGE_CHECK_ID} is reserved but allocated to a control")
    with open(SECURITY_CHECKS_DOC) as f:
        doc_total = re.search(r"reference for all (\d+) security checks", f.read())
    catalog_total = int(doc_total.group(1)) if doc_total else None
    if figures["derivable"] != len(AISF_DERIVED_MAP):
        drift.append(
            f"scope_text claims {figures['derivable']} derivable, map has "
            f"{len(AISF_DERIVED_MAP)}"
        )
    if figures["in_scope"] != summary["total"]:
        drift.append(
            f"scope_text claims {figures['in_scope']} in scope, ledger totals "
            f"{summary['total']}"
        )
    if None in (figures["derivable"], figures["remaining"], figures["in_scope"]) or (
        figures["derivable"] + figures["remaining"] != figures["in_scope"]
    ):
        drift.append(f"scope_text figures do not partition: {figures}")
    if figures["catalog"] != catalog_total:
        drift.append(
            f"scope_text claims a {figures['catalog']}-check catalog, "
            f"SECURITY_CHECKS.md publishes {catalog_total}"
        )
    if doc_figures != figures:
        drift.append(
            f"SECURITY_CHECKS_AISF.md publishes {doc_figures}, the report "
            f"section publishes {figures}"
        )
    gate(
        "baked AISF control text and published figures match their sources",
        not drift,
        f"{len(AISF_DERIVED_MAP)} mappings x 3 baked fields + "
        f"{len(figures)} figures in the report section + "
        f"{len(doc_figures)} in SECURITY_CHECKS_AISF.md checked, "
        f"figures={figures}" + (f", drift={drift}" if drift else ""),
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
