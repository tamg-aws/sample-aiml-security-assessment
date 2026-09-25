#!/usr/bin/env python3
"""Gate the AISF parity work ledger against the two repos it makes claims about.

Every check here can fail. A check that cannot fail is not a gate, so each one
prints its denominator beside its verdict.

Run:  python3 aisf-parity/check_ledger.py
Exit 0 = all gates pass. Exit 1 = at least one gate failed.
"""

import collections
import glob
import importlib.util
import json
import os
import re
import subprocess
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
OWASP_DOC = os.path.join(REPO, "docs", "SECURITY_CHECKS_OWASP.md")
GRC_DOC = os.path.join(REPO, "docs", "SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md")

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
#
# build_ledger is in the same list for the same reason: gate 10 renders the
# markdown through it, so a stale copy of the renderer would compare the json
# against yesterday's layout and pass. gen_compliance_maps likewise: gate 12
# derives the catalog total through its check_owners(), and a stale copy would
# count the ids the producers emitted the last time it was imported.
sys.dont_write_bytecode = True
for _dir, _name in (
    (REPORT_APP_DIR, "report_template"),
    (REPORT_APP_DIR, "aisf_mappings"),
    (HERE, "build_ledger"),
    (HERE, "gen_compliance_maps"),
):
    _cached = importlib.util.cache_from_source(os.path.join(_dir, _name + ".py"))
    if os.path.exists(_cached):
        os.remove(_cached)

sys.path.insert(0, REPORT_APP_DIR)
sys.path.insert(0, HERE)

from aisf_mappings import (  # noqa: E402
    AISF_COVERAGE_CHECK_ID,
    AISF_DERIVED_MAP,
    AISF_RISK_TO_SEVERITY,
    SEVERITY_COLLAPSE_NOTE,
    derive_aisf_findings,
)
from build_ledger import render_markdown  # noqa: E402
from gen_compliance_maps import check_owners  # noqa: E402
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


def figure_occurrences(text, patterns):
    """label -> every value its pattern finds, over whitespace-flattened text.

    Flattened for two independent reasons. A marker that hard-wraps is invisible
    to a literal-space pattern: measured against the tag-column paragraph as
    published, the patterns resolve 7 of 8 figures on the raw file and miss
    `naming 36\\ndistinct controls`. And the agreement rule below has to count
    copies on the same flattened text, or a hard-wrapped second copy carrying a
    different number is not seen as a copy at all, which leaves exactly the hole
    a first-match read left open.
    """
    flat = re.sub(r"\s+", " ", text)
    return {label: re.findall(pattern, flat) for label, pattern in patterns}


def agreed_figure(found):
    """The integer every occurrence agrees on, or None for none or a disagreement.

    A figure appearing more than once is not an error by itself: these figures
    live in nine files and move together, and one file can restate a paragraph.
    Two copies that *disagree* is the error, and taking the earliest match is how
    it stayed invisible -- a correct copy earlier in the file returned the right
    number while the published paragraph below it was wrong, and gate 12, gate 14
    and the whole battery passed. So every copy has to agree and there has to be
    at least one; zero is still a failure, exactly as it was.

    Compared as integers and not as the strings matched, so a zero-padded copy is
    not read as a second, different figure.
    """
    values = {int(v) for v in found}
    if len(values) != 1:
        return None
    return values.pop()


def agreed_mapping(found):
    """The same rule for the per-module split, compared as a parsed mapping.

    Parsed before comparing, so two copies listing the same modules in a
    different order agree. The names are part of the published claim: a renamed
    producer is how that sentence goes stale with no count moving.
    """
    parsed = [
        {m.group(1): int(m.group(2)) for m in re.finditer(r"(\w+) (\d+)", sentence)}
        for sentence in found
    ]
    if not parsed or any(p != parsed[0] for p in parsed):
        return None
    return parsed[0]


def figure_problems(source, values, found):
    """One message per figure `source` fails to publish once and consistently.

    Absence and disagreement both arrive as a None value and are reported apart,
    because they are different defects with different repairs: no match at all is
    a reworded or deleted sentence, while two matches that differ is a stale
    published paragraph masked by a correct copy elsewhere in the same file. The
    occurrence list is the only thing that tells them apart, so it is what this
    reads, and every value found is printed with the name of the figure.
    """
    problems = []
    for label, value in sorted(values.items()):
        if not found[label]:
            problems.append(
                f"{source} publishes no {label} figure these patterns can find"
            )
        elif value is None:
            problems.append(
                f"{source} publishes {len(found[label])} copies of {label} that "
                f"disagree: {found[label]}"
            )
    return problems


def copies_note(found):
    """`label xN` for every figure, for printing beside the values.

    The count belongs in the verdict line and is not a debug aid: it is what says
    how much the agreement rule had to compare. One copy asserts the agreement of
    one, which is the whole of what the old first-match read ever checked.
    """
    return " ".join(f"{label} x{len(hits)}" for label, hits in sorted(found.items()))


def scope_figures(text):
    """The AISF coverage figures a piece of prose publishes, and all their copies.

    The same three coverage figures are published twice, in the report section's
    scope_text and in docs/SECURITY_CHECKS_AISF.md, so both are read with one
    set of patterns and compared. Returns the figures beside every occurrence
    found for each. A figure is the value all of its copies agree on; gate 12
    reads None as a failure whether that is no copy or two that disagree, so a
    reworded sentence that drops a figure also drops it from the gate.
    """
    found = figure_occurrences(
        text,
        (
            ("derivable", r"(\d+) of the \d+ in-scope AISF controls"),
            ("in_scope", r"\d+ of the (\d+) in-scope AISF controls"),
            ("remaining", r"remaining (\d+) are not yet"),
            ("catalog", r"framework's (\d+)-check total"),
        ),
    )
    return {label: agreed_figure(hits) for label, hits in found.items()}, found


def tag_column_figures(text):
    """The Compliance_Frameworks figures a piece of prose publishes, and their copies.

    Whitespace is collapsed to single spaces over the whole text first. Measured
    against the paragraph as published: these same patterns without the flatten
    resolve 7 of the 8 figures and return one None. The miss is `controls`, because
    the prose reads `naming 36\\ndistinct controls` and the break falls inside that
    marker. The break in `sagemaker 7,\\nagentcore 12` costs nothing, because it
    falls between two pairs the per-module pattern matches separately.

    So a wrap only costs a figure when it lands inside a marker, and where it lands
    moves with the digit count of the figures themselves. Two consequences. An
    unflattened implementation reads as working, since seven figures and one None
    look like a doc that published seven figures. And a control that re-wraps the
    paragraph at some other width can leave the break inside the same marker and
    pass for the wrong reason, so pick the width by checking which marker it splits.
    Flattening removes the dependence on the wrap position altogether.

    Same fail-closed contract as scope_figures(): the value is what every copy of
    the figure agrees on, and gate 14 fails on None whether that is no copy at all
    or two copies that disagree. A reworded sentence that drops a figure drops the
    gate with it instead of quietly stopping the assertion.

    The qualifier census (bare/partial/joint) is deliberately absent. Gate 14
    prints it, two tools compute it, and no document publishes it, so there is no
    published claim to gate.
    """
    found = figure_occurrences(
        text,
        (
            ("pairs", r"(\d+) check-control pairs over \d+ tagged checks"),
            ("tagged", r"\d+ check-control pairs over (\d+) tagged checks"),
            ("modules", r"tagged checks in (\d+) modules"),
            ("controls", r"naming (\d+) distinct controls"),
            # The per-module split is read as a mapping and not as four numbers, so
            # the module *names* are asserted too: a renamed producer is the way
            # this sentence goes stale without any count changing.
            ("per_module", r"Tagged checks per module are ([^.]+)\."),
        ),
    )
    out = {
        label: agreed_figure(hits)
        for label, hits in found.items()
        if label != "per_module"
    }
    out["per_module"] = agreed_mapping(found["per_module"])
    return out, found


def load_aisf_control(rel_path, control_id):
    """One control item as authored in the AISF repository, or None."""
    with open(os.path.join(AISF_REPO, rel_path)) as f:
        doc = yaml.safe_load(f)
    for item in doc.get("items", []):
        if item.get("id") == control_id:
            return item
    return None


def load_compliance_maps():
    """module dir -> the AISF_COMPLIANCE_MAP that module ships.

    Loaded from source under the module's own unique name. The map modules are
    deliberately not all called `aisf_compliance`: several producers get loaded
    into one interpreter by the test suite, and a shared bare name resolves to
    whichever directory reached sys.path last, which returns "" for every other
    producer's check ids without raising. Any cached bytecode is dropped first,
    for the reason given at the top of this file.
    """
    out = {}
    for module_dir in sorted(MODULE_TO_FUNCTION):
        suffix = module_dir.removesuffix("_assessments")
        name = f"aisf_compliance_{suffix}"
        path = os.path.join(MODULES, module_dir, name + ".py")
        if not os.path.exists(path):
            continue
        cached = importlib.util.cache_from_source(path)
        if os.path.exists(cached):
            os.remove(cached)
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        out[module_dir] = module.AISF_COMPLIANCE_MAP
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

    # ---- gate 10: the markdown view is the json, rendered.
    # Content, not mtimes. The mtime version of this gate failed in every fresh
    # clone and passed in the tree the ledger was built in, because a checkout
    # writes both files inside the same second in git-index order, which puts
    # uppercase AISF-WORK-LEDGER.md before lowercase aisf-work-ledger.json. It
    # also passed for a `touch`, and failed for a regeneration that produced a
    # byte-identical file. Nothing here writes the markdown: a gate that
    # regenerates the artifact it is gating cannot fail.
    md = os.path.join(HERE, "AISF-WORK-LEDGER.md")
    expected = render_markdown(doc).split("\n")
    if os.path.exists(md):
        with open(md) as f:
            actual = f.read().split("\n")
    else:
        actual = None
    if actual is None:
        detail = f"{os.path.basename(md)} is missing; run build_ledger.py"
    elif actual == expected:
        detail = f"{len(expected)} rendered line(s) identical to the file on disk"
    else:
        first = next(
            (
                i
                for i in range(max(len(expected), len(actual)))
                if expected[i : i + 1] != actual[i : i + 1]
            ),
            0,
        )
        detail = (
            f"first difference at line {first + 1} of "
            f"{len(actual)} on disk vs {len(expected)} rendered: "
            f"disk={actual[first : first + 1] or ['<end of file>']!r} "
            f"rendered={expected[first : first + 1] or ['<end of file>']!r}; "
            "regenerate with build_ledger.py"
        )
    gate("markdown view renders from the json", actual == expected, detail)

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
        # `Critical` here (see the note on AISF_RISK_TO_SEVERITY). The map carries
        # the pre-collapse band as data because the rows disclose it, so the band
        # itself is compared against the source too: a control upgraded upstream
        # from high to critical must change the note the rows carry, and only the
        # `risk` comparison notices that while the collapsed severity holds still.
        if m["risk"] != item["risk"]:
            drift.append(
                f"{m['check_id']}: risk={m['risk']} but the control is {item['risk']}"
            )
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

    # A risk band whose name does not survive the collapse is disclosed in every
    # row it produces. Read off the derivation's output rather than the note
    # constant: the constant being right is not the claim, the row carrying it is,
    # and a change to how details are assembled could drop it while the constant
    # still reads correctly. Both status branches are exercised, because an `N/A`
    # row carries Informational and takes the other wording path.
    collapsed = [m for m in AISF_DERIVED_MAP if m["risk"] in SEVERITY_COLLAPSE_NOTE]
    for m in collapsed:
        for status in ("Passed", "N/A"):
            emitted = derive_aisf_findings(
                [
                    {
                        "Check_ID": cid,
                        "Status": status,
                        "Region": "us-east-1",
                        "Account_ID": "000000000000",
                    }
                    for cid in m["sources"]
                ]
            )
            row_out = next((r for r in emitted if r["Check_ID"] == m["check_id"]), None)
            if row_out is None:
                drift.append(f"{m['check_id']}: no row derived for status={status}")
            elif SEVERITY_COLLAPSE_NOTE[m["risk"]] not in row_out["Finding_Details"]:
                drift.append(
                    f"{m['check_id']}: {status} row does not disclose risk={m['risk']}"
                )
            elif row_out["Severity"] not in row_out["Finding_Details"]:
                # The disclosure names a severity, so the row has to name the one
                # it is actually carrying. On the N/A path those differ: the note
                # says High and the row is Informational, and without this the
                # gate would pass a row that reads as a claim about its own
                # severity while contradicting the Severity column beside it.
                drift.append(
                    f"{m['check_id']}: {status} row carries "
                    f"{row_out['Severity']} without naming it"
                )

    aisf_entry = next((s for s in COMPLIANCE_STANDARDS if s["slug"] == "aisf"), None)
    figures, figure_hits = scope_figures((aisf_entry or {}).get("scope_text", ""))
    with open(AISF_DOC) as f:
        doc_figures, doc_hits = scope_figures(f.read())
    # AISF-00 is the coverage marker row, never a control, so it is not in the map
    # and must not be counted among the derivable controls.
    allocated = [m["check_id"] for m in AISF_DERIVED_MAP]
    if AISF_COVERAGE_CHECK_ID in allocated:
        drift.append(f"{AISF_COVERAGE_CHECK_ID} is reserved but allocated to a control")
    with open(SECURITY_CHECKS_DOC) as f:
        sc_hits = figure_occurrences(
            f.read(), (("sc_total", r"reference for all (\d+) security checks"),)
        )
    catalog_total = agreed_figure(sc_hits["sc_total"])
    # Each figure above is the value all of its copies agree on, and a figure whose
    # copies disagree is a failure of its own, named here with every value found.
    # These three reads used to take the earliest match over the whole file, so a
    # correct copy above the published paragraph -- another section, a quoted
    # example, a deliberately dated appendix -- answered for the paragraph below
    # it. Reproduced: a duplicate sentence at the top of SECURITY_CHECKS_AISF.md
    # carrying the right figures left gate 14 green and the battery at 16/16 with
    # exit 0 while the paragraph it publishes read one control too many.
    drift += figure_problems("the report section's scope_text", figures, figure_hits)
    drift += figure_problems("SECURITY_CHECKS_AISF.md", doc_figures, doc_hits)
    drift += figure_problems("SECURITY_CHECKS.md", {"sc_total": catalog_total}, sc_hits)
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
    # The catalog total gets a third side, derived from the code that emits the
    # ids. The other two are both prose -- report_template's scope_text and
    # SECURITY_CHECKS.md line 3 -- so comparing only those two catches one copy
    # drifting and never both copies being equally stale. That is the failure that
    # already happened: the two read 208 to each other's satisfaction while the
    # producers emitted 218, and ten check ids shipped undocumented.
    #
    # Derived through gen_compliance_maps.check_owners() and not a regex written
    # here. It runs both call spellings, and agent_registry_assessments passes
    # check_id positionally, so a `check_id=` keyword scan resolves 0 of that
    # module's 9 ids while a scan loose enough to catch them also matches every
    # quoted id in a comment or docstring (BR alone measured 62 against a true 47).
    #
    # The `XX-00` rows are excluded by name: they are the "no resource of this type
    # in the account" markers, never a check, and the published total counts checks.
    # The excluded count is printed so the exclusion is visible and arguable.
    catalog_owners = check_owners()
    marker_ids = sorted(c for c in catalog_owners if c.endswith("-00"))
    emitted_catalog_ids = sorted(c for c in catalog_owners if not c.endswith("-00"))
    catalog_sides = {
        "emitted": len(emitted_catalog_ids),
        "scope_text": figures["catalog"],
        "SECURITY_CHECKS.md": catalog_total,
    }
    if not emitted_catalog_ids:
        # Zero is not agreement with a prose figure of zero either: it means the
        # derivation resolved nothing, which would make the comparison below and
        # gate 13's doc leg both vacuous.
        drift.append(
            f"check_owners() resolved no non-marker check id under {MODULES}, so "
            "the derived side of the catalog total measures nothing"
        )
    elif len(set(catalog_sides.values())) != 1:
        drift.append(
            f"the catalog total disagrees across its three sides: {catalog_sides}"
        )
    if doc_figures != figures:
        drift.append(
            f"SECURITY_CHECKS_AISF.md publishes {doc_figures}, the report "
            f"section publishes {figures}"
        )
    gate(
        "baked AISF control text and published figures match their sources",
        not drift,
        f"{len(AISF_DERIVED_MAP)} mappings x 4 baked fields + "
        f"{len(collapsed)} collapsed-band disclosures x 2 status paths + "
        f"{len(figures)} figures in the report section + "
        f"{len(doc_figures)} in SECURITY_CHECKS_AISF.md checked, "
        f"figures={figures}, copies scope_text [{copies_note(figure_hits)}] "
        f"SECURITY_CHECKS_AISF.md [{copies_note(doc_hits)}] "
        f"SECURITY_CHECKS.md [{copies_note(sc_hits)}], "
        f"catalog 3 sides: emitted {len(emitted_catalog_ids)} "
        f"({len(catalog_owners)} distinct ids minus {len(marker_ids)} "
        f"{marker_ids} markers) vs scope_text {figures['catalog']} vs "
        f"SECURITY_CHECKS.md {catalog_total}" + (f", drift={drift}" if drift else ""),
    )

    # ---- gate 13: the published id shape. Every id carries the registered prefix
    # and is documented. The prefix is four letters where every producing prefix is
    # two, so an id spelled with a different prefix length still looks plausible;
    # what it actually does is route to `else: service = "bedrock"` in both
    # consolidators, filing the row under Bedrock with no error anywhere. The doc
    # leg is here because a rename that misses the catalog leaves a published id
    # undocumented, which is the same evidence gap as an unregistered prefix.
    registered_prefix = (aisf_entry or {}).get("prefix", "")
    with open(AISF_DOC) as f:
        aisf_doc_text = f.read()
    shape = []
    all_ids = [m["check_id"] for m in AISF_DERIVED_MAP] + [AISF_COVERAGE_CHECK_ID]
    if registered_prefix != "AISF-":
        shape.append(f"registry prefix is {registered_prefix!r}, not 'AISF-'")
    for cid in all_ids:
        if not re.fullmatch(r"AISF-\d{2}", cid):
            shape.append(f"{cid} does not match ^AISF-\\d{{2}}$")
        if not cid.startswith(registered_prefix):
            shape.append(f"{cid} does not carry the registered prefix")
        if cid not in aisf_doc_text:
            shape.append(f"{cid} is not documented in SECURITY_CHECKS_AISF.md")

    # The same evidence gap, over the whole emitted catalog rather than the nine
    # derived ids. Read against SECURITY_CHECKS.md plus the two per-framework
    # catalogues, because the OW- and NR- ids are documented in their own files and
    # not in the main one. Not against SECURITY_CHECKS_AISF.md: that file
    # catalogues AISF-01..08 and has no per-service section, so `BR-01` has 0 hits
    # in it while `AISF-01` has 3, and reading it here would flag all 208 ids.
    #
    # docs/DEVELOPER_GUIDE.md is excluded, and not because it is wrong. Its line
    # 739 reads "Your new `Check_ID` (for example BR-41, SM-31, AR-09, AG-33,
    # OW-13, or NR-01)": it names the *next* id a contributor would add, so five of
    # those six do not exist here and the sentence is accurate as written. Counting
    # it as a documentation source would mark an id documented the day it ships,
    # from prose written before it existed, which is the drift this leg exists to
    # catch. Of the six only AG-33 exists at this base, and SECURITY_CHECKS.md
    # documents it properly, so the exclusion changes nothing here yet.
    doc_sources = (SECURITY_CHECKS_DOC, OWASP_DOC, GRC_DOC)
    catalogued = ""
    for path in doc_sources:
        with open(path) as f:
            catalogued += f.read()
    if not emitted_catalog_ids or not catalogued.strip():
        shape.append(
            f"{len(emitted_catalog_ids)} emitted id(s) against "
            f"{len(catalogued)} character(s) of catalogue: one side is empty, so "
            "the per-id loop below asserts nothing"
        )
    for cid in emitted_catalog_ids:
        if cid not in catalogued:
            shape.append(f"{cid} is emitted but documented in no catalogue")
    gate(
        "every derived id has the published AISF- shape, and every emitted id is "
        "documented",
        not shape,
        f"{len(all_ids)} ids ({len(AISF_DERIVED_MAP)} mapped + the coverage marker) "
        f"x 3 legs (^AISF-\\d{{2}}$, registered prefix {registered_prefix!r}, "
        f"documented) checked; {len(emitted_catalog_ids)} emitted non-marker id(s) "
        f"against {len(doc_sources)} catalogue(s) "
        f"({', '.join(os.path.basename(p) for p in doc_sources)}), "
        "DEVELOPER_GUIDE.md excluded as forward-looking"
        + (f", bad={shape}" if shape else ""),
    )

    # ---- gate 14: the per-module AISF tag maps agree with the ledger, in both
    # directions, and no tag overstates what its check asserts.
    #
    # Phase 2 tags rows the producers already emit, so unlike the derived map in
    # gate 11 it *may* reference a `tighten` control. What makes that sound is the
    # qualifier: `(partial)` says the check asserts less than the control needs,
    # and `(1 of N checks)` says the control is covered but not by this leg alone.
    # Drop the qualifier and the row reads as a full pass against a control the
    # assessment only partly checks, which is the same overclaim gate 11 exists to
    # prevent. So the qualifier is derived from the ledger here rather than
    # trusted, and the N is compared against the row's own incumbent count.
    #
    # Both directions, because a scan over the maps cannot see a control that was
    # never written into one, and that is the direction a newly-added ledger row
    # drifts.
    taggable = ("covered", "tighten")
    maps = load_compliance_maps()
    # Called again rather than reusing `emitted` from the top of main(): gate 12
    # rebinds that name to a list of derived findings, so by here it is no longer
    # the check_id -> modules map.
    emitting_modules = emitted_check_ids()
    expected_pairs = set()
    for r in rows:
        if r["verdict"] in taggable:
            for inc in r["incumbents"] or []:
                expected_pairs.add((inc, r["control"]))
    found_pairs = set()
    tag_problems = []
    element_re = re.compile(
        r"AISF (AIR-[A-Z]+-[A-Z]+-\d+)(?: \((partial|1 of (\d+) checks)\))?$"
    )
    for module_dir, mapping in sorted(maps.items()):
        for cid, tag in sorted(mapping.items()):
            if module_dir not in emitting_modules.get(cid, set()):
                tag_problems.append(f"{module_dir} maps {cid}, which it does not emit")
            for element in tag.split(" | "):
                m = element_re.fullmatch(element)
                if not m:
                    tag_problems.append(
                        f"{module_dir}:{cid} unparseable tag {element!r}"
                    )
                    continue
                control, qualifier, denominator = m.groups()
                row = by_control.get(control)
                if row is None or row["verdict"] not in taggable:
                    verdict = None if row is None else row["verdict"]
                    tag_problems.append(
                        f"{module_dir}:{cid}:{control} verdict={verdict}"
                    )
                    continue
                found_pairs.add((cid, control))
                legs = len(row["incumbents"] or [])
                want = (
                    "partial"
                    if row["verdict"] == "tighten"
                    else (None if legs == 1 else f"1 of {legs} checks")
                )
                if qualifier != want:
                    tag_problems.append(
                        f"{module_dir}:{cid}:{control} verdict={row['verdict']} "
                        f"legs={legs} qualifier={qualifier!r} want={want!r}"
                    )
                elif denominator is not None and int(denominator) != legs:
                    tag_problems.append(
                        f"{module_dir}:{cid}:{control} denominator={denominator} legs={legs}"
                    )
    missing = expected_pairs - found_pairs
    extra = found_pairs - expected_pairs
    if missing:
        tag_problems.append(f"in the ledger, absent from every map: {sorted(missing)}")
    if extra:
        tag_problems.append(f"in a map, not taggable in the ledger: {sorted(extra)}")
    # Every figure docs/SECURITY_CHECKS_AISF.md publishes about the tag column is
    # computed here, and now asserted against the doc rather than only printed
    # beside it. Printing was not enough: the eight figures in that paragraph are
    # transcribed by hand, and adding one entry to any aisf_compliance_*.py moves
    # four of them, so a stale paragraph shipped under a green gate that printed the
    # right numbers two lines further down.
    #
    # Asserted in gate 14 and not in a gate of its own, because these are the same
    # values the predicate above already computes. A separate gate would recompute
    # them and could then disagree with the line printed here.
    #
    # The qualifier census stays printed and unasserted: no document publishes it,
    # and it doubles as a shape check a reader can apply -- `bare` must equal the
    # number of covered controls with a single incumbent.
    computed = {
        "pairs": len(found_pairs),
        "tagged": sum(len(m) for m in maps.values()),
        "modules": len(maps),
        "controls": len({c for _, c in found_pairs}),
        "per_module": {
            d.removesuffix("_assessments"): len(m) for d, m in sorted(maps.items())
        },
    }
    # Re-read rather than reusing gate 13's copy of the text: the gates above rebind
    # names across blocks, and a figure gate that reads the wrong buffer fails open.
    with open(AISF_DOC) as f:
        published, published_hits = tag_column_figures(f.read())
    # Three outcomes, not two: no copy of the figure, copies that disagree with each
    # other, and a copy that disagrees with the gate. The middle one is new and was
    # the fail-open case -- an earlier copy carrying the right number answered for
    # the published paragraph. These messages name the computed value too, which is
    # why gate 14 does not reuse figure_problems() from gate 12.
    for label, want in published.items():
        if not published_hits[label]:
            tag_problems.append(
                f"SECURITY_CHECKS_AISF.md publishes no {label} figure these patterns "
                f"can find; gate 14 computes {computed[label]}"
            )
        elif want is None:
            tag_problems.append(
                f"SECURITY_CHECKS_AISF.md publishes {len(published_hits[label])} "
                f"copies of {label} that disagree: {published_hits[label]}; gate 14 "
                f"computes {computed[label]}"
            )
        elif want != computed[label]:
            tag_problems.append(
                f"SECURITY_CHECKS_AISF.md publishes {label}={want}, gate 14 computes "
                f"{computed[label]}"
            )
    per_module = " ".join(f"{k}={v}" for k, v in sorted(computed["per_module"].items()))
    census = collections.Counter()
    for module_dir, mapping in maps.items():
        for tag in mapping.values():
            for element in tag.split(" | "):
                m = element_re.fullmatch(element)
                if m:
                    census[
                        "bare"
                        if m.group(2) is None
                        else ("partial" if m.group(2) == "partial" else "joint")
                    ] += 1
    gate(
        "per-module AISF tag maps agree with the ledger both ways",
        not tag_problems,
        f"{len(found_pairs)}/{len(expected_pairs)} check-control pairs over "
        f"{sum(len(m) for m in maps.values())} tagged checks in {len(maps)} modules, "
        f"naming {len({c for _, c in found_pairs})} distinct controls; "
        f"checks per module {per_module}; qualifiers bare={census['bare']} "
        f"partial={census['partial']} joint={census['joint']} (printed, not gated: "
        "no document publishes them); each checked for module ownership, ledger "
        f"verdict and qualifier; {len(published) - 1} scalar figure(s) + "
        f"{len(published['per_module'] or {})} per-module figure(s) asserted against "
        f"SECURITY_CHECKS_AISF.md, doc={published} vs computed={computed}, "
        f"copies [{copies_note(published_hits)}]"
        + (f", bad={tag_problems}" if tag_problems else ""),
    )

    # ---- gate 15: the shipped maps are what the generator renders from the
    # ledger. Gate 14 asserts the semantics independently of the generator; this
    # one catches a hand-edit that happens to stay semantically legal, such as a
    # reordered or duplicated entry.
    gen = subprocess.run(
        [sys.executable, os.path.join(HERE, "gen_compliance_maps.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    gate(
        "shipped AISF tag maps match a fresh render of the ledger",
        gen.returncode == 0 and "maps match the ledger" in gen.stdout,
        f"generator --check exit {gen.returncode} over {len(maps)} modules"
        + (
            ""
            if gen.returncode == 0
            else f", output={(gen.stdout + gen.stderr).strip().splitlines()[-1:]}"
        ),
    )

    # ---- gate 16: every generated map is wired into its own module's schema.py.
    # A generated aisf_compliance_<module>.py that nothing imports stops tagging
    # without failing: `Compliance_Frameworks` falls back to its Field(default="")
    # while create_finding still fills it for the wired modules, so the column is
    # present in every CSV and one producer's cells are empty. Deleting the import
    # and keeping the call raises NameError, which is loud; the silent case is a
    # new producer whose schema.py never wires the map at all.
    #
    # The list is globbed rather than taken from MODULE_TO_FUNCTION above, because
    # a hardcoded module list is the thing this gate exists to close, and
    # load_compliance_maps() `continue`s past a missing file, which is the same
    # fail-open shape. A module that ships no map is simply not globbed: only
    # four of the six producers carry one.
    map_files = sorted(glob.glob(os.path.join(MODULES, "*", "aisf_compliance_*.py")))
    unwired = []
    for path in map_files:
        module_dir = os.path.basename(os.path.dirname(path))
        name = os.path.basename(path).removesuffix(".py")
        schema_path = os.path.join(os.path.dirname(path), "schema.py")
        if not os.path.exists(schema_path):
            unwired.append(f"{module_dir} ships {name}.py but has no schema.py")
            continue
        with open(schema_path) as f:
            schema_src = f.read()
        pattern = rf"^\s*(?:from {re.escape(name)} import|import {re.escape(name)}\b)"
        if not re.search(pattern, schema_src, re.M):
            unwired.append(f"{module_dir}/schema.py does not import {name}")
        elif "aisf_frameworks(" not in schema_src:
            unwired.append(f"{module_dir}/schema.py imports {name} but never calls it")
    gate(
        "every generated AISF map is imported and called by its own schema.py",
        # Fail closed on zero. An empty glob makes the loop above vacuously clean,
        # and "0/0 wired" would print beside a PASS.
        bool(map_files) and not unwired,
        f"{len(map_files) - len(unwired)}/{len(map_files)} map(s) wired into the "
        f"schema.py beside them"
        + (
            ""
            if map_files
            else "; no aisf_compliance_*.py exists at all, which is "
            "not a pass -- an empty set satisfies every per-file check above"
        )
        + (f", unwired={unwired}" if unwired else ""),
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
