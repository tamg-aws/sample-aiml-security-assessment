"""The producer table in `aisf-parity/probe_live.py`, checked offline.

The live gate runs the checks each shipped `AISF-` row cites, but it only runs
where credentials are, so a source missing from its table was first seen as a
KeyError on a live run. These tests hold the table to the modules' own source:
every function that names a shipped source id must be reachable from one of the
producers the table lists for that id. A module can emit one id from a regional
check and again from an account-wide check labelled Global, and the report folds
both into the verdict, so naming one of the two is not coverage.

The end-to-end cases run `main()` against a stub module, so they measure the
probe's wiring and need no AWS call.
"""

import ast
import copy
import glob
import importlib.util
import os
import sys
import types

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROBE = os.path.join(REPO_ROOT, "aisf-parity", "probe_live.py")
SRC = os.path.join(REPO_ROOT, "aiml-security-assessment", "functions", "security")
REPORT_DIR = os.path.join(SRC, "generate_consolidated_report")

# The dispatcher names ids only for its could-not-assess fallbacks, and it is
# not a function the probe can call, so it is the one name left out of the scan.
DISPATCHER = "lambda_handler"


def load_probe():
    spec = importlib.util.spec_from_file_location("probe_live_incumbents", PROBE)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    return probe


def shipped_sources():
    if REPORT_DIR not in sys.path:
        sys.path.insert(0, REPORT_DIR)
    import aisf_mappings

    marker = aisf_mappings.AISF_COVERAGE_CHECK_ID
    return {
        cid
        for m in aisf_mappings.AISF_DERIVED_MAP
        if m["check_id"] != marker
        for cid in m["sources"]
    }


def _module_functions(path):
    with open(path) as fh:
        tree = ast.parse(fh.read())
    return {
        n.name: n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _reached_from(functions, roots):
    """Every module-level function a root calls or passes, transitively."""
    seen, stack = set(), [r for r in roots if r in functions]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        for node in ast.walk(functions[name]):
            if (
                isinstance(node, ast.Name)
                and node.id in functions
                and node.id not in seen
            ):
                stack.append(node.id)
    return seen


def uncovered_emitters(incumbents, sources):
    """[(cid, module, function)] naming a shipped id that no producer reaches."""
    out = []
    for path in sorted(glob.glob(os.path.join(SRC, "*_assessments", "app.py"))):
        module_dir = os.path.basename(os.path.dirname(path))
        functions = _module_functions(path)
        for cid in sorted(sources):
            roots = [
                fn for mod, fn, _, _ in incumbents.get(cid, ()) if mod == module_dir
            ]
            reached = _reached_from(functions, roots)
            for name, fn in functions.items():
                if name == DISPATCHER or name in reached:
                    continue
                if any(
                    isinstance(n, ast.Constant) and n.value == cid for n in ast.walk(fn)
                ):
                    out.append((cid, module_dir, name))
    return out


def test_every_shipped_source_has_a_producer():
    probe = load_probe()
    sources = shipped_sources()
    assert sources, "AISF_DERIVED_MAP names no source; the check below guards nothing"
    assert sorted(sources - set(probe.INCUMBENTS)) == []


def test_every_function_naming_a_shipped_source_is_reached_by_a_producer():
    probe = load_probe()
    assert uncovered_emitters(probe.INCUMBENTS, shipped_sources()) == []


def test_the_scan_reports_a_global_producer_the_table_drops():
    # Control in the direction that would flatter the table: SM-09's Global rows
    # come from a second function, and a table naming only the regional one
    # must be reported. SM-09 and not BR-37: BR-37 is no longer a shipped
    # source since AISF-06 was retired, so the scan does not read it.
    probe = load_probe()
    table = copy.deepcopy(probe.INCUMBENTS)
    table["SM-09"] = tuple(
        p
        for p in table["SM-09"]
        if p[1] != "check_sagemaker_notebook_access_guardrails"
    )
    assert uncovered_emitters(table, shipped_sources()) == [
        ("SM-09", "sagemaker_assessments", "check_sagemaker_notebook_access_guardrails")
    ]


def test_every_classified_function_is_reached_from_the_function_called():
    # The fourth field names the source the classifier reads. It may differ from
    # the called function only when the call reaches it, or the verdict class
    # would describe code the run never executes.
    probe = load_probe()
    for cid, producers in probe.INCUMBENTS.items():
        for module_dir, fn_name, _, ast_name in producers:
            functions = _module_functions(os.path.join(SRC, module_dir, "app.py"))
            assert fn_name in functions, (cid, fn_name)
            assert ast_name in _reached_from(functions, [fn_name]), (
                cid,
                fn_name,
                ast_name,
            )


def test_every_call_mode_is_one_call_producer_accepts():
    probe = load_probe()
    modes = {p[2] for producers in probe.INCUMBENTS.values() for p in producers}
    stub = types.SimpleNamespace(
        GLOBAL_REGION_LABEL="Global", get_service_control_policy_inventory=dict
    )
    for how in sorted(modes):
        probe.call_producer(stub, lambda *a, **k: None, how, "us-east-1", {})
    with pytest.raises(ValueError):
        probe.call_producer(stub, lambda: None, "nope", "us-east-1", {})


# --------------------------------------------------------------------------
# main(), end to end against a stub module
# --------------------------------------------------------------------------


BR37_EMITS = {
    "check_bedrock_account_data_retention": ("BR-37", "Passed"),
    "check_bedrock_data_retention_scp": ("BR-37", "Failed"),
}


def _stub_module(calls, emits):
    """A module whose producers each emit one finding and record their call."""
    mod = types.SimpleNamespace(GLOBAL_REGION_LABEL="Global")
    mod.create_finding = lambda **kwargs: kwargs
    mod.get_service_control_policy_inventory = lambda: {"items": ["p-1"]}

    def producer(name, check_id, status):
        def fn(*args, **kwargs):
            calls.append((name, kwargs))
            return {"csv_data": [mod.create_finding(check_id=check_id, status=status)]}

        return fn

    for name, (check_id, status) in emits.items():
        setattr(mod, name, producer(name, check_id, status))
    return mod


def _run_main(probe, monkeypatch, rows, calls, tmp_path, emits=BR37_EMITS):
    monkeypatch.setattr(probe, "shipped_rows", lambda: rows)
    monkeypatch.setattr(
        probe,
        "build_permission_cache",
        lambda: {"role_permissions": {}, "user_permissions": {}},
    )
    monkeypatch.setattr(
        probe, "load_module", lambda module_dir: _stub_module(calls, emits)
    )
    out = tmp_path / "probe.json"
    monkeypatch.setattr(
        sys, "argv", ["probe_live.py", "--region", "us-east-1", "--json-out", str(out)]
    )
    return probe.main(), out


def test_an_uncovered_source_prints_leg_one_and_not_a_traceback(
    monkeypatch, tmp_path, capsys
):
    probe = load_probe()
    calls = []
    rc, _ = _run_main(
        probe, monkeypatch, {"AISF-X": ["ZZ-99", "BR-37"]}, calls, tmp_path
    )
    text = capsys.readouterr().out
    assert rc == 1
    assert "shipped sources with no entry in INCUMBENTS: ['ZZ-99']" in text
    # The covered id beside it is still read and still run.
    assert "reachability computed from source: 1 of 2 incumbents read" in text
    assert [c[0] for c in calls] == list(BR37_EMITS)


def test_both_producers_of_one_source_feed_the_row(monkeypatch, tmp_path, capsys):
    import json

    probe = load_probe()
    calls = []
    rc, out = _run_main(probe, monkeypatch, {"AISF-X": ["BR-37"]}, calls, tmp_path)
    capsys.readouterr()
    assert calls == [
        ("check_bedrock_account_data_retention", {"region": "us-east-1"}),
        (
            "check_bedrock_data_retention_scp",
            {"region": "Global", "scp_inventory": {"items": ["p-1"]}},
        ),
    ]
    report = json.loads(out.read_text())
    # The regional producer alone reaches Passed; the Failed comes from the
    # Global one, so a probe that ran one producer reads ONE_ONLY here.
    assert report["rows"]["AISF-X"]["verdict"] == "BOTH"
    assert report["rows"]["AISF-X"]["findings"] == 2
    assert set(report["producer_reachability"]) == {
        "BR-37 check_bedrock_account_data_retention",
        "BR-37 check_bedrock_data_retention_scp",
    }
    assert rc == 0


def test_a_source_takes_its_most_reachable_producer(monkeypatch, tmp_path, capsys):
    # SM-09's regional producer is ELSE_GUARDED and its Global producer is
    # REACHABLE. Taking the least reachable of the two would excuse a ONE_ONLY
    # that the Global producer alone is held to, so a Passed-only run must fail.
    import json

    probe = load_probe()
    calls = []
    emits = {
        "check_sagemaker_notebook_root_access": ("SM-09", "Passed"),
        "check_sagemaker_notebook_access_guardrails": ("SM-09", "Passed"),
    }
    rc, out = _run_main(
        probe, monkeypatch, {"AISF-08": ["SM-09"]}, calls, tmp_path, emits
    )
    text = capsys.readouterr().out
    report = json.loads(out.read_text())
    assert (
        report["producer_reachability"]["SM-09 check_sagemaker_notebook_root_access"][0]
        == probe.ELSE_GUARDED
    )
    assert report["reachability"]["SM-09"][0] == probe.REACHABLE
    assert report["rows"]["AISF-08"]["verdict"] == "ONE_ONLY"
    assert rc == 1
    assert "AISF-08 measured ONE_ONLY while BOTH is reachable from source" in text
