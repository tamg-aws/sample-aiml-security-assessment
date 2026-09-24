#!/usr/bin/env python3
"""Live-verifiability gate for the derived AISF rows.

Every shipped `AISF-` row restates the verdict of one or more incumbent checks.
This gate runs those incumbents against real AWS credentials and classifies each
row BOTH / ONE_ONLY / NONE / VACUOUS:

  BOTH      Passed and Failed both reached. The row discriminates.
  ONE_ONLY  one verdict reached, the other never fired.
  NONE      no Passed and no Failed at all. The row asserts nothing.
  VACUOUS   every finding came from a short-circuit (missing client, missing
            permission, unreadable field) instead of from the assertion.

NONE and VACUOUS always fail: a row that ships a green verdict without
exercising its assertion is a coverage claim with nothing behind it.

ONE_ONLY is judged against whether BOTH is *reachable in this account*, which
the gate computes from each incumbent's own source on every run (see
`classify_reachability`). Three structures exist in this repository:

  REACHABLE      a per-resource emit whose status is computed, or a summary
                 Passed under an `if` independent of the failure list. BOTH is
                 reachable, so ONE_ONLY means a fixture is missing and fails.
  ELSE_GUARDED   the only Passed sits in the `else` of the guard that emits the
                 Failed findings, so one non-compliant resource suppresses it
                 for the whole account. ONE_ONLY is recorded, not failed.
  SINGLETON      one account-level emit, so one verdict per region exists by
                 construction. ONE_ONLY is recorded, not failed.

Reachability is recomputed from source rather than declared in a table, so no
stored classification can go stale against an edited check. `--selftest` proves
the classifier on synthetic functions of each shape, including a control in the
surprising direction.

Read-only. The only AWS calls are the List/Describe/Get calls the checks make,
plus the IAM reads that build the permission cache.
"""

import argparse
import ast
import importlib.util
import inspect
import json
import os
import sys
import textwrap
from collections import defaultdict

sys.dont_write_bytecode = True

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "aiml-security-assessment", "functions", "security")
REPORT_DIR = os.path.join(SRC, "generate_consolidated_report")

REACHABLE = "REACHABLE"
ELSE_GUARDED = "ELSE_GUARDED"
SINGLETON = "SINGLETON"
NO_VERDICT_PATH = "NO_VERDICT_PATH"

# Where each incumbent lives and how to call it. The row list is NOT duplicated
# here: it comes from aisf_mappings.AISF_DERIVED_MAP, and leg 1 fails if this
# table does not cover every source id that map names.
INCUMBENTS = {
    "BR-10": (
        "bedrock_assessments",
        "check_bedrock_guardrail_iam_enforcement",
        "cache+region",
    ),
    "BR-20": (
        "bedrock_assessments",
        "check_bedrock_knowledge_base_kms_encryption",
        "region",
    ),
    "BR-26": ("bedrock_assessments", "check_bedrock_guardrail_pii_filters", "region"),
    "BR-37": ("bedrock_assessments", "check_bedrock_account_data_retention", "region"),
    "AC-06": ("agentcore_assessments", "check_browser_tool_recording", "noargs"),
    "AG-24": (
        "agentcore_assessments",
        "check_agentcore_gateway_agentic_security",
        "noargs",
    ),
    "SM-01": ("sagemaker_assessments", "check_sagemaker_internet_access", "region"),
    "SM-03": ("sagemaker_assessments", "check_sagemaker_data_protection", "region"),
    "SM-09": (
        "sagemaker_assessments",
        "check_sagemaker_notebook_root_access",
        "region",
    ),
    "SM-18": (
        "sagemaker_assessments",
        "check_sagemaker_transform_job_encryption",
        "region",
    ),
}

# A finding whose details match one of these reached its status without
# exercising the assertion. Matched against the text the check itself wrote.
VACUOUS_MARKERS = (
    "not available in this region",
    "Could not assess",
    "could not be assessed",
    "could not be determined",
    "permission cache",
    "Permission cache",
    "AccessDenied",
    "Unable to",
    "unable to",
)

# Rows whose ONE_ONLY is accepted despite BOTH being reachable. Each entry must
# name the fixture that would close it; an empty reason is rejected, so a waiver
# cannot be added silently.
FIXTURE_WAIVERS: dict[str, str] = {}


# --------------------------------------------------------------------------
# reachability, computed from source
# --------------------------------------------------------------------------


def _verdicts_of_status_arg(value):
    """Which of Passed/Failed a single `status=` argument can produce."""
    out = set()

    def lit(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    if isinstance(value, ast.IfExp):
        # status=PASSED if cond else FAILED -- one site, both verdicts.
        for branch in (value.body, value.orelse):
            name = lit(branch)
            if name and "PASS" in name.upper():
                out.add("Passed")
            elif name and "FAIL" in name.upper():
                out.add("Failed")
        return out
    name = lit(value)
    if name is None:
        # A status this cannot resolve to a literal: a variable, a dict lookup
        # (`kb["status"]`), a call. Read as able to produce either verdict.
        #
        # That is the fail-closed direction, and the direction matters. Reading
        # an unresolved status as carrying NO verdict drops a per-resource emit
        # site, and dropping it can turn a genuine REACHABLE into ELSE_GUARDED,
        # which excuses a ONE_ONLY row instead of demanding the missing fixture.
        # Measured here: BR-20's per-knowledge-base emit is `status=kb["status"]`,
        # it was dropped, and the row was classified from the managed-knowledge-
        # base summary pair instead -- the right answer off the wrong two sites.
        return {"Passed", "Failed"}
    if name:
        upper = name.upper()
        if "PASS" in upper:
            out.add("Passed")
        elif "FAIL" in upper:
            out.add("Failed")
    return out


def _emit_sites(fn):
    """[(lineno, {verdicts}, in_loop)] for every create_finding with a status."""
    loops = [
        (n.body[0].lineno, n.end_lineno or n.body[0].lineno)
        for n in ast.walk(fn)
        if isinstance(n, (ast.For, ast.While, ast.AsyncFor)) and n.body
    ]
    sites = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        fname = getattr(func, "id", None) or getattr(func, "attr", None)
        if fname != "create_finding":
            continue
        for kw in node.keywords:
            if kw.arg != "status":
                continue
            verdicts = _verdicts_of_status_arg(kw.value)
            if not verdicts:
                continue  # N/A-only site: carries no Passed/Failed path
            line = node.lineno
            sites.append(
                (line, verdicts, any(start <= line <= end for start, end in loops))
            )
    return sites


def _passed_is_else_guarded(fn, passed_lines):
    """True when every Passed site sits in the `else` of a Failed-emitting `if`.

    This is the shape `if failures: emit Failed... else: emit one Passed`, where
    a single non-compliant resource suppresses Passed for the whole account.
    """
    if not passed_lines:
        return False
    guarded = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.If) or not node.orelse:
            continue
        body_verdicts, else_lines = set(), set()
        for stmt in node.body:
            for _, v, _ in _emit_sites_in(stmt):
                body_verdicts |= v
        for stmt in node.orelse:
            for line, v, _ in _emit_sites_in(stmt):
                if "Passed" in v:
                    else_lines.add(line)
        if "Failed" in body_verdicts and "Passed" not in body_verdicts:
            guarded |= else_lines
    return set(passed_lines) <= guarded


def _emit_sites_in(stmt):
    wrapper = ast.Module(body=[stmt], type_ignores=[])
    holder = ast.FunctionDef(
        name="_x",
        args=ast.arguments(
            posonlyargs=[],
            args=[],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[],
        ),
        body=wrapper.body,
        decorator_list=[],
        returns=None,
        type_comment=None,
        lineno=getattr(stmt, "lineno", 1),
        col_offset=0,
    )
    return _emit_sites(holder)


def classify_reachability(fn):
    """REACHABLE / ELSE_GUARDED / SINGLETON / NO_VERDICT_PATH, plus why."""
    sites = _emit_sites(fn)
    if not sites:
        return (
            NO_VERDICT_PATH,
            "no create_finding site carries a Passed or Failed status",
        )
    passed_lines = [ln for ln, v, _ in sites if "Passed" in v]
    failed_lines = [ln for ln, v, _ in sites if "Failed" in v]
    if not passed_lines:
        return NO_VERDICT_PATH, f"no Passed path; Failed only, at {failed_lines}"
    if not failed_lines:
        return NO_VERDICT_PATH, f"no Failed path; Passed only, at {passed_lines}"

    if len(sites) == 1 and not sites[0][2]:
        return SINGLETON, (
            f"one emit site at line {sites[0][0]}, outside any loop, so one "
            f"verdict per region exists by construction"
        )

    both_at_one_site = [
        ln for ln, v, in_loop in sites if v == {"Passed", "Failed"} and in_loop
    ]
    if both_at_one_site:
        return REACHABLE, (
            f"line {both_at_one_site[0]} emits per resource with a computed "
            f"status, so both verdicts share one site"
        )

    if _passed_is_else_guarded(fn, passed_lines):
        return ELSE_GUARDED, (
            f"the only Passed site(s) {passed_lines} sit in the else of a "
            f"Failed-emitting if, so one failing resource suppresses Passed"
        )

    return REACHABLE, (
        f"Passed at {passed_lines} is not guarded by the failure branch that "
        f"emits {failed_lines}, so both can fire in one run"
    )


def function_ast(module_dir, fn_name):
    path = os.path.join(SRC, module_dir, "app.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    return next(
        (
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == fn_name
        ),
        None,
    )


# --------------------------------------------------------------------------
# selftest: the classifier must be provable, including in the direction that
# would flatter the gate if it were wrong
# --------------------------------------------------------------------------

SELFTEST_CASES = [
    (
        "per-resource computed status",
        REACHABLE,
        """
        def f(items):
            for i in items:
                findings.append(create_finding(check_id="X", status=StatusEnum.PASSED if i.ok else StatusEnum.FAILED))
        """,
    ),
    (
        "per-resource Failed plus independent summary Passed",
        REACHABLE,
        """
        def f(bad, good):
            for i in bad:
                findings.append(create_finding(check_id="X", status="Failed"))
            if good:
                findings.append(create_finding(check_id="X", status="Passed"))
        """,
    ),
    (
        "per-resource if/else, Passed in the body",
        REACHABLE,
        """
        def f(items):
            for i in items:
                if i.ok:
                    findings.append(create_finding(check_id="X", status=StatusEnum.PASSED))
                else:
                    findings.append(create_finding(check_id="X", status=StatusEnum.FAILED))
        """,
    ),
    (
        "Passed in the else of the failure guard",
        ELSE_GUARDED,
        """
        def f(bad, good):
            if bad:
                for i in bad:
                    findings.append(create_finding(check_id="X", status="Failed"))
            else:
                if good:
                    findings.append(create_finding(check_id="X", status="Passed"))
        """,
    ),
    (
        "one account-level emit with a computed status",
        SINGLETON,
        """
        def f(mode):
            status = "Passed" if mode == "none" else "Failed"
            findings.append(create_finding(check_id="X", status=status))
        """,
    ),
    (
        "no Passed path at all",
        NO_VERDICT_PATH,
        """
        def f(items):
            for i in items:
                findings.append(create_finding(check_id="X", status="Failed"))
        """,
    ),
    (
        "N/A-only emits carry no verdict path",
        NO_VERDICT_PATH,
        """
        def f(items):
            findings.append(create_finding(check_id="X", status=StatusEnum.NA))
        """,
    ),
    # BR-37's exact shape: one account-level computed emit plus an N/A emit on
    # the error path. If N/A sites were counted as verdict sites the site count
    # would be 2, the SINGLETON rule would not fire, and the row would be held
    # to BOTH -- which one account setting can never produce.
    (
        "one account-level emit alongside an N/A error path",
        SINGLETON,
        """
        def f(mode):
            try:
                status = "Passed" if mode == "none" else "Failed"
                findings.append(create_finding(check_id="X", status=status))
            except ClientError:
                findings.append(create_finding(check_id="X", status=StatusEnum.NA))
        """,
    ),
    # Control in the surprising direction. One Passed site is else-guarded and
    # another is not, so the answer is REACHABLE: the independent Passed can
    # fire in the same run as a Failed. A classifier that asks "is ANY Passed
    # else-guarded" instead of "is EVERY Passed else-guarded" answers
    # ELSE_GUARDED here and silently excuses a real missing fixture. This case
    # must not contain a computed-status emit, or the earlier rule returns
    # REACHABLE first and the else-guard logic is never exercised.
    (
        "control: one else-guarded Passed and one independent Passed",
        REACHABLE,
        """
        def f(bad, good, other, other_good):
            for i in bad:
                findings.append(create_finding(check_id="X", status="Failed"))
            if good:
                findings.append(create_finding(check_id="X", status="Passed"))
            if other:
                for i in other:
                    findings.append(create_finding(check_id="X", status="Failed"))
            else:
                if other_good:
                    findings.append(create_finding(check_id="X", status="Passed"))
        """,
    ),
    # BR-20's per-knowledge-base shape. The status is a dict lookup, not a
    # literal and not a ternary, so a classifier that only resolves literals
    # sees no verdict here at all and answers NO_VERDICT_PATH.
    (
        "per-resource emit whose status is a dict lookup",
        REACHABLE,
        """
        def f(items):
            for kb in items:
                findings.append(create_finding(check_id="X", status=kb["status"]))
        """,
    ),
    # The fail-open direction, and the reason the case above is not enough. A
    # dropped dict-lookup site leaves the else-guarded Passed as the only Passed,
    # so the row is classified ELSE_GUARDED and its ONE_ONLY is EXCUSED rather
    # than failed. The per-resource emit can produce a Passed in the same run as
    # the guarded branch's Failed, so the answer is REACHABLE and the row must be
    # held to BOTH.
    (
        "control: a dict-lookup emit alongside an else-guarded Passed",
        REACHABLE,
        """
        def f(items, bad, good):
            for kb in items:
                findings.append(create_finding(check_id="X", status=kb["status"]))
            if bad:
                for i in bad:
                    findings.append(create_finding(check_id="X", status="Failed"))
            else:
                if good:
                    findings.append(create_finding(check_id="X", status="Passed"))
        """,
    ),
]


def run_selftest():
    print("selftest: reachability classifier against synthetic shapes")
    failures = 0
    for name, expected, src in SELFTEST_CASES:
        tree = ast.parse(textwrap.dedent(src))
        fn = tree.body[0]
        got, why = classify_reachability(fn)
        ok = got == expected
        failures += 0 if ok else 1
        print(f"  [{'ok  ' if ok else 'FAIL'}] {name}: expected {expected}, got {got}")
        if not ok:
            print(f"           why: {why}")
    print(f"selftest: {len(SELFTEST_CASES)} cases, {failures} failing")
    if failures:
        print("[FAIL] selftest")
        return 1
    print("[PASS] selftest")
    return 0


# --------------------------------------------------------------------------
# live execution
# --------------------------------------------------------------------------


def load_module(module_dir):
    path = os.path.join(SRC, module_dir, "app.py")
    pkg_dir = os.path.join(SRC, module_dir)
    if pkg_dir not in sys.path:
        sys.path.insert(0, pkg_dir)
    spec = importlib.util.spec_from_file_location(f"gate_{module_dir}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def build_permission_cache():
    """Build the IAM cache the deployed pipeline stages in S3, in memory.

    BR-10 reads only this cache. Passing None sends it down its could-not-assess
    branch, which would be this harness reported as an account fact.
    """
    import boto3

    mod = load_module("iam_permission_caching")
    cache = mod.IAMPermissionCache(boto3.client("iam", config=mod.boto3_config))
    cache.initialize()
    return json.loads(
        json.dumps(
            {
                "role_permissions": cache.role_permissions,
                "user_permissions": cache.user_permissions,
            },
            default=str,
        )
    )


def prime_agentcore_client(mod, region):
    """Set the module global lambda_handler assigns, and prove it answers.

    The check functions read `agentcore_client` as a module global assigned only
    inside lambda_handler. Calling a check directly leaves it None and the check
    reports "AgentCore client not available in this region" against an account
    where AgentCore resources exist.
    """
    import boto3

    client = boto3.client(
        "bedrock-agentcore-control", config=mod.boto3_config, region_name=region
    )
    client.list_agent_runtimes(maxResults=1)
    mod.agentcore_client = client
    return client


def instrument(mod, sink):
    original = mod.create_finding

    def wrapped(*args, **kwargs):
        caller = inspect.stack()[1]
        row = original(*args, **kwargs)
        sink.append(
            {
                "check_id": kwargs.get("check_id") or (args[0] if args else None),
                "status": str(kwargs.get("status", "")),
                "details": str(kwargs.get("finding_details", ""))[:400],
                "emit_line": caller.lineno,
            }
        )
        return row

    mod.create_finding = wrapped
    return original


def norm(status):
    s = status.strip().lower()
    if s in {"n/a", "na", "statusenum.na"} or s.endswith(".na"):
        return "N/A"
    if "pass" in s:
        return "Passed"
    if "fail" in s:
        return "Failed"
    return status


def classify(records):
    if not records:
        return "NONE", "no finding emitted at all"
    statuses = {norm(r["status"]) for r in records}
    real = statuses & {"Passed", "Failed"}
    vacuous = [r for r in records if any(m in r["details"] for m in VACUOUS_MARKERS)]
    if not real:
        if vacuous:
            return (
                "VACUOUS",
                f"only N/A, via a short-circuit: {vacuous[0]['details'][:110]}",
            )
        return "NONE", f"only {sorted(statuses)}; no Passed and no Failed"
    if len(vacuous) == len(records):
        return (
            "VACUOUS",
            f"every finding is a short-circuit: {vacuous[0]['details'][:110]}",
        )
    if real == {"Passed", "Failed"}:
        return "BOTH", "Passed and Failed both reached"
    return "ONE_ONLY", f"{real.pop()} reached; the other verdict never fired"


def shipped_rows():
    """row id -> [source check ids], read from the module the report ships."""
    if REPORT_DIR not in sys.path:
        sys.path.insert(0, REPORT_DIR)
    import aisf_mappings

    marker = getattr(aisf_mappings, "AISF_COVERAGE_CHECK_ID", None)
    return {
        m["check_id"]: list(m["sources"])
        for m in aisf_mappings.AISF_DERIVED_MAP
        if m["check_id"] != marker
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--json-out")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return run_selftest()

    failures = []
    legs = 0

    print("live-verifiability gate for the derived AISF rows")
    print(f"region {args.region}")
    print(f"repo   {REPO_ROOT}")
    print()

    # Leg 1: this gate covers every incumbent the shipped map names.
    try:
        rows_map = shipped_rows()
        legs += 1
        needed = {cid for sources in rows_map.values() for cid in sources}
        uncovered = sorted(needed - set(INCUMBENTS))
        if uncovered:
            failures.append(f"shipped sources with no entry in INCUMBENTS: {uncovered}")
            print(
                f"[FAIL] gate covers every shipped source: {len(rows_map)} rows, "
                f"{len(needed)} sources, {len(uncovered)} uncovered"
            )
        else:
            print(
                f"[PASS] gate covers every shipped source: {len(rows_map)} rows, "
                f"{len(needed)} sources, 0 uncovered"
            )
    except Exception as exc:
        print(f"[FAIL] could not read AISF_DERIVED_MAP: {type(exc).__name__}: {exc}")
        print("[FAIL] gate ran nothing. Refusing to report success.")
        return 1

    # Leg 2: reachability, recomputed from each incumbent's source.
    reach = {}
    missing_fn = []
    for cid in sorted({c for s in rows_map.values() for c in s}):
        module_dir, fn_name, _ = INCUMBENTS[cid]
        fn = function_ast(module_dir, fn_name)
        legs += 1
        if fn is None:
            missing_fn.append(f"{cid}: {fn_name} not found in {module_dir}/app.py")
            continue
        reach[cid] = classify_reachability(fn)
    if missing_fn:
        failures.extend(missing_fn)
    tally_reach = defaultdict(int)
    for verdict, _ in reach.values():
        tally_reach[verdict] += 1
    print(
        f"[{'FAIL' if missing_fn else 'PASS'}] reachability computed from source: "
        f"{len(reach)} of {len(rows_map and {c for s in rows_map.values() for c in s})} "
        f"incumbents read, "
        + ", ".join(f"{k}={v}" for k, v in sorted(tally_reach.items()))
    )
    for cid in sorted(reach):
        verdict, why = reach[cid]
        print(f"         {cid:6s} {verdict:15s} {why}")
    for cid, (verdict, why) in sorted(reach.items()):
        if verdict == NO_VERDICT_PATH:
            failures.append(f"{cid} has no two-sided verdict path in source: {why}")

    # Harness setup. A short-circuit caused by any of these is not an account fact.
    import botocore
    from botocore.session import get_session

    setup = {
        "python": ".".join(str(p) for p in sys.version_info[:3]),
        "botocore": botocore.__version__,
        "bedrock_has_GetAccountDataRetention": "GetAccountDataRetention"
        in get_session().get_service_model("bedrock").operation_names,
        "s3vectors_available": "s3vectors" in get_session().get_available_services(),
    }
    try:
        permission_cache = build_permission_cache()
        setup["permission_cache"] = (
            f"built: {len(permission_cache['role_permissions'])} roles, "
            f"{len(permission_cache['user_permissions'])} users"
        )
    except Exception as exc:
        permission_cache = None
        setup["permission_cache"] = f"FAILED {type(exc).__name__}: {exc}"

    # Run each incumbent once.
    by_check = defaultdict(list)
    errors = {}
    loaded = {}
    for cid in sorted({c for s in rows_map.values() for c in s}):
        module_dir, fn_name, how = INCUMBENTS[cid]
        if module_dir not in loaded:
            try:
                loaded[module_dir] = load_module(module_dir)
            except Exception as exc:
                errors[module_dir] = f"{type(exc).__name__}: {exc}"
                continue
            if module_dir == "agentcore_assessments":
                try:
                    prime_agentcore_client(loaded[module_dir], args.region)
                    setup["agentcore_client"] = "primed, list_agent_runtimes answered"
                except Exception as exc:
                    setup["agentcore_client"] = f"FAILED {type(exc).__name__}: {exc}"
        mod = loaded.get(module_dir)
        if mod is None:
            continue
        sink = []
        original = instrument(mod, sink)
        fn = getattr(mod, fn_name, None)
        if fn is None:
            errors[cid] = f"{fn_name} not found at runtime"
        else:
            try:
                if how == "region":
                    fn(region=args.region)
                elif how == "noargs":
                    fn()
                elif how == "cache+region":
                    fn(permission_cache, region=args.region)
            except Exception as exc:
                errors[cid] = f"{type(exc).__name__}: {exc}"
        mod.create_finding = original
        for rec in sink:
            by_check[rec["check_id"]].append(rec)

    print()
    print(
        "harness setup (a short-circuit caused by any of these is not an account fact)"
    )
    for k, v in setup.items():
        print(f"  {k}: {v}")
        if isinstance(v, str) and v.startswith("FAILED"):
            failures.append(f"harness setup {k}: {v}")

    # Leg 3: classify every shipped row against its incumbents' reachability.
    rows = {}
    for row, sources in rows_map.items():
        recs = [r for cid in sources for r in by_check.get(cid, [])]
        verdict, why = classify(recs)
        verdicts = {reach.get(c, (NO_VERDICT_PATH, ""))[0] for c in sources}
        # A row is only as reachable as its least reachable leg: ELSE_GUARDED or
        # SINGLETON on any source means the row cannot be held to BOTH.
        if ELSE_GUARDED in verdicts:
            row_reach = ELSE_GUARDED
        elif SINGLETON in verdicts:
            row_reach = SINGLETON
        elif NO_VERDICT_PATH in verdicts:
            row_reach = NO_VERDICT_PATH
        else:
            row_reach = REACHABLE
        rows[row] = {
            "sources": sources,
            "verdict": verdict,
            "why": why,
            "reachability": row_reach,
            "findings": len(recs),
            "emit_lines": sorted({r["emit_line"] for r in recs}),
        }
    legs += len(rows)

    print()
    print(f"{'row':9s} {'source(s)':20s} {'reachable':15s} {'verdict':9s} n   why")
    print("-" * 120)
    for row in sorted(rows):
        r = rows[row]
        print(
            f"{row:9s} {','.join(r['sources']):20s} {r['reachability']:15s} "
            f"{r['verdict']:9s} {r['findings']:<3d} {r['why']}"
        )

    tally = defaultdict(int)
    for r in rows.values():
        tally[r["verdict"]] += 1
    print("-" * 120)
    print(
        f"{len(rows)} shipped rows measured: "
        + ", ".join(f"{k}={tally[k]}" for k in ("BOTH", "ONE_ONLY", "NONE", "VACUOUS"))
    )

    for row, r in sorted(rows.items()):
        if r["verdict"] in {"NONE", "VACUOUS"}:
            failures.append(f"{row} measured {r['verdict']}: {r['why']}")
        elif r["verdict"] == "ONE_ONLY" and r["reachability"] == REACHABLE:
            waiver = FIXTURE_WAIVERS.get(row, "").strip()
            if waiver:
                print(f"  waived: {row} ONE_ONLY, {waiver}")
            else:
                failures.append(
                    f"{row} measured ONE_ONLY while BOTH is reachable from source "
                    f"({','.join(r['sources'])}), so a fixture is missing: {r['why']}"
                )

    if errors:
        print()
        print("check errors")
        for k, v in errors.items():
            print(f"  {k}: {v}")
            failures.append(f"{k} raised {v}")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(
                {
                    "region": args.region,
                    "setup": setup,
                    "reachability": {k: list(v) for k, v in reach.items()},
                    "rows": rows,
                    "errors": errors,
                },
                fh,
                indent=2,
                sort_keys=True,
            )
        print(f"\nwrote {args.json_out}")

    print()
    if not rows or legs == 0:
        print(
            f"[FAIL] gate ran nothing: {legs} legs, {len(rows)} rows. Refusing to report success."
        )
        return 1
    if failures:
        print(
            f"[FAIL] live verifiability: {legs} legs run, {len(rows)} rows, {len(failures)} failing"
        )
        for f in failures:
            print(f"         {f}")
        return 1
    print(
        f"[PASS] live verifiability: {legs} legs run, {len(rows)} rows measured, 0 failing"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
