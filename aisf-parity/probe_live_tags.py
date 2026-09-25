#!/usr/bin/env python3
"""Measure the `Compliance_Frameworks` tag against the CSVs a real run produced.

`probe_live.py` is the live leg for phase 1: it asks whether each derived `AISF-`
row reaches both verdicts against a real account. This is the live leg for phase 2,
and it answers a different question that no offline test can.

Every assertion in `tests/test_aisf_compliance_column.py` builds its findings from
check ids it reads out of the map it is testing. That round trip is sound for the
lookup, and blind to whether the key is a check id any producer actually emits. A
key of `BR-4`, or a `AG-24` entry filed under the module that mentions it in a
comment instead of the module that emits it, ships a column that is empty for that
check in production while every offline test stays green.
`test_a_tag_names_a_check_its_own_module_emits` narrows that to a substring test
over `app.py`, which is weaker than it looks: the `AG-` ids are split across three
producers, so the string is present in modules that do not emit it.

A real run settles it. The CSVs a run leaves in the assessment bucket are the
authoritative set of ids each producer emits, so this script:

  1. confirms every map key against the ids its own module really emitted, and
     reports a key another module emitted as MISPLACED, which is the failure the
     substring test cannot see;
  2. replays the real rows through the real `create_finding` and the real
     `generate_csv_report`, asserting the 9-column header, that no row is gained
     or lost, and that every row's tag equals the map's answer for its id;
  3. counts which qualifier forms appear on real rows, so the vocabulary is known
     to be exercised in production and not only in fixtures.

A key the run did not emit is reported UNPROVEN, never as a pass. An account with
no SageMaker notebook emits no `SM-09`, which is a gap in the evidence and not a
defect in the map, and the two are only distinguishable by being counted apart.

Exit codes:
    0  every assertion passed
    1  at least one assertion failed
    2  usage error, or nothing could be measured (never read as a pass)

    # populate a directory from the bucket a run wrote to, then measure it
    AWS_PROFILE=<profile> .venv/bin/python aisf-parity/probe_live_tags.py \\
        --bucket aiml-sec-<account>-aimlassessmentbucket-<suffix>
    .venv/bin/python aisf-parity/probe_live_tags.py --selftest   # no credentials
"""

from __future__ import annotations

import argparse
import collections
import csv
import importlib.util
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

FAIL = 1
USAGE = 2

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES = REPO_ROOT / "aiml-security-assessment" / "functions" / "security"

# The four producers the tag column reaches. owasp_assessments is excluded because
# the ledger names no OW- incumbent, and responsible_ai_grc_assessments populates
# the field from its own COMPLIANCE_MAP; neither is part of this measurement.
PRODUCERS = ("bedrock", "sagemaker", "agentcore", "agent_registry")

LEGACY_COLUMNS = [
    "Check_ID",
    "Finding",
    "Finding_Details",
    "Resolution",
    "Reference",
    "Severity",
    "Status",
    "Region",
]
EXPECTED_COLUMNS = LEGACY_COLUMNS + ["Compliance_Frameworks"]

# <module>_security_report_<execution id>_<region>.csv
REPORT_RE = re.compile(
    r"^(?P<module>[a-z_]+)_security_report_(?P<execution>[0-9a-f-]{36})_"
    r"(?P<region>[a-z0-9-]+)\.csv$"
)

ELEMENT_RE = re.compile(
    r"AISF (AIR-[A-Z]+-[A-Z]+-\d+)(?: \((partial|1 of (\d+) checks)\))?"
)


class Report:
    """Assertion tally. A verdict is printed with the denominator behind it."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    @property
    def total(self) -> int:
        return self.passed + len(self.failed)

    def check(self, name: str, ok: bool, detail: str) -> None:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        print(f"         {detail}")
        if ok:
            self.passed += 1
        else:
            self.failed.append(name)


# --------------------------------------------------------------------------- #
# The measurements, as pure functions so --selftest can exercise them.
# --------------------------------------------------------------------------- #
def classify_map_keys(
    mapping: dict, own_emitted: set, emitted_elsewhere: dict
) -> tuple[list, list, list]:
    """Split a module's map keys by what the real run says about them.

    `emitted_elsewhere` maps a module name to the ids that module emitted. A key
    missing from `own_emitted` but present there is MISPLACED: the lookup runs
    inside the producer that emits the check, so the column is silently empty.
    A key missing from both is UNPROVEN, which is an evidence gap.
    """
    confirmed, unproven, misplaced = [], [], []
    for key in sorted(mapping):
        if key in own_emitted:
            confirmed.append(key)
            continue
        owners = sorted(m for m, ids in emitted_elsewhere.items() if key in ids)
        if owners:
            misplaced.append(f"{key} is emitted by {','.join(owners)}")
        else:
            unproven.append(key)
    return confirmed, unproven, misplaced


def tag_mismatches(mapping: dict, rows: list[dict]) -> list[str]:
    """Every row's tag must equal the map's answer for that row's id.

    Read over rows rather than over the map, so a row the map never mentions is
    covered too: it has to carry an empty tag, not a stale or inherited one.
    """
    wrong = []
    for index, row in enumerate(rows):
        expected = mapping.get(row["Check_ID"], "")
        actual = row.get("Compliance_Frameworks")
        if actual is None:
            wrong.append(f"row {index} ({row['Check_ID']}) has no tag field at all")
        elif actual != expected:
            wrong.append(
                f"row {index} ({row['Check_ID']}) tag {actual!r} != {expected!r}"
            )
    return wrong


def qualifier_census(tags) -> collections.Counter:
    """Count the qualifier forms observed, plus unparseable elements.

    `multi` counts tags naming several controls, which is the pipe-joined form a
    consumer splitting on `|` has to handle.
    """
    census = collections.Counter()
    for tag in tags:
        if not tag:
            continue
        elements = tag.split(" | ")
        if len(elements) > 1:
            census["multi"] += 1
        for element in elements:
            found = ELEMENT_RE.fullmatch(element)
            if not found:
                census["unparseable"] += 1
            elif found.group(2) is None:
                census["bare"] += 1
            elif found.group(2) == "partial":
                census["partial"] += 1
            else:
                census["joint"] += 1
    return census


# --------------------------------------------------------------------------- #
# Loading the real producer code, each with its own schema.
# --------------------------------------------------------------------------- #
def load_module(directory: Path, filename: str, alias: str, extra=None):
    """Import one file under a unique alias, seeding `extra` into sys.modules.

    All six producers name their files `schema.py` and `app.py`, and `app.py` does
    `from schema import create_finding`, resolved by bare name. Seeding `schema`
    is what gives each `app.py` its own, rather than whichever loaded first.
    """
    spec = importlib.util.spec_from_file_location(alias, directory / filename)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(directory))
    saved = {}
    for name, value in (extra or {}).items():
        saved[name] = sys.modules.get(name)
        sys.modules[name] = value
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(directory))
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    return module


def producer(module: str):
    directory = MODULES / f"{module}_assessments"
    schema = load_module(directory, "schema.py", f"live_schema_{module}")
    app = load_module(directory, "app.py", f"live_app_{module}", {"schema": schema})
    mapping = load_module(
        directory, f"aisf_compliance_{module}.py", f"live_map_{module}"
    ).AISF_COMPLIANCE_MAP
    return schema, app, mapping


def replay(module: str, schema, app, source_rows: list[dict]) -> str:
    """Rebuild the real rows through create_finding and re-render the CSV.

    The values come from the real run; the construction path is production's, so
    the tag on each row is the one the deployed code would write for that finding.
    """
    findings = [
        schema.create_finding(
            check_id=row["Check_ID"],
            finding_name=row["Finding"],
            finding_details=row["Finding_Details"],
            resolution=row["Resolution"],
            reference=row["Reference"],
            severity=schema.SeverityEnum(row["Severity"]),
            status=schema.StatusEnum(row["Status"]),
            region=row["Region"],
        )
        for row in source_rows
    ]
    payload = (
        [{"csv_data": findings}] if module in ("bedrock", "sagemaker") else findings
    )
    return app.generate_csv_report(payload)


# --------------------------------------------------------------------------- #
# Fetching a run's CSVs.
# --------------------------------------------------------------------------- #
def newest_execution(bucket: str, region: str | None):
    """Pick one execution's CSV set from the bucket, newest first.

    A partial set is refused rather than measured: validating three producers and
    reporting a pass would be a pass for the fourth as well.
    """
    import boto3

    client = boto3.client("s3")
    objects = []
    token = None
    while True:
        kwargs = {"Bucket": bucket}
        if token:
            kwargs["ContinuationToken"] = token
        page = client.list_objects_v2(**kwargs)
        objects.extend(page.get("Contents") or [])
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")

    runs = collections.defaultdict(dict)
    stamps = {}
    for obj in objects:
        found = REPORT_RE.match(obj["Key"])
        if not found:
            continue
        if region and found.group("region") != region:
            continue
        key = (found.group("execution"), found.group("region"))
        runs[key][found.group("module")] = obj["Key"]
        stamps[key] = max(stamps.get(key, obj["LastModified"]), obj["LastModified"])

    complete = [k for k, v in runs.items() if all(p in v for p in PRODUCERS)]
    if not complete:
        partial = {k: sorted(v) for k, v in runs.items()}
        raise SystemExit(
            f"no execution in s3://{bucket} has a CSV for all of {PRODUCERS}.\n"
            f"found: {partial or 'no report CSVs at all'}\n"
            "Refusing to measure a partial set: it would report a pass for the "
            "producers it never read."
        )
    chosen = max(complete, key=lambda k: stamps[k])
    print(f"bucket    s3://{bucket}")
    print(f"execution {chosen[0]}  region {chosen[1]}  written {stamps[chosen]}")
    print("          the timestamp is printed so a stale run is visible, not assumed")
    out = {}
    for module in PRODUCERS:
        key = runs[chosen][module]
        body = client.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
        out[module] = body
        print(f"          {key}")
    return out


def from_directory(path: Path):
    """Read an already-downloaded set. Provenance is the caller's to vouch for."""
    out = {}
    for module in PRODUCERS:
        candidates = sorted(path.glob(f"{module}*.csv"))
        if not candidates:
            raise SystemExit(
                f"{path} has no CSV matching {module}*.csv; a partial set is not "
                "measured, because a pass would cover the producer it never read."
            )
        out[module] = candidates[0].read_text()
        print(f"          {candidates[0].name}")
    print("          provenance NOT verified: --csv-dir cannot date the run it reads")
    return out


# --------------------------------------------------------------------------- #
def selftest() -> int:
    """Prove each classifier reddens, using no credentials and no real CSVs.

    A classifier that cannot fail is not measuring. Each case below is the
    failure the corresponding live assertion exists to catch.
    """
    cases = []

    confirmed, unproven, misplaced = classify_map_keys(
        {"BR-10": "x", "BR-99": "y", "AG-24": "z"},
        {"BR-10"},
        {"agentcore": {"AG-24"}},
    )
    cases.append(("a key its own module emits is confirmed", confirmed == ["BR-10"]))
    cases.append(
        ("a key nobody emitted is unproven, not passed", unproven == ["BR-99"])
    )
    cases.append(
        (
            "a key another module emits is misplaced",
            len(misplaced) == 1 and "agentcore" in misplaced[0],
        )
    )

    rows_ok = [{"Check_ID": "BR-10", "Compliance_Frameworks": "AISF AIR-BDR-GRD-01"}]
    rows_dropped = [{"Check_ID": "BR-10", "Compliance_Frameworks": ""}]
    rows_stale = [{"Check_ID": "ZZ-99", "Compliance_Frameworks": "AISF AIR-BDR-GRD-01"}]
    rows_nofield = [{"Check_ID": "BR-10"}]
    mapping = {"BR-10": "AISF AIR-BDR-GRD-01"}
    cases.append(("a correct row passes", tag_mismatches(mapping, rows_ok) == []))
    cases.append(
        ("a dropped tag fails", len(tag_mismatches(mapping, rows_dropped)) == 1)
    )
    cases.append(
        ("a tag on an unmapped id fails", len(tag_mismatches(mapping, rows_stale)) == 1)
    )
    cases.append(
        ("a missing tag field fails", len(tag_mismatches(mapping, rows_nofield)) == 1)
    )

    census = qualifier_census(
        [
            "AISF AIR-BDR-GRD-01",
            "AISF AIR-SGM-TRN-05 (1 of 3 checks)",
            "AISF AIR-BDR-MDL-02 (partial)",
            "AISF AIR-BDR-KB-06 (partial) | AISF AIR-BDR-MDL-07 (partial)",
            "AISF BAD FORM",
            "",
        ]
    )
    cases.append(
        (
            "the census separates all four forms and flags a bad one",
            census["bare"] == 1
            and census["joint"] == 1
            and census["partial"] == 3
            and census["multi"] == 1
            and census["unparseable"] == 1,
        )
    )

    if not cases:
        print("SELFTEST FAIL  no cases ran, which is not a pass")
        return USAGE
    failures = [name for name, ok in cases if not ok]
    for name, ok in cases:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"\nselftest: {len(cases)} cases, {len(failures)} failing")
    return FAIL if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", help="assessment bucket a real run wrote to")
    parser.add_argument("--region", help="limit to one scanned region")
    parser.add_argument("--csv-dir", type=Path, help="already-downloaded CSV set")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if bool(args.bucket) == bool(args.csv_dir):
        parser.error("give exactly one of --bucket or --csv-dir")

    print("=== source ===")
    texts = (
        newest_execution(args.bucket, args.region)
        if args.bucket
        else from_directory(args.csv_dir)
    )

    emitted = {}
    source_rows = {}
    for module, text in texts.items():
        rows = list(csv.DictReader(text.splitlines()))
        source_rows[module] = rows
        emitted[module] = {row["Check_ID"] for row in rows}

    report = Report()
    print("\n=== every map key is a check its own module really emits ===")
    totals = collections.Counter()
    for module in PRODUCERS:
        _, _, mapping = producer(module)
        others = {m: ids for m, ids in emitted.items() if m != module}
        confirmed, unproven, misplaced = classify_map_keys(
            mapping, emitted[module], others
        )
        totals["keys"] += len(mapping)
        totals["confirmed"] += len(confirmed)
        totals["unproven"] += len(unproven)
        totals["misplaced"] += len(misplaced)
        report.check(
            f"{module}: no map key belongs to another producer",
            not misplaced,
            f"{len(confirmed)}/{len(mapping)} key(s) confirmed against "
            f"{len(emitted[module])} id(s) this run emitted; "
            f"unproven (not emitted here, NOT a pass): "
            f"{' '.join(unproven) if unproven else 'none'}; "
            f"misplaced: {'; '.join(misplaced) if misplaced else 'none'}",
        )

    print("\n=== the real rows, replayed through the production path ===")
    census = collections.Counter()
    for module in PRODUCERS:
        schema, app, mapping = producer(module)
        text = replay(module, schema, app, source_rows[module])
        header = next(csv.reader(text.splitlines()))
        rows = list(csv.DictReader(text.splitlines()))
        wrong = tag_mismatches(mapping, rows)
        tagged = [row["Compliance_Frameworks"] for row in rows]
        census.update(qualifier_census(tagged))
        totals["rows"] += len(rows)
        totals["tagged"] += sum(1 for tag in tagged if tag)
        report.check(
            f"{module}: 9-column header, no row gained or lost, every tag correct",
            header == EXPECTED_COLUMNS
            and len(rows) == len(source_rows[module])
            and not wrong,
            f"header {len(header)} column(s)"
            + ("" if header == EXPECTED_COLUMNS else f" = {header}")
            + f"; {len(rows)} row(s) out of {len(source_rows[module])} in; "
            f"{sum(1 for t in tagged if t)} tagged; "
            f"{len(wrong)} tag mismatch(es)" + (f": {wrong[:3]}" if wrong else ""),
        )

    print("\n=== qualifier forms observed on real rows ===")
    report.check(
        "every tag on a real row parses, and the forms are exercised live",
        census["unparseable"] == 0 and census["bare"] and census["partial"],
        f"bare={census['bare']} partial={census['partial']} joint={census['joint']} "
        f"multi-control={census['multi']} unparseable={census['unparseable']} "
        f"over {totals['tagged']}/{totals['rows']} tagged row(s)",
    )

    print("\n=== what this cannot see ===")
    print("  - a map key no run has emitted yet: counted as unproven above, and an")
    print("    account without the resource can never confirm it.")
    print("  - whether the DEPLOYED Lambda carries this code. It replays the real")
    print("    rows through the tree's producers, so it proves the mapping against a")
    print("    real id population, not the running artifact.")
    print("  - whether a check's verdict is correct; only the tag beside it.")

    print()
    if totals["keys"] == 0 or totals["rows"] == 0:
        print("PROBE FAIL  nothing was measured, which is not a pass")
        return USAGE
    for name in report.failed:
        print(f"  failing assertion: {name}")
    summary = (
        f"{report.passed}/{report.total} assertions passed; "
        f"{totals['confirmed']}/{totals['keys']} map keys confirmed live, "
        f"{totals['unproven']} unproven, {totals['misplaced']} misplaced; "
        f"{totals['tagged']}/{totals['rows']} real rows tagged"
    )
    if report.failed:
        print(f"PROBE FAIL  {summary}")
        return FAIL
    print(f"PROBE PASS  {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
