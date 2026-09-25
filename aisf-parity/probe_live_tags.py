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
  2. reads the `Compliance_Frameworks` value the run itself wrote on every row and
     requires it to equal this tree's map, which is the only assertion here that
     can see a deployed artifact built from source older than this tree;
  3. replays the real rows through the real `create_finding` and the real
     `generate_csv_report`, asserting the 9-column header, that no row is gained
     or lost, and that every row's tag equals the map's answer for its id;
  4. counts which qualifier forms appear on real rows, so the vocabulary is known
     to be exercised in production and not only in fixtures.

(2) and (3) differ in what they can catch. The replay rebuilds each row through
this tree's producers, so it compares the map against itself and would pass
whatever the deployed Lambda wrote; it covers the rendering path instead. Only (2)
reads the shipped bytes. A CSV predating the column fails (2) rather than skipping
it, because a pass on that ground leaves the deployed hop unmeasured.

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


# Every refusal goes through here, because `raise SystemExit("<message>")` prints the
# message and exits **1** -- the code this file's docstring reserves for "at least one
# assertion failed". All three refusals below are nothing-could-be-measured
# conditions, so each one spent that whole distinction on a wrapper that would read
# them as a triageable failure. Spelled as mutate.py and push_safety.py already spell
# it, so the three scripts refuse the same way.
def die(msg: str, code: int = USAGE) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES = REPO_ROOT / "aiml-security-assessment" / "functions" / "security"


def producers_from_shipped_maps() -> tuple[str, ...]:
    """The producer names that ship a generated AISF map, in this file's spelling.

    The set used to be hand-listed as ("bedrock", "sagemaker", "agentcore",
    "agent_registry"), and the offline suite hand-listed the same four producers
    as directory names, so a new producer could be left out of either list with
    nothing to notice. Derived here from the map filenames, which carry exactly
    this spelling: `aisf_compliance_<name>.py` beside `<name>_assessments/app.py`.

    Derived again, separately, in tests/test_aisf_compliance_column.py. The two
    consumers genuinely need different strings, and one shared helper normalising
    one spelling into the other is where the next silent mismatch would live.

    owasp_assessments and responsible_ai_grc_assessments fall out of the
    derivation rather than being excluded by name: the ledger names no OW-
    incumbent, and the GRC module fills the column from its own COMPLIANCE_MAP.
    Neither ships an aisf_compliance_*.py, so neither is part of this
    measurement, and a module that starts shipping one joins it without an edit.

    Empty is fatal, and fatal here at derivation time rather than after the
    aggregation in newest_execution(): `all([])` is True, so an empty tuple marks
    every execution in the bucket complete and the `if not complete` guard below
    never fires.
    """
    found = sorted(
        path.name.removeprefix("aisf_compliance_").removesuffix(".py")
        for path in MODULES.glob("*/aisf_compliance_*.py")
    )
    if not found:
        die(
            f"no aisf_compliance_*.py under {MODULES}: there is no producer to "
            "measure. Not an empty measurement: an empty producer set marks every "
            "run in the bucket complete, because all([]) is True."
        )
    return tuple(found)


PRODUCERS = producers_from_shipped_maps()

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

# [<prefix>/]<module>_security_report_<execution>[_<region>].csv
#
# Three groups are looser than the shapes these keys were first read as, and each
# one was measured missing a key a real bucket held.
#
# The prefix is optional because two stacks write the same CSVs under two layouts:
# one at the bucket root, one under an account id. `^` alone put `[a-z_]+` against
# that account id, so every prefixed key missed the pattern and the probe refused
# with "no report CSVs at all" -- closed, but on a cause that was not true.
#
# The execution is any run of non-slash characters and not 36 hex-and-hyphen ones.
# StartExecution takes `--name`, so an execution id is a uuid only when nobody
# passed one: a run named `grc-owasp-payload-probe-20260925-173028` wrote six
# report CSVs that all missed the pattern, and the probe printed the same untrue
# "no report CSVs at all".
#
# The region is optional because one shipped key has no region segment,
# `responsible_ai_grc_security_report_<execution>.csv`, and bedrock's and
# agentcore's fallback branches write that shape too when `Region` arrives
# explicitly empty. The reader widens; the shipped key shape is not changed to suit
# the reader.
#
# What keeps the two loose groups from eating each other is the region's shape.
# `xx-word-N` and not `[a-z0-9-]+`, and the case that needs it is a key with no
# region: `bedrock_security_report_probe_20260925.csv` gives `_20260925` to a loose
# optional region group, and the run is then reported under a region that does not
# exist. The same execution name WITH a region parses correctly under either shape,
# because a loose region still has to be followed by `.csv`, so only the region-less
# form discriminates. `execution` is non-greedy and the region optional, so the split
# lands on the last region-shaped tail, and a key without one parses with region None
# instead of not parsing at all.
#
# The execution cannot start with `_`, which is how an empty execution id stays
# rejected once the region is optional. A handler given `execution_id=""` writes
# `bedrock_security_report__us-east-1.csv`; with the region required that key simply
# could not parse, but optional it reads as a region-less run named `_us-east-1`, so
# the leading character is constrained instead. The cost is stated rather than
# hidden: an execution someone names `_nightly` is then unreadable and the probe
# refuses on it. That refusal prints the unmatched keys it saw, which is the half the
# uuid defect did not have.
#
# Everything else stays exact. A key that is not a report CSV still misses on
# `_security_report_`, on the prefix having to end in `/`, or on `\.csv$`. The
# prefix and the region are captured rather than skipped because newest_execution()
# groups on both.
REPORT_RE = re.compile(
    r"^(?P<prefix>(?:.*/)?)(?P<module>[a-z_]+)_security_report_"
    r"(?P<execution>[^/_][^/]*?)(?:_(?P<region>[a-z]{2}(?:-[a-z]+)+-\d+))?\.csv$"
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


def written_tag_audit(mapping: dict, rows: list[dict], header: list[str]):
    """Audit the column the run itself wrote, not a replay of it.

    The replay assertion below rebuilds each row through this tree's producers, so
    it compares the map against itself and passes whatever the deployed Lambda
    actually wrote. This reads the shipped bytes instead, which is the only
    assertion here that can see a deployed artifact built from stale source.

    A missing column is a failure and not a skip. A run without it evidences
    nothing about phase 2, and a pass on that ground is how the one hop the offline
    suite cannot reach would go unmeasured.
    """
    if "Compliance_Frameworks" not in header:
        return False, (
            f"the source CSV has no Compliance_Frameworks column ({len(header)} "
            f"column(s): {header}). Either the run predates phase 2 or the deployed "
            "code does not carry it. Not a skip: nothing here evidences the column."
        )
    wrong = tag_mismatches(mapping, rows)
    tagged = sum(1 for row in rows if row.get("Compliance_Frameworks"))
    return not wrong, (
        f"{len(rows)} row(s) as the run wrote them, {tagged} tagged, "
        f"{len(wrong)} disagreeing with this tree's map"
        + (f": {wrong[:3]}" if wrong else "")
    )


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

    A run is identified by key prefix as well as execution id and region, so a set
    whose four CSVs live under two prefixes is partial for each prefix and refused.

    A key with no region segment forms its own group and does not join the
    region-bearing groups of the same prefix and execution. The bucket can hold only
    one such key per (prefix, execution) -- there is no region in the name to write a
    second one under -- so attaching it to a region group would assert a scanned
    region the key does not state, and for one run name executed in two regions it
    would attach the single CSV to both. That costs nothing today: the region-less
    key the estate holds is the GRC report, and GRC ships no aisf_compliance_*.py, so
    it is not in PRODUCERS. bedrock and agentcore do have a region-less fallback
    branch, so the refusal below names any producer found only under such a key. The
    incomplete set is then reported with its cause instead of reading as an estate
    that never ran.

    --region filters the keys that carry a region and leaves the rest, because
    excluding a key with no region segment would be asserting a region for it. The
    count of keys the filter removed is printed with the refusal.
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
    filtered_out = 0
    for obj in objects:
        found = REPORT_RE.match(obj["Key"])
        if not found:
            continue
        if region and found.group("region") not in (None, region):
            filtered_out += 1
            continue
        # The prefix is part of a run's identity, not decoration. Once any prefix
        # matches, one bucket can hold reports for more than one account -- in the
        # prefixed layout the prefix IS an account id -- and `runs[key][module]` is
        # last-write-wins, so pooling would let one CSV from each of two accounts
        # assemble a "complete" set that no account ever completed, then measure it
        # and print one figure with nothing in the output to say whose rows it
        # covers. Grouped, an incomplete prefix stays incomplete and the refusal
        # below fires instead.
        # An execution id can also be a constant, which this grouping cannot see.
        # Two of the four producers default it to the literal "unknown" when the
        # event carries no Execution block -- agentcore's handler, and
        # agent_registry's `_execution_name` on both of its branches -- while
        # bedrock and sagemaker index `event["Execution"]["Name"]` and raise
        # instead. So `(prefix, "unknown", region)` is a reachable key, and two
        # runs that both lose the block write the same object name: the loss is a
        # PutObject overwrite upstream of this listing, so only one object ever
        # reaches the loop and no count here can report the other. Both defaulting
        # modules are in PRODUCERS, so the surviving object is inside the set
        # `complete` is measured against.
        key = (found.group("prefix"), found.group("execution"), found.group("region"))
        runs[key][found.group("module")] = obj["Key"]
        stamps[key] = max(stamps.get(key, obj["LastModified"]), obj["LastModified"])

    complete = [k for k, v in runs.items() if all(p in v for p in PRODUCERS)]
    if not complete:
        partial = {k: sorted(v) for k, v in runs.items()}
        # An empty bucket and a listing whose keys no longer match the pattern used
        # to print the same sentence, which is how the anchor bug above read as an
        # empty estate. The object count and a sample key separate the two.
        detail = f"listed {len(objects)} object(s)"
        if filtered_out:
            detail += f"; --region {region} excluded {filtered_out} matching key(s)"
        # A producer whose only key carries no region segment is a grouping outcome
        # and not a missing report, and the two have different repairs. Named here,
        # because the set it would have completed is the one reported partial.
        with_region = {m for k, v in runs.items() if k[2] is not None for m in v}
        regionless_only = sorted(
            set(PRODUCERS)
            & ({m for k, v in runs.items() if k[2] is None for m in v} - with_region)
        )
        if regionless_only:
            detail += (
                f"; {regionless_only} appear only under a key with no region "
                "segment, which groups apart from the region-bearing keys of the "
                "same run"
            )
        if not partial:
            detail += f"; first: {[obj['Key'] for obj in objects[:3]]}"
        die(
            f"no execution in s3://{bucket} has a CSV for all of {PRODUCERS}.\n"
            f"found: {partial or 'no key matched a report CSV name'}\n"
            f"{detail}\n"
            "Refusing to measure a partial set: it would report a pass for the "
            "producers it never read. A set spread across two key prefixes is "
            "partial for each of them: one prefix has to carry all of it."
        )
    chosen = max(complete, key=lambda k: stamps[k])
    prefix, execution, scanned = chosen
    print(f"bucket    s3://{bucket}")
    print(f"prefix    {prefix or '(bucket root)'}  one prefix carries the whole set")
    print(
        f"execution {execution}  region "
        f"{scanned if scanned is not None else '(none in the key)'}  "
        f"written {stamps[chosen]}"
    )
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
            die(
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

    # The as-written audit, whose whole point is the case the replay cannot reach:
    # a deployed artifact built from source older than this tree.
    full_header = list(EXPECTED_COLUMNS)
    ok_written, detail_written = written_tag_audit(mapping, rows_ok, full_header)
    cases.append(("an as-written column matching the map passes", ok_written))
    cases.append(
        (
            "an as-written value the map disagrees with fails",
            not written_tag_audit(mapping, rows_dropped, full_header)[0],
        )
    )
    cases.append(
        (
            "a pre-phase-2 CSV fails instead of skipping",
            not written_tag_audit(mapping, rows_ok, LEGACY_COLUMNS)[0]
            and "predates" in written_tag_audit(mapping, rows_ok, LEGACY_COLUMNS)[1],
        )
    )
    cases.append(
        ("the passing audit still prints its denominator", "1 row(s)" in detail_written)
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

    # The denominator behind every section below, printed before any of them and on
    # the --selftest path too: a producer this derivation misses is a producer
    # nothing here measures, and the sections would report a clean run without it.
    print(
        f"producers {len(PRODUCERS)} derived from */aisf_compliance_*.py under "
        f"{MODULES.relative_to(REPO_ROOT)}: {', '.join(PRODUCERS)}"
    )

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
    source_header = {}
    for module, text in texts.items():
        lines = text.splitlines()
        source_header[module] = next(csv.reader(lines), [])
        rows = list(csv.DictReader(lines))
        source_rows[module] = rows
        emitted[module] = {row["Check_ID"] for row in rows}

    # Loaded once. Each producer seeds its own `schema` into sys.modules, so
    # re-importing per section would give a later section whichever schema the
    # previous import left behind.
    loaded = {module: producer(module) for module in PRODUCERS}

    report = Report()
    print("\n=== every map key is a check its own module really emits ===")
    totals = collections.Counter()
    for module in PRODUCERS:
        _, _, mapping = loaded[module]
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

    print("\n=== the tag column the deployed run actually wrote ===")
    for module in PRODUCERS:
        _, _, mapping = loaded[module]
        ok, detail = written_tag_audit(
            mapping, source_rows[module], source_header[module]
        )
        totals["written_rows"] += len(source_rows[module])
        totals["written_tagged"] += sum(
            1 for row in source_rows[module] if row.get("Compliance_Frameworks")
        )
        if not ok:
            totals["written_bad"] += 1
        report.check(
            f"{module}: the shipped column agrees with this tree's map", ok, detail
        )

    print("\n=== the real rows, replayed through the production path ===")
    census = collections.Counter()
    for module in PRODUCERS:
        schema, app, mapping = loaded[module]
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
    print("  - WHEN the run happened. The as-written section proves the artifact that")
    print("    wrote these CSVs agrees with this tree; it cannot date them. --bucket")
    print("    prints the run's timestamp for that reason, and --csv-dir cannot.")
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
        f"{totals['written_tagged']}/{totals['written_rows']} rows tagged as the run "
        f"wrote them, {totals['written_bad']} producer(s) disagreeing; "
        f"{totals['tagged']}/{totals['rows']} replayed rows tagged"
    )
    if report.failed:
        print(f"PROBE FAIL  {summary}")
        return FAIL
    print(f"PROBE PASS  {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
