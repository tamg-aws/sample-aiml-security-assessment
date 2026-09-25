"""The `Compliance_Frameworks` column that tags producer rows with AISF controls.

Phase 2 of the AISF parity work adds no new verdict. It annotates rows the four
producer modules already emit with the AISF control each check contributes to, so
a reader of `bedrock_security_report_*.csv` can trace a row back to the
framework. The tests here hold three properties that a silent drift would break.

1. **The qualifier cannot be dropped.** An unqualified tag asserts that the check
   alone covers the whole control. Writing one on a check that covers only part
   of it publishes a mapping the assessment never earned, which is the overclaim
   `aisf-parity/check_ledger.py` gate 11 refuses for phase 1's derived rows.
   Phase 2 is allowed to reference a partly-covered control precisely because the
   qualifier says so, so the qualifier is the thing that makes the mechanism
   sound and it is asserted against the ledger rather than against a literal.

2. **The maps must not cross-contaminate.** All six producers name their modules
   `schema.py` and `app.py`, and `app.py` reaches its schema with
   `from schema import create_finding`, resolved through `sys.modules` under that
   bare name. Loading two producers into one interpreter gives the second one the
   first one's schema. That was harmless while the three schema.py files were
   byte-identical; each now imports a different AISF map, so a collision empties
   the tag for every module but the first, with no import error to notice. The
   map modules are named per-producer for that reason and
   `test_two_producers_in_one_interpreter_keep_their_own_maps` is the regression.

3. **The column and the header move together.** Every producer writes its CSV
   with `csv.DictWriter` at the default `extrasaction="raise"`, so a finding that
   grows a key the fieldnames lack raises `ValueError` on the first row. That
   coupling fails closed, which is why it is worth a test: the failure is a
   crashed assessment, not a missing column.
"""

import csv
import glob
import importlib.util
import json
import os
import re
import subprocess
import sys
from io import StringIO

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULES = os.path.join(REPO_ROOT, "aiml-security-assessment", "functions", "security")
LEDGER = os.path.join(REPO_ROOT, "aisf-parity", "aisf-work-ledger.json")
GENERATOR = os.path.join(REPO_ROOT, "aisf-parity", "gen_compliance_maps.py")

# The verdicts whose rows name an incumbent that already ships a verdict. Kept in
# step with TAGGABLE in the generator; test_taggable_verdicts_agree_with_the
# _generator asserts they have not drifted apart.
TAGGABLE = ("covered", "tighten")


def _producers_from_shipped_maps():
    """The producer directories that ship a generated AISF map.

    Hand-listed before, as four directory names, while aisf-parity/
    probe_live_tags.py hand-listed the same four producers in its own spelling
    ("bedrock", not "bedrock_assessments"). A new producer could be left out of
    either list with nothing to notice. Both are derived now, and derived
    separately: the two consumers need different strings, and a shared helper
    normalising one spelling into the other is where the next silent mismatch
    would live.

    Empty raises. `pytest.mark.parametrize` over an empty sequence collects zero
    cases and reports a warning, not a failure, so an empty derivation would turn
    every parametrized test in this module into a no-op that reads as green.
    """
    found = sorted(
        os.path.basename(os.path.dirname(path))
        for path in glob.glob(os.path.join(MODULES, "*", "aisf_compliance_*.py"))
    )
    if not found:
        raise RuntimeError(
            f"no aisf_compliance_*.py under {MODULES}: the derivation found no "
            "producer at all, which would make every test in this module vacuous "
            "instead of red"
        )
    return tuple(found)


PRODUCERS = _producers_from_shipped_maps()

# The 8 columns every producer CSV carried before this change, in order.
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


def _load(module_dir, filename, alias, extra_modules=None):
    """Load one file from one producer directory under a unique module name.

    `extra_modules` is seeded into sys.modules for the duration of the load and
    removed afterwards, which is how `app.py` is given its *own* `schema` rather
    than whichever producer was imported first.
    """
    directory = os.path.join(MODULES, module_dir)
    path = os.path.join(directory, filename)
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, directory)
    saved = {}
    for name, value in (extra_modules or {}).items():
        saved[name] = sys.modules.get(name)
        sys.modules[name] = value
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(directory)
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    return module


def _schema(module_dir):
    return _load(module_dir, "schema.py", f"aisf_col_schema_{module_dir}")


def _app(module_dir, schema_module):
    return _load(
        module_dir,
        "app.py",
        f"aisf_col_app_{module_dir}",
        extra_modules={"schema": schema_module},
    )


@pytest.fixture(scope="module")
def schemas():
    return {d: _schema(d) for d in PRODUCERS}


@pytest.fixture(scope="module")
def ledger():
    with open(LEDGER) as handle:
        return json.load(handle)["rows"]


def _finding(schema_module, check_id, **kwargs):
    return schema_module.create_finding(
        check_id=check_id,
        finding_name="Name",
        finding_details="Details",
        resolution="Resolve",
        reference="https://docs.aws.amazon.com/test",
        severity=schema_module.SeverityEnum.MEDIUM,
        status=schema_module.StatusEnum.PASSED,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# The tag reaches the finding
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_every_mapped_check_id_gets_exactly_its_tag(schemas, module_dir):
    schema_module = schemas[module_dir]
    mapping = sys.modules[
        f"aisf_compliance_{module_dir.removesuffix('_assessments')}"
    ].AISF_COMPLIANCE_MAP
    assert mapping, f"{module_dir} has an empty map"
    for check_id, tag in mapping.items():
        finding = _finding(schema_module, check_id)
        assert finding["Compliance_Frameworks"] == tag, check_id


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_an_unmapped_check_id_gets_no_tag(schemas, module_dir):
    # ZZ-99 is a well-formed id that no producer emits, so the lookup must miss.
    assert _finding(schemas[module_dir], "ZZ-99")["Compliance_Frameworks"] == ""


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_a_caller_can_suppress_the_tag_with_an_empty_string(schemas, module_dir):
    """None means "look it up", "" means "deliberately untagged".

    They have to stay distinguishable: defaulting the parameter to "" instead of
    None would make an explicit suppression indistinguishable from the default
    and silently re-tag the row.
    """
    schema_module = schemas[module_dir]
    mapping = sys.modules[
        f"aisf_compliance_{module_dir.removesuffix('_assessments')}"
    ].AISF_COMPLIANCE_MAP
    check_id = sorted(mapping)[0]
    assert (
        _finding(schema_module, check_id)["Compliance_Frameworks"] == mapping[check_id]
    )
    assert (
        _finding(schema_module, check_id, compliance_frameworks="")[
            "Compliance_Frameworks"
        ]
        == ""
    )
    assert (
        _finding(schema_module, check_id, compliance_frameworks="AISF OTHER")[
            "Compliance_Frameworks"
        ]
        == "AISF OTHER"
    )


def test_two_producers_in_one_interpreter_keep_their_own_maps(schemas):
    """The regression for the shared-module-name collision.

    Before the map modules were named per producer, both of these resolved to
    whichever directory reached sys.path last, and the other one returned "".
    """
    bedrock = schemas["bedrock_assessments"]
    sagemaker = schemas["sagemaker_assessments"]
    assert _finding(bedrock, "BR-10")["Compliance_Frameworks"] == "AISF AIR-BDR-GRD-01"
    assert _finding(sagemaker, "SM-18")["Compliance_Frameworks"] == "AISF AIR-SGM-EP-08"
    # And neither answers for the other's ids.
    assert _finding(bedrock, "SM-18")["Compliance_Frameworks"] == ""
    assert _finding(sagemaker, "BR-10")["Compliance_Frameworks"] == ""


# ---------------------------------------------------------------------------
# The tag reaches the CSV
# ---------------------------------------------------------------------------
def _csv_rows(module_dir, schema_module, findings):
    app = _app(module_dir, schema_module)
    if module_dir in ("bedrock_assessments", "sagemaker_assessments"):
        payload = [{"csv_data": findings}]
    else:
        payload = findings
    return app.generate_csv_report(payload)


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_csv_header_is_the_nine_column_contract(schemas, module_dir):
    schema_module = schemas[module_dir]
    mapping = sys.modules[
        f"aisf_compliance_{module_dir.removesuffix('_assessments')}"
    ].AISF_COMPLIANCE_MAP
    text = _csv_rows(
        module_dir, schema_module, [_finding(schema_module, sorted(mapping)[0])]
    )
    header = next(csv.reader(StringIO(text)))
    assert header == EXPECTED_COLUMNS


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_the_tag_survives_the_csv_round_trip(schemas, module_dir):
    schema_module = schemas[module_dir]
    mapping = sys.modules[
        f"aisf_compliance_{module_dir.removesuffix('_assessments')}"
    ].AISF_COMPLIANCE_MAP
    check_id = sorted(mapping)[0]
    text = _csv_rows(module_dir, schema_module, [_finding(schema_module, check_id)])
    row = next(csv.DictReader(StringIO(text)))
    assert row["Compliance_Frameworks"] == mapping[check_id]


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_writing_a_finding_does_not_raise_on_an_unknown_column(schemas, module_dir):
    """DictWriter defaults to extrasaction="raise".

    So the schema field and the fieldnames list have to move together. This is
    the assertion that catches one landing without the other.
    """
    schema_module = schemas[module_dir]
    text = _csv_rows(module_dir, schema_module, [_finding(schema_module, "ZZ-99")])
    assert "Compliance_Frameworks" in text.splitlines()[0]


def test_agentcore_empty_and_populated_reports_have_the_same_header(schemas):
    """agentcore builds its header twice, once for the no-findings case.

    Updating one list and not the other gives an empty report 8 columns and a
    populated one 9, which a consumer joining the two sees as a missing column
    rather than as a bug.
    """
    schema_module = schemas["agentcore_assessments"]
    app = _app("agentcore_assessments", schema_module)
    empty_header = next(csv.reader(StringIO(app.generate_csv_report([]))))
    populated_header = next(
        csv.reader(
            StringIO(app.generate_csv_report([_finding(schema_module, "AC-06")]))
        )
    )
    assert empty_header == populated_header == EXPECTED_COLUMNS


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_the_new_column_is_appended_not_inserted(schemas, module_dir):
    """The 8 legacy columns keep their order and position.

    consolidate_html_reports.py and the report Lambda both read these CSVs with
    DictReader, so a reordering would not break them, but an archived report
    diffed against a fresh one would show every column as changed.
    """
    schema_module = schemas[module_dir]
    text = _csv_rows(module_dir, schema_module, [_finding(schema_module, "ZZ-99")])
    header = next(csv.reader(StringIO(text)))
    assert header[:8] == LEGACY_COLUMNS
    assert header[8] == "Compliance_Frameworks"


# ---------------------------------------------------------------------------
# The maps agree with the ledger, in both directions
# ---------------------------------------------------------------------------
def _all_maps():
    out = {}
    for module_dir in PRODUCERS:
        suffix = module_dir.removesuffix("_assessments")
        path = os.path.join(MODULES, module_dir, f"aisf_compliance_{suffix}.py")
        out[module_dir] = _load(
            module_dir, f"aisf_compliance_{suffix}.py", f"aisf_col_map_{suffix}"
        ).AISF_COMPLIANCE_MAP
        assert os.path.exists(path)
    return out


def test_the_producer_set_is_derived_and_not_empty():
    """The derived producer set, measured against a second reading of it.

    PRODUCERS is derived from which directories hold an `aisf_compliance_*.py`.
    This reads which `schema.py` imports one, which is a different file and a
    different mechanism, so a module that ships a map nothing imports, or imports
    a map it does not ship, appears in one reading and not the other. It also
    catches PRODUCERS being turned back into a hand-written literal, which is how
    this list and aisf-parity/probe_live_tags.py's drifted apart in the first
    place. Both counts are in the message, because a comparison of two empty sets
    holds.
    """
    wired = []
    for path in sorted(glob.glob(os.path.join(MODULES, "*", "schema.py"))):
        with open(path) as handle:
            source = handle.read()
        if re.search(
            r"^\s*from aisf_compliance_\w+ import aisf_frameworks", source, re.M
        ):
            wired.append(os.path.basename(os.path.dirname(path)))
    assert PRODUCERS, "the derived producer set is empty; every test here is vacuous"
    assert set(PRODUCERS) == set(wired), (
        f"{len(PRODUCERS)} producer(s) ship a map {sorted(PRODUCERS)}; "
        f"{len(wired)} wire one into schema.py {wired}"
    )


def test_taggable_verdicts_agree_with_the_generator():
    with open(GENERATOR) as handle:
        source = handle.read()
    found = re.search(r"^TAGGABLE = \(([^)]*)\)", source, re.M)
    assert found, "TAGGABLE is not where this test looks for it"
    assert tuple(re.findall(r'"([a-z_]+)"', found.group(1))) == TAGGABLE


def test_every_taggable_incumbent_appears_in_exactly_one_map(ledger):
    """Backward: nothing the ledger says is taggable is missing from a map.

    A forward-only scan over the maps cannot find a control that was never
    written into one, which is the direction a new ledger row drifts.
    """
    maps = _all_maps()
    expected = set()
    for row in ledger:
        if row.get("verdict") in TAGGABLE:
            expected.update(row.get("incumbents") or [])
    placements = {}
    for module_dir, mapping in maps.items():
        for check_id in mapping:
            placements.setdefault(check_id, []).append(module_dir)
    assert set(placements) == expected
    duplicated = {k: v for k, v in placements.items() if len(v) != 1}
    assert not duplicated, f"a check id is mapped by more than one module: {duplicated}"


def test_no_map_tags_a_control_the_ledger_does_not_call_taggable(ledger):
    """Forward: every control named in a map comes from a covered/tighten row.

    A `new` row has no incumbent to tag, and the 11 `unassessed` FND rows have
    not had their dedup pass, so their listed incumbents are candidates. Tagging
    either publishes a mapping the ledger has not settled.
    """
    verdicts = {row["control"]: row.get("verdict") for row in ledger}
    offenders = []
    for module_dir, mapping in _all_maps().items():
        for check_id, tag in mapping.items():
            for control in re.findall(r"AISF (AIR-[A-Z]+-[A-Z]+-\d+)", tag):
                if verdicts.get(control) not in TAGGABLE:
                    offenders.append(
                        f"{module_dir}:{check_id}:{control}={verdicts.get(control)}"
                    )
    assert not offenders, offenders


def test_a_partly_covered_control_is_never_tagged_unqualified(ledger):
    """The overclaim rule, asserted against the ledger verdict.

    `covered` with one incumbent is the only case that earns a bare tag. A
    `tighten` row must carry `(partial)`, and a `covered` row with several
    incumbents must carry `(1 of N checks)`, because no single leg of it asserts
    the whole control.
    """
    rows = {row["control"]: row for row in ledger}
    wrong = []
    for module_dir, mapping in _all_maps().items():
        for check_id, tag in mapping.items():
            for element in tag.split(" | "):
                found = re.fullmatch(
                    r"AISF (AIR-[A-Z]+-[A-Z]+-\d+)(?: \((partial|1 of (\d+) checks)\))?",
                    element,
                )
                assert found, f"{module_dir}:{check_id} tag element {element!r}"
                control, qualifier, denominator = found.groups()
                row = rows[control]
                legs = len(row.get("incumbents") or [])
                if row["verdict"] == "tighten":
                    expected = "partial"
                elif legs == 1:
                    expected = None
                else:
                    expected = f"1 of {legs} checks"
                if qualifier != expected:
                    wrong.append(
                        f"{module_dir}:{check_id}:{control} verdict={row['verdict']} "
                        f"legs={legs} qualifier={qualifier!r} expected={expected!r}"
                    )
                if denominator is not None:
                    assert int(denominator) == legs, f"{check_id}:{control}"
    assert not wrong, wrong


def test_a_tag_names_a_check_its_own_module_emits(ledger):
    """A map may only name check ids its own producer actually emits.

    Placing a check in the wrong module's map means create_finding never looks it
    up, because the lookup happens inside the producer that emits it, so the
    column silently stays empty for that check.
    """
    misplaced = []
    for module_dir, mapping in _all_maps().items():
        with open(os.path.join(MODULES, module_dir, "app.py")) as handle:
            source = handle.read()
        for check_id in mapping:
            if check_id not in source:
                misplaced.append(f"{check_id} not emitted by {module_dir}")
    assert not misplaced, misplaced


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_no_producer_builds_a_finding_outside_create_finding(module_dir):
    """The lookup lives in create_finding, so a row that skips it ships no tag.

    And it ships one silently: `csv.DictWriter` raises on a key the fieldnames
    lack, never on a key a row is missing, so a finding assembled as a literal
    dict writes an empty `Compliance_Frameworks` cell and every other test here
    still passes. This is the backward detector for that: no assertion over the
    maps can find a row that was never routed through the lookup.

    The count is not pinned, because it moves with every new check. The property
    is that it is the only construction path.
    """
    with open(os.path.join(MODULES, module_dir, "app.py")) as handle:
        source = handle.read()
    calls = len(re.findall(r"\bcreate_finding\(", source))
    assert calls > 0, f"{module_dir} builds no findings at all"
    literals = re.findall(r'["\']Check_ID["\']\s*:', source)
    assert not literals, (
        f"{module_dir} assembles {len(literals)} finding dict(s) directly beside "
        f"{calls} create_finding call(s); a direct dict skips the AISF tag lookup"
    )


def test_the_generated_maps_match_a_fresh_render():
    """The maps are generated, so a hand-edit has to fail somewhere."""
    completed = subprocess.run(
        [sys.executable, GENERATOR, "--check"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "maps match the ledger" in completed.stdout
