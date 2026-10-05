"""The report section's coverage sentence is read by gate 12 against the ledger.

The scope_text published `101 of the 105 are covered` and `the 93 covered
controls without a row` with no gate reading either: both were bumped by hand
when the ledger moved. These tests pin the extractor's three outcomes on
synthetic copies of that sentence, and the shipped sentence against the ledger.

No test asserts a figure's value. The figures move by design, and the ledger is
what the gate compares them to.
"""

import importlib.util
import inspect
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO, "aisf-parity", "check_ledger.py")

_spec = importlib.util.spec_from_file_location("check_ledger", LEDGER)
check_ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_ledger)

LABELS = ("covered", "covered_in_scope", "covered_without_row")


def scope_text():
    entry = next(s for s in check_ledger.COMPLIANCE_STANDARDS if s["slug"] == "aisf")
    return entry["scope_text"]


def summary():
    return check_ledger.load_ledger()["summary"]


def mapped_controls():
    return {m["control"] for m in check_ledger.AISF_DERIVED_MAP}


def drift(text):
    return check_ledger.scope_coverage_drift(text, summary(), mapped_controls())


def bump(text, pattern):
    """The one copy `pattern` matches, with its figure raised by one."""
    raised, count = re.subn(
        pattern,
        lambda m: m.group(0).replace(m.group(1), str(int(m.group(1)) + 1), 1),
        text,
        count=1,
    )
    assert count == 1, f"{pattern} matched {count} copies, not 1"
    return raised


def test_shipped_sentence_is_found_once_per_figure_and_agrees():
    values, found, computed, problems = drift(scope_text())
    assert problems == []
    assert tuple(found) == LABELS
    assert [len(found[label]) for label in LABELS] == [1, 1, 1]
    assert values == computed


def test_each_figure_raised_by_one_is_named_against_the_ledger():
    text = scope_text()
    patterns = {
        "covered": r"(\d+) of the \d+ are covered by checks",
        "covered_in_scope": r"\d+ of the (\d+) are covered by checks",
        "covered_without_row": r"the (\d+) covered controls without a row",
    }
    for label, pattern in patterns.items():
        _, _, computed, problems = drift(bump(text, pattern))
        assert problems == [
            f"the report section's scope_text publishes {label}="
            f"{computed[label] + 1}, the ledger computes {computed[label]}"
        ], label


def test_a_deleted_sentence_reports_every_figure_absent():
    text = scope_text()
    start = text.index("A row is a narrower claim")
    end = text.index("(partial) tag.", start) + len("(partial) tag.")
    _, found, computed, problems = drift(text[:start] + text[end:])
    assert all(found[label] == [] for label in LABELS)
    assert problems == [
        f"the report section's scope_text publishes no {label} figure these "
        f"patterns can find; the ledger computes {computed[label]}"
        for label in LABELS
    ]


def test_a_second_copy_that_disagrees_is_not_masked_by_the_right_one():
    text = scope_text()
    stale = "An older note: 7 of the 105 are covered by checks that already ship. "
    values, found, computed, problems = drift(stale + text)
    assert found["covered"] == ["7", str(computed["covered"])]
    assert values["covered"] is None
    assert problems == [
        "the report section's scope_text publishes 2 copies of covered that "
        f"disagree: {found['covered']}; the ledger computes {computed['covered']}"
    ]


def test_gate_12_reads_the_shipped_scope_text():
    source = inspect.getsource(check_ledger.main)
    call = source.index("scope_coverage_drift(")
    assert '(aisf_entry or {}).get("scope_text", "")' in source[call : call + 200]
    assert "drift += coverage_drift" in source
