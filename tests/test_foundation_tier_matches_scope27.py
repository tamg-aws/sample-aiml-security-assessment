"""SCOPE27 is the foundation tier, and every machine-checkable control has a row.

Gate 22 runs inside check_ledger.main(), which reads a sibling AISF clone that CI
does not check out. foundation_tier_problems() takes its populations as arguments,
so this file runs it: over the real verdict tables, and over synthetic inputs that
must fail. The negative controls matter more than the pass. A comparison of
SCOPE27 against a set derived from SCOPE27 passes whatever either holds.
"""

import importlib.util
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO, "aisf-parity", "check_ledger.py")

_spec = importlib.util.spec_from_file_location("check_ledger", LEDGER)
check_ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_ledger)

build_ledger = importlib.import_module("build_ledger")

SCOPE27 = build_ledger.SCOPE27
TIERS = build_ledger.TIERS
FOUNDATION = build_ledger.FOUNDATION
AI_SUBJECT = build_ledger.AI_SUBJECT


def ledger_rows(tiers):
    """The json rows' two fields the gate reads, rendered from a tier map."""
    return [{"control": c, "tier": t} for c, t in tiers.items()]


def test_the_verdict_tables_partition_rows_into_the_two_tiers():
    ai_subject = [r[0] for r in build_ledger.AI_SUBJECT_ROWS]
    foundation = [r[0] for r in build_ledger.FOUNDATION_ROWS]
    assert not set(ai_subject) & set(foundation)
    assert len(ai_subject) + len(foundation) == len(build_ledger.ROWS) == 105
    assert len(foundation) == len(SCOPE27) == 27
    assert set(TIERS) == {r[0] for r in build_ledger.ROWS}
    assert {build_ledger.table_fields(r)["tier"] for r in build_ledger.ROWS} == {
        AI_SUBJECT,
        FOUNDATION,
    }


def test_the_real_tables_satisfy_the_gate():
    # machine_checkable stands in for the AISF classification with every row,
    # which is the claim the third leg makes about the real one.
    problems = check_ledger.foundation_tier_problems(
        SCOPE27, ledger_rows(TIERS), TIERS, set(TIERS)
    )
    assert problems == []


def test_a_foundation_row_dropped_from_the_table_reds_every_leg():
    dropped = "AIR-SLF-RT-08"
    assert dropped in SCOPE27
    tiers = {c: t for c, t in TIERS.items() if c != dropped}
    problems = check_ledger.foundation_tier_problems(
        SCOPE27, ledger_rows(tiers), tiers, set(TIERS)
    )
    assert len(problems) == 2, problems
    assert all(dropped in p for p in problems)
    # The completeness leg: the classification still lists the control, so a
    # machine-checkable control with no row is a red and not a smaller total.
    problems = check_ledger.foundation_tier_problems(
        SCOPE27 - {dropped}, ledger_rows(tiers), tiers, set(TIERS)
    )
    assert problems == [
        f"['{dropped}'] are in machine-checkable controls with no ai_subject row "
        "and not in SCOPE27"
    ]


def test_a_control_dropped_from_scope27_alone_reds():
    problems = check_ledger.foundation_tier_problems(
        SCOPE27 - {"AIR-PHY-EDG-01"}, ledger_rows(TIERS), TIERS, set(TIERS)
    )
    assert len(problems) == 3, problems
    assert all("AIR-PHY-EDG-01" in p and "not in SCOPE27" in p for p in problems)


def test_a_foundation_row_filed_as_ai_subject_reds():
    moved = "AIR-FND-DAT-10"
    tiers = {**TIERS, moved: AI_SUBJECT}
    problems = check_ledger.foundation_tier_problems(
        SCOPE27, ledger_rows(tiers), tiers, set(TIERS)
    )
    assert len(problems) == 3, problems
    assert all(moved in p and "are in SCOPE27" in p for p in problems)


def test_the_json_disagreeing_with_the_tables_reds_one_leg():
    # A stale json against current tables: the source leg holds, the json leg does not.
    moved = "AIR-FND-DAT-10"
    stale = {**TIERS, moved: AI_SUBJECT}
    problems = check_ledger.foundation_tier_problems(
        SCOPE27, ledger_rows(stale), TIERS, set(TIERS)
    )
    assert any("the ledger json's foundation-tier rows" in p for p in problems)
    assert not any("FOUNDATION_ROWS" in p for p in problems)


def test_gate_3_reads_only_ai_subject_fnd_rows():
    """A foundation FND row the classification marks workload-specific is legal.

    Gate 3 lives in main(), so this pins the filter it applies over the real
    tables: the ai_subject FND rows are the 11 it judges, and at least one
    foundation FND row exists for the filter to exclude.
    """
    fnd = [r for r in build_ledger.ROWS if r[0].split("-")[1] == "FND"]
    judged = [r for r in fnd if TIERS[r[0]] != FOUNDATION]
    excluded = [r for r in fnd if TIERS[r[0]] == FOUNDATION]
    assert len(judged) == 11
    assert excluded
