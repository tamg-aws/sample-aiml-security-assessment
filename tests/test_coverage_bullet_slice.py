"""Gate 21 reads the Coverage and Traceability bullets, which nothing read before.

The block these figures live in published eleven figure instances over seven
distinct values for a whole phase with no gate reading any of them, and ten of the
eleven were wrong the whole time under 20/20 green. The fixture below is that
block transcribed verbatim from `bd0ecb8`, against the ledger as it stood at that
same head, so the suite measures the defect that was actually shipped rather than
one invented for it.

How the bullets lost their reader is the part worth protecting. `5ad07b5` narrowed
census_figures() to the paragraph it names, because the census `covered` pattern
had been reaching this block too and reporting the disagreement `['20', '28']`.
Narrowing made the printed scope label honest and removed the only reader the
block had. So a second slice is the repair, and the census suite's rationale does
not transfer to it: measured 2026-09-26, the whole-file read and the slice return
identical hits for all twelve of gate 21's patterns, because each pattern is tight
to the phrase around it. The slice earns its place as a fail-closed count and an
honest label, not as a disambiguator. If that ever stops being true -- some later
section starts publishing `all N taggable controls` too -- the slice becomes
load-bearing in the census sense as well, and nothing here has to change.

Every test reads only files inside this repo. `tests/` runs in GitHub Actions
against a bare checkout with no sibling AISF clone, so no test may run the ledger;
importing the module by path runs no gate and needs no clone.
"""

import importlib.util
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO, "aisf-parity", "check_ledger.py")

_spec = importlib.util.spec_from_file_location("check_ledger", LEDGER)
check_ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_ledger)

# The block as published at bd0ecb8, transcribed including its wraps. The wrap
# positions are part of the fixture: figure_occurrences() flattens whitespace
# because a marker straddling a line break is invisible to a literal-space
# pattern, and rewrapping these lines moves which markers straddle.
BULLETS_AT_BD0ECB8 = """\
- **Coverage:** 8 of the 78 in-scope AISF controls carry a derived `AISF-` row;
  the remaining 70 are not yet rendered as a row. A row is a narrower claim than
  coverage, so read this figure with the ledger census below it: 28 of the 78 are
  `covered`, all 8 rows sit on `covered` controls, and the other 20 `covered`
  controls are named by the `Compliance_Frameworks` tag column until each is
  walked through [Adding a control](#adding-a-control), which allocates an id and
  writes a per-control section. The 70 without a row are 20 `covered`, 18
  `tighten`, 18 `new`, 11 `unassessed` and 3 `not_implementable`. The parity
  analysis behind those figures is in
  [`aisf-parity/AISF-WORK-LEDGER.md`](../aisf-parity/AISF-WORK-LEDGER.md).
- **Traceability:** 18 controls are `tighten`, covered too partly to earn an
  `AISF-` row at all. The `Compliance_Frameworks` CSV column names all 46
  taggable controls on the producer rows themselves, the 28 `covered` and the 18
  `tighten`, and is described under
  [Traceability column on producer rows](#traceability-column-on-producer-rows).
  A tag carries no verdict."""

# This head's block, transcribed the same way. Used for the shape tests and as the
# base for the two redefinition fixtures, never as an expected value.
BULLETS_AT_THIS_HEAD = """\
- **Coverage:** 8 of the 78 in-scope AISF controls carry a derived `AISF-` row;
  the remaining 70 are not yet rendered as a row. A row is a narrower claim than
  coverage, so read this figure with the ledger census below it: 61 of the 78 are
  `covered`, all 8 rows sit on `covered` controls, and the other 53 `covered`
  controls are named by the `Compliance_Frameworks` tag column until each is
  walked through [Adding a control](#adding-a-control), which allocates an id and
  writes a per-control section. The 70 without a row are 53 `covered`, 11
  `tighten`, 2 `new` and 4 `not_implementable`, with no control left
  `unassessed`. The parity analysis behind those figures is in
  [`aisf-parity/AISF-WORK-LEDGER.md`](../aisf-parity/AISF-WORK-LEDGER.md).
- **Traceability:** 11 controls are `tighten`, covered too partly to earn an
  `AISF-` row at all. The `Compliance_Frameworks` CSV column names all 72
  taggable controls on the producer rows themselves, the 61 `covered` and the 11
  `tighten`, and is described under
  [Traceability column on producer rows](#traceability-column-on-producer-rows).
  A tag carries no verdict."""

# The three bullets above the anchor, which the slice has to exclude, and a
# following section so the `\n\n` terminator has something to stop at.
DOC_EXCERPT = (
    """\
- **Reference:** [AWS Well-Architected Generative AI Lens](https://example.invalid/lens),
  plus the control-specific AWS documentation linked in the per-control tables
  below.
- **Opt-in:** none. AISF is a derived view over checks that already run, so it
  needs no deployment parameter and adds no scan time.
- **Report location:** the "By Compliance Standard" sidebar section, alongside
  OWASP Top 10 for LLM.
"""
    + BULLETS_AT_THIS_HEAD
    + "\n\n## Disclaimer\n\nThese mappings are PRELIMINARY.\n"
)

# What the extractor reads out of the bd0ecb8 block. A transcription pin on the
# ten labels, not a claim about any ledger: it fixes which phrase each label is
# tight to, so a pattern edited to match a different clause fails here even when
# the two clauses happen to publish the same number today.
AS_PUBLISHED_AT_BD0ECB8 = {
    "covered": 28,
    "covered_without_row": 20,
    "covered_without_row_restated": 20,
    "tighten": 18,
    "tighten_in_the_split": 18,
    "new": 18,
    "not_implementable": 3,
    "taggable": 46,
    "taggable_covered": 28,
    "taggable_tighten": 18,
}

# What the ledger computed at bd0ecb8, transcribed from build_ledger's summary at
# that head: covered 61, tighten 11, new 3, not_implementable 3, unassessed 0 over
# 78 in-scope controls with 8 derived mappings. `new` and `not_implementable` moved
# to 2 and 4 afterwards, when AIR-ACR-MEM-07 was reclassified. Transcribed rather
# than computed, because computing it needs the AISF clone this suite cannot reach.
LEDGER_AT_BD0ECB8 = {
    "covered": 61,
    "covered_without_row": 53,
    "covered_without_row_restated": 53,
    "tighten": 11,
    "tighten_in_the_split": 11,
    "new": 3,
    "not_implementable": 3,
    "taggable": 72,
    "taggable_covered": 61,
    "taggable_tighten": 11,
    "unassessed": 0,
    "without_row_total": 70,
}

LEDGER_AT_THIS_HEAD = dict(LEDGER_AT_BD0ECB8, new=2, not_implementable=4)


def test_the_block_is_cut_out_of_the_raw_text_and_covers_both_bullets():
    sliced, count, problems = check_ledger.coverage_bullets(DOC_EXCERPT)
    assert (count, problems) == (1, [])
    assert sliced.startswith(check_ledger.BULLET_ANCHOR)
    assert sliced.endswith("A tag carries no verdict.")
    # One slice, both bullets, and nothing above the anchor. The Traceability
    # figures sit in the second bullet, so a terminator that stopped at the next
    # `\n- ` would read five of the ten labels and leave five reported absent.
    assert "- **Traceability:**" in sliced
    assert "Report location" not in sliced
    assert "Disclaimer" not in sliced


def test_a_marker_the_patterns_need_straddles_a_line_break():
    """Why the flatten is load-bearing for this block, on the fixture not the doc.

    Asserted against the transcribed fixture so it cannot rot on a rewrap: at this
    wrapping the taggable count and its `controls` land on different lines, as do
    four more markers. Which ones is a property of the wrapping and not of the
    document, which is why the count is in the comment at the pattern list and not
    asserted here.
    """
    assert re.search(r"all \d+\n\s+taggable controls", BULLETS_AT_THIS_HEAD)
    assert re.search(r"the other \d+ `covered`\n\s+controls", BULLETS_AT_THIS_HEAD)
    flattened = re.sub(r"\s+", " ", BULLETS_AT_THIS_HEAD)
    assert re.search(r"all \d+ taggable controls", flattened)


def test_the_block_pattern_finds_nothing_once_the_text_is_flattened():
    """The same order-of-operations fact the census slice rests on.

    Neither `^` nor the `\\n\\n` terminator survives the collapse
    figure_occurrences() does, so slicing after it would fail the exactly-one rule
    below on a correct document, forever.
    """
    flattened = re.sub(r"\s+", " ", DOC_EXCERPT)
    assert check_ledger.BULLET_ANCHOR in flattened
    assert len(check_ledger.COVERAGE_BULLETS.findall(DOC_EXCERPT)) == 1
    assert check_ledger.COVERAGE_BULLETS.findall(flattened) == []


def test_an_anchor_that_is_not_unique_reports_and_never_reads_as_a_pass():
    reworded = DOC_EXCERPT.replace(check_ledger.BULLET_ANCHOR, "- **Coverage note:**")
    twice = DOC_EXCERPT + "\n" + BULLETS_AT_BD0ECB8 + "\n"
    for text, expected in ((reworded, 0), (twice, 2)):
        sliced, count, problems = check_ledger.coverage_bullets(text)
        assert count == expected
        assert sliced == ""
        assert len(problems) == 1
        assert check_ledger.BULLET_ANCHOR in problems[0]
        assert f"{expected} block(s)" in problems[0]

        # And the empty slice reports every figure as absent rather than as
        # nothing at all: ten drift messages, plus the prose-zero relation, so a
        # reworded anchor can never leave gate 21 green with nothing asserted.
        values, found = check_ledger.coverage_bullet_figures(sliced)
        assert all(value is None for value in values.values())
        drift = check_ledger.figure_drift("fixture", values, found, LEDGER_AT_THIS_HEAD)
        assert len(drift) == len(values) == 10
        relations = check_ledger.coverage_bullet_relations(
            values, LEDGER_AT_THIS_HEAD, found
        )
        assert len(relations) == 1
        assert "does not say so" in relations[0]


def test_the_extractor_reads_the_published_block_as_these_ten_numbers():
    values, found = check_ledger.coverage_bullet_figures(BULLETS_AT_BD0ECB8)
    assert values == AS_PUBLISHED_AT_BD0ECB8
    assert all(len(found[label]) == 1 for label in values)


def test_the_shipped_defect_reds_on_nine_figure_legs_and_three_relations():
    """The block as published at bd0ecb8 against the ledger at bd0ecb8.

    Nine and not ten, and the tenth is the point: `3 not_implementable` agreed at
    that head and went wrong only later, so a suite that expected all ten to fail
    would be asserting something the document never did.
    """
    values, found = check_ledger.coverage_bullet_figures(BULLETS_AT_BD0ECB8)
    drift = check_ledger.figure_drift("doc", values, found, LEDGER_AT_BD0ECB8)
    assert len(drift) == 9
    assert not any("not_implementable" in message for message in drift)
    assert "doc publishes covered=28, the ledger computes 61" in drift
    assert "doc publishes taggable=46, the ledger computes 72" in drift

    relations = check_ledger.coverage_bullet_relations(values, LEDGER_AT_BD0ECB8, found)
    assert len(relations) == 3
    assert any("own split sums to 59" in message for message in relations)
    assert any("publishes ['11'] `unassessed`" in message for message in relations)


def test_the_traceability_sum_fires_alone_when_taggable_is_redefined():
    """The coordinated doc-and-code edit, which no figure leg can see.

    computed["taggable"] is written as covered + tighten. Redefine it and update
    the document to match and all ten figure legs agree, because they compare the
    document against whatever that expression says. The bullet's own sentence
    enumerates the covered and the tighten, so the sum is the leg that reads it.
    """
    doc = BULLETS_AT_THIS_HEAD.replace("all 72\n  taggable", "all 73\n  taggable")
    assert doc != BULLETS_AT_THIS_HEAD
    computed = dict(LEDGER_AT_THIS_HEAD, taggable=73)
    values, found = check_ledger.coverage_bullet_figures(doc)
    assert check_ledger.figure_drift("doc", values, found, computed) == []
    relations = check_ledger.coverage_bullet_relations(values, computed, found)
    assert len(relations) == 1
    assert "61 + 11 does not reach the 73 taggable controls" in relations[0]


def test_the_partition_sum_fires_alone_when_the_without_row_total_is_redefined():
    """The other computed expression, and the other direction: prose untouched.

    computed["without_row_total"] is total - mapped controls, which the four
    published parts have to cover. Nothing in the document moves here at all, so
    every figure leg is green by construction and the split is the only reader.
    """
    computed = dict(LEDGER_AT_THIS_HEAD, without_row_total=71)
    values, found = check_ledger.coverage_bullet_figures(BULLETS_AT_THIS_HEAD)
    assert check_ledger.figure_drift("doc", values, found, computed) == []
    relations = check_ledger.coverage_bullet_relations(values, computed, found)
    assert len(relations) == 1
    assert "own split sums to 70" in relations[0]
    assert "leaves 71 controls without a row" in relations[0]


def test_the_prose_zero_is_required_in_exactly_the_world_it_is_true_in():
    """Four cases, because a zero published as words has two ways to go stale.

    The document says `with no control left `unassessed`` and publishes no digit.
    That is gated as a relation and not as a figure: a pattern alone reads a
    digit-free sentence as an absent figure forever, and a zero stated in prose is
    still a published claim.
    """
    values, found = check_ledger.coverage_bullet_figures(BULLETS_AT_THIS_HEAD)
    # True world: the ledger is at zero and the words are there.
    assert (
        check_ledger.coverage_bullet_relations(values, LEDGER_AT_THIS_HEAD, found) == []
    )

    # The count moves off zero and the sentence is left behind. Both halves fire:
    # the phrase is now false, and the figure it should have been replaced with is
    # absent.
    moved = dict(LEDGER_AT_THIS_HEAD, unassessed=5, without_row_total=75)
    relations = check_ledger.coverage_bullet_relations(values, moved, found)
    assert len(relations) == 2
    assert any("says there are none" in message for message in relations)
    assert any("publishes [] `unassessed`" in message for message in relations)

    # And the mirror: a digit published while the ledger is at zero. The phrase
    # going missing and the digit appearing are separate failures, so a sentence
    # rewritten in one direction cannot satisfy the other.
    digit = BULLETS_AT_THIS_HEAD.replace(
        "with no control left\n  `unassessed`", "with 5 `unassessed`"
    )
    assert digit != BULLETS_AT_THIS_HEAD
    dv, df = check_ledger.coverage_bullet_figures(digit)
    relations = check_ledger.coverage_bullet_relations(dv, LEDGER_AT_THIS_HEAD, df)
    assert len(relations) == 2
    assert any("does not say so" in message for message in relations)
    assert any("publishes ['5'] `unassessed` while the ledger" in m for m in relations)


def test_the_unassessed_digit_is_read_wherever_it_sits_in_the_list():
    """The repaired document for the off-zero world, which a trailing pattern misses.

    The one ref that did publish this as a digit wrote it mid-list, between `new`
    and `not_implementable`. Read by an `and (\\d+)` pattern that is zero copies,
    so the gate failed closed but named the figure absent while the document was
    publishing it -- a different repair from the one the message asked for.
    """
    repaired = BULLETS_AT_THIS_HEAD.replace(
        "2 `new` and 4 `not_implementable`, with no control left\n  `unassessed`",
        "2 `new`, 5 `unassessed` and 4 `not_implementable`",
    )
    assert repaired != BULLETS_AT_THIS_HEAD
    values, found = check_ledger.coverage_bullet_figures(repaired)
    assert found["unassessed_as_figure"] == ["5"]
    assert found["unassessed_as_words"] == []
    computed = dict(LEDGER_AT_THIS_HEAD, unassessed=5, without_row_total=75)
    assert check_ledger.figure_drift("doc", values, found, computed) == []
    assert check_ledger.coverage_bullet_relations(values, computed, found) == []

    # The mid-list form is also what bd0ecb8 published, so the narrow pattern is
    # asserted gone rather than left to be reintroduced.
    with open(LEDGER) as f:
        assert r'r"and (\d+) `unassessed`"' not in f.read()


def test_the_shipped_bullets_still_resolve_through_this_path():
    """The live document, asserting shape and no value.

    The values are gate 21's business, against build_ledger's summary; asserting
    one here would red this suite on the day the populations legitimately move,
    which is every delivered check. What is asserted is that the block still
    resolves: one slice, ten readable figures, and exactly one of the two spellings
    of `unassessed` present, which holds on both sides of the zero.
    """
    with open(check_ledger.AISF_DOC) as f:
        sliced, count, problems = check_ledger.coverage_bullets(f.read())
    assert (count, problems) == (1, [])
    values, found = check_ledger.coverage_bullet_figures(sliced)
    assert len(values) == 10
    assert all(isinstance(value, int) for value in values.values())
    assert all(len(found[label]) == 1 for label in values)
    assert bool(found["unassessed_as_words"]) != bool(found["unassessed_as_figure"])


def test_gate_21_hands_the_slice_to_the_extractor_not_the_whole_document():
    """The wiring, which no value test above can see.

    Both functions stay correct if the call site passes the whole file, and on this
    document that returns the same ten figures -- measured, the whole-file read and
    the slice agree on every pattern today. So the call site is asserted directly,
    the way the census suite asserts its own.
    """
    with open(LEDGER) as f:
        source = f.read()
    assert "coverage_bullet_figures(bullet_slice)" in source
    assert "coverage_bullet_figures(bullet_text)" not in source
    # Both result sets have to reach the verdict. Dropping either leaves every
    # assertion in this file green and gate 21 green on a block that disagrees:
    # the slice's own problem list, the drift, and the relations.
    assert "bullet_bad = coverage_bullets(bullet_text)" in source
    assert source.count("bullet_bad += figure_drift(") == 1
    assert source.count("bullet_bad += coverage_bullet_relations(") == 1
    assert source.count("not bullet_bad,") == 1
