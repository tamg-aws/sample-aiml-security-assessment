"""Gate 14 reads its six census figures from one paragraph, sliced before the flatten.

Both halves of that sentence are load-bearing and neither is visible on this
branch's own document, where the whole-file read and the paragraph read return
the same six figures. The fixture below is therefore phase 3's head
(`feature/aisf-phase3-bdr-sgm`, doc at 43a3772) transcribed verbatim: the two
coverage bullets near the top of the file, the tag-shape table, and the census
paragraph under it. Against that text the whole-file read returns two disagreeing
copies of `covered` and the narrowing is what resolves it, so a suite that only
ever sees this branch's document would pass with the slice deleted.

The wrap positions are part of the fixture. figure_occurrences() flattens
whitespace because a marker that straddles a line break is invisible to a
literal-space pattern, and rewrapping these lines would move which markers
straddle.
"""

import importlib.util
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO, "aisf-parity", "check_ledger.py")

# Loaded by explicit path, as the other suites here load the modules they gate.
# check_ledger.py puts the directories its own imports need on sys.path as it
# loads, so nothing has to be arranged from this side, and importing it runs no
# gate: main() is guarded.
_spec = importlib.util.spec_from_file_location("check_ledger", LEDGER)
check_ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_ledger)

CENSUS_PARAGRAPH_AT_PHASE_3 = """\
Census at the current head, also printed by gate 14: 26 bare, 18 `(partial)`, 5
joint. The 26 bare tags plus the two jointly covered controls, `AIR-BDR-MDL-02`
over 2 checks and `AIR-SGM-TRN-05` over 3, account for the 28 `covered`
controls; the 18 `(partial)` tags are the 18 `tighten` controls, one tag each. A
bare tag on a `tighten` row, or a dropped `(1 of N)`, fails gate 14 with the
row's verdict and incumbent count named.
"""

# This branch's own paragraph, transcribed verbatim including its wraps. Here for
# the count spelled as a word: the two refs spell the jointly-covered-control
# count differently, `the single control that carries` against phase 3's `the two
# jointly covered controls`, and a digit-only pattern reads neither.
CENSUS_PARAGRAPH_AT_THIS_HEAD = """\
Census at the current head, also printed by gate 14: 7 bare, 29 `(partial)`, 3
`(1 of 3 checks)`. The 7 bare tags plus the single control that carries all 3
joint legs account for the 8 `covered` controls; the remaining 28 are `tighten`.
A bare tag on a `tighten` row, or a dropped `(1 of N)`, fails gate 14 with the
row's verdict and incumbent count named.
"""

# The numerals-only update a maintainer reaches for when the population moves,
# applied to phase 3's paragraph with the merge's figures: bare 26 -> 40, partial
# 18 -> 6, joint 5 -> 36, covered 28 -> 56, tighten 18 -> 6. Transcribed rather
# than substituted, because `over 2 checks` and `AIR-BDR-MDL-02` carry digits a
# replace() would move. The spelled-out `two` and the two named controls are left
# exactly as they were, which is the defect: at the merge there are 16 jointly
# covered controls, so the sentence reads 40 + two = 56 and names 2 of the 16.
CENSUS_PARAGRAPH_NUMERALS_ONLY = """\
Census at the current head, also printed by gate 14: 40 bare, 6 `(partial)`, 36
joint. The 40 bare tags plus the two jointly covered controls, `AIR-BDR-MDL-02`
over 2 checks and `AIR-SGM-TRN-05` over 3, account for the 56 `covered`
controls; the 6 `(partial)` tags are the 6 `tighten` controls, one tag each. A
bare tag on a `tighten` row, or a dropped `(1 of N)`, fails gate 14 with the
row's verdict and incumbent count named.
"""

# What gate 14 computes at that merge, from the shipped maps and build_ledger.ROWS.
COMPUTED_AT_THE_MERGE = {
    "bare": 40,
    "partial": 6,
    "joint": 36,
    "joint_controls": 16,
    "covered": 56,
    "tighten": 6,
}

# The `20 `covered` controls` in the first bullet is the second copy the
# whole-file read picks up, and `the 18 `tighten`` in the second is a figure over
# a different population: the tighten controls that carry no AISF- row.
DOC_EXCERPT_AT_PHASE_3 = (
    """\
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

| Tag | Means |
| ----- | ------- |
| `AISF AIR-BDR-GRD-01` | this check alone asserts the whole control |
| `AISF AIR-SGM-TRN-05 (1 of 3 checks)` | the control is covered, but jointly, so no single leg asserts it |
| `AISF AIR-BDR-MDL-08 (partial)` | the check asserts less than the control requires, and the gap is open in the ledger |

"""
    + CENSUS_PARAGRAPH_AT_PHASE_3
    + "\nA check that contributes to several controls carries them pipe-joined.\n"
)


def test_the_paragraph_is_cut_out_of_the_raw_text():
    sliced, count, problems = check_ledger.census_paragraph(DOC_EXCERPT_AT_PHASE_3)
    assert (count, problems) == (1, [])
    assert sliced.startswith(check_ledger.CENSUS_ANCHOR)
    assert sliced.endswith("incumbent count named.")
    assert len(sliced) < len(DOC_EXCERPT_AT_PHASE_3)


def test_covered_resolves_from_the_slice_and_disagrees_over_the_whole_text():
    """The negative control: the same patterns over the whole text return None.

    Two copies of `covered` that disagree is the failure the agreement rule
    exists for, and here it is a false one -- the census sentence publishes 28
    and the coverage bullet's 20 counts covered controls without an `AISF-` row.
    Narrowing to the paragraph is what tells them apart, so this test fails if
    the slice is dropped.
    """
    sliced, _, _ = check_ledger.census_paragraph(DOC_EXCERPT_AT_PHASE_3)
    from_slice, slice_hits, _ = check_ledger.census_figures(sliced)
    assert slice_hits["covered"] == ["28"]
    assert from_slice["covered"] == 28

    whole, whole_hits, _ = check_ledger.census_figures(DOC_EXCERPT_AT_PHASE_3)
    assert whole_hits["covered"] == ["20", "28"]
    assert whole["covered"] is None


def test_tighten_pools_the_second_published_spelling():
    """Phase 3's clause is the other spelling, and the pool has to reach it."""
    sliced, _, _ = check_ledger.census_paragraph(DOC_EXCERPT_AT_PHASE_3)
    values, hits, _ = check_ledger.census_figures(sliced)
    assert hits["tighten_as_remaining"] == []
    assert hits["tighten_as_controls"] == ["18"]
    assert hits["tighten"] == ["18"]
    assert values["tighten"] == 18


def test_the_shipped_paragraph_publishes_a_poolable_tighten_figure():
    """The same shape over the live document, asserting no value of its own.

    The values are gate 14's business, against build_ledger.ROWS; asserting one
    here would red this suite on the day the doc legitimately moves. What is
    asserted is that the live text still resolves through this path at all: one
    paragraph, six figures, and two pools that are their two spellings
    concatenated rather than either one alone.
    """
    with open(check_ledger.AISF_DOC) as f:
        sliced, count, problems = check_ledger.census_paragraph(f.read())
    assert (count, problems) == (1, [])
    values, hits, sums = check_ledger.census_figures(sliced)
    assert hits["tighten"] == (
        hits["tighten_as_remaining"] + hits["tighten_as_controls"]
    )
    assert hits["tighten"], "the shipped census paragraph publishes no tighten figure"
    assert hits["joint_controls"], (
        "the shipped census paragraph publishes no jointly-covered-control count "
        "under either spelling"
    )
    assert sorted(values) == [
        "bare",
        "covered",
        "joint",
        "joint_controls",
        "partial",
        "tighten",
    ]
    assert all(isinstance(v, int) for v in values.values())
    # The one value assertion this suite does make about the live document, and it
    # is about the document agreeing with itself rather than with any population:
    # the sum the sentence states has to add up at whatever figures it publishes.
    assert sums == []


def test_an_anchor_that_is_not_unique_reports_and_does_not_skip():
    reworded = DOC_EXCERPT_AT_PHASE_3.replace(
        check_ledger.CENSUS_ANCHOR, "Current census"
    )
    twice = DOC_EXCERPT_AT_PHASE_3 + "\n" + CENSUS_PARAGRAPH_AT_PHASE_3
    for text, expected in ((reworded, 0), (twice, 2)):
        sliced, count, problems = check_ledger.census_paragraph(text)
        assert count == expected
        assert sliced == ""
        assert len(problems) == 1
        assert check_ledger.CENSUS_ANCHOR in problems[0]
        assert f"{expected} paragraph(s)" in problems[0]

        # And every figure reports as absent rather than as nothing at all: an
        # empty slice resolves every figure to None, which figure_drift() turns
        # into a message per figure. A skip would leave gate 14 green with
        # nothing asserted.
        values, hits, sums = check_ledger.census_figures(sliced)
        assert all(value is None for value in values.values())
        drift = check_ledger.figure_drift(
            "fixture", values, hits, dict.fromkeys(values, 1)
        )
        assert len(drift) == len(values)
        # The sum reports the same way. An unreadable operand is the one case
        # where a relation could quietly assert nothing, so it names the
        # operands it could not read instead of returning no problem.
        assert len(sums) == 1
        assert "['bare', 'joint_controls', 'covered']" in sums[0]


def test_the_paragraph_pattern_finds_nothing_once_the_text_is_flattened():
    """Why the slice has to be cut first, as an executable fact.

    Measured at four refs: one match on the raw file, zero on the same text
    flattened. Neither `^` nor the `\\n\\n` terminator survives the collapse
    figure_occurrences() does, so slicing after it would leave the exactly-one
    rule above failing gate 14 forever on a correct document.
    """
    import re

    flattened = re.sub(r"\s+", " ", DOC_EXCERPT_AT_PHASE_3)
    assert check_ledger.CENSUS_ANCHOR in flattened
    assert check_ledger.CENSUS_PARAGRAPH.findall(DOC_EXCERPT_AT_PHASE_3) != []
    assert check_ledger.CENSUS_PARAGRAPH.findall(flattened) == []


def test_gate_14_hands_the_slice_to_census_figures_not_the_whole_document():
    """The wiring, which no value test above can see.

    census_paragraph() and census_figures() both stay correct if the call site
    goes back to passing the whole file, and on this branch's document that
    still returns the right six figures -- the disagreeing copy arrives with
    phase 3. So the call site is asserted directly.
    """
    with open(LEDGER) as f:
        source = f.read()
    assert "census_figures(census_slice)" in source
    assert "census_figures(published_text)" not in source
    # The sums are wired the same way and have the same blind spot: a call site
    # that unpacks them and drops them leaves every assertion in this file green
    # and gate 14 green on a sentence that does not add up.
    assert source.count("+ census_sum_problems") == 1


def test_the_jointly_covered_count_is_read_as_a_word_at_both_refs():
    """The sixth figure, spelled `single` here and `two` at phase 3's head.

    Neither ref writes it as a digit, so the figure was unreadable and the sum it
    is the middle term of was unassertable. It is pooled across the two spellings
    and is not the joint element count beside it: 3 legs on 1 control here, 5 on 2
    at phase 3, and gate 14's `pairs` reconciliation adds up the legs.
    """
    here, here_hits, here_sums = check_ledger.census_figures(
        CENSUS_PARAGRAPH_AT_THIS_HEAD
    )
    assert here_hits["joint_controls_as_carrier"] == ["single"]
    assert here_hits["joint_controls_as_jointly"] == []
    assert here_hits["joint_controls"] == ["1"]
    assert (here["joint_controls"], here["joint"]) == (1, 3)
    assert here_sums == []

    phase3, p3_hits, p3_sums = check_ledger.census_figures(CENSUS_PARAGRAPH_AT_PHASE_3)
    assert p3_hits["joint_controls_as_carrier"] == []
    assert p3_hits["joint_controls_as_jointly"] == ["two"]
    assert p3_hits["joint_controls"] == ["2"]
    assert (phase3["joint_controls"], phase3["joint"]) == (2, 5)
    assert p3_sums == []

    # The other half of the conditional leg, on this head's real figures: 29
    # partial tags over 28 tighten controls, because one tighten row carries two
    # incumbents. This paragraph claims no one tag each, so nothing asserts one,
    # and the absence of the claim is in the verdict line rather than implied.
    assert here["partial"] != here["tighten"]
    assert "one_tag_each x0" in check_ledger.copies_note(here_hits)


def test_the_numerals_only_update_fails_on_the_sum_five_figures_could_not_see():
    """The defect this change exists for, as the maintainer would have shipped it.

    Every figure the gate read before the sixth was added agrees with the merge's
    computation, which is the negative control: the five-figure gate was green on
    a sentence reading 40 + two = 56. The sixth figure disagrees and the sum says
    what the sentence claimed, so the failure names the arithmetic and not only
    the transcription.
    """
    values, hits, sums = check_ledger.census_figures(CENSUS_PARAGRAPH_NUMERALS_ONLY)
    before = {k: v for k, v in values.items() if k != "joint_controls"}
    assert (
        check_ledger.figure_drift("fixture", before, hits, COMPUTED_AT_THE_MERGE) == []
    )

    drift = check_ledger.figure_drift("fixture", values, hits, COMPUTED_AT_THE_MERGE)
    assert len(drift) == 1
    assert "publishes joint_controls=2, gate 14 computes 16" in drift[0]
    assert len(sums) == 1
    assert "40 bare tags plus 2 jointly covered control(s)" in sums[0]
    assert "which sums to 42" in sums[0]


def test_the_repaired_paragraph_passes_on_all_six_figures_and_the_sum():
    """The same paragraph with the middle term written as the digit it is."""
    text = CENSUS_PARAGRAPH_NUMERALS_ONLY.replace(
        "plus the two jointly", "plus the 16 jointly"
    )
    values, hits, sums = check_ledger.census_figures(text)
    assert hits["joint_controls"] == ["16"]
    assert values["joint_controls"] == 16
    assert values == COMPUTED_AT_THE_MERGE
    assert sums == []
    assert (
        check_ledger.figure_drift("fixture", values, hits, COMPUTED_AT_THE_MERGE) == []
    )


def test_a_second_partial_tag_on_one_control_fails_the_one_tag_each_clause():
    """The relation the six figures still cannot see, and the one with a catch.

    partial counts tag elements and tighten counts ROWS verdicts, so the two are
    different populations that nothing else here compares. A `tighten` row with
    two incumbents carries two `(partial)` tags, which is legal, passes gate 14a,
    and makes `one tag each` false while both figures match their own
    computation -- the negative control below. That state is this base's, at 29
    over 28.
    """
    text = CENSUS_PARAGRAPH_AT_PHASE_3.replace("18 `(partial)`", "19 `(partial)`")
    assert text.count("19 `(partial)`") == 2
    values, hits, sums = check_ledger.census_figures(text)
    computed = {
        "bare": 26,
        "partial": 19,
        "joint": 5,
        "joint_controls": 2,
        "covered": 28,
        "tighten": 18,
    }
    assert check_ledger.figure_drift("fixture", values, hits, computed) == []
    assert hits["one_tag_each"] != []
    assert len(sums) == 1
    assert "one `(partial)` tag per `tighten` control" in sums[0]
    assert "publishes 19 tags over 18 controls" in sums[0]


def test_a_count_spelled_in_a_word_this_cannot_read_is_named_not_dropped():
    """An unreadable token fails the gate carrying the word, never silently.

    Dropping it would leave the pool empty, which reads as a paragraph that
    publishes no such figure: a true statement about the pattern and a false one
    about the document, and a different repair.
    """
    text = CENSUS_PARAGRAPH_AT_PHASE_3.replace(
        "plus the two jointly", "plus the dozen jointly"
    )
    values, hits, sums = check_ledger.census_figures(text)
    assert hits["joint_controls_as_jointly"] == ["dozen"]
    assert hits["joint_controls"] == []
    assert values["joint_controls"] is None
    assert len(sums) == 2
    assert any("['joint_controls'] absent" in problem for problem in sums)
    assert any("['dozen']" in problem for problem in sums)
