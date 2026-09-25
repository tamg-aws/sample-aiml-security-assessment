"""Gate 14 reads its five census figures from one paragraph, sliced before the flatten.

Both halves of that sentence are load-bearing and neither is visible on this
branch's own document, where the whole-file read and the paragraph read return
the same five figures. The fixture below is therefore phase 3's head
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
    from_slice, slice_hits = check_ledger.census_figures(sliced)
    assert slice_hits["covered"] == ["28"]
    assert from_slice["covered"] == 28

    whole, whole_hits = check_ledger.census_figures(DOC_EXCERPT_AT_PHASE_3)
    assert whole_hits["covered"] == ["20", "28"]
    assert whole["covered"] is None


def test_tighten_pools_the_second_published_spelling():
    """Phase 3's clause is the other spelling, and the pool has to reach it."""
    sliced, _, _ = check_ledger.census_paragraph(DOC_EXCERPT_AT_PHASE_3)
    values, hits = check_ledger.census_figures(sliced)
    assert hits["tighten_as_remaining"] == []
    assert hits["tighten_as_controls"] == ["18"]
    assert hits["tighten"] == ["18"]
    assert values["tighten"] == 18


def test_the_shipped_paragraph_publishes_a_poolable_tighten_figure():
    """The same shape over the live document, asserting no value of its own.

    The values are gate 14's business, against build_ledger.ROWS; asserting one
    here would red this suite on the day the doc legitimately moves. What is
    asserted is that the live text still resolves through this path at all: one
    paragraph, five figures, and a tighten pool that is the two spellings
    concatenated rather than either one alone.
    """
    with open(check_ledger.AISF_DOC) as f:
        sliced, count, problems = check_ledger.census_paragraph(f.read())
    assert (count, problems) == (1, [])
    values, hits = check_ledger.census_figures(sliced)
    assert hits["tighten"] == (
        hits["tighten_as_remaining"] + hits["tighten_as_controls"]
    )
    assert hits["tighten"], "the shipped census paragraph publishes no tighten figure"
    assert sorted(values) == ["bare", "covered", "joint", "partial", "tighten"]
    assert all(isinstance(v, int) for v in values.values())


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

        # And the five figures report as absent rather than as nothing at all:
        # an empty slice resolves every figure to None, which figure_drift()
        # turns into a message per figure. A skip would leave gate 14 green with
        # nothing asserted.
        values, hits = check_ledger.census_figures(sliced)
        assert all(value is None for value in values.values())
        drift = check_ledger.figure_drift(
            "fixture", values, hits, dict.fromkeys(values, 1)
        )
        assert len(drift) == len(values)


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
    still returns the right five figures -- the disagreeing copy arrives with
    phase 3. So the call site is asserted directly.
    """
    with open(LEDGER) as f:
        source = f.read()
    assert "census_figures(census_slice)" in source
    assert "census_figures(published_text)" not in source
