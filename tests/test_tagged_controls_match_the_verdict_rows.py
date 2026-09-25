"""The tagged controls ARE the covered and tighten rows, as sets and not as counts.

The census paragraph states two identities: the controls a bare-or-joint tag names
are the `covered` rows, and the controls a `(partial)` tag names are the `tighten`
rows. Gate 14c reads the numerals that sentence publishes; the numerals can agree
while the membership does not, because two sets of one size can have different
members. Gate 14d compares the sets, and this file is where its parser and the
discriminating input live.

Inside the battery the identity is entailed, and this file is where that is stated
plainly: gate 14a derives each tag's expected qualifier from the ledger json
verdict and reports both directions of the pair set, and gate 15 ties that json to
build_ledger.ROWS field by field while re-rendering the maps from ROWS. What is
left over is two things, and neither is the entailment.

  * CI runs this file and cannot run any of those legs. They all live inside
    check_ledger.main(), which opens a path under a sibling AISF clone before it
    prints a verdict, and .github/workflows/python-tests.yml checks out this
    repository alone. So the real-tree case below is the only form of the claim a
    runner executes, and it reaches it through load_compliance_maps() and ROWS,
    which need no clone.
  * The element count is not equated with the set size, deliberately. One `tighten`
    control with two incumbents carries two `(partial)` tags. The case below pins
    that as a pass, because asserting one tag per control would red this tree.

The tag parser here is written from the published tag shape rather than imported
from check_ledger.py. An identity checked with the gate's own parser on both sides
agrees with itself whatever the parser does.
"""

import collections
import importlib.util
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO, "aisf-parity", "check_ledger.py")

_spec = importlib.util.spec_from_file_location("check_ledger", LEDGER)
check_ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_ledger)

# `AISF <control>` alone, or with one of the two qualifiers, which is the whole tag
# vocabulary docs/SECURITY_CHECKS_AISF.md publishes. Anchored both ends, so a tag
# this cannot read is counted as unparseable below instead of silently skipped.
ELEMENT = re.compile(
    r"AISF (AIR-[A-Z]+-[A-Z]+-\d+)(?: \((?:(partial)|1 of (\d+) checks)\))?"
)


def tree_tag_controls():
    """kind -> the controls that kind of tag names, read from the shipped maps.

    Returns the element tally beside it: the two differ whenever one control
    carries several tags of one kind, and that difference is the thing gate 14d
    prints and does not assert.
    """
    controls = collections.defaultdict(set)
    elements = collections.Counter()
    unparseable = []
    for module_dir, mapping in check_ledger.load_compliance_maps().items():
        for check_id, tag in mapping.items():
            for element in tag.split(" | "):
                found = ELEMENT.fullmatch(element)
                if not found:
                    unparseable.append(f"{module_dir}:{check_id}:{element!r}")
                    continue
                control, partial, denominator = found.groups()
                kind = "partial" if partial else ("joint" if denominator else "bare")
                controls[kind].add(control)
                elements[kind] += 1
    return controls, elements, unparseable


def tree_verdict_controls():
    """verdict -> the controls build_ledger.ROWS gives that verdict.

    r[0] and r[1] of each tuple, which is the shape check_ledger.py reads. The
    field count is asserted rather than assumed, because a positional read of a
    widened tuple is wrong without raising.
    """
    controls = collections.defaultdict(set)
    for row in check_ledger.ROWS:
        assert len(row) == 8, f"ROWS tuple is {len(row)} fields wide, not 8: {row}"
        controls[row[1]].add(row[0])
    return controls


def test_the_shipped_maps_and_rows_satisfy_both_identities():
    """The real tree, through a parser the gate does not share.

    The population is asserted first: empty sets satisfy both identities, and an
    identity over nothing is the pass this whole file would otherwise be.
    """
    tags, elements, unparseable = tree_tag_controls()
    verdicts = tree_verdict_controls()
    assert not unparseable, f"tags this test cannot read: {unparseable}"
    assert elements["bare"] and elements["partial"] and elements["joint"], (
        f"one of the three tag kinds is unpopulated {dict(elements)}, so the "
        "identities below hold over an empty set"
    )
    assert verdicts["covered"] and verdicts["tighten"]

    assert check_ledger.tagged_control_problems(tags, verdicts) == []


def test_the_element_count_exceeding_the_control_count_is_not_a_failure_here():
    """One `tighten` control with two incumbents carries two `(partial)` tags.

    Legal, and the state of this tree. The doc-side clause that does claim one tag
    each is asserted by census_relations() at the refs that publish it, so the
    claim is gated where it is made and not where it would red a correct tree.
    """
    tags, elements, _ = tree_tag_controls()
    assert elements["partial"] > len(tags["partial"]), (
        "no control carries two tags of one kind in this tree, so this case no "
        f"longer measures anything: {elements['partial']} element(s) over "
        f"{len(tags['partial'])} control(s)"
    )
    assert check_ledger.tagged_control_problems(tags, tree_verdict_controls()) == []


def test_two_populations_of_one_size_over_different_members_fail():
    """The input that separates an identity from a pair of counts.

    Both legs are of equal size on both sides here, so every count a figure gate
    could compare agrees. One member differs on each leg.
    """
    tags = {
        "bare": {"AIR-BDR-GRD-01"},
        "joint": {"AIR-SGM-TRN-05"},
        "partial": {"AIR-BDR-GRD-02", "AIR-BDR-GRD-04"},
    }
    verdicts = {
        "covered": {"AIR-BDR-GRD-01", "AIR-SGM-TRN-99"},
        "tighten": {"AIR-BDR-GRD-02", "AIR-BDR-GRD-99"},
    }
    assert len(tags["bare"] | tags["joint"]) == len(verdicts["covered"])
    assert len(tags["partial"]) == len(verdicts["tighten"])

    problems = check_ledger.tagged_control_problems(tags, verdicts)
    assert len(problems) == 4, f"expected both directions of both legs: {problems}"
    joined = " ".join(problems)
    for control in ("AIR-SGM-TRN-05", "AIR-SGM-TRN-99", "AIR-BDR-GRD-04"):
        assert control in joined, f"{control} is not named: {problems}"


def test_the_two_directions_are_separate_messages():
    """A tag with no row and a row with no tag are different repairs.

    One is a map edit or a changed verdict, the other a map that was never
    regenerated. Pooled into one message a reader cannot tell which happened.
    """
    extra = check_ledger.tagged_control_problems(
        {"bare": {"AIR-BDR-GRD-01"}, "joint": set(), "partial": set()},
        {"covered": set(), "tighten": set()},
    )
    absent = check_ledger.tagged_control_problems(
        {"bare": set(), "joint": set(), "partial": set()},
        {"covered": {"AIR-BDR-GRD-01"}, "tighten": set()},
    )
    assert len(extra) == len(absent) == 1
    assert "are not `covered` in build_ledger.ROWS" in extra[0]
    assert "and no `bare` or `joint` tag names them" in absent[0]
    assert extra[0] != absent[0]


def test_a_partial_tag_on_a_covered_row_reds_both_legs():
    """The qualifier and the verdict disagreeing, which is one edit and two claims.

    The control leaves the bare-or-joint side and arrives on the partial side, so
    both identities break and both messages name it. Gate 14a catches the same
    edit against the json; this is the ROWS side of it.
    """
    problems = check_ledger.tagged_control_problems(
        {"bare": set(), "joint": set(), "partial": {"AIR-BDR-GRD-01"}},
        {"covered": {"AIR-BDR-GRD-01"}, "tighten": set()},
    )
    assert len(problems) == 2, problems
    assert any("no `bare` or `joint` tag names them" in p for p in problems)
    assert any("are not `tighten` in build_ledger.ROWS" in p for p in problems)


def test_the_leg_is_wired_once_and_prints_the_overlap():
    """Source-level, because main() needs a sibling clone CI does not have.

    Two things the function cannot assert about itself: that its result reaches a
    gate verdict at all, and that the bare/joint overlap is printed. A union
    absorbs an overlap silently, so the count is what makes a nonzero one visible,
    and it is the only state where the identity holds and the paragraph's sum
    does not.
    """
    with open(LEDGER) as handle:
        source = handle.read()
    # The leading `= ` is what makes this the call site. Without it the count is 2,
    # because `def tagged_control_problems(tag_controls, verdict_controls):` carries
    # the same substring, and a present substring need not be unique.
    assert (
        source.count("= tagged_control_problems(tag_controls, verdict_controls)") == 1
    )
    assert source.count("not tagged_problems,") == 1, (
        "the set identities are computed and not used as a verdict"
    )
    assert source.count('overlap = tag_controls["bare"] & tag_controls["joint"]') == 1
    assert source.count("bare/joint overlap {len(overlap)}") == 1
