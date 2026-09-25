"""README publishes the catalog total six times, and gate 12 reconciles all six.

Two failures, and they are caught by different legs. Six copies that disagree
resolve to None through the agreement rule, which is the partial-bump case. Six
copies that become five resolve cleanly and would leave the gate green, so each
pattern is separately required to match and the gate names the ones that do not.
Both legs are asserted below, and the shipped file is checked against the second
one on every run.

No test below asserts the value of the total. It moves by design -- 208 at this
head, 218 on the branch that raises it -- and gate 12 is what compares it to the
emitted ids, the report section and SECURITY_CHECKS.md. What is asserted is the
shape: six copies, one figure, and a call site that puts README on the side list.

The bumps below are applied through the gate's own pattern tuple and not by
replacing a digit string, which would edit whichever copy came first in the file
six times over and read as six per-copy tests.
"""

import importlib.util
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO, "aisf-parity", "check_ledger.py")

_spec = importlib.util.spec_from_file_location("check_ledger", LEDGER)
check_ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_ledger)

PATTERNS = dict(check_ledger.README_CATALOG_PATTERNS)

# Spelled out here on purpose, and kept in the gate's own order. Every assertion
# below that iterates the gate's tuple follows it when a pattern is deleted from
# it -- five labels, five copies, five passing tests -- so the published count of
# six is pinned to something the gate cannot edit. The gate's own per-pattern rule
# cannot cover this either: it reports the patterns that stopped matching, not the
# ones that were removed.
PUBLISHED_COPIES = (
    "run_checks_link",
    "security_checks_link",
    "standardized",
    "across_seven",
    "reference_for_all",
    "excluded_from",
)


def readme_text():
    with open(check_ledger.README_DOC) as f:
        return f.read()


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


def test_each_published_copy_is_found_exactly_once():
    """Six copies, one hit each, in the file as it ships.

    The gate requires each pattern to match and so does this, one layer apart: the
    gate reports a pattern that stopped matching, and the literal list above
    catches a pattern removed from the tuple, which the gate reads as six-of-six
    over five. Exactly once rather than at least once, because two hits from one
    pattern means it found a sentence nobody counted.
    """
    assert tuple(PATTERNS) == PUBLISHED_COPIES
    total, hits, problems = check_ledger.readme_catalog_figures(readme_text())
    assert problems == []
    assert [len(hits[label]) for label in PUBLISHED_COPIES] == [1] * 6
    assert len(hits["readme_total"]) == 6
    assert isinstance(total, int)


def test_a_pattern_that_stops_matching_is_named_and_fails_the_gate():
    """The leg the pooled figure cannot provide, per pattern, in both directions.

    Rewording one sentence away leaves five copies agreeing, so the figure stays
    resolvable and the value legs all pass -- measured on a transient edit to the
    badge line: exit 0, verdict reading `run_checks_link x0 readme_total x5`. The
    message has to name the pattern, because five sixths of a side asserted looks
    exactly like a side asserted.
    """
    text = readme_text()
    for label in PUBLISHED_COPIES:
        retired = re.sub(PATTERNS[label], "the checks", text, count=1)
        assert retired != text
        total, hits, problems = check_ledger.readme_catalog_figures(retired)
        assert hits[label] == []
        assert len(hits["readme_total"]) == 5
        assert isinstance(total, int), "the five copies left still agree"
        assert (
            check_ledger.figure_problems("README.md", {"readme_total": total}, hits)
            == []
        ), "the pooled leg is not what catches this"
        assert len(problems) == 1
        assert label in problems[0]
        assert "1 of them no longer match" in problems[0]

    # And every pattern gone at once is one message naming all six, not silence:
    # an empty side is the case the per-side guard covers, and it must still be
    # reported from here so the reason reads as "nothing matched" and not "the
    # file publishes no figure".
    stripped = text
    for label in PUBLISHED_COPIES:
        stripped = re.sub(PATTERNS[label], "the checks", stripped, count=1)
    total, hits, problems = check_ledger.readme_catalog_figures(stripped)
    assert (total, hits["readme_total"]) == (None, [])
    assert len(problems) == 1
    assert "6 of them no longer match" in problems[0]


def test_any_one_copy_moving_resolves_to_no_figure_at_all():
    """Six bumps, one per published copy: each on its own reds the agreement.

    Every copy is bumped in turn because a pool is only as good as its worst
    member. A pattern that matched the day it was written and matches nothing now
    contributes no copy, and the five that remain agree without it -- which is
    what the exactly-once test above exists to catch, and what this one would
    otherwise hide behind five passing siblings.
    """
    text = readme_text()
    for label in PUBLISHED_COPIES:
        moved, moved_hits, moved_problems = check_ledger.readme_catalog_figures(
            bump(text, PATTERNS[label])
        )
        assert moved is None, f"bumping the {label} copy left the figure resolvable"
        assert len(moved_hits["readme_total"]) == 6
        assert moved_problems == [], "a moved copy is not a dead pattern"
        problems = check_ledger.figure_problems(
            "README.md", {"readme_total": moved}, moved_hits
        )
        assert len(problems) == 1
        assert "copies of readme_total that disagree" in problems[0]


def test_all_six_bumped_together_agree_with_each_other():
    """The negative control: internal agreement is not agreement with the code.

    A bump applied to all six copies resolves cleanly, so README's own agreement
    rule passes it and every assertion in this file except this one would pass
    with the figure ten too high. The comparison against the emitted ids is what
    catches it, which is why README is a side of the catalog total and not a
    check against itself. Measured through the gate on a transient edit: exit 1,
    naming its 4 sides with README at 209 and the other three at 208.

    This is the failure that shipped, not a hypothetical one: 80f9864 dropped
    SECURITY_CHECKS.md to 51 and left README at 52, where its copies agreed with
    each other for 46 days until an unrelated bump reset both to 116.
    """
    text = readme_text()
    total, _, _ = check_ledger.readme_catalog_figures(text)
    for label in PUBLISHED_COPIES:
        text = bump(text, PATTERNS[label])
    raised, hits, problems = check_ledger.readme_catalog_figures(text)
    assert raised == total + 1
    assert problems == []
    assert (
        check_ledger.figure_problems("README.md", {"readme_total": raised}, hits) == []
    )


def test_the_patterns_do_not_depend_on_the_line_wraps():
    """Unlike the census slice, this read is safe either side of the flatten.

    figure_occurrences() collapses whitespace, so these six patterns already
    match post-flatten text and handing them raw or flattened text is the same
    read. Asserted because the census paragraph next door is the opposite case,
    where slicing after the flatten returns nothing, and a reader who has that
    hazard in mind should not have to re-derive that this one is exempt.
    """
    assert check_ledger.readme_catalog_figures(
        readme_text()
    ) == check_ledger.readme_catalog_figures(re.sub(r"\s+", " ", readme_text()))


def test_gate_12_puts_readme_on_the_catalog_side_list():
    """The wiring, which no value test above can see.

    readme_catalog_figures() stays correct if the gate stops reading its result,
    and the gate stays green: all four sides read 208 here, so nothing about this
    branch's own files tells four sides from three.
    """
    with open(LEDGER) as f:
        source = f.read()
    assert '"README.md": readme_total' in source
    assert 'figure_problems("README.md", {"readme_total": readme_total}' in source
    # Both legs reach the drift list. The per-pattern one is a separate statement,
    # so it is separately droppable.
    assert "drift += readme_dead" in source
    # The side count in the failure message and in the verdict is derived from the
    # dict, so a fifth side cannot leave either of them still saying four.
    assert "disagrees across its three sides" not in source
    assert "catalog 3 sides" not in source
