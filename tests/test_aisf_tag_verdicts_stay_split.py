"""The three AISF tag-column claims stay three verdicts with three names.

One boolean under one name used to cover all three claims -- the per-module tag
maps, the tag-column figures the AISF document publishes, and its census
paragraph. Four mutations with unrelated causes printed the same gate name as
their first red, so the name told a reader nothing about which claim broke. The
split is only useful while it survives, and re-pooling the three back under one
verdict is a two-line edit that nothing else here would notice: the battery
derives its sub-gate count from the output and cross-checks it against the
summary, so both numbers move together and stay consistent.

Read from check_ledger.py alone, which is what makes this merge-safe. It asserts
no gate number, no letter, no printed position and no denominator. All four move
legitimately. The split gave its legs letters instead of new numbers, because the
number they share is cited throughout the documentation and the generated map
headers; the gates that follow them now print later than the numbers their own
comments use; and the sub-gate total changes whenever a gate is added. So no
count of any of those appears below, in an assertion or in this note.

Source and not stdout, for a measured reason. check_ledger.py's main() calls
load_aisf_classification() before it prints anything, and that opens a path under
AISF_REPO, which is os.path.expanduser'd into a sibling clone. Run with that
clone unreachable, main() raises FileNotFoundError at its first statement and
prints zero verdict lines -- not just these three. `tests/` runs in GitHub Actions
on every pull request to main against a bare checkout with no sibling clone
(.github/workflows/python-tests.yml), so a test that executes the ledger would
red there on every run for a reason unrelated to the gate. Skipping when the
clone is absent would retire the test exactly where it is cheapest to break.

The first substring is "per-module AISF tag maps" and not "tag maps". The gate
that renders the maps fresh from the ledger and compares them carries "tag maps"
in its own name, so requiring one match for the shorter string reds at green.
Loosening the rule to at-least-one instead would stop the count of three from
meaning three separate verdicts, which is the property.

Not covered: that the three calls are reached. A call site guarded out of the
run would satisfy every assertion below. gate_all.sh closes that leg from the
other side, by counting the printed verdicts and failing when the count and the
summary disagree.
"""

import ast
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO, "aisf-parity", "check_ledger.py")

# Each identifies one leg and appears in exactly one gate name. Each is drawn
# from the claim its leg makes, so a reword that keeps the claim keeps the
# substring, and no substring depends on where the leg prints.
LEG_SUBSTRINGS = (
    "per-module AISF tag maps",
    "tag-column figures",
    "census paragraph",
)


def gate_calls():
    """Every `gate(...)` call site in check_ledger.py, sorted by line.

    ast.walk yields breadth-first, so the sort is what makes a failure message
    name the same line numbers on every run. Nothing below asserts the order.
    """
    with open(LEDGER) as f:
        tree = ast.parse(f.read())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "gate"
    ]
    return sorted(calls, key=lambda node: node.lineno)


def named_gates():
    """(name, call) for every gate call whose name is a plain string literal.

    A name built at runtime is skipped here and so drops out of the counts
    below. That reds; it does not pass.
    """
    out = []
    for call in gate_calls():
        first = call.args[0] if call.args else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            out.append((first.value, call))
    return out


def test_the_population_of_gate_calls_is_not_empty():
    """Before any per-substring count, since zero would satisfy no-match rules.

    Asserted first for the same reason the gates print their denominators: a
    predicate over nothing is not a pass. No figure is pinned -- the count of
    gate calls moves whenever a gate is added.
    """
    calls = gate_calls()
    named = named_gates()
    assert calls, f"no gate() call sites parsed out of {LEDGER}"
    assert len(named) == len(calls), (
        f"{len(calls) - len(named)} of {len(calls)} gate() call sites do not "
        "name themselves with a string literal, so their names cannot be read"
    )


def test_each_of_the_three_claims_is_a_verdict_of_its_own():
    """Three substrings, one gate name each, three distinct names."""
    matched = {}
    for substring in LEG_SUBSTRINGS:
        hits = [name for name, _ in named_gates() if substring in name]
        assert len(hits) == 1, (
            f"{len(hits)} gate name(s) contain {substring!r}, expected 1: {hits}"
        )
        matched[substring] = hits[0]

    assert len(set(matched.values())) == 3, (
        "the three claims resolve to fewer than three distinct gate names, so "
        f"at least two share a verdict: {matched}"
    )


def test_the_three_verdicts_do_not_share_one_predicate():
    """Three separate names over one pooled boolean is the subtler re-pool.

    Each call's second argument is its verdict. Three calls reading the same
    expression print three names that cannot disagree, which loses the same
    information as merging them into one call.
    """
    predicates = {}
    for substring in LEG_SUBSTRINGS:
        for name, call in named_gates():
            if substring in name:
                predicates[substring] = ast.unparse(call.args[1])

    assert len(predicates) == 3, f"expected a predicate per claim, read {predicates}"
    assert len(set(predicates.values())) == 3, (
        f"the three verdicts share a predicate: {predicates}"
    )
