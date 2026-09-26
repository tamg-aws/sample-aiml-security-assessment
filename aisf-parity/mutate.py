#!/usr/bin/env python3
"""Mutate the AISF derived-standard code and require the local gates to catch it.

A gate that stays green when the code is wrong is decoration. This applies the
defects this work could plausibly have shipped, one at a time, and requires that
something goes red: either a gate in `aisf-parity/check_ledger.py` or a test.
The catcher is OBSERVED, never assumed -- the gate name and the test node id are
parsed out of the run and printed. A hardcoded "this is caught by test X" list
has already been wrong in this project, in the flattering direction.

A mutation nothing catches is a FAILURE OF THE SUITE, not of the mutation. The
defect is shippable; the answer is an assertion, not a gentler mutation.

Every find-string is validated before the first mutation applies, and the run
prints `entries N/N find-strings validated`. A stale string is therefore one loud
failure naming every stale entry, never a battery that stops partway and reads as
a shorter complete run, which is how a 12-of-15 run came to be quoted as 12/12.

Safety. This script never restores with git. It snapshots bytes in memory and to
a `*.mutate-backup` file beside the target, restores from that, and proves the
restore with `diff -q` against the backup AND `git status --porcelain`. It also
fingerprints the whole tree: a test that writes files (the report generator
writes `test_reports/*.html`, which `.gitignore:45` hides from git) would
otherwise leave residue that no git check can see.

Usage:
    .venv/bin/python aisf-parity/mutate.py
    .venv/bin/python aisf-parity/mutate.py --tests tests/test_aisf_derived_standard.py
    .venv/bin/python aisf-parity/mutate.py --list

Exit codes:
    0  baseline green and every mutation caught
    1  a mutation was caught by nothing, or a baseline was not green
    2  usage/environment error, or a restore failed -- files may be dirty, READ IT
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

# This process must not write bytecode of its own, and neither must its children
# (PYTHONDONTWRITEBYTECODE below). Paired with purge_bytecode(), which deletes
# the cache entry for the file it is about to mutate.
sys.dont_write_bytecode = True

FAIL = 1
USAGE = 2
TIMEOUT = int(os.environ.get("AISF_MUTATE_TIMEOUT", "1800"))

MAPPINGS = (
    "aiml-security-assessment/functions/security/"
    "generate_consolidated_report/aisf_mappings.py"
)

BEDROCK = "aiml-security-assessment/functions/security/bedrock_assessments/app.py"

BUILD_LEDGER = "aisf-parity/build_ledger.py"

AISF_DOC = "docs/SECURITY_CHECKS_AISF.md"

# Phase 2's surfaces: the generated tag maps, the schema that looks a tag up, and
# the CSV fieldnames list a tag has to reach.
SECURITY = "aiml-security-assessment/functions/security"
MAP_SAGEMAKER = f"{SECURITY}/sagemaker_assessments/aisf_compliance_sagemaker.py"
MAP_AGENTCORE = f"{SECURITY}/agentcore_assessments/aisf_compliance_agentcore.py"
SCHEMA_BEDROCK = f"{SECURITY}/bedrock_assessments/schema.py"
AGENTCORE = f"{SECURITY}/agentcore_assessments/app.py"

# The generated tag maps, in the order partial_qualifier_mutation() reads them.
# Sorted paths, so two clones derive the same entry, and the sort happens to put
# agent_registry first, which is the map neither branch in flight rewrites.
TAG_MAP_GLOB = "*_assessments/aisf_compliance_*.py"

# One map entry whose value is a single tag carrying the `(partial)` qualifier.
# Anchored on the dict-entry shape because every map's module docstring documents
# the vocabulary with a bare "AISF <control> (partial)" line, and a scan that
# matched prose mutated a comment and left gate 14 green.
PARTIAL_ENTRY = re.compile(
    r'^(?P<indent>[ ]+)"(?P<check>[A-Z]{2,3}-\d{2})": '
    r'"AISF (?P<control>AIR(?:-[A-Z0-9]+)+) \(partial\)",$'
)

# Placeholder for the derived `(partial)` entry, replaced in resolve_mutations()
# before anything reads a find-string. A sentinel rather than an append, because
# the position of the entry is the position of the comment that explains it.
DERIVED_PARTIAL_QUALIFIER = "derive: the (partial) qualifier entry"

# Each find-string must occur EXACTLY ONCE in its file; the run aborts otherwise.
# That replaces the `nth` occurrence selector the prowler harness carries, whose
# 0-based field and 1-based display have mutated the wrong arm of a duplicated
# guard while the author believed otherwise. Uniqueness cannot be off by one.
MUTATIONS = [
    {
        "name": "collapse-note append removed",
        "file": MAPPINGS,
        "defect": "the severity downgrade stops being disclosed on every row, "
        "while the row still reports High for a critical control",
        "find": '                note = _collapse_note(mapping["risk"], status)\n'
        "                if note:\n"
        '                    details = f"{details} {note}"\n',
        "replace": '                note = _collapse_note(mapping["risk"], status)\n',
    },
    {
        "name": "N/A clause removed from the collapse note",
        "file": MAPPINGS,
        "defect": "an N/A row keeps the critical-band note without saying it "
        "carries Informational, so the note reads as a severity claim",
        "find": '    if note and status == "N/A":\n',
        "replace": "    if False:\n",
    },
    {
        "name": "critical maps to a lowercase severity (length-identical)",
        "file": MAPPINGS,
        "defect": "SeverityEnum has no lowercase member, so this is the "
        "fail-open shape: same byte count, so mtime+size pyc invalidation "
        "cannot see it, and a stale cache would report the old value",
        "find": '    "critical": "High",\n',
        "replace": '    "critical": "high",\n',
    },
    {
        "name": "AISF-05 reverted to the pre-rename AI-05",
        "file": MAPPINGS,
        "defect": "one row keeps the short prefix, which routes by "
        "check_id.split('-')[0] and misfiles silently under a wrong service",
        "find": '        "check_id": "AISF-05",\n',
        "replace": '        "check_id": "AI-05",\n',
    },
    {
        "name": "S3 Vectors CMK test accepts any sseType",
        "file": BEDROCK,
        "defect": "AES256 (SSE-S3) passes BR-20's encryption leg, so a vector "
        "store on the service default key reports as customer-managed. SSE-S3 is "
        "the default for any vector bucket created without an "
        "encryptionConfiguration, and S3 Vectors has no Put*Encryption operation "
        "to fix one afterwards, so this mutation reports the rows a customer can "
        "only remediate by re-ingesting as already compliant",
        "find": '    encryption_ok = encryption.get("sseType") == "aws:kms" '
        "and bool(kms_key_arn)\n",
        "replace": '    encryption_ok = bool(encryption.get("sseType"))\n',
    },
    {
        "name": "S3 Vectors missing bucket policy reverted to N/A",
        "file": BEDROCK,
        "defect": "NotFoundException from GetVectorBucketPolicy is laundered "
        "into a could-not-assess, which is how BR-20 came to emit 9 N/A rows "
        "for 9 knowledge bases it could in fact assess",
        "find": '        if error_code == "NotFoundException":\n',
        "replace": '        if error_code == "NotFoundException":\n'
        "            policy_unreadable = error_code\n",
    },
    {
        "name": "S3 Vectors index encryption accepts any sseType",
        "file": BEDROCK,
        "defect": "an index created with its own AES256 encryptionConfiguration "
        "passes BR-20's index leg, so the override that decides what the "
        "embeddings are actually encrypted with reads as customer-managed. The "
        "same fail-open shape as the bucket leg above, on the member that wins",
        "find": '            elif index_sse == "aws:kms" and index_kms_key_arn:\n',
        "replace": "            elif bool(index_sse):\n",
    },
    {
        "name": "the index verdict dropped from the S3 Vectors combine",
        "file": BEDROCK,
        "defect": "the index leg is read, named in the finding detail, and then "
        "not counted: an aws:kms bucket holding an AES256 index falls through to "
        "Passed while the row says the index is AES256. A leg that reports but "
        "does not decide is the shape a reader cannot tell from a working one",
        "find": "    if not encryption_ok or index_failed:\n",
        "replace": "    if not encryption_ok:\n",
    },
    {
        "name": "an index inheriting the bucket's key is failed",
        "file": BEDROCK,
        "defect": "the opposite direction: an index created without an "
        "encryptionConfiguration inherits the bucket's, which is what a "
        "compliant store looks like, and this fails every one of them. A "
        "false positive on the majority shape is as unshippable as a fail-open",
        "find": "            if not index_encryption:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "the knowledge base loop truncated to the first entry",
        "file": BEDROCK,
        "defect": "BR-20 assesses one knowledge base per region and reports its "
        "verdict for all of them. Every single-store case in the suite still "
        "passes, because one resource cannot tell a loop from a first-element "
        "read",
        "find": "            for kb_summary in knowledge_bases:\n",
        "replace": "            for kb_summary in knowledge_bases[:1]:\n",
    },
    {
        "name": "source findings collapsed to one status per check id",
        "file": MAPPINGS,
        "defect": "a check's findings overwrite each other, so a Failed resource "
        "followed by the check's summary Passed row publishes Passed -- BR-20 "
        "emits in exactly that order, and one account showed 16 findings on a "
        "single leg",
        "find": "            legs.setdefault(key, {})."
        'setdefault(row["check_id"].upper(), []).append(\n'
        '                row["status"]\n'
        "            )\n",
        "replace": "            legs.setdefault(key, {})["
        'row["check_id"].upper()] = [row["status"]]\n',
    },
    {
        "name": "ledger markdown renders a figure from the wrong summary key",
        "file": BUILD_LEDGER,
        "defect": "the generated markdown reports the total control count where "
        "the covered count belongs, and the committed markdown is not "
        "regenerated -- the mtime version of gate 10 could not see this at all, "
        "because a renderer edit does not touch either artifact",
        "find": "        f\"| covered | {s['covered']} | an incumbent already "
        'asserts this; nothing to write |"\n',
        "replace": "        f\"| covered | {s['total']} | an incumbent already "
        'asserts this; nothing to write |"\n',
    },
    # ---------------------------------------------------------------- phase 2
    # The tag column. The next two entries are the two halves of the qualifier
    # vocabulary and are both here because they fail different branches of the
    # same gate: a `tighten` row wants `(partial)`, a multi-leg `covered` row
    # wants `(1 of N checks)`. An earlier hand-run of the first hit the
    # `(partial)` in a map's own module docstring instead of a map entry, which
    # left gate 14 green and looked like a weak gate, so both find-strings carry
    # the whole map entry including its check id and cannot drift onto prose.
    # They are referred to by name and not by position: inserting a mutation
    # renumbers every one after it.
    #
    # The `(partial)` half is DERIVED at run time, not written here. Naming a
    # check id has gone stale twice: the entry named BR-04 until 8faf24f retired
    # bedrock's qualifiers, and AC-07, which replaced it, is one of the three
    # agentcore tags feature/aisf-phase4-acr converts to `(1 of N checks)`. The
    # vocabulary is being retired map by map, so this reads the maps instead of
    # naming one. See partial_qualifier_mutation().
    DERIVED_PARTIAL_QUALIFIER,
    {
        "name": "a (1 of N checks) qualifier dropped from a joint leg",
        "file": MAP_SAGEMAKER,
        "defect": "SM-01 claims to assert AIR-SGM-TRN-05 alone, when the ledger "
        "names three incumbents for it; a reader who sees SM-01 Passed concludes "
        "the control is met without SM-03 or SM-09 having run",
        "find": '    "SM-01": "AISF AIR-SGM-TRN-05 (1 of 3 checks)",\n',
        "replace": '    "SM-01": "AISF AIR-SGM-TRN-05",\n',
    },
    {
        "name": "a tag placed in a module that does not emit the check",
        "file": MAP_AGENTCORE,
        "defect": "the lookup runs inside the producer that emits the check, so "
        "a BR-10 entry in agentcore's map is never consulted and BR-10's rows "
        "ship untagged. The symptom is an empty column, not an error, which is "
        "why ownership is asserted rather than assumed",
        "find": '    "AC-02": ',
        "replace": '    "BR-10": "AISF AIR-BDR-GRD-01",\n    "AC-02": ',
    },
    {
        "name": "the tag sentinel defaults to empty instead of None (length-identical)",
        "file": SCHEMA_BEDROCK,
        "defect": "create_finding only looks a tag up when the argument is None, "
        'so defaulting to "" makes every bedrock row untagged while the column '
        "still exists and every CSV still validates. Same byte count, so a stale "
        "pyc keyed on mtime and size cannot see the edit either",
        "find": "    compliance_frameworks: Optional[str] = None,\n",
        "replace": '    compliance_frameworks: Optional[str] = "",\n',
    },
    {
        "name": "agentcore's empty-report header loses the column",
        "file": AGENTCORE,
        "defect": "agentcore builds its fieldnames twice, and only the "
        "no-findings branch is mutated here: an empty report ships 8 columns and "
        "a populated one 9, so a consumer concatenating reports across accounts "
        "sees the column appear and disappear rather than a failure",
        "find": '                "Region",\n                "Compliance_Frameworks",\n',
        "replace": '                "Region",\n',
    },
    # ------------------------------------------------------ the census paragraph
    # The first mutation of a document rather than of code, and it breaks the
    # anchor instead of a figure. The ledger reads its six census figures out of one
    # paragraph, located by this sentence, and returns an empty slice when the
    # sentence is not found exactly once. Nothing proved that fail-closed path
    # fired.
    #
    # The anchor is the find-string because it is the only candidate unique at
    # every ref this battery runs at. Counted as raw bytes, no flattening:
    # "Census at the current head" is 1 at this base, on this branch, at phase 3's
    # head and in the merge tree, while a figure phrase moves with the branch --
    # "; the remaining 28 are `tighten`.\n" is 1/1/0/0 because phase 3 rewords the
    # clause, and "the 28 `covered` controls" is 0 everywhere because the document
    # wraps inside the phrase, which a flattened extractor finds and a find-string
    # never will.
    {
        "name": "the census anchor sentence is reworded",
        "file": AISF_DOC,
        "defect": "the ledger locates the census paragraph by this sentence and "
        "reads its six published figures from that slice alone. A reworded "
        "anchor has to return zero paragraphs, report the count and the sentence "
        "it looked for, and leave the six figures absent; the failure it must "
        "not become is a widening back to the whole 23 KB document, where at "
        "phase 3's head a coverage bullet 239 lines above the anchor answers the "
        "covered pattern with a different population",
        "find": "Census at the current head",
        "replace": "Census at the present head",
    },
]

# Directories whose contents are generated by the suites and hidden from git by
# `.gitignore:45:**/test_reports/`. Their bytes are snapshotted so a mutation
# that provokes a rewrite can be undone rather than merely reported.
ARTIFACT_DIR = "test_reports"
WALK_SKIP = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}


def die(msg: str, code: int = USAGE) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def partial_qualifier_mutation(repo: Path) -> dict[str, str]:
    """Build the `(partial)` mutation from whichever map still carries one.

    Reads the maps in sorted path order and takes the first single-tag
    `(partial)` entry, so the entry survives a rename, a re-hosting, and the
    conversion of any one map's qualifiers. When no map carries one, this fails
    loudly instead of skipping: an absent qualifier means gate 14's qualifier
    branch has nothing left to break, which is a fact about the maps that the
    reader of a mutation report has to be told, not a mutation to drop.
    """
    maps = sorted((repo / SECURITY).glob(TAG_MAP_GLOB))
    if not maps:
        die(f"no tag maps under {repo / SECURITY}/{TAG_MAP_GLOB}")
    for path in maps:
        for line in path.read_text(encoding="utf-8").splitlines():
            found = PARTIAL_ENTRY.match(line)
            if not found:
                continue
            check, control = found["check"], found["control"]
            return {
                "name": f"a (partial) qualifier dropped from {check}'s tag",
                "file": path.relative_to(repo).as_posix(),
                "defect": (
                    f"{check}'s tag reads as a full assertion of {control}, a "
                    "control the ledger says it only partly covers, so a Passed "
                    f"{check} row publishes a pass against the whole control, "
                    "the same overclaim gate 11 refuses for the derived AISF- "
                    "rows, arriving by the other surface"
                ),
                "find": f"{line}\n",
                "replace": f'{found["indent"]}"{check}": "AISF {control}",\n',
            }
    die(
        "no tag map carries a single-tag (partial) entry, so this mutation has "
        f"nothing to break. Maps read, in order: "
        f"{', '.join(p.relative_to(repo).as_posix() for p in maps)}.\n"
        "  If the qualifier has been retired on purpose, delete the derived "
        "entry and say so in the commit; do not leave a mutation that cannot "
        "apply, because the run would abort partway and read as a short pass."
    )
    raise AssertionError("unreachable: die() raises")


def resolve_mutations(repo: Path) -> list[dict[str, str]]:
    """MUTATIONS with every derived entry built against this tree."""
    return [
        partial_qualifier_mutation(repo)
        if entry == DERIVED_PARTIAL_QUALIFIER
        else entry
        for entry in MUTATIONS
    ]


def child_env() -> dict[str, str]:
    """The environment the three CI pytest sessions use, plus pyc suppression.

    Without the bucket name and credentials the module-level boto3 clients in
    the assessment packages raise at import, which errors whole sessions out --
    a different failure from the red test a mutation is supposed to cause.
    """
    return {
        **os.environ,
        "AIML_ASSESSMENT_BUCKET_NAME": os.environ.get(
            "AIML_ASSESSMENT_BUCKET_NAME", "test-assessment-bucket"
        ),
        "AWS_DEFAULT_REGION": os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",  # pragma: allowlist secret
        "PYTHONDONTWRITEBYTECODE": "1",
    }


PURGE_SRC = """
import importlib.util
import os
import sys

removed = []
for src in sys.argv[1:]:
    cache = importlib.util.cache_from_source(src)
    if os.path.exists(cache):
        os.remove(cache)
        removed.append(cache)
print(f"{len(removed)} removed; cache path is {importlib.util.cache_from_source(sys.argv[1])}")
"""


def purge_bytecode(python: Path, path: Path) -> str:
    """Delete the cached bytecode for one source file, via the interpreter that
    will import it.

    `importlib.util.cache_from_source` is the only correct way to name that
    file: a hand-built `<dir>/__pycache__/<stem>.cpython-312.pyc` path ignores
    `pycache_prefix`, which relocates the whole cache tree, and the macOS
    platform python sets one. Computing it in the CHILD matters for the same
    reason -- the prefix is a property of the interpreter doing the import.

    Why this is load-bearing here: CPython invalidates a .pyc by (source mtime
    in WHOLE SECONDS, source size). The `critical` mutation is byte-identical in
    length, so a mutation applied in the same second as the snapshot read is
    invisible to that check and the old bytecode is served -- the mutation would
    be reported as caught-by-nothing when it was never actually loaded.
    """
    result = subprocess.run(
        [str(python), "-c", PURGE_SRC, str(path)],
        capture_output=True,
        text=True,
        env=child_env(),
        check=False,
    )
    return (result.stdout or result.stderr).strip()


def run_ledger(python: Path, repo: Path) -> tuple[bool, str, list[str]]:
    """Catcher 1: the ledger gates. Returns (green, summary, failing gate names)."""
    result = subprocess.run(
        [str(python), "aisf-parity/check_ledger.py"],
        cwd=repo,
        capture_output=True,
        text=True,
        env=child_env(),
        check=False,
        timeout=TIMEOUT,
    )
    out = result.stdout + result.stderr
    failed = [
        line.split(":", 1)[0].removeprefix("[FAIL] ").strip()
        for line in out.splitlines()
        if line.startswith("[FAIL] ")
    ]
    summary = next(
        (ln.strip() for ln in out.splitlines() if "gates passed" in ln),
        "(no summary line)",
    )
    # rc==0 alone is not the verdict: a ledger that printed nothing at all also
    # exits 0 if its gate list is empty, and that is not a green run.
    green = result.returncode == 0 and not failed and "gates passed" in out
    return green, summary, failed


def run_pytest(
    python: Path, repo: Path, cwd: Path, target: str
) -> tuple[bool, str, list[str]]:
    """Catcher 2: a pytest target. Returns (green, tail, failing node ids).

    `-rf` forces the short failure list even under `-q`, which is what makes the
    catcher observed instead of inferred. `-p no:randomly` keeps two runs of the
    same mutation comparable.
    """
    result = subprocess.run(
        [
            str(python),
            "-m",
            "pytest",
            target,
            "-q",
            "--tb=no",
            "-rf",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:randomly",
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=child_env(),
        check=False,
        timeout=TIMEOUT,
    )
    out = result.stdout + result.stderr
    failed = [
        line.removeprefix("FAILED ").split(" - ")[0].strip()
        for line in out.splitlines()
        if line.startswith("FAILED ")
    ]
    lines = [ln for ln in out.strip().splitlines() if ln.strip()]
    tail = lines[-1] if lines else "(no output)"
    # An empty collection exits 4 or 5 and prints a calm one-liner. Requiring a
    # passed count means the path trap in gate_all.sh cannot read as green here.
    green = result.returncode == 0 and "passed" in tail
    return green, tail, failed


def fingerprint(repo: Path) -> dict[str, str]:
    """sha256 of every tracked-or-not file in the tree, excluding caches.

    197 files here, 5ms. This is the only detector that can see a rewritten
    `test_reports/*.html`, because git cannot: the path is gitignored.
    """
    prints: dict[str, str] = {}
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in WALK_SKIP]
        for name in files:
            if name.endswith(".mutate-backup"):
                continue
            path = Path(root) / name
            try:
                prints[str(path.relative_to(repo))] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
            except OSError:
                continue
    return prints


def artifact_bytes(repo: Path) -> dict[str, bytes]:
    """Bytes of the generated report artifacts, so a rewrite can be undone."""
    return {
        str(p.relative_to(repo)): p.read_bytes()
        for p in repo.rglob(f"{ARTIFACT_DIR}/*")
        if p.is_file() and ".venv" not in p.parts
    }


def reconcile(
    repo: Path, before: dict[str, str], keep: dict[str, bytes]
) -> tuple[list[str], list[str]]:
    """Undo tree changes a mutation's test run left behind.

    Returns (cleaned, unresolved). A generated artifact is restored or removed
    and reported; anything else is unresolved and the caller must stop, because
    an unexplained new file in a shared checkout is not this script's to delete.
    """
    after = fingerprint(repo)
    cleaned: list[str] = []
    unresolved: list[str] = []
    for rel in sorted(set(after) | set(before)):
        if before.get(rel) == after.get(rel):
            continue
        if rel in keep:
            (repo / rel).write_bytes(keep[rel])
            cleaned.append(f"restored generated artifact {rel}")
        elif rel not in before and f"/{ARTIFACT_DIR}/" in f"/{rel}":
            (repo / rel).unlink(missing_ok=True)
            cleaned.append(f"removed new generated artifact {rel}")
        else:
            state = (
                "appeared"
                if rel not in before
                else "vanished"
                if rel not in after
                else "changed"
            )
            unresolved.append(f"{rel} {state}")
    return cleaned, unresolved


def porcelain(repo: Path, rel: str) -> str:
    result = subprocess.run(
        ["git", "--no-optional-locks", "status", "--porcelain", "--", rel],
        cwd=repo,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    default_repo = Path(__file__).resolve().parent.parent
    ap.add_argument("--repo", type=Path, default=default_repo)
    ap.add_argument(
        "--tests",
        default="tests/",
        help="pytest target used as the second catcher (default: tests/)",
    )
    ap.add_argument(
        "--tests-cwd",
        default="",
        help="working directory for --tests, relative to the repo. CI runs the "
        "report-generator tests from their own directory, and that is the run "
        "that rewrites test_reports/*.html.",
    )
    ap.add_argument("--list", action="store_true", help="print the mutations and exit")
    args = ap.parse_args()

    repo = args.repo.expanduser().resolve()
    mutations = resolve_mutations(repo)

    if args.list:
        for index, mutation in enumerate(mutations, 1):
            print(
                f"  [{index}] {mutation['name']}\n        defect: {mutation['defect']}"
            )
        print(f"\n{len(mutations)} mutation(s) defined")
        return 0

    python = repo / ".venv" / "bin" / "python"
    if not python.is_file():
        die(f"no interpreter at {python} (python3 -m venv .venv)")
    tests_cwd = (repo / args.tests_cwd).resolve() if args.tests_cwd else repo
    if not tests_cwd.is_dir():
        die(f"--tests-cwd {tests_cwd} is not a directory")

    # ---------------------------------------------------------------- snapshot
    touched = sorted({m["file"] for m in mutations})
    snapshots: dict[str, str] = {}
    for rel in touched:
        path = repo / rel
        if not path.is_file():
            die(f"mutation target absent: {path}")
        backup = repo / f"{rel}.mutate-backup"
        if backup.exists():
            # REFUSE A POISONED BASELINE. A run killed mid-mutation leaves the
            # target holding the mutation and a backup beside it. Snapshotting
            # that as pristine measures every mutation against a mutated
            # baseline and reports uncaught defects that are pure artifact.
            die(
                f"{rel}.mutate-backup exists -- a previous run died mid-mutation, "
                f"so {rel} cannot be trusted as a baseline.\n"
                f"  1. Read both: git diff -- {rel}  and  diff {rel}.mutate-backup {rel}\n"
                f"  2. Decide which content is correct. Do NOT assume the backup is "
                f"clean: it may hold the mutation, which is why this guard exists.\n"
                f"  3. Restore that content, delete the backup, re-run.\n"
                f"  No overwrite command is offered on purpose -- the file may also "
                f"hold unrelated work, and a blind restore takes it with it."
            )
        if porcelain(repo, rel):
            # A stale stat-cache has false-positived this check on a clean tree
            # before. Refreshing is cheap; a guard whose remedy is destructive
            # must not fire on a clean file.
            subprocess.run(
                ["git", "update-index", "--refresh"],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
        if porcelain(repo, rel):
            die(
                f"{rel} is modified relative to HEAD. A mutation verdict only means "
                f"something against a committed baseline: an uncommitted edit is "
                f"indistinguishable from a defect nothing caught.\n"
                f"  INSPECT FIRST, do not blind-overwrite: git diff -- {rel}\n"
                f"  Then commit it, or stash it (git stash push -- {rel}), or if you "
                f"have READ the diff and are certain, discard it explicitly."
            )
        snapshots[rel] = path.read_text(encoding="utf-8")
        backup.write_text(snapshots[rel], encoding="utf-8")

    def restore() -> None:
        for rel, content in snapshots.items():
            (repo / rel).write_text(content, encoding="utf-8")

    def abort(msg: str, code: int = USAGE) -> None:
        restore()
        for rel in snapshots:
            (repo / f"{rel}.mutate-backup").unlink(missing_ok=True)
        die(msg, code)

    print(f"repo      {repo}")
    print(f"python    {python}")
    print(f"catchers  ledger gates (aisf-parity/check_ledger.py) + pytest {args.tests}")
    print(f"          pytest cwd: {tests_cwd}")
    print(f"snapshot  {len(touched)} file(s), backups written as *.mutate-backup")

    # ------------------------------------------------------------- pre-flight
    # Every find-string, validated before the first mutation applies. This check
    # used to sit inside the mutation loop, where one stale string aborted the
    # battery partway and the run read as a shorter complete one: on 2026-09-25 a
    # dead entry 13 of 15 printed twelve CAUGHT lines above the abort and was
    # quoted as 12/12. Validating up front turns that into one loud failure that
    # names every stale entry, and the count below is what a report should quote.
    stale = [
        f"[{index}] {mutation['name']}: {occurrences} occurrence(s) in "
        f"{mutation['file']}"
        for index, mutation in enumerate(mutations, 1)
        if (occurrences := snapshots[mutation["file"]].count(mutation["find"])) != 1
    ]
    if stale:
        abort(
            f"{len(stale)} of {len(mutations)} find-string(s) do not occur exactly "
            "once in their file, so this battery cannot run. Refresh each against "
            "the current code; do not guess which occurrence was meant:\n  "
            + "\n  ".join(stale)
        )
    print(f"entries   {len(mutations)}/{len(mutations)} find-strings validated")

    # Every target, not just the first: a stale .pyc for the SECOND file would
    # serve the pre-mutation bytecode to the baseline run and to any mutation
    # whose byte count matches, and the length-identical `critical` mutation is
    # exactly that case.
    for rel in touched:
        print(f"bytecode  {rel}\n          {purge_bytecode(python, repo / rel)}")

    base_prints = fingerprint(repo)
    base_artifacts = artifact_bytes(repo)
    print(
        f"tree      {len(base_prints)} file(s) fingerprinted, "
        f"{len(base_artifacts)} generated artifact(s) held for restore"
    )

    # ---------------------------------------------------------------- baseline
    print(
        "\n=== baseline: both catchers must be GREEN before a verdict means anything ==="
    )
    led_green, led_summary, _ = run_ledger(python, repo)
    pyt_green, pyt_tail, _ = run_pytest(python, repo, tests_cwd, args.tests)
    print(f"  {'PASS' if led_green else 'FAIL'}  ledger: {led_summary}")
    print(f"  {'PASS' if pyt_green else 'FAIL'}  tests:  {pyt_tail}")
    cleaned, unresolved = reconcile(repo, base_prints, base_artifacts)
    for line in cleaned:
        print(f"        baseline artifact: {line}")
    if unresolved:
        abort(
            "baseline run changed files this script cannot attribute: "
            + "; ".join(unresolved)
        )
    if not (led_green and pyt_green):
        abort(
            "baseline is not green -- fix that first. Every mutation verdict below "
            "would be measured against a red suite.",
            FAIL,
        )

    # --------------------------------------------------------------- mutations
    print(
        f"\n=== {len(mutations)} mutation(s); each must be caught by a gate or a test ==="
    )
    uncaught: list[str] = []
    artifacts_cleaned = 0
    for index, mutation in enumerate(mutations, 1):
        rel = mutation["file"]
        text = snapshots[rel]
        mutated = text.replace(mutation["find"], mutation["replace"])
        if mutated == text:
            abort(f"mutation {index} changed nothing -- find and replace are identical")
        (repo / rel).write_text(mutated, encoding="utf-8")
        purge_bytecode(python, repo / rel)

        # PROVE it is on disk. A harness that printed APPLY-FAIL and exited 0 read
        # as "nothing to worry about" when its find-string had gone stale. A
        # mutation that never applied is an untested assertion, not a pass.
        if (repo / rel).read_text(encoding="utf-8") == text:
            abort(f"mutation {index} ({mutation['name']}) did NOT change {rel} on disk")

        try:
            led_green, led_summary, led_failed = run_ledger(python, repo)
            pyt_green, pyt_tail, pyt_failed = run_pytest(
                python, repo, tests_cwd, args.tests
            )
        finally:
            # Restore on EVERY exit path, before anything else can observe a
            # mutated tree. A timeout or a KeyboardInterrupt here is exactly the
            # case where the mutation would otherwise be left on disk.
            restore()
            purge_bytecode(python, repo / rel)

        # Two independent restore proofs. `diff -q` compares against the backup
        # file written before the run; git compares against HEAD. The in-memory
        # snapshot compare can agree with itself and still be wrong.
        diff = subprocess.run(
            ["diff", "-q", str(repo / f"{rel}.mutate-backup"), str(repo / rel)],
            capture_output=True,
            text=True,
            check=False,
        )
        dirty = porcelain(repo, rel)
        if diff.returncode != 0 or dirty:
            die(
                f"mutation {index} left {rel} NOT restored:\n"
                f"  diff -q: rc={diff.returncode} {diff.stdout.strip()}\n"
                f"  git status --porcelain: {dirty or '(clean)'}\n"
                f"Recover from {rel}.mutate-backup, which is left in place. Do NOT commit.",
                USAGE,
            )

        cleaned, unresolved = reconcile(repo, base_prints, base_artifacts)
        artifacts_cleaned += len(cleaned)
        for line in cleaned:
            print(f"        artifact: {line}")
        if unresolved:
            die(
                f"mutation {index} changed files this script cannot attribute: "
                + "; ".join(unresolved)
                + f"\nThe source file itself restored cleanly; {rel}.mutate-backup is "
                "left in place. Investigate before committing.",
                USAGE,
            )

        caught_by = []
        if led_failed:
            caught_by.append(
                f"ledger: {len(led_failed)} gate(s) red, first: {led_failed[0]}"
            )
        elif not led_green:
            caught_by.append(f"ledger: not green but named no gate -- {led_summary}")
        if pyt_failed:
            caught_by.append(f"tests:  {len(pyt_failed)} red, first: {pyt_failed[0]}")
        elif not pyt_green:
            caught_by.append(f"tests:  not green but named no test -- {pyt_tail}")

        if caught_by:
            print(f"  [{index}] CAUGHT   {mutation['name']}")
            for line in caught_by:
                print(f"        {line}")
        else:
            print(f"  [{index}] UNCAUGHT {mutation['name']}")
            print(f"        defect: {mutation['defect']}")
            print(f"        ledger stayed green: {led_summary}")
            print(f"        tests stayed green:  {pyt_tail}")
            print("        SUITE FAILURE: this defect ships undetected. Add an")
            print("        assertion or a gate -- do not soften the mutation.")
            uncaught.append(mutation["name"])

    # ----------------------------------------------------------------- verdict
    if any(
        (repo / rel).read_text(encoding="utf-8") != content
        for rel, content in snapshots.items()
    ):
        die(
            "RESTORE VERIFICATION FAILED at exit -- the tree does not match the "
            f"snapshot. Recover from the *.mutate-backup files beside {touched}.",
            USAGE,
        )
    for rel in touched:
        (repo / f"{rel}.mutate-backup").unlink(missing_ok=True)
    print("\nrestore verified byte-identical against the snapshot; backups removed")

    print("=== post-restore baseline (proves the tree is what it was) ===")
    led_green, led_summary, _ = run_ledger(python, repo)
    pyt_green, pyt_tail, _ = run_pytest(python, repo, tests_cwd, args.tests)
    print(f"  {'PASS' if led_green else 'FAIL'}  ledger: {led_summary}")
    print(f"  {'PASS' if pyt_green else 'FAIL'}  tests:  {pyt_tail}")
    cleaned, unresolved = reconcile(repo, base_prints, base_artifacts)
    artifacts_cleaned += len(cleaned)
    for line in cleaned:
        print(f"        artifact: {line}")
    if unresolved:
        die(
            "post-restore run changed files this script cannot attribute: "
            + "; ".join(unresolved)
        )
    if not (led_green and pyt_green):
        die(
            "a catcher is red AFTER restore -- the tree is not what it was. Investigate."
        )

    caught = len(mutations) - len(uncaught)
    totals = (
        f"{caught}/{len(mutations)} mutations caught, "
        f"{2 * len(mutations)} catcher run(s) (2 per mutation), "
        f"{artifacts_cleaned} generated artifact(s) cleaned"
    )
    print()
    if uncaught:
        print(f"GATE FAIL  {totals}")
        for name in uncaught:
            print(f"  uncaught: {name}")
        return FAIL
    print(f"GATE PASS  {totals}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
