#!/usr/bin/env python3
"""Assert the push about to be run is safe, and audit the battery that vouches for it.

This authorises ONE specific command, which is why the command itself is an argument
instead of being inferred: a check that guesses `git push origin <branch>` says
nothing about the `--force` the operator actually typed.

    .venv/bin/python aisf-parity/push_safety.py --battery-output /tmp/battery.txt \\
        -- git push origin feature/aisf-report-section

Nothing here pushes, fetches or writes. Every git call is read-only.

The battery output is REQUIRED and fail-closed: a push with no recorded gate run is
not a verified push, and an absent recording is treated as a failed assertion rather
than as an unknown. The self-audit re-reads that recording and compares the gate names
in it against the gate list `aisf-parity/gate_all.sh` defines, so a gate that silently
stopped running cannot pass as green -- the recording being at a different commit than
HEAD is itself a failure, because a recording of other code proves nothing about this
push.

Exit codes:
    0  every assertion passed
    1  at least one assertion failed -- DO NOT PUSH
    2  usage error, or nothing could be measured (never read as a pass)
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

FAIL = 1
USAGE = 2

# The user's own fork. Anything else, and in particular the aws-samples upstream, is
# not a destination this work may reach by accident.
FORK_URL = "git@github.com:tamg-aws/sample-aiml-security-assessment.git"
UPSTREAM_REMOTE = "upstream"
UPSTREAM_MARKER = "aws-samples/"
PROTECTED_BRANCHES = {"main", "master"}

# A pushable URL shape. `upstream`'s push URL here is the string
# "no-push-aws-samples", which matches none of these, and that is the point: git
# rejects it before it can reach a network. Note the substring "aws-samples" appears
# in that sentinel, so the upstream test below matches "aws-samples/" WITH the slash.
URL_SHAPES = ("git@", "ssh://", "https://", "http://", "git://", "file://", "/")

SECRET_PATHS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.pfx",
    "*.p12",
    "*secret*",
    "*credentials*",
    "id_rsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
)

SECRET_CONTENT = (
    ("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("aws_secret_access_key assignment", r"(?i)aws_secret_access_key\s*[=:]\s*\S"),
    ("private key block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    (
        "quoted credential literal",
        r"""(?i)\b(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*["'][^"'\n]{8,}["']""",
    ),
    ("slack token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("github token", r"gh[pousr]_[0-9A-Za-z]{20,}"),
)

# detect-secrets' marker, already used in this repo on lines that name a variable
# rather than a value. It is a fail-open path, so every skipped line is PRINTED: a
# suppression nobody reads is how a real credential gets through behind a pragma.
ALLOWLIST_MARKER = "pragma: allowlist secret"

ATTRIBUTION = (
    ("Co-Authored-By trailer", r"(?i)^\s*co-authored-by:"),
    ("generated-with attribution", r"(?i)generated with \[?claude"),
    ("assistant name in the message", r"(?i)\b(claude|copilot|chatgpt|gpt-[45])\b"),
    ("robot emoji attribution", "\U0001f916"),
)

# Force and force-adjacent forms. `+refspec` is the one that hides: it is a force
# with no flag anywhere on the command line.
FORCE_FLAGS = ("-f", "--force", "--force-with-lease", "--mirror", "--delete", "-d")


def die(msg: str, code: int = USAGE) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def git(repo: Path, *args: str) -> tuple[int, str]:
    """Read-only git. --no-optional-locks plus GIT_OPTIONAL_LOCKS=0 keeps this from
    touching the index of a checkout another session may be using."""
    result = subprocess.run(
        ["git", "--no-optional-locks", "--no-pager", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        check=False,
    )
    return result.returncode, (result.stdout + result.stderr).strip()


class Report:
    """Every assertion prints its detail on PASS as well as on FAIL, and the run ends
    with the denominator. A verdict with no figure beside it has been wrong in this
    project while reading as careful."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def check(self, name: str, ok: bool, detail: str) -> bool:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        print(f"         {detail}")
        if ok:
            self.passed += 1
        else:
            self.failed.append(name)
        return ok

    @property
    def total(self) -> int:
        return self.passed + len(self.failed)


def parse_push(command: list[str]) -> dict:
    """Pull the remote, the refspecs and the force forms out of the push command."""
    if not command or Path(command[0]).name != "git" or "push" not in command:
        die(
            "pass the exact push command after `--`, starting with git: "
            "-- git push origin feature/aisf-report-section"
        )
    rest = command[command.index("push") + 1 :]
    remote = ""
    refspecs: list[str] = []
    forces = [tok for tok in rest if tok in FORCE_FLAGS or tok.startswith("--force")]
    for token in rest:
        if token.startswith("-"):
            continue
        if not remote:
            remote = token
        else:
            refspecs.append(token)
    forces += [f"+{spec}" for spec in refspecs if spec.startswith("+")]
    return {"remote": remote, "refspecs": refspecs, "forces": forces}


def commit_range(
    repo: Path, remote: str, src_rev: str, dst_branch: str
) -> tuple[str, list[str], str]:
    """The commits ONE refspec would send, and the base they were measured against.

    Both ends are per-refspec on purpose. An earlier version measured
    `remote-tracking-ref-of-the-CURRENT-branch..HEAD` no matter which ref the command
    named. Pushing an ancestor branch while sitting on a descendant then resolved a
    base that equalled HEAD, so the range was empty and the secret, path and
    attribution scans all passed over a population of zero while printing
    `0 commit(s)` as though that were a clean result.

    The base is PRINTED by the caller because a silent fallback to a different ref is
    fail-open: it once published 24 controls as 16 and exited 0. If no base resolves,
    the caller fails rather than scanning all of history and calling that a measurement.
    """
    for candidate, how in (
        (
            f"refs/remotes/{remote}/{dst_branch}",
            "the remote-tracking ref for the branch being landed on",
        ),
        (
            f"refs/remotes/{remote}/main",
            f"{remote}/main ({dst_branch} is not on the remote yet)",
        ),
    ):
        rc, _ = git(repo, "rev-parse", "--verify", "--quiet", candidate)
        if rc == 0:
            rc, out = git(repo, "rev-list", f"{candidate}..{src_rev}")
            if rc != 0:
                continue
            return candidate, [line for line in out.splitlines() if line], how
    return "", [], "no base ref resolved"


def scan_commits(repo: Path, commits: list[str]) -> dict:
    """Paths, added lines and messages of each commit, with the counts that were read."""
    bad_paths: list[str] = []
    bad_content: list[str] = []
    allowlisted: list[str] = []
    attribution: list[str] = []
    files = lines = 0
    for sha in commits:
        _, names = git(repo, "show", "--pretty=format:", "--name-only", sha)
        for path in (p for p in names.splitlines() if p.strip()):
            files += 1
            base = Path(path).name
            for pattern in SECRET_PATHS:
                if fnmatch.fnmatch(base.lower(), pattern.lower()):
                    bad_paths.append(f"{sha[:9]} {path} matches {pattern}")
        _, diff = git(repo, "show", "--pretty=format:", "--unified=0", sha)
        for line in diff.splitlines():
            if not line.startswith("+") or line.startswith("+++"):
                continue
            lines += 1
            if ALLOWLIST_MARKER in line:
                allowlisted.append(f"{sha[:9]} {line.strip()[:100]}")
                continue
            for label, pattern in SECRET_CONTENT:
                if re.search(pattern, line):
                    bad_content.append(f"{sha[:9]} {label}: {line.strip()[:100]}")
        _, message = git(repo, "log", "-1", "--format=%B%n%an <%ae>%n%cn <%ce>", sha)
        # Line by line, because the Co-Authored-By pattern is anchored at the start of
        # a line: a trailer is only a trailer in the leftmost column.
        for label, pattern in ATTRIBUTION:
            for msg_line in message.splitlines():
                if re.search(pattern, msg_line):
                    attribution.append(f"{sha[:9]} {label}: {msg_line.strip()[:100]}")
    return {
        "bad_paths": bad_paths,
        "bad_content": bad_content,
        "allowlisted": allowlisted,
        "attribution": attribution,
        "files": files,
        "lines": lines,
    }


def defined_gates(script: Path) -> dict[str, set[str]]:
    """Gate ids and names as gate_all.sh itself spells them.

    Derived from the script instead of from a list kept here, so a renamed or renumbered
    gate cannot leave this audit comparing against names that no longer exist. `skip` is
    included because a skipped gate prints a shorter name for the same id; the self-audit
    still fails on a skip, because a skip is not a pass.
    """
    text = script.read_text(encoding="utf-8")
    gates: dict[str, set[str]] = {}
    for match in re.finditer(r'(?:report|run_suite|skip)\s+(\d+)\s+"([^"]+)"', text):
        gates.setdefault(match.group(1), set()).add(match.group(2))
    return gates


def defined_checks(source: Path) -> dict[str, int]:
    """How many assertions each function in this file defines.

    Read from the source rather than declared, for the same reason gate_all.sh derives
    its gate ids from its own `report` calls: a hand-kept total is wrong the moment an
    assertion is added or removed, and it is wrong in the direction that still prints
    PASS.

    Only a line that IS the call counts. Counting every occurrence of the substring
    also counted the comment in main() that talks about these call sites, which
    inflated the expected total by one and failed a clean run -- prose about code
    reading as code is a trap this project has hit in both directions.
    """
    text = source.read_text(encoding="utf-8")
    counts: dict[str, int] = {}
    for block in re.split(r"^def ", text, flags=re.M)[1:]:
        name = block.split("(", 1)[0].strip()
        counts[name] = sum(
            1 for line in block.splitlines() if line.strip() == "report.check("
        )
    return counts


def audit_battery(repo: Path, report: Report, recording: Path, script: Path) -> None:
    """Re-read the recorded battery run and compare it against the gate definitions."""
    if not recording.is_file():
        report.check(
            "battery self-audit: recording exists",
            False,
            f"{recording} is absent. Run: bash aisf-parity/gate_all.sh --out {recording}",
        )
        return
    text = recording.read_text(encoding="utf-8", errors="replace")
    gates = defined_gates(script)

    head_match = re.search(r"^head\s+(\S+)\s+on\s+(\S+)", text, re.M)
    _, head_sha = git(repo, "rev-parse", "HEAD")
    recorded_sha = ""
    if head_match:
        rc, resolved = git(repo, "rev-parse", f"{head_match.group(1)}^{{commit}}")
        recorded_sha = resolved if rc == 0 else ""
    report.check(
        "battery self-audit: the recording is of THIS commit",
        bool(recorded_sha) and recorded_sha == head_sha,
        f"recorded {head_match.group(1) if head_match else '(no head line)'} "
        f"-> {recorded_sha[:12] or 'unresolvable'}, HEAD is {head_sha[:12]}. "
        "Short sha length varies by clone, so both are resolved to full shas.",
    )

    verdicts = dict()
    order: list[tuple[str, str, str]] = []
    for match in re.finditer(
        r"^\s{2}\[(\d+)\] (PASS|FAIL|SKIP)\s+(.+?)\s*$", text, re.M
    ):
        verdicts[match.group(1)] = match.group(2)
        order.append(match.groups())
    missing = sorted(set(gates) - set(verdicts), key=int)
    report.check(
        "battery self-audit: every defined gate reported",
        not missing and bool(gates),
        f"{len(verdicts)} verdict line(s) for {len(gates)} defined gate(s) "
        f"{sorted(gates, key=int)}; missing: {missing or 'none'}",
    )

    mismatched = [
        f"[{gid}] recorded {name!r}, defined {sorted(gates.get(gid, set()))}"
        for gid, _, name in order
        if name.split("  ")[0].strip() not in gates.get(gid, set())
    ]
    report.check(
        "battery self-audit: recorded gate names match the definitions",
        not mismatched,
        f"{len(order)} name(s) compared against {script.name}; mismatched: "
        f"{mismatched or 'none'}",
    )

    not_pass = [
        f"[{gid}] {state} {name}" for gid, state, name in order if state != "PASS"
    ]
    report.check(
        "battery self-audit: no gate failed or was skipped",
        not not_pass,
        f"{sum(1 for _, s, _ in order if s == 'PASS')}/{len(order)} verdict(s) are PASS; "
        f"other: {not_pass or 'none'} -- a SKIP is not a pass",
    )

    final = re.search(r"^GATE (PASS|FAIL)\s+(\d+)/(\d+) gates passed", text, re.M)
    pass_lines = sum(1 for _, state, _ in order if state == "PASS")
    ok = bool(final) and final.group(1) == "PASS" and int(final.group(2)) == pass_lines
    ok = ok and int(final.group(3)) == len(gates) if final else False
    report.check(
        "battery self-audit: the final line agrees with the verdicts above it",
        ok,
        f"final line: {final.group(0) if final else '(absent)'}; counted {pass_lines} "
        f"PASS verdict(s) and {len(gates)} defined gate(s). A summary that contradicts "
        "the lines above it is the failure mode this compares.",
    )

    exit_match = re.search(r"^BATTERY_EXIT=(\d+)", text, re.M)
    report.check(
        "battery self-audit: the recorded run exited 0",
        bool(exit_match) and exit_match.group(1) == "0",
        f"BATTERY_EXIT={exit_match.group(1) if exit_match else '(not recorded)'}. "
        "Record it with: bash aisf-parity/gate_all.sh --out FILE; "
        'echo "BATTERY_EXIT=$?" >>FILE',
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    default_repo = Path(__file__).resolve().parent.parent
    ap.add_argument("--repo", type=Path, default=default_repo)
    ap.add_argument(
        "--battery-output",
        type=Path,
        required=True,
        help="the file `gate_all.sh --out` wrote. Required: a push with no recorded "
        "gate run is not a verified push.",
    )
    ap.add_argument(
        "command", nargs=argparse.REMAINDER, help="-- git push <remote> <refspec>"
    )
    args = ap.parse_args()

    repo = args.repo.expanduser().resolve()
    if not (repo / ".git").exists():
        die(f"{repo} is not a git clone or worktree")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    push = parse_push(command)

    rc, branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    if rc != 0 or not branch:
        die("cannot resolve the current branch")

    report = Report()
    print(f"repo      {repo}")
    print(f"branch    {branch}")
    print(f"command   {' '.join(command)}")
    print()
    print("=== pre-push assertions ===")

    remote = push["remote"] or "origin"
    rc, push_url = git(repo, "remote", "get-url", "--push", remote)
    report.check(
        f"the push remote {remote!r} is the user's own fork",
        rc == 0 and push_url == FORK_URL and UPSTREAM_MARKER not in push_url,
        f"push url: {push_url or '(none)'}; required: {FORK_URL}",
    )

    rc, up_url = git(repo, "remote", "get-url", "--push", UPSTREAM_REMOTE)
    unusable = rc != 0 or (
        UPSTREAM_MARKER not in up_url and not up_url.startswith(URL_SHAPES)
    )
    report.check(
        f"{UPSTREAM_REMOTE!r} has no usable push url",
        unusable,
        f"push url: {up_url or '(remote absent)'}; a pushable url starts with one of "
        f"{URL_SHAPES}. The sentinel here contains the string aws-samples, so this "
        f"tests for {UPSTREAM_MARKER!r} with the slash.",
    )

    # One range per refspec. A single range measured against the current branch scanned
    # zero commits whenever the ref being pushed was not the current branch, so the
    # pair being measured has to come from the command, not from HEAD.
    pairs: list[tuple[str, str]] = []
    for spec in push["refspecs"]:
        src, _, dst = spec.lstrip("+").partition(":")
        if not src:
            # A delete refspec sends no content. The ancestry assertion below fails it.
            continue
        pairs.append((src, (dst or src).removeprefix("refs/heads/")))
    if not pairs:
        pairs = [("HEAD", branch)]

    commits: list[str] = []
    unmeasured: list[str] = []
    for src_rev, dst in pairs:
        base, part, how = commit_range(repo, remote, src_rev, dst)
        if not base:
            die(
                f"no base ref resolved for {remote}/{dst} or {remote}/main, so the set of "
                "commits about to be pushed cannot be measured. Scanning all of history "
                "instead would be a different measurement reported under the same name.",
                USAGE,
            )
        print(
            f"  range    {base}..{src_rev} -- {len(part)} commit(s), "
            f"base chosen as {how}"
        )
        commits += [sha for sha in part if sha not in commits]
        if part:
            continue
        # An empty range is sound only when the remote ref already holds exactly what
        # is being pushed. Otherwise the push publishes commits that nothing scanned.
        rc_d, dst_sha = git(
            repo, "rev-parse", "--verify", "--quiet", f"refs/remotes/{remote}/{dst}"
        )
        rc_s, src_sha = git(
            repo, "rev-parse", "--verify", "--quiet", f"{src_rev}^{{commit}}"
        )
        if rc_d != 0 or rc_s != 0 or dst_sha != src_sha:
            where = "absent from the remote" if rc_d != 0 else f"at {dst_sha[:12]}"
            unmeasured.append(
                f"{src_rev} -> {dst}: 0 commit(s) measured from {base}, yet the "
                f"destination is {where}, not {src_sha[:12] if rc_s == 0 else '(unresolved)'}"
            )

    report.check(
        "every ref being pushed contributed a measured commit population",
        not unmeasured,
        f"{len(pairs)} refspec(s) measured, {len(commits)} distinct commit(s) to scan; "
        f"an empty range is sound only where the destination already equals the source; "
        f"unmeasured: {unmeasured or 'none'}",
    )
    scan = scan_commits(repo, commits)

    report.check(
        "no commit about to be pushed adds a secret-shaped path",
        not scan["bad_paths"],
        f"{scan['files']} changed file path(s) across {len(commits)} commit(s) matched "
        f"against {len(SECRET_PATHS)} pattern(s); hits: {scan['bad_paths'] or 'none'}",
    )
    report.check(
        "no commit about to be pushed adds a credential-shaped line",
        not scan["bad_content"],
        f"{scan['lines']} added line(s) matched against {len(SECRET_CONTENT)} pattern(s); "
        f"hits: {scan['bad_content'] or 'none'}",
    )
    for line in scan["allowlisted"]:
        print(f"           allowlisted by pragma (READ THESE): {line}")
    report.check(
        "no commit message carries an attribution line",
        not scan["attribution"],
        f"{len(commits)} message(s) matched against {len(ATTRIBUTION)} pattern(s); "
        f"hits: {scan['attribution'] or 'none'}",
    )

    dests = [
        spec.split(":")[-1].removeprefix("refs/heads/") for spec in push["refspecs"]
    ]
    on_protected = [b for b in [branch, *dests] if b.lstrip("+") in PROTECTED_BRANCHES]
    report.check(
        "the push neither comes from nor lands on a protected branch",
        not on_protected,
        f"source branch {branch!r}, destination ref(s) {dests or ['(default: same name)']}; "
        f"protected: {sorted(PROTECTED_BRANCHES)}; hits: {on_protected or 'none'}",
    )

    report.check(
        "the push is not a force",
        not push["forces"],
        f"{len(push['refspecs'])} refspec(s) and {len(command)} command token(s) checked "
        f"against {FORCE_FLAGS} plus a leading + on any refspec; hits: "
        f"{push['forces'] or 'none'}",
    )

    # Everything above, and the whole battery self-audit below, measures HEAD. The
    # command names a ref, and nothing so far compares the two, so a battery recorded
    # on a green branch would vouch for pushing a different, ungated one. An empty
    # source is caught here too: `git push origin :branch` deletes the remote ref
    # while carrying neither a leading + nor --delete, so the force check is blind
    # to it.
    rc, head_sha = git(repo, "rev-parse", "HEAD")
    if rc != 0 or not head_sha:
        die("cannot resolve HEAD")
    sources = [spec.lstrip("+").split(":")[0] for spec in push["refspecs"]]
    compared: list[str] = []
    off_head: list[str] = []
    for src in sources:
        if not src:
            off_head.append("(empty source): deletes the remote ref")
            continue
        rc, resolved = git(
            repo, "rev-parse", "--verify", "--quiet", f"{src}^{{commit}}"
        )
        if rc != 0 or not resolved:
            off_head.append(f"{src}: does not resolve to a commit")
            continue
        rc, _ = git(repo, "merge-base", "--is-ancestor", resolved, head_sha)
        if rc == 0:
            compared.append(f"{src}={resolved[:12]}")
        else:
            off_head.append(f"{src}: {resolved[:12]} is not HEAD nor an ancestor of it")
    if sources:
        detail = (
            f"{len(compared)} of {len(sources)} refspec source(s) are HEAD "
            f"{head_sha[:12]} or an ancestor: {compared or 'none'}; "
            f"off-HEAD: {off_head or 'none'}"
        )
    else:
        detail = (
            f"no refspec given, so git pushes the current branch {branch!r}, which is "
            f"HEAD {head_sha[:12]} by definition; 0 source(s) needed comparing"
        )
    report.check(
        "every ref being pushed is HEAD or an ancestor of it",
        not off_head,
        detail,
    )

    print()
    print("=== battery self-audit ===")
    audit_battery(
        repo, report, args.battery_output, repo / "aisf-parity" / "gate_all.sh"
    )

    print()
    print("=== what this cannot see ===")
    print(
        "  - whether the remote branch moved since the recording: nothing here fetches."
    )
    print(
        "  - a secret already committed BEFORE a base ref above; only those ranges are read."
    )
    print(
        "  - a secret whose shape is not in the pattern lists, and anything behind an"
    )
    print("    allowlist pragma (printed above so it is reviewed rather than trusted).")
    print(
        "  - what the push does server-side: branch protection, hooks, required checks."
    )
    print(
        "  - whether the battery's own gates are sufficient. It audits that they RAN."
    )

    # Did every assertion this file defines actually run? The count comes from this
    # file's own `report.check(` call sites, so nothing here states a total that could
    # drift. An assertion deleted or short-circuited in a refactor would otherwise
    # leave a smaller denominator that still reads PASS.
    # audit_battery holds one call site on a mutually exclusive path: if the recording
    # is absent it makes that one assertion and returns, so exactly one of the two
    # counts can run and the present-recording total is its call sites minus that one.
    defined = defined_checks(Path(__file__))
    audit_expected = (
        defined["audit_battery"] - 1 if args.battery_output.is_file() else 1
    )
    expected = defined["main"] + audit_expected
    print()
    ran_all = report.total == expected
    print(
        f"  [{'PASS' if ran_all else 'FAIL'}] every assertion this script defines ran"
    )
    print(
        f"         {report.total} ran, {expected} expected "
        f"({defined['main']} pre-push + {audit_expected} self-audit), counted from the "
        f"assertion call sites in {Path(__file__).name}"
        + (
            ""
            if args.battery_output.is_file()
            else "; the recording is absent, so the "
            "self-audit stops at its first assertion"
        )
    )

    totals = f"{report.passed}/{report.total} assertions passed"
    print()
    if report.failed or not ran_all:
        for name in report.failed:
            print(f"  failing assertion: {name}")
        if not ran_all:
            print("  failing assertion: not every defined assertion ran")
        print(f"PUSH SAFETY FAIL  {totals} -- DO NOT PUSH")
        return FAIL
    print(f"PUSH SAFETY PASS  {totals}, all {expected} defined assertions ran")
    return 0


if __name__ == "__main__":
    sys.exit(main())
