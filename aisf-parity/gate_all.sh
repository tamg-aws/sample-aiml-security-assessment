#!/usr/bin/env bash
# Run every local gate for the AISF parity work: the ledger gates, the three test
# sessions CI runs, and ruff. One command, one verdict, a denominator beside each.
#
# Why this exists. The ledger gates, the four pytest invocations and the two ruff
# commands have been run by hand, in different orders, with the numbers copied into
# prose afterwards. A hand-assembled run omits a step silently: the invocation that
# collects nothing (gate 3 below) exits 4 and prints "no tests ran", which scrolls
# past as easily as a pass. So every figure this battery reports is measured here and
# printed next to the verdict that used it, and a gate that produces no verdict at
# all is a failure of the battery rather than a detail.
#
# Usage:
#   bash aisf-parity/gate_all.sh                 # every gate
#   bash aisf-parity/gate_all.sh --only 1,6,7    # named gates only
#   bash aisf-parity/gate_all.sh --list          # gate ids and names, from this file
#   bash aisf-parity/gate_all.sh --out FILE      # also record the run for push_safety.py
#
# A recording push_safety.py will accept needs this script's own exit code in it, and
# only the caller can capture that:
#   bash aisf-parity/gate_all.sh --out FILE; echo "BATTERY_EXIT=$?" >>FILE
# This script does not write that line itself. The last line it prints is the run's
# denominator, and a second BATTERY_EXIT line from an appending caller would leave two
# answers to one question.
#
# Exit codes: 0 every selected gate passed; 1 at least one failed or fell silent;
#             2 usage/environment error, or zero gates ran.
set -uo pipefail

# PIPESTATUS below is a bash array. In zsh it is not populated, so `zsh gate_all.sh`
# would read the exit status of `tee` as the battery's own and report a failing run as
# clean. Measured in this project: `${PIPESTATUS[0]}` after a zsh pipeline printed an
# empty string, and the surrounding check treated empty as zero.
[[ -n "${BASH_VERSION:-}" ]] || { echo "ERROR: run this with bash; the shell running $0 does not populate PIPESTATUS" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd -P)"
ONLY=""; OUT=""
ORIG_ARGS=("$@")

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --out)  OUT="$2"; shift 2 ;;
    --repo) REPO="${2/#\~/$HOME}"; shift 2 ;;
    -h|--help) sed -n '2,/^# Exit codes/p' "${BASH_SOURCE[0]}"; exit 0 ;;
    # Ids and names derived from this file's own `report` calls, so no document has to
    # state a gate count. A hand-maintained total drifts the moment a gate lands.
    --list)
      grep -oE '(report|run_suite) +[0-9]+ +"[^"]+"' "${BASH_SOURCE[0]}" \
        | sed -E 's/(report|run_suite) +([0-9]+) +"(.*)"/\2|\3/' \
        | sort -t'|' -k1,1n -u | awk -F'|' '{printf "  %2s  %s\n", $1, $2}'
      exit 0 ;;
    *) echo "ERROR: unknown argument $1" >&2; exit 2 ;;
  esac
done

GATE_IDS="$(grep -oE '^if want [0-9]+' "${BASH_SOURCE[0]}" | grep -oE '[0-9]+' | tr '\n' ' ')"
# A typo in --only must not read as a clean run: want() does substring membership, so
# `--only 1-7` matches no gate and every gate is skipped. Ids come from this file's own
# `if want` lines, so a renumbered gate makes a stale --only fail loudly.
for tok in ${ONLY//,/ }; do
  [[ " $GATE_IDS " == *" $tok "* ]] \
    || { echo "ERROR: --only token '$tok' is not a gate id -- gates are: $GATE_IDS" >&2; exit 2; }
done

# Recording for push_safety.py --battery-output. Re-exec once with the whole run piped
# through tee, so the recorded file is byte-identical to what the operator read: a
# recording assembled separately can disagree with the terminal, and then the self-audit
# is auditing a transcript nobody saw. The marker stops the child re-exec'ing forever.
if [[ -n "$OUT" && -z "${AISF_GATE_ALL_RECORDING:-}" ]]; then
  : >"$OUT" || { echo "ERROR: cannot write --out $OUT" >&2; exit 2; }
  AISF_GATE_ALL_RECORDING=1 bash "${BASH_SOURCE[0]}" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"} 2>&1 | tee "$OUT"
  exit "${PIPESTATUS[0]}"
fi

cd "$REPO" 2>/dev/null || { echo "ERROR: cannot cd to $REPO" >&2; exit 2; }
[[ -e .git ]] || { echo "ERROR: $REPO is not a git clone or worktree" >&2; exit 2; }
PY="$REPO/.venv/bin/python"
[[ -x "$PY" ]] || { echo "ERROR: no interpreter at $PY (python3 -m venv .venv)" >&2; exit 2; }
RUFF="$(command -v ruff || true)"

# The credentials and bucket name the three CI pytest sessions set. Without them the
# module-level boto3 clients in the assessment packages raise at import and whole
# sessions error out, which is a different failure from a red test.
export AIML_ASSESSMENT_BUCKET_NAME="${AIML_ASSESSMENT_BUCKET_NAME:-test-assessment-bucket}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-testing}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-testing}"  # pragma: allowlist secret

GRC_TESTS="aiml-security-assessment/functions/security/responsible_ai_grc_tests"
REPORT_DIR="aiml-security-assessment/functions/security/generate_consolidated_report"

PASSED=0; FAILED=0; SKIPPED=0
declare -a FAILED_NAMES=(); declare -a REPORTED_IDS=()
SUBGATES=0; TESTS=0; SUITES=0

want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

# report <id> <name> <rc> [detail]. The detail prints on PASS as well as FAIL: a gate
# that measured 875 tests and threw the figure away on success is why every count in
# this project had to be re-derived by hand before it could be published.
report() {
  local n="$1" name="$2" rc="$3" detail="${4:-}"
  REPORTED_IDS+=("$n")
  if [[ "$rc" -eq 0 ]]; then
    printf '  [%s] PASS  %s\n' "$n" "$name"
    PASSED=$((PASSED+1))
  else
    printf '  [%s] FAIL  %s\n' "$n" "$name"
    FAILED=$((FAILED+1)); FAILED_NAMES+=("$n $name")
  fi
  [[ -n "$detail" ]] && printf '          %s\n' "$detail"
  return 0
}
skip() { printf '  [%s] SKIP  %s -- %s\n' "$1" "$2" "$3"; SKIPPED=$((SKIPPED+1)); REPORTED_IDS+=("$1"); }

# Count the tests a pytest tail reports. `N passed` is the only figure this battery
# quotes from pytest, and an absent count is treated as zero by the callers, which is
# what makes "no tests ran" fail instead of passing.
passed_count() { grep -oE '[0-9]+ passed' <<<"$1" | head -1 | grep -oE '[0-9]+' || echo 0; }

# run_suite <id> <name> <cwd> <pytest target...>
run_suite() {
  local id="$1" name="$2" dir="$3"; shift 3
  local out rc n
  out="$(cd "$dir" && "$PY" -m pytest "$@" -q -p no:cacheprovider 2>&1)"; rc=$?
  n="$(passed_count "$out")"
  # rc 4 is a pytest usage error and rc 5 is "no tests collected". Both print a short,
  # calm tail and neither is a pass; requiring a non-zero passed count makes them red
  # even if a future pytest returns 0 for an empty selection.
  [[ "$n" -gt 0 ]] || rc=1
  if [[ "$rc" -eq 0 ]]; then
    TESTS=$((TESTS+n)); SUITES=$((SUITES+1))
    report "$id" "$name" 0 "$n passed in $* (pytest: $(tail -1 <<<"$out"))"
  else
    report "$id" "$name" 1 "rc=$rc, $n passed in $*: $(tail -2 <<<"$out" | tr '\n' ' ')"
  fi
}

echo "repo      $REPO"
echo "head      $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)"
echo "python    $("$PY" --version 2>&1)"
echo "ruff      ${RUFF:-not on PATH}${RUFF:+ $(ruff --version)}"
echo "gates     $(wc -w <<<"$GATE_IDS" | tr -d ' ') defined: $GATE_IDS"
echo
echo "=== gates ==="

# ---------------------------------------------------------------- 1 ledger gates
# Three figures have to agree: the exit code, the summary line, and the number of
# per-gate verdicts printed above it. Checking only the exit code would accept a
# battery whose summary says 13/13 over twelve verdicts, and a printed line that
# contradicts the verdict directly above it is a failure mode this project has met.
if want 1; then
  out="$("$PY" aisf-parity/check_ledger.py 2>&1)"; rc=$?
  ran="$(grep -cE '^\[(PASS|FAIL)\]' <<<"$out")"
  summary="$(grep -oE '[0-9]+/[0-9]+ gates passed' <<<"$out" | head -1)"
  s_pass="${summary%%/*}"; s_total="$(sed -E 's#^[0-9]+/([0-9]+) .*#\1#' <<<"$summary")"
  bad=""
  [[ "$rc" -eq 0 ]] || bad="exit $rc"
  [[ -n "$summary" ]] || bad="${bad:+$bad; }no 'N/M gates passed' summary line"
  [[ "${ran:-0}" -gt 0 ]] || bad="${bad:+$bad; }zero gate verdicts printed"
  [[ "${s_pass:-0}" == "${s_total:-1}" ]] || bad="${bad:+$bad; }summary reports failures"
  [[ "${ran:-0}" == "${s_total:-0}" ]] \
    || bad="${bad:+$bad; }$ran verdict line(s) but the summary claims ${s_total:-?}"
  if [[ -z "$bad" ]]; then
    SUBGATES="$ran"
    report 1 "ledger gates (aisf-parity/check_ledger.py)" 0 \
      "$summary, $ran verdict line(s) printed, exit 0; $(grep -oE "figures=\{[^}]*\}" <<<"$out" | head -1)"
  else
    report 1 "ledger gates (aisf-parity/check_ledger.py)" 1 \
      "$bad -- $(grep -E '^\[FAIL\]' <<<"$out" | head -3 | tr '\n' ' ')"
  fi
fi

# ---------------------------------------------------------------- 2 root test suite
if want 2; then run_suite 2 "tests/ (CI session 1)" "$REPO" tests/; fi

# ---------------------------------------------------------------- 3 Responsible AI GRC
# THE PATH TRAP. `pytest responsible_ai_grc_tests/` from the repo root collects nothing
# and exits 4: the directory lives four levels down. Measured in this project while
# reporting suite totals, where the short path printed "no tests ran in 0.00s" and was
# nearly recorded as a pass. The positive control below proves the trap is still live,
# so this gate cannot quietly become a tautology if the layout changes.
if want 3; then
  if [[ -d responsible_ai_grc_tests ]]; then
    report 3 "Responsible AI GRC suite at its real path (CI session 2)" 1 \
      "a bare responsible_ai_grc_tests/ now exists at the repo root -- this gate's positive control is void; re-derive it"
  else
    bare_out="$("$PY" -m pytest responsible_ai_grc_tests/ -q -p no:cacheprovider 2>&1)"; bare_rc=$?
    out="$("$PY" -m pytest "$GRC_TESTS/" -q -p no:cacheprovider 2>&1)"; rc=$?
    n="$(passed_count "$out")"
    [[ "$n" -gt 0 ]] || rc=1
    [[ "$bare_rc" -ne 0 ]] || rc=1
    if [[ "$rc" -eq 0 ]]; then
      TESTS=$((TESTS+n)); SUITES=$((SUITES+1))
      report 3 "Responsible AI GRC suite at its real path (CI session 2)" 0 \
        "$n passed at $GRC_TESTS/; control: the bare path exits $bare_rc ($(tail -1 <<<"$bare_out")), which is not a pass"
    else
      report 3 "Responsible AI GRC suite at its real path (CI session 2)" 1 \
        "rc=$rc, $n passed at $GRC_TESTS/; bare path rc=$bare_rc: $(tail -1 <<<"$out")"
    fi
  fi
fi

# ---------------------------------------------------------------- 4 report generator
# CI runs this one with the report-generator directory as the working directory,
# because that package ships an __init__.py and its tests import by bare module name.
# The gate name carries no variable on purpose: --list and push_safety.py's self-audit
# compare the names in this file against the names in a recorded run, and an interpolated
# name reads as a mismatch in one of the two places.
if want 4; then run_suite 4 "test_generate_report.py from the report-generator directory (CI session 3)" "$REPO/$REPORT_DIR" test_generate_report.py; fi

# ---------------------------------------------------------------- 5 consolidator test
if want 5; then run_suite 5 "tests/test_consolidate_responsible_ai_grc.py (CI session 3)" "$REPO" tests/test_consolidate_responsible_ai_grc.py; fi

# ---------------------------------------------------------------- 6 ruff check
if want 6; then
  if [[ -n "$RUFF" ]]; then
    out="$("$RUFF" check . 2>&1)"; rc=$?
    report 6 "ruff check ." "$rc" "$(tail -1 <<<"$out")"
  else skip 6 "ruff check" "ruff is not on PATH: brew install ruff"; fi
fi

# ---------------------------------------------------------------- 7 ruff format
if want 7; then
  if [[ -n "$RUFF" ]]; then
    out="$("$RUFF" format --check . 2>&1)"; rc=$?
    report 7 "ruff format --check ." "$rc" "$(tail -1 <<<"$out")"
  else skip 7 "ruff format --check" "ruff is not on PATH: brew install ruff"; fi
fi

echo
echo "=== summary ==="
echo "  passed=$PASSED  failed=$FAILED  skipped=$SKIPPED"

# Per-gate accounting. The counters above cannot answer "did every selected gate
# report?", so name the silent ones instead: a gate that neither passed, failed nor
# skipped produced no verdict, and is indistinguishable from a gate that was deleted.
EXPECTED=0; SILENT=""
for g in $GATE_IDS; do
  want "$g" || continue
  EXPECTED=$((EXPECTED+1))
  seen=0
  for r in ${REPORTED_IDS[@]+"${REPORTED_IDS[@]}"}; do [[ "$r" == "$g" ]] && { seen=1; break; }; done
  [[ "$seen" -eq 0 ]] && SILENT="$SILENT $g"
done
echo "  gates selected: $EXPECTED of $(wc -w <<<"$GATE_IDS" | tr -d ' ') defined"
if [[ -n "$SILENT" ]]; then
  # Printed, not exited on, so a run with both a real failure and a silent gate still
  # names the failing gate before the verdict.
  echo "  GATE FAIL  selected gate(s) reported nothing at all:$SILENT"
  echo "             a gate with no verdict has not run. Do not read this battery as clean."
fi
[[ "$SKIPPED" -gt 0 ]] && echo "  NOTE: $SKIPPED gate(s) skipped -- a skip is not a pass."

# The two live legs are deliberately NOT gates above: they need AWS credentials and they
# measure an account, not this tree. Printed on every run, pass or fail, so a green
# battery is never read as evidence that any AISF- row reached both verdicts, nor that
# any tag was confirmed against a check id a producer really emits. Kept to ONE line
# with the existing prefix: push_safety.py's self-audit counts verdict lines and matches
# gate names against this file, and this is not a verdict line by design.
echo "  live leg:  NOT RUN here. aisf-parity/probe_live.py (AISF- rows) and probe_live_tags.py (tag column) need credentials; see aisf-parity/LIVE-FIXTURES.md"

TOTALS="$PASSED/$EXPECTED gates passed, $SUBGATES ledger sub-gates, $TESTS tests across $SUITES suite(s)"
# An empty run is the failure this battery exists to prevent, and this check comes before
# the two below deliberately. Every gate above reports or skips, so zero verdicts also
# means every selected gate is silent; if the silent branch exited first, this branch
# could never fire and would be an unreachable guard reading as a live one.
if [[ $((PASSED+FAILED+SKIPPED)) -eq 0 ]]; then
  echo "GATE FAIL  zero gates ran -- an empty run is not a pass (selected:${SILENT:- none})"
  exit 2
fi
if [[ -n "$SILENT" || "$FAILED" -gt 0 ]]; then
  [[ "$FAILED" -gt 0 ]] && printf '  failing gate: %s\n' "${FAILED_NAMES[@]}"
  echo "GATE FAIL  $TOTALS, $FAILED failed,${SILENT:- none} silent"
  exit 1
fi
echo "GATE PASS  $TOTALS"
exit 0
