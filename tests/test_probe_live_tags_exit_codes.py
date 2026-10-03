"""The exit status of every refusal in `aisf-parity/probe_live_tags.py`.

That script publishes a three-code contract in its own docstring: 0 every assertion
passed, 1 at least one assertion failed, 2 usage error or nothing could be measured,
never read as a pass. The distinction is the point of the third code -- a wrapper that
branches on it sends 1 to triage and 2 to "populate the bucket first" -- and all three
of its refusals spent it, because they were written as `raise SystemExit("<message>")`
and a string argument sets the message while exiting **1**.

Two of the three predate this suite. The one that matters most in practice fires
whenever the bucket holds no complete CSV set, which is the ordinary state before a
run has happened, so the most likely refusal was the one that mis-reported.

These assert the status of a real process. A test that only asserts SystemExit is
raised passes against the defect, and so does one that reads `.code` without
comparing it: pre-fix, `.code` is the message string, which is truthy and not 1.
The message text is asserted alongside the status, because a fix that silences the
message to get the code right would trade one defect for another.
"""

import os
import subprocess
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROBE = os.path.join(REPO_ROOT, "aisf-parity", "probe_live_tags.py")
USAGE = 2

# Loads the script under test as a module without importing it as a package, the way
# tests/test_aisf_compliance_column.py loads the producer files. The module-level
# `PRODUCERS = producers_from_shipped_maps()` runs here against the real tree and has
# to succeed; each case below then breaks one input on purpose.
PREAMBLE = f"""
import importlib.util, sys
spec = importlib.util.spec_from_file_location("probe_live_tags", {PROBE!r})
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
"""

NO_PRODUCER = """
import pathlib
probe.MODULES = pathlib.Path(sys.argv[1])
probe.producers_from_shipped_maps()
"""

# A bucket holding one producer's CSV and not the others: the state the message calls
# a partial set, reached through the real key regex and the real completeness test.
PARTIAL_BUCKET = """
import datetime, types
key = probe.PRODUCERS[0] + (
    "_security_report_00000000-0000-0000-0000-000000000000_us-east-1.csv"
)
class FakeS3:
    def list_objects_v2(self, **kwargs):
        return {
            "Contents": [{"Key": key, "LastModified": datetime.datetime(2026, 1, 1)}],
            "IsTruncated": False,
        }
sys.modules["boto3"] = types.SimpleNamespace(client=lambda *a, **k: FakeS3())
probe.newest_execution("some-bucket", None)
"""


def _child(body, *args):
    """Run one refusal in its own interpreter and report what the shell would see."""
    return subprocess.run(
        [sys.executable, "-c", PREAMBLE + body, *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def test_no_producer_to_measure_exits_usage(tmp_path):
    result = _child(NO_PRODUCER, str(tmp_path))
    assert result.returncode == USAGE, (
        f"exit {result.returncode}, expected {USAGE}; 1 is the pre-fix value and "
        f"reads as a failed assertion\n{result.stderr}"
    )
    assert "there is no producer to measure" in result.stderr


def test_a_bucket_without_a_complete_csv_set_exits_usage():
    result = _child(PARTIAL_BUCKET)
    assert result.returncode == USAGE, (
        f"exit {result.returncode}, expected {USAGE}; 1 is the pre-fix value and "
        f"reads as a failed assertion\n{result.stderr}"
    )
    assert "Refusing to measure a partial set" in result.stderr


def test_an_empty_csv_dir_exits_usage(tmp_path):
    """Through the CLI, which is how a reader reaches this refusal."""
    result = subprocess.run(
        [sys.executable, PROBE, "--csv-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == USAGE, (
        f"exit {result.returncode}, expected {USAGE}; 1 is the pre-fix value and "
        f"reads as a failed assertion\n{result.stderr}"
    )
    assert "a partial set is not measured" in result.stderr


def test_the_selftest_still_exits_zero():
    """The 0 leg of the same contract, so the three cases above cannot pass by
    making every path exit 2."""
    result = subprocess.run(
        [sys.executable, PROBE, "--selftest"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 failing" in result.stdout


def test_no_refusal_is_spelled_as_a_bare_system_exit():
    """The three cases above cover the three sites that exist. A fourth added later is
    invisible to them, and the mistake is available again the moment someone writes
    the idiom this file used to use."""
    with open(PROBE) as handle:
        source = handle.read()
    # Anchored to statement position, because the comment above die() quotes the
    # idiom it exists to prevent: a plain `in` or `.count()` over the whole file
    # counts that prose as a second site and fails on correct source.
    sites = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith("raise SystemExit(")
    ]
    assert len(sites) == 1, (
        f"{len(sites)} `raise SystemExit(` statement(s), expected only die()'s own: "
        f"{sites}. With a string argument that exits 1, which this script's docstring "
        "reserves for a failed assertion"
    )
