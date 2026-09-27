"""The tag assertions in `aisf-parity/probe_live_tags.py`, run offline.

The probe's live leg reads the CSVs a real run left in the assessment bucket, and its
positive controls (aisf-parity/LIVE-FIXTURES.md) were driven red once by hand. Those
CSVs carry account ids and cannot be committed, so nothing in the battery could see
the comparison itself break: `--selftest` feeds `tag_mismatches` one row, and a probe
that read only the first row, or passed a set when any row agreed, still passed it.

Every fixture here has two rows, the first correct and the second wrong. One row
cannot tell `all` from `any`, and cannot tell a loop over every row from a loop over
the first.

The end-to-end cases build a `--csv-dir` set from this tree's own maps, so they
measure the probe's wiring and not a snapshot of the maps. They assert named
assertion lines and not the overall verdict: on this tree a correct set still ends
`PROBE FAIL`, on the qualifier census alone, because no map carries a `(partial)`
tag any more and the census requires one. That is a defect in the census and is not
asserted either way here.
"""

import csv
import importlib.util
import os
import subprocess
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROBE = os.path.join(REPO_ROOT, "aisf-parity", "probe_live_tags.py")
FAIL = 1

MAPPING = {
    "AC-01": "AISF AIR-ACR-RT-08",
    "AC-02": "AISF AIR-ACR-EVAL-01 | AISF AIR-FND-IAM-05 (1 of 4 checks)",
}


def load_probe():
    spec = importlib.util.spec_from_file_location("probe_live_tags_assertions", PROBE)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    return probe


def _row(check_id, tag):
    return {"Check_ID": check_id, "Compliance_Frameworks": tag}


def test_a_wrong_second_row_is_reported_and_the_right_first_row_is_not():
    probe = load_probe()
    rows = [_row("AC-01", MAPPING["AC-01"]), _row("AC-02", MAPPING["AC-01"])]
    wrong = probe.tag_mismatches(MAPPING, rows)
    assert len(wrong) == 1, wrong
    assert wrong[0].startswith("row 1 (AC-02) tag "), wrong


def test_two_correct_rows_report_no_mismatch():
    probe = load_probe()
    rows = [_row("AC-01", MAPPING["AC-01"]), _row("AC-02", MAPPING["AC-02"])]
    assert probe.tag_mismatches(MAPPING, rows) == []


def test_a_row_the_map_never_names_must_carry_an_empty_tag():
    probe = load_probe()
    rows = [_row("AC-01", MAPPING["AC-01"]), _row("AC-99", "AISF AIR-ACR-RT-08")]
    wrong = probe.tag_mismatches(MAPPING, rows)
    assert wrong == ["row 1 (AC-99) tag 'AISF AIR-ACR-RT-08' != ''"]


def test_the_written_audit_fails_when_one_of_two_rows_disagrees():
    probe = load_probe()
    header = list(probe.EXPECTED_COLUMNS)
    rows = [_row("AC-01", MAPPING["AC-01"]), _row("AC-02", "")]
    ok, detail = probe.written_tag_audit(MAPPING, rows, header)
    assert ok is False, detail
    assert "2 row(s) as the run wrote them, 1 tagged, 1 disagreeing" in detail


def test_the_written_audit_passes_when_both_rows_agree():
    probe = load_probe()
    header = list(probe.EXPECTED_COLUMNS)
    rows = [_row("AC-01", MAPPING["AC-01"]), _row("AC-02", MAPPING["AC-02"])]
    ok, detail = probe.written_tag_audit(MAPPING, rows, header)
    assert ok is True, detail
    assert "2 row(s) as the run wrote them, 2 tagged, 0 disagreeing" in detail


# --------------------------------------------------------------------------- #
# End to end, through main() and --csv-dir.
# --------------------------------------------------------------------------- #
def _write_set(probe, directory, spoil=None):
    """Two mapped rows per producer, tagged as this tree's map says.

    `spoil` names one producer whose second row has its tag blanked, the shape of the
    hand-run `AC-02` control in LIVE-FIXTURES.md. Every other row is correct, so a
    probe that stops after row 0 or passes on any agreeing row reads the set as clean.
    """
    for module in probe.PRODUCERS:
        mapping = probe.load_module(
            probe.MODULES / f"{module}_assessments",
            f"aisf_compliance_{module}.py",
            f"assertions_map_{module}",
        ).AISF_COMPLIANCE_MAP
        first, second = sorted(mapping)[:2]
        tags = [mapping[first], mapping[second]]
        if module == spoil:
            tags[1] = ""
        path = directory / f"{module}_security_report_offline_us-east-1.csv"
        with open(path, "w", newline="") as handle:
            writer = csv.DictWriter(handle, probe.EXPECTED_COLUMNS)
            writer.writeheader()
            for check_id, tag in zip((first, second), tags):
                writer.writerow(
                    {
                        "Check_ID": check_id,
                        "Finding": "offline fixture",
                        "Finding_Details": "offline fixture",
                        "Resolution": "none",
                        "Reference": "https://example.com",
                        "Severity": "High",
                        "Status": "Failed",
                        "Region": "us-east-1",
                        "Compliance_Frameworks": tag,
                    }
                )


def _run(directory):
    env = dict(os.environ)
    env.update(
        AWS_ACCESS_KEY_ID="testing",
        AWS_SECRET_ACCESS_KEY="testing",  # pragma: allowlist secret - synthetic test credential
        AWS_SESSION_TOKEN="testing",
        AWS_DEFAULT_REGION="us-east-1",
    )
    env.pop("AWS_PROFILE", None)
    return subprocess.run(
        [sys.executable, PROBE, "--csv-dir", str(directory)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )


def _verdict(stdout, name):
    """The PASS or FAIL printed beside one named assertion, exactly once."""
    lines = [line for line in stdout.splitlines() if line.endswith(f"] {name}")]
    assert len(lines) == 1, (name, lines)
    return lines[0].strip().split("]")[0].lstrip("[")


def test_a_correct_set_passes_every_as_written_and_replay_assertion(tmp_path):
    probe = load_probe()
    _write_set(probe, tmp_path)
    result = _run(tmp_path)
    for module in probe.PRODUCERS:
        name = f"{module}: the shipped column agrees with this tree's map"
        assert _verdict(result.stdout, name) == "PASS", result.stdout
        name = f"{module}: 9-column header, no row gained or lost, every tag correct"
        assert _verdict(result.stdout, name) == "PASS", result.stdout


def test_one_wrong_row_fails_its_producer_as_written_and_nothing_else(tmp_path):
    probe = load_probe()
    spoil = "agentcore"
    assert spoil in probe.PRODUCERS
    _write_set(probe, tmp_path, spoil=spoil)
    result = _run(tmp_path)
    assert result.returncode == FAIL, result.stdout + result.stderr
    for module in probe.PRODUCERS:
        name = f"{module}: the shipped column agrees with this tree's map"
        expected = "FAIL" if module == spoil else "PASS"
        assert _verdict(result.stdout, name) == expected, result.stdout
        # The replay rebuilds each row from the map, so it agrees with itself and
        # has to stay green. That is what shows the red above is the as-written
        # assertion and not the replay beside it.
        name = f"{module}: 9-column header, no row gained or lost, every tag correct"
        assert _verdict(result.stdout, name) == "PASS", result.stdout
    assert (
        f"  failing assertion: {spoil}: the shipped column agrees with this "
        "tree's map" in result.stdout
    )
    assert "1 producer(s) disagreeing" in result.stdout
