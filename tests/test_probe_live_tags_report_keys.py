"""Which S3 keys `aisf-parity/probe_live_tags.py` reads, and how it groups them.

Two stacks write the same report CSVs under two layouts: one at the bucket root, one
under an account id. `REPORT_RE` was anchored with a bare `^`, so `[a-z_]+` landed on
the account id, no prefixed key matched, and the probe refused with "no report CSVs at
all". It failed closed, so no wrong figure was ever published, and the message named a
cause that was not true: the bucket held a complete set from one execution.

Widening the anchor has a second-order cost, and both halves are asserted here.

  * Loosening only the prefix. A widening that also starts matching non-reports is a
    worse defect than the one it fixes, because the probe would then read a file it
    cannot parse as a report. The negative controls below carry that half, and they
    are prefixed, so they exercise the new branch of the pattern and not the old one.
  * Grouping. Once any prefix matches, one bucket can hold reports for more than one
    account, and `runs[key][module]` is last-write-wins. Pooled, one CSV from each of
    two accounts assembles a set that neither account completed, and the probe would
    print one figure over two accounts' rows with nothing to say so. The probe groups
    on the prefix, so a spread set is partial for each prefix and refused.

The two-prefix listing is the only input that separates those two designs: a
single-prefix fixture passes under both, so it cannot tell them apart.
"""

import datetime
import importlib.util
import io
import os
import sys
import types

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROBE = os.path.join(REPO_ROOT, "aisf-parity", "probe_live_tags.py")
USAGE = 2
EXECUTION = "2654a727-0000-4000-8000-000000000000"
STAMP = datetime.datetime(2026, 9, 25, 12, 0)


def load_probe():
    """The script as a module, the way tests/test_aisf_compliance_column.py loads a
    producer: it is not importable as a package."""
    spec = importlib.util.spec_from_file_location("probe_live_tags", PROBE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load_probe()


def report_key(prefix, module, execution=EXECUTION, region="us-east-1"):
    return f"{prefix}{module}_security_report_{execution}_{region}.csv"


class FakeS3:
    """As much of the S3 client as newest_execution() calls, and a record of what it
    read: a grouping bug that refuses nothing is visible in `fetched`."""

    def __init__(self, stamped):
        self.stamped = stamped
        self.fetched = []

    def list_objects_v2(self, **kwargs):
        return {
            "Contents": [
                {"Key": key, "LastModified": stamp}
                for key, stamp in self.stamped.items()
            ],
            "IsTruncated": False,
        }

    def get_object(self, **kwargs):
        self.fetched.append(kwargs["Key"])
        return {"Body": io.BytesIO(b"Check_ID,Compliance_Frameworks\n")}


def install_s3(monkeypatch, stamped):
    """`import boto3` happens inside newest_execution(), so the fake goes in
    sys.modules. Through monkeypatch, so it is out again before the next test: the
    suites in this directory import boto3 for real."""
    fake = FakeS3(stamped)
    monkeypatch.setitem(
        sys.modules, "boto3", types.SimpleNamespace(client=lambda *a, **k: fake)
    )
    return fake


def split_producers():
    """Two halves of the producer set: their union is complete and neither half is.

    Derived from PRODUCERS. Hard-coding today's names would leave the union
    incomplete the day a fifth producer ships, and an incomplete union is refused
    under both the pooled and the grouped design, so the test would keep passing and
    stop discriminating.
    """
    producers = probe.PRODUCERS
    assert len(producers) >= 2, (
        f"{len(producers)} producer(s): a complete set cannot be split across two "
        "prefixes, so the case below would prove nothing"
    )
    middle = len(producers) // 2
    return producers[:middle], producers[middle:]


# --------------------------------------------------------------------------- #
# What the pattern matches.
# --------------------------------------------------------------------------- #
def test_a_key_at_the_bucket_root_still_matches():
    """The layout that worked before the widening, kept as the control in the other
    direction: a fix that moved the match instead of adding to it reddens here."""
    found = probe.REPORT_RE.match(report_key("", "bedrock"))
    assert found, "the root layout stopped matching"
    assert found.group("prefix") == ""
    assert found.group("module") == "bedrock"


def test_a_prefixed_key_matches_and_the_prefix_is_not_read_as_the_module():
    found = probe.REPORT_RE.match(report_key("123456789012/", "bedrock"))
    assert found, "a key under an account-id prefix still misses the pattern"
    assert found.group("prefix") == "123456789012/"
    assert found.group("module") == "bedrock"
    assert found.group("execution") == EXECUTION
    assert found.group("region") == "us-east-1"


def test_a_deep_prefix_belongs_to_the_prefix_and_the_module_starts_after_it():
    found = probe.REPORT_RE.match(report_key("reports/2026/123456789012/", "sagemaker"))
    assert found, "a multi-segment prefix misses the pattern"
    assert found.group("prefix") == "reports/2026/123456789012/"
    assert found.group("module") == "sagemaker"


@pytest.mark.parametrize(
    "key,why",
    [
        (
            f"123456789012/bedrock_findings_summary_{EXECUTION}_us-east-1.csv",
            "a CSV that is not a report: the middle of the name is not "
            "_security_report_",
        ),
        (
            f"123456789012/bedrock_security_report_{EXECUTION}_us-east-1.json",
            "a report-shaped name that is not a CSV",
        ),
        (
            f"aiml-bedrock_security_report_{EXECUTION}_us-east-1.csv",
            "the prefix group has to end in a slash, so it cannot absorb the front "
            "of a filename and let a module name hold a hyphen",
        ),
        (
            "123456789012/bedrock_security_report_2654a727-0000-4000-8000-"
            "00000000000_us-east-1.csv",
            "a 35-character execution id: the {36} count is still exact",
        ),
    ],
)
def test_a_key_that_is_not_a_report_csv_still_misses(key, why):
    assert not probe.REPORT_RE.match(key), (
        f"the widening started matching {key!r}, which is {why}. Matching a "
        "non-report is worse than missing a report: the probe would read it"
    )


# --------------------------------------------------------------------------- #
# How the matches are grouped.
# --------------------------------------------------------------------------- #
def test_one_prefix_carrying_the_whole_set_is_measured(monkeypatch, capsys):
    """The positive case, so the refusals below cannot pass by refusing everything."""
    prefix = "123456789012/"
    fake = install_s3(
        monkeypatch, {report_key(prefix, m): STAMP for m in probe.PRODUCERS}
    )

    texts = probe.newest_execution("one-account", None)

    assert sorted(texts) == sorted(probe.PRODUCERS)
    assert fake.fetched == [report_key(prefix, m) for m in probe.PRODUCERS]
    assert f"prefix    {prefix}" in capsys.readouterr().out


def test_a_set_spread_across_two_prefixes_is_refused(monkeypatch, capsys):
    """The discriminating input. Its union is a complete producer set and neither
    prefix is complete alone, which is exactly the case a pooled probe measures as one
    run: it would report an execution that no account ever completed."""
    first, second = split_producers()
    stamped = {report_key("111122223333/", m): STAMP for m in first}
    stamped.update({report_key("444455556666/", m): STAMP for m in second})
    fake = install_s3(monkeypatch, stamped)

    with pytest.raises(SystemExit) as raised:
        probe.newest_execution("two-accounts", None)

    assert raised.value.code == USAGE, (
        f"exit {raised.value.code}, expected {USAGE}; this is a "
        "nothing-could-be-measured refusal, not a failed assertion"
    )
    err = capsys.readouterr().err
    assert "one prefix has to carry all of it" in err, (
        f"refused without naming the reason, so a reader sees a partial set and not "
        f"a split one:\n{err}"
    )
    assert fake.fetched == [], (
        f"read {fake.fetched} after refusing, so the refusal came too late to stop "
        "the measurement"
    )


def test_between_two_complete_prefixes_the_newer_one_is_read_whole(monkeypatch, capsys):
    """Grouping does not mean pooling the winners either: the newest complete prefix
    is measured, and every CSV read comes from it."""
    older, newer = "111122223333/", "444455556666/"
    stamped = {report_key(older, m): STAMP for m in probe.PRODUCERS}
    stamped.update(
        {
            report_key(newer, m): STAMP + datetime.timedelta(hours=1)
            for m in probe.PRODUCERS
        }
    )
    fake = install_s3(monkeypatch, stamped)

    probe.newest_execution("two-accounts", None)

    assert fake.fetched == [report_key(newer, m) for m in probe.PRODUCERS]
    assert f"prefix    {newer}" in capsys.readouterr().out


def test_a_listing_with_no_matching_key_says_so_and_counts_what_it_saw(
    monkeypatch, capsys
):
    """The message the anchor bug produced. "No report CSVs at all" described an empty
    bucket and an unreadable layout identically, and the second one was the truth."""
    fake = install_s3(monkeypatch, {"123456789012/notes.txt": STAMP})

    with pytest.raises(SystemExit) as raised:
        probe.newest_execution("wrong-layout", None)

    assert raised.value.code == USAGE
    err = capsys.readouterr().err
    assert "no key matched a report CSV name" in err
    assert "listed 1 object(s)" in err, f"no count of what was listed:\n{err}"
    assert "notes.txt" in err, f"no sample key, so the cause is still a guess:\n{err}"
    assert fake.fetched == []
