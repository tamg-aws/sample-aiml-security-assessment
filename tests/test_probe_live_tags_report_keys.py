"""Which S3 keys `aisf-parity/probe_live_tags.py` reads, and how it groups them.

`REPORT_RE` read three parts of the key more narrowly than the keys are written, and
each one produced the same refusal: "no report CSVs at all", failing closed on a
cause that was not true while the bucket held a complete set.

  * The prefix. Two stacks write the same CSVs under two layouts, one at the bucket
    root and one under an account id, and a bare `^` put `[a-z_]+` against that
    account id.
  * The execution. `[0-9a-f-]{36}` is a uuid, which is what StartExecution invents
    when nobody passes `--name`. A run named `grc-owasp-payload-probe-20260925-173028`
    wrote six report CSVs and none of them matched.
  * The region. `responsible_ai_grc_security_report_<execution>.csv` has no region
    segment at all, and bedrock and agentcore write that shape from their fallback
    branches. The reader is what widens: the shipped key is not changed to suit it.

Widening has a second-order cost, and both halves of it are asserted here.

  * Matching a non-report is worse than missing a report, because the probe would
    read a file it cannot parse. The negative controls below carry that half, and
    they are prefixed, so they exercise the widened branch of the pattern. Two of the
    three are the same controls as before the execution and region groups widened; the
    third, a 35-character execution id, is now a positive case, because the exact
    count is the constraint that was removed.
  * The two loose groups must not eat each other. An execution named `probe_20260925`
    against a loose `[a-z0-9-]+` region gave up its trailing digits to the region
    group, so the run would have been reported under a region that does not exist.

Grouping is asserted separately. Once any prefix matches, one bucket can hold reports
for more than one account, and `runs[key][module]` is last-write-wins: pooled, one CSV
from each of two accounts assembles a set that neither completed and the probe prints
one figure over two accounts' rows with nothing to say so. Keys with no region segment
group apart for the same reason in the other direction -- one such key exists per
prefix and execution, so it cannot be attributed to either region of a run executed
twice -- and the refusal names any producer found only under one.

The two-prefix listing is the only input that separates the pooled design from the
grouped one: a single-prefix fixture passes under both.
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
# The name the measured run carried. Not a uuid, 39 characters, and it is what the
# execution group has to read: `aws stepfunctions start-execution --name` takes any
# name, and the console's own re-run button sets one.
NAMED_EXECUTION = "grc-owasp-payload-probe-20260925-173028"
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
    """One key, region optional. `region=None` is the GRC shape, written verbatim.

    Built by concatenation and not by dropping a segment from the region-bearing form,
    so the region-less key here is the string the handler writes rather than a
    derivative of the other case.
    """
    tail = f"_{region}" if region is not None else ""
    return f"{prefix}{module}_security_report_{execution}{tail}.csv"


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


# The shapes one bucket holds, written out as literal keys instead of built by the
# helper above. A helper that constructs both sides of a comparison agrees with
# itself, and all three defects here were defects in reading a literal key. Measured
# against account 178113193057, bucket
# aiml-sec-178113193057-aimlassessmentbucket-gywyxnvqxpvx, where the run named below
# wrote six report CSVs and every one of them missed the pattern.
RAW_KEYS = [
    (
        "123456789012/bedrock_security_report_2654a727-0000-4000-8000-"
        "000000000000_us-east-1.csv",
        ("123456789012/", "bedrock", EXECUTION, "us-east-1"),
        "prefixed, uuid execution, region-bearing: the shape that already worked",
    ),
    (
        "sagemaker_security_report_2654a727-0000-4000-8000-000000000000_eu-west-1.csv",
        ("", "sagemaker", EXECUTION, "eu-west-1"),
        "the root layout, and a region that is not the default",
    ),
    (
        "agentcore_security_report_grc-owasp-payload-probe-20260925-"
        "173028_us-east-1.csv",
        ("", "agentcore", NAMED_EXECUTION, "us-east-1"),
        "a named execution, which is exactly what the {36} count refused",
    ),
    (
        "123456789012/agent_registry_security_report_grc-owasp-payload-probe-"
        "20260925-173028_ap-southeast-2.csv",
        ("123456789012/", "agent_registry", NAMED_EXECUTION, "ap-southeast-2"),
        "a named execution under a prefix, with an underscore inside the module name",
    ),
    (
        "responsible_ai_grc_security_report_grc-owasp-payload-probe-20260925-"
        "173028.csv",
        ("", "responsible_ai_grc", NAMED_EXECUTION, None),
        "the GRC key, which carries no region segment at all",
    ),
    (
        "owasp_security_report_probe_20260925_us-east-1.csv",
        ("", "owasp", "probe_20260925", "us-east-1"),
        "an underscore inside the execution name, which the split has to keep on the "
        "execution side of the last region-shaped tail",
    ),
    (
        "bedrock_security_report_probe_20260925.csv",
        ("", "bedrock", "probe_20260925", None),
        "no region and an underscore inside the execution name, which is the input "
        "the region's shape is tight for: against `[a-z0-9-]+` the optional group "
        "matches `_20260925`, and the run is reported under a region 20260925 that "
        "does not exist. The same name WITH a region parses correctly under both "
        "shapes, because a loose region still has to be followed by `.csv`, so the "
        "region-bearing case above cannot tell the two apart",
    ),
]


@pytest.mark.parametrize("key,expected,why", RAW_KEYS)
def test_every_shape_the_bucket_holds_parses_into_its_parts(key, expected, why):
    found = probe.REPORT_RE.match(key)
    assert found, f"{key!r} misses the pattern: {why}"
    parts = (
        found.group("prefix"),
        found.group("module"),
        found.group("execution"),
        found.group("region"),
    )
    assert parts == expected, f"{key!r} parsed as {parts}, expected {expected}: {why}"


def test_the_35_character_execution_id_is_now_a_positive_case():
    """The one negative control the fix removes, kept as a positive.

    The exact count was the constraint, so a key one character short of a uuid has to
    parse now: it is what a named execution looks like to the pattern. Dropping this
    case instead of flipping it would leave no record that the boundary moved.
    """
    short = (
        "123456789012/bedrock_security_report_2654a727-0000-4000-8000-"
        "00000000000_us-east-1.csv"
    )
    found = probe.REPORT_RE.match(short)
    assert found, "an execution id that is not 36 characters has to parse now"
    assert found.group("execution") == "2654a727-0000-4000-8000-00000000000"
    assert found.group("region") == "us-east-1"


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
            "123456789012/bedrock_security_report_.csv",
            "no execution at all: the group is non-greedy, not optional, so a key "
            "with nothing between the literal and the extension still misses",
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


def test_a_named_execution_is_measured_and_not_only_parsed(monkeypatch, capsys):
    """The end-to-end half of the execution widening.

    The pattern test above proves the key parses. This proves the run assembles,
    survives the completeness rule and is read: the defect was that a named run read
    as an empty bucket, and a pattern fix that left the grouping key wrong would still
    print that refusal.
    """
    prefix = "178113193057/"
    fake = install_s3(
        monkeypatch,
        {
            report_key(prefix, m, execution=NAMED_EXECUTION): STAMP
            for m in probe.PRODUCERS
        },
    )

    texts = probe.newest_execution("named-run", None)

    assert sorted(texts) == sorted(probe.PRODUCERS)
    assert fake.fetched == [
        report_key(prefix, m, execution=NAMED_EXECUTION) for m in probe.PRODUCERS
    ]
    assert f"execution {NAMED_EXECUTION}" in capsys.readouterr().out


def test_a_producer_found_only_under_a_regionless_key_is_named_in_the_refusal(
    monkeypatch, capsys
):
    """The grouping decision, and the message it exists to produce.

    A key with no region segment forms its own group, so this listing holds no
    complete set: one producer is in a region-less group of its own and the rest are
    in a region-bearing group without it. The refusal has to name the producer and the
    reason, because "no execution has a CSV for all of" reads as a run that never
    finished, and the repair is in the key shape.
    """
    prefix = "178113193057/"
    orphan, *rest = probe.PRODUCERS
    stamped = {report_key(prefix, m): STAMP for m in rest}
    stamped[report_key(prefix, orphan, region=None)] = STAMP
    fake = install_s3(monkeypatch, stamped)

    with pytest.raises(SystemExit) as raised:
        probe.newest_execution("regionless-producer", None)

    assert raised.value.code == USAGE
    err = capsys.readouterr().err
    assert f"'{orphan}'] appear only under a key with no region segment" in err, (
        f"{orphan} is the whole cause and the refusal does not name it:\n{err}"
    )
    assert "no key matched a report CSV name" not in err, (
        "the region-less key parsed, so the refusal must not report an unreadable "
        f"layout:\n{err}"
    )
    assert fake.fetched == []


def test_a_regionless_key_does_not_join_two_regions_of_one_run_name(monkeypatch):
    """Why the region-less group stays apart, as the input that makes it matter.

    One run name executed in two regions writes two region-bearing sets and one
    region-less key, because the region-less name has nowhere to put the second. A
    design that attached it to every region group would report it as part of whichever
    set won, measuring one region's CSV against another region's run. Kept apart, both
    region-bearing sets are complete on their own and the region-less key is a group of
    one that completes nothing.
    """
    prefix = "178113193057/"
    stamped = {
        report_key(prefix, m, region=region): STAMP
        for region in ("us-east-1", "eu-west-1")
        for m in probe.PRODUCERS
    }
    grc = f"{prefix}responsible_ai_grc_security_report_{EXECUTION}.csv"
    stamped[grc] = STAMP + datetime.timedelta(hours=2)
    fake = install_s3(monkeypatch, stamped)

    texts = probe.newest_execution("two-regions", "eu-west-1")

    assert sorted(texts) == sorted(probe.PRODUCERS)
    assert fake.fetched == [
        report_key(prefix, m, region="eu-west-1") for m in probe.PRODUCERS
    ]
    assert grc not in fake.fetched, (
        "the region-less key was read as part of a region's set, which is the "
        "attribution the grouping refuses"
    )


def test_the_region_filter_counts_the_keys_it_excluded(monkeypatch, capsys):
    """A filter that removes everything and a bucket that held nothing print the same
    refusal otherwise, and only one of them is repaired by passing a different
    --region."""
    prefix = "178113193057/"
    fake = install_s3(
        monkeypatch,
        {report_key(prefix, m, region="us-east-1"): STAMP for m in probe.PRODUCERS},
    )

    with pytest.raises(SystemExit) as raised:
        probe.newest_execution("wrong-region", "eu-west-1")

    assert raised.value.code == USAGE
    err = capsys.readouterr().err
    assert (
        f"--region eu-west-1 excluded {len(probe.PRODUCERS)} matching key(s)" in err
    ), f"the refusal does not say the filter is what emptied the listing:\n{err}"
    assert fake.fetched == []


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
