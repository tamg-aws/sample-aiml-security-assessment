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

# The live leg for the tag column. Its CSVs cannot be committed, so the catchers
# are the synthetic two-row fixtures in tests/test_probe_live_tags_assertions.py.
PROBE_TAGS = "aisf-parity/probe_live_tags.py"

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

# The same entry shape with no qualifier: a single bare tag, which is a covered
# control. Used when no map carries a `(partial)` entry, see
# partial_qualifier_mutation().
BARE_ENTRY = re.compile(
    r'^(?P<indent>[ ]+)"(?P<check>[A-Z]{2,3}-\d{2})": '
    r'"AISF (?P<control>AIR(?:-[A-Z0-9]+)+)",$'
)

# One name for the derived entry in either direction, so GROUPS keys a string
# that no check id, map, or verdict population can make stale.
DERIVED_PARTIAL_QUALIFIER_NAME = "a single tag's (partial) qualifier flipped"

# Placeholder for the derived `(partial)` entry, replaced in resolve_mutations()
# before anything reads a find-string. A sentinel rather than an append, because
# the position of the entry is the position of the comment that explains it.
DERIVED_PARTIAL_QUALIFIER = "derive: the (partial) qualifier entry"

# The report section's scope_text, whose coverage sentence carries figures that
# move every time the ledger does, so its entry is built at run time as well.
TEMPLATE = f"{SECURITY}/generate_consolidated_report/report_template.py"

# One name and one placeholder for the derived scope_text figure entry, for the
# reasons DERIVED_PARTIAL_QUALIFIER_NAME and DERIVED_PARTIAL_QUALIFIER give.
DERIVED_SCOPE_COVERED_NAME = "the report section's covered figure drifts by one"
DERIVED_SCOPE_COVERED = "derive: the scope_text covered figure entry"
DERIVED_SCOPE_WITHOUT_ROW_NAME = (
    "the report section's covered-without-a-row figure drifts by one"
)
DERIVED_SCOPE_WITHOUT_ROW = "derive: the scope_text covered-without-a-row entry"

# The covered figure as the template writes it, on one source line.
SCOPE_COVERED = re.compile(r"(?<![-\w])(\d+) of the \d+ are covered by checks")
# The without-row figure, the pattern gate 12 reads it with.
SCOPE_WITHOUT_ROW = re.compile(r"the (\d+) covered controls without a row")

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
    {
        "name": "the incumbent-name lookup reverts to its fail-open form",
        "file": BUILD_LEDGER,
        # WHAT THIS ENTRY ACTUALLY EXERCISES. The shipped form does two things:
        # it raises on an id the map does not hold, and it flattens the three
        # tuple-valued entries. This mutation removes both, but only the second
        # is observable HERE, because the map is now complete and so no id is
        # unmapped -- the `if i in INCUMBENT_NAMES` filter drops nothing today.
        # What goes red is the tuple leaking into the row unflattened. The
        # unmapped-id leg is a separate discriminating input and has its own
        # entry below; claiming this one covers it would be claiming a catch the
        # run does not produce.
        #
        # This entry went UNCAUGHT at 6455a80, 21 of 22, and the reason is worth
        # keeping: the line it edits lived inside build_ledger.build(), and
        # NEITHER catcher runs build_ledger.py. check_ledger.py reads the shipped
        # json, which a mutation to the generator cannot touch until the generator
        # is re-run, and gen_compliance_maps rendered its comparison side from a
        # second copy of the same mapping. The fix was to give both sides one
        # table_fields(), not to drop the entry: a mutation no catcher can observe
        # is a statement about the gates, not about the mutation.
        "defect": "the lookup stops flattening the ids that publish more than one "
        "finding name, so a row carries a nested tuple where the schema says "
        "strings. Observed: gate 15 names every row whose incumbents include one of "
        "those ids as differing between the shipped json and a fresh render of the "
        "verdict table. No count and no id list here on purpose -- the previous "
        "text said three ids and named them, and went stale the hour the FND block "
        "was assessed, because assessing it added four more. Nothing gates prose in "
        "a mutation entry, so the only safe figure is none. This is half of the "
        "shipped defect, restored",
        "find": '        "incumbent_names": [name for i in incumbents for name in '
        "published_names(i)],\n",
        "replace": '        "incumbent_names": [\n'
        "            INCUMBENT_NAMES[i] for i in incumbents if i in INCUMBENT_NAMES\n"
        "        ],\n",
    },
    {
        "name": "an incumbent is cited with no INCUMBENT_NAMES entry at all",
        "file": BUILD_LEDGER,
        # The other half, and the one that actually shipped: 12 of 78 rows
        # published an incumbent check_id beside an empty name list -- every
        # check phase 3 added, because the map was never extended with them. It
        # failed open in the only direction that matters: gate 8 decides whether
        # a new_id row quotes its incumbent by reading that same list, so a
        # missing name could only ever make that gate easier to pass.
        #
        # The catcher differs from every other entry here and that is the point.
        # published_names raises, so build_ledger REFUSES to regenerate rather
        # than writing a row it cannot name. check_ledger then reads the last
        # good json and its first fourteen gates pass on it; what goes red is
        # gate 15, which runs the generator as a subprocess and surfaces the
        # exit code. Measured: build_ledger exit 1 with the KeyError's own
        # remedy text, check_ledger 18/19 with gate 15 the one red.
        "defect": "a check is cited as an incumbent without recording the finding "
        "name it publishes, so the ledger has no name to print for it. Under the "
        "fail-open form this shipped as a blank name; under the strict form the "
        "build stops here instead",
        "find": '    "BR-46": "Knowledge Base Source Data Classification",\n',
        "replace": "",
    },
    {
        "name": "an incumbent is named something it does not publish",
        "file": BUILD_LEDGER,
        "defect": "the ledger prints a finding name no create_finding call emits, "
        "so a reader filtering the report CSV for the name the ledger gave them "
        "matches nothing. This is the error the map already carried for SM-02, "
        "which named 'SageMaker IAM Permissions' while the check publishes "
        "'SageMaker IAM Permissions Check'",
        "find": '    "BR-46": "Knowledge Base Source Data Classification",\n',
        "replace": '    "BR-46": "Knowledge Base Source Classification",\n',
    },
    {
        "name": "a control is dropped from SCOPE27",
        "file": BUILD_LEDGER,
        # Gate 22 alone reads SCOPE27, so it is the only catcher: the json, the
        # maps and ROWS are all unchanged by this edit.
        "defect": "the scope constant loses a foundation control while its row "
        "stays in the verdict table, so the stated scope and the ledger's rows "
        "no longer describe the same controls",
        "find": '        "AIR-FND-NET-08",\n        "AIR-PHY-EDG-01",\n',
        "replace": '        "AIR-FND-NET-08",\n',
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
    # naming one. When no `tighten` row is open, no map carries a `(partial)`
    # tag, and the entry adds one to a covered tag instead. See
    # partial_qualifier_mutation().
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
    # -------------------------------------- the field names the APIs return
    # Both of these revert a field name to the spelling that shipped, and both
    # spellings are real: each belongs to a different AWS API. That is the class
    # of defect no assertion inside the check can catch, because the leg reading
    # the absent key does not run, and a leg that does not run publishes nothing
    # to disagree with. Each one's unit fixture set the same absent key the code
    # read, so the test agreed with the code it covered and with nothing else --
    # 2839 green tests over both defects. The catcher for each entry below is the
    # test whose fixture carries the documented shape, which is the only kind of
    # test that can tell the two spellings apart.
    {
        "name": "AC-01 reads Bedrock's spelling of the subnet field",
        "file": AGENTCORE,
        "defect": "GetAgentRuntime reports a VPC runtime's subnets under "
        "networkModeConfig, spelled `subnets`, in the same object the egress leg "
        "twelve lines above reads for securityGroups. `subnetIds` is Bedrock's "
        "VpcConfig spelling and networkConfiguration has no such key, so "
        "reverting leaves the subnet list empty for every runtime, the "
        "route-table block below it unreachable, and no public subnet ever "
        "reported. This half fails OPEN",
        "find": (
            "                            subnet_ids = (\n"
            '                                network_config.get("networkModeConfig")'
            " or {}\n"
            '                            ).get("subnets") or []'
        ),
        "replace": (
            "                            subnet_ids = "
            'network_config.get("subnetIds", [])'
        ),
    },
    {
        "name": "BR-11 reads the output key off the wrong object",
        "file": BEDROCK,
        "defect": "GetModelCustomizationJob returns an outputDataConfig holding "
        "s3Uri alone and reports the output key as a top-level "
        "outputModelKmsKeyArn. Reverting to outputDataConfig.kmsKeyId makes "
        "has_cmk always False, so the passing branch is unreachable and every "
        "custom model is reported as needing review. This half fails CLOSED, "
        "which is the one a reader mistakes for a check finding real problems",
        "find": 'if job_details.get("outputModelKmsKeyArn"):',
        "replace": 'if job_details.get("outputDataConfig", {}).get("kmsKeyId"):',
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
    {
        "name": "a mutation group disappears from the published battery figures",
        "file": AISF_DOC,
        # Respells one group phrase rather than changing one of its digits. A
        # wrong digit is the easy half and the equality check finds it; the half
        # that needs a mutation is a group the sentence stops naming at all,
        # because a figure that is absent cannot disagree with a computed count.
        # The find-string is a phrase and not a number on purpose: a number here
        # would go stale every time the battery grows, and the entry would then be
        # lost to the pre-flight rather than exercising anything.
        # The defect text below counts no groups for the same reason: it said
        # "five of the six" while the battery had grown to seven groups, which is
        # the drift this entry exists to catch, in the entry itself.
        "defect": "step 7 of the parity doc splits the battery by group, and this "
        "leaves one of those groups unnamed in the sentence. Gate 20 has to "
        "report that group's figure as occurring zero times in the slice, not "
        "reconcile the ones it can still find",
        "find": "1 in the census anchor",
        "replace": "1 in the census marker",
    },
    # ------------------------------------------------- the coverage bullets
    # Three document mutations over the two figure families that shipped stale
    # while every gate passed. All three find-strings are digit-free and hold no
    # line break, for the reason the census entry records: a phrase carrying a
    # figure goes stale the next time the figure moves, and the entry is then lost
    # to the pre-flight instead of exercising anything.
    {
        "name": "the coverage bullet anchor is reworded",
        "file": AISF_DOC,
        "defect": "the ledger reads ten verdict figures out of the Coverage and "
        "Traceability bullets, located as one block by this label. A reworded label "
        "has to return zero blocks and leave all ten figures absent. Widening back "
        "to the whole document is the failure it must not become: the word "
        "`covered` publishes two different populations eleven words apart inside "
        "this one bullet, so a whole-file read answers with whichever the pattern "
        "reaches first",
        "find": "- **Coverage:**",
        "replace": "- **Coverage note:**",
    },
    {
        "name": "the coverage bullet stops saying no control is unassessed",
        "file": AISF_DOC,
        "defect": "this is the one published figure in the block that is a word and "
        "not a digit: the count is zero and the bullet states it as prose. No "
        "figure pattern can reach it, so the gate asserts the phrase while the "
        "ledger computes zero and a digit once it does not. Dropping the clause "
        "leaves the bullet silent about a whole verdict, which is how `unassessed` "
        "came to be published as 11 while the ledger had none",
        "find": "with no control left",
        "replace": "with few controls left",
    },
    {
        "name": "the multi-control sentence stops publishing its count",
        "file": AISF_DOC,
        "defect": "the count of pipe-joined checks is published twice, here and as "
        "the back-reference the next paragraph rests on. Pooling the two spellings "
        "passes this mutation: the back-reference survives as the pool's only "
        "member and agrees with the maps, leaving a document that says `14 of those "
        "23` with nothing defining 23. Each sentence is required to carry it",
        "find": "checks name more than one control",
        "replace": "checks name several controls",
    },
    # A figure edit and not a phrase edit, unlike the entries above: the defect
    # this guards is the hand bump that was missed, and a reworded phrase would
    # exercise the absent branch instead. Derived, so the figure moving does not
    # cost the battery the entry.
    DERIVED_SCOPE_COVERED,
    # The second figure in the same sentence, read by the same gate leg. Without
    # its own entry the leg's reader for it is proven only by hand.
    DERIVED_SCOPE_WITHOUT_ROW,
    # ----------------------------------------------------- the live tag probe
    # The probe's positive controls in LIVE-FIXTURES.md were run once by hand
    # against a real run's CSVs, and `--selftest` hands `tag_mismatches` one row.
    # Three of these four survived every probe test before the two-row fixtures
    # existed; only the inverted comparison was caught, by `--selftest`.
    {
        "name": "the live tag probe reads only the first row",
        "file": PROBE_TAGS,
        "defect": "a run whose first row per producer is tagged correctly passes "
        "the as-written audit whatever every later row carries, so a deployed "
        "artifact built from a stale map reads as agreeing with this tree",
        "find": "    for index, row in enumerate(rows):\n",
        "replace": "    for index, row in enumerate(rows[:1]):\n",
    },
    {
        "name": "the live tag probe passes when any row agrees",
        "file": PROBE_TAGS,
        "defect": "the as-written audit passes a producer while fewer than all of "
        "its rows disagree, so one stale tag among correct ones is a PASS. A "
        "one-row fixture cannot tell this from `all`",
        "find": "    return not wrong, (\n",
        "replace": "    return len(wrong) < len(rows), (\n",
    },
    {
        "name": "the live tag probe's as-written verdict is discarded",
        "file": PROBE_TAGS,
        "defect": "main() computes the as-written verdict and records a PASS "
        "regardless, while the detail line beside it still counts the "
        "disagreeing rows. The replay assertion stays green on the same set "
        "because it compares the map against itself, so nothing else reddens",
        "find": "the shipped column agrees with this tree's map\", ok, detail",
        "replace": "the shipped column agrees with this tree's map\", True, detail",
    },
    {
        "name": "the live tag probe's comparison is inverted",
        "file": PROBE_TAGS,
        "defect": "every correctly tagged row is reported as a mismatch and "
        "every wrong one passes, so a live run built from this tree fails and "
        "one built from a different map passes",
        "find": "        elif actual != expected:\n",
        "replace": "        elif actual == expected:\n",
    },
    {
        "name": "a ForAnyValue: model-list Deny is credited again",
        "file": BEDROCK,
        "defect": "a ForAnyValue:ArnNotLike Deny on bedrock:ModelArn reads as a "
        "complete allow-list with no gaps, so BR-42 and BR-43 pass while "
        "InvokeModelWithResponseStream, which sends no bedrock:ModelArn, stays "
        "open to every model",
        "find": '        if list_key is not None and list_key[0].startswith("foranyvalue:"):\n',
        "replace": "        if False:\n",
    },
    {
        "name": "a non-available VPC endpoint counts as coverage again",
        "file": BEDROCK,
        "defect": "a pendingAcceptance, rejected or failed Bedrock endpoint is "
        "collected as coverage, so BR-02 passes a workload whose VPC endpoint "
        "carries no traffic",
        "find": '            if str(endpoint.get("State", "")).lower() != "available":\n',
        "replace": "            if False:\n",
    },
    {
        "name": "a role shared by two Regions passes BR-57 again",
        "file": BEDROCK,
        "defect": "the cross-Region leg counts a role as shared only when three "
        "Regions run it, so agents in two Regions that share one role pass",
        "find": "            if len(placed) > 1\n",
        "replace": "            if len(placed) > 2\n",
    },
    {
        "name": "a single-Region event data store elsewhere counts again",
        "file": BEDROCK,
        "defect": "BR-06 credits a store homed in another assessed Region that "
        "records only its own Region, so this Region's Bedrock calls pass "
        "unrecorded",
        "find": '        if home_region and detail.get("MultiRegionEnabled") is not True:\n',
        "replace": "        if False:\n",
    },
    {
        "name": "a training bucket open to every principal passes BR-42 again",
        "file": BEDROCK,
        "defect": "the bucket-policy leg drops every open grant, so a training "
        "bucket any AWS identity can read passes on identity policies alone",
        "find": '            if not grants["open"]:\n',
        "replace": "            if True:\n",
    },
    {
        "name": "a user reaching AI through a role leaves BR-50 again",
        "file": BEDROCK,
        "defect": "a user whose only route to AI is sts:AssumeRole into a role the "
        "account trusts drops out of scope, so its access key is never judged",
        "find": "                elif delegates and _identity_allows_assume_role("
        "permissions, role_arn):\n",
        "replace": "                elif False:\n",
    },
    {
        "name": "a KENDRA knowledge base goes back to manual review",
        "file": BEDROCK,
        "defect": "BR-20 stops reading the Kendra index key, so a KENDRA knowledge "
        "base whose index names no customer managed key reads N/A, not Failed",
        "find": '                    elif kb_type == "KENDRA":\n',
        "replace": "                    elif False:\n",
    },
    {
        "name": "a wildcard PrincipalArn exemption passes BR-47",
        "file": BEDROCK,
        "defect": "BR-47 credits an aws:PrincipalArn exclusion with a wildcard or "
        "policy variable in its ARN, so a TLS Deny that exempts every role reads "
        "Passed",
        "find": '            and not any(character in arn for character in "*?$")\n',
        "replace": "            and True\n",
    },
    {
        "name": "a second ListMemories page goes unread in BR-04",
        "file": BEDROCK,
        "defect": "BR-04 stops after the first ListMemories page, so a memory on a "
        "later page gets no event retention row",
        "find": '            summaries.extend(page.get("memories") or [])\n',
        "replace": '            summaries.extend(page.get("memories") or [])\n'
        "            break\n",
    },
    {
        "name": "an agent guardrail screens retrieved chunks for BR-26 again",
        "file": BEDROCK,
        "defect": "BR-26 credits an agent or flow guardrail as screening the chunks a "
        "knowledge base returns, so an unredacted source behind one reads N/A",
        "find": "    fronts_screen_chunks: bool = False,\n",
        "replace": "    fronts_screen_chunks: bool = True,\n",
    },
    {
        "name": "an object written after the redaction job passes BR-26 again",
        "file": BEDROCK,
        "defect": "BR-26 stops comparing each ingested object with the redaction "
        "job's EndTime, so an unredacted object under its output is credited",
        "find": "                    if gap > 0:\n",
        "replace": "                    if False:\n",
    },
    {
        "name": "a guardrail that lets an example key through passes the BR-26 probe",
        "file": BEDROCK,
        "defect": "BR-26 reads every ApplyGuardrail probe as Passed, so a version "
        "that returns the example credentials unmasked is credited",
        "find": '        if action == "GUARDRAIL_INTERVENED" and not missing:\n',
        "replace": "        if True:\n",
    },
    {
        "name": "BR-51 stops matching the tag key to its access control attribute",
        "file": BEDROCK,
        "defect": "BR-51 never finds the configured attribute for a Deny's tag key, "
        "so every guarded permission set reads as taking its tag from SAML alone",
        "find": '    sources = abac["attributes"].get(tag.lower())\n',
        "replace": '    sources = abac["attributes"].get("")\n',
    },
    {
        "name": "a public Redshift Serverless workgroup passes BR-20",
        "file": BEDROCK,
        "defect": "BR-20 stops reading publiclyAccessible on the workgroup behind a SQL "
        "knowledge base, so a public query engine with a customer key passes",
        "find": '    if workgroup.get("publiclyAccessible") is True:\n',
        "replace": "    if False:\n",
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
    """Build the `(partial)` mutation against whichever entry shape the maps carry.

    Reads the maps in sorted path order and takes the first single-tag
    `(partial)` entry, so the entry survives a rename, a re-hosting, and the
    conversion of any one map's qualifiers, and drops its qualifier. When no map
    carries one, which is the state once every `tighten` row has closed, it adds
    the qualifier to the first single bare tag instead: gate 14 derives each
    tag's qualifier from the ledger verdict, so a `(partial)` on a covered control
    reds it from the other side. That direction does not reach the branch that
    catches a dropped qualifier, and the defect text says which one ran. When
    neither shape exists, this fails loudly instead of skipping, because gate
    14's qualifier derivation would have nothing left to break.
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
                "name": DERIVED_PARTIAL_QUALIFIER_NAME,
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
    for path in maps:
        for line in path.read_text(encoding="utf-8").splitlines():
            found = BARE_ENTRY.match(line)
            if not found:
                continue
            check, control = found["check"], found["control"]
            return {
                "name": DERIVED_PARTIAL_QUALIFIER_NAME,
                "file": path.relative_to(repo).as_posix(),
                "defect": (
                    f"{check}'s tag marks {control} as partly covered, a control "
                    "the ledger says is covered, so the tag column understates a "
                    "verdict the ledger publishes. No map carries a (partial) "
                    "tag, so this is the added-qualifier direction; the "
                    "dropped-qualifier branch of gate 14 is not reached"
                ),
                "find": f"{line}\n",
                "replace": (
                    f'{found["indent"]}"{check}": "AISF {control} (partial)",\n'
                ),
            }
    die(
        "no tag map carries a single-tag entry, bare or (partial), so this "
        f"mutation has nothing to break. Maps read, in order: "
        f"{', '.join(p.relative_to(repo).as_posix() for p in maps)}.\n"
        "  If the qualifier has been retired on purpose, delete the derived "
        "entry and say so in the commit; do not leave a mutation that cannot "
        "apply, because the run would abort partway and read as a short pass."
    )
    raise AssertionError("unreachable: die() raises")


def scope_figure_mutation(
    repo: Path, pattern: re.Pattern, name: str, figure: str
) -> dict[str, str]:
    """Raise one scope_text figure by one, whatever it reads today.

    The find-string is the phrase with its current digits, read from the
    template, so it is unique for the same reason the gate's pattern is. When
    the phrase is gone this fails loudly: the gate would then be reading an
    absent figure, and a skipped entry would read as a shorter clean run.
    """
    text = (repo / TEMPLATE).read_text(encoding="utf-8")
    hits = pattern.findall(text)
    if len(hits) != 1:
        die(
            f"{TEMPLATE} carries {len(hits)} copies of the {figure} phrase "
            f"{pattern.pattern!r}, not 1, so the scope_text figure "
            "mutation has nothing unique to break"
        )
    found = pattern.search(text)
    raised = str(int(found[1]) + 1)
    start = found.start(1) - found.start()
    return {
        "name": name,
        "file": TEMPLATE,
        "defect": (
            f"the report publishes {raised} {figure} controls while the ledger "
            f"computes {found[1]}, the missed hand bump in a copy the report "
            "ships that no gate read before gate 12's coverage leg"
        ),
        "find": found[0],
        "replace": found[0][:start] + raised + found[0][start + len(found[1]) :],
    }


# Which published figure each mutation counts toward, keyed by name because the
# target file does not separate them: the tag-column group spans five files, and
# build_ledger.py carries two unrelated groups. The value is the phrase the doc
# uses, so `docs/SECURITY_CHECKS_AISF.md` can be gated against a count derived
# from this list instead of a number someone typed. Ordered as the doc reads.
#
# Keyed by name, so GROUPS and MUTATIONS are asserted to describe the same
# population in BOTH directions below. A roster keyed by name that has drifted
# out of the population guards nothing: an entry whose name was reworded would
# silently leave the census, and the doc figure would still reconcile against
# the smaller list. That is the failure this pairing exists to prevent, which is
# why a missing key is an error and not a default group.
GROUPS: dict[str, str] = {
    "collapse-note append removed": "defects in the derived mapping",
    "N/A clause removed from the collapse note": "defects in the derived mapping",
    "critical maps to a lowercase severity (length-identical)": (
        "defects in the derived mapping"
    ),
    "AISF-05 reverted to the pre-rename AI-05": "defects in the derived mapping",
    "source findings collapsed to one status per check id": (
        "defects in the derived mapping"
    ),
    "S3 Vectors CMK test accepts any sseType": "in `BR-20`'s S3 Vectors legs",
    "S3 Vectors missing bucket policy reverted to N/A": (
        "in `BR-20`'s S3 Vectors legs"
    ),
    "S3 Vectors index encryption accepts any sseType": ("in `BR-20`'s S3 Vectors legs"),
    "the index verdict dropped from the S3 Vectors combine": (
        "in `BR-20`'s S3 Vectors legs"
    ),
    "an index inheriting the bucket's key is failed": "in `BR-20`'s S3 Vectors legs",
    "the knowledge base loop truncated to the first entry": (
        "in `BR-20`'s S3 Vectors legs"
    ),
    DERIVED_PARTIAL_QUALIFIER_NAME: "in the tag column",
    "a (1 of N checks) qualifier dropped from a joint leg": "in the tag column",
    "a tag placed in a module that does not emit the check": "in the tag column",
    "the tag sentinel defaults to empty instead of None (length-identical)": (
        "in the tag column"
    ),
    "agentcore's empty-report header loses the column": "in the tag column",
    "AC-01 reads Bedrock's spelling of the subnet field": (
        "in the API field names the checks read"
    ),
    "BR-11 reads the output key off the wrong object": (
        "in the API field names the checks read"
    ),
    "the incumbent-name lookup reverts to its fail-open form": (
        "in the incumbent-name map"
    ),
    "an incumbent is cited with no INCUMBENT_NAMES entry at all": (
        "in the incumbent-name map"
    ),
    "an incumbent is named something it does not publish": (
        "in the incumbent-name map"
    ),
    "ledger markdown renders a figure from the wrong summary key": (
        "in the ledger's markdown renderer"
    ),
    "a control is dropped from SCOPE27": "in the foundation scope",
    "the census anchor sentence is reworded": "in the census anchor",
    "a mutation group disappears from the published battery figures": (
        "in the published battery figures"
    ),
    "the coverage bullet anchor is reworded": "in the coverage bullets",
    "the coverage bullet stops saying no control is unassessed": (
        "in the coverage bullets"
    ),
    "the multi-control sentence stops publishing its count": (
        "in the multi-control figures"
    ),
    DERIVED_SCOPE_COVERED_NAME: "in the report section's coverage figures",
    DERIVED_SCOPE_WITHOUT_ROW_NAME: "in the report section's coverage figures",
    "the live tag probe reads only the first row": "in the live tag probe",
    "the live tag probe passes when any row agrees": "in the live tag probe",
    "the live tag probe's as-written verdict is discarded": "in the live tag probe",
    "the live tag probe's comparison is inverted": "in the live tag probe",
    "a ForAnyValue: model-list Deny is credited again": (
        "in the Bedrock condition parsers"
    ),
    "a non-available VPC endpoint counts as coverage again": (
        "in the Bedrock endpoint collector"
    ),
    "a role shared by two Regions passes BR-57 again": (
        "in the Bedrock cross-Region agent roles"
    ),
    "a single-Region event data store elsewhere counts again": (
        "in the Bedrock CloudTrail Lake reader"
    ),
    "a training bucket open to every principal passes BR-42 again": (
        "in the Bedrock training bucket policies"
    ),
    "a user reaching AI through a role leaves BR-50 again": (
        "in the Bedrock AI user population"
    ),
    "a KENDRA knowledge base goes back to manual review": (
        "in the Bedrock knowledge base stores"
    ),
    "a wildcard PrincipalArn exemption passes BR-47": (
        "in the Bedrock data path TLS exemptions"
    ),
    "a second ListMemories page goes unread in BR-04": (
        "in the Bedrock AgentCore memory retention"
    ),
    "an agent guardrail screens retrieved chunks for BR-26 again": (
        "in the Bedrock knowledge base redaction"
    ),
    "an object written after the redaction job passes BR-26 again": (
        "in the Bedrock knowledge base redaction"
    ),
    "a guardrail that lets an example key through passes the BR-26 probe": (
        "in the Bedrock guardrail output probe"
    ),
    "BR-51 stops matching the tag key to its access control attribute": (
        "in the Bedrock Identity Center attributes"
    ),
    "a public Redshift Serverless workgroup passes BR-20": (
        "in the Bedrock knowledge base stores"
    ),
}


def resolve_mutations(repo: Path) -> list[dict[str, str]]:
    """MUTATIONS with every derived entry built against this tree, plus its group.

    The group is attached here rather than written into each literal so that the
    derived entry, whose name is built at run time, cannot skip it.
    """
    resolved = [
        partial_qualifier_mutation(repo)
        if entry == DERIVED_PARTIAL_QUALIFIER
        else scope_figure_mutation(
            repo, SCOPE_COVERED, DERIVED_SCOPE_COVERED_NAME, "covered"
        )
        if entry == DERIVED_SCOPE_COVERED
        else scope_figure_mutation(
            repo,
            SCOPE_WITHOUT_ROW,
            DERIVED_SCOPE_WITHOUT_ROW_NAME,
            "covered-without-a-row",
        )
        if entry == DERIVED_SCOPE_WITHOUT_ROW
        else entry
        for entry in MUTATIONS
    ]
    names = {entry["name"] for entry in resolved}
    ungrouped = sorted(names - set(GROUPS))
    orphaned = sorted(set(GROUPS) - names)
    if ungrouped or orphaned:
        die(
            "GROUPS and MUTATIONS do not describe the same population, so the "
            "figures the parity doc publishes cannot be derived:\n"
            + (f"  no group for: {ungrouped}\n" if ungrouped else "")
            + (f"  group for a mutation that is gone: {orphaned}\n" if orphaned else "")
            + "  Add or rename the GROUPS key. Do not default an unlisted "
            "mutation into a group: it would leave the published split "
            "reconciling against a population one entry short."
        )
    return [{**entry, "group": GROUPS[entry["name"]]} for entry in resolved]


def group_counts(repo: Path) -> dict[str, int]:
    """doc phrase -> how many mutations count toward it, in the doc's order.

    Imported by check_ledger.py's doc-figure gate. Kept here because this list is
    the only authority for the split, and a second copy of the grouping would
    agree with the first as readily on a wrong answer as on a right one.
    """
    counts = dict.fromkeys(GROUPS.values(), 0)
    for entry in resolve_mutations(repo):
        counts[entry["group"]] += 1
    return counts


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
