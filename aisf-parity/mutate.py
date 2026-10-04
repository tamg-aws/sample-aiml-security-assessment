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
SAGEMAKER = f"{SECURITY}/sagemaker_assessments/app.py"

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
    {
        "name": "BR-04 credits any object in the log bucket as a retained entry",
        "file": BEDROCK,
        "defect": "BR-04 lists the log bucket from its root, so an object outside the "
        "AWSLogs/ root Bedrock writes under reads as a retained invocation log entry",
        "find": "                    Prefix=log_root,\n",
        "replace": '                    Prefix="",\n',
    },
    {
        "name": "an unread list read lets the BR-53 sweep summary pass",
        "file": BEDROCK,
        "defect": "BR-53 passes the SageMaker and AgentCore summary while a list "
        "read failed, so resources it never listed read as owned",
        "find": "    complete = owned > 0 and not unowned and not unread\n",
        "replace": "    complete = owned > 0 and not unowned\n",
    },
    {
        "name": "BR-43 stops reducing a profile ARN modelId to its ID",
        "file": BEDROCK,
        "defect": "BR-43 misses a call that names the inference profile by ARN, so "
        "a profile in use reads as not called",
        "find": '    if model_id.startswith("arn:") and "inference-profile/" in model_id:\n',
        "replace": "    if False:\n",
    },
    {
        "name": "BR-57 credits a SourceAccount naming another account",
        "file": BEDROCK,
        "defect": "BR-57 accepts any aws:SourceAccount value on an agent role trust, "
        "so Bedrock acting for another account can assume it",
        "find": "                and all(text == account for text in texts)\n",
        "replace": "                and all(text for text in texts)\n",
    },
    {
        "name": "two action group functions on one role pass BR-57",
        "file": BEDROCK,
        "defect": "BR-57 fails a shared execution role only when three functions run "
        "as it, so a pair shares one identity unnoticed",
        "find": "            if len(arns) > 1\n",
        "replace": "            if len(arns) > 2\n",
    },
    {
        "name": "BR-33 credits an image its repository scans only on push",
        "file": BEDROCK,
        "defect": "BR-33 ignores the repository scan frequency, so an image scanned "
        "once at push passes though a CVE published later is never reported",
        "find": '            elif frequencies != ["CONTINUOUS_SCAN"]:\n',
        "replace": "            elif False:\n",
    },
    {
        "name": "BR-33 judges another account's image by this account's coverage",
        "file": BEDROCK,
        "defect": "BR-33 matches an image from another account to a same-named "
        "repository here, so a coverage record for a different image passes it",
        "find": "        elif match.group(1) != account:\n",
        "replace": "        elif False:\n",
    },
    {
        "name": "BR-34 credits a detected prompt attack the guardrail let through",
        "file": BEDROCK,
        "defect": "BR-34 counts any PROMPT_ATTACK filter entry as a catch, so a "
        "detection whose action was NONE reads as a blocked attack",
        "find": '                item.get("type") == "PROMPT_ATTACK" and item.get("action") == "BLOCKED"\n',
        "replace": '                item.get("type") == "PROMPT_ATTACK"\n',
    },
    {
        "name": "BR-34 credits an untagged guarded InvokeModel call",
        "file": BEDROCK,
        "defect": "BR-34 stops reading the request body for the guardContent tag, so "
        "an InvokeModel prompt the prompt attack filter never evaluated passes",
        "find": "            elif GUARDRAIL_INPUT_TAG not in json.dumps(body):\n",
        "replace": "            elif False:\n",
    },
    {
        "name": "BR-27 reads an absent text delivery flag as delivered",
        "file": BEDROCK,
        "defect": "BR-27 fails grounding capture only on an explicit false, so an "
        "account with no logging configuration escapes the Failed row",
        "find": "    if text_delivery is not True:\n",
        "replace": "    if text_delivery is False:\n",
    },
    # ------------------------------------------- SageMaker round-6 check logic
    # SM-39's egress legs for ECS and Lambda VPCs (AIR-SLF-RT-02) and SM-43's
    # artifact reads (AIR-SLF-CMP-08). Each was killed by hand on a byte backup
    # on 2026-10-03 before it was added here.
    {
        "name": "SM-39 evaluates DNS Firewall rule groups in list order",
        "file": SAGEMAKER,
        "defect": "DNS Firewall evaluates associated rule groups from the lowest "
        "Priority, and the API does not return them sorted. Read in list order, "
        "a terminal BLOCK group listed first passes a VPC whose lower-Priority "
        "ALLOW over every name answers every query",
        "find": (
            '    ordered = sorted(live, key=lambda item: item.get("Priority") or 0)\n'
        ),
        "replace": "    ordered = live\n",
    },
    {
        "name": "SM-39 accepts a DNS Firewall that fails open",
        "file": SAGEMAKER,
        "defect": "with FirewallFailOpen ENABLED, VPC Resolver answers every "
        "query while DNS Firewall is impaired, including the names the terminal "
        "BLOCK denies. Dropping the ENABLED branch turns that Failed into N/A, "
        "so the row stops naming the open path",
        "find": '    if fail_open == "ENABLED":\n',
        "replace": '    if fail_open == "ENABLED-NOT-A-VALUE":\n',
    },
    {
        "name": "SM-39 loses a NAT gateway path to an internet gateway",
        "file": SAGEMAKER,
        "defect": "a hosting subnet that egresses through a NAT gateway whose "
        "own subnet routes to an internet gateway bypasses every Network "
        "Firewall. Without the onward igw branch that route reads as not "
        "followed, so the bypass is reported N/A instead of Failed",
        "find": (
            '                    elif onward_key == "GatewayId" and '
            'onward_target.startswith("igw-"):\n'
        ),
        "replace": "                    elif False:\n",
    },
    {
        "name": "SM-43 drops the objects past the HeadObject cap",
        "file": SAGEMAKER,
        "defect": "a prefix holding more objects than the run reads has objects "
        "whose encryption nobody read. Without the unread row the first 1,000 "
        "listed objects stand for the whole prefix and the endpoint passes",
        "find": (
            "        if more:\n"
            "            unreads.append(\n"
            '                f"{where} {uri} holds more objects than the "\n'
        ),
        "replace": (
            "        if False:\n"
            "            unreads.append(\n"
            '                f"{where} {uri} holds more objects than the "\n'
        ),
    },
    {
        "name": "SM-43 ignores an execution role's NotResource grant",
        "file": SAGEMAKER,
        "defect": "an Allow on s3:GetObject with NotResource reaches every object "
        "but the excluded ones, so the role can read model data from any bucket. "
        "Skipping the branch leaves no Resource to judge, and the role reads as "
        "staying inside its artifact buckets",
        "find": '        if "NotResource" in statement:\n            excluded = ',
        "replace": "        if False:\n            excluded = ",
    },
    # ------------------------------------------ the AgentCore verdict legs
    # Each entry reverts one round-6 verdict leg in agentcore_assessments to the
    # behaviour the regrade graded partial. The catcher is the test that pins the
    # stricter verdict, with a resource or principal on each side of the guard.
    {
        "name": "AC-37 reads an allow-list SCP's omission as an Allow",
        "file": AGENTCORE,
        "defect": "a level from the account to the root whose attached SCPs allow no part of bedrock:InvokeGuardrailChecks denies it implicitly, and the explicit-Deny scan cannot see that. Inverting the guard passes every gateway behind such an allow-list",
        "find": '    if unallowed and not unread:\n        return "denied", (\n',
        "replace": '    if unallowed and unread:\n        return "denied", (\n',
    },
    {
        "name": "AC-37 passes when the organization's SCPs could not be listed",
        "file": AGENTCORE,
        "defect": "an Organizations read that fails leaves both an explicit Deny and an allow-list unread, and the row used to fall through to Passed with a disclaimer, which no failed read may produce",
        "find": '        elif granted and scp_state in ("conditioned", "incomplete", "unread"):\n',
        "replace": '        elif granted and scp_state in ("conditioned", "incomplete"):\n',
    },
    {
        "name": "AC-42 passes the population beside an unread configuration",
        "file": AGENTCORE,
        "defect": "a configuration GetOnlineEvaluationConfig could not read may name a role no read configuration names, so a principal able to pass only that role is unseen while the population row says no principal can pass one",
        "find": "        and not errors\n        and not gap_rows\n",
        "replace": "        and not gap_rows\n",
    },
    {
        "name": "AC-44 passes a model grant only code-based evaluators sit beside",
        "file": AGENTCORE,
        "defect": "a custom evaluator that names no Bedrock judge model uses no model grant, the same unused-grant case the built-in branch fails, so the guard decides whether such a grant fails or passes with a note",
        "find": "                if (called or evaluators)\n",
        "replace": "                if called\n",
    },
    {
        "name": "AC-40 counts an alarm no listed metric ties to an evaluator",
        "file": AGENTCORE,
        "defect": "with no listed metric naming an attached evaluator, an alarm on an answer-quality score in the namespace reads as watching safety and the configuration passes",
        "find": "        elif metric_error or untied:\n",
        "replace": "        elif metric_error:\n",
    },
    {
        "name": "AC-40 judges a stopped configuration as scoring safety",
        "file": AGENTCORE,
        "defect": "a DISABLED configuration attaches the right evaluators and an alarm, and its Passed row then says it scores safety while it scores no traffic",
        "find": "        not_running = _online_evaluation_problems(detail)\n",
        "replace": "        not_running = []\n",
    },
    {
        "name": "AC-17 reads a stopped configuration with no runtime as N/A",
        "file": AGENTCORE,
        "defect": "with no runtime in the region, a configuration that exists names agent traffic, and without this branch a stopped one reads N/A unless an environment variable that defaults off is set",
        "find": "        elif judged:\n            # A configuration names the agent traffic",
        "replace": "        elif False:\n            # A configuration names the agent traffic",
    },
    {
        "name": "AC-29 credits a runtime deny-list of AWS_IAM",
        "file": AGENTCORE,
        "defect": "AWS publishes no list of the values RuntimeAuthorizerType takes, so a Deny that fires on AWS_IAM but not on an unlisted value is not shown to deny a SigV4 write, and dropping the probe passes it",
        "find": "            also_denies=(RUNTIME_AUTHORIZER_UNLISTED_VALUE,),\n            absent_denied=True,\n",
        "replace": "            absent_denied=True,\n",
    },
    {
        "name": "AC-07 passes a memory beside a strategy with no namespace",
        "file": AGENTCORE,
        "defect": "a strategy that reports no namespace was skipped, so one partitioned strategy beside it passed the memory with the other's records unread",
        "find": '    if unread:\n        return create_finding(\n            check_id="AC-07",\n',
        "replace": '    if False:\n        return create_finding(\n            check_id="AC-07",\n',
    },
    {
        "name": "AC-23 passes a read bound by a fixed literal partition",
        "file": AGENTCORE,
        "defect": "a literal partition with no policy variable is shared by every caller of the principal, and whether one actor or many use it is not read, so it cannot reach Passed",
        "find": "                    severity=SeverityEnum.INFORMATIONAL,\n                    status=StatusEnum.NA,\n                    region=GLOBAL_REGION_LABEL,\n                )\n            )\n\n        if bound:\n",
        "replace": "                    severity=SeverityEnum.HIGH,\n                    status=StatusEnum.PASSED,\n                    region=GLOBAL_REGION_LABEL,\n                )\n            )\n\n        if bound:\n",
    },
    {
        "name": "AC-21 bounds an APPLICATION_LOGS-wide unmask",
        "file": AGENTCORE,
        "defect": "gateway and memory log delivery writes one group per resource under APPLICATION_LOGS/, so logs:Unmask on APPLICATION_LOGS/* reaches every such group and read as bounded without those kinds",
        "find": '    "memory/APPLICATION_LOGS/",\n    "gateway/APPLICATION_LOGS/",\n',
        "replace": "",
    },
    {
        "name": "AC-20 reads a key id as customer managed encryption",
        "file": AGENTCORE,
        "defect": "an AWS managed key or a disabled customer managed key on the group passed, because the key id's presence was read as customer managed encryption",
        "find": "        has_cmk = bool(key_id) and not key_gap\n",
        "replace": '        has_cmk = bool(key_id)\n        key_gap = ""\n',
    },
    {
        "name": "AC-02 passes a budget writer with no ProcessPayment Deny",
        "file": AGENTCORE,
        "defect": "the ManagementRole carries an explicit Deny on ProcessPayment so a later Allow cannot join setting a budget with spending it; a writer that lacks it passed because it does not hold the action today",
        "find": '        if not denied:\n            labels.append(f"{principal_kind} {principal_name}")\n',
        "replace": '        if False:\n            labels.append(f"{principal_kind} {principal_name}")\n',
    },
    {
        "name": "AC-48 judges a foreign role by a same-named local role",
        "file": AGENTCORE,
        "defect": "GetRole reads by name in this account, so a role ARN in another account was judged by the trust policy of a local role that only shares its name",
        "find": '        if str(role.get("Arn") or "") != str(role_arn):\n',
        "replace": "        if False:\n",
    },
    {
        "name": "AC-48 passes a trust that names another service",
        "file": AGENTCORE,
        "defect": "an execution role whose trust names lambda.amazonaws.com beside the AgentCore principal lends the resource's permissions to that service",
        "find": "                and principal != AGENTCORE_SERVICE_PRINCIPAL\n",
        "replace": "                and False\n",
    },
    {
        "name": "AC-53 credits an alarm on another Environment",
        "file": AGENTCORE,
        "defect": "an alarm with the pair's Service and RemoteService on another Environment watches another deployment's calls, and the Passed text claimed the pair's own metrics were alarmed",
        "find": '                and dimensions.get("Environment") in edge_environments[edge]\n',
        "replace": "",
    },
    {
        "name": "AC-01 passes a broad public egress range",
        "file": AGENTCORE,
        "defect": "a single public range such as 0.0.0.0/1 reaches half the IPv4 internet without covering 0.0.0.0/0, and passed because only the union to /0 was tested",
        "find": "                if network.prefixlen > AGENTCORE_BROAD_EGRESS_PREFIX[network.version]:\n",
        "replace": "                if True:\n",
    },
    {
        "name": "AC-27 passes a gateway policy statement with no source ARN",
        "file": AGENTCORE,
        "defect": "aws:SourceAccount alone admits any resource of the service in the account, so a service principal statement without aws:SourceArn naming the gateway lets another resource in the account invoke it as a deputy",
        "find": "                and _statement_pins_source_arn(statement, str(gateway_arn))\n",
        "replace": "",
    },
    {
        "name": "AC-36 credits a source-context statement with only SourceAccount",
        "file": AGENTCORE,
        "defect": "the guide's source-context statement pins aws:SourceAccount and aws:SourceArn together; SourceAccount alone lets any AgentCore resource in the account decrypt with the policy engine's key",
        "find": '            and _confused_deputy_guard_account(\n                statement, account_id, keys=("aws:sourcearn",)\n            )\n        ]\n        for action in POLICY_ENGINE_SOURCE_GUARDED_ACTIONS\n',
        "replace": "        ]\n        for action in POLICY_ENGINE_SOURCE_GUARDED_ACTIONS\n",
    },
    {
        "name": "AG-24 passes a gateway with no REQUEST interceptor",
        "file": AGENTCORE,
        "defect": "the recommendation asks for a request interceptor on every gateway so tool access does not rest on the model, and a gateway with none passed on its authorizer alone",
        "find": "        if not request_interceptors:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "AG-24 counts a RESPONSE-only interceptor as a request guard",
        "file": AGENTCORE,
        "defect": "a RESPONSE interceptor runs after the target has executed the call, so it cannot stop the tool call it inspects",
        "find": '            and "REQUEST" in (entry.get("interceptionPoints") or [])\n',
        "replace": "",
    },
    {
        "name": "AC-25 passes a portal-served target with its own return URL",
        "file": AGENTCORE,
        "defect": "a consent portal binds consent only at <portalUrl>/connect/callback, and a target created before the portal keeps a return URL elsewhere, so the consent never binds to the session and the target passed",
        "find": "                        elif callbacks and return_url not in callbacks:\n",
        "replace": "                        elif False:\n",
    },
    {
        "name": "AC-25 passes token exchange on a gateway with no JWT inbound",
        "file": AGENTCORE,
        "defect": "TOKEN_EXCHANGE exchanges an inbound user token, which only a CUSTOM_JWT gateway receives, and the target was labelled and passed without that join",
        "find": '                        and authorizer_type != "CUSTOM_JWT"\n',
        "replace": "                        and False\n",
    },
    {
        "name": "AC-25 passes an AUTHORIZATION_CODE target beside an unread portal list",
        "file": AGENTCORE,
        "defect": "with ListConsentPortals unread, whether the return URL must be a portal callback is unknown, and the target passed on a failed read",
        "find": "                        elif portal_error:\n",
        "replace": "                        elif False:\n",
    },
    {
        "name": "AG-24 passes an authorized gateway with no enforcing engine",
        "file": AGENTCORE,
        "defect": "an AWS_IAM or CUSTOM_JWT authorizer decides who calls the gateway, not which tool call that caller makes, and such a gateway passed with no default-deny engine in ENFORCE",
        "find": '            if engine_status == StatusEnum.FAILED.value:\n                findings.append(\n                    create_finding(\n                        check_id="AG-24",\n                        finding_name="Agentic AI Gateway Tool Call Authorization Missing",\n',
        "replace": '            if False:\n                findings.append(\n                    create_finding(\n                        check_id="AG-24",\n                        finding_name="Agentic AI Gateway Tool Call Authorization Missing",\n',
    },
    {
        "name": "AC-29 credits a runtime Deny narrowed to some resources",
        "file": AGENTCORE,
        "defect": "a Deny whose Resource names one Region or a name prefix leaves runtimes outside it free to move to SigV4, and it was credited as the guardrail",
        "find": "        if not _scp_deny_reaches_every_resource(statement, resource_type):\n            continue\n",
        "replace": "",
    },
    {
        "name": "AC-33 reads only the primary Region's runtimes",
        "file": AGENTCORE,
        "defect": "AC-33 runs once, on the primary Region, and a JWT runtime in another assessed Region was never judged for either ForUser leg and got no row",
        "find": "            agentcore_client = client\n            found, failed, runtimes, arns = _workload_identities_by_role()\n",
        "replace": "            if region != regions[0]:\n                continue\n            agentcore_client = client\n            found, failed, runtimes, arns = _workload_identities_by_role()\n",
    },
    {
        "name": "AC-33 fails a JWT runtime role whose own Deny removes ForUserId",
        "file": AGENTCORE,
        "defect": "the role's own explicit Deny or permissions boundary removes GetWorkloadAccessTokenForUserId, and counting the Allow alone fails a role that cannot make the call",
        "find": '        if granted and _grant_survives(\n            permissions, "bedrock-agentcore:getworkloadaccesstokenforuserid"\n        ):\n',
        "replace": "        if granted:\n",
    },
    {
        "name": "AC-33 lets a ? Deny pattern cover every runtime endpoint",
        "file": AGENTCORE,
        "defect": "fnmatch reads the endpoint probe's literal * as text, so a ? in the Deny pattern matched it and the Deny read as covering endpoints it does not name",
        "find": '            and not (probe != runtime_arn and "?" in pattern)\n',
        "replace": "",
    },
    {
        "name": "AC-33 reads a NotResource ForUser grant as reaching nothing",
        "file": AGENTCORE,
        "defect": "a NotResource Allow of InvokeAgentRuntimeForUser reaches every runtime it does not exclude, and reading only Resource passed it",
        "find": '    probes = (runtime_arn, f"{runtime_arn}/runtime-endpoint/*")\n    if "NotResource" in statement:\n        excluded = statement.get("NotResource")\n        excluded = excluded if isinstance(excluded, list) else [excluded]\n        return not all(\n',
        "replace": '    probes = (runtime_arn, f"{runtime_arn}/runtime-endpoint/*")\n    if False:\n        excluded = statement.get("NotResource")\n        excluded = excluded if isinstance(excluded, list) else [excluded]\n        return not all(\n',
    },
    {
        "name": "AC-33 never credits a foreign identity in a read Region as crossing",
        "file": AGENTCORE,
        "defect": "a role named for another agent's workload identity in a Region whose resources were read acts as that agent, and with no Region compared the row fell back to N/A",
        "find": "                    in {region.lower() for region in read_regions}\n",
        "replace": "                    in set()\n",
    },
    {
        "name": "AC-32 passes an issuer pin with no application pin",
        "file": AGENTCORE,
        "defect": "an approved issuer mints tokens for every application registered with it, so a statement pinning iss alone accepts a token minted for another application, and the control asks for aud or client_id beside it",
        "find": '                elif not _statement_inbound_jwt_pins(\n                    statement, INBOUND_JWT_APPLICATION_KEYS\n                ):\n                    verdicts.add("application")\n',
        "replace": '                elif False:\n                    verdicts.add("application")\n',
    },
    {
        "name": "AC-32 passes claim pins with no network pin",
        "file": AGENTCORE,
        "defect": "the control combines the claim conditions with aws:SourceVpc or aws:SourceVpce, and without them a stolen token is exchanged from any network path",
        "find": '                elif not _statement_inbound_jwt_pins(\n                    statement, INBOUND_JWT_NETWORK_KEYS\n                ):\n                    verdicts.add("network")\n',
        "replace": '                elif False:\n                    verdicts.add("network")\n',
    },
    {
        "name": "AC-32 passes an issuer no authorizer trusts",
        "file": AGENTCORE,
        "defect": "a literal iss pin names one issuer but not an approved one, and the row passed without comparing it with the issuers the runtimes' and gateways' JWT authorizers trust",
        "find": "                if strange:\n                    unmatched.append(",
        "replace": "                if False:\n                    unmatched.append(",
    },
    {
        "name": "AC-32 credits a DiscoveryUrl deny-list of one bad issuer",
        "file": AGENTCORE,
        "defect": "a Deny that fires on one named bad issuer admits every issuer it does not name, so the probe must be a discovery URL no policy lists",
        "find": "            GATEWAY_DISCOVERY_URL_CONDITION_KEY,\n            GATEWAY_DISCOVERY_URL_UNLISTED_VALUE,\n",
        "replace": '            GATEWAY_DISCOVERY_URL_CONDITION_KEY,\n            "https://evil.example.com/.well-known/openid-configuration",\n',
    },
    {
        "name": "AC-47 passes a PrincipalArn Deny naming no fronting gateway role",
        "file": AGENTCORE,
        "defect": "a Deny outside a bounded aws:PrincipalArn list admits whoever the list names, and a list that is not the fronting gateway's execution role lets those principals invoke the agent without passing through the gateway",
        "find": '    if not admitted:\n        return "failed", (\n            "has a resource policy Deny that admits only the aws:PrincipalArn "\n',
        "replace": '    if False:\n        return "failed", (\n            "has a resource policy Deny that admits only the aws:PrincipalArn "\n',
    },
    {
        "name": "AC-47 passes a PrincipalArn Deny naming a role beside the gateway's",
        "file": AGENTCORE,
        "defect": "a list naming the gateway's execution role and a developer role lets the developer role invoke the runtime directly, and the gateway's presence in the list passed it",
        "find": "    extras = [value for value in values if value not in roles]\n",
        "replace": "    extras = []\n",
    },
    {
        "name": "AC-06 credits an IfExists aws:PrincipalAccount binding",
        "file": AGENTCORE,
        "defect": "an anonymous request carries no aws:PrincipalAccount, so an Allow to * under StringEqualsIfExists matches it and the recordings are readable by anyone",
        "find": "        if name not in CONFUSED_DEPUTY_GUARD_OPERATORS:\n            continue\n        for entry_key, raw in entries.items():\n",
        "replace": '        if name.removesuffix("ifexists") not in CONFUSED_DEPUTY_GUARD_OPERATORS:\n            continue\n        for entry_key, raw in entries.items():\n',
    },
    {
        "name": "AC-06 credits an IfExists aws:SourceAccount binding",
        "file": AGENTCORE,
        "defect": "aws:SourceAccount is present only on a service-to-service call, so under IfExists the Allow matches every direct and anonymous request",
        "find": "        if name not in CONFUSED_DEPUTY_GUARD_OPERATORS:\n            continue\n        for key, raw in entries.items():\n            values = _condition_values(raw)\n            if not values:\n                continue\n            key = str(key).strip().lower()\n            if key not in keys:\n",
        "replace": '        if name.removesuffix("ifexists") not in CONFUSED_DEPUTY_GUARD_OPERATORS:\n            continue\n        for key, raw in entries.items():\n            values = _condition_values(raw)\n            if not values:\n                continue\n            key = str(key).strip().lower()\n            if key not in keys:\n',
    },
    {
        "name": "AC-06 credits an IfExists aws:PrincipalOrgID binding",
        "file": AGENTCORE,
        "defect": "an anonymous request carries no aws:PrincipalOrgID, so the organization binding under IfExists admits it",
        "find": '    if operator.startswith("forallvalues:") or operator.endswith("ifexists"):\n        return False\n',
        "replace": '    if operator.startswith("forallvalues:"):\n        return False\n    operator = operator.removesuffix("ifexists")\n',
    },
    {
        "name": "AC-18 fails a memory selector that names every memory by ARN",
        "file": AGENTCORE,
        "defect": "the memory audit guidance scopes the data-event selector to the memory ARNs, and reading any resources.ARN value narrower than the region prefix as narrowing failed a trail that records every memory listed",
        "find": '        if family["key"] == "memory":\n            for resource_type in list(missing):\n',
        "replace": "        if False:\n            for resource_type in list(missing):\n",
    },
    {
        "name": "AC-18 credits an ARN selector that names one of two memories",
        "file": AGENTCORE,
        "defect": "a selector naming mem-1 records nothing for mem-2, so crediting it when any memory matches passes a memory whose reads and writes are not in the audit trail",
        "find": "                if arns and len(matched) == len(arns) and all(matched.values()):\n",
        "replace": "                if arns and any(matched.values()):\n",
    },
    {
        "name": "AC-45 reads the shell alarm in the primary Region only",
        "file": AGENTCORE,
        "defect": "a metric filter and its alarm are regional, so a shell-capable runtime in another assessed Region with no alarm there was never judged",
        "find": "        else _command_shell_region_alarm_rows(permission_cache)\n",
        "replace": "        else []\n",
    },
    {
        "name": "AC-45 asks for a shell alarm in a Region with no runtime",
        "file": AGENTCORE,
        "defect": "a Region with no runtime has no session to open a shell in, and failing it for a missing alarm is a finding nobody can act on",
        "find": "    if not runtimes:\n        return []\n    alarm, alarm_unread = _metric_filter_alarm(_command_shell_filter_matches)\n",
        "replace": "    alarm, alarm_unread = _metric_filter_alarm(_command_shell_filter_matches)\n",
    },
    {
        "name": "AC-41 credits an evaluation key on DescribeKey alone",
        "file": AGENTCORE,
        "defect": "an enabled customer managed key whose policy lets any caller decrypt outside AgentCore passed, so the evaluator instructions it protects were readable by every principal the key policy names",
        "find": "            if status == StatusEnum.PASSED:\n                status, fact = _evaluation_key_policy_verdict(\n                    key_arn,\n                    evaluators[evaluator_id]",
        "replace": "            if False:\n                status, fact = _evaluation_key_policy_verdict(\n                    key_arn,\n                    evaluators[evaluator_id]",
    },
    {
        "name": "AC-41 drops kms:ViaService from an evaluator's caller leg",
        "file": AGENTCORE,
        "defect": "a caller grant with no kms:ViaService lets the evaluation role decrypt evaluator data directly, outside AgentCore",
        "find": "        and (\n            batch\n            or any(\n",
        "replace": "        and (\n            True\n            or any(\n",
    },
    {
        "name": "AC-41 accepts an encryption context open in the account segment",
        "file": AGENTCORE,
        "defect": "a context pattern of any account binds no evaluator of this account, so a key shared across accounts passed",
        "find": "                or not (parts[4].isdigit() and len(parts[4]) == 12)\n                or resource_arn is not None\n",
        "replace": "                or resource_arn is not None\n",
    },
    {
        "name": "AC-41 credits a context that names another evaluator",
        "file": AGENTCORE,
        "defect": "a key policy naming only judge-9 passed judge-1, whose data the policy grants no scoped decrypt for",
        "find": "                    or not fnmatchcase(target, value)\n",
        "replace": "",
    },
    {
        "name": "AC-41 ignores a service-principal grant with no aws:SourceArn",
        "file": AGENTCORE,
        "defect": "a decrypt grant to bedrock-agentcore.amazonaws.com with no aws:SourceArn is a confused-deputy path from another account's evaluations",
        "find": '        and not _statement_names_evaluation_resource(statement, "aws:sourcearn")\n',
        "replace": "        and False\n",
    },
    {
        "name": "AC-41 passes a key policy it could not read",
        "file": AGENTCORE,
        "defect": "a denied kms:GetKeyPolicy says nothing about who may decrypt, so a Passed from it is a clean result from a failed read",
        "find": '    if isinstance(key_policy, Exception):\n        return StatusEnum.NA, (\n            f"names customer managed key {key_arn}, whose key policy could not be "\n',
        "replace": '    if isinstance(key_policy, Exception):\n        return StatusEnum.PASSED, (\n            f"names customer managed key {key_arn}, whose key policy could not be "\n',
    },
    {
        "name": "AC-41 credits a batch evaluation key on DescribeKey alone",
        "file": AGENTCORE,
        "defect": "a batch output key whose policy grants no batch-scoped decrypt passed, so the stored results were readable by any principal the key policy names",
        "find": "            if status == StatusEnum.PASSED:\n                status, fact = _evaluation_key_policy_verdict(\n                    key_arn,\n                    batch.get(",
        "replace": "            if False:\n                status, fact = _evaluation_key_policy_verdict(\n                    key_arn,\n                    batch.get(",
    },
    {
        "name": "AC-36 credits a key-loss metric filter no trail feeds",
        "file": AGENTCORE,
        "defect": "a metric filter on a log group no logging trail delivers KMS events to never sees DisableKey or ScheduleKeyDeletion, so its alarm never fires",
        "find": '        trail_event_source="kms.amazonaws.com",\n',
        "replace": "",
    },
    {
        "name": "AC-36 credits a trail that is not logging",
        "file": AGENTCORE,
        "defect": "a stopped trail delivers nothing to its log group, so the filter on it counts no key-loss call",
        "find": '            if status.get("IsLogging") is not True:\n                continue\n            selectors = cloudtrail_client.get_event_selectors(\n',
        "replace": "            selectors = cloudtrail_client.get_event_selectors(\n",
    },
    {
        "name": "AC-36 credits a read-only management selector",
        "file": AGENTCORE,
        "defect": "DisableKey and ScheduleKeyDeletion are write events, which a ReadOnly selector drops",
        "find": '            and selector.get("ReadWriteType", "All") in ("All", "WriteOnly")\n',
        "replace": "",
    },
    {
        "name": "AC-36 ignores ExcludeManagementEventSources",
        "file": AGENTCORE,
        "defect": "a trail excluding kms.amazonaws.com records no KMS call, so the filter on its group sees none",
        "find": '            and event_source\n            not in (selector.get("ExcludeManagementEventSources") or [])\n',
        "replace": "",
    },
    {
        "name": "AC-36 credits a read-only advanced selector",
        "file": AGENTCORE,
        "defect": "an advanced selector with readOnly true records no write event",
        "find": '            or (read_only.get("Equals") or []) != ["false"]\n',
        "replace": "            and False\n",
    },
    {
        "name": "AC-36 credits a trail homed in another Region",
        "file": AGENTCORE,
        "defect": "a single-Region trail homed elsewhere records no KMS call made in this Region",
        "find": '            if detail.get("IsMultiRegionTrail") is not True and (\n                detail.get("HomeRegion") != region\n            ):\n                continue\n            status = cloudtrail_client.get_trail_status(',
        "replace": "            status = cloudtrail_client.get_trail_status(",
    },
    {
        "name": "AC-49 reads the latest runtime version only",
        "file": AGENTCORE,
        "defect": "an endpoint serving an earlier version runs in that version's subnets, so a VPC only an earlier version uses went unjudged",
        "find": "        for number in earlier:\n            version_label = ",
        "replace": "        for number in []:\n            version_label = ",
    },
    {
        "name": "AC-49 drops an unlisted runtime version set silently",
        "file": AGENTCORE,
        "defect": "a denied ListAgentRuntimeVersions left the earlier versions' VPCs unread with nothing reported",
        "find": '            errors.append(\n                (\n                    f"The earlier versions of {label}",\n',
        "replace": '            continue\n            errors.append(\n                (\n                    f"The earlier versions of {label}",\n',
    },
    {
        "name": "AC-44 does not read the evaluation role's other grants",
        "file": AGENTCORE,
        "defect": "the role the service assumes while scoring agent output could hold any other grant, such as s3:GetObject on every bucket, and no row said so",
        "find": "        extra_grants = _evaluation_role_extra_grants(permissions)\n",
        "replace": "        extra_grants = []\n",
    },
    {
        "name": "AC-44 credits a NotAction Allow on the evaluation role",
        "file": AGENTCORE,
        "defect": "an Allow with NotAction grants every action it does not list",
        "find": "                label = f\"NotAction {', '.join(_statement_not_actions(statement))}\"\n                if label not in extra:\n                    extra.append(label)\n                continue\n",
        "replace": "                continue\n",
    },
    {
        "name": "AC-44 credits evaluation log writes on any group",
        "file": AGENTCORE,
        "defect": "PutLogEvents on the runtime log groups lets the role write into the agent's own logs, outside the evaluations groups the service needs",
        "find": "                if action in EVALUATION_ROLE_LOG_READS:\n",
        "replace": "                if action in EVALUATION_ROLE_LOG_READS + EVALUATION_ROLE_LOG_WRITES:\n",
    },
    {
        "name": "AC-44 credits a log-group pattern open in the account segment",
        "file": AGENTCORE,
        "defect": "a log write on any account's evaluations groups reaches groups the assessed account does not own",
        "find": '        or parts[2] != "logs"\n        or not (parts[4].isdigit() and len(parts[4]) == 12)\n        or parts[5] != "log-group"\n',
        "replace": '        or parts[2] != "logs"\n        or parts[5] != "log-group"\n',
    },
    {
        "name": "AC-44 credits PutIndexPolicy on any log group",
        "file": AGENTCORE,
        "defect": "an index policy written on any group changes which fields of every log group are indexed, beyond aws/spans",
        "find": '                        if not _log_group_resource_within(resource, "aws/spans", True)\n',
        "replace": "                        if False\n",
    },
    {
        "name": "AC-44 counts an extra grant the role's own Deny removes",
        "file": AGENTCORE,
        "defect": "an Allow removed by the role's own unconditioned Deny grants nothing, so reporting it fails a role that holds no extra grant",
        "find": '                if action.startswith("bedrock:invokemodel") or not _grant_survives(\n                    permissions, action\n                ):\n',
        "replace": '                if action.startswith("bedrock:invokemodel"):\n',
    },
    {
        "name": "AC-27 does not read consent portal execution roles",
        "file": AGENTCORE,
        "defect": "the setup guide creates the portal role with no Condition and nothing re-checks it, so a role any AgentCore resource could assume for another account kept access to the gateway's OAuth client secrets",
        "find": "    findings.extend(_consent_portal_role_trust_findings(trust_cache))\n",
        "replace": "",
    },
    {
        "name": "AC-27 accepts any resource type in a portal role's aws:SourceArn",
        "file": AGENTCORE,
        "defect": "an aws:SourceArn naming gateway/* lets the service assume the portal role for a gateway, not only for the portal",
        "find": '        unscoped = _statements_without_scoped_source_arn(\n            statements, account_id, resource_types=("consent-portal",)\n        )\n',
        "replace": "        unscoped = _statements_without_scoped_source_arn(\n            statements, account_id, resource_types=None\n        )\n",
    },
    {
        "name": "AC-27 passes a consent portal it could not read",
        "file": AGENTCORE,
        "defect": "a denied GetConsentPortal says nothing about the role's trust, so a Passed from it is a clean result from a failed read",
        "find": '                    "Grant bedrock-agentcore:GetConsentPortal and retry.",\n                    SeverityEnum.INFORMATIONAL,\n                    StatusEnum.NA,\n',
        "replace": '                    "Grant bedrock-agentcore:GetConsentPortal and retry.",\n                    SeverityEnum.INFORMATIONAL,\n                    StatusEnum.PASSED,\n',
    },
    {
        "name": "AC-47 judges only the default runtime version",
        "file": AGENTCORE,
        "defect": "an endpoint still serving a version with no allowedWorkloadConfiguration lets a caller skip the gateway while the latest version's gate reads as the runtime's",
        "find": '        caller_details = [(label, detail)]\n        default_version = str(detail.get("agentRuntimeVersion"))\n        for version in sorted(v for v in served if v != default_version):\n',
        "replace": '        caller_details = [(label, detail)]\n        default_version = str(detail.get("agentRuntimeVersion"))\n        for version in sorted(v for v in served if v != default_version and False):\n',
    },
    {
        "name": "AC-47 ignores the version an endpoint rolls toward",
        "file": AGENTCORE,
        "defect": "a targetVersion takes the endpoint's traffic once the update completes, so its authorizer goes unjudged",
        "find": '            endpoints, endpoints_error = [], error\n        served: Dict[str, List[str]] = {}\n        for endpoint in endpoints:\n            endpoint_name = endpoint.get("name") or endpoint.get("id") or "unnamed"\n            for field in ("liveVersion", "targetVersion"):\n',
        "replace": '            endpoints, endpoints_error = [], error\n        served: Dict[str, List[str]] = {}\n        for endpoint in endpoints:\n            endpoint_name = endpoint.get("name") or endpoint.get("id") or "unnamed"\n            for field in ("liveVersion",):\n',
    },
    {
        "name": "AC-47 passes the caller leg when the endpoints are unlisted",
        "file": AGENTCORE,
        "defect": "a denied ListAgentRuntimeEndpoints hides every served version, so the latest version's Passed is a clean result from a failed read",
        "find": '            if findings[-1]["Status"] == StatusEnum.PASSED.value:\n                findings[-1] = create_finding(\n                    check_id="AC-47",\n',
        "replace": '            if False:\n                findings[-1] = create_finding(\n                    check_id="AC-47",\n',
    },
    {
        "name": "AC-47 passes a served version it could not read",
        "file": AGENTCORE,
        "defect": "a denied GetAgentRuntime on a served version says nothing about its authorizer, so a Passed from it is a clean result from a failed read",
        "find": '                            "Grant bedrock-agentcore:GetAgentRuntime on this "\n                            "runtime and retry."\n                        ),\n                        reference=AGENTCORE_ALLOWED_WORKLOAD_REFERENCE_URL,\n                        severity=SeverityEnum.INFORMATIONAL,\n                        status=StatusEnum.NA,\n',
        "replace": '                            "Grant bedrock-agentcore:GetAgentRuntime on this "\n                            "runtime and retry."\n                        ),\n                        reference=AGENTCORE_ALLOWED_WORKLOAD_REFERENCE_URL,\n                        severity=SeverityEnum.INFORMATIONAL,\n                        status=StatusEnum.PASSED,\n',
    },
    {
        "name": "AC-18 does not read CloudTrail Lake event data stores",
        "file": AGENTCORE,
        "defect": "Memory data events recorded only in an ENABLED event data store read as absent, so a compliant account fails",
        "find": '        for store in stores:\n            store_arn = store.get("EventDataStoreArn")\n',
        "replace": '        for store in []:\n            store_arn = store.get("EventDataStoreArn")\n',
    },
    {
        "name": "AC-18 credits an event data store that is not ingesting",
        "file": AGENTCORE,
        "defect": "a store with ingestion stopped records nothing, so crediting its selectors passes memory calls no store records",
        "find": '            if detail.get("Status") != "ENABLED":\n                excluded.append(\n                    f"{store_label} is not ingesting (Status "\n',
        "replace": '            if False:\n                excluded.append(\n                    f"{store_label} is not ingesting (Status "\n',
    },
    {
        "name": "AC-18 fails a gap when an event data store was not read",
        "file": AGENTCORE,
        "defect": "a denied GetEventDataStore hides that store's selectors, so the Failed is a verdict from a failed read",
        "find": '                logger.warning(f"Could not read {store_label}: {type(error).__name__}")\n                unreadable.append(store_label)\n',
        "replace": '                logger.warning(f"Could not read {store_label}: {type(error).__name__}")\n',
    },
    {
        "name": "AC-18 ignores an event data store's memory ARN scope",
        "file": AGENTCORE,
        "defect": "a store scoped to every memory ARN, the scoping the control recommends, fails as uncovered",
        "find": "        for resource_type, scopes in store_scoped.items():\n",
        "replace": "        for resource_type, scopes in {}.items():\n",
    },
    {
        "name": "AC-50 matches Inspector coverage on repository name alone",
        "file": AGENTCORE,
        "defect": "a delegated administrator sees member accounts' repositories, so a member's ACTIVE repository of the same name passes an unscanned one",
        "find": '        resource = covered.get((registry_of.get(name, ""), name))\n',
        "replace": "        resource = next(\n            (r for (_, n), r in covered.items() if n == name), None\n        )\n",
    },
    {
        "name": "AC-34 claims the agent code is unreadable through any API",
        "file": AGENTCORE,
        "defect": "GetAgentRuntime returns the code's S3 location and the image URI, so the ceiling the Passed row states is false",
        "find": '    "The agent\'s code and container image were not scanned: GetAgentRuntime "\n',
        "replace": '    "The agent\'s code and container image are not readable through any "\n',
    },
    {
        "name": "AC-26 accepts several exempt principals on the tamper SCP",
        "file": AGENTCORE,
        "defect": "DET-09 exempts a single provisioning role, and each further exempt principal can delete the agent logs or turn protection off",
        "find": "    return len(exempted) <= 1 and not any(\n",
        "replace": "    return len(exempted) <= 9 and not any(\n",
    },
    {
        "name": "AC-26 accepts a wildcard name as the tamper SCP exemption",
        "file": AGENTCORE,
        "defect": "role/LogAdmin* exempts every role whose name starts that way, not one named role",
        "find": '        "*" in value.split(":", 5)[5] or "?" in value.split(":", 5)[5]\n',
        "replace": "        False\n",
    },
    {
        "name": "AC-06 does not read the recording key policy",
        "file": AGENTCORE,
        "defect": "a key policy granting decrypt to * makes every fetched recording plaintext to any account while the row passes",
        "find": "                    _recording_key_gaps(reads, bucket, key_cache),\n",
        "replace": "                    ([], [], [], [], []),\n",
    },
    {
        "name": "AC-06 passes a recording key whose policy it could not read",
        "file": AGENTCORE,
        "defect": "a denied GetKeyPolicy or DescribeKey says nothing about who can decrypt, so a Passed from it is a clean result from a failed read",
        "find": "        if isinstance(second, Exception):\n            unread.append(\n                f\"bucket '{bucket}' key {key_id} policy ({first} \"\n",
        "replace": "        if isinstance(second, Exception):\n            (lambda *_: None)(\n                f\"bucket '{bucket}' key {key_id} policy ({first} \"\n",
    },
    {
        "name": "AC-06 credits a recording key that lets anyone decrypt",
        "file": AGENTCORE,
        "defect": "the key read but never judged reports an open decrypt grant as a key that admits no unbounded principal",
        "find": "        elif _kms_key_policy_allows_open_decrypt(second):\n",
        "replace": "        elif False:\n",
    },
    {
        "name": "AC-51 claims no API identifies other AI front doors",
        "file": AGENTCORE,
        "defect": "an API Gateway integration URI can name bedrock-runtime, so the row stated a ceiling that does not exist",
        "find": '    "not read: finding them takes the AWS WAF association reads wafv2:ListWebACLs "\n    "and wafv2:ListResourcesForWebACL, whose grant was declined for this "\n    "assessment. CloudFront distributions are judged only where an origin is an "\n',
        "replace": '    "not identifiable as AI entry points by any API, so they are not judged. "\n    "CloudFront distributions are judged only where an origin is an "\n',
    },
    {
        "name": "AC-22 credits a link from a suspended member account",
        "file": AGENTCORE,
        "defect": "a link from a SUSPENDED or CLOSED member still shares its telemetry, and reading membership alone passes it",
        "find": '        if states.get(account) != "ACTIVE"\n',
        "replace": "        if account not in states\n",
    },
    {
        "name": "AC-22 passes stale links when ListAccounts fails",
        "file": AGENTCORE,
        "defect": "a failed ListAccounts read gives a verdict on every link instead of an N/A",
        "find": "    if states is None:\n",
        "replace": "    if states is None:\n        states = {}\n    if False:\n",
    },
    {
        "name": "AC-22 drops the link review on the policy continue",
        "file": AGENTCORE,
        "defect": "the link review is computed but never emitted",
        "find": "    return findings + link_findings\n",
        "replace": "    return findings\n",
    },
    {
        "name": "AC-45 skips memory, harness and payment manager roles",
        "file": AGENTCORE,
        "defect": "a memory role granting every model passes IAM-05 because no check reads it",
        "find": "            for family, label, role_arn, resource_arn in service_references\n",
        "replace": "            for family, label, role_arn, resource_arn in service_references[:0]\n",
    },
    {
        "name": "AC-45 judges a foreign service role by a local namesake",
        "file": AGENTCORE,
        "defect": "a memory naming another account's role is judged by the local role of the same name",
        "find": '            or detail.get("resourceArn"),\n',
        "replace": "",
    },
    {
        "name": "AC-45 hides a failed memory or payment manager read",
        "file": AGENTCORE,
        "defect": "a denied GetMemory or ListPaymentManagers drops the family with no N/A row",
        "find": '            "AgentCore Execution Role Scope",\n            service_errors,\n',
        "replace": '            "AgentCore Execution Role Scope",\n            [],\n',
    },
    {
        "name": "AC-45 reads CallWithBearerToken on * as every resource",
        "file": AGENTCORE,
        "defect": "an action with no resource type can only be granted on *, so failing it names a grant no policy can narrow",
        "find": '        "bedrock-mantle:callwithbearertoken",\n',
        "replace": "",
    },
    {
        "name": "AC-18 lists event data stores in this region only",
        "file": AGENTCORE,
        "defect": "a multi-Region event data store homed in another assessed Region records this Region's Memory events and was read as absent",
        "find": "    store_clients = [(region, cloudtrail_client)]\n    for other_region in target_regions or []:\n",
        "replace": "    store_clients = [(region, cloudtrail_client)]\n    for other_region in []:\n",
    },
    {
        "name": "AC-18 counts a single-region store homed elsewhere",
        "file": AGENTCORE,
        "defect": "a single-Region store in another Region records nothing here and was credited",
        "find": '            if store_region != region and detail.get("MultiRegionEnabled") is not True:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "AC-18 drops an unlisted region's stores silently",
        "file": AGENTCORE,
        "defect": "a denied ListEventDataStores in another Region turned a gap into a Failed verdict instead of N/A",
        "find": '            stores = []\n            unreadable.append(\n                "the CloudTrail Lake event data stores (ListEventDataStores "\n                f"failed in {store_region} with {type(error).__name__})"\n            )\n        except Exception',
        "replace": "            stores = []\n        except Exception",
    },
    {
        "name": "AC-18 reads a store listed in two regions twice",
        "file": AGENTCORE,
        "defect": "a store returned by two Regions' lists was counted twice",
        "find": "            if store_arn in seen_stores:\n                continue\n",
        "replace": "",
    },
    {
        "name": "AC-47 reads fronting gateways in its own region only",
        "file": AGENTCORE,
        "defect": "a gateway in another assessed Region routing to the runtime was not read, so its execution role read as an extra principal",
        "find": '        for region in other_regions or []:\n            try:\n                agentcore_client = boto3.client(\n                    "bedrock-agentcore-control", config=boto3_config, region_name=region\n',
        "replace": '        for region in []:\n            try:\n                agentcore_client = boto3.client(\n                    "bedrock-agentcore-control", config=boto3_config, region_name=region\n',
    },
    {
        "name": "AC-47 drops a denied region's gateways silently",
        "file": AGENTCORE,
        "defect": "a denied ListGateways in another Region left a caller Passed that an unread gateway there could contradict",
        "find": '                unread.append(\n                    f"bedrock-agentcore:ListGateways in {region} "\n                    f"({_assessment_error_label(error)})"\n                )\n                continue\n            except Exception',
        "replace": "                continue\n            except Exception",
    },
    {
        "name": "AC-47 reads a region not opted into as unread",
        "file": AGENTCORE,
        "defect": "a Region the account has not opted into, which holds no gateway, turned the verdict into N/A",
        "find": '                    in REGION_UNAVAILABLE_ERROR_CODES\n                ):\n                    continue\n                unread.append(\n                    f"bedrock-agentcore:ListGateways in {region} "\n',
        "replace": '                    in ()\n                ):\n                    continue\n                unread.append(\n                    f"bedrock-agentcore:ListGateways in {region} "\n',
    },
    {
        "name": "AC-47 claims this region after reading every region",
        "file": AGENTCORE,
        "defect": "the finding said 'this region' after reading the gateways of every assessed Region",
        "find": '    return fronting, unread, "any assessed region" if other_regions else "this region"\n',
        "replace": '    return fronting, unread, "this region"\n',
    },
    {
        "name": "AC-47 leaves the agentcore client on another region",
        "file": AGENTCORE,
        "defect": "the runtime reads after the gateway sweep went to the last assessed Region's client",
        "find": "    finally:\n        agentcore_client = held\n    return fronting, unread,",
        "replace": "    finally:\n        pass\n    return fronting, unread,",
    },
    {
        "name": "AC-26 credits a filter pattern",
        "file": AGENTCORE,
        "defect": "a subscription filter that forwards only matching events was credited as an archive of every event",
        "find": '    pattern = str(subscription.get("filterPattern") or "").strip()\n    if pattern:\n',
        "replace": '    pattern = str(subscription.get("filterPattern") or "").strip()\n    if False:\n',
    },
    {
        "name": "AC-26 credits field selection criteria",
        "file": AGENTCORE,
        "defect": "a filter narrowed by field selection criteria was credited",
        "find": '    if str(subscription.get("fieldSelectionCriteria") or "").strip():\n',
        "replace": "    if False:\n",
    },
    {
        "name": "AC-26 credits a filter on transformed logs",
        "file": AGENTCORE,
        "defect": "a filter applied on transformed logs was credited as a copy of the ingested events",
        "find": '    if subscription.get("applyOnTransformedLogs") is True:\n',
        "replace": "    if False:\n",
    },
    {
        "name": "AC-26 follows another account's stream",
        "file": AGENTCORE,
        "defect": "a stream in another account was described with this account's credentials and its failure misread",
        "find": "    if parts[4] != account:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-26 credits an inactive stream",
        "file": AGENTCORE,
        "defect": "a Firehose stream that is not ACTIVE was credited",
        "find": '    if status != "ACTIVE":\n',
        "replace": "    if False:\n",
    },
    {
        "name": "AC-26 credits a Lambda record processor",
        "file": AGENTCORE,
        "defect": "a stream whose Lambda processor can drop records was credited",
        "find": '        if processing.get("Enabled") is True and lambdas:\n',
        "replace": "        if False:\n",
    },
    {
        "name": "AC-26 credits a non-S3 stream destination",
        "file": AGENTCORE,
        "defect": "a Firehose stream delivering to Splunk was read as an S3 archive",
        "find": "        if not s3_target:\n            kinds",
        "replace": "        if False:\n            kinds",
    },
    {
        "name": "AC-26 credits Object Lock off",
        "file": AGENTCORE,
        "defect": "a bucket with Object Lock off was credited as WORM",
        "find": '    if value.get("ObjectLockEnabled") != "Enabled":\n',
        "replace": "    if False:\n",
    },
    {
        "name": "AC-26 credits GOVERNANCE retention",
        "file": AGENTCORE,
        "defect": "GOVERNANCE mode, which s3:BypassGovernanceRetention overrides, was credited",
        "find": '    if mode != "COMPLIANCE":\n',
        "replace": "    if False:\n",
    },
    {
        "name": "AC-26 reads an unread bucket as off",
        "file": AGENTCORE,
        "defect": "a denied Object Lock read was reported as a Failed bucket",
        "find": '    if state == "error":\n        return "unread", (\n            f"s3:GetBucketObjectLockConfiguration',
        "replace": '    if state == "error":\n        return "bad", (\n            f"s3:GetBucketObjectLockConfiguration',
    },
    {
        "name": "AC-26 passes a group whose filters are unreadable",
        "file": AGENTCORE,
        "defect": "an unread archive chain produced a Passed row",
        "find": '    passed = [text for state, text in verdicts if state == "ok"]\n',
        "replace": '    passed = [text for state, text in verdicts if state in ("ok", "unread")]\n',
    },
    {
        "name": "AC-26 skips the spans group",
        "file": AGENTCORE,
        "defect": "aws/spans, which holds the trace spans, was not judged for an archive",
        "find": "                _agentcore_delivery_log_group_names()\n                | {TRANSACTION_SEARCH_SPANS_LOG_GROUP}\n",
        "replace": "                _agentcore_delivery_log_group_names()\n",
    },
    {
        "name": "AC-26 drops the no-filter verdict",
        "file": AGENTCORE,
        "defect": "a group with no subscription filter did not fail",
        "find": '    if not subscriptions:\n        return create_finding(\n            check_id="AC-26",\n            finding_name=AGENTCORE_LOG_ARCHIVE_FINDING,\n',
        "replace": '    if False:\n        return create_finding(\n            check_id="AC-26",\n            finding_name=AGENTCORE_LOG_ARCHIVE_FINDING,\n',
    },
    {
        "name": "AC-26 describes a stream once per group",
        "file": AGENTCORE,
        "defect": "the Firehose stream shared by two groups was described twice",
        "find": "    if destination not in stream_cache:\n",
        "replace": "    if True:\n",
    },
    {
        "name": "AC-26 judges a trail bucket of another region",
        "file": AGENTCORE,
        "defect": "a single-Region trail homed elsewhere was judged for this Region",
        "find": '        if not detail.get("IsMultiRegionTrail") and detail.get("HomeRegion") != region:\n            continue\n        findings.append(\n            _trail_bucket_lock_finding(',
        "replace": "        findings.append(\n            _trail_bucket_lock_finding(",
    },
    {
        "name": "AC-26 reads an unread trail bucket as clean",
        "file": AGENTCORE,
        "defect": "a denied trail-bucket read produced a row that was not N/A",
        "find": '    if state == "unread":\n        return create_finding(\n            check_id="AC-26",\n            finding_name=finding_name,\n',
        "replace": '    if state == "unread":\n        state = "ok"\n    if False:\n        return create_finding(\n            check_id="AC-26",\n            finding_name=finding_name,\n',
    },
    {
        "name": "AC-26 drops the trail bucket verdict",
        "file": AGENTCORE,
        "defect": "an unlocked trail bucket was reported Passed",
        "find": '    if state == "ok":\n        return create_finding(\n            check_id="AC-26",\n            finding_name=finding_name,\n            finding_details=f"Trail {label} writes to {text}.",\n',
        "replace": '    if True:\n        return create_finding(\n            check_id="AC-26",\n            finding_name=finding_name,\n            finding_details=f"Trail {label} writes to {text}.",\n',
    },
    {
        "name": "AC-06 credits an unbound service reader",
        "file": AGENTCORE,
        "defect": "a service principal reading the recordings for a resource in any account was credited",
        "find": "        if services and not _confused_deputy_guard_account(statement, account):\n",
        "replace": "        if False:\n",
    },
    {
        "name": "AC-06 skips services under RestrictPublicBuckets",
        "file": AGENTCORE,
        "defect": "a public statement under RestrictPublicBuckets hid an unbound service principal grant",
        "find": "    services_only = bool(\n        restrict and any(_s3_public_statement(st) for st in statements)\n    )\n",
        "replace": "    services_only = bool(\n        restrict and any(_s3_public_statement(st) for st in statements)\n    )\n    if services_only:\n        return [], []\n",
    },
    {
        "name": "AC-06 judges public grants under RestrictPublicBuckets",
        "file": AGENTCORE,
        "defect": "another account's role named beside '*', which RestrictPublicBuckets confines, was reported as a reader",
        "find": "        if services_only:\n            continue\n",
        "replace": "",
    },
    {
        "name": "AC-06 credits ACLs left on",
        "file": AGENTCORE,
        "defect": "a bucket with ACLs enabled was credited",
        "find": '        if ownership == ["BucketOwnerEnforced"]:\n',
        "replace": "        if True:\n",
    },
    {
        "name": "AC-06 reads an unread ownership setting as enforced",
        "file": AGENTCORE,
        "defect": "a denied ownership read was credited as BucketOwnerEnforced",
        "find": '    state, response = reads["ownership"]\n    if state == "error":\n',
        "replace": '    state, response = reads["ownership"]\n    if state == "error":\n        state, response = "read", {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}\n    if False:\n',
    },
    {
        "name": "AC-06 skips the recording key-use leg",
        "file": AGENTCORE,
        "defect": "a role that cannot use the bucket's key for kms:GenerateDataKey was reported able to write recordings",
        "find": "    for key_arn, key_policy in recording_keys or []:\n",
        "replace": "    for key_arn, key_policy in []:\n",
    },
    {
        "name": "AC-06 credits a key policy Deny",
        "file": AGENTCORE,
        "defect": "a Deny of kms:GenerateDataKey reaching the role was ignored",
        "find": '        if not statement.get("Condition"):\n            return "failed", (\n                f"a Deny in {source} refuses execution role {role_name} "\n                f"kms:GenerateDataKey',
        "replace": '        if False:\n            return "failed", (\n                f"a Deny in {source} refuses execution role {role_name} "\n                f"kms:GenerateDataKey',
    },
    {
        "name": "AC-06 reads any key grant as root delegation",
        "file": AGENTCORE,
        "defect": "a key policy that delegates to no one but an admin role was read as delegating to the account",
        "find": "        elif names(statement, {root, account}):\n",
        "replace": "        elif True:\n",
    },
    {
        "name": "AC-06 admits any kms:CallerAccount",
        "file": AGENTCORE,
        "defect": "a key grant limited to another account's callers was credited",
        "find": '            if key == "kms:calleraccount" and account not in values:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "AC-06 admits any kms:ViaService",
        "file": AGENTCORE,
        "defect": "a key grant limited to calls through EC2 was credited for S3",
        "find": '            if key == "kms:viaservice" and not any(\n',
        "replace": "            if False and not any(\n",
    },
    {
        "name": "AC-06 admits an unread key-policy condition key",
        "file": AGENTCORE,
        "defect": "a key grant conditioned on a principal tag was credited without evaluating the tag",
        "find": "            if key not in RECORDING_KEY_USE_CONDITION_KEYS or not values:\n",
        "replace": "            if not values:\n",
    },
    {
        "name": "AC-06 ignores the boundary for the recording key",
        "file": AGENTCORE,
        "defect": "a permissions boundary that allows no kms action was ignored for the recording key",
        "find": '    if (\n        boundary is not None\n        and not allows(boundary_statements, "the permissions boundary")\n        and len(conditional) == before\n    ):\n        return "failed", (\n            f"the permissions boundary of execution role {role_name} does not "\n            f"allow kms:GenerateDataKey',
        "replace": '    if (\n        False\n        and not allows(boundary_statements, "the permissions boundary")\n        and len(conditional) == before\n    ):\n        return "failed", (\n            f"the permissions boundary of execution role {role_name} does not "\n            f"allow kms:GenerateDataKey',
    },
    {
        "name": "AC-06 SCP leg keeps set-operator prefixes",
        "file": AGENTCORE,
        "defect": "a ForAnyValue:StringNotLike PrincipalArn Deny reaching the role was read as unevaluated",
        "find": '                name = name[len(prefix) :]\n        if name.endswith("ifexists"):\n            name = name[: -len("ifexists")]\n        if not isinstance(entries, dict):\n            unevaluated.append(str(operator))\n',
        "replace": '                pass\n        if name.endswith("ifexists"):\n            name = name[: -len("ifexists")]\n        if not isinstance(entries, dict):\n            unevaluated.append(str(operator))\n',
    },
    {
        "name": "AC-06 SCP leg keeps IfExists suffixes",
        "file": AGENTCORE,
        "defect": "an ArnNotLikeIfExists Deny reaching the role was read as unevaluated",
        "find": '            name = name[: -len("ifexists")]\n        if not isinstance(entries, dict):\n            unevaluated.append(str(operator))\n',
        "replace": "            pass\n        if not isinstance(entries, dict):\n            unevaluated.append(str(operator))\n",
    },
    {
        "name": "AC-06 SCP leg ignores negated operators",
        "file": AGENTCORE,
        "defect": "a Deny exempting only an admin role was read as exempting the recording role",
        "find": '                holds = not matched if "not" in name else matched\n',
        "replace": "                holds = matched\n",
    },
    {
        "name": "AC-06 SCP leg ignores a condition that excludes the write",
        "file": AGENTCORE,
        "defect": "a Deny exempting the recording role failed the browser",
        "find": "    if failed:\n        return False, []\n    return (None, unevaluated) if unevaluated else (True, [])\n",
        "replace": "    if False:\n        return False, []\n    return (None, unevaluated) if unevaluated else (True, [])\n",
    },
    {
        "name": "AC-06 SCP leg reads an unknown condition key as holding",
        "file": AGENTCORE,
        "defect": "a Deny under aws:RequestedRegion was judged as unconditional",
        "find": "    return (None, unevaluated) if unevaluated else (True, [])\n",
        "replace": "    return True, []\n",
    },
    {
        "name": "AC-06 SCP leg ignores attachment",
        "file": AGENTCORE,
        "defect": "a Deny attached to another OU failed the browser",
        "find": "                        [node for node in labels if node in targets]\n",
        "replace": "                        list(labels)\n",
    },
    {
        "name": "AC-06 SCP leg skips the per-level Allow",
        "file": AGENTCORE,
        "defect": "an OU whose SCPs allow no s3:PutObject on the prefix passed",
        "find": '                    if state == ("none",) and not unread_policies:\n',
        "replace": "                    if False:\n",
    },
    {
        "name": "AC-06 SCP leg credits a conditioned Allow",
        "file": AGENTCORE,
        "defect": "an Allow under aws:RequestedRegion was credited at its level",
        "find": '                            if holds:\n                                allowed[node] = ("allowed",)\n',
        "replace": '                            if True:\n                                allowed[node] = ("allowed",)\n',
    },
    {
        "name": "AC-06 SCP leg drops unread policies",
        "file": AGENTCORE,
        "defect": "an SCP whose attachment targets were not read let the browser pass",
        "find": "        unread.extend(unread_policies)\n",
        "replace": "",
    },
    {
        "name": "AC-06 SCP leg skips the recording key",
        "file": AGENTCORE,
        "defect": "an SCP denying kms:GenerateDataKey on the recording key passed",
        "find": "                for arn in key_arns\n            ]\n            for spelling, action, resource in legs:\n",
        "replace": "                for arn in []\n            ]\n            for spelling, action, resource in legs:\n",
    },
    {
        "name": "AC-06 SCP leg binds the management account",
        "file": AGENTCORE,
        "defect": "the management account was judged against SCPs that cannot bind it",
        "find": '    if accounts <= {_arn_account(policy.get("Arn")) for policy in policies}:\n',
        "replace": "    if False:\n",
    },
    {
        "name": "AC-06 SCP leg passes an unread bucket encryption",
        "file": AGENTCORE,
        "defect": "an unread recording bucket encryption let the browser pass",
        "find": "        return [], [\n            f\"the default encryption of bucket '{bucket}' \"\n",
        "replace": "        return [], [][:0] and [\n            f\"the default encryption of bucket '{bucket}' \"\n",
    },
    {
        "name": "AC-35 input guard ignores the order inside an operand",
        "file": AGENTCORE,
        "defect": "an if ... has ... then read was failed as unguarded",
        "find": "            start < match.start() and tested == field for start, tested in tests\n",
        "replace": "            start > match.start() and tested == field for start, tested in tests\n",
    },
    {
        "name": "AC-35 input guard drops the && carry",
        "file": AGENTCORE,
        "defect": "a read after a has() conjunct was failed as unguarded",
        "find": '            if not _cedar_unwrap_parentheses(conjunct).startswith("!"):\n                carried |= _cedar_input_has_tests(conjunct)\n',
        "replace": "            if False:\n                carried |= _cedar_input_has_tests(conjunct)\n",
    },
    {
        "name": "AC-35 input guard carries a negated has across &&",
        "file": AGENTCORE,
        "defect": "a read after !(has) && was credited as guarded",
        "find": '            if not _cedar_unwrap_parentheses(conjunct).startswith("!"):\n',
        "replace": "            if True:\n",
    },
    {
        "name": "AC-35 input guard drops the negated || carry",
        "file": AGENTCORE,
        "defect": "a read after !(has) || was failed as unguarded",
        "find": '            if stripped.startswith("!"):\n                carried |= _cedar_input_has_tests(stripped)\n',
        "replace": "            if False:\n                carried |= _cedar_input_has_tests(stripped)\n",
    },
    {
        "name": "AC-35 input guard carries a positive has across ||",
        "file": AGENTCORE,
        "defect": "a read after has || was credited as guarded",
        "find": '            if stripped.startswith("!"):\n',
        "replace": "            if True:\n",
    },
    {
        "name": "AC-35 input guard drops the when-block carry",
        "file": AGENTCORE,
        "defect": "a read guarded by an earlier when block was failed",
        "find": '        if keyword == "when":\n            guarded |= _cedar_input_has_tests(body)\n',
        "replace": "        if False:\n            guarded |= _cedar_input_has_tests(body)\n",
    },
    {
        "name": "AC-35 input guard skips unless blocks",
        "file": AGENTCORE,
        "defect": "an unguarded optional read in an unless block passed",
        "find": '        unguarded |= _cedar_unguarded_input_reads(body, guarded)\n        if keyword == "when":\n',
        "replace": '        unguarded |= (\n            set() if keyword == "unless" else _cedar_unguarded_input_reads(body, guarded)\n        )\n        if keyword == "when":\n',
    },
    {
        "name": "AC-35 input guard reads string literals",
        "file": AGENTCORE,
        "defect": "a string literal naming context.input.memo failed the forbid",
        "find": '        if blanked[match.start()] == " ":\n            continue\n',
        "replace": "        if False:\n            continue\n",
    },
    {
        "name": "AC-35 input guard judges permits",
        "file": AGENTCORE,
        "defect": "a permit that fails closed on a missing input was failed",
        "find": '                    _cedar_forbid_unguarded_inputs(conditions)\n                    if effect == "forbid"\n',
        "replace": '                    _cedar_forbid_unguarded_inputs(conditions)\n                    if effect in ("forbid", "permit")\n',
    },
    {
        "name": "AC-35 input guard ignores the required list",
        "file": AGENTCORE,
        "defect": "a read of a required input was failed",
        "find": "                optional = sorted(fields - tools[action])\n",
        "replace": "                optional = sorted(fields)\n",
    },
    {
        "name": "AC-35 input guard reads a bare action as no tool",
        "file": AGENTCORE,
        "defect": "a forbid over every action reading an input optional on one tool passed",
        "find": "                in_scope = sorted(tools)\n",
        "replace": "                in_scope = []\n",
    },
    {
        "name": "AC-35 input guard reads an action group as every action",
        "file": AGENTCORE,
        "defect": "a forbid over an action group was judged as over every tool",
        "find": '    if not names or (words[1:2] == ["in"] and "[" not in part):\n        return None\n',
        "replace": '    if not names or (words[1:2] == ["in"] and "[" not in part):\n        return []\n',
    },
    {
        "name": "AC-35 input guard drops an unreadable target",
        "file": AGENTCORE,
        "defect": "a gateway whose targets could not be read passed",
        "find": '            unread[name] = (\n                f"bedrock-agentcore:GetGatewayTarget {_assessment_error_label(error)}"\n            )\n',
        "replace": "            pass\n",
    },
    {
        "name": "AC-35 input guard reads an S3 tool schema as empty",
        "file": AGENTCORE,
        "defect": "a forbid over a tool whose schema is in S3 passed",
        "find": '        if "inlinePayload" not in schema:\n',
        "replace": "        if False:\n",
    },
    {
        "name": "AG-39 omits the unread front doors",
        "file": AGENTCORE,
        "defect": "an AG-39 row did not name the front doors it leaves unread",
        "find": '        if finding.get("Check_ID") in ("AG-27", "AG-39"):\n',
        "replace": '        if finding.get("Check_ID") in ("AG-27",):\n',
    },
    {
        "name": "AC-45 names a customer policy as the AWS default",
        "file": AGENTCORE,
        "defect": "a customer managed policy was named as AWS's own default",
        "find": '            and ":iam::aws:policy/" in str(policy.get("arn") or "")\n',
        "replace": "            and True\n",
    },
    {
        "name": "AC-45 hides the AWS managed policy",
        "file": AGENTCORE,
        "defect": "the AWS managed memory policy failed without being named",
        "find": '                            "fails. "\n                            if aws_managed\n',
        "replace": '                            "fails. "\n                            if False\n',
    },
    {
        "name": "AC-51 shield: origin host compared case-sensitively",
        "file": AGENTCORE,
        "defect": "an origin spelled in upper case escaped the gateway match",
        "find": '                str(origin.get("DomainName") or "").lower()\n',
        "replace": '                str(origin.get("DomainName") or "")\n',
    },
    {
        "name": "AC-51 shield: any distribution read as a front door",
        "file": AGENTCORE,
        "defect": "a distribution fronting no gateway was judged",
        "find": "            & set(hosts)\n",
        "replace": "            | set(hosts)\n",
    },
    {
        "name": "AC-51 shield: an inactive subscription is judged",
        "file": AGENTCORE,
        "defect": "an account with no Shield Advanced subscription was failed",
        "find": '    if state != "ACTIVE":\n',
        "replace": '    if state not in ("ACTIVE", "INACTIVE"):\n',
    },
    {
        "name": "AC-51 shield: any protection credits every distribution",
        "file": AGENTCORE,
        "defect": "a protection on another resource credited the distribution",
        "find": "        if arn and arn in protected:\n",
        "replace": "        if arn and protected:\n",
    },
    {
        "name": "AC-51 shield: unread gateways dropped",
        "file": AGENTCORE,
        "defect": "a gateway whose URL could not be read vanished from the report",
        "find": "    if unread and distributions:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-51 shield: only the first distribution page read",
        "file": AGENTCORE,
        "defect": "distributions past the first page were not read",
        "find": '            for page in cloudfront_client.get_paginator("list_distributions").paginate()\n',
        "replace": '            for page in cloudfront_client.get_paginator("list_distributions").paginate()[:1]\n',
    },
    {
        "name": "AC-51 shield: only the first protection page read",
        "file": AGENTCORE,
        "defect": "protections past the first page were not read",
        "find": '            for page in shield_client.get_paginator("list_protections").paginate()\n',
        "replace": '            for page in shield_client.get_paginator("list_protections").paginate()[:1]\n',
    },
    {
        "name": "AC-48 credits an IfExists deputy guard",
        "file": AGENTCORE,
        "defect": "an IfExists aws:SourceAccount or aws:SourceArn guard was credited",
        "find": '    "stringequals",\n    "stringequalsignorecase",\n    "stringlike",\n    "arnequals",\n    "arnlike",\n}\n\n\n# Negated operators whose Deny',
        "replace": '    "stringequals",\n    "stringequalsignorecase",\n    "stringlike",\n    "arnequals",\n    "arnlike",\n    "stringequalsifexists",\n    "arnlikeifexists",\n}\n\n\n# Negated operators whose Deny',
    },
    {
        "name": "AC-48 credits a ForAllValues deputy guard",
        "file": AGENTCORE,
        "defect": "a ForAllValues: aws:SourceAccount or aws:SourceArn guard was credited",
        "find": '    if not account_id:\n        return False\n    conditions = statement.get("Condition")\n    if not isinstance(conditions, dict):\n        return False\n    for operator, entries in conditions.items():\n        if not isinstance(entries, dict):\n            continue\n        name = str(operator).strip().lower()\n        if name.startswith("foranyvalue:"):\n',
        "replace": '    if not account_id:\n        return False\n    conditions = statement.get("Condition")\n    if not isinstance(conditions, dict):\n        return False\n    for operator, entries in conditions.items():\n        if not isinstance(entries, dict):\n            continue\n        name = str(operator).strip().lower().replace("forallvalues:", "foranyvalue:")\n        if name.startswith("foranyvalue:"):\n',
    },
    {
        "name": "AC-48 credits a partial wildcard account segment",
        "file": AGENTCORE,
        "defect": "an aws:SourceArn account segment with a wildcard was credited",
        "find": '            if key == "aws:sourcearn" and all(\n                _arn_account(value.strip()) == account_id for value in values\n            ):\n',
        "replace": '            if key == "aws:sourcearn" and all(\n                account_id.startswith(_arn_account(value.strip()).rstrip("*")) and _arn_account(value.strip()) for value in values\n            ):\n',
    },
    {
        "name": "AC-50 image: a cross-account image is judged",
        "file": AGENTCORE,
        "defect": "an image in another account's registry was resolved and judged",
        "find": "        if key in runtime_images:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "AC-50 image: another account's scan credited",
        "file": AGENTCORE,
        "defect": "an image scan in another account credited this account's image",
        "find": '            if str(resource.get("accountId") or "") != registry:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "AC-50 image: another repository's scan credited",
        "file": AGENTCORE,
        "defect": "an image scan was keyed without its repository",
        "find": "                    if image_repo == repo_name:\n",
        "replace": "                    if True:\n",
    },
    {
        "name": "AC-50 image: an inactive repository's images judged",
        "file": AGENTCORE,
        "defect": "an image under an INACTIVE repository was judged on its own scan",
        "find": '            if repository_status != "ACTIVE":\n',
        "replace": "            if repository_status is None:\n",
    },
    {
        "name": "AC-50 image: an untagged URI resolved without latest",
        "file": AGENTCORE,
        "defect": "an image URI with no tag was not resolved as latest",
        "find": '                tag = image_ref[1:] if image_ref.startswith(":") else "latest"\n',
        "replace": '                tag = image_ref[1:] if image_ref.startswith(":") else ""\n',
    },
    {
        "name": "AC-50 image: any scanned image credits the runtime",
        "file": AGENTCORE,
        "defect": "a scan of another image in the repository credited the runtime",
        "find": "            resource = scanned.get(digest)\n",
        "replace": "            resource = next(iter(scanned.values()), None)\n",
    },
    {
        "name": "AC-50 image: a lapsed image scan passes",
        "file": AGENTCORE,
        "defect": "an image whose scan lapsed passed",
        "find": '            if code == "ACTIVE":\n',
        "replace": '            if code in ("ACTIVE", "INACTIVE"):\n',
    },
    {
        "name": "AC-40 safety: one named evaluator stands in for both",
        "file": AGENTCORE,
        "defect": "a configuration attaching Harmfulness without Stereotyping passed",
        "find": "        if safety_missing:\n",
        "replace": "        if len(safety_missing) == len(EVALUATOR_REQUIRED_SAFETY_IDS):\n",
    },
    {
        "name": "AC-29 authorizer: an absent authorizer type is not judged",
        "file": AGENTCORE,
        "defect": "a guardrail that never fires on an absent authorizer type passed",
        "find": "            also_denies=(RUNTIME_AUTHORIZER_UNLISTED_VALUE,),\n            absent_denied=True,\n        )\n",
        "replace": "            also_denies=(RUNTIME_AUTHORIZER_UNLISTED_VALUE,),\n        )\n",
    },
    {
        "name": "AC-36 engine key: DescribeKey is not source-guarded",
        "file": AGENTCORE,
        "defect": "a key policy granting kms:DescribeKey without a source guard passed",
        "find": '    "kms:GenerateDataKey",\n    "kms:DescribeKey",\n)\nPOLICY_ENGINE_CONTEXT_BOUND_ACTIONS',
        "replace": '    "kms:GenerateDataKey",\n)\nPOLICY_ENGINE_CONTEXT_BOUND_ACTIONS',
    },
    {
        "name": "AC-27 deputy: a private path excuses any gateway",
        "file": AGENTCORE,
        "defect": "an AWS_IAM gateway allowing Principal '*' bounded by aws:SourceVpce passed",
        "find": '        if str(authorizer_type or "") == "CUSTOM_JWT":\n',
        "replace": "        if True:\n",
    },
    {
        "name": "AC-08 OAuth discovery: a named principal admits the discovery call",
        "file": AGENTCORE,
        "defect": "an endpoint policy allowing only a named principal passed OAuth discovery",
        "find": '            and "NotPrincipal" not in statement\n            and "*" in _statement_principals(statement)\n            and _statement_matches_action(statement, action)\n',
        "replace": '            and "NotPrincipal" not in statement\n            and _statement_matches_action(statement, action)\n',
    },
    # ------------------------------------- end of the AgentCore verdict legs
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
    "BR-04 credits any object in the log bucket as a retained entry": (
        "in the Bedrock invocation log entries"
    ),
    "an unread list read lets the BR-53 sweep summary pass": (
        "in the Bedrock owner tag sweep"
    ),
    "BR-43 stops reducing a profile ARN modelId to its ID": (
        "in the Bedrock profiles in use"
    ),
    "BR-57 credits a SourceAccount naming another account": (
        "in the Bedrock agent workload identity"
    ),
    "two action group functions on one role pass BR-57": (
        "in the Bedrock agent workload identity"
    ),
    "BR-33 credits an image its repository scans only on push": (
        "in the Bedrock container image scanning"
    ),
    "BR-33 judges another account's image by this account's coverage": (
        "in the Bedrock container image scanning"
    ),
    "BR-34 credits a detected prompt attack the guardrail let through": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-34 credits an untagged guarded InvokeModel call": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 reads an absent text delivery flag as delivered": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "SM-39 evaluates DNS Firewall rule groups in list order": (
        "in `SM-39`'s egress legs"
    ),
    "SM-39 accepts a DNS Firewall that fails open": "in `SM-39`'s egress legs",
    "SM-39 loses a NAT gateway path to an internet gateway": (
        "in `SM-39`'s egress legs"
    ),
    "SM-43 drops the objects past the HeadObject cap": "in `SM-43`'s artifact reads",
    "SM-43 ignores an execution role's NotResource grant": (
        "in `SM-43`'s artifact reads"
    ),
    "AC-37 reads an allow-list SCP's omission as an Allow": "in the AgentCore verdict legs",
    "AC-37 passes when the organization's SCPs could not be listed": "in the AgentCore verdict legs",
    "AC-42 passes the population beside an unread configuration": "in the AgentCore verdict legs",
    "AC-44 passes a model grant only code-based evaluators sit beside": "in the AgentCore verdict legs",
    "AC-40 counts an alarm no listed metric ties to an evaluator": "in the AgentCore verdict legs",
    "AC-40 judges a stopped configuration as scoring safety": "in the AgentCore verdict legs",
    "AC-17 reads a stopped configuration with no runtime as N/A": "in the AgentCore verdict legs",
    "AC-29 credits a runtime deny-list of AWS_IAM": "in the AgentCore verdict legs",
    "AC-07 passes a memory beside a strategy with no namespace": "in the AgentCore verdict legs",
    "AC-23 passes a read bound by a fixed literal partition": "in the AgentCore verdict legs",
    "AC-21 bounds an APPLICATION_LOGS-wide unmask": "in the AgentCore verdict legs",
    "AC-20 reads a key id as customer managed encryption": "in the AgentCore verdict legs",
    "AC-02 passes a budget writer with no ProcessPayment Deny": "in the AgentCore verdict legs",
    "AC-48 judges a foreign role by a same-named local role": "in the AgentCore verdict legs",
    "AC-48 passes a trust that names another service": "in the AgentCore verdict legs",
    "AC-53 credits an alarm on another Environment": "in the AgentCore verdict legs",
    "AC-01 passes a broad public egress range": "in the AgentCore verdict legs",
    "AC-27 passes a gateway policy statement with no source ARN": "in the AgentCore verdict legs",
    "AC-36 credits a source-context statement with only SourceAccount": "in the AgentCore verdict legs",
    "AG-24 passes a gateway with no REQUEST interceptor": "in the AgentCore verdict legs",
    "AG-24 counts a RESPONSE-only interceptor as a request guard": "in the AgentCore verdict legs",
    "AC-25 passes a portal-served target with its own return URL": "in the AgentCore verdict legs",
    "AC-25 passes token exchange on a gateway with no JWT inbound": "in the AgentCore verdict legs",
    "AC-25 passes an AUTHORIZATION_CODE target beside an unread portal list": "in the AgentCore verdict legs",
    "AG-24 passes an authorized gateway with no enforcing engine": "in the AgentCore verdict legs",
    "AC-29 credits a runtime Deny narrowed to some resources": "in the AgentCore verdict legs",
    "AC-33 reads only the primary Region's runtimes": "in the AgentCore verdict legs",
    "AC-33 fails a JWT runtime role whose own Deny removes ForUserId": "in the AgentCore verdict legs",
    "AC-33 lets a ? Deny pattern cover every runtime endpoint": "in the AgentCore verdict legs",
    "AC-33 reads a NotResource ForUser grant as reaching nothing": "in the AgentCore verdict legs",
    "AC-33 never credits a foreign identity in a read Region as crossing": "in the AgentCore verdict legs",
    "AC-32 passes an issuer pin with no application pin": "in the AgentCore verdict legs",
    "AC-32 passes claim pins with no network pin": "in the AgentCore verdict legs",
    "AC-32 passes an issuer no authorizer trusts": "in the AgentCore verdict legs",
    "AC-32 credits a DiscoveryUrl deny-list of one bad issuer": "in the AgentCore verdict legs",
    "AC-47 passes a PrincipalArn Deny naming no fronting gateway role": "in the AgentCore verdict legs",
    "AC-47 passes a PrincipalArn Deny naming a role beside the gateway's": "in the AgentCore verdict legs",
    "AC-06 credits an IfExists aws:PrincipalAccount binding": "in the AgentCore verdict legs",
    "AC-06 credits an IfExists aws:SourceAccount binding": "in the AgentCore verdict legs",
    "AC-06 credits an IfExists aws:PrincipalOrgID binding": "in the AgentCore verdict legs",
    "AC-18 fails a memory selector that names every memory by ARN": "in the AgentCore verdict legs",
    "AC-18 credits an ARN selector that names one of two memories": "in the AgentCore verdict legs",
    "AC-45 reads the shell alarm in the primary Region only": "in the AgentCore verdict legs",
    "AC-45 asks for a shell alarm in a Region with no runtime": "in the AgentCore verdict legs",
    "AC-41 credits an evaluation key on DescribeKey alone": "in the AgentCore verdict legs",
    "AC-41 drops kms:ViaService from an evaluator's caller leg": "in the AgentCore verdict legs",
    "AC-41 accepts an encryption context open in the account segment": "in the AgentCore verdict legs",
    "AC-41 credits a context that names another evaluator": "in the AgentCore verdict legs",
    "AC-41 ignores a service-principal grant with no aws:SourceArn": "in the AgentCore verdict legs",
    "AC-41 passes a key policy it could not read": "in the AgentCore verdict legs",
    "AC-41 credits a batch evaluation key on DescribeKey alone": "in the AgentCore verdict legs",
    "AC-36 credits a key-loss metric filter no trail feeds": "in the AgentCore verdict legs",
    "AC-36 credits a trail that is not logging": "in the AgentCore verdict legs",
    "AC-36 credits a read-only management selector": "in the AgentCore verdict legs",
    "AC-36 ignores ExcludeManagementEventSources": "in the AgentCore verdict legs",
    "AC-36 credits a read-only advanced selector": "in the AgentCore verdict legs",
    "AC-36 credits a trail homed in another Region": "in the AgentCore verdict legs",
    "AC-49 reads the latest runtime version only": "in the AgentCore verdict legs",
    "AC-49 drops an unlisted runtime version set silently": "in the AgentCore verdict legs",
    "AC-44 does not read the evaluation role's other grants": "in the AgentCore verdict legs",
    "AC-44 credits a NotAction Allow on the evaluation role": "in the AgentCore verdict legs",
    "AC-44 credits evaluation log writes on any group": "in the AgentCore verdict legs",
    "AC-44 credits a log-group pattern open in the account segment": "in the AgentCore verdict legs",
    "AC-44 credits PutIndexPolicy on any log group": "in the AgentCore verdict legs",
    "AC-44 counts an extra grant the role's own Deny removes": "in the AgentCore verdict legs",
    "AC-27 does not read consent portal execution roles": "in the AgentCore verdict legs",
    "AC-27 accepts any resource type in a portal role's aws:SourceArn": "in the AgentCore verdict legs",
    "AC-27 passes a consent portal it could not read": "in the AgentCore verdict legs",
    "AC-47 judges only the default runtime version": "in the AgentCore verdict legs",
    "AC-47 ignores the version an endpoint rolls toward": "in the AgentCore verdict legs",
    "AC-47 passes the caller leg when the endpoints are unlisted": "in the AgentCore verdict legs",
    "AC-47 passes a served version it could not read": "in the AgentCore verdict legs",
    "AC-18 does not read CloudTrail Lake event data stores": "in the AgentCore verdict legs",
    "AC-18 credits an event data store that is not ingesting": "in the AgentCore verdict legs",
    "AC-18 fails a gap when an event data store was not read": "in the AgentCore verdict legs",
    "AC-18 ignores an event data store's memory ARN scope": "in the AgentCore verdict legs",
    "AC-50 matches Inspector coverage on repository name alone": "in the AgentCore verdict legs",
    "AC-34 claims the agent code is unreadable through any API": "in the AgentCore verdict legs",
    "AC-26 accepts several exempt principals on the tamper SCP": "in the AgentCore verdict legs",
    "AC-26 accepts a wildcard name as the tamper SCP exemption": "in the AgentCore verdict legs",
    "AC-06 does not read the recording key policy": "in the AgentCore verdict legs",
    "AC-06 passes a recording key whose policy it could not read": "in the AgentCore verdict legs",
    "AC-06 credits a recording key that lets anyone decrypt": "in the AgentCore verdict legs",
    "AC-51 claims no API identifies other AI front doors": "in the AgentCore verdict legs",
    "AC-22 credits a link from a suspended member account": "in the AgentCore verdict legs",
    "AC-22 passes stale links when ListAccounts fails": "in the AgentCore verdict legs",
    "AC-22 drops the link review on the policy continue": "in the AgentCore verdict legs",
    "AC-45 skips memory, harness and payment manager roles": "in the AgentCore verdict legs",
    "AC-45 judges a foreign service role by a local namesake": "in the AgentCore verdict legs",
    "AC-45 hides a failed memory or payment manager read": "in the AgentCore verdict legs",
    "AC-45 reads CallWithBearerToken on * as every resource": "in the AgentCore verdict legs",
    "AC-18 lists event data stores in this region only": "in the AgentCore verdict legs",
    "AC-18 counts a single-region store homed elsewhere": "in the AgentCore verdict legs",
    "AC-18 drops an unlisted region's stores silently": "in the AgentCore verdict legs",
    "AC-18 reads a store listed in two regions twice": "in the AgentCore verdict legs",
    "AC-47 reads fronting gateways in its own region only": "in the AgentCore verdict legs",
    "AC-47 drops a denied region's gateways silently": "in the AgentCore verdict legs",
    "AC-47 reads a region not opted into as unread": "in the AgentCore verdict legs",
    "AC-47 claims this region after reading every region": "in the AgentCore verdict legs",
    "AC-47 leaves the agentcore client on another region": "in the AgentCore verdict legs",
    "AC-26 credits a filter pattern": "in the AgentCore verdict legs",
    "AC-26 credits field selection criteria": "in the AgentCore verdict legs",
    "AC-26 credits a filter on transformed logs": "in the AgentCore verdict legs",
    "AC-26 follows another account's stream": "in the AgentCore verdict legs",
    "AC-26 credits an inactive stream": "in the AgentCore verdict legs",
    "AC-26 credits a Lambda record processor": "in the AgentCore verdict legs",
    "AC-26 credits a non-S3 stream destination": "in the AgentCore verdict legs",
    "AC-26 credits Object Lock off": "in the AgentCore verdict legs",
    "AC-26 credits GOVERNANCE retention": "in the AgentCore verdict legs",
    "AC-26 reads an unread bucket as off": "in the AgentCore verdict legs",
    "AC-26 passes a group whose filters are unreadable": "in the AgentCore verdict legs",
    "AC-26 skips the spans group": "in the AgentCore verdict legs",
    "AC-26 drops the no-filter verdict": "in the AgentCore verdict legs",
    "AC-26 describes a stream once per group": "in the AgentCore verdict legs",
    "AC-26 judges a trail bucket of another region": "in the AgentCore verdict legs",
    "AC-26 reads an unread trail bucket as clean": "in the AgentCore verdict legs",
    "AC-26 drops the trail bucket verdict": "in the AgentCore verdict legs",
    "AC-06 credits an unbound service reader": "in the AgentCore verdict legs",
    "AC-06 skips services under RestrictPublicBuckets": "in the AgentCore verdict legs",
    "AC-06 judges public grants under RestrictPublicBuckets": "in the AgentCore verdict legs",
    "AC-06 credits ACLs left on": "in the AgentCore verdict legs",
    "AC-06 reads an unread ownership setting as enforced": "in the AgentCore verdict legs",
    "AC-06 skips the recording key-use leg": "in the AgentCore verdict legs",
    "AC-06 credits a key policy Deny": "in the AgentCore verdict legs",
    "AC-06 reads any key grant as root delegation": "in the AgentCore verdict legs",
    "AC-06 admits any kms:CallerAccount": "in the AgentCore verdict legs",
    "AC-06 admits any kms:ViaService": "in the AgentCore verdict legs",
    "AC-06 admits an unread key-policy condition key": "in the AgentCore verdict legs",
    "AC-06 ignores the boundary for the recording key": "in the AgentCore verdict legs",
    "AC-06 SCP leg keeps set-operator prefixes": "in the AgentCore verdict legs",
    "AC-06 SCP leg keeps IfExists suffixes": "in the AgentCore verdict legs",
    "AC-06 SCP leg ignores negated operators": "in the AgentCore verdict legs",
    "AC-06 SCP leg ignores a condition that excludes the write": "in the AgentCore verdict legs",
    "AC-06 SCP leg reads an unknown condition key as holding": "in the AgentCore verdict legs",
    "AC-06 SCP leg ignores attachment": "in the AgentCore verdict legs",
    "AC-06 SCP leg skips the per-level Allow": "in the AgentCore verdict legs",
    "AC-06 SCP leg credits a conditioned Allow": "in the AgentCore verdict legs",
    "AC-06 SCP leg drops unread policies": "in the AgentCore verdict legs",
    "AC-06 SCP leg skips the recording key": "in the AgentCore verdict legs",
    "AC-06 SCP leg binds the management account": "in the AgentCore verdict legs",
    "AC-06 SCP leg passes an unread bucket encryption": "in the AgentCore verdict legs",
    "AC-35 input guard ignores the order inside an operand": "in the AgentCore verdict legs",
    "AC-35 input guard drops the && carry": "in the AgentCore verdict legs",
    "AC-35 input guard carries a negated has across &&": "in the AgentCore verdict legs",
    "AC-35 input guard drops the negated || carry": "in the AgentCore verdict legs",
    "AC-35 input guard carries a positive has across ||": "in the AgentCore verdict legs",
    "AC-35 input guard drops the when-block carry": "in the AgentCore verdict legs",
    "AC-35 input guard skips unless blocks": "in the AgentCore verdict legs",
    "AC-35 input guard reads string literals": "in the AgentCore verdict legs",
    "AC-35 input guard judges permits": "in the AgentCore verdict legs",
    "AC-35 input guard ignores the required list": "in the AgentCore verdict legs",
    "AC-35 input guard reads a bare action as no tool": "in the AgentCore verdict legs",
    "AC-35 input guard reads an action group as every action": "in the AgentCore verdict legs",
    "AC-35 input guard drops an unreadable target": "in the AgentCore verdict legs",
    "AC-35 input guard reads an S3 tool schema as empty": "in the AgentCore verdict legs",
    "AG-39 omits the unread front doors": "in the AgentCore verdict legs",
    "AC-45 names a customer policy as the AWS default": "in the AgentCore verdict legs",
    "AC-45 hides the AWS managed policy": "in the AgentCore verdict legs",
    "AC-51 shield: origin host compared case-sensitively": "in the AgentCore verdict legs",
    "AC-51 shield: any distribution read as a front door": "in the AgentCore verdict legs",
    "AC-51 shield: an inactive subscription is judged": "in the AgentCore verdict legs",
    "AC-51 shield: any protection credits every distribution": "in the AgentCore verdict legs",
    "AC-51 shield: unread gateways dropped": "in the AgentCore verdict legs",
    "AC-51 shield: only the first distribution page read": "in the AgentCore verdict legs",
    "AC-51 shield: only the first protection page read": "in the AgentCore verdict legs",
    "AC-48 credits an IfExists deputy guard": "in the AgentCore verdict legs",
    "AC-48 credits a ForAllValues deputy guard": "in the AgentCore verdict legs",
    "AC-48 credits a partial wildcard account segment": "in the AgentCore verdict legs",
    "AC-50 image: a cross-account image is judged": "in the AgentCore verdict legs",
    "AC-50 image: another account's scan credited": "in the AgentCore verdict legs",
    "AC-50 image: another repository's scan credited": "in the AgentCore verdict legs",
    "AC-50 image: an inactive repository's images judged": "in the AgentCore verdict legs",
    "AC-50 image: an untagged URI resolved without latest": "in the AgentCore verdict legs",
    "AC-50 image: any scanned image credits the runtime": "in the AgentCore verdict legs",
    "AC-50 image: a lapsed image scan passes": "in the AgentCore verdict legs",
    "AC-40 safety: one named evaluator stands in for both": "in the AgentCore verdict legs",
    "AC-29 authorizer: an absent authorizer type is not judged": "in the AgentCore verdict legs",
    "AC-36 engine key: DescribeKey is not source-guarded": "in the AgentCore verdict legs",
    "AC-27 deputy: a private path excuses any gateway": "in the AgentCore verdict legs",
    "AC-08 OAuth discovery: a named principal admits the discovery call": "in the AgentCore verdict legs",
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
