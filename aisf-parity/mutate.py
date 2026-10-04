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
        "find": "        if delegates and _identity_allows_assume_role(permissions, "
        "role_arn):\n",
        "replace": "        if False:\n",
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
        "name": "BR-26 credits a credential type as the PII redaction layer",
        "file": BEDROCK,
        "defect": "an agent guardrail that masks only AWS keys and passwords is credited as the PII/PHI defense-in-depth layer",
        "find": '\n        and entity.get("type") not in CREDENTIAL_PII_ENTITY_TYPES\n',
        "replace": "\n",
    },
    {
        "name": "BR-26 drops the regex from the PII redaction layer",
        "file": BEDROCK,
        "defect": "an agent guardrail with PII entities and no custom regex is credited as the defense-in-depth layer",
        "find": '\n    ) and any(masks(regex) for regex in policy.get("regexes") or [])\n',
        "replace": "\n    )\n",
    },
    {
        "name": "BR-26 reads the input side for the PII redaction layer",
        "file": BEDROCK,
        "defect": "a PII type masked on the input only is credited as masking the generated response",
        "find": '\n            and _sensitive_information_action(element, "output")\n',
        "replace": '\n            and _sensitive_information_action(element, "input")\n',
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
        "name": "BR-26 probe blames no owner policy for a cross-account denial",
        "file": BEDROCK,
        "defect": "BR-26 reports an ApplyGuardrail denial on another account's guardrail as a missing grant in this account, though the owner's resource policy is what refused it",
        "find": "\n            if _guardrail_apply_denied_cross_account(error, identifier, accounts):\n",
        "replace": "\n            if False:\n",
    },
    {
        "name": "BR-26 probe calls every ARN denial cross-account",
        "file": BEDROCK,
        "defect": "BR-26 blames the owner's resource policy for an ApplyGuardrail denial on this account's own guardrail",
        "find": '\n    return isinstance(accounts["self"], str) and parts[4] != accounts["self"]\n',
        "replace": "\n    return True\n",
    },
    {
        "name": "BR-26 probe ignores the different-account denial message",
        "file": BEDROCK,
        "defect": "BR-26 misses Bedrock's 'from a different account' denial on a guardrail named by id, so the owner's resource policy goes unnamed",
        "find": '\n    ):\n        return True\n    parts = identifier.split(":")\n',
        "replace": '\n    ):\n        pass\n    parts = identifier.split(":")\n',
    },
    {
        "name": "BR-26 probe blames the owner when this account is unknown",
        "file": BEDROCK,
        "defect": "BR-26 names the owner's resource policy for an ARN denial although sts:GetCallerIdentity failed, so whose guardrail it is was not established",
        "find": '\n    return isinstance(accounts["self"], str) and parts[4]',
        "replace": "\n    return parts[4]",
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
        "name": "BR-04 retains a log object whose replication FAILED",
        "file": BEDROCK,
        "defect": "BR-04 ignores ReplicationStatus FAILED, so a replicated log "
        "bucket whose objects S3 Lifecycle never expires passes",
        "find": '                if status == "FAILED":\n',
        "replace": "                if False:\n",
    },
    {
        "name": "BR-46 passes an object written between the last run and the latest read",
        "file": BEDROCK,
        "defect": "BR-46 lists the source but ignores each LastModified, so an "
        "object ingested after the Macie job last ran passes unclassified",
        "find": "            elif after_run > 0 and before_read >= 0:\n",
        "replace": "            elif False:\n",
    },
    {
        "name": "BR-46 credits a document with no metadata sidecar",
        "file": BEDROCK,
        "defect": "BR-46 stops pairing documents with their .metadata.json "
        "sidecars, so a knowledge base whose classification never reaches "
        "per-document metadata passes",
        "find": "    missing = [key for key in documents if key + METADATA_SIDECAR_SUFFIX not in keys]\n",
        "replace": "    missing = []\n",
    },
    {
        "name": "BR-20 source: an identity Deny is ignored",
        "file": BEDROCK,
        "defect": "BR-20 skips an unconditioned identity-policy Deny of s3:GetObject on the source bucket, so a principal its own policy keeps from the documents passes",
        "find": '                return "denied", f"{label} denies s3:GetObject on every object"\n',
        "replace": "                pass\n",
    },
    {
        "name": "BR-20 source: a missing identity grant reads as a read",
        "file": BEDROCK,
        "defect": "BR-20 credits a principal no identity policy lets read the source bucket, beside a bucket policy that allows no one",
        "find": "    if granted == 0:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "BR-20 source: a boundary Allow counts as a grant",
        "file": BEDROCK,
        "defect": "BR-20 reads a permissions boundary Allow as a grant, though a boundary only limits one",
        "find": '                if source == "permissions boundary":\n                    bounded = max(\n',
        "replace": "                if False:\n                    bounded = max(\n",
    },
    {
        "name": "BR-20 source: a boundary scoped elsewhere is not read",
        "file": BEDROCK,
        "defect": "BR-20 credits a principal whose permissions boundary allows s3:GetObject only on other buckets",
        "find": "    if boundary is not None and bounded == 0:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "BR-20 source: a boundary on part of the bucket is credited",
        "file": BEDROCK,
        "defect": "BR-20 credits a principal whose permissions boundary allows s3:GetObject on one prefix of the source bucket only",
        "find": "    if boundary is not None and bounded == 1:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "BR-20 source: any wildcard grant reaches the bucket",
        "file": BEDROCK,
        "defect": "BR-20 credits a wildcard s3:GetObject Allow on another bucket as a grant on the source",
        "find": "            if _wildcard_matches(resource[:end], target):\n",
        "replace": "            if True:\n",
    },
    {
        "name": "BR-20 source: a pattern ending past the bucket covers it",
        "file": BEDROCK,
        "defect": "BR-20 reads a Resource that matches the bucket prefix but does not end in a wildcard as covering every object",
        "find": '        return resource.endswith("*") and _wildcard_matches(resource, target)\n',
        "replace": "        return _wildcard_matches(resource, target)\n",
    },
    {
        "name": "BR-20 source: a grant on part of the bucket is credited",
        "file": BEDROCK,
        "defect": "BR-20 credits an identity Allow of s3:GetObject on one prefix of the source bucket as a read of every document",
        "find": "    if granted == 1:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "BR-20 source: a NotResource Allow excluding a prefix covers the bucket",
        "file": BEDROCK,
        "defect": "BR-20 credits a NotResource Allow that excludes a prefix of the source bucket as a read of every document",
        "find": "        return 1 if any(map(reaches, excluded)) else 2\n",
        "replace": "        return 2\n",
    },
    {
        "name": "BR-20 source: the identity verdict is not read",
        "file": BEDROCK,
        "defect": "BR-20 computes the identity-policy verdict and never fails on it",
        "find": "            if denials:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "BR-20 source: an unjudged identity reads as passed",
        "file": BEDROCK,
        "defect": "BR-20 passes a principal whose identity policies were not read or not computed",
        "find": "            elif holds:\n",
        "replace": "            elif False:\n",
    },
    {
        "name": "BR-20 SCP: an attached Deny of the source is ignored",
        "file": BEDROCK,
        "defect": "BR-20 passes a principal an attached SCP Deny keeps from every source object",
        "find": '                return "denied", f"{label} denies {noun}"\n',
        "replace": "                pass\n",
    },
    {
        "name": "BR-20 SCP: a level with no Allow is not read",
        "file": BEDROCK,
        "defect": "BR-20 passes a principal although a level of the organization path allows no source read",
        "find": '        if level == 0:\n            return "denied", (',
        "replace": '        if False:\n            return "denied", (',
    },
    {
        "name": "BR-20 SCP: a conditioned level Allow is credited",
        "file": BEDROCK,
        "defect": "BR-20 credits an SCP Allow of s3:GetObject that applies under a Condition only",
        "find": '                if coverage and statement.get("Condition"):\n',
        "replace": "                if False:\n",
    },
    {
        "name": "BR-20 SCP: a partial level Allow is credited",
        "file": BEDROCK,
        "defect": "BR-20 credits an SCP level that allows s3:GetObject on part of the source only",
        "find": "        if level == 1:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "BR-20 SCP: an unread inventory reads as applied",
        "file": BEDROCK,
        "defect": "BR-20 passes a principal when the SCP inventory could not be read",
        "find": '    if list_error:\n        return "held"',
        "replace": '    if False:\n        return "held"',
    },
    {
        "name": "BR-20 SCP: unread policy targets are ignored",
        "file": BEDROCK,
        "defect": "BR-20 passes a principal when some SCP targets could not be read",
        "find": '    if inventory.get("errors"):\n',
        "replace": "    if False:\n",
    },
    {
        "name": "BR-20 SCP: a conditioned Deny is read as total",
        "file": BEDROCK,
        "defect": "BR-20 fails a principal on an SCP Deny whose Condition it does not compute",
        "find": '            elif statement.get("Condition"):\n                held.append(f"{label} denies {noun} under a Condition")',
        "replace": '            elif False:\n                held.append(f"{label} denies {noun} under a Condition")',
    },
    {
        "name": "BR-20 SCP: the management account is restricted",
        "file": BEDROCK,
        "defect": "BR-20 applies SCPs to the management account, which they never restrict",
        "find": '    if inventory.get("management_account"):\n        return "reads", (',
        "replace": '    if False:\n        return "reads", (',
    },
    {
        "name": "BR-20 SCP: no organization reads as unread",
        "file": BEDROCK,
        "defect": "BR-20 holds an account outside any organization at N/A, though no SCP can apply",
        "find": '    if "AWSOrganizationsNotInUseException" in list_error:\n',
        "replace": "    if False:\n",
    },
    {
        "name": "BR-20 SCP: kms:Decrypt is not judged",
        "file": BEDROCK,
        "defect": "BR-20 skips an SCP Deny of kms:Decrypt on the source key",
        "find": '                    if key["kind"] == "cmk":\n                        verdicts.append(\n                            _scp_read_verdict(',
        "replace": "                    if False:\n                        verdicts.append(\n                            _scp_read_verdict(",
    },
    {
        "name": "BR-20 SCP: the leg never runs",
        "file": BEDROCK,
        "defect": "BR-20 never reads SCPs for a vector principal",
        "find": '                if ":role/aws-service-role/" not in principal:\n',
        "replace": "                if False:\n",
    },
    {
        "name": "BR-20 key: a key policy Deny is ignored",
        "file": BEDROCK,
        "defect": "BR-20 passes a principal a key policy Deny keeps from kms:Decrypt",
        "find": '            return "denied", f"{label} denies kms:Decrypt on key {key_arn}"\n',
        "replace": "            continue\n",
    },
    {
        "name": "BR-20 key: a conditioned grant is credited",
        "file": BEDROCK,
        "defect": "BR-20 credits a key policy grant under a Condition it does not compute",
        "find": "        if not met:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "BR-20 key: kms:ViaService names any Region",
        "file": BEDROCK,
        "defect": "BR-20 credits a kms:ViaService condition naming S3 in another Region",
        "find": "            if any(_wildcard_matches(str(v).lower(), via) for v in values):\n",
        "replace": "            if True:\n",
    },
    {
        "name": "BR-20 key: StringEquals on kms:ViaService takes a wildcard",
        "file": BEDROCK,
        "defect": "BR-20 credits a StringEquals kms:ViaService wildcard that never matches a request",
        "find": "            if via in [str(v).lower() for v in values]:\n",
        "replace": "            if any(_wildcard_matches(str(v).lower(), via) for v in values):\n",
    },
    {
        "name": "BR-20 key: kms:CallerAccount names any account",
        "file": BEDROCK,
        "defect": "BR-20 credits a kms:CallerAccount condition naming another account",
        "find": "            if account in [str(v) for v in values]:\n",
        "replace": "            if True:\n",
    },
    {
        "name": "BR-20 key: root delegation needs no identity grant",
        "file": BEDROCK,
        "defect": "BR-20 credits a key policy that delegates to the account root without an identity Allow",
        "find": '    granted = direct or (delegated and identity["granted"])\n',
        "replace": "    granted = direct or delegated\n",
    },
    {
        "name": "BR-20 key: an identity Allow on another key counts",
        "file": BEDROCK,
        "defect": "BR-20 credits an identity kms:Decrypt Allow on a different key",
        "find": "            reached = _statement_coverage(statement, covers, covers) == 2\n",
        "replace": "            reached = True\n",
    },
    {
        "name": "BR-20 key: an identity Deny of decrypt is ignored",
        "file": BEDROCK,
        "defect": "BR-20 passes a principal whose own policy denies kms:Decrypt on the key",
        "find": '    if identity["denied"]:\n',
        "replace": "    if False:\n",
    },
    {
        "name": "BR-20 key: a role boundary does not limit a direct grant",
        "file": BEDROCK,
        "defect": "BR-20 credits a key policy naming a role whose boundary allows no kms:Decrypt",
        "find": '    if identity["bounded"] is False and (kind == "role" or not direct):\n',
        "replace": '    if identity["bounded"] is False and not direct:\n',
    },
    {
        "name": "BR-20 key: a grant to another principal counts",
        "file": BEDROCK,
        "defect": "BR-20 credits a KMS grant whose grantee is another principal",
        "find": '            if grant.get("GranteePrincipal") != principal or "Decrypt" not in (\n',
        "replace": '            if "Decrypt" not in (\n',
    },
    {
        "name": "BR-20 key: grant constraints are ignored",
        "file": BEDROCK,
        "defect": "BR-20 credits a KMS grant whose constraints it does not compute",
        "find": '            if grant.get("Constraints"):\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-20 key: unread grants read as none",
        "file": BEDROCK,
        "defect": "BR-20 fails a principal when the key's grants were not read",
        "find": "        if grants is None:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "BR-20 key: the key leg never runs",
        "file": BEDROCK,
        "defect": "BR-20 never compares a vector principal with the source bucket's key",
        "find": '                if key["kind"] == "cmk":\n                    verdicts.append(\n                        _source_key_read(',
        "replace": "                if False:\n                    verdicts.append(\n                        _source_key_read(",
    },
    {
        "name": "BR-20 key: an unread key reads as passed",
        "file": BEDROCK,
        "defect": "BR-20 passes a principal when the source key or its policy was not read",
        "find": '                elif key["kind"] == "held":\n',
        "replace": "                elif False:\n",
    },
    {
        "name": "BR-20 key: each key is read for every bucket",
        "file": BEDROCK,
        "defect": "BR-20 reads a source key's policy and grants again for every bucket on it",
        "find": '    if encryption["key"] in cache:\n',
        "replace": "    if False:\n",
    },
    {
        "name": "BR-46 sidecar budget resets for each source",
        "file": BEDROCK,
        "defect": "BR-46 gives every source the whole sidecar read budget, so "
        "a run over many sources reads past the measured 300 GetObject calls",
        "find": '    room = max(0, METADATA_SIDECAR_READ_CAP - budget["sidecars"])\n',
        "replace": "    room = METADATA_SIDECAR_READ_CAP\n",
    },
    {
        "name": "BR-46 listing budget is not spent",
        "file": BEDROCK,
        "defect": "BR-46 never counts its ListObjectsV2 pages against the region "
        "run's budget, so many sources list past the measured 150 pages",
        "find": '                budget["pages"] += 1\n',
        "replace": "                pass\n",
    },
    {
        "name": "BR-46 capped listing does not name where it stopped",
        "file": BEDROCK,
        "defect": "BR-46 reports a capped source listing without the last key "
        "it read, so the objects past the cap are not located",
        "find": '                    stopped = f"after key {items[-1][0]}" if items else "before any key"\n',
        "replace": '                    stopped = "before any key"\n',
    },
    {
        "name": "BR-43 credits a Region allow-list in the management account",
        "file": BEDROCK,
        "defect": "BR-43 passes a Region allow-list in the management account, which no service control policy restricts",
        "find": "        if allow_listed and not uncovered and not global_open and management:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "BR-42 credits a model list in the management account",
        "file": BEDROCK,
        "defect": "BR-42 passes an approved model list in the management account, which no service control policy restricts",
        "find": '        if enforcing and not uncovered and inventory.get("management_account"):\n',
        "replace": "        if False:\n",
    },
    {
        "name": "BR-43 credits an AI service Region deny in the management account",
        "file": BEDROCK,
        "defect": "BR-43 passes the AI service Region deny in the management account, which no service control policy restricts",
        "find": '        if not uncovered and scp_inventory.get("management_account"):\n',
        "replace": "        if False:\n",
    },
    {
        "name": "BR-43 credits a Region deny that names only the listed invoke actions",
        "file": BEDROCK,
        "defect": "BR-43 drops its service probes, so a Region deny naming the nine listed actions passes while bedrock:CreateAgent runs in any Region",
        "find": '    _region_probe("bedrock"),\n    _region_probe("bedrock-agentcore"),\n    _region_probe("bedrock-mantle"),\n',
        "replace": "",
    },
    {
        "name": "BR-43 credits an AI service Region deny that omits the vector stores",
        "file": BEDROCK,
        "defect": "BR-43 drops the vector store probes, so es:CreateDomain and rds:CreateDBCluster run in any Region while the row passes",
        "find": '    _region_probe("es"),\n    _region_probe("rds"),\n    _region_probe("neptune-graph"),\n    _region_probe("kendra"),\n',
        "replace": "",
    },
    {
        "name": "BR-47 names only five enforcing buckets in its Passed text",
        "file": BEDROCK,
        "defect": "BR-47's Passed text lists the first five enforcing buckets, so the exempted principals of a sixth bucket go unnamed",
        "find": '                            len(inventory["buckets"]),\n                            denied,\n                            "; ".join(enforced),\n                        )\n                    ),\n                    resolution=(\n                        "No action required.',
        "replace": '                            len(inventory["buckets"]),\n                            denied,\n                            "; ".join(enforced[:5]),\n                        )\n                    ),\n                    resolution=(\n                        "No action required.',
    },
    {
        "name": "BR-47 drops the SageMaker transform and processing job buckets",
        "file": BEDROCK,
        "defect": "BR-47 never reads transform or processing jobs, so their plaintext buckets are missing from the data path and the row passes",
        "find": "        _sagemaker_batch_job_locations,\n",
        "replace": "",
    },
    {
        "name": "BR-47 drops the SageMaker endpoint capture and async buckets",
        "file": BEDROCK,
        "defect": "BR-47 never reads endpoints, so a data capture or asynchronous output bucket that accepts plaintext is missing from the data path",
        "find": "        _sagemaker_endpoint_locations,\n",
        "replace": "",
    },
    {
        "name": "BR-47 drops the Bedrock evaluation job buckets",
        "file": BEDROCK,
        "defect": "BR-47 never reads evaluation jobs, so a dataset or output bucket that accepts plaintext is missing from the data path",
        "find": "        _evaluation_job_locations,\n",
        "replace": "",
    },
    {
        "name": "BR-55 credits an all-zero PCR pin",
        "file": BEDROCK,
        "defect": "BR-55 reads a pin on the all-zero measurement a debug-mode "
        "enclave presents as an exact image measurement, so a debug enclave can "
        "decrypt",
        "find": '        "*" in str(value) or "?" in str(value) or not str(value).strip("0")\n',
        "replace": '        "*" in str(value) or "?" in str(value)\n',
    },
    {
        "name": "BR-48 ignores a service section with no leaf",
        "file": BEDROCK,
        "defect": "BR-48 reads a service section that delegates operators but sets "
        "no opt_out_policy as delegating nothing, so a child can opt the service in",
        "find": '            if list(control) != ["@@none"] and "opt_out_policy" not in node:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-26 credits a secrets regex that acts on the output only",
        "file": BEDROCK,
        "defect": "BR-26 passes a guardrail whose secrets regex acts on the output "
        "only, so a credential the built-in types do not name reaches the model",
        "find": '    for side in ("output", "input"):\n        if not side_regexes[side]:\n',
        "replace": '    for side in ("output",):\n        if not side_regexes[side]:\n',
    },
    {
        "name": "BR-42 credits an IfExists or ForAllValues bound on an open training grant",
        "file": BEDROCK,
        "defect": "BR-42 reads an IfExists or ForAllValues: account test as limiting an every-principal training bucket grant, though either is true when the key is absent",
        "find": '    if operator.startswith("forallvalues:") or operator.endswith("ifexists"):\n',
        "replace": "    if False:\n",
    },
    {
        "name": "BR-42 ignores a training grant to another account",
        "file": BEDROCK,
        "defect": "BR-42 skips a training bucket grant to another account's principals, so that account's own IAM decides who reads the training data",
        "find": "            foreign = [other for other in named if other != account]\n",
        "replace": "            foreign = []\n",
    },
    {
        "name": "BR-42 credits a bound naming another account",
        "file": BEDROCK,
        "defect": "BR-42 credits an every-principal training bucket grant whose aws:PrincipalAccount test also names another account",
        "find": '        inside = [text for text, accounts in bounds if accounts <= {account, "org"}]\n',
        "replace": "        inside = [text for text, accounts in bounds]\n",
    },
    {
        "name": "BR-42 credits any condition on an open training grant",
        "file": BEDROCK,
        "defect": "BR-42 passes an every-principal training bucket grant under any condition, such as aws:SourceVpce, that names no account of the caller",
        "find": '        else:\n            grants["failed"].append(\n                f"{label} allows s3:GetObject to every principal under a "\n',
        "replace": '        elif False:\n            grants["failed"].append(\n                f"{label} allows s3:GetObject to every principal under a "\n',
    },
    {
        "name": "BR-50 walks one role hop only",
        "file": BEDROCK,
        "defect": "BR-50 stops after one role, so a user who assumes a non-AI role that can assume an AI role keeps an access key nobody lists",
        "find": "        frontier = sorted(reached)\n",
        "replace": "        frontier = []\n",
    },
    {
        "name": "BR-51 skips the role principals of an AI role's trust",
        "file": BEDROCK,
        "defect": "BR-51 skips a role principal in an AI write role's trust, so a chain from a role a user assumes without MFA passes",
        "find": "        for owner, name in _trust_role_principals_without_mfa(trust_policy)\n",
        "replace": "        for owner, name in []\n",
    },
    {
        "name": "BR-51 follows one role hop only",
        "file": BEDROCK,
        "defect": "BR-51 follows one trusted role only, so a longer chain to a role assumed without MFA passes",
        "find": "            for next_owner, next_name in onward\n",
        "replace": "            for next_owner, next_name in []\n",
    },
    {
        "name": "BR-20 skips the Data Catalog tables of a SQL knowledge base",
        "file": BEDROCK,
        "defect": "BR-20 ignores the Glue Data Catalog tables a SQL knowledge base "
        "reads, so a table whose S3 bucket has no customer managed key passes",
        "find": "    buckets, unread = _data_catalog_table_buckets(table_names, region)\n",
        "replace": "    buckets, unread = {}, []\n",
    },
    {
        "name": "BR-20 reads no Data Catalog partition locations",
        "file": BEDROCK,
        "defect": "BR-20 judges a partitioned table by its table location only, so "
        "a partition in a plaintext bucket passes",
        "find": "                    locations.extend(\n",
        "replace": "                    list(\n",
    },
    {
        "name": "BR-20 reads Data Catalog partitions past its page cap",
        "file": BEDROCK,
        "defect": "BR-20 stops at the partition page cap and judges the pages it "
        "read, so a partition past the cap goes unjudged in a Passed result",
        "find": "                    if count > DATA_CATALOG_PARTITION_PAGES:\n",
        "replace": "                    if False:\n",
    },
    {
        "name": "BR-07 reads no CreatePrompt holder",
        "file": BEDROCK,
        "defect": "BR-07 never lists the holders of bedrock:CreatePrompt, which has "
        "no resource type, so who can add prompts to the catalog goes unreported",
        "find": "            if creates:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "BR-07 lets a prompt creator render prompts",
        "file": BEDROCK,
        "defect": "BR-07 passes a runtime role that holds bedrock:RenderPrompt and "
        "bedrock:CreatePrompt, so a runtime caller can add a prompt to the catalog",
        "find": "                    creating_renderers.append(f\"{kind} '{name}'\")\n",
        "replace": "                    pass\n",
    },
    {
        "name": "BR-57 reads no runtime JWT authorizer",
        "file": BEDROCK,
        "defect": "BR-57 passes an AgentCore runtime whose JWT authorizer names no audience, client, scope or claim, so any token its issuer signs invokes it",
        "find": "        if jwt is not None and not any(jwt.get(field) for field in RUNTIME_JWT_BOUNDS):\n",
        "replace": "        if False:\n",
    },
    {
        "name": "BR-57 credits any account bound on an open runtime policy",
        "file": BEDROCK,
        "defect": "BR-57 passes a runtime resource policy open to every principal under a condition naming another account",
        "find": '                    accounts is not None and accounts <= {account, "org"}\n',
        "replace": "                    accounts is not None\n",
    },
    {
        "name": "BR-57 ignores a runtime policy grant to another account",
        "file": BEDROCK,
        "defect": "BR-57 passes a runtime resource policy that lets another account's principals invoke it",
        "find": '            if foreign:\n                failures.append(\n                    f"{label} lets principals of account(s)',
        "replace": '            if False:\n                failures.append(\n                    f"{label} lets principals of account(s)',
    },
    {
        "name": "BR-57 passes beside an unread runtime policy",
        "file": BEDROCK,
        "defect": "BR-57 reports Passed while a runtime or endpoint resource policy was not read",
        "find": '        unread += inventory.get("gate_errors") or []\n',
        "replace": "        pass\n",
    },
    {
        "name": "BR-57 reads no runtime endpoint policy",
        "file": BEDROCK,
        "defect": "BR-57 reads the runtime's resource policy only, so an endpoint policy open to every principal goes unread",
        "find": '        targets = [runtime.get("agentRuntimeArn")] + [\n',
        "replace": '        targets = [runtime.get("agentRuntimeArn")] + 0 * [\n',
    },
    {
        "name": "BR-02 credits a gateway endpoint for its whole VPC",
        "file": BEDROCK,
        "defect": "BR-02 credits an S3 or DynamoDB gateway endpoint to every workload in its VPC, so a subnet whose route table it does not name passes",
        "find": "            if table not in gateway_routes[(vpc_id, surface)]:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "BR-02 credits a gateway endpoint to a workload with unread subnets",
        "file": BEDROCK,
        "defect": "BR-02 passes a gateway-only workload whose subnets were not read, though its route tables were never compared",
        "find": "                return None, None\n            return None, (\n",
        "replace": "                return None, None\n            return None, None and (\n",
    },
    {
        "name": "BR-02 leaves a SageMaker runtime workload out",
        "file": BEDROCK,
        "defect": "BR-02 judges only workloads granted a Bedrock or AgentCore surface, so a workload that invokes SageMaker endpoints is never judged",
        "find": "            surfaces = _granted_bedrock_surfaces(roles[role], AI_WORKLOAD_SURFACES)\n",
        "replace": "            surfaces = _granted_bedrock_surfaces(roles[role], WORKLOAD_ENDPOINT_SURFACES)\n",
    },
    {
        "name": "BR-02 passes beside unread route tables",
        "file": BEDROCK,
        "defect": "BR-02 reports a gateway-only workload Passed while the route tables of its VPC were not read",
        "find": "        elif held:\n            unread.extend(held)\n",
        "replace": "        elif False:\n            unread.extend(held)\n",
    },
    {
        "name": "BR-02 drops the subnets of a Lambda workload",
        "file": BEDROCK,
        "defect": "BR-02 never records a Lambda function's subnets, so its gateway endpoint coverage can never be compared",
        "find": '                    "subnets": (function.get("VpcConfig") or {}).get("SubnetIds")\n',
        "replace": '                    "subnets": (function.get("VpcConfig") or {}).get("SubnetIdz")\n',
    },
    {
        "name": "BR-20 compares no Neptune Analytics graph reader",
        "file": BEDROCK,
        "defect": "BR-20 never compares who reads a Neptune Analytics graph with who reads its source bucket",
        "find": '\n                            storage_type == "NEPTUNE_ANALYTICS"\n                            and "graph/" in graph_arn\n',
        "replace": '\n                            storage_type == "NONE"\n                            and "graph/" in graph_arn\n',
    },
    {
        "name": "BR-20 compares no Kendra index reader",
        "file": BEDROCK,
        "defect": "BR-20 never compares who queries a Kendra index with who reads its source bucket",
        "find": '\n    verdict["readers"] = readers\n',
        "replace": "\n",
    },
    {
        "name": "BR-20 drops the Kendra index sources",
        "file": BEDROCK,
        "defect": "BR-20 reads a Kendra index's S3 data sources and then discards them",
        "find": '\n    verdict["kendra_sources"] = corpus["sources"]\n',
        "replace": '\n    verdict["kendra_sources"] = []\n',
    },
    {
        "name": "BR-20 never merges the Kendra sources",
        "file": BEDROCK,
        "defect": "BR-20 leaves the Kendra index sources out of the bucket population",
        "find": '\n    for source in list(inventory["s3_sources"]) + list(kendra_sources or []):\n',
        "replace": '\n    for source in list(inventory["s3_sources"]):\n',
    },
    {
        "name": "BR-20 drops the Kendra source read errors",
        "file": BEDROCK,
        "defect": "an unread Kendra data source leaves no row",
        "find": '\n    inventory["errors"] = list(inventory["errors"]) + list(kendra_errors or [])\n',
        "replace": "\n",
    },
    {
        "name": "BR-20 builds a store reader's ARN without its path",
        "file": BEDROCK,
        "defect": "BR-20 names a role by name alone, so a bucket policy that admits its full path ARN reads as a denial",
        "find": '\n            principal = listing["arns"].get((kind, name))\n',
        "replace": '\n            principal = f"arn:aws:iam::123456789012:{kind}/{name}"\n',
    },
    {
        "name": "BR-20 ignores an identity Deny of the store read",
        "file": BEDROCK,
        "defect": "a role whose identity policy denies the graph read is still counted as a reader",
        "find": '\n            else:\n                return "none", ""\n    if deny_held:\n',
        "replace": "\n            else:\n                pass\n    if deny_held:\n",
    },
    {
        "name": "BR-20 credits a conditioned store read",
        "file": BEDROCK,
        "defect": "an Allow under a Condition counts as an established store read",
        "find": '\n                if statement.get("Condition"):\n                    allow_held.append(f"{label} allows {action} under a Condition")\n',
        "replace": '\n                if False:\n                    allow_held.append(f"{label} allows {action} under a Condition")\n',
    },
    {
        "name": "BR-20 ignores the permissions boundary on the store read",
        "file": BEDROCK,
        "defect": "a role whose boundary does not allow the graph read is still counted as a reader",
        "find": '\n    boundary = _boundary_document(permissions)\n    if boundary is None:\n        return "reads", ""\n    bounded, boundary_held',
        "replace": '\n    boundary = None\n    if boundary is None:\n        return "reads", ""\n    bounded, boundary_held',
    },
    {
        "name": "BR-20 counts a grant on another store as a read",
        "file": BEDROCK,
        "defect": "an Allow on another graph or index counts as a read of this one",
        "find": "\n            if reaches:\n                found.append(statement)\n",
        "replace": "\n            if True:\n                found.append(statement)\n",
    },
    {
        "name": "BR-20 needs every store read action to survive",
        "file": BEDROCK,
        "defect": "a Deny or boundary of one Kendra read action drops a role that still reads the index with the other",
        "find": '\n            if any(verdict == "reads" for verdict, _ in verdicts):\n',
        "replace": '\n            if all(verdict == "reads" for verdict, _ in verdicts):\n',
    },
    {
        "name": "BR-20 ignores an SCP Deny of the store read",
        "file": BEDROCK,
        "defect": "a role an attached SCP keeps from every store read action is still counted as a reader",
        "find": '\n                    if scp_verdict == "denied":\n',
        "replace": "\n                    if False:\n",
    },
    {
        "name": "BR-20 ignores an SCP that cannot judge the store read",
        "file": BEDROCK,
        "defect": "an unread SCP inventory or a conditioned SCP Deny leaves a store reader counted as established",
        "find": '\n                    elif scp_verdict == "held":\n',
        "replace": "\n                    elif False:\n",
    },
    {
        "name": "BR-20 applies SCPs to a service-linked store reader",
        "file": BEDROCK,
        "defect": "an SCP Deny drops a service-linked role from the store readers, though SCPs do not restrict it",
        "find": '\n                if verdict != "none" and ":role/aws-service-role/" not in principal:\n',
        "replace": '\n                if verdict != "none":\n',
    },
    {
        "name": "BR-20 judges every store action by the first action's SCP",
        "file": BEDROCK,
        "defect": "an SCP Deny of kendra:Query also drops a role that reads the index with kendra:Retrieve",
        "find": "\n                    scp_verdict, scp_why = scps[action]\n",
        "replace": '\n                    scp_verdict, scp_why = scps[spec["actions"][0]]\n',
    },
    {
        "name": "BR-20 ignores principals the cache failed to read",
        "file": BEDROCK,
        "defect": "a store comparison passes while a principal that may read the store went unread",
        "find": '\n    if unread:\n        held.append(\n            "{} IAM principal(s) had a policy read fail in the IAM permissions "\n',
        "replace": '\n    if False:\n        held.append(\n            "{} IAM principal(s) had a policy read fail in the IAM permissions "\n',
    },
    {
        "name": "BR-20 ignores an unread IAM principal listing",
        "file": BEDROCK,
        "defect": "a store comparison runs on a partial role and user listing",
        "find": '\n    if listing["error"]:\n        return {"principals": [], "held": held + [listing["error"]]}\n',
        "replace": '\n    if False:\n        return {"principals": [], "held": held + [listing["error"]]}\n',
    },
    {
        "name": "BR-20 ignores a USER_TOKEN Kendra index",
        "file": BEDROCK,
        "defect": "a Kendra index that filters results by user token is judged as if every reader saw every document",
        "find": '\n        if str(response.get("UserContextPolicy") or "") == "USER_TOKEN":\n',
        "replace": '\n        if str(response.get("UserContextPolicy") or "") == "NONE":\n',
    },
    {
        "name": "BR-20 counts readers beside a store-level hold",
        "file": BEDROCK,
        "defect": "a store whose readers are held still contributes established readers",
        "find": '\n    held = list(spec.get("held") or [])\n    if held:\n        return {"principals": [], "held": held}\n',
        "replace": '\n    held = list(spec.get("held") or [])\n',
    },
    {
        "name": "BR-20 passes beside held store readers",
        "file": BEDROCK,
        "defect": "held store readers do not withhold Passed",
        "find": '\n        elif restrictions["held"] or unread or identity_held or readers_held:\n',
        "replace": '\n        elif restrictions["held"] or unread or identity_held:\n',
    },
    {
        "name": "BR-20 drops a TEMPLATE Kendra source silently",
        "file": BEDROCK,
        "defect": "a Kendra TEMPLATE connector, which may sit on an S3 bucket, leaves no row",
        "find": '\n        if kind == "TEMPLATE":\n',
        "replace": "\n        if False:\n",
    },
    {
        "name": "BR-20 IAM principal listing ignores the invocation deadline",
        "file": BEDROCK,
        "defect": "BR-20 keeps listing IAM roles and users past the deadline",
        "find": '\n                if _deadline_reached():\n                    return {\n                        "arns": arns,\n',
        "replace": '\n                if False:\n                    return {\n                        "arns": arns,\n',
    },
    {
        "name": "BR-20 Kendra data source reads ignore the invocation deadline",
        "file": BEDROCK,
        "defect": "BR-20 keeps calling kendra:DescribeDataSource past the deadline",
        "find": "\n    for position, summary in enumerate(summaries):\n        if _deadline_reached():\n",
        "replace": "\n    for position, summary in enumerate(summaries):\n        if False:\n",
    },
    {
        "name": "BR-10 caps the versions an unversioned pin reads",
        "file": BEDROCK,
        "defect": "BR-10 reads at most 20 versions of a pin with no version, though the 20-version quota plus the working draft makes 21",
        "find": "\n            for version in versions:\n                for surface in sorted(surfaces):\n",
        "replace": "\n            for version in versions[:20]:\n                for surface in sorted(surfaces):\n",
    },
    {
        "name": "BR-10 caps the versions a guardrail condition value reads",
        "file": BEDROCK,
        "defect": "BR-10 judges at most 20 versions of a versionless guardrail condition value, so the 21st is never read",
        "find": '\n        for version in versions:\n            if _deadline_reached():\n                result["unread"] = (\n',
        "replace": '\n        for version in versions[:20]:\n            if _deadline_reached():\n                result["unread"] = (\n',
    },
    {
        "name": "guardrail attachment reads ignore the invocation deadline",
        "file": BEDROCK,
        "defect": "the deployed-guardrail inventory keeps calling GetGuardrail past the deadline",
        "find": '\n        if _deadline_reached():\n            entry["error"] = DEADLINE_STOP\n            continue\n        if target_region not in clients:\n',
        "replace": "\n        if target_region not in clients:\n",
    },
    {
        "name": "a cross-account guardrail denial is not recognised",
        "file": BEDROCK,
        "defect": "a GetGuardrail denied by another account's guardrail resource policy reads as a bare AccessDeniedException",
        "find": '\nGUARDRAIL_CROSS_ACCOUNT_DENIAL = "from a different account"\n',
        "replace": '\nGUARDRAIL_CROSS_ACCOUNT_DENIAL = "from another account"\n',
    },
    {
        "name": "BR-10 names GetGuardrail for a denied cross-account version listing",
        "file": BEDROCK,
        "defect": "BR-10 labels a ListGuardrails refusal on another account's guardrail as the owner's resource policy not allowing bedrock:GetGuardrail, a remedy that cannot work",
        "find": '\n                    result["unread"] = GUARDRAIL_CROSS_ACCOUNT_LIST_CEILING\n',
        "replace": '\n                    result["unread"] = _guardrail_read_error(error)\n',
    },
    {
        "name": "BR-10 calls any version listing denial the cross-account ceiling",
        "file": BEDROCK,
        "defect": "BR-10 reports an in-account ListGuardrails denial, a missing grant, as the AWS limit on listing another account's versions",
        "find": '\n                ) == "AccessDeniedException" and GUARDRAIL_CROSS_ACCOUNT_DENIAL in str(\n',
        "replace": '\n                ) == "AccessDeniedException" or GUARDRAIL_CROSS_ACCOUNT_DENIAL in str(\n',
    },
    {
        "name": "BR-10 unread row omits the cross-account listing ceiling",
        "file": BEDROCK,
        "defect": "BR-10's N/A row does not say a versionless pin to another account's guardrail stays N/A at the listing limit",
        "find": "\n                            if ceilings\n",
        "replace": "\n                            if False\n",
    },
    {
        "name": "every guardrail denial blames the owner's resource policy",
        "file": BEDROCK,
        "defect": "an AccessDeniedException from this role's own policies is reported as the owner's guardrail resource policy",
        "find": '\n        and label == "AccessDeniedException"\n        and GUARDRAIL_CROSS_ACCOUNT_DENIAL\n        in str(error.response.get("Error", {}).get("Message", ""))\n',
        "replace": '\n        and label == "AccessDeniedException"\n',
    },
    {
        "name": "the attachment inventory drops the cross-account denial text",
        "file": BEDROCK,
        "defect": "a deployed guardrail version in another account is reported unread with no word of its owner's resource policy",
        "find": '\n            entry["error"] = _guardrail_read_error(error)\n    return inventory\n',
        "replace": '\n            entry["error"] = get_assessment_error_label(error)\n    return inventory\n',
    },
    {
        "name": "BR-10 condition values drop the cross-account denial text",
        "file": BEDROCK,
        "defect": "a guardrail condition value in another account is reported unread with no word of its owner's resource policy",
        "find": '\n            result["unread"] = _guardrail_read_error(error)\n',
        "replace": '\n            result["unread"] = get_assessment_error_label(error)\n',
    },
    {
        "name": "BR-41 reasoning reads drop the cross-account denial text",
        "file": BEDROCK,
        "defect": "the Automated Reasoning read of an administrator-account guardrail is reported unread with no word of its resource policy",
        "find": "\n                    _guardrail_read_error(error),\n                ),\n",
        "replace": "\n                    get_assessment_error_label(error),\n                ),\n",
    },
    {
        "name": "knowledge base screening drops the cross-account denial text",
        "file": BEDROCK,
        "defect": "an agent's guardrail in another account is reported unread with no word of its owner's resource policy",
        "find": '\n                "error": _guardrail_read_error(error),\n',
        "replace": '\n                "error": get_assessment_error_label(error),\n',
    },
    {
        "name": "BR-27 grounding reads drop the cross-account denial text",
        "file": BEDROCK,
        "defect": "a grounding guardrail version in another account is reported unread with no word of its owner's resource policy",
        "find": '\n                        f"({_guardrail_read_error(error)})"\n',
        "replace": '\n                        f"({get_assessment_error_label(error)})"\n',
    },
    {
        "name": "BR-46 prompt reads drop the cross-account denial text",
        "file": BEDROCK,
        "defect": "a joined guardrail in another account is reported unread with no word of its owner's resource policy",
        "find": '\n                entry["error"] = _guardrail_read_error(error)\n\n',
        "replace": '\n                entry["error"] = get_assessment_error_label(error)\n\n',
    },
    {
        "name": "BR-02 credits every route table to a Lambda without subnets",
        "file": BEDROCK,
        "defect": "BR-02 credits a gateway endpoint on every route table to any workload without subnets, though a Lambda's or instance's subnets are read and their absence is a missing read",
        "find": '\n                workload["kind"] in EKS_WORKLOAD_KINDS\n',
        "replace": "\n                True\n",
    },
    {
        "name": "BR-02 drops running SageMaker training and processing jobs",
        "file": BEDROCK,
        "defect": "BR-02's workload inventory reads no SageMaker training or processing job, so one in a VPC with no S3 gateway endpoint is never failed",
        "find": "\n    _sagemaker_job_workloads(region, inventory)\n",
        "replace": "\n",
    },
    {
        "name": "BR-02 reads every SageMaker job, not only running ones",
        "file": BEDROCK,
        "defect": "BR-02 lists SageMaker jobs with no status filter, so finished jobs that no longer run in any subnet are judged",
        "find": '\n                StatusEquals="InProgress",\n',
        "replace": "\n",
    },
    {
        "name": "BR-02 reads a processing job's VpcConfig at the top level",
        "file": BEDROCK,
        "defect": "BR-02 looks for a processing job's VpcConfig outside NetworkConfig, so every processing job reads as having no VPC",
        "find": '\n        ("NetworkConfig", "VpcConfig"),\n',
        "replace": '\n        ("VpcConfig",),\n',
    },
    {
        "name": "BR-02 job descriptions ignore the invocation deadline",
        "file": BEDROCK,
        "defect": "BR-02 keeps describing running SageMaker jobs past the deadline",
        "find": '\n            if _deadline_reached():\n                inventory["errors"].append(\n                    "{} running {}(s) from',
        "replace": '\n            if False:\n                inventory["errors"].append(\n                    "{} running {}(s) from',
    },
    {
        "name": "BR-02 keeps a job whose subnet EC2 does not return",
        "file": BEDROCK,
        "defect": "BR-02 judges a SageMaker job on the subnets EC2 returned and drops the one it did not, so the job is not named as unread",
        "find": '\n            if missing:\n                inventory["errors"].append(\n                    "subnet(s) {} of {} were not returned by ec2:DescribeSubnets".format(\n                        ", ".join(missing), label\n                    )\n                )\n                continue\n            role_arn = str(detail.get("RoleArn") or "")\n',
        "replace": '\n            vpcs = {subnet: vpc for subnet, vpc in vpcs.items() if vpc}\n            role_arn = str(detail.get("RoleArn") or "")\n',
    },
    {
        "name": "BR-02 credits an EKS workload a gateway on one route table",
        "file": BEDROCK,
        "defect": "BR-02 credits an EKS workload a gateway endpoint that names any route table of the cluster VPC, though its pods may run on a subnet off the others",
        "find": "\n                and every <= gateway_routes[(vpc_id, surface)]\n",
        "replace": "\n                and every & gateway_routes[(vpc_id, surface)]\n",
    },
    {
        "name": "BR-02 credits an EKS workload beside an unread route table listing",
        "file": BEDROCK,
        "defect": "BR-02 credits an EKS workload from the route tables a failed DescribeRouteTables listing returned before its error",
        "find": '\n                and "error" not in tables\n                and every\n',
        "replace": "\n                and every\n",
    },
    {
        "name": "BR-02 collects no route table of a gateway VPC",
        "file": BEDROCK,
        "defect": "BR-02 never records the route tables of a gateway VPC, so an EKS workload is never credited a gateway on every one",
        "find": '\n                    if table.get("RouteTableId"):\n                        tables["all"].add(table["RouteTableId"])\n',
        "replace": "\n",
    },
    {
        "name": "BR-32 passes an acting alarm with no log forwarding",
        "file": BEDROCK,
        "defect": "BR-32 passes an acting intervention alarm while no subscription filter forwards the invocation log group",
        "find": '        elif forwarding_state == "none":\n',
        "replace": "        elif False:\n",
    },
    {
        "name": "BR-32 reads a log group beside S3 as unforwarded",
        "file": BEDROCK,
        "defect": "BR-32 fails a log group with no subscription filter whose logs also go to S3, though forwarding from the S3 copy is not read",
        "find": '        if forwarding_state == "none" and log_bucket:\n',
        "replace": "        if False:\n",
    },
    {
        "name": "BR-32 credits a trail that records another Region",
        "file": BEDROCK,
        "defect": "BR-32 credits a single-Region trail homed in another Region with recording this Region's guardrail calls",
        "find": '            records_region = trail_config.get("IsMultiRegionTrail") or (\n',
        "replace": "            records_region = True or (\n",
    },
    {
        "name": "BR-32 credits a trail that is not logging",
        "file": BEDROCK,
        "defect": "BR-32 credits a stopped trail with recording guardrail calls",
        "find": '            if not client.get_trail_status(Name=trail_arn).get("IsLogging", False):\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-32 credits a narrowed guardrail selector",
        "file": BEDROCK,
        "defect": "BR-32 credits a trail whose AWS::Bedrock::Guardrail selector is narrowed by eventName or readOnly, which records a subset of the calls",
        "find": "        if GUARDRAIL_DATA_EVENT_TYPE in credited:\n",
        "replace": "        if GUARDRAIL_DATA_EVENT_TYPE in credited or GUARDRAIL_DATA_EVENT_TYPE in narrowed:\n",
    },
    {
        "name": "BR-32 ignores event data stores for guardrail calls",
        "file": BEDROCK,
        "defect": "BR-32 fails a Region whose enabled event data store records every AWS::Bedrock::Guardrail data event",
        "find": '    state["recorders"].extend(stores["credited"].get(GUARDRAIL_DATA_EVENT_TYPE, []))\n',
        "replace": '    state["recorders"].extend(stores["credited"].get("AWS::Bedrock::Guardrailz", []))\n',
    },
    {
        "name": "BR-32 passes beside an unread record leg",
        "file": BEDROCK,
        "defect": "BR-32 passes an acting alarm while the subscription filters, the trails or the event data stores were not read",
        "find": "        if record_unread:\n            return row(\n",
        "replace": "        if False:\n            return row(\n",
    },
    {
        "name": "BR-32 drops an unread trail list",
        "file": BEDROCK,
        "defect": "BR-32 fails, and does not hold, a Region whose trail list could not be read",
        "find": '        state["unread"].append(\n            f"CloudTrail trails (cloudtrail:ListTrails: "\n',
        "replace": '        [].append(\n            f"CloudTrail trails (cloudtrail:ListTrails: "\n',
    },
    {
        "name": "BR-46 clears a source by a job alone",
        "file": BEDROCK,
        "defect": "BR-46 passes a source a qualifying Macie job covers while automated sensitive data discovery is off or does not monitor its bucket",
        "find": '                if precondition["ready"] and automated == "MONITORED":\n',
        "replace": "                if True:\n",
    },
    {
        "name": "BR-46 fails an unread discovery state",
        "file": BEDROCK,
        "defect": "BR-46 fails a source whose automated discovery configuration or bucket monitoring status was not read, though neither was established",
        "find": '                elif precondition["permissions"] or (\n',
        "replace": "                elif False and (\n",
    },
    {
        "name": "BR-04 reads agent memory at DRAFT only",
        "file": BEDROCK,
        "defect": "BR-04 judges a Bedrock agent's memory retention at DRAFT and never at the versions its aliases route to",
        "find": '                configurations.append(\n                    (f"version {version}", detail.get("memoryConfiguration"))\n',
        "replace": '                [].append(\n                    (f"version {version}", detail.get("memoryConfiguration"))\n',
    },
    {
        "name": "BR-04 passes an agent memory of 0 days",
        "file": BEDROCK,
        "defect": "BR-04 passes an agent memory whose storageDays is 0, a period the API reference does not define",
        "find": "            elif days == 0:\n",
        "replace": "            elif False:\n",
    },
    {
        "name": "BR-04 judges inference data at the AWSLogs root",
        "file": BEDROCK,
        "defect": "BR-04 requires a SageMaker capture bucket's lifecycle rule to cover AWSLogs/ and not the capture URI's own path",
        "find": "    if root is not None:\n        log_root = root\n",
        "replace": "    if False:\n        log_root = root\n",
    },
    {
        "name": "BR-04 probes replicated inference data it cannot read",
        "file": BEDROCK,
        "defect": "BR-04 runs the invocation log ReplicationStatus probe on a replicated SageMaker capture bucket, whose objects it has no s3:GetObject grant on",
        "find": "    elif replicas and root is None:\n",
        "replace": "    elif replicas:\n",
    },
    {
        "name": "BR-04 passes inference data beside an unread endpoint",
        "file": BEDROCK,
        "defect": "BR-04 reports SageMaker inference data retention Passed while an endpoint was not read",
        "find": '                "N/A" if undetermined else "Passed",\n',
        "replace": '                "Passed",\n',
    },
    {
        "name": "BR-26 credits a Glue PIIDetection node that only audits",
        "file": BEDROCK,
        "defect": "BR-26 treats an Audit PiiType as masking, so a Glue job that only reports PII is credited as redacting a knowledge base source",
        "find": '    "ColumnHashing",\n)\n',
        "replace": '    "ColumnHashing",\n    "ColumnAudit",\n    "RowAudit",\n)\n',
    },
    {
        "name": "BR-26 credits a Glue target one path reaches unmasked",
        "file": BEDROCK,
        "defect": "BR-26 skips an unmasked path into a Glue target, so a job whose raw input also flows straight to the target is credited",
        "find": "        if upstream is None:\n            return None\n",
        "replace": "        if upstream is None:\n            continue\n",
    },
    {
        "name": "BR-26 matches a Glue path as a name prefix",
        "file": BEDROCK,
        "defect": "BR-26 stops treating a Glue path as a folder, so s3://b/cle is credited as covering s3://b/clean/",
        "find": '            prefix = prefix.rstrip("/") + "/" if prefix.strip("/") else ""\n',
        "replace": "",
    },
    {
        "name": "BR-26 judges the oldest SUCCEEDED Glue run",
        "file": BEDROCK,
        "defect": "BR-26 dates a Glue job by its oldest successful run, so a run that rewrote the source after the latest ingestion is missed",
        "find": "            end = max(succeeded) if succeeded else None\n",
        "replace": "            end = min(succeeded) if succeeded else None\n",
    },
    {
        "name": "BR-26 dates a Glue job by a run that did not succeed",
        "file": BEDROCK,
        "defect": "BR-26 counts every Glue run state, so a FAILED run dates the job's redaction",
        "find": 'if run.get("JobRunState") == "SUCCEEDED" and run.get("CompletedOn")',
        "replace": 'if run.get("CompletedOn")',
    },
    {
        "name": "BR-26 fails a source over an unread Glue read",
        "file": BEDROCK,
        "defect": "BR-26 drops the Glue read errors, so an unread GetJobs or GetJobRuns fails a source a Glue job may redact",
        "find": "        ) + glue_errors\n",
        "replace": "        )\n",
    },
    {
        "name": "BR-26 ignores Glue redaction jobs",
        "file": BEDROCK,
        "defect": "BR-26 drops the Glue outputs, so a source a Glue job masks still fails",
        "find": "        redaction_outputs = redaction_outputs + glue_outputs\n",
        "replace": "",
    },
    {
        "name": "BR-53 trusts GetResources for Bedrock job tags",
        "file": BEDROCK,
        "defect": "BR-53 sends Bedrock job ARNs to GetResources, which may not return jobs, so a job's own tags are never read",
        "find": '            arn for arn in arns if inventory["arns"][arn] in BEDROCK_LIST_TAGS_LABELS\n',
        "replace": "            arn for arn in ()\n",
    },
    {
        "name": "BR-53 reads Bedrock job tags with the tagging API's key case",
        "file": BEDROCK,
        "defect": "BR-53 reads Key and Value from bedrock:ListTagsForResource, whose tags use key and value, so every owned job fails",
        "find": '{"Key": tag.get("key"), "Value": tag.get("value")}',
        "replace": '{"Key": tag.get("Key"), "Value": tag.get("Value")}',
    },
    {
        "name": "BR-53 fails a job whose tags were not read",
        "file": BEDROCK,
        "defect": "BR-53 treats an unread job tag read as no tags, so AccessDenied fails the job",
        "find": "                unread.append(arn)\n",
        "replace": "                tags_by_arn[arn] = []\n",
    },
    {
        "name": "BR-53 lists workload identities past the page cap",
        "file": BEDROCK,
        "defect": "BR-53 asks ListWorkloadIdentities for 100 per page, above its maximum of 20, so the read fails",
        "find": '{"max_results": 20}',
        "replace": "{}",
    },
    {
        "name": "BR-53 drops never-tagged pipelines",
        "file": BEDROCK,
        "defect": "BR-53 reads the wrong result key for ListPipelines, so a pipeline never tagged passes unseen",
        "find": '"PipelineSummaries",',
        "replace": '"Pipelines",',
    },
    {
        "name": "BR-20 credits an Aurora store with password logins only",
        "file": BEDROCK,
        "defect": "BR-20 drops the IAM database authentication leg, so an Aurora cluster with IAMDatabaseAuthenticationEnabled false passes",
        "find": "            (_aurora_iam_authentication(cluster), AURORA_IAM_AUTH_RESOLUTION),\n",
        "replace": "",
    },
    {
        "name": "BR-20 reads an absent IAM authentication value as off",
        "file": BEDROCK,
        "defect": "BR-20 fails an Aurora cluster whose IAMDatabaseAuthenticationEnabled was not returned",
        "find": "    if enabled is False:\n",
        "replace": "    if enabled is not True:\n",
    },
    {
        "name": "BR-20 names only one Aurora fix",
        "file": BEDROCK,
        "defect": "BR-20 joins only the first failed Aurora leg's fix, so a public, password-only cluster is told one of two changes",
        "find": '" ".join(fix for leg, fix in legs if leg["status"] == "Failed")',
        "replace": 'next((fix for leg, fix in legs if leg["status"] == "Failed"), "")',
    },
    {
        "name": "BR-12 credits a GOVERNANCE-mode invocation log bucket",
        "file": BEDROCK,
        "defect": "BR-12 accepts any Object Lock retention mode, so a GOVERNANCE bucket a privileged principal can override passes",
        "find": '    if mode != "COMPLIANCE":\n',
        "replace": '    if mode not in ("COMPLIANCE", "GOVERNANCE"):\n',
    },
    {
        "name": "BR-12 credits a filter pattern on the invocation log group",
        "file": BEDROCK,
        "defect": "BR-12 ignores the subscription filter pattern, so a filter forwarding only ERROR events counts as the archive",
        "find": '\n    pattern = str(subscription.get("filterPattern") or "").strip()\n',
        "replace": '\n    pattern = ""\n',
    },
    {
        "name": "BR-12 follows another account's Firehose stream",
        "file": BEDROCK,
        "defect": "BR-12 reads a Firehose stream in another account as this account's, so it judges a stream it cannot see",
        "find": "\n    if parts[4] != account:\n",
        "replace": "\n    if False:\n",
    },
    {
        "name": "BR-12 credits a Firehose stream with a Lambda processor",
        "file": BEDROCK,
        "defect": "BR-12 ignores a Lambda record processor, which can drop or rewrite records before the bucket holds them",
        "find": '\n        if processing.get("Enabled") is True and any(\n',
        "replace": "\n        if False and any(\n",
    },
    {
        "name": "BR-12 credits an inactive Firehose stream",
        "file": BEDROCK,
        "defect": "BR-12 accepts a stream that is not ACTIVE",
        "find": '\n    if status != "ACTIVE":\n',
        "replace": '\n    if status == "DELETING":\n',
    },
    {
        "name": "BR-12 drops the invocation log archive rows",
        "file": BEDROCK,
        "defect": "BR-12 stops reporting the WORM archive leg",
        "find": "            log_group_name, [name for name, _ in buckets], s3_client, region\n",
        "replace": "            None, [], s3_client, region\n",
    },
    {
        "name": "BR-12 credits a bucket with Object Lock off",
        "file": BEDROCK,
        "defect": "BR-12 reads the default retention without ObjectLockEnabled",
        "find": '    if value.get("ObjectLockEnabled") != "Enabled":\n',
        "replace": "    if not value:\n",
    },
    {
        "name": "BR-12 credits a filter on transformed logs",
        "file": BEDROCK,
        "defect": "BR-12 credits a subscription filter applied on transformed logs as forwarding the ingested events",
        "find": '\n    if subscription.get("applyOnTransformedLogs") is True:\n',
        "replace": "\n    if False:\n",
    },
    {
        "name": "BR-34 credits a detector with AI Protection off",
        "file": BEDROCK,
        "defect": "BR-34 reads only the detector Status, so a detector without the AI_PROTECTION feature passes",
        "find": '        if detector.get("Status") != "ENABLED" or ai_protection != "ENABLED":\n',
        "replace": '        if detector.get("Status") != "ENABLED":\n',
    },
    {
        "name": "BR-34 credits a disabled GuardDuty detector",
        "file": BEDROCK,
        "defect": "BR-34 reads only the AI_PROTECTION feature, so a suspended detector passes",
        "find": '        if detector.get("Status") != "ENABLED" or ai_protection != "ENABLED":\n',
        "replace": '        if ai_protection != "ENABLED":\n',
    },
    {
        "name": "BR-34 passes a Region with no GuardDuty detector",
        "file": BEDROCK,
        "defect": "BR-34 reports nothing for a Region with no detector",
        "find": "    if not detector_ids:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "BR-34 reads only the first GuardDuty findings page",
        "file": BEDROCK,
        "defect": "BR-34 stops at the first ListFindings page",
        "find": '                token_response_keys=("NextToken",),\n                max_results=GUARDDUTY_FINDINGS_BATCH,\n                DetectorId=detector_id,\n',
        "replace": "                token_response_keys=(),\n                max_results=GUARDDUTY_FINDINGS_BATCH,\n                DetectorId=detector_id,\n",
    },
    {
        "name": "BR-34 reads only the first GetFindings batch",
        "file": BEDROCK,
        "defect": "BR-34 reads 50 finding details and drops the rest",
        "find": "            for start in range(0, len(finding_ids), GUARDDUTY_FINDINGS_BATCH):\n",
        "replace": "            for start in range(0, min(len(finding_ids), 1), GUARDDUTY_FINDINGS_BATCH):\n",
    },
    {
        "name": "BR-34 counts archived GuardDuty findings",
        "file": BEDROCK,
        "defect": "BR-34 drops the service.archived criterion, so archived findings read as current",
        "find": '                        "service.archived": {"Eq": ["false"]},\n',
        "replace": "",
    },
    {
        "name": "BR-34 names a non-injection finding as a flagged event",
        "file": BEDROCK,
        "defect": "BR-34 names any Bedrock finding as a prompt injection example",
        "find": '                if finding.get("Type") == GUARDDUTY_PROMPT_INJECTION_TYPE\n',
        "replace": '                if finding.get("Type")\n',
    },
    {
        "name": "BR-34 names the oldest injection finding first",
        "file": BEDROCK,
        "defect": "BR-34 sorts the flagged events oldest first, so the newest can fall outside the three named",
        "find": '            key=lambda finding: str(finding.get("UpdatedAt") or ""),\n            reverse=True,\n',
        "replace": '            key=lambda finding: str(finding.get("UpdatedAt") or ""),\n            reverse=False,\n',
    },
    {
        "name": "BR-34 passes an unread GuardDuty detector",
        "file": BEDROCK,
        "defect": "BR-34 turns a failed GetDetector into Passed",
        "find": '                "whether its AI Protection feature is on is not known.",\n                COULD_NOT_ASSESS_RESOLUTION,\n                "Informational",\n                "N/A",\n',
        "replace": '                "whether its AI Protection feature is on is not known.",\n                COULD_NOT_ASSESS_RESOLUTION,\n                "Informational",\n                "Passed",\n',
    },
    {
        "name": "BR-34 passes an unread GuardDuty findings list",
        "file": BEDROCK,
        "defect": "BR-34 turns a failed ListFindings or GetFindings into Passed",
        "find": '                "is named.",\n                COULD_NOT_ASSESS_RESOLUTION,\n                "Informational",\n                "N/A",\n',
        "replace": '                "is named.",\n                COULD_NOT_ASSESS_RESOLUTION,\n                "Informational",\n                "Passed",\n',
    },
    {
        "name": "BR-34 drops the GuardDuty row from the handler",
        "file": BEDROCK,
        "defect": "BR-34 never runs the GuardDuty leg",
        "find": "        all_findings.append(check_guardduty_prompt_injection_detection(region=region))\n",
        "replace": "",
    },
    {
        "name": "BR-57 credits an S3 wildcard bucket name as scoped",
        "file": BEDROCK,
        "defect": "BR-57 reads no wildcard in the resource name as unscoped, so arn:aws:s3:::* passes",
        "find": '    return not parent or "*" in parent or "?" in parent\n',
        "replace": "    return not parent\n",
    },
    {
        "name": "BR-57 credits a wildcard resource type such as tab*/orders",
        "file": BEDROCK,
        "defect": "BR-57 credits a wildcard in an ARN that no published sub-resource format matches, such as tab*/orders or role/service-role/*",
        "find": "    if prefix is None:\n        return True\n",
        "replace": "    if prefix is None:\n        return False\n",
    },
    {
        "name": "BR-57 reads a bucket-named S3 key wildcard as unscoped",
        "file": BEDROCK,
        "defect": "BR-57 treats arn:aws:s3:::bucket/* as every bucket, so a scoped data grant fails",
        "find": "    prefixes = ARN_SUB_RESOURCES.get(service, {})\n",
        "replace": "    prefixes = {}\n",
    },
    {
        "name": "BR-57 credits a NotResource grant as scoped",
        "file": BEDROCK,
        "defect": "BR-57 judges only Resource, so an Allow with NotResource passes",
        "find": '                    if "NotResource" not in statement and not any(\n                        _arn_covers_every_resource(resource) for resource in resources\n                    ):\n',
        "replace": "                    if not any(\n                        _arn_covers_every_resource(resource) for resource in resources\n                    ):\n",
    },
    {
        "name": "BR-57 ignores the permissions boundary on a wide grant",
        "file": BEDROCK,
        "defect": "BR-57 fails a role whose boundary already scopes the grant",
        "find": '                            if allowance in ("none", "unscoped"):\n                                actions.append(action)\n',
        "replace": "                            if True:\n                                actions.append(action)\n",
    },
    {
        "name": "BR-57 judges the boundary with the model-only scope test",
        "file": BEDROCK,
        "defect": "BR-57 reads bucket/* in a boundary as unscoped, so a scoping boundary is not credited",
        "find": "                            allowance = _boundary_allowance(\n                                permissions, action, _arn_covers_every_resource\n                            )\n",
        "replace": "                            allowance = _boundary_allowance(\n                                permissions, action\n                            )\n",
    },
    {
        "name": "BR-57 passes a conditioned wide grant",
        "file": BEDROCK,
        "defect": "BR-57 drops a wide grant under a Condition instead of naming it",
        "find": '                    if statement.get("Condition"):\n                        held.append(label)\n',
        "replace": '                    if statement.get("Condition"):\n                        pass\n',
    },
    {
        "name": "BR-57 passes a role missing from the IAM cache",
        "file": BEDROCK,
        "defect": "BR-57 skips a role the cache does not hold without saying so",
        "find": '                unread.append(f"role {role_arn} is not in the IAM permissions cache")\n',
        "replace": "",
    },
    {
        "name": "BR-57 passes a role with a policy read error",
        "file": BEDROCK,
        "defect": "BR-57 ignores the principal_errors the cache records for a role",
        "find": "            if name in errored:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "BR-57 leaves action group function roles out of the scope test",
        "file": BEDROCK,
        "defect": "BR-57 judges only agent roles",
        "find": '        for role_arn, arns in functions["roles"].items():\n            population.setdefault(role_arn, []).extend(\n',
        "replace": "        for role_arn, arns in {}.items():\n            population.setdefault(role_arn, []).extend(\n",
    },
    {
        "name": "BR-57 drops the scope row from the handler",
        "file": BEDROCK,
        "defect": "BR-57 never runs the role scope leg",
        "find": "            else check_bedrock_agent_role_scope(\n                permission_cache,\n",
        "replace": "            else check_bedrock_agent_workload_identity(\n                permission_cache,\n",
    },
    {
        "name": "BR-57 counts another version of an action group function as outside",
        "file": BEDROCK,
        "defect": "BR-57 compares qualified ARNs, so version 3 of an action group function reads as a second function",
        "find": "                if _unqualified_function_arn(arn) in inside:\n",
        "replace": "                if arn in inside:\n",
    },
    {
        "name": "BR-57 reads only the $LATEST function versions",
        "file": BEDROCK,
        "defect": "BR-57 lists functions without FunctionVersion ALL",
        "find": '    try:\n        for page in lambda_client.get_paginator("list_functions").paginate(\n            FunctionVersion="ALL"\n        ):\n',
        "replace": '    try:\n        for page in lambda_client.get_paginator("list_functions").paginate():\n',
    },
    {
        "name": "BR-57 drops the outside-function sharing rows",
        "file": BEDROCK,
        "defect": "BR-57 never fails a role a function outside every action group runs as",
        "find": '        for role_arn, arns in sorted(outside["roles"].items()):\n',
        "replace": "        for role_arn, arns in sorted({}.items()):\n",
    },
    {
        "name": "BR-57 passes the function row when ListFunctions fails",
        "file": BEDROCK,
        "defect": "BR-57 ignores a failed ListFunctions read",
        "find": '        function_errors = functions["errors"] + outside["errors"]\n',
        "replace": '        function_errors = functions["errors"]\n',
    },
    {
        "name": "BR-06 skips stores homed in unassessed enabled Regions",
        "file": BEDROCK,
        "defect": "BR-06 reads stores only in the assessed Regions, so a multi-Region store homed elsewhere reads as a gap",
        "find": '        others.update(enabled["regions"])\n',
        "replace": "",
    },
    {
        "name": "BR-06 ignores an unlisted Region list",
        "file": BEDROCK,
        "defect": "BR-06 drops a failed account:ListRegions, so a store homed in an unread Region reads as a gap",
        "find": '        if enabled["error"]:\n            coverage["unread"].append(\n                "the Regions enabled for the account, where a multi-Region store "\n',
        "replace": '        if False:\n            coverage["unread"].append(\n                "the Regions enabled for the account, where a multi-Region store "\n',
    },
    {
        "name": "BR-06 traces a failed invoke call",
        "file": BEDROCK,
        "defect": "BR-06 keeps a call CloudTrail recorded with an errorCode, which has no invocation log record",
        "find": '            if not isinstance(detail, dict) or detail.get("errorCode"):\n',
        "replace": "            if not isinstance(detail, dict):\n",
    },
    {
        "name": "BR-06 joins the oldest calls",
        "file": BEDROCK,
        "defect": "BR-06 samples the oldest calls of the day, not the newest",
        "find": '    calls.sort(key=lambda call: call["time"], reverse=True)\n',
        "replace": '    calls.sort(key=lambda call: call["time"])\n',
    },
    {
        "name": "BR-06 reads calls newer than the settle time",
        "file": BEDROCK,
        "defect": "BR-06 looks up calls up to now, which may have no record yet",
        "find": "                EndTime=now - INFERENCE_TRACE_SETTLE,\n",
        "replace": "                EndTime=now,\n",
    },
    {
        "name": "BR-06 credits an unjoined call as traced",
        "file": BEDROCK,
        "defect": "BR-06 counts every sampled call as joined",
        "find": '        joined = [call for call in events["calls"] if call["request_id"] in records]\n',
        "replace": '        joined = list(events["calls"])\n',
    },
    {
        "name": "BR-06 claims logged bodies a record lacks",
        "file": BEDROCK,
        "defect": "BR-06 reports input and output bodies from any input key",
        "find": "                if any(str(name).startswith(key) for name in (record.get(part) or {}))\n",
        "replace": "                if record.get(part) is not None\n",
    },
    {
        "name": "BR-06 fails a trace whose read failed",
        "file": BEDROCK,
        "defect": "BR-06 turns a failed invocation log read into Failed",
        "find": '        elif scan["error"] or scan["capped"]:\n',
        "replace": "        elif False:\n",
    },
    {
        "name": "BR-06 reads text delivery off as unread",
        "file": BEDROCK,
        "defect": "BR-06 reports logging without text as N/A, though no trace can be built",
        "find": '            "Failed" if source["logging"] is False else "N/A",\n',
        "replace": '            "N/A",\n',
    },
    {
        "name": "BR-06 ignores a Lake store for centralization",
        "file": BEDROCK,
        "defect": "BR-06 never credits a CloudTrail Lake store recording Bedrock",
        "find": '    if stores["management"]:\n',
        "replace": "    if False:\n",
    },
    {
        "name": "BR-06 credits any AWSLogs table as CloudTrail",
        "file": BEDROCK,
        "defect": "BR-06 accepts a Glue table over any AWS log path",
        "find": '            if logs < 0 or "/CloudTrail" not in location[logs:]:\n',
        "replace": "            if logs < 0:\n",
    },
    {
        "name": "BR-06 misses a Security Lake CloudTrail table",
        "file": BEDROCK,
        "defect": "BR-06 drops a Security Lake CLOUD_TRAIL_MGMT table without "
        "naming why it is not credited",
        "find": '            if "/aws/CLOUD_TRAIL_MGMT/" in location:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-06 fails centralization over an unread Glue catalog",
        "file": BEDROCK,
        "defect": "BR-06 drops Glue read errors, so an unread catalog reads as no table",
        "find": '    unread = list(tables["errors"])\n',
        "replace": "    unread = []\n",
    },
    {
        "name": "BR-06 drops the trace rows from the handler",
        "file": BEDROCK,
        "defect": "BR-06 never runs the trace legs",
        "find": "        all_findings.append(check_bedrock_inference_trace(region=region))\n",
        "replace": "",
    },
    {
        "name": "BR-44 passes a Subscribe bound with no invocation block",
        "file": BEDROCK,
        "defect": "BR-44 passes a Subscribe Deny alone, which Bedrock's auto-subscription bypasses",
        "find": '            if invocation["blocked_by"]:\n',
        "replace": "            if True:\n",
    },
    {
        "name": "BR-44 credits an organization leg with a failed row",
        "file": BEDROCK,
        "defect": "BR-44 reads one Passed row of BR-42's organization leg as a block",
        "find": '    elif statuses == {"Passed"}:\n',
        "replace": '    elif "Passed" in statuses:\n',
    },
    {
        "name": "BR-44 fails over an unread BR-42 leg",
        "file": BEDROCK,
        "defect": "BR-44 reports Failed when a BR-42 leg was not read",
        "find": '            if invocation["unread"]:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-42 lists no identity that can invoke any model",
        "file": BEDROCK,
        "defect": "BR-42's invocation_open stays empty, so BR-44 reads every account as blocked",
        "find": '            if access["unrestricted"] or access["mantle"]:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-44 is not given the BR-42 identity leg",
        "file": BEDROCK,
        "defect": "the handler drops BR-42's identity leg from BR-44",
        "find": "                        allow_list_findings=allow_list_findings,\n",
        "replace": "",
    },
    {
        "name": "BR-33 drops a task with no task role",
        "file": BEDROCK,
        "defect": "BR-33 skips an ECS task with no task role, so an EC2 task whose "
        "container instance role holds Bedrock is never judged",
        "find": '                if not role_arn and task.get("containerInstanceArn"):\n',
        "replace": "                if False:\n",
    },
    {
        "name": "an unread list read lets the BR-53 sweep summary pass",
        "file": BEDROCK,
        "defect": "BR-53 passes the SageMaker and AgentCore summary while a list "
        "read failed, so resources it never listed read as owned",
        "find": "    complete = owned + direct_owned > 0 and not unowned and not unread\n",
        "replace": "    complete = owned + direct_owned > 0 and not unowned\n",
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
        "find": '            if state == "untagged":\n',
        "replace": "            if False:\n",
    },
    # Round 7: the tagSuffix match, the Converse turn, the S3-only destination
    # and the large-data skip. Each was killed by hand on a byte backup on
    # 2026-10-03 before it was added here.
    {
        "name": "BR-34 credits an input tag with another tagSuffix",
        "file": BEDROCK,
        "defect": "BR-34 credits any guardContent tag, so a prompt wrapped in a "
        "tag whose suffix is not the configured tagSuffix passes, although the "
        "prompt attack filter evaluates only the configured tag",
        "find": "        tagged = any(\n",
        "replace": "        tagged = GUARDRAIL_INPUT_TAG in text or any(\n",
    },
    {
        "name": "BR-34 judges the first Converse user turn",
        "file": BEDROCK,
        "defect": "BR-34 reads the first user message of a Converse request, so a "
        "call whose earlier turn was marked and whose latest turn was not passes",
        "find": "    for message in reversed(messages if isinstance(messages, list) else []):\n",
        "replace": "    for message in messages if isinstance(messages, list) else []:\n",
    },
    {
        "name": "BR-34 credits a Converse turn with no guardContent block",
        "file": BEDROCK,
        "defect": "BR-34 accepts any content block as a mark, so a guarded Converse "
        "call that sent plain text passes",
        "find": '                        isinstance(block, dict) and "guardContent" in block\n'
        "                        for block in turn\n",
        "replace": "                        isinstance(block, dict)\n"
        "                        for block in turn\n",
    },
    {
        "name": "BR-27 and BR-34 read nothing from an S3-only log destination",
        "file": BEDROCK,
        "defect": "the S3 reader returns an empty read, so an untagged call or a "
        "grounding score in an S3-only invocation log is never seen",
        "find": (
            "    return _scan_invocation_log_s3(\n"
            '        region, source["s3"], [(match, visit) for _, match, visit in legs]\n'
            "    )\n"
        ),
        "replace": (
            '    return [{"read": 0, "capped": False, "error": None, '
            '"action": "s3:GetObject"} for _ in legs]\n'
        ),
    },
    {
        "name": "BR-34 reads a large-data body as an invocation log record",
        "file": BEDROCK,
        "defect": "the S3 reader opens the data/ objects too, which hold request "
        "bodies and not records, and reads prompts it does not need",
        "find": '                    if "/data/" in key[len(request["Prefix"]) - 1 :]:\n',
        "replace": "                    if False:\n",
    },
    {
        "name": "BR-27 reads an absent text delivery flag as delivered",
        "file": BEDROCK,
        "defect": "BR-27 fails grounding capture only on an explicit false, so an "
        "account with no logging configuration escapes the Failed row",
        "find": "    if text_delivery is not True:\n",
        "replace": "    if text_delivery is False:\n",
    },
    # ------------------------------------------- Bedrock round-8 check logic
    # GRD-02, GRD-04, GRD-09, KB-03, KB-08, MDL-01, MDL-07, MDL-08, DET-04,
    # IAM-01 and IAM-05. Each was killed by hand on a byte backup on
    # 2026-10-04 before it was added here.
    {
        "name": "BR-32 spike: Average and Minimum alarms credited",
        "file": BEDROCK,
        "defect": "an alarm on Average, which a spike can leave flat, was credited as a spike alarm",
        "find": 'SPIKE_STATISTICS = ("Sum", "SampleCount", "Maximum")\n',
        "replace": 'SPIKE_STATISTICS = ("Sum", "SampleCount", "Maximum", "Average", "Minimum")\n',
    },
    {
        "name": "BR-32 spike: a lower-band alarm credited",
        "file": BEDROCK,
        "defect": "an anomaly band alarm that enters ALARM only below the band was credited",
        "find": 'SPIKE_BAND_OPERATORS = (\n    "GreaterThanUpperThreshold",\n',
        "replace": 'SPIKE_BAND_OPERATORS = (\n    "LessThanLowerThreshold",\n    "GreaterThanUpperThreshold",\n',
    },
    {
        "name": "BR-32 S3 forward: any notification event credited",
        "file": BEDROCK,
        "defect": "an S3 notification on s3:ObjectRemoved:* was credited as forwarding the log objects",
        "find": '            if "s3:ObjectCreated:*" not in events:\n',
        "replace": "            if not events:\n",
    },
    {
        "name": "BR-32 S3 forward: a narrower prefix rule credited",
        "file": BEDROCK,
        "defect": "a notification filtered to a prefix under the log root was credited for every object",
        "find": '            elif not root.startswith(rules.get("prefix", "")):\n',
        "replace": "            elif False:\n",
    },
    {
        "name": "BR-32 composite: an AND rule credits each alarm it names",
        "file": BEDROCK,
        "defect": "an intervention alarm ANDed with another raises the composite "
        "only with it, so crediting it passes an alarm that never notifies alone",
        "find": "                    can_false or right_false,\n",
        "replace": "                    can_false and right_false,\n",
    },
    {
        "name": "BR-32 composite: an ARN reference is not mapped to its name",
        "file": BEDROCK,
        "defect": "a composite rule may name an alarm by ARN, so crediting only "
        "the ARN leaves the alarm, judged by name, reading as silent",
        "find": "                notifying.update(aliases.get(reference, {reference}))\n",
        "replace": "                notifying.add(reference)\n",
    },
    {
        "name": "BR-32 composite: an unread rule credits its alarms",
        "file": BEDROCK,
        "defect": "a rule this parser does not read, such as AT_LEAST, may need "
        "several alarms, so crediting its alarms passes one that never notifies "
        "alone",
        "find": "        if not match or match.end() == position:\n            return None\n",
        "replace": "        if not match or match.end() == position:\n            return True\n",
    },
    {
        "name": "BR-20 network: a public rule is not judged",
        "file": BEDROCK,
        "defect": "a network policy allowing the collection from public networks passed",
        "find": '            if entry.get("AllowFromPublic") is True:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-20 APIAccessAll: only a bare * is wide",
        "file": BEDROCK,
        "defect": "an aoss:APIAccessAll grant with a wildcard in the account segment passed",
        "find": '                    else [r for r in resources if "*" in r or "?" in r]\n',
        "replace": '                    else [r for r in resources if r == "*"]\n',
    },
    {
        "name": "BR-20 source: a PrincipalArn allow-list is not compared",
        "file": BEDROCK,
        "defect": "a vector principal the source bucket's aws:PrincipalArn Deny keeps out passed",
        "find": "            or any(\n                not any(_wildcard_matches(p, principal) for p in patterns)\n",
        "replace": "            or any(\n                False\n",
    },
    {
        "name": "BR-20 source: S3 Vectors exemptions are not compared",
        "file": BEDROCK,
        "defect": "an S3 Vectors principal the source bucket policy denies was not compared",
        "find": '                admitted = {"principals": scope["principals"]}\n',
        "replace": "                admitted = {}\n",
    },
    {
        "name": "BR-20 MANAGED: supplemental storage key not judged",
        "file": BEDROCK,
        "defect": "a MANAGED knowledge base keeping supplemental data in an SSE-S3 bucket passed",
        "find": '        if encryption["customer_managed"]:\n            met.append(',
        "replace": "        if True:\n            met.append(",
    },
    {
        "name": "BR-57 scope: only the probe actions are judged",
        "file": BEDROCK,
        "defect": "a role holding aoss:APIAccessAll on every collection passed",
        "find": "                            if action in AGENT_ROLE_RESOURCELESS_ACTIONS:\n",
        "replace": "                            if action not in AGENT_ROLE_SCOPE_PROBE_ACTIONS:\n",
    },
    {
        "name": "BR-57 scope: an unbounded NotAction read on the probe set",
        "file": BEDROCK,
        "defect": "a NotAction Allow on every resource with no boundary was judged on the probe set only",
        "find": '                    if "NotAction" in statement and not bounded:\n',
        "replace": "                    if False:\n",
    },
    {
        "name": "BR-07 runtime: a draft prompt call counted as versioned",
        "file": BEDROCK,
        "defect": "a Converse call naming a prompt ARN with no version passed",
        "find": '                found["versioned" if match.group(1) else "draft"].append(label)\n',
        "replace": '                found["versioned"].append(label)\n',
    },
    {
        "name": "BR-07 runtime: a capped lookup names its newest event",
        "file": BEDROCK,
        "defect": "event history is read newest first, so naming the newest time "
        "read as the cap claims every older call of the window was read",
        "find": '                    oldest = min(oldest or detail["eventTime"], detail["eventTime"])\n',
        "replace": '                    oldest = max(oldest or detail["eventTime"], detail["eventTime"])\n',
    },
    {
        "name": "BR-06 centralization: any CloudTrail table credited",
        "file": BEDROCK,
        "defect": "a Glue table under no recording trail's log root was credited as central",
        "find": "            if trail is None:\n                unmatched.append(",
        "replace": "            if False:\n                unmatched.append(",
    },
    {
        "name": "BR-06 centralization: invocation logs not required",
        "file": BEDROCK,
        "defect": "a store with no table over the invocation log path passed",
        "find": '            if "BedrockModelInvocationLogs/" in location and invocation[\n                "root"\n            ].startswith(location):\n',
        "replace": "            if True:\n",
    },
    {
        "name": "BR-06 log group: a filter pattern forwards every event",
        "file": BEDROCK,
        "defect": "a subscription filter with a filter pattern was credited as forwarding every invocation log event",
        "find": "            missed.append(f\"{label} forwards only the events matching '{pattern}'\")\n            continue\n",
        "replace": "            pass\n",
    },
    {
        "name": "BR-06 log group: field selection forwards every event",
        "file": BEDROCK,
        "defect": "a subscription filter with field selection criteria was credited as forwarding every event",
        "find": "            missed.append(f\"{label} forwards only the events '{criteria}' selects\")\n            continue\n",
        "replace": "            pass\n",
    },
    {
        "name": "BR-06 log group: transformed events credited",
        "file": BEDROCK,
        "defect": "a subscription filter on transformed logs was credited as forwarding the records",
        "find": '            missed.append(f"{label} forwards the transformed events, not the records")\n            continue\n',
        "replace": "            pass\n",
    },
    {
        "name": "BR-06 log group: an inactive stream credited",
        "file": BEDROCK,
        "defect": "a Firehose stream that is not ACTIVE was credited as delivering the log group",
        "find": '        if status != "ACTIVE":\n            missed.append(',
        "replace": "        if False:\n            missed.append(",
    },
    {
        "name": "BR-06 log group: a Lambda processor not held",
        "file": BEDROCK,
        "defect": "a Firehose stream whose Lambda record processor can rewrite the records was credited",
        "find": '            if processing.get("Enabled") is True and any(\n                processor.get("Type") == "Lambda"\n                for processor in processing.get("Processors") or []\n            ):\n                found["held"].append(',
        "replace": '            if False:\n                found["held"].append(',
    },
    {
        "name": "BR-06 log group: another account's stream followed",
        "file": BEDROCK,
        "defect": "a subscription to another account's Firehose stream was followed as if this account could read it",
        "find": '        if parts[4] != account:\n            found["held"].append(',
        "replace": '        if False:\n            found["held"].append(',
    },
    {
        "name": "BR-06 log group: a string-prefix table credited",
        "file": BEDROCK,
        "defect": "a Glue table whose location is a string prefix but not a folder of the Firehose path was credited",
        "find": '                if root.startswith(table["location"].rstrip("/") + "/")\n',
        "replace": '                if root.startswith(table["location"])\n',
    },
    {
        "name": "BR-06 log group: one dropped subscription blocks a full one",
        "file": BEDROCK,
        "defect": "a full subscription was not credited beside a filtered one, so any filtered subscription failed the leg",
        "find": '    if found["met"]:\n        return {"met": found["met"], "gaps": [], "held": []}\n',
        "replace": '    if found["met"] and not missed:\n        return {"met": found["met"], "gaps": [], "held": []}\n',
    },
    {
        "name": "BR-06 log group: Athena connectors not read",
        "file": BEDROCK,
        "defect": "a LAMBDA Athena connector that may query the log group did not hold a missing subscription",
        "find": '            if kind == "LAMBDA" or (\n',
        "replace": "            if False and (\n",
    },
    {
        "name": "BR-06 log group: any FEDERATED catalog held",
        "file": BEDROCK,
        "defect": "a FEDERATED Athena catalog over another source, such as DynamoDB, held the verdict",
        "find": '                kind == "FEDERATED" and not catalog.get("ConnectionType")\n',
        "replace": '                kind == "FEDERATED"\n',
    },
    {
        "name": "BR-06 log group: catalogs read in one Region",
        "file": BEDROCK,
        "defect": "Athena data catalogs were listed only in the scanned Region, though a connector elsewhere can query the group",
        "find": "    for catalog_region in regions:\n",
        "replace": "    for catalog_region in [region]:\n",
    },
    {
        "name": "BR-06 log group: an unfollowed chain fails",
        "file": BEDROCK,
        "defect": "a chain that was not followed in full was reported as a gap and Failed",
        "find": '    if found["held"]:\n        found["held"] = [\n',
        "replace": '    if False:\n        found["held"] = [\n',
    },
    {
        "name": "BR-06 log group: the chain is not consulted",
        "file": BEDROCK,
        "defect": "a CloudWatch Logs-only invocation log group with no queryable path passed",
        "find": '        gaps += chain["gaps"]\n',
        "replace": "        gaps += []\n",
    },
    {
        "name": "BR-34 Converse: an earlier untagged turn not judged",
        "file": BEDROCK,
        "defect": "a Converse call tagging only its latest user turn passed",
        "find": '            elif call["earlier"]:\n',
        "replace": "            elif False:\n",
    },
    {
        "name": "BR-34 strength: only HIGH blocks a prompt attack",
        "file": BEDROCK,
        "defect": "a PROMPT_ATTACK filter tuned to MEDIUM failed",
        "find": '        and filter_item.get("inputStrength") in GUARDRAIL_BLOCKING_STRENGTHS\n',
        "replace": '        and filter_item.get("inputStrength") == "HIGH"\n',
    },
    {
        "name": "BR-27 grounding: Converse qualifiers not read",
        "file": BEDROCK,
        "defect": "a guarded Converse call with no grounding_source qualifier passed",
        "find": '            if not call["qualified"]:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-26 front layer: a credited source ends the judgment",
        "file": BEDROCK,
        "defect": "a redacted knowledge base generated from with no PII guardrail was not failed",
        "find": "            elif front_layer_resolution and not enforced_screen:\n",
        "replace": "            elif False:\n",
    },
    {
        "name": "BR-42 parse: an unparsed policy keeps Passed",
        "file": BEDROCK,
        "defect": "an identity policy that could not be parsed left the model access row Passed",
        "find": "            if unparsed:\n                # An unparsed policy may allow invocation on '*'.\n",
        "replace": "            if False:\n                # An unparsed policy may allow invocation on '*'.\n",
    },
    {
        "name": "BR-42 training: Search results ignored",
        "file": BEDROCK,
        "defect": "training jobs past the DescribeTrainingJob cap were reported unread although Search returned them",
        "find": '                searched[found["TrainingJobName"]] = found\n',
        "replace": "                pass\n",
    },
    {
        "name": "BR-34 Converse: a tool-result turn is judged as the latest turn",
        "file": BEDROCK,
        "defect": "a Converse call whose latest user turn holds only a tool result failed",
        "find": "            if _tool_result_only(content):\n                continue\n",
        "replace": "            if False:\n                continue\n",
    },
    {
        "name": "BR-27 InvokeModel: one grounding tag counts as both",
        "file": BEDROCK,
        "defect": "a guarded InvokeModel call sending a source tag and no query tag passed",
        "find": "            if len(tags) < 2:\n",
        "replace": "            if not tags:\n",
    },
    {
        "name": "BR-27 InvokeModel: an untagged call with an unknown guardrail is judged",
        "file": BEDROCK,
        "defect": "an untagged InvokeModel call was failed though its guardrail is not logged",
        "find": "            if not tags and not any(\n",
        "replace": "            if False and not any(\n",
    },
    {
        "name": "BR-27 InvokeModel: the CloudTrail guardrail is not read for grounding",
        "file": BEDROCK,
        "defect": "an untagged InvokeModel call failed through a guardrail with no grounding filter",
        "find": '            if not grounds(joined["guardrail"], joined["version"]):\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-27 InvokeModel: an unjoined call is dropped",
        "file": BEDROCK,
        "defect": "an untagged InvokeModel call with no CloudTrail match let the row pass",
        "find": "                unjudged.append(f\"{call['label']}, {joined['reason']}\")\n",
        "replace": "                pass\n",
    },
    {
        "name": "BR-27 InvokeModel: a matched call stays pending",
        "file": BEDROCK,
        "defect": "an untagged InvokeModel call matched to its CloudTrail event was still reported unmatched",
        "find": "                    pending.discard(request_id)\n",
        "replace": "                    pass\n",
    },
    {
        "name": "BR-27 InvokeModel: the CloudTrail join reads one page",
        "file": BEDROCK,
        "defect": "an untagged InvokeModel call whose event is on a later LookupEvents page went unjudged",
        "find": '                request["NextToken"] = next_token\n            if stopped:\n',
        "replace": "                break\n            if stopped:\n",
    },
    {
        "name": "BR-27 InvokeModel: the windowed query stops at the first page",
        "file": BEDROCK,
        "defect": "the LookupEvents stream ended after one page with calls still unmatched",
        "find": "                if not pending or not isinstance(next_token, str) or not next_token:\n",
        "replace": "                if True:\n",
    },
    {
        "name": "BR-27 InvokeModel: the window ends at the earliest call",
        "file": BEDROCK,
        "defect": "the LookupEvents window missed the events of every call after the first",
        "find": '            "EndTime": max(when for when, _ in timed) + GROUNDING_JOIN_WINDOW,\n',
        "replace": '            "EndTime": min(when for when, _ in timed) + GROUNDING_JOIN_WINDOW,\n',
    },
    # ------------------------------------------- Bedrock round-9 Converse join
    # GRD-02, GRD-09 and DET-04: a Converse call's guardrail is read from its
    # CloudTrail event, and the scans and joins of one region run share reads.
    {
        "name": "Converse join: the event's guardrailConfig is ignored",
        "file": BEDROCK,
        "defect": "a Converse event carries its guardrail under "
        "requestParameters.guardrailConfig, so reading only the top level calls "
        "every guarded Converse call unguarded and an untagged one passes",
        "find": "                    if isinstance(config, dict):\n"
        "                        parameters = config\n",
        "replace": "                    if False:\n"
        "                        parameters = config\n",
    },
    {
        "name": "BR-34 Converse: a CloudTrail-guarded call is not judged",
        "file": BEDROCK,
        "defect": "the logged request never names its guardrail, so a guarded, "
        "untraced Converse call that sent untagged input passes",
        "find": '            if not call["log_guarded"] and call["request_id"] not in joined["guarded"]:\n',
        "replace": '            if not call["log_guarded"]:\n',
    },
    {
        "name": "BR-27 Converse: the joined guardrail version is ignored",
        "file": BEDROCK,
        "defect": "a call through a version without grounding filters is judged "
        "as if it ran through another, so an unqualified call is missed or "
        "a call outside the population fails",
        "find": '                or not grounds(version["guardrail"], version["version"])\n',
        "replace": '                or not grounds(version["guardrail"], "1")\n',
    },
    {
        "name": "Converse join: an old call with no event reads as recent",
        "file": BEDROCK,
        "defect": "a Converse call older than the event-history lag with no "
        "CloudTrail event is counted as too recent, so its unknown guardrail no "
        "longer holds the row at N/A",
        "find": "            >= settled\n",
        "replace": "            >= settled - timedelta(days=1)\n",
    },
    {
        "name": "Converse join: an unguarded event reads as unread",
        "file": BEDROCK,
        "defect": "a Converse event that names no guardrail is reported as not "
        "read, so every unguarded call in the account holds the row at N/A",
        "find": '        elif entry.get("unguarded"):\n',
        "replace": "        elif False:\n",
    },
    {
        "name": "Join: the region run's page budget is not shared",
        "file": BEDROCK,
        "defect": "each join reads its own 50 pages per operation, so BR-27 and "
        "BR-34 together read past the 100 pages the timeout was measured for",
        "find": '                        GROUNDING_JOIN_BUDGET_PAGES - joins["pages"],\n',
        "replace": "                        GROUNDING_JOIN_BUDGET_PAGES,\n",
    },
    {
        "name": "Join: a call BR-27 joined is looked up again",
        "file": BEDROCK,
        "defect": "BR-34 rereads every Converse event BR-27 already joined, "
        "doubling the LookupEvents pages of a region run",
        "find": '        known = joins["resolved"].get(call["request_id"])\n',
        "replace": "        known = None\n",
    },
    {
        "name": "S3 scan: only the first leg sees each record",
        "file": BEDROCK,
        "defect": "one read of each S3 object serves every leg, so passing a "
        "record to the first leg alone drops the untagged calls and Converse "
        "calls of an S3-only destination",
        "find": "                            if match(line, record):\n",
        "replace": "                            if index == 0 and match(line, record):\n",
    },
    {
        "name": "Capped log scan names the start of the window",
        "file": BEDROCK,
        "defect": "a capped scan must name the time from which matching records "
        "were not read; without the last record's time it names the window "
        "start and overstates what was not read",
        "find": '                    last = max(last, event["timestamp"])\n',
        "replace": "                    pass\n",
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
            "        if skipped:\n"
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
    # ------------------------------------------ the SageMaker verdict legs
    # Each entry reverts one round-7 verdict leg in sagemaker_assessments to the
    # behaviour the regrade graded partial. Each was killed by hand on a byte
    # backup on 2026-10-03 before it was added here.
    {
        "name": "SM-34 lets either network key stand for both",
        "file": SAGEMAKER,
        "defect": "the control asks for approved subnets and approved security "
        "groups. Read as one key group, a Deny on the security groups alone "
        "passes the approved network category, and a job runs in any subnet",
        "find": (
            "        _guardrail_requirements(\n"
            '            ("sagemaker:VpcSubnets", "sagemaker:VpcSecurityGroupIds")\n'
            "        ),\n"
        ),
        "replace": (
            "        tuple(\n"
            '            (a, ("sagemaker:VpcSubnets", "sagemaker:VpcSecurityGroupIds"))\n'
            "            for a, _, d in SAGEMAKER_GUARDED_ACTION_KEYS\n"
            '            if "sagemaker:VpcSubnets" in d\n'
            "        ),\n"
        ),
    },
    # Round 9: the guarded population is the sagemaker service reference's.
    # Each was killed by hand on a byte backup on 2026-10-04.
    {
        "name": "SM-34 guards only the five original create actions",
        "file": SAGEMAKER,
        "defect": "a tuning, processing, AutoML, monitoring, HyperPod or Studio "
        "action launches compute on its own condition keys, so an SCP on "
        "CreateTrainingJob alone passes while those paths stay open",
        "find": "        for action, _, defined in SAGEMAKER_GUARDED_ACTION_KEYS\n",
        "replace": "        for action, _, defined in SAGEMAKER_GUARDED_ACTION_KEYS[:5]\n",
    },
    {
        "name": "SM-34 holds the tuning job to the encryption keys only",
        "file": SAGEMAKER,
        "defect": "CreateHyperParameterTuningJob defines sagemaker:VpcSubnets, "
        "VpcSecurityGroupIds and NetworkIsolation, so a tuning job outside the "
        "approved network passes",
        "find": (
            '        "sagemaker:CreateHyperParameterTuningJob",\n'
            '        "hyper-parameter-tuning-job",\n'
            '        (*_SM_ENC_NET, "sagemaker:NetworkIsolation"),\n'
        ),
        "replace": (
            '        "sagemaker:CreateHyperParameterTuningJob",\n'
            '        "hyper-parameter-tuning-job",\n'
            "        _SM_ENC,\n"
        ),
    },
    {
        "name": "SM-34 drops the Studio internet key from its category",
        "file": SAGEMAKER,
        "defect": "CreateDomain and UpdateDomain take AppNetworkAccessType, so a "
        "PublicInternetOnly domain passes the no direct internet access category",
        "find": (
            '                "sagemaker:DirectInternetAccess",\n'
            '                "sagemaker:AppNetworkAccessType",\n'
            "            )\n"
        ),
        "replace": '                "sagemaker:DirectInternetAccess",\n            )\n',
    },
    {
        "name": "SM-34 has no non-compliant AppNetworkAccessType value",
        "file": SAGEMAKER,
        "defect": "a StringEqualsIfExists PublicInternetOnly Deny fires on an "
        "omitted key and on the public value, so it enforces the key, but it "
        "reads as a one-value deny and withholds the Passed",
        "find": '    "sagemaker:appnetworkaccesstype": "publicinternetonly",\n',
        "replace": "",
    },
    {
        "name": "SM-34 probes a job ARN with no category segment",
        "file": SAGEMAKER,
        "defect": "a job ARN is job/<category>/<name>, so a Deny on job/*/* "
        "covers every job but misses a probe with no category, and the "
        "CreateJob guard reads as scoped to named resources",
        "find": '    "job": "job/zz-probe/zz-probe",\n',
        "replace": "",
    },
    {
        "name": "SM-35 regional leg never reads Detective",
        "file": SAGEMAKER,
        "defect": "Detective designates its administrator per Region, so a Region where the organization behavior graph has no administrator, or the management account administers it, passes",
        "find": '    admins["Amazon Detective"] = _detective_regional_admin(region, account_id)\n',
        "replace": "",
    },
    {
        "name": "SM-35 regional leg drops the Macie administrator it read",
        "file": SAGEMAKER,
        "defect": "Macie designates its administrator per Region, so a Region where the management account administers Macie passes",
        "find": '        admins["Amazon Macie"] = macie_admin\n',
        "replace": "        pass\n",
    },
    {
        "name": "SM-35 takes any Detective membership as the organization graph",
        "file": SAGEMAKER,
        "defect": "any account that enables Detective administers its own behavior graph, so this account's standalone graph reads as the organization administrator",
        "find": '            if membership.get("InvitationType") == "ORGANIZATION":\n',
        "replace": "            if True:\n",
    },
    {
        "name": "SM-35 credits a standalone Detective graph",
        "file": SAGEMAKER,
        "defect": "DescribeOrganizationConfiguration answers only for the organization behavior graph, so skipping its ValidationException reads a standalone graph as the organization administrator",
        "find": '                if error.response.get("Error", {}).get("Code", "") != (\n                    "ValidationException"\n                ):\n                    raise\n                continue\n',
        "replace": "                pass\n",
    },
    {
        "name": "SM-35 reads every Detective membership page as the first",
        "file": SAGEMAKER,
        "defect": "an organization membership past the first ListInvitations page is never read, so the Region reads as having no Detective administrator",
        "find": '            items.extend(page.get(key) or [])\n            token = page.get("NextToken")\n',
        "replace": "            items.extend(page.get(key) or [])\n            token = None\n",
    },
    {
        "name": "SM-35 reads Macie's not-administrator answer as an unread",
        "file": SAGEMAKER,
        "defect": "Macie answers a member that is not its organization administrator with AccessDeniedException, so treating that answer as a denied read withholds a Failed the Region has earned",
        "find": "            if MACIE_NOT_ADMINISTRATOR_MESSAGE in _client_error_message(error):\n",
        "replace": "            if False:\n",
    },
    {
        "name": "SM-35 reads every Macie AccessDenied as Macie being off",
        "file": SAGEMAKER,
        "defect": "an IAM denial of macie2:GetAdministratorAccount also answers AccessDeniedException, so without the message test a read the role cannot make fails the Region instead of withholding the Passed",
        "find": "        and MACIE_NOT_ENABLED_MESSAGE in _client_error_message(response)\n",
        "replace": "        and True\n",
    },
    {
        "name": "SM-35 does not fail a Region where Macie is off",
        "file": SAGEMAKER,
        "defect": "a Region where Macie is not enabled has no Macie administrator, so it must fail as a Region without a GuardDuty detector does",
        "find": "    ):\n        return None\n\n    def _administrator():\n",
        "replace": "    ):\n        pass\n\n    def _administrator():\n",
    },
    {
        "name": "SM-31 passes a capture that records one direction",
        "file": SAGEMAKER,
        "defect": "DescribeEndpoint reports Started for an Input-only capture, so without the endpoint config's CaptureOptions an endpoint that never records responses passes",
        "find": '                    and not ("InputAndOutput" in modes or {"Input", "Output"} <= modes)\n',
        "replace": "                    and False\n",
    },
    {
        "name": "SM-31 takes either capture direction for both",
        "file": SAGEMAKER,
        "defect": "an endpoint config with only Input or only Output then reads as capturing requests and responses",
        "find": '                    and not ("InputAndOutput" in modes or {"Input", "Output"} <= modes)\n',
        "replace": '                    and not ("InputAndOutput" in modes or {"Input", "Output"} & modes)\n',
    },
    {
        "name": "SM-43 stops counting at the page that hit the cap",
        "file": SAGEMAKER,
        "defect": "the objects on later listing pages are past the cap too, so a count of the first page understates what was not read",
        "find": "                    if count_pages[0] <= 0:\n",
        "replace": "                    if True:\n",
    },
    {
        "name": "SM-43 reports a stopped count as exact",
        "file": SAGEMAKER,
        "defect": "a count the page budget stopped is a lower bound, so stating it as exact claims what was not listed",
        "find": "                        uncounted = True\n                        break\n",
        "replace": "                        uncounted = False\n                        break\n",
    },
    {
        "name": "SM-43 never spends the counting page budget",
        "file": SAGEMAKER,
        "defect": "an unbounded count over a prefix of millions of objects outruns the 600 s Lambda timeout",
        "find": "                    count_pages[0] -= 1\n",
        "replace": "                    pass\n",
    },
    {
        "name": "SM-38 credits a MicroVM selector narrowed by another field",
        "file": SAGEMAKER,
        "defect": "a selector that adds eventName, readOnly or resources.ARN records a subset of the MicroVM calls, so crediting it passes a trail that misses some",
        "find": "        if not extra:\n            return True, []\n        narrowed |= extra\n",
        "replace": "        if True:\n            return True, []\n        narrowed |= extra\n",
    },
    {
        "name": "SM-38 credits a MicroVM trail that is not logging",
        "file": SAGEMAKER,
        "defect": "a stopped trail records nothing, so its selectors cannot stand for the MicroVM data events",
        "find": '        if status.get("IsLogging") is not True:\n            if credited:\n                coverage["gaps"].append(f"trail \'{name}\' is not logging")\n',
        "replace": '        if status.get("IsLogging") is None:\n            if credited:\n                coverage["gaps"].append(f"trail \'{name}\' is not logging")\n',
    },
    {
        "name": "SM-38 counts a single-Region event data store homed elsewhere",
        "file": SAGEMAKER,
        "defect": "a store that is not multi-Region records only its home Region's events, so it cannot record this Region's MicroVM calls",
        "find": '            if store_region != region and detail.get("MultiRegionEnabled") is not True:\n                continue\n',
        "replace": "            if False:\n                continue\n",
    },
    {
        "name": "SM-38 credits an event data store that is not ENABLED",
        "file": SAGEMAKER,
        "defect": "a store that stopped ingestion records no new MicroVM events",
        "find": '            if detail.get("Status") != "ENABLED":\n',
        "replace": '            if detail.get("Status") is None:\n',
    },
    {
        "name": "SM-38 never reports a failed ListRegions",
        "file": SAGEMAKER,
        "defect": "without the Region list a multi-Region store homed elsewhere goes unread, so the missing-store failure would rest on a partial read",
        "find": '        coverage["unread"].append(\n            "the Regions where a multi-Region event data store may be homed "\n',
        "replace": '        str(\n            "the Regions where a multi-Region event data store may be homed "\n',
    },
    {
        "name": "SM-38 credits a MicroVM flow log in any status",
        "file": SAGEMAKER,
        "defect": "an INACTIVE flow log records no traffic from the egress subnet",
        "find": '            if flow_log.get("FlowLogStatus") == "ACTIVE"\n            and flow_log.get("TrafficType") == "ALL"\n',
        "replace": '            if flow_log.get("FlowLogStatus") is not None\n            and flow_log.get("TrafficType") == "ALL"\n',
    },
    {
        "name": "SM-38 credits a MicroVM flow log of accepted traffic only",
        "file": SAGEMAKER,
        "defect": "an ACCEPT flow log drops every rejected connection, so the MicroVM egress it should record is partly unseen",
        "find": '            and flow_log.get("TrafficType") == "ALL"\n        }\n',
        "replace": '            and flow_log.get("TrafficType") in ("ALL", "ACCEPT")\n        }\n',
    },
    {
        "name": "SM-38 credits only a subnet-level MicroVM flow log",
        "file": SAGEMAKER,
        "defect": "a flow log on the VPC covers every subnet in it, so ignoring it fails a logged egress subnet",
        "find": "            elif subnet not in logged and subnet_vpc[subnet] not in logged:\n",
        "replace": "            elif subnet not in logged:\n",
    },
    {
        "name": "SM-38 fails the MicroVM data events on a partial read",
        "file": SAGEMAKER,
        "defect": "a trail or store that was not read may record the MicroVM data events, so no verdict follows",
        "find": '    if not events["credited"] and not events["unread"]:\n',
        "replace": '    if not events["credited"]:\n',
    },
    {
        "name": "SM-38 never runs the MicroVM tier",
        "file": SAGEMAKER,
        "defect": "MicroVMs are outside Runtime Monitoring, so without this leg they are never in SM-38's population",
        "find": '        findings["csv_data"].extend(_microvm_runtime_tier_findings(region))\n',
        "replace": "        pass\n",
    },
    {
        "name": "SM-39 drops the SageMaker workloads from its population",
        "file": SAGEMAKER,
        "defect": "SageMaker endpoints, running jobs, notebook instances and Studio domains run in customer VPCs whose egress SM-39 then never judges",
        "find": "        references.extend(sagemaker_references)\n",
        "replace": "        sagemaker_references.clear()\n",
    },
    {
        "name": "SM-39 reads only InProgress jobs",
        "file": SAGEMAKER,
        "defect": "a Stopping job still runs and egresses until its instances are released",
        "find": 'RUNNING_JOB_STATUSES = ("InProgress", "Stopping")\n',
        "replace": 'RUNNING_JOB_STATUSES = ("InProgress",)\n',
    },
    {
        "name": "SM-39 takes one isolated model for the whole endpoint",
        "file": SAGEMAKER,
        "defect": "an endpoint that also serves a model without network isolation and has no VPC reaches the internet through SageMaker's network",
        "find": "        if complete and not subnets and not all(isolated):\n",
        "replace": "        if complete and not subnets and not any(isolated):\n",
    },
    {
        "name": "SM-39 ignores a running job's network isolation",
        "file": SAGEMAKER,
        "defect": "a network-isolated job outside a VPC has no egress, so failing it reports a path that does not exist",
        "find": '                if not subnets and network.get("EnableNetworkIsolation") is not True:\n',
        "replace": "                if not subnets:\n",
    },
    {
        "name": "SM-39 drops an unread SageMaker job",
        "file": SAGEMAKER,
        "defect": "a job whose description failed may run in a VPC whose egress is then never judged, and nothing says so",
        "find": '                    unread.append(f"{label} ({get_assessment_error_label(error)})")\n                    continue\n',
        "replace": "                    continue\n",
    },
    {
        "name": "SM-39 passes a notebook with direct internet access",
        "file": SAGEMAKER,
        "defect": "DirectInternetAccess Enabled adds SageMaker's own internet path beside the VPC, where neither firewall applies",
        "find": '        if detail.get("DirectInternetAccess") != "Disabled":\n',
        "replace": '        if detail.get("DirectInternetAccess") is None:\n',
    },
    {
        "name": "SM-39 passes a Studio domain that is not VpcOnly",
        "file": SAGEMAKER,
        "defect": "PublicInternetOnly sends the domain's app internet traffic through SageMaker's network, where neither firewall applies",
        "find": '        if detail.get("AppNetworkAccessType") != "VpcOnly":\n',
        "replace": '        if detail.get("AppNetworkAccessType") is None:\n',
    },
    {
        "name": "SM-39 drops the Bedrock jobs from its population",
        "file": SAGEMAKER,
        "defect": "active Bedrock model customization and batch inference jobs run in customer VPCs whose egress SM-39 then never judges",
        "find": "        references.extend(bedrock_references)\n",
        "replace": "        bedrock_references.clear()\n",
    },
    {
        "name": "SM-39 reads only the first HyperPod cluster page",
        "file": SAGEMAKER,
        "defect": "a cluster past the first ListClusters page runs in subnets SM-39 never judges",
        "find": '            for cluster in _paged(client, "list_clusters", "ClusterSummaries")\n',
        "replace": '            for cluster in _paged(client, "list_clusters", "ClusterSummaries")[:1]\n',
    },
    {
        "name": "SM-39 judges a HyperPod cluster's subnets when every group overrides them",
        "file": SAGEMAKER,
        "defect": "no instance runs in the cluster VpcConfig when every group carries an OverrideVpcConfig, so naming the cluster in that VPC claims a workload it does not host",
        "find": "        if not inherit:\n            continue\n",
        "replace": "        if False:\n            continue\n",
    },
    {
        "name": "SM-39 drops a HyperPod restricted instance group",
        "file": SAGEMAKER,
        "defect": "a restricted instance group's OverrideVpcConfig places its instances in subnets SM-39 then never judges",
        "find": '            *(detail.get("RestrictedInstanceGroups") or []),\n',
        "replace": "\n",
    },
    {
        "name": "SM-39 passes a HyperPod cluster without a VpcConfig",
        "file": SAGEMAKER,
        "defect": "a cluster with no VpcConfig runs in the SageMaker platform VPC, where no firewall of the account applies to its egress",
        "find": "        if not cluster_subnets:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "SM-39 reads only InProgress Bedrock customization jobs",
        "file": SAGEMAKER,
        "defect": "a Stopping customization job still runs and still egresses",
        "find": 'BEDROCK_CUSTOMIZATION_ACTIVE_STATUSES = ("InProgress", "Stopping")\n',
        "replace": 'BEDROCK_CUSTOMIZATION_ACTIVE_STATUSES = ("InProgress",)\n',
    },
    {
        "name": "SM-39 skips queued Bedrock batch inference jobs",
        "file": SAGEMAKER,
        "defect": "a Submitted, Validating or Scheduled batch job will run in the vpcConfig it carries, so its subnets are in scope",
        "find": '    "Submitted",\n    "Validating",\n    "Scheduled",\n    "InProgress",\n    "Stopping",\n)\n',
        "replace": '    "InProgress",\n    "Stopping",\n)\n',
    },
    {
        "name": "SM-39 passes a Bedrock job without a vpcConfig",
        "file": SAGEMAKER,
        "defect": "a job with no vpcConfig runs in Bedrock's own network, where no firewall of the account applies",
        "find": "                open_bedrock,\n",
        "replace": "                [],\n",
    },
    {
        "name": "SM-39 reports no VPC workload beside an open Bedrock job",
        "file": SAGEMAKER,
        "defect": "a Bedrock job outside the VPC is a workload, so the no-workload N/A contradicts the Failed rows beside it",
        "find": "            and not open_bedrock\n",
        "replace": "            and True\n",
    },
    {
        "name": "SM-39 drops an unread Bedrock job list",
        "file": SAGEMAKER,
        "defect": "an unread job list may hold jobs in VPCs SM-39 never judges, so a Passed rests on a partial read",
        "find": "        unread.extend(bedrock_unread)\n",
        "replace": "        [].extend(bedrock_unread)\n",
    },
    {
        "name": "SM-39 reports no VPC workload beside an open SageMaker workload",
        "file": SAGEMAKER,
        "defect": "a SageMaker workload outside the VPC is a workload, so the no-workload N/A contradicts the Failed rows beside it",
        "find": "            and not open_sagemaker\n",
        "replace": "            and True\n",
    },
    {
        "name": "SM-39 egress reads only each function's $LATEST",
        "file": SAGEMAKER,
        "defect": "a published version keeps its own VpcConfig, so an alias can run it in subnets whose egress is never judged",
        "find": "    functions, lambda_unread = _lambda_functions(region, all_versions=True)\n    unread.extend(lambda_unread)\n    for function in functions:\n        label = ",
        "replace": "    functions, lambda_unread = _lambda_functions(region)\n    unread.extend(lambda_unread)\n    for function in functions:\n        label = ",
    },
    {
        "name": "SM-39 matches a named function against the qualified $LATEST ARN",
        "file": SAGEMAKER,
        "defect": "ListFunctions with FunctionVersion ALL appends :$LATEST, so an agent-named function is never found and its open egress reads as unread",
        "find": '        str(f.get("FunctionArn") or "").removesuffix(":$LATEST"): f for f in functions\n',
        "replace": '        str(f.get("FunctionArn") or ""): f for f in functions\n',
    },
    {
        "name": "SM-35 reads a repeated Detective token as the last page",
        "file": SAGEMAKER,
        "defect": "a repeated NextToken means the memberships were not all read, so returning the pages so far can miss the organization graph and fail or pass on a partial read",
        "find": '                raise RuntimeError(f"{key} paging repeated a NextToken")\n',
        "replace": "                return items\n",
    },
    {
        "name": "SM-38 notes a MicroVM without an egress connector out of the Passed row",
        "file": SAGEMAKER,
        "defect": "a MicroVM with no egress connector has no network telemetry at all, so a Passed over it claims a tier that does not exist",
        "find": "    if no_egress:\n        problems.append(\n",
        "replace": "    if False:\n        problems.append(\n",
    },
    {
        "name": "SM-38 credits a MicroVM image version with logging disabled",
        "file": SAGEMAKER,
        "defect": "an image version with logging disabled sends no application telemetry to CloudWatch Logs, so the row must say so",
        "find": '        if "disabled" in logging_config:\n',
        "replace": "        if False:\n",
    },
    {
        "name": "SM-38 credits a MicroVM image version with no log group",
        "file": SAGEMAKER,
        "defect": "an image version that names no CloudWatch Logs log group establishes no application telemetry",
        "find": "        elif not group:\n",
        "replace": "        elif False:\n",
    },
    {
        "name": "SM-38 reads only the first MicroVM image version page",
        "file": SAGEMAKER,
        "defect": "the version a MicroVM runs may be on a later page, so its logging goes unread",
        "find": "                    versions[f\"{image_arn}|{item.get('imageVersion')}\"] = item\n",
        "replace": "                    versions[f\"{image_arn}|{item.get('imageVersion')}\"] = item\n                break\n",
    },
    {
        "name": "SM-38 matches a MicroVM image version by image alone",
        "file": SAGEMAKER,
        "defect": "each image version carries its own logging, so taking another version's setting judges the wrong configuration",
        "find": '        item = versions.get(f"{image_arn}|{version}")\n',
        "replace": '        item = next((v for k, v in versions.items() if k.startswith(f"{image_arn}|")), None)\n',
    },
    {
        "name": "SM-38 passes on a MicroVM image version it did not read",
        "file": SAGEMAKER,
        "defect": "a version ListMicrovmImageVersions did not return has no logging read, so a Passed rests on a partial read",
        "find": '            unread.append(\n                f"{label} (ListMicrovmImageVersions did not return the version)"\n',
        "replace": '            [].append(\n                f"{label} (ListMicrovmImageVersions did not return the version)"\n',
    },
    {
        "name": "SM-38 drops the MicroVM image logging read errors",
        "file": SAGEMAKER,
        "defect": "a failed ListMicrovmImageVersions leaves the image versions' logging unread, so a Passed rests on a partial read",
        "find": "    unread.extend(logging_unread)\n",
        "replace": "    [].extend(logging_unread)\n",
    },
    {
        "name": "SM-38 reads a repeated store token as the last page",
        "file": SAGEMAKER,
        "defect": "the stores not yet listed may record the MicroVM data events, so a missing-store failure would rest on a partial read",
        "find": '                    raise RuntimeError("ListEventDataStores repeated a NextToken")\n',
        "replace": "                    break\n",
    },
    {
        "name": "SM-11 invoke leg passes with the root user unbound",
        "file": SAGEMAKER,
        "defect": "identity policies bind roles and users only, so passing on them leaves the account root user free to call the public runtime endpoint",
        "find": '        rows.append(_row(details, INVOKE_SOURCE_NETWORK_RESOLUTION, "Medium", "Failed"))\n',
        "replace": '        rows.append(_row(details, "No action required", "Medium", "Passed"))\n',
    },
    {
        "name": "SM-11 invoke leg credits an SCP that misses an invoke action",
        "file": SAGEMAKER,
        "defect": "InvokeEndpointAsync and InvokeEndpointWithResponseStream reach the same endpoint, so an SCP on InvokeEndpoint alone leaves two public paths",
        "find": "        for action in INVOKE_SOURCE_SCP_ACTIONS\n    }\n    scp_open",
        "replace": "        for action in INVOKE_SOURCE_SCP_ACTIONS[:1]\n    }\n    scp_open",
    },
    {
        "name": "SM-11 invoke leg fails the root user on an unread SCP",
        "file": SAGEMAKER,
        "defect": "an SCP the check could not read may hold the root user, so a Failed claims what was not established",
        "find": '    elif not open_principals and any(\n        leg["state"] in INVOKE_SOURCE_SCP_UNDETERMINED',
        "replace": '    elif False and any(\n        leg["state"] in INVOKE_SOURCE_SCP_UNDETERMINED',
    },
    {
        "name": "SM-11 identity Deny on one invoke action holds the principal",
        "file": SAGEMAKER,
        "defect": "a Deny on InvokeEndpoint alone leaves InvokeEndpointAsync and InvokeEndpointWithResponseStream callable from any network, so the principal is not held to the private path",
        "find": "            open_actions = unpinned_actions - denied_actions\n",
        "replace": "            open_actions = set() if denied_actions else unpinned_actions\n",
    },
    {
        "name": "SM-11 invoke leg ignores an attached SCP",
        "file": SAGEMAKER,
        "defect": "an attached SCP Deny binds every principal, the root user included, so ignoring it fails a compliant account",
        "find": "    if not scp_open:\n        policies = sorted(",
        "replace": "    if False:\n        policies = sorted(",
    },
    {
        "name": "SM-37 reads only the latest AgentCore runtime version",
        "file": SAGEMAKER,
        "defect": "each runtime version carries its own networkConfiguration, so an older version an endpoint serves on other subnets or in PUBLIC mode goes unjudged",
        "find": "        for version in sorted(served - {latest}):\n",
        "replace": "        for version in sorted(set()):\n",
    },
    {
        "name": "SM-37 ignores an endpoint's targetVersion",
        "file": SAGEMAKER,
        "defect": "an endpoint mid-update serves its targetVersion next, so its network is in scope",
        "find": '                    for field in ("liveVersion", "targetVersion"):\n                        if endpoint.get(field):\n                            served.add(str(endpoint[field]))\n',
        "replace": '                    for field in ("liveVersion",):\n                        if endpoint.get(field):\n                            served.add(str(endpoint[field]))\n',
    },
    {
        "name": "SM-37 passes on unlisted AgentCore runtime endpoints",
        "file": SAGEMAKER,
        "defect": "a failed ListAgentRuntimeEndpoints leaves the served versions unread",
        "find": '            unread.append(\n                f"the endpoints of {label}, so the versions they serve "\n',
        "replace": '            [].append(\n                f"the endpoints of {label}, so the versions they serve "\n',
    },
    {
        "name": "SM-37 drops a served AgentCore version it could not read",
        "file": SAGEMAKER,
        "defect": "a served version GetAgentRuntime did not return has no network read",
        "find": '                unread.append(\n                    f"{label} version {version} (bedrock-agentcore:GetAgentRuntime: "\n',
        "replace": '                [].append(\n                    f"{label} version {version} (bedrock-agentcore:GetAgentRuntime: "\n',
    },
    {
        "name": "SM-11 lists only the $LATEST Lambda version",
        "file": SAGEMAKER,
        "defect": "a published version keeps its own Role and VpcConfig, so reading $LATEST alone leaves a version outside a VPC unjudged",
        "find": "    functions, lambda_unread = _lambda_functions(region, all_versions=True)\n    unread.extend(lambda_unread)\n    granted_functions = []\n",
        "replace": "    functions, lambda_unread = _lambda_functions(region)\n    unread.extend(lambda_unread)\n    granted_functions = []\n",
    },
    {
        "name": "SM-11 skips every version of a named Lambda function",
        "file": SAGEMAKER,
        "defect": "an agent names the unqualified function, which runs $LATEST, so its published versions still need judging by grant",
        "find": '            version == "$LATEST" and str(arn).rsplit(":", 1)[0] in named\n',
        "replace": '            str(arn).rsplit(":", 1)[0] in named\n',
    },
    {
        "name": "SM-02 never marks a Lambda target AI by grant",
        "file": SAGEMAKER,
        "defect": "an API fronting a Lambda function whose role may invoke a model passes unseen",
        "find": '        target = _ai_integration_target(method["uri"], ai_functions, granted)\n',
        "replace": '        target = _ai_integration_target(method["uri"], ai_functions)\n',
    },
    {
        "name": "SM-02 reads only the $LATEST role of a Lambda target",
        "file": SAGEMAKER,
        "defect": "an alias can run a published version whose role differs from $LATEST",
        "find": "    functions, lambda_unread = _lambda_functions(region, all_versions=True)\n    unread.extend(lambda_unread)\n    if lambda_unread:\n",
        "replace": "    functions, lambda_unread = _lambda_functions(region)\n    unread.extend(lambda_unread)\n    if lambda_unread:\n",
    },
    {
        "name": "SM-02 drops a Lambda target ListFunctions did not return",
        "file": SAGEMAKER,
        "defect": "a target in another account or Region has no role read, so dropping it lets the leg pass",
        "find": "        if arn not in versions:\n            unread.append(\n",
        "replace": "        if arn not in versions:\n            [].append(\n",
    },
    {
        "name": "SM-02 passes on a failed Lambda listing",
        "file": SAGEMAKER,
        "defect": "a failed ListFunctions leaves every unnamed Lambda target unjudged",
        "find": "    unread.extend(lambda_unread)\n    if lambda_unread:\n        return {}\n",
        "replace": "    if lambda_unread:\n        return {}\n",
    },
    {
        "name": "SM-02 passes without the cache on an unnamed Lambda target",
        "file": SAGEMAKER,
        "defect": "without the IAM cache no Lambda target can be marked AI by grant, so the leg is unread",
        "find": "    if unnamed and permission_cache is None:\n        unread.append(\n",
        "replace": "    if unnamed and permission_cache is None:\n        [].append(\n",
    },
    {
        "name": "SM-22 drops shadow variants from the deployed-model trace",
        "file": SAGEMAKER,
        "defect": "a shadow variant serves a copy of live traffic, so skipping it leaves a model on an unapproved package out of the deployed population",
        "find": '                (variant, " (shadow)")\n                for variant in config.get("ShadowProductionVariants") or []\n',
        "replace": '                (variant, " (shadow)")\n                for variant in []\n',
    },
    {
        "name": "SM-22 approver leg passes over unread versions",
        "file": SAGEMAKER,
        "defect": "a version DescribeModelPackage or ListModelPackages did not return has no approver read, so passing the leg credits it",
        "find": "                region,\n                versions_unread=len(unread),\n",
        "replace": "                region,\n                versions_unread=0,\n",
    },
    {
        "name": "SM-22 lifecycle leg passes over unread versions",
        "file": SAGEMAKER,
        "defect": "a version that was not read has no ModelLifeCycle read, so passing the leg credits it",
        "find": "                    region,\n                    versions_unread=len(unread),\n",
        "replace": "                    region,\n                    versions_unread=0,\n",
    },
    {
        "name": "SM-22 leaves ListModelPackages to its UNVERSIONED default",
        "file": SAGEMAKER,
        "defect": "ListModelPackages documents UNVERSIONED as the default type and a group holds versioned packages, so the default can return none of them",
        "find": 'ModelPackageGroupName=group_name, ModelPackageType="Both"',
        "replace": "ModelPackageGroupName=group_name",
    },
    {
        "name": "SM-31 passes an endpoint whose config was not read",
        "file": SAGEMAKER,
        "defect": "a denied DescribeEndpointConfig leaves the capture modes unknown, so crediting them puts an unread endpoint in the Passed count",
        "find": "                        continue\n                    modes = {\n",
        "replace": '                        config = {"DataCaptureConfig": {"CaptureOptions": [{"CaptureMode": "InputAndOutput"}]}}\n                    modes = {\n',
    },
    {
        "name": "SM-09 holds no Studio domain or update action",
        "file": SAGEMAKER,
        "defect": "UpdateNotebookInstance can turn RootAccess back on and "
        "CreateDomain or UpdateDomain can open a domain to the internet, so a "
        "bar on CreateNotebookInstance alone passes Studio unexamined",
        "find": (
            '            "sagemaker:CreateNotebookInstance",\n'
            '            "sagemaker:UpdateNotebookInstance",\n'
            '            "sagemaker:CreateDomain",\n'
            '            "sagemaker:UpdateDomain",\n'
            '            "sagemaker:CreateUserProfile",\n'
            '            "sagemaker:UpdateUserProfile",\n'
        ),
        "replace": '            "sagemaker:CreateNotebookInstance",\n',
    },
    {
        "name": "SM-09 credits a key-group Deny with a weak half",
        "file": SAGEMAKER,
        "defect": "a Deny on aws:SourceIp and aws:SourceVpce together fires only "
        "when both are outside their approved values, so each condition must "
        "enforce on its own. Crediting a 0.0.0.0/0 range or a ForAnyValue half "
        "passes a presigned URL guard that admits every caller",
        "find": (
            '            == "enforced"\n            for operator, key, values in entries\n'
        ),
        "replace": (
            '            in ("enforced", "presence", "absent-open", "value")\n'
            "            for operator, key, values in entries\n"
        ),
    },
    {
        "name": "SM-33 exempts S3 interface endpoints from private DNS",
        "file": SAGEMAKER,
        "defect": "without private DNS a job resolves the default S3 hostname to "
        "the public service, so the interface endpoint carries none of its "
        "traffic. The exemption credits it as the private S3 path for training "
        "and transform jobs alike",
        "find": (
            '                    if vpce.get("VpcEndpointType") == "Interface" and (\n'
        ),
        "replace": (
            '                    if vpce.get("VpcEndpointType") == "Interface" '
            'and short != "s3" and (\n'
        ),
    },
    {
        "name": "SM-04 passes GuardDuty findings nobody reviewed",
        "file": SAGEMAKER,
        "defect": "an ACTIVE GuardDuty finding still in Workflow.Status NEW past "
        "the review window was never reviewed. Skipping the branch passes the "
        "review row over the stale findings GetFindings returned",
        "find": "    if stale:\n        oldest = stale[0]\n",
        "replace": "    if False:\n        oldest = stale[0]\n",
    },
    {
        "name": "SM-41 drops iot:RetainPublish from the device actions",
        "file": SAGEMAKER,
        "defect": "RetainPublish is a topic action of its own, so iot:Publish "
        "does not cover it. Without it a fleet-wide RetainPublish on topic/* "
        "passes as device-scoped",
        "find": '    "iot:retainpublish",\n',
        "replace": "",
    },
    {
        "name": "SM-41 credits a thing attribute two things share",
        "file": SAGEMAKER,
        "defect": "a thing attribute bounds a topic to one device only while no "
        "two things hold the same value. Ignoring the shared value passes a "
        "policy under which each of those devices reaches the others' topics",
        "find": "            if len(names) > 1:\n                shared.append(\n",
        "replace": "            if len(names) > 99:\n                shared.append(\n",
    },
    {
        "name": "SM-23 and SM-31 ignore composite alarm routing",
        "file": SAGEMAKER,
        "defect": "a drift or capture-disk alarm with no action of its own pages "
        "through a composite alarm whose rule ORs it in. Dropping the composite "
        "leg fails an endpoint whose alarms do reach an action",
        "find": (
            '        or (alarm.get("AlarmName") and actioned.get(alarm["AlarmName"]))\n'
        ),
        "replace": "        or False\n",
    },
    {
        "name": "SM-43 lets an IMDSv1 instance read the weights",
        "file": SAGEMAKER,
        "defect": "an EC2 instance whose role can read the artifact bucket and "
        "whose metadata service still answers without a session token hands the "
        "role's credentials to any request it serves. Skipping every instance "
        "passes the endpoint beside it",
        "find": (
            '            if options.get("HttpTokens") == "required":\n'
            "                continue\n"
        ),
        "replace": (
            '            if options.get("HttpTokens") != "never":\n'
            "                continue\n"
        ),
    },
    {
        "name": "SM-43 reads only the first instance",
        "file": SAGEMAKER,
        "defect": "the instance population is the whole DescribeInstances "
        "listing. Judging only the first instance passes an IMDSv1 instance that "
        "sorts after a compliant one",
        "find": "        for instance in instances:\n            profile_arn = str(",
        "replace": "        for instance in instances[:1]:\n            profile_arn = str(",
    },
    {
        "name": "SM-40 ignores the MicroVM resume hook",
        "file": SAGEMAKER,
        "defect": "a MicroVM resumed from a suspended state runs only its /resume "
        "hook, so an image version without one never re-fetches a rotated "
        "secret. Ignoring the hook passes every MicroVM image",
        "find": '        if hooks.get("resume") != "ENABLED":\n',
        "replace": "        if False:\n",
    },
    {
        "name": "SM-02 leaves IAM-authorized methods unjudged",
        "file": SAGEMAKER,
        "defect": "the execute-api:Invoke grants that split read from write are "
        "in the IAM cache. Sending IAM methods to the not-judged row hides a "
        "grant whose one pattern reaches both the read and the write method",
        "find": '        elif kind == "AWS_IAM" and permission_cache is not None:\n',
        "replace": "        elif False:\n",
    },
    {
        "name": "SM-02 lets a stage span a slash",
        "file": SAGEMAKER,
        "defect": "no stage name holds a slash, so a GET/* grant reaches no POST "
        "method. Letting the stage token take a slash reads a read-only grant as "
        "reaching the write method and fails it",
        "find": (
            '                here == "?" or token == EXECUTE_API_REST or here != "/"\n'
        ),
        "replace": "                True\n",
    },
    {
        "name": "SM-39 does not count an agent Lambda outside a VPC",
        "file": SAGEMAKER,
        "defect": "an agent Lambda function outside a VPC egresses with no DNS "
        "Firewall or Network Firewall in its path. Not counting it reports the "
        "Region as having no workload VPC to judge",
        "find": (
            '        elif not (function.get("VpcConfig") or {}).get("SubnetIds"):\n'
            "            open_functions.append("
        ),
        "replace": "        elif False:\n            open_functions.append(",
    },
    {
        "name": "SM-39 drops EKS cluster subnets",
        "file": SAGEMAKER,
        "defect": "an agent on EKS egresses from its cluster's subnets. Dropping "
        "them leaves the cluster's VPC without a DNS or Network Firewall row",
        "find": '            references.append((f"EKS cluster {cluster}", subnet_id))\n',
        "replace": "            pass\n",
    },
    {
        "name": "SM-33 and SM-11 credit private DNS in a VPC with DNS off",
        "file": SAGEMAKER,
        "defect": "private DNS creates no record for the default hostname in a "
        "VPC with enableDnsSupport or enableDnsHostnames false, so the job "
        "reaches the public service while the endpoint is credited",
        "find": "            if value is False:\n                dns_off",
        "replace": "            if False:\n                dns_off",
    },
    {
        "name": "SM-33 passes a VPC whose DNS attributes were not read",
        "file": SAGEMAKER,
        "defect": "a VPC whose DescribeVpcAttribute read failed is counted "
        "complete, so a failed read yields Passed",
        "find": (
            "        elif vpc_id in dns_unread:\n"
            "            unread.extend(dns_unread[vpc_id])"
        ),
        "replace": "        elif False:\n            unread.extend(dns_unread[vpc_id])",
    },
    {
        "name": "SM-33 reads only the first VPC's DNS attributes",
        "file": SAGEMAKER,
        "defect": "only the first VPC holding an interface endpoint is read, so "
        "a second VPC with DNS off passes",
        "find": "[vpc_id for vpc_id in sorted(present) if dns_served(vpc_id)]",
        "replace": "[vpc_id for vpc_id in sorted(present) if dns_served(vpc_id)][:1]",
    },
    {
        "name": "SM-18 holds a gateway-served S3 to the DNS attributes",
        "file": SAGEMAKER,
        "defect": "a service a gateway endpoint serves is reached by route, so "
        "failing its interface endpoint on the VPC DNS attributes is a false "
        "Failed",
        "find": (
            '            if not any(v.get("VpcEndpointType") == "Gateway" '
            "for v in vpces)\n"
        ),
        "replace": "            if True\n",
    },
    {
        "name": "SM-40 judges a DELETED MicroVM image",
        "file": SAGEMAKER,
        "defect": "an image in DELETED state is judged, so its versions fail a "
        "workload that was removed",
        "find": 'if i.get("state") != "DELETED"',
        "replace": "if True",
    },
    {
        "name": "SM-40 skips a DELETING MicroVM image",
        "file": SAGEMAKER,
        "defect": "an image still DELETING may hold ACTIVE versions RunMicrovm "
        "launches, so skipping it narrows the population",
        "find": 'i.get("state") != "DELETED"\n',
        "replace": 'i.get("state") not in ("DELETING", "DELETED")\n',
    },
    {
        "name": "SM-11 passes a runtime endpoint in a VPC with DNS off",
        "file": SAGEMAKER,
        "defect": "a sagemaker.runtime interface endpoint in a VPC with a DNS "
        "attribute false is credited, though no record maps the runtime "
        "hostname to it",
        "find": "    if dns_off:\n        off = [",
        "replace": "    if False:\n        off = [",
    },
    {
        "name": "SM-11 passes when a DNS attribute was not read",
        "file": SAGEMAKER,
        "defect": "a failed DescribeVpcAttribute read yields Passed",
        "find": (
            "    if dns_unread:\n        return [\n            "
            '_unread_resources_finding(\n                "SM-11"'
        ),
        "replace": (
            "    if False:\n        return [\n            "
            '_unread_resources_finding(\n                "SM-11"'
        ),
    },
    {
        "name": "SM-11 reads only the first VPC's DNS attributes",
        "file": SAGEMAKER,
        "defect": "only the first VPC holding a runtime endpoint is read, so a "
        "second VPC with DNS off passes",
        "find": "sorted({vpc for _, vpc in private if vpc not in gateway_vpcs}),",
        "replace": "sorted({vpc for _, vpc in private if vpc not in gateway_vpcs})[:1],",
    },
    {
        "name": "SM-41 credits a ForAllValues IsAttached condition",
        "file": SAGEMAKER,
        "defect": "ForAllValues is true on an absent key, so a Connect Allow under ForAllValues:Bool admits a certificate with no attached thing",
        "find": '        if operator_name.startswith("forallvalues:"):\n            continue\n',
        "replace": "",
    },
    {
        "name": "SM-36 passes the AI standard without FSBP",
        "file": SAGEMAKER,
        "defect": "the control asks for AWS Foundational Security Best Practices beside the AI standard; dropping the guard passes a Region running the AI standard alone",
        "find": "    if active and not fsbp_active:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "SM-36 passes central configuration without reading its policy",
        "file": SAGEMAKER,
        "defect": "an association names a policy whose standards are unread; treating a read that failed as an empty success passes a policy that may enable neither standard",
        "find": "        policy = client.get_configuration_policy(Identifier=policy_id).get(\n",
        "replace": "        policy = {'SecurityHub': {'ServiceEnabled': True, 'EnabledStandardIdentifiers': ['standards/ai-security-best-practices/v/1.0.0', 'standards/aws-foundational-security-best-practices/v/1.0.0']}} or client.get_configuration_policy(Identifier=policy_id).get(\n",
    },
    {
        "name": "SM-02 ignores the REST API resource policy",
        "file": SAGEMAKER,
        "defect": "a REST API resource policy grants execute-api:Invoke beside identity policies; dropping its problems passes a policy Allow over read and write AI methods",
        "find": "    problems += policy_problems\n",
        "replace": "",
    },
    {
        "name": "SM-39 skips standalone ECS tasks in segmentation",
        "file": SAGEMAKER,
        "defect": "a task started with RunTask belongs to no service, so its security groups go unjudged",
        "find": "        task_interfaces[_ecs_task_label(cluster_name, task)] = interfaces\n",
        "replace": "        pass\n",
    },
    {
        "name": "SM-39 passes a MicroVM with no egress connector in segmentation",
        "file": SAGEMAKER,
        "defect": "a MicroVM without an egress connector leaves on the default internet egress, which no security group bounds",
        "find": '            elif workload.get("microvm"):\n                open_microvms.append(workload["label"])\n',
        "replace": '            elif workload.get("microvm"):\n                pass\n',
    },
    {
        "name": "SM-39 passes a MicroVM with shell ingress",
        "file": SAGEMAKER,
        "defect": "SHELL_INGRESS opens the MicroVM to an interactive shell; not recording it passes the ingress leg",
        "find": "        if MICROVM_SHELL_INGRESS in connectors:\n            shell.append(label)\n",
        "replace": "        if MICROVM_SHELL_INGRESS in connectors:\n            pass\n",
    },
    {
        "name": "SM-39 drops standalone ECS task subnets from egress",
        "file": SAGEMAKER,
        "defect": "a standalone task egresses from its own subnets, so dropping them leaves its VPC without a DNS or Network Firewall row",
        "find": "            references.append((_ecs_task_label(cluster_name, task), subnet_id))\n",
        "replace": "            pass\n",
    },
    {
        "name": "SM-39 drops Fargate profile subnets from egress",
        "file": SAGEMAKER,
        "defect": "a Fargate pod egresses from its profile's subnets, which may lie outside the cluster's own",
        "find": '                    references.append(\n                        (f"EKS Fargate profile {profile} of {cluster}", subnet_id)\n                    )\n',
        "replace": "                    pass\n",
    },
    {
        "name": "SM-39 drops MicroVM connector subnets from the firewall leg",
        "file": SAGEMAKER,
        "defect": "a MicroVM egresses through its connector's subnets, so dropping them leaves that VPC without a Network Firewall row",
        "find": "                firewall_references.append(\n",
        "replace": "                (lambda *_: None)(\n",
    },
    {
        "name": "SM-39 passes a MicroVM with no egress connector on the firewall leg",
        "file": SAGEMAKER,
        "defect": "a MicroVM without an egress connector reaches the internet through no Network Firewall",
        "find": '        for microvm in microvms\n        if not microvm["egress"]\n    ]\n',
        "replace": "        for microvm in microvms\n        if False\n    ]\n",
    },
    {
        "name": "SM-39 credits a function VPC deny for network connectors",
        "file": SAGEMAKER,
        "defect": "the connector guardrail must deny lambda:CreateNetworkConnector; judging lambda:CreateFunction credits the function VPC deny for connectors",
        "find": '                "lambda:CreateNetworkConnector",\n                ("lambda:SubnetIds", "lambda:SecurityGroupIds"),\n',
        "replace": '                "lambda:CreateFunction",\n                ("lambda:SubnetIds", "lambda:SecurityGroupIds"),\n',
    },
    {
        "name": "SM-40 skips standalone ECS tasks",
        "file": SAGEMAKER,
        "defect": "a task started outside a service resolves its secrets at start too, so skipping it passes a stale rotating secret",
        "find": '                task.get("taskDefinitionArn"),\n                overrides,\n            )\n        )\n    for label, arn, overrides in ecs_workloads:\n',
        "replace": '                task.get("taskDefinitionArn"),\n                overrides,\n            )\n        ) if False else None\n    for label, arn, overrides in ecs_workloads:\n',
    },
    {
        "name": "SM-40 ignores a task override's environment",
        "file": SAGEMAKER,
        "defect": "RunTask can override a container's environment with a plaintext credential the task definition does not hold",
        "find": '                *overrides.get(str(container.get("name")), []),\n',
        "replace": "",
    },
    {
        "name": "SM-11 drops Lambda functions granted AI invoke",
        "file": SAGEMAKER,
        "defect": "no Lambda field marks AI compute, so a function whose role may invoke a model is AI by grant; dropping it passes one outside a VPC",
        "find": "        if actions:\n            granted_functions.append(\n",
        "replace": "        if False:\n            granted_functions.append(\n",
    },
    {
        "name": "SM-11 drops ECS workloads granted AI invoke",
        "file": SAGEMAKER,
        "defect": "an ECS service or task whose task role may invoke a model is AI compute; dropping it passes one in a public subnet",
        "find": "    attached.extend(ecs_workloads)\n",
        "replace": "",
    },
    {
        "name": "SM-11 ignores a task's overridden task role",
        "file": SAGEMAKER,
        "defect": "RunTask can override the task role, so the role in the task definition is not the one the task runs as",
        "find": "        role = override_role or task_role(arn, label)\n",
        "replace": "        role = task_role(arn, label)\n",
    },
    {
        "name": "SM-39 does not follow a transit gateway route",
        "file": SAGEMAKER,
        "defect": "a hosting VPC whose only internet route names a transit gateway, the centralized inspection pattern, is never judged: the route reads as not followed and every such VPC is N/A",
        "find": '            elif key == "TransitGatewayId":\n',
        "replace": '            elif key == "TransitGatewayId-NOT-A-KEY":\n',
    },
    {
        "name": "SM-39 passes a hub firewall with no HOME_NET",
        "file": SAGEMAKER,
        "defect": "an unset HOME_NET is the firewall's own VPC, so a firewall a transit gateway reaches in another VPC inspects none of the hosting subnets' traffic with its allow-list, and the row passes it",
        "find": "    if allow_groups and remote_vpc and not definitions:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "SM-39 loses a transit gateway hop to an internet gateway",
        "file": SAGEMAKER,
        "defect": "an inspection VPC whose attachment subnet routes straight to an internet gateway bypasses every Network Firewall. Read as not followed, that bypass is reported N/A instead of Failed",
        "find": '                        hops.append(("bypassing", text, {}))\n',
        "replace": '                        hops.append(("unresolved", text, {}))\n',
    },
    {
        "name": "SM-39 follows a blackhole transit gateway route",
        "file": SAGEMAKER,
        "defect": "a blackhole route sends nothing, so following it judges a path no traffic takes and fails a VPC whose active route is inspected",
        "find": '            "Filters": [{"Name": "state", "Values": ["active"]}],\n',
        "replace": '            "Filters": [{"Name": "state", "Values": ["active", "blackhole"]}],\n',
    },
    {
        "name": "SM-39 trusts a truncated transit gateway route search",
        "file": SAGEMAKER,
        "defect": "SearchTransitGatewayRoutes returns at most 1,000 routes and reports AdditionalRoutesAvailable past that, so the route the traffic takes may be one the search did not return",
        "find": "    if truncated:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "SM-39 follows another account's VPC attachment",
        "file": SAGEMAKER,
        "defect": "this account cannot read another account's route tables or firewalls, so a VPC attachment owned elsewhere is judged on a read that describes no such VPC here",
        "find": '            if not owner or owner != attachment.get("ResourceOwnerId"):\n',
        "replace": "            if not owner:\n",
    },
    {
        "name": "SM-39 reads only the first transit gateway route page",
        "file": SAGEMAKER,
        "defect": "SearchTransitGatewayRoutes pages by NextToken, so a first-page reader misses the internet route on a later page",
        "find": '                request["NextToken"] = response["NextToken"]\n',
        "replace": "                break\n",
    },
    {
        "name": "SM-39 sync row ignores names only the DNS Firewall admits",
        "file": SAGEMAKER,
        "defect": "a name the DNS Firewall answers that no Network Firewall ALLOWLIST target admits is held by one layer, which the recommendation to keep the lists in sync rules out",
        "find": "        if dns_only:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "SM-39 sync row ignores targets only the Network Firewall admits",
        "file": SAGEMAKER,
        "defect": "a Network Firewall target the DNS Firewall does not answer is held by one layer, so the allow-lists differ and the row passes them",
        "find": "        if nfw_only:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "SM-39 drops the action of a denied transit gateway read",
        "file": SAGEMAKER,
        "defect": "a denied hop read leaves the route unjudged, and without its own row the VPC reads as reaching no firewall, naming no grant to retry",
        "find": '                except _HopReadError as error:\n                    return _not_read(\n                        f"{subject} was not judged: {error.text}.", error.action\n                    )\n',
        "replace": "                except _HopReadError:\n                    continue\n",
    },
    {
        "name": "SM-39 sync: an earlier BLOCK does not withdraw a name",
        "file": SAGEMAKER,
        "defect": "a name an earlier DNS Firewall BLOCK refuses was still counted as answered, so a Network Firewall allow-list that correctly omits it failed the row",
        "find": "                    if domain in allowed or _domain_patterns_cover(\n",
        "replace": "                    if domain in allowed or False and _domain_patterns_cover(\n",
    },
    {
        "name": "SM-39 sync: a wildcard BLOCK is matched literally",
        "file": SAGEMAKER,
        "defect": "an earlier DNS Firewall BLOCK on *.example.com withdrew only the entry *.example.com, so the subdomains it refuses counted as allowed",
        "find": "                blocked.extend(_domain_pattern(domain, False) for domain in domains)\n",
        "replace": "                blocked.extend((domain, True, False) for domain in domains)\n",
    },
    {
        "name": "SM-39 sync: an allowed wildcard is compared whole",
        "file": SAGEMAKER,
        "defect": "an allowed *.example.com counted every subdomain as answered, so a firewall target a.example.com that an earlier BLOCK refuses read as in sync",
        "find": "            if not _dns_allow_list_covers(names, pattern)\n",
        "replace": "            if not _domain_patterns_cover(dns_patterns, pattern)\n",
    },
    {
        "name": "SM-39 sync: a BLOCK inside an allowed wildcard is not recorded",
        "file": SAGEMAKER,
        "defect": "an earlier BLOCK on a name under an allowed wildcard was dropped, so the refused name counted as answered",
        "find": '                        if subdomains and pattern[0].endswith("." + base)\n',
        "replace": "                        if False\n",
    },
    {
        "name": "SM-39 sync: a refused part another ALLOW answers is not rescued",
        "file": SAGEMAKER,
        "defect": "a name an earlier ALLOW answers ahead of the BLOCK was read as refused, failing an allow-list that is in sync",
        "find": "                    answered(part) if exact else subdomains_answered(part)\n",
        "replace": "                    False\n",
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
        "find": "        elif metric_error or untied or tie_unlisted:\n",
        "replace": "        elif metric_error or tie_unlisted:\n",
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
        "name": "AC-53 passes a pair with no message rate alarm",
        "file": AGENTCORE,
        "defect": "a pair alarmed on latency and errors passed with no band over its Latency SampleCount, so a change in how often the agents call each other notified nobody",
        "find": "                    APPLICATION_SIGNALS_RATE_LABEL in watched,\n",
        "replace": "                    True,\n",
    },
    {
        "name": "AC-53 credits a SampleCount band as latency",
        "file": AGENTCORE,
        "defect": "a band over the pair's Latency SampleCount counts calls, and was credited as watching how long the pair takes",
        "find": '                ("Latency", "how long that pair takes", "Latency" in watched),\n',
        "replace": '                ("Latency", "how long that pair takes", bool(watched & {"Latency", APPLICATION_SIGNALS_RATE_LABEL})),\n',
    },
    {
        "name": "AC-53 reads an Error SampleCount band as the message rate",
        "file": AGENTCORE,
        "defect": "a SampleCount band over the pair's Error metric was credited as the Latency SampleCount message rate",
        "find": '            if metric_name == "Latency" and stat == "SampleCount":\n',
        "replace": '            if stat == "SampleCount":\n',
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
        "name": "AC-27 credits a source ARN in another account",
        "file": AGENTCORE,
        "defect": "an aws:SourceArn naming a resource in another account names nothing this account owns, and passed as the invoking resource",
        "find": "\n        and parts[4] == account_id\n        and bool(parts[5])\n",
        "replace": "\n        and bool(parts[5])\n",
    },
    {
        "name": "AC-27 credits a wildcard source ARN",
        "file": AGENTCORE,
        "defect": "an aws:SourceArn with a wildcard in any segment matches more than the one invoking resource, and passed as naming it",
        "find": '\n    if any(token in value for token in ("*", "?", "${")):\n        return False\n    parts = value.split(":", 5)\n',
        "replace": '\n    parts = value.split(":", 5)\n',
    },
    {
        "name": "AC-27 credits a policy variable in a source ARN",
        "file": AGENTCORE,
        "defect": "a policy variable in aws:SourceArn resolves per request, so the value names no one resource",
        "find": '\n    if any(token in value for token in ("*", "?", "${")):\n',
        "replace": '\n    if any(token in value for token in ("*", "?")):\n',
    },
    {
        "name": "AC-45 ignores an invoker Deny on a named resource",
        "file": AGENTCORE,
        "defect": "an invoker whose unconditioned Deny names the very resource the tool role grants lacks that grant, and still counted as holding it",
        "find": "\n                    _grant_survives(permissions, action, resource)\n",
        "replace": "\n                    _grant_survives(permissions, action)\n",
    },
    {
        "name": "AC-45 subtracts a conditioned invoker Deny",
        "file": AGENTCORE,
        "defect": "a conditioned Deny may never fire, so subtracting it fails an invoker who may hold the grant",
        "find": "\n    return any(\n        not _statement_condition_keys(statement)\n        and _deny_overlaps_grant(statement, action, resource)\n",
        "replace": "\n    return any(\n        _deny_overlaps_grant(statement, action, resource)\n",
    },
    {
        "name": "AC-45 drops the conditioned invoker Deny from the text",
        "file": AGENTCORE,
        "defect": "a conditioned Deny the comparison does not subtract went unnamed, so the Passed text claimed every invoker held the grant",
        "find": "\n        if any(\n            _statement_condition_keys(statement)\n            and _deny_overlaps_grant(statement, action, resource)\n",
        "replace": "\n        if any(\n            False\n            and _deny_overlaps_grant(statement, action, resource)\n",
    },
    {
        "name": "AC-45 reads an invoker NotResource Deny as reaching nothing",
        "file": AGENTCORE,
        "defect": "a NotResource Deny applies to every resource it does not exclude, so an invoker denied the tool role's resource by one still passed",
        "find": "\n    return not any(_resource_pattern_covers(str(p), resource) for p in excluded)\n",
        "replace": "\n    return False\n",
    },
    {
        "name": "AC-45 compares invoker Deny ARNs case-insensitively",
        "file": AGENTCORE,
        "defect": "IAM compares ARNs case-sensitively, so a Deny on a bucket whose name differs only in case removed a grant it never reaches",
        "find": "\n            _action_patterns_overlap(denied, resource, ignore_case=False)\n",
        "replace": "\n            _action_patterns_overlap(denied, resource)\n",
    },
    {
        "name": "AC-45 reads an invoker boundary by action only",
        "file": AGENTCORE,
        "defect": "a boundary that allows the tool role's action on another resource, or only under a condition, withholds the grant, and the invoker still counted as holding it",
        "find": "\n            boundary is None\n            or any(\n",
        "replace": "\n            True\n            or any(\n",
    },
    {
        "name": "AC-45 counts an invoker whose boundary withholds the start action",
        "file": AGENTCORE,
        "defect": "a principal whose permissions boundary allows no session start cannot run code with the tool role, and was held to it as an invoker",
        "find": "\n                or not _grant_survives(permissions, start_action)\n",
        "replace": "\n",
    },
    {
        "name": "AC-45 counts an invoker denied this tool",
        "file": AGENTCORE,
        "defect": "a principal whose unconditioned Deny names this tool cannot start its sessions, and was held to the tool role as an invoker",
        "find": "\n                or _unconditioned_deny_reaches(permissions, start_action, tool_arn)\n",
        "replace": "\n",
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
        "find": '    "The agent\'s code that agentRuntimeArtifact names in S3 is judged in the "\n',
        "replace": '    "The agent\'s code is not readable through any API; in S3 it is judged in the "\n',
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
        "find": '        if not statement.get("Condition"):\n            return "failed", (\n                f"a Deny in {source} refuses execution role {role_name} "\n                f"{spelling} on recording key',
        "replace": '        if False:\n            return "failed", (\n                f"a Deny in {source} refuses execution role {role_name} "\n                f"{spelling} on recording key',
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
        "find": '    if (\n        boundary is not None\n        and not allows(boundary_statements, "the permissions boundary")\n        and len(conditional) == before\n    ):\n        return "failed", (\n            f"the permissions boundary of execution role {role_name} does not "\n            f"allow {spelling} on recording key',
        "replace": '    if (\n        False\n        and not allows(boundary_statements, "the permissions boundary")\n        and len(conditional) == before\n    ):\n        return "failed", (\n            f"the permissions boundary of execution role {role_name} does not "\n            f"allow {spelling} on recording key',
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
        "find": "                for arn in key_arns\n                for spelling, action, _ in RECORDING_KEY_WRITE_ACTIONS\n",
        "replace": "                for arn in []\n                for spelling, action, _ in RECORDING_KEY_WRITE_ACTIONS\n",
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
        "find": "                missing = fields - tools.get(action, set())\n",
        "replace": "                missing = set(fields)\n",
    },
    {
        "name": "AC-35 input guard reads a bare action as no tool",
        "file": AGENTCORE,
        "defect": "a forbid over every action reading an input optional on one tool passed",
        "find": "                in_scope = sorted(tools) + sorted(unproven)\n",
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
        "find": '                    definitions = json.loads(_s3_schema_text(schema["s3"]))\n',
        "replace": "                    definitions = []\n",
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
        "find": '            for _, label in fronting\n        ]\n    if state != "ACTIVE":\n',
        "replace": '            for _, label in fronting\n        ]\n    if state not in ("ACTIVE", "INACTIVE"):\n',
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
    {
        "name": "AC-22 viewing: an Action wildcard is not a defect",
        "file": AGENTCORE,
        "defect": "a monitoring-account viewer granted logs:* passed",
        "find": "            if wildcards:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "AC-06 recording key: kms:Decrypt is not required",
        "file": AGENTCORE,
        "defect": "a recording role without kms:Decrypt passed the multipart write",
        "find": '    (\n        "kms:Decrypt",\n        RECORDING_KEY_DECRYPT_ACTION,\n        "a multipart upload of a recording fails",\n    ),\n)\n',
        "replace": ")\n",
    },
    {
        "name": "AC-26 archive: the model invocation log group is not read",
        "file": AGENTCORE,
        "defect": "the model invocation log group was left out of the archive population",
        "find": "                | invocation_names\n",
        "replace": "",
    },
    {
        "name": "AC-26 archive: a logs destination is not followed",
        "file": AGENTCORE,
        "defect": "a subscription filter to a logs destination was never judged",
        "find": "    return findings + _log_archive_destination_findings(stream_cache, lock_cache)\n",
        "replace": "    return findings\n",
    },
    {
        "name": "AC-38 prerequisite: an unconditioned forbid does not block",
        "file": AGENTCORE,
        "defect": "a prior response blocked by an unconditioned forbid passed",
        "find": "            if blockers:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "AC-35 input guard: a nested read is judged at its top level",
        "file": AGENTCORE,
        "defect": "a forbid reading an optional nested field of a required object passed",
        "find": '    return [".".join(segments[:index]) for index in range(1, len(segments) + 1)]\n',
        "replace": "    return segments[:1]\n",
    },
    {
        "name": "AC-35 input guard: a named OpenAPI or Smithy operation is not judged",
        "file": AGENTCORE,
        "defect": "a forbid reading an optional OpenAPI input passed",
        "find": "                    if action in tools or action in unproven\n",
        "replace": "                    if action in tools\n",
    },
    {
        "name": "AC-51 Firewall Manager: any value of the managed flag counts",
        "file": AGENTCORE,
        "defect": "a web ACL Firewall Manager does not manage passed",
        "find": "            if web_acl.get(field) is True\n",
        "replace": "            if web_acl.get(field) is not None\n",
    },
    {
        "name": "AC-51 SRT: a pending proactive engagement counts",
        "file": AGENTCORE,
        "defect": "Shield proactive engagement that is not ENABLED passed",
        "find": '    if status == "ENABLED":\n',
        "replace": '    if status != "DISABLED":\n',
    },
    {
        "name": "AC-49 alert log: a firewall with no ALERT log is not a gap",
        "file": AGENTCORE,
        "defect": "a firewall that keeps no ALERT log passed the threat row",
        "find": "                if NETWORK_FIREWALL_ALERT_LOG_TYPE not in {\n",
        "replace": "                if False and {\n",
    },
    {
        "name": "AC-01 ports: a range from port 1 is not every port",
        "file": AGENTCORE,
        "defect": "an egress rule allowing TCP 1-65535 passed",
        "find": "                and int(from_port) <= 1\n",
        "replace": "                and int(from_port) <= 0\n",
    },
    {
        "name": "AC-48 analyzer: a tag exclusion still covers every role",
        "file": AGENTCORE,
        "defect": "an unused access analyzer excluding a resource tag passed every role",
        "find": '            elif any(exclusion.get("resourceTags") for exclusion in exclusions):\n',
        "replace": "            elif False:\n",
    },
    {
        "name": "AC-41 personal data: a digit run is a card without Luhn",
        "file": AGENTCORE,
        "defect": "a 16-digit number failing Luhn was reported as a card",
        "find": "        13 <= len(digits) <= 19 and _luhn_valid(digits)\n",
        "replace": "        13 <= len(digits) <= 19\n",
    },
    {
        "name": "AC-41 personal data: evaluator tags are not scanned",
        "file": AGENTCORE,
        "defect": "an evaluator tag holding an email passed",
        "find": '                agentcore_client.list_tags_for_resource(resourceArn=arn).get("tags")\n',
        "replace": "                {}\n",
    },
    {
        "name": "AC-34 image: only the first platform of an index is read",
        "file": AGENTCORE,
        "defect": "an image index whose second platform holds a credential passed",
        "find": '        manifests = [manifest({"imageDigest": digest})[1] for digest in children]\n',
        "replace": '        manifests = [manifest({"imageDigest": digest})[1] for digest in children[:1]]\n',
    },
    {
        "name": "AC-34 image: Entrypoint and Cmd are not scanned",
        "file": AGENTCORE,
        "defect": "an image whose Cmd holds an access key ID passed",
        "find": "            if _text_holds_a_credential(text) and field not in found:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "AC-34 image: another account's registry is read",
        "file": AGENTCORE,
        "defect": "an image in another account's registry was fetched with this account's reads",
        "find": "            if account and registry != account:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "AC-34 code: files are not matched for credentials",
        "file": AGENTCORE,
        "defect": "a code archive file holding an access key ID passed",
        "find": "    found = [path] if _text_holds_a_credential(text) else []\n",
        "replace": "    found = []\n",
    },
    {
        "name": "AC-34 code: a .env file's variables are not judged",
        "file": AGENTCORE,
        "defect": "a .env file in the code archive holding a credential passed",
        "find": '        found.extend(f"{path} variable {name}" for name in literals)\n',
        "replace": "        pass\n",
    },
    {
        "name": "AC-34 code: the unpacked bound is not enforced",
        "file": AGENTCORE,
        "defect": "an archive unpacking past its bound was scanned and passed",
        "find": "            if unpacked > AC34_CODE_UNPACKED_MAX_BYTES:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "AC-35 input guard: an S3 schema is not held to its owner",
        "file": AGENTCORE,
        "defect": "an S3 tool schema was read without the bucket owner the target names",
        "find": "        expected_owner=owner if isinstance(owner, str) else None,\n",
        "replace": "        expected_owner=None,\n",
    },
    {
        "name": "AC-27 credits an address-only Deny as a private path",
        "file": AGENTCORE,
        "defect": "a gateway policy Deny keyed only on aws:SourceIp passed the network leg, leaving the gateway reachable from a listed public address",
        "find": "        PRIVATE_NETWORK_PATH_CONDITION_KEYS,\n        _network_values_are_bounded,\n        exempt_aws_service=True,\n    )\n    address_keys, address_gaps = _resource_policy_restriction(\n",
        "replace": "        NETWORK_PATH_CONDITION_KEYS,\n        _network_values_are_bounded,\n        exempt_aws_service=True,\n    )\n    address_keys, address_gaps = _resource_policy_restriction(\n",
    },
    {
        "name": "AC-47 credits an address-only Deny as a private path",
        "file": AGENTCORE,
        "defect": "a runtime policy Deny keyed only on aws:SourceIp passed the network leg, leaving the runtime reachable from a listed public address",
        "find": "            PRIVATE_NETWORK_PATH_CONDITION_KEYS,\n            _network_values_are_bounded,\n            exempt_aws_service=True,\n        )\n        address_keys, address_gaps, _ = _runtime_invoke_restriction(\n",
        "replace": "            NETWORK_PATH_CONDITION_KEYS,\n            _network_values_are_bounded,\n            exempt_aws_service=True,\n        )\n        address_keys, address_gaps, _ = _runtime_invoke_restriction(\n",
    },
    {
        "name": "AC-40 safety: an unlisted safety score is not required",
        "file": AGENTCORE,
        "defect": "a configuration passed on a tool-choice alarm while ListMetrics listed no score for a named safety evaluator",
        "find": "                    if unlisted:\n                        tie_unlisted.extend(unlisted)\n",
        "replace": "                    if False:\n                        tie_unlisted.extend(unlisted)\n",
    },
    {
        "name": "AC-34 image: file system layers are not scanned",
        "file": AGENTCORE,
        "defect": "an image whose layer holds an access key ID in a file passed",
        "find": "    for layer_digest in layers:\n",
        "replace": "    for layer_digest in []:\n",
    },
    {
        "name": "AC-34 image: the unpacked layer bound is not enforced",
        "file": AGENTCORE,
        "defect": "an image whose layers unpack past the bound was scanned and passed",
        "find": "                    if unpacked[0] > AC34_IMAGE_UNPACKED_MAX_BYTES:\n",
        "replace": "                    if False:\n",
    },
    {
        "name": "AC-34 image: the compressed layer bound is not enforced",
        "file": AGENTCORE,
        "defect": "an image whose layers exceed the compressed bound was fetched and passed",
        "find": "    if compressed > AC34_IMAGE_LAYERS_MAX_BYTES:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-35 input guard: an MCP server's inline tool schema is not read",
        "file": AGENTCORE,
        "defect": "an MCP server target whose inline tool schema leaves a required input unguarded passed",
        "find": '                    definitions = _mcp_tool_definitions(\n                        json.loads(tool_schema.get("inlinePayload") or "")\n                    )\n',
        "replace": "                    definitions = []\n",
    },
    {
        "name": "AC-35 input guard: an MCP server with no static schema is not named",
        "file": AGENTCORE,
        "defect": "an MCP server target whose tools are discovered at run time was not reported as unread",
        "find": "            elif isinstance(server, dict):\n                unread[name] = (\n",
        "replace": "            elif False:\n                unread[name] = (\n",
    },
    {
        "name": "AC-26 credits an archive bucket the assessed account owns",
        "file": AGENTCORE,
        "defect": "a locked archive bucket in the assessed account passed as a separate Log Archive copy",
        "find": '    if owned:\n        return "bad", (\n',
        "replace": '    if False:\n        return "bad", (\n',
    },
    {
        "name": "AC-26 reads an unread bucket owner as another account",
        "file": AGENTCORE,
        "defect": "an owner read that failed for a reason other than the owner mismatch passed",
        "find": '                lock_cache[owner_key] = ("error", _assessment_error_label(error))\n',
        "replace": '                lock_cache[owner_key] = ("read", False)\n',
    },
    {
        "name": "AC-26 holds a destination's own bucket to another account",
        "file": AGENTCORE,
        "defect": "the Log Archive account's destination failed for owning its own archive bucket",
        "find": "            separate_account=False,\n",
        "replace": "            separate_account=True,\n",
    },
    {
        "name": "AC-49 egress: a transit gateway route is not followed",
        "file": AGENTCORE,
        "defect": "a hosting subnet routing to a transit gateway whose inspection VPC reaches an internet gateway read N/A instead of Failed",
        "find": '                elif key == "TransitGatewayId":\n',
        "replace": "                elif False:\n",
    },
    {
        "name": "AC-49 egress: a remote firewall's unset HOME_NET is credited",
        "file": AGENTCORE,
        "defect": "an inspection-VPC firewall with no HOME_NET passed its allow-list over hosting subnets it does not inspect",
        "find": "    if allow_groups and remote_vpc and not definitions:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-49 egress: another account's inspection VPC is followed",
        "file": AGENTCORE,
        "defect": "a transit gateway attachment of a VPC in another account was judged on routes this account read under its own name",
        "find": '            if not owner or owner != attachment.get("ResourceOwnerId"):\n',
        "replace": "            if not owner:\n",
    },
    {
        "name": "AC-49 egress: a non-VPC transit gateway attachment is followed",
        "file": AGENTCORE,
        "defect": "a transit gateway route to a VPN attachment was followed as if it were a VPC",
        "find": '            if kind != "vpc":\n',
        "replace": "            if False:\n",
    },
    {
        "name": "AC-49 egress: a truncated transit gateway route search is trusted",
        "file": AGENTCORE,
        "defect": "a route table search that reported more routes than it returned was judged on the routes it returned",
        "find": "    if truncated:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-49 egress: a failed transit gateway read is not reported",
        "file": AGENTCORE,
        "defect": "a denied transit gateway read produced egress rows instead of N/A naming the action",
        "find": "        if tgw_error:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "AC-49 sync: a DNS name the firewall allow-list omits is not named",
        "file": AGENTCORE,
        "defect": "a DNS Firewall allow-list admitting a name the Network Firewall ALLOWLIST omits passed the sync row",
        "find": "            if dns_only:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "AC-49 sync: a firewall target the DNS allow-list omits is not named",
        "file": AGENTCORE,
        "defect": "a Network Firewall ALLOWLIST admitting a target the DNS Firewall allow-list omits passed the sync row",
        "find": "            if nfw_only:\n",
        "replace": "            if False:\n",
    },
    {
        "name": "AC-49 sync: an earlier BLOCK does not withdraw a name",
        "file": AGENTCORE,
        "defect": "a name an earlier DNS Firewall BLOCK refuses counted as allowed",
        "find": "                    if domain in allowed or _domain_patterns_cover(\n",
        "replace": "                    if domain in allowed or False and _domain_patterns_cover(\n",
    },
    {
        "name": "AC-49 sync: a DNS Firewall answering every name is compared",
        "file": AGENTCORE,
        "defect": 'a DNS Firewall whose ALERT over "*" answers every name was compared as an allow-list',
        "find": '                if action == "BLOCK":\n                    return allowed, "", None\n',
        "replace": '                if True:\n                    return allowed, "", None\n',
    },
    {
        "name": "AC-49 sync: an allowed AWS managed list is skipped",
        "file": AGENTCORE,
        "defect": "a DNS Firewall ALLOW over an AWS managed domain list, whose names are unread, was compared without them",
        "find": '                if action != "BLOCK":\n',
        "replace": "                if False:\n",
    },
    {
        "name": "AC-45 invoker: a tool role grant an invoker lacks is not named",
        "file": AGENTCORE,
        "defect": "a tool role holding a grant a principal starting its sessions lacks passed the invoker bound",
        "find": "            if lacking:\n                gaps.append(\n",
        "replace": "            if False:\n                gaps.append(\n",
    },
    {
        "name": "AC-45 invoker: a conditioned invoker grant covers an unconditioned one",
        "file": AGENTCORE,
        "defect": "an invoker granted an action only under a condition was read as holding the tool role's unconditioned grant",
        "find": '    own = statement.get("Condition") or {}\n    if own and own != condition:\n',
        "replace": '    own = statement.get("Condition") or {}\n    if False:\n',
    },
    {
        "name": "AC-45 invoker: an invoker's own boundary and Deny are not read",
        "file": AGENTCORE,
        "defect": "an invoker whose permissions boundary removes the action was read as holding the tool role's grant",
        "find": "                    _grant_survives(permissions, action, resource)\n                    and any(\n",
        "replace": "                    True\n                    and any(\n",
    },
    {
        "name": "AC-45 invoker: a start grant on another tool makes an invoker",
        "file": AGENTCORE,
        "defect": "a principal granted StartCodeInterpreterSession on another tool was held to this tool's role",
        "find": "                _statement_reaches_arn(statement, tool_arn)\n                and _statement_reached_actions(statement, [start_suffix])\n",
        "replace": "                True\n                and _statement_reached_actions(statement, [start_suffix])\n",
    },
    {
        "name": "AC-45 invoker: an unreadable invoker policy is not reported",
        "file": AGENTCORE,
        "defect": "an invoker policy the cache could not parse let the invoker bound pass",
        "find": '    if unreadable:\n        return finding(\n            f"These cached policy documents could not be parsed, so whether a "\n',
        "replace": '    if False:\n        return finding(\n            f"These cached policy documents could not be parsed, so whether a "\n',
    },
    {
        "name": "AC-45 invoker: a narrower resource pattern covers a wider one",
        "file": AGENTCORE,
        "defect": "an invoker granted one bucket prefix was read as holding a tool role grant on every app- bucket",
        "find": '        return False\n    return fnmatchcase(inner, outer.replace("[", "[[]"))\n',
        "replace": "        return False\n    return True\n",
    },
    {
        "name": "AC-45 invoker: the tool role is counted as its own invoker",
        "file": AGENTCORE,
        "defect": "a tool role granted StartCodeInterpreterSession on its own tool passed as an invoker holding every grant",
        "find": '                kind == "role" and name == role_name\n',
        "replace": "                False\n",
    },
    {
        "name": "AC-45 invoker: a tool role grant its own Deny removes is compared",
        "file": AGENTCORE,
        "defect": "a tool role action its own Deny removes failed an invoker that lacks it",
        "find": "                if _grant_survives(role_permissions, action):\n",
        "replace": "                if True:\n",
    },
    {
        "name": "AC-45 invoker: an invoker's NotResource covers a pattern",
        "file": AGENTCORE,
        "defect": "an invoker's NotResource grant was read as covering a tool role grant on every object of a bucket",
        "find": '    return not any(wildcard in resource for wildcard in ("*", "?")) and not any(\n',
        "replace": "    return True and not any(\n",
    },
    {
        "name": "AC-45 invoker: an invoker whose Deny removes the start grant is held to the role",
        "file": AGENTCORE,
        "defect": "a principal whose own Deny removes StartCodeInterpreterSession was held to the tool role",
        "find": "\n                or not _grant_survives(permissions, start_action)\n                or _unconditioned_deny_reaches(permissions, start_action, tool_arn)\n",
        "replace": "\n",
    },
    {
        "name": "AC-08 data path: a hosting VPC's endpoints are not judged",
        "file": AGENTCORE,
        "defect": "an S3 endpoint in the VPC a runtime runs in went unjudged when that VPC held no AgentCore endpoint",
        "find": "                agentcore_vpc_ids.update(\n",
        "replace": "                set().update(\n",
    },
    {
        "name": "AC-08 data path: an unresolved hosting VPC is not reported",
        "file": AGENTCORE,
        "defect": "a hosting resource whose VPC could not be read left its data-path endpoints unjudged without an N/A",
        "find": "        if hosting_errors:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "AC-45 shell: a matching character pair ends the pattern overlap",
        "file": AGENTCORE,
        "defect": "a principal granted bedrock-agentcore:InvokeAgentRuntimeCommand* was read as not reaching the shell action",
        "find": "                        row[j] = below[j + 1]\n",
        "replace": "                        row[j] = 0\n",
    },
    {
        "name": "AC-08 data path: a tools-only Region is not judged",
        "file": AGENTCORE,
        "defect": (
            "a Region holding only VPC-mode Code Interpreter or Browser tools "
            "reported no AgentCore resources and never judged the data-path "
            "endpoints in their VPCs"
        ),
        "find": "            if not hosting_references and not hosting_errors:\n",
        "replace": "            if True:\n",
    },
    {
        "name": "AC-34 image: a digest already read is downloaded again",
        "file": AGENTCORE,
        "defect": (
            "an image that two tags, versions or runtimes name was pulled once "
            "per URI, so repeated 512 MiB pulls could run the Lambda past its "
            "timeout and return no rows"
        ),
        "find": "    if image_digest and key in scans:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-34 image: a digest that failed is downloaded again",
        "file": AGENTCORE,
        "defect": (
            "an image whose read failed was pulled again for every URI that "
            "names its digest"
        ),
        "find": "            scans[key] = error\n",
        "replace": "            pass\n",
    },
    {
        "name": "AC-49 sync: a wildcard BLOCK is matched literally",
        "file": AGENTCORE,
        "defect": (
            "an earlier DNS Firewall BLOCK on *.example.com withdrew only the "
            "entry *.example.com, so the subdomains it refuses counted as allowed"
        ),
        "find": (
            "                blocked.extend(_domain_pattern(domain, False) "
            "for domain in domains)\n"
        ),
        "replace": (
            "                blocked.extend((domain, True, False) for domain in domains)\n"
        ),
    },
    {
        "name": "AC-49 sync: an allowed wildcard is compared whole",
        "file": AGENTCORE,
        "defect": (
            "an allowed *.example.com counted every subdomain as answered, so a "
            "firewall target a.example.com that an earlier BLOCK refuses read as "
            "in sync"
        ),
        "find": "                if not _dns_allow_list_covers(names, pattern)\n",
        "replace": "                if not _domain_patterns_cover(dns_patterns, pattern)\n",
    },
    {
        "name": "AC-49 sync: a BLOCK inside an allowed wildcard is not recorded",
        "file": AGENTCORE,
        "defect": (
            "an earlier BLOCK on a name under an allowed wildcard was dropped, so "
            "the refused name counted as answered"
        ),
        "find": (
            '                        if subdomains and pattern[0].endswith("." + base)\n'
        ),
        "replace": "                        if False\n",
    },
    {
        "name": "AC-49 sync: a refused part another ALLOW answers is not rescued",
        "file": AGENTCORE,
        "defect": (
            "a name an earlier ALLOW answers ahead of the BLOCK was read as "
            "refused, failing an allow-list that is in sync"
        ),
        "find": (
            "                    answered(part) if exact else subdomains_answered(part)\n"
        ),
        "replace": "                    False\n",
    },
    {
        "name": "AC-12 credits a gateway's own ARN beside a pattern",
        "file": AGENTCORE,
        "defect": "a key policy whose encryption context lists this gateway's ARN beside gateway/* passed, so the key served every gateway the pattern matches",
        "find": "            if values and all(value == target for value in values):\n",
        "replace": "            if values and any(value == target for value in values):\n",
    },
    {
        "name": "AC-24 credits a per-tool Throttles series",
        "file": AGENTCORE,
        "defect": "an alarm on a series narrowed by a Name or Method dimension was credited for the whole gateway, so throttling on every other tool raised no alarm",
        "find": '    if {"Name", "Method"} & set(values):\n        return False\n',
        "replace": "    if False:\n        return False\n",
    },
    {
        "name": "AC-24 credits another gateway's Throttles series",
        "file": AGENTCORE,
        "defect": "an alarm on another gateway's Resource dimension was credited to this one",
        "find": '    return values.get("Resource") in (None, gateway_arn)\n',
        "replace": "    return True\n",
    },
    {
        "name": "AG-27 credits an alarm on a series that is never published",
        "file": AGENTCORE,
        "defect": "an alarm reading a series ListMetrics does not list passed, though it can never fire",
        "find": "            if any(key in listed for key in keys)\n",
        "replace": "            if True\n",
    },
    {
        "name": "AC-27 accepts a consent portal role trust that names the type, not the portal",
        "file": AGENTCORE,
        "defect": "a portal role whose aws:SourceArn names consent-portal/* passed, so the service could assume it for any portal in the account",
        "find": "            and not _statement_names_source_arn(statement, portal_arn)\n",
        "replace": "            and False\n",
    },
    {
        "name": "AC-27 credits a portal's ARN listed beside a pattern",
        "file": AGENTCORE,
        "defect": "a trust listing the portal's ARN beside consent-portal/* passed, though the pattern admits every portal in the account",
        "find": '                "*" in value or "?" in value for value in values\n            ):\n                return True\n',
        "replace": "                False for value in values\n            ):\n                return True\n",
    },
    {
        "name": "AC-27 passes an aws:SourceVpc that names no VPC in the account",
        "file": AGENTCORE,
        "defect": "a resource policy Deny naming another account's VPC passed, letting callers in that VPC reach the gateway",
        "find": "    unmatched_vpcs = [value for value in vpc_values if value not in vpcs]\n",
        "replace": "    unmatched_vpcs = []\n",
    },
    {
        "name": "AC-27 judges aws:SourceVpc when DescribeVpcs failed",
        "file": AGENTCORE,
        "defect": "a failed DescribeVpcs was read as a VPC list, so the network path row was judged on no data",
        "find": "    if isinstance(vpcs, str):\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-34 loses a credential that straddles two scan chunks",
        "file": AGENTCORE,
        "defect": "a credential split across a chunk boundary was never matched whole, so a large file holding it passed",
        "find": '        carry = tail[tail.find("\\n") + 1 :]\n',
        "replace": '        carry = ""\n',
    },
    {
        "name": "AC-34 ignores an API key assigned in code",
        "file": AGENTCORE,
        "defect": "an api_key or client_secret assigned a key-shaped literal in code passed",
        "find": "        and _literal_is_a_credential(match.group(3))\n",
        "replace": "        and False\n",
    },
    {
        "name": "AC-34 fails installed packages' sample credentials",
        "file": AGENTCORE,
        "defect": "sample credentials under site-packages failed every runtime that vendors a dependency",
        "find": '    if any(segment in CODE_DEPENDENCY_PATH_SEGMENTS for segment in path.split("/")):\n        return []\n',
        "replace": "    if False:\n        return []\n",
    },
    {
        "name": "AC-34 ignores a quoted Bearer token",
        "file": AGENTCORE,
        "defect": "a Bearer token written out as a header value passed",
        "find": "    if CODE_BEARER_LITERAL_PATTERN.search(text):\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-34 fails a placeholder assigned to a credential name",
        "file": AGENTCORE,
        "defect": "an example or changeme value assigned to api_key failed as a credential",
        "find": "    if _value_points_at_a_credential_store(value) or any(\n        fragment in lowered for fragment in CREDENTIAL_PLACEHOLDER_FRAGMENTS\n    ):\n        return False\n    if (\n",
        "replace": "    if _value_points_at_a_credential_store(value):\n        return False\n    if (\n",
    },
    {
        "name": "AC-35 judges API Gateway operations the target's toolFilters leave out",
        "file": AGENTCORE,
        "defect": "an exported operation no toolFilters entry selects was judged as a tool",
        "find": "        if not any(_api_gateway_filter_selects(f, path, method) for f in filters):\n            continue\n",
        "replace": "        if False:\n            continue\n",
    },
    {
        "name": "AC-35 reads a trailing-star filterPath as a literal path",
        "file": AGENTCORE,
        "defect": "a /pets/* filter selected no path, so the tools it exposes went unjudged",
        "find": "        return path.startswith(filter_path[:-1])\n",
        "replace": "        return path == filter_path\n",
    },
    {
        "name": "AC-35 ignores the methods a toolFilters entry names",
        "file": AGENTCORE,
        "defect": "a filter for GET also selected POST on the same path",
        "find": "    if method not in methods:\n        return False\n    if filter_path",
        "replace": "    if False:\n        return False\n    if filter_path",
    },
    {
        "name": "AC-35 ignores a toolOverrides name",
        "file": AGENTCORE,
        "defect": "a tool renamed by toolOverrides was keyed by its operationId, so the policy reads on it were never matched",
        "find": "        name = overrides.get((path, method)) or operation_id\n",
        "replace": "        name = operation_id\n",
    },
    {
        "name": "AC-35 reads no API Gateway target",
        "file": AGENTCORE,
        "defect": "an API Gateway target's tools were reported unread though the stage export names them",
        "find": '            elif "apiGateway" in mcp:\n',
        "replace": "            elif False:\n",
    },
    {
        "name": "AC-41 charges a ThirdParty evaluator a customer key",
        "file": AGENTCORE,
        "defect": "an AWS-authored ThirdParty evaluator, under an ARN with no account, failed for lacking a customer managed key",
        "find": 'SERVICE_AUTHORED_EVALUATOR_TYPES = ("Builtin", "ThirdParty")\n',
        "replace": 'SERVICE_AUTHORED_EVALUATOR_TYPES = ("Builtin",)\n',
    },
    {
        "name": "AC-41 judges only attached evaluators",
        "file": AGENTCORE,
        "defect": "a custom evaluator no configuration attaches kept its instructions under an unjudged key",
        "find": "        set(defined)\n        | set(_attached_custom_evaluator_ids(details))\n",
        "replace": "        set()\n        | set(_attached_custom_evaluator_ids(details))\n",
    },
    {
        "name": "AC-41 passes when ListEvaluators failed",
        "file": AGENTCORE,
        "defect": "a denied evaluator listing left unattached evaluators unjudged with no N/A row",
        "find": "    if listing_error:\n        findings.append(\n",
        "replace": "    if False:\n        findings.append(\n",
    },
    {
        "name": "AC-45 passes the invoker bound beside an unread principal",
        "file": AGENTCORE,
        "defect": "a principal the IAM cache could not read may hold the start action, yet the bound passed",
        "find": "    if read_gaps:\n        return finding(\n",
        "replace": "    if False:\n        return finding(\n",
    },
    {
        "name": "AC-46 credits a LINKED_ACCOUNT monitor on other accounts",
        "file": AGENTCORE,
        "defect": "a CUSTOM monitor tracking only other linked accounts was credited for the runtimes' account",
        "find": '    return bool(accounts & set(dimensions.get("Values") or []))\n',
        "replace": "    return True\n",
    },
    {
        "name": "AC-46 fails an AWS managed LINKED_ACCOUNT monitor",
        "file": AGENTCORE,
        "defect": "an AWS managed monitor on the LINKED_ACCOUNT dimension watches each account's total spend, AgentCore included, and was failed as not alerting",
        "find": '        and monitor.get("MonitorDimension") == "LINKED_ACCOUNT"\n',
        "replace": "        and False\n",
    },
    {
        "name": "AC-46 credits a SERVICE monitor that omits AgentCore",
        "file": AGENTCORE,
        "defect": "a CUSTOM monitor whose SERVICE specification names only Amazon Bedrock was credited with watching AgentCore spend",
        "find": '        return AGENTCORE_COST_EXPLORER_SERVICE in (dimensions.get("Values") or [])\n',
        "replace": "        return True\n",
    },
    {
        "name": "AC-46 fails a TAG or COST_CATEGORY monitor",
        "file": AGENTCORE,
        "defect": "an AWS managed TAG or COST_CATEGORY monitor, which the API does not resolve to AgentCore spend, was failed as not alerting",
        "find": '            and monitor.get("MonitorDimension") not in {"SERVICE", "LINKED_ACCOUNT"}\n',
        "replace": "            and False\n",
    },
    {
        "name": "AC-49 credits one ThreatSignatures category for all",
        "file": AGENTCORE,
        "defect": "a policy dropping on one AWS managed ThreatSignatures category passed while the Region lists others",
        "find": "    if signatures and missing_categories:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-49 credits one domain reputation group for all",
        "file": AGENTCORE,
        "defect": "a policy dropping on one named reputation group passed without the others",
        "find": "    elif set(reputation) != set(NETWORK_FIREWALL_REPUTATION_GROUPS):\n",
        "replace": "    elif False:\n",
    },
    {
        "name": "AC-49 passes the threat row when ListRuleGroups failed",
        "file": AGENTCORE,
        "defect": "a failed category listing was read as an empty requirement, so any one category passed",
        "find": "        if reached and isinstance(threat_categories, str):\n",
        "replace": "        if False:\n",
    },
    {
        "name": "AC-49 passes the threat row when the ALERT log group is unread",
        "file": AGENTCORE,
        "defect": "a failed DescribeLogStreams still produced Passed, with no detection read",
        "find": "                    if detection_error:\n",
        "replace": "                    if False:\n",
    },
    {
        "name": "AC-49 claims a detection time from a shared log group",
        "file": AGENTCORE,
        "defect": "the newest event in a group shared with FLOW logs was reported as the newest detection",
        "find": '            other.get("LogType") != NETWORK_FIREWALL_ALERT_LOG_TYPE\n            and',
        "replace": "            False\n            and",
    },
    {
        "name": "AC-53 credits a disabled scheduled query",
        "file": AGENTCORE,
        "defect": "a DISABLED scheduled query was credited for the log groups it names",
        "find": '        if query.get("state") != "ENABLED":\n            continue\n',
        "replace": "        if False:\n            continue\n",
    },
    {
        "name": "AC-53 credits a scheduled query whose last run failed",
        "file": AGENTCORE,
        "defect": "a query whose last run ended InvalidQuery was credited, though it produced no result",
        "find": '        if query.get("lastExecutionStatus") in SCHEDULED_QUERY_FAILED_STATUSES:\n',
        "replace": "        if False:\n",
    },
    {
        "name": "AC-53 fails log groups when a scheduled query is unread",
        "file": AGENTCORE,
        "defect": "an uncovered group beside an unreadable query failed, though that query may read it",
        "find": "    if uncovered and not_read:\n",
        "replace": "    if False:\n",
    },
    {
        "name": "AC-53 misreads a log group ARN identifier",
        "file": AGENTCORE,
        "defect": "a query naming a group by ARN covered nothing, failing a group it reads",
        "find": '    if text.startswith("arn:") and ":log-group:" in text:\n',
        "replace": "    if False:\n",
    },
    {
        "name": "AC-51 holds a distribution with no web ACL at N/A",
        "file": AGENTCORE,
        "defect": "a CloudFront distribution fronting a gateway with no web ACL was not failed",
        "find": "        if not web_acl_id:\n            findings.append(\n                anti_ddos(\n",
        "replace": "        if False:\n            findings.append(\n                anti_ddos(\n",
    },
    {
        "name": "AG-39 reads the regional body limit on a CloudFront ACL",
        "file": AGENTCORE,
        "defect": "the CLOUDFRONT body inspection limit was never read on a distribution's web ACL",
        "find": "            acl_label, web_acl_id, web_acl, None, WAF_CLOUDFRONT_RESOURCE_TYPE\n",
        "replace": "            acl_label, web_acl_id, web_acl, None\n",
    },
    {
        "name": "AC-51 reads a global web ACL in the wrong Region",
        "file": AGENTCORE,
        "defect": "a CloudFront web ACL was read in a Region its ARN does not name",
        "find": '        region = web_acl_id.split(":")[3]\n',
        "replace": '        region = "us-west-2"\n',
    },
    {
        "name": "AC-51 never judges a fronting distribution's web ACL",
        "file": AGENTCORE,
        "defect": "the web ACL on a distribution fronting a gateway went unread",
        "find": "    findings.extend(_front_door_web_acl_findings(fronting_acls))\n",
        "replace": "",
    },
    {
        "name": "AC-27 adds an Unrestricted row beside a foreign SourceVpc",
        "file": AGENTCORE,
        "defect": "a Deny naming another account's VPC also reported the gateway as having no network restriction at all",
        "find": "    elif not unmatched_vpcs:\n        gap_text = (\n",
        "replace": "    else:\n        gap_text = (\n",
    },
    {
        "name": "AC-45 widens a Secrets Manager random-suffix pattern",
        "file": AGENTCORE,
        "defect": "secret:prod/db-?????? names one secret by its six-character suffix, yet a tool role granted it failed as reaching every secret",
        "find": '    if service == "secretsmanager" and SECRET_SUFFIX_PATTERN.fullmatch(resource_part):\n        return False\n',
        "replace": "    if False:\n        return False\n",
    },
    {
        "name": "AC-45 credits a wildcard in a resource type with no published sub-resource",
        "file": AGENTCORE,
        "defect": "a wildcard after the type of a service or type the sub-resource table does not list was read as scoped, so arn:...:thing/x/* passed",
        "find": "    if prefix is None:\n        return True\n",
        "replace": "    if prefix is None:\n        return False\n",
    },
    {
        "name": "AC-45 credits a path wildcard inside a name that may hold a slash",
        "file": AGENTCORE,
        "defect": "log-group:/aws/lambda/* and role/service-role/* were read as one named resource, though each name runs to the end of the ARN",
        "find": "    if end < 0:\n        return True\n    parent = rest[:end]\n",
        "replace": "    if end < 0:\n        return False\n    parent = rest[:end]\n",
    },
    {
        "name": "AC-45 credits a sub-resource under a wildcard parent",
        "file": AGENTCORE,
        "defect": "table/ord*/index/* was read as inside one table, though the parent matches every table it names",
        "find": '    return not parent or "*" in parent or "?" in parent\n',
        "replace": "    return not parent\n",
    },
    {
        "name": "AC-45 reads an empty resource name as scoped",
        "file": AGENTCORE,
        "defect": "an ARN with no resource segment, such as arn:aws:s3:::, was read as naming one resource",
        "find": '    if not resource_part:\n        return True\n    if "*" not in resource_part',
        "replace": '    if not resource_part:\n        return False\n    if "*" not in resource_part',
    },
    {
        "name": "AC-34 matches assignments in files a package RECORD lists",
        "file": AGENTCORE,
        "defect": "botocore's examples assigning Password and GrantToken failed every runtime whose code archive vendors its dependencies at the root",
        "find": "                            posixpath.normpath(info.filename) in installed,\n",
        "replace": "                            False,\n",
    },
    {
        "name": "AC-34 reads a package RECORD from the archive root only",
        "file": AGENTCORE,
        "defect": "a RECORD under app/ was resolved against the root, so the files it lists were matched as the agent's own code",
        "find": "        root = posixpath.dirname(posixpath.dirname(name))\n",
        "replace": '        root = ""\n',
    },
    {
        "name": "AC-34 fails AWS's EXAMPLE placeholder access key ids",
        "file": AGENTCORE,
        "defect": "botocore's and boto3's example ids such as AKIAIOSFODNN7EXAMPLE failed every runtime whose code archive vendors them",
        "find": '    r"(?<![A-Z0-9])(?:AKIA|ASIA)(?![A-Z0-9]{9}EXAMPLE(?![A-Z0-9]))[A-Z0-9]{16}"\n',
        "replace": '    r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}"\n',
    },
    {
        "name": "AC-34 spares any access key id holding EXAMPLE",
        "file": AGENTCORE,
        "defect": "an id with EXAMPLE anywhere in its 16 characters passed, though AWS's placeholder form ends in EXAMPLE",
        "find": "(?![A-Z0-9]{9}EXAMPLE(?![A-Z0-9]))",
        "replace": "(?![A-Z0-9]*EXAMPLE)",
    },
    {
        "name": "AC-34 reports a PEM private key header with no body",
        "file": AGENTCORE,
        "defect": "a header string literal, as cryptography's ssh.py holds, failed the runtime as a private key",
        "find": '    rf"(?:[A-Za-z0-9+/]{{40,}}{_PEM_LINE_BREAK}){{2,}}"\n',
        "replace": '    rf"(?:[A-Za-z0-9+/]{{40,}}{_PEM_LINE_BREAK}){{0,}}"\n',
    },
    {
        "name": "AC-34 reports a PEM block of one base64 line",
        "file": AGENTCORE,
        "defect": "a block with one base64 line, shorter than any private key, failed the runtime",
        "find": "{_PEM_LINE_BREAK}){{2,}}",
        "replace": "{_PEM_LINE_BREAK}){{1,}}",
    },
    {
        "name": "AC-34 reports a PEM block whose footer names another key type",
        "file": AGENTCORE,
        "defect": "a BEGIN RSA header closed by an END EC footer was reported as one private key",
        "find": '    r"-----END \\1PRIVATE KEY-----"\n',
        "replace": '    r"-----END [A-Z0-9 ]*PRIVATE KEY-----"\n',
    },
    {
        "name": "AC-34 misses a PEM block whose line breaks are escaped",
        "file": AGENTCORE,
        "defect": "a private key in a JSON or .env value, its newlines written as \\n, passed",
        "find": "(?:\\n|\\\\n)(?:[ \\t\"'\\r\\n]",
        "replace": "(?:\\n)(?:[ \\t\"'\\r\\n]",
    },
    {
        "name": "AC-34 carries too little overlap to hold a private key block",
        "file": AGENTCORE,
        "defect": "a 3.2 KiB private key block spanning chunk boundaries was never matched whole, so a large file holding it passed",
        "find": "AC34_SCAN_OVERLAP_CHARS = 64 * 1024\n",
        "replace": "AC34_SCAN_OVERLAP_CHARS = 1024\n",
    },
    {
        "name": "AC-34 fails any 20-character AKIA value held as a variable",
        "file": AGENTCORE,
        "defect": "a variable holding a 20-character AKIA value with a lowercase body, or AWS's EXAMPLE id, failed the runtime",
        "find": "        return CREDENTIAL_TEXT_PATTERN.fullmatch(value) is not None\n",
        "replace": "        return True\n",
    },
    {
        "name": "AC-34 fails a PEM header held as a variable value",
        "file": AGENTCORE,
        "defect": "an environment variable holding a private key header and no key failed the runtime",
        "find": '    return value.startswith("-----BEGIN") and _text_holds_a_credential(value)\n',
        "replace": '    return value.startswith("-----BEGIN") and "PRIVATE KEY" in value\n',
    },
    # ------------------------------------- end of the AgentCore verdict legs
    {
        "name": "BR-43 credits a NotAction Deny that exempts an action of a probed service",
        "file": BEDROCK,
        "defect": "BR-43 credits a whole-prefix probe to a NotAction Deny that exempts "
        "bedrock:CreateAgent or es:CreateDomain, so those actions run in any Region "
        "while the row passes",
        "find": "                if open_patterns:\n",
        "replace": "                if False:\n",
    },
    {
        "name": "BR-43 stops crediting the Control Tower default S3 exemptions",
        "file": BEDROCK,
        "defect": "BR-43 fails the Control Tower Region deny for the S3 account-level "
        "and Multi-Region Access Point actions it exempts by default",
        "find": "                    if pattern.lower() not in CONTROL_TOWER_REGION_DENY_EXEMPTIONS\n",
        "replace": "                    if pattern.lower() not in ()\n",
    },
    {
        "name": "BR-53 drops Marketplace model endpoints from the Bedrock inventory",
        "file": BEDROCK,
        "defect": "BR-53 reads no Marketplace model endpoint ARN, so one never tagged "
        "passes unseen under the complete Passed row",
        "find": '            "marketplaceModelEndpoints",\n            "endpointArn",\n',
        "replace": '            "marketplaceModelEndpoints",\n            "missingArn",\n',
    },
    {
        "name": "BR-53 drops SageMaker transform jobs from the sweep lists",
        "file": BEDROCK,
        "defect": "BR-53 reads no transform job ARN from sagemaker:ListTransformJobs, "
        "so a transform job never tagged passes unseen",
        "find": '        "TransformJobSummaries",\n        "TransformJobArn",\n',
        "replace": '        "TransformJobSummaries",\n        "MissingArn",\n',
    },
    {
        "name": "BR-39 passes an AI workload on a subnet routed to an internet gateway",
        "file": BEDROCK,
        "defect": "BR-39 stops failing an AI workload whose subnet routes to an igw- "
        "gateway, so an ECS service granted Bedrock in a public subnet passes",
        "find": "            if public:\n                failed.append(\n"
        "                    \"{} in {} (role '{}') runs on subnet(s) that route to an \"\n",
        "replace": "            if False:\n                failed.append(\n"
        "                    \"{} in {} (role '{}') runs on subnet(s) that route to an \"\n",
    },
    {
        "name": "BR-39 stops failing an AI workload outside any VPC",
        "file": BEDROCK,
        "defect": "BR-39 reads a Lambda function granted Bedrock with no VpcConfig as "
        "unread instead of failing it",
        "find": '            if not workload.get("vpc_id"):\n                failed.append(\n'
        "                    f\"{label} (role '{role}') is not attached to a VPC, so it runs \"\n",
        "replace": "            if False:\n                failed.append(\n"
        "                    f\"{label} (role '{role}') is not attached to a VPC, so it runs \"\n",
    },
    {
        "name": "BR-02 skips the data path endpoint policies in AI VPCs",
        "file": BEDROCK,
        "defect": "BR-02 judges no S3, DynamoDB or SageMaker endpoint policy, so a "
        "default full-access S3 gateway endpoint in an AI VPC goes unreported",
        "find": '        if endpoint.get("vpc_id") in ai_vpcs["vpcs"]\n',
        "replace": "        if False\n",
    },
    {
        "name": "BR-02 credits a wildcard bucket name in a data path endpoint policy",
        "file": BEDROCK,
        "defect": "BR-02 reads arn:aws:s3:::* as naming a bucket, so an endpoint "
        "policy open to every bucket passes as least privilege",
        "find": "    if not name or _resource_has_wildcard(name):\n",
        "replace": "    if not name:\n",
    },
    {
        "name": "BR-12 passes a COMPLIANCE bucket the assessed account owns",
        "file": BEDROCK,
        "defect": "BR-12 credits an Object Lock bucket in the assessed account as the "
        "WORM archive, though the control prescribes a separate Log Archive account",
        "find": '    if owner == "same":\n',
        "replace": "    if False:\n",
    },
    {
        "name": "BR-57 drops Lambda MicroVM roles from the agent roles",
        "file": BEDROCK,
        "defect": "BR-57 reads no Lambda MicroVM execution role, so two agent images "
        "on one role and a MicroVM role's trust edges go unjudged",
        "find": '    for role_arn, label in microvms["microvms"]:\n        add_role(role_arn, label)\n',
        "replace": '    for role_arn, label in microvms["microvms"]:\n        pass\n',
    },
    {
        "name": "BR-57 passes a MicroVM run with the SHELL_INGRESS connector",
        "file": BEDROCK,
        "defect": "BR-57 ignores the ingress connectors, so a MicroVM any shell-token "
        "holder can open a shell in passes",
        "find": '            result["shell"].append(label)\n',
        "replace": "            pass\n",
    },
    {
        "name": "BR-57 reads a terminated MicroVM as an agent",
        "file": BEDROCK,
        "defect": "BR-57 counts MicroVMs that no longer run, so a terminated "
        "MicroVM's role fails a live agent for sharing it",
        "find": 'MICROVM_LIVE_STATES = ("PENDING", "RUNNING", "SUSPENDING", "SUSPENDED")\n',
        "replace": 'MICROVM_LIVE_STATES = ("PENDING", "RUNNING", "SUSPENDING", "SUSPENDED", "TERMINATED")\n',
    },
    {
        "name": "BR-57 drops a failure when no agent role exists",
        "file": BEDROCK,
        "defect": "BR-57 replaces a roleless SHELL_INGRESS MicroVM's failure with "
        "the empty-estate N/A row",
        "find": "        if not agent_roles and not unread and not failures:\n",
        "replace": "        if not agent_roles and not unread:\n",
    },
    {
        "name": "BR-47 caps the training job Search at the describe cap",
        "file": BEDROCK,
        "defect": "BR-47 reads only the newest training jobs Search returns, so a "
        "Region with more jobs than the cap never judges the older ones",
        "find": "    names = listed + [name for name in searched if name not in set(listed)]\n",
        "replace": "    names = (listed + [name for name in searched if name not in set(listed)])[\n        :MAX_SAGEMAKER_TRAINING_JOB_READS\n    ]\n",
    },
    {
        "name": "BR-47 ignores the trial component job descriptions",
        "file": BEDROCK,
        "defect": "BR-47 describes every transform and processing job, so a Region "
        "past the cap stays N/A though trial components hold every job",
        "find": "        held = _trial_component_job_details(client, kind)\n",
        "replace": "        held = {}\n",
    },
    {
        "name": "BR-47 skips the jobs a trial component holds",
        "file": BEDROCK,
        "defect": "BR-47 reads only the jobs it describes, so a transform or "
        "processing job held by a trial component goes unjudged",
        "find": "        for job in [job for job in jobs if job.get(name_key) in held] + read:\n",
        "replace": "        for job in read:\n",
    },
    {
        "name": "BR-47 reads only each runtime's listed version for code buckets",
        "file": BEDROCK,
        "defect": "BR-47 skips the versions a runtime endpoint serves, so a live "
        "version's code bucket with no TLS deny goes unjudged",
        "find": '        for endpoint in endpoints:\n            for field in ("liveVersion", "targetVersion"):\n                if endpoint.get(field):\n                    versions.add(str(endpoint[field]))\n        for version in sorted(',
        "replace": '        for endpoint in []:\n            for field in ("liveVersion", "targetVersion"):\n                if endpoint.get(field):\n                    versions.add(str(endpoint[field]))\n        for version in sorted(',
    },
    {
        "name": "BR-47 passes beside an unlisted runtime endpoint set",
        "file": BEDROCK,
        "defect": "BR-47 reports Passed when a runtime's endpoints were not listed, "
        "so the versions they serve were never read",
        "find": '            endpoints = []\n            errors.append(\n                f"the endpoints of AgentCore runtime',
        "replace": '            endpoints = []\n            [].append(\n                f"the endpoints of AgentCore runtime',
    },
    {
        "name": "BR-04 passes an overdue log object",
        "file": BEDROCK,
        "defect": "BR-04 never reports an object kept past its lifecycle rule, so deletion that has not run reads as retention",
        "find": "    if now > due + timedelta(days=LIFECYCLE_DELETION_GRACE_DAYS):\n",
        "replace": "    if False:\n",
    },
    {
        "name": "BR-04 enters the latest date folder",
        "file": BEDROCK,
        "defect": "BR-04 descends into the newest date folder, so the oldest object it reports is not the oldest held",
        "find": "            pending.append(min(folders))\n",
        "replace": "            pending.append(max(folders))\n",
    },
    {
        "name": "BR-04 reads one ListObjectsV2 page per level",
        "file": BEDROCK,
        "defect": "BR-04 stops after the first ListObjectsV2 page of each level, so an older object on a later page goes unread",
        "find": '            if not page.get("IsTruncated") or not token:\n',
        "replace": "            if True:\n",
    },
    {
        "name": "BR-04 passes a bucket whose deletion evidence was not read",
        "file": BEDROCK,
        "defect": "BR-04 names a bucket as retained when its ListObjectsV2 read failed",
        "find": '    on_schedule = not deletion["overdue"] and not deletion["error"]\n',
        "replace": '    on_schedule = not deletion["overdue"]\n',
    },
    {
        "name": "BR-04 keeps the HeadObject cap N/A with no overdue object",
        "file": BEDROCK,
        "defect": "BR-04 leaves a replicated log bucket past the HeadObject cap N/A even when no object is past its rule",
        "find": '        if held["capped"] and not held["failed"] and on_schedule:\n',
        "replace": "        if False:\n",
    },
    {
        "name": "BR-04 passes an overdue replica",
        "file": BEDROCK,
        "defect": "BR-04 never fails a replica bucket that kept an object past its lifecycle rule",
        "find": '            if replica_deletion["overdue"]:\n',
        "replace": "            if False:\n",
    },
    {
        "name": "BR-04 never dues a Date rule",
        "file": BEDROCK,
        "defect": "BR-04 reads an Expiration Date as never due, so an object left past the date passes",
        "find": '            dues.append((max(date, written), f"expiry date',
        "replace": '            dues.append((date + timedelta(days=36500), f"expiry date',
    },
    {
        "name": "BR-55 ignores an all-zero digest in KMS event history",
        "file": BEDROCK,
        "defect": "BR-55 never fails a key whose CloudTrail event history records a request from a debug-mode enclave",
        "find": 'if events["zero"]:',
        "replace": "if False:",
    },
    {
        "name": "BR-55 reads one LookupEvents page per key",
        "file": BEDROCK,
        "defect": "BR-55 stops after the first LookupEvents page, so a debug-mode request on a later page goes unread",
        "find": '            request["NextToken"] = token\n',
        "replace": "            break\n",
    },
    {
        "name": "BR-55 passes a key whose event history was not read",
        "file": BEDROCK,
        "defect": "BR-55 drops a LookupEvents error, so a key whose event history was never read is Passed",
        "find": '        error = f"cloudtrail:LookupEvents, {get_assessment_error_label(lookup_error)}"',
        "replace": '        error = ""',
    },
    {
        "name": "BR-55 reads a base64 all-zero digest as a measurement",
        "file": BEDROCK,
        "defect": "BR-55 recognizes only a hex all-zero digest, so a base64-encoded one passes",
        "find": "    return bool(decoded) and not any(decoded)\n",
        "replace": "    return False\n",
    },
    {
        "name": "BR-55 passes past the event history page cap",
        "file": BEDROCK,
        "defect": "BR-55 reports a key Passed after reading only the first pages of its event history",
        "find": '    error = f"events past the first {ENCLAVE_EVENT_MAX_PAGES} page(s) were not read"',
        "replace": '    error = ""',
    },
    {
        "name": "BR-04 passes an overdue noncurrent version",
        "file": BEDROCK,
        "defect": "BR-04 never reports a noncurrent version kept past its NoncurrentDays rule",
        "find": '    if now > oldest["since"] + timedelta(days=days + LIFECYCLE_DELETION_GRACE_DAYS):',
        "replace": "    if False:",
    },
    {
        "name": "BR-04 ages a noncurrent version from its own write",
        "file": BEDROCK,
        "defect": "BR-04 counts NoncurrentDays from a version's own write, not from when the next version made it noncurrent",
        "find": '                        "since": newer["LastModified"],',
        "replace": '                        "since": item["LastModified"],',
    },
    {
        "name": "BR-04 enters only the first date folder for versions",
        "file": BEDROCK,
        "defect": "BR-04 stops at the earliest date folder even when it holds only delete markers, so a later noncurrent version goes unread",
        "find": "            if dated and found:",
        "replace": "            if dated:",
    },
    {
        "name": "BR-04 passes a bucket whose version listing failed",
        "file": BEDROCK,
        "defect": "BR-04 drops a ListObjectVersions error and names the bucket as retained",
        "find": "        return dict(current, error=describe_api_error(error, action, region))",
        "replace": "        return current",
    },
    {
        "name": "BR-04 lists no versions on a versioned bucket",
        "file": BEDROCK,
        "defect": "BR-04 never reads noncurrent versions, so a versioned bucket's NoncurrentDays rule is taken on trust",
        "find": '            noncurrent_days if versioning_status in ("Enabled", "Suspended") else []',
        "replace": "            []",
    },
    {
        "name": "BR-04 reads one ListObjectVersions page per level",
        "file": BEDROCK,
        "defect": "BR-04 stops after the first ListObjectVersions page of each level, so a later folder goes unread",
        "find": '            request["KeyMarker"] = key_marker\n',
        "replace": "            break\n",
    },
    {
        "name": "BR-47 caps evaluation jobs at the SageMaker describe cap",
        "file": BEDROCK,
        "defect": "BR-47 reads only the newest 200 evaluation jobs, so an older job's buckets go unjudged",
        "find": "    for job in jobs[:MAX_EVALUATION_JOB_READS]:",
        "replace": "    for job in jobs[:MAX_SAGEMAKER_TRAINING_JOB_READS]:",
    },
    {
        "name": "BR-47 drops the evaluation jobs past the read cap",
        "file": BEDROCK,
        "defect": "BR-47 says nothing of the evaluation jobs past its read cap, so the Passed row stands with jobs unread",
        "find": "    if unread:\n        rest = len(unread) - EVALUATION_JOBS_NAMED_PAST_CAP\n",
        "replace": "    if False:\n        rest = len(unread) - EVALUATION_JOBS_NAMED_PAST_CAP\n",
    },
    {
        "name": "BR-51 credits a ForAllValues: MFA condition",
        "file": BEDROCK,
        "defect": "BR-51 credits ForAllValues:Bool aws:MultiFactorAuthPresent true, which is true when the key is absent, so a trust with no MFA passes",
        "find": '        not operator.startswith("forallvalues:")\n        and _strip_condition_set_operator(operator) == "bool"\n        and key == MFA_PRESENT_CONDITION_KEY\n',
        "replace": '        _strip_condition_set_operator(operator) == "bool"\n        and key == MFA_PRESENT_CONDITION_KEY\n',
    },
    {
        "name": "BR-57 credits a wildcard partition, service, account or Region",
        "file": BEDROCK,
        "defect": "BR-57 reads only the resource segment, so arn:aws:dynamodb:us-east-1:*:table/orders passes",
        "find": '    if any(wildcard in segment for segment in segments for wildcard in "*?"):\n        return True\n',
        "replace": "",
    },
    {
        "name": "BR-57 reads a Bedrock Region wildcard as unscoped",
        "file": BEDROCK,
        "defect": "BR-57 fails a foundation model ARN with a Region wildcard, although a model id names the same model in every Region",
        "find": '    if service != "bedrock":\n        segments.append(arn_region)\n',
        "replace": "    segments.append(arn_region)\n",
    },
    {
        "name": "BR-57 leaves Lambda MicroVM roles out of the scope test",
        "file": BEDROCK,
        "defect": "BR-57 scopes only Bedrock agent and action group roles, so a MicroVM execution role with a wide grant is never judged",
        "find": '                if label.startswith(("Bedrock agent ", "Lambda MicroVM ")):\n',
        "replace": '                if label.startswith("Bedrock agent "):\n',
    },
    {
        "name": "BR-02 lists only the $LATEST function versions",
        "file": BEDROCK,
        "defect": "BR-02 lists functions without FunctionVersion ALL, so a published version an alias routes to is never a workload",
        "find": '        # with, and an alias can route to it, so every version is a workload.\n        for page in lambda_client.get_paginator("list_functions").paginate(\n            FunctionVersion="ALL"\n        ):\n',
        "replace": '        # with, and an alias can route to it, so every version is a workload.\n        for page in lambda_client.get_paginator("list_functions").paginate():\n',
    },
    {
        "name": "BR-02 leaves an ECS workload without awsvpc unplaced",
        "file": BEDROCK,
        "defect": "BR-02 never resolves the container instance behind a bridge or host mode task, so its VPC stays unread",
        "find": "        if not subnets and cluster and container_instances:\n",
        "replace": "        if False:\n",
    },
    {
        "name": "BR-02 reads no IRSA roles",
        "file": BEDROCK,
        "defect": "BR-02 drops the roles an EKS cluster gives pods through IAM roles for service accounts",
        "find": "    _eks_irsa_workloads(oidc_clusters, inventory)\n",
        "replace": "",
    },
    {
        "name": "BR-02 matches an IRSA trust to any OIDC provider",
        "file": BEDROCK,
        "defect": "BR-02 places a role in a cluster's VPC when its trust names any OIDC provider, not that cluster's",
        "find": "                    str(value).endswith(provider)\n",
        "replace": '                    ":oidc-provider/" in str(value)\n',
    },
    {
        "name": "BR-53 drops the automated reasoning policies",
        "file": BEDROCK,
        "defect": "BR-53 never reads the automated reasoning policies it lists, so an unowned one goes unjudged",
        "find": '            "automatedReasoningPolicySummaries",\n            "policyArn",\n            None,\n        ),\n        (\n            "custom model deployment",\n',
        "replace": '            "automatedReasoningPolicySummariesX",\n            "policyArn",\n            None,\n        ),\n        (\n            "custom model deployment",\n',
    },
    {
        "name": "BR-53 judges AWS default prompt routers",
        "file": BEDROCK,
        "defect": "BR-53 lists every prompt router, so an AWS default router no one in the account owns fails",
        "find": '        "list_prompt_routers": {"type": "custom"},\n',
        "replace": "",
    },
    {
        "name": "BR-04 credits a log group retention setting alone",
        "file": BEDROCK,
        "defect": "BR-04 never reports a CloudWatch Logs event kept past its retentionInDays",
        "find": '                if deletion["overdue"]:\n',
        "replace": "                if False:\n",
    },
    {
        "name": "BR-04 searches for expired log events without the deletion window",
        "file": BEDROCK,
        "defect": "BR-04 asks for events older than retentionInDays alone, so an event CloudWatch Logs has up to 72 hours to delete fails the group",
        "find": "    cutoff = now - timedelta(days=retention_days) - LOG_EVENT_DELETION_GRACE\n",
        "replace": "    cutoff = now - timedelta(days=retention_days)\n",
    },
    {
        "name": "BR-04 passes a log group search that reached its page cap",
        "file": BEDROCK,
        "defect": "BR-04 reports an unfinished FilterLogEvents search as no expired event",
        "find": '    return {\n        "overdue": None,\n        "evidence": "",\n        "error": (\n            f"FilterLogEvents had not finished',
        "replace": '    return {\n        "overdue": None,\n        "evidence": "",\n        "error": "" and (\n            f"FilterLogEvents had not finished',
    },
    {
        "name": "BR-04 credits replicated inference data with an overdue object",
        "file": BEDROCK,
        "defect": "BR-04 credits a replicated SageMaker capture bucket whose oldest object is past its rule",
        "find": "    if replicas and root is not None and not lock and on_schedule:\n",
        "replace": "    if replicas and root is not None and not lock:\n",
    },
    {
        "name": "the data path is handed out uncopied",
        "file": BEDROCK,
        "defect": "the memoized data path is returned by reference, so one check's edit reaches every later check in the Region",
        "find": "    return copy.deepcopy(_AI_DATA_PATH_BUCKETS_BY_REGION[region])\n",
        "replace": "    return _AI_DATA_PATH_BUCKETS_BY_REGION[region]\n",
    },
    {
        "name": "the data path memo outlives its invocation",
        "file": BEDROCK,
        "defect": "a warm Lambda container reuses the previous invocation's data path buckets",
        "find": "    _AI_DATA_PATH_BUCKETS_BY_REGION.clear()\n",
        "replace": "",
    },
    {
        "name": "BR-57 credits a path wildcard inside a name that may hold /",
        "file": BEDROCK,
        "defect": "BR-57 ends a name at its first / when the type publishes no sub-resource, so role/service-role/* passes",
        "find": "    if end < 0:\n        return True\n    parent = rest[:end]\n",
        "replace": '    if end < 0:\n        end = rest.find("/") if "/" in rest else len(rest)\n    parent = rest[:end]\n',
    },
    {
        "name": "BR-57 reads an ARN against the shortest matching type prefix",
        "file": BEDROCK,
        "defect": "BR-57 reads accesspoint/*/object/x as bucket accesspoint, so a wildcard access point passes",
        "find": "        key=len,\n        default=None,\n",
        "replace": "        key=lambda prefix: -len(prefix),\n        default=None,\n",
    },
    {
        "name": "BR-57 fails a secret ARN pinned to its six-character suffix",
        "file": BEDROCK,
        "defect": "BR-57 reads secret:name-?????? as a wildcard, although it matches only the secret named name",
        "find": '    if service == "secretsmanager" and SECRET_SUFFIX_PATTERN.fullmatch(resource_part):\n',
        "replace": "    if False:\n",
    },
    {
        "name": "BR-57 credits a secret suffix wildcard of any length",
        "file": BEDROCK,
        "defect": "BR-57 credits secret:name-????? as one secret, although fewer than six ? match other secrets' names",
        "find": 'SECRET_SUFFIX_PATTERN = re.compile(r"secret:[^*?]+-\\?{6}")\n',
        "replace": 'SECRET_SUFFIX_PATTERN = re.compile(r"secret:[^*?]+-\\?+")\n',
    },
    {
        "name": "BR-57 credits a secret suffix pin after a wildcard name",
        "file": BEDROCK,
        "defect": "BR-57 credits secret:*-?????? as one secret, although its name wildcard matches every secret",
        "find": 'SECRET_SUFFIX_PATTERN = re.compile(r"secret:[^*?]+-\\?{6}")\n',
        "replace": 'SECRET_SUFFIX_PATTERN = re.compile(r"secret:.+-\\?{6}")\n',
    },
    {
        "name": "BR-02 hands a half-read container instance to the next workload",
        "file": BEDROCK,
        "defect": "BR-02 keeps the EC2 instance id of a container instance whose instance read failed, so the next workload on it is told only that id",
        "find": '            for arn in wanted:\n                instance_subnets[arn] = (\n                    f"container instance {arn} was not read with "\n',
        "replace": '            for arn in ():\n                instance_subnets[arn] = (\n                    f"container instance {arn} was not read with "\n',
    },
    {
        "name": "the invocation deadline is never reached",
        "file": BEDROCK,
        "defect": "_deadline_reached always answers False, so a run whose caps together pass the 600 s timeout times out and writes no report",
        "find": "    return _DEADLINE is not None and time.monotonic() >= _DEADLINE\n",
        "replace": "    return False\n",
    },
    {
        "name": "the handler keeps the previous invocation's deadline",
        "file": BEDROCK,
        "defect": "lambda_handler never sets the deadline, so a warm container stops every capped read at a deadline spent in an earlier invocation",
        "find": "    _DEADLINE = time.monotonic() + remaining - DEADLINE_MARGIN_SECONDS\n",
        "replace": "    _DEADLINE = _DEADLINE\n",
    },
    {
        "name": "the deadline leaves no margin for the report",
        "file": BEDROCK,
        "defect": "the deadline is the Lambda timeout itself, so a read can run until the invocation is killed before the report is written",
        "find": "    _DEADLINE = time.monotonic() + remaining - DEADLINE_MARGIN_SECONDS\n",
        "replace": "    _DEADLINE = time.monotonic() + remaining\n",
    },
    {
        "name": "BR-56 lookups ignore the invocation deadline",
        "file": BEDROCK,
        "defect": "BR-56 keeps paging event history past the deadline",
        "find": '        if _deadline_reached():\n            return {"events": events, "truncated": True, "deadline": True}\n',
        "replace": '        if False:\n            return {"events": events, "truncated": True, "deadline": True}\n',
    },
    {
        "name": "BR-56 reports a deadline stop as its page cap",
        "file": BEDROCK,
        "defect": "BR-56 says an action had more than 5 pages when the deadline stopped its lookup",
        "find": '                    f"lookup stopped {DEADLINE_STOP}"\n                    if result.get("deadline")\n',
        "replace": '                    f"lookup stopped {DEADLINE_STOP}"\n                    if False\n',
    },
    {
        "name": "BR-04 log deletion search ignores the invocation deadline",
        "file": BEDROCK,
        "defect": "the FilterLogEvents search for an expired event keeps paging past the deadline",
        "find": '            if _deadline_reached():\n                return {\n                    "overdue": None,\n',
        "replace": '            if False:\n                return {\n                    "overdue": None,\n',
    },
    {
        "name": "BR-04 oldest object listing ignores the invocation deadline",
        "file": BEDROCK,
        "defect": "the ListObjectsV2 walk for the oldest invocation log object keeps listing past the deadline",
        "find": "            if calls >= OLDEST_OBJECT_LIST_CAP or _deadline_reached():\n",
        "replace": "            if calls >= OLDEST_OBJECT_LIST_CAP:\n",
    },
    {
        "name": "invocation log scan ignores the invocation deadline",
        "file": BEDROCK,
        "defect": "the FilterLogEvents scan of the invocation log keeps paging past the deadline",
        "find": '            if _deadline_reached():\n                cap = "invocation deadline"\n',
        "replace": '            if False:\n                cap = "invocation deadline"\n',
    },
    {
        "name": "CloudTrail guardrail join ignores the invocation deadline",
        "file": BEDROCK,
        "defect": "the LookupEvents join of untagged calls keeps paging past the deadline",
        "find": '                if _deadline_reached():\n                    break\n                joins["pages"] += 1\n',
        "replace": '                if False:\n                    break\n                joins["pages"] += 1\n',
    },
    {
        "name": "BR-07 prompt lookup ignores the invocation deadline",
        "file": BEDROCK,
        "defect": "the BR-07 runtime prompt lookup keeps paging event history past the deadline",
        "find": '            if _deadline_reached():\n                found["deadline"] = True\n',
        "replace": '            if False:\n                found["deadline"] = True\n',
    },
    {
        "name": "evaluation job reads ignore the invocation deadline",
        "file": BEDROCK,
        "defect": "GetEvaluationJob keeps reading jobs past the deadline",
        "find": '        if _deadline_reached():\n            stopped.append(name)\n            continue\n        try:\n            detail = client.get_evaluation_job(jobIdentifier=job.get("jobArn"))\n',
        "replace": '        if False:\n            stopped.append(name)\n            continue\n        try:\n            detail = client.get_evaluation_job(jobIdentifier=job.get("jobArn"))\n',
    },
    {
        "name": "BR-46 sidecar reads ignore the invocation deadline",
        "file": BEDROCK,
        "defect": "BR-46 keeps reading metadata sidecars past the deadline",
        "find": "        if _deadline_reached():\n            break\n        sidecars_read += 1\n",
        "replace": "        if False:\n            break\n        sidecars_read += 1\n",
    },
    {
        "name": "BR-46 prompt credits an output-only PII entity",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg reads each PII entity's output action, so a guardrail that screens only responses is credited for prompts",
        "find": '\n        and _sensitive_information_action(entity, "input")\n        in SENSITIVE_INFORMATION_ACTING\n    )\n',
        "replace": '\n        and _sensitive_information_action(entity, "output")\n        in SENSITIVE_INFORMATION_ACTING\n    )\n',
    },
    {
        "name": "BR-46 prompt credits a narrowed enforced configuration",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg counts an account-enforced configuration that guards only part of the traffic as use",
        "find": '\n            surfaces = [s for s in entry["surfaces"] if s not in narrowed]\n',
        "replace": '\n            surfaces = list(entry["surfaces"])\n',
    },
    {
        "name": "BR-46 prompt fails beside an unmatched invocation",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg drops logged calls whose guardrail is unknown, so it fails an estate it has not read",
        "find": "\n            else:\n                joins_unread += 1\n",
        "replace": "\n            elif False:\n                joins_unread += 1\n",
    },
    {
        "name": "BR-46 prompt skips an unguarded invocation",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg drops a logged call whose CloudTrail event names no guardrail, so a Region passes while prompts reach the model unscreened",
        "find": "\n                unguarded_requests.append(request_id)\n",
        "replace": "\n                pass\n",
    },
    {
        "name": "BR-46 prompt credits any guardrail for an unguarded invocation",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg treats a guardrail an agent or a logged call applies as account-enforced, so a call naming no guardrail is credited to it",
        "find": '\n                surface.startswith("account-enforced configuration ")\n',
        "replace": "\n                True\n",
    },
    {
        "name": "BR-46 prompt fails an unguarded invocation beside an unread enforced guardrail",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg fails a call naming no guardrail though the account-enforced guardrail that would screen it was not read",
        "find": '\n            elif enforced["unread"]:\n',
        "replace": "\n            elif False:\n",
    },
    {
        "name": "BR-46 prompt reads a joined guardrail at its working draft",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg reads a CloudTrail-joined guardrail without its version, so the draft is judged in place of the version that ran",
        "find": "\n                response = clients[target].get_guardrail(\n                    guardrailIdentifier=identifier, guardrailVersion=version\n                )\n",
        "replace": "\n                response = clients[target].get_guardrail(\n                    guardrailIdentifier=identifier\n                )\n",
    },
    {
        "name": "BR-46 prompt passes beside an unread guardrail",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg reports Passed though a listed guardrail or used version was not read",
        "find": '\n                "Informational" if unread else "Low",\n                "N/A" if unread else "Passed",\n            )\n        elif unread:\n            findings["status"] = "WARN"\n            row(\n                "No guardrail version read is shown',
        "replace": '\n                "Informational" if unread else "Low",\n                "Passed",\n            )\n        elif unread:\n            findings["status"] = "WARN"\n            row(\n                "No guardrail version read is shown',
    },
    {
        "name": "BR-46 prompt guardrail listing ignores the invocation deadline",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg keeps calling GetGuardrail on listed guardrails past the deadline",
        "find": "\n            if _deadline_reached():\n                unread.append(\n                    \"{} guardrail(s) from '{}' on were not read with \"\n",
        "replace": "\n            if False:\n                unread.append(\n                    \"{} guardrail(s) from '{}' on were not read with \"\n",
    },
    {
        "name": "BR-46 prompt version reads ignore the invocation deadline",
        "file": BEDROCK,
        "defect": "BR-46's prompt leg keeps reading used guardrail versions past the deadline",
        "find": '\n            if _deadline_reached():\n                entry["error"] = DEADLINE_STOP\n',
        "replace": '\n            if False:\n                entry["error"] = DEADLINE_STOP\n',
    },
    {
        "name": "BR-53 drops the HyperPod clusters",
        "file": BEDROCK,
        "defect": "BR-53's sweep reads the wrong result key of sagemaker:ListClusters, so a HyperPod cluster never tagged is invisible",
        "find": '\n        "list_clusters",\n        "ClusterSummaries",\n',
        "replace": '\n        "list_clusters",\n        "Clusters",\n',
    },
    {
        "name": "BR-53 drops the AgentCore harnesses",
        "file": BEDROCK,
        "defect": "BR-53's sweep reads the wrong result key of bedrock-agentcore:ListHarnesses, so a harness never tagged is invisible",
        "find": '\n        "list_harnesses",\n        "harnesses",\n',
        "replace": '\n        "list_harnesses",\n        "harnessSummaries",\n',
    },
    {
        "name": "BR-53 calls a cluster GetResources misses never tagged",
        "file": BEDROCK,
        "defect": "BR-53 skips the direct tag read, so a tagged HyperPod cluster or harness tag:GetResources does not return fails as never tagged",
        "find": "\n        if action in RESOURCE_OWNER_SWEEP_TAG_READS:\n",
        "replace": "\n        if False:\n",
    },
    {
        "name": "BR-53 credits an unread harness tag read",
        "file": BEDROCK,
        "defect": "BR-53 counts a resource whose direct tag read failed as owned, so the sweep passes on a read that never happened",
        "find": '\n                except (ClientError, BotoCoreError, TypeError) as error:\n                    unread.append(\n                        f"{tag_action} on {arn}',
        "replace": '\n                except (ClientError, BotoCoreError, TypeError) as error:\n                    direct_owned += 1\n                    continue\n                    unread.append(\n                        f"{tag_action} on {arn}',
    },
    {
        "name": "BR-53 direct tag reads ignore the invocation deadline",
        "file": BEDROCK,
        "defect": "BR-53 keeps reading cluster and harness tags past the deadline",
        "find": '\n                if _deadline_reached():\n                    unread.append(\n                        "{} for {} {}(s) from {} on, {}".format(\n',
        "replace": '\n                if False:\n                    unread.append(\n                        "{} for {} {}(s) from {} on, {}".format(\n',
    },
    {
        "name": "BR-51 matches a provisioned role by its name prefix",
        "file": BEDROCK,
        "defect": "BR-51 lets the AWSReservedSSO_ suffix hold an underscore, so a set named write takes the role of a set named write_extra",
        "find": '\n    pattern = re.compile(rf"AWSReservedSSO_{re.escape(name)}_[0-9A-Za-z]+")\n',
        "replace": '\n    pattern = re.compile(rf"AWSReservedSSO_{re.escape(name)}_.+")\n',
    },
    {
        "name": "BR-51 sets aside a customer managed set with a provisioned role",
        "file": BEDROCK,
        "defect": "BR-51 names every permission set with a customer managed policy as not judged, though its provisioned role is in the cache",
        "find": '\n                if not provisioned["roles"]:\n                    try:\n',
        "replace": "\n                if True:\n                    try:\n",
    },
    {
        "name": "BR-51 ignores a provisioned role the cache failed to read",
        "file": BEDROCK,
        "defect": "BR-51 does not name a provisioned role the permissions cache records as unread",
        "find": "\n    if errored:\n        return {\n",
        "replace": "\n    if False:\n        return {\n",
    },
    {
        "name": "BR-51 drops an unjudged customer managed set from the granting count",
        "file": BEDROCK,
        "defect": "BR-51 leaves a set whose own policies grant AI writes out of the count when its provisioned role is absent, so the summary says no set grants them",
        "find": "\n                    if own:\n                        granting.append(\n",
        "replace": "\n                    if False:\n                        granting.append(\n",
    },
    {
        "name": "BR-51 leaves a federated role without a tag Deny unjudged",
        "file": BEDROCK,
        "defect": "BR-51 never fails an in-account role assumed through a SAML or OIDC provider whose policies carry no aws:PrincipalTag Deny over its AI writes",
        "find": '\n                if tag_deny["uncovered"]:\n',
        "replace": "\n                if False:\n",
    },
    {
        "name": "BR-51 judges a visible instance's SSO role a second time",
        "file": BEDROCK,
        "defect": "BR-51 fails an AWSReservedSSO_ role on its own policies though the visible Identity Center instance already judges it through its permission set",
        "find": '\n                if identity_center["visible"] and role_name.startswith(\n',
        "replace": "\n                if False and role_name.startswith(\n",
    },
    {
        "name": "BR-51 ignores a tag Deny in a federated role's boundary",
        "file": BEDROCK,
        "defect": "BR-51 fails a federated role whose permissions boundary holds the aws:PrincipalTag Deny, because only its identity policies are read",
        "find": '\n        sources.append(("permissions boundary", boundary))\n    services = _ai_write_services(permissions)\n',
        "replace": "\n        pass\n    services = _ai_write_services(permissions)\n",
    },
    {
        "name": "BR-51 passes beside a tag-guarded federated role",
        "file": BEDROCK,
        "defect": "BR-51 reports Passed though a federated role is held only by a session tag whose MFA meaning the provider decides and is not read",
        "find": '\n            if (federated or federated_guarded) and status == "Passed":\n',
        "replace": '\n            if federated and status == "Passed":\n',
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
    "BR-32 spike: Average and Minimum alarms credited": "in the Bedrock guardrail spike alarms",
    "BR-32 spike: a lower-band alarm credited": "in the Bedrock guardrail spike alarms",
    "BR-32 S3 forward: any notification event credited": "in the Bedrock guardrail spike alarms",
    "BR-32 S3 forward: a narrower prefix rule credited": "in the Bedrock guardrail spike alarms",
    "BR-32 composite: an AND rule credits each alarm it names": (
        "in the Bedrock guardrail spike alarms"
    ),
    "BR-32 composite: an ARN reference is not mapped to its name": (
        "in the Bedrock guardrail spike alarms"
    ),
    "BR-32 composite: an unread rule credits its alarms": (
        "in the Bedrock guardrail spike alarms"
    ),
    "BR-20 network: a public rule is not judged": "in the Bedrock knowledge base stores",
    "BR-20 APIAccessAll: only a bare * is wide": "in the Bedrock knowledge base stores",
    "BR-20 source: a PrincipalArn allow-list is not compared": "in the Bedrock knowledge base stores",
    "BR-20 source: S3 Vectors exemptions are not compared": "in the Bedrock knowledge base stores",
    "BR-20 MANAGED: supplemental storage key not judged": "in the Bedrock knowledge base stores",
    "BR-57 scope: only the probe actions are judged": "in the Bedrock agent role scope",
    "BR-57 scope: an unbounded NotAction read on the probe set": "in the Bedrock agent role scope",
    "BR-07 runtime: a draft prompt call counted as versioned": "in the Bedrock runtime prompt references",
    "BR-07 runtime: a capped lookup names its newest event": (
        "in the Bedrock runtime prompt references"
    ),
    "BR-06 centralization: any CloudTrail table credited": "in the Bedrock inference trace",
    "BR-06 centralization: invocation logs not required": "in the Bedrock inference trace",
    "BR-06 log group: a filter pattern forwards every event": "in the Bedrock inference trace",
    "BR-06 log group: field selection forwards every event": "in the Bedrock inference trace",
    "BR-06 log group: transformed events credited": "in the Bedrock inference trace",
    "BR-06 log group: an inactive stream credited": "in the Bedrock inference trace",
    "BR-06 log group: a Lambda processor not held": "in the Bedrock inference trace",
    "BR-06 log group: another account's stream followed": "in the Bedrock inference trace",
    "BR-06 log group: a string-prefix table credited": "in the Bedrock inference trace",
    "BR-06 log group: one dropped subscription blocks a full one": "in the Bedrock inference trace",
    "BR-06 log group: Athena connectors not read": "in the Bedrock inference trace",
    "BR-06 log group: any FEDERATED catalog held": "in the Bedrock inference trace",
    "BR-06 log group: catalogs read in one Region": "in the Bedrock inference trace",
    "BR-06 log group: an unfollowed chain fails": "in the Bedrock inference trace",
    "BR-06 log group: the chain is not consulted": "in the Bedrock inference trace",
    "BR-34 Converse: an earlier untagged turn not judged": "in the Bedrock invocation log guardrail evidence",
    "BR-34 strength: only HIGH blocks a prompt attack": "in the Bedrock invocation log guardrail evidence",
    "BR-27 grounding: Converse qualifiers not read": "in the Bedrock invocation log guardrail evidence",
    "BR-26 front layer: a credited source ends the judgment": "in the Bedrock knowledge base redaction",
    "BR-42 parse: an unparsed policy keeps Passed": "in the Bedrock model allow-list policy reads",
    "BR-42 training: Search results ignored": "in the Bedrock training bucket policies",
    "BR-34 Converse: a tool-result turn is judged as the latest turn": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 InvokeModel: one grounding tag counts as both": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 InvokeModel: an untagged call with an unknown guardrail is judged": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 InvokeModel: the CloudTrail guardrail is not read for grounding": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 InvokeModel: an unjoined call is dropped": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 InvokeModel: a matched call stays pending": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 InvokeModel: the CloudTrail join reads one page": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 InvokeModel: the windowed query stops at the first page": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 InvokeModel: the window ends at the earliest call": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "Converse join: the event's guardrailConfig is ignored": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-34 Converse: a CloudTrail-guarded call is not judged": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 Converse: the joined guardrail version is ignored": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "Converse join: an old call with no event reads as recent": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "Converse join: an unguarded event reads as unread": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "Join: the region run's page budget is not shared": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "Join: a call BR-27 joined is looked up again": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "S3 scan: only the first leg sees each record": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "Capped log scan names the start of the window": (
        "in the Bedrock invocation log guardrail evidence"
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
    "BR-26 credits a credential type as the PII redaction layer": (
        "in the Bedrock knowledge base redaction"
    ),
    "BR-26 drops the regex from the PII redaction layer": (
        "in the Bedrock knowledge base redaction"
    ),
    "BR-26 reads the input side for the PII redaction layer": (
        "in the Bedrock knowledge base redaction"
    ),
    "an object written after the redaction job passes BR-26 again": (
        "in the Bedrock knowledge base redaction"
    ),
    "a guardrail that lets an example key through passes the BR-26 probe": (
        "in the Bedrock guardrail output probe"
    ),
    "BR-26 probe blames no owner policy for a cross-account denial": (
        "in the Bedrock guardrail output probe"
    ),
    "BR-26 probe calls every ARN denial cross-account": (
        "in the Bedrock guardrail output probe"
    ),
    "BR-26 probe ignores the different-account denial message": (
        "in the Bedrock guardrail output probe"
    ),
    "BR-26 probe blames the owner when this account is unknown": (
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
    "BR-04 retains a log object whose replication FAILED": (
        "in the Bedrock invocation log entries"
    ),
    "BR-46 passes an object written between the last run and the latest read": (
        "in the Bedrock knowledge base classification"
    ),
    "BR-46 credits a document with no metadata sidecar": (
        "in the Bedrock knowledge base classification"
    ),
    "BR-20 source: an identity Deny is ignored": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: a missing identity grant reads as a read": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: a boundary Allow counts as a grant": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: a boundary scoped elsewhere is not read": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: a boundary on part of the bucket is credited": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: any wildcard grant reaches the bucket": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: a pattern ending past the bucket covers it": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: a grant on part of the bucket is credited": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: a NotResource Allow excluding a prefix covers the bucket": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: the identity verdict is not read": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 source: an unjudged identity reads as passed": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 SCP: an attached Deny of the source is ignored": "in the Bedrock knowledge base stores",
    "BR-20 SCP: a level with no Allow is not read": "in the Bedrock knowledge base stores",
    "BR-20 SCP: a conditioned level Allow is credited": "in the Bedrock knowledge base stores",
    "BR-20 SCP: a partial level Allow is credited": "in the Bedrock knowledge base stores",
    "BR-20 SCP: an unread inventory reads as applied": "in the Bedrock knowledge base stores",
    "BR-20 SCP: unread policy targets are ignored": "in the Bedrock knowledge base stores",
    "BR-20 SCP: a conditioned Deny is read as total": "in the Bedrock knowledge base stores",
    "BR-20 SCP: the management account is restricted": "in the Bedrock knowledge base stores",
    "BR-20 SCP: no organization reads as unread": "in the Bedrock knowledge base stores",
    "BR-20 SCP: kms:Decrypt is not judged": "in the Bedrock knowledge base stores",
    "BR-20 SCP: the leg never runs": "in the Bedrock knowledge base stores",
    "BR-20 key: a key policy Deny is ignored": "in the Bedrock knowledge base stores",
    "BR-20 key: a conditioned grant is credited": "in the Bedrock knowledge base stores",
    "BR-20 key: kms:ViaService names any Region": "in the Bedrock knowledge base stores",
    "BR-20 key: StringEquals on kms:ViaService takes a wildcard": "in the Bedrock knowledge base stores",
    "BR-20 key: kms:CallerAccount names any account": "in the Bedrock knowledge base stores",
    "BR-20 key: root delegation needs no identity grant": "in the Bedrock knowledge base stores",
    "BR-20 key: an identity Allow on another key counts": "in the Bedrock knowledge base stores",
    "BR-20 key: an identity Deny of decrypt is ignored": "in the Bedrock knowledge base stores",
    "BR-20 key: a role boundary does not limit a direct grant": "in the Bedrock knowledge base stores",
    "BR-20 key: a grant to another principal counts": "in the Bedrock knowledge base stores",
    "BR-20 key: grant constraints are ignored": "in the Bedrock knowledge base stores",
    "BR-20 key: unread grants read as none": "in the Bedrock knowledge base stores",
    "BR-20 key: the key leg never runs": "in the Bedrock knowledge base stores",
    "BR-20 key: an unread key reads as passed": "in the Bedrock knowledge base stores",
    "BR-20 key: each key is read for every bucket": "in the Bedrock knowledge base stores",
    "BR-46 sidecar budget resets for each source": (
        "in the Bedrock knowledge base classification"
    ),
    "BR-46 listing budget is not spent": (
        "in the Bedrock knowledge base classification"
    ),
    "BR-46 capped listing does not name where it stopped": (
        "in the Bedrock knowledge base classification"
    ),
    "BR-43 credits a Region allow-list in the management account": (
        "in the Bedrock management-account SCP credit"
    ),
    "BR-42 credits a model list in the management account": (
        "in the Bedrock management-account SCP credit"
    ),
    "BR-43 credits an AI service Region deny in the management account": (
        "in the Bedrock management-account SCP credit"
    ),
    "BR-43 credits a Region deny that names only the listed invoke actions": (
        "in the Bedrock Region deny service prefixes"
    ),
    "BR-43 credits an AI service Region deny that omits the vector stores": (
        "in the Bedrock Region deny service prefixes"
    ),
    "BR-47 names only five enforcing buckets in its Passed text": (
        "in the Bedrock data path TLS exemptions"
    ),
    "BR-47 drops the SageMaker transform and processing job buckets": (
        "in the Bedrock data path inventory"
    ),
    "BR-47 drops the SageMaker endpoint capture and async buckets": (
        "in the Bedrock data path inventory"
    ),
    "BR-47 drops the Bedrock evaluation job buckets": (
        "in the Bedrock data path inventory"
    ),
    "BR-55 credits an all-zero PCR pin": ("in the Bedrock attestation pins"),
    "BR-48 ignores a service section with no leaf": (
        "in the Bedrock AI opt-out delegation"
    ),
    "BR-26 credits a secrets regex that acts on the output only": (
        "in the Bedrock guardrail secrets regex"
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
    "BR-33 drops a task with no task role": ("in the Bedrock container image scanning"),
    "BR-50 walks one role hop only": ("in the Bedrock AI role chains"),
    "BR-51 skips the role principals of an AI role's trust": (
        "in the Bedrock AI role chains"
    ),
    "BR-51 follows one role hop only": ("in the Bedrock AI role chains"),
    "BR-20 skips the Data Catalog tables of a SQL knowledge base": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 reads no Data Catalog partition locations": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 reads Data Catalog partitions past its page cap": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-07 reads no CreatePrompt holder": ("in the Bedrock prompt creators"),
    "BR-07 lets a prompt creator render prompts": ("in the Bedrock prompt creators"),
    "BR-57 reads no runtime JWT authorizer": ("in the Bedrock runtime inbound gate"),
    "BR-57 credits any account bound on an open runtime policy": (
        "in the Bedrock runtime inbound gate"
    ),
    "BR-57 ignores a runtime policy grant to another account": (
        "in the Bedrock runtime inbound gate"
    ),
    "BR-57 passes beside an unread runtime policy": (
        "in the Bedrock runtime inbound gate"
    ),
    "BR-57 reads no runtime endpoint policy": ("in the Bedrock runtime inbound gate"),
    "BR-02 credits a gateway endpoint for its whole VPC": (
        "in the Bedrock workload route tables"
    ),
    "BR-02 credits a gateway endpoint to a workload with unread subnets": (
        "in the Bedrock workload route tables"
    ),
    "BR-02 leaves a SageMaker runtime workload out": (
        "in the Bedrock workload route tables"
    ),
    "BR-02 passes beside unread route tables": ("in the Bedrock workload route tables"),
    "BR-02 drops the subnets of a Lambda workload": (
        "in the Bedrock workload route tables"
    ),
    "BR-32 passes an acting alarm with no log forwarding": (
        "in the Bedrock guardrail record legs"
    ),
    "BR-32 reads a log group beside S3 as unforwarded": (
        "in the Bedrock guardrail record legs"
    ),
    "BR-32 credits a trail that records another Region": (
        "in the Bedrock guardrail record legs"
    ),
    "BR-32 credits a trail that is not logging": (
        "in the Bedrock guardrail record legs"
    ),
    "BR-32 credits a narrowed guardrail selector": (
        "in the Bedrock guardrail record legs"
    ),
    "BR-32 ignores event data stores for guardrail calls": (
        "in the Bedrock guardrail record legs"
    ),
    "BR-32 passes beside an unread record leg": (
        "in the Bedrock guardrail record legs"
    ),
    "BR-32 drops an unread trail list": ("in the Bedrock guardrail record legs"),
    "BR-46 clears a source by a job alone": (
        "in the Bedrock Macie discovery requirement"
    ),
    "BR-46 fails an unread discovery state": (
        "in the Bedrock Macie discovery requirement"
    ),
    "BR-04 reads agent memory at DRAFT only": (
        "in the Bedrock agent and SageMaker retention legs"
    ),
    "BR-04 passes an agent memory of 0 days": (
        "in the Bedrock agent and SageMaker retention legs"
    ),
    "BR-04 judges inference data at the AWSLogs root": (
        "in the Bedrock agent and SageMaker retention legs"
    ),
    "BR-04 probes replicated inference data it cannot read": (
        "in the Bedrock agent and SageMaker retention legs"
    ),
    "BR-04 passes inference data beside an unread endpoint": (
        "in the Bedrock agent and SageMaker retention legs"
    ),
    "BR-26 credits a Glue PIIDetection node that only audits": (
        "in the Bedrock knowledge base redaction"
    ),
    "BR-26 credits a Glue target one path reaches unmasked": (
        "in the Bedrock knowledge base redaction"
    ),
    "BR-26 matches a Glue path as a name prefix": (
        "in the Bedrock knowledge base redaction"
    ),
    "BR-26 judges the oldest SUCCEEDED Glue run": (
        "in the Bedrock knowledge base redaction"
    ),
    "BR-26 dates a Glue job by a run that did not succeed": (
        "in the Bedrock knowledge base redaction"
    ),
    "BR-26 fails a source over an unread Glue read": (
        "in the Bedrock knowledge base redaction"
    ),
    "BR-26 ignores Glue redaction jobs": ("in the Bedrock knowledge base redaction"),
    "BR-53 trusts GetResources for Bedrock job tags": (
        "in the Bedrock owner tag sweep"
    ),
    "BR-53 reads Bedrock job tags with the tagging API's key case": (
        "in the Bedrock owner tag sweep"
    ),
    "BR-53 fails a job whose tags were not read": ("in the Bedrock owner tag sweep"),
    "BR-53 lists workload identities past the page cap": (
        "in the Bedrock owner tag sweep"
    ),
    "BR-53 drops never-tagged pipelines": ("in the Bedrock owner tag sweep"),
    "BR-20 credits an Aurora store with password logins only": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 reads an absent IAM authentication value as off": (
        "in the Bedrock knowledge base stores"
    ),
    "BR-20 names only one Aurora fix": ("in the Bedrock knowledge base stores"),
    "BR-12 credits a GOVERNANCE-mode invocation log bucket": (
        "in the Bedrock invocation log WORM archive"
    ),
    "BR-12 credits a filter pattern on the invocation log group": (
        "in the Bedrock invocation log WORM archive"
    ),
    "BR-12 follows another account's Firehose stream": (
        "in the Bedrock invocation log WORM archive"
    ),
    "BR-12 credits a Firehose stream with a Lambda processor": (
        "in the Bedrock invocation log WORM archive"
    ),
    "BR-12 credits an inactive Firehose stream": (
        "in the Bedrock invocation log WORM archive"
    ),
    "BR-12 drops the invocation log archive rows": (
        "in the Bedrock invocation log WORM archive"
    ),
    "BR-12 credits a bucket with Object Lock off": (
        "in the Bedrock invocation log WORM archive"
    ),
    "BR-12 credits a filter on transformed logs": (
        "in the Bedrock invocation log WORM archive"
    ),
    "BR-34 credits a detector with AI Protection off": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 credits a disabled GuardDuty detector": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 passes a Region with no GuardDuty detector": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 reads only the first GuardDuty findings page": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 reads only the first GetFindings batch": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 counts archived GuardDuty findings": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 names a non-injection finding as a flagged event": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 names the oldest injection finding first": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 passes an unread GuardDuty detector": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 passes an unread GuardDuty findings list": "in the Bedrock GuardDuty prompt injection leg",
    "BR-34 drops the GuardDuty row from the handler": "in the Bedrock GuardDuty prompt injection leg",
    "BR-57 credits an S3 wildcard bucket name as scoped": "in the Bedrock agent role scope",
    "BR-57 credits a wildcard resource type such as tab*/orders": "in the Bedrock agent role scope",
    "BR-57 reads a bucket-named S3 key wildcard as unscoped": "in the Bedrock agent role scope",
    "BR-57 credits a NotResource grant as scoped": "in the Bedrock agent role scope",
    "BR-57 ignores the permissions boundary on a wide grant": "in the Bedrock agent role scope",
    "BR-57 judges the boundary with the model-only scope test": "in the Bedrock agent role scope",
    "BR-57 passes a conditioned wide grant": "in the Bedrock agent role scope",
    "BR-57 passes a role missing from the IAM cache": "in the Bedrock agent role scope",
    "BR-57 passes a role with a policy read error": "in the Bedrock agent role scope",
    "BR-57 leaves action group function roles out of the scope test": "in the Bedrock agent role scope",
    "BR-57 drops the scope row from the handler": "in the Bedrock agent role scope",
    "BR-57 counts another version of an action group function as outside": "in the Bedrock agent role scope",
    "BR-57 reads only the $LATEST function versions": "in the Bedrock agent role scope",
    "BR-57 drops the outside-function sharing rows": "in the Bedrock agent role scope",
    "BR-57 passes the function row when ListFunctions fails": "in the Bedrock agent role scope",
    "BR-06 skips stores homed in unassessed enabled Regions": "in the Bedrock inference trace",
    "BR-06 ignores an unlisted Region list": "in the Bedrock inference trace",
    "BR-06 traces a failed invoke call": "in the Bedrock inference trace",
    "BR-06 joins the oldest calls": "in the Bedrock inference trace",
    "BR-06 reads calls newer than the settle time": "in the Bedrock inference trace",
    "BR-06 credits an unjoined call as traced": "in the Bedrock inference trace",
    "BR-06 claims logged bodies a record lacks": "in the Bedrock inference trace",
    "BR-06 fails a trace whose read failed": "in the Bedrock inference trace",
    "BR-06 reads text delivery off as unread": "in the Bedrock inference trace",
    "BR-06 ignores a Lake store for centralization": "in the Bedrock inference trace",
    "BR-06 credits any AWSLogs table as CloudTrail": "in the Bedrock inference trace",
    "BR-06 misses a Security Lake CloudTrail table": "in the Bedrock inference trace",
    "BR-06 fails centralization over an unread Glue catalog": "in the Bedrock inference trace",
    "BR-06 drops the trace rows from the handler": "in the Bedrock inference trace",
    "BR-44 passes a Subscribe bound with no invocation block": "in the Bedrock Marketplace invocation gate",
    "BR-44 credits an organization leg with a failed row": "in the Bedrock Marketplace invocation gate",
    "BR-44 fails over an unread BR-42 leg": "in the Bedrock Marketplace invocation gate",
    "BR-42 lists no identity that can invoke any model": "in the Bedrock Marketplace invocation gate",
    "BR-44 is not given the BR-42 identity leg": "in the Bedrock Marketplace invocation gate",
    "BR-42 credits an IfExists or ForAllValues bound on an open training grant": (
        "in the Bedrock training bucket policies"
    ),
    "BR-42 ignores a training grant to another account": (
        "in the Bedrock training bucket policies"
    ),
    "BR-42 credits a bound naming another account": (
        "in the Bedrock training bucket policies"
    ),
    "BR-42 credits any condition on an open training grant": (
        "in the Bedrock training bucket policies"
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
    "BR-34 credits an input tag with another tagSuffix": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-34 judges the first Converse user turn": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-34 credits a Converse turn with no guardContent block": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-27 and BR-34 read nothing from an S3-only log destination": (
        "in the Bedrock invocation log guardrail evidence"
    ),
    "BR-34 reads a large-data body as an invocation log record": (
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
    "SM-34 lets either network key stand for both": "in the SageMaker verdict legs",
    "SM-34 guards only the five original create actions": "in the SageMaker verdict legs",
    "SM-34 holds the tuning job to the encryption keys only": "in the SageMaker verdict legs",
    "SM-34 drops the Studio internet key from its category": "in the SageMaker verdict legs",
    "SM-34 has no non-compliant AppNetworkAccessType value": "in the SageMaker verdict legs",
    "SM-34 probes a job ARN with no category segment": "in the SageMaker verdict legs",
    "SM-09 holds no Studio domain or update action": "in the SageMaker verdict legs",
    "SM-31 passes a capture that records one direction": "in the SageMaker verdict legs",
    "SM-31 takes either capture direction for both": "in the SageMaker verdict legs",
    "SM-31 passes an endpoint whose config was not read": "in the SageMaker verdict legs",
    "SM-43 stops counting at the page that hit the cap": "in the SageMaker verdict legs",
    "SM-43 reports a stopped count as exact": "in the SageMaker verdict legs",
    "SM-43 never spends the counting page budget": "in the SageMaker verdict legs",
    "SM-38 credits a MicroVM selector narrowed by another field": "in the SageMaker verdict legs",
    "SM-38 credits a MicroVM trail that is not logging": "in the SageMaker verdict legs",
    "SM-38 counts a single-Region event data store homed elsewhere": "in the SageMaker verdict legs",
    "SM-38 credits an event data store that is not ENABLED": "in the SageMaker verdict legs",
    "SM-38 never reports a failed ListRegions": "in the SageMaker verdict legs",
    "SM-38 credits a MicroVM flow log in any status": "in the SageMaker verdict legs",
    "SM-38 credits a MicroVM flow log of accepted traffic only": "in the SageMaker verdict legs",
    "SM-38 credits only a subnet-level MicroVM flow log": "in the SageMaker verdict legs",
    "SM-38 fails the MicroVM data events on a partial read": "in the SageMaker verdict legs",
    "SM-38 never runs the MicroVM tier": "in the SageMaker verdict legs",
    "SM-39 drops the SageMaker workloads from its population": "in the SageMaker verdict legs",
    "SM-39 reads only InProgress jobs": "in the SageMaker verdict legs",
    "SM-39 takes one isolated model for the whole endpoint": "in the SageMaker verdict legs",
    "SM-39 ignores a running job's network isolation": "in the SageMaker verdict legs",
    "SM-39 drops an unread SageMaker job": "in the SageMaker verdict legs",
    "SM-39 passes a notebook with direct internet access": "in the SageMaker verdict legs",
    "SM-39 passes a Studio domain that is not VpcOnly": "in the SageMaker verdict legs",
    "SM-39 reports no VPC workload beside an open SageMaker workload": "in the SageMaker verdict legs",
    "SM-39 drops the Bedrock jobs from its population": "in the SageMaker verdict legs",
    "SM-39 reads only the first HyperPod cluster page": "in the SageMaker verdict legs",
    "SM-39 judges a HyperPod cluster's subnets when every group overrides them": "in the SageMaker verdict legs",
    "SM-39 drops a HyperPod restricted instance group": "in the SageMaker verdict legs",
    "SM-39 passes a HyperPod cluster without a VpcConfig": "in the SageMaker verdict legs",
    "SM-39 reads only InProgress Bedrock customization jobs": "in the SageMaker verdict legs",
    "SM-39 skips queued Bedrock batch inference jobs": "in the SageMaker verdict legs",
    "SM-39 passes a Bedrock job without a vpcConfig": "in the SageMaker verdict legs",
    "SM-39 reports no VPC workload beside an open Bedrock job": "in the SageMaker verdict legs",
    "SM-39 drops an unread Bedrock job list": "in the SageMaker verdict legs",
    "SM-39 egress reads only each function's $LATEST": "in the SageMaker verdict legs",
    "SM-39 matches a named function against the qualified $LATEST ARN": "in the SageMaker verdict legs",
    "SM-35 reads a repeated Detective token as the last page": "in the SageMaker verdict legs",
    "SM-38 reads a repeated store token as the last page": "in the SageMaker verdict legs",
    "SM-38 notes a MicroVM without an egress connector out of the Passed row": "in the SageMaker verdict legs",
    "SM-38 credits a MicroVM image version with logging disabled": "in the SageMaker verdict legs",
    "SM-38 credits a MicroVM image version with no log group": "in the SageMaker verdict legs",
    "SM-38 reads only the first MicroVM image version page": "in the SageMaker verdict legs",
    "SM-38 matches a MicroVM image version by image alone": "in the SageMaker verdict legs",
    "SM-38 passes on a MicroVM image version it did not read": "in the SageMaker verdict legs",
    "SM-38 drops the MicroVM image logging read errors": "in the SageMaker verdict legs",
    "SM-11 invoke leg passes with the root user unbound": "in the SageMaker verdict legs",
    "SM-11 invoke leg credits an SCP that misses an invoke action": "in the SageMaker verdict legs",
    "SM-11 invoke leg fails the root user on an unread SCP": "in the SageMaker verdict legs",
    "SM-11 invoke leg ignores an attached SCP": "in the SageMaker verdict legs",
    "SM-11 identity Deny on one invoke action holds the principal": "in the SageMaker verdict legs",
    "SM-37 reads only the latest AgentCore runtime version": "in the SageMaker verdict legs",
    "SM-37 ignores an endpoint's targetVersion": "in the SageMaker verdict legs",
    "SM-37 passes on unlisted AgentCore runtime endpoints": "in the SageMaker verdict legs",
    "SM-37 drops a served AgentCore version it could not read": "in the SageMaker verdict legs",
    "SM-11 lists only the $LATEST Lambda version": "in the SageMaker verdict legs",
    "SM-11 skips every version of a named Lambda function": "in the SageMaker verdict legs",
    "SM-02 never marks a Lambda target AI by grant": "in the SageMaker verdict legs",
    "SM-02 reads only the $LATEST role of a Lambda target": "in the SageMaker verdict legs",
    "SM-02 drops a Lambda target ListFunctions did not return": "in the SageMaker verdict legs",
    "SM-02 passes on a failed Lambda listing": "in the SageMaker verdict legs",
    "SM-02 passes without the cache on an unnamed Lambda target": "in the SageMaker verdict legs",
    "SM-22 drops shadow variants from the deployed-model trace": "in the SageMaker verdict legs",
    "SM-22 approver leg passes over unread versions": "in the SageMaker verdict legs",
    "SM-22 lifecycle leg passes over unread versions": "in the SageMaker verdict legs",
    "SM-22 leaves ListModelPackages to its UNVERSIONED default": "in the SageMaker verdict legs",
    "SM-35 regional leg never reads Detective": "in the SageMaker verdict legs",
    "SM-35 regional leg drops the Macie administrator it read": "in the SageMaker verdict legs",
    "SM-35 takes any Detective membership as the organization graph": "in the SageMaker verdict legs",
    "SM-35 credits a standalone Detective graph": "in the SageMaker verdict legs",
    "SM-35 reads every Detective membership page as the first": "in the SageMaker verdict legs",
    "SM-35 reads Macie's not-administrator answer as an unread": "in the SageMaker verdict legs",
    "SM-35 reads every Macie AccessDenied as Macie being off": "in the SageMaker verdict legs",
    "SM-35 does not fail a Region where Macie is off": "in the SageMaker verdict legs",
    "SM-09 credits a key-group Deny with a weak half": "in the SageMaker verdict legs",
    "SM-33 exempts S3 interface endpoints from private DNS": "in the SageMaker verdict legs",
    "SM-04 passes GuardDuty findings nobody reviewed": "in the SageMaker verdict legs",
    "SM-41 drops iot:RetainPublish from the device actions": "in the SageMaker verdict legs",
    "SM-41 credits a thing attribute two things share": "in the SageMaker verdict legs",
    "SM-23 and SM-31 ignore composite alarm routing": "in the SageMaker verdict legs",
    "SM-43 lets an IMDSv1 instance read the weights": "in the SageMaker verdict legs",
    "SM-43 reads only the first instance": "in the SageMaker verdict legs",
    "SM-40 ignores the MicroVM resume hook": "in the SageMaker verdict legs",
    "SM-02 leaves IAM-authorized methods unjudged": "in the SageMaker verdict legs",
    "SM-02 lets a stage span a slash": "in the SageMaker verdict legs",
    "SM-39 does not count an agent Lambda outside a VPC": "in the SageMaker verdict legs",
    "SM-39 drops EKS cluster subnets": "in the SageMaker verdict legs",
    "SM-33 and SM-11 credit private DNS in a VPC with DNS off": "in the SageMaker verdict legs",
    "SM-33 passes a VPC whose DNS attributes were not read": "in the SageMaker verdict legs",
    "SM-33 reads only the first VPC's DNS attributes": "in the SageMaker verdict legs",
    "SM-18 holds a gateway-served S3 to the DNS attributes": "in the SageMaker verdict legs",
    "SM-40 judges a DELETED MicroVM image": "in the SageMaker verdict legs",
    "SM-40 skips a DELETING MicroVM image": "in the SageMaker verdict legs",
    "SM-11 passes a runtime endpoint in a VPC with DNS off": "in the SageMaker verdict legs",
    "SM-11 passes when a DNS attribute was not read": "in the SageMaker verdict legs",
    "SM-11 reads only the first VPC's DNS attributes": "in the SageMaker verdict legs",
    "SM-41 credits a ForAllValues IsAttached condition": "in the SageMaker verdict legs",
    "SM-36 passes the AI standard without FSBP": "in the SageMaker verdict legs",
    "SM-36 passes central configuration without reading its policy": "in the SageMaker verdict legs",
    "SM-02 ignores the REST API resource policy": "in the SageMaker verdict legs",
    "SM-39 skips standalone ECS tasks in segmentation": "in the SageMaker verdict legs",
    "SM-39 passes a MicroVM with no egress connector in segmentation": "in the SageMaker verdict legs",
    "SM-39 passes a MicroVM with shell ingress": "in the SageMaker verdict legs",
    "SM-39 drops standalone ECS task subnets from egress": "in the SageMaker verdict legs",
    "SM-39 drops Fargate profile subnets from egress": "in the SageMaker verdict legs",
    "SM-39 drops MicroVM connector subnets from the firewall leg": "in the SageMaker verdict legs",
    "SM-39 passes a MicroVM with no egress connector on the firewall leg": "in the SageMaker verdict legs",
    "SM-39 credits a function VPC deny for network connectors": "in the SageMaker verdict legs",
    "SM-40 skips standalone ECS tasks": "in the SageMaker verdict legs",
    "SM-40 ignores a task override's environment": "in the SageMaker verdict legs",
    "SM-11 drops Lambda functions granted AI invoke": "in the SageMaker verdict legs",
    "SM-11 drops ECS workloads granted AI invoke": "in the SageMaker verdict legs",
    "SM-11 ignores a task's overridden task role": "in the SageMaker verdict legs",
    "SM-39 does not follow a transit gateway route": "in the SageMaker verdict legs",
    "SM-39 passes a hub firewall with no HOME_NET": "in the SageMaker verdict legs",
    "SM-39 loses a transit gateway hop to an internet gateway": "in the SageMaker verdict legs",
    "SM-39 follows a blackhole transit gateway route": "in the SageMaker verdict legs",
    "SM-39 trusts a truncated transit gateway route search": "in the SageMaker verdict legs",
    "SM-39 follows another account's VPC attachment": "in the SageMaker verdict legs",
    "SM-39 reads only the first transit gateway route page": "in the SageMaker verdict legs",
    "SM-39 sync row ignores names only the DNS Firewall admits": "in the SageMaker verdict legs",
    "SM-39 sync row ignores targets only the Network Firewall admits": "in the SageMaker verdict legs",
    "SM-39 drops the action of a denied transit gateway read": "in the SageMaker verdict legs",
    "SM-39 sync: an earlier BLOCK does not withdraw a name": "in the SageMaker verdict legs",
    "SM-39 sync: a wildcard BLOCK is matched literally": "in the SageMaker verdict legs",
    "SM-39 sync: an allowed wildcard is compared whole": "in the SageMaker verdict legs",
    "SM-39 sync: a BLOCK inside an allowed wildcard is not recorded": "in the SageMaker verdict legs",
    "SM-39 sync: a refused part another ALLOW answers is not rescued": "in the SageMaker verdict legs",
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
    "AC-53 passes a pair with no message rate alarm": "in the AgentCore verdict legs",
    "AC-53 credits a SampleCount band as latency": "in the AgentCore verdict legs",
    "AC-53 reads an Error SampleCount band as the message rate": "in the AgentCore verdict legs",
    "AC-01 passes a broad public egress range": "in the AgentCore verdict legs",
    "AC-27 passes a gateway policy statement with no source ARN": "in the AgentCore verdict legs",
    "AC-27 credits a source ARN in another account": "in the AgentCore verdict legs",
    "AC-27 credits a wildcard source ARN": "in the AgentCore verdict legs",
    "AC-27 credits a policy variable in a source ARN": "in the AgentCore verdict legs",
    "AC-45 ignores an invoker Deny on a named resource": "in the AgentCore verdict legs",
    "AC-45 subtracts a conditioned invoker Deny": "in the AgentCore verdict legs",
    "AC-45 drops the conditioned invoker Deny from the text": "in the AgentCore verdict legs",
    "AC-45 reads an invoker NotResource Deny as reaching nothing": "in the AgentCore verdict legs",
    "AC-45 compares invoker Deny ARNs case-insensitively": "in the AgentCore verdict legs",
    "AC-45 reads an invoker boundary by action only": "in the AgentCore verdict legs",
    "AC-45 counts an invoker denied this tool": "in the AgentCore verdict legs",
    "AC-45 counts an invoker whose boundary withholds the start action": "in the AgentCore verdict legs",
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
    "AC-22 viewing: an Action wildcard is not a defect": "in the AgentCore verdict legs",
    "AC-06 recording key: kms:Decrypt is not required": "in the AgentCore verdict legs",
    "AC-26 archive: the model invocation log group is not read": "in the AgentCore verdict legs",
    "AC-26 archive: a logs destination is not followed": "in the AgentCore verdict legs",
    "AC-38 prerequisite: an unconditioned forbid does not block": "in the AgentCore verdict legs",
    "AC-35 input guard: a nested read is judged at its top level": "in the AgentCore verdict legs",
    "AC-35 input guard: a named OpenAPI or Smithy operation is not judged": "in the AgentCore verdict legs",
    "AC-51 Firewall Manager: any value of the managed flag counts": "in the AgentCore verdict legs",
    "AC-51 SRT: a pending proactive engagement counts": "in the AgentCore verdict legs",
    "AC-49 alert log: a firewall with no ALERT log is not a gap": "in the AgentCore verdict legs",
    "AC-01 ports: a range from port 1 is not every port": "in the AgentCore verdict legs",
    "AC-48 analyzer: a tag exclusion still covers every role": "in the AgentCore verdict legs",
    "AC-41 personal data: a digit run is a card without Luhn": "in the AgentCore verdict legs",
    "AC-41 personal data: evaluator tags are not scanned": "in the AgentCore verdict legs",
    "AC-34 image: only the first platform of an index is read": "in the AgentCore verdict legs",
    "AC-34 image: Entrypoint and Cmd are not scanned": "in the AgentCore verdict legs",
    "AC-34 image: another account's registry is read": "in the AgentCore verdict legs",
    "AC-34 code: files are not matched for credentials": "in the AgentCore verdict legs",
    "AC-34 code: a .env file's variables are not judged": "in the AgentCore verdict legs",
    "AC-34 code: the unpacked bound is not enforced": "in the AgentCore verdict legs",
    "AC-35 input guard: an S3 schema is not held to its owner": "in the AgentCore verdict legs",
    "BR-43 credits a NotAction Deny that exempts an action of a probed service": (
        "in the Bedrock Region deny service prefixes"
    ),
    "BR-43 stops crediting the Control Tower default S3 exemptions": (
        "in the Bedrock Region deny service prefixes"
    ),
    "BR-53 drops Marketplace model endpoints from the Bedrock inventory": (
        "in the Bedrock owner tag sweep"
    ),
    "BR-53 drops SageMaker transform jobs from the sweep lists": (
        "in the Bedrock owner tag sweep"
    ),
    "BR-39 passes an AI workload on a subnet routed to an internet gateway": (
        "in the Bedrock workload route tables"
    ),
    "BR-39 stops failing an AI workload outside any VPC": (
        "in the Bedrock workload route tables"
    ),
    "BR-02 skips the data path endpoint policies in AI VPCs": (
        "in the Bedrock data path endpoint policies"
    ),
    "BR-02 credits a wildcard bucket name in a data path endpoint policy": (
        "in the Bedrock data path endpoint policies"
    ),
    "BR-12 passes a COMPLIANCE bucket the assessed account owns": (
        "in the Bedrock invocation log WORM archive"
    ),
    "BR-57 drops Lambda MicroVM roles from the agent roles": (
        "in the Bedrock Lambda MicroVM agent legs"
    ),
    "BR-57 passes a MicroVM run with the SHELL_INGRESS connector": (
        "in the Bedrock Lambda MicroVM agent legs"
    ),
    "BR-57 reads a terminated MicroVM as an agent": (
        "in the Bedrock Lambda MicroVM agent legs"
    ),
    "BR-57 drops a failure when no agent role exists": (
        "in the Bedrock Lambda MicroVM agent legs"
    ),
    "BR-47 caps the training job Search at the describe cap": (
        "in the Bedrock data path inventory"
    ),
    "BR-47 ignores the trial component job descriptions": (
        "in the Bedrock data path inventory"
    ),
    "BR-47 skips the jobs a trial component holds": (
        "in the Bedrock data path inventory"
    ),
    "BR-47 reads only each runtime's listed version for code buckets": (
        "in the Bedrock data path inventory"
    ),
    "BR-47 passes beside an unlisted runtime endpoint set": (
        "in the Bedrock data path inventory"
    ),
    "BR-04 passes an overdue log object": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 enters the latest date folder": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 reads one ListObjectsV2 page per level": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 passes a bucket whose deletion evidence was not read": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 keeps the HeadObject cap N/A with no overdue object": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 passes an overdue replica": ("in the Bedrock lifecycle deletion evidence"),
    "BR-04 never dues a Date rule": ("in the Bedrock lifecycle deletion evidence"),
    "BR-55 ignores an all-zero digest in KMS event history": (
        "in the Bedrock attestation event history"
    ),
    "BR-55 reads one LookupEvents page per key": (
        "in the Bedrock attestation event history"
    ),
    "BR-55 passes a key whose event history was not read": (
        "in the Bedrock attestation event history"
    ),
    "BR-55 reads a base64 all-zero digest as a measurement": (
        "in the Bedrock attestation event history"
    ),
    "BR-55 passes past the event history page cap": (
        "in the Bedrock attestation event history"
    ),
    "BR-04 passes an overdue noncurrent version": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 ages a noncurrent version from its own write": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 enters only the first date folder for versions": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 passes a bucket whose version listing failed": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 lists no versions on a versioned bucket": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-04 reads one ListObjectVersions page per level": (
        "in the Bedrock lifecycle deletion evidence"
    ),
    "BR-47 caps evaluation jobs at the SageMaker describe cap": (
        "in the Bedrock data path inventory"
    ),
    "BR-47 drops the evaluation jobs past the read cap": (
        "in the Bedrock data path inventory"
    ),
    "AC-27 credits an address-only Deny as a private path": "in the AgentCore verdict legs",
    "AC-47 credits an address-only Deny as a private path": "in the AgentCore verdict legs",
    "AC-40 safety: an unlisted safety score is not required": "in the AgentCore verdict legs",
    "AC-34 image: file system layers are not scanned": "in the AgentCore verdict legs",
    "AC-34 image: the unpacked layer bound is not enforced": "in the AgentCore verdict legs",
    "AC-34 image: the compressed layer bound is not enforced": "in the AgentCore verdict legs",
    "AC-35 input guard: an MCP server's inline tool schema is not read": "in the AgentCore verdict legs",
    "AC-35 input guard: an MCP server with no static schema is not named": "in the AgentCore verdict legs",
    "AC-26 credits an archive bucket the assessed account owns": "in the AgentCore verdict legs",
    "AC-26 reads an unread bucket owner as another account": "in the AgentCore verdict legs",
    "AC-26 holds a destination's own bucket to another account": "in the AgentCore verdict legs",
    "AC-49 egress: a transit gateway route is not followed": "in the AgentCore verdict legs",
    "AC-49 egress: a remote firewall's unset HOME_NET is credited": "in the AgentCore verdict legs",
    "AC-49 egress: another account's inspection VPC is followed": "in the AgentCore verdict legs",
    "AC-49 egress: a non-VPC transit gateway attachment is followed": "in the AgentCore verdict legs",
    "AC-49 egress: a truncated transit gateway route search is trusted": "in the AgentCore verdict legs",
    "AC-49 egress: a failed transit gateway read is not reported": "in the AgentCore verdict legs",
    "AC-49 sync: a DNS name the firewall allow-list omits is not named": "in the AgentCore verdict legs",
    "AC-49 sync: a firewall target the DNS allow-list omits is not named": "in the AgentCore verdict legs",
    "AC-49 sync: an earlier BLOCK does not withdraw a name": "in the AgentCore verdict legs",
    "AC-49 sync: a DNS Firewall answering every name is compared": "in the AgentCore verdict legs",
    "AC-49 sync: an allowed AWS managed list is skipped": "in the AgentCore verdict legs",
    "AC-45 invoker: a tool role grant an invoker lacks is not named": "in the AgentCore verdict legs",
    "AC-45 invoker: a conditioned invoker grant covers an unconditioned one": "in the AgentCore verdict legs",
    "AC-45 invoker: an invoker's own boundary and Deny are not read": "in the AgentCore verdict legs",
    "AC-45 invoker: a start grant on another tool makes an invoker": "in the AgentCore verdict legs",
    "AC-45 invoker: an unreadable invoker policy is not reported": "in the AgentCore verdict legs",
    "AC-45 invoker: a narrower resource pattern covers a wider one": "in the AgentCore verdict legs",
    "AC-45 invoker: the tool role is counted as its own invoker": "in the AgentCore verdict legs",
    "AC-45 invoker: a tool role grant its own Deny removes is compared": "in the AgentCore verdict legs",
    "AC-45 invoker: an invoker's NotResource covers a pattern": "in the AgentCore verdict legs",
    "AC-45 invoker: an invoker whose Deny removes the start grant is held to the role": "in the AgentCore verdict legs",
    "AC-08 data path: a hosting VPC's endpoints are not judged": "in the AgentCore verdict legs",
    "AC-08 data path: an unresolved hosting VPC is not reported": "in the AgentCore verdict legs",
    "AC-45 shell: a matching character pair ends the pattern overlap": "in the AgentCore verdict legs",
    "AC-08 data path: a tools-only Region is not judged": "in the AgentCore verdict legs",
    "AC-34 image: a digest already read is downloaded again": "in the AgentCore verdict legs",
    "AC-34 image: a digest that failed is downloaded again": "in the AgentCore verdict legs",
    "AC-49 sync: a wildcard BLOCK is matched literally": "in the AgentCore verdict legs",
    "AC-49 sync: an allowed wildcard is compared whole": "in the AgentCore verdict legs",
    "AC-49 sync: a BLOCK inside an allowed wildcard is not recorded": "in the AgentCore verdict legs",
    "AC-49 sync: a refused part another ALLOW answers is not rescued": "in the AgentCore verdict legs",
    "BR-51 credits a ForAllValues: MFA condition": "in the Bedrock AI role chains",
    "BR-57 credits a wildcard partition, service, account or Region": "in the Bedrock agent role scope",
    "BR-57 reads a Bedrock Region wildcard as unscoped": "in the Bedrock agent role scope",
    "BR-57 leaves Lambda MicroVM roles out of the scope test": "in the Bedrock agent role scope",
    "BR-02 lists only the $LATEST function versions": "in the Bedrock workload route tables",
    "BR-02 leaves an ECS workload without awsvpc unplaced": "in the Bedrock workload route tables",
    "BR-02 reads no IRSA roles": "in the Bedrock workload route tables",
    "BR-02 matches an IRSA trust to any OIDC provider": "in the Bedrock workload route tables",
    "BR-53 drops the automated reasoning policies": "in the Bedrock owner tag sweep",
    "BR-53 judges AWS default prompt routers": "in the Bedrock owner tag sweep",
    "BR-04 credits a log group retention setting alone": "in the Bedrock lifecycle deletion evidence",
    "BR-04 searches for expired log events without the deletion window": "in the Bedrock lifecycle deletion evidence",
    "BR-04 passes a log group search that reached its page cap": "in the Bedrock lifecycle deletion evidence",
    "BR-04 credits replicated inference data with an overdue object": "in the Bedrock lifecycle deletion evidence",
    "the data path is handed out uncopied": "in the Bedrock data path inventory",
    "the data path memo outlives its invocation": "in the Bedrock data path inventory",
    "BR-02 hands a half-read container instance to the next workload": "in the Bedrock workload route tables",
    "BR-57 credits a path wildcard inside a name that may hold /": "in the Bedrock agent role scope",
    "BR-57 reads an ARN against the shortest matching type prefix": "in the Bedrock agent role scope",
    "BR-57 fails a secret ARN pinned to its six-character suffix": "in the Bedrock agent role scope",
    "BR-57 credits a secret suffix wildcard of any length": "in the Bedrock agent role scope",
    "BR-57 credits a secret suffix pin after a wildcard name": "in the Bedrock agent role scope",
    "the invocation deadline is never reached": "in the Bedrock invocation deadline",
    "the handler keeps the previous invocation's deadline": "in the Bedrock invocation deadline",
    "the deadline leaves no margin for the report": "in the Bedrock invocation deadline",
    "BR-56 lookups ignore the invocation deadline": "in the Bedrock invocation deadline",
    "BR-56 reports a deadline stop as its page cap": "in the Bedrock invocation deadline",
    "BR-04 log deletion search ignores the invocation deadline": "in the Bedrock invocation deadline",
    "BR-04 oldest object listing ignores the invocation deadline": "in the Bedrock invocation deadline",
    "invocation log scan ignores the invocation deadline": "in the Bedrock invocation deadline",
    "CloudTrail guardrail join ignores the invocation deadline": "in the Bedrock invocation deadline",
    "BR-07 prompt lookup ignores the invocation deadline": "in the Bedrock invocation deadline",
    "evaluation job reads ignore the invocation deadline": "in the Bedrock invocation deadline",
    "BR-46 sidecar reads ignore the invocation deadline": "in the Bedrock invocation deadline",
    "BR-46 prompt credits an output-only PII entity": "in the Bedrock knowledge base classification",
    "BR-46 prompt credits a narrowed enforced configuration": "in the Bedrock knowledge base classification",
    "BR-46 prompt fails beside an unmatched invocation": "in the Bedrock knowledge base classification",
    "BR-46 prompt skips an unguarded invocation": "in the Bedrock knowledge base classification",
    "BR-46 prompt credits any guardrail for an unguarded invocation": "in the Bedrock knowledge base classification",
    "BR-46 prompt fails an unguarded invocation beside an unread enforced guardrail": "in the Bedrock knowledge base classification",
    "BR-46 prompt reads a joined guardrail at its working draft": "in the Bedrock knowledge base classification",
    "BR-46 prompt passes beside an unread guardrail": "in the Bedrock knowledge base classification",
    "BR-46 prompt guardrail listing ignores the invocation deadline": "in the Bedrock invocation deadline",
    "BR-46 prompt version reads ignore the invocation deadline": "in the Bedrock invocation deadline",
    "BR-53 drops the HyperPod clusters": "in the Bedrock owner tag sweep",
    "BR-53 drops the AgentCore harnesses": "in the Bedrock owner tag sweep",
    "BR-53 calls a cluster GetResources misses never tagged": "in the Bedrock owner tag sweep",
    "BR-53 credits an unread harness tag read": "in the Bedrock owner tag sweep",
    "BR-53 direct tag reads ignore the invocation deadline": "in the Bedrock invocation deadline",
    "BR-51 matches a provisioned role by its name prefix": "in the Bedrock Identity Center attributes",
    "BR-51 sets aside a customer managed set with a provisioned role": "in the Bedrock Identity Center attributes",
    "BR-51 ignores a provisioned role the cache failed to read": "in the Bedrock Identity Center attributes",
    "BR-51 drops an unjudged customer managed set from the granting count": "in the Bedrock Identity Center attributes",
    "BR-51 leaves a federated role without a tag Deny unjudged": "in the Bedrock Identity Center attributes",
    "BR-51 judges a visible instance's SSO role a second time": "in the Bedrock Identity Center attributes",
    "BR-51 ignores a tag Deny in a federated role's boundary": "in the Bedrock Identity Center attributes",
    "BR-51 passes beside a tag-guarded federated role": "in the Bedrock Identity Center attributes",
    "BR-02 credits every route table to a Lambda without subnets": "in the Bedrock workload route tables",
    "BR-02 credits an EKS workload a gateway on one route table": "in the Bedrock workload route tables",
    "BR-02 credits an EKS workload beside an unread route table listing": "in the Bedrock workload route tables",
    "BR-02 collects no route table of a gateway VPC": "in the Bedrock workload route tables",
    "BR-02 drops running SageMaker training and processing jobs": "in the Bedrock workload route tables",
    "BR-02 reads every SageMaker job, not only running ones": "in the Bedrock workload route tables",
    "BR-02 reads a processing job's VpcConfig at the top level": "in the Bedrock workload route tables",
    "BR-02 job descriptions ignore the invocation deadline": "in the Bedrock invocation deadline",
    "BR-02 keeps a job whose subnet EC2 does not return": "in the Bedrock workload route tables",
    "BR-10 caps the versions an unversioned pin reads": "in the Bedrock cross-account guardrail reads",
    "BR-10 caps the versions a guardrail condition value reads": "in the Bedrock cross-account guardrail reads",
    "guardrail attachment reads ignore the invocation deadline": "in the Bedrock invocation deadline",
    "a cross-account guardrail denial is not recognised": "in the Bedrock cross-account guardrail reads",
    "BR-10 names GetGuardrail for a denied cross-account version listing": "in the Bedrock cross-account guardrail reads",
    "BR-10 calls any version listing denial the cross-account ceiling": "in the Bedrock cross-account guardrail reads",
    "BR-10 unread row omits the cross-account listing ceiling": "in the Bedrock cross-account guardrail reads",
    "every guardrail denial blames the owner's resource policy": "in the Bedrock cross-account guardrail reads",
    "the attachment inventory drops the cross-account denial text": "in the Bedrock cross-account guardrail reads",
    "BR-10 condition values drop the cross-account denial text": "in the Bedrock cross-account guardrail reads",
    "BR-41 reasoning reads drop the cross-account denial text": "in the Bedrock cross-account guardrail reads",
    "knowledge base screening drops the cross-account denial text": "in the Bedrock cross-account guardrail reads",
    "BR-27 grounding reads drop the cross-account denial text": "in the Bedrock cross-account guardrail reads",
    "BR-46 prompt reads drop the cross-account denial text": "in the Bedrock cross-account guardrail reads",
    "BR-20 compares no Neptune Analytics graph reader": "in the Bedrock knowledge base stores",
    "BR-20 compares no Kendra index reader": "in the Bedrock knowledge base stores",
    "BR-20 drops the Kendra index sources": "in the Bedrock knowledge base stores",
    "BR-20 never merges the Kendra sources": "in the Bedrock knowledge base stores",
    "BR-20 drops the Kendra source read errors": "in the Bedrock knowledge base stores",
    "BR-20 builds a store reader's ARN without its path": "in the Bedrock knowledge base stores",
    "BR-20 ignores an identity Deny of the store read": "in the Bedrock knowledge base stores",
    "BR-20 needs every store read action to survive": "in the Bedrock knowledge base stores",
    "BR-20 ignores an SCP Deny of the store read": "in the Bedrock knowledge base stores",
    "BR-20 ignores an SCP that cannot judge the store read": "in the Bedrock knowledge base stores",
    "BR-20 applies SCPs to a service-linked store reader": "in the Bedrock knowledge base stores",
    "BR-20 judges every store action by the first action's SCP": "in the Bedrock knowledge base stores",
    "BR-20 credits a conditioned store read": "in the Bedrock knowledge base stores",
    "BR-20 ignores the permissions boundary on the store read": "in the Bedrock knowledge base stores",
    "BR-20 counts a grant on another store as a read": "in the Bedrock knowledge base stores",
    "BR-20 ignores principals the cache failed to read": "in the Bedrock knowledge base stores",
    "BR-20 ignores an unread IAM principal listing": "in the Bedrock knowledge base stores",
    "BR-20 ignores a USER_TOKEN Kendra index": "in the Bedrock knowledge base stores",
    "BR-20 counts readers beside a store-level hold": "in the Bedrock knowledge base stores",
    "BR-20 passes beside held store readers": "in the Bedrock knowledge base stores",
    "BR-20 drops a TEMPLATE Kendra source silently": "in the Bedrock knowledge base stores",
    "BR-20 IAM principal listing ignores the invocation deadline": "in the Bedrock invocation deadline",
    "BR-20 Kendra data source reads ignore the invocation deadline": "in the Bedrock invocation deadline",
    "AC-12 credits a gateway's own ARN beside a pattern": "in the AgentCore verdict legs",
    "AC-24 credits a per-tool Throttles series": "in the AgentCore verdict legs",
    "AC-24 credits another gateway's Throttles series": "in the AgentCore verdict legs",
    "AG-27 credits an alarm on a series that is never published": "in the AgentCore verdict legs",
    "AC-27 accepts a consent portal role trust that names the type, not the portal": "in the AgentCore verdict legs",
    "AC-27 credits a portal's ARN listed beside a pattern": "in the AgentCore verdict legs",
    "AC-27 passes an aws:SourceVpc that names no VPC in the account": "in the AgentCore verdict legs",
    "AC-27 judges aws:SourceVpc when DescribeVpcs failed": "in the AgentCore verdict legs",
    "AC-34 loses a credential that straddles two scan chunks": "in the AgentCore verdict legs",
    "AC-34 ignores an API key assigned in code": "in the AgentCore verdict legs",
    "AC-34 fails installed packages' sample credentials": "in the AgentCore verdict legs",
    "AC-34 ignores a quoted Bearer token": "in the AgentCore verdict legs",
    "AC-34 fails a placeholder assigned to a credential name": "in the AgentCore verdict legs",
    "AC-35 judges API Gateway operations the target's toolFilters leave out": "in the AgentCore verdict legs",
    "AC-35 reads a trailing-star filterPath as a literal path": "in the AgentCore verdict legs",
    "AC-35 ignores the methods a toolFilters entry names": "in the AgentCore verdict legs",
    "AC-35 ignores a toolOverrides name": "in the AgentCore verdict legs",
    "AC-35 reads no API Gateway target": "in the AgentCore verdict legs",
    "AC-41 charges a ThirdParty evaluator a customer key": "in the AgentCore verdict legs",
    "AC-41 judges only attached evaluators": "in the AgentCore verdict legs",
    "AC-41 passes when ListEvaluators failed": "in the AgentCore verdict legs",
    "AC-45 passes the invoker bound beside an unread principal": "in the AgentCore verdict legs",
    "AC-46 credits a LINKED_ACCOUNT monitor on other accounts": "in the AgentCore verdict legs",
    "AC-46 fails an AWS managed LINKED_ACCOUNT monitor": "in the AgentCore verdict legs",
    "AC-46 credits a SERVICE monitor that omits AgentCore": "in the AgentCore verdict legs",
    "AC-46 fails a TAG or COST_CATEGORY monitor": "in the AgentCore verdict legs",
    "AC-49 credits one ThreatSignatures category for all": "in the AgentCore verdict legs",
    "AC-49 credits one domain reputation group for all": "in the AgentCore verdict legs",
    "AC-49 passes the threat row when ListRuleGroups failed": "in the AgentCore verdict legs",
    "AC-49 passes the threat row when the ALERT log group is unread": "in the AgentCore verdict legs",
    "AC-49 claims a detection time from a shared log group": "in the AgentCore verdict legs",
    "AC-53 credits a disabled scheduled query": "in the AgentCore verdict legs",
    "AC-53 credits a scheduled query whose last run failed": "in the AgentCore verdict legs",
    "AC-53 fails log groups when a scheduled query is unread": "in the AgentCore verdict legs",
    "AC-53 misreads a log group ARN identifier": "in the AgentCore verdict legs",
    "AC-51 holds a distribution with no web ACL at N/A": "in the AgentCore verdict legs",
    "AG-39 reads the regional body limit on a CloudFront ACL": "in the AgentCore verdict legs",
    "AC-51 reads a global web ACL in the wrong Region": "in the AgentCore verdict legs",
    "AC-51 never judges a fronting distribution's web ACL": "in the AgentCore verdict legs",
    "AC-27 adds an Unrestricted row beside a foreign SourceVpc": "in the AgentCore verdict legs",
    "AC-45 widens a Secrets Manager random-suffix pattern": "in the AgentCore verdict legs",
    "AC-45 credits a wildcard in a resource type with no published sub-resource": "in the AgentCore verdict legs",
    "AC-45 credits a path wildcard inside a name that may hold a slash": "in the AgentCore verdict legs",
    "AC-45 credits a sub-resource under a wildcard parent": "in the AgentCore verdict legs",
    "AC-45 reads an empty resource name as scoped": "in the AgentCore verdict legs",
    "AC-34 matches assignments in files a package RECORD lists": "in the AgentCore verdict legs",
    "AC-34 reads a package RECORD from the archive root only": "in the AgentCore verdict legs",
    "AC-34 fails AWS's EXAMPLE placeholder access key ids": "in the AgentCore verdict legs",
    "AC-34 spares any access key id holding EXAMPLE": "in the AgentCore verdict legs",
    "AC-34 reports a PEM private key header with no body": "in the AgentCore verdict legs",
    "AC-34 reports a PEM block of one base64 line": "in the AgentCore verdict legs",
    "AC-34 reports a PEM block whose footer names another key type": "in the AgentCore verdict legs",
    "AC-34 misses a PEM block whose line breaks are escaped": "in the AgentCore verdict legs",
    "AC-34 carries too little overlap to hold a private key block": "in the AgentCore verdict legs",
    "AC-34 fails any 20-character AKIA value held as a variable": "in the AgentCore verdict legs",
    "AC-34 fails a PEM header held as a variable value": "in the AgentCore verdict legs",
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
