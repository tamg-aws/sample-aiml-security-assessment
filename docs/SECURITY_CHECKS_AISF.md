# AWS AI Security Framework (AISF) Checks

This document catalogs the `AISF-XX` rows the report renders under "By
Compliance Standard", the AWS AI Security Framework control each one reports on,
and the shipped BR/SM/AC/AG check every row is derived from.

- **Reference:** [AWS Well-Architected Generative AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/generative-ai-lens.html),
  plus the control-specific AWS documentation linked in the per-control tables
  below.
- **Opt-in:** none. AISF is a derived view over checks that already run, so it
  needs no deployment parameter and adds no scan time.
- **Report location:** the "By Compliance Standard" sidebar section, alongside
  OWASP Top 10 for LLM.
- **Coverage:** 8 of the 78 in-scope AISF controls carry a derived `AISF-` row;
  the remaining 70 are not yet rendered as a row. A row is a narrower claim than
  coverage, so read this figure with the ledger census below it: 28 of the 78 are
  `covered`, all 8 rows sit on `covered` controls, and the other 20 `covered`
  controls are named by the `Compliance_Frameworks` tag column until each is
  walked through [Adding a control](#adding-a-control), which allocates an id and
  writes a per-control section. The 70 without a row are 20 `covered`, 18
  `tighten`, 18 `new`, 11 `unassessed` and 3 `not_implementable`. The parity
  analysis behind those figures is in
  [`aisf-parity/AISF-WORK-LEDGER.md`](../aisf-parity/AISF-WORK-LEDGER.md).
- **Traceability:** 18 controls are `tighten`, covered too partly to earn an
  `AISF-` row at all. The `Compliance_Frameworks` CSV column names all 46
  taggable controls on the producer rows themselves, the 28 `covered` and the 18
  `tighten`, and is described under
  [Traceability column on producer rows](#traceability-column-on-producer-rows).
  A tag carries no verdict.

## Disclaimer

> **These mappings are PRELIMINARY and ILLUSTRATIVE.** They have not been
> reviewed by AWS Security Assurance Services or external auditors. Validate
> each mapping against your own reading of the AISF control before relying on
> an `AISF-` row as audit evidence. A control that is absent from this catalog
> is unassessed, which is not evidence of compliance.

## Design

AISF is a **derived** compliance standard. No Lambda runs AISF checks, no
`aisf_security_report_*.csv` is written to S3, and the state machine has no
AISF branch. `derive_aisf_findings()` in
`aiml-security-assessment/functions/security/generate_consolidated_report/aisf_mappings.py`
runs at consolidation time in both report paths (the
`generate_consolidated_report` Lambda for single-account runs, and the root
`consolidate_html_reports.py` for multi-account runs) and restates verdicts the
incumbent checks already produced under AISF control ids.

Every control below carries verdict `covered` in the parity ledger, meaning one
or more incumbent checks assert the control exactly. A control whose ledger
verdict is `tighten` is deliberately excluded: its incumbent asserts only part
of the control, so republishing that incumbent's `Passed` under the AISF
control id would publish a pass the assessment never earned.
`aisf-parity/check_ledger.py` gate 11 fails if a `tighten` control reaches the
map, gate 12 fails if the control text baked into the map drifts from the
AISF control definition, and gate 13 fails if an id does not carry the
registered `AISF-` prefix or is missing from this catalogue.

**`AISF-` rows are not counted in the framework's 218-check total.** They carry
no new assertion, so counting them would double-count the incumbent check. They
are excluded from the report's pass-rate denominator and from Open Action Items
for the same reason, which is how OWASP-mapped rows already behave.

**Ids are allocated once and never renumbered.** `AISF_DERIVED_MAP` is
append-only: a new control takes the next free `AISF-` number. Reusing or
resequencing an id rewrites the meaning of every archived report that already
carries it.

### Registry entry

The standard is registered by one entry in `COMPLIANCE_STANDARDS`
(`report_template.py`) carrying `"derived": True`. That key keeps the slug out
of the S3 prefix list the report Lambda builds in `app.py`: the Lambda's
`s3:ListBucket` grant restricts `s3:prefix` to the producing artifacts, so
listing a prefix for a standard that writes no CSV returns `AccessDenied` and
fails report generation for every category. A producing standard (the
OWASP-style wire-up in
[DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md#adding-a-compliance-standard-owasp-style))
omits the key.

### Status semantics

| Situation | Emitted |
| ----------- | --------- |
| every source check for the control passed | `Passed` |
| any source check for the control failed | `Failed` |
| a source check reported `N/A`, so no verdict is available | `N/A`, `Informational` |
| some source checks present for the account and region, others absent | `N/A`, `Informational`, naming the absent `Check_ID`s |
| no source check for the control present at all | no `AISF-` row for that control; the absence is reported once per account and region by `AISF-00` |

A source check emits one finding per resource, so a leg normally carries several
verdicts for one account and region. All of them are aggregated, and
`Finding_Details` names the count per leg (`BR-20 (10 findings: 9 Failed, 1
Passed)`), so a failing resource cannot be hidden behind a later `Passed` row
from the same check. BR-20 emits its summary `Passed` row after its per-resource
rows, which is the order that made this concrete.

`AISF-00` is a report-completeness marker, not an AISF control. It lists every
derived control that had no source check for that account and region, so an
incomplete scan reads as unassessed instead of silently omitting rows.

### Severity

Severity comes from the AISF control's own `risk` band, not from the source
row. An `AISF-` row is a verdict on an AISF control, and one incumbent check's
severity is not that control's risk rating; `AISF-08` makes that concrete,
since its three source checks carry different severities. AISF uses five risk
bands and this framework's `SeverityEnum` has four, so `critical` and `high`
both report as `High`, following section 6 of
[SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md](SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md),
which keeps four levels and accepts that a genuinely critical risk is reported
as `High`. The three controls AISF rates `critical` (`AISF-01`, `AISF-03`,
`AISF-04`) name that band and the downgrade in their `Finding_Details`, so a
reader who sees `High` against a critical control learns why from the finding
itself. A row with `Status=N/A` always reports `Informational`.

## Check catalogue

| Check | AISF control | Severity | Source checks |
| ------- | -------------- | ---------- | --------------- |
| AISF-00 | none (coverage marker) | Informational | none |
| AISF-01 | AIR-ACR-GW-01 | High | `AG-24` |
| AISF-02 | AIR-ACR-RT-09 | Medium | `AC-06` |
| AISF-03 | AIR-BDR-GRD-01 | High | `BR-10` |
| AISF-04 | AIR-BDR-GRD-03 | High | `BR-26` |
| AISF-05 | AIR-BDR-KB-03 | High | `BR-20` |
| AISF-06 | AIR-BDR-MDL-10 | High | `BR-37` |
| AISF-07 | AIR-SGM-EP-08 | High | `SM-18` |
| AISF-08 | AIR-SGM-TRN-05 | Medium | `SM-09`, `SM-01`, `SM-03` |

### AISF-01 AIR-ACR-GW-01 Gateway Inbound Authorization

When the gateway exposes tools or APIs to a model, does it enforce its own
inbound authentication and authorization, independent of what the model
requests?

| Source | Signal |
| -------- | -------- |
| AG-24 | Agentic AI Gateway Inbound Authorization (`CUSTOM_JWT` / `AWS_IAM` authorizer configured and enforced) |

Reference: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-inbound-auth.html>

### AISF-02 AIR-ACR-RT-09 Agent Browser Session Forensic Record

For browser-based agent tools, is there a forensic record of what the agent did
in the browser session (pages visited, actions taken)?

| Source | Signal |
| -------- | -------- |
| AC-06 | AgentCore Browser Session Recording (capture and replay configured) |

Reference: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-session-recording.html>

### AISF-03 AIR-BDR-GRD-01 Guardrail Enforced on Model Input and Output

Is a content-safety guardrail applied to model input and output for every
production use case, instead of being left optional per application?

| Source | Signal |
| -------- | -------- |
| BR-10 | Bedrock Guardrail IAM Enforcement Check (guardrail attachment enforced on the invocation path) |

Reference: <https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html>

### AISF-04 AIR-BDR-GRD-03 Sensitive Data Output Filtering

Is leakage of sensitive data types (PII, secrets, credentials) through model
output specifically checked for and blocked or redacted?

| Source | Signal |
| -------- | -------- |
| BR-26 | Guardrail Sensitive Information Filter Check (PII and regex filter policy) |

Reference: <https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html>

### AISF-05 AIR-BDR-KB-03 Knowledge Base Vector Store Encryption

Is the underlying vector store or index for a knowledge base encrypted and
access-restricted the same way as the source data it was built from?

| Source | Signal |
| -------- | -------- |
| BR-20 | Knowledge Base Customer-Managed KMS Encryption Check |

Reference: <https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html>

### AISF-06 AIR-BDR-MDL-10 Bedrock Data Retention Mode Pinned

Is the Amazon Bedrock data-retention mode explicitly set and pinned org-wide,
so no account or project can opt into sharing prompts and outputs with a model
provider?

| Source | Signal |
| -------- | -------- |
| BR-37 | Bedrock Account Data Retention (`GetAccountDataRetention` mode explicitly set) |

Reference: <https://docs.aws.amazon.com/bedrock/latest/userguide/data-retention.html>

### AISF-07 AIR-SGM-EP-08 Batch Inference Network and Encryption Parity

Are batch (offline) inference jobs that process data in bulk held to the same
private-network and encryption standard as real-time inference?

| Source | Signal |
| -------- | -------- |
| SM-18 | SageMaker Transform Job Encryption Check (model VPC/isolation config plus job KMS configuration) |

Reference: <https://docs.aws.amazon.com/sagemaker/latest/dg/batch-vpc.html>

### AISF-08 AIR-SGM-TRN-05 Notebook and Development Environment Access Control

Is access to notebook instances and development environments used for model
experimentation restricted and monitored the same way as production access?

This is the one control with several source checks. All three legs must report
`Passed` for `AISF-08` to report `Passed`; any `Failed` leg makes it `Failed`;
a leg that is missing or `N/A` makes it `N/A` and the finding details name the
leg.

| Source | Signal |
| -------- | -------- |
| SM-09 | SageMaker Notebook Root Access Check |
| SM-01 | SageMaker Internet Access Check |
| SM-03 | SageMaker Data Protection Check |

Reference: <https://docs.aws.amazon.com/whitepapers/latest/sagemaker-studio-admin-best-practices/permissions-management.html>

## Traceability column on producer rows

The `AISF-` rows above are derived verdicts. The `Compliance_Frameworks` column
is the second half of the parity work and publishes no verdict at all: it tags
rows the BR/SM/AC/AG/AR checks already emit with the AISF control each check
contributes to, so a reader of `bedrock_security_report_*.csv` can trace a row
back to the framework. The `Status` column still carries the verdict.

Measured by `check_ledger.py` gate 14, which prints each of these figures on
every run: 49 check-control pairs over 41 tagged checks in 4 modules, naming 46
distinct controls. Tagged checks per module are bedrock 17, sagemaker 11,
agentcore 12, agent_registry 1.

### The qualifier is what makes a `tighten` control safe to name

Gate 11 keeps a `tighten` control out of `AISF_DERIVED_MAP`, because an `AISF-`
row restates the incumbent's `Passed` under the control id. A tag restates
nothing, so it may name a partly-covered control as long as it says so. Three
forms, and gate 14 derives which one is correct from the ledger row instead of
trusting the literal in the file:

| Tag | Means |
| ----- | ------- |
| `AISF AIR-BDR-GRD-01` | this check alone asserts the whole control |
| `AISF AIR-SGM-TRN-05 (1 of 3 checks)` | the control is covered, but jointly, so no single leg asserts it |
| `AISF AIR-BDR-MDL-08 (partial)` | the check asserts less than the control requires, and the gap is open in the ledger |

Census at the current head, also printed by gate 14: 26 bare, 18 `(partial)`, 5
joint. The 26 bare tags plus the two jointly covered controls, `AIR-BDR-MDL-02`
over 2 checks and `AIR-SGM-TRN-05` over 3, account for the 28 `covered`
controls; the 18 `(partial)` tags are the 18 `tighten` controls, one tag each. A
bare tag on a `tighten` row, or a dropped `(1 of N)`, fails gate 14 with the
row's verdict and incumbent count named.

A check that contributes to several controls carries them pipe-joined, with the
`AISF ` prefix repeated on each element so a consumer that splits on `|` gets a
complete token. `AC-02` names four controls that way, all `(partial)`. `SM-03` is the case that
mixes forms inside one value, a bare `AIR-SGM-TRN-02` beside
`AIR-SGM-TRN-05 (1 of 3 checks)`; no check pairs a `(partial)` with a tag of
another form.

### Generated, not hand-written

`aisf-parity/gen_compliance_maps.py` renders one map module per producer from
the ledger, resolving each incumbent to the module that emits it. `--check`
re-renders and diffs without writing, which is gate 15. Gate 14 asserts the same
maps semantically with its own logic, so a wrong derivation cannot pass by
agreeing with itself: a semantically legal hand-edit, such as reordering two
entries, passes gate 14 and fails gate 15.

The map files are named per producer (`aisf_compliance_bedrock.py` and so on)
for a measured reason. All six producers name their files `schema.py` and
`app.py`, and `app.py` reaches its schema with `from schema import
create_finding`, resolved through `sys.modules` under that bare name. With four
files all called `aisf_compliance.py`, loading two producers into one
interpreter gave the second one the first one's map, and
`aisf_frameworks("BR-10")` returned `""` inside the bedrock module. The symptom
is an empty tag and no `ImportError`, so nothing raises.

### Scope, and what it does not cover

- **CSV and the schema contract only.** The column reaches all four producer
  CSVs. `generate_table_rows` renders 6 columns and never reads the field, so
  the HTML report does not show it; a 7th column would touch the OWASP and
  FinServ sections plus the `colspan="6"` assertions.
- **4 producer modules, not 5.** `owasp_assessments` is excluded because the
  ledger names no `OW-` incumbent for any control, so the field would ship
  unpopulated on every OWASP row.
- **`responsible_ai_grc_assessments` is untouched.** It already declared the
  field and populates it from its own 64-entry `COMPLIANCE_MAP`, none of whose
  26 tokens is AISF. Its frozen inventory baseline, whose tuples carry the
  compliance string as their 5th element, is unchanged.
- **The lookup cannot be bypassed.** Every finding in the four producers is
  built by `create_finding`, and
  `test_no_producer_builds_a_finding_outside_create_finding` fails if any is
  assembled as a literal dict. Such a row would ship an empty tag silently,
  because `csv.DictWriter` raises on a key the fieldnames lack and never on a
  key a row is missing. That same `extrasaction="raise"` default couples the
  schema field to the fieldnames list, so landing one without the other raises
  `ValueError` on the first row. `agentcore_assessments` builds its header
  twice, once for the no-findings case, and both lists are asserted.

## Live verification

The local battery proves the mapping is internally consistent. It cannot prove a
row reports anything against real infrastructure, and a row that only ever
returns one verdict is indistinguishable from a working one in every offline
test. `aisf-parity/probe_live.py` measures that separately: it runs each
incumbent check against an account and records, per `AISF-` row, whether the
findings reach **BOTH** verdicts, **ONE_ONLY**, **NONE**, or are **VACUOUS**
(emitted by a short-circuit rather than by exercising the check's logic).

A ONE_ONLY row is excused only when the check's own source makes the second
verdict unreachable. The probe recomputes that from the AST every run
(`REACHABLE`, `ELSE_GUARDED`, `SINGLETON`, `NO_VERDICT_PATH`), so no excuse
survives an edit that makes the missing verdict reachable, and nothing has to be
kept in sync by hand.

It is not part of `gate_all.sh`, because it needs AWS credentials and measures an
account rather than this tree. The battery prints `live leg: NOT RUN here` on
every run so a green battery is never mistaken for live evidence.

```bash
AWS_PROFILE=<profile> .venv/bin/python aisf-parity/probe_live.py --region us-east-1
aisf-parity/probe_live.py --selftest    # 11 classifier cases, no credentials
```

Two rows need a fixture that no ordinary account has, both documented with their
cost and teardown in `aisf-parity/LIVE-FIXTURES.md`. Measured at the current
head: BOTH=4, ONE_ONLY=4, NONE=0, VACUOUS=0.

The tag column has its own live leg, `aisf-parity/probe_live_tags.py`, because
the offline tests cannot reach the question it asks. Each of them builds its
findings from check ids read out of the map being tested, so the round trip proves
the lookup and not that the key is an id a producer emits. The `AG-` ids are split
across three producers, which makes the substring check in
`test_a_tag_names_a_check_its_own_module_emits` weaker than it looks: the string is
present in modules that do not emit it, so a key filed under the wrong module
ships a permanently empty column with every test green. The probe reads the CSVs a
real run left in the assessment bucket, which are the authoritative set of emitted
ids, and reports a key the run did not emit as UNPROVEN rather than as a pass. It
then reads each row's shipped `Compliance_Frameworks` value and requires it to equal
this tree's map, and separately replays the rows through the real `create_finding`
and `generate_csv_report`. The replay compares the map against itself and so covers
the rendering path; the as-written comparison is the one that can see a deployed
artifact built from stale source.

```bash
AWS_PROFILE=<profile> .venv/bin/python aisf-parity/probe_live_tags.py \
    --bucket <assessment bucket> --region us-east-1
aisf-parity/probe_live_tags.py --selftest   # 12 classifier cases, no credentials
```

Measured against execution `2654a727`, written by a CodeBuild run that resolved to
commit `6ac8dca`: 13/13 assertions, 31/31 map keys confirmed against an id the
module really emitted, 0 unproven, 0 misplaced, 115 of 356 rows tagged as the run
wrote them, 0 producers disagreeing. The head has moved past `6ac8dca` since, and
the probe still passes because the commits since then touch no map, `schema.py` or
`app.py`: the deployed maps and this tree's maps are the same bytes. Check that
before reusing an older run's CSVs, because the as-written section compares them
against whatever the tree says now. Because a 100% result is also what a probe measuring
nothing prints, every live assertion was driven red once against real CSVs; the four
injections and their observed failures are tabulated in
`aisf-parity/LIVE-FIXTURES.md`.

That deploy is what closes the last hop. The running artifact is built by CodeBuild
from a GitHub branch, so the tree alone could never evidence it; the build resolved
to commit `6ac8dca` and the CSVs it produced carry the 9-column header and a tag
column that agrees with this tree on all 356 rows. What remains unproven is the
run's currency: a pass says the artifact that wrote those CSVs agrees with this
tree, not that the run is recent, which is why `--bucket` prints the execution's
timestamp and `--csv-dir` says it cannot.

## Adding a control

1. Confirm the control's ledger verdict is `covered` in
   `aisf-parity/aisf-work-ledger.json`. A `tighten` verdict means the incumbent
   asserts less than the control does; close the gap in the incumbent check
   first.
2. Append an entry to `AISF_DERIVED_MAP` with the next free `AISF-` number, the
   incumbent `Check_ID`s exactly as the ledger row names them, and the
   control's `risk`, `rec`, and first `src` URL copied from the AISF control
   YAML.
3. Update the `scope_text` figures on the AISF entry in `COMPLIANCE_STANDARDS`
   and the coverage sentence in this file. Gate 12 compares both against
   `AISF_DERIVED_MAP` and the ledger, so a stale figure fails the gate.
4. Add the row to the check catalogue above with its own per-control section.
5. Regenerate the tag maps with `.venv/bin/python
   aisf-parity/gen_compliance_maps.py`, and commit the four files it writes. A
   control that became `covered` is also newly taggable, and a control that was
   already tagged `(partial)` changes qualifier when its verdict moves, so the
   maps go stale on the same edit. Gate 15 fails if the shipped maps are not what
   the ledger renders, and gate 14 fails if a qualifier disagrees with the row.
6. Run the whole local battery, recording its exit code into the same file
   because step 8 reads it:

   ```bash
   bash aisf-parity/gate_all.sh --out /tmp/battery.txt
   echo "BATTERY_EXIT=$?" >>/tmp/battery.txt
   ```

   It wraps the ledger gates, the three pytest sessions CI runs and both ruff
   commands, and prints the denominator beside every verdict. Run it with bash:
   under zsh `PIPESTATUS` is empty and a failing run would be read as clean. A
   bare `pytest responsible_ai_grc_tests/` collects nothing and exits 4 while
   looking like a pass, so gate 3 runs that path as a positive control and fails
   if it ever succeeds.
7. Run `.venv/bin/python aisf-parity/mutate.py`. Before it mutates anything it
   validates every entry's find-string against its file and prints
   `entries 17/17 find-strings validated`, aborting and naming each entry whose
   string no longer occurs exactly once, so a battery that lost entries to a
   refactor cannot report a clean run on the entries it still reached. It then
   breaks the code 17 ways and requires a ledger gate or a test to go red for
   each one, naming the catcher it observed: 5 defects in the derived mapping, 6
   in `BR-20`'s S3 Vectors legs, 5 in the tag column and 1 in the ledger's
   markdown renderer. The `(partial)` entry reads its target check out of the
   shipped maps at run time, because a branch that respells one qualifier would
   otherwise silently cost the battery that entry. A mutation nothing catches
   means the new control's assertions are missing; the answer is an assertion,
   not a gentler mutation.
8. Before any push, run `.venv/bin/python aisf-parity/push_safety.py
   --battery-output /tmp/battery.txt -- git push origin <branch>`. It pushes
   nothing: it asserts the remote is the fork and not `aws-samples`, that no
   commit in the range carries a secret or an attribution line, that the push is
   neither a force nor aimed at `main`, and it re-reads the recorded battery run
   to confirm every gate that file claims actually reported at this commit.
9. Run `probe_live.py` against an account that has a resource on each side of the
   new control. If the new row comes back ONE_ONLY with a `REACHABLE`
   classification, the missing verdict is a missing fixture, not a waiver: add it
   to `aisf-parity/LIVE-FIXTURES.md` with its cost and its teardown.
10. Run `probe_live_tags.py --bucket <assessment bucket>` against the CSVs of a
    run that scanned an account holding the new control's resource. A new map key
    that comes back UNPROVEN has not been confirmed against a real emitted id, so
    it is unverified rather than passing; a key reported MISPLACED is filed under a
    producer that does not emit it and ships an empty column. The run has to be a
    deploy of the branch under test: the as-written section compares the shipped
    column against this tree, so CSVs from an earlier build fail it, and that
    failure is the point rather than a nuisance.
