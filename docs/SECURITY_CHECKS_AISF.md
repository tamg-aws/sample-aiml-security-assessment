# AWS AI Security Framework (AISF) Checks

This document catalogs the `AI-XX` rows the report renders under "By Compliance
Standard", the AWS AI Security Framework control each one reports on, and the
shipped BR/SM/AC/AG check every row is derived from.

- **Reference:** [AWS Well-Architected Generative AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/generative-ai-lens.html),
  plus the control-specific AWS documentation linked in the per-control tables
  below.
- **Opt-in:** none. AISF is a derived view over checks that already run, so it
  needs no deployment parameter and adds no scan time.
- **Report location:** the "By Compliance Standard" sidebar section, alongside
  OWASP Top 10 for LLM.
- **Coverage:** 8 of the 78 in-scope AISF controls are currently derivable from
  checks that already ship; the remaining 70 are not yet assessed. The parity
  analysis behind those figures is in
  [`aisf-parity/AISF-WORK-LEDGER.md`](../aisf-parity/AISF-WORK-LEDGER.md).

## Disclaimer

> **These mappings are PRELIMINARY and ILLUSTRATIVE.** They have not been
> reviewed by AWS Security Assurance Services or external auditors. Validate
> each mapping against your own reading of the AISF control before relying on
> an `AI-` row as audit evidence. A control that is absent from this catalog is
> unassessed, which is not evidence of compliance.

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
map, and gate 12 fails if the control text baked into the map drifts from the
AISF control definition.

**`AI-` rows are not counted in the framework's 208-check total.** They carry no
new assertion, so counting them would double-count the incumbent check. They
are excluded from the report's pass-rate denominator and from Open Action Items
for the same reason, which is how OWASP-mapped rows already behave.

**Ids are allocated once and never renumbered.** `AISF_DERIVED_MAP` is
append-only: a new control takes the next free `AI-` number. Reusing or
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
| no source check for the control present at all | no `AI-` row for that control; the absence is reported once per account and region by `AI-00` |

`AI-00` is a report-completeness marker, not an AISF control. It lists every
derived control that had no source check for that account and region, so an
incomplete scan reads as unassessed instead of silently omitting rows.

### Severity

Severity comes from the AISF control's own `risk` band, not from the source
row. An `AI-` row is a verdict on an AISF control, and one incumbent check's
severity is not that control's risk rating; `AI-08` makes that concrete, since
its three source checks carry different severities. AISF uses five risk bands
and this framework's `SeverityEnum` has four, so `critical` and `high` both
report as `High`, following section 6 of
[SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md](SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md),
which keeps four levels and accepts that a genuinely critical risk is reported
as `High`. The three controls AISF rates `critical` (`AI-01`, `AI-03`, `AI-04`)
name that band and the downgrade in their `Finding_Details`, so a reader who
sees `High` against a critical control learns why from the finding itself.
A row with `Status=N/A` always reports `Informational`.

## Check catalogue

| Check | AISF control | Severity | Source checks |
| ------- | -------------- | ---------- | --------------- |
| AI-00 | none (coverage marker) | Informational | none |
| AI-01 | AIR-ACR-GW-01 | High | `AG-24` |
| AI-02 | AIR-ACR-RT-09 | Medium | `AC-06` |
| AI-03 | AIR-BDR-GRD-01 | High | `BR-10` |
| AI-04 | AIR-BDR-GRD-03 | High | `BR-26` |
| AI-05 | AIR-BDR-KB-03 | High | `BR-20` |
| AI-06 | AIR-BDR-MDL-10 | High | `BR-37` |
| AI-07 | AIR-SGM-EP-08 | High | `SM-18` |
| AI-08 | AIR-SGM-TRN-05 | Medium | `SM-09`, `SM-01`, `SM-03` |

### AI-01 AIR-ACR-GW-01 Gateway Inbound Authorization

When the gateway exposes tools or APIs to a model, does it enforce its own
inbound authentication and authorization, independent of what the model
requests?

| Source | Signal |
| -------- | -------- |
| AG-24 | Agentic AI Gateway Inbound Authorization (`CUSTOM_JWT` / `AWS_IAM` authorizer configured and enforced) |

Reference: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-inbound-auth.html>

### AI-02 AIR-ACR-RT-09 Agent Browser Session Forensic Record

For browser-based agent tools, is there a forensic record of what the agent did
in the browser session (pages visited, actions taken)?

| Source | Signal |
| -------- | -------- |
| AC-06 | AgentCore Browser Session Recording (capture and replay configured) |

Reference: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-session-recording.html>

### AI-03 AIR-BDR-GRD-01 Guardrail Enforced on Model Input and Output

Is a content-safety guardrail applied to model input and output for every
production use case, instead of being left optional per application?

| Source | Signal |
| -------- | -------- |
| BR-10 | Bedrock Guardrail IAM Enforcement Check (guardrail attachment enforced on the invocation path) |

Reference: <https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html>

### AI-04 AIR-BDR-GRD-03 Sensitive Data Output Filtering

Is leakage of sensitive data types (PII, secrets, credentials) through model
output specifically checked for and blocked or redacted?

| Source | Signal |
| -------- | -------- |
| BR-26 | Guardrail Sensitive Information Filter Check (PII and regex filter policy) |

Reference: <https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html>

### AI-05 AIR-BDR-KB-03 Knowledge Base Vector Store Encryption

Is the underlying vector store or index for a knowledge base encrypted and
access-restricted the same way as the source data it was built from?

| Source | Signal |
| -------- | -------- |
| BR-20 | Knowledge Base Customer-Managed KMS Encryption Check |

Reference: <https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html>

### AI-06 AIR-BDR-MDL-10 Bedrock Data Retention Mode Pinned

Is the Amazon Bedrock data-retention mode explicitly set and pinned org-wide,
so no account or project can opt into sharing prompts and outputs with a model
provider?

| Source | Signal |
| -------- | -------- |
| BR-37 | Bedrock Account Data Retention (`GetAccountDataRetention` mode explicitly set) |

Reference: <https://docs.aws.amazon.com/bedrock/latest/userguide/data-retention.html>

### AI-07 AIR-SGM-EP-08 Batch Inference Network and Encryption Parity

Are batch (offline) inference jobs that process data in bulk held to the same
private-network and encryption standard as real-time inference?

| Source | Signal |
| -------- | -------- |
| SM-18 | SageMaker Transform Job Encryption Check (model VPC/isolation config plus job KMS configuration) |

Reference: <https://docs.aws.amazon.com/sagemaker/latest/dg/batch-vpc.html>

### AI-08 AIR-SGM-TRN-05 Notebook and Development Environment Access Control

Is access to notebook instances and development environments used for model
experimentation restricted and monitored the same way as production access?

This is the one control with several source checks. All three legs must report
`Passed` for `AI-08` to report `Passed`; any `Failed` leg makes it `Failed`;
a leg that is missing or `N/A` makes it `N/A` and the finding details name the
leg.

| Source | Signal |
| -------- | -------- |
| SM-09 | SageMaker Notebook Root Access Check |
| SM-01 | SageMaker Internet Access Check |
| SM-03 | SageMaker Data Protection Check |

Reference: <https://docs.aws.amazon.com/whitepapers/latest/sagemaker-studio-admin-best-practices/permissions-management.html>

## Adding a control

1. Confirm the control's ledger verdict is `covered` in
   `aisf-parity/aisf-work-ledger.json`. A `tighten` verdict means the incumbent
   asserts less than the control does; close the gap in the incumbent check
   first.
2. Append an entry to `AISF_DERIVED_MAP` with the next free `AI-` number, the
   incumbent `Check_ID`s exactly as the ledger row names them, and the
   control's `risk`, `rec`, and first `src` URL copied from the AISF control
   YAML.
3. Update the `scope_text` figures on the AISF entry in `COMPLIANCE_STANDARDS`
   and the coverage sentence in this file. Gate 12 compares both against
   `AISF_DERIVED_MAP` and the ledger, so a stale figure fails the gate.
4. Add the row to the check catalogue above with its own per-control section.
5. Run `python3 aisf-parity/check_ledger.py` (expects 12 of 12) and
   `.venv/bin/python -m pytest tests/test_aisf_derived_standard.py -v`.
