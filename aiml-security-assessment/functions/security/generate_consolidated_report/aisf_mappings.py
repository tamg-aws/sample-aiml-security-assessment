"""AISF framework view: derive `AISF-*` rows from check verdicts that already ship.

The AWS AI Security Framework (AISF) is registered in
`report_template.COMPLIANCE_STANDARDS` as a **derived** standard. No Lambda runs
AISF checks, no AISF CSV is written to S3, and no Step Functions branch exists
for it. Every row in this module is a relabelling of a verdict an incumbent
check already produced, computed at consolidation time by
`derive_aisf_findings()`.

Why derived rather than a producing module: all eight AISF controls handled here
carry verdict `covered` in `aisf-parity/AISF-WORK-LEDGER.md`, which means an
incumbent check already asserts the control exactly. There is nothing new to
call. A control whose ledger verdict is `tighten` must NOT be added here: the
incumbent asserts only part of the control, so restating its `Passed` under the
AISF control id would publish a false pass. `aisf-parity/check_ledger.py`
gate 11 fails if that happens.

**Ids are allocated once and never renumbered.** `AISF_DERIVED_MAP` is
append-only: a new control takes the next free `AISF-` number. Reusing or
resequencing an id silently rewrites the meaning of every archived report and
CSV that already carries it. `AISF-00` is reserved for the coverage marker row
emitted by `derive_aisf_findings()` and must never be allocated to a control.

The control text (risk, severity, resolution, reference) is baked into the literal
because the AISF repository is not on the Lambda's filesystem at runtime.
`aisf-parity/check_ledger.py` gate 12 compares every baked value against the
AISF control YAML, so drift fails a gate rather than shipping.
"""

import logging
from typing import Any, Dict, List

from report_template import GENAI_LENS_URL

logger = logging.getLogger(__name__)

# The report slug this standard's rows route to. Must match the `slug` on the
# AISF entry in `report_template.COMPLIANCE_STANDARDS`.
AISF_SERVICE_SLUG = "aisf"

# Reserved for the coverage marker row (the `OW-00` analogue). Never a control.
AISF_COVERAGE_CHECK_ID = "AISF-00"

# Severity comes from the AISF control's own `risk` field, NOT from the source
# check's severity. This deviates from OWASP, which inherits the source row's
# severity (AGENTS.md:132). The deviation is deliberate: an `AISF-` row is a
# verdict on an AISF control, and the severity of one incumbent check is not
# that control's risk rating. AISF-08 makes the difference concrete: it derives
# from three source checks whose own severities differ, so there is no single
# source severity to inherit.
#
# AISF `risk` has five bands and this repository's `SeverityEnum` has four:
# there is no `Critical`. The collapse below follows the decision recorded at
# `docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md:156-169`
# ("keep four levels; a genuinely critical risk is reported as High"), so this
# module inherits an existing repository decision rather than inventing one.
AISF_RISK_TO_SEVERITY = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

# A band whose collapse changes its name is disclosed in every row it produces.
# The methodology accepts "a genuinely critical risk is reported as High" as a
# known cost of keeping four levels; stating it in the row keeps that cost in
# front of the person reading the finding, who otherwise sees `High` against a
# control AISF rates critical and has no way to tell that a downgrade happened.
# `critical` is the only such band today: `high`, `medium` and `low` keep their
# names. A future band that does not is caught by
# `tests/test_aisf_derived_standard.py` and by `check_ledger.py` gate 12. Adding
# a control in a collapsed band also changes the sentence in
# `docs/SECURITY_CHECKS_AISF.md` that names the three critical ones, which is
# what `TestSeverityCollapseDisclosure.CRITICAL_IDS` pins.
SEVERITY_COLLAPSE_NOTE = {
    "critical": (
        "AISF risk: critical, reported as High because this framework's "
        "severity scale has four levels and no Critical band (see "
        "docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md "
        "section 6)."
    ),
}

# Status `N/A` forces `Severity=Informational`, matching the OWASP rule at
# AGENTS.md:132: a row that asserts nothing must not carry High/Medium.
NA_SEVERITY = "Informational"

# Append-only. See the module docstring: ids are allocated once, never renumbered.
AISF_DERIVED_MAP: List[Dict[str, Any]] = [
    {
        "check_id": "AISF-01",
        "control": "AIR-ACR-GW-01",
        # ledger verdict: covered. incumbents: AG-24
        "sources": ["AG-24"],
        "finding": "AISF AIR-ACR-GW-01: AgentCore Gateway Inbound Authorization",
        "risk": "critical",
        "severity": "High",
        "resolution": "Require a real inbound authorizer on every production Gateway: set authorizerType to CUSTOM_JWT (CustomJWTAuthorizerConfiguration with an OIDC discoveryUrl plus allowedClients/allowedAudience/allowedScopes) for end-user apps, or AWS_IAM (SigV4, bedrock-agentcore:InvokeGateway) for AWS principals. Avoid NONE and AUTHENTICATE_ONLY in production — both offload authorization, so if used they REQUIRE a policy engine, interceptor, or downstream target to make the decision. Authorize the call itself with AgentCore Policy (Cedar) in ENFORCE default-deny (see AIR-ACR-POL-01) plus a fail-safe request interceptor, so tool access does not depend on the model behaving.",
        "reference": "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-inbound-auth.html",
    },
    {
        "check_id": "AISF-02",
        "control": "AIR-ACR-RT-09",
        # ledger verdict: covered. incumbents: AC-06
        "sources": ["AC-06"],
        "finding": "AISF AIR-ACR-RT-09: Agent Browser Session Forensic Record",
        "risk": "medium",
        "severity": "Medium",
        "resolution": "Create the browser tool with session recording enabled — recording.enabled plus an s3Location (bucket + prefix) on CreateBrowser, and an execution role allowed to write there — because it is a create-time property of a custom browser, not something you can switch on after an incident. Recording captures far more than page URLs: session DOM changes and mutations, user actions including clicks, scrolls and form interactions, console logs and error messages, Chrome DevTools Protocol events, and network events and HTTP requests, which is what lets a responder reconstruct what the agent actually did rather than infer it. Add Live View for real-time monitoring of an in-flight session, including taking over or releasing control from the automation, which doubles as a containment step. Then treat the recording bucket as one of the most sensitive stores in the workload — it holds the rendered DOM and form input of authenticated sessions, laid out as s3://bucket/prefix/session-id/batch_N.ndjson.gz — so apply KMS encryption, Block Public Access, a TLS-only bucket policy, tight read access for responders only, and a retention/lifecycle rule. Do NOT plan on CloudTrail for the in-session detail: AgentCore's only data-event resource type is AWS::BedrockAgentCore::Gateway, so there are no Browser data events; CloudTrail gives you the control-plane and session-start record, and the recording plus CloudWatch spans give you the rest.",
        "reference": "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-session-recording.html",
    },
    {
        "check_id": "AISF-03",
        "control": "AIR-BDR-GRD-01",
        # ledger verdict: covered. incumbents: BR-10
        "sources": ["BR-10"],
        "finding": "AISF AIR-BDR-GRD-01: Guardrail Enforced on Model Input and Output",
        "risk": "critical",
        "severity": "High",
        "resolution": "Attach an Amazon Bedrock Guardrail to every production use case and enforce it on both the input and output path by passing guardrailIdentifier and guardrailVersion on each Converse or InvokeModel call — both are required together, and the request is rejected if contentType is not application/json. For self-hosted or third-party models that do not run through Bedrock inference, call the ApplyGuardrail API directly instead — once with source=INPUT before the model sees the prompt, and again with source=OUTPUT before the response reaches the user. Make enforcement mandatory rather than optional per application: deny bedrock:InvokeModel and bedrock:InvokeModelWithResponseStream unless the bedrock:GuardrailIdentifier condition key matches your approved guardrail, so an application cannot simply omit the parameter.",
        "reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html",
    },
    {
        "check_id": "AISF-04",
        "control": "AIR-BDR-GRD-03",
        # ledger verdict: covered. incumbents: BR-26
        "sources": ["BR-26"],
        "finding": "AISF AIR-BDR-GRD-03: Sensitive Data Output Filtering",
        "risk": "critical",
        "severity": "High",
        "resolution": "Configure the Guardrail sensitive-information filter (sensitiveInformationPolicyConfig) with the required PII entity types (piiEntitiesConfig) set to BLOCK or ANONYMIZE on the output path, and add custom regexesConfig patterns for secrets, credentials, and internal identifiers not covered by the built-in PII types; enable the same checks on the input path to stop echoed exfiltration. Verify with an ApplyGuardrail call using source=OUTPUT that the entities are detected and masked or blocked. In tool-using workloads the filter does not reach every field: it does not evaluate toolUse input parameters, toolResult content, or a toolSpec description or input schema, so PII in those fields is neither blocked nor masked — redact tool inputs and results in your own code, or pass them through ApplyGuardrail explicitly, before treating the filter as complete coverage.",
        "reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html",
    },
    {
        "check_id": "AISF-05",
        "control": "AIR-BDR-KB-03",
        # ledger verdict: covered. incumbents: BR-20
        "sources": ["BR-20"],
        "finding": "AISF AIR-BDR-KB-03: Knowledge Base Vector Store Encryption",
        "risk": "high",
        "severity": "High",
        "resolution": "Do not assume one customer managed key covers the whole knowledge base — the default is an AWS owned key, and how far a CMK reaches depends on the vector store. On a Bedrock Managed Knowledge Base the CMK set at creation covers transient ingestion storage and the managed vector store through a Bedrock-created KMS grant, so the creating identity needs kms:CreateGrant, kms:GenerateDataKey and kms:Decrypt on that key conditioned with kms:ViaService bedrock.<region>.amazonaws.com, while the knowledge base service role needs no KMS permissions at all. On a bring-your-own vector store the Bedrock CMK covers only transient ingestion storage and the retrieval session (kmsKeyArn on RetrieveAndGenerate); it reaches the index itself only where Bedrock created that store for you (quick create for OpenSearch Serverless or Amazon S3 Vectors). Otherwise encrypt each store on its own terms: an OpenSearch Serverless collection is always encrypted at rest but uses a CMK only when an encryption policy sets AWSOwnedKey false with KmsARN (or CreateCollection names the key), and the choice is immutable — changing it means recreating the collection. Aurora pgvector inherits the DB cluster's own StorageEncrypted KMS key. Pinecone, Redis Enterprise Cloud and MongoDB Atlas are third-party SaaS that AWS KMS does not encrypt, so the AWS-side controls there are a CMK on the Secrets Manager secret holding the credentials plus TLS in transit. Set serverSideEncryptionConfiguration.kmsKeyArn on each data source. Critically, the key is not the access boundary: OpenSearch Serverless does not check a caller's permissions on the CMK, so anyone a data access policy admits can query the encrypted vectors — restrict the index with the collection's data access policy and network policy plus aoss:APIAccessAll scoped to that one collection ARN.",
        "reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
    },
    {
        "check_id": "AISF-06",
        "control": "AIR-BDR-MDL-10",
        # ledger verdict: covered. incumbents: BR-37
        "sources": ["BR-37"],
        "finding": "AISF AIR-BDR-MDL-10: Bedrock Data Retention Mode Pinned",
        "risk": "high",
        "severity": "High",
        "resolution": "Set the retention mode explicitly and pin it preventively; do not rely on defaults. The mode acts as a ceiling, not a floor — a model whose allowed_modes include none still runs at zero retention regardless of the account setting — but inherit is the default for new accounts and projects, so an unconfigured account has made no decision at all. Set each account with bedrock:PutAccountDataRetention (aws bedrock put-account-data-retention --mode none), whose valid values are default, none, provider_data_share and inherit, then attach an SCP that Denies the write actions unless the mode equals your approved value. Cover both endpoints, because they publish separate condition keys: Deny bedrock:PutAccountDataRetention on StringNotEquals bedrock:DataRetentionMode, and Deny bedrock-mantle:PutAccountDataRetention plus bedrock-mantle:CreateProject and bedrock-mantle:UpdateProject on StringNotEquals bedrock-mantle:DataRetentionMode — the project actions matter because bedrock-mantle allows a per-project override that would otherwise bypass the account-level setting. Verify with GetAccountDataRetention per account rather than by reading the SCP, and check a specific model's effective mode and allowed_modes to see which scope (project, account, or model default) is actually deciding. Both checks are API- or SDK-only, because there is no console UI for data retention at launch — an assessment that goes looking for a console setting will find nothing and wrongly record the control as absent. Understand the trade-off before pinning to none: models whose only allowed mode is provider_data_share (currently Claude Mythos 5 and Claude Fable 5) become unavailable org-wide, surfacing as status unavailable in the models list rather than as an invocation error, and on the Responses API store=true is rejected while background mode is unavailable — that is the intended consequence of requiring zero retention, not a misconfiguration. Where a specific model is genuinely needed under zero retention, the documented route is a per-account, per-model ZDR exception requested through your AWS account team (Anthropic manages eligibility for Claude models), after which none appears in that model's allowed_modes for the approved account only — so treat allowed_modes as an account-specific value to be read per account, not a fixed property of the model. Two residual limits to record rather than assume away: where cross-Region inference is enabled for a retaining model, retained inputs and outputs are stored in the destination Region that processed the request, so a data-residency review has to cover the whole destination set (see AIR-BDR-MDL-03); and AWS's abuse-detection page states, without qualifying it by retention mode, that apparent CSAM in image inputs is blocked and the flagged input or output may be stored and reviewed and reported to NCMEC — so none should not be presented to an auditor as an unqualified guarantee that no content is ever stored.",
        "reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/data-retention.html",
    },
    {
        "check_id": "AISF-07",
        "control": "AIR-SGM-EP-08",
        # ledger verdict: covered. incumbents: SM-18
        "sources": ["SM-18"],
        "finding": "AISF AIR-SGM-EP-08: Batch Inference Network and Encryption Parity",
        "risk": "high",
        "severity": "High",
        "resolution": "A batch transform job inherits its private-network posture from the model, not from the job: set VpcConfig (private-subnet Subnets + SecurityGroupIds) and EnableNetworkIsolation=true on CreateModel, then reference that model by ModelName on CreateTransformJob — the transform job itself takes no VpcConfig or isolation flag. Get the S3 path right, because the obvious reading of network isolation is wrong here and it changes what your endpoint and bucket policies must admit: the algorithm container never reads or writes S3 itself. AWS documents that internal SageMaker processes running on the nodes download the input data and upload the results, and that whether or not you specify VpcConfig the container is given no AWS credentials. With VpcConfig, SageMaker creates two elastic network interfaces — one for the algorithm container and one for Amazon S3 — and EnableNetworkIsolation removes the container's interface while the S3 interface remains and is what carries the transfer. So an Amazon S3 gateway VPC endpoint is still required for a private path, but scope its endpoint policy and the bucket policy to the SageMaker-managed transfer and the job's execution role rather than to any identity inside the container. Encrypt at rest with KMS customer-managed keys on the job — TransformResources.VolumeKmsKeyId for the compute EBS volume and TransformOutput.KmsKeyId for the S3 results — and keep the source/output buckets SSE-KMS with an aws:SecureTransport deny. Note where preventive IAM can and cannot carry this: CreateTransformJob defines sagemaker:OutputKmsKeyArn and sagemaker:VolumeKmsKeyArn condition keys, so the KMS half is enforceable with an SCP on the job itself, while sagemaker:NetworkIsolation, sagemaker:VpcSubnets and sagemaker:VpcSecurityGroupIds are CreateModel keys only — the guardrail has to be written across both actions, and a policy that conditions only on CreateTransformJob leaves the network posture unenforced. This closes the batch-inference path that the real-time endpoint controls (AIR-SGM-EP-01/03) do not cover.",
        "reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/batch-vpc.html",
    },
    {
        "check_id": "AISF-08",
        "control": "AIR-SGM-TRN-05",
        # ledger verdict: covered. incumbents: SM-09, SM-01, SM-03
        "sources": ["SM-09", "SM-01", "SM-03"],
        "finding": "AISF AIR-SGM-TRN-05: Notebook and Development Environment Access Control",
        "risk": "medium",
        "severity": "Medium",
        "resolution": "Hold SageMaker Studio and Notebook Instances to the same bar as production: attach least-privilege execution roles (avoid broad AmazonSageMakerFullAccess), enforce sagemaker:DirectInternetAccess=Disabled, sagemaker:RootAccess=Disabled, private VpcSubnets/VpcSecurityGroupIds and sagemaker:VolumeKmsKeyArn via IAM, and restrict presigned-URL access with aws:SourceIp / aws:sourceVpce conditions on CreatePresignedDomainUrl / CreatePresignedNotebookInstanceUrl. Log all API activity through CloudTrail into CloudWatch and monitor with the AWS Config rules sagemaker-notebook-no-direct-internet-access and sagemaker-notebook-instance-kms-key-configured (both Periodic, so treat them as a lagging backstop to the IAM conditions, and pass kmsKeyArns to the latter to pin approved keys).",
        "reference": "https://docs.aws.amazon.com/whitepapers/latest/sagemaker-studio-admin-best-practices/permissions-management.html",
    },
]


def _source_check_ids() -> set:
    """Every incumbent Check_ID any mapping derives from."""
    return {cid for m in AISF_DERIVED_MAP for cid in m["sources"]}


def _normalise(row: Dict[str, Any]) -> Dict[str, str]:
    """Read a source row under either key casing.

    The report Lambda hands this function CSV-cased rows (`Check_ID`, `Region`,
    `Account_ID`); the root consolidator's rows are lowercase-keyed
    (`consolidate_html_reports.py:146-156`). Normalising on input means one
    derivation serves both callers.
    """
    return {
        "check_id": str(row.get("Check_ID", row.get("check_id", "")) or "").strip(),
        "account_id": str(
            row.get("Account_ID", row.get("account_id", "")) or ""
        ).strip(),
        "region": str(row.get("Region", row.get("region", "")) or "").strip(),
        "status": str(row.get("Status", row.get("status", "")) or "").strip(),
    }


def _collapse_note(risk: str, status: str) -> str:
    """The pre-collapse disclosure for one row, empty when nothing was collapsed.

    An `N/A` row carries `Informational` regardless of the control's risk, so it
    says which severity it is carrying and why: without that clause the note
    would read as a claim about this row's severity instead of about the band.
    """
    note = SEVERITY_COLLAPSE_NOTE.get(risk, "")
    if note and status == "N/A":
        note = f"{note} This row carries {NA_SEVERITY} because it asserts no verdict."
    return note


def _legs_txt(present: Dict[str, List[str]], have: List[str]) -> str:
    """Name each present leg with its verdicts, multiplicity included.

    One incumbent check emits one finding per resource, so a leg routinely holds
    several statuses for one account and region: 16 for `AG-24` and 11 for the
    `SM-09`/`SM-01`/`SM-03` leg in one account and region, measured against a
    real account. Quoting one status per leg would credit a Failed resource to
    whichever verdict happened to be listed last, and the derived status is
    aggregated over all of them, so the sentence that explains the status has to
    show the same population.
    """
    order = {"failed": 0, "passed": 1, "n/a": 2}
    parts = []
    for cid in have:
        statuses = present[cid]
        if len(statuses) == 1:
            parts.append(f"{cid} ({statuses[0]})")
            continue
        counts: Dict[str, int] = {}
        for status in statuses:
            counts[status] = counts.get(status, 0) + 1
        # Sorted by verdict, not by the order the rows arrived in, so the same
        # findings in a different CSV order produce the same sentence.
        breakdown = ", ".join(
            f"{n} {s or 'blank'}"
            for s, n in sorted(
                counts.items(), key=lambda kv: (order.get(kv[0].lower(), 3), kv[0])
            )
        )
        parts.append(f"{cid} ({len(statuses)} findings: {breakdown})")
    return ", ".join(parts)


def _aggregate_status(statuses: List[str]) -> str:
    """Failed if any leg failed; Passed only if every leg passed; else N/A."""
    lowered = [s.lower() for s in statuses]
    if any(s == "failed" for s in lowered):
        return "Failed"
    if lowered and all(s == "passed" for s in lowered):
        return "Passed"
    return "N/A"


def _row(
    check_id: str,
    finding: str,
    details: str,
    resolution: str,
    reference: str,
    severity: str,
    status: str,
    account_id: str,
    region: str,
) -> Dict[str, str]:
    """Build one derived finding in the CSV-cased shape the report layer reads.

    Every key here is read by `report_template.generate_table_rows` (:201-234),
    which accepts either casing via `finding.get("x", finding.get("X"))`.
    """
    if status == "N/A":
        severity = NA_SEVERITY
    return {
        "Check_ID": check_id,
        "Finding": finding,
        "Finding_Details": details,
        "Resolution": resolution,
        "Reference": reference,
        "Severity": severity,
        "Status": status,
        "Region": region,
        "Account_ID": account_id,
        "_service": AISF_SERVICE_SLUG,
    }


def derive_aisf_findings(source_rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Restate incumbent verdicts as `AISF-` rows, one per control per join key.

    The join key is `(Account_ID, Region)`. All ten source checks are regional
    (none is tagged with the `Global` sentinel), so a control's legs share a key.

    A control whose legs are not all present for a key that has at least one leg
    is emitted as `Status=N/A` naming the missing `Check_ID`s, never dropped: a
    silent drop would read as "this control was not relevant here" when what
    actually happened is that coverage was incomplete.

    Per-row work is isolated with try/except, matching
    `owasp_assessments.build_owasp_mapping_findings`, so one malformed source
    row drops only itself.
    """
    relevant = _source_check_ids()
    # (account_id, region) -> {source check id: [status per source finding]}
    # A list, not a status: an incumbent check emits one finding per resource, so
    # one check id contributes several statuses to one key. Keeping only the last
    # one published a Passed for a key that held a Failed resource whenever the
    # check emitted its summary Passed row after its per-resource rows, which is
    # the order BR-20 emits in.
    legs: Dict[tuple, Dict[str, List[str]]] = {}
    for raw in source_rows:
        try:
            row = _normalise(raw)
            if row["check_id"].upper() not in relevant:
                continue
            key = (row["account_id"], row["region"])
            legs.setdefault(key, {}).setdefault(row["check_id"].upper(), []).append(
                row["status"]
            )
        except Exception as e:
            logger.warning(f"AISF: skipping unreadable source row: {e}")
            continue

    findings: List[Dict[str, str]] = []
    for (account_id, region), present in sorted(legs.items()):
        absent_controls: List[str] = []
        for mapping in AISF_DERIVED_MAP:
            try:
                sources = mapping["sources"]
                have = [cid for cid in sources if cid in present]
                missing = [cid for cid in sources if cid not in present]
                if not have:
                    # No leg at all for this key. Reported once per key by the
                    # AISF-00 row below rather than as a per-control N/A, so an
                    # account that never ran a service does not get a wall of
                    # rows for controls that were never in play.
                    absent_controls.append(
                        f"{mapping['check_id']} ({mapping['control']}, "
                        f"sources {', '.join(sources)})"
                    )
                    continue
                legs_txt = _legs_txt(present, have)
                if missing:
                    status = "N/A"
                    details = (
                        f"AISF control {mapping['control']}. Derived from "
                        f"{legs_txt}. Source checks not found for this account "
                        f"and region: {', '.join(missing)}. Coverage is "
                        "incomplete, so no verdict is asserted for this control."
                    )
                else:
                    status = _aggregate_status(
                        [s for cid in have for s in present[cid]]
                    )
                    details = (
                        f"AISF control {mapping['control']}. Derived from "
                        f"{legs_txt}. This row restates existing check verdicts "
                        "under an AISF control id; it is not an additional check."
                    )
                note = _collapse_note(mapping["risk"], status)
                if note:
                    details = f"{details} {note}"
                findings.append(
                    _row(
                        check_id=mapping["check_id"],
                        finding=mapping["finding"],
                        details=details,
                        resolution=mapping["resolution"],
                        reference=mapping["reference"],
                        severity=mapping["severity"],
                        status=status,
                        account_id=account_id,
                        region=region,
                    )
                )
            except Exception as e:
                logger.warning(
                    f"AISF: skipping mapping {mapping.get('check_id')} for "
                    f"{account_id}/{region}: {e}"
                )
                continue

        if absent_controls:
            findings.append(
                _row(
                    check_id=AISF_COVERAGE_CHECK_ID,
                    finding="AISF Derived Control Coverage",
                    details=(
                        "AISF-relevant source checks were present for this "
                        "account and region, but no source check was found for "
                        f"{len(absent_controls)} derived control(s): "
                        f"{'; '.join(absent_controls)}. Those controls are "
                        "unassessed here rather than compliant."
                    ),
                    resolution=(
                        "Review the upstream assessment for the named source "
                        "checks and rerun. This row is informational and "
                        "records incomplete AISF coverage, not a control "
                        "failure."
                    ),
                    reference=GENAI_LENS_URL,
                    severity=NA_SEVERITY,
                    status="N/A",
                    account_id=account_id,
                    region=region,
                )
            )

    return findings
