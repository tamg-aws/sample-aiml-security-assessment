#!/usr/bin/env python3
"""Generate the AISF parity work ledger from the verdict table.

The verdict table below is the single source of truth. It was derived by reading
both sides of every pair: the AISF control's assertion and the incumbent check's
actual comparison. See AISF-PARITY-PROPOSAL.md section 4.4 for the reasoning.

Run:  python3 aisf-parity/build_ledger.py
Emits aisf-parity/aisf-work-ledger.json and aisf-parity/AISF-WORK-LEDGER.md.

Neither output is hand-edited. Change ROWS, re-run, commit both.
"""

import json
import os
from datetime import date

# verdict values
COVERED = "covered"  # an incumbent already asserts this; nothing to write
TIGHTEN = "tighten"  # an incumbent asserts part of it
NEW = "new"  # no incumbent asserts any part of it
NOT_IMPL = "not_implementable"  # flagged machine_checkable but is not
UNASSESSED = "unassessed"  # in scope, dedup pass not yet run

# disposition values, for TIGHTEN rows only (proposal decision 2)
EXTEND = "extend"  # incumbent name is honest, assertion merely narrower
NEW_ID = "new_id"  # incumbent name claims more than it asserts

# (control, verdict, disposition, module, incumbents, gap, extra_iam, phase)
ROWS = [
    # ---------------- BDR: 19 controls, bedrock_assessments ----------------
    ("AIR-BDR-GRD-01", COVERED, None, "bedrock_assessments", ["BR-10"], "", [], 3),
    ("AIR-BDR-GRD-03", COVERED, None, "bedrock_assessments", ["BR-26"], "", [], 3),
    ("AIR-BDR-KB-03", COVERED, None, "bedrock_assessments", ["BR-20"], "", [], 3),
    (
        "AIR-BDR-MDL-10",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-37"],
        "same GetAccountDataRetention call",
        [],
        3,
    ),
    ("AIR-BDR-GRD-02", COVERED, None, "bedrock_assessments", ["BR-34"], "", [], 3),
    ("AIR-BDR-GRD-04", COVERED, None, "bedrock_assessments", ["BR-32"], "", [], 3),
    ("AIR-BDR-GRD-09", COVERED, None, "bedrock_assessments", ["BR-27"], "", [], 3),
    ("AIR-BDR-GRD-10", COVERED, None, "bedrock_assessments", ["BR-41"], "", [], 3),
    ("AIR-BDR-KB-06", COVERED, None, "bedrock_assessments", ["BR-06"], "", [], 3),
    ("AIR-BDR-MDL-07", COVERED, None, "bedrock_assessments", ["BR-06"], "", [], 3),
    (
        "AIR-BDR-MDL-02",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-04", "BR-12"],
        "",
        [],
        3,
    ),
    ("AIR-BDR-KB-01", COVERED, None, "bedrock_assessments", ["BR-46"], "", [], 3),
    ("AIR-BDR-MDL-01", COVERED, None, "bedrock_assessments", ["BR-42"], "", [], 3),
    ("AIR-BDR-MDL-03", COVERED, None, "bedrock_assessments", ["BR-43"], "", [], 3),
    ("AIR-BDR-MDL-04", COVERED, None, "bedrock_assessments", ["BR-44"], "", [], 3),
    ("AIR-BDR-MDL-09", COVERED, None, "bedrock_assessments", ["BR-45"], "", [], 3),
    (
        "AIR-BDR-KB-05",
        NOT_IMPL,
        None,
        None,
        [],
        "depends on customer Lambda code, not configuration",
        [],
        None,
    ),
    (
        "AIR-BDR-KB-08",
        NOT_IMPL,
        None,
        None,
        [],
        "depends on customer Lambda code, not configuration",
        [],
        None,
    ),
    (
        "AIR-BDR-MDL-08",
        TIGHTEN,
        EXTEND,
        "bedrock_assessments",
        ["BR-07"],
        "BR-07 holds the catalog leg (ListPrompts non-empty is its Passed row, zero prompts "
        "is Not Applicable) and its second row only counts variants. The "
        "production-version leg is unwritten and cannot be written on the calls BR-07 "
        "already makes: bare ListPrompts returns each prompt's DRAFT, and BR-07's "
        "get_prompt omits promptVersion, which the API documents as returning the working "
        "draft, so a version != DRAFT test over either reports Failed for every prompt in "
        "every account and no configuration clears it. The falsifiable form is "
        "ListPrompts(promptIdentifier=...) for that prompt's version list, "
        "GetPrompt(promptVersion=N) for customerEncryptionKeyArn, which PromptSummary does "
        "not carry, and for flows the prompt node's resource.promptArn version suffix, "
        "with inline being the hardcoded prompt the control names",
        [],
        4,
    ),
    # ---------------- SGM: 11 controls, sagemaker_assessments ----------------
    (
        "AIR-SGM-EP-08",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-18"],
        "",
        [],
        3,
    ),
    (
        "AIR-SGM-TRN-05",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-09", "SM-01", "SM-03"],
        "all three legs present",
        [],
        3,
    ),
    ("AIR-SGM-EP-01", COVERED, None, "sagemaker_assessments", ["SM-11"], "", [], 3),
    ("AIR-SGM-EP-02", COVERED, None, "sagemaker_assessments", ["SM-02"], "", [], 3),
    ("AIR-SGM-GOV-01", COVERED, None, "sagemaker_assessments", ["SM-22"], "", [], 3),
    ("AIR-SGM-TRN-02", COVERED, None, "sagemaker_assessments", ["SM-03"], "", [], 3),
    ("AIR-SGM-EP-06", COVERED, None, "sagemaker_assessments", ["SM-31"], "", [], 3),
    ("AIR-SGM-GOV-10", COVERED, None, "sagemaker_assessments", ["SM-32"], "", [], 3),
    ("AIR-SGM-TRN-01", COVERED, None, "sagemaker_assessments", ["SM-33"], "", [], 3),
    ("AIR-SGM-TRN-08", COVERED, None, "sagemaker_assessments", ["SM-34"], "", [], 3),
    (
        "AIR-SGM-EP-03",
        NOT_IMPL,
        None,
        None,
        [],
        "slug names sagemaker_endpoint_intercontainer_encryption_enabled but "
        "EnableInterContainerTrafficEncryption is absent from DescribeEndpointConfig and present "
        "only on DescribeTrainingJob; do not port as written, fix in the AISF repo first",
        [],
        None,
    ),
    # ---------------- ACR: 37 controls, agentcore_assessments ----------------
    (
        "AIR-ACR-GW-01",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-24"],
        "AG-24 accepts authorizerType in {AWS_IAM, CUSTOM_JWT}, or AUTHENTICATE_ONLY with a "
        "policy engine in ENFORCE, which is GW-01's assertion exactly",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-09",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-06"],
        "recording.enabled is True plus an S3 bucket",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-01",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AC-02"],
        "AC-02 detects AgentCore full-access and wildcard grants only, so a role holding a "
        "single over-broad named action passes it",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-10",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AC-02"],
        "AC-02 detects full-access and wildcard grants only",
        [],
        4,
    ),
    (
        "AIR-ACR-PAY-01",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AC-02"],
        "AC-02 detects full-access and wildcard grants only",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-03",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AC-02"],
        "AC-02 detects full-access and wildcard grants only",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-05",
        TIGHTEN,
        NEW_ID,
        "agentcore_assessments",
        ["AC-17"],
        'AC-17 is named "Online Evaluation Coverage" but tests only status == ACTIVE, '
        "executionStatus == ENABLED and bool(evaluators); it never reads a sampling rate and "
        "never asks which evaluators, so coverage is the one thing it does not measure",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-06",
        TIGHTEN,
        NEW_ID,
        "agentcore_assessments",
        ["AC-17"],
        'AC-17 is named "Online Evaluation Coverage" and never asks which evaluators are '
        "attached, so it cannot distinguish a safety evaluator from a latency one",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-03",
        TIGHTEN,
        NEW_ID,
        "agentcore_assessments",
        ["AC-10"],
        'AC-10 is named "Resource-Based Policies Check" but reports only that a policy is '
        "present and never evaluates its conditions, so the confused-deputy leg is unasserted",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-13",
        TIGHTEN,
        NEW_ID,
        "agentcore_assessments",
        ["AC-10"],
        'AC-10 is named "Resource-Based Policies Check" but never evaluates policy conditions, '
        "so the aws:SourceVpc / aws:SourceVpce leg is unasserted; both keys are 0 hits "
        "corpus-wide",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-04",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AC-08"],
        "AC-08 tests endpoint existence and available state, not endpoint policy or "
        "security-group scope; it does hold one leg GW-04 lacks, endpoint health",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-05",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AG-27"],
        "AG-27 has the WAF leg; the rate-limit leg needs ListGatewayRateLimits, "
        "so botocore >= 1.43.66",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-05",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AC-14"],
        "AC-14 has the CMK leg; the string 'secret' appears 0 times in the module, so the "
        "secret-scan leg is unwritten",
        [],
        4,
    ),
    (
        "AIR-ACR-MEM-01",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AC-07"],
        "AC-07's presence-only CMK test is sound (encryptionKeyArn is an optional "
        "customer-supplied CreateMemory input); MEM-01 adds per-actor and namespace "
        "access scoping",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-04",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AC-11"],
        "AC-11's presence-only CMK test is sound; POL-04 adds key-policy scoping plus a "
        "disable/delete alarm",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-01",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AG-25"],
        "AG-25 tests mode ENFORCE plus status/enforcementMode ACTIVE, with no default-deny "
        "leg, no decision log, and nothing session-aware",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-07",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AG-25"],
        "AG-25 has no session-aware leg",
        [],
        4,
    ),
    (
        "AIR-ACR-REG-02",
        TIGHTEN,
        NEW_ID,
        "agent_registry_assessments",
        ["AR-03"],
        'AR-03 is named "Publication Approval Governance" but covers auto-approval only, '
        "behind the REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL env gate; no curator/publisher "
        "separation and no EventBridge rule",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-08",
        TIGHTEN,
        EXTEND,
        "agentcore_assessments",
        ["AC-01"],
        "AC-01 requires VPC placement and flags public subnets but never reads what the "
        "security-group rules permit; describe_security_groups is 0 hits in the module, so "
        "VPC placement is proven and egress filtering is not",
        ["ec2:DescribeSecurityGroups"],
        4,
    ),
    (
        "AIR-ACR-EVAL-02",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "PassRole returns 0 across all six modules; AssumeRolePolicyDocument is read once at "
        ":2725 but only to match principal.Service for role discovery, never a condition",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-03",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "confused-deputy conditions absent: SourceAccount/SourceArn are 1 hit corpus-wide, "
        "in sagemaker_assessments, none in AgentCore",
        [],
        4,
    ),
    ("AIR-ACR-EVAL-04", NEW, None, "agentcore_assessments", [], "", [], 4),
    ("AIR-ACR-EVAL-07", NEW, None, "agentcore_assessments", [], "", [], 4),
    (
        "AIR-ACR-GW-02",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "asserts an SCP; the corpus already enumerates SCPs in two modules, so the cost is "
        "the Organizations read",
        ["organizations:ListPolicies", "organizations:DescribePolicy"],
        4,
    ),
    ("AIR-ACR-GW-08", NEW, None, "agentcore_assessments", [], "", [], 4),
    ("AIR-ACR-GW-10", NEW, None, "agentcore_assessments", [], "", [], 4),
    (
        "AIR-ACR-ID-04",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "asserts an SCP; same Organizations read as GW-02",
        ["organizations:ListPolicies", "organizations:DescribePolicy"],
        4,
    ),
    (
        "AIR-ACR-ID-08",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "GetAgentRuntime.authorizerConfiguration exists in botocore 1.43.85 and is never read "
        "anywhere; AG-24 is gateway-only, ID-08 is about the runtime",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-11",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "the corpus reads authorizerType exactly once, at :3578, and never reads "
        "authorizerConfiguration; customJWTAuthorizer.{allowedAudience, allowedClients, "
        "allowedScopes, customClaims, discoveryUrl} are all present in the API and unread, so "
        "a gateway that trusts any issuer passes AG-24 today",
        [],
        4,
    ),
    ("AIR-ACR-MEM-07", NEW, None, "agentcore_assessments", [], "", [], 4),
    (
        "AIR-ACR-MEM-12",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "CloudTrail event selectors; reads no AgentCore API",
        ["cloudtrail:GetEventSelectors", "cloudtrail:ListTrails"],
        4,
    ),
    (
        "AIR-ACR-OBS-02",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "CloudTrail event selectors; reads no AgentCore API",
        ["cloudtrail:GetEventSelectors", "cloudtrail:ListTrails"],
        4,
    ),
    (
        "AIR-ACR-OBS-03",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "AC-04 is X-Ray tracingConfig.enabled over list_agent_runtimes only, so it cannot "
        "cover Gateway, Memory, Policy or Identity, which is OBS-03's whole subject; this row "
        "was a tightening in an earlier draft and the resource-scope check moved it",
        [],
        4,
    ),
    (
        "AIR-ACR-OBS-04",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "CloudWatch Logs data-protection policy",
        ["logs:GetDataProtectionPolicy", "logs:DescribeAccountPolicies"],
        4,
    ),
    (
        "AIR-ACR-OBS-06",
        NEW,
        None,
        "agentcore_assessments",
        [],
        "OAM sink policy",
        ["oam:ListSinks", "oam:GetSinkPolicy"],
        4,
    ),
    ("AIR-ACR-POL-06", NEW, None, "agentcore_assessments", [], "", [], 4),
    ("AIR-ACR-RT-04", NEW, None, "agentcore_assessments", [], "", [], 4),
    # ------- FND, AI-resource subject: 11 controls, dedup pass not yet run -------
    (
        "AIR-FND-DAT-01",
        UNASSESSED,
        None,
        ["bedrock_assessments", "responsible_ai_grc_assessments"],
        ["BR-20", "FS-65"],
        "candidate incumbents only; dedup not run. Spans two modules: BR-20 covers knowledge "
        "base CMK, FS-65 covers the data-source buckets",
        [],
        5,
    ),
    (
        "AIR-FND-DAT-02",
        UNASSESSED,
        None,
        "bedrock_assessments",
        [],
        "needs s3:GetBucketPolicy, which no function is granted",
        ["s3:GetBucketPolicy"],
        5,
    ),
    (
        "AIR-FND-DAT-03",
        UNASSESSED,
        None,
        "responsible_ai_grc_assessments",
        [],
        "macie2 already granted to this function",
        [],
        5,
    ),
    (
        "AIR-FND-DAT-09",
        UNASSESSED,
        None,
        "bedrock_assessments",
        [],
        "AISERVICES_OPT_OUT_POLICY via DescribeEffectivePolicy, which no function is granted; "
        "the AI-services opt-out is the most AI-specific control in the FND area",
        ["organizations:DescribeEffectivePolicy"],
        5,
    ),
    (
        "AIR-FND-DET-01",
        UNASSESSED,
        None,
        "bedrock_assessments",
        ["BR-04", "BR-12"],
        "candidate incumbents only; dedup not run",
        [],
        5,
    ),
    (
        "AIR-FND-DET-04",
        UNASSESSED,
        None,
        "bedrock_assessments",
        ["BR-34"],
        "candidate incumbent only; dedup not run",
        [],
        5,
    ),
    (
        "AIR-FND-IAM-05",
        UNASSESSED,
        None,
        "agentcore_assessments",
        ["AC-02"],
        "candidate incumbent only; dedup not run",
        [],
        5,
    ),
    (
        "AIR-FND-NET-01",
        UNASSESSED,
        None,
        ["agentcore_assessments", "sagemaker_assessments"],
        ["AC-01", "SM-11"],
        "spans two modules; candidate incumbents only. 'AI workloads run privately' has no "
        "single host, which is why the FND area has no module of its own",
        [],
        5,
    ),
    (
        "AIR-FND-NET-02",
        UNASSESSED,
        None,
        "agentcore_assessments",
        ["AC-08"],
        "candidate incumbent only; dedup not run",
        [],
        5,
    ),
    (
        "AIR-FND-NET-04",
        UNASSESSED,
        None,
        ["responsible_ai_grc_assessments", "agentcore_assessments"],
        ["AG-27"],
        "wafv2 is already granted to the GRC function, but the AG-27 incumbent lives in the "
        "AgentCore module; pick one before writing it",
        [],
        5,
    ),
    (
        "AIR-FND-NET-06",
        UNASSESSED,
        None,
        "agentcore_assessments",
        ["AC-01"],
        "overlaps RT-08; resolve the two together",
        ["ec2:DescribeSecurityGroups"],
        5,
    ),
]

# Incumbent check_id -> its published finding name, extracted from the modules.
# A NEW_ID disposition is a claim about this name versus what the check asserts,
# so the name is recorded here rather than paraphrased.
INCUMBENT_NAMES = {
    "AC-01": "AgentCore Runtime VPC Configuration",
    "AC-02": "AgentCore IAM Full Access Check",
    "AC-04": "AgentCore Observability Check",
    "AC-06": "AgentCore Browser Session Recording",
    "AC-07": "AgentCore Memory Encryption",
    "AC-08": "AgentCore VPC Endpoints Check",
    "AC-10": "AgentCore Resource-Based Policies Check",
    "AC-11": "AgentCore Policy Engine Encryption Check",
    "AC-14": "AgentCore Identity Token Vault CMK Encryption",
    "AC-17": "AgentCore Online Evaluation Coverage",
    "AG-24": "Agentic AI Gateway Inbound Authorization",
    "AG-25": "Agentic AI Gateway Tool Policy Enforcement",
    "AG-27": "Agentic AI Gateway WAF Protection",
    "AR-03": "AWS Agent Registry Publication Approval Governance",
    "BR-04": "Bedrock Model Invocation Logging Check",
    "BR-06": "Bedrock CloudTrail Logging Check",
    "BR-10": "Bedrock Guardrail IAM Enforcement Check",
    "BR-12": "Bedrock Invocation Log Encryption",
    "BR-15": "Cross-Account Guardrails Enforcement Check",
    "BR-20": "Knowledge Base Customer-Managed KMS Encryption Check",
    "BR-26": "Guardrail Sensitive Information Filter Check",
    "BR-27": "Guardrail Contextual Grounding Check",
    "BR-32": "Bedrock CloudWatch Alarm Check",
    "BR-34": "Guardrail Prompt Attack Filter",
    "BR-37": "Bedrock Account Data Retention",
    "FS-65": "KB Data Source Buckets Missing S3 Event Notifications",
    "SM-01": "SageMaker Internet Access Check",
    "SM-02": "SageMaker IAM Permissions",
    "SM-03": "SageMaker Data Protection Check",
    "SM-09": "SageMaker Notebook Root Access Check",
    "SM-11": "SageMaker Model Network Isolation Check",
    "SM-18": "SageMaker Transform Job Encryption Check",
    "SM-22": "Model Approval Workflow Check",
}

AISF_REPO = os.path.expanduser(
    "~/WorkDocs/Builder/aws-ai-security-framework-assessment"
)
HERE = os.path.dirname(os.path.abspath(__file__))


def load_aisf():
    """Return {control_id: {q, ev, machine_checkable, workload_agnostic}}."""
    import glob

    import yaml

    ledger_path = os.path.join(AISF_REPO, "crosswalk", "classification-ledger.json")
    with open(ledger_path) as f:
        classification = json.load(f)["controls"]

    out = {}
    for path in glob.glob(
        os.path.join(AISF_REPO, "controls", "**", "*.yaml"), recursive=True
    ):
        with open(path) as f:
            doc = yaml.safe_load(f)

        def walk(node):
            if isinstance(node, dict):
                cid = node.get("id")
                if isinstance(cid, str) and cid.startswith("AIR-"):
                    flags = classification.get(cid, {})
                    out[cid] = {
                        "q": (node.get("q") or "").strip(),
                        "ev": (node.get("ev") or "").strip(),
                        "machine_checkable": bool(flags.get("machine_checkable")),
                        "workload_agnostic": bool(flags.get("workload_agnostic")),
                        "source": os.path.relpath(path, AISF_REPO),
                    }
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(doc)
    return out


def build():
    aisf = load_aisf()
    rows = []
    for (
        control,
        verdict,
        disposition,
        module,
        incumbents,
        gap,
        extra_iam,
        phase,
    ) in ROWS:
        meta = aisf.get(control)
        if meta is None:
            raise SystemExit(f"{control} is not a control in the AISF repo")
        if not meta["machine_checkable"]:
            raise SystemExit(f"{control} is not machine_checkable in the ledger")
        rows.append(
            {
                "control": control,
                "area": control.split("-")[1],
                "question": meta["q"],
                "assert": meta["ev"],
                "workload_agnostic": meta["workload_agnostic"],
                "verdict": verdict,
                "disposition": disposition,
                # a list: some controls have no single host module
                "target_modules": (
                    []
                    if module is None
                    else [module]
                    if isinstance(module, str)
                    else list(module)
                ),
                "incumbents": incumbents,
                "incumbent_names": [
                    INCUMBENT_NAMES[i] for i in incumbents if i in INCUMBENT_NAMES
                ],
                "gap": gap,
                "extra_iam": extra_iam,
                "phase": phase,
                "source": meta["source"],
            }
        )

    def count(**kw):
        return sum(1 for r in rows if all(r.get(k) == v for k, v in kw.items()))

    hosted = [r for r in rows if r["area"] in ("BDR", "SGM", "ACR")]
    fnd = [r for r in rows if r["area"] == "FND"]
    new_functions = (
        count(verdict=NEW)
        + count(verdict=TIGHTEN, disposition=NEW_ID)
        + count(verdict=UNASSESSED)
    )
    summary = {
        "hosted": len(hosted),
        "fnd_ai_subject": len(fnd),
        "total": len(rows),
        "covered": count(verdict=COVERED),
        "tighten": count(verdict=TIGHTEN),
        "tighten_extend": count(verdict=TIGHTEN, disposition=EXTEND),
        "tighten_new_id": count(verdict=TIGHTEN, disposition=NEW_ID),
        "new": count(verdict=NEW),
        "not_implementable": count(verdict=NOT_IMPL),
        "unassessed": count(verdict=UNASSESSED),
        "new_check_functions": new_functions,
        "extensions": count(verdict=TIGHTEN, disposition=EXTEND),
        "extra_iam_actions": sorted({a for r in rows for a in r["extra_iam"]}),
    }

    doc = {
        "generated": date.today().isoformat(),
        "generator": "aisf-parity/build_ledger.py",
        "aisf_repo": AISF_REPO,
        "summary": summary,
        "rows": rows,
    }
    with open(os.path.join(HERE, "aisf-work-ledger.json"), "w") as f:
        json.dump(doc, f, indent=2, sort_keys=False)
        f.write("\n")
    write_markdown(doc)
    return doc


def render_markdown(doc):
    """Render the markdown view of a ledger doc. Pure: reads nothing, writes nothing.

    Separate from write_markdown so check_ledger.py's gate 10 can render the json
    and compare the result against the file on disk. That gate used to compare
    mtimes, which measures checkout order and not content: a clone writes every
    file within the same second, ordered by the git index, so the uppercase
    markdown name always lands before the lowercase json and the gate failed in
    every fresh clone while passing in the tree the ledger was generated in.
    """
    s = doc["summary"]
    out = []
    out.append("# AISF parity work ledger")
    out.append("")
    out.append(
        f"Generated {doc['generated']} by `{doc['generator']}`. Do not hand-edit: "
        "change `ROWS` in the generator and re-run."
    )
    out.append("")
    out.append(
        f"{s['total']} controls in scope: {s['hosted']} hosted (BDR, SGM, ACR) plus "
        f"{s['fnd_ai_subject']} FND controls whose assertion subject is an AI resource."
    )
    out.append("")
    out.append("| verdict | rows | meaning |")
    out.append("|---|---|---|")
    out.append(
        f"| covered | {s['covered']} | an incumbent already asserts this; nothing to write |"
    )
    out.append(
        f"| tighten / extend | {s['tighten_extend']} | incumbent name is honest, its "
        "assertion is narrower; extend it in place |"
    )
    out.append(
        f"| tighten / new_id | {s['tighten_new_id']} | incumbent name claims more than it "
        "asserts; allocate a new id beside it |"
    )
    out.append(f"| new | {s['new']} | no incumbent asserts any part of it |")
    out.append(
        f"| not_implementable | {s['not_implementable']} | flagged machine_checkable in the "
        "ledger but is not checkable from configuration |"
    )
    out.append(f"| unassessed | {s['unassessed']} | in scope, dedup pass not yet run |")
    out.append("")
    out.append(
        f"**{s['new_check_functions']} new check functions and {s['extensions']} extensions "
        "to existing checks.**"
    )
    out.append("")
    out.append("## New IAM actions required")
    out.append("")
    for action in s["extra_iam_actions"]:
        holders = [r["control"] for r in doc["rows"] if action in r["extra_iam"]]
        out.append(f"- `{action}` — {', '.join(holders)}")
    out.append("")
    for area in ("BDR", "SGM", "ACR", "FND"):
        rows = [r for r in doc["rows"] if r["area"] == area]
        if not rows:
            continue
        out.append(f"## {area} ({len(rows)} controls)")
        out.append("")
        out.append("| control | verdict | do | module | incumbent | gap |")
        out.append("|---|---|---|---|---|---|")
        order = {COVERED: 0, TIGHTEN: 1, NEW: 2, UNASSESSED: 3, NOT_IMPL: 4}
        for r in sorted(rows, key=lambda r: (order[r["verdict"]], r["control"])):
            inc = ", ".join(f"`{i}`" for i in r["incumbents"]) or "—"
            do = r["disposition"] or "—"
            mod = ", ".join(f"`{m}`" for m in r["target_modules"]) or "—"
            gap = r["gap"].replace("|", "\\|") or "—"
            wa = "" if r["workload_agnostic"] else " *(workload-specific)*"
            out.append(
                f"| `{r['control']}`{wa} | {r['verdict']} | {do} | {mod} | {inc} | {gap} |"
            )
        out.append("")
    return "\n".join(out)


def write_markdown(doc):
    with open(os.path.join(HERE, "AISF-WORK-LEDGER.md"), "w") as f:
        f.write(render_markdown(doc))


if __name__ == "__main__":
    result = build()
    print(json.dumps(result["summary"], indent=2))
