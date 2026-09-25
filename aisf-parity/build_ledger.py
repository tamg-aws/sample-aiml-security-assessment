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
    (
        "AIR-BDR-GRD-02",
        TIGHTEN,
        EXTEND,
        "bedrock_assessments",
        ["BR-34"],
        "BR-34 tests the BLOCK action; AISF tests inputStrength HIGH",
        [],
        3,
    ),
    (
        "AIR-BDR-GRD-04",
        TIGHTEN,
        EXTEND,
        "bedrock_assessments",
        ["BR-32"],
        "BR-32 accepts any AWS/Bedrock alarm; AISF wants the guardrail-intervention metric filter",
        [],
        3,
    ),
    (
        "AIR-BDR-GRD-09",
        TIGHTEN,
        EXTEND,
        "bedrock_assessments",
        ["BR-27"],
        "BR-27 tests presence; AISF tests the grounding and relevance thresholds",
        [],
        3,
    ),
    (
        "AIR-BDR-GRD-10",
        TIGHTEN,
        NEW_ID,
        "bedrock_assessments",
        ["BR-15"],
        'BR-15 is named "Cross-Account Guardrails Enforcement Check" but only tests that an '
        "org policy exists; AISF requires it be non-DRAFT, which is what enforcement means here",
        [],
        3,
    ),
    (
        "AIR-BDR-KB-06",
        TIGHTEN,
        EXTEND,
        "bedrock_assessments",
        ["BR-06"],
        "BR-06 tests that a trail covers Bedrock; AISF wants named data-event resource types",
        [],
        3,
    ),
    (
        "AIR-BDR-MDL-07",
        TIGHTEN,
        EXTEND,
        "bedrock_assessments",
        ["BR-06"],
        "BR-06 tests that a trail covers Bedrock; AISF wants named data-event resource types",
        [],
        3,
    ),
    (
        "AIR-BDR-MDL-02",
        TIGHTEN,
        EXTEND,
        "bedrock_assessments",
        ["BR-04", "BR-12"],
        "BR-04 and BR-12 cover logging and destination encryption; AISF adds retention",
        [],
        3,
    ),
    (
        "AIR-BDR-KB-01",
        NEW,
        None,
        "bedrock_assessments",
        [],
        "no incumbent in this module reads macie2",
        ["macie2:GetAutomatedDiscoveryConfiguration", "macie2:GetMacieSession"],
        3,
    ),
    (
        "AIR-BDR-MDL-01",
        NEW,
        None,
        "bedrock_assessments",
        [],
        "no check asserts model-ARN scoping on bedrock:InvokeModel; aws:RequestedRegion, "
        "aws:SourceVpc, aws:SourceVpce and aws:PrincipalOrgID are 0 hits corpus-wide",
        [],
        3,
    ),
    (
        "AIR-BDR-MDL-03",
        NEW,
        None,
        "bedrock_assessments",
        [],
        "model allow-list; FS-12 is not a dedup risk, its whole test is "
        "'bedrock' in json.dumps(doc).lower() over every SCP",
        [],
        3,
    ),
    (
        "AIR-BDR-MDL-04",
        NEW,
        None,
        "bedrock_assessments",
        [],
        "model allow-list dimension with no incumbent",
        [],
        3,
    ),
    ("AIR-BDR-MDL-09", NEW, None, "bedrock_assessments", [], "", [], 3),
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
        NOT_IMPL,
        None,
        None,
        [],
        "needs a published-versus-DRAFT distinction GetPrompt does not return",
        [],
        None,
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
    (
        "AIR-SGM-EP-01",
        TIGHTEN,
        EXTEND,
        "sagemaker_assessments",
        ["SM-11"],
        "SM-11 has the EnableNetworkIsolation leg, not the VpcConfig leg",
        [],
        3,
    ),
    (
        "AIR-SGM-EP-02",
        TIGHTEN,
        EXTEND,
        "sagemaker_assessments",
        ["SM-02"],
        "SM-02 scans IAM permissions but never tests resource-scoped sagemaker:InvokeEndpoint "
        "against a named endpoint ARN; SageMaker endpoints carry no resource-based policy, so "
        "the identity policy is the whole surface",
        [],
        3,
    ),
    (
        "AIR-SGM-GOV-01",
        TIGHTEN,
        EXTEND,
        "sagemaker_assessments",
        ["SM-22"],
        "SM-22 has approval status, not approver metadata",
        [],
        3,
    ),
    (
        "AIR-SGM-TRN-02",
        TIGHTEN,
        EXTEND,
        "sagemaker_assessments",
        ["SM-03"],
        "SM-03 has the KMS legs, not inter-container traffic encryption",
        [],
        3,
    ),
    (
        "AIR-SGM-EP-06",
        NEW,
        None,
        "sagemaker_assessments",
        [],
        "DataCaptureConfig; SM-23 reads monitoring schedules, not data capture",
        [],
        3,
    ),
    (
        "AIR-SGM-GOV-10",
        NEW,
        None,
        "sagemaker_assessments",
        [],
        "Config recorder state; no incumbent in this module reads config",
        ["config:DescribeConfigurationRecorders", "config:DescribeConfigRules"],
        3,
    ),
    (
        "AIR-SGM-TRN-01",
        NEW,
        None,
        "sagemaker_assessments",
        [],
        "training-job network isolation; SM-21 does this for AutoML jobs only",
        [],
        3,
    ),
    (
        "AIR-SGM-TRN-08",
        NEW,
        None,
        "sagemaker_assessments",
        [],
        "SCP asserting encryption/no-internet/VPC at creation; the corpus already enumerates "
        "SCPs in two modules, so the cost is the Organizations read, not a new mechanism",
        ["organizations:ListPolicies", "organizations:DescribePolicy"],
        3,
    ),
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
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-33"],
        "AC-33 judges the resource element on the five token issuance actions per cached role "
        "and user: a resource ending in a wildcard mints a token for every workload identity "
        "in the account, while a resource naming one identity bounds the grant to that agent. "
        "A grant that names only the workload identity directory is reported separately at "
        "medium, because the service authorization reference marks both the directory and the "
        "identity required on these actions and never says whether the directory alone "
        "authorizes the call, so that grant either reaches every identity the directory holds "
        "or authorizes nothing",
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
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-10", "AC-27"],
        "AC-10 reports that a gateway resource policy is present; AC-27 judges whether its "
        "Allow statements and the gateway execution role's trust policy carry "
        "aws:SourceAccount or aws:SourceArn, and fails an unconditioned statement even when a "
        "guarded sibling sits beside it in the same document",
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
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-08", "AC-27"],
        "AC-08 now judges each AgentCore endpoint's policy against the default "
        "allow-everything document and reads its security groups for 0.0.0.0/0 and ::/0 "
        "inbound rules, alongside the existence and health legs it already held; AC-27 adds "
        "the gateway resource policy's aws:SourceVpc / aws:SourceVpce / aws:VpcSourceIp / "
        "aws:SourceIp leg",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-05",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-27", "AC-24"],
        "AG-27 holds the WAF leg; AC-24 requires an ACTIVE gateway rate limit carrying a "
        "requests, tokens or connections ceiling, because dimensions is the only required "
        "member of a limit entry and a limit can therefore name a dimension and bound nothing",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-05",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-14", "AC-34"],
        "AC-14 has the token vault CMK leg; AC-34 adds the secret-scan leg, reading "
        "GetAgentRuntime.environmentVariables and failing a runtime whose definition holds an "
        "access key id or a PEM private key inline. Only variable names reach the finding "
        "because the API models the map as sensitive, and the resolution states the blind "
        "spot: a value holding a slash reads as a secret name, so the remaining values are "
        "the reader's to confirm",
        [],
        4,
    ),
    (
        "AIR-ACR-MEM-01",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-07", "AC-23"],
        "AC-07 asserts a customer managed key and an {actorId} namespace per memory, "
        "AC-23 asserts that no cached role or user reads memory records without a "
        "namespace, strategy, actor or session condition",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-11", "AC-36"],
        "AC-11 asserts the engine names a customer managed key, AC-36 asserts the key "
        "policy names who may decrypt with it and who may disable it or schedule it for "
        "deletion; the key cannot be added to or changed on an existing engine, so the "
        "key policy is the whole guard. The disable/delete alarm and the break-glass "
        "runbook are not readable from the key, and AC-36's passing resolution says so",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-01",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-25", "AC-19", "AC-35"],
        "AG-25 asserts mode ENFORCE plus status/enforcementMode ACTIVE, AC-19 asserts the "
        "gateway delivers APPLICATION_LOGS, which is where a policy decision record "
        "lands, and AC-35 asserts no enforcing permit leaves the action position "
        "unconstrained; default-deny and forbid-wins are engine behaviour and not a "
        "setting to read, so a permit over every tool is the only way to restore "
        "allow-all",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-07",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-25", "AC-38"],
        "AG-25 counts enforcing policies, AC-38 asserts a temporal policy exists and that "
        "the gateway carrying it authenticates callers with CUSTOM_JWT or AWS_IAM, the "
        "two authorizer types the devguide names as binding a session to the caller's "
        "identity; the session-id propagation path is fail-closed by the service, since a "
        "request to an engine holding a temporal policy fails validation without the "
        "header",
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
        "security-group rules permit; ec2:DescribeSecurityGroups is now granted to this "
        "function for AC-08's endpoint scope leg, so RT-08 costs no further permission",
        [],
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
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-28"],
        "AC-28 requires a service control policy that denies both CreateGateway and "
        "UpdateGateway when bedrock-agentcore:GatewayAuthorizerType is NONE, either by naming "
        "NONE in an equals-family condition or by omitting it from a not-equals-family one, "
        "so no approved-authorizer list has to be invented; attachment targets are outside "
        "the grant and the finding says so. The condition key carries a documentation drift: "
        "the AgentCore devguide wires GatewayAuthorizerType to CreateGateway and UpdateGateway "
        "and shows sibling gateway keys used this way in SCPs, while the machine-readable "
        "service reference and the service authorization reference page wire it to zero "
        "actions. The devguide wins for feature availability. Access Analyzer validate-policy "
        "accepts the key name but is no oracle for the wiring: it also accepts "
        "RuntimeAuthorizerType on CreateGateway, a pairing neither surface declares",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-08",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-25"],
        "AC-25 reads credentialProviderConfigurations per target through GetGatewayTarget, "
        "which is the only surface that carries it: the ListGatewayTargets summary omits the "
        "field. The control's second leg, a Lambda target scoped to one function ARN, is not "
        "expressible because the target ARN members reject a wildcard",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-10",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-19", "AC-20", "AC-26"],
        "AC-19 pairs each AgentCore delivery source with its delivery and AC-20 asserts "
        "masking plus a customer managed key; AC-26 adds the two legs neither held, an "
        "explicitly configured retentionInDays and a key policy that does not let every "
        "principal decrypt without a condition",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-29"],
        "AC-29 requires a service control policy that denies both CreateAgentRuntime and "
        "UpdateAgentRuntime when bedrock-agentcore:RuntimeAuthorizerType is AWS_IAM, so a "
        "runtime cannot be created on, or moved back to, the SigV4 mode that authenticates "
        "the hosting application's shared role instead of the end user; a policy written the "
        "other way round, denying CUSTOM_JWT, is reported separately because it reads as "
        "configured to anyone counting policies. organizations:ListPolicies and "
        "organizations:DescribePolicy are granted to this function for GW-02's AC-28, so "
        "ID-04 costs no further permission. Attachment targets are outside the grant and "
        "every finding says so",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-08",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-30"],
        "AC-30 reads GetAgentRuntime.authorizerConfiguration per runtime: an absent "
        "configuration means every invoke is SigV4-signed, and a customJWTAuthorizer that "
        "pins neither allowedAudience nor allowedClients accepts every token its issuer "
        "minted for every application registered there, so the claims are validated but not "
        "against this agent. allowedScopes and customClaims are credited in the detail and "
        "cannot substitute, because a scope bounds what a token may ask for and not who it "
        "was minted for",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-11",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-31", "AC-32"],
        "AG-24 passed every CUSTOM_JWT gateway on the authorizer type alone. AC-31 reads the "
        "authorizer's allow-lists and fails a gateway that pins neither allowedAudience nor "
        "allowedClients, because it then honours any token its issuer minted for any "
        "application registered there; allowedScopes and customClaims bound what a token may "
        "ask for and not who minted it for whom, so they are credited but do not substitute. "
        "AC-32 covers the second door, where the token-exchange APIs take an end user's JWT "
        "without passing a gateway authorizer at all, and fails a cached principal holding "
        "GetWorkloadAccessTokenForJWT or CompleteResourceTokenAuth with no InboundJwtClaim "
        "condition",
        [],
        4,
    ),
    ("AIR-ACR-MEM-07", NEW, None, "agentcore_assessments", [], "", [], 4),
    (
        "AIR-ACR-MEM-12",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-18"],
        "AC-18 asserts that a CloudTrail advanced event selector logs data events for "
        "AWS::BedrockAgentCore::Memory whenever the region holds a memory resource",
        [],
        4,
    ),
    (
        "AIR-ACR-OBS-02",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-18"],
        "AC-18 asserts data-event coverage per resource family, so a trail that logs only "
        "the runtime types still fails for memory and for the built-in tools",
        [],
        4,
    ),
    (
        "AIR-ACR-OBS-03",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-19"],
        "AC-04 is X-Ray tracingConfig.enabled over list_agent_runtimes only, so it cannot "
        "cover Gateway, Memory, Policy or Identity, which is OBS-03's whole subject. AC-19 "
        "asserts an APPLICATION_LOGS delivery source wired to a destination per gateway and "
        "per memory; runtime logging is service-managed, WorkloadIdentity delivery is "
        "configured on the associated runtime or gateway resource, and policy engines have "
        "no log-destination surface, so those three legs need no separate assertion",
        [],
        4,
    ),
    (
        "AIR-ACR-OBS-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-20", "AC-21"],
        "AC-20 asserts a Deidentify data-protection policy and a customer managed key on "
        "the AgentCore log groups, AC-21 asserts that no cached role or user holds "
        "logs:Unmask on every resource",
        [],
        4,
    ),
    (
        "AIR-ACR-OBS-06",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-22"],
        "AC-22 asserts that every Allow statement on an OAM sink policy either names its "
        "principals or carries an organization condition key",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-06",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-37"],
        "AC-37 asserts the workload-independent half: a policy carrying a guardrails "
        "condition needs bedrock:InvokeGuardrailChecks on the gateway execution role, "
        "because the Policy data plane calls Bedrock Guardrails with that role's forward "
        "access session. Whether this workload's content belongs at the authorization "
        "boundary at all, and which safeguard categories and thresholds apply, is the "
        "workload owner's decision, which AC-37 reports and does not judge",
        [],
        4,
    ),
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
        "overlaps RT-08; resolve the two together. Both now cost no further permission: "
        "ec2:DescribeSecurityGroups is granted to this function for AC-08's endpoint scope leg",
        [],
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
    "AC-18": "AgentCore CloudTrail Data Event Coverage",
    "AC-19": "AgentCore Log Delivery Configuration",
    "AC-20": "AgentCore Log Data Protection",
    "AC-21": "AgentCore Log Unmask Restriction",
    "AC-22": "AgentCore Telemetry Sink Scope",
    "AC-23": "AgentCore Memory Record Access Scope",
    "AC-24": "AgentCore Gateway Rate Limiting",
    "AC-25": "AgentCore Gateway Target Authorization",
    "AC-26": "AgentCore Log Retention and Key Scope",
    "AC-27": "AgentCore Gateway Policy Conditions",
    "AC-28": "AgentCore Gateway Authorizer Guardrail",
    "AC-29": "AgentCore Runtime Authorizer Guardrail",
    "AC-30": "AgentCore Runtime Inbound Authorization",
    "AC-31": "AgentCore Gateway Inbound Allow Lists",
    "AC-32": "AgentCore Inbound JWT Issuer Conditions",
    "AC-33": "AgentCore Token Issuance Scope",
    "AC-34": "AgentCore Runtime Inline Credentials",
    "AC-35": "AgentCore Policy Tool Scope",
    "AC-36": "AgentCore Policy Engine Key Scope",
    "AC-37": "AgentCore Policy Guardrail Wiring",
    "AC-38": "AgentCore Policy Session Binding",
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
