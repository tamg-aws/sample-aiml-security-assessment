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
        "the screening step is readable configuration and reading it proves nothing: "
        "GetDataSource returns vectorIngestionConfiguration.customTransformationConfiguration"
        ".transformations[].transformationFunction.transformationLambdaConfiguration.lambdaArn "
        "with stepToApply POST_CHUNKING, so a check can see that a customer Lambda rewrites "
        "each chunk, and no API says whether it looks for instruction-like patterns. The "
        "guardrail leg is readable and unattributable: GetGuardrail exposes the PROMPT_ATTACK "
        "content filter, but KnowledgeBase has no guardrailConfiguration member, only Agent "
        "and KnowledgeBaseFlowNodeConfiguration do, and a direct RetrieveAndGenerate caller "
        "supplies guardrailId per request, so a read cannot bind the filter to this knowledge "
        "base",
        [],
        None,
    ),
    (
        "AIR-BDR-KB-08",
        NOT_IMPL,
        None,
        None,
        [],
        "every nearby surface is readable and none of them is evidence of redaction: a "
        "pre-ingestion Comprehend or Glue job is not an attribute of the knowledge base, "
        "macie2 GetAutomatedDiscoveryConfiguration reports that discovery is enabled and "
        "where sensitive data was found, never that it was removed, and a guardrail "
        "sensitiveInformationPolicy with piiEntities action ANONYMIZE or BLOCK is readable on "
        "GetGuardrail but recorded on an Agent or a flow node and not on the knowledge base, "
        "with a direct RetrieveAndGenerate caller supplying guardrailId per request. The "
        "strongest assertable statement is that some guardrail in the account masks PII, "
        "which is not evidence that this knowledge base's content reaches a model redacted",
        [],
        None,
    ),
    (
        "AIR-BDR-MDL-08",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-07"],
        "BR-07 holds the catalog leg (ListPrompts non-empty is its Passed row, zero prompts"
        " is Not Applicable) and now the production-version leg as well. For each prompt it"
        " calls ListPrompts(promptIdentifier=...) for the numbered versions, fails a prompt"
        " that has only its DRAFT, and reads GetPrompt(promptVersion=N) on the highest "
        "numbered version for customerEncryptionKeyArn, which PromptSummary does not carry. For flows it reads "
        "the prompt node's resource.promptArn and fails a node that pins no version suffix,"
        " since an unversioned ARN resolves to the working draft. A version != DRAFT test "
        "on bare ListPrompts or on a GetPrompt with no promptVersion would have failed "
        "every prompt in every account, because both return the draft",
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
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-02"],
        "AC-02 now reads wildcard action patterns at any resource scope, on cached roles and "
        "users alike, so bedrock-agentcore:* narrowed to one evaluation ARN is reported where "
        "the full-access legs saw nothing. A pattern reaching any one of the six evaluator and "
        "online-evaluation-config writes grants all six, and a principal that can delete an "
        'evaluation can stop the measurement of the agent it watches. A bare Action "*" stays '
        "with the existing legs as a service-agnostic administrator grant",
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
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-02"],
        "AC-02 now fails any role or user whose Allow statements reach both an AgentCore "
        "payment session or instrument write and ProcessPayment with no account-wide Deny on "
        "the latter. A payment session carries its own limits.maxSpendAmount, so that one "
        "principal sets the budget it then spends against, which is the single failure behind "
        "both legs the devguide draws: its ManagementRole denies ProcessPayment and its "
        "ProcessPaymentRole holds no session write. A Deny scoped to one payment manager or "
        "carrying a condition is read as no account-wide Deny, so a narrower Deny never "
        "excuses the collision",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-03",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-02", "AC-45"],
        "AC-45 reads the execution role of every code interpreter and browser in the account "
        "and fails a role whose Allow statements reach every resource, name a NotResource, or "
        "carry a service-wide or bare action wildcard. AC-02 judges the same wildcards but "
        "only over the bedrock-agentcore namespace and only on the assessment's own roles, so "
        "a tool role granting s3:* on every bucket is a verdict it cannot reach",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-05",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-17", "AC-39"],
        "AC-39 judges every online evaluation configuration that exists whatever "
        "REQUIRE_AGENTCORE_ONLINE_EVALUATION is set to, and names the setting that stops it "
        "running: a status other than ACTIVE, an executionStatus other than ENABLED, no "
        "sampling percentage above zero, no input log group or service, no output log group, "
        "or no evaluator attached. AC-17 reads the same settings and returns N/A with that "
        "variable unset, so Failed is the verdict it cannot reach by default",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-06",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-17", "AC-40"],
        "AC-40 classifies the evaluators each configuration attaches against the account's own "
        "catalogue, which marks a service-authored evaluator's category in its description and "
        "reports the level it scores at, and fails a configuration attaching no safety "
        "evaluator or none at TOOL_CALL level. Evaluators written in this account are named for "
        "the owner to classify, because their descriptions are prose no check can verify. "
        "AgentCore publishes no evaluation score metric, so an alarm on a falling score is a "
        "metric filter over the results log group whose pattern and threshold belong to the "
        "workload, and every AC-40 verdict says so",
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
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-08", "AC-10", "AC-47"],
        "AC-47 fails a runtime whose resource policy restricts neither the network path nor "
        "the caller: the network leg reads aws:SourceVpc, aws:SourceVpce, aws:VpcSourceIp and "
        "aws:SourceIp on any statement, the caller leg reads a named principal or an "
        "allowedWorkloadConfiguration on the JWT authorizer. AC-08 fails an AgentCore "
        "interface endpoint with private DNS off, which is the leg that keeps the runtime's "
        "own callers off the public endpoint name. AC-10 reports only that a policy exists",
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
        COVERED,
        None,
        "agent_registry_assessments",
        ["AR-03", "AR-09", "AR-10"],
        'AR-03 is named "Publication Approval Governance" and covers auto-approval, behind '
        "the REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL env gate. AR-09 asserts the separation "
        "leg: it fails any role or user whose attached and inline policies allow, by an "
        "action pattern that names the service, both a record write (CreateRegistryRecord, "
        "UpdateRegistryRecord, SubmitRegistryRecordForApproval) and "
        "UpdateRegistryRecordStatus, the one operation that can set a record to APPROVED, "
        "in either the agent-registry namespace or the public-preview bedrock-agentcore "
        "spelling of it. A bare * grant is reported under AR-01, and only a Deny with no "
        "condition on Resource * removes an action. AR-10 asserts the observation leg: an "
        "enabled rule on the default event bus that matches the aws.agent-registry "
        "Pending Approval, Approved and Rejected state-change events and has a target. A rule that matches only the aws.bedrock-agentcore preview source is "
        "reported apart, because that source stops routing on 30 October 2026. Rules on a "
        "custom bus are not read, since AWS delivers these events to the default bus",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-08",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-01"],
        "AC-01 now reads the outbound rules of every security group attached to a VPC runtime, "
        "code interpreter or browser and fails a group permitting 0.0.0.0/0 or ::/0 egress. A "
        "tool in PUBLIC network mode fails without a describe call, because the service grants "
        "it open internet egress by configuration; SANDBOX passes at Medium, because the "
        "sandbox reaches no network the workload can name. A group the describe did not return "
        "and a denied ec2:DescribeSecurityGroups are both reported N/A on their own line, so "
        "an unread group is never counted as closed",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-02",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-42"],
        "AC-42 reads iam:PassRole on every cached role and user against the execution roles the "
        "region's online evaluation configurations name, and judges the widest statement that "
        "reaches one of them: a Resource pattern wider than the role itself, or a grant "
        "carrying no iam:PassedToService condition, lets the holder run a role it could not "
        "assume by writing a configuration that names it",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-03",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-43"],
        "AC-43 reads each evaluation execution role's own trust policy and reports every Allow "
        "statement trusting an AWS service principal, or every principal, with no "
        "aws:SourceAccount and no aws:SourceArn condition. The role can read the scored traces "
        "and invoke the judge model, so a service acting for another customer's configuration "
        "reaches both. AC-27 makes the same assertion on gateway execution roles and reaches no "
        "evaluation role, because it reads the roles gateways name",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-44"],
        "AC-44 reports whether each evaluation execution role's model-invocation grant names "
        "models at all: a Resource pattern ending in a bare wildcard reaches every model the "
        "account can invoke, and the judge prompt carries the agent output being scored, so "
        "every model it reaches is one attacker-influenced text can be sent to. Which models a "
        "workload's judges may use is the workload owner's decision, so the check names the "
        "patterns it found and asserts only that they are bounded",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-07",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-20", "AC-26", "AC-41"],
        "AC-41 anchors on the log group each configuration's outputConfig names and asserts a "
        "retention period, a customer managed key, and membership of the AgentCore log group "
        "prefixes, so a results group whose creator chose a name outside them is reported "
        "rather than skipped. AC-20 and AC-26 judge masking and key policy on the groups under "
        "those prefixes and neither reaches a group outside them. Tag values and the "
        "configuration's own description are free-form text AC-41 discloses instead of judging",
        [],
        4,
    ),
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
    (
        "AIR-ACR-MEM-07",
        NOT_IMPL,
        None,
        None,
        [],
        "the only retention field AgentCore Memory exposes is required, and it bounds a "
        "different thing from the one this control asks about. eventExpiryDuration is "
        "Required: Yes on CreateMemory, 3 to 365 days, and comes back on the Memory shape "
        "GetMemory returns, so a presence check over it passes for every memory that "
        "exists, which is worse than no check. It also bounds the wrong subject: the "
        "create page calls it event retention for raw events in short-term memory and "
        "applies it per event at write time, so updating it moves only later events, "
        "while what this control asks to bound is the long-term cross-session records "
        "extracted from those events, and neither CreateMemory nor Memory carries any "
        "retention field for those. Which value is short enough is the workload owner's "
        "judgment in any case, and this row will not invent a ceiling. What is readable "
        "is the namespace partitioning, already asserted under AIR-ACR-MEM-01 by AC-07 "
        "and AC-23 on {actorId}; session partitioning cannot join it, because AWS "
        "documents /summaries/{actorId}/{sessionId}/ for a summary strategy and "
        "/users/{actorId}/preferences/ for a user-preference strategy, so failing the "
        "absence of {sessionId} would fail a documented configuration. The log-retention "
        "clause asks for a compliance schedule only the workload owner can name",
        [],
        None,
    ),
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
    (
        "AIR-ACR-RT-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-46"],
        "AC-46 fails a runtime that configures neither idleRuntimeSessionTimeout nor "
        "maxLifetime, or that sets either at the service ceiling of 1209600 seconds, which is "
        "the setting that lets one runaway session hold its resources for 14 days. AgentCore "
        "exposes no per-session memory or cost limit to read, so the time bound is the only "
        "limit the API can answer for, and every verdict says which values it found so the "
        "workload owner can judge whether the bound suits the task",
        [],
        4,
    ),
    # ------- FND, AI-resource subject: 11 controls -------
    (
        "AIR-FND-DAT-01",
        COVERED,
        None,
        [
            "bedrock_assessments",
            "sagemaker_assessments",
        ],
        ["BR-20", "BR-11", "BR-17", "SM-03"],
        "four checks cover the stores this control names: BR-20 the customer-managed key "
        "of a managed or S3 Vectors store, reporting any other vector store as needing a "
        "storage-layer review, and the default encryption of each data source bucket, which is where "
        "the ingested objects sit before any index exists; BR-11 the customization job "
        "output, read from outputModelKmsKeyArn, the field GetModelCustomizationJob "
        "returns; BR-17 the custom model's own modelKmsKeyArn; SM-03 the training output "
        "and volume keys. BR-11 used to read outputDataConfig.kmsKeyId, which the API never"
        " returns, so every custom model read as needing review until the documented field "
        "was read. FS-65 is not an incumbent: its finding is about S3 event notifications "
        "and says nothing about keys",
        [],
        5,
    ),
    (
        "AIR-FND-DAT-02",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-47"],
        "BR-47 reads the bucket policy of each S3 bucket on the Bedrock data path "
        "(knowledge base S3 sources, the invocation log S3 destination and its CloudWatch "
        "large-data bucket, and the training, validation, output and distillation "
        "invocation-log source buckets of the newest 50 customization jobs). It passes a "
        "bucket only when one Deny, conditioned by Bool or BoolIfExists on "
        "aws:SecureTransport false, reaches every principal, covers s3:*, and names both "
        "the bucket and its objects. A bucket with no policy fails, because S3 then "
        "accepts plaintext requests. For each Deny that falls short, the finding names the "
        "principals, resources or actions it misses, since a Deny scoped to some "
        "principals leaves the rest able to use HTTP. A data source or job cap, or a failed "
        "read, withholds the Passed row, since an unread bucket may accept plaintext",
        [],
        5,
    ),
    (
        "AIR-FND-DAT-03",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-46"],
        "BR-46 holds both legs. It reads automatedDiscoveryMonitoringStatus for each "
        "knowledge base source bucket, which is the sampling leg, and, for a bucket "
        "automated discovery does not monitor, whether a SCHEDULED classification job that "
        "is RUNNING or IDLE and whose last run did not error names the bucket, which is the "
        "per-object leg the control keeps separate because automated discovery samples. A "
        "job that selects buckets by criteria is reported, not credited, and neither leg "
        "is read unless the Macie session and automated discovery are enabled. A ListClassificationJobs item carries "
        "bucketDefinitions, bucketCriteria, jobType and jobStatus, so "
        "DescribeClassificationJob is not needed. The pre-ingest Comprehend detection the "
        "control also recommends is a call the application makes, which no account "
        "configuration records",
        [],
        5,
    ),
    (
        "AIR-FND-DAT-09",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-48"],
        "BR-48 reads both surfaces. DescribeEffectivePolicy on AISERVICES_OPT_OUT_POLICY "
        "answers what resolves for the account, and an absent effective policy fails "
        "because the account is then opted in. The effective document has the inheritance "
        "operators stripped, so from the management account BR-48 also reads every AI "
        "services opt-out policy in the organization through ListPolicies and "
        "DescribePolicy, and names any whose opt_out_policy value is open to child "
        "policies: an unset @@operators_allowed_for_child_policies defaults to @@all, "
        'and only ["@@none"] locks the value',
        [],
        5,
    ),
    (
        "AIR-FND-DET-01",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-04", "BR-12"],
        "BR-04 reads loggingConfig for a destination, the log group's retention, the five "
        "modality flags (textDataDeliveryEnabled, imageDataDeliveryEnabled, "
        "embeddingDataDeliveryEnabled, videoDataDeliveryEnabled, audioDataDeliveryEnabled) "
        "and, for a CloudWatch destination, cloudWatchConfig.largeDataDeliveryS3Config, "
        "without which CloudWatch drops the largest payloads. Any modality flag set false "
        "fails, since that modality's prompts and completions go unlogged, and an absent "
        "flag is Not Applicable. An S3-only configuration is not failed on the "
        "large-payload field, which sits on CloudWatchConfig. BR-12 asserts a "
        "customer-managed key on the S3 destination bucket and reports a CloudWatch-only "
        "configuration as Not Applicable",
        [],
        5,
    ),
    (
        "AIR-FND-DET-04",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-34", "BR-41", "BR-49"],
        "three checks, one per enforcement surface. BR-34 asserts a guardrail carries a "
        "PROMPT_ATTACK filter with inputEnabled true, inputAction BLOCK and inputStrength "
        "HIGH. BR-41 reads ListEnforcedGuardrailsConfiguration, including "
        "modelEnforcement.includedModels and excludedModels, where ALL with an empty "
        "excludedModels is every model and a non-empty excludedModels leaves holes, and "
        "selectiveContentGuarding, where SELECTIVE on either the system or the messages "
        "field leaves content the caller does not tag unguarded. "
        "BR-49 asserts the identity-policy fallback: each identity allowed to invoke a "
        "model is denied bedrock:InvokeModel and bedrock:InvokeModelWithResponseStream "
        "without an approved bedrock:GuardrailIdentifier. Those two actions authorize "
        "Converse and ConverseStream as well; the Converse operations have no IAM action of"
        " their own",
        [],
        5,
    ),
    (
        "AIR-FND-IAM-05",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-43", "AC-45", "AC-02", "AC-48"],
        "AC-45 scopes what a tool execution role may do and AC-02 flags wildcard or "
        "allow-except AgentCore grants on all resources across every cached role. AC-43 "
        "asserts the confused-deputy guard on evaluation roles. AC-48 reads the trust "
        "policy of every runtime, gateway, browser and code interpreter execution role: it "
        "fails a service principal or * with no aws:SourceAccount or aws:SourceArn "
        "condition and an account-root or bare account-id principal with no condition, "
        "and it fails a role that more than one AgentCore resource names, since the shared "
        "role carries the union of what each needs. AC-27 also reads the gateway roles",
        [],
        5,
    ),
    (
        "AIR-FND-NET-01",
        COVERED,
        None,
        [
            "agentcore_assessments",
            "sagemaker_assessments",
            "bedrock_assessments",
        ],
        ["AC-01", "SM-10", "SM-11", "SM-28", "SM-33", "BR-39"],
        "spans three modules, because 'AI workloads run privately' has no single host. Six "
        "checks read the subnets a resource names and resolve each subnet's route table, "
        "the explicit association first and the VPC main table otherwise, and fail a route "
        "to an igw- gateway that is not a blackhole: AC-01 for the runtime, SM-10 for "
        "notebooks, SM-11 for models, SM-28 for HyperPod clusters, SM-33 for training jobs "
        "together with EnableNetworkIsolation, and BR-39 for marketplace model endpoints. "
        "An egress-only gateway, a NAT gateway and a peering connection do not make a "
        "subnet public. A route read that fails is reported Not Applicable and never passes",
        [],
        5,
    ),
    (
        "AIR-FND-NET-02",
        COVERED,
        None,
        [
            "agentcore_assessments",
            "bedrock_assessments",
        ],
        ["AC-08", "BR-02"],
        "AC-08 judges private DNS on interface endpoints, the endpoint policy, and whether "
        "the endpoint's security groups admit inbound traffic from 0.0.0.0/0 or ::/0, on "
        "the AgentCore interface endpoints and on the S3, DynamoDB and SageMaker endpoints "
        "in the same VPCs, so an endpoint left on the default full-access policy is "
        "reported. BR-02 reads "
        "private DNS and the endpoint policy on the Bedrock endpoints, where it used to "
        "report only that an endpoint existed",
        [],
        5,
    ),
    (
        "AIR-FND-NET-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-27", "AG-39"],
        "AG-27 asserts association: a gateway names a webAclArn. AG-39 reads the rule "
        "content behind it through wafv2:GetWebACL and fails an ACL with no rule, AWS "
        "managed rule group or default action that blocks, no SQL injection or cross-site "
        "scripting coverage, no rate-based rule, or an association body inspection limit "
        "left at the 16 KB default, since a tool call carries its arguments in the body. A "
        "customer rule group or a non-AWS managed rule group, whose rules AG-39 does not "
        "read, turns a missing filter into Not Applicable with the group named. AWS "
        "managed groups are credited by name, and their rule overrides are not read. The subject is AgentCore gateways",
        [],
        5,
    ),
    (
        "AIR-FND-NET-06",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-01", "AC-15", "AC-49"],
        "AC-01 fails a runtime or built-in tool whose security groups allow egress to "
        "0.0.0.0/0 or ::/0, and AC-15 requires each custom code interpreter to run in VPC "
        "mode with subnets and security groups. AC-49 asserts egress by destination "
        "name on each VPC that hosts an AgentCore runtime, browser or code interpreter: it "
        "walks the associated DNS Firewall rule groups in ascending association Priority "
        "and the enforcing rules in each in ascending Priority, as DNS Firewall evaluates "
        'them, and judges the first rule whose customer domain list holds "*", because the '
        "first match ends evaluation. It passes only when that rule is a BLOCK with no "
        "query type, which is the walled garden pattern Route 53 documents; an ALLOW or "
        'ALERT over "*" fails, and rules after the deciding rule are not reached. '
        'ListFirewallDomains returns that entry fully qualified as "*.", and '
        "AC-49 reads either spelling. Rule groups whose rules only BLOCK over an AWS managed "
        'list, over DNS threat protection, over a list without "*", or over "*" for one '
        "query type fail, because every name or query type those rules do not match is "
        "answered. An IAM Deny on the bedrock-agentcore:subnets or :securityGroups keys "
        "does not substitute for this: the devguide lists those keys while the "
        "machine-readable IAM reference lists none for CreateGatewayTarget or "
        "UpdateGatewayTarget, so such a Deny can fail open",
        [],
        5,
    ),
]

# Incumbent check_id -> its published finding name, extracted from the modules.
# A NEW_ID disposition is a claim about this name versus what the check asserts,
# so the name is recorded here rather than paraphrased.
INCUMBENT_NAMES = {
    "AC-48": "AgentCore Execution Role Trust",
    "AC-49": "AgentCore DNS Egress Control",
    "AG-39": "Agentic AI Gateway WAF Rule Coverage",
    "AR-10": "AWS Agent Registry Lifecycle Event Routing",
    "BR-47": "Bedrock Data Path Bucket TLS Enforcement",
    "BR-48": "AI Services Opt-Out Policy Enforcement",
    "BR-49": "Guardrail Invocation Deny Enforcement",
    "AC-01": "AgentCore Runtime VPC Configuration",
    "AC-02": "AgentCore IAM Full Access Check",
    "AC-04": "AgentCore Observability Check",
    "AC-06": "AgentCore Browser Session Recording",
    "AC-07": "AgentCore Memory Encryption",
    "AC-08": "AgentCore VPC Endpoints Check",
    "AC-10": "AgentCore Resource-Based Policies Check",
    "AC-11": "AgentCore Policy Engine Encryption Check",
    "AC-14": "AgentCore Identity Token Vault CMK Encryption",
    "AC-15": "AgentCore Code Interpreter Network Isolation",
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
    "AC-39": "AgentCore Online Evaluation Operation",
    "AC-40": "AgentCore Evaluation Safety Coverage",
    "AC-41": "AgentCore Evaluation Result Protection",
    "AC-42": "AgentCore Evaluation Pass Role Scope",
    "AC-43": "AgentCore Evaluation Role Trust",
    "AC-44": "AgentCore Evaluation Judge Model Scope",
    "AC-45": "AgentCore Tool Execution Role Scope",
    "AC-46": "AgentCore Runtime Session Limits",
    "AC-47": "AgentCore Runtime Invocation Path",
    "AG-24": "Agentic AI Gateway Inbound Authorization",
    "AG-25": "Agentic AI Gateway Tool Policy Enforcement",
    "AG-27": "Agentic AI Gateway WAF Protection",
    "AR-03": "AWS Agent Registry Publication Approval Governance",
    "AR-09": "AWS Agent Registry Approval Authority Separation",
    # Four names for one check, one per status branch: the Passed row, the Failed
    # row and each of the two N/A rows carry a different name. The subject is one
    # thing -- whether a Bedrock VPC endpoint is in use -- so no single CSV filter
    # returns this check's verdicts, and filtering on the Passed name reports a
    # clean estate for an account whose only row said "not used".
    "BR-02": (
        "Amazon Bedrock private connectivity",
        "Amazon Bedrock private connectivity check",
        "Amazon Bedrock private connectivity not used",
        "Bedrock VPC Endpoint Check",
    ),
    # The second name is published by the outer `except` alone, where every other
    # path publishes the first. An operator filtering the report on the name the
    # passing rows carry therefore sees no row at all for the runs that failed
    # with an exception, which is the direction that hides a broken check.
    "BR-04": (
        "Bedrock Model Invocation Logging Check",
        "Bedrock Logging Configuration Check",
    ),
    "BR-06": "Bedrock CloudTrail Logging Check",
    # BR-07 publishes its Failed line under a different name than its Passed and
    # N/A lines, so both are recorded. Filtering the report CSV on either name
    # alone hides half of this check's verdicts.
    "BR-07": ("Bedrock Prompt Management Check", "Bedrock Prompt Variants Check"),
    "BR-10": "Bedrock Guardrail IAM Enforcement Check",
    # Same split as BR-07: the second name carries this check's Failed rows, one
    # per custom model found without a CMK, and the first carries everything else.
    "BR-11": (
        "Bedrock Custom Model Encryption Check",
        "Bedrock Custom Model Encryption Review",
    ),
    "BR-12": "Bedrock Invocation Log Encryption",
    "BR-15": "Cross-Account Guardrails Enforcement Check",
    "BR-17": "Custom Model Customer-Managed KMS Encryption Check",
    "BR-20": "Knowledge Base Customer-Managed KMS Encryption Check",
    "BR-26": "Guardrail Sensitive Information Filter Check",
    "BR-27": "Guardrail Contextual Grounding Check",
    "BR-32": "Bedrock CloudWatch Alarm Check",
    "BR-34": "Guardrail Prompt Attack Filter",
    "BR-37": "Bedrock Account Data Retention",
    "BR-39": "Marketplace Model Endpoint VPC Configuration",
    "BR-41": "Central Guardrail Enforcement Policy Check",
    "BR-42": "Foundation Model Invocation Allow-List",
    "BR-43": "Bedrock Region Invocation Control",
    "BR-44": "Marketplace Model Subscription Control",
    # An inventory line and a prevention line, by design.
    "BR-45": (
        "Bedrock API Key Inventory",
        "Bedrock API Key Age And Token Type Control",
    ),
    "BR-46": "Knowledge Base Source Data Classification",
    "FS-65": "KB Data Source Buckets Missing S3 Event Notifications",
    "SM-01": "SageMaker Internet Access Check",
    "SM-02": "SageMaker IAM Permissions Check",
    "SM-03": "SageMaker Data Protection Check",
    "SM-09": "SageMaker Notebook Root Access Check",
    # Failed under the first name, Passed and both N/A rows under the second.
    "SM-10": (
        "SageMaker Notebook Not in VPC",
        "SageMaker Notebook VPC Deployment Check",
    ),
    "SM-11": "SageMaker Model Network Isolation Check",
    "SM-18": "SageMaker Transform Job Encryption Check",
    "SM-22": "Model Approval Workflow Check",
    "SM-28": "HyperPod VPC Configuration",
    "SM-31": "Endpoint Inference Data Capture",
    # Recording is the precondition, rule compliance is the assertion.
    "SM-32": ("SageMaker Configuration Recording", "SageMaker Config Rule Compliance"),
    "SM-33": "Training Job Network Boundary",
    "SM-34": "SageMaker Creation Guardrail",
}


def published_names(check_id):
    """Every finding name one incumbent publishes, as a list.

    A value may be one string or a tuple of them, because several check ids
    publish more than one name -- usually the Failed rows under one name and
    everything else under another, and BR-02 a different name per status branch.
    No count is stated here on purpose: the last one drifted from three to seven
    the first time this map was extended, and nothing gates a number in a
    docstring. Raises on an unmapped id rather than returning nothing, so adding a
    check without recording its name stops the build here instead of shipping a
    row whose incumbent has no name.
    """
    try:
        entry = INCUMBENT_NAMES[check_id]
    except KeyError:
        raise KeyError(
            f"{check_id} is cited as an incumbent but has no INCUMBENT_NAMES "
            "entry. Add the finding name(s) the check actually publishes, as "
            "read from its create_finding calls."
        ) from None
    return [entry] if isinstance(entry, str) else list(entry)


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


def table_fields(row):
    """The nine ledger fields the verdict table above decides, for one ROWS entry.

    Shared with gen_compliance_maps.rows_from_source(), which renders these same
    fields so that `--check` can compare the shipped json against this table.
    That comparison used to carry its own copy of this mapping, and a defect in
    build()'s copy was therefore invisible to it: neither copy was the other's
    oracle, so both could be read as agreeing while only one was right.

    Measured, which is why this function exists: the mutation battery's entry
    "the incumbent-name lookup reverts to its fail-open form" edits the
    incumbent_names comprehension below, and with two copies NO catcher went red
    -- check_ledger.py never re-runs build_ledger.py, so the shipped json it
    reads was still the good one, and gen_compliance_maps rendered its side from
    the unmutated copy. 21 of 22 caught. One function read by both makes the
    defect observable as a gate-15 drift.

    The other five fields a ledger row carries (`area`, `question`, `assert`,
    `workload_agnostic`, `source`) are not here: four are read from the sibling
    AISF repository and one is derived from the control id, so no verdict-table
    edit can change them.
    """
    control, verdict, disposition, module, incumbents, gap, extra_iam, phase = row
    return {
        "control": control,
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
        # Strict on purpose. The `if i in INCUMBENT_NAMES` guard this replaces
        # dropped any unmapped id silently, so 12 of 78 rows shipped an incumbent
        # id beside an empty name list -- every check phase 3 added, because the
        # map was never extended with them. A blank name list is also what gate 8
        # reads to decide whether a new_id row quotes its incumbent, so the
        # omission could only ever make that gate easier to pass.
        "incumbent_names": [name for i in incumbents for name in published_names(i)],
        "gap": gap,
        "extra_iam": extra_iam,
        "phase": phase,
    }


def build():
    aisf = load_aisf()
    rows = []
    for row in ROWS:
        control = row[0]
        meta = aisf.get(control)
        if meta is None:
            raise SystemExit(f"{control} is not a control in the AISF repo")
        if not meta["machine_checkable"]:
            raise SystemExit(f"{control} is not machine_checkable in the ledger")
        fields = table_fields(row)
        rows.append(
            {
                "control": control,
                "area": control.split("-")[1],
                "question": meta["q"],
                "assert": meta["ev"],
                "workload_agnostic": meta["workload_agnostic"],
                # Key order is preserved as it was when these nine were spelled
                # out here, so that regenerating produces the same json bytes and
                # a reader diffing the file sees only the rows that changed.
                **{k: v for k, v in fields.items() if k != "control"},
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
