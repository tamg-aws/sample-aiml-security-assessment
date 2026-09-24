# AISF parity work ledger

Generated 2026-09-24 by `aisf-parity/build_ledger.py`. Do not hand-edit: change `ROWS` in the generator and re-run.

78 controls in scope: 67 hosted (BDR, SGM, ACR) plus 11 FND controls whose assertion subject is an AI resource.

| verdict | rows | meaning |
|---|---|---|
| covered | 8 | an incumbent already asserts this; nothing to write |
| tighten / extend | 22 | incumbent name is honest, its assertion is narrower; extend it in place |
| tighten / new_id | 6 | incumbent name claims more than it asserts; allocate a new id beside it |
| new | 27 | no incumbent asserts any part of it |
| not_implementable | 4 | flagged machine_checkable in the ledger but is not checkable from configuration |
| unassessed | 11 | in scope, dedup pass not yet run |

**44 new check functions and 22 extensions to existing checks.**

## New IAM actions required

- `cloudtrail:GetEventSelectors` — AIR-ACR-MEM-12, AIR-ACR-OBS-02
- `cloudtrail:ListTrails` — AIR-ACR-MEM-12, AIR-ACR-OBS-02
- `config:DescribeConfigRules` — AIR-SGM-GOV-10
- `config:DescribeConfigurationRecorders` — AIR-SGM-GOV-10
- `ec2:DescribeSecurityGroups` — AIR-ACR-RT-08, AIR-FND-NET-06
- `logs:DescribeAccountPolicies` — AIR-ACR-OBS-04
- `logs:GetDataProtectionPolicy` — AIR-ACR-OBS-04
- `macie2:GetAutomatedDiscoveryConfiguration` — AIR-BDR-KB-01
- `macie2:GetMacieSession` — AIR-BDR-KB-01
- `oam:GetSinkPolicy` — AIR-ACR-OBS-06
- `oam:ListSinks` — AIR-ACR-OBS-06
- `organizations:DescribeEffectivePolicy` — AIR-FND-DAT-09
- `organizations:DescribePolicy` — AIR-SGM-TRN-08, AIR-ACR-GW-02, AIR-ACR-ID-04
- `organizations:ListPolicies` — AIR-SGM-TRN-08, AIR-ACR-GW-02, AIR-ACR-ID-04
- `s3:GetBucketPolicy` — AIR-FND-DAT-02

## BDR (19 controls)

| control | verdict | do | module | incumbent | gap |
|---|---|---|---|---|---|
| `AIR-BDR-GRD-01` | covered | — | `bedrock_assessments` | `BR-10` | — |
| `AIR-BDR-GRD-03` | covered | — | `bedrock_assessments` | `BR-26` | — |
| `AIR-BDR-KB-03` | covered | — | `bedrock_assessments` | `BR-20` | — |
| `AIR-BDR-MDL-10` | covered | — | `bedrock_assessments` | `BR-37` | same GetAccountDataRetention call |
| `AIR-BDR-GRD-02` | tighten | extend | `bedrock_assessments` | `BR-34` | BR-34 tests the BLOCK action; AISF tests inputStrength HIGH |
| `AIR-BDR-GRD-04` | tighten | extend | `bedrock_assessments` | `BR-32` | BR-32 accepts any AWS/Bedrock alarm; AISF wants the guardrail-intervention metric filter |
| `AIR-BDR-GRD-09` | tighten | extend | `bedrock_assessments` | `BR-27` | BR-27 tests presence; AISF tests the grounding and relevance thresholds |
| `AIR-BDR-GRD-10` | tighten | new_id | `bedrock_assessments` | `BR-15` | BR-15 is named "Cross-Account Guardrails Enforcement Check" but only tests that an org policy exists; AISF requires it be non-DRAFT, which is what enforcement means here |
| `AIR-BDR-KB-06` | tighten | extend | `bedrock_assessments` | `BR-06` | BR-06 tests that a trail covers Bedrock; AISF wants named data-event resource types |
| `AIR-BDR-MDL-02` | tighten | extend | `bedrock_assessments` | `BR-04`, `BR-12` | BR-04 and BR-12 cover logging and destination encryption; AISF adds retention |
| `AIR-BDR-MDL-07` | tighten | extend | `bedrock_assessments` | `BR-06` | BR-06 tests that a trail covers Bedrock; AISF wants named data-event resource types |
| `AIR-BDR-KB-01` | new | — | `bedrock_assessments` | — | no incumbent in this module reads macie2 |
| `AIR-BDR-MDL-01` *(workload-specific)* | new | — | `bedrock_assessments` | — | no check asserts model-ARN scoping on bedrock:InvokeModel; aws:RequestedRegion, aws:SourceVpc, aws:SourceVpce and aws:PrincipalOrgID are 0 hits corpus-wide |
| `AIR-BDR-MDL-03` *(workload-specific)* | new | — | `bedrock_assessments` | — | model allow-list; FS-12 is not a dedup risk, its whole test is 'bedrock' in json.dumps(doc).lower() over every SCP |
| `AIR-BDR-MDL-04` *(workload-specific)* | new | — | `bedrock_assessments` | — | model allow-list dimension with no incumbent |
| `AIR-BDR-MDL-09` | new | — | `bedrock_assessments` | — | — |
| `AIR-BDR-KB-05` | not_implementable | — | — | — | depends on customer Lambda code, not configuration |
| `AIR-BDR-KB-08` | not_implementable | — | — | — | depends on customer Lambda code, not configuration |
| `AIR-BDR-MDL-08` | not_implementable | — | — | — | needs a published-versus-DRAFT distinction GetPrompt does not return |

## SGM (11 controls)

| control | verdict | do | module | incumbent | gap |
|---|---|---|---|---|---|
| `AIR-SGM-EP-08` | covered | — | `sagemaker_assessments` | `SM-18` | — |
| `AIR-SGM-TRN-05` | covered | — | `sagemaker_assessments` | `SM-09`, `SM-01`, `SM-03` | all three legs present |
| `AIR-SGM-EP-01` | tighten | extend | `sagemaker_assessments` | `SM-11` | SM-11 has the EnableNetworkIsolation leg, not the VpcConfig leg |
| `AIR-SGM-EP-02` *(workload-specific)* | tighten | extend | `sagemaker_assessments` | `SM-02` | SM-02 scans IAM permissions but never tests resource-scoped sagemaker:InvokeEndpoint against a named endpoint ARN; SageMaker endpoints carry no resource-based policy, so the identity policy is the whole surface |
| `AIR-SGM-GOV-01` | tighten | extend | `sagemaker_assessments` | `SM-22` | SM-22 has approval status, not approver metadata |
| `AIR-SGM-TRN-02` | tighten | extend | `sagemaker_assessments` | `SM-03` | SM-03 has the KMS legs, not inter-container traffic encryption |
| `AIR-SGM-EP-06` | new | — | `sagemaker_assessments` | — | DataCaptureConfig; SM-23 reads monitoring schedules, not data capture |
| `AIR-SGM-GOV-10` | new | — | `sagemaker_assessments` | — | Config recorder state; no incumbent in this module reads config |
| `AIR-SGM-TRN-01` | new | — | `sagemaker_assessments` | — | training-job network isolation; SM-21 does this for AutoML jobs only |
| `AIR-SGM-TRN-08` | new | — | `sagemaker_assessments` | — | SCP asserting encryption/no-internet/VPC at creation; the corpus already enumerates SCPs in two modules, so the cost is the Organizations read, not a new mechanism |
| `AIR-SGM-EP-03` | not_implementable | — | — | — | slug names sagemaker_endpoint_intercontainer_encryption_enabled but EnableInterContainerTrafficEncryption is absent from DescribeEndpointConfig and present only on DescribeTrainingJob; do not port as written, fix in the AISF repo first |

## ACR (37 controls)

| control | verdict | do | module | incumbent | gap |
|---|---|---|---|---|---|
| `AIR-ACR-GW-01` | covered | — | `agentcore_assessments` | `AG-24` | AG-24 accepts authorizerType in {AWS_IAM, CUSTOM_JWT}, or AUTHENTICATE_ONLY with a policy engine in ENFORCE, which is GW-01's assertion exactly |
| `AIR-ACR-RT-09` | covered | — | `agentcore_assessments` | `AC-06` | recording.enabled is True plus an S3 bucket |
| `AIR-ACR-EVAL-01` | tighten | extend | `agentcore_assessments` | `AC-02` | AC-02 detects AgentCore full-access and wildcard grants only, so a role holding a single over-broad named action passes it |
| `AIR-ACR-EVAL-05` | tighten | new_id | `agentcore_assessments` | `AC-17` | AC-17 is named "Online Evaluation Coverage" but tests only status == ACTIVE, executionStatus == ENABLED and bool(evaluators); it never reads a sampling rate and never asks which evaluators, so coverage is the one thing it does not measure |
| `AIR-ACR-EVAL-06` | tighten | new_id | `agentcore_assessments` | `AC-17` | AC-17 is named "Online Evaluation Coverage" and never asks which evaluators are attached, so it cannot distinguish a safety evaluator from a latency one |
| `AIR-ACR-GW-03` | tighten | new_id | `agentcore_assessments` | `AC-10` | AC-10 is named "Resource-Based Policies Check" but reports only that a policy is present and never evaluates its conditions, so the confused-deputy leg is unasserted |
| `AIR-ACR-GW-04` *(workload-specific)* | tighten | extend | `agentcore_assessments` | `AC-08` | AC-08 tests endpoint existence and available state, not endpoint policy or security-group scope; it does hold one leg GW-04 lacks, endpoint health |
| `AIR-ACR-GW-05` | tighten | extend | `agentcore_assessments` | `AG-27` | AG-27 has the WAF leg; the rate-limit leg needs ListGatewayRateLimits, so botocore >= 1.43.66 |
| `AIR-ACR-ID-05` | tighten | extend | `agentcore_assessments` | `AC-14` | AC-14 has the CMK leg; the string 'secret' appears 0 times in the module, so the secret-scan leg is unwritten |
| `AIR-ACR-ID-10` | tighten | extend | `agentcore_assessments` | `AC-02` | AC-02 detects full-access and wildcard grants only |
| `AIR-ACR-MEM-01` | tighten | extend | `agentcore_assessments` | `AC-07` | AC-07's presence-only CMK test is sound (encryptionKeyArn is an optional customer-supplied CreateMemory input); MEM-01 adds per-actor and namespace access scoping |
| `AIR-ACR-PAY-01` | tighten | extend | `agentcore_assessments` | `AC-02` | AC-02 detects full-access and wildcard grants only |
| `AIR-ACR-POL-01` | tighten | extend | `agentcore_assessments` | `AG-25` | AG-25 tests mode ENFORCE plus status/enforcementMode ACTIVE, with no default-deny leg, no decision log, and nothing session-aware |
| `AIR-ACR-POL-04` | tighten | extend | `agentcore_assessments` | `AC-11` | AC-11's presence-only CMK test is sound; POL-04 adds key-policy scoping plus a disable/delete alarm |
| `AIR-ACR-POL-07` | tighten | extend | `agentcore_assessments` | `AG-25` | AG-25 has no session-aware leg |
| `AIR-ACR-REG-02` | tighten | new_id | `agent_registry_assessments` | `AR-03` | AR-03 is named "Publication Approval Governance" but covers auto-approval only, behind the REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL env gate; no curator/publisher separation and no EventBridge rule |
| `AIR-ACR-RT-03` | tighten | extend | `agentcore_assessments` | `AC-02` | AC-02 detects full-access and wildcard grants only |
| `AIR-ACR-RT-08` | tighten | extend | `agentcore_assessments` | `AC-01` | AC-01 requires VPC placement and flags public subnets but never reads what the security-group rules permit; describe_security_groups is 0 hits in the module, so VPC placement is proven and egress filtering is not |
| `AIR-ACR-RT-13` | tighten | new_id | `agentcore_assessments` | `AC-10` | AC-10 is named "Resource-Based Policies Check" but never evaluates policy conditions, so the aws:SourceVpc / aws:SourceVpce leg is unasserted; both keys are 0 hits corpus-wide |
| `AIR-ACR-EVAL-02` | new | — | `agentcore_assessments` | — | PassRole returns 0 across all six modules; AssumeRolePolicyDocument is read once at :2725 but only to match principal.Service for role discovery, never a condition |
| `AIR-ACR-EVAL-03` | new | — | `agentcore_assessments` | — | confused-deputy conditions absent: SourceAccount/SourceArn are 1 hit corpus-wide, in sagemaker_assessments, none in AgentCore |
| `AIR-ACR-EVAL-04` *(workload-specific)* | new | — | `agentcore_assessments` | — | — |
| `AIR-ACR-EVAL-07` | new | — | `agentcore_assessments` | — | — |
| `AIR-ACR-GW-02` | new | — | `agentcore_assessments` | — | asserts an SCP; the corpus already enumerates SCPs in two modules, so the cost is the Organizations read |
| `AIR-ACR-GW-08` | new | — | `agentcore_assessments` | — | — |
| `AIR-ACR-GW-10` | new | — | `agentcore_assessments` | — | — |
| `AIR-ACR-ID-04` | new | — | `agentcore_assessments` | — | asserts an SCP; same Organizations read as GW-02 |
| `AIR-ACR-ID-08` | new | — | `agentcore_assessments` | — | GetAgentRuntime.authorizerConfiguration exists in botocore 1.43.85 and is never read anywhere; AG-24 is gateway-only, ID-08 is about the runtime |
| `AIR-ACR-ID-11` | new | — | `agentcore_assessments` | — | the corpus reads authorizerType exactly once, at :3578, and never reads authorizerConfiguration; customJWTAuthorizer.{allowedAudience, allowedClients, allowedScopes, customClaims, discoveryUrl} are all present in the API and unread, so a gateway that trusts any issuer passes AG-24 today |
| `AIR-ACR-MEM-07` *(workload-specific)* | new | — | `agentcore_assessments` | — | — |
| `AIR-ACR-MEM-12` | new | — | `agentcore_assessments` | — | CloudTrail event selectors; reads no AgentCore API |
| `AIR-ACR-OBS-02` | new | — | `agentcore_assessments` | — | CloudTrail event selectors; reads no AgentCore API |
| `AIR-ACR-OBS-03` | new | — | `agentcore_assessments` | — | AC-04 is X-Ray tracingConfig.enabled over list_agent_runtimes only, so it cannot cover Gateway, Memory, Policy or Identity, which is OBS-03's whole subject; this row was a tightening in an earlier draft and the resource-scope check moved it |
| `AIR-ACR-OBS-04` | new | — | `agentcore_assessments` | — | CloudWatch Logs data-protection policy |
| `AIR-ACR-OBS-06` | new | — | `agentcore_assessments` | — | OAM sink policy |
| `AIR-ACR-POL-06` *(workload-specific)* | new | — | `agentcore_assessments` | — | — |
| `AIR-ACR-RT-04` *(workload-specific)* | new | — | `agentcore_assessments` | — | — |

## FND (11 controls)

| control | verdict | do | module | incumbent | gap |
|---|---|---|---|---|---|
| `AIR-FND-DAT-01` | unassessed | — | `bedrock_assessments`, `responsible_ai_grc_assessments` | `BR-20`, `FS-65` | candidate incumbents only; dedup not run. Spans two modules: BR-20 covers knowledge base CMK, FS-65 covers the data-source buckets |
| `AIR-FND-DAT-02` | unassessed | — | `bedrock_assessments` | — | needs s3:GetBucketPolicy, which no function is granted |
| `AIR-FND-DAT-03` | unassessed | — | `responsible_ai_grc_assessments` | — | macie2 already granted to this function |
| `AIR-FND-DAT-09` | unassessed | — | `bedrock_assessments` | — | AISERVICES_OPT_OUT_POLICY via DescribeEffectivePolicy, which no function is granted; the AI-services opt-out is the most AI-specific control in the FND area |
| `AIR-FND-DET-01` | unassessed | — | `bedrock_assessments` | `BR-04`, `BR-12` | candidate incumbents only; dedup not run |
| `AIR-FND-DET-04` | unassessed | — | `bedrock_assessments` | `BR-34` | candidate incumbent only; dedup not run |
| `AIR-FND-IAM-05` | unassessed | — | `agentcore_assessments` | `AC-02` | candidate incumbent only; dedup not run |
| `AIR-FND-NET-01` | unassessed | — | `agentcore_assessments`, `sagemaker_assessments` | `AC-01`, `SM-11` | spans two modules; candidate incumbents only. 'AI workloads run privately' has no single host, which is why the FND area has no module of its own |
| `AIR-FND-NET-02` | unassessed | — | `agentcore_assessments` | `AC-08` | candidate incumbent only; dedup not run |
| `AIR-FND-NET-04` | unassessed | — | `responsible_ai_grc_assessments`, `agentcore_assessments` | `AG-27` | wafv2 is already granted to the GRC function, but the AG-27 incumbent lives in the AgentCore module; pick one before writing it |
| `AIR-FND-NET-06` | unassessed | — | `agentcore_assessments` | `AC-01` | overlaps RT-08; resolve the two together |
