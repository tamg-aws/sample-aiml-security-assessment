# AISF parity work ledger

Generated 2026-09-25 by `aisf-parity/build_ledger.py`. Do not hand-edit: change `ROWS` in the generator and re-run.

78 controls in scope: 67 hosted (BDR, SGM, ACR) plus 11 FND controls whose assertion subject is an AI resource.

| verdict | rows | meaning |
|---|---|---|
| covered | 20 | an incumbent already asserts this; nothing to write |
| tighten / extend | 19 | incumbent name is honest, its assertion is narrower; extend it in place |
| tighten / new_id | 5 | incumbent name claims more than it asserts; allocate a new id beside it |
| new | 19 | no incumbent asserts any part of it |
| not_implementable | 4 | flagged machine_checkable in the ledger but is not checkable from configuration |
| unassessed | 11 | in scope, dedup pass not yet run |

**35 new check functions and 19 extensions to existing checks.**

## New IAM actions required

- `config:DescribeConfigRules` — AIR-SGM-GOV-10
- `config:DescribeConfigurationRecorders` — AIR-SGM-GOV-10
- `macie2:GetAutomatedDiscoveryConfiguration` — AIR-BDR-KB-01
- `macie2:GetMacieSession` — AIR-BDR-KB-01
- `organizations:DescribeEffectivePolicy` — AIR-FND-DAT-09
- `organizations:DescribePolicy` — AIR-SGM-TRN-08
- `organizations:ListPolicies` — AIR-SGM-TRN-08
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
| `AIR-ACR-GW-02` | covered | — | `agentcore_assessments` | `AC-28` | AC-28 requires a service control policy that denies both CreateGateway and UpdateGateway when bedrock-agentcore:GatewayAuthorizerType is NONE, either by naming NONE in an equals-family condition or by omitting it from a not-equals-family one, so no approved-authorizer list has to be invented; attachment targets are outside the grant and the finding says so. The condition key carries a documentation drift: the AgentCore devguide wires GatewayAuthorizerType to CreateGateway and UpdateGateway and shows sibling gateway keys used this way in SCPs, while the machine-readable service reference and the service authorization reference page wire it to zero actions. The devguide wins for feature availability. Access Analyzer validate-policy accepts the key name but is no oracle for the wiring: it also accepts RuntimeAuthorizerType on CreateGateway, a pairing neither surface declares |
| `AIR-ACR-GW-03` | covered | — | `agentcore_assessments` | `AC-10`, `AC-27` | AC-10 reports that a gateway resource policy is present; AC-27 judges whether its Allow statements and the gateway execution role's trust policy carry aws:SourceAccount or aws:SourceArn, and fails an unconditioned statement even when a guarded sibling sits beside it in the same document |
| `AIR-ACR-GW-04` *(workload-specific)* | covered | — | `agentcore_assessments` | `AC-08`, `AC-27` | AC-08 now judges each AgentCore endpoint's policy against the default allow-everything document and reads its security groups for 0.0.0.0/0 and ::/0 inbound rules, alongside the existence and health legs it already held; AC-27 adds the gateway resource policy's aws:SourceVpc / aws:SourceVpce / aws:VpcSourceIp / aws:SourceIp leg |
| `AIR-ACR-GW-05` | covered | — | `agentcore_assessments` | `AG-27`, `AC-24` | AG-27 holds the WAF leg; AC-24 requires an ACTIVE gateway rate limit carrying a requests, tokens or connections ceiling, because dimensions is the only required member of a limit entry and a limit can therefore name a dimension and bound nothing |
| `AIR-ACR-GW-08` | covered | — | `agentcore_assessments` | `AC-25` | AC-25 reads credentialProviderConfigurations per target through GetGatewayTarget, which is the only surface that carries it: the ListGatewayTargets summary omits the field. The control's second leg, a Lambda target scoped to one function ARN, is not expressible because the target ARN members reject a wildcard |
| `AIR-ACR-GW-10` | covered | — | `agentcore_assessments` | `AC-19`, `AC-20`, `AC-26` | AC-19 pairs each AgentCore delivery source with its delivery and AC-20 asserts masking plus a customer managed key; AC-26 adds the two legs neither held, an explicitly configured retentionInDays and a key policy that does not let every principal decrypt without a condition |
| `AIR-ACR-MEM-01` | covered | — | `agentcore_assessments` | `AC-07`, `AC-23` | AC-07 asserts a customer managed key and an {actorId} namespace per memory, AC-23 asserts that no cached role or user reads memory records without a namespace, strategy, actor or session condition |
| `AIR-ACR-MEM-12` | covered | — | `agentcore_assessments` | `AC-18` | AC-18 asserts that a CloudTrail advanced event selector logs data events for AWS::BedrockAgentCore::Memory whenever the region holds a memory resource |
| `AIR-ACR-OBS-02` | covered | — | `agentcore_assessments` | `AC-18` | AC-18 asserts data-event coverage per resource family, so a trail that logs only the runtime types still fails for memory and for the built-in tools |
| `AIR-ACR-OBS-03` | covered | — | `agentcore_assessments` | `AC-19` | AC-04 is X-Ray tracingConfig.enabled over list_agent_runtimes only, so it cannot cover Gateway, Memory, Policy or Identity, which is OBS-03's whole subject. AC-19 asserts an APPLICATION_LOGS delivery source wired to a destination per gateway and per memory; runtime logging is service-managed, WorkloadIdentity delivery is configured on the associated runtime or gateway resource, and policy engines have no log-destination surface, so those three legs need no separate assertion |
| `AIR-ACR-OBS-04` | covered | — | `agentcore_assessments` | `AC-20`, `AC-21` | AC-20 asserts a Deidentify data-protection policy and a customer managed key on the AgentCore log groups, AC-21 asserts that no cached role or user holds logs:Unmask on every resource |
| `AIR-ACR-OBS-06` | covered | — | `agentcore_assessments` | `AC-22` | AC-22 asserts that every Allow statement on an OAM sink policy either names its principals or carries an organization condition key |
| `AIR-ACR-RT-09` | covered | — | `agentcore_assessments` | `AC-06` | recording.enabled is True plus an S3 bucket |
| `AIR-ACR-EVAL-01` | tighten | extend | `agentcore_assessments` | `AC-02` | AC-02 detects AgentCore full-access and wildcard grants only, so a role holding a single over-broad named action passes it |
| `AIR-ACR-EVAL-05` | tighten | new_id | `agentcore_assessments` | `AC-17` | AC-17 is named "Online Evaluation Coverage" but tests only status == ACTIVE, executionStatus == ENABLED and bool(evaluators); it never reads a sampling rate and never asks which evaluators, so coverage is the one thing it does not measure |
| `AIR-ACR-EVAL-06` | tighten | new_id | `agentcore_assessments` | `AC-17` | AC-17 is named "Online Evaluation Coverage" and never asks which evaluators are attached, so it cannot distinguish a safety evaluator from a latency one |
| `AIR-ACR-ID-05` | tighten | extend | `agentcore_assessments` | `AC-14` | AC-14 has the CMK leg; the string 'secret' appears 0 times in the module, so the secret-scan leg is unwritten |
| `AIR-ACR-ID-10` | tighten | extend | `agentcore_assessments` | `AC-02` | AC-02 detects full-access and wildcard grants only |
| `AIR-ACR-PAY-01` | tighten | extend | `agentcore_assessments` | `AC-02` | AC-02 detects full-access and wildcard grants only |
| `AIR-ACR-POL-01` | tighten | extend | `agentcore_assessments` | `AG-25` | AG-25 tests mode ENFORCE plus status/enforcementMode ACTIVE, with no default-deny leg, no decision log, and nothing session-aware |
| `AIR-ACR-POL-04` | tighten | extend | `agentcore_assessments` | `AC-11` | AC-11's presence-only CMK test is sound; POL-04 adds key-policy scoping plus a disable/delete alarm |
| `AIR-ACR-POL-07` | tighten | extend | `agentcore_assessments` | `AG-25` | AG-25 has no session-aware leg |
| `AIR-ACR-REG-02` | tighten | new_id | `agent_registry_assessments` | `AR-03` | AR-03 is named "Publication Approval Governance" but covers auto-approval only, behind the REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL env gate; no curator/publisher separation and no EventBridge rule |
| `AIR-ACR-RT-03` | tighten | extend | `agentcore_assessments` | `AC-02` | AC-02 detects full-access and wildcard grants only |
| `AIR-ACR-RT-08` | tighten | extend | `agentcore_assessments` | `AC-01` | AC-01 requires VPC placement and flags public subnets but never reads what the security-group rules permit; ec2:DescribeSecurityGroups is now granted to this function for AC-08's endpoint scope leg, so RT-08 costs no further permission |
| `AIR-ACR-RT-13` | tighten | new_id | `agentcore_assessments` | `AC-10` | AC-10 is named "Resource-Based Policies Check" but never evaluates policy conditions, so the aws:SourceVpc / aws:SourceVpce leg is unasserted; both keys are 0 hits corpus-wide |
| `AIR-ACR-EVAL-02` | new | — | `agentcore_assessments` | — | PassRole returns 0 across all six modules; AssumeRolePolicyDocument is read once at :2725 but only to match principal.Service for role discovery, never a condition |
| `AIR-ACR-EVAL-03` | new | — | `agentcore_assessments` | — | confused-deputy conditions absent: SourceAccount/SourceArn are 1 hit corpus-wide, in sagemaker_assessments, none in AgentCore |
| `AIR-ACR-EVAL-04` *(workload-specific)* | new | — | `agentcore_assessments` | — | — |
| `AIR-ACR-EVAL-07` | new | — | `agentcore_assessments` | — | — |
| `AIR-ACR-ID-04` | new | — | `agentcore_assessments` | — | asserts an SCP; organizations:ListPolicies and organizations:DescribePolicy are now granted to this function for GW-02's AC-28, so ID-04 costs no further permission |
| `AIR-ACR-ID-08` | new | — | `agentcore_assessments` | — | GetAgentRuntime.authorizerConfiguration exists in botocore 1.43.85 and is never read anywhere; AG-24 is gateway-only, ID-08 is about the runtime |
| `AIR-ACR-ID-11` | new | — | `agentcore_assessments` | — | the corpus reads authorizerType exactly once, at :3578, and never reads authorizerConfiguration; customJWTAuthorizer.{allowedAudience, allowedClients, allowedScopes, customClaims, discoveryUrl} are all present in the API and unread, so a gateway that trusts any issuer passes AG-24 today |
| `AIR-ACR-MEM-07` *(workload-specific)* | new | — | `agentcore_assessments` | — | — |
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
| `AIR-FND-NET-06` | unassessed | — | `agentcore_assessments` | `AC-01` | overlaps RT-08; resolve the two together. Both now cost no further permission: ec2:DescribeSecurityGroups is granted to this function for AC-08's endpoint scope leg |
