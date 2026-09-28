# Changelog

All notable user-facing and deployable changes to this project are documented
in this file.

Changes are accumulated under **Unreleased** as they are merged. Creating a
release is not required for every change. When a version is tagged, move its
entries into a dated version section and create a new empty **Unreleased**
section.

## Unreleased

### Added

- Added an **AWS AI Security Framework (AISF)** section to the HTML report,
  alongside OWASP Top 10 for LLM under "By Compliance Standard". It reports 8
  of the 105 in-scope AISF controls as `AISF-01` through `AISF-08`. Behavior
  worth knowing:
  - The section is always on. It needs no deployment parameter, runs no
    additional AWS API calls, and adds no scan time, because each row restates
    the verdict of a check that already ran under an AISF control id.
  - `AISF-` rows are excluded from the 273-check catalog total, from the report
    pass rate, and from Open Action Items, for the same reason OWASP-mapped
    rows are: the underlying check is already counted.
  - `AISF-08` aggregates three SageMaker checks (`SM-09`, `SM-01`, `SM-03`). It
    reports `Passed` only when all three passed, `Failed` when any failed, and
    `N/A` naming the absent checks when coverage is incomplete.
  - An informational `AISF-00` row appears per account and region where
    AISF-relevant checks ran but a mapped source check was absent, so partial
    coverage reads as unassessed instead of compliant.
  - Severity comes from the AISF control's own risk band. The three controls
    AISF rates `critical` (`AISF-01`, `AISF-03`, `AISF-04`) report as `High`,
    because this framework has four severity levels and no `Critical`; each of
    their rows states the pre-collapse risk in `Finding_Details`, so the
    downgrade is visible in the finding and not only in the methodology.
  - The mappings are preliminary and illustrative. Validate them with your
    security and compliance team before using a row as audit evidence.
    `docs/SECURITY_CHECKS_AISF.md` documents every row and its source checks.
- Added 15 checks for the AISF foundation controls and extended six, growing
  the catalog from 256 to 271 checks (156 core): `BR-50` to `BR-55` in
  Bedrock, `SM-35` to `SM-41` in SageMaker AI, and `AC-50` and `AC-51` in
  AgentCore, with new legs on `BR-01`, `BR-04`, `BR-12`, `BR-43`, `SM-02` and
  `AC-26`. The three entries that follow give the per-module detail.
- The AISF parity ledger now reports 97 of the 105 in-scope AISF controls as
  `covered` and 8 as `not_implementable`, with none left `tighten` or `new`.
  The 19 foundation controls that waited on those checks and legs are
  `covered`, and the new check ids carry their AISF control in the
  `Compliance_Frameworks` column.
- Added `AC-50` and `AC-51`, and extended `AC-26`. The assessment role gains
  one read-only permission, `ecr:GetRegistryScanningConfiguration`.
  - `AC-50` fails an AgentCore image repository that Amazon Inspector enhanced
    scanning does not cover, including every repository on a `BASIC` registry.
  - `AC-51` fails an AgentCore gateway whose web ACL does not run
    `AWSManagedRulesAntiDDoSRuleSet`, runs it with the group or its rules set
    to `Count`, or that has no web ACL. Other front doors such as API Gateway,
    ALB, and CloudFront are not judged, because no API identifies them as AI
    entry points.
  - `AC-26` now also fails a runtime log group, or the `aws/spans` group, with
    deletion protection off. A group that reports no setting is read as off,
    so an `AC-26` row that passed before can now fail.
- Added 48 checks so every machine-verifiable AISF control has a producing
  check, growing the catalog from 208 to 256 checks (141 core, 39 Agentic AI,
  64 Responsible AI GRC, and 12 OWASP): `BR-41` through `BR-49`, `SM-31`
  through `SM-34`, `AC-18` through `AC-49`, `AR-09`, `AR-10`, and `AG-39`.
  Of the 78 in-scope AISF controls, 74 are now covered by a shipped check and
  the other 4 ask about evidence no AWS API returns; the parity ledger in
  `aisf-parity/AISF-WORK-LEDGER.md` names the reason for each. Each producer
  row names its AISF controls in the `Compliance_Frameworks` CSV column.
  Behavior worth knowing:
  - `AC-49` reads Route 53 Resolver DNS Firewall in evaluation order: rule
    groups by ascending association priority, rules by ascending priority, and
    the first rule over a `*` domain list decides, because the first match ends
    evaluation. It passes only when that rule is a `BLOCK` with no query type.
    `ListFirewallDomains` returns the walled garden catch-all as `*.`, and the
    check accepts that spelling as well as `*`.
  - `AC-49` passes that `BLOCK` only when the VPC's DNS Firewall config has
    `FirewallFailOpen` `DISABLED`. `ENABLED` fails, because VPC Resolver then
    answers every query while DNS Firewall is impaired, and
    `USE_LOCAL_RESOURCE_SETTING`, which Route 53 does not document, is `N/A`
    with the value named.
  - `BR-47` fails a Bedrock data path bucket with no bucket policy, because S3
    then accepts plaintext requests, and passes only a `Deny` on
    `aws:SecureTransport` `false` that reaches every principal and covers
    `s3:*` on both the bucket and its objects. A `Deny` whose `Condition`
    also tests another key, such as `aws:SourceVpce`, is not credited.
  - `BR-47` also reads the invocation log large-data bucket
    (`cloudWatchConfig.largeDataDeliveryS3Config`) and the invocation-log
    source bucket of distillation jobs, and no longer reports `Passed` when
    the bucket list is incomplete. Before, reaching the 50 data source cap
    went unreported and the check read "50 of 50" as `Passed`; a cap or a
    failed read now turns the enforced buckets into an `N/A` row that names
    how many were read.
  - `BR-42` and `BR-49` read a `Resource` whose resource segment carries a
    `*` that still matches every model, such as
    `arn:aws:bedrock:*::foundation-model*`, `foundation-model/**` or
    `inference-profile/?*`, as unscoped. Before, only `*` and entries ending
    in `/*` or `:*` were, so `BR-42` passed such an Allow as a named model
    list and `BR-49` refused credit to such a Deny.
  - `BR-48` reads the organization's effective AI services opt-out policy.
    From the management account it also reads every opt-out policy to name
    any whose value a child policy may change. An unset
    `@@operators_allowed_for_child_policies` means `@@all`, and only
    `["@@none"]` locks the value; from a member account that leg is skipped.
  - `SM-32` reads compliance only for customer-managed Config rules. A rule
    with `CreatedBy` set is service-linked, for example one Security Hub
    creates, and AWS Config refuses its compliance results to every caller;
    such rules get their own `N/A` naming the owning service and never count
    toward a `Passed`.
  - `AR-10` credits a default-bus rule whose only targets are event buses
    only when the events reach a target other than an event bus. A forward to
    a bus in the same account and Region is followed one hop, and a rule there
    must match the events and deliver them. A forward to a bus in another
    account or Region is reported `N/A` naming that bus, because its rules
    cannot be read. `ListRules` on the forwarded bus is covered by the
    existing `*` grant and `ListTargetsByRule` by the existing `rule/*` grant.
  - `AG-39` does not read the rules inside customer rule groups or non-AWS
    managed rule groups. An ACL that relies on one for a missing filter is
    reported `N/A` with the group named.
  - `AG-39` credits a filter only to a rule whose action is `Block`. An
    `Allow`, `Captcha` or `Challenge` rule over a SQL injection, cross-site
    scripting or rate-based statement is not coverage, and neither is an AWS
    managed group whose providing rule is set to another action by
    `RuleActionOverrides` or listed in `ExcludedRules`.
  - `AG-39` reads the gateway's `wafConfiguration.failureMode`. A gateway set
    to `FAIL_OPEN` allows requests when AWS WAF cannot be evaluated and fails
    whatever its web ACL applies. A gateway that reports no `failureMode` is
    `N/A`, because the API states no default.
- Added 7 SageMaker assessment checks for AISF foundation controls: `SM-35`
  security service delegated administrator, `SM-36` the Security Hub AI Security Best Practices
  standard, `SM-37` GuardDuty Lambda Protection, `SM-38` GuardDuty Runtime
  Monitoring, `SM-39` EKS vpc-cni network policy, `SM-40` Secrets Manager
  rotation, and `SM-41` AWS IoT device-scoped policies. `SM-02` gains a
  `SageMaker Service-Wide Grant in Customer Policy` finding. Behavior worth
  knowing:
  - `SM-35` emits one row per service from a fixed list of six and names the
    list on every row. It runs once, on the primary region, tagged `Global`.
    A denied `ListDelegatedAdministrators` is `N/A` for that service, because
    the list is readable only from the management account or a delegated
    administrator account.
  - `SM-38` fails a detector with only the legacy `EKS_RUNTIME_MONITORING`
    feature enabled, because that feature covers EKS only.
  - `SM-39` passes a cluster whose managed vpc-cni add-on enables network
    policy, which makes enforcement available; whether NetworkPolicy objects
    restrict pod traffic is a Kubernetes-API fact the scan cannot read. EKS
    Auto Mode clusters are `N/A`, because Auto Mode sets network policy on the
    NodeClass, a Kubernetes object no AWS API returns.
  - `SM-40` skips secrets that another AWS service owns (`OwningService`),
    fails a secret with rotation turned on that has never rotated, and reports
    `N/A` for a `cron()` form it does not interpret. It reads rotation
    metadata only, never a secret value.
  - `SM-02`'s new finding reads customer-managed and inline policies only. A
    bare `"*"` and AWS managed policies are left to the existing findings.
  - `SM-36` through `SM-41` run after the SageMaker availability probe, so a
    region where SageMaker is unavailable does not report them.

- Added six Bedrock checks: `BR-50` (active access keys on IAM users with a
  non-read Bedrock, SageMaker AI or AgentCore grant), `BR-51` (console password without MFA on
  the same users), `BR-52` (COMPLIANCE-mode Object Lock on Bedrock data path
  buckets), `BR-53` (an owner tag on agents, knowledge bases, guardrails,
  custom and imported models, and provisioned throughputs), `BR-54` (public
  Lambda function URLs and unconditioned `*` invoke grants), and `BR-55`
  (KMS keys that use Nitro Enclave or NitroTPM attestation but allow
  decryption, shared secret derivation or data key generation without an
  attestation pin). Four existing checks gain a leg:
  - `BR-01` fails customer-managed, inline and group policies that grant
    every Bedrock action or grant Bedrock through `NotAction`.
  - `BR-04` credits only a lifecycle rule that covers the `<keyPrefix>/AWSLogs/`
    root, and on a versioned bucket also requires noncurrent-version
    expiration.
  - `BR-12` reports deletion protection on the invocation log group.
  - `BR-43` adds an organization-wide finding that a service control policy
    denies model invocation outside a named list of model ARNs.
  - The IAM permissions cache now records each user's group policies, which
    `BR-01`, `BR-50` and `BR-51` read. A user whose groups cannot be read is
    reported `N/A`, never clean.
- Added `BR-56` and `AC-52`, growing the catalog from 271 to 273 checks (158
  core). They answer two requirements in Prowler's AWS AI Security Framework
  mapping that no check asserted, and carry no `Compliance_Frameworks` tag,
  because Prowler's requirement ids are not AISF catalogue controls.
  `docs/SECURITY_CHECKS_AISF.md` records the cross-reference and names five
  Prowler requirements judged out of charter as account hygiene.
  - `BR-56` reproduces Prowler's `cloudtrail_threat_detection_llm_jacking`
    (AISF-AI-06). It fails an identity that called more than 40% of 14 Bedrock
    and Marketplace actions in the last 24 hours of the Region's CloudTrail
    event history. Event history holds management events only, so the row
    names the Bedrock data events it cannot see. An action cut off at the
    5-page limit, or one whose lookup failed, is reported `N/A` for every
    identity it could push over the threshold, never passed.
  - `AC-52` answers AISF-IAM-07 for the Cognito user pools named by an
    AgentCore gateway or runtime JWT authorizer: MFA, threat protection
    enforcement, admin-only sign-up, deletion protection, temporary password
    validity, and per app client token revocation and user existence errors.
    A pool used only through the `client_credentials` flow is judged on
    deletion protection and token revocation alone.

### Fixed

- `AC-07` names the fix that matches the `GetMemory` error for a memory it
  cannot describe. `AccessDeniedException` now names `kms:Decrypt` on the
  memory's customer managed key as well as `bedrock-agentcore:GetMemory`,
  because AgentCore decrypts the memory's strategies on the caller's behalf,
  and the derived `AG-19` row carries that cause. Only
  `ResourceNotFoundException` still suggests a memory deleted mid-assessment.
  The AgentCore assessment role gains that `kms:Decrypt` grant, and a
  remaining denial names the key policy, which must also allow the role.

- AgentCore checks that read the IAM permissions cache, trust policies and
  resource policies now judge the values they read and the whole population
  they cover:
  - The cache consumers accept the version 2 contract. A principal named in
    `principal_errors` withholds `Passed` from every population-wide claim
    that includes it and is named in an `N/A` row; a permissions boundary is
    intersected with the principal's grants; a version 1 cache is read with a
    note that principal read errors were not recorded. SCPs are not evaluated
    per principal, and the finding text says so.
  - `AC-02` reads users and group policies as well as roles, counts a bare
    `Action: "*"` and a `NotAction` that leaves AgentCore in, and adds three
    legs: evaluator author and reader separation, the payments `iam:PassRole`
    scope, and each payment manager's retrieval role trust, which must name
    only `bedrock-agentcore.amazonaws.com` and pin `aws:SourceArn` to that
    manager.
  - The confused-deputy guard in `AC-27`, `AC-43` and `AC-48` counts only when
    every `aws:SourceAccount` or `aws:SourceArn` value names the assessed
    account. `IfExists`, `ForAllValues` and wildcard values no longer pass.
    `AC-27` fails a gateway role that trusts a second principal.
  - `AC-10` fails an Allow statement that opens a runtime or gateway to any
    principal without binding the caller's account or organization, and
    reports a failed runtime or gateway list instead of passing.
  - `AC-48` adds memory, payment manager and harness execution roles to the
    population, withholds the sharing `Passed` when any family could not be
    listed, and clears an account-root trust only when its condition names
    the calling principal.
  - `AC-03`, `AC-21` and `AC-23` count a bare `Action: "*"`, any pattern or
    `NotAction` that reaches the action, and group policies on users, and
    drop a grant the principal's own Deny or boundary removes. A policy that
    cannot be parsed is named in an `N/A` row. Rows that passed before can now
    fail.
  - `AC-03` pages through the last-accessed report and names every principal
    whose report failed, was throttled or errored, instead of passing
    without it.
  - `AC-21` treats a log group resource as unbounded only when the group name
    is wildcard-only or a wider ARN segment is a wildcard.
  - `AC-23` judges each read by the key that action carries: `namespace` for
    record reads, `actorId` or `sessionId` for event reads. A `strategyId`
    condition alone, an `IfExists`, `ForAllValues` or negated operator, and a
    wildcard-only value no longer pass. A scoped principal is reported as
    bound to the caller when every value carries a policy variable, and as
    fixed otherwise.
  - `AC-32`, `AC-33`, `AC-42` and `AC-44` read the same way as `AC-23`: a
    bare `Action: "*"` and group policies count, a grant the principal's own
    Deny or boundary removes does not, and a principal the IAM cache could
    not read is named in an `N/A` row that withholds `Passed`.
  - `AC-32` accepts an issuer pin only by value: every value of
    `InboundJwtClaim/iss` must be a literal or a pattern narrower than `*`.
  - `AC-33` fails a token grant written with `NotResource`, or with a
    wildcard in the region or account of the workload identity ARN.
  - `AC-42` reads a `NotResource` pass-role grant as reaching every role it
    does not list, and adds a writer leg on the primary region that fails a
    principal able to create or update an online evaluation configuration
    whose `iam:PassRole` grant does not name its roles or does not pin
    `iam:PassedToService` to `bedrock-agentcore.amazonaws.com`.
  - `AC-44` fails a model grant whose service, account or resource type
    segment is a wildcard (`arn:aws:bedrock:*::*`) or that uses
    `NotResource`. A region wildcard on a named model still passes.

### Deployment impact

**CodeBuild run required.** No parameter or deployment-stack change. The AWS
SAM templates (`aiml-security-assessment/template.yaml` and
`aiml-security-assessment/template-multi-account.yaml`) add read-only actions
to the assessment Lambda execution roles for the new checks, among them
the four named `route53resolver:ListFirewall` read actions,
`route53resolver:GetFirewallConfig`, `wafv2:GetWebACL`,
`organizations:DescribeEffectivePolicy`, `macie2:ListClassificationJobs`,
`s3:GetBucketPolicy`, and `bedrock:ListModelCustomizationJobs`. The AgentCore
role also gains `kms:Decrypt` on the account's keys, allowed only when the
request comes through `bedrock-agentcore` (`kms:ViaService`), so `AC-07` can
describe a memory encrypted with a customer managed key. A key whose policy
does not allow the role still denies it. A CodeBuild
run that redeploys the assessment code and SAM templates applies them. No
member-role StackSet update and no central or single-account infrastructure
update are required.

The `BR-50` to `BR-55` checks and legs above add, in both SAM templates: on the
Bedrock assessment role, `bedrock:ListProvisionedModelThroughputs`,
`kms:GetKeyPolicy`, `kms:ListKeys`, `iam:ListAccessKeys`,
`iam:GetLoginProfile`, `iam:ListMFADevices`, `s3:GetBucketVersioning`,
`s3:GetBucketObjectLockConfiguration`, `backup:ListBackupVaults`,
`tag:GetResources`, `lambda:ListFunctionUrlConfigs` and `lambda:GetPolicy`;
on the IAM permissions cache role, `iam:ListGroupsForUser`,
`iam:ListAttachedGroupPolicies`, `iam:ListGroupPolicies` and
`iam:GetGroupPolicy`. All are read-only. `kms:ListKeys`,
`backup:ListBackupVaults` and `tag:GetResources` are granted on `*` because
none has a resource type in the IAM service authorization reference.

The SageMaker assessment role gains `organizations:ListDelegatedAdministrators`,
`securityhub:GetEnabledStandards`, `eks:ListClusters`, `eks:DescribeCluster`,
`eks:ListAddons`, `eks:DescribeAddon`, `secretsmanager:ListSecrets`, `iot:ListPolicies`,
`iot:ListTargetsForPolicy`, and `iot:GetPolicy` for `SM-35` through `SM-41`,
in both SAM templates. The same CodeBuild run applies them.

`BR-56` and `AC-52` add, in both SAM templates: on the Bedrock assessment
role, `cloudtrail:LookupEvents`, granted on `*` because it has no resource
type in the IAM service authorization reference; on the AgentCore assessment
role, `cognito-idp:DescribeUserPool`, `cognito-idp:ListUserPoolClients` and
`cognito-idp:DescribeUserPoolClient`, scoped to the account's user pools. All
are read-only, and the same CodeBuild run applies them. No parameter,
deployment-stack or member-role StackSet change is required.

The AgentCore assessment role gains `bedrock-agentcore:GetPaymentManager` and
`bedrock-agentcore:GetHarness`, scoped to the account's `payment-manager/*` and
`harness/*` ARNs, in both SAM templates. Both are read-only, and the same
CodeBuild run applies them. `bedrock-agentcore:ListPaymentManagers` and
`bedrock-agentcore:ListHarnesses` have no resource type and are not granted;
until they are, the payment manager and harness legs of `AC-02` and `AC-48`
report `N/A` naming the missing action.

## 2.0.0 - 2026-09-18

This release grows the catalog from 161 checks across five areas to 208 checks
across seven, adding OWASP Top 10 for LLM and AWS Agent Registry as assessment
areas and renaming the Financial Services GenAI risk capability to Responsible
AI GRC. It also hardens the assessment IAM roles and makes incomplete
multi-account coverage fail a run rather than publish a partial report.

Upgrading is not a single step and is not fully backward compatible:

- Apply the updates in the order given under **Deployment impact** below. The
  multi-account member-role StackSet must be updated first.
- `TargetRegions=all` is no longer accepted. Any stored parameter value, saved
  stack input, or automation using it must change to an empty value or an
  explicit region list before upgrading.
- `EnableFinServAssessment` still works as a deprecated alias for
  `EnableResponsibleAIGRCAssessment`, but direct Step Functions input using
  `"enableFinServ": "true"` is rejected.

### Added

- Added AWS Agent Registry as an independent assessment area with its own
  regional Lambda, Step Functions branch, CSV artifact, and HTML report area
  (including a dashboard summary tile and assessment-scope chip), plus an
  `AR-00` through `AR-08` check namespace covering IAM full access, IAM stale
  access, publication approval governance, discovery authorization,
  customer-managed KMS encryption, organization auto-detection, record
  lifecycle governance, and record provenance. Behavior worth knowing:
  - `AR-01` and `AR-02` evaluate attached and inline policies whose
    `Statement` is either a single object or a list. `AR-02` uses IAM
    service-last-accessed data: access older than 60 days fails, while IAM job
    errors and deadlines stay visible as indeterminate `N/A` rows.
  - Record inventory is bounded to 1,000 records and paginates within the
    Lambda deadline. A truncation or deadline notice is reported as an
    additional `N/A`/Informational row and does not discard the records
    already assessed.
  - Absent optional service metadata — approval configuration, discovery
    authorizer, auto-detection, creator attribution, and provenance source
    type — is reported as indeterminate `N/A` rather than as a failure, and an
    unrecognized authorizer type is reported as unsupported instead of as a
    reviewed JWT configuration. Auto-detected records must carry
    `DETECTED_FROM` lineage naming an AgentCore runtime or gateway matching
    the declared source type.
  - Discovery authorization and record lifecycle states are reported as
    informational evidence requiring review rather than as passes.
  - Registries in regions the account has not enabled are reported as
    unavailable, and client initialization or API failures become incomplete
    assessments with error-specific remediation. A single failing check
    produces an incomplete `N/A` row while the regional CSV is still written;
    an unrecoverable CSV-generation or S3-write failure raises so Step
    Functions records the failed task instead of treating a returned
    `statusCode: 500` payload as success.
- Added Agentic AI Security mappings `AG-33` through `AG-38`, derived from the
  new `AR-03` through `AR-08` controls. The catalog now contains 208 checks
  (94 core, 38 Agentic AI, 64 Responsible AI GRC, and 12 OWASP). Agent
  Registry findings are deliberately outside OWASP scope — the `AR-*` controls
  establish Registry governance but do not directly prove an OWASP
  LLM01–LLM10 control — so enabling OWASP does not change Registry counts.
- Added configurable `RequireAgentRegistryManualApproval` and
  `RequireAgentRegistryCMK` deployment baselines. Both are advisory by
  default, so a registry that auto-approves submitted records or uses the AWS
  owned encryption key is reported as informational, and remediation guidance
  is shown only when the baseline requires the control.
- Added SDK contract, IAM coverage, baseline-wiring, registry inventory,
  error-path, and finding-behavior tests, including pass/fail (or advisory
  `N/A`), no-resource, and access-denied coverage for `AR-01` and `AR-04`
  through `AR-07`.

### Changed

- Hardened assessment deployment roles. `AIMLSecurityMemberRole` now contains
  only cross-account deployment, Step Functions polling, and report-retrieval
  permissions; assessment APIs remain exclusively on the SAM-created Lambda
  execution roles. CodeBuild roles now scope Lambda, IAM, S3, and `PassRole`
  access to assessment resources, restrict `PassRole` to Lambda and Step
  Functions, remove stale Lambda/S3 administration actions, and no longer
  define unused local member roles. SAM runtime roles now use exact,
  prefix-scoped S3 artifact permissions instead of bucket-wide
  `S3CrudPolicy`, and remove stale IAM, SageMaker, GuardDuty, AgentCore, ECR,
  Logs, EC2, Lambda, ECS, CloudTrail, and S3 actions. The IAM permission-cache
  Lambda retains only the identity and policy reads it actually performs.
  Per-resource reads are ARN-scoped wherever the AWS service supports it;
  account-level enumeration APIs that do not support resource-level
  authorization (`bedrock:ListGuardrails`, `bedrock:ListPrompts`,
  `bedrock:ListAutomatedReasoningPolicies`, `sagemaker:ListPipelineExecutions`)
  remain on `Resource: "*"` so their checks are not silently denied.
  IAM service-last-access job creation is limited to roles and users in the
  assessed account using partition-aware principal ARNs, and AgentCore metric
  publication is constrained to the `AIMLSecurity/AgentCore` CloudWatch
  namespace.
- Standardized all AWS SDK dependencies on exact `boto3==1.43.85` and
  `botocore==1.43.85` pins.
- Narrowed `AC-02` wildcard findings and `AC-03` stale-access discovery to the
  `bedrock-agentcore` IAM namespace. Overly permissive `agent-registry` grants
  are now reported by `AR-01` and `AR-02`.
- Added end-user guidance for determining whether an upgrade requires only a
  CodeBuild run, a top-level infrastructure stack update, or a multi-account
  member-role StackSet update.
- Clarified that the provided deployment is validated and supported only in
  the standard AWS commercial partition. The README, developer guide,
  troubleshooting guidance, and `TargetRegions` parameter descriptions now
  state that partition-aware implementation details do not establish support
  for AWS GovCloud (US) or AWS China.
- Updated the screenshot capture tool to enforce the repository-root `.venv`,
  install its optional Python dependencies when missing, and verify a
  venv-local Playwright Chromium browser before capturing screenshots. Capture
  height now expands dynamically so every left-navigation section is visible.
- Removed the `all` value from the `TargetRegions` parameter. Scans now target
  either the deployment region (default, empty value) or an explicit comma- or
  space-separated region list; the `all` fan-out is no longer accepted because
  it could produce very long assessment runs and oversized HTML reports. The
  runtime region parsers, the `AllowedPattern` in all four SAM and deployment
  templates, the `buildspec.yml` validation gate, and the README and
  troubleshooting guidance are updated to match.

### Fixed

- Classify Bedrock access-denied results and AgentCore check execution errors
  as incomplete informational `N/A` findings instead of security failures.
  AgentCore now records unexpected errors under each affected `AC-*` or
  `AG-*` control ID, preserves valid findings collected before an error, and
  does not emit a compliant pass when a cached IAM policy cannot be parsed.
  Confirmed workload misconfigurations remain scored failures.
- Treat a missing, unreadable, or malformed IAM permissions cache as an
  incomplete assessment prerequisite instead of replacing it with empty role
  and user collections. Bedrock, SageMaker, AgentCore, and Responsible AI GRC
  cache-dependent controls now emit explicit informational `N/A` rows rather
  than false passes or ambiguous “no permissions” results, while independent
  service checks continue running.
- Correct IAM remediation guidance across Bedrock, AgentCore, Responsible AI
  GRC, and derived OWASP findings. Bedrock model allowlists now use valid
  model and inference-profile ARN scoping instead of the nonexistent
  `bedrock:ModelId` condition key; BR-15 lists every Organizations permission
  it calls; AC-09 documents the exact service-linked-role creation permission
  and condition; AC-11 lists the complete KMS permissions and constraints for
  policy-engine encryption; and FS-27 directs operators to redeploy the
  SAM-created Lambda execution role through CodeBuild instead of changing the
  multi-account member role. Agent Registry stale-access errors no longer
  recommend granting `sts:GetCallerIdentity`, which requires no IAM Allow.
- Correct Bedrock Agents, Flows, Knowledge Bases, and Prompt Management
  remediation guidance to use the valid `bedrock:` IAM namespace instead of
  the `bedrock-agent` boto3 client name.
- Flag wildcard-resource `bedrock:TagResource` and `bedrock:UntagResource`
  grants in FS-22 when reviewing Bedrock Knowledge Base IAM policies.
- Recover assessment deployment stacks in `ROLLBACK_COMPLETE` or
  `DELETE_FAILED` before rerunning SAM deployment. The build now performs this
  recovery for member-account, multi-account management, and single-account
  paths, using narrowly scoped `cloudformation:DeleteStack` permissions for
  assessment and SAM-managed stacks.
- Fail multi-account CodeBuild runs when any expected account cannot deploy,
  start or complete its Step Functions execution, expose its assessment
  bucket, or produce and upload the current execution's required CSV and HTML
  artifacts. The separately launched management-account assessment is always
  included in the expected set, including when `MultiAccountListOverride`
  contains only member accounts. Healthy accounts still complete and upload
  their individual results, but a consolidated report is withheld when
  coverage is incomplete, and the build prints every affected account, stage,
  and reason before exiting unsuccessfully.
- Fail report generation when HTML rendering or S3 upload raises an exception,
  so Step Functions and CodeBuild cannot treat an uploaded error page as a
  successful assessment report. Before rendering, the report Lambda also
  requires a non-empty execution-scoped CSV from every regional service in
  every resolved target region, plus the one-time Responsible AI GRC artifact
  whenever that assessment or OWASP is enabled. The execution-scoped IAM
  permissions cache is still removed on both successful and failed
  report-generation attempts.
- Stop OWASP inventory pagination when an AWS API repeats a continuation token,
  preventing OW-11 or OW-12 from looping until the Lambda timeout.
- Restore `bedrock-agentcore:GetTokenVault` on `Resource: "*"` for AC-14.
  Although the service reference documents a token-vault resource type, the
  runtime authorization request is evaluated against `"*"`. The scoped policy
  therefore returned access denied and silently changed a failed token-vault
  customer-managed-KMS check into informational `N/A`; the Agentic AI and
  OWASP findings derived from AC-14 now receive the real result again.
- Restore CodeBuild and cross-account member-role access to start and poll the
  SAM-generated `AIMLAssessmentStateMachine-*` state machines. The
  least-privilege policies now explicitly include the generated state-machine
  and execution ARN patterns without widening access to unrelated workflows.
- Restore `lambda:ListFunctions` to the Bedrock assessment Lambda role so
  BR-33 can inventory Bedrock-related Lambda functions before checking Amazon
  Inspector code-scanning status, instead of reporting an access-denied
  assessment as informational `N/A`.
- Permit the AgentCore service-linked-role check to return the intended missing
  role finding by authorizing `iam:GetRole` for both the root-path lookup ARN
  and the service-linked-role ARN.
- Keep Bedrock, SageMaker, AgentCore, and Agent Registry stale-access checks
  running when an incomplete or malformed STS caller ARN is returned by
  falling back safely to the standard AWS partition.
- Prevented `FS-22` from flagging assessment-created roles solely for Bedrock
  inventory APIs that AWS requires to use `Resource: "*"`. It still flags
  wildcard Bedrock actions and exact Bedrock actions with supported resource
  scoping that remain unscoped. Corrected the FS-22 action catalog so
  non-scopable query actions do not create false positives and actions with
  supported Bedrock resource scoping—including data-source, association,
  resource-policy, tag, and log-delivery actions—remain covered; remediation
  now identifies the supported resource ARN(s)
  instead of incorrectly prescribing a Knowledge Base ARN for every action.
- Calculate report pass rates from unique direct-service controls instead of
  resource-row counts: any failed assessable row fails its `Check_ID`, controls
  pass only when all assessable rows pass, and N/A rows are excluded.
- Stop `AC-03` IAM last-access polling before the Lambda timeout, preserve
  completed results with an explicit incomplete-assessment row, and classify
  IAM job timeouts as indeterminate instead of failed controls.
- Require `AC-03` candidate permissions to come from attached or inline policy
  documents instead of inferring access from attached-policy names.
- Evaluate attached customer-managed IAM policy documents as well as inline
  policies in `AC-02` and `AC-03`, and score `Allow`/`NotAction` allow-except
  policies only when their exclusions name the AgentCore namespace without
  fully covering it, so an administrator-style grant is treated the same
  whether it is written as `Action: "*"` or as `NotAction`.
- Preserve case-insensitive IAM wildcard matching while supporting embedded and
  partial wildcard action patterns.
- Report AgentCore as unavailable in regions the account has not enabled. A
  missing regional endpoint and the credential-shaped codes AWS returns for a
  disabled region (`UnrecognizedClientException`, `InvalidClientTokenId`,
  `AuthFailure`) are classified as regional unavailability, so scanning all
  partition regions no longer produces per-region rows advising operators to
  troubleshoot DNS, VPC routing, or credentials. Genuinely expired or malformed
  credentials (`ExpiredToken`, `SignatureDoesNotMatch`) and other API failures
  remain incomplete assessments with credential- or error-specific
  remediation.
- Backfill deadline-skipped AgentCore and Agentic AI checks before writing the
  regional CSV so an approaching timeout no longer drops controls from the
  report.
- Make screenshot capture failures, including clipped-sidebar guard failures,
  terminate the capture tool with a non-zero exit status.

### Deployment impact

Apply these updates in order.

1. **Multi-account member-role StackSet update required first** because
   `deployment/1-aiml-security-member-roles.yaml` changed. It creates the
   member-role customer-managed deployment policy and narrows
   `AIMLSecurityMemberRole` to deployment, execution-polling, and
   report-retrieval operations, including narrowly scoped recovery of failed
   assessment or SAM-managed stacks; assessment service API permissions remain
   on SAM Lambda execution roles.
2. **Multi-account central infrastructure update required next** because
   `deployment/2-aiml-security-codebuild.yaml` changed with the AWS Agent
   Registry baselines, least-privilege CodeBuild deployment policy, and
   narrowly scoped failed-stack recovery. This update also removes the obsolete
   conditional local member-role resource if an older stack still tracks it.
3. **Single-account infrastructure update required** because
   `deployment/aiml-security-single-account.yaml` changed with the same
   baselines, CodeBuild policy hardening, and failed-stack recovery. This
   update also removes the obsolete local member-role resource if an older
   stack still tracks it.
4. **CodeBuild run required last** to deploy the updated assessment code,
   dependencies, `buildspec.yml`, and AWS SAM templates
   (`aiml-security-assessment/template.yaml` and
   `aiml-security-assessment/template-multi-account.yaml`). The updated
   buildspec also makes incomplete multi-account coverage fail the run instead
   of publishing an apparently complete consolidated report, and report
   rendering or upload failures now fail the Step Functions execution. The SAM
   templates create the standalone AWS Agent Registry assessment Lambda and
   update the state machine.

The template and CodeBuild updates above also tighten the `TargetRegions`
`AllowedPattern` to reject `all`. Any stored parameter value, saved stack
input, or automation that passes `TargetRegions=all` must be changed to an
empty value or an explicit region list before the next deployment or CodeBuild
run, or CloudFormation/buildspec validation will fail.

Deployments pinned to a tag or commit must update the `GitHubBranch`
CloudFormation parameter to the revision containing these changes before
starting CodeBuild.

## 1.0.0 - 2026-07-10

- Initial tagged release.
