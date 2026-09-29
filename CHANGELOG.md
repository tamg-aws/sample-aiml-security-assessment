# Changelog

All notable user-facing and deployable changes to this project are documented
in this file.

Changes are accumulated under **Unreleased** as they are merged. Creating a
release is not required for every change. When a version is tagged, move its
entries into a dated version section and create a new empty **Unreleased**
section.

## Unreleased

### Added

- Added `AC-53` Inter-Agent Anomaly Alarms, growing the catalog from 276 to
  277 checks (162 core). It covers AISF `AIR-FND-DET-10`, which the ledger
  had marked `not_implementable`. Application Signals publishes an `Error`,
  `Fault` and `Latency` metric per caller and callee, so `ListMetrics` on the
  `ApplicationSignals` namespace names each pair where an AgentCore runtime
  or gateway calls another one. Each pair fails without a metric alarm that
  has actions and whose threshold is an `ANOMALY_DETECTION_BAND` over one of
  those metrics, with the pair's `Service` and `RemoteService` whatever other
  dimensions it carries. A caller whose `RemoteService` is
  `UnknownRemoteService` is named in an `N/A` row, never `Passed`, because the
  callee may be an agent. A gateway's call to its policy engine is not a pair. With no
  pair the row is `N/A` and says runtimes not instrumented with Application
  Signals cannot be assessed. Every row names what no API records: workflow
  run frequency, per-workflow metric definitions, and alerting on a new pair.
  The check uses the role's existing `cloudwatch:ListMetrics` and
  `cloudwatch:DescribeAlarms` grants.
- Added `SM-43` Model Artifact Integrity, growing the catalog from 275 to 276
  checks (161 core). It covers AISF `AIR-SLF-CMP-08`, which the ledger had
  marked `not_implementable`, over the containers every InService endpoint
  serves, including model package and inference component containers. An
  image passes when it is pinned by digest or by a tag its ECR repository
  holds immutable, read through the repository's exclusion filters. When a
  managed signing rule of the registry covers the repository, the image also
  needs a `COMPLETE` signing status, read by the digest the endpoint resolved
  the image to. S3 model data passes when an `ETag`, `ManifestEtag` or
  `ModelDataETag` is recorded, or when it comes from SageMaker hub content; a
  bare `ModelDataUrl` fails, and so does an `HF_MODEL_ID` environment key
  with no model data. Only environment keys are read. Each artifact bucket
  needs SSE-KMS under a named key. A denied read leaves the endpoint `N/A`
  naming the permission. The row says an expected value is recorded, never
  that it was compared at load time, and names weights fetched by startup
  code, and models loaded on ECS, EKS or EC2, as not read.
- Added `SM-42` Batch Transform Creation Guardrail, growing the catalog from
  274 to 275 checks (160 core). It runs the `SM-34` legs over `CreateModel`
  and `CreateTransformJob` only, so AISF `AIR-SGM-EP-08` can cite a verdict
  that a training or notebook gap does not fail. It runs in each scanned
  Region, so its rows join the `SM-18` transform job rows on account and
  Region.
- `SM-34`, `SM-42` and `SM-09` give no credit to a negated condition operator
  on `sagemaker:VpcSubnets` or `sagemaker:VpcSecurityGroupIds` with no
  `ForAllValues` or `ForAnyValue` prefix, or to an Allow on either key with no
  set operator. IAM defines a multivalued key only under a set operator, and
  the row names the operator as undefined.
- Added `BR-57` Agent Handoff Source Identity, growing the catalog from 273
  to 274 checks (159 core). It covers AISF `AIR-SLF-AGT-05`, which the ledger
  had marked `not_implementable`. It fails a Bedrock collaborator that runs as
  its supervisor's own role, and a role trust statement that an agent role can
  use to call `sts:AssumeRole` without an `sts:SourceIdentity` condition naming
  exact values. The agent roles are the Bedrock agent roles of every routed
  version and the AgentCore runtime roles. ECS task and Lambda execution roles
  are not marked as agents by any AWS API and are not judged. The Bedrock
  assessment role gains `bedrock:ListAgentCollaborators` on the account's
  agents and `bedrock-agentcore:GetAgentRuntime` on its runtimes, both
  read-only. Runtimes are listed with `bedrock-agentcore:ListAgentRuntimes`
  and `bedrock-agentcore:ListAgentRuntimeEndpoints` on `*`, and a failed list
  reports `N/A` naming the action.
- Added an **AWS AI Security Framework (AISF)** section to the HTML report,
  alongside OWASP Top 10 for LLM under "By Compliance Standard". It reports 8
  of the 105 in-scope AISF controls as `AISF-01` through `AISF-08`. Behavior
  worth knowing:
  - The section is always on. It needs no deployment parameter, runs no
    additional AWS API calls, and adds no scan time, because each row restates
    the verdict of a check that already ran under an AISF control id.
  - `AISF-` rows are excluded from the 274-check catalog total, from the report
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
- The AISF parity ledger now reports 100 of the 105 in-scope AISF controls as
  `covered` and 5 as `not_implementable`, with none left `tighten` or `new`.
  The 19 foundation controls that waited on those checks and legs are
  `covered`, and the new check ids carry their AISF control in the
  `Compliance_Frameworks` column.
- `AIR-SGM-EP-03` moves from `not_implementable` to `covered` by `SM-11` and
  `SM-14`, bringing the ledger to 101 `covered` and 4 `not_implementable`.
  Its one unread field, inter-container traffic encryption, is named in the
  ledger gap: `EnableInterContainerTrafficEncryption` is on the training,
  processing and tuning job APIs and on no endpoint API. Seven checks that
  already asserted part of a covered control now carry it in the
  `Compliance_Frameworks` column: `SM-23` on `AIR-SGM-EP-06`, `SM-34` on
  `AIR-SGM-TRN-01`, `AC-48` on `AIR-ACR-RT-03`, `AC-49` on `AIR-ACR-RT-08`,
  `AG-39` on `AIR-FND-NET-08`, `AC-18` on `AIR-ACR-GW-10` and `AC-19` on
  `AIR-ACR-MEM-12`. No check logic or IAM grant changes.
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

- `SM-35` security service delegated administrator passes a service only
  when its principal also has trusted access in the organization, read with
  `organizations:ListAWSServiceAccessForOrganization` (newly granted to the
  SageMaker function on `*`, because the action has no resource type). A
  registered non-management administrator whose service principal lacks
  trusted access fails, and an unread trusted-access list makes each such
  service `N/A`. Trusted access used to go unread.

- `SM-41` AWS IoT device-scoped policy adds an `AWS IoT Role Alias Device
  Scope` row. It lists and describes each credentials-provider role alias
  (`iot:ListRoleAliases` on `*`, which has no resource type, and
  `iot:DescribeRoleAlias` on `rolealias/*`, both newly granted to the
  SageMaker function) and fails an alias whose IAM role, read from the
  permissions cache, names no `credentials-iot:` policy variable in the
  `Resource` or `Condition` of any Allow statement. The role a device assumes
  through the credentials provider used to go unread.

- `SM-26` GuardDuty AI Protection adds a `GuardDuty AI Protection
  Organization Auto-Enable` row for an `ENABLED` detector. It reads
  `guardduty:DescribeOrganizationConfiguration` (newly granted to the
  SageMaker function on `*`, because the action has no resource type) and
  passes only when `AutoEnableOrganizationMembers` and the `AI_PROTECTION`
  feature's `AutoEnable` are both `ALL`. Outside the GuardDuty delegated
  administrator the read fails and the row is `N/A`. Whether AI Protection
  reached every member account used to go unread.

- `SM-38` runtime monitoring coverage compares every running EC2 instance
  (`ec2:DescribeInstances`, newly granted to the SageMaker function on `*`
  because the action has no resource type) with the EC2 instances in
  GuardDuty coverage, and fails an instance that is absent. An instance
  tagged `eks:cluster-name` or `kubernetes.io/cluster/*` is left to its
  cluster's covered-node count, and a Windows instance is not compared; both
  counts are stated. An instance list that could not be read gives `N/A`. An
  unenrolled standalone instance used to go uncounted.

- `SM-38` runtime monitoring coverage adds a `GuardDuty EKS Audit Log
  Monitoring` row in each Region that has an EKS cluster. It passes only when
  the detector is `ENABLED` with its `EKS_AUDIT_LOGS` feature `ENABLED`, and
  it is judged whether or not Runtime Monitoring is on. The feature used to go
  unread. A Region whose EKS clusters could not be listed gets an `N/A` row.

- `SM-09` execution role privilege also judges each Studio domain's
  `DefaultSpaceSettings.ExecutionRole`, the default execution role for spaces,
  beside the domain's default user role and each user profile's role. A
  broad grant on the space role used to go unread.

- `SM-22` deployed model registration also judges the model each batch
  transform job ran, read from `DescribeTransformJob`, beside the models
  serving on endpoints. An unregistered or unapproved model used only by a
  transform job used to go unread, and the row said so. A transform job that
  could not be listed or described now leaves the row `N/A`, and an account
  with transform jobs but no endpoint now gets the row.

- `SM-23` model drift detection adds a `Model Monitor Baseline Constraints`
  row. Each Scheduled monitoring schedule on an InService endpoint must name a
  baseline `ConstraintsResource`, read from its inline job definition or from
  the named job definition's describe for its monitoring type
  (`DescribeDataQualityJobDefinition`, `DescribeModelQualityJobDefinition`,
  `DescribeModelBiasJobDefinition` or
  `DescribeModelExplainabilityJobDefinition`). A schedule with no constraints
  file fails, because its reports have nothing to be validated against. A job
  definition that could not be described is `N/A` naming the describe, and so
  is one that names a baselining job but no constraints file.

- `SM-23` `Model Monitor Violation Alarm` passed row now says that which
  Model Monitor metric each alarm evaluates, and whether its threshold marks
  drift for the model, are not judged. The row used to read as a drift
  verdict when the check credits any enabled alarm with an action on the
  schedule's metrics.

- `SM-11` endpoint model network path also judges the model each inference
  component names, from `Specification` and every `Specifications` entry,
  beside the endpoint config's own `EnableNetworkIsolation` and
  `VpcConfig`. A component model with isolation off or no `VpcConfig` used
  to pass behind a compliant endpoint config, and a component that could not
  be listed or described now leaves its endpoint `N/A`.

- `AR-10` credited a rule filtered on `region`, `time`, `id` or any other
  top-level field beyond `source`, `detail-type`, `detail`, `resources` and
  `account` as routing every approval transition. Every such field now
  narrows the rule, which is reported `N/A` and not credited. An `account` or
  `region` filter that matches the rule's own account or Region, read from
  the rule ARN, no longer narrows, because every Registry event the check
  judges carries those values.

- `SM-35` security service delegated administrator also reads
  `config-multiaccountsetup.amazonaws.com`, the principal AWS Config rules
  and conformance packs are delegated through, beside
  `config.amazonaws.com`. A Config rules administrator left on the
  management account, or on a second account, used to go unread, so the
  consolidation row could pass.

- `SM-37` endpoint network alerting no longer passes on an alarm that can
  never fire. An alarm is credited only when it reads the dimension names
  and unit its metric filter publishes, and, when the filter publishes
  literal values, only when its static threshold can be crossed: a
  `LessThanThreshold 0` alarm on a count, or a `Maximum` above the largest
  value the filter publishes, is named as unable to fire. A space-delimited
  (bracketed) pattern whose field equality names a value no flow-log record
  carries, such as `action="DENY"`, now counts as matching no record.

- `SM-04` credits an EventBridge rule on `aws.guardduty` only when its
  pattern sets no `detail-type` or lists `GuardDuty Finding`. A rule on
  another detail-type, such as `AWS API Call via CloudTrail`, used to pass
  as routing findings to alerting.

- `SM-09` no longer credits an `aws:SourceIp` condition on the presigned
  notebook and domain URL actions when its ranges together cover every IPv4
  or every IPv6 address, such as `0.0.0.0/0` or `::/0`. A `NotIpAddress`
  `Deny` on such values fires only when the key is absent, and an
  `IpAddress` `Allow` on them admits any caller.

- `SM-39` workload segmentation fails a rule that references the VPC's
  default security group. A CIDR of /16 (IPv6 /48) or wider still fails. A
  CIDR narrower than that and wider than a /24 (IPv6 /64) used to pass; it
  now withholds `Passed` in a `CIDR Width Not Judged` `N/A` row that names
  both bounds, because AIR-SLF-RT-05 asks for security group references in
  place of broad CIDR allowances and names no width. A rule that
  references a group that was not read also withholds `Passed` in an `N/A`
  row. A rule that names a customer-managed prefix list is judged on each
  of the list's entries with the same bounds, labelled with the list, so a
  list holding `0.0.0.0/0` fails the workload that uses it. A rule that
  names an AWS-managed prefix list, one AWS service's published ranges such
  as the S3 list's /15 and /16 entries, is credited without a width
  judgment. A prefix list whose owner or entries were not read withholds
  `Passed` in an `N/A` row naming the list, the groups whose rules name it
  and the failed action.

- `SM-40` fails a secret whose rotation schedule allows a gap longer than 90
  days, the default of Security Hub control `SecretsManager.4`, so
  `rate(365 days)` no longer passes. An ECS service that injects a rotating
  secret and relies on an EventBridge rotation rule with a target is now
  `N/A` naming the rule, where it passed without reading what the target
  runs.

- `SM-43` resolves an artifact bucket's default `KMSMasterKeyID` with
  `kms:DescribeKey` and fails a bucket whose key is AWS managed, such as
  `alias/aws/s3` named explicitly, which used to pass as a named key. A key
  the call cannot describe leaves the endpoint `N/A`.

- `SM-41` requires `${iot:Connection.Thing.ThingName}` to fill a whole path
  segment of a device policy resource. `topic/*${iot:Connection.Thing.ThingName}`
  and `topic/x-${iot:Connection.Thing.ThingName}` used to pass, and they reach
  the topics of every thing whose name ends with the device's own. A device
  policy attached to a thing group now makes the unique-certificate row
  `N/A` and names the group, where the check read only certificates that a
  policy is attached to directly and could pass without the group's.

- `SM-23` reports a Region with no InService endpoint as `N/A`, where it used
  to pass with no endpoint to judge.

- `SM-14` names a model whose `DescribeModel` call failed, or a failed
  `ListModels`, in an `N/A` Incomplete row and withholds `Passed`. Such a
  model used to be logged and dropped, so the rest could pass, and a failed
  list read as no models found.

- `SM-03` reads the `KeyState` that `kms:DescribeKey` returns beside
  `KeyManager`. A notebook, domain, training job output or volume, training
  file system, or training data bucket whose customer managed key has a
  state other than `Enabled`, for example `PendingDeletion` or `Disabled`,
  now fails in a `Customer Managed Key Not Enabled` row or its bucket row,
  where it used to pass as customer managed.

- `SM-26` reads the GuardDuty detector `Status`. A detector whose status is
  `DISABLED` now fails even when its `AI_PROTECTION` feature is `ENABLED`,
  where it used to pass, and a Region with no detector fails where it used to
  report `N/A`. Neither produces an AI Protection finding.

- `SM-02` no longer counts an `aws:ResourceTag` condition as scoping an
  endpoint invocation grant when a `Like` operator's value is made only of
  wildcards, such as `*` or `?*`, because that value matches every tag value.
  This applies to identity policies and to the `sagemaker.runtime` VPC
  endpoint policy. A `Like` value with a fixed part, such as `fraud-*`, still
  scopes the grant.

- `SM-34` and `SM-42` no longer credit an `ArnEquals` or `ArnNotEquals`
  condition whose KMS key ARN holds a `*` or `?`. Those operators match
  wildcards as `ArnLike` does, so `arn:aws:kms:*:*:key/*` admits every key.
  Such an Allow no longer guards creation, and such a Deny only requires the
  key to be present, which is how a wildcard under `ArnLike` or `ArnNotLike`
  was already read.

- `BR-10` counts a guardrail direction only from a content filter with
  strength `LOW`, `MEDIUM` or `HIGH` and action `BLOCK`, where any configured
  element used to count. An identity that names no guardrail passes when a
  central mechanism binds every invocation in the Region: an account-enforced
  configuration, the effective Organizations Bedrock policy, or an attached
  service control policy in a member account. `BR-41` reads the effective
  Bedrock policy's per-Region configurations and judges their model and
  content scope, fails `inputTags` `HONOR`, credits a service control policy
  only when its Deny covers every invoke resource type, and reports `N/A`
  where a Region relies on a guardrail share it could not read. The `BR-06`
  knowledge base row needs `textDataDeliveryEnabled`.
- `BR-26`, `BR-27` and `BR-34` judge every guardrail version that a
  `bedrock:GuardrailIdentifier` condition pins in a role, user or group policy,
  a permissions boundary, an attached service control policy or the effective
  Organizations Bedrock policy for the Region, and report `N/A` for a wildcard
  condition value, an errored principal or a version 1 IAM cache. `BR-26`
  needs `AWS_ACCESS_KEY`, `AWS_SECRET_KEY` and `PASSWORD` to block or mask on
  each side that sets an entity. `BR-32` credits an intervention alarm only
  when one intervention raises it, fails a threshold or slice-dimension alarm,
  and reports a per-version or metric-math alarm as `N/A`. The knowledge base
  rows of `BR-26` and `BR-34` no longer credit an account-enforced
  configuration that narrows its model or content scope.
- `BR-42` and `BR-43` no longer credit a model deny list that has a wildcard
  in a model or profile ID or requires a second condition key, and `BR-43`
  names each uncredited list. `BR-44` counts an unconditioned `Deny` on a
  marketplace action as removing the grant. `BR-46` reports an exclude
  condition it cannot compare as `N/A`, fails a source that an ingestion,
  customization or SageMaker training job read before its Macie job was
  created, and adds SageMaker training data buckets to the population.
- `BR-47` and `BR-52` add batch inference, SageMaker training, AgentCore
  runtime code and AgentCore browser recording buckets to the data path, and
  name each unread leg. `BR-52` no longer credits a recovery point created
  before its vault's lock date whose own lifecycle deletes it before the
  vault's minimum retention.
- The `BR-04` row `AgentCore Memory Event Retention` no longer names
  `bedrock-agentcore:GetMemory` as a missing grant. AISF `AIR-ACR-MEM-07` and
  `AIR-FND-DAT-08` set no maximum retention period, so the row reads Partial,
  ceiling reached, and assumes no threshold for `eventExpiryDuration`.
- `BR-34` fails a Region whose model invocation logging is off or does not
  deliver text, so a guardrail intervention leaves no record. `AIR-FND-DET-04`
  now also counts `SM-26`, which reads GuardDuty AI Protection.
- `BR-53` also fails SageMaker and AgentCore resources that the Resource
  Groups Tagging API returns without an owner tag, and never passes that
  population, since a resource never tagged is not returned.
- `BR-50` counts IAM users allowed only to read Bedrock, SageMaker AI or
  AgentCore, so a long-term key used for reads is no longer out of scope.
- `BR-02` fails a workload whose role is granted AgentCore when its VPC has
  no private-DNS endpoint for the AgentCore data plane, control plane or
  Gateway it calls. Bedrock endpoints no longer cover an AgentCore grant.
- `BR-33` scopes Lambda functions by the Bedrock and AgentCore grants on
  their role as well as by name, and fails a function Inspector does not
  scan: one encrypted with a customer managed key, or tagged for exclusion.
- `BR-32` now sees composite alarms. The Bedrock assessment role read
  `cloudwatch:DescribeAlarms` on the account's `alarm:*` ARNs, and
  DescribeAlarms returns no composite alarm to a grant narrower than `*`, so a
  runtime or guardrail alarm reached only through an acting composite alarm
  was reported as reaching no action. The grant is now on `*`.
- `BR-06` lists the Region's CloudTrail Lake event data stores and reads
  each one with `cloudtrail:GetEventDataStore`. An `ENABLED` store's advanced
  selectors are judged as a trail's are, and can credit the management row
  and each data-event row. A store that could not be read turns a gap into
  `N/A` naming the action; a gap that no read store closes stays `Failed`.
- `BR-51` no longer passes an account whose IAM Identity Center instance it
  cannot judge. The `Passed` row becomes `N/A` when `sso:ListInstances` in the
  primary scan Region returns an instance, or cannot be read.
- `BR-53` fails an AgentCore agent runtime that `ListAgentRuntimes` lists and
  `GetResources` does not return, since such a runtime was never tagged.
- `BR-53` compares `GetResources` with SageMaker endpoints, models and
  notebook instances, and AgentCore memories, gateways and custom browsers,
  as well as agent runtimes, and fails each listed resource it did not return
  as never tagged. The summary row names the resource types still listed only
  by `GetResources` and cites its API reference.
- `BR-33` reads per-function Inspector coverage (`inspector2:ListCoverage`)
  and fails a zip function whose `$LATEST` `PACKAGE` or `CODE` record is
  missing or not `ACTIVE`, naming the reason; it used to pass on account
  status alone. The rows name each enabled EventBridge rule on the default bus
  that matches Inspector findings. An unread coverage list makes the `Passed`
  row `N/A`.
- `BR-02` reads ECS services and SageMaker notebook instances alongside
  Lambda functions, and its EC2 leg now runs. A notebook instance with no
  subnet fails as outside a VPC, and an ECS service with no `awsvpc` subnets
  is named as not read.
- `BR-51` names the IAM Identity Center permission sets whose inline policy
  grants an AI write. The row stays `N/A` with its ceiling. Each such
  permission set fails in its own row unless the same inline policy carries a
  `Deny` over every AI service it grants, keyed on one `aws:PrincipalTag`
  value under a negated string operator.
- `BR-02` names an ECS service that `ecs:DescribeServices` returns in its
  `failures` list as not read, and never reads a service's `roleArn` as its
  task role.
- `BR-33` names, on the `Failed` row for disabled Lambda code scanning, each
  in-scope function without `ACTIVE` coverage in `inspector2:ListCoverage`,
  with its reason, such as `SCAN_ELIGIBILITY_EXPIRED`.
- `BR-52` names `backup:ListRecoveryPointsByResource` or
  `backup:DescribeRecoveryPoint` as not granted, "Partial, ceiling reached",
  when the read is denied.
- `BR-20` reads OpenSearch Serverless collections with
  `aoss:BatchGetCollection`, now granted, and names the action when the read
  fails. It also reads every data access policy and fails a knowledge base when
  an index rule reaching its index has a wildcard in the collection segment,
  or a wildcard principal, because OpenSearch Serverless
  does not check a caller's permission on the collection's KMS key. An unread
  policy is `N/A`.
- Bedrock checks judge values that they used to credit on presence. `BR-07`,
  `BR-17`, `BR-20` (S3 Vectors), `BR-30` and `BR-38` describe each named KMS
  key and pass only an enabled customer managed key. `BR-07` also fails inline
  flow prompt nodes, runs its flow leg with no prompt in the Region, and adds
  `Bedrock Prompt Change Permission Scope` for wildcard `bedrock:UpdatePrompt`
  and `bedrock:CreatePromptVersion` grants. `BR-12` fails a log bucket with
  no default encryption where it used to report `N/A`. `BR-04` fails Object
  Lock beside a lifecycle rule, reports a replicated log bucket and AgentCore
  Memory retention as `N/A` naming the reads the role lacks, and its logging
  row no longer calls the configuration proper. `BR-55` needs an image pin
  (`ImageSha384`, `PCR0` or `PCR8`) and a deployment pin (`PCR3` or `PCR4`),
  so a `PCR3`-only pin fails. `BR-43` covers agent, flow,
  RetrieveAndGenerate and AgentCore runtime invocation, rejects wildcard
  `aws:PrincipalArn` exemptions and every-Region patterns such as `*-*`, and
  reports `N/A` when an inference profile listing failed. `BR-45` needs both
  the age cap and the `LONG_TERM` bearer token Deny, and reads the age cap
  from identity policies when no SCP carries it. `BR-48` compares `optOut`
  exactly and no longer says the policy covers Amazon Bedrock. `BR-02`
  credits an endpoint policy scope only on exact values under one condition.
- `AC-36`, `AC-40`, `AC-45`, `AC-46` and `AC-53` credit a metric alarm that
  notifies only through a composite alarm. Each failed such an alarm, because
  it read `MetricAlarms` alone and required the alarm's own actions. The
  checks now page `DescribeAlarms` with `AlarmTypes` `MetricAlarm` and
  `CompositeAlarm`, and credit a metric alarm when a composite alarm with
  enabled, non-empty actions joins it with `OR`-only `ALARM(...)` terms,
  directly or through a nested composite. A composite with `ActionsEnabled`
  false credits nothing, and each row names the composite that carries the
  action. The AgentCore role's `cloudwatch:DescribeAlarms` grant moves from
  `alarm:*` to `'*'`, because `API_DescribeAlarms` returns composite alarms
  only to a `'*'`-scoped grant.
- `AC-01` reads every runtime version `ListAgentRuntimeVersions` returns, not
  only the latest one, and fails a runtime created before the 2026-05-05
  rollout that does not report `requireServiceS3Endpoint`, since an unset
  field keeps the service-managed Amazon S3 gateway. A runtime that
  `GetAgentRuntime` cannot find is now `N/A` by name; it was dropped, and the
  `Passed` row reported all runtimes without it. A denied `bedrock-agentcore:ListAgentRuntimeVersions` read makes each runtime `N/A` naming that action.
- `AC-19` reads the region's X-Ray trace segment destination when AgentCore
  runtimes, gateways or memories exist, and fails `XRay`, because AgentCore
  tracing needs CloudWatch Transaction Search, which sends segments to
  CloudWatch Logs. The report said the setting was not read. The AgentCore
  assessment role gains `xray:GetTraceSegmentDestination`, and a denied read
  is `N/A` naming that action.
- `AC-20` judges a log group outside the AgentCore prefixes that an AgentCore
  delivery writes to. A delivery to such a group escaped the check. The
  AgentCore assessment role gains `logs:DescribeDeliveryDestinations`. When it
  is denied, the check reports an `N/A` row naming it and judges the prefixed
  groups only.
- `AC-22` reads the links an account with no sink shares telemetry through,
  and fails a link that omits log groups, traces or metrics. The check said
  source-account links were not read. The AgentCore assessment role gains
  `oam:ListLinks` and `organizations:DescribeOrganization`, and a denied read
  is `N/A` naming the action.
- `AC-46` judges runtime spend on a new `AgentCore Runtime Cost Anomaly
  Alerting` row: the account needs a Cost Anomaly Detection subscription that
  notifies someone about a monitor for every AWS service. The check reported
  that no cost limit could be read. The AgentCore assessment role gains
  `ce:GetAnomalySubscriptions`. A denied `ce:GetAnomalyMonitors` read makes the row `N/A` naming that action.
- `AC-06` reads the recording account's Block Public Access settings when the
  recording bucket leaves one off, and fails a setting off on both. Such a
  bucket was `N/A`. The AgentCore assessment role gains
  `s3:GetAccountPublicAccessBlock`, and a denied read stays `N/A` naming that
  action.
- `AC-30` judges the inbound authorizer of every version a runtime endpoint
  serves, not only the default version, which let an endpoint route callers
  to a version with an unbounded JWT authorizer while the runtime passed. The
  AgentCore assessment role gains `bedrock-agentcore:ListAgentRuntimeEndpoints`;
  when it is denied, a runtime that would pass is `N/A` naming it.
- `AC-17` requires the log group of every endpoint a runtime serves to be
  read by a running online evaluation, which let a configuration over
  `<runtimeId>-DEFAULT` pass a runtime whose `prod` endpoint was unscored. A
  service name scoped to one endpoint (`agent.DEFAULT`) no longer covers the
  others. When `bedrock-agentcore:ListAgentRuntimeEndpoints` is denied, a
  runtime that would pass is `N/A` naming it.
- `AC-44` fails a bounded model pattern on an evaluation execution role that
  reaches no model the role's custom evaluators call, as `GetEvaluator`
  reports it. `AC-41` gains rows for the key of each custom evaluator and
  batch evaluation, credited only by `DescribeKey`, and judges each batch
  evaluation's results log group. The AgentCore assessment role gains
  `bedrock-agentcore:GetEvaluator`, `ListBatchEvaluations` and
  `GetBatchEvaluation`, and a denied leg is `N/A` naming the action.
- `AC-40` counts a score alarm only when `cloudwatch:ListMetrics` lists the
  metric it reads, by name and dimension set, in the configuration's
  namespace. An alarm on a misspelled metric name, or on a dimension set the
  service does not publish, passed on its namespace alone and never fires.
  The AgentCore assessment role gains `cloudwatch:ListMetrics`; when it is
  denied, a configuration that would pass is `N/A` naming it.
- `AC-49` gains a Network Firewall leg that follows each hosting subnet's
  default route to a firewall endpoint, one hop or through a NAT gateway,
  and judges the reached policy for a domain allow-list over `TLS_SNI` and
  `HTTP_HOST` and for AWS managed threat signature and domain reputation
  groups. DNS Firewall alone passed a VPC whose agents could connect to any
  address. The AgentCore assessment role gains
  `network-firewall:ListFirewalls`, `DescribeFirewall` and `DescribeRuleGroup`.
  A denied `network-firewall:DescribeFirewallPolicy` or `ec2:DescribeNatGateways` read makes the rows `N/A` naming the action.
- `AC-50` reads Inspector coverage per AgentCore repository and requires an
  EventBridge rule with a target that matches Inspector findings on ECR
  images. A registry scanning rule passed while Inspector reported the
  repository `INACTIVE`, and no finding had to reach a deploy stage. The
  AgentCore assessment role gains `inspector2:ListCoverage` and
  `events:ListRules`. A denied `events:ListTargetsByRule` read makes the gate row `N/A` naming that action.
- `AC-45` judges each AgentCore runtime's own execution role by the rules it
  applies to a tool role. No check read a runtime role outside the AgentCore
  namespace, so one granting `s3:*` or every foundation model passed.
- `AC-51` requires a rate-based rule whose action is `Block` beside the
  Anti-DDoS managed rule group, and keeps the gateways it judged when a
  gateway or web ACL read fails below the API. A web ACL with the group and no
  per-caller rate cap passed, and a transport error on one gateway discarded
  every gateway's finding.
- `AC-26` requires the log tamper SCP to deny `logs:DeleteLogStream` on each
  group's `:log-stream:*` ARN, and to reach the Bedrock model invocation log
  group, reporting `N/A` naming `bedrock:GetModelInvocationLoggingConfiguration`
  when that configuration cannot be read. It also holds the
  `/aws/vendedlogs/bedrock-agentcore/` groups to deletion protection. The SCP
  leg passed with streams deletable and the invocation log group unguarded,
  and the vended-log groups were never judged for deletion protection.
- `AC-47` credits a runtime network or caller `Deny` only when it reaches all
  six runtime invoke actions, and names the ones it misses. A `Deny` on
  `InvokeAgentRuntime` alone passed, leaving the command shell, command,
  WebSocket and per-user paths open. The network `Deny` of `AC-47` and
  `AC-27` now accepts `Bool` `aws:ViaAWSService` `false`, the
  form AISF `AIR-ACR-RT-13` gives, which failed as an ANDed key.
- `AC-01` egress and `AC-08` endpoint inbound scope read the entries of each
  prefix list a security group rule names, so a prefix list holding
  `0.0.0.0/0` or the VPC CIDR fails, and an unread prefix list reports
  `N/A` naming `ec2:GetManagedPrefixListEntries`. Both legs passed a rule
  that named a prefix list on its IP ranges alone.
- `AC-45` fails the runtime command shell leg when a principal can open a
  shell and no metric filter counting shell connections feeds an alarm with
  an action, and reports `N/A` naming `logs:DescribeMetricFilters` or
  `cloudwatch:DescribeAlarms` when either read fails. The shell leg passed
  on the grant alone, although the service never logs what a shell runs.
- `AC-37` credits the gateway role's `bedrock:InvokeGuardrailChecks` grant only
  on `Resource: "*"` with no condition, since the action has no resource
  type, and fails a guardrail comparison that drops the score equal to the
  safeguard's documented default, such as `greaterThan(decimal("0.2"))` on a
  content filter. It previously matched the grant by action alone.
- `AC-36` requires the policy engine's encryption context on the key policy's
  `kms:CreateGrant`, `kms:Decrypt` and `kms:GenerateDataKey` statements, fails
  a statement scoped to AgentCore that grants any action beyond the four the
  service needs, and reads the alarm on the key's `DisableKey` and
  `ScheduleKeyDeletion` calls through EventBridge rules or a metric filter and
  alarm. A key policy with none of these passed; without `events:ListRules` or
  `logs:DescribeMetricFilters` the alarm leg is now `N/A` and names them.
- `AC-35` no longer reads a bare `principal` as bounded because the word
  `principal` appears somewhere in the conditions. Only a `when` block that
  reads the principal outside string literals now counts: an `unless` block,
  a string literal such as `"principal"` and `context.principal` each passed
  before and now fail as `Caller Scope Unbounded`.
- `AC-02` and `AC-42` fail a payment manager or evaluation writer whose
  `iam:PassRole` names roles by a wildcard pattern such as `role/pay-*`. Only a
  Resource reaching every role failed, so a pattern passed as scoped to the one
  role the resource needs.
- `AC-18` inventories the account's own evaluators and requires the
  `AWS::BedrockAgentCore::Evaluator` data-event type for them. Built-in
  evaluators are not counted.
- `AC-20` requires a managed credentials identifier and a managed personal or
  health identifier among the masked ones. Any single identifier passed, and an
  account policy hid the log-group policy it is cumulative with.
- `AC-21` fails `logs:Unmask` on a wildcard after an AgentCore log group
  prefix. `/aws/bedrock-agentcore/*` reached every AgentCore group and passed
  as scoped.
- `AC-22` compares a sink's organization condition to this account's
  organization and no longer passes a statement naming other accounts. Any
  organization id and any foreign account passed.
- `AC-18` no longer reads a selector field that keeps every AgentCore event
  as narrowing. `readOnly` listing both values, and a `resources.ARN` prefix
  covering every AgentCore resource of the region, failed a type they log
  whole.
- `AC-33` ties a named workload identity to the principal's own agent. It
  passed any grant naming one identity, whichever agent owned it. A runtime
  or gateway role naming another agent's identity now fails, and a principal
  no runtime or gateway runs as is `N/A` as unattributed.
- `AC-14` reads the token vault key's policy. It passed any vault whose key
  was customer managed and enabled, whoever the key policy let decrypt. A
  policy with no statement limiting `kms:Decrypt` to AgentCore Identity and
  the vault's encryption context, or one open to every principal, now fails,
  and an unreadable key policy is `N/A` naming `kms:GetKeyPolicy`.
- `AC-12` describes each gateway's key and reads its key policy. It passed
  any gateway that named a key ARN, AWS managed or disabled keys included,
  and dropped a gateway whose `GetGateway` call failed without a trace. A key
  policy that does not bind decrypt to `kms:ViaService` and the gateway's
  encryption context now fails, and every unread leg is `N/A` by name.
- `AC-08` requires an available `bedrock-agentcore` endpoint in the VPC of
  each VPC-mode runtime, resolved from its subnets, where an endpoint in any
  VPC of the region counted before. It also requires the
  `bedrock-agentcore-control` endpoint whenever a runtime or gateway exists.
- `AC-08` fails an endpoint whose security group inbound ranges cover the
  VPC CIDR, alone or pieced together, or that open any protocol or port other
  than TCP 443. Both passed before, because only `0.0.0.0/0` and `::/0` were
  compared. An endpoint whose VPC CIDR is unknown is `N/A`.
- `AG-24` takes an `AUTHENTICATE_ONLY` gateway's verdict from `AG-25`. It
  passed whenever a policy engine was attached in `ENFORCE` mode, even when
  that engine held no enforcing policy or an unconditioned permit over every
  action, so no tool call was denied by anyone.
- `AC-27` and `AC-43` fail an execution role trust statement whose
  `aws:SourceArn` is absent or open across Regions or resource types, as
  `Source ARN Not Scoped`. A trust guarded by `aws:SourceAccount` alone, or by
  `arn:aws:bedrock-agentcore:*:<account>:*`, passed, though the service could
  assume the role for any AgentCore resource in the account. The documented
  form, a fixed Region and resource type with a wildcard resource id, passes.
- `AC-02` lists, beside each principal granted AgentCore evaluation writes
  through a wildcard pattern, the writes its patterns reach. The finding said
  every such principal could create, change and delete evaluations, though
  `bedrock-agentcore:DeleteEval*` reaches only `DeleteEvaluator` of the six.
- `AC-23` fails a memory read conditioned on a `StringLike` namespace that
  spans callers. `/users/*` read as one fixed partition and passed, though it
  matches every user's records; so did `/actors/*` and a partial wildcard
  such as `/actors/alice*`. A trailing `*` under a fixed identifier
  (`/actors/a-1/*`) and a wildcard after a policy variable still pass.
- `AC-32` no longer reads a `StringLike` issuer, audience or client id that
  holds a `*` or `?` as pinned. `https://cognito-idp.*.amazonaws.com/*`
  passed, though it admits every Cognito user pool.
- `AC-28` and `AC-29` credit a service control policy Deny only when the
  authorizer type is its sole condition key and its `Resource` reaches every
  gateway or runtime. A Deny with an ANDed `aws:PrincipalArn` exemption or tag
  test, a `NotResource`, or a `Resource` narrowed to one Region or to
  `gateway/prod-*` counted as covering both writes.
- `AC-24` counts a rate limit only when it is keyed on a dimension the caller
  cannot renew with a fresh token. A deny-list of `jti`, `iat`, `exp` and
  `nbf` passed `nonce` and any other per-token claim; an allow-list of the
  tool, model, IAM principal and stable JWT identity claims replaces it.
- `AC-45` reads a resource ARN with a partial wildcard, such as
  `arn:aws:s3:::prod-*`, as every resource, and `AC-25` and `AC-45` report a
  role from another account as `N/A`. The permission cache reads only the
  assessed account and keys roles by name, so a foreign role that shared a
  local role's name was judged by the local role's policies.
- `AC-46` fails a lifecycle field above the 28,800-second maximum lifetime
  AWS applies by default, as `Session Limit Above Default`. Only the
  1,209,600-second ceiling failed, so 1,209,599 seconds passed.
- `AC-38` requires every temporal event pattern to carry
  `eventResource: resource`. Any value passed, so a pattern counting events on
  another entity read as scoped, and only the first temporal statement of each
  policy was read.
- `SM-37` endpoint network alerting names, for each alarm a passing endpoint
  relies on, when the metric alarm last entered `ALARM`, read from its
  `StateUpdate` history with `cloudwatch:DescribeAlarmHistory`. A denied or
  empty history is named and does not change the status. A composite route
  also names when the composite alarm that carries the action last entered
  `ALARM`, read with the `CompositeAlarm` alarm type.
- `SM-03` reads the encryption of an EFS or FSx for Lustre file system a
  training job reads through `FileSystemDataSource`. An unencrypted file
  system fails, an AWS managed key or the Amazon FSx service key of a
  `SCRATCH` Lustre file system counts as not customer managed, and a
  customer managed key joins the key-manager leg. A file system that cannot
  be read, or returns no key, holds back `Passed` and is named.
- `SM-36` names what stays unread when a Security Hub configuration policy
  governs the Region: the policy's enabled standards and controls, returned
  only by `securityhub:GetConfigurationPolicy`, which only the delegated
  administrator can call from its home Region. The row names the policy id
  to confirm there.
- `SM-37` endpoint network alerting credits a metric alarm with no action of
  its own when a composite alarm with an action names it in an `ALARM()` term
  joined only by `OR`, including through a nested composite. A rule holding
  `AND`, `NOT`, `OK()`, `INSUFFICIENT_DATA()`, `TRUE` or `FALSE` credits
  nothing. Each passing endpoint names the alarm and its current
  `StateValue`. CloudWatch returns composite alarms only to
  `cloudwatch:DescribeAlarms` on `*`, so this credit takes effect once the
  grant change under Deployment impact is deployed; before that no composite
  is returned and a composite route reads as unactioned.
- `SM-43` judges every specification of an inference component created with
  several (`Specifications`), where `DescribeInferenceComponent` returns no
  `Specification`. It judges only `InService` components hosted on the
  endpoint, and a component that returns no model name, image or artifact URL
  holds back `Passed` and is named. The resolution says a component whose
  container names an S3 `ArtifactUrl` has no ETag field, so the component
  should reference a model whose `ModelDataSource` records the ETag.
- `SM-34` and `SM-42` no longer say a principal "can call it with no
  condition on that key" when its Allow or Deny names the key without
  enforcing it, for example a Null-only Deny or a bare negated operator on a
  multivalued key. Those principals are named separately as calling it under
  a condition that does not enforce the key.
- `AC-04` no longer fails every runtime. It read `loggingConfig` and
  `tracingConfig` from `GetAgentRuntime`, which returns neither, so each
  runtime failed both legs whatever its configuration. It now reports one row
  per runtime from the runtime's log groups under
  `/aws/bedrock-agentcore/runtimes/<runtimeId>-` and a `bedrock-agentcore`
  `TRACES` delivery source with a delivery, the reads `AC-19` uses. A read
  that fails leaves the runtime `N/A`. No IAM grant changes.
- `AC-07` names the fix that matches the `GetMemory` error for a memory it
  cannot describe. `AccessDeniedException` now names `kms:Decrypt` on the
  memory's customer managed key as well as `bedrock-agentcore:GetMemory`,
  because AgentCore decrypts the memory's strategies on the caller's behalf,
  and the derived `AG-19` row carries that cause. Only
  `ResourceNotFoundException` still suggests a memory deleted mid-assessment.
  The AgentCore assessment role gains that `kms:Decrypt` grant, and a
  remaining denial names the key policy, which must also allow the role.
- The IAM permissions cache no longer drops a principal's policies silently
  when a read fails. It writes `cache_schema_version: 2`, a top-level
  `principal_errors` list naming each role or user whose attached, inline,
  group or permissions-boundary read failed and at which stage, and a
  `permissions_boundary` document (or `null`) for every role and user. It
  now reads every page of each role's and user's attached and inline policy
  lists; before, it read only the first page of each.
- `FS-07`, `FS-22`, `AR-01`, `AR-02` and `AR-09` read that cache contract. A
  role or user named in `principal_errors` turns a `Passed` row into `N/A`
  that names the principal and the failed stage, and a failing row is kept
  beside that `N/A` row. A permissions boundary removes an action it does
  not allow. A cache written before version 2 keeps its verdict and says the
  per-principal errors were not recorded. `FS-07` also reports an agent whose
  `GetAgent` call failed, or whose role is missing from the cache, as not
  read; before, it skipped the agent and could pass.
- `AR-01` now reads users and their group policies as well as roles, and
  fails any identity holding a wildcard or `NotAction` grant that allows both
  a read and a write action on one AWS Agent Registry resource type, under
  either the `agent-registry` or the `bedrock-agentcore` namespace
  (AIR-FND-IAM-09). The read and write split per resource type comes from the
  AWS service authorization reference, written to `iam_access_levels.json` by
  `generate_iam_access_levels.py`. `AR-09` now counts a bare `*`, a `*:*` and
  a `NotAction` Allow as granting publication and approval, so an
  administrator that `AR-09` passed before now fails it.
- `AR-03` fails every registry that automatically approves submitted records
  (a non-empty `autoApprovalRules`) and passes one that returns no
  auto-approval rules, including one that omits `approvalConfiguration`,
  which the `GetRegistry` API model defines as manual review (AIR-ACR-REG-02).
  Before, automatic approval was an informational `N/A` unless the
  `RequireAgentRegistryManualApproval` parameter was `true`, and an omitted
  configuration was `N/A`. The parameter is removed.
- `AR-10` credits a lifecycle-event rule only when it has a Lambda function,
  SNS topic, SQS queue or Step Functions state machine target, and a
  forwarded bus only when its rule has one. Before, any target passed, so a
  rule delivering only to a CloudWatch Logs group or an API destination
  passed; it now fails.
- `AR-10` evaluates the `prefix`, `suffix`, `wildcard`, `equals-ignore-case`,
  `anything-but`, `exists` and `numeric` matchers on `source` and
  `detail-type`. Before, any content matcher made a rule `N/A`, so a rule on
  `{"prefix": "aws.s3"}` was reported as undecidable, and one on
  `{"prefix": "aws.agent-"}` that routes every approval event was not
  credited. A rule that stays undecidable, now one using `$or` or a matcher
  the check does not evaluate, or one whose targets cannot be read, no longer
  leaves a `Failed` beside its `N/A` saying no rule routes the approval
  events. The same applies on a forwarded bus whose rules cannot be listed.
  No IAM grant changes.
- `AR-01` fails a wildcard `agent-registry` action on a resource ARN with a
  wildcard in any segment, such as `arn:aws:agent-registry:*:*:*` or
  `registry/*`, and on a `NotResource`. Before, only a literal `Resource: "*"`
  counted, so `agent-registry:Get*` on `arn:aws:agent-registry:*:*:*` passed
  with a finding saying no principal held a wildcard grant on all resources.
  No IAM grant changes.
- `AC-01`, `SM-10`, `SM-33` and `BR-39` read more of the AI compute
  population for AIR-FND-NET-01. `AC-01` fails a custom Code Interpreter or
  Browser in a subnet whose route table routes to an internet gateway, fails a
  VPC-mode runtime reporting `requireServiceS3Endpoint` `true`, and reports a
  runtime that omits the field, or names no subnet, as `N/A` where it passed
  before. `SM-10` fails a Studio domain whose `AppNetworkAccessType` is
  `PublicInternetOnly` or unset, fails a `VpcOnly` domain in a public subnet,
  and no longer reports `Passed` or "none found" after a notebook read error.
  `SM-33` reads every processing job's `NetworkConfig` and every training job,
  where it read only the 50 most recent. `BR-39` describes every named subnet
  in batches of 50, where it stopped after 50 and reported the rest `N/A`.
- `BR-01`, `SM-02` and `AC-02` each gain a finding that fails a wildcard or
  `NotAction` Allow granting both a read and a write action on one resource
  type of the service (AIR-FND-IAM-09): `Bedrock or Data Store Read and Write
  Merged in One Grant`, `SageMaker Read and Write Merged in One Grant` and
  `AgentCore Read and Write Merged in One Grant`. They read every attached,
  inline and group policy of every cached role and user, AWS managed
  included, apply account-wide Denies and the permissions boundary, and drop
  resource types the statement's `Resource` entries cannot name. `BR-01` also
  reads the `s3`, `dynamodb` and `s3vectors` namespaces for an identity
  granted a Bedrock action. A bare `*`, a `*:*`, a partial pattern such as
  `bedrock:*Guardrail*` and `bedrock-agentcore:Get*` (which reaches
  `GetWorkloadAccessToken`) now fail where they passed before. The
  `Bedrock Wildcard Action Grant` and `SageMaker Service-Wide Grant in
  Customer Policy` findings now count a bare `*` and skip an identity whose
  permissions boundary allows no action of the service; the SageMaker one
  also reads group policies and reports a policy it cannot parse as `N/A`.
  All three checks hold a `Passed` row as `N/A` while `principal_errors`
  names an unread principal, and `AC-02`'s incomplete row names the
  principals whose policies it could not parse. `iam_access_levels.json`
  now carries each resource type's ARN formats.
- A principal whose permissions boundary the cache could not read is no
  longer reported `Failed` by a leg that applies the boundary. The cache
  writes `null` both for no boundary and for a failed read, and only a
  `permissions_boundary` entry in `principal_errors` tells them apart, so the
  leg read the principal as unbounded and could fail a grant the boundary
  removes. The wildcard and merged read and write rows of `BR-01`, `SM-02`
  and `AC-02`, every `AR-01` row, `AR-09`, `FS-07` and `FS-22` now skip that
  principal, and `AR-02` leaves it out of its population. The `N/A` row
  names it.

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
  - `AC-45` reads a tool role's resources by value, so `arn:aws:s3:::*`,
    `table/*` and a region or account wildcard fail, and fails an action
    pattern such as `s3:Get*` and an Allow written with `NotAction`. On the
    primary region it adds a Global row naming every principal that can run a
    command or open a shell in a runtime session through a grant that does not
    name `bedrock-agentcore:InvokeAgentRuntimeCommandShell` or
    `InvokeAgentRuntimeCommand`, or that reaches every runtime.
  - `AC-37` reads each `BedrockGuardrails` call by value and fails a guardrail
    policy that no returned score (0, 0.2, 0.4, 0.6, 0.8, 1.0) can make act,
    or whose call names no category or data path. A `suppressOutput` policy
    in a plain `when` block now counts, a threshold it cannot read is named
    in an `N/A` row, and the gateway role's grant counts after its own Deny
    and boundary. A readable grant beside an unparseable policy no longer
    passes.
  - `AC-27` and `AC-47` pass the network leg only on a resource policy Deny
    that refuses the invoke action to every principal outside a bounded
    `aws:SourceVpc`, `aws:SourceVpce`, `aws:VpcSourceIp` or `aws:SourceIp`
    value. A Deny form now passes on `AC-27`, which read Allow statements only.
    An Allow condition alone, a positive or `ForAnyValue` operator, a
    wildcard endpoint, an address list covering every address (the split
    `0.0.0.0/1` plus `128.0.0.0/1` included), and a Deny that ANDs in
    another key or names specific principals now fail, and the finding names
    the reason. The `AC-47` caller leg no longer passes on an Allow naming
    principals, account root included, because an Allow does not stop a
    same-account caller. It passes on `allowedWorkloadConfiguration` or a
    Deny refusing every principal outside a bounded `aws:PrincipalArn` list.
  - `AC-28` and `AC-29` count a guarding service control policy only when it
    is attached to the assessed account, to an organizational unit above it,
    or to the root, read with `organizations:ListParents` and
    `organizations:ListTargetsForPolicy`. A guard attached elsewhere fails as
    `Unattached`, the management account fails as `Not Enforced` because no
    SCP restricts it, and an unreadable parent chain or attachment list is
    `N/A` and never `Passed`. `IfExists` operators now read as their plain
    form, so `StringEqualsIfExists` on the denied value counts. An inverted
    `AC-29` policy is reported only when it is attached.
  - `AC-01` adds a preventive leg, reported once under `Global`: an attached
    service control policy has to deny `CreateAgentRuntime`,
    `UpdateAgentRuntime`, `CreateCodeInterpreter` and `CreateBrowser` with a
    `Null` true test on `bedrock-agentcore:subnets` or
    `bedrock-agentcore:securityGroups`, and a second one has to pin both keys
    with `ForAnyValue:StringNotEquals` to IDs without wildcards. The egress leg
    now unions the outbound ranges of every security group on a resource, so
    `0.0.0.0/1` plus `128.0.0.0/1` fails as `0.0.0.0/0` does. A tool in
    `SANDBOX` network mode now fails at Medium severity instead of passing,
    because no customer security group names what it reaches.
  - `AC-26` adds two legs. A `Global` leg requires an attached service control
    policy that denies `logs:DeleteLogGroup`, `logs:PutRetentionPolicy`,
    `logs:PutLogGroupDeletionProtection` and `logs:DeleteSubscriptionFilter`
    on the AgentCore log groups and `aws/spans` in every Region, exempting at
    most principals named by `aws:PrincipalArn`. A regional leg reads every
    trail with `cloudtrail:GetTrail` and fails a trail that records the
    Region with log file validation off; an unreadable trail is `N/A` and
    blocks a `Passed`.
  - `AC-30`, `AC-31` and `AG-24` judge the values of a JWT authorizer. An
    `allowedAudience` or `allowedClients` list holding a blank value or a `*`
    names no single application and no longer counts, and a `discoveryUrl`
    that is not `https` fails as `Issuer Not HTTPS` whatever the allow-lists
    hold. `AG-24` stops passing a `CUSTOM_JWT` gateway on its authorizer type:
    it passes only when that check would, fails as `Unbounded` when no
    audience or client list pins the application, and is `N/A` when the
    gateway reports no `customJWTAuthorizer`. The `AC-30` pass now states that
    it read the version `GetAgentRuntime` returns by default.
  - `AC-24` no longer counts a limit keyed on `$.context.jwt.jti`, `iat`,
    `exp` or `nbf`, claims that take a new value with every token, so a
    caller who mints a fresh token no longer escapes a limit that passed.
  - `AG-27` reads the gateway's `wafConfiguration` `failureMode` beside the
    web ACL association. `FAIL_OPEN` fails, an unset value is `N/A`, and only
    `FAIL_CLOSE` passes, so an `AG-27` row that passed before can now be
    `Failed` or `N/A`.
  - `AC-25` adds a `Gateway Role Scope` row per gateway. It reads the
    attached and inline policies of the gateway's `roleArn` from the IAM
    permission cache with the `AC-45` rules, so a wildcard action, a
    `Resource: "*"` or an unbounded ARN segment that no Deny or permissions
    boundary removes fails as `Unscoped`. A role the cache records as
    unreadable, a role missing from the cache, and a missing cache are `N/A`
    and never `Passed`. No new IAM action.
  - `AG-25` reads the text of each enforcing policy it used to count. A
    permit over every action with no condition fails as `Allows All`, and an
    enforcing policy with no readable text is `N/A`, so a gateway that passed
    on a policy count can now be `Failed` or `N/A`.
  - `AC-35` reads the principal and resource of every permit over named
    tools. A bare `principal` that no condition reads fails as
    `Caller Scope Unbounded`, and a resource named by type alone or not at all
    fails as `Gateway Scope Unbounded`. A policy with no readable text, or a
    head without three scope positions, now withholds the gateway's `Passed`
    where it was reported beside one.
  - `AC-38` reads each event pattern of a temporal policy and fails one with
    no `eventResource` as `Session Rule Resource Unscoped`. A temporal policy
    with no readable event pattern is `N/A` and no longer passes.
  - `AC-18` requires every data-event type in use, where one selected type
    used to pass its family. Runtimes need `RuntimeEndpoint` as well as
    `Runtime`, the AWS-managed code interpreter and browser need the
    unsuffixed types, and gateways, identity (workload identities and
    credential providers) and policy engines are new families. A selector
    narrowed by `readOnly`, `eventName`, `resources.ARN` or any other field no
    longer counts, nor does a trail that is not logging or that neither spans
    all Regions nor is homed in the scanned one. An unreadable trail status is
    `N/A`.
  - `AC-22` reads a sink policy's principal and organization condition by
    value. A statement naming principals passes only when no principal is a
    wildcard and no `NotPrincipal` is present; otherwise it needs
    `aws:PrincipalOrgID` or `aws:PrincipalOrgPaths` under `StringEquals`,
    `StringEqualsIgnoreCase` or `StringLike` with a value whose organization
    segment has no wildcard. A negated, `IfExists` or `ForAllValues` operator
    and a wildcard organization no longer pass.
  - `AC-26`, `AC-36` and `AC-41` read a key policy by value. An Allow whose
    principal is a wildcard or a `NotPrincipal` fails unless a condition
    binds the caller's account, organization, principal ARN or source with a
    bounded value under a positive operator. `kms:ViaService` alone no longer
    passes, because it narrows the path and not the caller, and neither do
    `IfExists`, `ForAllValues` or a wildcard account. A grant to the CloudWatch
    Logs service principal that does not bind the account or the
    `kms:EncryptionContext:aws:logs:arn` value fails, because it serves log
    groups in any account. `AC-41` now reads the results group's key policy
    itself, so a results group outside an AgentCore prefix is judged by the
    same rules, and an unreadable key policy is `N/A` and never `Passed`.
    Retention length is reported and not judged: no API field states the
    workload's schedule.
  - `AC-19` adds runtimes to its population and requires a `TRACES`
    delivery for every runtime, gateway and memory, beside the
    `APPLICATION_LOGS` delivery it already required for gateways and
    memories. A delivery source reporting `INACTIVE` no longer counts, and an
    unlistable runtime inventory is `N/A`. A gateway or memory that passed on
    application logs alone now fails.
  - `AC-20` states in its `Passed` text that `AC-26` judges the key policy
    and that delivery destination log groups outside the AgentCore prefixes
    are not read.
  - `AC-17` reports one finding per runtime and no longer waits on
    `RequireAgentCoreOnlineEvaluation`. A runtime that no running online
    evaluation reads by its log group and service name fails, where it was
    `N/A` with the parameter unset. The parameter now decides only a region
    with no runtime. An unreadable configuration or runtime inventory is
    `N/A`. `AC-39` also reads `logGroupNamePrefixes` as an input source.
  - `AC-40` counts only `Builtin.ToolSelectionAccuracy` and
    `Builtin.ToolParameterAccuracy` as tool-choice evaluators, where any
    `TOOL_CALL` level evaluator counted, so a skill evaluator no longer
    passes the leg. It also fails a configuration whose scores no CloudWatch
    alarm with actions reads, matched on the configuration's
    `metricsNamespace` or the default `Bedrock-AgentCore/Evaluations`.
    Unreadable alarms are `N/A`, never `Passed`.
  - `AC-39` accepts `resultDestination` `SOURCE_LOG_GROUP` as an output,
    which names no log group and failed before. `AC-41` reports such a
    configuration as `N/A` and names `AC-20` and `AC-26` as the checks that
    judge the input log groups.
  - `AC-08` judges a region that holds gateways and no runtime, where it
    reported `N/A`. It requires an available
    `com.amazonaws.<region>.bedrock-agentcore` endpoint when runtimes exist
    and an available `com.amazonaws.<region>.bedrock-agentcore.gateway`
    endpoint when gateways exist, where any endpoint whose service name
    carried `agentcore`, the control-plane endpoint included, passed. The
    inbound leg fails security groups whose ranges together cover
    `0.0.0.0/0` or `::/0`, which passed when split across narrower ranges.
    VPCs are read across every page.
  - `AG-39` credits a customer `SqliMatchStatement` only at `SensitivityLevel`
    `HIGH`, where the `LOW` default passed, and a customer SQL injection or
    cross-site scripting statement on the body only with `OversizeHandling`
    `MATCH`, or `NO_MATCH` beside a rule that blocks an oversized body, where
    the `CONTINUE` default passed.
  - `AC-51` names the Block and Challenge sensitivities the Anti-DDoS group
    runs with, and says that Shield Advanced enrollment is not judged because
    `shield:CreateProtection` accepts no AgentCore gateway ARN.
  - `AC-50` judges every repository an AgentCore runtime's `containerUri`
    names, where only repositories named for AgentCore were judged, and
    fails `SCAN_ON_PUSH` alone, which passed. A runtime whose image could
    not be read or lives in another registry is `N/A`.
  - `AC-11` reads each policy engine key with `kms:DescribeKey` and fails a
    key whose `KeyManager` is not `CUSTOMER` or whose `KeyState` is not
    `Enabled`, where any named key passed. A disabled key or one pending
    deletion makes every decision the engine takes `DENY`. An engine whose
    detail or key could not be read is `N/A`, where a denied
    `GetPolicyEngine` dropped the engine from the finding.
  - `AC-36` requires the key policy statements the policy encryption guide
    shows: `kms:CreateGrant` only with `kms:ViaService` for the engine's
    Region and `kms:GrantConstraintType` `EncryptionContextSubset`, and
    `kms:Decrypt` and `kms:GenerateDataKey` through AgentCore only with an
    `aws:SourceAccount` or `aws:SourceArn` naming the account. An `IfExists`
    or wildcard `kms:ViaService` is not credited. It also requires the
    key to carry a separate management and evaluation grant bound to the
    engine ARN, read with `kms:ListGrants` across every page. A key whose
    grants could not be listed is `N/A`, where it passed.
  - `AC-14` judges every token vault a credential provider ARN names, read
    from the OAuth2, API key and payment provider lists across every page,
    beside the configured vault, where only the configured vault was read.
    The vault key must be customer managed and `Enabled` by `kms:DescribeKey`,
    where any named key passed. A vault that returns not found while a
    provider names it, a rejected vault id, and a provider list that could not
    be read are `N/A` naming what was not read, where the first two read
    `N/A` with "No action required".
  - `AC-34` scans gateway targets and harnesses as well as runtimes, over
    every field those APIs model as sensitive, and fails a URL carrying a
    password or a credential-named query value. A base64 string of 40 or
    more characters now fails under a credential name even when it holds a
    slash, where every slashed value read as a secret name. A region with
    targets or harnesses and no runtime is scanned, where it read `N/A`.
  - `AC-46` fails a runtime with no delivered `USAGE_LOGS` source of its own,
    and every runtime in a region with no alarm with actions on
    `ActiveSessionCount` (`AWS/Bedrock-AgentCore`, `Service=AgentCore.Runtime`),
    where only the lifecycle ceiling was judged. A runtime reporting one
    lifecycle field and not the other is `N/A`, where it passed on the one it
    reported, and a missing lifecycle value no longer tells the reader to grant
    `GetAgentRuntime`, a call that had succeeded.
  - `AC-06` judges where a custom browser's recordings go, where it passed on
    `recording.enabled` and a bucket name. The bucket, read with
    `ExpectedBucketOwner` set to the browser's account, must encrypt by
    default with `aws:kms` or `aws:kms:dsse`, deny every principal
    `s3:GetObject` and `s3:PutObject` on the recording prefix when
    `aws:SecureTransport` is false, and expire the prefix with an enabled
    lifecycle rule carrying no tag or size filter, plus a noncurrent-version
    expiration when the bucket is versioned. A browser with no
    `executionRoleArn`, or whose role no identity policy or bucket policy
    statement allows to write the prefix, or whose boundary or a Deny refuses
    the write, fails. Bucket Block Public Access left off, a leg that could
    not be read, a role the permission cache did not read and a conditioned
    grant are `N/A`.
  - `AC-07` reads the key each memory names with `kms:DescribeKey` and passes
    it only when KMS reports it customer managed and `Enabled`, where any
    named key passed. A key that is not customer managed, is disabled or is
    pending deletion fails, and a key that could not be described, one in
    another account included, is `N/A`, so a memory that passed before can
    now be `Failed` or `N/A`.

### Deployment impact

**AgentCore role grants.** The AgentCore assessment role gains seven
read-only grants: `events:ListTargetsByRule` on `rule/*`,
`logs:DescribeMetricFilters` on `log-group:*`, `ce:GetAnomalyMonitors` on
`anomalymonitor/*` and `network-firewall:DescribeFirewallPolicy` on
`firewall-policy/*` in this account, and `ec2:DescribeNatGateways`,
`bedrock:GetModelInvocationLoggingConfiguration` and
`bedrock-agentcore:ListAgentRuntimeVersions` on `'*'`, which have no resource
type. Its fifteen unconditioned `Resource: '*'` statements are folded into one,
`AgentCoreReadsWithoutResourceType`, with the same set of granted actions, so
the role renders to 8,548 inline-policy characters in `aws-us-gov`, below the
9,000-character project budget.

**Deployment-stack update and CodeBuild run required.** The
`RequireAgentRegistryManualApproval` parameter is removed from both SAM
templates, both top-level deployment templates
(`deployment/2-aiml-security-codebuild.yaml` and
`deployment/aiml-security-single-account.yaml`) and `buildspec.yml`. A
stack update that still passes the parameter fails, so drop it from any
saved parameter file before updating the deployment stack. The AWS
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
member-role StackSet update is required.

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

The Bedrock assessment role gains, in both SAM templates, on `*` because none
has a resource type in the IAM service authorization reference:
`aoss:BatchGetCollection` (`BR-20`), `comprehend:ListPiiEntitiesDetectionJobs`
(`BR-26`), `cloudtrail:ListEventDataStores` (`BR-06`), `sso:ListInstances`
(`BR-51`), `bedrock-agentcore:ListAgentRuntimes` (`BR-47`, `BR-53`, `BR-57`)
and `bedrock-agentcore:ListAgentRuntimeEndpoints` (`BR-57`). Its
`cloudwatch:DescribeAlarms` grant moves from the account's `alarm:*` ARNs to
`*`, because DescribeAlarms returns composite alarms only to a `*` grant
(`BR-32`). `inspector2:BatchGetAccountStatus` moves from its own statement
into the `LambdaInventoryPermissions` statement, still on `*`. All are
read-only, and the same CodeBuild run applies them.

The Bedrock assessment role gains, in both SAM templates, on `*` because none
has a resource type in the IAM service authorization reference:
`inspector2:ListCoverage` and `events:ListRules` (`BR-33`),
`ec2:DescribeInstances`, `ecs:ListClusters`, `ecs:ListServices` and
`ecs:DescribeTaskDefinition` (`BR-02`), `sagemaker:ListNotebookInstances`
(`BR-02`, `BR-53`), `sagemaker:ListEndpoints`, `sagemaker:ListModels`,
`bedrock-agentcore:ListMemories`, `bedrock-agentcore:ListGateways` and
`bedrock-agentcore:ListBrowsers` (`BR-53`). It also gains `lambda:ListTags` on
the account's `function:*` ARNs (`BR-33`), `ecs:DescribeServices` on
`service/*` (`BR-02`), `sagemaker:DescribeNotebookInstance` on
`notebook-instance/*` (`BR-02`), `sso:ListPermissionSets` on Identity Center
`instance/*` ARNs, and `sso:GetInlinePolicyForPermissionSet` on `instance/*`
and `permissionSet/*/*` ARNs (`BR-51`). `bedrock:GetResourcePolicy`
(`BR-43`) and `bedrock:ListDataSources` and `bedrock:GetDataSource` (`BR-46`)
move into the statements that already grant the same `custom-model/*` and
`knowledge-base/*` resources. Every unconditioned `*` statement of
the role is folded into one `AccountReadsOnWildcard` statement, which keeps
the rendered inline policy under 9000 characters; the folded statement grants
exactly the actions the former statements did, plus the new ones. All are
read-only, and the same CodeBuild run applies them.

Both SAM templates add one new resource, `BedrockAssessmentReadsPolicy`, an
`AWS::IAM::ManagedPolicy` attached only to the Bedrock assessment function
through its `Policies` list, for reads that do not fit the 9000-character
inline budget. It renders to under 5500 of IAM's 6144-character managed
policy limit and holds: `aoss:ListAccessPolicies` and `aoss:GetAccessPolicy`
on `*` (`BR-20`), `cloudtrail:GetEventDataStore` on the account's
`eventdatastore/*` ARNs (`BR-06`), `bedrock:ListIngestionJobs` on the
account's `knowledge-base/*` ARNs (`BR-46`), `sagemaker:ListTrainingJobs` on
`*` and `sagemaker:DescribeTrainingJob` on the account's `training-job/*`
ARNs (`BR-46`, `BR-47`, `BR-52`). `aoss:ListAccessPolicies`,
`aoss:GetAccessPolicy` and `sagemaker:ListTrainingJobs` have no resource type
in the IAM service authorization reference. All six are read-only. Each
stack creates one more customer managed policy, named with the stack name as
its prefix.

Both SAM templates add `SageMakerAssessmentReadsPolicy`, an
`AWS::IAM::ManagedPolicy` attached only to the SageMaker assessment function
through its `Policies` list, for reads that do not fit that function's
9000-character inline budget. It renders to under 5500 of IAM's
6144-character managed policy limit and holds
`organizations:ListAWSServiceAccessForOrganization` on `*` (`SM-35`), which
has no resource type and moves out of the inline
`OrganizationsInventoryPermissions` statement, and
`sagemaker:DescribeModelQualityJobDefinition`,
`sagemaker:DescribeModelBiasJobDefinition` and
`sagemaker:DescribeModelExplainabilityJobDefinition` on the account's
`model-quality-job-definition/*`, `model-bias-job-definition/*` and
`model-explainability-job-definition/*` ARNs (`SM-23`), and
`ec2:DescribeManagedPrefixLists` on `*`, which has no resource type, and
`ec2:GetManagedPrefixListEntries` on `prefix-list/*` with the account
segment open, because a list can be shared through AWS RAM from another
account (`SM-39`). All are read-only. The deployment role permissions added
for `BedrockAssessmentReadsPolicy` cover this policy too.

**Update the deployment stack first.** The CodeBuild and member deployment
roles could attach only `AWSLambdaBasicExecutionRole` and could not create a
managed policy, so an assessment deploy from this version on an old deployment
stack fails with `iam:CreatePolicy` denied and rolls back. Update
`deployment/aiml-security-single-account.yaml` or
`deployment/2-aiml-security-codebuild.yaml`, and the member-role StackSet from
`deployment/1-aiml-security-member-roles.yaml`, before the next assessment
deploy. Each deployment role gains `iam:CreatePolicy`, `iam:DeletePolicy`,
`iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicyVersions`,
`iam:CreatePolicyVersion`, `iam:DeletePolicyVersion` and
`iam:ListEntitiesForPolicy` on the account's `policy/aiml-security-*` and
`policy/aiml-sec-*` ARNs (the `AWS::IAM::ManagedPolicy` handler permissions),
and its `iam:AttachRolePolicy` and `iam:DetachRolePolicy` condition admits
those two policy patterns beside `AWSLambdaBasicExecutionRole`. The roles
could already write any inline policy on the same `aiml-security-*` and
`aiml-sec-*` roles.

The AgentCore assessment role gains `bedrock-agentcore:GetPaymentManager` and
`bedrock-agentcore:GetHarness`, scoped to the account's `payment-manager/*` and
`harness/*` ARNs, in both SAM templates. Both are read-only, and the same
CodeBuild run applies them. `bedrock-agentcore:ListPaymentManagers` and
`bedrock-agentcore:ListHarnesses` have no resource type and are not granted;
until they are, the payment manager and harness legs of `AC-02` and `AC-48`
report `N/A` naming the missing action.

The AgentCore assessment role gains `organizations:ListTargetsForPolicy`,
scoped to `service_control_policy` ARNs, and `organizations:ListParents`,
scoped to this account's own `account` ARN and to `ou` ARNs, in both SAM
templates, so `AC-28` and `AC-29` can read attachment. Both are read-only, and
the same CodeBuild run applies them. A member account that cannot list the
organization's policies still reports `N/A`, as before.

The AgentCore assessment role gains `cloudtrail:GetTrail`, scoped to the
account's `trail/*` ARNs, in both SAM templates, so `AC-26` can read log file
validation. It is read-only, and the same CodeBuild run applies it. The new
`AC-01` and `AC-26` service control policy legs use the Organizations grants
added for `AC-28` and `AC-29`.

The AgentCore assessment role gains `cloudtrail:GetTrailStatus`, scoped to the
account's `trail/*` ARNs, and `bedrock-agentcore:ListWorkloadIdentities`,
`bedrock-agentcore:ListOauth2CredentialProviders` and
`bedrock-agentcore:ListApiKeyCredentialProviders`, scoped to the account's
`workload-identity-directory/*` and `token-vault/*` ARNs, in both SAM
templates, so `AC-18` can read each trail's logging state and count the
identity resources. All are read-only, and the same CodeBuild run applies
them. Until it runs, the `AC-18` identity family reports `N/A`.

`AC-22`, `AC-26`, `AC-36` and `AC-41` change no IAM grant: `kms:GetKeyPolicy`
is already scoped to `key/*` in both SAM templates. Rows of these checks that
passed before can now fail after the same CodeBuild run.

`AC-19` changes no IAM grant: it reads runtimes with
`bedrock-agentcore:ListAgentRuntimes`, which the role already holds.

`AC-17` changes no IAM grant either, and reads the same two list calls. The
`RequireAgentCoreOnlineEvaluation` parameter keeps its name and default, and
only its description changes in both templates. With the default `false`, a
region with runtimes that online evaluation does not score now reports
`Failed` rows where it reported `N/A`.

The AgentCore assessment role gains `cloudwatch:DescribeAlarms`, scoped to the
account's `alarm:*` ARNs, in both SAM templates, so `AC-40` can read the
alarms on evaluation scores. It is read-only, and the same CodeBuild run
applies it. Until it runs, `AC-40` rows that meet the evaluator legs report
`N/A`, and a configuration whose scores no alarm reads now fails.

`AC-08` changes no IAM grant: `bedrock-agentcore:ListGateways` and
`ec2:DescribeVpcs` are already on the AgentCore role. A region whose only
AgentCore endpoint is the control-plane or runtime endpoint now fails where
its gateways are in use.

`AG-39`, `AC-50` and `AC-51` change no IAM grant: they read fields of
`wafv2:GetWebACL`, `bedrock-agentcore:ListAgentRuntimes`,
`bedrock-agentcore:GetAgentRuntime` and `ecr:DescribeRepositories`, which
the AgentCore role already holds. A web ACL whose customer SQL injection or
cross-site scripting statements use the API defaults, and a repository
scanned at `SCAN_ON_PUSH` alone, now fail where they passed.

`AC-11` and `AC-36` add `kms:DescribeKey` and `kms:ListGrants` to the AgentCore
role in both templates, scoped to `arn:${AWS::Partition}:kms:*:${AWS::AccountId}:key/*`
under the new Sid `PolicyEngineKeyStateRead`. Redeploy the stack before the
next scan: without the grants every policy engine reads as `N/A` in `AC-11`
and `AC-36`. A key policy missing the guide's service-use statements, and a
key missing either engine grant, now fail where they passed.

`AC-14` adds `bedrock-agentcore:ListPaymentCredentialProviders` to the
`AgentCoreIdentityInventory` Sid in both templates, scoped to the
`token-vault/*` ARN beside the two provider lists already there, and reads the
vault key with the `kms:DescribeKey` grant above. Redeploy before the next
scan: without it `AC-14` reads the payment provider list as unread and reports
`N/A`. `AC-34` adds no grant. Its gateway leg uses `ListGatewayTargets` and
`GetGatewayTarget`, already on the role. Its harness leg calls
`bedrock-agentcore:ListHarnesses`, which the role does not hold pending
approval, so harnesses read `N/A` and are never reported clean.

`AC-46` adds no grant. It reads deliveries with `logs:DescribeDeliverySources`
and `logs:DescribeDeliveries` and alarms with `cloudwatch:DescribeAlarms`, all
already on the AgentCore role. No runtime delivers `USAGE_LOGS` until one is
configured, so expect `AC-46` to fail runtimes that passed before.

`AC-06` adds the `BrowserRecordingBucketRead` Sid to the AgentCore role in both
templates: `s3:GetEncryptionConfiguration`, `s3:GetBucketPublicAccessBlock`,
`s3:GetBucketPolicy`, `s3:GetLifecycleConfiguration` and
`s3:GetBucketVersioning` on `arn:${AWS::Partition}:s3:::*`, because the
recording bucket is named by the customer. Redeploy before the next scan:
without it every recording browser reads `N/A`. The account-level Block Public
Access read, `s3:GetAccountPublicAccessBlock`, is not granted pending approval,
so a bucket that leaves its own setting off reads `N/A`. Expect `AC-06` to
fail recording browsers that passed before.

`AC-07` adds no grant. It reads memory keys with `kms:DescribeKey`, which the
AgentCore role already holds on this account's keys in the
`PolicyEngineKeyStateRead` Sid. A memory whose key lives in another account
reads `N/A`.

The SageMaker assessment role gains seven read-only actions in both SAM
templates: `ecr:DescribeRepositories` and `ecr:DescribeImageSigningStatus` on
the account's repositories (`ModelImageRepositoryRead`, for `SM-43`),
`elasticfilesystem:DescribeFileSystems` on the account's file systems
(`TrainingFileSystemRead`, for `SM-03`), `ecr:GetSigningConfiguration`,
`fsx:DescribeFileSystems` and `sagemaker:ListInferenceComponents` (for
`SM-43` and `SM-03`) on `*` in `ApprovedInventoryWithoutResourceType`,
because none has a resource type in the service authorization reference, and
`cloudwatch:DescribeAlarmHistory` (for `SM-37`) on `*` in the new
`CompositeAlarmRead` Sid. The role's `cloudwatch:DescribeAlarms` grant (for
`SM-23`, `SM-31` and `SM-37`) moves from the account's alarms to `*` in the
same Sid, which replaces `FlowLogAlarmRead`. The CloudWatch API reference for
both actions says composite alarm information is returned only when the
permission is scoped to `*`. Until the stack is redeployed, `SM-43` reads
each tag-pinned image and each inference component endpoint as `N/A`, `SM-03`
names each training file system as not read, and `SM-37` receives no
composite alarms. `SM-43` reads artifact bucket encryption through the
existing `s3:GetEncryptionConfiguration` grant.

The IAM permissions cache role gains `iam:GetRole` on the account's roles and
`iam:GetUser` on its users in both SAM templates, because only those calls
return a principal's permissions boundary. Both are read-only, and the same
CodeBuild run applies them.

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

- `BR-07` now reads the encryption key of every numbered prompt version, so an
  older version with no `customerEncryptionKeyArn` fails even when the latest
  version carries a customer managed key, and an unread version is `N/A`. Its
  flow leg reads each flow version an alias routes to (`ListFlowAliases`,
  `GetFlowVersion`) as well as the working draft, so a deployed version that
  references an unversioned prompt fails. The `Bedrock Prompt Variants Check`
  row is now an Informational `N/A` advisory and no longer sets the check
  status to `WARN`.
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
