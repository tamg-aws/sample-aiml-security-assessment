# Security Checks Reference

This document provides a comprehensive reference for all 277 security checks performed by the AI/ML Security Assessment framework (162 core checks across Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, and AWS Agent Registry, 39 Agentic AI Security checks, 64 Responsible AI GRC checks, and 12 OWASP Top 10 for LLM checks).

Sources differ by bucket and are not interchangeable: the core Bedrock, SageMaker, AgentCore, and AWS Agent Registry checks derive from the AWS Well-Architected **Generative AI Lens** security best practices (`gensec*`) and service security documentation; the Agentic AI Security checks from the AWS Well-Architected **Agentic AI Lens**; the `FS-*` **Responsible AI GRC** checks from the AWS GRC User Guide; and the `OW-*` checks from the OWASP Top 10 for LLM. The AWS Well-Architected **Responsible AI Lens** is not a source for any of them — see [Responsible AI GRC — scope, sources, and compatibility](RESPONSIBLE_AI_GRC_SCOPE.md).

The 64 Responsible AI GRC checks occupy 69 `FS-*` numbers: 64 ship as standalone checks and 5 are merged into upstream Bedrock/SageMaker checks. The framework also emits `BR-00`, `SM-00`, `AC-00`, `AR-00`, `FS-00`, `OW-00`, and `AISF-00` operational marker rows at runtime; these are not controls and are excluded from the 277-check total. `AISF-01` through `AISF-08` are AWS AI Security Framework view rows: each one restates the verdict of a check already counted above under an AISF control id, so they are excluded from the 277-check total for the same reason ([AWS AI Security Framework (AISF) Checks](SECURITY_CHECKS_AISF.md)). Per-control provenance, including which controls are project extensions rather than guide-derived, is recorded in [`provenance.json`](../aiml-security-assessment/functions/security/responsible_ai_grc_assessments/provenance.json).

## Table of Contents

- [Overview](#overview)
- [Check ID Convention](#check-id-convention)
- [Report Scoring](#report-scoring)
- [Severity Levels](#severity-levels)
- [Status Values](#status-values)
- [Amazon SageMaker AI Security Checks (42)](#amazon-sagemaker-ai-security-checks-42)
- [Amazon Bedrock Security Checks (57)](#amazon-bedrock-security-checks-57)
- [Amazon Bedrock AgentCore Security Checks (53)](#amazon-bedrock-agentcore-security-checks-53)
- [AWS Agent Registry Security Checks (10)](#aws-agent-registry-security-checks-10)
- [Agentic AI Security Checks (39)](#agentic-ai-security-checks-39)
- [Responsible AI GRC Checks (64)](#responsible-ai-grc-checks-64-additional-5-upstream-extensions)
- [OWASP Top 10 for LLM Checks (12)](#owasp-top-10-for-llm-checks-12)

---

## Overview

The framework evaluates your AI/ML workloads against AWS security best practices across four services:

| Service | Number of Checks | Focus Areas |
| --------- | ------------------ | ------------- |
| Amazon SageMaker AI | 40 | Security Hub controls, encryption, network isolation, GuardDuty AI Protection, HyperPod, IAM, MLOps, Model Registry policy exposure, inference data capture, Config compliance evaluation, training VPC boundary, creation guardrails, security service delegated administration, the Security Hub AI standard, GuardDuty Lambda Protection and Runtime Monitoring, EKS network policy, secret rotation, IoT device-scoped policies |
| Amazon Bedrock | 57 | Guardrails, prompt-attack/image filters, retention, inference profiles, automated reasoning and Marketplace endpoint governance, encryption, networking, IAM, logging, monitoring, evaluation, central guardrail enforcement, model allow-lists, Region and Marketplace subscription control, API key governance, knowledge base source classification, LLM jacking activity in CloudTrail event history, agent handoff source identity |
| Amazon Bedrock AgentCore | 52 | Runtime/tool VPC isolation, encryption, browser recording, observability, resource policies, Identity token vaults, online evaluation, and the Cognito user pools that issue tokens to gateways and runtimes |
| AWS Agent Registry | 10 | IAM access, approval governance, discovery authorization, encryption, organization auto-detection, record lifecycle, and provenance |
| Agentic AI Security | 39 | Bounded autonomy, agent identity, tool authorization, Registry governance and provenance, guardrail enforcement, prompt/input protection, memory privacy, auditability, continuous assurance, abuse protection |
| Responsible AI GRC | 64 | Unbounded consumption, excessive agency, supply chain, training data poisoning, vector weaknesses, non-compliant output, misinformation, harmful output, biased output, PII disclosure, hallucination, prompt injection, improper output handling, off-topic output, out-of-date training data |
| OWASP Top 10 for LLM | 12 | LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption |

---

## Check ID Convention

Each security check has a unique identifier with a service prefix:

| Prefix | Service | Example |
| -------- | --------- | --------- |
| **SM-XX** | Amazon SageMaker | SM-01, SM-43 (`SM-29` reserved) |
| **BR-XX** | Amazon Bedrock | BR-01, BR-57 |
| **AC-XX** | Amazon Bedrock AgentCore | AC-01, AC-53 |
| **AR-XX** | AWS Agent Registry | AR-01, AR-10 |
| **AG-XX** | Agentic AI Security | AG-01, AG-39 |
| **FS-XX** | Responsible AI GRC | FS-01, FS-69 |
| **OW-XX** | OWASP Top 10 for LLM | OW-01, OW-12 |

### Runtime marker IDs (not controls)

The `*-00` rows below make assessment coverage and execution problems visible in
CSV and HTML reports. They are operational markers rather than security
controls, do not increase the published check counts, and must not be treated as
evidence that a control passed or failed.

| Marker | Runtime meaning | Normal status / severity |
| -------- | --------------- | ------------------------ |
| `BR-00` | Amazon Bedrock is unavailable or not enabled in the target region, so regional Bedrock checks were not run. | `N/A` / Informational |
| `SM-00` | Amazon SageMaker AI is unavailable or not enabled in the target region, so regional SageMaker checks were not run. | `N/A` / Informational |
| `AC-00` | Amazon Bedrock AgentCore is unavailable in the target region, or the Runtime availability probe rejected the assessment credentials before regional checks could run. Unexpected errors inside individual checks use their affected `AC-*` or `AG-*` control IDs instead. | `N/A` / Informational |
| `AR-00` | AWS Agent Registry is unavailable in the target region, so regional `AR-03` through `AR-08` checks were not run. | `N/A` / Informational |
| `FS-00` | No regional Bedrock, AgentCore, or SageMaker resource footprint was found, so Responsible AI GRC was not applicable to that region. | `N/A` / Informational |
| `OW-00` | A required upstream assessment CSV was missing, so one or more mapping-derived OWASP rows could not be generated. | `N/A` / Informational |

When a Bedrock API is access-denied or an AgentCore check raises an unexpected
execution error, the affected control ID is reported as informational `N/A`
with an incomplete-assessment message. These rows remain visible for
troubleshooting but are excluded from scoring. A control is `Failed` only when
the scanner successfully observes evidence that violates its baseline.

`FS-00` is described in more detail in
[Responsible AI GRC Checks](SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md#fs-00--regional-scope-not-applicable-not-a-control),
and `OW-00` in
[OWASP Top 10 for LLM Security Checks](SECURITY_CHECKS_OWASP.md).

---

## Report Scoring

Pass rates are calculated from unique direct-service `Check_ID` values, not
from report-row counts. Findings for resources, Regions, or accounts are
aggregated into one result per control: any assessable `Failed` row makes the
control fail, and a control passes only when all assessable rows pass.
Informational and `N/A` rows are excluded from the score. Agentic AI and
compliance-mapping rows are contextual views of source evidence and are also
excluded to prevent double counting. Resource-level rows remain visible for
investigation and remediation.

---

## Severity Levels

| Severity | Description | Action Required |
| ---------- | ------------- | ----------------- |
| **High** | Critical security issues that could lead to data exposure, unauthorized access, or compliance violations | Immediate remediation recommended |
| **Medium** | Important security improvements that strengthen your security posture | Address in next maintenance window |
| **Low** | Minor optimizations and best practice recommendations | Address when convenient |
| **Informational** | Advisory information about your configuration | No action required |

---

## Status Values

| Status | Description |
| -------- | ------------- |
| **Failed** | Security issue identified that requires remediation |
| **Passed** | Checked resources met the assessed best practice at time of scan |
| **N/A** | The check was not applicable, advisory-only, unavailable in the region, or could not be assessed (for example, because no resources exist or access was denied). |

---

## Amazon SageMaker AI Security Checks (42)

### SM-01: Internet Access

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.2
- **Description:** Checks for direct internet access on notebooks and domains.

### SM-02: AWS IAM Permissions

- **Severity:** High
- **Description:** Identifies overly permissive policies and stale access from
  the shared IAM permissions cache. A missing, unreadable, or malformed cache
  produces an informational `N/A` incomplete-assessment row rather than a
  compliant result.
  A separate `SageMaker Service-Wide Grant in Customer Policy` finding reads
  customer-managed and inline policies on roles and users and fails any Allow
  statement that grants every SageMaker action, through `sagemaker:*`, a bare
  `"*"` or a pattern that covers it, or through a `NotAction` list that does
  not exclude SageMaker, on an identity whose permissions boundary allows a
  SageMaker action. It also reads group policies. AWS managed policies are left
  to the full-access finding above and to the next finding. A policy that
  cannot be parsed produces `N/A` naming it.
  A `SageMaker Read and Write Merged in One Grant` finding covers
  AIR-FND-IAM-09 over the `sagemaker` namespace. It reads every attached (AWS managed included), inline and group policy of every cached role and user, and fails a wildcard `Action` pattern (a bare `"*"`, `*:*` and a partial pattern among them) or a `NotAction` Allow that grants both a read and a write action on one resource type, as the [service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html) classifies them (the table is `iam_access_levels.json`, generated by `generate_iam_access_levels.py`). An explicit action list is never reported, because it separates read from write. An action counts only when no unconditioned `Resource: "*"` Deny removes it and the permissions boundary also allows it. A condition applies to the read and the write alike and is not read; the `Resource` entries are read only to drop resource types none of them can name, with a policy variable read as any value. Service control policies are not evaluated per principal, which can only make a row a false `Failed`, and each failing row says so. A policy that cannot be parsed produces `N/A` naming the principal. While the cache's `principal_errors` names a principal, each `Passed` row becomes `N/A` naming the unread principals; a cache without `principal_errors` (schema v1) keeps its verdict and says the errors were not recorded. A principal whose permissions boundary the cache could not read (a `permissions_boundary` stage in `principal_errors`) is not reported `Failed` by the service-wide or merged rows, because a boundary could remove the grant; the `N/A` row names it.

### SM-03: Data Protection

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.1
- **Description:** Verifies encryption at rest and in transit for notebooks and domains.

### SM-04: Amazon GuardDuty Integration

- **Severity:** High
- **Description:** Verifies Amazon GuardDuty runtime threat detection is enabled.

### SM-05: MLOps Features

- **Severity:** Low
- **Description:** Checks MLOps pipelines, experiment tracking, and model registry usage.

### SM-06: Clarify Usage

- **Severity:** Low
- **Description:** Validates SageMaker Clarify for bias detection and explainability.

### SM-07: Model Monitor

- **Severity:** Medium
- **Description:** Checks Model Monitor configuration for drift detection.

### SM-08: Model Registry

- **Severity:** Medium
- **Description:** Validates model registry usage and permissions.

### SM-09: Notebook Root Access

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.3
- **Description:** Validates root access is disabled on notebooks.

### SM-10: Notebook Amazon VPC Deployment

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.2
- **Description:** Ensures notebooks are deployed within an Amazon VPC, and fails a notebook whose subnet's route table routes to an internet gateway. A notebook list or describe error is `N/A` and withholds the all-in-VPC `Passed`. The same check reads every SageMaker Studio domain (AIR-FND-NET-01): `DescribeDomain` reporting `AppNetworkAccessType` `PublicInternetOnly`, or omitting it (the default is `PublicInternetOnly`), fails `SageMaker Studio Domain Network Boundary`, because that mode sends non-EFS traffic through a SageMaker-managed VPC that allows direct internet access. A `VpcOnly` domain's `SubnetIds` go through the same route-table read under `SageMaker Studio Domain Subnet Internet Exposure`. A domain list or describe error, or a `VpcOnly` domain with no `SubnetIds`, is `N/A`.

### SM-11: Model Network Isolation

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.4
- **Description:** Checks inference containers have network isolation.

### SM-12: Endpoint Instance Count

- **Severity:** Medium
- **AWS Security Hub Control:** SageMaker.5
- **Description:** Verifies endpoints have 2+ instances for high availability.

### SM-13: Monitoring Network Isolation

- **Severity:** Medium
- **Description:** Checks monitoring job network isolation.

### SM-14: Model Container Repository

- **Severity:** Medium
- **Description:** Validates model container repository access.

### SM-15: Feature Store Encryption

- **Severity:** High
- **Description:** Checks feature group encryption settings.

### SM-16: Data Quality Encryption

- **Severity:** Medium
- **Description:** Validates data quality job encryption.

### SM-17: Processing Job Encryption

- **Severity:** Medium
- **Description:** Verifies processing job encryption.

### SM-18: Transform Job Encryption

- **Severity:** Medium
- **Description:** Checks transform job volume encryption.

### SM-19: Hyperparameter Tuning Encryption

- **Severity:** Medium
- **Description:** Validates hyperparameter tuning job encryption.

### SM-20: Compilation Job Encryption

- **Severity:** Medium
- **Description:** Checks compilation job encryption.

### SM-21: AutoML Network Isolation

- **Severity:** Medium
- **Description:** Validates AutoML job network isolation.

### SM-22: Model Approval Workflow

- **Severity:** Medium
- **Description:** Checks model approval and governance workflow.

### SM-23: Model Drift Detection

- **Severity:** Medium
- **Description:** Validates model drift monitoring configuration.

### SM-24: A/B Testing and Shadow Deployment

- **Severity:** Low
- **Description:** Checks for safe deployment patterns.

### SM-25: ML Lineage Tracking

- **Severity:** Low
- **Description:** Validates experiment tracking and lineage.

### SM-26: GuardDuty AI Protection

- **Severity:** High
- **Description:** Reuses the regional GuardDuty detector inventory and verifies the `AI_PROTECTION` feature is `ENABLED`. No detector is N/A because SM-04 separately reports GuardDuty enablement.

### SM-27: HyperPod EBS CMK Encryption

- **Severity:** Medium
- **Description:** Verifies every HyperPod instance group configures a customer-managed KMS key for its root EBS volume and all configured secondary EBS volumes. AWS documents that HyperPod root volumes use an AWS-owned key by default and that a customer-managed key is supplied through `InstanceStorageConfigs`; therefore, an absent root-volume storage configuration fails this CMK baseline rather than producing `N/A`.

### SM-28: HyperPod VPC Configuration

- **Severity:** Medium
- **Description:** Verifies each HyperPod instance group's effective VPC configuration has subnets and security groups, honoring `OverrideVpcConfig` before the cluster-level `VpcConfig`.

`SM-29` is reserved for SageMaker Unified Studio private networking. It is not currently emitted because the available domain APIs do not expose a sufficient domain-level networking configuration.

### SM-30: Model Package Group Resource Policy Exposure

- **Severity:** High for public or configured-boundary violations; Informational for unclassified external sharing
- **Description:** Parses model package group resource policies to identify public wildcard principals and external accounts or organizations outside optional `AIML_APPROVED_EXTERNAL_ACCOUNT_IDS` / `AIML_APPROVED_ORG_IDS` boundaries. Configure those boundaries through the `ApprovedExternalAccountIds` and `ApprovedOrganizationIds` deployment parameters, respectively; both default to empty. Wildcard principals constrained by exact `aws:PrincipalAccount` or `aws:PrincipalOrgID` values, fixed-account `aws:PrincipalArn` patterns, or fixed-organization `aws:PrincipalOrgPaths` patterns are treated as bounded. Wildcard account/organization identifiers remain public; `ForAllValues` organization-path conditions count as boundaries only when a matching `Null: false` condition requires the key to be present. Because AWS supports `NotPrincipal` only with `Deny`, an `Allow` statement containing `NotPrincipal` is reported as unsupported and `N/A` rather than silently passing or being treated as public. Valid `Deny` statements do not create exposure and are ignored. If `sts:GetCallerIdentity` is unavailable, public wildcard statements are still reported, but account principals that cannot be distinguished as same-account or external produce `N/A` instead of an external-access finding. This is a conservative heuristic, not a complete IAM authorization simulator.

### SM-31: Endpoint Inference Data Capture

- **Severity:** Medium
- **Description:** Requires each SageMaker endpoint to capture inference requests and responses. `DescribeEndpoint` reports the live capture state as `DataCaptureConfig.EnableCapture` plus `CaptureStatus`, so an endpoint whose configuration enables capture but whose `CaptureStatus` is `Stopped` is reported as a failure and not as compliant.

### SM-32: SageMaker Configuration Compliance Evaluation

- **Severity:** Medium
- **Description:** Two independent legs, each with its own finding. `SageMaker Configuration Recording` requires an AWS Config recorder whose recording group covers SageMaker resource types. `SageMaker Config Rule Compliance` requires at least one active Config rule evaluating SageMaker and reports that rule's current compliance result. Neither verdict implies the other: a recorder with no rules evaluates nothing, and a rule with no recorder cannot see configuration changes. Service-linked rules, which carry `CreatedBy` (for example `securityhub.amazonaws.com`), are reported `N/A` naming the owning service, because AWS Config returns their compliance results to no caller.

### SM-33: Training Job Network Boundary

- **Severity:** Medium
- **Description:** Requires training jobs to run inside a customer VPC. Network isolation and `VpcConfig` are reported separately, because a job can set `EnableNetworkIsolation` with no VPC attachment, and an isolated job without a VPC attachment still has no private path to Amazon S3 or Amazon ECR. SM-21 asserts the same VPC boundary for AutoML jobs only. Every training job is listed and described, with no item cap. The same check lists and describes every processing job (AIR-FND-NET-01): a job whose `NetworkConfig` names no `VpcConfig` fails `Processing Job Network Boundary`, and the subnets of the others go through the route-table read under `SageMaker Processing Job Subnet Internet Exposure`. A list or describe error is `N/A`, and `No SageMaker training or processing jobs found` appears only when both lists read empty. In an estate with many jobs this check makes one describe call per job.

### SM-34: SageMaker Creation Guardrails

- **Severity:** Medium
- **Description:** Requires a service control policy that denies creation of unencrypted, internet-exposed, or non-VPC SageMaker resources, with one verdict per guardrail category: `encryption` (`sagemaker:VolumeKmsKey`, `sagemaker:OutputKmsKey`, `sagemaker:InterContainerTrafficEncryption`), `approved network` (`sagemaker:VpcSubnets`, `sagemaker:VpcSecurityGroupIds`, `sagemaker:NetworkIsolation`), and `no direct internet access` (`sagemaker:DirectInternetAccess`). Categories are reported separately because an organization commonly guards encryption at creation and leaves the network parameters unguarded. A Deny that fires when the parameter is absent or holds a non-approved value counts as enforced; a Deny naming one specific value is reported as ambiguous, because whether that value is the non-compliant one depends on the value and this check does not interpret it. An unreadable organization view produces `N/A`.

### SM-35: Security Service Delegated Administrator

- **Severity:** High
- **Description:** Emits one row per security service from a fixed list (Amazon GuardDuty, AWS Security Hub, Amazon Inspector, Amazon Macie, AWS Config, IAM Access Analyzer), each row naming the list. A service passes when an `ACTIVE` delegated administrator other than the organization management account is registered, and fails when none is registered or the only active one is the management account. `ListDelegatedAdministrators` is readable only from the management account or a delegated administrator account, so an access denial for one service is `N/A` for that service alone. An account outside AWS Organizations produces one `N/A` row. Runs once, on the primary region, tagged `Global`.

### SM-36: Security Hub AI Security Standard

- **Severity:** High
- **Description:** Requires the AWS Security Hub AI Security Best Practices v1.0.0 standard (`standards/ai-security-best-practices/v/1.0.0`) to be enabled in the region. `READY` passes; `INCOMPLETE` passes with a note to review the standard's `StatusReason`; any other subscription status fails. Security Hub not enabled in the region (`InvalidAccessException`) fails, because no standard is evaluating anything.

### SM-37: GuardDuty Lambda Protection

- **Severity:** Medium
- **Description:** Requires the GuardDuty `LAMBDA_NETWORK_LOGS` feature to be `ENABLED` on an enabled detector, so network activity from AI workload Lambda functions is monitored. A disabled or absent feature fails and names its state. No detector produces `N/A`; SM-04 reports the missing detector.

### SM-38: GuardDuty Runtime Monitoring

- **Severity:** High
- **Description:** Requires the GuardDuty `RUNTIME_MONITORING` feature to be `ENABLED` and reports the automated agent management state for EKS, ECS Fargate and EC2. The legacy `EKS_RUNTIME_MONITORING` feature covers EKS only, so a detector with only that feature enabled fails. No detector produces `N/A`.

### SM-39: EKS VPC CNI Network Policy

- **Severity:** Medium
- **Description:** For each EKS cluster, reads the managed `vpc-cni` add-on's `configurationValues` and requires `enableNetworkPolicy` to be true (EKS returns the value as the string `"true"` inside a JSON or YAML document). A pass means network-policy enforcement is enabled on the add-on; whether NetworkPolicy objects restrict pod traffic is a Kubernetes-API fact this scan cannot read. An EKS Auto Mode cluster (`computeConfig.enabled`) is reported `N/A`, because Auto Mode sets network policy on the NodeClass, a Kubernetes object no AWS API returns. Any other cluster without the managed add-on is reported `N/A`, because enforcement by a self-managed CNI is not readable through the EKS API. One cluster's read error is reported for that cluster alone.

### SM-40: Secrets Manager Rotation

- **Severity:** Medium
- **Description:** For each customer-managed secret, requires automatic rotation to be turned on and the last rotation to fall within the rotation schedule plus one day. A secret with rotation turned on that has never rotated fails. Schedules are read from `rate()` (hours or days), `cron()` (the longest gap between two scheduled dates), or `AutomaticallyAfterDays`; a `cron()` form this check does not interpret, such as `W`, is reported `N/A`. Secrets with `OwningService` set rotate under that service's control and are skipped and counted. Secret values are never read.

### SM-41: AWS IoT Device-Scoped Policy

- **Severity:** High
- **Description:** For each AWS IoT policy attached to a certificate or other principal, fails an Allow statement that reaches `Publish`, `Subscribe`, `Receive` or `Connect` on `*`, on all topics, topic filters or client IDs, or through `NotResource`, unless the resource embeds `${iot:Connection.Thing.ThingName}`. `NotAction` Allow statements are expanded to the device actions they reach. A statement allowing `Connect` also needs a `Bool` condition requiring `iot:Connection.Thing.IsAttached` to be `true`. Unattached policies are skipped. No attached policy produces `N/A`.

### SM-42: Batch Transform Creation Guardrail

- **Severity:** Medium
- **Description:** Applies the `SM-34` creation guardrail to the batch transform path only: `CreateTransformJob` on `sagemaker:VolumeKmsKeyArn` and `sagemaker:OutputKmsKeyArn`, and `CreateModel` on `sagemaker:VpcSubnets` or `sagemaker:VpcSecurityGroupIds` and on `sagemaker:NetworkIsolation`. A transform job takes its network posture from its model, so `CreateModel` carries the network keys. Each requirement is met by a service control policy Deny on this account's path to the root or by a condition in every identity policy that grants the action. A training, endpoint configuration or notebook gap does not fail this check. It emits one row per category in each scanned Region, so it shares an account and Region key with the `SM-18` transform job rows.

### SM-43: Model Artifact Integrity

- **Severity:** Medium
- **Description:** Judges every container each InService endpoint serves, including the containers of a model package the model names and of each inference component. The image passes when it is pinned by digest (`@sha256:`) or by a tag that its Amazon ECR repository holds immutable: `IMMUTABLE`, `IMMUTABLE_WITH_EXCLUSION` for a tag no exclusion filter matches, or `MUTABLE_WITH_EXCLUSION` for a tag an exclusion filter matches. An untagged image is read as `latest`. When a managed signing rule of the registry covers the repository (a rule with no filters covers every repository), the image also needs a `COMPLETE` status from `DescribeImageSigningStatus`, read by the digest `DescribeEndpoint` reports the image resolved to; no status, or a `FAILED` one, fails. S3 model data passes when `ModelDataSource.S3DataSource` records an `ETag` or `ManifestEtag`, when a model package container records `ModelDataETag`, or when the source names SageMaker hub content (`HubAccessConfig.HubContentArn`). A bare `ModelDataUrl` fails, as does each `AdditionalModelDataSources` entry with no ETag, and a container whose environment sets `HF_MODEL_ID` with no model data. Only environment keys are read, never values. Each artifact bucket must default to SSE-KMS with a named `KMSMasterKeyID`. A repository in another account, an image outside ECR with a tag, or any denied read leaves the endpoint `N/A` naming the permission. A recorded value means an expected value is recorded: whether it was compared at load time is not returned by any API this check reads, and weights fetched by startup code, and models loaded on ECS, EKS or EC2, are not read. Inference components are listed per variant with `ListInferenceComponents`; only `InService` components hosted on the endpoint are judged, every entry of a multi-specification component is judged, and a component that returns no model name, image or artifact URL reads `N/A`.

---

## Amazon Bedrock Security Checks (57)

### BR-01: AWS IAM Least Privilege

- **Severity:** High
- **Description:** Identifies roles with AmazonBedrockFullAccess policy. A second finding, `Bedrock Wildcard Action Grant`, reads every customer-managed, inline and group policy on each cached role and user and fails an Allow that grants every Bedrock action (`bedrock:*` or an equivalent wildcard such as `bed*`) or that grants Bedrock through `NotAction` without excluding it. A bare `*` or `*:*` counts. AWS managed policies are left to the first finding. An identity whose permissions boundary allows no Bedrock action is not reported. A policy or group policy list that could not be read produces `N/A`, and the `Passed` row is then downgraded to `N/A`. A third finding, `Bedrock or Data Store Read and Write Merged in One Grant`, covers AIR-FND-IAM-09 over the `bedrock` namespace, and over the `s3`, `dynamodb` and `s3vectors` namespaces for an identity that is granted some Bedrock action. It reads every attached (AWS managed included), inline and group policy of every cached role and user, and fails a wildcard `Action` pattern (a bare `"*"`, `*:*` and a partial pattern among them) or a `NotAction` Allow that grants both a read and a write action on one resource type, as the [service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html) classifies them (the table is `iam_access_levels.json`, generated by `generate_iam_access_levels.py`). An explicit action list is never reported, because it separates read from write. An action counts only when no unconditioned `Resource: "*"` Deny removes it and the permissions boundary also allows it. A condition applies to the read and the write alike and is not read; the `Resource` entries are read only to drop resource types none of them can name, with a policy variable read as any value. Service control policies are not evaluated per principal, which can only make a row a false `Failed`, and each failing row says so. A policy that cannot be parsed produces `N/A` naming the principal. While the cache's `principal_errors` names a principal, each `Passed` row becomes `N/A` naming the unread principals; a cache without `principal_errors` (schema v1) keeps its verdict and says the errors were not recorded. A principal whose permissions boundary the cache could not read (a `permissions_boundary` stage in `principal_errors`) is not reported `Failed` by the wildcard or merged rows, because a boundary could remove the grant; the `N/A` row names it.

### BR-02: Amazon VPC Endpoint Configuration

- **Severity:** High
- **Description:** Lists interface endpoints for the five Bedrock surfaces (`bedrock`, `bedrock-runtime`, `bedrock-agent`, `bedrock-agent-runtime` and `bedrock-mantle`) across every VPC page, then reads each Lambda function, ECS service, SageMaker notebook instance and EC2 instance in the Region, resolves its execution, task, notebook or instance-profile role, and computes from the IAM cache which surfaces that role is granted (attached, inline and group policies, with a permissions boundary that denies an action removing it). The three AgentCore surfaces (`bedrock-agentcore`, `bedrock-agentcore-control` and `bedrock-agentcore.gateway`) count as surfaces for this leg only: a `bedrock-agentcore` action is placed on the data plane or control plane by its botocore model, and `bedrock-agentcore:InvokeGateway` on the Gateway endpoint. The `Bedrock Workload Private Connectivity` finding fails a workload outside a VPC, and a workload whose VPC has no private-DNS endpoint for a surface its role is granted. Endpoint presence alone is reported as `N/A` and no longer passes. An endpoint listing that fails is reported as not read. ECS services are listed on every page of every cluster (`ecs:ListClusters`, `ecs:ListServices`; a denied cluster list falls back to the default cluster and is named), described 10 at a time (`ecs:DescribeServices`), and placed in the VPC of each `awsvpc` subnet with the task role of their task definition (`ecs:DescribeTaskDefinition`). The service's own `roleArn` is not read as the task role. A service with no `awsvpc` subnets, or one that `ecs:DescribeServices` returns in its `failures` list, is reported as not read. Each notebook instance is described (`sagemaker:DescribeNotebookInstance`), and one with no `SubnetId` runs outside a VPC and fails. EKS pods, SageMaker endpoints, ECS tasks started outside a service, and private hosted zones shared from another VPC are not read, and the ceiling text says so. A workload whose role the cache does not hold, a collector error, or cache `principal_errors` downgrade the `Passed` row to `N/A`. Service control policies are not evaluated per principal. An endpoint policy counts as scoped only through a `Deny` on `bedrock:InvokeModel` with `Resource` `*`, no `NotResource`, and exactly one condition: a negated test on exact values of a principal or network scope key. A `Null` test, a second condition key, or a wildcard value is not credited. An `Allow` is scoped by a key only under a positive, non-`IfExists` test on exact values, and a principal with `*` or `?` in it is unbounded.

### BR-03: Marketplace Subscription Access

- **Severity:** Medium
- **Description:** Checks for overly permissive marketplace subscription access.

BR-01, BR-02, BR-03, BR-08, BR-10, and BR-21 depend on the shared IAM
permissions cache. If that prerequisite is missing, unreadable, or malformed,
each affected control is reported as informational `N/A`; an empty replacement
inventory is never treated as evidence of compliance.

### BR-04: Model Invocation Logging

- **Severity:** Medium
- **Description:** Checks invocation logging is enabled. The check is scoped by use, not by resources: a Region with no Bedrock resource is still judged when its CloudTrail event history holds an `InvokeModel`, `InvokeModelWithResponseStream`, `Converse` or `ConverseStream` call from `bedrock.amazonaws.com`, because on-demand inference creates no resource to list. Only a Region with neither is `N/A` as out of scope; when either read fails, the result is `N/A` and names the read that failed. Enabled logging is judged whatever the footprint. For S3 delivery, the retention leg credits only an enabled lifecycle rule whose filter covers `<keyPrefix>/AWSLogs/`, the root Bedrock writes under. A rule on another prefix, or one that also filters on tags or object size, is named and not credited. When the bucket has versioning `Enabled` or `Suspended`, a rule that expires noncurrent versions is also required, because expiring the current object leaves a noncurrent version behind. An unreadable versioning status is `N/A`, never a pass. The same lifecycle test runs on the CloudWatch large-data delivery bucket when it differs from the S3 destination, and on every bucket an enabled replication rule copies a log bucket to, because a replica keeps every prompt and response after the source expires them. An Object Lock default retention on a log bucket fails the retention leg, because S3 Lifecycle does not delete a version Object Lock retains, so the lifecycle period is not the period the record is kept. A log bucket with an enabled replication rule is `N/A` for the retention leg: S3 Lifecycle takes no action on an object whose replication status is `PENDING` or `FAILED`, that status is returned per object only by `HeadObject`, and the assessment role holds no `s3:GetObject` on log buckets. Each replica is still judged. The logging row that names the destinations states that it records the destinations only. AgentCore Memory event retention (`eventExpiryDuration`) is reported as an `N/A` row, `AgentCore Memory Event Retention`, that reads Partial, ceiling reached: AIR-ACR-MEM-07 and AIR-FND-DAT-08 set no maximum retention period, so no memory is judged and no retention threshold is assumed. Whether deletion has run, and legal holds on individual versions, are not read.

### BR-05: Guardrail Configuration

- **Severity:** High
- **Description:** Verifies guardrails are configured and enforced.

### BR-06: AWS CloudTrail Logging

- **Severity:** Medium
- **Description:** Validates AWS CloudTrail logging for Bedrock API calls on logging multi-region trails, judging every selector field. The management row credits a basic selector with `IncludeManagementEvents` and `ReadWriteType` `All` that does not exclude `bedrock.amazonaws.com`, or an advanced `eventCategory` `Management` selector with no field that drops Bedrock (`readOnly`, or an `eventSource` that leaves it out). `WriteOnly` is not credited because `InvokeModel` is a read-only management event. A `NetworkActivity` selector is not management coverage. The data-event rows credit a resource type only from a selector whose sole other field is `eventCategory` `Data`; a type named only beside `eventName`, `readOnly`, `resources.ARN` or any other field is reported as narrowed. The knowledge base row needs `AWS::Bedrock::KnowledgeBase` and enabled model invocation logging with `textDataDeliveryEnabled` `true`; a flag the API does not return is reported as unread. The inference row needs `AWS::Bedrock::Model`, `AWS::Bedrock::AsyncInvoke`, `AWS::Bedrock::AgentAlias` and `AWS::Bedrock::InlineAgent`. `Bedrock Inference Forensic Record` needs invocation logging with `textDataDeliveryEnabled` and every destination under an enabled customer managed KMS key. A trail that cannot be read makes a row without coverage `N/A`. The Region's CloudTrail Lake event data stores are listed (`ListEventDataStores`, every page) and each is read with `cloudtrail:GetEventDataStore`. A store counts only with `Status` `ENABLED`, and its `AdvancedEventSelectors` are judged by the same rules as a trail's, so a store can credit the management row and each data-event row, and a narrowed store selector is named and not credited. A store that could not be read, and an unlisted store list, turn a gap on those rows into `N/A` naming the action. A gap that no read store closes fails. When no store is homed in the Region, the `Failed` row says a multi-Region store homed elsewhere would be named in that Region's row. The check is scoped by use as BR-04 is. Not read: the `bedrock-mantle` endpoint's CloudTrail events, RetrieveAndGenerate citations, and Athena centralization.

### BR-07: Prompt Management

- **Severity:** Low
- **Description:** Reports whether Prompt Management is in use, then judges the prompts it holds. A prompt with only a DRAFT fails `Bedrock Prompt Production Version` (Medium). `Bedrock Prompt Version Encryption` reads `GetPrompt(promptVersion=N)` for every numbered version, since any version stays invocable by its ARN, and fails a prompt when any version reports no `customerEncryptionKeyArn`, or names a key that `kms:DescribeKey` does not report as `KeyManager` `CUSTOMER` and `KeyState` `Enabled`; an unread version or key is `N/A` naming the version. The flow leg walks the prompt nodes of each flow's working draft and of every flow version an alias routes to, including nodes inside DoWhile loops, and fails a `promptArn` with no version suffix and a prompt node that defines its prompt inline. The flow leg runs whether or not the Region holds a Prompt management prompt. A flow, alias list or flow version that cannot be read is `N/A`. `Bedrock Prompt Change Permission Scope` fails each role or user whose identity policies allow `bedrock:UpdatePrompt` or `bedrock:CreatePromptVersion` on a `Resource` with a `*` or `?` in any segment, or through `NotResource`; service control policies are not evaluated per principal. The `Bedrock Prompt Variants Check` row is an Informational `N/A` advisory outside these verdicts. Prompts held in application code, and the split between the roles that release a version and the roles that call `RenderPrompt`, are not judged.

### BR-08: Agent AWS IAM Configuration

- **Severity:** Medium
- **Description:** Checks agent execution role permissions.

### BR-09: Knowledge Base Encryption

- **Severity:** High
- **Description:** Checks knowledge base encryption settings.

### BR-10: Guardrail AWS IAM Enforcement

- **Severity:** Medium
- **Description:** Verifies guardrails are enforced through AWS IAM conditions. Each role or user that may invoke a model must name an approved guardrail on every invoke grant, or be covered by a central mechanism in the Region: an account-enforced guardrail configuration scoped to all models with comprehensive guarding, a configuration for the Region in the effective Organizations Bedrock policy at a non-`DRAFT` version, or, in a member account, an attached service control policy denying both invoke actions without an approved `bedrock:GuardrailIdentifier` on a `Resource` that covers every invoke resource type in the service authorization reference. A central source that cannot be read is named and keeps the identity failed. Each guardrail version that may be named, directly or centrally, must apply a content filter with strength `LOW`, `MEDIUM` or `HIGH` and action `BLOCK` to the input and to the output; denied topics, word filters, sensitive information filters, contextual grounding and automated reasoning checks do not count toward either direction. Service control policies are not evaluated per principal.

### BR-11: Custom Model Encryption

- **Severity:** High
- **Description:** Judges every custom model's key and every bucket its customization data sits in. The key is `GetCustomModel.modelKmsKeyArn`, or the customization job's `outputModelKmsKeyArn` when the model record names none, and it passes only when `kms:DescribeKey` reports `KeyManager` `CUSTOMER` and `KeyState` `Enabled`. A model with no key anywhere, an AWS managed key, or a key in any state other than Enabled fails (Medium). A model record or a customization job that cannot be read, or a key that cannot be described, is `N/A` naming the model and the failed call, so a model nobody read never sits under the Passed summary, which counts models as "N of M". A second finding, `Bedrock Customization Data Bucket Encryption`, reads the default encryption of each bucket named by the model's `trainingDataConfig.s3Uri`, `trainingDataConfig.invocationLogsConfig.invocationLogSource.s3Uri`, `validationDataConfig.validators[].s3Uri` and `outputDataConfig.s3Uri`, once per bucket. SSE-S3, `aws:kms` with no key id (served with `aws/s3`), no default encryption configuration, and a key that fails the same DescribeKey test all fail (High); a bucket or key that cannot be read is `N/A`.

### BR-12: Invocation Log Encryption

- **Severity:** Medium
- **Description:** Judges the key on every destination invocation logs are written to: the S3 bucket, the large-data delivery bucket when it differs, and the CloudWatch Logs group. A bucket passes only when its default encryption is `aws:kms` or `aws:kms:dsse` with a key that `kms:DescribeKey` reports as `KeyManager` `CUSTOMER` and `KeyState` `Enabled`. SSE-S3, the `aws/s3` managed key, and `aws:kms` with no key id (which S3 serves with `aws/s3`) fail. A bucket whose `GetBucketEncryption` returns `ServerSideEncryptionConfigurationNotFoundError` fails, and the text says whether S3 applied SSE-S3 to each object was not read. The log group finding, `Bedrock Invocation Log Group Encryption`, fails when the group has no `kmsKeyId` or its key is not an enabled customer managed key. A key that cannot be described, including a key in another account, is `N/A`. A second finding, `Bedrock Invocation Log Group Deletion Protection`, reads `deletionProtectionEnabled` on the CloudWatch Logs group that receives invocation logs and fails when it is not `true`; `DescribeLogGroups` omits the field on a group that never had it set, so an absent value reads as off. No CloudWatch delivery, or a group that is not returned to this account, is `N/A`.

### BR-13: Flows Guardrails

- **Severity:** Medium
- **Description:** Validates Bedrock Flows have guardrails attached.

### BR-14: Stale Bedrock Access

- **Severity:** Medium
- **Description:** Detects principals with Bedrock permissions that have not used the service recently, using IAM service-last-accessed data. As an IAM-global check, it runs once per execution and is tagged with the `Global` region in multi-region scans.

### BR-15: Cross-Account Guardrails Enforcement

- **Severity:** High
- **Type:** Global (runs once)
- **Description:** Verifies organization-level guardrails are configured using AWS Organizations Amazon Bedrock policies (the `BEDROCK_POLICY` policy type) for centralized safety control enforcement across all accounts. Checks if running in the AWS Organizations management account, validates the Bedrock policy type is enabled at the organization root, and verifies that Bedrock policies are attached.

### BR-16: Guardrail Tier Validation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies guardrails use the `STANDARD` content-filter tier (vs the `CLASSIC` tier) for enhanced protection and broader language support. Lists all guardrails in the region and inspects each guardrail's `contentPolicy.tier.tierName`. The STANDARD tier requires cross-Region inference.

### BR-17: Custom Model Customer-Managed KMS Encryption

- **Severity:** High
- **Type:** Regional
- **Description:** Lists every custom model and reads `GetCustomModel.modelKmsKeyArn`. No key fails as the AWS owned key. A named key passes only when `kms:DescribeKey` reports it `KeyManager` `CUSTOMER` and `KeyState` `Enabled`; an AWS managed or disabled key fails. A model whose details or key cannot be read is `N/A` naming the model and the read that failed.

### BR-18: Model Evaluation Implementation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Checks if model evaluation jobs exist to assess safety metrics (toxicity, accuracy, semantic robustness) before production deployment. Lists all model evaluation jobs, identifies recent evaluations (completed within 30 days), and analyzes evaluation configurations for safety metrics.

### BR-19: Prompt Flow Validation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies Bedrock Agents prompt flows are validated using `validate_flow_definition` API before deployment to prevent misconfigured flows. Lists all flows in the region, checks for validation records or status, identifies unvalidated flows, and reports flows deployed without validation.

### BR-20: Knowledge Base Encryption Enhancement

- **Severity:** High
- **Type:** Regional
- **Description:** Extends existing BR-09 to verify Knowledge Base encryption uses customer-managed KMS keys. Uses the authoritative knowledge base `type` (`VECTOR | KENDRA | SQL | MANAGED`) to decide how to assess each KB: for `MANAGED` knowledge bases it reads `knowledgeBaseConfiguration.managedKnowledgeBaseConfiguration.serverSideEncryptionConfiguration.kmsKeyArn` and passes only when `kms:DescribeKey` reports the key customer managed and Enabled. An S3 Vectors bucket or index key is judged the same way, and an undescribable one is `N/A`. For a custom vector store it follows the store to its own resource: an OpenSearch Serverless collection through `aoss:BatchGetCollection` (`kmsKeyArn`), an Aurora cluster through `rds:DescribeDBClusters` (`StorageEncrypted` and `KmsKeyId`), an OpenSearch domain through `es:DescribeDomain` (`EncryptionAtRestOptions`), and a Neptune Analytics graph through `neptune-graph:GetGraph` (`kmsKeyIdentifier`), and judges the key it finds with the same DescribeKey test. `aoss:BatchGetCollection` has no resource type, so the role holds it on `Resource: '*'`; a collection it cannot read is `N/A` naming the action. For an OpenSearch Serverless collection the check also lists every data access policy (`aoss:ListAccessPolicies`, every page) and reads each one (`aoss:GetAccessPolicy`, both on `Resource: '*'` for want of a resource type), because OpenSearch Serverless does not check a caller's permission on the collection's KMS key. Data policies are additive, so each index rule whose `Resource` pattern matches `index/<collection>/<vectorIndexName>` is judged: a wildcard in the collection segment (`index/*/*`, `index/kb*/*`) reaches other collections and fails, and so does a principal with a wildcard. A policy that could not be read or parsed, or a knowledge base with no `vectorIndexName`, is `N/A`. Rules on other resource types, such as `collection`, are not counted. For Pinecone, MongoDB Atlas and Redis Enterprise Cloud the vector data sits with the provider; the check reads the credentials secret with `secretsmanager:DescribeSecret` and fails a secret with no `KmsKeyId` (the `aws/secretsmanager` key), and otherwise reports the store `N/A` because the provider's key cannot be judged. `KENDRA` and `SQL` knowledge bases are `N/A`. A knowledge base whose `GetKnowledgeBase` call fails is `N/A` under `Knowledge Base Customer-Managed KMS Encryption Review`. Each data source's `serverSideEncryptionConfiguration.kmsKeyArn`, the key for transient data during ingestion, is judged under `Knowledge Base Data Source Transient Data Key`: no key fails, and each key is described once. If a `MANAGED` KB's encryption block is missing from the API response (deployed botocore older than 1.43.32, which silently drops the unmodeled field), the KB is reported as N/A "indeterminate" rather than a false-positive failure.
- **S3 Vectors:** An `S3_VECTORS` storage configuration is the one custom store this check assesses instead of deferring, because both halves of the control are readable one ARN hop away. It follows `storageConfiguration.s3VectorsConfiguration.vectorBucketArn` and calls `s3vectors:GetVectorBucket` (fails unless `encryptionConfiguration.sseType` is `aws:kms` with a `kmsKeyArn`, so SSE-S3 `AES256` fails, the same bar as every other storage type) and `s3vectors:GetVectorBucketPolicy`. The policy passes only when it holds no Allow whose principal is a wildcard or `NotPrincipal` unless an exact-valued positive condition on a principal key bounds it, and holds a Deny with `Principal` `*` covering `s3vectors:QueryVectors`, `GetVectors` and `ListVectors` on the index, whose every condition is a negated principal-key operator with exact values and no `IfExists`. An attached policy with no such Deny fails, as does no policy at all (`NotFoundException` is an answer about the workload, not an assessment gap). Which principals the Deny's exception list names is not judged. A third leg calls `s3vectors:GetIndex` on the one index the knowledge base names, by `indexArn` when the API returns one and otherwise by the bucket name plus `indexName`: an index created with its own `encryptionConfiguration` overrides the bucket's default for every vector it holds, so an `aws:kms` bucket holding an `AES256` index is Failed. An index that carries no `encryptionConfiguration` of its own inherits the bucket's and is not held against the knowledge base. Only the index that knowledge base names is read, because a vector bucket can hold indexes belonging to other workloads. The client is built for the region in the bucket ARN, which need not be the scanned region. One finding per knowledge base. `AccessDenied` on any of the three calls is reported as N/A naming the missing action, so a permission gap stays visible, and a knowledge base reporting a `vectorBucketArn` but neither `indexArn` nor `indexName` is N/A for the same reason: an index-level override cannot be ruled out.

### BR-21: Agent Action Group IAM Least Privilege

- **Severity:** High
- **Type:** Regional
- **Description:** Extends existing BR-08 to specifically check if Bedrock Agent action groups use scoped Lambda execution roles with minimal permissions. Enumerates agents and their action groups, retrieves Lambda execution roles for each action group, analyzes IAM policies for overly broad permissions (AdministratorAccess, FullAccess, Resource: "*"), and verifies principle of least privilege.

### BR-22: Model Invocation Throttling Limits

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies service quotas are configured for model invocation throttling to prevent abuse/DoS and control costs. Queries Service Quotas for Bedrock, checks if custom limits are set for on-demand model invocation TPM (tokens per minute), provisioned throughput limits, and concurrent requests. Reports accounts relying solely on default quotas.

### BR-23: Guardrail Content Filter Coverage

- **Severity:** High
- **Type:** Regional
- **Description:** Extends existing BR-05 to verify guardrails have ALL content filters enabled (hate, insults, sexual, violence) with appropriate thresholds. For each guardrail, checks content filter configuration for all four filter types, verifies filter thresholds are configured, and reports missing or misconfigured filters.

### BR-24: Automated Reasoning Policy Implementation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Checks if Automated Reasoning policies are configured on guardrails for formal verification of model responses. Enumerates guardrails, checks for Automated Reasoning policy configuration, validates policy syntax and enabled state, and reports guardrails without formal verification capability.

### BR-25: RAG Evaluation Jobs

- **Severity:** Low
- **Type:** Regional
- **Description:** Verifies RAG applications have evaluation jobs configured to assess context relevance, response correctness, and prevent hallucinations. Lists Knowledge Bases, checks for associated RAG evaluation jobs for each KB, verifies evaluation metrics include context relevance, response correctness, faithfulness, and harmfulness checks. Reports KBs without evaluation jobs.

### BR-26: Guardrail Sensitive Information Filter

- **Severity:** High
- **Type:** Regional
- **Description:** Extends BR-23 (which covers the harmful-content filters). Reads `GetGuardrail.sensitiveInformationPolicy` and judges each PII entity and regex by the action it takes on each side: `inputAction` or `outputAction`, falling back to `action`, with `inputEnabled` or `outputEnabled` false meaning the side is off. A guardrail passes when some entity or regex blocks or masks on the input and on the output, each side that sets an entity also sets `AWS_ACCESS_KEY`, `AWS_SECRET_KEY` and `PASSWORD` to `BLOCK` or `ANONYMIZE` on that side, and a custom regex blocks or masks on the output for secrets, credentials and internal identifiers the built-in types do not name. Detect-only (`NONE`) entities are named. The regex patterns are not evaluated, and the filter does not reach toolUse input, toolResult content or a toolSpec. The same judgment runs on each deployed guardrail version: every version an agent (DRAFT and each version an alias routes to), a flow Prompt or KnowledgeBase node (DRAFT and each alias-routed version) an account-enforced configuration, the effective Organizations Bedrock policy configuration for the Region, or a `bedrock:GuardrailIdentifier` condition on an invoke action applies is read with `GetGuardrail` at that version, including a guardrail ARN in another Region. Condition values are read from role, user and group policies and permissions boundaries in the IAM permissions cache and, in a member account, from service control policies attached to the root, an OU in the account's path or the account. A condition that names a guardrail without a version joins every version `ListGuardrails` returns plus DRAFT, a value in another Region is left to that Region's run, and a wildcard value is reported as not enumerated. A version that could not be read, an agent, flow or enforced-configuration list that could not be read, a wildcard condition value, a principal the IAM cache recorded an error for, a version 1 cache (which recorded no principal errors) or an unavailable cache keeps the deployed `Passed` row at `N/A`. A guardrail passed per request to InvokeModel, Converse, ApplyGuardrail or RetrieveAndGenerate is recorded by no configuration API and is not judged, and neither is guardContent tagging. The Knowledge Base PII Redaction Before Model rows fail a knowledge base that ingests a source with no redaction step and is reached through no guardrail that sets a PII entity type to `BLOCK` or `ANONYMIZE`, or through an agent or node whose guardrail sets none. For each knowledge base, every data source is read with `GetDataSource` for a `POST_CHUNKING` transformation Lambda, and every agent version (DRAFT and each alias-routed version, through `ListAgentKnowledgeBases`, skipping `DISABLED` links) and flow KnowledgeBase node (DRAFT and each alias-routed version) that retrieves from it is paired with the guardrail version it applies. An S3 source is also credited when a `COMPLETED` Comprehend `ONLY_REDACTION` job writes to its bucket at a prefix holding every inclusion prefix the source ingests. `comprehend:ListPiiEntitiesDetectionJobs` has no resource type and is not granted by the template, so until it is granted an S3 source with no transformation step reads `N/A` naming that read. It never passes a knowledge base: a transformation Lambda's logic is not read, a knowledge base carries no guardrail of its own, and a direct RetrieveAndGenerate caller supplies its guardrail per request, so a knowledge base with a screening step is `N/A` and named as not failed. An account-enforced guardrail that meets the same test clears every knowledge base only when the configuration applies to every model and every message: a configuration whose `includedModels` does not name `ALL`, that excludes models, that guards system or message content `SELECTIVE`, or that sets `inputTags` `HONOR` is named as not credited. An agent, flow, guardrail or enforced-configuration read that failed turns a would-be `Failed` into `N/A` naming what was not read.

### BR-27: Guardrail Contextual Grounding Check

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies guardrails enable contextual grounding checks to detect hallucinated (ungrounded) and off-topic model responses. Reads `GetGuardrail.contextualGroundingPolicy.filters` and fails a guardrail unless both GROUNDING and RELEVANCE block with a threshold above 0 and no higher than 0.99. Each deployed row names the Automated Reasoning policies and confidence threshold the version applies, or says none is attached. Whether callers supply the grounding_source and query qualifiers, and any scored response, are not recorded by a configuration API, and RetrieveAndGenerate passes no grounding source. The same judgment runs on each deployed guardrail version: every version an agent (DRAFT and each version an alias routes to), a flow Prompt or KnowledgeBase node (DRAFT and each alias-routed version) an account-enforced configuration, the effective Organizations Bedrock policy configuration for the Region, or a `bedrock:GuardrailIdentifier` condition on an invoke action applies is read with `GetGuardrail` at that version, including a guardrail ARN in another Region. Condition values are read from role, user and group policies and permissions boundaries in the IAM permissions cache and, in a member account, from service control policies attached to the root, an OU in the account's path or the account. A condition that names a guardrail without a version joins every version `ListGuardrails` returns plus DRAFT, a value in another Region is left to that Region's run, and a wildcard value is reported as not enumerated. A version that could not be read, an agent, flow or enforced-configuration list that could not be read, a wildcard condition value, a principal the IAM cache recorded an error for, a version 1 cache (which recorded no principal errors) or an unavailable cache keeps the deployed `Passed` row at `N/A`. A guardrail passed per request to InvokeModel, Converse, ApplyGuardrail or RetrieveAndGenerate is recorded by no configuration API and is not judged, and neither is guardContent tagging. Complements BR-25 (RAG evaluation) with a runtime control.

### BR-28: Agent Guardrail Association

- **Severity:** High
- **Type:** Regional
- **Description:** Verifies each Bedrock Agent has a guardrail associated so agent interactions are subject to content filtering, PII protection, and denied-topic controls. Reads `guardrailConfiguration` from the agent summaries returned by `ListAgents` and reports agents with no guardrail attached.

### BR-29: Agent Idle Session TTL

- **Severity:** Low
- **Type:** Regional
- **Description:** Verifies Bedrock Agents do not use an excessively long idle session TTL, which widens the window for session and conversation-context reuse. Reads `GetAgent.idleSessionTTLInSeconds` and reports agents whose TTL exceeds a conservative ceiling (3600 seconds).

### BR-30: Imported Model Customer-Managed KMS Encryption

- **Severity:** High
- **Type:** Regional
- **Description:** Lists imported models and reads `GetImportedModel.modelKmsKeyArn`. No key fails as the AWS owned key. A named key passes only when `kms:DescribeKey` reports it customer managed and Enabled; an AWS managed or disabled key fails, and a model or key that cannot be read is `N/A`.

### BR-31: Batch Inference Output Encryption

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies batch inference (model invocation) jobs encrypt their S3 output with a customer-managed KMS key. Reads `outputDataConfig.s3OutputDataConfig.s3EncryptionKeyId` from the job summaries returned by `ListModelInvocationJobs` and reports jobs without a customer-managed output key.

### BR-32: CloudWatch Alarms on Bedrock Metrics

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies CloudWatch alarms that reach an action exist on Amazon Bedrock runtime metrics (the `AWS/Bedrock` namespace) to detect abuse, denial-of-wallet, sustained throttling, and content-filter spikes. Uses `DescribeAlarms` for metric and composite alarms and matches alarms that target the `AWS/Bedrock` namespace in the alarm or in a metric-math expression. An alarm counts only when `ActionsEnabled` is true and `AlarmActions` names a target, or when an acting composite alarm's rule reads it as `ALARM(...)`. DescribeAlarms returns composite alarms only to a `cloudwatch:DescribeAlarms` grant on `*`, so the assessment role holds it there. The runtime row is assessed only in regions that have Bedrock resources. A second row, Guardrail Intervention Monitoring Signal, is judged wherever a guardrail applies: a guardrail in the Region, a version an agent, flow node or account-enforced configuration applies, or an `ApplyGuardrail` call in the Region's event history. It passes on an acting alarm on `AWS/Bedrock/Guardrails` `InvocationsIntervened`, or on a metric filter over the invocation log group whose pattern selects `INTERVENED` (no `!=` and no `-` exclusion) and whose emitted metric an acting alarm evaluates. An alarm counts only when one intervention raises it: a static `Threshold` with `GreaterThanThreshold` below 1 or `GreaterThanOrEqualToThreshold` at or below 1, statistic `Sum`, `SampleCount` or `Maximum`, and one breaching datapoint (`DatapointsToAlarm`, or `EvaluationPeriods` when that is absent). An alarm that fails that test, or that carries an `Operation`, `GuardrailContentSource` or `GuardrailPolicyType` dimension and so sees one slice of interventions, is named as not credited. An alarm on one `GuardrailArn` or `GuardrailVersion`, or a metric-math alarm, is not judged and keeps the row at `N/A`. Whether CloudWatch publishes `InvocationsIntervened` with no dimension is not confirmed from a configuration API. A metric filter alone does not pass when `ApplyGuardrail` is called, because invocation logging does not record those calls, and it reports `N/A` when the event history could not be read. Subscription filters on the invocation log group are reported as forwarding evidence and do not change the status.

### BR-33: Amazon Inspector Lambda Code Scanning

- **Severity:** Medium
- **Type:** Regional
- **Description:** When in-scope Lambda functions exist in the region, verifies Amazon Inspector Lambda standard scanning (`lambda`) and Lambda code scanning (`lambdaCode`) are both enabled so those functions and their dependencies are scanned for vulnerable packages and hardcoded secrets. A function is in scope when its name, ARN, description, handler, role or environment names Bedrock, or when the IAM cache shows its execution role granted a Bedrock or AgentCore action (attached, inline and group policies, with the permissions boundary applied). Calls `lambda:ListFunctions` for scoping, `inspector2:BatchGetAccountStatus` for Inspector status, and `lambda:GetFunction` per in-scope function for its tags. Reports `Failed` when either `resourceState.lambda.status` or `resourceState.lambdaCode.status` is not `ENABLED`; that row also reads `inspector2:ListCoverage` and names each in-scope function without `ACTIVE` coverage, with its reason (for example `SCAN_ELIGIBILITY_EXPIRED`), so a disabled code scan and an expired eligibility are both named, and, with both enabled, for each in-scope function that Inspector does not scan: one with a `KMSKeyArn` (a customer managed key) or one tagged `InspectorExclusion=LambdaStandardScanning` (key and value compared without case). GetFunction returns tags only to a caller allowed `lambda:ListTags`, which the scan role holds; a function whose tags were still withheld, or whose role the IAM cache does not hold, is named in an `N/A` row and the `Passed` row becomes `N/A`; cache `principal_errors` do the same. Every page of `inspector2:ListCoverage` for `AWS_LAMBDA_FUNCTION` is read, and each zip function not already excluded fails unless its `$LATEST` record for both the `PACKAGE` and `CODE` scan types is `ACTIVE`; a missing record or an inactive one is named with its reason, so a function idle for 90 days or on an unsupported runtime fails. Container-image functions are left to AC-50. An unread coverage list makes the `Passed` row `N/A`. The rows name each `ENABLED` EventBridge rule on the default bus whose pattern matches source `aws.inspector2` (`events:ListRules`), or say none does; the targets of a rule are not read (`events:ListTargetsByRule` is not granted), and no API records whether a deployment pipeline blocks on a finding, so the row states that ceiling. No in-scope Lambda functions, access denied, and region-unavailable states resolve to `N/A`.

### BR-34: Guardrail Prompt Attack Filter

- **Severity:** High
- **Description:** Requires each guardrail to have a preventive `PROMPT_ATTACK` input filter with `inputEnabled=true`, `inputAction=BLOCK` and `inputStrength=HIGH` on the STANDARD content-filter tier. A CLASSIC tier fails because prompt-leakage detection is STANDARD only, and a tier `GetGuardrail` does not report is `N/A`. The same judgment runs on each deployed guardrail version: every version an agent (DRAFT and each version an alias routes to), a flow Prompt or KnowledgeBase node (DRAFT and each alias-routed version) an account-enforced configuration, the effective Organizations Bedrock policy configuration for the Region, or a `bedrock:GuardrailIdentifier` condition on an invoke action applies is read with `GetGuardrail` at that version, including a guardrail ARN in another Region. Condition values are read from role, user and group policies and permissions boundaries in the IAM permissions cache and, in a member account, from service control policies attached to the root, an OU in the account's path or the account. A condition that names a guardrail without a version joins every version `ListGuardrails` returns plus DRAFT, a value in another Region is left to that Region's run, and a wildcard value is reported as not enumerated. A version that could not be read, an agent, flow or enforced-configuration list that could not be read, a wildcard condition value, a principal the IAM cache recorded an error for, a version 1 cache (which recorded no principal errors) or an unavailable cache keeps the deployed `Passed` row at `N/A`. A guardrail passed per request to InvokeModel, Converse, ApplyGuardrail or RetrieveAndGenerate is recorded by no configuration API and is not judged, and neither is guardContent tagging. The Knowledge Base Ingestion Prompt Attack Screening rows fail a knowledge base that ingests a source with no transformation step and is reached through no guardrail whose `PROMPT_ATTACK` input filter blocks at HIGH strength (the deployed-version test above, with an unreported tier credited), or through an agent or node with no such guardrail. For each knowledge base, every data source is read with `GetDataSource` for a `POST_CHUNKING` transformation Lambda, and every agent version (DRAFT and each alias-routed version, through `ListAgentKnowledgeBases`, skipping `DISABLED` links) and flow KnowledgeBase node (DRAFT and each alias-routed version) that retrieves from it is paired with the guardrail version it applies. It never passes a knowledge base: a transformation Lambda's logic is not read, a knowledge base carries no guardrail of its own, and a direct RetrieveAndGenerate caller supplies its guardrail per request, so a knowledge base with a screening step is `N/A` and named as not failed. An account-enforced guardrail that meets the same test clears every knowledge base only when the configuration applies to every model and every message: a configuration whose `includedModels` does not name `ALL`, that excludes models, that guards system or message content `SELECTIVE`, or that sets `inputTags` `HONOR` is named as not credited. An agent, flow, guardrail or enforced-configuration read that failed turns a would-be `Failed` into `N/A` naming what was not read. The Guardrail Intervention Logging row reads `GetModelInvocationLoggingConfiguration` in each Region: it fails when invocation logging has no S3 or CloudWatch Logs destination, or when `textDataDeliveryEnabled` is not `true`, because the text output body (a Converse `stopReason` of `guardrail_intervened`) is the record of an intervention. An absent flag or an unread configuration is `N/A`. A `Passed` row does not say that any call carried a guardrail, and only calls through the `bedrock-runtime` endpoint are logged.

### BR-35: Guardrail Image Content Filter Coverage

- **Severity:** Informational
- **Description:** Uses `HATE`, `INSULTS`, `SEXUAL`, and `VIOLENCE` as the cross-region image-filter baseline. Because AWS documents `MISCONDUCT` image filtering as region-dependent, its absence is not reported as a gap, but a configured `MISCONDUCT` filter is reported when its input or output modalities omit `IMAGE`. Complete coverage is `Passed`; advisory gaps are `N/A`/Informational because the scanner cannot infer whether protected applications accept or produce images.

### BR-36: Application Inference Profile Governance

- **Severity:** Low
- **Description:** Lists application inference profiles and reports completely untagged profiles. Organization-specific required tag keys can be enforced outside the default baseline.

### BR-37: Bedrock Account Data Retention

- **Severity:** High for the regional mode, Medium for the service control policy
- **Description:** Passes the regional `GetAccountDataRetention` mode only when it is `none`; `default`, `inherit` and `provider_data_share` fail. A second, organization-wide row passes only when attached service control policies Deny `bedrock:PutAccountDataRetention` on `StringNotEquals bedrock:DataRetentionMode` and `bedrock-mantle:PutAccountDataRetention`, `CreateProject` and `UpdateProject` on `StringNotEquals bedrock-mantle:DataRetentionMode`, each with `none` as the only approved value. The bedrock-mantle account mode, its project overrides and per-model `allowed_modes` are not read because botocore has no bedrock-mantle client. The `RequireBedrockZeroDataRetention` parameter is no longer read.

### BR-38: Automated Reasoning Policy CMK Encryption

- **Severity:** Medium
- **Description:** Deduplicates Automated Reasoning policy summaries and judges each policy's `kmsKeyArn` with `kms:DescribeKey`: no key fails, a key that is not customer managed and Enabled fails, and a key that cannot be described is `N/A`.

### BR-39: Marketplace Model Endpoint VPC Configuration

- **Severity:** High
- **Description:** Requires SageMaker-backed Bedrock Marketplace endpoint configurations to include non-empty VPC subnet and security-group lists. It also resolves the effective route table of each named subnet (its explicit association, else the VPC main table) and fails a subnet whose table routes to an internet gateway. A named subnet that is not present in the Region is reported `N/A` by id, and the other subnets are still judged. Every named subnet is described, 50 per `DescribeSubnets` request; there is no cap on how many are resolved.

### BR-40: Marketplace Model Endpoint CMK Encryption

- **Severity:** Medium by default
- **Description:** Resolves the Marketplace endpoint `kmsEncryptionKey` with `kms:DescribeKey` and requires `KeyMetadata.KeyManager` to be `CUSTOMER`; AWS-managed keys do not pass. The `RequireMarketplaceEndpointCMK` deployment parameter defaults to `true` (`REQUIRE_MARKETPLACE_ENDPOINT_CMK` in the Lambda). Set it to `false` to make a missing or AWS-managed key an `N/A`/Informational hardening advisory rather than a failure. An inconclusive KMS lookup is always `N/A`/Informational.

### BR-41: Central Guardrail Enforcement

- **Severity:** High
- **Description:** Requires a published guardrail to apply to every model the account can invoke. Three independent legs satisfy it: an account-enforced guardrail configuration whose model and content scope covers all models, an attached Organizations Bedrock policy naming a non-`DRAFT` guardrail version, or a service control policy denying invocation unless an approved `bedrock:GuardrailIdentifier` is supplied. `ListEnforcedGuardrailsConfiguration` is the leg that runs from any account, and its `owner` field enumerates `ACCOUNT` alone, so a configuration inherited from an Organizations policy never appears in it; an unreadable organization view therefore produces `N/A` instead of being reported as an absence. BR-15 reads the same API but decides on how many configurations exist, while this check reads the model and content scope inside each one. A configuration with `inputTags` `HONOR` fails, since a caller choosing input tags chooses which content is evaluated. The Organizations leg reads each configuration under `bedrock.guardrail_inference.<region>` of the effective policy, credits it only in its own Region, fails a `DRAFT` or missing version, and fails a configuration whose `model_enforcement` names models or excludes any, or whose `selective_content_guarding` is `SELECTIVE`; an empty `included_models` covers all models. A policy that names a guardrail outside that layout is `N/A`. The service control policy leg is judged per Region and credits a Deny only when its `Resource` covers every invoke resource type, so a Deny on `foundation-model/*` alone fails. When the Bedrock policy is the only mechanism in a Region and whether members can apply its guardrail was not read, the enforcement row is `N/A`.

### BR-42: Foundation Model Invocation Allow-List

- **Severity:** High
- **Description:** Requires identity policies to scope `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` to named foundation model or inference-profile ARNs. Only Allow statements that cover an invoke action are judged, so a policy that never grants invocation is not counted against this control. An unscoped resource with no `bedrock:ModelArn` condition fails, because every model available in the account can then be invoked. An unscoped resource carrying a `bedrock:ModelArn` condition also fails for the streaming action, which does not support that condition key. A resource is unscoped when it is `*`, ends in `/*` or `:*`, or is a Bedrock ARN pattern whose resource segment ends in `*` and matches `foundation-model/` or `inference-profile/` followed by any model ID, such as `arn:aws:bedrock:*::foundation-model*` or `arn:aws:bedrock:::foundation-model/?*`, in any Region, account or partition. A family pattern such as `foundation-model/anthropic.*` is not unscoped. An identity `Deny` outside a named model list scopes the grant only when every list value names one model or profile ID with no wildcard and the statement carries no other condition key.

### BR-43: Region Invocation Control

- **Severity:** Medium
- **Description:** Reads two halves of cross-Region invocation, because neither answers the other. Service control policies conditioned on `aws:RequestedRegion` bound the Region a request is sent to, and the inference profiles the account can route through determine where the inference is then served. A global profile call presents the literal `unspecified` for that condition key, so a Region allow-list bounds a global profile only when it excludes `unspecified`. A direct invocation bounded by an SCP alongside an unbounded global profile is reported as a failure. A second, organization-wide finding, `Bedrock Approved Model Control`, requires a service control policy `Deny` on `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` outside a named list of foundation-model or inference-profile ARNs, written either as `NotResource` or as a negated condition. A `Deny` written with `NotAction` covers every action it does not name. The Region leg covers every action that sends a prompt to a model: `InvokeModel`, `InvokeModelWithResponseStream`, `CreateModelInvocationJob`, `InvokeAgent`, `InvokeInlineAgent`, `InvokeFlow`, `RetrieveAndGenerate` and `bedrock-agentcore:InvokeAgentRuntime`, and a list missing any of them fails and names it. An `aws:PrincipalArn` exemption is credited only when its role or user name segment has no wildcard; a wildcard partition or account segment is tolerated because an SCP governs this account's principals only. An allow-list value matching every Region, such as `*-*`, is no list. A `NotResource` on the Region `Deny` narrows it only when a value names the service of a covered action. When the allow-list would pass but `ListInferenceProfiles` failed in a Region, the row is `N/A` naming `bedrock:ListInferenceProfiles`. A list written as a wildcard over every model counts as no list. A list is not credited, and is named as `Not credited` in the text, when any value has a wildcard in the model or profile ID (the Region and account segments may be wildcards, because an SCP spans accounts) or when the statement requires a second condition key, since it then denies only the requests that meet that test too, and a list that covers only one of the two actions fails because the other can invoke any model. Which models belong on the list is the customer's decision and is not judged. Batch inference jobs are not read. An unreadable organization view is `N/A`.

### BR-44: Marketplace Model Subscription Control

- **Severity:** High
- **Description:** Requires an `aws-marketplace:ProductId` condition to restrict `aws-marketplace:Subscribe` to approved products. An Allow statement granting the action with no product condition fails. A Deny that names approved products positively is reported as failing open, because a product the statement does not name is not denied; only an Allow carrying the product condition, or a Deny with a negated or `Null` test, restricts the set of subscribable models. A `Deny` on the action over `Resource` `*` with no condition, in an identity policy or a service control policy, removes the grant for that action only. `aws-marketplace:ViewSubscriptions` is a list action and is not judged.

### BR-45: API Key Governance

- **Severity:** High
- **Description:** Two findings. `Bedrock API Key Inventory` lists the `bedrock.amazonaws.com` service-specific credentials in the account. `Bedrock API Key Age And Token Type Control` passes only when both legs hold: a `Deny` capping `iam:ServiceSpecificCredentialAgeDays` at 90 days on `iam:CreateServiceSpecificCredential`, and a `Deny` on the `LONG_TERM` bearer token type on both `bedrock:CallWithBearerToken` and `bedrock-mantle:CallWithBearerToken`, each with its own key. Either leg alone fails and names the missing one. The age cap is read from service control policies and, failing that, from the identity policies and permissions boundary of every cached principal granted `iam:CreateServiceSpecificCredential`; the identity-policy cap is credited only when every such principal carries one, and the text says it binds those principals only. No cached principal holding the grant is not a cap. Cache `principal_errors` make an uncredited age leg `N/A`. The token leg is read from service control policies only. An unreadable organization view produces `N/A`.

### BR-46: Knowledge Base Source Data Classification

- **Severity:** High
- **Description:** Requires every S3 bucket an AI data path reads to be classified by a recurring, full-depth Amazon Macie classification job. The population is every knowledge base S3 data source (with its `inclusionPrefixes`) the training, validation and invocation-log source buckets of every model customization job, and the `InputDataConfig` channel buckets of the newest 200 SageMaker training jobs (`ListTrainingJobs` sorted by `CreationTime`, then `DescribeTrainingJob` per job, with older jobs named as unread); customization and training output buckets are excluded. Every knowledge base, data source and customization job is read with no cap. For each source bucket the check describes (`DescribeClassificationJob`, once per job) every job whose `bucketDefinitions` name the bucket and the job in the bucket's `DescribeBuckets` `jobDetails.lastJobId`. A job clears the source only when `jobType` is `SCHEDULED`, `jobStatus` is `RUNNING` or `IDLE`, `lastRunErrorStatus.code` is not `ERROR`, `statistics.numberOfRuns` is at least 1, `initialRun` is true, `samplingPercentage` is 100, its data identifiers are not empty (`managedDataIdentifierSelector` `NONE`, or `INCLUDE` with no managed ids, and no custom ids), every include condition is an `OBJECT_KEY` `STARTS_WITH` term that covers the source prefix, and no `OBJECT_KEY` `STARTS_WITH` exclude overlaps it. An exclude condition on extension, size, date or tag makes the source `N/A`, because it is not compared with what the source ingests. The job's `createdAt` is compared with when the source was first read: the earliest `startedAt` over every page of `ListIngestionJobs` for a knowledge base data source, or the `creationTime` of the customization job or `CreationTime` of the SageMaker training job. A reader that started before the job was created fails. A missing `createdAt` when a reader started is `N/A`. An unread `ListIngestionJobs` is `N/A` naming `bedrock:ListIngestionJobs`. A latest ingestion after the job's `lastRunTime` is stated in the Passed text; object write times are not read. Automated sensitive data discovery samples objects, so a `MONITORED` bucket with no qualifying job fails, and the discovery status is reported in the Failed text. `GetClassificationScope` is deliberately not used: its `s3` member is `excludes.bucketNames`, an exclusion list. A failed read is `N/A` and names what was not read: the Macie session, the bucket inventory, the job list, a job describe, a bucket `errorCode`, a bucket absent from the inventory, or a failed data source, customization job or SageMaker training job read. A bucket Macie reports `isMonitoredByJob` `TRUE` that no candidate job clears, while a job that selects buckets by criteria was not tied to it, is `N/A`. When Macie is not enabled in the Region, the check reports `N/A` and no bucket failure. FS-44 asserts the two account-level Macie legs. Passed rows are published as `Knowledge Base Source Classification Job Coverage` and state that per-object classification order and per-document metadata are not judged.

### BR-47: Bedrock Data Path Bucket TLS Enforcement

- **Severity:** High
- **Description:** Reads the bucket policy of each S3 bucket on the Bedrock data path: knowledge base S3 data sources, the S3 destination of model invocation logging, the `cloudWatchConfig.largeDataDeliveryS3Config` bucket that holds payloads over 100 KB when logs go to CloudWatch Logs, and the training, validation, output and distillation invocation-log source (`trainingDataConfig.invocationLogsConfig.invocationLogSource`) buckets of every model customization job, the input and output buckets of every batch inference job (`ListModelInvocationJobs`), the training channel, output and model artifact buckets of the newest 200 SageMaker training jobs (`ListTrainingJobs`, `DescribeTrainingJob`), the code artifact bucket of each AgentCore runtime's listed version (`ListAgentRuntimes`, `GetAgentRuntime`), and the recording bucket of each custom AgentCore browser with recording enabled (`ListBrowsers`, `GetBrowser`). A failed read of any of these is named with its action and makes the bucket list incomplete. A bucket named by several sources is read once and reported with every source. A bucket passes only when one `Deny` statement, conditioned by `Bool` or `BoolIfExists` on `aws:SecureTransport` `false`, applies to principal `*`, covers `s3:*`, and names both the bucket and `bucket/*`. A `Deny` that falls short is reported with the principals, resources or actions it misses, and `NotPrincipal` or `NotAction` counts as falling short. A `Deny` whose `Condition` also tests a key other than `aws:SecureTransport`, such as `aws:SourceVpce` or an `aws:PrincipalArn` exemption for a role, is not credited, because a plaintext request that does not match that key is not denied. The one exception is `Bool` or `BoolIfExists` `aws:PrincipalIsAWSService` `false`, the form in the S3 TLS-only example policy: the Deny still reaches every IAM identity and anonymous caller, and the Passed text names the exemption. The same key tested as `true` is not credited. A bucket with no bucket policy fails, because S3 then accepts plaintext requests. Any other policy read error is informational `N/A`. Every data source and customization job is read with no cap. When the bucket list is incomplete through a failed read, the buckets that enforce TLS are reported as `N/A` with the count read and not as `Passed`, because a bucket that was never read may accept plaintext. Failed buckets are still reported `Failed`.

### BR-48: AI Services Opt-Out Policy Enforcement

- **Severity:** High
- **Description:** Reads `DescribeEffectivePolicy` for `AISERVICES_OPT_OUT_POLICY`. No effective policy, or the policy type not enabled, fails, because the account is then opted in to AI service data use. The policy type does not govern Amazon Bedrock, and every row says it does not establish how Bedrock handles content. `optOut` and `optIn` are compared exactly, so a value in another case is reported as unreadable and the default does not pass. An account outside an organization, or a denied read, is informational `N/A`. The effective document has its inheritance operators stripped, so an optOut default passes only when an opt-out policy attached to the root, an OU in the account's path (`ListParents`, `ListTargetsForPolicy`) or the account itself assigns `optOut` and sets `@@operators_allowed_for_child_policies` to `["@@none"]` at all of `services`, `services.default` and `services.default.opt_out_policy` (AWS Example 1). A lock on the value alone still lets a child policy add a service section that opts back in (AWS Example 2), so it fails, as does an unset operator, which defaults to `@@all`. A policy attached outside the path is not credited. A member-account run, an unread path or an unread policy with no lock found is `N/A` and names what was not read.

### BR-49: Guardrail Invocation Deny Enforcement

- **Severity:** High
- **Description:** For each IAM role and user allowed to invoke a model, requires a `Deny` on `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream`, on an unscoped `Resource` (as defined for [BR-42](#br-42-foundation-model-invocation-allow-list)), conditioned by a negated operator or by `Null` `true` on `bedrock:GuardrailIdentifier`, so a call without an approved guardrail is refused. Those two IAM actions also authorize `Converse` and `ConverseStream`, which have no IAM action of their own. BR-34 judges the guardrail content and BR-41 the account-level enforced guardrail configuration; this check covers identities whose calls neither of those reaches. Only role and user policies (attached and inline) are read. Group policies, permissions boundaries and service control policies are not read, so a `Deny` placed in one of them is not credited.

### BR-50: AI User Long-Term Access Key

- **Severity:** High
- **Description:** For each IAM user whose attached, inline or group policies allow any Bedrock, SageMaker AI or AgentCore action, reads included, fails an `Active` access key and reports its age and last four characters. A user allowed only `bedrock:Get*` is in scope, since a long-term key that reads a model or a guardrail still reaches the service; a `NotAction` Allow that does not exclude the service puts the user in scope too. A permissions boundary that allows no such action takes the user out of scope. Inactive keys cannot sign a request and are not counted. Deny statements and service control policies are not evaluated. A user whose group policies or policy documents could not be read is reported `N/A`, never clean. Without the IAM permissions cache the check reports `N/A`.

### BR-51: AI User Console MFA

- **Severity:** High
- **Description:** For the BR-50 user population, fails a user with a console password (`GetLoginProfile`) and no MFA device (`ListMFADevices`). A user without a console password is not failed. Only IAM users are read: users signing in through IAM Identity Center are not covered, and every row says so. The `Passed` row lists IAM Identity Center instances with `sso:ListInstances` (every page) in the primary scan Region. An instance visible to the account makes that row `N/A`, "Partial, ceiling reached", naming the instance and its owner account, because no sso-admin operation returns an instance's MFA settings. The row also pages through each instance's permission sets (`sso:ListPermissionSets`) and reads each inline policy (`sso:GetInlinePolicyForPermissionSet`), naming the permission sets whose inline policy grants an AI write, or saying none that was read does; an unread list or policy is named. A permission set whose inline policy grants an AI write fails in its own row unless the same policy carries a `Deny` on `Resource` `*` over every AI service it grants, with one `aws:PrincipalTag/<key>` test under `StringNotEquals`, `StringNotEqualsIgnoreCase` or `StringNotLike`; an `IfExists` form, a set operator or a second condition key is not credited, and a Deny that covers only some services leaves the others named. A Deny on `aws:MultiFactorAuthPresent` does not count, because the key is absent from federated sessions. Managed and customer managed policies attached to a permission set, and the attributes for access control that set the tag (`sso:DescribeInstanceAccessControlAttributeConfiguration`), are not read. An unlisted instance list is `N/A` naming the action, and when none is returned the row says an instance homed only in another Region is not listed. A denied read is `N/A`. Without the IAM permissions cache the check reports `N/A`.

### BR-52: Bedrock Data Path Bucket Object Lock

- **Severity:** Medium
- **Description:** For each S3 bucket on the Bedrock data path (the population BR-47 reads), requires Object Lock `Enabled` with a `COMPLIANCE`-mode default retention that states `Days` or `Years`. `GOVERNANCE` mode fails, because a principal with `s3:BypassGovernanceRetention` can delete or shorten the retention. A bucket with no Object Lock configuration fails; any other read error is `N/A`. A bucket without that lock passes when its newest `COMPLETED` or `AVAILABLE` AWS Backup recovery point (`ListRecoveryPointsByResource`) is in a vault whose Vault Lock (`DescribeBackupVault`) is in compliance mode past its `LockDate` grace period with a `MinRetentionDays` set. The minimum retention binds only backups made after the lock, so a newest recovery point created before the `LockDate` is read with `DescribeRecoveryPoint`: it clears the bucket only when its `CalculatedLifecycle.DeleteAt` is absent or at least `MinRetentionDays` after its creation, and an unread point never clears it. A vault lock with no `LockDate` is governance mode and fails, as do a grace period still running and a lock with no minimum retention. An unread recovery point list or vault is named in the finding and never clears a bucket. The scan role holds neither `backup:ListRecoveryPointsByResource` nor `backup:DescribeRecoveryPoint`, so when either is denied a bucket without the Object Lock stays `Failed`, its row says whether a backup covers it is unknown, and it names the action as not granted, "Partial, ceiling reached". The Region's locked vaults are listed with their mode as evidence. When the bucket list is incomplete, compliant buckets are reported `N/A` and not `Passed`.

### BR-53: Bedrock Resource Owner Tag

- **Severity:** Low
- **Description:** Lists agents, knowledge bases, flows, prompts, guardrails, custom models, imported models, provisioned throughputs and application inference profiles, reads their tags through the Resource Groups Tagging API in batches of 100 ARNs, and fails each resource with no owner tag whose value names someone. An owner key is `owner` (any case) after any `:` or `/` namespace, alone or beside words that only say which owner it is or how to reach them (`BusinessOwner`, `owner-email`, `team:owner`). Any other word, as in `previous_owner` or `FormerOwner`, is not credited, and neither is an empty value or a placeholder such as `TBD`, `unknown` or `n/a`. Each rejected tag is named on the row. Whether a value resolves to a person or an on-call rotation is not verified, and no API marks a resource as production, so every listed resource is judged. `GetResources` omits an ARN that has no tags, so a missing ARN is reported as untagged. Failed rows are capped at 25 plus one overflow row. A tag read error is `N/A`; a list error is `N/A` and downgrades the `Passed` row. An empty inventory is `N/A`. The AI Resource Owner Tag Outside Bedrock rows page through `GetResources` with `ResourceTypeFilters` `sagemaker` and then `bedrock-agentcore`, apply the same owner-tag test, and fail each returned resource without one. `GetResources` returns only resources that are or were tagged. When a filter's `GetResources` read succeeds, every page of its list operations is compared with it by resource segment, without case: `sagemaker:ListEndpoints`, `ListModels` and `ListNotebookInstances`, and `bedrock-agentcore:ListAgentRuntimes`, `ListMemories`, `ListGateways` (matched as `gateway/<id>`, since a gateway summary carries no ARN) and `ListBrowsers` for custom browsers. A listed resource that `GetResources` did not return fails as never tagged; an unlisted list is named on the summary row. Other resource types, such as SageMaker domains and training jobs and AgentCore code interpreters, are listed only by `GetResources`, so one never tagged is not seen: a summary row counts the owned resources, is always `N/A` with that ceiling and the `GetResources` API reference, and names each read that failed.

### BR-54: Lambda Function Public Invoke Configuration

- **Severity:** High
- **Description:** Reads every Lambda function in the Region. A function URL with `AuthType` `NONE` fails, because it disables IAM authentication. The resource-based policy still decides whether the URL accepts requests, so the finding says the URL is invocable by unauthenticated callers only when the policy also grants public access, and otherwise says the policy grants no public access today and one permission granted to `*` would open it. A function URL whose CORS `AllowOrigins` holds a `*`, alone or inside a pattern, fails whatever its `AuthType`. A resource-based policy `Allow` to principal `*` covering `lambda:InvokeFunction` or `lambda:InvokeFunctionUrl` fails unless one condition test names a single source: `aws:SourceAccount` with 12-digit account IDs, `aws:PrincipalOrgID` with `o-` organization IDs, or `aws:SourceArn` with an ARN whose partition, service, Region and account segments and resource ID carry no wildcard and whose account is a 12-digit ID. Only `StringEquals`, `StringLike`, `ArnEquals` and `ArnLike` count; an `IfExists` form, a `ForAllValues:` prefix or a negated operator does not, and one wildcard value among several leaves the test open. An S3 source ARN names no account, so it needs `aws:SourceAccount` beside it. `lambda:FunctionUrlAuthType` and `lambda:InvokedViaFunctionUrl` describe how the function is called, not who calls it, so neither clears a `*` principal; this includes the public statement pair Lambda writes for a `NONE` URL. A public `lambda:InvokeFunctionUrl` statement on a function with no URL fails too, because deleting a URL leaves its statement in place. The unqualified policy and the policy of every alias (`ListAliases`) and published version (`ListVersionsByFunction`) are read, and a URL on an alias is judged against that alias's policy. The check makes no network reachability claim; every row says so. On the primary Region a `Global` row judges the attached service control policies: it passes when `Deny` statements on `Resource` `*` (or a function ARN pattern with wildcard Region, account and name) cover both `lambda:CreateFunctionUrlConfig` and `lambda:UpdateFunctionUrlConfig`, each with no condition or with only a `lambda:FunctionUrlAuthType` test that matches `NONE` (`StringEquals NONE`, `StringNotEquals AWS_IAM`, and their `IfExists` forms). A `Deny` also conditioned on another key is not credited. Unread policies make it `N/A`, and the management account, which service control policies do not restrict, fails it. Per-function read errors are aggregated into one `N/A` row. A Region with no functions is `N/A`.

### BR-55: KMS Key Enclave Attestation Binding

- **Severity:** High
- **Description:** For each customer-managed KMS key whose policy uses a `kms:RecipientAttestation:` condition, fails an `Allow` covering `kms:Decrypt`, `kms:DeriveSharedSecret`, `kms:GenerateDataKey` or `kms:GenerateDataKeyPair` with no attestation pin, unless a `Deny` to principal `*` with a negated or `Null` `true` test on an attestation key already refuses such calls. `kms:GenerateRandom` also honors attestation but takes no key, so no key policy grants it. A pin is an exact value on `ImageSha384`, any `PCR<ID>` or any `NitroTPMPCR<ID>`, under an operator that is not negated, not `Null` and not `...IfExists`, with no wildcard values. `ImageSha384` corresponds to `PCR0`. The enclave image file is not secret, so an image pin alone is met by the same image launched from any parent instance: every statement that releases those operations on a Nitro Enclave binding needs both an exact image measurement (`ImageSha384`, `PCR0` or `PCR8`, the signing certificate) and an exact deployment value (`PCR3`, parent IAM role, or `PCR4`, parent instance ID), each in the statement itself or through a `Deny` to `*` with a negated exact test on it. A `PCR3`-only or `PCR8`-only pin fails. A `NitroTPMPCR<ID>` pin needs no enclave deployment PCR. Every row names the family that matched: Nitro Enclave for `ImageSha384` and `PCR<ID>`, NitroTPM for `NitroTPMPCR<ID>`. The default key-policy statement that delegates to IAM through the account root is reported as a bypass with its own text, and the key can pass only when that statement carries an attestation pin or a `Deny` covers every operation it opens. A `Deny` that tests only for a missing attestation (`Null` `true`, or a negated test on wildcard values) closes that path but does not by itself pin an image. A `Deny` under a positive operator, with or without `IfExists`, is not credited. Condition keys in one statement are ANDed, so a `Deny` that also tests a non-attestation key is not credited, and a `Deny` with two attestation tests only refuses a missing attestation and pins neither measurement. Each key's grants (`ListGrants`, every page) are read too: a grant of `Decrypt`, `DeriveSharedSecret`, `GenerateDataKey` or `GenerateDataKeyPair` carries no attestation condition, so it fails the key unless a key-policy `Deny` covers that operation. A key whose grants could not be read is `N/A`, never `Passed`. Keys whose policy uses no attestation are summarized in one `N/A` row. AWS managed keys are skipped.

### BR-56: Bedrock LLM Jacking Activity

- **Severity:** High
- **Description:** Reproduces Prowler's `cloudtrail_threat_detection_llm_jacking`, which Prowler maps to its AISF-AI-06 "Bedrock API Audit Trail" requirement. Reads the Region's CloudTrail event history with `LookupEvents`, one event name at a time, over the last 24 hours, for Prowler's 14 actions: `PutUseCaseForModelAccess`, `PutFoundationModelEntitlement`, `PutModelInvocationLoggingConfiguration`, `CreateFoundationModelAgreement`, `InvokeModel`, `InvokeModelWithResponseStream`, `GetUseCaseForModelAccess`, `GetModelInvocationLoggingConfiguration`, `GetFoundationModelAvailability`, `ListFoundationModelAgreementOffers`, `ListFoundationModels`, `ListProvisionedModelThroughputs`, `SearchAgreements` and `AcceptAgreementRequest`. An identity, keyed by `userIdentity.arn` and `userIdentity.type`, fails when the share of those actions it called is above 0.4, which is 6 or more of the 14. Events with no identity ARN are skipped as AWS service calls, as Prowler does. Event history holds management events only, whether or not a trail exists: it sees `InvokeModel` and `InvokeModelWithResponseStream`, and it cannot see `InvokeModelWithBidirectionalStream`, `StartAsyncInvoke`, `GetAsyncInvoke`, `InvokeAgent` or `InvokeInlineAgent`, which Bedrock logs as data events. `Converse` and `ConverseStream` are management events but are not in Prowler's list. Every `Passed` and `N/A` row states this. Three departures from Prowler: each event name is read up to 5 pages of 50 events, where Prowler reads one page; the Region under assessment is read, where Prowler reads only its trails' home Region and passes an account with no trail; and an event name that was cut off at the page limit, failed to read, or held an unparseable event is never passed over. Such a name is credited to every identity, and an identity that could then exceed the threshold is reported in one informational `N/A` row with the names that were not read in full. The `Passed` row names any such names when crediting them changes no verdict. When every lookup fails the check is informational `N/A` with the error code.

### BR-57: Agent Handoff Source Identity

- **Severity:** High
- **Description:** Fails an agent-to-agent handoff that carries no checked caller binding. The agent roles are the roles Bedrock agents run as (`GetAgent` for the working draft and `GetAgentVersion` for every version an alias routes to, `agentResourceRoleArn`) and the roles AgentCore runtimes run as (`GetAgentRuntime` `roleArn` for the latest version and for the live and target version of every endpoint). Two legs are judged. First, for every supervisor version (`agentCollaboration` `SUPERVISOR` or `SUPERVISOR_ROUTER`), `ListAgentCollaborators` names each collaborator's alias, the alias routing is resolved to the collaborator's version roles, and a collaborator that runs as its supervisor's own role fails, because it acts with the supervisor's authority. Second, the trust policy of every role in the IAM permissions cache is read with `iam:GetRole`, and an `Allow` statement on `sts:AssumeRole` is an edge from an agent role when it names the agent role as a principal, or when it names the agent role's account or `*` (or uses `NotPrincipal`) and the agent role's own cached identity policy allows `sts:AssumeRole` on that role. A permissions boundary that allows `sts:AssumeRole` nowhere removes the edge. An edge passes only when the statement pins `sts:SourceIdentity` (or `aws:SourceIdentity`) with `StringEquals`, `StringEqualsIgnoreCase` or `StringLike` and no value holds a wildcard; an `IfExists` operator, a `ForAllValues:` prefix, a negated operator or a `Null` test does not pin it. Identity-policy `Deny` statements and service control policies are not evaluated per principal, which can only add an edge. A collaborator alias in another account or Region, an agent or runtime that failed to read, an agent role missing from the cache, a trust policy that failed to read, and a principal the cache recorded as unread each report an informational `N/A` row, and the `Passed` row becomes `N/A`. Runtimes are listed with `bedrock-agentcore:ListAgentRuntimes` and `bedrock-agentcore:ListAgentRuntimeEndpoints`, granted on `*` because neither has a resource type; a list that fails reports `N/A` naming the action. Partial, ceiling reached: no AWS API marks which ECS task roles, Lambda execution roles or other roles host an agent, `GetAgentRuntime` returns no field for the scope of a runtime session's token, and a role in another account that trusts an agent role is not read.

---

## Amazon Bedrock AgentCore Security Checks (53)

### AC-01: Runtime Amazon VPC Configuration

- **Severity:** High
- **Description:** Validates agent runtimes have proper Amazon VPC settings. The egress leg unions the outbound ranges of every security group on a runtime, Code Interpreter or Browser and fails when they together cover `0.0.0.0/0` or `::/0`, split ranges included. A rule naming a prefix list counts as every CIDR in it, and a prefix list whose entries could not be read leaves that resource `N/A` naming `ec2:GetManagedPrefixListEntries`. `PUBLIC` mode fails at High severity and `SANDBOX` mode at Medium, because neither carries a customer security group. A preventive leg, reported once under the `Global` region, requires a service control policy attached to the account, an organizational unit above it, or the root that denies `CreateAgentRuntime`, `UpdateAgentRuntime`, `CreateCodeInterpreter` and `CreateBrowser` when `bedrock-agentcore:subnets` or `bedrock-agentcore:securityGroups` is absent (`Null` true), and one that denies them when either names an ID outside a fixed list (`ForAnyValue:StringNotEquals`, no wildcards). A Deny that ANDs in another key does not count. The internet route leg fails a runtime in `PUBLIC` network mode, and fails a VPC-mode runtime, custom Code Interpreter or custom Browser whose subnet's route table (its explicit association, else the VPC main table) routes to an internet gateway that is not a blackhole (AIR-FND-NET-01). Tools report their subnets as `networkConfiguration.vpcConfig.subnets`, under `AgentCore Tool Subnet Internet Exposure`; `PUBLIC` and `SANDBOX` tools attach no customer subnet and are judged by the egress leg. A VPC-mode runtime reporting `requireServiceS3Endpoint` `true` fails `AgentCore Runtime Service-Managed S3 Gateway`, because a runtime created before the 2026-05-05 rollout keeps a service-managed Amazon S3 gateway outside its VPC configuration until the field is set `false` through `UpdateAgentRuntime`. A runtime that does not report the field fails the same way when its `createdAt` falls before 2026-05-05, since an unset field keeps the gateway; the rollout is gradual, so one created on or after that date, or with no `createdAt`, is `N/A`. `GetAgentRuntime` without a version reads only the latest one, so every version `ListAgentRuntimeVersions` returns is read by number and held to the network mode, subnet and S3 gateway legs, named as `version N`. A runtime whose versions cannot be listed is `N/A` naming `bedrock-agentcore:ListAgentRuntimeVersions`, and the `Passed` row is withheld. A runtime `ListAgentRuntimes` names that `GetAgentRuntime` reports `ResourceNotFoundException` for is `N/A` by name. A VPC-mode resource with no subnets, a subnet not present in the Region, and an unreadable route table are `N/A`. The `Passed` row names each runtime and states what was read. VPC endpoints are judged by AC-08. NAT gateways are not read: a NAT route gives no inbound path. The tool-level destination allow-list is not read, because no AgentCore API returns one.

### AC-02: AWS IAM Full Access

- **Severity:** High
- **Description:** Checks attached and inline policy documents for AgentCore full-access managed policies, wildcard IAM action patterns, and `Allow`/`NotAction` allow-except statements that still grant the AgentCore namespace when they apply to all resources. Only the valid `bedrock-agentcore` IAM namespace is evaluated; overly permissive `agent-registry` grants are reported by [AR-01](#ar-01-aws-iam-full-access) instead. These wildcard legs leave service-agnostic administrator-style grants (a bare `Action: "*"`, and a `NotAction` whose exclusions name no platform namespace) to the next finding. An `AgentCore Read and Write Merged in One Grant` finding covers AIR-FND-IAM-09 over the `bedrock-agentcore` namespace, registry resource types excluded. It reads every attached (AWS managed included), inline and group policy of every cached role and user, and fails a wildcard `Action` pattern (a bare `"*"`, `*:*` and a partial pattern among them) or a `NotAction` Allow that grants both a read and a write action on one resource type, as the [service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html) classifies them (the table is `iam_access_levels.json`, generated by `generate_iam_access_levels.py`). An explicit action list is never reported, because it separates read from write. An action counts only when no unconditioned `Resource: "*"` Deny removes it and the permissions boundary also allows it. A condition applies to the read and the write alike and is not read; the `Resource` entries are read only to drop resource types none of them can name, with a policy variable read as any value. Service control policies are not evaluated per principal, which can only make a row a false `Failed`, and each failing row says so. A policy that cannot be parsed produces `N/A` naming the principal. While the cache's `principal_errors` names a principal, each `Passed` row becomes `N/A` naming the unread principals; a cache without `principal_errors` (schema v1) keeps its verdict and says the errors were not recorded. A principal whose permissions boundary the cache could not read (a `permissions_boundary` stage in `principal_errors`) is not reported `Failed` by the merged row, because a boundary could remove the grant; the `N/A` row names it. `bedrock-agentcore:Get*` is reported when it can reach a workload identity, because `GetWorkloadAccessToken` and its two variants are Write actions there. A missing, unreadable, or malformed permissions cache is reported as informational `N/A`. If an individual cached policy document cannot be parsed, valid findings from other policies are retained and an additional informational `N/A` row names the principals whose policies were not parsed; the unparsed policy cannot produce a compliant pass.

### AC-03: Stale Access

- **Severity:** Low
- **Description:** Detects unused AgentCore permissions by inspecting `Allow` and `NotAction` grants in attached and inline policy documents before querying IAM service-last-accessed history. Only the `bedrock-agentcore` namespace is evaluated; `agent-registry` grants are reported by [AR-02](#ar-02-stale-access) instead. As in the AC-02 wildcard legs, a `NotAction` whose exclusions name no platform namespace is a service-agnostic administrator grant and is not treated as an AgentCore-specific permission. Attached policy names alone are never treated as proof of access. IAM last-accessed jobs are polled within the Lambda deadline; a job that does not complete in time is reported as an indeterminate `N/A` rather than a failed control. A missing, unreadable, or malformed permissions cache is also reported as informational `N/A`. This identifies candidate grants from the cached policy documents; it is not a complete effective-permissions simulation across boundaries, session policies, or organization controls.

### AC-04: Observability

- **Severity:** Medium
- **Description:** Reports one row per AgentCore runtime. `GetAgentRuntime` returns no logging or tracing configuration, so the check reads where AgentCore puts both: a runtime passes when at least one log group under `/aws/bedrock-agentcore/runtimes/<runtimeId>-` exists and a `bedrock-agentcore` `TRACES` delivery source names the runtime with a delivery to a destination. A trace source with no delivery fails distinctly. A log group list or delivery read that fails leaves the runtime `N/A` and names the read, unless the other leg already fails it. Whether CloudWatch Transaction Search is on is reported by AC-19, and custom CloudWatch metrics are not assessed. Gateway and memory delivery is reported by [AC-19](#ac-19-log-delivery-configuration).

### AC-05: Amazon ECR Repository Encryption

- **Severity:** High
- **Description:** Validates Amazon ECR repositories use encryption.

### AC-06: Browser Tool Recording

- **Severity:** Medium
- **Description:** Uses custom browser inventory and requires `recording.enabled=true` with a non-empty S3 recording bucket. The bucket is read with `ExpectedBucketOwner` set to the account in the browser ARN, and must encrypt by default with `aws:kms` or `aws:kms:dsse`, carry a bucket policy Deny for every principal on `s3:GetObject` and `s3:PutObject` over the recording prefix conditioned only on `aws:SecureTransport` false, and expire the prefix with an enabled lifecycle rule that has no tag or size filter, with `NoncurrentVersionExpiration` as well when versioning is `Enabled` or `Suspended`. The browser must name an `executionRoleArn`, and the permission cache must show that role allowed `s3:PutObject` on the prefix by an unconditioned identity policy or a bucket policy statement naming its ARN, allowed by its permissions boundary, and reached by no Deny other than one keyed only on `aws:SecureTransport`. A Block Public Access setting the bucket leaves off is read from the owning account through the S3 Control `GetPublicAccessBlock` API, because S3 applies the most restrictive combination of the bucket and account settings: a setting off on both, or off on the bucket in an account with no configuration, fails, and one the account turns on passes. A denied account read is `N/A` naming `s3:GetAccountPublicAccessBlock`. A bucket read that fails, a role the cache did not read, and a conditioned grant or Deny are `N/A`. SCPs, the bucket key policy and the role's use of that key are not evaluated, so a Passed write can still be refused. The AWS managed browser is outside the population: it has no recording configuration.

### AC-07: Memory Encryption

- **Severity:** Medium
- **Description:** Checks agent memory encryption with AWS KMS. A memory that `GetMemory` cannot describe is informational `N/A`, and the resolution follows the error. `AccessDeniedException` names `bedrock-agentcore:GetMemory` on the memory and `kms:Decrypt` on its customer managed key through `bedrock-agentcore`, allowed by both the role's IAM policy and the key policy, because AgentCore decrypts the memory's strategies on the caller's behalf and a caller without the key grant is denied `GetMemory`. The assessment role carries that `kms:Decrypt` grant, conditioned on `kms:ViaService` `bedrock-agentcore.*.amazonaws.com`, so a denial that remains points at a key policy that does not allow the role. Only `ResourceNotFoundException` points at a memory deleted mid-assessment. The key a memory names is read with `kms:DescribeKey` and passes only when `KeyManager` is `CUSTOMER` and `KeyState` is `Enabled`. A key that is not customer managed, is disabled or is pending deletion fails, and a key `DescribeKey` cannot read is informational `N/A`, which includes every key in another account because the role's grant names this account's keys. A second row per memory fails a strategy namespace with no `{actorId}` variable.

### AC-08: Amazon VPC Endpoints

- **Severity:** High
- **Description:** Requires an available interface endpoint for the service each AgentCore surface in use is called through: `com.amazonaws.<region>.bedrock-agentcore` when the region holds a runtime, `com.amazonaws.<region>.bedrock-agentcore.gateway` when it holds a gateway, and `com.amazonaws.<region>.bedrock-agentcore-control`, through which both are managed, when it holds either. An endpoint for one service does not count for another, and a region with gateways and no runtime is judged. Each VPC-mode runtime's subnets are resolved to their VPCs through `DescribeSubnets`, and `AgentCore Runtime VPC Endpoint Missing` fails a runtime whose VPC holds no available `bedrock-agentcore` endpoint, since an endpoint in another VPC carries none of its calls. A runtime that cannot be read, reports no subnets, or names a subnet that is not returned is `N/A` by name, and the leg passes only when every VPC-mode runtime was resolved and covered. `PUBLIC` runtimes are judged by AC-01. Each AgentCore endpoint, and each S3, DynamoDB and SageMaker endpoint in the same VPCs, is also judged on its policy against the default allow-everything document, on private DNS for interface endpoints, and on its security groups' inbound rules. Ranges that together cover `0.0.0.0/0` or `::/0` fail as unrestricted, so `0.0.0.0/1` on one group and `128.0.0.0/1` on another fail. Ranges that together cover a CIDR block of the endpoint's VPC, primary or secondary, and any rule for a protocol or port other than TCP 443, fail `AgentCore VPC Endpoint Network Scope Too Wide`. A rule naming a prefix list counts as every CIDR in it, read with `ec2:GetManagedPrefixListEntries` across every page, and an endpoint whose prefix list could not be read is `N/A` naming the action. An endpoint whose VPC reported no CIDR block is `N/A`. VPCs, endpoints and both AgentCore inventories are read across every page, and an unreadable inventory is informational `N/A`.

### AC-09: Service-Linked Role

- **Severity:** Medium
- **Description:** Verifies the AgentCore service-linked role exists.

### AC-10: Resource-Based Policies

- **Severity:** Medium
- **Description:** Fails an Allow statement on a runtime or gateway resource policy that opens it to any principal without binding the caller's account or organization. An unreadable runtime or gateway list is informational `N/A`.

### AC-11: Policy Engine Encryption

- **Severity:** Medium
- **Description:** Requires every policy engine to name a customer managed key whose `kms:DescribeKey` metadata reports `KeyManager` `CUSTOMER` and `KeyState` `Enabled`. A key that is disabled, pending deletion, pending import or unavailable fails as `AgentCore Policy Engine Key Unusable`: the engine cannot decrypt its policies, so every decision it takes is `DENY`. An engine whose `GetPolicyEngine` read fails, which also happens when its key is unusable because the read decrypts first, and a key `DescribeKey` cannot read, are informational `N/A` naming the engine.

### AC-12: Gateway Encryption

- **Severity:** Medium
- **Description:** Reads each gateway's `kmsKeyArn` and describes the key. A gateway with no key, or with a key `kms:DescribeKey` reports as not `CUSTOMER` managed, fails `AgentCore Gateway Encryption Missing`, and one whose customer managed key is not `Enabled` fails `AgentCore Gateway Key Unusable`. The key policy is then read against the example in the gateway encryption guide: `kms:Decrypt` and `kms:GenerateDataKey` have to be allowed with `kms:ViaService` `bedrock-agentcore.<region>.amazonaws.com` and `kms:EncryptionContext:aws:bedrock-agentcore-gateway:arn` naming the gateway, `kms:CreateGrant` with that `kms:ViaService` and `kms:GrantConstraintType` `EncryptionContextSubset`, and no unbounded principal may decrypt. An encryption context value binds when it names the partition, service, region, account and resource type literally, so `gateway/*` in the account binds. IfExists forms do not count. A gap fails `AgentCore Gateway Key Policy Unscoped`. A gateway whose `GetGateway`, `kms:DescribeKey` or `kms:GetKeyPolicy` read fails, a gateway deleted during the run included, is `N/A` by name and is not counted in the `Passed` row. A statement granting the same actions with no condition, such as the account-root `kms:*` statement, is not subtracted.

### AC-13: Gateway Configuration

- **Severity:** Medium
- **Description:** Validates gateway security configuration.

### AC-14: Identity Token Vault CMK Encryption

- **Severity:** High
- **Description:** Checks every regional Identity token vault in use and requires `CustomerManagedKey` with a KMS key that `kms:DescribeKey` reports as customer managed and `Enabled`, because a disabled key or one pending deletion leaves the stored credentials undecryptable. There is no `ListTokenVaults`, so the population is the configured vault plus every vault an OAuth2, API key or payment credential provider ARN names, read from all three provider lists across every page. Set the `AgentCoreTokenVaultId` deployment parameter to override the `default` vault ID (`AGENTCORE_TOKEN_VAULT_ID` in the Lambda). A configured vault that does not exist while no provider names a vault is informational `N/A`, because no credential is stored. A vault or key that could not be read, a vault a provider names that returns not found, and a provider list that could not be read are informational `N/A` and never `Passed`. A vault no provider names and that is not configured is not read. The key policy is read with `kms:GetKeyPolicy` and has to allow `kms:Decrypt` in one statement that carries `kms:ViaService` for `bedrock-agentcore-identity` in the key's region (the region may be `*`, as in the devguide example, because a key policy governs only its own regional key) and `kms:EncryptionContext:aws-crypto-ec:aws:bedrock-agentcore-identity:token-vault-arn` naming a `token-vault/` resource that matches the vault, with a literal account or `aws:ResourceAccount` equal to `${aws:PrincipalAccount}` in the same statement. IfExists and ForAllValues forms bind nothing. A policy that lacks that statement, or that lets every principal decrypt with no bounding condition, fails as `AgentCore Identity Token Vault Key Policy Unscoped`; a key policy that could not be read is `N/A` naming `kms:GetKeyPolicy`. A statement granting `kms:Decrypt` with no condition, such as the account-root `kms:*` statement, is not subtracted.

### AC-15: Code Interpreter Network Isolation

- **Severity:** High
- **Description:** Requires custom Code Interpreters to use `VPC` network mode with non-empty subnets and security groups.

### AC-16: Custom Browser Network Isolation

- **Severity:** High
- **Description:** Requires custom browsers to use `VPC` network mode with non-empty subnets and security groups. Shares browser inventory with AC-06.

### AC-17: Online Evaluation Coverage

- **Severity:** Medium
- **Description:** Reports one finding per AgentCore runtime, whatever the deployment parameters say. A runtime passes when a running online evaluation configuration reads it: the configuration is `ACTIVE` and `ENABLED`, samples above zero, attaches an evaluator and writes to an output log group, and its `dataSourceConfig.cloudWatchLogs` names a log group under `/aws/bedrock-agentcore/runtimes/<runtimeId>-` (by `logGroupNames` or `logGroupNamePrefixes`) together with a `serviceNames` entry equal to the runtime id or name, or starting with either and a dot. Each endpoint `ListAgentRuntimeEndpoints` returns must then have its own log group `<runtimeId>-<endpointName>` read by a running configuration whose service name is the runtime id or name, or that identity followed by a dot and the endpoint name; an endpoint none reads fails the runtime and is named. When the endpoints cannot be listed, a runtime that would pass is informational `N/A` naming `bedrock-agentcore:ListAgentRuntimeEndpoints`. A runtime no configuration reads fails, and one only a stopped configuration reads fails with the stopped settings named. A configuration that cannot be read makes every runtime not already scored `N/A`, and an unlistable runtime inventory is `N/A`. Rule filters are counted in the `Passed` text and not judged, because which sessions an operator means to score has no API field. In a region with no runtime, `RequireAgentCoreOnlineEvaluation` set to `true` (`REQUIRE_AGENTCORE_ONLINE_EVALUATION` in the Lambda) requires one running configuration, for agents hosted outside AgentCore Runtime; unset, that region is informational `N/A`.

### AC-18: CloudTrail Data Event Coverage

- **Severity:** Medium
- **Description:** Requires a CloudTrail advanced event selector of category `Data` on every AgentCore data-event type in use in the region, one finding per family: `AWS::BedrockAgentCore::Runtime` and `::RuntimeEndpoint` for runtimes, `::Memory` for memory, `::CodeInterpreter` and `::Browser` for the AWS-managed tools and `::CodeInterpreterCustom` and `::BrowserCustom` for custom ones, `::Gateway` for gateways, `::WorkloadIdentity`, `::WorkloadIdentityDirectory`, `::OAuth2CredentialProvider`, `::APIKeyCredentialProvider` and `::TokenVault` for identity, `::PolicyEngine` and `::Policy` for policy engines, and `::Evaluator` for the account's own evaluators. `ListEvaluators` also returns the AWS-provided `Builtin` evaluators every account sees, so those are not counted, and an account with only built-in evaluators reads `N/A` for the Evaluator family. A type counts only when a selector names it with no field other than `eventCategory` and `resources.type` that drops some of its events, on a trail whose `GetTrailStatus` reports `IsLogging` true and that is multi-Region or homed in the scanned Region. Two extra fields keep every event and do not narrow: `readOnly` listing both `true` and `false`, and a `resources.ARN` field with one operator that is `StartsWith` a prefix of `arn:<partition>:bedrock-agentcore:<region>:`, or `NotStartsWith` or `NotEquals` values that cannot match that prefix. Every other field, and a field selector mixing operators, narrows. A family with some types covered fails and names the rest. CloudTrail Lake event data stores are not read. Management events do not satisfy it, because they record that a runtime or memory was created and not the invocations and memory record reads that follow. Presence of resources is decided from this module's own inventory, so a family with no resources in the region reports informational `N/A` instead of a failure nobody can act on. An unavailable CloudTrail client, a failed `ListTrails` call, an uninventoriable family, and the case where no readable trail selects the type while other trails, or their detail or status, could not be read are also informational `N/A`.

### AC-19: Log Delivery Configuration

- **Severity:** Medium
- **Description:** Reports one finding per runtime, gateway and memory resource. A gateway or memory needs a `bedrock-agentcore` `APPLICATION_LOGS` delivery source and a `TRACES` delivery source, each with a delivery carrying it to a destination, because AgentCore configures no log destination for either. A runtime needs the `TRACES` delivery only, because AgentCore creates a log group for a runtime's service-provided logs. A resource with a delivery source and no delivery fails, because nothing stores what it collects, and a source reporting status `INACTIVE` does not count. When the region holds any runtime, gateway or memory, one `AgentCore Transaction Search` row reads the region's trace segment destination with `xray:GetTraceSegmentDestination`, because tracing needs CloudWatch Transaction Search, which sends segments to CloudWatch Logs. `CloudWatchLogs` with status `ACTIVE` passes, `XRay` fails, and `PENDING` or an unreadable destination is informational `N/A`, naming the action when the read is denied. The share of spans Transaction Search indexes is not read. Built-in tools, Identity, and policy engines are covered by one informational `N/A` row that names why none of the three has a delivery configuration to assert. An unavailable CloudWatch Logs client, an unreadable delivery configuration, and a failed runtime, gateway or memory listing are informational `N/A`.

### AC-20: Log Data Protection

- **Severity:** Medium
- **Description:** For every log group under `/aws/bedrock-agentcore/` or `/aws/vendedlogs/bedrock-agentcore/`, requires a data-protection policy that de-identifies at least one AWS managed credentials identifier (`AwsSecretKey` or one of the four private key identifiers) and at least one managed personal or health identifier, the two categories the control names, and a customer managed KMS key, and names what is missing. A country-coded identifier such as `DriversLicense-US` is classified by its name. Financial identifiers fall in neither category, and a custom identifier is not classified because its pattern is not read. Masking set on the log group and masking inherited from an account-level policy both count and are cumulative: when the account policy lacks a category, an attached log-group policy is read and its identifiers are added. An account-level data-protection policy takes no `selectionCriteria` and its scope can only be `ALL`, so it covers every group. AC-26 judges the policy of the key named here, for the same groups. A log group outside the two prefixes that a delivery from a `bedrock-agentcore` delivery source writes to is resolved through `DescribeDeliveries` and `DescribeDeliveryDestinations` and judged by the same rules; S3 and Firehose destinations are not log groups and are not read here, and a named group that no longer exists is not reported. When the deliveries or destinations cannot be read, an informational `N/A` row names `logs:DescribeDeliveryDestinations`, `logs:DescribeDeliveries` and `logs:DescribeDeliverySources`, and the prefixed groups are still judged. Which data identifiers the workload's data needs is not read: no API field states it. Agent prompts, tool arguments, and memory records reach these log groups verbatim, so a guardrail at the model boundary does not cover them. A region with no AgentCore log groups, an unreadable account policy list, and a log group whose policy document cannot be read are informational `N/A`.

### AC-21: Log Unmask Restriction

- **Severity:** Medium
- **Description:** Fails any cached IAM role or user granted `logs:Unmask` on a resource pattern that reaches every AgentCore log group, because masking is reversible by whoever holds that action. A log group name of wildcards alone reaches every group, and so does a literal head that `/aws/bedrock-agentcore/` or `/aws/vendedlogs/bedrock-agentcore/` starts with followed by wildcards alone, such as `/aws/bedrock-agentcore/*` or `/aws/*`. A trailing `:*` log-stream suffix is ignored. A pattern short of a whole prefix, such as `/aws/bedrock-agentcore/runtimes/*`, counts as scoped. A principal holding it only on scoped resources passes, and so does an account where no cached principal holds it at all. An empty or unreadable permission cache is informational `N/A`. Reported once under the `Global` region, because the grant does not vary by scanned region.

### AC-22: Telemetry Sink Scope

- **Severity:** Medium
- **Description:** Requires every `Allow` statement in an observability sink policy to name only principals of the sink's own account or to carry an organization condition naming this account's organization, so an unrelated account cannot link its telemetry into the account that aggregates agent traces. The organization is read with `organizations:DescribeOrganization`, and when that read is denied an organization-bound sink reads informational `N/A` naming the action. A statement naming other accounts with no organization condition is informational `N/A`, because whether those accounts belong to the organization is not read. A statement whose only binding organization condition names another organization, or a value list that includes one, fails. Both are read by value: a statement names its principals only when no principal is a wildcard and no `NotPrincipal` is present, and an organization condition counts only under `StringEquals`, `StringEqualsIgnoreCase` or `StringLike` (a `ForAnyValue:` prefix is read), with a value whose organization segment has no wildcard. A negated, `IfExists` or `ForAllValues` operator reads as true when the key is absent and does not count. A region with no sink is judged as a source account: each link `ListLinks` returns must share `AWS::Logs::LogGroup`, `AWS::XRay::Trace` and `AWS::CloudWatch::Metric`, the types AgentCore telemetry is written as, and fails naming the types it omits. A link sharing all three passes and names its sink, whose policy AC-22 judges in the account that owns it; the link's log group and metric filters are not read. No link is informational `N/A`, and a denied `ListLinks` is informational `N/A` naming `oam:ListLinks`. A sink with no policy attached is informational `N/A` because no source account can link to it, as are an unavailable client, a failed `ListSinks` call, an unreadable policy, and a policy that is not valid JSON.

### AC-23: Memory Record Access Scope

- **Severity:** High
- **Description:** Fails any cached IAM role or user that can read memory records or events with no namespace, strategy, actor, or session condition, because one such call returns every actor's stored records out of the same memory. AC-07 judges each memory's own namespace partitioning; partitioning separates records only when retrieval is bound to one actor too. A principal whose read is conditioned passes, as does an account where no cached principal holds a memory read action. A `StringLike` namespace value is conditioned only when it stays inside one caller's partition: a wildcard after a policy variable, or a whole trailing `*` under a fixed identifier (`/actors/a-1/*`), counts, while `/users/*`, `/actors/*`, `/strategies/s-1/actors/*`, a path of collection segments alone such as `/sessions/*`, and a partial wildcard such as `/actors/alice*` read as unscoped. An empty or unreadable permission cache is informational `N/A`. Reported once under the `Global` region.

### AC-24: Gateway Rate Limiting

- **Severity:** Medium
- **Description:** Requires each gateway to carry at least one `ACTIVE` rate limit with a requests, tokens, or connections ceiling. A limit counts only when its key is one the caller cannot renew by fetching a new token: `targetName`, `toolName`, `qualifiedModelId`, `$.context.iam.principal`, `$.context.iam.sourceIdentity`, or one of the JWT claims `sub`, `client_id`, `azp`, `aud`, `iss`, `oid`, `tid`, `username`, `cognito:username` or `email`. Any other claim, such as `jti`, `iat` or `nonce`, is not known to stay the same across one caller's tokens, and a caller who presents a fresh token can start a fresh count. A gateway with rate limits none of which is active with a ceiling fails separately from a gateway with no rate limit at all, because a limit that bounds nothing reads as configured. The WAF association AG-27 reports filters request content and sets no throughput ceiling. An unavailable client, a region with no gateways, and unreadable rate limits are informational `N/A`.

### AC-25: Gateway Target Authorization

- **Severity:** High
- **Description:** Requires each gateway target to declare a credential provider, because `credentialProviderConfigurations` is optional on `CreateGatewayTarget` and the console offers "No authorization", so a target can reach its backend with no gateway-supplied credential and the backend cannot tell one caller from another. The provider types found are reported; which of the five suits a given backend is a workload decision. A region with no targets, an unlistable gateway, and an unreadable target are informational `N/A`. A second row per gateway reads the attached and inline policies of the gateway execution role (`roleArn`) from the IAM permission cache and fails the role as `Unscoped` when it grants a wildcard action, `Resource: "*"`, or an ARN with a wildcard segment that widens the population, unless a Deny or the role's permissions boundary removes the grant. Service control policies are not evaluated per role, so they can only make this row a false `Failed`. A role the cache records as unreadable, a role absent from the cache, a role in an account other than the gateway's (the cache reads only the assessed account and keys roles by name), and a missing cache are informational `N/A`, never `Passed`.

### AC-26: Log Retention and Key Scope

- **Severity:** Medium
- **Description:** Requires a retention period on every AgentCore log group, and requires the key policy behind its customer managed key to bind the principals allowed to decrypt and the administrators allowed to disable the key or schedule it for deletion. A group with no retention keeps agent prompts, tool arguments, and memory records for as long as the account exists. AC-20 asserts that a customer managed key is set; this check judges the policy behind it. An Allow whose principal is a wildcard or a `NotPrincipal` counts as bound only when `kms:CallerAccount`, `aws:PrincipalAccount`, `aws:SourceAccount`, `aws:PrincipalOrgID`, `aws:PrincipalArn` or `aws:SourceArn` holds a value with no wildcard in its account under a positive operator; `kms:ViaService` narrows the path and not the caller and does not count, and `IfExists` and `ForAllValues` do not count. A grant to the CloudWatch Logs service principal fails unless it binds the account or `kms:EncryptionContext:aws:logs:arn`. A Deny is not subtracted, so a Deny can only make this a false `Failed`. A log group whose key policy cannot be read is reported as informational `N/A` on its own row, so the retention verdict still stands. Each runtime log group under `/aws/bedrock-agentcore/runtimes/` and each vended-log group under `/aws/vendedlogs/bedrock-agentcore/`, which carries memory and gateway log delivery, must also have deletion protection on, and so must the `aws/spans` group that Transaction Search writes AgentCore spans to, because a principal allowed to call `DeleteLogGroup` otherwise erases the agent's record. A group that does not report `deletionProtectionEnabled` is read as unprotected. A region with no `aws/spans` group reports no spans row, and an unreadable spans group is informational `N/A`. Two further legs read tampering. A `Global` leg requires an attached service control policy denying `logs:DeleteLogGroup`, `logs:DeleteLogStream`, `logs:PutRetentionPolicy`, `logs:PutLogGroupDeletionProtection` and `logs:DeleteSubscriptionFilter` on the AgentCore log groups and `aws/spans` in every Region, and on the Bedrock model invocation log group that the primary Region's `GetModelInvocationLoggingConfiguration` names, with no condition or only negated `aws:PrincipalArn` exemptions that name principals. `DeleteLogStream` is authorized on the log-stream ARN, so its `Deny` must name each group's `:log-stream:*` ARN or a resource of `*`; a log-group pattern whose `*` would have to span the `:log-stream:` part does not count. An unreadable invocation logging configuration turns a pass into informational `N/A` naming `bedrock:GetModelInvocationLoggingConfiguration`, and leaves a failure failed. Invocation log groups that other Regions name are not probed. A regional leg reads each trail with `GetTrail` and fails a trail that records the Region with `LogFileValidationEnabled` off, fails when no trail records the Region, and is `N/A` while any trail is unreadable. Forwarding the log groups to an Object Lock archive is not read.

### AC-27: Gateway Policy Conditions

- **Severity:** High for the confused-deputy legs; Medium for the network-path leg
- **Description:** Judges the conditions on each gateway's resource policy and on its execution role's trust policy. An `Allow` statement that trusts an AWS service principal or every principal with no `aws:SourceAccount` or `aws:SourceArn` condition fails, because another account's resource can then make the service call this gateway on its behalf, and a guarded statement elsewhere in the same policy does not narrow an unguarded one. A guarded statement that trusts a service or `*` also needs an `aws:SourceArn` condition whose every value names the account, a Region and a resource type with no wildcard (`arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/*` passes; `arn:aws:bedrock-agentcore:*:111122223333:*` and `aws:SourceAccount` alone fail the execution role leg as `Source ARN Not Scoped`), because the service could otherwise assume the role for any AgentCore resource in the account. The network leg is separate, and passes only on a resource policy `Deny` that refuses the invoke action to every principal outside a bounded `aws:SourceVpc`, `aws:SourceVpce`, `aws:VpcSourceIp`, or `aws:SourceIp` value. An `Allow` condition alone does not restrict a same-account caller whose identity policy grants the call, and a positive or `ForAnyValue` operator, a wildcard endpoint, an address list covering every address, and a `Deny` that ANDs in another key or names specific principals fail with the reason named. Without it any caller holding a valid authorizer token reaches the gateway over any path, including the public internet. AC-10 reports that a resource policy is present. Trust policies are read from IAM, because the permission cache stores attached and inline policies only, and roles are cached per invocation because several gateways can share one execution role. A gateway with no cross-account or service-principal policy, a gateway with no execution role, and an unreadable policy are informational `N/A`.

### AC-28: Gateway Authorizer Guardrail

- **Severity:** High
- **Description:** Requires a service control policy that denies both `CreateGateway` and `UpdateGateway` when `bedrock-agentcore:GatewayAuthorizerType` is `NONE`. A deny on create alone fails separately, because it leaves an authenticated gateway one `UpdateGateway` call away from accepting unauthenticated requests. A policy that conditions on the key in a shape which cannot deny the value `NONE`, such as a `Null` test on a member the create request always carries, fails as ineffective. AG-24 reads the authorizer type of the gateways that exist now, which says nothing about the next one created. A policy counts only when it is attached to the assessed account, to an organizational unit above it, or to the root, read with `ListParents` and `ListTargetsForPolicy`: a guard attached elsewhere fails as unattached, the management account fails as not enforced because no SCP restricts it, and an unreadable parent chain or attachment list is `N/A`, never `Passed`. `IfExists` operators read as their plain form. A Deny counts only when the authorizer type is its sole condition key and its `Resource` is `*` or an ARN pattern with wildcard Region, account and resource id: an ANDed `aws:PrincipalArn` exemption or tag test, a `NotResource`, and a `Resource` narrowed to one Region or to `gateway/prod-*` each leave writes outside them undenied. A member account that cannot list the organization's policies is reported as informational `N/A` and never as a failure. Reported once under the `Global` region.

### AC-29: Runtime Authorizer Guardrail

- **Severity:** High
- **Description:** Requires a service control policy that denies both `CreateAgentRuntime` and `UpdateAgentRuntime` when `bedrock-agentcore:RuntimeAuthorizerType` is `AWS_IAM`, because a runtime on SigV4-only inbound auth authenticates the calling AWS principal, which for a hosting application is one shared role for every end user, and the end user then arrives in an unverified header. A deny on create alone fails separately. A policy written the other way round, denying `CUSTOM_JWT` and leaving SigV4 as the only way to deploy, is reported as inverted, and a condition shape that denies neither value is reported as ineffective. As with AC-28, a Deny counts only with no other condition key and a `Resource` reaching every runtime, a policy counts only when it is attached to the account or a parent of it, an inverted policy is reported only when attached, and a member account that cannot list policies is informational `N/A`. Reported once under the `Global` region.

### AC-30: Runtime Inbound Authorization

- **Severity:** High
- **Description:** Reports how each runtime authenticates its caller. A runtime with no inbound authorizer passes, because every invoke must then be SigV4-signed and IAM decides which principal reaches the agent. A JWT authorizer that pins neither `allowedAudience` nor `allowedClients` fails, because it accepts every token its issuer minted for every application registered with that issuer. A list holding a blank value or a `*` does not pin, and a `discoveryUrl` that is not `https` fails whatever the lists hold. Each version a runtime endpoint names as its `liveVersion` or `targetVersion` is read with `GetAgentRuntime` and judged on its own row, because each version carries its own authorizer. When `ListAgentRuntimeEndpoints` is denied, the version `GetAgentRuntime` returns by default is still judged, a pass on it is informational `N/A` naming `bedrock-agentcore:ListAgentRuntimeEndpoints`, and a failure stands. AG-24 asks this of a gateway, and a runtime callers invoke directly never passes through one. An authorizer shape the pinned botocore model does not define is informational `N/A` and names the members it found.

### AC-31: Gateway Inbound Allow Lists

- **Severity:** High
- **Description:** Judges which issuers and applications each gateway accepts tokens from. A `CUSTOM_JWT` gateway that allow-lists neither the audience nor the client id fails, because any application registered with that issuer reaches its tools. A list holding a blank value or a `*` does not pin, and a `discoveryUrl` that is not `https` fails whatever the lists hold. A scope or custom-claim constraint bounds what a token may ask for and not who minted it for whom, so it does not satisfy the check. `authorizerType` `NONE` fails as performing no inbound authentication at all. A SigV4 gateway passes, having no bearer token to allow-list, and an unrecognized authorizer type or a missing `customJWTAuthorizer` is informational `N/A`.

### AC-32: Inbound JWT Issuer Conditions

- **Severity:** High
- **Description:** Fails any cached IAM role or user that can call `GetWorkloadAccessTokenForJWT` or `CompleteResourceTokenAuth` with no condition on the inbound token's issuer, audience, or client id, or with one whose `StringLike` value carries a `*` or `?` (`https://cognito-idp.*.amazonaws.com/*` admits every user pool), because the token-exchange APIs accept an end user's JWT directly and never pass through a gateway authorizer. AC-31 pins the issuer at the gateway's front door; this is the second path to the same workload token. An `Action` element of `"*"` is a service-agnostic administrator grant and is left to AC-02. An empty or unreadable permission cache is informational `N/A`. Reported once under the `Global` region.

### AC-33: Token Issuance Scope

- **Severity:** High for a wildcard resource; Medium for a grant naming only a workload-identity directory
- **Description:** Judges which resources each cached principal may mint agent tokens against. The control is not enforced by removing the actions: the reference execution role grants all three `GetWorkloadAccessToken*` actions and an agent breaks without them, so what a policy can still do is bound which workload identity, token vault, and credential provider they reach. A wildcard resource fails, and AWS's own consent-portal execution role allows three of these actions on `Resource: "*"`, so the widest grant on the page is one a customer may have copied forward. A grant naming only a workload-identity directory is reported at Medium, because the service authorization reference marks both the identity and the directory as required and does not say whether the directory alone authorizes the call. A grant naming workload identities passes only for a role that a runtime or gateway in the assessed region runs as, and only when every identity it names is one those resources report in `workloadIdentityDetails`, read with `ListAgentRuntimes`, `GetAgentRuntime`, `ListGateways` and `GetGateway`. A runtime or gateway role naming another agent's identity in the assessed region fails at High. A principal no resource runs as, a user, an identity in another region, and any identity left unmatched while one of those reads failed are informational `N/A` as `AgentCore Token Issuance Scope Unattributed`, naming the failed reads. Reported once under the `Global` region.

### AC-34: Runtime Inline Credentials

- **Severity:** High
- **Description:** Scans every AgentCore definition that can carry a credential inline and fails one that holds any, because a credential pasted into a definition never reaches the token vault. Three definitions are read, one finding each: a runtime's environment variables; a gateway target's static query parameters, OAuth custom parameters and inline schema payloads; and a harness's environment variables, remote MCP headers and URLs, OAuth custom parameters, system prompt, `apiBase` URL and model `additionalParams`. These are the fields the APIs model as sensitive, and only names and field paths are reported, never values. A credential-named entry fails unless its value is an ARN, a path, a URL, a number or a boolean; a value holding a slash reads as a secret name unless it is a base64 string of 40 or more characters. An access key id, a PEM private key, and a URL carrying a password or a credential-named query value fail under any name, and an inline schema or prompt is searched for access key ids and PEM private keys. `Authorization`, `Proxy-Authorization` and `Cookie` headers count as credential-named. AC-14 judges the token vault's own encryption. A definition with nothing to scan passes; an unreadable runtime, gateway, target or harness, and a harness list that could not be read, are informational `N/A`. When `bedrock-agentcore:ListHarnesses` is denied, the harness leg reads `N/A` naming it. The agent's code and container image are not readable through any AgentCore API, and every passing resolution says so.

### AC-35: Policy Tool Scope

- **Severity:** High for an unconditional permit; Medium for a permit that names no action under a condition
- **Description:** Reads the active enforcing policies of the policy engine each gateway enforces and fails a permit that names no action. With no condition on it, such a permit authorizes every tool the gateway exposes for every caller the scope admits and the engine's default-deny decides nothing; under a condition, the one condition gates every tool the gateway exposes today and every tool added later. Default-deny and forbid-wins are enforced by the engine and are not settings to read. A permit over named tools is also read for its principal and resource, following the recommendation to scope each policy to a principal type, an exact action, and a gateway ARN. A bare `principal` fails as `Caller Scope Unbounded` unless a `when` block reads the principal, such as a tag test; the condition body is not evaluated. An `unless` block on the principal only removes callers, and a `principal` word inside a string literal or as a context attribute (`context.principal`) is not a read of the principal, so none of them bounds a bare principal. A resource named by type alone, such as `resource is AgentCore::Gateway`, or not at all fails as `Gateway Scope Unbounded`, because the permit then follows the engine onto every gateway it is attached to; only `==` or `in` an entity names one. A gateway enforcing no engine and an engine with no active enforcing policy are informational `N/A`. A policy still being generated carries no text, and a policy head without three scope positions cannot be scored; either is informational `N/A` and withholds the gateway's `Passed`, because the unread policy could permit any tool.

### AC-36: Policy Engine Key Scope

- **Severity:** High
- **Description:** Requires the key policy behind a policy engine's customer managed key to bind the principals allowed to decrypt with it, read by the AC-26 rules, and the administrators allowed to disable it or schedule it for deletion. The key cannot be added to or changed on an existing engine, so the key policy is the whole guard: a principal who can schedule the key for deletion makes every stored Cedar policy unreadable with no way to repoint the engine. AC-11 asserts that a key is named, which is presence only. The key policy must also carry the service-use statements the policy encryption guide shows: `kms:CreateGrant` only with `kms:ViaService` `bedrock-agentcore.<region>.amazonaws.com` for the engine's Region and `kms:GrantConstraintType` `EncryptionContextSubset`, and `kms:Decrypt` and `kms:GenerateDataKey` with the same `kms:ViaService` and an `aws:SourceAccount` or `aws:SourceArn` naming the engine's account. An `IfExists`, `ForAllValues` or wildcard `kms:ViaService` scopes nothing and is not credited: `ForAllValues` is true for a request that carries no `kms:ViaService`, such as a direct call. The `kms:CreateGrant` statement and the `kms:Decrypt` and `kms:GenerateDataKey` statement must each carry a `kms:EncryptionContext:aws:bedrock-agentcore-policy:policy-engine-arn` condition whose every value names the `bedrock-agentcore` service and a `policy-engine/` resource and matches the engine's ARN, as the guide's `arn:aws*:bedrock-agentcore:*:*:policy-engine/*` does; `*`, another resource type, another engine and the `IfExists` and `ForAllValues` forms are not credited. A statement scoped to AgentCore by `kms:ViaService` fails when it grants any action beyond `kms:CreateGrant`, `kms:Decrypt`, `kms:GenerateDataKey` and `kms:DescribeKey`, including `kms:*`, `kms:GenerateDataKey*` and a `NotAction`. The key must carry two distinct grants whose encryption context names the engine ARN under `aws:bedrock-agentcore-policy:policy-engine-arn`, one allowing `GenerateDataKey` (management) and one allowing a `ReEncrypt` operation (evaluation); `kms:ListGrants` is read across every page. A statement that grants the same actions with no condition, such as the account-root `kms:*` statement, is not subtracted. An engine with no customer managed key is informational `N/A` and AC-11 reports it; an unreadable key policy, a key whose grants could not be listed, and an engine reporting no ARN are informational `N/A`. The key also needs an alarm in the engine's Region on its `DisableKey` and `ScheduleKeyDeletion` calls: an `ENABLED` EventBridge rule on the default bus whose pattern matches both calls as CloudTrail delivers them (`source` `aws.kms`, `detail-type` `AWS API Call via CloudTrail`, `detail.eventName`), or a CloudWatch Logs metric filter whose pattern names both calls feeding an alarm with actions enabled and at least one alarm action, or when an acting composite alarm's rule joins only `ALARM(...)` terms with `OR` and reads it, directly or through a nested composite. A rule that also filters on the key id or uses a content filter is not credited. With neither found and every read made, the key fails; when `events:ListRules`, `logs:DescribeMetricFilters` or `cloudwatch:DescribeAlarms` could not be read, the leg is informational `N/A`, never `Passed`, and the resolution names the actions. The rule must have a target, found through `ListTargetsByRule`; what the target does with the event, the trail feeding the filter's log group, and the break-glass runbook are not read, and the passing resolution says so.

### AC-37: Policy Guardrail Wiring

- **Severity:** High
- **Description:** For each gateway enforcing a policy with a `when guardrails` condition, requires the gateway's execution role to grant `bedrock:InvokeGuardrailChecks`, because the Policy data plane calls the Bedrock Guardrails API with forward access session credentials derived from that role. Without the grant the call is denied and the content safety the policy claims is either absent or the tool is unreachable, which the devguide does not resolve either way. The action has no resource type in the IAM service reference, so IAM matches it only with `Resource: "*"`: a grant scoped to guardrail ARNs or other named resources fails, and a grant that reaches `*` only under a `Condition` is informational `N/A`, because the condition is not evaluated against the forward access session. A scored guardrail comparison that leaves out a score equal to the safeguard's documented default threshold (0.2 for `ContentFilter`, 0.4 for `PromptAttack`, 0.2 for `SensitiveInformation`), which is `greaterThan` at the default in a `forbid` or `suppressOutput` policy or `lessThanOrEqual` at the default in a `permit`, fails at Medium as `Default Band Excluded` and withholds the `Passed`, because guardrails return only the discrete scores 0, 0.2, 0.4, 0.6, 0.8 and 1.0. A policy fails as `Guardrail Inert` when no score the guardrail returns changes its decision, read through the `&&` and `||` that join its calls and its when blocks: a `forbid` conjunction holding a comparison no score satisfies, such as `greaterThan(decimal("1.0"))`, never acts, and a `permit` disjunction holding one every score satisfies always applies. A negated guardrail condition, or a guardrail call in an `unless` block, is informational `N/A`. Whether content-safety decisions belong at the authorization boundary at all is the workload owner's call, and a gateway enforcing no guardrail policy is reported as informational `N/A` that says so. An execution role outside the permission cache, and a role with unparsable policy documents, are informational `N/A`.

### AC-38: Policy Session Binding

- **Severity:** High when a temporal policy runs on a gateway that authenticates no caller; Medium when no enforcing policy is session-aware
- **Description:** Judges whether a rule that only reads across a sequence of actions, such as an unverified payee or a cumulative overspend, is evaluated against a policy session, and whether that session binds to a caller. The Gateway binds a session to the caller's authenticated identity on `CUSTOM_JWT` and `AWS_IAM` gateways, so on a gateway that authenticates no caller two callers presenting the same session id share one accumulated history and a per-session limit is reset or consumed by someone else. An engine whose active enforcing policies carry no temporal condition is reported at Medium, because every request is then judged on its own and any sequence rule is enforced by agent or tool code. AG-25 does not read whether any enforcing policy is session-aware. Each event pattern a temporal policy matches, written as `AgentCore::Action::"<tool>"::request{ ... }` or `::response` or `::error`, has to carry `eventResource: resource`, naming the request's own resource, and every temporal statement in a policy is read. A policy with a pattern that omits `eventResource` or sets it to another entity fails as `Session Rule Resource Unscoped`. A temporal policy in which no event pattern can be read is informational `N/A` and withholds the `Passed`. Whether the workload's multi-step rules are the ones written and whether the first caller sends the `x-amzn-bedrock-agentcore-policy-session-id` header are not read: the rules have no declared counterpart in any API, and the header is set per request.

### AC-39: Online Evaluation Operation

- **Severity:** Medium
- **Description:** Requires each online evaluation configuration to be `ACTIVE` and `ENABLED`, to sample a non-zero share of traffic, to read from at least one input source, and to write its scores to a log group, and names which of those stopped it running. An input log group is read from `logGroupNames` or `logGroupNamePrefixes`. A region with no configurations is informational `N/A`, and AC-17 reports whether each runtime is scored.

### AC-40: Evaluation Safety Coverage

- **Severity:** Medium
- **Description:** Requires each online evaluation configuration to attach a safety evaluator and a tool-choice evaluator, and a CloudWatch alarm to watch its scores. The safety evaluator is classified from the evaluator catalogue by a service-authored description carrying `safety metric`. The tool-choice evaluator is `Builtin.ToolSelectionAccuracy` or `Builtin.ToolParameterAccuracy`, named by id because the skill evaluators also score at `TOOL_CALL` level. The alarm leg reads `cloudwatch:DescribeAlarms` across every page and counts a metric alarm, or a metric-math alarm through its `MetricStat` entries, that reads a metric in the configuration's `metricsNamespace` (or `Bedrock-AgentCore/Evaluations` in either documented spelling when unset), has `ActionsEnabled` true and names an `AlarmActions` target, or when an acting composite alarm's rule joins only `ALARM(...)` terms with `OR` and reads it, directly or through a nested composite. When such an alarm exists the check lists the namespace's metrics with `cloudwatch:ListMetrics`, and an alarm counts only when its metric name and dimension set match a listed metric exactly, because an alarm on a misspelled name or on dimensions the service does not publish never fires. When `ListMetrics` lists nothing in the namespace the namespace match stands and the row says so, since `ListMetrics` returns only metrics with recent data. A denied `ListMetrics` makes a configuration that would otherwise pass informational `N/A` naming the action. AC-17 and AC-39 count evaluators without asking what any of them scores, so ten answer-quality judges read the same as a harmful-content judge. If either evaluator category is empty in the catalogue the check judges no configuration and reports informational `N/A` with both counts. An unreadable catalogue is informational `N/A`, and unreadable alarms make a configuration that would otherwise pass informational `N/A`, never `Passed`.

### AC-41: Evaluation Result Protection

- **Severity:** Medium
- **Description:** Judges the log group each online evaluation writes its results to, anchored on the configuration's `outputConfig` and not on a log group name. An evaluation result carries the agent output that was scored and the judge's reasoning about it, and AC-20 and AC-26 judge only log groups under an AgentCore prefix, so this check reads the results group's retention, key and key policy itself, with the AC-26 key policy rules. An unreadable key policy is informational `N/A` and never `Passed`. Retention length is reported and not judged, because no API field states the workload's schedule. A results group that does not exist in the region fails, because CloudWatch Logs creates it on first write with no encryption key and no retention period. A configuration naming no results group is informational `N/A`: with `resultDestination` `SOURCE_LOG_GROUP` the results go to the input log groups, which AC-20 and AC-26 judge under the AgentCore prefixes, and otherwise AC-39 reports the missing output configuration. A second set of rows judges keys. Each custom evaluator an online configuration or a batch evaluation attaches is read with `GetEvaluator` (`METADATA_ONLY`, which needs no `kms:Decrypt`): no `kmsKeyArn` fails, because an online configuration takes no key of its own and the evaluator's instructions and rating scale are then under a key the account does not control. Each batch evaluation `ListBatchEvaluations` returns fails with no `kmsKeyArn`, and its `GetBatchEvaluation` results log group is judged by the rules above. A named key is credited only when `DescribeKey` reports `KeyManager` `CUSTOMER` and `KeyState` `Enabled`. Built-in evaluators are not read. The key policies' encryption context and `kms:ViaService` conditions are not read. A denied `GetEvaluator`, `ListBatchEvaluations`, `GetBatchEvaluation` or `DescribeKey` is informational `N/A` naming the action.

### AC-42: Evaluation Pass Role Scope

- **Severity:** High
- **Description:** Fails any cached principal that can pass an evaluation execution role through an `iam:PassRole` grant wider than the one role, or without an `iam:PassedToService` condition naming the service the role was written for. Creating or updating a configuration means passing the role named in `evaluationExecutionRoleArn`, so a wide grant turns evaluation administration into a way to run a role the caller could not assume. A role-name pattern such as the recommended `role/AgentCoreEvaluationRole*` is wide only when it reaches a cached role that no configuration names, and the failure names that role. The cache holds role names and no paths, so a pattern with a path, a leading wildcard, or no literal account is still read as wide. On the primary region, principals that can write a configuration are judged the same way whether or not one exists, and a grant whose `iam:PassedToService` condition excludes `bedrock-agentcore.amazonaws.com` (for example `StringEquals` on `lambda.amazonaws.com` alone) is skipped there because it cannot pass any role to AgentCore. A region whose configurations name no execution role, and an empty permission cache, are informational `N/A`; unparsable cached policy documents are reported on their own informational `N/A` row so the judged grants still stand.

### AC-43: Evaluation Role Trust

- **Severity:** High
- **Description:** Requires every `Allow` statement in an evaluation execution role's trust policy to carry `aws:SourceAccount` or `aws:SourceArn`, or to name no service or wildcard principal. A guarded statement fails as `Source ARN Not Scoped` unless it also carries an `aws:SourceArn` whose every value names the account, a Region and an AgentCore `evaluator` or `online-evaluation-config` resource, the form AWS documents (`arn:aws:bedrock-agentcore:<region>:<account>:evaluator/*` and `online-evaluation-config/*`). `aws:SourceAccount` alone, or a value such as `arn:aws:bedrock-agentcore:*:<account>:*`, lets the service assume the role for any AgentCore resource in the account, and a value naming another resource type (`gateway/*`) lets it assume the role for that resource. The role lets the service read the scored traces and invoke the judge model on the account's behalf, so without a guard the same service principal assumes it while acting for another customer's configuration. AC-27 judges this on gateway execution roles and reaches no evaluation role, because it reads the roles that gateways name. A configuration naming no role, and an unreadable trust policy, are informational `N/A`.

### AC-44: Evaluation Judge Model Scope

- **Severity:** Medium
- **Description:** Fails an evaluation execution role that can invoke a model through a `Resource` pattern naming no model, because an LLM-as-a-judge prompt carries the agent output being scored, so every model such a grant reaches is a model attacker-influenced text can be sent to at that model's price. Which models a workload's judges may use is the workload owner's decision, so the check asserts that the grant names models, and then reads each custom evaluator the role's configurations attach with `GetEvaluator` (`METADATA_ONLY`) and fails a pattern that reaches no model those evaluators call. A pattern is compared to a model id as `foundation-model/<id>` or `inference-profile/<id>`, and a cross-Region profile id (`us.`, `eu.`, `apac.`, `global.`, `us-gov.`) also reaches its foundation model, because a profile call needs that grant too. An evaluator that cannot be read turns a pass into informational `N/A` naming `bedrock-agentcore:GetEvaluator`. Built-in evaluators are not read, so a role whose configurations attach only built-ins passes on bounded patterns. A role with no model-invocation grant passes. A role outside the permission cache is informational `N/A`, and unparsable documents are reported on a separate informational `N/A` row.

### AC-45: Tool Execution Role Scope

- **Severity:** High
- **Description:** Judges the execution role a custom Code Interpreter or custom Browser Tool can use, and fails a role whose `Allow` statements grant every resource or every action of a service. Code the model writes runs in the sandbox with that role, and a browser session follows the pages it is pointed at with the same role, so the role has to be read as available to whatever the sandbox ends up running. `executionRoleArn` is optional on both create calls, so a tool that names no role passes, holding no credentials to misuse. A resource ARN with a wildcard anywhere in its resource part, such as `arn:aws:s3:::prod-*` or `table/prod-*`, counts as every resource. A role outside the permission cache, and a role in an account other than the tool's, are informational `N/A`. Each AgentCore runtime's own `roleArn` is judged by the same rules as an `AgentCore Runtime Execution Role Scope` row, because the agent's code runs with it; AC-02 reads the AgentCore namespace only, so a runtime role granting `s3:*` or every foundation model passed it. For a runtime role, a statement whose every action has no resource type in its service reference (`ecr:GetAuthorizationToken`, `logs:DescribeLogGroups` and the four X-Ray actions a runtime needs) is not read as granting every resource, since `*` is the only resource such a grant can name. A runtime whose detail reports no `roleArn`, which `CreateAgentRuntime` requires, and a runtime or runtime list that cannot be read, are informational `N/A` naming the action. On the primary region the check also reads who can call `InvokeAgentRuntimeCommandShell` or `InvokeAgentRuntimeCommand`, and fails a grant that reaches either without naming it or on every runtime. When any principal holds either action, the service's shell sessions go unlogged, so a CloudWatch Logs metric filter in that region has to count shell connections, by naming the `InvokeAgentRuntimeCommandShell` event or by naming a shell on a `/aws/bedrock-agentcore/runtimes/` log group, and feed an alarm with actions enabled and an alarm action, or when an acting composite alarm's rule joins only `ALARM(...)` terms with `OR` and reads it, directly or through a nested composite. Without one the row fails at Medium as `Unwatched`; a `logs:DescribeMetricFilters` or `cloudwatch:DescribeAlarms` read that fails is informational `N/A` naming the action and withholds the `Passed`. The runtime log line for a shell connection is not documented, so the runtime log group form is matched by name, and the alarm's targets are not read.

### AC-46: Runtime Session Limits

- **Severity:** Medium
- **Description:** Fails a runtime whose `idleRuntimeSessionTimeout` or `maxLifetime` is set to the service ceiling of 1,209,600 seconds (14 days) as `Session Limit Unbounded`, and one whose either field exceeds the 28,800-second (8 hour) maximum lifetime AWS applies when none is set as `Session Limit Above Default`, because each `runtimeSessionId` gets its own microVM and a runaway task holds its session, its filesystem, and its accumulated context until one of the two timers fires. A ceiling test alone passed 1,209,599 seconds. A value at or under the default passes; how much shorter this workload's sessions should be is the workload owner's decision. `GetAgentRuntime` reports the defaults of 900 and 28,800 seconds for a runtime that sets neither field, so whether the owner chose the values is not readable. The control plane carries no per-session memory or cost limit, so the check judges whether usage is recorded and alarmed: a runtime fails as `AgentCore Runtime Session Usage Unmonitored` when it has no `USAGE_LOGS` delivery source with a delivery to a destination, or when no CloudWatch alarm in the region that reaches an action (its own `ActionsEnabled` true and an `AlarmActions` target, or an acting composite alarm whose rule joins only `ALARM(...)` terms with `OR`) reads `ActiveSessionCount` in `AWS/Bedrock-AgentCore` with the `Service` dimension `AgentCore.Runtime`, on the alarm itself or through a metric-math `MetricStat`. That metric carries only the `Service` dimension, so one alarm covers every runtime in the region. A runtime missing either lifecycle field, and a delivery or alarm inventory that could not be read, are informational `N/A` naming what was not read, and neither hides a failure found on another leg. Spend is judged on one `AgentCore Runtime Cost Anomaly Alerting` row per region that holds a runtime: the account needs a Cost Anomaly Detection subscription with a subscriber whose status is not `DECLINED`, on a `DIMENSIONAL` monitor with `MonitorDimension` `SERVICE`, which watches every AWS service. No such subscription fails. A subscription whose only monitors are `CUSTOM` is informational `N/A`, because the monitor's specification is not judged, and the alert threshold is not judged. A denied `ce:GetAnomalySubscriptions` or `ce:GetAnomalyMonitors` is informational `N/A` naming the action; the AgentCore assessment role is granted both.

### AC-47: Runtime Invocation Path

- **Severity:** High for the caller leg; Medium for the network-path leg
- **Description:** Judges who may invoke each runtime and over what path. A runtime carrying neither an `allowedWorkloadConfiguration` on its JWT authorizer nor a resource policy naming the principals allowed to invoke it fails, because a caller that satisfies its inbound authentication then reaches the agent directly and the tool policy, rate limits, and audit trail of the gateway in front of it do not apply. The network leg passes only on a resource policy `Deny` that refuses every runtime invoke action (`InvokeAgentRuntime`, `InvokeAgentRuntimeForUser`, `InvokeAgentRuntimeCommand`, `InvokeAgentRuntimeCommandShell`, `InvokeAgentRuntimeWithWebSocketStream`, `InvokeAgentRuntimeWithWebSocketStreamForUser`) to every principal outside a bounded `aws:SourceVpc`, `aws:SourceVpce`, `aws:VpcSourceIp`, or `aws:SourceIp` value, and names each invoke action no `Deny` reaches. A `Bool` `aws:ViaAWSService` `false` entry on that `Deny` is accepted and named in the finding, since it exempts only a call an AWS service makes on the caller's behalf; any other value or operator on that key fails as an ANDed key. An `Allow` condition alone does not restrict a same-account caller whose identity policy grants the call, and a positive or `ForAnyValue` operator, a wildcard endpoint, an address list covering every address, and a `Deny` that ANDs in another key or names specific principals fail with the reason named. The caller leg passes on `allowedWorkloadConfiguration` or a `Deny` refusing every runtime invoke action to every principal outside a bounded `aws:PrincipalArn` list, where the `aws:ViaAWSService` exemption is not accepted, and a resource policy `Allow` naming principals does not pass it. AC-10 reports that a resource policy exists; the conditions inside it are what restrict anything. An unreadable runtime or resource policy is informational `N/A`.

### AC-48: Execution Role Trust and Sharing

- **Severity:** High for the trust leg; Medium for the sharing leg
- **Description:** Reads the trust policy of the execution role named by every runtime, gateway, browser and custom code interpreter. A statement that trusts the service principal, or `*`, with no `aws:SourceAccount` or `aws:SourceArn` condition fails as a confused-deputy gap, and an account-root or bare account-id principal with no condition fails as account-wide trust. A second finding fails a role that more than one AgentCore resource names, because the shared role carries the union of the permissions each workload needs. AC-27 reads the gateway roles for the same deputy guard. An unreadable role is informational `N/A`.

### AC-49: DNS Egress Control

- **Severity:** Medium
- **Description:** For each VPC that hosts an AgentCore runtime, browser or code interpreter, reads the Route 53 Resolver DNS Firewall rule group associations and walks them in the order DNS Firewall evaluates them: rule groups by ascending association priority, and the enforcing rules in each by ascending priority. The first match ends evaluation for `ALLOW`, `ALERT` and `BLOCK` alike, so the check judges the first rule whose customer domain list holds `*`, names its rule group and rule, and ignores every rule after it. It passes only when that rule is a `BLOCK` with no query type, which is the walled garden pattern Route 53 documents; an `ALLOW` or `ALERT` over `*` fails. `ListFirewallDomains` returns that entry fully qualified as `*.`, and the check reads either spelling. A VPC with no rule group fails, and so do rule groups with no rule over `*`, where only a `BLOCK` over an AWS managed list, over DNS threat protection, over a list without `*`, or over `*` for one query type (`Qtype`) stands, because every name or query type those rules do not match is answered. A deciding `BLOCK` passes only when `GetFirewallConfig` reports `FirewallFailOpen` `DISABLED` for the VPC, which Route 53 documents as the default. `ENABLED` fails as `AgentCore DNS Egress Control Fails Open`, because VPC Resolver answers every query while DNS Firewall is impaired, including a name the rule blocks. The documentation defines no other value, so `USE_LOCAL_RESOURCE_SETTING` or a missing value is informational `N/A` with the value named, and an unreadable firewall config is informational `N/A`. A VPC whose rules already fail is not read for this setting. A hosting subnet that no longer exists is reported by id as not present. AC-01 and AC-15 judge egress by security group and network mode; this check judges it by destination name.
- **Network Firewall leg:** For the same VPCs, follows each hosting subnet's `0.0.0.0/0` and `::/0` routes one hop, to an AWS Network Firewall endpoint in the VPC or through a NAT gateway to the route of the NAT gateway's subnet. A route to an internet gateway, an egress-only internet gateway, or a NAT gateway that routes to one fails both rows. Two rows are reported per VPC. `AgentCore Network Firewall Egress` requires each reached firewall's policy to reference an `ALLOWLIST` domain list rule group matching `TLS_SNI` and `HTTP_HOST`, fails a `REJECTLIST` or `ALERTLIST` domain group beside it under `DEFAULT_ACTION_ORDER` (the default when no rule order is set), and fails a `HOME_NET` set in the policy or the allow-list group that does not hold every hosting subnet CIDR. `AgentCore Network Firewall Threat Inspection` requires an AWS managed `ThreatSignatures` rule group and one of `MalwareDomains`, `BotNetCommandAndControlDomains` or `AbusedLegitMalwareDomains`, neither overridden to `DROP_TO_ALERT`. A transit gateway, Gateway Load Balancer endpoint or other target is not followed and is informational `N/A`, and so is a VPC whose subnets reach no firewall. IP and CIDR rules and the stateful default actions are not judged. A denied `network-firewall:DescribeFirewallPolicy` or `ec2:DescribeNatGateways` read makes these rows informational `N/A` naming the denied action.

### AC-50: ECR Enhanced Scanning

- **Severity:** Medium
- **Description:** Requires the registry scanning configuration to put every AgentCore image repository under Amazon Inspector enhanced scanning at `CONTINUOUS_SCAN` frequency. `SCAN_ON_PUSH` fails, because it scans an image once when pushed and a CVE published later is not reported against it. A repository is an AgentCore repository when an AgentCore runtime's `containerUri` from `GetAgentRuntime` names it, matched on registry account, region and repository path, or when its name contains `agentcore` or `bedrock-agent`. A runtime whose detail cannot be read, whose image is not an Amazon ECR URI, or whose image comes from a registry in another account or region is informational `N/A` with the runtime named, and so is a runtime inventory that cannot be listed; the repositories named for AgentCore are still judged. A runtime deployed from code has no image and adds no repository. A registry on `BASIC` scanning fails every such repository, and so does a repository that no `WILDCARD` rule matches, which Amazon ECR scans at frequency `Off`. Filters follow the ECR rule: a filter with no `*` matches every name that contains it, and a filter with `*` must match the whole name. When two rules match, `CONTINUOUS_SCAN` is reported. AC-05 judges the encryption of the same repositories. A region with no AgentCore repository is informational `N/A`, and an unreadable scanning configuration is informational `N/A`.
- **Inspector coverage and finding gate:** `AgentCore ECR Inspector Coverage` reads Amazon Inspector `ListCoverage` for `AWS_ECR_REPOSITORY` resources and passes a repository only when Inspector reports it `ACTIVE`; any other status fails with the reason Inspector gives, and a repository Inspector does not list fails. `AgentCore Image Finding Gate` passes when an enabled EventBridge rule on the default bus matches source `aws.inspector2` and detail-type `Inspector2 Finding`, is not limited by a literal `detail.resources.type` list that omits `AWS_ECR_CONTAINER_IMAGE`, and has a target. A severity filter is the workload's threshold and is not judged, and what the target does with a finding is not read. A denied `events:ListTargetsByRule` read makes the gate row informational `N/A` naming it, and a denied `ListCoverage` or `ListRules` read is `N/A` naming that action.

### AC-51: Web ACL Anti-DDoS

- **Severity:** Medium
- **Description:** For each AgentCore gateway, reads the web ACL that `GetGateway` reports and requires it to run the AWS managed rule group `AWSManagedRulesAntiDDoSRuleSet`. A gateway with no web ACL fails, because nothing mitigates a request flood against it, and AG-27 reports the missing association. The group is not credited when its rule overrides the group action to `Count`, when a rule inside it is overridden to `Count` or `Allow` or excluded, because the group's soft mitigation is a `Challenge`, or when a group of that name comes from a vendor other than AWS. Rule groups that Firewall Manager adds before and after the web ACL's own rules are read as part of it. The web ACL must also apply a rate-based rule whose action is `Block`, which caps the request rate of one caller and so the inference spend a flood runs up; a rule set to `Count`, `Captcha` or `Challenge` is not credited, and the rule's limit and scope-down statement are not judged. Neither the group nor the rate-based rule is credited when it runs after an `Allow` rule, in the order AWS WAF runs the rules, and the finding names the `Allow` rule. When no such rule is found and the ACL references a customer rule group or another vendor's managed rule group, whose rules live in another resource, the rate leg is informational `N/A`. A passing gateway's finding names the `SensitivityToBlock` and `ClientSideActionConfig.Challenge` settings the group runs with, filling in the API defaults (`LOW` to block, `HIGH` to challenge) where the configuration omits one, and says when `UsageOfAction` is `DISABLED`. The settings are reported and not graded: the control asks for a deliberate choice, and the configuration records a value, not whether it was chosen. Shield Advanced enrollment is not judged, because `shield:CreateProtection` accepts no AgentCore gateway ARN. A gateway whose association cannot be read, and a web ACL whose rules cannot be read, are informational `N/A` with the reason. Front doors other than AgentCore gateways (API Gateway, ALB, CloudFront) are not identifiable as AI entry points by any API, so they are not judged.

### AC-52: Cognito User Pool Authentication

- **Severity:** Medium
- **Description:** Answers Prowler's AISF-IAM-07 "Cognito User Authentication for AI Apps" for the user pools an AI application uses: the pools named in the `discoveryUrl` of a `CUSTOM_JWT` inbound authorizer on an AgentCore gateway or runtime. Each pool is judged once, in one row that names every gateway and runtime using it. Per pool, reproducing Prowler's Cognito checks: `MfaConfiguration` is `ON`; threat protection (`AdvancedSecurityMode`) is `ENFORCED`, so `AUDIT` fails; `AllowAdminCreateUserOnly` is true; `DeletionProtection` is `ACTIVE`; and temporary passwords are valid for 7 days or fewer. Per app client: `EnableTokenRevocation` is on, and `PreventUserExistenceErrors` is `ENABLED`. The row names the pool's feature plan (`UserPoolTier`). A pool whose every app client allows only the `client_credentials` OAuth flow and no sign-in flow other than `ALLOW_REFRESH_TOKEN_AUTH` signs in no end user, so the MFA, threat protection, self-registration, temporary password and user existence legs do not apply to it, and it is judged on deletion protection and token revocation. A client with no `ExplicitAuthFlows` is user-facing, because Cognito gives such a client the SRP and custom sign-in flows by default. Up to 100 app clients are read per pool; when more exist, a leg the unread clients could change is reported as unproven in an informational `N/A` row, and a leg already failed by a client that was read still fails. A pool in another Region, a pool this account cannot find (another account's, or deleted), and a pool or resource that cannot be read are informational `N/A` with the reason. Issuers other than Cognito are not judged. Prowler's `cognito_user_pool_waf_acl_attached` and `cognito_identity_pool_guest_access_disabled` are not reproduced: the first needs a web ACL lookup per pool that the assessment role is not granted, and no AgentCore authorizer names an identity pool, so none can be traced to an AI application.

### AC-53: Inter-Agent Anomaly Alarms

- **Severity:** Medium
- **Description:** Answers AISF `AIR-FND-DET-10` for the agent-to-agent calls Application Signals records. `ListMetrics` on the `ApplicationSignals` namespace, for `Error`, `Fault` and `Latency`, lists a dependency metric per caller (`Service`) and callee (`RemoteService`). A pair is judged when its `Environment` starts with `bedrock-agentcore:` and its `RemoteService`, with any `AWS::` prefix removed, names another runtime or gateway from `ListAgentRuntimes` or `ListGateways`: a gateway by its id or name, a runtime by its id or name or `<agentRuntimeName>.<endpointName>`. A call from a gateway to its policy engine (`ListPolicyEngines`) is excluded, as is a call a resource makes to itself. Each pair fails without a metric alarm whose actions are enabled and non-empty, or that an acting composite alarm reads through a rule joining only `ALARM(...)` terms with `OR`, and whose `ThresholdMetricId` names an `ANOMALY_DETECTION_BAND` expression over a `MetricStat` in `ApplicationSignals` on one of the three metrics. That metric must carry the pair's `Service` and `RemoteService`; other dimensions it carries, `Operation` included, do not change the result. A caller whose `RemoteService` is `UnknownRemoteService` is named in an informational `N/A` row and is never `Passed`, because Application Signals did not name its callee. Passed names each pair and its alarms. With no pair the row is informational `N/A` and says a runtime or gateway not instrumented with Application Signals cannot be assessed. Every row names what no AWS API records: how often each multi-agent workflow runs, which metrics a workflow defines as its own, and whether a new pair raises an alert when it first appears. A denied or failed `ListAgentRuntimes`, `ListGateways`, `ListPolicyEngines`, `ListMetrics` or `DescribeAlarms` read is informational `N/A` naming the action. A composite route is named in the row.

---

## AWS Agent Registry Security Checks (10)

AWS Agent Registry checks use the `AR-XX` namespace and run in a dedicated
regional Lambda that writes its own CSV artifact and HTML report area. They are
included with the default assessment.

`AR-01` and `AR-02` are account-scoped IAM checks that read the shared
permission cache and are reported once under the `Global` region. `AR-03`
through `AR-08` are regional and use the generally available
`agent-registry-control` API. Registry detail is read once per registry and
shared across `AR-03` through `AR-06`; record inventory is shared between
`AR-07` and `AR-08`.

Record inventory is bounded to 1,000 records and paginates within the Lambda
deadline. When the cap or the deadline is reached, `AR-07` and `AR-08` report a
single informational `N/A` incomplete-assessment row and continue assessing
the records already collected. A registry that is not `READY`, a registry
whose detail call fails, an access-denied response, and a region where AWS
Agent Registry is unavailable all resolve to informational `N/A` with
error-specific remediation rather than to a failure.

### AR-01: AWS IAM Full Access

- **Severity:** High
- **Description:** Checks the attached, inline and group policy documents of every cached role and user for AWS Agent Registry full-access managed policies, wildcard IAM action patterns, and `Allow`/`NotAction` allow-except statements that still grant the `agent-registry` namespace when they apply to every resource, to a resource ARN with a wildcard in any segment, or to a `NotResource`. A registry id is service-generated, so a wildcard in it cannot select registries by name, and one in the Region or account segment reaches every registry there. A separate `AWS Agent Registry Read and Write in One Grant` row fails each identity holding a wildcard `Action` or a `NotAction` Allow that grants both a read and a write action on one Registry resource type (`registry` or `registry-record`), in the `agent-registry` namespace or the `bedrock-agentcore` spelling of it. A bare `Action: "*"` counts. An explicit action list separates the read from the write however long it is, so it is not reported; a condition or resource scope on the Allow applies to the read and the write alike, so it does not excuse the grant. The read and write split per resource type comes from the AWS service authorization reference, recorded in `iam_access_levels.json` by `generate_iam_access_levels.py`; an account-wide `Deny` with no condition removes an action. The row names up to 20 identities and summarizes the rest. A role or user the permission cache names in `principal_errors` turns a `Passed` row into `N/A` naming the principal and the failed stage, and a failing row is kept beside it; a cache written before schema version 2 keeps its verdict and says the per-principal errors were not recorded. A principal whose permissions boundary the cache could not read (a `permissions_boundary` stage in `principal_errors`) is not reported `Failed` by any AR-01 row, because a boundary could remove the grant; the `N/A` row names it. A permissions boundary removes any action it does not allow. Service control policies are not evaluated per principal; they only remove permissions, so they can make a row a false `Failed` but cannot hide a grant. An empty permission cache is an informational `N/A` tooling condition, not a failure.

### AR-02: Stale Access

- **Severity:** Medium for 60+ day inactivity; Low when all principals are active; Informational when never used or incomplete
- **Description:** Identifies IAM roles and users whose attached or inline policy documents grant the `agent-registry` namespace, either through an `Allow` action or through a `NotAction` allow-except statement that does not fully cover the namespace. Attached policy names alone are never treated as proof of access. A permissions boundary that allows no `agent-registry` action removes the principal from the population. It uses IAM service-last-accessed jobs to identify access older than 60 days and principals with no Registry usage evidence. A role or user named in the cache's `principal_errors` turns a `Passed` row into `N/A` naming it. A principal whose permissions boundary the cache could not read (a `permissions_boundary` stage in `principal_errors`) is left out of the population, because a boundary could remove its Registry access, and the `N/A` row names it. IAM job errors, timeouts, and inaccessible principals are indeterminate informational `N/A` findings rather than failures.

### AR-03: Registry Publication Approval Governance

- **Severity:** Medium
- **Description:** Fails each `READY` registry whose `approvalConfiguration.autoApprovalRules` is non-empty, such as `["APPROVE_ALL"]`, because it approves submitted records automatically, and names the rules. A registry with no auto-approval rules passes, whether it returns an empty list, omits the list, or omits `approvalConfiguration`: the `GetRegistry` API model states that submitted records require manual review when `autoApprovalRules` is omitted or empty. No deployment parameter changes this verdict.

### AR-04: Registry Discovery Authorization

- **Severity:** Informational for configured authorizers; High for an unconstrained custom JWT authorizer
- **Description:** Inventories the discovery authorizer on each `READY` registry. A custom JWT authorizer without **both** an OpenID Connect discovery URL and at least one caller constraint (`allowedAudience`, `allowedClients`, `allowedScopes`, or `customClaims`) fails. Every other outcome is informational `N/A` pending review, because the authorizer configuration alone does not establish which callers hold effective discovery access: `AWS_IAM` requires an effective-policy review, a constrained custom JWT authorizer requires comparing the approved audiences, clients, scopes, and claims against intended consumers, and an absent or unrecognized `discoveryConfiguration` establishes no authorization fact either way.

### AR-05: Registry Customer-Managed KMS Encryption

- **Severity:** Informational by default; Medium when required
- **Description:** Reads `GetRegistry.encryptionConfiguration.kmsKeyArn`. Registries with a customer-managed KMS key pass. Registries using the default AWS owned key are informational by default because AWS Agent Registry still encrypts them at rest. Set `RequireAgentRegistryCMK` to `true` (`REQUIRE_AGENT_REGISTRY_CMK` in the Lambda) to make the AWS owned key configuration fail. The registry encryption key is immutable after creation, so remediation requires a replacement registry and record migration.

### AR-06: Registry Organization Auto-Detection

- **Severity:** Medium when active; otherwise Informational
- **Description:** Passes only when a `READY` registry reports auto-detection that is enabled, scoped to `ORGANIZATION`, and `ACTIVE`. Disabled, account-scoped, or `INACTIVE` configurations are informational `N/A` because the feature is optional. An omitted or incomplete optional `autoDetection` block, and a registry that has not reached `READY`, are also informational `N/A` because the control state could not be established.

### AR-07: Registry Record Lifecycle Governance

- **Severity:** Informational
- **Description:** Paginates `ListRegistryRecords` across every accessible registry and reports the lifecycle state returned in each record summary as an advisory `N/A` observation, because occupying a documented service state does not by itself prove a security control. Review failed or unknown lifecycle states operationally. Per-registry listing failures are reported individually with error-specific remediation so one inaccessible registry does not hide the rest. `AR-07` does not affect the score unless a future baseline defines a genuine noncompliant lifecycle state.

### AR-08: Registry Record Provenance

- **Severity:** Medium
- **Description:** Verifies that manually created records retain a 12-digit creator-account attribution and that auto-detected records carry a `DETECTED_FROM` provenance summary whose `sourceId` is a `bedrock-agentcore` ARN matching its declared `sourceType`: a `runtime/...` resource for `AWS::BedrockAgentCore::Runtime` or a `gateway/...` resource for `AWS::BedrockAgentCore::Gateway`. A record whose declared lineage does not match fails, and it continues to fail even when another provenance entry omits its own source type. Optional origin-mode, creator-attribution, provenance, and source-type metadata are reported as informational `N/A` rather than as operator-remediable failures.

### AR-09: Registry Approval Authority Separation

- **Severity:** High
- **Description:** Fails any cached IAM role or user that can both write a registry record (`CreateRegistryRecord`, `UpdateRegistryRecord`, or `SubmitRegistryRecordForApproval`) and approve one with `UpdateRegistryRecordStatus`, the only operation in the registry control plane that can set a record's status to `APPROVED`. Such a principal is the publisher and the curator of the same entry, so the review the approval workflow exists to impose never happens. AR-03 reads the auto-approval setting, so it asserts nothing about who holds the two authorities. Both IAM namespace spellings are read, because a policy written during the public preview grants the same authorities under `bedrock-agentcore` until 30 October 2026, and a single-namespace read would answer "no collision" for it. A `Deny` scoped to one registry or carrying a condition is not treated as an account-wide `Deny`, so a narrower `Deny` reports the principal instead of excusing it. Every Allow that grants the actions counts, including a bare `*`, a `*:*` and a `NotAction` Allow, and the attached, inline and group policies of each identity are read. A permissions boundary that does not allow an action removes it. A role or user the permission cache names in `principal_errors` turns a `Passed` row into `N/A` naming the principal and the failed stage, and a failing row is kept beside it; a cache written before schema version 2 keeps its verdict and says the per-principal errors were not recorded. A principal whose permissions boundary the cache could not read (a `permissions_boundary` stage in `principal_errors`) is not reported `Failed` by AR-09, because a boundary could remove the grant; the `N/A` row names it. A permissions boundary removes any action it does not allow. Service control policies are not evaluated per principal; they only remove permissions, so they can make a row a false `Failed` but cannot hide a grant. An empty permission cache is an informational `N/A` tooling condition. Reported once under the `Global` region.

### AR-10: Registry Lifecycle Event Routing

- **Severity:** Medium
- **Description:** Requires an enabled EventBridge rule on the `default` event bus that matches source `aws.agent-registry` and the `Registry Record State changed to Pending Approval`, `Approved` and `Rejected` detail types, and that has at least one review-pipeline target, a Lambda function, SNS topic, SQS queue or Step Functions state machine, read from the service segment of the target ARN. A matching rule whose targets are all something else, such as a CloudWatch Logs group or an API destination, fails and is not credited, because nothing reviews what it delivers. A rule that matches only the public-preview `aws.bedrock-agentcore` source is reported apart, because that source stops routing on 30 October 2026, when its pattern has no detail-type filter or names an approval detail type; a preview-source rule filtered to other detail types is not a Registry rule. A rule whose pattern also filters on `detail`, `resources` or `account` is reported `N/A` and not credited, because it routes only the events that match the filter. AWS delivers these events to the default bus, so a rule on a custom event bus sees them only when a default-bus rule forwards them there. A matching default-bus rule with an event-bus target and no review-pipeline target is followed one hop to a bus in the same account and Region: it is credited only when an enabled rule on that bus matches the same events, with no `detail`, `resources` or `account` filter, and has a review-pipeline target, and only for the detail types both rules match. Event-bus targets on that bus are not followed, so a bus-to-bus cycle cannot loop. A forward to an event bus in another account or Region is reported `N/A` naming the bus, because its rules cannot be read from here, and the detail types it carries count as neither routed nor missing. The `prefix`, `suffix`, `wildcard`, `equals-ignore-case`, `anything-but`, `exists` and `numeric` matchers on `source` and `detail-type` are evaluated against the Registry source and lifecycle detail types, so a rule whose matcher cannot reach `aws.agent-registry`, such as `{"prefix": "aws.s3"}`, is not a Registry rule. A rule whose pattern uses `$or` or a matcher this check does not evaluate, or whose targets cannot be read, is reported `N/A`, and the approval transitions it might route count as neither routed nor missing, so no `Failed` rests on it; the same holds on a forwarded bus whose rules, or a rule's pattern or targets there, cannot be read. An unreadable rule list is informational `N/A`.

---

## Agentic AI Security Checks (39)

Agentic AI Security checks use the `AG-XX` namespace and are included with the
default assessment. They follow a hybrid model:

- Reused API-backed controls from Amazon Bedrock, Amazon Bedrock AgentCore,
  and AWS Agent Registry are mapped into agentic security domains.
- New checks are added only where AWS APIs can prove the control state.
- Controls that cannot be proven by AWS APIs are not scored. Human-in-the-loop
  governance is therefore documented as a methodology note, not emitted as an
  automated pass/fail finding.

These checks reference the
[AWS Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html),
with scope limited to the Security pillar.

### AG-01: Agent Guardrail Association

- **Severity:** High
- **Source:** BR-28
- **Domain:** Guardrail Enforcement
- **Description:** Maps Bedrock agent guardrail association into the Agentic AI Security view.

### AG-02: Harmful Content Guardrail Coverage

- **Severity:** Source check severity
- **Source:** BR-23
- **Domain:** Guardrail Enforcement
- **Description:** Maps guardrail content filter coverage for agent-facing workloads.

### AG-03: Sensitive Information Protection

- **Severity:** Source check severity
- **Source:** BR-26
- **Domain:** Memory & Data Privacy
- **Description:** Maps guardrail sensitive-information and PII protection controls.

### AG-04: Automated Reasoning Guardrails

- **Severity:** Source check severity
- **Source:** BR-24
- **Domain:** Guardrail Enforcement
- **Description:** Maps automated reasoning policies used to verify responses against deterministic rules.

### AG-05: Grounding Controls

- **Severity:** Source check severity
- **Source:** BR-27
- **Domain:** Prompt & Input Protection
- **Description:** Maps contextual grounding checks for RAG and tool-using agents.

### AG-06: Tool Execution Least Privilege

- **Severity:** Source check severity
- **Source:** BR-21
- **Domain:** Tool Authorization
- **Description:** Maps Bedrock agent action group IAM least-privilege findings.

### AG-07: Model Invocation Logging

- **Severity:** Source check severity
- **Source:** BR-04
- **Domain:** Auditability & Observability
- **Description:** Maps model invocation logging for agent prompts, responses, and guardrail traces.

### AG-08: API Audit Trail

- **Severity:** Source check severity
- **Source:** BR-06
- **Domain:** Auditability & Observability
- **Description:** Maps CloudTrail coverage for Bedrock activity.

### AG-09: Guardrail Enforcement Boundary

- **Severity:** Source check severity
- **Source:** BR-15
- **Domain:** Guardrail Enforcement
- **Description:** Maps organization-level guardrail enforcement controls.

### AG-10: Adversarial Evaluation Coverage

- **Severity:** Source check severity
- **Source:** BR-18
- **Domain:** Prompt & Input Protection
- **Description:** Maps model/application evaluation coverage for adversarial and safety testing.

### AG-11: Prompt Flow Validation

- **Severity:** Source check severity
- **Source:** BR-19
- **Domain:** Prompt & Input Protection
- **Description:** Maps Bedrock flow validation before deployment.

### AG-12: Invocation Abuse Controls

- **Severity:** Source check severity
- **Source:** BR-22
- **Domain:** Abuse & Cost Protection
- **Description:** Maps Bedrock service quota and throttling controls.

### AG-13: Session Boundary

- **Severity:** Source check severity
- **Source:** BR-29
- **Domain:** Bounded Autonomy
- **Description:** Maps Bedrock agent idle session TTL controls.

### AG-14: Operational Abuse Alarms

- **Severity:** Source check severity
- **Source:** BR-32
- **Domain:** Abuse & Cost Protection
- **Description:** Maps CloudWatch alarms for Bedrock invocation abuse and operational anomalies.

### AG-15: Runtime Network Boundary

- **Severity:** Source check severity
- **Source:** AC-01
- **Domain:** Bounded Autonomy
- **Description:** Maps AgentCore runtime VPC configuration.

### AG-16: AgentCore Least Privilege

- **Severity:** Source check severity
- **Source:** AC-02
- **Domain:** Agent Identity & Access
- **Description:** Maps AgentCore full-access IAM findings.

### AG-17: Stale AgentCore Access

- **Severity:** Source check severity
- **Source:** AC-03
- **Domain:** Agent Identity & Access
- **Description:** Maps stale AgentCore permissions.

### AG-18: AgentCore Observability

- **Severity:** Source check severity
- **Source:** AC-04
- **Domain:** Auditability & Observability
- **Description:** Maps AgentCore logging, tracing, and observability coverage.

### AG-19: Memory Data Protection

- **Severity:** Source check severity
- **Source:** AC-07
- **Domain:** Memory & Data Privacy
- **Description:** Maps AgentCore memory encryption controls. The row carries AC-07's details, so the row for a memory that `GetMemory` denied names the `kms:Decrypt` cause too.

### AG-20: Private AgentCore Connectivity

- **Severity:** Source check severity
- **Source:** AC-08
- **Domain:** Bounded Autonomy
- **Description:** Maps VPC endpoint coverage for AgentCore services.

### AG-21: Resource Policy Boundary

- **Severity:** Source check severity
- **Source:** AC-10
- **Domain:** Agent Identity & Access
- **Description:** Maps AgentCore runtime and gateway resource-based policy controls.

### AG-22: Policy Engine Data Protection

- **Severity:** Source check severity
- **Source:** AC-11
- **Domain:** Tool Authorization
- **Description:** Maps AgentCore policy engine encryption controls.

### AG-23: Gateway Data Protection

- **Severity:** Source check severity
- **Source:** AC-12
- **Domain:** Tool Authorization
- **Description:** Maps AgentCore gateway encryption controls.

### AG-24: Gateway Inbound Authorization

- **Severity:** High
- **Source:** AgentCore `ListGateways` and `GetGateway`
- **Domain:** Tool Authorization
- **Description:** Fails gateways with missing, unknown, or `NONE` authorizers. Passes `AWS_IAM`. A `CUSTOM_JWT` gateway passes only when its `discoveryUrl` is `https` and an `allowedAudience` or `allowedClients` list pins the application with values that carry no `*` and are not blank; otherwise it fails, and a gateway that reports no `customJWTAuthorizer` is informational `N/A`. `AUTHENTICATE_ONLY` passes only when an AgentCore policy engine is attached in `ENFORCE` mode and AG-25 passes that engine, because the gateway authenticates the SigV4 caller but does not make an authorization decision for that authorizer type. An engine AG-25 fails (no enforcing policy, or a permit over every action with no condition) fails AG-24 too, and an engine whose policies AG-25 could not read makes AG-24 informational `N/A`.

### AG-25: Gateway Tool Policy Enforcement

- **Severity:** High
- **Source:** AgentCore `GetGateway.policyEngineConfiguration` plus `ListPolicies`
- **Domain:** Tool Authorization
- **Description:** Fails gateways without a policy engine, with mode other than `ENFORCE`, or with no `ACTIVE` policy whose enforcement mode is `ACTIVE`. The text of each enforcing policy is read: a permit over every action with no condition fails as `Allows All`, because the engine's default-deny then denies no tool call, and an enforcing policy whose text cannot be read is informational `N/A` and never `Passed`. A mix of enforcing and `LOG_ONLY`/inactive policies passes with an advisory. AC-35 judges the tools, callers and gateway each permit names.

### AG-26: Gateway Error Detail Exposure

- **Severity:** Medium
- **Source:** AgentCore `GetGateway.exceptionLevel`
- **Domain:** Auditability & Observability
- **Description:** Fails gateways configured to return `DEBUG`-level exception detail.

### AG-27: Gateway WAF Protection

- **Severity:** Low
- **Source:** AgentCore `GetGateway.webAclArn` and `GetGateway.wafConfiguration`
- **Domain:** Abuse & Cost Protection
- **Description:** Fails AgentCore gateways without an associated AWS WAF web ACL. An associated gateway passes only with `wafConfiguration` `failureMode` `FAIL_CLOSE`; `FAIL_OPEN` fails, because the gateway then allows a request unfiltered when AWS WAF cannot be evaluated, and an unset value is informational `N/A` because the API states no default.

### AG-28: Identity Token Vault Protection

- **Severity:** Source check severity
- **Source:** AC-14
- **Domain:** Agent Identity & Access
- **Description:** Maps AgentCore Identity token-vault CMK encryption.

### AG-29: Code Interpreter Isolation

- **Severity:** Source check severity
- **Source:** AC-15
- **Domain:** Bounded Autonomy
- **Description:** Maps custom Code Interpreter VPC isolation.

### AG-30: Prompt Attack Protection

- **Severity:** Source check severity
- **Source:** BR-34
- **Domain:** Prompt & Input Protection
- **Description:** Maps preventive Bedrock Guardrails prompt-attack filtering.

### AG-31: Browser Tool Isolation

- **Severity:** Source check severity
- **Source:** AC-16
- **Domain:** Bounded Autonomy
- **Description:** Maps custom AgentCore browser VPC isolation.

### AG-32: Online Evaluation Assurance

- **Severity:** Source check severity
- **Source:** AC-17
- **Domain:** Auditability & Continuous Assurance
- **Description:** Maps AgentCore online evaluation configuration without claiming universal runtime trace coverage.

### AG-33: Registry Publication Approval Governance

- **Severity:** Source check severity
- **Source:** AR-03
- **Domain:** Agent Identity & Access
- **Description:** Maps Agent Registry publication approval configuration into the Agentic AI Security view.

### AG-34: Registry Discovery Authorization

- **Severity:** Source check severity
- **Source:** AR-04
- **Domain:** Agent Identity & Access
- **Description:** Maps Agent Registry authorizer inventory and manual-review guidance into the Agentic AI Security view. Configured IAM and constrained JWT authorizers remain informational until effective access or approved JWT caller values can be established.

### AG-35: Registry Metadata Encryption

- **Severity:** Source check severity
- **Source:** AR-05
- **Domain:** Memory & Data Privacy
- **Description:** Maps Agent Registry customer-managed KMS encryption into the Agentic AI Security view.

### AG-36: Organization Discovery Coverage

- **Severity:** Source check severity
- **Source:** AR-06
- **Domain:** Auditability & Continuous Assurance
- **Description:** Maps organization-scoped Agent Registry auto-detection health into the Agentic AI Security view.

### AG-37: Registry Record Lifecycle Governance

- **Severity:** Source check severity
- **Source:** AR-07
- **Domain:** Agent Identity & Access
- **Description:** Maps advisory Agent Registry record lifecycle observations into the Agentic AI Security view.

### AG-38: Registry Record Provenance

- **Severity:** Source check severity
- **Source:** AR-08
- **Domain:** Auditability & Continuous Assurance
- **Description:** Maps Agent Registry creator attribution and auto-detected runtime or gateway lineage into the Agentic AI Security view.

### AG-39: Gateway WAF Rule Coverage

- **Severity:** Medium
- **Source:** AWS WAF `GetWebACL` for the web ACL AG-27 finds, and the gateway's `wafConfiguration` from `GetGateway`
- **Domain:** Abuse & Cost Protection
- **Description:** Judges whether the web ACL on an AgentCore gateway filters the request. It fails an ACL missing any of five filters: a rule, AWS managed rule group or default action that blocks; SQL injection inspection; cross-site scripting inspection; a rate-based rule; and a `DefaultSizeInspectionLimit` above `KB_16` for the `AGENTCORE_GATEWAY` association, since a tool call carries its arguments in the request body. Only a rule whose action is `Block` is credited: `Allow` lets the matching request through, `Count` observes it, and `Captcha` and `Challenge` let through a request that carries a valid token. A rule group whose `OverrideAction` is `Count` is not credited. Rules are read in the order AWS WAF runs them: Firewall Manager pre-process groups, the web ACL's rules by `Priority`, then post-process groups. A filter in a rule that runs after an `Allow` rule is not credited, because the `Allow` ends evaluation for the requests it matches; the `Allow` statement is not judged for which requests it matches, so an allowlist rule placed first removes the SQL injection, cross-site scripting and rate-based credit of every rule behind it. A match statement inside the `ScopeDownStatement` of a rate-based or managed rule group statement is not credited as inspection, because it only picks the requests the outer statement counts or inspects. A customer `SqliMatchStatement` is credited only at `SensitivityLevel` `HIGH`; the API default is `LOW`. A customer SQL injection or cross-site scripting statement on `Body` or `JsonBody` is credited only when its `OversizeHandling` is `MATCH`, or `NO_MATCH` beside a blocking rule that matches an oversized body (a `SizeConstraintStatement` on the body with `GT` or `GE`, or the core rule set with `SizeRestrictions_BODY` not overridden). `CONTINUE`, the API default, forwards the part of a body past the inspection limit uninspected. The finding names each statement not credited for these values. The statements inside an AWS managed group are not returned by `GetWebACL`, so their sensitivity and oversize handling are not read. AWS managed groups are credited by name (`AWSManagedRulesSQLiRuleSet`, `AWSManagedRulesCommonRuleSet`) unless a rule that provides the filter is overridden: any `RuleActionOverrides` entry other than `Block`, or any `ExcludedRules` entry, in the SQL injection group removes its SQL injection credit, and one on a `CrossSiteScripting_` rule of the core rule set removes its cross-site scripting credit. The check does not read a group's rule list, so a group carrying such an override is credited as blocking only while it still provides one of those two filters. A customer rule group or a non-AWS managed rule group, whose rules the check does not read, turns a missing filter into informational `N/A` with the group named. The gateway's `wafConfiguration.failureMode` decides what happens when AWS WAF cannot be evaluated: `FAIL_OPEN` lets the request through, so a gateway set to it fails whatever its web ACL applies, and an ACL that applies all five filters passes only when the gateway reports `FAIL_CLOSE`. The API states no default, so a gateway that reports no `failureMode` is informational `N/A`.

### Runtime guardrail methodology note

`InvokeGuardrailChecks` / `ApplyGuardrail` are per-request runtime APIs rather than a persistent configuration surface. The assessment therefore does not emit a pass/fail finding for their use; applications should validate these calls through runtime architecture review, telemetry, and testing.

---

## Additional Resources

- [Amazon SageMaker Security Best Practices](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [Amazon Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [AWS Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html)
- [AWS Security Hub SageMaker Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/sagemaker-controls.html)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)

---

## Responsible AI GRC Checks (64 additional, 5 upstream extensions)

These 64 standalone checks (FS-XX) extend the framework with cross-industry AI
governance, risk, and compliance controls derived from the
[AWS User Guide to Governance, Risk, and Compliance for Responsible AI Adoption](https://aws.amazon.com/blogs/security/introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/).
An additional 5 FS checks are contributed as extensions to existing SM-07,
SM-22, SM-23, BR-04, and BR-06 (see in-file extension notes).

The full catalog is in **[`SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md`](./SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md)**,
organized into three parts:

- **Part 1 — Infrastructure & Resource Controls** — FS-01 to FS-26
  (Unbounded Consumption, Excessive Agency, Supply Chain, Training Poisoning, Vector
  Weaknesses).
- **Part 2 — Guardrails & Content Safety** — FS-27 to FS-46
  (Non-Compliant Output, Misinformation, Abusive/Harmful Output, Biased Output,
  Sensitive Information Disclosure).
- **Part 3 — Application-Layer Controls & Material Gaps** — FS-47 to FS-69
  (Hallucination, Prompt Injection, Improper Output Handling, Off-Topic Output,
  Out-of-Date Training Data, and 6 cross-category material gap checks).

The same document includes the shared intro, severity rubric, validation note,
upstream-overlap table, and the compliance framework mapping table
(SR 11-7, FFIEC CAT, NYDFS 500.06, PCI-DSS 12.3.2, DORA Art.6, MAS TRM 9,
ISO 27001 A.12, ECOA, OWASP LLM Top 10).

---

## OWASP Top 10 for LLM Checks (12)

These 12 checks (OW-XX) map the AI/ML Security Assessment findings to the
[OWASP Top 10 for LLM 2025](https://genai.owasp.org/llm-top-10/) categories.
OW-01..OW-10 are **derived by mapping** from existing BR/SM/AC/FS findings.
The OWASP Lambda itself does not call AWS APIs for mapped rows, but enabling
OWASP can auto-run Responsible AI GRC to produce FS-* source findings when
Responsible AI GRC is otherwise disabled. OW-11 and OW-12 are net-new checks
that address LLM07 (System Prompt Leakage), which the existing checks do not
directly cover.
If a required source CSV is missing, the OWASP Lambda emits an informational
`OW-00` completeness row rather than silently dropping derived rows.

**Opt-in.** OWASP checks run only when the `EnableOWASPAssessment` deployment
parameter is `true` and the Step Functions execution includes `"enableOWASP": "true"`.

**Rendered under a new "By Compliance Standard" sidebar section** of the HTML
report, alongside future NIST AI RMF and EU AI Act sections.

The full catalog is in **[`SECURITY_CHECKS_OWASP.md`](./SECURITY_CHECKS_OWASP.md)**,
organized by OWASP category:

- **LLM01 Prompt Injection** — OW-01
- **LLM02 Sensitive Information Disclosure** — OW-02
- **LLM03 Supply Chain** — OW-03
- **LLM04 Data and Model Poisoning** — OW-04
- **LLM05 Improper Output Handling** — OW-05
- **LLM06 Excessive Agency** — OW-06
- **LLM07 System Prompt Leakage** — OW-07 (mapping-based) + OW-11, OW-12 (native)
- **LLM08 Vector and Embedding Weaknesses** — OW-08
- **LLM09 Misinformation** — OW-09
- **LLM10 Unbounded Consumption** — OW-10

**Preliminary and illustrative.** OWASP mappings have not been reviewed by
external auditors. Validate mappings with your Security/Compliance team
before using as audit evidence.
