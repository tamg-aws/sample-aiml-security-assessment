# Security Checks Reference

This document provides a comprehensive reference for all 208 security checks performed by the AI/ML Security Assessment framework (94 core checks across Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, and AWS Agent Registry, 38 Agentic AI Security checks, 64 Responsible AI GRC checks, and 12 OWASP Top 10 for LLM checks).

Sources differ by bucket and are not interchangeable: the core Bedrock, SageMaker, AgentCore, and AWS Agent Registry checks derive from the AWS Well-Architected **Generative AI Lens** security best practices (`gensec*`) and service security documentation; the Agentic AI Security checks from the AWS Well-Architected **Agentic AI Lens**; the `FS-*` **Responsible AI GRC** checks from the AWS GRC User Guide; and the `OW-*` checks from the OWASP Top 10 for LLM. The AWS Well-Architected **Responsible AI Lens** is not a source for any of them — see [Responsible AI GRC — scope, sources, and compatibility](RESPONSIBLE_AI_GRC_SCOPE.md).

The 64 Responsible AI GRC checks occupy 69 `FS-*` numbers: 64 ship as standalone checks and 5 are merged into upstream Bedrock/SageMaker checks. The framework also emits `BR-00`, `SM-00`, `AC-00`, `AR-00`, `FS-00`, `OW-00`, and `AISF-00` operational marker rows at runtime; these are not controls and are excluded from the 208-check total. `AISF-01` through `AISF-08` are AWS AI Security Framework view rows: each one restates the verdict of a check already counted above under an AISF control id, so they are excluded from the 208-check total for the same reason ([AWS AI Security Framework (AISF) Checks](SECURITY_CHECKS_AISF.md)). Per-control provenance, including which controls are project extensions rather than guide-derived, is recorded in [`provenance.json`](../aiml-security-assessment/functions/security/responsible_ai_grc_assessments/provenance.json).

## Table of Contents

- [Overview](#overview)
- [Check ID Convention](#check-id-convention)
- [Report Scoring](#report-scoring)
- [Severity Levels](#severity-levels)
- [Status Values](#status-values)
- [Amazon SageMaker AI Security Checks (29)](#amazon-sagemaker-ai-security-checks-29)
- [Amazon Bedrock Security Checks (40)](#amazon-bedrock-security-checks-40)
- [Amazon Bedrock AgentCore Security Checks (17)](#amazon-bedrock-agentcore-security-checks-17)
- [AWS Agent Registry Security Checks (8)](#aws-agent-registry-security-checks-8)
- [Agentic AI Security Checks (38)](#agentic-ai-security-checks-38)
- [Responsible AI GRC Checks (64)](#responsible-ai-grc-checks-64-additional-5-upstream-extensions)
- [OWASP Top 10 for LLM Checks (12)](#owasp-top-10-for-llm-checks-12)

---

## Overview

The framework evaluates your AI/ML workloads against AWS security best practices across four services:

| Service | Number of Checks | Focus Areas |
| --------- | ------------------ | ------------- |
| Amazon SageMaker AI | 29 | Security Hub controls, encryption, network isolation, GuardDuty AI Protection, HyperPod, IAM, MLOps, Model Registry policy exposure |
| Amazon Bedrock | 40 | Guardrails, prompt-attack/image filters, retention, inference profiles, automated reasoning and Marketplace endpoint governance, encryption, networking, IAM, logging, monitoring, and evaluation |
| Amazon Bedrock AgentCore | 17 | Runtime/tool VPC isolation, encryption, browser recording, observability, resource policies, Identity token vaults, and online evaluation |
| AWS Agent Registry | 8 | IAM access, approval governance, discovery authorization, encryption, organization auto-detection, record lifecycle, and provenance |
| Agentic AI Security | 38 | Bounded autonomy, agent identity, tool authorization, Registry governance and provenance, guardrail enforcement, prompt/input protection, memory privacy, auditability, continuous assurance, abuse protection |
| Responsible AI GRC | 64 | Unbounded consumption, excessive agency, supply chain, training data poisoning, vector weaknesses, non-compliant output, misinformation, harmful output, biased output, PII disclosure, hallucination, prompt injection, improper output handling, off-topic output, out-of-date training data |
| OWASP Top 10 for LLM | 12 | LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption |

---

## Check ID Convention

Each security check has a unique identifier with a service prefix:

| Prefix | Service | Example |
| -------- | --------- | --------- |
| **SM-XX** | Amazon SageMaker | SM-01, SM-30 (`SM-29` reserved) |
| **BR-XX** | Amazon Bedrock | BR-01, BR-40 |
| **AC-XX** | Amazon Bedrock AgentCore | AC-01, AC-17 |
| **AR-XX** | AWS Agent Registry | AR-01, AR-08 |
| **AG-XX** | Agentic AI Security | AG-01, AG-38 |
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

## Amazon SageMaker AI Security Checks (29)

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
- **Description:** Ensures notebooks are deployed within an Amazon VPC.

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

---

## Amazon Bedrock Security Checks (40)

### BR-01: AWS IAM Least Privilege

- **Severity:** High
- **Description:** Identifies roles with AmazonBedrockFullAccess policy.

### BR-02: Amazon VPC Endpoint Configuration

- **Severity:** High
- **Description:** Validates Bedrock Amazon VPC endpoints exist for private connectivity.

### BR-03: Marketplace Subscription Access

- **Severity:** Medium
- **Description:** Checks for overly permissive marketplace subscription access.

BR-01, BR-02, BR-03, BR-08, BR-10, and BR-21 depend on the shared IAM
permissions cache. If that prerequisite is missing, unreadable, or malformed,
each affected control is reported as informational `N/A`; an empty replacement
inventory is never treated as evidence of compliance.

### BR-04: Model Invocation Logging

- **Severity:** Medium
- **Description:** Checks invocation logging is enabled.

### BR-05: Guardrail Configuration

- **Severity:** High
- **Description:** Verifies guardrails are configured and enforced.

### BR-06: AWS CloudTrail Logging

- **Severity:** Medium
- **Description:** Validates AWS CloudTrail logging for Bedrock API calls.

### BR-07: Prompt Management

- **Severity:** Low
- **Description:** Validates Bedrock Prompt template usage and variants.

### BR-08: Agent AWS IAM Configuration

- **Severity:** Medium
- **Description:** Checks agent execution role permissions.

### BR-09: Knowledge Base Encryption

- **Severity:** High
- **Description:** Checks knowledge base encryption settings.

### BR-10: Guardrail AWS IAM Enforcement

- **Severity:** Medium
- **Description:** Verifies guardrails are enforced through AWS IAM conditions.

### BR-11: Custom Model Encryption

- **Severity:** High
- **Description:** Validates custom models use customer-managed AWS KMS keys.

### BR-12: Invocation Log Encryption

- **Severity:** Medium
- **Description:** Verifies logs are encrypted with AWS KMS.

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
- **Description:** Verifies fine-tuned/customized models use customer-managed KMS keys instead of AWS-owned keys for greater control over encryption. Lists all custom models, retrieves model details to check KMS key configuration, and validates KMS key ARN format. This extends the existing BR-11 check by specifically verifying the type of encryption key used.

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
- **Description:** Extends existing BR-09 to verify Knowledge Base encryption uses customer-managed KMS keys. Uses the authoritative knowledge base `type` (`VECTOR | KENDRA | SQL | MANAGED`) to decide how to assess each KB: for `MANAGED` knowledge bases it reads `knowledgeBaseConfiguration.managedKnowledgeBaseConfiguration.serverSideEncryptionConfiguration.kmsKeyArn` and fails KBs encrypted with an AWS-owned key; for custom vector stores (OpenSearch, RDS, Pinecone, etc.) the encryption key lives on the underlying storage resource and cannot be read from the KB API, so those are reported as N/A for manual review. If a `MANAGED` KB's encryption block is missing from the API response (deployed botocore older than 1.43.32, which silently drops the unmodeled field), the KB is reported as N/A "indeterminate" rather than a false-positive failure.
- **S3 Vectors:** An `S3_VECTORS` storage configuration is the one custom store this check assesses instead of deferring, because both halves of the control are readable one ARN hop away. It follows `storageConfiguration.s3VectorsConfiguration.vectorBucketArn` and calls `s3vectors:GetVectorBucket` (fails unless `encryptionConfiguration.sseType` is `aws:kms` with a `kmsKeyArn`, so SSE-S3 `AES256` fails, the same bar as every other storage type) and `s3vectors:GetVectorBucketPolicy` (fails when no policy is attached; `NotFoundException` is an answer about the workload, not an assessment gap). The client is built for the region in the bucket ARN, which need not be the scanned region. One finding per knowledge base. `AccessDenied` on either call is reported as N/A naming the missing action, so a permission gap stays visible. Index-level `encryptionConfiguration` overrides set by `CreateIndex` are not read.

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
- **Description:** Extends BR-23 (which covers the harmful-content filters) to verify guardrails configure sensitive-information protection. For each guardrail, reads `GetGuardrail.sensitiveInformationPolicy` and reports guardrails that have no PII entity types (`piiEntities`) or custom regex patterns (`regexes`) configured, leaving prompts and responses unscreened for sensitive data.

### BR-27: Guardrail Contextual Grounding Check

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies guardrails enable contextual grounding checks to detect hallucinated (ungrounded) and off-topic model responses. Reads `GetGuardrail.contextualGroundingPolicy.filters` and reports guardrails with no enabled grounding/relevance filters. Complements BR-25 (RAG evaluation) with a runtime control.

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
- **Description:** Complements BR-11/BR-17 by verifying imported custom models use customer-managed KMS keys. Lists imported models and reads `GetImportedModel.modelKmsKeyArn`, reporting models encrypted with AWS-owned keys instead of a customer-managed key.

### BR-31: Batch Inference Output Encryption

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies batch inference (model invocation) jobs encrypt their S3 output with a customer-managed KMS key. Reads `outputDataConfig.s3OutputDataConfig.s3EncryptionKeyId` from the job summaries returned by `ListModelInvocationJobs` and reports jobs without a customer-managed output key.

### BR-32: CloudWatch Alarms on Bedrock Metrics

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies CloudWatch alarms exist on Amazon Bedrock runtime metrics (the `AWS/Bedrock` namespace) to detect abuse, denial-of-wallet, sustained throttling, and content-filter spikes. Uses `DescribeAlarms` and matches alarms that target the `AWS/Bedrock` namespace directly or via a metric-math expression. Only assessed in regions that have Bedrock resources.

### BR-33: Amazon Inspector Lambda Code Scanning

- **Severity:** Medium
- **Type:** Regional
- **Description:** When Lambda functions with Bedrock indicators are detected in the region, verifies Amazon Inspector Lambda standard scanning (`lambda`) and Lambda code scanning (`lambdaCode`) are both enabled so those in-scope functions and their dependencies are scanned for vulnerable packages and hardcoded secrets. Calls `lambda:ListFunctions` for scoping and `inspector2:BatchGetAccountStatus` for Inspector status. Reports `Failed` only when in-scope Lambda functions exist and either `resourceState.lambda.status` or `resourceState.lambdaCode.status` is not `ENABLED`. No in-scope Lambda functions, access denied, and region-unavailable states resolve to `N/A`.

### BR-34: Guardrail Prompt Attack Filter

- **Severity:** High
- **Description:** Requires each guardrail to have a preventive `PROMPT_ATTACK` input filter with `inputEnabled=true`, `inputAction=BLOCK`, and a non-`NONE` input strength. Standard tier is reported as a strengthening note.

### BR-35: Guardrail Image Content Filter Coverage

- **Severity:** Informational
- **Description:** Uses `HATE`, `INSULTS`, `SEXUAL`, and `VIOLENCE` as the cross-region image-filter baseline. Because AWS documents `MISCONDUCT` image filtering as region-dependent, its absence is not reported as a gap, but a configured `MISCONDUCT` filter is reported when its input or output modalities omit `IMAGE`. Complete coverage is `Passed`; advisory gaps are `N/A`/Informational because the scanner cannot infer whether protected applications accept or produce images.

### BR-36: Application Inference Profile Governance

- **Severity:** Low
- **Description:** Lists application inference profiles and reports completely untagged profiles. Organization-specific required tag keys can be enforced outside the default baseline.

### BR-37: Bedrock Account Data Retention

- **Severity:** High for provider sharing or an explicitly required zero-data-retention violation
- **Description:** Fails `provider_data_share`, passes `none`, and reports `default`/`inherit` as informational unless the `RequireBedrockZeroDataRetention` deployment parameter is `true` (`REQUIRE_BEDROCK_ZERO_DATA_RETENTION` in the Lambda), in which case those modes fail.

### BR-38: Automated Reasoning Policy CMK Encryption

- **Severity:** Medium
- **Description:** Deduplicates Automated Reasoning policy summaries and verifies each policy exposes a non-empty `kmsKeyArn`.

### BR-39: Marketplace Model Endpoint VPC Configuration

- **Severity:** High
- **Description:** Requires SageMaker-backed Bedrock Marketplace endpoint configurations to include non-empty VPC subnet and security-group lists.

### BR-40: Marketplace Model Endpoint CMK Encryption

- **Severity:** Medium by default
- **Description:** Resolves the Marketplace endpoint `kmsEncryptionKey` with `kms:DescribeKey` and requires `KeyMetadata.KeyManager` to be `CUSTOMER`; AWS-managed keys do not pass. The `RequireMarketplaceEndpointCMK` deployment parameter defaults to `true` (`REQUIRE_MARKETPLACE_ENDPOINT_CMK` in the Lambda). Set it to `false` to make a missing or AWS-managed key an `N/A`/Informational hardening advisory rather than a failure. An inconclusive KMS lookup is always `N/A`/Informational.

---

## Amazon Bedrock AgentCore Security Checks (17)

### AC-01: Runtime Amazon VPC Configuration

- **Severity:** High
- **Description:** Validates agent runtimes have proper Amazon VPC settings.

### AC-02: AWS IAM Full Access

- **Severity:** High
- **Description:** Checks attached and inline policy documents for AgentCore full-access managed policies, wildcard IAM action patterns, and `Allow`/`NotAction` allow-except statements that still grant the AgentCore namespace when they apply to all resources. Only the valid `bedrock-agentcore` IAM namespace is evaluated; overly permissive `agent-registry` grants are reported by [AR-01](#ar-01-aws-iam-full-access) instead. Service-agnostic administrator-style grants are out of scope in both forms: a bare `Action: "*"` and a `NotAction` whose exclusions name no platform namespace are treated alike and not reported as AgentCore-specific grants. A missing, unreadable, or malformed permissions cache is reported as informational `N/A`. If an individual cached policy document cannot be parsed, valid findings from other policies are retained and an additional informational `N/A` row marks the control incomplete; the unparsed policy cannot produce a compliant pass.

### AC-03: Stale Access

- **Severity:** Low
- **Description:** Detects unused AgentCore permissions by inspecting `Allow` and `NotAction` grants in attached and inline policy documents before querying IAM service-last-accessed history. Only the `bedrock-agentcore` namespace is evaluated; `agent-registry` grants are reported by [AR-02](#ar-02-stale-access) instead. As in AC-02, a `NotAction` whose exclusions name no platform namespace is a service-agnostic administrator grant and is not treated as an AgentCore-specific permission. Attached policy names alone are never treated as proof of access. IAM last-accessed jobs are polled within the Lambda deadline; a job that does not complete in time is reported as an indeterminate `N/A` rather than a failed control. A missing, unreadable, or malformed permissions cache is also reported as informational `N/A`. This identifies candidate grants from the cached policy documents; it is not a complete effective-permissions simulation across boundaries, session policies, or organization controls.

### AC-04: Observability

- **Severity:** Medium
- **Description:** Verifies Amazon CloudWatch Logs and AWS X-Ray tracing configuration.

### AC-05: Amazon ECR Repository Encryption

- **Severity:** High
- **Description:** Validates Amazon ECR repositories use encryption.

### AC-06: Browser Tool Recording

- **Severity:** Medium
- **Description:** Uses custom browser inventory and requires `recording.enabled=true` with a non-empty S3 recording bucket.

### AC-07: Memory Encryption

- **Severity:** Medium
- **Description:** Checks agent memory encryption with AWS KMS.

### AC-08: Amazon VPC Endpoints

- **Severity:** High
- **Description:** Validates Amazon VPC endpoints for AgentCore services.

### AC-09: Service-Linked Role

- **Severity:** Medium
- **Description:** Verifies the AgentCore service-linked role exists.

### AC-10: Resource-Based Policies

- **Severity:** Medium
- **Description:** Checks runtime and gateway resource policies.

### AC-11: Policy Engine Encryption

- **Severity:** Medium
- **Description:** Validates policy engine encryption settings.

### AC-12: Gateway Encryption

- **Severity:** Medium
- **Description:** Verifies gateway encryption settings.

### AC-13: Gateway Configuration

- **Severity:** Medium
- **Description:** Validates gateway security configuration.

### AC-14: Identity Token Vault CMK Encryption

- **Severity:** High
- **Description:** Checks the configured/default regional Identity token vault and requires `CustomerManagedKey` with a KMS key ARN. Set the `AgentCoreTokenVaultId` deployment parameter to override the `default` vault ID (`AGENTCORE_TOKEN_VAULT_ID` in the Lambda).

### AC-15: Code Interpreter Network Isolation

- **Severity:** High
- **Description:** Requires custom Code Interpreters to use `VPC` network mode with non-empty subnets and security groups.

### AC-16: Custom Browser Network Isolation

- **Severity:** High
- **Description:** Requires custom browsers to use `VPC` network mode with non-empty subnets and security groups. Shares browser inventory with AC-06.

### AC-17: Online Evaluation Coverage

- **Severity:** Informational by default; Medium when required
- **Description:** Reports whether online evaluation configurations are active/enabled and include non-zero sampling, evaluators, CloudWatch input data, and output logging. Set the `RequireAgentCoreOnlineEvaluation` deployment parameter to `true` (`REQUIRE_AGENTCORE_ONLINE_EVALUATION` in the Lambda) to make incomplete coverage fail.

### AC-18: CloudTrail Data Event Coverage

- **Severity:** Medium
- **Description:** Requires a CloudTrail advanced event selector of category `Data` on each AgentCore family that has resources in the region: `AWS::BedrockAgentCore::Runtime` and `::RuntimeEndpoint` for runtimes, `::Memory` for memory, and `::CodeInterpreter`, `::CodeInterpreterCustom`, `::Browser`, `::BrowserCustom` for custom tools. Management events do not satisfy it, because they record that a runtime or memory was created and not the invocations and memory record reads that follow. Presence of resources is decided from this module's own inventory, so a family with no resources in the region reports informational `N/A` instead of a failure nobody can act on. An unavailable CloudTrail client, a failed `ListTrails` call, an uninventoriable family, and the case where no readable trail selects the type while other trails could not be read are also informational `N/A`.

### AC-19: Log Delivery Configuration

- **Severity:** Medium
- **Description:** Reports one finding per gateway and per memory resource, and requires both a `bedrock-agentcore` `APPLICATION_LOGS` delivery source for that resource and a delivery carrying the source to a destination. A resource with a delivery source and no delivery fails, because nothing stores the logs it collects. Runtimes are out of scope: runtime logging is service-managed, and AC-04 covers runtime tracing. Built-in tools, Identity, and policy engines are covered by one informational `N/A` row that names why none of the three has a delivery configuration to assert. An unavailable CloudWatch Logs client, an unreadable delivery configuration, and a failed gateway or memory listing are informational `N/A`.

### AC-20: Log Data Protection

- **Severity:** Medium
- **Description:** For every log group under `/aws/bedrock-agentcore/` or `/aws/vendedlogs/bedrock-agentcore/`, requires a data-protection policy that masks at least one data identifier and a customer managed KMS key, and names which of the two is missing. Masking set on the log group and masking inherited from an account-level policy both count. Agent prompts, tool arguments, and memory records reach these log groups verbatim, so a guardrail at the model boundary does not cover them. A region with no AgentCore log groups, an unreadable account policy list, and a log group whose policy document cannot be read are informational `N/A`.

### AC-21: Log Unmask Restriction

- **Severity:** Medium
- **Description:** Fails any cached IAM role or user granted `logs:Unmask` on a resource pattern that names no log group, because masking is reversible by whoever holds that action. A principal holding it only on named log group resources passes, and so does an account where no cached principal holds it at all. An empty or unreadable permission cache is informational `N/A`. Reported once under the `Global` region, because the grant does not vary by scanned region.

### AC-22: Telemetry Sink Scope

- **Severity:** Medium
- **Description:** Requires every `Allow` statement in an observability sink policy to name its principals or to carry an organization condition key, so an unrelated account cannot link its telemetry into the account that aggregates agent traces. Condition operators are matched with their set-operator prefixes stripped, so a key under `ForAllValues:StringEquals` is read. A sink with no policy attached is informational `N/A` because no source account can link to it, as are an unavailable client, a failed `ListSinks` call, an unreadable policy, and a policy that is not valid JSON.

### AC-23: Memory Record Access Scope

- **Severity:** High
- **Description:** Fails any cached IAM role or user that can read memory records or events with no namespace, strategy, actor, or session condition, because one such call returns every actor's stored records out of the same memory. AC-07 judges each memory's own namespace partitioning; partitioning separates records only when retrieval is bound to one actor too. A principal whose read is conditioned passes, as does an account where no cached principal holds a memory read action. An empty or unreadable permission cache is informational `N/A`. Reported once under the `Global` region.

### AC-24: Gateway Rate Limiting

- **Severity:** Medium
- **Description:** Requires each gateway to carry at least one `ACTIVE` rate limit with a requests, tokens, or connections ceiling. A gateway with rate limits none of which is active with a ceiling fails separately from a gateway with no rate limit at all, because a limit that bounds nothing reads as configured. The WAF association AG-27 reports filters request content and sets no throughput ceiling. An unavailable client, a region with no gateways, and unreadable rate limits are informational `N/A`.

### AC-25: Gateway Target Authorization

- **Severity:** High
- **Description:** Requires each gateway target to declare a credential provider, because `credentialProviderConfigurations` is optional on `CreateGatewayTarget` and the console offers "No authorization", so a target can reach its backend with no gateway-supplied credential and the backend cannot tell one caller from another. The provider types found are reported; which of the five suits a given backend is a workload decision. A region with no targets, an unlistable gateway, and an unreadable target are informational `N/A`.

### AC-26: Log Retention and Key Scope

- **Severity:** Medium
- **Description:** Requires a retention period on every AgentCore log group, and requires the key policy behind its customer managed key to name the principals allowed to decrypt and the administrators allowed to disable the key or schedule it for deletion. A group with no retention keeps agent prompts, tool arguments, and memory records for as long as the account exists. AC-20 asserts that a customer managed key is set; this check judges the policy behind it. A log group whose key policy cannot be read is reported as informational `N/A` on its own row, so the retention verdict still stands.

### AC-27: Gateway Policy Conditions

- **Severity:** High for the confused-deputy legs; Medium for the network-path leg
- **Description:** Judges the conditions on each gateway's resource policy and on its execution role's trust policy. An `Allow` statement that trusts an AWS service principal or every principal with no `aws:SourceAccount` or `aws:SourceArn` condition fails, because another account's resource can then make the service call this gateway on its behalf, and a guarded statement elsewhere in the same policy does not narrow an unguarded one. The network leg is separate: a resource policy carrying no `aws:SourceVpc`, `aws:SourceVpce`, `aws:VpcSourceIp`, or `aws:SourceIp` condition admits any caller holding a valid authorizer token over any path, including the public internet. AC-10 reports that a resource policy is present. Trust policies are read from IAM, because the permission cache stores attached and inline policies only, and roles are cached per invocation because several gateways can share one execution role. A gateway with no cross-account or service-principal policy, a gateway with no execution role, and an unreadable policy are informational `N/A`.

### AC-28: Gateway Authorizer Guardrail

- **Severity:** High
- **Description:** Requires a service control policy that denies both `CreateGateway` and `UpdateGateway` when `bedrock-agentcore:GatewayAuthorizerType` is `NONE`. A deny on create alone fails separately, because it leaves an authenticated gateway one `UpdateGateway` call away from accepting unauthenticated requests. A policy that conditions on the key in a shape which cannot deny the value `NONE`, such as a `Null` test on a member the create request always carries, fails as ineffective. AG-24 reads the authorizer type of the gateways that exist now, which says nothing about the next one created. The check reads policy content only, so every finding says that attachment is still the reader's to confirm, and a member account that cannot list the organization's policies is reported as informational `N/A` and never as a failure. Reported once under the `Global` region.

### AC-29: Runtime Authorizer Guardrail

- **Severity:** High
- **Description:** Requires a service control policy that denies both `CreateAgentRuntime` and `UpdateAgentRuntime` when `bedrock-agentcore:RuntimeAuthorizerType` is `AWS_IAM`, because a runtime on SigV4-only inbound auth authenticates the calling AWS principal, which for a hosting application is one shared role for every end user, and the end user then arrives in an unverified header. A deny on create alone fails separately. A policy written the other way round, denying `CUSTOM_JWT` and leaving SigV4 as the only way to deploy, is reported as inverted, and a condition shape that denies neither value is reported as ineffective. As with AC-28, policy content is read but attachment is not, and a member account that cannot list policies is informational `N/A`. Reported once under the `Global` region.

### AC-30: Runtime Inbound Authorization

- **Severity:** High
- **Description:** Reports how each runtime authenticates its caller. A runtime with no inbound authorizer passes, because every invoke must then be SigV4-signed and IAM decides which principal reaches the agent. A JWT authorizer that pins neither `allowedAudience` nor `allowedClients` fails, because it accepts every token its issuer minted for every application registered with that issuer. AG-24 asks this of a gateway, and a runtime callers invoke directly never passes through one. An authorizer shape the pinned botocore model does not define is informational `N/A` and names the members it found.

### AC-31: Gateway Inbound Allow Lists

- **Severity:** High
- **Description:** Judges which issuers and applications each gateway accepts tokens from. A `CUSTOM_JWT` gateway that allow-lists neither the audience nor the client id fails, because any application registered with that issuer reaches its tools; AG-24 passes the same gateway on the authorizer type alone. A scope or custom-claim constraint bounds what a token may ask for and not who minted it for whom, so it does not satisfy the check. `authorizerType` `NONE` fails as performing no inbound authentication at all. A SigV4 gateway passes, having no bearer token to allow-list, and an unrecognized authorizer type or a missing `customJWTAuthorizer` is informational `N/A`.

### AC-32: Inbound JWT Issuer Conditions

- **Severity:** High
- **Description:** Fails any cached IAM role or user that can call `GetWorkloadAccessTokenForJWT` or `CompleteResourceTokenAuth` with no condition on the inbound token's issuer, audience, or client id, because the token-exchange APIs accept an end user's JWT directly and never pass through a gateway authorizer. AC-31 pins the issuer at the gateway's front door; this is the second path to the same workload token. An `Action` element of `"*"` is a service-agnostic administrator grant and is left to AC-02. An empty or unreadable permission cache is informational `N/A`. Reported once under the `Global` region.

### AC-33: Token Issuance Scope

- **Severity:** High for a wildcard resource; Medium for a grant naming only a workload-identity directory
- **Description:** Judges which resources each cached principal may mint agent tokens against. The control is not enforced by removing the actions: the reference execution role grants all three `GetWorkloadAccessToken*` actions and an agent breaks without them, so what a policy can still do is bound which workload identity, token vault, and credential provider they reach. A wildcard resource fails, and AWS's own consent-portal execution role allows three of these actions on `Resource: "*"`, so the widest grant on the page is one a customer may have copied forward. A grant naming only a workload-identity directory is reported at Medium, because the service authorization reference marks both the identity and the directory as required and does not say whether the directory alone authorizes the call. Reported once under the `Global` region.

### AC-34: Runtime Inline Credentials

- **Severity:** High
- **Description:** Scans each runtime's environment variables for inline credential material and fails a runtime that holds any, because a credential pasted into the agent's definition never reaches the token vault and every process in the microVM reads the variable. Only variable names are reported, never values, because `environmentVariables` is modelled as sensitive. AC-14 judges the token vault's own encryption. A runtime with no environment variables passes; an unreadable runtime is informational `N/A`.

### AC-35: Policy Tool Scope

- **Severity:** High for an unconditional permit; Medium for a permit that names no action under a condition
- **Description:** Reads the active enforcing policies of the policy engine each gateway enforces and fails a permit that names no action. With no condition on it, such a permit authorizes every tool the gateway exposes for every caller the scope admits and the engine's default-deny decides nothing; under a condition, the one condition gates every tool the gateway exposes today and every tool added later. Default-deny and forbid-wins are enforced by the engine and are not settings to read. AG-25 counts enforcing policies without reading one, so a single permit over every tool passes it. A gateway enforcing no engine, an engine with no active enforcing policy, and a policy still being generated that carries no text are informational `N/A`.

### AC-36: Policy Engine Key Scope

- **Severity:** High
- **Description:** Requires the key policy behind a policy engine's customer managed key to name the principals allowed to decrypt with it and the administrators allowed to disable it or schedule it for deletion. The key cannot be added to or changed on an existing engine, so the key policy is the whole guard: a principal who can schedule the key for deletion makes every stored Cedar policy unreadable with no way to repoint the engine. AC-11 asserts that a key is named, which is presence only. An engine with no customer managed key is informational `N/A` and AC-11 reports it; an unreadable key policy is informational `N/A`.

### AC-37: Policy Guardrail Wiring

- **Severity:** High
- **Description:** For each gateway enforcing a policy with a `when guardrails` condition, requires the gateway's execution role to grant `bedrock:InvokeGuardrailChecks`, because the Policy data plane calls the Bedrock Guardrails API with forward access session credentials derived from that role. Without the grant the call is denied and the content safety the policy claims is either absent or the tool is unreachable, which the devguide does not resolve either way. The action is resourceless, so the grant is read by action and no guardrail ARN is required of it. Whether content-safety decisions belong at the authorization boundary at all is the workload owner's call, and a gateway enforcing no guardrail policy is reported as informational `N/A` that says so. An execution role outside the permission cache, and a role with unparsable policy documents, are informational `N/A`.

### AC-38: Policy Session Binding

- **Severity:** High when a temporal policy runs on a gateway that authenticates no caller; Medium when no enforcing policy is session-aware
- **Description:** Judges whether a rule that only reads across a sequence of actions, such as an unverified payee or a cumulative overspend, is evaluated against a policy session, and whether that session binds to a caller. The Gateway binds a session to the caller's authenticated identity on `CUSTOM_JWT` and `AWS_IAM` gateways, so on a gateway that authenticates no caller two callers presenting the same session id share one accumulated history and a per-session limit is reset or consumed by someone else. An engine whose active enforcing policies carry no temporal condition is reported at Medium, because every request is then judged on its own and any sequence rule is enforced by agent or tool code. AG-25 counts enforcing policies without reading whether any is session-aware.

### AC-39: Online Evaluation Operation

- **Severity:** Medium
- **Description:** Requires each online evaluation configuration to be `ACTIVE` and `ENABLED`, to sample a non-zero share of traffic, to read from at least one input source, and to write its scores to a log group, and names which of those stopped it running. AC-17 reads the same settings but reports `N/A` unless `REQUIRE_AGENTCORE_ONLINE_EVALUATION` is set, so the one verdict it cannot return by default is Failed. This check judges a configuration that exists whatever that parameter is set to. A region with no configurations is informational `N/A`, and AC-17 reports whether one is expected.

### AC-40: Evaluation Safety Coverage

- **Severity:** Medium
- **Description:** Requires each online evaluation configuration to attach both a safety evaluator and a tool-call evaluator, classified from the evaluator catalogue: a service-authored description carrying `safety metric` for the first, and an evaluation level of `TOOL_CALL` for the second. AC-17 and AC-39 count evaluators without asking what any of them scores, so ten answer-quality judges read the same as a harmful-content judge. If either category is empty in the catalogue the check judges no configuration and reports informational `N/A` with both counts, because the catalogue cannot then say which attached evaluator scores safety. An unreadable catalogue is informational `N/A`.

### AC-41: Evaluation Result Protection

- **Severity:** Medium
- **Description:** Judges the log group each online evaluation writes its results to, anchored on the configuration's `outputConfig` and not on a log group name. An evaluation result carries the agent output that was scored and the judge's reasoning about it, and AC-20 and AC-26 judge only log groups under an AgentCore prefix, so a results group named anywhere else is judged by neither. A results group that does not exist in the region fails, because CloudWatch Logs creates it on first write with no encryption key and no retention period. A configuration naming no results group is informational `N/A` and AC-39 reports the missing output configuration.

### AC-42: Evaluation Pass Role Scope

- **Severity:** High
- **Description:** Fails any cached principal that can pass an evaluation execution role through an `iam:PassRole` grant wider than the one role, or without an `iam:PassedToService` condition naming the service the role was written for. Creating or updating a configuration means passing the role named in `evaluationExecutionRoleArn`, so a wide grant turns evaluation administration into a way to run a role the caller could not assume. A region whose configurations name no execution role, and an empty permission cache, are informational `N/A`; unparsable cached policy documents are reported on their own informational `N/A` row so the judged grants still stand.

### AC-43: Evaluation Role Trust

- **Severity:** High
- **Description:** Requires every `Allow` statement in an evaluation execution role's trust policy to carry `aws:SourceAccount` or `aws:SourceArn`, or to name no service or wildcard principal. The role lets the service read the scored traces and invoke the judge model on the account's behalf, so without a guard the same service principal assumes it while acting for another customer's configuration. AC-27 judges this on gateway execution roles and reaches no evaluation role, because it reads the roles that gateways name. A configuration naming no role, and an unreadable trust policy, are informational `N/A`.

### AC-44: Evaluation Judge Model Scope

- **Severity:** Medium
- **Description:** Fails an evaluation execution role that can invoke a model through a `Resource` pattern naming no model, because an LLM-as-a-judge prompt carries the agent output being scored, so every model such a grant reaches is a model attacker-influenced text can be sent to at that model's price. Which models a workload's judges may use is the workload owner's decision, so the check asserts only that the grant names models at all and reports the patterns it found for the owner to confirm. A role with no model-invocation grant passes. A role outside the permission cache is informational `N/A`, and unparsable documents are reported on a separate informational `N/A` row.

### AC-45: Tool Execution Role Scope

- **Severity:** High
- **Description:** Judges the execution role a custom Code Interpreter or custom Browser Tool can use, and fails a role whose `Allow` statements grant every resource or every action of a service. Code the model writes runs in the sandbox with that role, and a browser session follows the pages it is pointed at with the same role, so the role has to be read as available to whatever the sandbox ends up running. `executionRoleArn` is optional on both create calls, so a tool that names no role passes, holding no credentials to misuse. A role outside the permission cache is informational `N/A`.

### AC-46: Runtime Session Limits

- **Severity:** Medium
- **Description:** Fails a runtime whose `idleRuntimeSessionTimeout` or `maxLifetime` is set to the service ceiling of 1,209,600 seconds (14 days), because a limit at the ceiling bounds nothing one session could do: each `runtimeSessionId` gets its own microVM, and a runaway task holds its session, its filesystem, and its accumulated context until one of the two timers fires. How long this workload's sessions should live is the workload owner's decision, so the assertion is the one that holds regardless. The control plane carries no per-session memory or cost limit, so those two halves of the control are named in the finding for the owner to confirm elsewhere. A runtime reporting neither setting is informational `N/A`.

### AC-47: Runtime Invocation Path

- **Severity:** High for the caller leg; Medium for the network-path leg
- **Description:** Judges who may invoke each runtime and over what path. A runtime carrying neither an `allowedWorkloadConfiguration` on its JWT authorizer nor a resource policy naming the principals allowed to invoke it fails, because a caller that satisfies its inbound authentication then reaches the agent directly and the tool policy, rate limits, and audit trail of the gateway in front of it do not apply. The network leg fails a resource policy with no `aws:SourceVpc`, `aws:SourceVpce`, `aws:VpcSourceIp`, or `aws:SourceIp` condition. AC-10 reports that a resource policy exists; the conditions inside it are what restrict anything. An unreadable runtime or resource policy is informational `N/A`.

---

## AWS Agent Registry Security Checks (8)

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
- **Description:** Checks attached and inline policy documents from the permission cache for AWS Agent Registry full-access managed policies, wildcard IAM action patterns, and `Allow`/`NotAction` allow-except statements that still grant the `agent-registry` namespace when they apply to all resources. Only the valid `agent-registry` IAM namespace is evaluated; `bedrock-agentcore` grants are reported by [AC-02](#ac-02-aws-iam-full-access) instead. Service-agnostic administrator-style grants are out of scope in both forms: a bare `Action: "*"` and a `NotAction` whose exclusions name no platform namespace are treated alike and not reported as Registry-specific grants. An empty permission cache is an informational `N/A` tooling condition, not a failure.

### AR-02: Stale Access

- **Severity:** Medium for 60+ day inactivity; Low when all principals are active; Informational when never used or incomplete
- **Description:** Identifies IAM roles and users whose attached or inline policy documents grant the `agent-registry` namespace, either through an `Allow` action or through a `NotAction` allow-except statement that does not fully cover the namespace. Attached policy names alone are never treated as proof of access. It uses IAM service-last-accessed jobs to identify access older than 60 days and principals with no Registry usage evidence. IAM job errors, timeouts, and inaccessible principals are indeterminate informational `N/A` findings rather than failures.

### AR-03: Registry Publication Approval Governance

- **Severity:** Informational by default; Medium when required
- **Description:** Verifies whether each `READY` registry requires manual review for submitted records. A registry whose `approvalConfiguration` carries `autoApprovalRules` approves submitted records automatically and is informational by default; set `RequireAgentRegistryManualApproval` to `true` (`REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL` in the Lambda) to make automatic approval fail, which also switches the remediation text from advisory to actionable. A registry with no auto-approval rules passes. `approvalConfiguration` is optional in the GA response; a registry that omits it is reported as informational `N/A` because manual review was never observed, not as a pass.

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
- **Description:** Fails any cached IAM role or user that can both write a registry record (`CreateRegistryRecord`, `UpdateRegistryRecord`, or `SubmitRegistryRecordForApproval`) and approve one with `UpdateRegistryRecordStatus`, the only operation in the registry control plane that can set a record's status to `APPROVED`. Such a principal is the publisher and the curator of the same entry, so the review the approval workflow exists to impose never happens. AR-03 reads the auto-approval setting and only when `REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL` is set, so it asserts nothing about who holds the two authorities. Both IAM namespace spellings are read, because a policy written during the public preview grants the same authorities under `bedrock-agentcore` until 30 October 2026, and a single-namespace read would answer "no collision" for it. A `Deny` scoped to one registry or carrying a condition is not treated as an account-wide `Deny`, so a narrower `Deny` reports the principal instead of excusing it. Service-agnostic administrator grants stay with AR-01. An empty permission cache is an informational `N/A` tooling condition. Reported once under the `Global` region.

---

## Agentic AI Security Checks (38)

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
- **Description:** Maps AgentCore memory encryption controls.

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
- **Description:** Fails gateways with missing, unknown, or `NONE` authorizers. Passes `AWS_IAM` and `CUSTOM_JWT`. `AUTHENTICATE_ONLY` passes only when an AgentCore policy engine is attached in `ENFORCE` mode, because the gateway authenticates the SigV4 caller but does not make an authorization decision for that authorizer type.

### AG-25: Gateway Tool Policy Enforcement

- **Severity:** High
- **Source:** AgentCore `GetGateway.policyEngineConfiguration` plus `ListPolicies`
- **Domain:** Tool Authorization
- **Description:** Fails gateways without a policy engine, with mode other than `ENFORCE`, or with no `ACTIVE` policy whose enforcement mode is `ACTIVE`. A mix of enforcing and `LOG_ONLY`/inactive policies passes with an advisory.

### AG-26: Gateway Error Detail Exposure

- **Severity:** Medium
- **Source:** AgentCore `GetGateway.exceptionLevel`
- **Domain:** Auditability & Observability
- **Description:** Fails gateways configured to return `DEBUG`-level exception detail.

### AG-27: Gateway WAF Protection

- **Severity:** Low
- **Source:** AgentCore `GetGateway.webAclArn`
- **Domain:** Abuse & Cost Protection
- **Description:** Fails AgentCore gateways without an associated AWS WAF web ACL.

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
