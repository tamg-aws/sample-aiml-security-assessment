"""Least-privilege guards for the SAM-generated runtime execution roles.

The assessment Lambdas intentionally inventory broad portions of an AWS
account, so many read-only List/Describe/Get actions require ``Resource: '*'``.
That does not justify unrelated actions or bucket-wide CRUD. This file records
the reviewed action inventory for each SAM resource and verifies that both
single- and multi-account runtime templates stay synchronized with it.
"""

import json
import os
import re

import pytest
import yaml


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SAM_TEMPLATES = [
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"),
]

_ACTION_RE = re.compile(r"-\s+([a-z0-9-]+:[A-Za-z0-9]+)")
_RESOURCE_HEADER_RE = re.compile(r"^  [A-Za-z][A-Za-z0-9]*:\s*$", re.MULTILINE)
_LARGEST_PARTITION = "aws-us-gov"
_INLINE_ROLE_POLICY_LIMIT = 10_240
_INLINE_ROLE_POLICY_BUDGET = 9_000
_MANAGED_POLICY_LIMIT = 6_144
_MANAGED_POLICY_BUDGET = 5_500


class _CfnLoader(yaml.SafeLoader):
    """Safe YAML loader that preserves CloudFormation short-form intrinsics."""


def _cfn_multi_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"Fn::{tag_suffix}": value}


_CfnLoader.add_multi_constructor("!", _cfn_multi_constructor)


def _resource_block(path, logical_id):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    header = f"\n  {logical_id}:"
    start = text.find(header)
    assert start != -1, f"resource {logical_id!r} not found in {path}"
    start += 1
    match = _RESOURCE_HEADER_RE.search(text, start + len(header))
    end = match.start() if match else len(text)
    return text[start:end]


def _actions(path, logical_id):
    return set(_ACTION_RE.findall(_resource_block(path, logical_id)))


def _statement_block(path, logical_id, sid):
    resource = _resource_block(path, logical_id)
    marker = f"- Sid: {sid}"
    start = resource.find(marker)
    assert start != -1, f"statement {sid!r} not found in {logical_id} ({path})"
    match = re.search(r"^\s+- Sid:\s+", resource[start + len(marker) :], re.MULTILINE)
    end = start + len(marker) + match.start() if match else len(resource)
    return resource[start:end]


def _unconditioned_wildcard_actions(path, logical_id):
    """Actions an Allow statement grants on Resource '*' with no Condition."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.load(fh, Loader=_CfnLoader)  # nosec B506
    return {
        action
        for policy in data["Resources"][logical_id]["Properties"]["Policies"]
        if isinstance(policy, dict)
        for statement in policy.get("Statement", [])
        if statement.get("Effect") == "Allow"
        and statement.get("Resource") == "*"
        and not {"Condition", "NotAction", "NotResource"} & set(statement)
        for action in statement.get("Action") or []
    }


def _render_policy_intrinsics(value, partition=_LARGEST_PARTITION):
    """Render policy intrinsics conservatively for IAM character-count checks."""
    if isinstance(value, list):
        return [_render_policy_intrinsics(item, partition) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"Fn::Sub"}:
        template = value["Fn::Sub"]
        assert isinstance(template, str), "size guard supports string !Sub values"
        return template.replace("${AWS::Partition}", partition).replace(
            "${AWS::AccountId}", "123456789012"
        )
    if len(value) == 1 and next(iter(value)).startswith("Fn::"):
        # A realistic upper-bound placeholder for !GetAtt/!Ref policy values.
        return "x" * 128
    return {
        key: _render_policy_intrinsics(item, partition) for key, item in value.items()
    }


_EXPECTED_ACTIONS = {
    "AIMLAssessmentStateMachine": set(),
    "ResolveRegionsFunction": set(),
    "CleanupBucketFunction": {
        "s3:DeleteObject",
        "s3:ListBucket",
    },
    "IAMPermissionCachingFunction": {
        "iam:GetGroupPolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:GetUser",
        "iam:GetUserPolicy",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupPolicies",
        "iam:ListGroupsForUser",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "s3:PutObject",
    },
    "GenerateConsolidatedReportFunction": {
        "s3:DeleteObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject",
    },
    "BedrockAssessmentReadsPolicy": {
        "aoss:GetAccessPolicy",
        "aoss:ListAccessPolicies",
        "bedrock:ListIngestionJobs",
        "cloudtrail:GetEventDataStore",
        "sagemaker:DescribeTrainingJob",
        "sagemaker:ListTrainingJobs",
    },
    "BedrockSecurityAssessmentFunction": {
        "aoss:BatchGetCollection",
        "backup:DescribeBackupVault",
        "backup:ListBackupVaults",
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:ListAgentRuntimeEndpoints",
        "bedrock-agentcore:ListAgentRuntimes",
        "bedrock-agentcore:ListBrowsers",
        "bedrock-agentcore:ListGateways",
        "bedrock-agentcore:ListMemories",
        "bedrock:GetAccountDataRetention",
        "bedrock:GetAgent",
        "bedrock:GetAgentActionGroup",
        "bedrock:GetAgentVersion",
        "bedrock:GetAutomatedReasoningPolicy",
        "bedrock:GetCustomModel",
        "bedrock:GetDataSource",
        "bedrock:GetFlow",
        "bedrock:GetFlowVersion",
        "bedrock:GetGuardrail",
        "bedrock:GetImportedModel",
        "bedrock:GetKnowledgeBase",
        "bedrock:GetMarketplaceModelEndpoint",
        "bedrock:GetModelCustomizationJob",
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock:GetPrompt",
        "bedrock:GetResourcePolicy",
        "bedrock:ListAgentActionGroups",
        "bedrock:ListAgentAliases",
        "bedrock:ListAgentCollaborators",
        "bedrock:ListAgentKnowledgeBases",
        "bedrock:ListAgents",
        "bedrock:ListAutomatedReasoningPolicies",
        "bedrock:ListCustomModels",
        "bedrock:ListDataSources",
        "bedrock:ListEnforcedGuardrailsConfiguration",
        "bedrock:ListEvaluationJobs",
        "bedrock:ListFlowAliases",
        "bedrock:ListFlows",
        "bedrock:ListGuardrails",
        "bedrock:ListImportedModels",
        "bedrock:ListInferenceProfiles",
        "bedrock:ListKnowledgeBases",
        "bedrock:ListMarketplaceModelEndpoints",
        "bedrock:ListModelCustomizationJobs",
        "bedrock:ListModelInvocationJobs",
        "bedrock:ListPrompts",
        "bedrock:ListProvisionedModelThroughputs",
        "bedrock:ListTagsForResource",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListEventDataStores",
        "cloudtrail:ListTrails",
        "cloudtrail:LookupEvents",
        "cloudwatch:DescribeAlarms",
        "comprehend:ListPiiEntitiesDetectionJobs",
        "ec2:DescribeInstances",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcs",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "ecs:ListClusters",
        "ecs:ListServices",
        "es:DescribeDomain",
        "events:ListRules",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetInstanceProfile",
        "iam:GetLoginProfile",
        "iam:GetRole",
        "iam:GetServiceLastAccessedDetails",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListServiceSpecificCredentials",
        "inspector2:BatchGetAccountStatus",
        "inspector2:ListCoverage",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:ListGrants",
        "kms:ListKeys",
        "lambda:GetFunction",
        "lambda:GetPolicy",
        "lambda:ListAliases",
        "lambda:ListFunctionUrlConfigs",
        "lambda:ListFunctions",
        "lambda:ListTags",
        "lambda:ListVersionsByFunction",
        "logs:DescribeLogGroups",
        "logs:DescribeMetricFilters",
        "logs:DescribeSubscriptionFilters",
        "macie2:DescribeBuckets",
        "macie2:DescribeClassificationJob",
        "macie2:GetAutomatedDiscoveryConfiguration",
        "macie2:GetMacieSession",
        "macie2:ListClassificationJobs",
        "neptune-graph:GetGraph",
        "organizations:DescribeEffectivePolicy",
        "organizations:DescribeOrganization",
        "organizations:DescribePolicy",
        "organizations:ListParents",
        "organizations:ListPolicies",
        "organizations:ListRoots",
        "organizations:ListTargetsForPolicy",
        "rds:DescribeDBClusters",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketPolicy",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetObject",
        "s3:GetReplicationConfiguration",
        "s3:PutObject",
        "s3vectors:GetIndex",
        "s3vectors:GetVectorBucket",
        "s3vectors:GetVectorBucketPolicy",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListEndpoints",
        "sagemaker:ListModels",
        "sagemaker:ListNotebookInstances",
        "secretsmanager:DescribeSecret",
        "servicequotas:GetAWSDefaultServiceQuota",
        "servicequotas:GetServiceQuota",
        "servicequotas:ListServiceQuotas",
        "sso:GetInlinePolicyForPermissionSet",
        "sso:ListInstances",
        "sso:ListPermissionSets",
        "tag:GetResources",
    },
    "SageMakerAssessmentReadsPolicy": {
        "organizations:ListAWSServiceAccessForOrganization",
        "sagemaker:DescribeModelBiasJobDefinition",
        "sagemaker:DescribeModelExplainabilityJobDefinition",
        "sagemaker:DescribeModelQualityJobDefinition",
    },
    "SagemakerSecurityAssessmentFunction": {
        "cloudtrail:LookupEvents",
        "config:DescribeComplianceByConfigRule",
        "config:DescribeConfigRules",
        "config:DescribeConfigurationRecorders",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSubnets",
        "ecs:DescribeServices",
        "eks:DescribeAddon",
        "eks:DescribeCluster",
        "eks:ListAddons",
        "eks:ListClusters",
        "guardduty:GetDetector",
        "guardduty:ListCoverage",
        "guardduty:ListDetectors",
        "guardduty:DescribeOrganizationConfiguration",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails",
        "iot:GetPolicy",
        "iot:ListPolicies",
        "iot:ListTargetsForPolicy",
        "organizations:DescribeOrganization",
        "organizations:DescribePolicy",
        "organizations:ListDelegatedAdministrators",
        "organizations:ListParents",
        "organizations:ListPolicies",
        "organizations:ListTargetsForPolicy",
        "s3:GetObject",
        "s3:PutObject",
        "sagemaker:DescribeAutoMLJob",
        "sagemaker:DescribeCluster",
        "sagemaker:DescribeCompilationJob",
        "sagemaker:DescribeDataQualityJobDefinition",
        "sagemaker:DescribeDomain",
        "sagemaker:DescribeEndpoint",
        "sagemaker:DescribeEndpointConfig",
        "sagemaker:DescribeFeatureGroup",
        "sagemaker:DescribeHyperParameterTuningJob",
        "sagemaker:DescribeModel",
        "sagemaker:DescribeModelPackage",
        "sagemaker:DescribeMonitoringSchedule",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:DescribeProcessingJob",
        "sagemaker:DescribeTrainingJob",
        "sagemaker:DescribeTransformJob",
        "sagemaker:GetModelPackageGroupPolicy",
        "sagemaker:ListArtifacts",
        "sagemaker:ListAssociations",
        "sagemaker:ListAutoMLJobs",
        "sagemaker:ListClusters",
        "sagemaker:ListCompilationJobs",
        "sagemaker:ListDataQualityJobDefinitions",
        "sagemaker:ListDomains",
        "sagemaker:ListEndpoints",
        "sagemaker:ListExperiments",
        "sagemaker:ListFeatureGroups",
        "sagemaker:ListHyperParameterTuningJobs",
        "sagemaker:ListModelPackageGroups",
        "sagemaker:ListModelPackages",
        "sagemaker:ListModels",
        "sagemaker:ListMonitoringSchedules",
        "sagemaker:ListNotebookInstances",
        "sagemaker:ListPipelineExecutions",
        "sagemaker:ListPipelines",
        "sagemaker:ListProcessingJobs",
        "sagemaker:ListTrainingJobs",
        "sagemaker:ListTransformJobs",
        "sagemaker:ListTrials",
        "secretsmanager:ListSecrets",
        "securityhub:DescribeOrganizationConfiguration",
        "securityhub:GetEnabledStandards",
        "securityhub:ListEnabledProductsForImport",
        "cloudwatch:DescribeAlarms",
        "logs:DescribeMetricFilters",
        "events:ListTargetsByRule",
        "iot:ListPrincipalThings",
        "iot:DescribeScheduledAudit",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPolicy",
        "kms:DescribeKey",
        "sagemaker:DescribeUserProfile",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeConformancePackCompliance",
        "sagemaker:DescribeInferenceComponent",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "config:DescribeConformancePacks",
        "iot:DescribeAccountAuditConfiguration",
        "iot:ListAuditFindings",
        "iot:ListRoleAliases",
        "iot:DescribeRoleAlias",
        "inspector2:BatchGetAccountStatus",
        "lambda:ListFunctions",
        "cloudtrail:DescribeTrails",
        "config:ListConfigurationRecorders",
        "ecs:DescribeTaskDefinition",
        "ecs:ListClusters",
        "ecs:ListServices",
        "events:ListRules",
        "inspector2:ListCoverage",
        "iot:ListScheduledAudits",
        "ram:ListResources",
        "securityhub:GetConfigurationPolicyAssociation",
        "cloudwatch:DescribeAlarmHistory",
        "ecr:DescribeRepositories",
        "ecr:DescribeImageSigningStatus",
        "ecr:GetSigningConfiguration",
        "elasticfilesystem:DescribeFileSystems",
        "fsx:DescribeFileSystems",
        "sagemaker:ListInferenceComponents",
    },
    "AgentCoreSecurityAssessmentFunction": {
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:GetBrowser",
        "bedrock-agentcore:GetCodeInterpreter",
        "bedrock-agentcore:GetGateway",
        "bedrock-agentcore:GetGatewayTarget",
        "bedrock-agentcore:GetHarness",
        "bedrock-agentcore:GetMemory",
        "bedrock-agentcore:GetOnlineEvaluationConfig",
        "bedrock-agentcore:GetPaymentManager",
        "bedrock-agentcore:GetPolicyEngine",
        "bedrock-agentcore:GetResourcePolicy",
        "bedrock-agentcore:GetTokenVault",
        "bedrock-agentcore:ListAgentRuntimes",
        "bedrock-agentcore:ListApiKeyCredentialProviders",
        "bedrock-agentcore:ListBrowsers",
        "bedrock-agentcore:ListCodeInterpreters",
        "bedrock-agentcore:ListEvaluators",
        "bedrock-agentcore:ListGatewayRateLimits",
        "bedrock-agentcore:ListGatewayTargets",
        "bedrock-agentcore:ListGateways",
        "bedrock-agentcore:ListMemories",
        "bedrock-agentcore:ListOauth2CredentialProviders",
        "bedrock-agentcore:ListPaymentCredentialProviders",
        "bedrock-agentcore:ListOnlineEvaluationConfigs",
        "bedrock-agentcore:ListPolicies",
        "bedrock-agentcore:ListPolicyEngines",
        "bedrock-agentcore:ListWorkloadIdentities",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTrails",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:PutMetricData",
        "cognito-idp:DescribeUserPool",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListUserPoolClients",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcs",
        "ecr:DescribeRepositories",
        "ecr:GetRegistryScanningConfiguration",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetRole",
        "iam:GetServiceLastAccessedDetails",
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:ListGrants",
        "logs:DescribeAccountPolicies",
        "logs:DescribeDeliveries",
        "logs:DescribeDeliverySources",
        "logs:DescribeLogGroups",
        "logs:GetDataProtectionPolicy",
        "oam:GetSinkPolicy",
        "oam:ListSinks",
        "organizations:DescribePolicy",
        "organizations:ListPolicies",
        "organizations:ListParents",
        "organizations:ListTargetsForPolicy",
        "route53resolver:GetFirewallConfig",
        "route53resolver:ListFirewallDomainLists",
        "route53resolver:ListFirewallDomains",
        "route53resolver:ListFirewallRuleGroupAssociations",
        "route53resolver:ListFirewallRules",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetObject",
        "s3:PutObject",
        "wafv2:GetWebACL",
        "bedrock-agentcore:GetBatchEvaluation",
        "bedrock-agentcore:GetEvaluator",
        "bedrock-agentcore:ListAgentRuntimeEndpoints",
        "bedrock-agentcore:ListBatchEvaluations",
        "bedrock-agentcore:ListHarnesses",
        "bedrock-agentcore:ListPaymentManagers",
        "ce:GetAnomalySubscriptions",
        "cloudwatch:ListMetrics",
        "ec2:GetManagedPrefixListEntries",
        "events:ListRules",
        "inspector2:ListCoverage",
        "logs:DescribeDeliveryDestinations",
        "network-firewall:DescribeFirewall",
        "network-firewall:DescribeRuleGroup",
        "network-firewall:ListFirewalls",
        "oam:ListLinks",
        "organizations:DescribeOrganization",
        "s3:GetAccountPublicAccessBlock",
        "xray:GetTraceSegmentDestination",
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock-agentcore:ListAgentRuntimeVersions",
        "ce:GetAnomalyMonitors",
        "ec2:DescribeNatGateways",
        "events:ListTargetsByRule",
        "logs:DescribeMetricFilters",
        "network-firewall:DescribeFirewallPolicy",
    },
    "AgentRegistrySecurityAssessmentFunction": {
        "agent-registry:GetRegistry",
        "agent-registry:ListRegistries",
        "agent-registry:ListRegistryRecords",
        "events:ListRules",
        "events:ListTargetsByRule",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails",
        "s3:GetObject",
        "s3:PutObject",
    },
    "ResponsibleAIGRCAssessmentFunction": {
        "aoss:ListCollections",
        "aoss:ListSecurityPolicies",
        "apigateway:GET",
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:ListAgentRuntimes",
        "bedrock:GetAgent",
        "bedrock:GetDataSource",
        "bedrock:GetGuardrail",
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock:ListAgents",
        "bedrock:ListAutomatedReasoningPolicies",
        "bedrock:ListCustomModels",
        "bedrock:ListDataSources",
        "bedrock:ListEvaluationJobs",
        "bedrock:ListFoundationModels",
        "bedrock:ListGuardrails",
        "bedrock:ListIngestionJobs",
        "bedrock:ListKnowledgeBases",
        "bedrock:ListTagsForResource",
        "budgets:ViewBudget",
        "ce:GetAnomalyMonitors",
        "cloudwatch:DescribeAlarms",
        "config:DescribeConfigRules",
        "ecr:DescribeRepositories",
        "events:ListRules",
        "inspector2:BatchGetAccountStatus",
        "lambda:GetFunctionConcurrency",
        "lambda:ListFunctions",
        "logs:DescribeAccountPolicies",
        "logs:GetDataProtectionPolicy",
        "macie2:GetAutomatedDiscoveryConfiguration",
        "macie2:GetMacieSession",
        "organizations:DescribePolicy",
        "organizations:ListPolicies",
        "s3:GetBucketNotification",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetObject",
        "s3:ListAllMyBuckets",
        "s3:PutObject",
        "sagemaker:DescribeFeatureGroup",
        "sagemaker:ListEndpoints",
        "sagemaker:ListFeatureGroups",
        "sagemaker:ListModelCards",
        "sagemaker:ListModels",
        "sagemaker:ListMonitoringSchedules",
        "sagemaker:ListTags",
        "scheduler:ListSchedules",
        "servicequotas:ListAWSDefaultServiceQuotas",
        "servicequotas:ListServiceQuotas",
        "shield:DescribeSubscription",
        "states:DescribeStateMachine",
        "states:ListStateMachines",
        "wafv2:GetWebACL",
        "wafv2:ListWebACLs",
    },
    "OWASPSecurityAssessmentFunction": {
        "bedrock:GetGuardrail",
        "bedrock:ListGuardrails",
        "lambda:ListFunctions",
        "s3:GetObject",
        "s3:PutObject",
    },
}


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
@pytest.mark.parametrize("logical_id", sorted(_EXPECTED_ACTIONS))
def test_sam_resource_actions_match_reviewed_inventory(template, logical_id):
    actual = _actions(template, logical_id)
    expected = _EXPECTED_ACTIONS[logical_id]
    assert actual == expected, (
        f"{os.path.basename(template)} {logical_id} IAM drift. "
        f"Missing: {sorted(expected - actual)}; excess: {sorted(actual - expected)}"
    )


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_agentcore_memory_decrypt_is_confined_to_agentcore(template):
    """AC-07's kms:Decrypt reaches only keys AgentCore uses on the role's behalf.

    GetMemory on a customer managed key memory with strategies ran kms:Decrypt
    under the caller through forward access sessions (CloudTrail, 2026-09-27),
    so the role needs the grant. Without the kms:ViaService condition it would
    decrypt any ciphertext under any key in the account.
    """
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    statements = [
        statement
        for policy in data["Resources"]["AgentCoreSecurityAssessmentFunction"][
            "Properties"
        ]["Policies"]
        if isinstance(policy, dict)
        for statement in policy.get("Statement", [])
    ]
    decrypting = [
        statement
        for statement in statements
        if "kms:Decrypt" in (statement.get("Action") or [])
    ]

    assert decrypting == [
        {
            "Sid": "AgentCoreMemoryKeyDecrypt",
            "Effect": "Allow",
            "Action": ["kms:Decrypt"],
            "Resource": {
                "Fn::Sub": "arn:${AWS::Partition}:kms:*:${AWS::AccountId}:key/*"
            },
            "Condition": {
                "StringLike": {"kms:ViaService": "bedrock-agentcore.*.amazonaws.com"}
            },
        }
    ]


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_sam_templates_do_not_use_bucket_wide_crud_policy(template):
    with open(template, encoding="utf-8") as fh:
        text = fh.read()
    assert "S3CrudPolicy" not in text
    assert "sts:GetCallerIdentity" not in text
    assert "s3:GetBucketEncryption" not in text


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_sam_lambda_inline_policy_documents_stay_within_budget(template):
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    for logical_id, resource in data["Resources"].items():
        if resource.get("Type") != "AWS::Serverless::Function":
            continue
        policy_documents = []
        for policy in resource.get("Properties", {}).get("Policies", []) or []:
            if isinstance(policy, dict) and "Statement" in policy:
                policy_documents.append(
                    {"Version": "2012-10-17", "Statement": policy["Statement"]}
                )

        aggregate_size = sum(
            len(
                json.dumps(
                    _render_policy_intrinsics(document),
                    separators=(",", ":"),
                )
            )
            for document in policy_documents
        )
        assert aggregate_size <= _INLINE_ROLE_POLICY_BUDGET, (
            f"{os.path.basename(template)} {logical_id} renders to an estimated "
            f"{aggregate_size:,} inline-policy characters in {_LARGEST_PARTITION}; "
            f"keep it below the {_INLINE_ROLE_POLICY_BUDGET:,}-character project "
            f"budget and never exceed IAM's aggregate "
            f"{_INLINE_ROLE_POLICY_LIMIT:,}-character role quota."
        )


def _references(value, logical_id):
    """Whether a parsed template value refers to logical_id by any intrinsic."""
    if isinstance(value, list):
        return any(_references(item, logical_id) for item in value)
    if isinstance(value, dict):
        return any(
            _references(key, logical_id) or _references(item, logical_id)
            for key, item in value.items()
        )
    return isinstance(value, str) and re.search(rf"\b{logical_id}\b", value) is not None


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
@pytest.mark.parametrize("partition", ["aws", "aws-us-gov"])
def test_bedrock_managed_policy_renders_within_its_budget(template, partition):
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    document = data["Resources"]["BedrockAssessmentReadsPolicy"]["Properties"][
        "PolicyDocument"
    ]
    rendered = json.dumps(
        _render_policy_intrinsics(document, partition), separators=(",", ":")
    )
    assert partition + ":" in rendered
    assert len(rendered) <= _MANAGED_POLICY_BUDGET, (
        f"{os.path.basename(template)} BedrockAssessmentReadsPolicy renders to "
        f"{len(rendered):,} characters in {partition}; keep it below the "
        f"{_MANAGED_POLICY_BUDGET:,}-character project budget and never exceed "
        f"IAM's {_MANAGED_POLICY_LIMIT:,}-character managed policy limit."
    )


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_bedrock_managed_policy_holds_exactly_the_approved_grants(template):
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    resource = data["Resources"]["BedrockAssessmentReadsPolicy"]
    assert resource["Type"] == "AWS::IAM::ManagedPolicy"
    document = resource["Properties"]["PolicyDocument"]
    grants = sorted(
        (
            statement["Effect"],
            action,
            json.dumps(statement["Resource"], sort_keys=True),
        )
        for statement in document["Statement"]
        for action in statement["Action"]
    )
    assert all(
        set(s) <= {"Sid", "Effect", "Action", "Resource"} for s in document["Statement"]
    )
    assert grants == sorted(
        [
            ("Allow", "aoss:ListAccessPolicies", '"*"'),
            ("Allow", "aoss:GetAccessPolicy", '"*"'),
            ("Allow", "sagemaker:ListTrainingJobs", '"*"'),
            (
                "Allow",
                "cloudtrail:GetEventDataStore",
                json.dumps(
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:cloudtrail:*:"
                        "${AWS::AccountId}:eventdatastore/*"
                    }
                ),
            ),
            (
                "Allow",
                "bedrock:ListIngestionJobs",
                json.dumps(
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:bedrock:*:"
                        "${AWS::AccountId}:knowledge-base/*"
                    }
                ),
            ),
            (
                "Allow",
                "sagemaker:DescribeTrainingJob",
                json.dumps(
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:sagemaker:*:"
                        "${AWS::AccountId}:training-job/*"
                    }
                ),
            ),
        ]
    )
    inline = _actions(template, "BedrockSecurityAssessmentFunction")
    assert not {action for _, action, _ in grants} & inline


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_bedrock_managed_policy_is_attached_only_to_the_bedrock_function(template):
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    managed = {
        logical_id
        for logical_id, resource in data["Resources"].items()
        if resource.get("Type") == "AWS::IAM::ManagedPolicy"
    }
    assert managed == {"BedrockAssessmentReadsPolicy", "SageMakerAssessmentReadsPolicy"}
    properties = data["Resources"]["BedrockAssessmentReadsPolicy"]["Properties"]
    assert not {"Roles", "Users", "Groups"} & set(properties)

    referencing = {
        logical_id
        for logical_id, resource in data["Resources"].items()
        if logical_id != "BedrockAssessmentReadsPolicy"
        and _references(resource, "BedrockAssessmentReadsPolicy")
    }
    assert referencing == {"BedrockSecurityAssessmentFunction"}
    policies = data["Resources"]["BedrockSecurityAssessmentFunction"]["Properties"][
        "Policies"
    ]
    references = [p for p in policies if _references(p, "BedrockAssessmentReadsPolicy")]
    assert references == [{"Fn::Ref": "BedrockAssessmentReadsPolicy"}]
    assert not _references(data.get("Outputs", {}), "BedrockAssessmentReadsPolicy")


_SAGEMAKER_MONITORING_JOB_DEFINITIONS = json.dumps(
    [
        {
            "Fn::Sub": "arn:${AWS::Partition}:sagemaker:*:${AWS::AccountId}:"
            f"{kind}-job-definition/*"
        }
        for kind in ("model-quality", "model-bias", "model-explainability")
    ]
)
_SAGEMAKER_MANAGED_GRANTS = [
    ("Allow", "organizations:ListAWSServiceAccessForOrganization", '"*"'),
    *(
        ("Allow", action, _SAGEMAKER_MONITORING_JOB_DEFINITIONS)
        for action in (
            "sagemaker:DescribeModelQualityJobDefinition",
            "sagemaker:DescribeModelBiasJobDefinition",
            "sagemaker:DescribeModelExplainabilityJobDefinition",
        )
    ),
]


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
@pytest.mark.parametrize("partition", ["aws", "aws-us-gov"])
def test_sagemaker_managed_policy_renders_within_its_budget(template, partition):
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    document = data["Resources"]["SageMakerAssessmentReadsPolicy"]["Properties"][
        "PolicyDocument"
    ]
    rendered = json.dumps(
        _render_policy_intrinsics(document, partition), separators=(",", ":")
    )
    assert len(rendered) <= _MANAGED_POLICY_BUDGET, (
        f"{os.path.basename(template)} SageMakerAssessmentReadsPolicy renders to "
        f"{len(rendered):,} characters in {partition}; keep it below the "
        f"{_MANAGED_POLICY_BUDGET:,}-character project budget and never exceed "
        f"IAM's {_MANAGED_POLICY_LIMIT:,}-character managed policy limit."
    )


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_sagemaker_managed_policy_holds_exactly_the_approved_grants(template):
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    resource = data["Resources"]["SageMakerAssessmentReadsPolicy"]
    assert resource["Type"] == "AWS::IAM::ManagedPolicy"
    document = resource["Properties"]["PolicyDocument"]
    assert all(
        set(s) <= {"Sid", "Effect", "Action", "Resource"} for s in document["Statement"]
    )
    grants = sorted(
        (
            statement["Effect"],
            action,
            json.dumps(statement["Resource"], sort_keys=True),
        )
        for statement in document["Statement"]
        for action in statement["Action"]
    )
    assert grants == sorted(_SAGEMAKER_MANAGED_GRANTS)
    inline = _actions(template, "SagemakerSecurityAssessmentFunction")
    assert not {action for _, action, _ in grants} & inline


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_sagemaker_managed_policy_is_attached_only_to_the_sagemaker_function(template):
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    properties = data["Resources"]["SageMakerAssessmentReadsPolicy"]["Properties"]
    assert not {"Roles", "Users", "Groups"} & set(properties)
    referencing = {
        logical_id
        for logical_id, resource in data["Resources"].items()
        if logical_id != "SageMakerAssessmentReadsPolicy"
        and _references(resource, "SageMakerAssessmentReadsPolicy")
    }
    assert referencing == {"SagemakerSecurityAssessmentFunction"}
    policies = data["Resources"]["SagemakerSecurityAssessmentFunction"]["Properties"][
        "Policies"
    ]
    references = [
        p for p in policies if _references(p, "SageMakerAssessmentReadsPolicy")
    ]
    assert references == [{"Fn::Ref": "SageMakerAssessmentReadsPolicy"}]
    assert not _references(data.get("Outputs", {}), "SageMakerAssessmentReadsPolicy")


_ARTIFACT_PREFIXES = {
    "IAMPermissionCachingFunction": ("permissions_cache_*.json",),
    "GenerateConsolidatedReportFunction": (
        "bedrock_security_report_*.csv",
        "sagemaker_security_report_*.csv",
        "agentcore_security_report_*.csv",
        "agent_registry_security_report_*.csv",
        "responsible_ai_grc_security_report_*.csv",
        "owasp_security_report_*.csv",
        "security_assessment_single_account_*.html",
        "permissions_cache_*.json",
    ),
    "BedrockSecurityAssessmentFunction": (
        "permissions_cache_*.json",
        "bedrock_security_report_*.csv",
    ),
    "SagemakerSecurityAssessmentFunction": (
        "permissions_cache_*.json",
        "sagemaker_security_report_*.csv",
    ),
    "AgentCoreSecurityAssessmentFunction": (
        "permissions_cache_*.json",
        "agentcore_security_report_*.csv",
    ),
    "AgentRegistrySecurityAssessmentFunction": (
        "permissions_cache_*.json",
        "agent_registry_security_report_*.csv",
    ),
    "ResponsibleAIGRCAssessmentFunction": (
        "permissions_cache_*.json",
        "responsible_ai_grc_security_report_*.csv",
    ),
    "OWASPSecurityAssessmentFunction": (
        "bedrock_security_report_*.csv",
        "sagemaker_security_report_*.csv",
        "agentcore_security_report_*.csv",
        "responsible_ai_grc_security_report_*.csv",
        "owasp_security_report_*.csv",
    ),
}


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
@pytest.mark.parametrize("logical_id", sorted(_ARTIFACT_PREFIXES))
def test_assessment_artifact_access_is_prefix_scoped(template, logical_id):
    block = _resource_block(template, logical_id)
    assert "${AIMLAssessmentBucket.Arn}/*" not in block
    for prefix in _ARTIFACT_PREFIXES[logical_id]:
        assert f"${{AIMLAssessmentBucket.Arn}}/{prefix}" in block


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_iam_permission_cache_identity_reads_are_resource_scoped(template):
    block = _resource_block(template, "IAMPermissionCachingFunction")
    required_resources = {
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*",
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:user/*",
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:group/*",
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/*",
        "arn:${AWS::Partition}:iam::aws:policy/*",
    }
    missing = sorted(
        resource for resource in required_resources if resource not in block
    )
    assert not missing


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
@pytest.mark.parametrize(
    "logical_id",
    [
        "BedrockSecurityAssessmentFunction",
        "SagemakerSecurityAssessmentFunction",
        "AgentCoreSecurityAssessmentFunction",
        "AgentRegistrySecurityAssessmentFunction",
    ],
)
def test_service_last_access_generation_is_identity_scoped(template, logical_id):
    generation = _statement_block(
        template, logical_id, "IAMServiceLastAccessGeneration"
    )
    assert "iam:GenerateServiceLastAccessedDetails" in generation
    assert "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*" in generation
    assert "arn:${AWS::Partition}:iam::${AWS::AccountId}:user/*" in generation
    assert not re.search(r"Resource:\s+['\"]\*['\"]", generation)

    assert "iam:GetServiceLastAccessedDetails" in _unconditioned_wildcard_actions(
        template, logical_id
    )
    # The Bedrock and AgentCore roles fold their unconditioned '*' reads into
    # one statement to stay under the inline policy budget.
    results_sid = {
        "BedrockSecurityAssessmentFunction": "AccountReadsOnWildcard",
        "AgentCoreSecurityAssessmentFunction": "AgentCoreReadsWithoutResourceType",
    }.get(logical_id, "IAMServiceLastAccessResults")
    results = _statement_block(template, logical_id, results_sid)
    assert "iam:GetServiceLastAccessedDetails" in results
    assert re.search(r"Resource:\s+['\"]\*['\"]", results)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_bedrock_resource_level_actions_are_arn_scoped(template):
    """Bedrock inventory stays wildcarded only where IAM requires it."""
    inventory = _statement_block(
        template,
        "BedrockSecurityAssessmentFunction",
        "AccountReadsOnWildcard",
    )
    assert re.search(r"Resource:\s+['\"]\*['\"]", inventory)
    # Account-level enumerations with no resource-level authorization support
    # stay on the wildcard inventory statement.
    for action in (
        "bedrock:ListGuardrails",
        "bedrock:ListPrompts",
        "bedrock:ListAutomatedReasoningPolicies",
        "bedrock:ListProvisionedModelThroughputs",
    ):
        assert action in inventory
    for action in (
        "bedrock:GetKnowledgeBase",
        "bedrock:GetAgent",
        "bedrock:GetGuardrail",
        "bedrock:GetPrompt",
        "bedrock:GetCustomModel",
        "bedrock:GetFlow",
        "bedrock:ListAgentAliases",
        "bedrock:GetAgentVersion",
        "bedrock:ListFlowAliases",
        "bedrock:GetFlowVersion",
    ):
        assert action not in inventory

    expected_resources = {
        "BedrockGuardrailRead": "bedrock:*:${AWS::AccountId}:guardrail/*",
        "BedrockPromptRead": "bedrock:*:${AWS::AccountId}:prompt/*",
        "BedrockAgentRead": "bedrock:*:${AWS::AccountId}:agent/*",
        "BedrockCustomModelRead": "bedrock:*:${AWS::AccountId}:custom-model/*",
        "BedrockCustomizationJobRead": (
            "bedrock:*:${AWS::AccountId}:model-customization-job/*"
        ),
        "BedrockFlowRead": "bedrock:*:${AWS::AccountId}:flow/*",
        "BedrockKnowledgeBaseRead": "bedrock:*:${AWS::AccountId}:knowledge-base/*",
        # BR-20 reads the S3 Vectors bucket behind a knowledge base and the one
        # index that knowledge base names. The region is wildcarded (a knowledge
        # base can point at a bucket in another region) but the account and the
        # resource type are not: an index ARN is bucket/<name>/index/<name>, so
        # this bucket/* resource covers GetIndex without a second statement.
        "S3VectorsKnowledgeBaseStoreRead": "s3vectors:*:${AWS::AccountId}:bucket/*",
        "BedrockImportedModelRead": "bedrock:*:${AWS::AccountId}:imported-model/*",
        "BedrockInferenceProfileTagRead": (
            "bedrock:*:${AWS::AccountId}:inference-profile/*"
        ),
        "BedrockAutomatedReasoningRead": (
            "bedrock:*:${AWS::AccountId}:automated-reasoning-policy/*"
        ),
        "BedrockMarketplaceEndpointRead": (
            "bedrock:*:${AWS::AccountId}:marketplace/model-endpoint/all-access"
        ),
    }
    for sid, resource in expected_resources.items():
        statement = _statement_block(template, "BedrockSecurityAssessmentFunction", sid)
        assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)
    # BR-43's GetResourcePolicy and BR-46's data-source reads share the
    # custom-model/* and knowledge-base/* resources, so they sit in those
    # statements instead of two duplicate-resource Sids.
    for sid, actions in {
        "BedrockCustomModelRead": ("bedrock:GetResourcePolicy",),
        "BedrockKnowledgeBaseRead": (
            "bedrock:ListDataSources",
            "bedrock:GetDataSource",
        ),
    }.items():
        statement = _statement_block(template, "BedrockSecurityAssessmentFunction", sid)
        for action in actions:
            assert action in statement


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_bedrock_organizations_policy_target_read_is_arn_scoped(template):
    inventory = _statement_block(
        template,
        "BedrockSecurityAssessmentFunction",
        "AccountReadsOnWildcard",
    )
    assert "organizations:ListPolicies" in inventory
    assert "organizations:ListTargetsForPolicy" not in inventory
    assert re.search(r"Resource:\s+['\"]\*['\"]", inventory)

    policy_targets = _statement_block(
        template,
        "BedrockSecurityAssessmentFunction",
        "OrganizationsPolicyTargetRead",
    )
    assert "organizations:ListTargetsForPolicy" in policy_targets
    assert "organizations::*:policy/*/*/*" in policy_targets
    assert "organizations::aws:policy/*/*" in policy_targets
    assert not re.search(r"Resource:\s+['\"]\*['\"]", policy_targets)

    account_path = _statement_block(
        template,
        "BedrockSecurityAssessmentFunction",
        "OrganizationsAccountPathRead",
    )
    assert "organizations:ListParents" in account_path
    assert "organizations::*:account/o-*/${AWS::AccountId}" in account_path
    assert "organizations::*:ou/o-*/ou-*" in account_path
    assert not re.search(r"Resource:\s+['\"]\*['\"]", account_path)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_bedrock_quota_and_alarm_reads_are_arn_scoped(template):
    quota = _statement_block(
        template, "BedrockSecurityAssessmentFunction", "BedrockServiceQuotaRead"
    )
    assert "servicequotas:GetServiceQuota" in quota
    assert "servicequotas:*:${AWS::AccountId}:bedrock/*" in quota
    assert not re.search(r"Resource:\s+['\"]\*['\"]", quota)

    alarms = _statement_block(
        template, "BedrockSecurityAssessmentFunction", "AccountReadsOnWildcard"
    )
    # API_DescribeAlarms returns composite alarms only to a grant scoped to
    # '*', and BR-32 credits an acting composite, so alarm:* would hide them.
    assert "cloudwatch:DescribeAlarms" in alarms
    assert re.search(r"Resource:\s+['\"]\*['\"]", alarms)
    assert "cloudwatch:*:${AWS::AccountId}:alarm:*" not in alarms
    assert "composite alarms if your" in alarms
    assert [
        action
        for action in re.findall(r"-\s+([a-z0-9-]+:[A-Za-z0-9]+)", alarms)
        if action.startswith("cloudwatch:")
    ] == ["cloudwatch:DescribeAlarms"]
    # The folded statement holds other services' reads, so pin the whole role:
    # DescribeAlarms is its only CloudWatch action and it appears only once.
    role = _resource_block(template, "BedrockSecurityAssessmentFunction")
    assert re.findall(r"-\s+(cloudwatch:[A-Za-z0-9]+)", role) == [
        "cloudwatch:DescribeAlarms"
    ]


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_sagemaker_and_guardduty_resource_reads_are_arn_scoped(template):
    inventory = _statement_block(
        template,
        "SagemakerSecurityAssessmentFunction",
        "SageMakerAccountInventoryPermissions",
    )
    assert "sagemaker:ListNotebookInstances" in inventory
    # ListPipelineExecutions is an account-level enumeration with no
    # resource-level authorization support, so it stays on Resource '*'.
    assert "sagemaker:ListPipelineExecutions" in inventory
    for action in (
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListModelPackages",
        "sagemaker:GetModelPackageGroupPolicy",
    ):
        assert action not in inventory
    assert re.search(r"Resource:\s+['\"]\*['\"]", inventory)

    reads = _statement_block(
        template,
        "SagemakerSecurityAssessmentFunction",
        "SageMakerResourceReadPermissions",
    )
    assert "sagemaker:ListPipelineExecutions" not in reads
    for action in (
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListModelPackages",
        "sagemaker:GetModelPackageGroupPolicy",
    ):
        assert action in reads
    for resource in (
        "sagemaker:*:${AWS::AccountId}:notebook-instance/*",
        "sagemaker:*:${AWS::AccountId}:model-package/*",
        "sagemaker:*:${AWS::AccountId}:model-package-group/*",
        "sagemaker:*:${AWS::AccountId}:pipeline/*",
        "sagemaker:*:${AWS::AccountId}:cluster/*",
    ):
        assert resource in reads
    assert not re.search(r"Resource:\s+['\"]\*['\"]", reads)

    detector = _statement_block(
        template, "SagemakerSecurityAssessmentFunction", "GuardDutyDetectorRead"
    )
    assert "guardduty:GetDetector" in detector
    assert "guardduty:ListCoverage" in detector
    assert "guardduty:*:${AWS::AccountId}:detector/*" in detector
    assert not re.search(r"Resource:\s+['\"]\*['\"]", detector)

    ecs_services = _statement_block(
        template, "SagemakerSecurityAssessmentFunction", "EcsServiceRead"
    )
    assert "ecs:DescribeServices" in ecs_services
    assert "ecs:*:${AWS::AccountId}:service/*" in ecs_services
    assert not re.search(r"Resource:\s+['\"]\*['\"]", ecs_services)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_sagemaker_scope27_reads_wildcard_only_where_iam_has_no_resource_type(
    template,
):
    """SM-35..SM-41 take '*' only on list actions with no IAM resource type.

    The servicereference.us-east-1.amazonaws.com action lists give no resource
    type for organizations:ListDelegatedAdministrators, eks:ListClusters,
    secretsmanager:ListSecrets or iot:ListPolicies, and give hub, cluster,
    addon and policy for the four scoped reads below.
    """
    for sid, actions in (
        (
            "OrganizationsInventoryPermissions",
            ("organizations:ListDelegatedAdministrators",),
        ),
        (
            "AccountInventoryWithoutResourceType",
            (
                "eks:ListClusters",
                "secretsmanager:ListSecrets",
                "iot:ListPolicies",
                "cloudtrail:LookupEvents",
            ),
        ),
        (
            "EC2NetworkPostureInventory",
            (
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
            ),
        ),
        (
            "GuardDutyInventoryPermissions",
            ("guardduty:ListDetectors", "guardduty:DescribeOrganizationConfiguration"),
        ),
        ("ConformancePackInventory", ("config:DescribeConformancePacks",)),
        (
            "IoTDeviceDefenderAuditRead",
            (
                "iot:DescribeAccountAuditConfiguration",
                "iot:ListAuditFindings",
                "iot:ListRoleAliases",
            ),
        ),
        ("InspectorAccountStatusRead", ("inspector2:BatchGetAccountStatus",)),
        ("LambdaFunctionInventory", ("lambda:ListFunctions",)),
    ):
        statement = _statement_block(
            template, "SagemakerSecurityAssessmentFunction", sid
        )
        for action in actions:
            assert action in statement
        assert re.search(r"Resource:\s+['\"]\*['\"]", statement)

    for sid, actions, resources in (
        (
            "SecurityHubStandardsRead",
            ("securityhub:GetEnabledStandards",),
            ("securityhub:*:${AWS::AccountId}:hub/default",),
        ),
        (
            "EKSAddonRead",
            ("eks:DescribeCluster", "eks:ListAddons", "eks:DescribeAddon"),
            (
                "eks:*:${AWS::AccountId}:cluster/*",
                "eks:*:${AWS::AccountId}:addon/*/*/*",
            ),
        ),
        (
            "IoTPolicyRead",
            ("iot:GetPolicy", "iot:ListTargetsForPolicy"),
            ("iot:*:${AWS::AccountId}:policy/*",),
        ),
        (
            "IoTRoleAliasRead",
            ("iot:DescribeRoleAlias",),
            ("iot:*:${AWS::AccountId}:rolealias/*",),
        ),
    ):
        statement = _statement_block(
            template, "SagemakerSecurityAssessmentFunction", sid
        )
        for action in actions:
            assert action in statement
        for resource in resources:
            assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)

    # SM-40 reads rotation metadata only; a secret value read would widen the
    # role from inventory to data access.
    block = _resource_block(template, "SagemakerSecurityAssessmentFunction")
    assert "secretsmanager:GetSecretValue" not in block


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_agentcore_resource_reads_and_metric_writes_are_constrained(template):
    wildcard = _unconditioned_wildcard_actions(
        template, "AgentCoreSecurityAssessmentFunction"
    )
    merged = _statement_block(
        template,
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreReadsWithoutResourceType",
    )
    assert "bedrock-agentcore:ListAgentRuntimes" in wildcard
    assert "bedrock-agentcore:GetAgentRuntime" not in wildcard
    assert "bedrock-agentcore:ListPolicies" not in wildcard
    assert re.search(r"Resource:\s+['\"]\*['\"]", merged)

    reads = _statement_block(
        template,
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreResourceReadPermissions",
    )
    for action in (
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:GetGateway",
        "bedrock-agentcore:GetResourcePolicy",
        "bedrock-agentcore:ListPolicies",
    ):
        assert action in reads
    for resource in (
        "bedrock-agentcore:*:${AWS::AccountId}:runtime/*",
        "bedrock-agentcore:*:${AWS::AccountId}:runtime/*/runtime-endpoint/*",
        "bedrock-agentcore:*:${AWS::AccountId}:gateway/*",
        "bedrock-agentcore:*:${AWS::AccountId}:policy-engine/*",
        "bedrock-agentcore:*:${AWS::AccountId}:online-evaluation-config/*",
    ):
        assert resource in reads
    assert not re.search(r"Resource:\s+['\"]\*['\"]", reads)

    assert "bedrock-agentcore:GetTokenVault" in wildcard
    assert re.search(r"Resource:\s+['\"]\*['\"]", merged)
    assert "token-vault/" not in merged

    service_role = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "IAMRolePermissions"
    )
    assert (
        "iam::${AWS::AccountId}:role/AWSServiceRoleForBedrockAgentCoreNetwork"
    ) in service_role
    assert (
        "iam::${AWS::AccountId}:role/aws-service-role/"
        "network.bedrock-agentcore.amazonaws.com/"
        "AWSServiceRoleForBedrockAgentCoreNetwork"
    ) in service_role
    assert "iam::*:role/" not in service_role

    metrics = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "CloudWatchPermissions"
    )
    assert "cloudwatch:PutMetricData" in metrics
    assert "cloudwatch:namespace: AIMLSecurity/AgentCore" in metrics

    repositories = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "ECRPermissions"
    )
    assert "ecr:DescribeRepositories" in repositories
    assert "ecr:*:${AWS::AccountId}:repository/*" in repositories
    assert not re.search(r"Resource:\s+['\"]\*['\"]", repositories)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_agentcore_observability_and_governance_reads_are_scoped_where_iam_allows(
    template,
):
    """The AgentCore telemetry and policy reads wildcard only the enumerations.

    Each enumeration below has no resource type in the IAM service authorization
    reference, so an ARN on it denies the call. The read that follows it does take
    a resource, and is scoped. Splitting them keeps the wildcard on the statement
    that cannot avoid it instead of on the statement that can.
    """
    wildcard_enumerations = {
        "CloudTrailTrailInventory": ("cloudtrail:ListTrails",),
        "LogsDeliveryInventory": (
            "logs:DescribeDeliverySources",
            "logs:DescribeDeliveries",
        ),
        "LogsAccountPolicyInventory": ("logs:DescribeAccountPolicies",),
        "ObservabilitySinkInventory": ("oam:ListSinks",),
        "OrganizationsInventoryPermissions": ("organizations:ListPolicies",),
    }
    # Keyed by the Sid each group held before the fold into
    # AgentCoreReadsWithoutResourceType.
    wildcard = _unconditioned_wildcard_actions(
        template, "AgentCoreSecurityAssessmentFunction"
    )
    merged = _statement_block(
        template,
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreReadsWithoutResourceType",
    )
    for former_sid, actions in wildcard_enumerations.items():
        for action in actions:
            assert action in wildcard, former_sid
        assert re.search(r"Resource:\s+['\"]\*['\"]", merged)

    scoped_reads = {
        "CloudTrailEventSelectorRead": (
            "cloudtrail:GetEventSelectors",
            "cloudtrail:*:${AWS::AccountId}:trail/*",
        ),
        "AgentCoreIdentityInventory": (
            "bedrock-agentcore:ListWorkloadIdentities",
            "bedrock-agentcore:*:${AWS::AccountId}:workload-identity-directory/*",
        ),
        "LogsDataProtectionPolicyRead": (
            "logs:GetDataProtectionPolicy",
            "logs:*:${AWS::AccountId}:log-group:*",
        ),
        "ObservabilitySinkPolicyRead": (
            "oam:GetSinkPolicy",
            "oam:*:${AWS::AccountId}:sink/*",
        ),
        "LogEncryptionKeyPolicyRead": (
            "kms:GetKeyPolicy",
            "kms:*:${AWS::AccountId}:key/*",
        ),
        "PolicyEngineKeyStateRead": (
            "kms:ListGrants",
            "kms:*:${AWS::AccountId}:key/*",
        ),
        "OrganizationsPolicyRead": (
            "organizations:DescribePolicy",
            "organizations::*:policy/*/*/*",
        ),
    }
    for sid, (action, resource) in scoped_reads.items():
        statement = _statement_block(
            template, "AgentCoreSecurityAssessmentFunction", sid
        )
        assert action in statement
        assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)

    # AC-18 reads each trail's logging state beside its selectors, on the same
    # trail ARN, and lists the credential providers in the token vault.
    trail_read = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "CloudTrailEventSelectorRead"
    )
    assert "cloudtrail:GetTrailStatus" in trail_read
    identity = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "AgentCoreIdentityInventory"
    )
    assert "bedrock-agentcore:ListOauth2CredentialProviders" in identity
    assert "bedrock-agentcore:ListApiKeyCredentialProviders" in identity
    assert "bedrock-agentcore:*:${AWS::AccountId}:token-vault/*" in identity

    # DescribeSecurityGroups has no resource-level authorization either, so it
    # is granted on '*' with no condition.
    assert "ec2:DescribeSecurityGroups" in wildcard
    assert re.search(r"Resource:\s+['\"]\*['\"]", merged)

    # The gateway execution role's name is chosen by whoever created the gateway,
    # so the trust read covers role/* in this account and no other account.
    gateway_role = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "AgentCoreGatewayRoleTrustRead"
    )
    assert "iam:GetRole" in gateway_role
    assert "iam::${AWS::AccountId}:role/*" in gateway_role
    assert "iam::*:role/" not in gateway_role
    assert not re.search(r"Resource:\s+['\"]\*['\"]", gateway_role)

    # AC-06 reads each recording bucket, whose name the customer chose, so the
    # grant covers bucket ARNs and nothing wider.
    recording = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "BrowserRecordingBucketRead"
    )
    for action in (
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicy",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketVersioning",
    ):
        assert action in recording
    assert "Resource: !Sub 'arn:${AWS::Partition}:s3:::*'" in recording
    assert "s3:GetAccountPublicAccessBlock" not in recording
    assert not re.search(r"Resource:\s+['\"]\*['\"]", recording)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_agentcore_round2_reads_wildcard_only_enumerations(template):
    """The round-2 AgentCore reads take '*' only where no resource is named.

    The first group's actions have no resource type in the service
    authorization reference. The second group's actions list every
    resource of their type, so the request names no ARN to match. Both are
    granted on '*' with no condition. Every per-resource read is scoped to
    its resource type.
    """
    unscoped = _unconditioned_wildcard_actions(
        template, "AgentCoreSecurityAssessmentFunction"
    )
    merged = _statement_block(
        template,
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreReadsWithoutResourceType",
    )
    for action in (
        "xray:GetTraceSegmentDestination",
        "logs:DescribeDeliveryDestinations",
        "organizations:DescribeOrganization",
        "oam:ListLinks",
        "s3:GetAccountPublicAccessBlock",
        "events:ListRules",
        "inspector2:ListCoverage",
        "bedrock-agentcore:ListPaymentManagers",
        "bedrock-agentcore:ListHarnesses",
        "bedrock-agentcore:ListBatchEvaluations",
        "bedrock-agentcore:ListAgentRuntimeEndpoints",
        "bedrock-agentcore:ListAgentRuntimeVersions",
        "ec2:DescribeNatGateways",
        "bedrock:GetModelInvocationLoggingConfiguration",
    ):
        assert action in unscoped
    assert re.search(r"Resource:\s+['\"]\*['\"]", merged)

    for action in (
        "network-firewall:ListFirewalls",
        "cloudwatch:ListMetrics",
        "ce:GetAnomalySubscriptions",
    ):
        assert action in unscoped
    assert not any(a.startswith("network-firewall:Describe") for a in unscoped)

    scoped = {
        "NetworkFirewallRead": (
            (
                "network-firewall:DescribeFirewall",
                "network-firewall:DescribeRuleGroup",
            ),
            (
                "network-firewall:*:${AWS::AccountId}:firewall/*",
                "network-firewall:*:*:stateful-rulegroup/*",
            ),
        ),
        # Its own statement, so the policy ARN pairs with no other action.
        "FirewallPolicyRead": (
            ("network-firewall:DescribeFirewallPolicy",),
            ("network-firewall:*:${AWS::AccountId}:firewall-policy/*",),
        ),
        "PrefixListEntryRead": (
            ("ec2:GetManagedPrefixListEntries",),
            ("ec2:*:*:prefix-list/*",),
        ),
        "AgentCoreEvaluationRead": (
            ("bedrock-agentcore:GetEvaluator", "bedrock-agentcore:GetBatchEvaluation"),
            (
                "bedrock-agentcore:*:${AWS::AccountId}:evaluator/*",
                "bedrock-agentcore:*:${AWS::AccountId}:batch-evaluate/*",
            ),
        ),
        # rule/* covers both service reference formats, rule/${RuleName} on the
        # default bus and rule/${EventBusName}/${RuleName} on a custom one.
        "EventRuleTargetRead": (
            ("events:ListTargetsByRule",),
            ("events:*:${AWS::AccountId}:rule/*",),
        ),
        "MetricFilterRead": (
            ("logs:DescribeMetricFilters",),
            ("logs:*:${AWS::AccountId}:log-group:*",),
        ),
        "CostAnomalyMonitorRead": (
            ("ce:GetAnomalyMonitors",),
            ("ce::${AWS::AccountId}:anomalymonitor/*",),
        ),
    }
    for sid, (actions, resources) in scoped.items():
        statement = _statement_block(
            template, "AgentCoreSecurityAssessmentFunction", sid
        )
        for action in actions:
            assert action in statement
        for resource in resources:
            assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)

    firewall = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "NetworkFirewallRead"
    )
    assert "firewall-policy/" not in firewall
    assert "DescribeFirewallPolicy" not in firewall

    # Not approved, so the AgentCore role must not hold it.
    agentcore = _actions(template, "AgentCoreSecurityAssessmentFunction")
    assert "wafv2:GetSampledRequests" not in agentcore


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_aisf_phase5_reads_wildcard_only_where_iam_has_no_resource_type(template):
    """The phase-5 AISF grants take '*' only on actions with no resource type.

    Each wildcard action below names no resource type in the IAM service
    authorization reference. Each scoped action does, and is pinned to this
    account except ListFirewallRules, whose rule group can be shared from
    another account through AWS RAM.
    """
    wildcard = {
        # The Bedrock role folds every unconditioned '*' read into one
        # statement: former Sids MaciePermissions, EC2Permissions,
        # BedrockAccountInventoryPermissions, CloudTrailPermissions,
        # LambdaInventoryPermissions, KMSKeyInventory, BackupVaultInventory,
        # ResourceTagRead and CloudTrailEventHistoryRead.
        ("BedrockSecurityAssessmentFunction", "AccountReadsOnWildcard"): (
            "macie2:ListClassificationJobs",
            "ec2:DescribeSubnets",
            "ec2:DescribeRouteTables",
            "bedrock:ListModelCustomizationJobs",
            "aoss:BatchGetCollection",
            "comprehend:ListPiiEntitiesDetectionJobs",
            "sso:ListInstances",
            "bedrock-agentcore:ListAgentRuntimes",
            "bedrock-agentcore:ListAgentRuntimeEndpoints",
            "cloudtrail:ListEventDataStores",
            "lambda:ListFunctions",
            "inspector2:BatchGetAccountStatus",
            "kms:ListKeys",
            "backup:ListBackupVaults",
            "tag:GetResources",
            "cloudtrail:LookupEvents",
            "inspector2:ListCoverage",
            "events:ListRules",
            "ec2:DescribeInstances",
            "ecs:ListClusters",
            "ecs:ListServices",
            "ecs:DescribeTaskDefinition",
            "sagemaker:ListNotebookInstances",
            "sagemaker:ListEndpoints",
            "sagemaker:ListModels",
            "bedrock-agentcore:ListMemories",
            "bedrock-agentcore:ListGateways",
            "bedrock-agentcore:ListBrowsers",
        ),
        ("SagemakerSecurityAssessmentFunction", "EC2SubnetExposureInventory"): (
            "ec2:DescribeSubnets",
            "ec2:DescribeRouteTables",
        ),
        ("AgentCoreSecurityAssessmentFunction", "AgentCoreReadsWithoutResourceType"): (
            "route53resolver:ListFirewallRuleGroupAssociations",
            "route53resolver:ListFirewallDomainLists",
            "ecr:GetRegistryScanningConfiguration",
        ),
        ("AgentRegistrySecurityAssessmentFunction", "RegistryEventRuleInventory"): (
            "events:ListRules",
        ),
    }
    for (logical_id, sid), actions in wildcard.items():
        statement = _statement_block(template, logical_id, sid)
        unconditioned = _unconditioned_wildcard_actions(template, logical_id)
        for action in actions:
            assert action in statement
            assert action in unconditioned
        assert re.search(r"Resource:\s+['\"]\*['\"]", statement)

    scoped = {
        ("BedrockSecurityAssessmentFunction", "S3BucketEncryptionPermissions"): (
            "s3:GetBucketPolicy",
            "s3:::*",
        ),
        ("BedrockSecurityAssessmentFunction", "KMSPermissions"): (
            "kms:GetKeyPolicy",
            "kms:*:${AWS::AccountId}:key/*",
        ),
        ("BedrockSecurityAssessmentFunction", "LambdaPermissions"): (
            "lambda:GetPolicy",
            "lambda:ListTags",
            "lambda:*:${AWS::AccountId}:function:*",
        ),
        ("BedrockSecurityAssessmentFunction", "BedrockApiKeyInventoryRead"): (
            "iam:ListMFADevices",
            "iam::${AWS::AccountId}:user/*",
        ),
        ("BedrockSecurityAssessmentFunction", "AIRoleTrustPolicyRead"): (
            "iam:GetRole",
            "iam::${AWS::AccountId}:role/*",
        ),
        ("BedrockSecurityAssessmentFunction", "EC2InstanceProfileRoleRead"): (
            "iam:GetInstanceProfile",
            "iam::${AWS::AccountId}:instance-profile/*",
        ),
        ("BedrockSecurityAssessmentFunction", "BedrockInvocationLogInspection"): (
            "logs:DescribeSubscriptionFilters",
            "logs:*:${AWS::AccountId}:log-group:*",
        ),
        ("BedrockSecurityAssessmentFunction", "OrganizationsEffectivePolicyRead"): (
            "organizations:DescribeEffectivePolicy",
            "organizations::*:account/o-*/${AWS::AccountId}",
        ),
        ("BedrockSecurityAssessmentFunction", "ECSServiceRead"): (
            "ecs:DescribeServices",
            "ecs:*:${AWS::AccountId}:service/*",
        ),
        ("BedrockSecurityAssessmentFunction", "SageMakerNotebookRead"): (
            "sagemaker:DescribeNotebookInstance",
            "sagemaker:*:${AWS::AccountId}:notebook-instance/*",
        ),
        ("BedrockSecurityAssessmentFunction", "SSOPermissionSetList"): (
            "sso:ListPermissionSets",
            "sso:::instance/*",
        ),
        ("BedrockAssessmentReadsPolicy", "CloudTrailEventDataStoreRead"): (
            "cloudtrail:GetEventDataStore",
            "cloudtrail:*:${AWS::AccountId}:eventdatastore/*",
        ),
        ("BedrockSecurityAssessmentFunction", "SSOPermissionSetRead"): (
            "sso:GetInlinePolicyForPermissionSet",
            "sso:::permissionSet/*/*",
        ),
        ("AgentCoreSecurityAssessmentFunction", "AgentCoreGatewayWebACLRead"): (
            "wafv2:GetWebACL",
            "wafv2:*:${AWS::AccountId}:regional/webacl/*/*",
        ),
        ("AgentCoreSecurityAssessmentFunction", "DNSFirewallRuleRead"): (
            "route53resolver:ListFirewallRules",
            "route53resolver:*:*:firewall-rule-group/*",
        ),
        ("AgentCoreSecurityAssessmentFunction", "DNSFirewallDomainRead"): (
            "route53resolver:ListFirewallDomains",
            "route53resolver:*:*:firewall-domain-list/*",
        ),
        ("AgentCoreSecurityAssessmentFunction", "DNSFirewallConfigRead"): (
            "route53resolver:GetFirewallConfig",
            "route53resolver:*:${AWS::AccountId}:firewall-config/*",
        ),
        ("AgentRegistrySecurityAssessmentFunction", "RegistryEventRuleTargetRead"): (
            "events:ListTargetsByRule",
            "events:*:${AWS::AccountId}:rule/*",
        ),
        ("AgentCoreSecurityAssessmentFunction", "CognitoUserPoolRead"): (
            "cognito-idp:DescribeUserPoolClient",
            "cognito-idp:*:${AWS::AccountId}:userpool/*",
        ),
    }
    for (logical_id, sid), (*actions, resource) in scoped.items():
        statement = _statement_block(template, logical_id, sid)
        for action in actions:
            assert action in statement
        assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_responsible_ai_bedrock_and_owasp_reads_are_arn_scoped(template):
    inventory = _statement_block(
        template,
        "ResponsibleAIGRCAssessmentFunction",
        "BedrockAccountInventoryPermissions",
    )
    assert re.search(r"Resource:\s+['\"]\*['\"]", inventory)
    # Account-level enumerations with no resource-level authorization support
    # stay on the wildcard inventory statement.
    assert "bedrock:ListGuardrails" in inventory
    assert "bedrock:ListAutomatedReasoningPolicies" in inventory
    for action in (
        "bedrock:GetAgent",
        "bedrock:GetGuardrail",
        "bedrock:GetDataSource",
        "bedrock:ListDataSources",
        "bedrock:ListIngestionJobs",
    ):
        assert action not in inventory

    for sid, resource in {
        "BedrockGuardrailRead": "bedrock:*:${AWS::AccountId}:guardrail/*",
        "BedrockCustomModelTagRead": "bedrock:*:${AWS::AccountId}:custom-model/*",
        "BedrockAgentRead": "bedrock:*:${AWS::AccountId}:agent/*",
        "BedrockKnowledgeBaseDataSourceRead": (
            "bedrock:*:${AWS::AccountId}:knowledge-base/*"
        ),
    }.items():
        statement = _statement_block(
            template, "ResponsibleAIGRCAssessmentFunction", sid
        )
        assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)

    # GetGuardrail stays ARN-scoped; ListGuardrails is a wildcard enumeration.
    owasp = _statement_block(
        template, "OWASPSecurityAssessmentFunction", "OWASPBedrockPermissions"
    )
    assert "bedrock:GetGuardrail" in owasp
    assert "bedrock:*:${AWS::AccountId}:guardrail/*" in owasp
    assert not re.search(r"Resource:\s+['\"]\*['\"]", owasp)

    owasp_list = _statement_block(
        template, "OWASPSecurityAssessmentFunction", "OWASPBedrockGuardrailList"
    )
    assert "bedrock:ListGuardrails" in owasp_list
    assert re.search(r"Resource:\s+['\"]\*['\"]", owasp_list)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_responsible_ai_non_bedrock_resource_reads_are_arn_scoped(template):
    logical_id = "ResponsibleAIGRCAssessmentFunction"
    expected = {
        "WAFWebACLRead": (
            "wafv2:GetWebACL",
            "wafv2:*:${AWS::AccountId}:regional/webacl/*/*",
        ),
        "BudgetRead": (
            "budgets:ViewBudget",
            "budgets::${AWS::AccountId}:budget/*",
        ),
        "LogsDataProtectionPolicyRead": (
            "logs:GetDataProtectionPolicy",
            "logs:*:${AWS::AccountId}:log-group:*",
        ),
        "BedrockAgentCoreRuntimeRead": (
            "bedrock-agentcore:GetAgentRuntime",
            "bedrock-agentcore:*:${AWS::AccountId}:runtime/*",
        ),
        "SageMakerFeatureGroupRead": (
            "sagemaker:DescribeFeatureGroup",
            "sagemaker:*:${AWS::AccountId}:feature-group/*",
        ),
        "SageMakerModelTagRead": (
            "sagemaker:ListTags",
            "sagemaker:*:${AWS::AccountId}:model/*",
        ),
        "LambdaConcurrencyRead": (
            "lambda:GetFunctionConcurrency",
            "lambda:*:${AWS::AccountId}:function:*",
        ),
        "StepFunctionsDefinitionRead": (
            "states:DescribeStateMachine",
            "states:*:${AWS::AccountId}:stateMachine:*",
        ),
        "CloudWatchPermissions": (
            "cloudwatch:DescribeAlarms",
            "cloudwatch:*:${AWS::AccountId}:alarm:*",
        ),
        "ECRPermissions": (
            "ecr:DescribeRepositories",
            "ecr:*:${AWS::AccountId}:repository/*",
        ),
    }
    for sid, (action, resource) in expected.items():
        statement = _statement_block(template, logical_id, sid)
        assert action in statement
        assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)

    api_gateway = _statement_block(template, logical_id, "APIGatewayPermissions")
    for resource in (
        "apigateway:*::/usageplans",
        "apigateway:*::/restapis",
        "apigateway:*::/restapis/*/requestvalidators",
        "apigateway:*::/restapis/*/models",
    ):
        assert resource in api_gateway
    assert not re.search(r"Resource:\s+['\"]\*['\"]", api_gateway)

    organizations = _statement_block(template, logical_id, "OrganizationsPolicyRead")
    assert "organizations:DescribePolicy" in organizations
    assert "organizations::*:policy/*/*/*" in organizations
    assert "organizations::aws:policy/*/*" in organizations
    assert not re.search(r"Resource:\s+['\"]\*['\"]", organizations)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_agentcore_reads_alarms_on_star_so_composites_are_returned(template):
    """DescribeAlarms omits composite alarms under a grant narrower than '*'
    (API_DescribeAlarms), which would fail every alarm actioned only through
    a composite. The '*' grant must be the role's only DescribeAlarms grant."""
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    statements = [
        statement
        for policy in data["Resources"]["AgentCoreSecurityAssessmentFunction"][
            "Properties"
        ]["Policies"]
        if isinstance(policy, dict)
        for statement in policy.get("Statement", [])
    ]
    reading = [
        statement
        for statement in statements
        if "cloudwatch:DescribeAlarms" in (statement.get("Action") or [])
    ]

    assert len(reading) == 1
    assert reading[0]["Sid"] == "AgentCoreReadsWithoutResourceType"
    assert reading[0]["Effect"] == "Allow"
    assert reading[0]["Resource"] == "*"
    assert "Condition" not in reading[0]
    block = _statement_block(
        template,
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreReadsWithoutResourceType",
    )
    assert "API_DescribeAlarms" in block
