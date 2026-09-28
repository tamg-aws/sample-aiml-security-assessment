import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATHS = [
    REPO_ROOT / "aiml-security-assessment" / "template.yaml",
    REPO_ROOT / "aiml-security-assessment" / "template-multi-account.yaml",
]

# These actions back the SageMaker checks that the assessment Lambda actually runs
# for transform jobs, tuning jobs, compilation jobs, AutoML, and lineage tracking.
REQUIRED_SAGEMAKER_ACTIONS = [
    "sagemaker:ListTransformJobs",
    "sagemaker:DescribeTransformJob",
    "sagemaker:ListHyperParameterTuningJobs",
    "sagemaker:DescribeHyperParameterTuningJob",
    "sagemaker:ListCompilationJobs",
    "sagemaker:DescribeCompilationJob",
    "sagemaker:ListAutoMLJobs",
    "sagemaker:DescribeAutoMLJob",
    "sagemaker:ListExperiments",
    "sagemaker:ListTrials",
    "sagemaker:ListAssociations",
]


def test_sagemaker_lambda_templates_include_required_actions():
    for template_path in TEMPLATE_PATHS:
        template_text = template_path.read_text(encoding="utf-8")
        missing_actions = [
            action
            for action in REQUIRED_SAGEMAKER_ACTIONS
            if action not in template_text
        ]
        assert not missing_actions, (
            f"{template_path.name} is missing SageMaker Lambda permissions: "
            f"{', '.join(missing_actions)}"
        )


# Actions the full-grade SageMaker legs added, each with the resource ARN its
# statement must name. A resource-typed action granted on '*' fails here.
SCOPED_SAGEMAKER_GRANTS = {
    "sagemaker:DescribeEndpointConfig": ":endpoint-config/*'",
    "organizations:ListTargetsForPolicy": ":policy/o-*/service_control_policy/p-*'",
    "organizations:ListParents": ":account/o-*/${AWS::AccountId}'",
    "securityhub:DescribeOrganizationConfiguration": ":hub/default'",
    "securityhub:ListEnabledProductsForImport": ":hub/default'",
    "logs:DescribeMetricFilters": ":log-group:*'",
    "cloudwatch:DescribeAlarms": ":alarm:*'",
    "events:ListTargetsByRule": ":rule/*'",
    "iot:ListPrincipalThings": ":cert/*'",
    "iot:DescribeScheduledAudit": ":scheduledaudit/*'",
    "s3:GetEncryptionConfiguration": ":s3:::*'",
    "s3:GetBucketPolicy": ":s3:::*'",
    "kms:DescribeKey": ":key/*'",
    "sagemaker:DescribeUserProfile": ":user-profile/*/*'",
    "sagemaker:DescribeInferenceComponent": ":inference-component/*'",
    "cloudtrail:GetTrailStatus": ":cloudtrail:*:*:trail/*'",
    "cloudtrail:GetEventSelectors": ":cloudtrail:*:*:trail/*'",
    "config:DescribeConfigurationRecorderStatus": ":configuration-recorder/*/*'",
    "config:DescribeConformancePackCompliance": ":conformance-pack/*/*'",
    "cloudwatch:DescribeAlarmHistory": ":cloudwatch:*:${AWS::AccountId}:alarm:*'",
    "ecr:DescribeRepositories": ":ecr:*:${AWS::AccountId}:repository/*'",
    "ecr:DescribeImageSigningStatus": ":ecr:*:${AWS::AccountId}:repository/*'",
    "elasticfilesystem:DescribeFileSystems": (
        ":elasticfilesystem:*:${AWS::AccountId}:file-system/*'"
    ),
}


def _sagemaker_function_statements(template_text):
    start = re.search(
        r"^  SagemakerSecurityAssessmentFunction:\n", template_text, re.MULTILINE
    )
    rest = template_text[start.end() :]
    match = re.search(r"\n  [A-Za-z0-9]+:\n", rest)
    block = rest[: match.start()] if match else rest
    return block.split("- Sid:")[1:]


def test_new_sagemaker_grants_are_resource_scoped_on_the_sagemaker_function():
    for template_path in TEMPLATE_PATHS:
        statements = _sagemaker_function_statements(
            template_path.read_text(encoding="utf-8")
        )
        for action, resource in SCOPED_SAGEMAKER_GRANTS.items():
            holding = [s for s in statements if re.search(rf"- {action}\b", s)]
            assert len(holding) == 1, f"{template_path.name}: {action} not granted once"
            assert resource in holding[0], f"{template_path.name}: {action} scope"
            assert "Resource: '*'" not in holding[0], f"{template_path.name}: {action}"


# Approved reads with no IAM resource type, each with the statement that holds
# it on '*'.
APPROVED_WILDCARD_SAGEMAKER_GRANTS = {
    "ec2:DescribeVpcEndpoints": "EC2NetworkPostureInventory",
    "ec2:DescribeFlowLogs": "EC2NetworkPostureInventory",
    "ec2:DescribeSecurityGroups": "EC2NetworkPostureInventory",
    "config:DescribeConformancePacks": "ConformancePackInventory",
    "iot:DescribeAccountAuditConfiguration": "IoTDeviceDefenderAuditRead",
    "iot:ListAuditFindings": "IoTDeviceDefenderAuditRead",
    "inspector2:BatchGetAccountStatus": "InspectorAccountStatusRead",
    "lambda:ListFunctions": "LambdaFunctionInventory",
    "cloudtrail:DescribeTrails": "ApprovedInventoryWithoutResourceType",
    "config:ListConfigurationRecorders": "ApprovedInventoryWithoutResourceType",
    "ecs:DescribeTaskDefinition": "ApprovedInventoryWithoutResourceType",
    "ecs:ListClusters": "ApprovedInventoryWithoutResourceType",
    "ecs:ListServices": "ApprovedInventoryWithoutResourceType",
    "events:ListRules": "ApprovedInventoryWithoutResourceType",
    "inspector2:ListCoverage": "ApprovedInventoryWithoutResourceType",
    "iot:ListScheduledAudits": "ApprovedInventoryWithoutResourceType",
    "ram:ListResources": "ApprovedInventoryWithoutResourceType",
    "securityhub:GetConfigurationPolicyAssociation": "ApprovedInventoryWithoutResourceType",
    "ecr:GetSigningConfiguration": "ApprovedInventoryWithoutResourceType",
    "fsx:DescribeFileSystems": "ApprovedInventoryWithoutResourceType",
}

# Reads the SageMaker legs call that are not approved. Each leg reports "not
# read" on AccessDenied, so none may be granted.
UNAPPROVED_SAGEMAKER_READS = [
    "ec2:DescribeVpcs",
    "ec2:DescribeDhcpOptions",
    "sagemaker:ListInferenceComponents",
    "sagemaker:ListUserProfiles",
    "sagemaker:ListMonitoringExecutions",
    "guardduty:ListMembers",
    "organizations:ListAccounts",
    "s3:GetObjectAttributes",
]


def test_approved_wildcard_grants_sit_in_their_named_statement():
    for template_path in TEMPLATE_PATHS:
        statements = _sagemaker_function_statements(
            template_path.read_text(encoding="utf-8")
        )
        for action, sid in APPROVED_WILDCARD_SAGEMAKER_GRANTS.items():
            holding = [s for s in statements if re.search(rf"- {action}\b", s)]
            assert len(holding) == 1, f"{template_path.name}: {action} not granted once"
            assert holding[0].split()[0] == sid, f"{template_path.name}: {action} sid"
            assert "Resource: '*'" in holding[0], f"{template_path.name}: {action}"


def test_unapproved_reads_are_not_granted_to_the_sagemaker_function():
    for template_path in TEMPLATE_PATHS:
        statements = _sagemaker_function_statements(
            template_path.read_text(encoding="utf-8")
        )
        for action in UNAPPROVED_SAGEMAKER_READS:
            assert not [s for s in statements if re.search(rf"- {action}\b", s)], (
                f"{template_path.name}: {action} is granted without approval"
            )
