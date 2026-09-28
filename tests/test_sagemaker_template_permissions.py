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
