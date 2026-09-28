import os
import subprocess
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATHS = [
    REPO_ROOT / "aiml-security-assessment" / "template.yaml",
    REPO_ROOT / "aiml-security-assessment" / "template-multi-account.yaml",
]
EXPECTED_ENV_OWNERS = {
    "REQUIRE_BEDROCK_ZERO_DATA_RETENTION": (
        "BedrockSecurityAssessmentFunction",
        "RequireBedrockZeroDataRetention",
    ),
    "REQUIRE_MARKETPLACE_ENDPOINT_CMK": (
        "BedrockSecurityAssessmentFunction",
        "RequireMarketplaceEndpointCMK",
    ),
    "AIML_APPROVED_EXTERNAL_ACCOUNT_IDS": (
        "SagemakerSecurityAssessmentFunction",
        "ApprovedExternalAccountIds",
    ),
    "AIML_APPROVED_ORG_IDS": (
        "SagemakerSecurityAssessmentFunction",
        "ApprovedOrganizationIds",
    ),
    "AGENTCORE_TOKEN_VAULT_ID": (
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreTokenVaultId",
    ),
    "REQUIRE_AGENTCORE_ONLINE_EVALUATION": (
        "AgentCoreSecurityAssessmentFunction",
        "RequireAgentCoreOnlineEvaluation",
    ),
    "REQUIRE_AGENT_REGISTRY_CMK": (
        "AgentRegistrySecurityAssessmentFunction",
        "RequireAgentRegistryCMK",
    ),
}
CLEARABLE_SAM_PARAMETERS = {
    "SAM_TARGET_REGIONS_PARAMETER": "TargetRegions",
    "SAM_APPROVED_EXTERNAL_ACCOUNT_IDS_PARAMETER": "ApprovedExternalAccountIds",
    "SAM_APPROVED_ORGANIZATION_IDS_PARAMETER": "ApprovedOrganizationIds",
}
SYNTHETIC_APPROVED_ACCOUNT_IDS = "111122223333,444455556666"
SYNTHETIC_APPROVED_ORGANIZATION_ID = "o-a1b2c3d4e5"


class CfnLoader(yaml.SafeLoader):
    pass


def _construct_intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"Fn::{tag_suffix}": value}


CfnLoader.add_multi_constructor("!", _construct_intrinsic)


def _load_sam_parameter_script():
    with (REPO_ROOT / "buildspec.yml").open(encoding="utf-8") as buildspec_file:
        buildspec = yaml.safe_load(buildspec_file)

    for command in buildspec["phases"]["build"]["commands"]:
        if "SAM_TARGET_REGIONS_PARAMETER=" in command:
            return command

    raise AssertionError("Could not find the SAM parameter construction block")


def _run_sam_parameter_script(env_overrides):
    parameter_script = _load_sam_parameter_script()
    output_commands = "\n".join(
        f"printf '%s=%s\\n' '{variable}' \"${{{variable}}}\""
        for variable in CLEARABLE_SAM_PARAMETERS
    )
    result = subprocess.run(
        ["bash", "-c", f"{parameter_script}\n{output_commands}"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env_overrides},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )


@pytest.mark.parametrize("template_path", TEMPLATE_PATHS, ids=lambda path: path.name)
def test_optional_policy_baselines_are_wired_to_consuming_lambdas(template_path):
    with template_path.open(encoding="utf-8") as template_file:
        template = yaml.load(template_file, Loader=CfnLoader)  # nosec B506

    resources = template["Resources"]
    for variable, (expected_owner, parameter) in EXPECTED_ENV_OWNERS.items():
        owners = []
        for logical_id, resource in resources.items():
            variables = (
                resource.get("Properties", {})
                .get("Environment", {})
                .get("Variables", {})
            )
            if variable in variables:
                owners.append(logical_id)
                assert variables[variable] == {"Fn::Ref": parameter}

        assert owners == [expected_owner], (
            f"{variable} must be configured only on {expected_owner}; found {owners}"
        )


@pytest.mark.parametrize(
    ("env_overrides", "expected_values"),
    [
        (
            {},
            {
                "TargetRegions": "",
                "ApprovedExternalAccountIds": "",
                "ApprovedOrganizationIds": "",
            },
        ),
        (
            {
                "TARGET_REGIONS": "us-east-1,us-west-2",
                "APPROVED_EXTERNAL_ACCOUNT_IDS": SYNTHETIC_APPROVED_ACCOUNT_IDS,
                "APPROVED_ORGANIZATION_IDS": SYNTHETIC_APPROVED_ORGANIZATION_ID,
            },
            {
                "TargetRegions": "us-east-1,us-west-2",
                "ApprovedExternalAccountIds": SYNTHETIC_APPROVED_ACCOUNT_IDS,
                "ApprovedOrganizationIds": SYNTHETIC_APPROVED_ORGANIZATION_ID,
            },
        ),
    ],
    ids=["empty-values", "non-empty-values"],
)
def test_clearable_sam_parameters_preserve_literal_quotes(
    env_overrides, expected_values
):
    parameters = _run_sam_parameter_script(env_overrides)

    for variable, parameter_name in CLEARABLE_SAM_PARAMETERS.items():
        assert parameters[variable] == (
            f"ParameterKey={parameter_name},ParameterValue="
            f'"{expected_values[parameter_name]}"'
        )


def test_readme_uses_json_for_comma_separated_cloudformation_parameters():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "--parameters file://params.json" in readme
    assert '"ParameterKey": "ApprovedExternalAccountIds"' in readme
    assert '"ParameterValue": "111122223333,444455556666"' in readme
    assert '"ParameterKey": "ApprovedOrganizationIds"' in readme


def test_agent_registry_manual_approval_is_not_an_opt_in_on_any_deploy_path():
    """AR-03 fails automatic approval by default, so no deploy path may carry
    the parameter that once made that failure opt-in."""
    for path in (
        "buildspec.yml",
        "aiml-security-assessment/template.yaml",
        "aiml-security-assessment/template-multi-account.yaml",
        "deployment/aiml-security-single-account.yaml",
        "deployment/2-aiml-security-codebuild.yaml",
        "aiml-security-assessment/functions/security/agent_registry_assessments/app.py",
    ):
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        assert "RequireAgentRegistryManualApproval" not in text, path
        assert "REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL" not in text, path


def test_agent_registry_cmk_baseline_reaches_every_deploy_path():
    buildspec = (REPO_ROOT / "buildspec.yml").read_text(encoding="utf-8")
    parameter_variable = "SAM_REQUIRE_AGENT_REGISTRY_CMK_PARAMETER"

    assert (
        f'{parameter_variable}="ParameterKey=RequireAgentRegistryCMK,'
        'ParameterValue=${REQUIRE_AGENT_REGISTRY_CMK:-false}"' in buildspec
    )
    deploy_commands = [
        line for line in buildspec.splitlines() if "sam deploy --template-file" in line
    ]
    assert len(deploy_commands) == 3
    assert all(f'"${parameter_variable}"' in line for line in deploy_commands)

    for template_name in (
        "deployment/aiml-security-single-account.yaml",
        "deployment/2-aiml-security-codebuild.yaml",
    ):
        template = (REPO_ROOT / template_name).read_text(encoding="utf-8")
        assert "RequireAgentRegistryCMK:" in template
        assert "Name: REQUIRE_AGENT_REGISTRY_CMK" in template
        assert "Value: !Ref RequireAgentRegistryCMK" in template
