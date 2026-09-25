"""
Tests for Amazon Bedrock AgentCore security assessment checks (AC-01 through AC-17).

AgentCore checks differ from Bedrock/SageMaker:
- Return List[Dict] directly (not a dict with 'csv_data' key)
- Use module-level boto3 clients that must be patched at module level
- Use SeverityEnum/StatusEnum values in create_finding calls

Each check is tested for:
- No resources found -> N/A status
- Compliant resources -> Passed status
- Non-compliant resources -> Failed with correct severity
- Exception handling -> returns error finding (list not empty)
- Output schema validity
"""

import ast
import sys
import json
import inspect
import os
import importlib.util
import textwrap
from unittest.mock import patch, MagicMock

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, "aiml-security-assessment/functions/security/agentcore_assessments")
from tests.test_helpers import extract_csv_data, assert_finding_schema

# Load agentcore app module directly to avoid name collisions with other app.py files
_ac_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/agentcore_assessments",
    )
)
if _ac_dir not in sys.path:
    sys.path.insert(0, _ac_dir)

_spec = importlib.util.spec_from_file_location(
    "agentcore_app", os.path.join(_ac_dir, "app.py")
)
agentcore_app = importlib.util.module_from_spec(_spec)
sys.modules["agentcore_app"] = agentcore_app
_spec.loader.exec_module(agentcore_app)


@pytest.mark.parametrize(
    ("caller_identity", "expected_partition"),
    [
        ({"Arn": "arn:aws:sts::123456789012:assumed-role/test/session"}, "aws"),
        (
            {"Arn": "arn:aws-us-gov:sts::123456789012:assumed-role/test/session"},
            "aws-us-gov",
        ),
        ({}, "aws"),
        ({"Arn": ""}, "aws"),
        ({"Arn": None}, "aws"),
        ({"Arn": "not-an-arn"}, "aws"),
    ],
)
def test_caller_identity_partition_handles_incomplete_arns(
    caller_identity, expected_partition
):
    assert (
        agentcore_app._caller_identity_partition(caller_identity) == expected_partition
    )


def test_missing_permissions_cache_raises_instead_of_returning_empty_inventory():
    error = _make_client_error("NoSuchKey", "Cache not found")
    with patch.object(agentcore_app, "s3_client") as mock_s3:
        mock_s3.get_object.side_effect = error
        with pytest.raises(ClientError):
            agentcore_app.get_permissions_cache("execution-123")


# ---------------------------------------------------------------------------
# Helper: patch AgentCore module-level clients
# ---------------------------------------------------------------------------
def _make_client_error(code="ResourceNotFoundException", message="Not found"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "operation")


def test_incomplete_check_findings_preserve_control_ids_without_scored_failures():
    findings = agentcore_app._incomplete_check_findings(
        ["AC-01", "AG-24"],
        "AgentCore Test Check",
        RuntimeError("sensitive implementation detail"),
        "us-east-1",
    )

    assert [finding["Check_ID"] for finding in findings] == ["AC-01", "AG-24"]
    assert {finding["Status"] for finding in findings} == {"N/A"}
    assert {finding["Severity"] for finding in findings} == {"Informational"}
    assert all(finding["Check_ID"] != "AC-00" for finding in findings)
    assert all(
        "sensitive implementation detail" not in finding["Finding_Details"]
        for finding in findings
    )


# ===================================================================
# AC-01: check_agentcore_vpc_configuration
# ===================================================================
class TestAC01VPCConfiguration:
    """AC-01: Check VPC configuration for AgentCore resources."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac01_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-01"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac01_no_runtimes_returns_na(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac01_runtime_public_returns_failed(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1", "agentRuntimeName": "TestRT"}]
        }
        mock_ac.get_agent_runtime.return_value = {
            "networkConfiguration": {"networkMode": "PUBLIC"}
        }
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac01_runtime_vpc_configured_returns_passed(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1", "agentRuntimeName": "TestRT"}]
        }
        mock_ac.get_agent_runtime.return_value = {
            "networkConfiguration": {
                "networkMode": "VPC",
                "subnetIds": ["subnet-123"],
            }
        }
        mock_ec2.describe_subnets.return_value = {
            "Subnets": [{"SubnetId": "subnet-123"}]
        }
        mock_ec2.describe_route_tables.return_value = {
            "RouteTables": [{"Routes": [{"GatewayId": "local"}]}]
        }
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac01_exception_returns_incomplete_na(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = Exception("VPC error")
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac01_schema_valid(self):
        result = agentcore_app.check_agentcore_vpc_configuration()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-02: check_agentcore_full_access_roles
# ===================================================================
class TestAC02FullAccessRoles:
    """AC-02: Check for roles with AgentCore full access."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac02_client_unavailable_returns_na(self, empty_permission_cache):
        result = agentcore_app.check_agentcore_full_access_roles(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-02"

    @patch("agentcore_app.agentcore_client")
    def test_ac02_no_full_access_returns_passed(
        self, mock_ac, permission_cache_compliant
    ):
        result = agentcore_app.check_agentcore_full_access_roles(
            permission_cache_compliant
        )
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Compliant cache has no AgentCore full access

    @patch("agentcore_app.agentcore_client")
    def test_ac02_full_access_returns_failed(
        self, mock_ac, permission_cache_agentcore_full_access
    ):
        result = agentcore_app.check_agentcore_full_access_roles(
            permission_cache_agentcore_full_access
        )
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        has_failed = any(f["Status"] == "Failed" for f in findings)
        assert has_failed

    def test_ac02_detects_wildcard_in_generic_attached_policy_document(self):
        permission_cache = {
            "role_permissions": {
                "AgentCoreOperator": {
                    "attached_policies": [
                        {
                            "name": "AgentCoreOps",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "bedrock-agentcore:*",
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        wildcard_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore IAM Wildcard Permissions"
        )
        assert wildcard_finding["Status"] == "Failed"
        assert "AgentCoreOperator" in wildcard_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "action",
        [
            "bedrock-agentcore:*",
            "bedrock-agentcore:Get*",
            "bedrock-agentcore:*Runtime*",
            "BEDROCK-AGENTCORE:GetAgentRuntim?",
        ],
        ids=["full", "prefix", "embedded", "case-insensitive-question-mark"],
    )
    def test_ac02_detects_agent_platform_wildcard_action_patterns(self, action):
        permission_cache = {
            "role_permissions": {
                "WildcardRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "WildcardPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        wildcard_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore IAM Wildcard Permissions"
        )
        assert wildcard_finding["Status"] == "Failed"
        assert "WildcardRole" in wildcard_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "not_action",
        [
            ["bedrock-agentcore:DeleteAgentRuntime"],
        ],
        ids=["partial-agentcore"],
    )
    def test_ac02_detects_allow_not_action_that_includes_platform_services(
        self, not_action
    ):
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": not_action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        wildcard_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore IAM Wildcard Permissions"
        )
        assert wildcard_finding["Status"] == "Failed"
        assert "AllowExceptRole" in wildcard_finding["Finding_Details"]
        assert "allow-except" in wildcard_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "not_action",
        [
            ["iam:*", "organizations:*"],
            ["s3:DeleteBucket"],
        ],
        ids=["administrator-except-iam", "administrator-except-one-action"],
    )
    def test_ac02_ignores_not_action_that_names_no_platform_namespace(self, not_action):
        """A NotAction naming no platform namespace is an administrator-style
        grant, which AC-02 ignores exactly as it ignores ``Action: "*"``."""
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": not_action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        "not_action",
        [
            ["bedrock-agentcore:*", "bedrock-agentcore:*"],
            ["bedrock-*:*", "bedrock-agentcore:*"],
            "*",
            "*:*",
        ],
        ids=["both-namespaces", "service-pattern", "all-actions", "all-services"],
    )
    def test_ac02_ignores_not_action_that_excludes_all_platform_access(
        self, not_action
    ):
        permission_cache = {
            "role_permissions": {
                "ExcludedPlatformRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "ExcludedPlatformPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": not_action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        ("action", "resource"),
        [
            ("bedrock-agentcore:GetAgentRuntime", "*"),
            ("unrelated-service:Get*", "*"),
            ("bedrock-agentcore-control:*", "*"),
            (
                "bedrock-agentcore:Get*",
                "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-1",
            ),
        ],
        ids=[
            "exact-action",
            "unrelated-service",
            "invalid-iam-prefix",
            "scoped-resource",
        ],
    )
    def test_ac02_ignores_non_risky_or_unrelated_action_patterns(
        self, action, resource
    ):
        permission_cache = {
            "role_permissions": {
                "ScopedRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "ScopedPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": action,
                                    "Resource": resource,
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        "statements",
        [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:*",
                    "Resource": "*",
                },
            ],
        ],
        ids=["administrator-access", "administrator-access-with-platform-deny"],
    )
    def test_ac02_ignores_service_agnostic_wildcard_actions(self, statements):
        permission_cache = {
            "role_permissions": {
                "Administrator": {
                    "attached_policies": [
                        {
                            "name": "AdministratorAccess",
                            "document": {"Statement": statements},
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac02_empty_cache_returns_findings(self, mock_ac, empty_permission_cache):
        result = agentcore_app.check_agentcore_full_access_roles(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    def test_ac02_malformed_policy_document_returns_incomplete_na(self):
        permission_cache = {
            "role_permissions": {
                "MalformedRole": {
                    "attached_policies": [{"document": "{not-json"}],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-02"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client")
    def test_ac02_schema_valid(self, mock_ac, empty_permission_cache):
        result = agentcore_app.check_agentcore_full_access_roles(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    # --- EVAL-01: evaluation administration reached through a wildcard ---

    _EVALUATION_CONFIG_ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:online-evaluation-config/oec-1"

    @staticmethod
    def _evaluation_admin_cache(action, resource, principal_kind="role_permissions"):
        return {
            principal_kind: {
                "EvaluationAdmin": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "EvaluationAdminPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": action,
                                    "Resource": resource,
                                }
                            },
                        }
                    ],
                }
            }
        }

    @pytest.mark.parametrize(
        "action",
        [
            "bedrock-agentcore:*",
            "bedrock-agentcore:Delete*",
            "bedrock-agentcore:*Evaluat*",
            "bedrock-agentcore:DeleteOnlineEvaluationConfi?",
            "bedrock-*:*OnlineEvaluationConfig",
        ],
        ids=["all", "delete-prefix", "embedded", "question-mark", "service-pattern"],
    )
    def test_ac02_reports_a_wildcard_reaching_an_evaluation_write_on_a_scoped_resource(
        self, action
    ):
        # The wildcard leg above only reads statements whose Resource is a bare
        # `*`, so each of these patterns passes AC-02 today while granting every
        # evaluation write on the named configuration.
        permission_cache = self._evaluation_admin_cache(
            action, self._EVALUATION_CONFIG_ARN
        )

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        evaluation_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Evaluation Administration Wildcard"
        )
        assert evaluation_finding["Status"] == "Failed"
        assert evaluation_finding["Severity"] == "High"
        assert "role EvaluationAdmin" in evaluation_finding["Finding_Details"]
        assert action.lower() in evaluation_finding["Finding_Details"]
        assert (
            "bedrock-agentcore:DeleteOnlineEvaluationConfig"
            in evaluation_finding["Resolution"]
        )
        assert_finding_schema(evaluation_finding)

    def test_ac02_reports_an_iam_user_reaching_an_evaluation_write(self):
        permission_cache = self._evaluation_admin_cache(
            "bedrock-agentcore:*",
            self._EVALUATION_CONFIG_ARN,
            principal_kind="user_permissions",
        )

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        evaluation_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Evaluation Administration Wildcard"
        )
        assert "user EvaluationAdmin" in evaluation_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "action",
        [
            "bedrock-agentcore:DeleteOnlineEvaluationConfig",
            "bedrock-agentcore:Get*",
            "bedrock-agentcore:*Runtime*",
            "unrelated-service:*Evaluator",
            "*",
        ],
        ids=[
            "named-write",
            "read-prefix",
            "other-resource-family",
            "other-service",
            "service-agnostic",
        ],
    )
    def test_ac02_ignores_patterns_that_reach_no_evaluation_write(self, action):
        permission_cache = self._evaluation_admin_cache(
            action, self._EVALUATION_CONFIG_ARN
        )

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert [finding["Finding"] for finding in findings] == [
            "AgentCore IAM Full Access Check"
        ]
        assert findings[0]["Status"] == "Passed"

    def test_ac02_reads_a_deny_statement_as_no_grant(self):
        permission_cache = {
            "role_permissions": {
                "EvaluationAdmin": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "EvaluationAdminPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Deny",
                                    "Action": "bedrock-agentcore:*",
                                    "Resource": self._EVALUATION_CONFIG_ARN,
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    def test_ac02_judges_every_principal_not_only_the_first(self):
        permission_cache = {
            "role_permissions": {
                "FirstRole": {"attached_policies": [], "inline_policies": []},
                "SecondRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "EvaluationAdminPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "bedrock-agentcore:*Evaluator",
                                    "Resource": self._EVALUATION_CONFIG_ARN,
                                }
                            },
                        }
                    ],
                },
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        evaluation_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Evaluation Administration Wildcard"
        )
        assert "role SecondRole" in evaluation_finding["Finding_Details"]

    def test_ac02_reads_attached_and_inline_documents_for_the_evaluation_leg(self):
        permission_cache = {
            "role_permissions": {
                "EvaluationAdmin": {
                    "attached_policies": [
                        {
                            "name": "AttachedPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "bedrock-agentcore:Create*",
                                    "Resource": self._EVALUATION_CONFIG_ARN,
                                }
                            },
                        }
                    ],
                    "inline_policies": [
                        {
                            "name": "InlinePolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "bedrock-agentcore:Delete*",
                                    "Resource": self._EVALUATION_CONFIG_ARN,
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        evaluation_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Evaluation Administration Wildcard"
        )
        assert "bedrock-agentcore:create*" in evaluation_finding["Finding_Details"]
        assert "bedrock-agentcore:delete*" in evaluation_finding["Finding_Details"]

    def test_ac02_user_documents_alone_are_still_assessed(self):
        # The early return reads both dicts, so a cache holding only users is
        # assessed rather than reported as an empty cache.
        permission_cache = {
            "role_permissions": {},
            "user_permissions": {
                "EvaluationAdmin": {"attached_policies": [], "inline_policies": []}
            },
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    def test_the_evaluation_admin_actions_are_the_modelled_writes(self):
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        modelled = {
            operation
            for operation in model.operation_names
            if operation.startswith(("Create", "Update", "Delete"))
            and ("Evaluator" in operation or "OnlineEvaluationConfig" in operation)
        }
        assert {
            action.split(":", 1)[1]
            for action in agentcore_app.EVALUATION_ADMINISTRATION_ACTIONS
        } == modelled
        # The service segment carries the scope the check no longer matches
        # separately, so it has to be the agent platform's own namespace.
        assert {
            action.split(":", 1)[0]
            for action in agentcore_app.EVALUATION_ADMINISTRATION_ACTIONS
        } <= agentcore_app.AGENT_PLATFORM_IAM_NAMESPACES


# ===================================================================
# AC-03: check_stale_agentcore_access
# ===================================================================
def _agent_platform_policy(name, action):
    return {
        "name": name,
        "arn": f"arn:aws:iam::123456789012:policy/{name}",
        "document": {
            "Statement": {
                "Effect": "Allow",
                "Action": action,
                "Resource": "*",
            }
        },
    }


class TestAC03StaleAccess:
    """AC-03: Check stale AgentCore access."""

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac03_client_unavailable_returns_na(
        self, mock_boto_client, empty_permission_cache
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        result = agentcore_app.check_stale_agentcore_access(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-03"

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac03_empty_cache_returns_findings(
        self, mock_ac, mock_iam, mock_boto_client, empty_permission_cache
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        result = agentcore_app.check_stale_agentcore_access(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac03_schema_valid(
        self, mock_ac, mock_iam, mock_boto_client, empty_permission_cache
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        result = agentcore_app.check_stale_agentcore_access(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @pytest.mark.parametrize(
        ("principal_key", "principal_name"),
        [("role_permissions", "AgentCoreRole"), ("user_permissions", "AgentCoreUser")],
        ids=["role", "user"],
    )
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_recognizes_generic_attached_policy_documents(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        principal_key,
        principal_name,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                }
            ],
        }
        permission_cache = {
            "role_permissions": {},
            "user_permissions": {},
        }
        permission_cache[principal_key][principal_name] = {
            "attached_policies": [
                {
                    "name": "AgentCoreOps",
                    "document": {
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "bedrock-agentcore:ListAgentRuntimes",
                            "Resource": "*",
                        }
                    },
                }
            ],
            "inline_policies": [],
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"
        mock_iam.generate_service_last_accessed_details.assert_called_once()

    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_includes_allow_not_action_principal(
        self, mock_iam, mock_boto_client, mock_sleep
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                }
            ],
        }
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": ["bedrock-agentcore:StopAgentRuntime"],
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"
        mock_iam.generate_service_last_accessed_details.assert_called_once()

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_ignores_not_action_that_names_no_platform_namespace(
        self, mock_iam, mock_boto_client
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": ["iam:*", "organizations:*"],
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_ignores_not_action_excluding_both_platform_namespaces(
        self, mock_iam, mock_boto_client
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "ExcludedPlatformRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "ExcludedPlatformPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": [
                                        "bedrock-agentcore:*",
                                        "bedrock-agentcore:*",
                                    ],
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_ignores_service_agnostic_wildcard_actions(
        self, mock_iam, mock_boto_client
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "Administrator": {
                    "attached_policies": [
                        {
                            "name": "AdministratorAccess",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "No IAM principals with AgentCore permissions found"
        )
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @pytest.mark.parametrize(
        ("policy_name", "statement"),
        [
            (
                "DenyAgentCoreAccess",
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:*",
                    "Resource": "*",
                },
            ),
            (
                "AgentCoreDocumentationOnly",
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-docs/*",
                },
            ),
        ],
        ids=["deny-only", "misleading-name"],
    )
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_attached_policy_names_do_not_imply_access(
        self, mock_iam, mock_boto_client, policy_name, statement
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "NoAgentPlatformAccess": {
                    "attached_policies": [
                        {
                            "name": policy_name,
                            "arn": (f"arn:aws:iam::123456789012:policy/{policy_name}"),
                            "document": {"Statement": statement},
                        }
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "No IAM principals with AgentCore permissions found"
        )
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @patch("agentcore_app.check_timeout", return_value=False)
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_timeout_before_first_principal_returns_incomplete_na(
        self, mock_iam, mock_boto_client, mock_check_timeout
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
                "AgentCoreReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "2 IAM principal(s)" in findings[0]["Finding_Details"]
        mock_iam.generate_service_last_accessed_details.assert_not_called()
        mock_check_timeout.assert_called_once()

    @patch("agentcore_app.check_timeout", side_effect=[True, True, False])
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_timeout_during_polling_stops_before_next_principal(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        mock_check_timeout,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
                "AgentCoreReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "2 IAM principal(s)" in findings[0]["Finding_Details"]
        mock_iam.generate_service_last_accessed_details.assert_called_once()
        mock_iam.get_service_last_accessed_details.assert_not_called()
        mock_sleep.assert_called_once_with(2)
        assert mock_check_timeout.call_count == 3

    @patch(
        "agentcore_app.check_timeout",
        side_effect=[True, True, True, False],
    )
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_timeout_preserves_completed_principal_findings(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        mock_check_timeout,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": "2020-01-01T00:00:00+00:00",
                }
            ],
        }
        permission_cache = {
            "role_permissions": {
                "StaleRuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
                "AgentCoreReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert {finding["Status"] for finding in findings} == {"Failed", "N/A"}
        stale_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Stale Access"
        )
        incomplete_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Stale Access Check Incomplete"
        )
        assert "StaleRuntimeReader" in stale_finding["Finding_Details"]
        assert "1 IAM principal(s)" in incomplete_finding["Finding_Details"]
        assert incomplete_finding["Severity"] == "Informational"
        mock_iam.generate_service_last_accessed_details.assert_called_once()
        mock_iam.get_service_last_accessed_details.assert_called_once_with(
            JobId="job-1"
        )
        mock_sleep.assert_called_once_with(2)
        assert mock_check_timeout.call_count == 4

    @patch("agentcore_app.check_timeout", return_value=True)
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_iam_job_timeout_is_informational_na(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        mock_check_timeout,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "IN_PROGRESS"
        }
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "IAM job timed out after 30s" in findings[0]["Finding_Details"]
        assert mock_iam.get_service_last_accessed_details.call_count == 15
        assert mock_sleep.call_count == 15
        assert mock_check_timeout.call_count == 31

    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_uses_most_recent_matching_service_access(
        self, mock_iam, mock_boto_client, mock_sleep
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": "2020-01-01T00:00:00+00:00",
                },
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                },
            ],
        }
        permission_cache = {
            "role_permissions": {
                "AgentPlatformReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_access_denied_returns_incomplete_na(self, mock_iam, mock_boto_client):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.side_effect = (
            _make_client_error("AccessDenied", "Denied")
        )
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-03"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"


# ===================================================================
# AC-04: check_agentcore_observability
# ===================================================================
class TestAC04Observability:
    """AC-04: Check AgentCore observability (logging/tracing)."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac04_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_observability()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-04"

    @patch("agentcore_app.cloudwatch_client")
    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac04_no_runtimes_returns_na(self, mock_ac, mock_logs, mock_cw):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_observability()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac04_exception_returns_incomplete_na(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = Exception("Observability error")
        result = agentcore_app.check_agentcore_observability()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac04_schema_valid(self):
        result = agentcore_app.check_agentcore_observability()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-05: check_agentcore_encryption
# ===================================================================
class TestAC05Encryption:
    """AC-05: Check AgentCore ECR encryption."""

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac05_client_unavailable_returns_na(self, mock_ecr):
        mock_ecr.describe_repositories.return_value = {"repositories": []}
        result = agentcore_app.check_agentcore_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-05"

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac05_no_runtimes_returns_na(self, mock_ac, mock_ecr):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac05_exception_returns_incomplete_na(self, mock_ac, mock_ecr):
        # Raise on the ECR call which is the first thing the check does
        mock_ecr.describe_repositories.side_effect = Exception("Encryption error")
        result = agentcore_app.check_agentcore_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac05_schema_valid(self, mock_ecr):
        mock_ecr.describe_repositories.return_value = {"repositories": []}
        result = agentcore_app.check_agentcore_encryption()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-06: check_browser_tool_recording
# ===================================================================
class TestAC06BrowserToolRecording:
    """AC-06: Check custom browser session recording."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac06_client_unavailable_returns_na(self):
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-06"

    @patch("agentcore_app.agentcore_client")
    def test_ac06_no_custom_browsers_returns_na(self, mock_ac):
        mock_ac.list_browsers.return_value = {"browserSummaries": []}

        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-06"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == "No custom AgentCore browsers found"
        mock_ac.list_browsers.assert_called_once_with(type="CUSTOM")

    @patch("agentcore_app.agentcore_client")
    def test_ac06_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_browsers.side_effect = Exception("Browser tool error")
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac06_schema_valid(self):
        result = agentcore_app.check_browser_tool_recording()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    def test_ac06_all_paths_use_consistent_name_and_reference(self):
        findings = []

        with patch("agentcore_app.agentcore_client", None):
            findings.extend(agentcore_app.check_browser_tool_recording())

        inventories = [
            {
                "items": [],
                "errors": [],
                "list_error": RuntimeError("list failed"),
            },
            {"items": [], "errors": [], "list_error": None},
            {
                "items": [
                    {
                        "summary": {"browserId": "br-1", "name": "browser-1"},
                        "detail": {
                            "recording": {
                                "enabled": True,
                                "s3Location": {"bucket": "recordings"},
                            }
                        },
                    }
                ],
                "errors": [],
                "list_error": None,
            },
            {
                "items": [],
                "errors": [
                    {
                        "summary": {"browserId": "br-2", "name": "browser-2"},
                        "error": RuntimeError("detail failed"),
                    }
                ],
                "list_error": None,
            },
        ]
        with patch("agentcore_app.agentcore_client", MagicMock()):
            for inventory in inventories:
                findings.extend(agentcore_app.check_browser_tool_recording(inventory))

            broken_inventory = MagicMock()
            broken_inventory.get.side_effect = RuntimeError("inventory failed")
            findings.extend(
                agentcore_app.check_browser_tool_recording(broken_inventory)
            )

        assert findings
        assert {finding["Finding"] for finding in findings} == {
            "AgentCore Browser Session Recording"
        }
        assert {finding["Reference"] for finding in findings} == {
            agentcore_app.AGENTCORE_SECURITY_HUB_REFERENCE_URL
        }


# ===================================================================
# AC-07: check_agentcore_memory_configuration
# ===================================================================
class TestAC07MemoryConfiguration:
    """AC-07: Check memory resource encryption."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac07_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-07"

    @patch("agentcore_app.agentcore_client")
    def test_ac07_no_memories_returns_na(self, mock_ac):
        mock_ac.list_memories.return_value = {"memories": []}
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac07_memory_with_wrapped_kms_key_returns_passed(self, mock_ac):
        mock_ac.list_memories.return_value = {
            "memories": [{"id": "mem-123456789012", "name": "TestMemory"}]
        }
        mock_ac.get_memory.return_value = {
            "memory": {
                "id": "mem-123456789012",
                "encryptionKeyArn": "arn:aws:kms:us-east-1:123:key/abc",
            }
        }
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac07_exception_returns_incomplete_na(self, mock_ac):
        mock_ac.list_memories.side_effect = Exception("Memory error")
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac07_schema_valid(self):
        result = agentcore_app.check_agentcore_memory_configuration()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    # --- AC-07 namespace partitioning leg (AIR-ACR-MEM-01) ---

    _ACTOR_NAMESPACE = (
        "/strategies/{memoryStrategyId}/actors/{actorId}/sessions/{sessionId}"
    )

    @staticmethod
    def _memory_detail(**overrides):
        detail = {
            "id": "mem-123456789012",
            "encryptionKeyArn": "arn:aws:kms:us-east-1:123:key/abc",
            "strategies": [
                {
                    "strategyId": "strat-1",
                    "name": "summary",
                    "namespaceTemplates": [
                        TestAC07MemoryConfiguration._ACTOR_NAMESPACE
                    ],
                }
            ],
        }
        detail.update(overrides)
        return detail

    @classmethod
    def _one_memory(cls, mock_ac, **overrides):
        mock_ac.list_memories.return_value = {
            "memories": [{"id": "mem-123456789012", "name": "TestMemory"}]
        }
        mock_ac.get_memory.return_value = {"memory": cls._memory_detail(**overrides)}

    @patch("agentcore_app.agentcore_client")
    def test_ac07_actor_scoped_namespace_passes(self, mock_ac):
        self._one_memory(mock_ac)

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["Passed", "Passed"]
        assert findings[1]["Finding"] == "AgentCore Memory Access Scope"
        for finding in findings:
            assert_finding_schema(finding)

    @patch("agentcore_app.agentcore_client")
    def test_ac07_namespace_without_an_actor_variable_fails(self, mock_ac):
        self._one_memory(
            mock_ac,
            strategies=[
                {
                    "strategyId": "strat-1",
                    "name": "summary",
                    "namespaceTemplates": ["/"],
                }
            ],
        )

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["Passed", "Failed"]
        assert findings[1]["Severity"] == "High"
        assert "summary" in findings[1]["Finding_Details"]
        assert "{actorId}" in findings[1]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_ac07_legacy_namespaces_member_is_read(self, mock_ac):
        # A strategy created before namespaceTemplates existed reports only
        # namespaces, so reading one member alone would judge the wrong field.
        self._one_memory(
            mock_ac,
            strategies=[
                {
                    "strategyId": "strat-1",
                    "name": "summary",
                    "namespaces": [self._ACTOR_NAMESPACE],
                }
            ],
        )

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["Passed", "Passed"]

    @patch("agentcore_app.agentcore_client")
    def test_ac07_a_flat_legacy_namespace_beside_a_scoped_template_fails(self, mock_ac):
        # Both members are read because either list can name a namespace the
        # other does not, and records land in whichever one the strategy uses.
        self._one_memory(
            mock_ac,
            strategies=[
                {
                    "strategyId": "strat-1",
                    "name": "summary",
                    "namespaceTemplates": [self._ACTOR_NAMESPACE],
                    "namespaces": ["/"],
                }
            ],
        )

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_ac07_memory_without_a_strategy_is_na(self, mock_ac):
        self._one_memory(mock_ac, strategies=[])

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["Passed", "N/A"]
        assert "no memory strategy" in findings[1]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac07_strategy_without_a_namespace_is_na(self, mock_ac):
        self._one_memory(
            mock_ac, strategies=[{"strategyId": "strat-1", "name": "summary"}]
        )

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["Passed", "N/A"]
        assert "reports no namespace" in findings[1]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac07_malformed_strategies_value_is_na(self, mock_ac):
        self._one_memory(mock_ac, strategies={"unexpected": "shape"})

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["Passed", "N/A"]

    @patch("agentcore_app.agentcore_client")
    def test_ac07_missing_key_and_flat_namespace_fail_independently(self, mock_ac):
        self._one_memory(
            mock_ac,
            encryptionKeyArn=None,
            strategies=[
                {
                    "strategyId": "strat-1",
                    "name": "summary",
                    "namespaceTemplates": ["/"],
                }
            ],
        )

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["Failed", "Failed"]
        assert [f["Finding"] for f in findings] == [
            "AgentCore Memory Encryption",
            "AgentCore Memory Access Scope",
        ]

    @patch("agentcore_app.agentcore_client")
    def test_ac07_emits_one_verdict_pair_per_memory(self, mock_ac):
        # The aggregate "all memories are fine" row is gone: two memories mean
        # two encryption verdicts and two access-scope verdicts.
        mock_ac.list_memories.return_value = {
            "memories": [
                {"id": "mem-1", "name": "First"},
                {"id": "mem-2", "name": "Second"},
            ]
        }
        mock_ac.get_memory.return_value = {"memory": self._memory_detail()}

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert len(findings) == 4
        names = [f["Finding"] for f in findings]
        assert names.count("AgentCore Memory Encryption") == 2
        assert names.count("AgentCore Memory Access Scope") == 2

    @patch("agentcore_app.agentcore_client")
    def test_ac07_unreadable_memory_does_not_hide_a_readable_one(self, mock_ac):
        # An earlier revision swallowed this error and emitted the aggregate
        # pass, so a run that could read nothing looked identical to a clean one.
        mock_ac.list_memories.return_value = {
            "memories": [
                {"id": "mem-1", "name": "Gone"},
                {"id": "mem-2", "name": "Readable"},
            ]
        }
        mock_ac.get_memory.side_effect = [
            _make_client_error("ResourceNotFoundException", "gone"),
            {"memory": self._memory_detail()},
        ]

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["N/A", "Passed", "Passed"]
        assert "ResourceNotFoundException" in findings[0]["Finding_Details"]
        assert "'Gone' (mem-1)" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac07_access_denied_on_every_memory_never_reads_as_clean(self, mock_ac):
        mock_ac.list_memories.return_value = {"memories": [{"id": "mem-1"}]}
        mock_ac.get_memory.side_effect = _make_client_error(
            "AccessDeniedException", "no"
        )

        findings = extract_csv_data(
            agentcore_app.check_agentcore_memory_configuration()
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "bedrock-agentcore:GetMemory" in findings[0]["Resolution"]

    def test_memory_namespace_is_a_customer_supplied_input(self):
        # The Failed verdict is only reachable because the namespace is an
        # optional CreateMemory input: if the service required an actor-scoped
        # template, the check could never discriminate.
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        strategy_input = (
            model.operation_model("CreateMemory")
            .input_shape.members["memoryStrategies"]
            .member
        )
        assert strategy_input.members
        for wrapper in strategy_input.members.values():
            assert "namespaceTemplates" in wrapper.members
            assert "namespaces" in wrapper.members
            assert set(wrapper.metadata.get("required") or []) == {"name"}


# ===================================================================
# AC-08: check_agentcore_vpc_endpoints
# ===================================================================
class TestAC08VPCEndpoints:
    """AC-08: Check VPC endpoints for AgentCore."""

    @patch("agentcore_app.agentcore_client")
    def test_agentcore_list_all_stops_on_repeated_token(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "runtime-1"}],
            "nextToken": "repeated",
        }

        runtimes = agentcore_app._agentcore_list_all(
            "list_agent_runtimes", ["agentRuntimes"]
        )

        assert runtimes == [
            {"agentRuntimeId": "runtime-1"},
            {"agentRuntimeId": "runtime-1"},
        ]
        assert mock_ac.list_agent_runtimes.call_count == 2

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac08_client_unavailable_returns_na(self, mock_ec2):
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}
        result = agentcore_app.check_agentcore_vpc_endpoints()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-08"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac08_no_runtimes_returns_na(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_vpc_endpoints()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == "No AgentCore resources found"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac08_reads_runtimes_from_all_pages(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.side_effect = [
            {"agentRuntimes": [], "nextToken": "runtime-page-2"},
            {
                "agentRuntimes": [
                    {
                        "agentRuntimeId": "runtime-2",
                        "agentRuntimeName": "SecondPageRuntime",
                    }
                ]
            },
        ]
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}

        findings = extract_csv_data(agentcore_app.check_agentcore_vpc_endpoints())

        assert findings[0]["Finding_Details"] == "No VPCs found in the account"
        assert mock_ac.list_agent_runtimes.call_count == 2
        mock_ac.list_agent_runtimes.assert_any_call(nextToken="runtime-page-2")

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac08_exception_returns_incomplete_na(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "runtime-1",
                    "agentRuntimeName": "TestRuntime",
                }
            ]
        }
        mock_ec2.describe_vpcs.side_effect = Exception("VPC endpoint error")
        result = agentcore_app.check_agentcore_vpc_endpoints()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac08_schema_valid(self, mock_ec2):
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}
        result = agentcore_app.check_agentcore_vpc_endpoints()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-09: check_agentcore_service_linked_role
# ===================================================================
class TestAC09ServiceLinkedRole:
    """AC-09: Check AgentCore service-linked role."""

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac09_client_unavailable_returns_na(self, mock_iam):
        mock_iam.get_role.side_effect = _make_client_error(
            "NoSuchEntity", "Role not found"
        )
        mock_iam.exceptions.NoSuchEntityException = ClientError
        result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-09"

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac09_slr_exists_returns_passed(self, mock_ac, mock_iam):
        mock_iam.get_role.return_value = {
            "Role": {
                "RoleName": "AWSServiceRoleForBedrockAgentCoreNetwork",
                "Arn": "arn:aws:iam::123:role/aws-service-role/network.bedrock-agentcore.amazonaws.com/AWSServiceRoleForBedrockAgentCoreNetwork",
                "Path": "/aws-service-role/network.bedrock-agentcore.amazonaws.com/",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "network.bedrock-agentcore.amazonaws.com"
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            }
        }
        result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac09_slr_missing_returns_failed(self, mock_ac, mock_iam):
        mock_iam.get_role.side_effect = _make_client_error(
            "NoSuchEntity", "Role not found"
        )
        mock_iam.exceptions.NoSuchEntityException = ClientError
        result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert "iam:CreateServiceLinkedRole" in findings[0]["Resolution"]
        assert (
            "iam:AWSServiceName = network.bedrock-agentcore.amazonaws.com"
            in findings[0]["Resolution"]
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac09_exception_returns_incomplete_na(self, mock_ac):
        # Patch iam_client to raise
        with patch("agentcore_app.iam_client") as mock_iam:
            mock_iam.get_role.side_effect = Exception("IAM error")
            result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac09_schema_valid(self, mock_iam):
        mock_iam.get_role.side_effect = _make_client_error(
            "NoSuchEntity", "Role not found"
        )
        mock_iam.exceptions.NoSuchEntityException = ClientError
        result = agentcore_app.check_agentcore_service_linked_role()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-10: check_agentcore_resource_based_policies
# ===================================================================
class TestAC10ResourceBasedPolicies:
    """AC-10: Check resource-based policies."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac10_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-10"

    @patch("agentcore_app.agentcore_client")
    def test_ac10_no_runtimes_returns_na(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        mock_ac.list_gateways.return_value = {"items": []}
        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac10_uses_generic_resource_policy_api(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "rt-1",
                    "agentRuntimeName": "TestRuntime",
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1",
                }
            ]
        }
        mock_ac.list_gateways.return_value = {"items": []}
        mock_ac.get_resource_policy.return_value = {
            "policy": '{"Version":"2012-10-17"}'
        }

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_ac.get_resource_policy.assert_called_once_with(
            resourceArn="arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1"
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_gets_gateway_by_gateway_identifier(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1"
        }
        mock_ac.get_resource_policy.return_value = {
            "policy": '{"Version":"2012-10-17"}'
        }

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_ac.get_gateway.assert_called_once_with(gatewayIdentifier="gw-1")
        mock_ac.get_resource_policy.assert_called_once_with(
            resourceArn="arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1"
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_access_denied_policy_read_returns_na_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "rt-1",
                    "agentRuntimeName": "TestRuntime",
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1",
                }
            ]
        }
        mock_ac.list_gateways.return_value = {"items": []}
        mock_ac.get_resource_policy.side_effect = _make_client_error(
            "AccessDeniedException", "Denied"
        )

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert any(
            f["Finding"] == "AgentCore Resource-Based Policy Assessment Access Denied"
            and f["Status"] == "N/A"
            for f in findings
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_policy_read_throttling_returns_incomplete_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "rt-1",
                    "agentRuntimeName": "TestRuntime",
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1",
                }
            ]
        }
        mock_ac.list_gateways.return_value = {"items": []}
        mock_ac.get_resource_policy.side_effect = _make_client_error(
            "ThrottlingException", "Try again"
        )

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert any(
            f["Finding"] == "AgentCore Resource-Based Policy Assessment Incomplete"
            and f["Status"] == "N/A"
            for f in findings
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_exception_returns_incomplete_na(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = Exception("RBP error")
        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac10_schema_valid(self):
        result = agentcore_app.check_agentcore_resource_based_policies()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-11: check_agentcore_policy_engine_encryption
# ===================================================================
class TestAC11PolicyEngineEncryption:
    """AC-11: Check policy engine encryption."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac11_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-11"

    @patch("agentcore_app.agentcore_client")
    def test_ac11_no_policy_engines_returns_na(self, mock_ac):
        mock_ac.list_policy_engines.return_value = {"policyEngines": []}
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac11_missing_cmk_lists_required_kms_permissions(self, mock_ac):
        mock_ac.list_policy_engines.return_value = {
            "policyEngines": [{"policyEngineId": "pe-1", "name": "PolicyEngine"}]
        }
        mock_ac.get_policy_engine.return_value = {
            "policyEngineId": "pe-1",
            "name": "PolicyEngine",
        }

        findings = extract_csv_data(
            agentcore_app.check_agentcore_policy_engine_encryption()
        )
        failed = next(finding for finding in findings if finding["Status"] == "Failed")

        for action in (
            "kms:CreateGrant",
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "kms:DescribeKey",
        ):
            assert action in failed["Resolution"]
        assert "kms:ViaService" in failed["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_ac11_exception_returns_incomplete_na(self, mock_ac):
        mock_ac.list_policy_engines.side_effect = Exception("Policy engine error")
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac11_schema_valid(self):
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-12: check_agentcore_gateway_encryption
# ===================================================================
class TestAC12GatewayEncryption:
    """AC-12: Check gateway encryption."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac12_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-12"

    @patch("agentcore_app.agentcore_client")
    def test_ac12_no_gateways_returns_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac12_gateway_with_kms_key_returns_passed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "kmsKeyArn": "arn:aws:kms:us-east-1:123:key/abc",
        }
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_ac.get_gateway.assert_called_once_with(gatewayIdentifier="gw-1")

    @patch("agentcore_app.agentcore_client")
    def test_ac12_exception_returns_incomplete_na(self, mock_ac):
        mock_ac.list_gateways.side_effect = Exception("Gateway encryption error")
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac12_schema_valid(self):
        result = agentcore_app.check_agentcore_gateway_encryption()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-13: check_agentcore_gateway_configuration
# ===================================================================
class TestAC13GatewayConfiguration:
    """AC-13: Check gateway configuration."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac13_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-13"

    @patch("agentcore_app.agentcore_client")
    def test_ac13_no_gateways_returns_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac13_items_gateway_shape_returns_passed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac13_exception_returns_incomplete_na(self, mock_ac):
        mock_ac.list_gateways.side_effect = Exception("Gateway config error")
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac13_schema_valid(self):
        result = agentcore_app.check_agentcore_gateway_configuration()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AG-24..AG-27: check_agentcore_gateway_agentic_security
# ===================================================================
class TestAgenticGatewaySecurity:
    """Agentic AI Gateway security checks."""

    @patch("agentcore_app.agentcore_client")
    def test_gateway_policy_controls_fail_when_not_enforced(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "NONE",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "LOG_ONLY",
            },
            "exceptionLevel": "DEBUG",
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        statuses = {f["Check_ID"]: f["Status"] for f in findings}

        assert statuses["AG-24"] == "Failed"
        assert statuses["AG-25"] == "Failed"
        assert statuses["AG-26"] == "Failed"
        assert statuses["AG-27"] == "Failed"
        for finding in findings:
            assert_finding_schema(finding)

    @patch("agentcore_app.agentcore_client")
    def test_gateway_authorizer_unspecified_fails_closed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "ENFORCE",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag24 = [f for f in findings if f["Check_ID"] == "AG-24"]

        assert ag24
        assert ag24[0]["Status"] == "Failed"
        assert "unspecified" in ag24[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_gateway_authenticate_only_without_enforced_policy_fails_closed(
        self, mock_ac
    ):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "AUTHENTICATE_ONLY",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "LOG_ONLY",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag24 = [f for f in findings if f["Check_ID"] == "AG-24"]

        assert ag24
        assert ag24[0]["Status"] == "Failed"
        assert "AUTHENTICATE_ONLY" in ag24[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_gateway_authenticate_only_with_enforced_policy_passes(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "AUTHENTICATE_ONLY",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "ENFORCE",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag24 = [f for f in findings if f["Check_ID"] == "AG-24"]

        assert ag24
        assert ag24[0]["Status"] == "Passed"
        assert "policy engine" in ag24[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_gateway_detail_access_denied_returns_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.side_effect = _make_client_error(
            "AccessDeniedException", "Denied"
        )

        findings = agentcore_app.check_agentcore_gateway_agentic_security()

        assert {finding["Check_ID"] for finding in findings} == {
            "AG-24",
            "AG-25",
            "AG-26",
            "AG-27",
        }
        assert all(finding["Status"] == "N/A" for finding in findings)
        assert all(finding["Severity"] == "Informational" for finding in findings)
        for finding in findings:
            assert_finding_schema(finding)

    @patch("agentcore_app.agentcore_client")
    def test_gateway_list_sdk_error_returns_all_controls_incomplete(self, mock_ac):
        mock_ac.list_gateways.side_effect = _make_client_error(
            "ThrottlingException", "Throttled"
        )

        findings = agentcore_app.check_agentcore_gateway_agentic_security()

        assert {finding["Check_ID"] for finding in findings} == {
            "AG-24",
            "AG-25",
            "AG-26",
            "AG-27",
        }
        assert all(finding["Status"] == "N/A" for finding in findings)
        assert all(finding["Severity"] == "Informational" for finding in findings)

    @patch("agentcore_app.agentcore_client")
    def test_gateway_policy_controls_pass_when_enforced(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "AWS_IAM",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "ENFORCE",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        statuses = {f["Check_ID"]: f["Status"] for f in findings}

        assert statuses["AG-24"] == "Passed"
        assert statuses["AG-25"] == "Passed"
        assert statuses["AG-26"] == "Passed"
        assert statuses["AG-27"] == "Passed"


class TestAgenticAgentCoreMapping:
    """Agentic AI AG-* rows are generated from API-backed AgentCore checks."""

    EXPECTED_AGENTIC_MAPPINGS = {
        "AC-01": "AG-15",
        "AC-02": "AG-16",
        "AC-03": "AG-17",
        "AC-04": "AG-18",
        "AC-07": "AG-19",
        "AC-08": "AG-20",
        "AC-10": "AG-21",
        "AC-11": "AG-22",
        "AC-12": "AG-23",
        "AC-14": "AG-28",
        "AC-15": "AG-29",
        "AC-16": "AG-31",
        "AC-17": "AG-32",
    }

    def test_all_agentcore_agentic_mappings_emit_expected_rows(self):
        source_findings = []
        for source_check_id in self.EXPECTED_AGENTIC_MAPPINGS:
            source_findings.append(
                {
                    "Account_ID": "123456789012",
                    "Check_ID": source_check_id,
                    "Finding": f"{source_check_id} source finding",
                    "Finding_Details": f"{source_check_id} source details",
                    "Resolution": "No action required.",
                    "Reference": "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security.html",
                    "Severity": "Medium",
                    "Status": "Passed",
                    "Region": "us-east-1",
                }
            )

        findings = agentcore_app.build_agentic_agentcore_security_findings(
            source_findings
        )

        assert len(findings) == len(self.EXPECTED_AGENTIC_MAPPINGS)
        actual_by_source = {}
        for finding in findings:
            details = finding["Finding_Details"]
            source_check_id = details.split("Source check ", 1)[1].split(":", 1)[0]
            actual_by_source[source_check_id] = finding

            assert finding["Status"] == "Passed"
            assert finding["Severity"] == "Medium"
            assert finding["Region"] == "us-east-1"
            assert f"Source check {source_check_id}" in details
            assert_finding_schema(finding)

        assert set(actual_by_source) == set(self.EXPECTED_AGENTIC_MAPPINGS)
        for source_check_id, expected_ag_id in self.EXPECTED_AGENTIC_MAPPINGS.items():
            assert actual_by_source[source_check_id]["Check_ID"] == expected_ag_id


class TestProposedAgentCoreChecks:
    """AC-14 through AC-17 and the AC-06 correction."""

    @patch("agentcore_app.agentcore_client")
    def test_ac14_customer_managed_token_vault_passes(self, mock_ac):
        mock_ac.get_token_vault.return_value = {
            "tokenVaultId": "default",
            "kmsConfiguration": {
                "keyType": "CustomerManagedKey",
                "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
            },
        }
        finding = agentcore_app.check_agentcore_token_vault_encryption()[0]
        assert finding["Check_ID"] == "AC-14"
        assert finding["Status"] == "Passed"

    @patch.dict(
        os.environ,
        {"AGENTCORE_TOKEN_VAULT_ID": "team-security-vault"},
        clear=False,
    )
    @patch("agentcore_app.agentcore_client")
    def test_ac14_uses_configured_non_default_token_vault(self, mock_ac):
        mock_ac.get_token_vault.return_value = {
            "tokenVaultId": "team-security-vault",
            "kmsConfiguration": {
                "keyType": "CustomerManagedKey",
                "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-2",
            },
        }

        finding = agentcore_app.check_agentcore_token_vault_encryption()[0]

        mock_ac.get_token_vault.assert_called_once_with(
            tokenVaultId="team-security-vault"
        )
        assert finding["Status"] == "Passed"
        assert "team-security-vault" in finding["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac14_service_managed_token_vault_fails(self, mock_ac):
        mock_ac.get_token_vault.return_value = {
            "tokenVaultId": "default",
            "kmsConfiguration": {"keyType": "ServiceManagedKey"},
        }
        finding = agentcore_app.check_agentcore_token_vault_encryption()[0]
        assert finding["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_custom_interpreter_vpc_passes(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "interpreter-1"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {
            "networkConfiguration": {
                "networkMode": "VPC",
                "vpcConfig": {
                    "subnets": ["subnet-1"],
                    "securityGroups": ["sg-1"],
                },
            }
        }
        finding = agentcore_app.check_agentcore_code_interpreter_isolation()[0]
        assert finding["Check_ID"] == "AC-15"
        assert finding["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_public_interpreter_fails(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "interpreter-1"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {
            "networkConfiguration": {"networkMode": "PUBLIC"}
        }
        finding = agentcore_app.check_agentcore_code_interpreter_isolation()[0]
        assert finding["Status"] == "Failed"

    def test_ac06_and_ac16_share_browser_inventory(self):
        inventory = {
            "items": [
                {
                    "summary": {"browserId": "br-1", "name": "browser-1"},
                    "detail": {
                        "networkConfiguration": {
                            "networkMode": "VPC",
                            "vpcConfig": {
                                "subnets": ["subnet-1"],
                                "securityGroups": ["sg-1"],
                            },
                        },
                        "recording": {
                            "enabled": True,
                            "s3Location": {"bucket": "recordings"},
                        },
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        with patch("agentcore_app.agentcore_client", MagicMock()):
            ac06 = agentcore_app.check_browser_tool_recording(inventory)[0]
            ac16 = agentcore_app.check_agentcore_browser_network_isolation(inventory)[0]
        assert ac06["Status"] == "Passed"
        assert ac16["Status"] == "Passed"

    def test_ac16_public_browser_fails(self):
        inventory = {
            "items": [
                {
                    "summary": {"browserId": "br-1", "name": "browser-1"},
                    "detail": {
                        "networkConfiguration": {"networkMode": "PUBLIC"},
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        with patch("agentcore_app.agentcore_client", MagicMock()):
            finding = agentcore_app.check_agentcore_browser_network_isolation(
                inventory
            )[0]
        assert finding["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac17_operational_evaluation_passes_advisory(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                {
                    "onlineEvaluationConfigId": "eval-1",
                    "onlineEvaluationConfigName": "evaluation-1",
                }
            ]
        }
        mock_ac.get_online_evaluation_config.return_value = {
            "status": "ACTIVE",
            "executionStatus": "ENABLED",
            "rule": {"samplingConfig": {"samplingPercentage": 10}},
            "evaluators": [{"evaluatorId": "evaluator-1"}],
            "dataSourceConfig": {
                "cloudWatchLogs": {"logGroupNames": ["/aws/agentcore/input"]}
            },
            "outputConfig": {
                "cloudWatchConfig": {"logGroupName": "/aws/agentcore/output"}
            },
        }
        finding = agentcore_app.check_agentcore_online_evaluation_coverage()[0]
        assert finding["Check_ID"] == "AC-17"
        assert finding["Status"] == "Passed"
        assert finding["Severity"] == "Informational"

    @patch.dict(
        os.environ,
        {"REQUIRE_AGENTCORE_ONLINE_EVALUATION": "false"},
        clear=False,
    )
    @patch("agentcore_app.agentcore_client")
    def test_ac17_incomplete_advisory_evaluation_returns_na(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                {
                    "onlineEvaluationConfigId": "eval-1",
                    "onlineEvaluationConfigName": "evaluation-1",
                }
            ]
        }
        mock_ac.get_online_evaluation_config.return_value = {
            "status": "ACTIVE",
            "executionStatus": "DISABLED",
        }

        finding = agentcore_app.check_agentcore_online_evaluation_coverage()[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Resolution"].startswith("Set the evaluation ACTIVE")

    @patch.dict(
        os.environ,
        {"REQUIRE_AGENTCORE_ONLINE_EVALUATION": "true"},
        clear=False,
    )
    @patch("agentcore_app.agentcore_client")
    def test_ac17_incomplete_required_evaluation_fails(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                {
                    "onlineEvaluationConfigId": "eval-1",
                    "onlineEvaluationConfigName": "evaluation-1",
                }
            ]
        }
        mock_ac.get_online_evaluation_config.return_value = {
            "status": "ACTIVE",
            "executionStatus": "DISABLED",
        }
        finding = agentcore_app.check_agentcore_online_evaluation_coverage()[0]
        assert finding["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_new_agentcore_checks_access_denied_return_na(self, mock_ac):
        error = _make_client_error("AccessDeniedException", "Denied")

        mock_ac.get_token_vault.side_effect = error
        ac14 = agentcore_app.check_agentcore_token_vault_encryption()[0]

        mock_ac.reset_mock()
        mock_ac.list_code_interpreters.side_effect = error
        ac15 = agentcore_app.check_agentcore_code_interpreter_isolation()[0]

        mock_ac.reset_mock()
        ac16 = agentcore_app.check_agentcore_browser_network_isolation(
            {"items": [], "errors": [], "list_error": error}
        )[0]

        mock_ac.reset_mock()
        mock_ac.list_online_evaluation_configs.side_effect = error
        ac17 = agentcore_app.check_agentcore_online_evaluation_coverage()[0]

        for finding in (ac14, ac15, ac16, ac17):
            assert finding["Status"] == "N/A"
            assert finding["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client")
    def test_ag25_fails_when_engine_has_only_log_only_policy(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "gateway-1"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "gateway-1",
            "authorizerType": "AWS_IAM",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/pe-1",
                "mode": "ENFORCE",
            },
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "LOG_ONLY",
                }
            ]
        }
        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag25 = [finding for finding in findings if finding["Check_ID"] == "AG-25"]
        assert ag25[0]["Status"] == "Failed"

    def test_new_agentcore_operation_contracts_exist(self):
        client = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        )
        model = client.meta.service_model
        for operation in [
            "GetTokenVault",
            "ListCodeInterpreters",
            "GetCodeInterpreter",
            "ListBrowsers",
            "GetBrowser",
            "ListOnlineEvaluationConfigs",
            "GetOnlineEvaluationConfig",
            "ListPolicies",
        ]:
            assert model.operation_model(operation)


# ===================================================================
# AC-18: check_agentcore_cloudtrail_data_events
# ===================================================================
def _data_event_selector(*resource_types):
    """An advanced event selector that logs data events for resource types."""
    return {
        "Name": "agentcore",
        "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": list(resource_types)},
        ],
    }


def _management_selector(*resource_types):
    """A selector naming resource types without opting into data events."""
    return {
        "Name": "management",
        "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Management"]},
            {"Field": "resources.type", "Equals": list(resource_types)},
        ],
    }


def _empty_agentcore_inventory(mock_ac):
    """Stub every AgentCore list API AC-18 and AC-19 read as returning nothing.

    A MagicMock attribute returns a MagicMock whose .get() is also a MagicMock,
    which the paginator rejects and reports as an empty page, so an unstubbed
    list API would silently read as "no resources" instead of failing the test.
    """
    mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
    mock_ac.list_memories.return_value = {"memories": []}
    mock_ac.list_code_interpreters.return_value = {"codeInterpreterSummaries": []}
    mock_ac.list_browsers.return_value = {"browserSummaries": []}
    mock_ac.list_gateways.return_value = {"items": []}


def _family_finding(findings, label):
    """Return the one AC-18 finding for a resource family."""
    matches = [
        f for f in findings if f"AgentCore {label} resource" in f["Finding_Details"]
    ]
    assert len(matches) == 1, findings
    return matches[0]


class TestAC18CloudTrailDataEvents:
    """AC-18: CloudTrail data-event coverage per AgentCore resource family."""

    _TRAIL = {
        "Name": "org-trail",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
    }

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.cloudtrail_client")
    def test_memory_data_events_selected_passes(self, mock_ct, mock_ac):
        mock_ct.list_trails.return_value = {"Trails": [self._TRAIL]}
        mock_ct.get_event_selectors.return_value = {
            "AdvancedEventSelectors": [
                _data_event_selector("AWS::BedrockAgentCore::Memory")
            ]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_memories.return_value = {"memories": [{"id": "mem-1"}]}

        findings = agentcore_app.check_agentcore_cloudtrail_data_events()

        memory = _family_finding(findings, "Memory")
        assert memory["Check_ID"] == "AC-18"
        assert memory["Status"] == "Passed"
        for finding in findings:
            assert_finding_schema(finding)

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.cloudtrail_client")
    def test_memory_data_events_absent_fails(self, mock_ct, mock_ac):
        mock_ct.list_trails.return_value = {"Trails": [self._TRAIL]}
        mock_ct.get_event_selectors.return_value = {
            "AdvancedEventSelectors": [_data_event_selector("AWS::S3::Object")]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_memories.return_value = {"memories": [{"id": "mem-1"}]}

        findings = agentcore_app.check_agentcore_cloudtrail_data_events()

        assert _family_finding(findings, "Memory")["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.cloudtrail_client")
    def test_management_category_selector_does_not_count(self, mock_ct, mock_ac):
        mock_ct.list_trails.return_value = {"Trails": [self._TRAIL]}
        mock_ct.get_event_selectors.return_value = {
            "AdvancedEventSelectors": [
                _management_selector("AWS::BedrockAgentCore::Memory")
            ]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_memories.return_value = {"memories": [{"id": "mem-1"}]}

        findings = agentcore_app.check_agentcore_cloudtrail_data_events()

        assert _family_finding(findings, "Memory")["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.cloudtrail_client")
    def test_each_family_gets_its_own_verdict(self, mock_ct, mock_ac):
        mock_ct.list_trails.return_value = {"Trails": [self._TRAIL]}
        mock_ct.get_event_selectors.return_value = {
            "AdvancedEventSelectors": [
                _data_event_selector("AWS::BedrockAgentCore::Runtime")
            ]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": [{"id": "rt-1"}]}
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [{"codeInterpreterId": "ci-1"}]
        }

        findings = agentcore_app.check_agentcore_cloudtrail_data_events()

        assert _family_finding(findings, "Runtime")["Status"] == "Passed"
        assert _family_finding(findings, "Tool")["Status"] == "Failed"
        assert _family_finding(findings, "Memory")["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.cloudtrail_client")
    def test_a_tool_inventory_spans_both_list_apis(self, mock_ct, mock_ac):
        mock_ct.list_trails.return_value = {"Trails": [self._TRAIL]}
        mock_ct.get_event_selectors.return_value = {
            "AdvancedEventSelectors": [
                _data_event_selector("AWS::BedrockAgentCore::BrowserCustom")
            ]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_browsers.return_value = {
            "browserSummaries": [{"browserId": "b-1"}]
        }

        findings = agentcore_app.check_agentcore_cloudtrail_data_events()

        assert _family_finding(findings, "Tool")["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.cloudtrail_client")
    def test_unreadable_trail_reads_unknown_not_uncovered(self, mock_ct, mock_ac):
        mock_ct.list_trails.return_value = {"Trails": [self._TRAIL]}
        mock_ct.get_event_selectors.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_memories.return_value = {"memories": [{"id": "mem-1"}]}

        findings = agentcore_app.check_agentcore_cloudtrail_data_events()

        memory = _family_finding(findings, "Memory")
        assert memory["Status"] == "N/A"
        assert "could not be read" in memory["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.cloudtrail_client")
    def test_event_selectors_are_read_by_trail_arn(self, mock_ct, mock_ac):
        trail_arn = "arn:aws:cloudtrail:us-west-2:999988887777:trail/shadow"
        mock_ct.list_trails.return_value = {
            "Trails": [{"Name": "shadow", "TrailARN": trail_arn}]
        }
        mock_ct.get_event_selectors.return_value = {"AdvancedEventSelectors": []}
        _empty_agentcore_inventory(mock_ac)

        agentcore_app.check_agentcore_cloudtrail_data_events()

        mock_ct.get_event_selectors.assert_called_once_with(TrailName=trail_arn)

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.cloudtrail_client")
    def test_every_trail_page_is_read(self, mock_ct, mock_ac):
        mock_ct.list_trails.side_effect = [
            {
                "Trails": [
                    {"TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/t1"}
                ],
                "NextToken": "page-2",
            },
            {
                "Trails": [
                    {"TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/t2"}
                ]
            },
        ]
        mock_ct.get_event_selectors.side_effect = [
            {"AdvancedEventSelectors": [_data_event_selector("AWS::S3::Object")]},
            {
                "AdvancedEventSelectors": [
                    _data_event_selector("AWS::BedrockAgentCore::Memory")
                ]
            },
        ]
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_memories.return_value = {"memories": [{"id": "mem-1"}]}

        findings = agentcore_app.check_agentcore_cloudtrail_data_events()

        assert mock_ct.get_event_selectors.call_count == 2
        # CloudTrail capitalizes the continuation member; a lowercase nextToken
        # is a ParamValidationError against the real API.
        assert mock_ct.list_trails.call_args_list[1].kwargs == {"NextToken": "page-2"}
        assert _family_finding(findings, "Memory")["Status"] == "Passed"

    def test_no_cloudtrail_client_is_na(self):
        with patch("agentcore_app.cloudtrail_client", None):
            findings = agentcore_app.check_agentcore_cloudtrail_data_events()
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.cloudtrail_client")
    def test_list_trails_failure_is_na(self, mock_ct):
        mock_ct.list_trails.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )
        findings = agentcore_app.check_agentcore_cloudtrail_data_events()
        assert findings[0]["Status"] == "N/A"
        assert "cloudtrail:ListTrails" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.cloudtrail_client")
    def test_uninventoriable_family_is_na_not_failed(self, mock_ct, mock_ac):
        mock_ct.list_trails.return_value = {"Trails": [self._TRAIL]}
        mock_ct.get_event_selectors.return_value = {"AdvancedEventSelectors": []}
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_memories.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )

        findings = agentcore_app.check_agentcore_cloudtrail_data_events()

        memory = [
            f for f in findings if "could not be inventoried" in f["Finding_Details"]
        ]
        assert memory[0]["Status"] == "N/A"


# ===================================================================
# AC-19: check_agentcore_log_delivery_configuration
# ===================================================================
class TestAC19LogDeliveryConfiguration:
    """AC-19: Application-log delivery per gateway and memory resource."""

    @staticmethod
    def _sources(*entries):
        return {"deliverySources": list(entries)}

    @staticmethod
    def _gateway_source(
        name="gw-logs-source", log_type="APPLICATION_LOGS", service="bedrock-agentcore"
    ):
        return {
            "name": name,
            "service": service,
            "logType": log_type,
            "resourceArns": [
                "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1"
            ],
        }

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.logs_client")
    def test_gateway_with_source_and_delivery_passes(self, mock_logs, mock_ac):
        mock_logs.describe_delivery_sources.return_value = self._sources(
            self._gateway_source()
        )
        mock_logs.describe_deliveries.return_value = {
            "deliveries": [{"deliverySourceName": "gw-logs-source"}]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "gateway-1"}]
        }

        findings = agentcore_app.check_agentcore_log_delivery_configuration()

        gateway = [f for f in findings if "gateway-1" in f["Finding_Details"]]
        assert gateway[0]["Check_ID"] == "AC-19"
        assert gateway[0]["Status"] == "Passed"
        for finding in findings:
            assert_finding_schema(finding)

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.logs_client")
    def test_source_without_delivery_fails_distinctly(self, mock_logs, mock_ac):
        mock_logs.describe_delivery_sources.return_value = self._sources(
            self._gateway_source()
        )
        mock_logs.describe_deliveries.return_value = {"deliveries": []}
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "gateway-1"}]
        }

        findings = agentcore_app.check_agentcore_log_delivery_configuration()

        gateway = [f for f in findings if "gateway-1" in f["Finding_Details"]]
        assert gateway[0]["Status"] == "Failed"
        assert "no delivery to a" in gateway[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.logs_client")
    def test_no_source_fails_with_its_own_detail(self, mock_logs, mock_ac):
        mock_logs.describe_delivery_sources.return_value = self._sources()
        mock_logs.describe_deliveries.return_value = {"deliveries": []}
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "gateway-1"}]
        }

        findings = agentcore_app.check_agentcore_log_delivery_configuration()

        gateway = [f for f in findings if "gateway-1" in f["Finding_Details"]]
        assert gateway[0]["Status"] == "Failed"
        assert "no bedrock-agentcore" in gateway[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.logs_client")
    def test_memory_is_matched_on_its_exact_arn(self, mock_logs, mock_ac):
        memory_arn = "arn:aws:bedrock-agentcore:us-east-1:123456789012:memory/mem-1"
        mock_logs.describe_delivery_sources.return_value = self._sources(
            {
                "name": "mem-logs-source",
                "service": "bedrock-agentcore",
                "logType": "APPLICATION_LOGS",
                "resourceArns": [memory_arn],
            }
        )
        mock_logs.describe_deliveries.return_value = {
            "deliveries": [{"deliverySourceName": "mem-logs-source"}]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_memories.return_value = {
            "memories": [{"id": "mem-1", "arn": memory_arn}]
        }

        findings = agentcore_app.check_agentcore_log_delivery_configuration()

        memory = [f for f in findings if "mem-1" in f["Finding_Details"]]
        assert memory[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.logs_client")
    def test_traces_only_source_does_not_satisfy_application_logs(
        self, mock_logs, mock_ac
    ):
        mock_logs.describe_delivery_sources.return_value = self._sources(
            self._gateway_source(name="gw-traces-source", log_type="TRACES")
        )
        mock_logs.describe_deliveries.return_value = {
            "deliveries": [{"deliverySourceName": "gw-traces-source"}]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "gateway-1"}]
        }

        findings = agentcore_app.check_agentcore_log_delivery_configuration()

        gateway = [f for f in findings if "gateway-1" in f["Finding_Details"]]
        assert gateway[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.logs_client")
    def test_another_service_source_on_the_same_arn_does_not_count(
        self, mock_logs, mock_ac
    ):
        mock_logs.describe_delivery_sources.return_value = self._sources(
            self._gateway_source(name="other-source", service="bedrock")
        )
        mock_logs.describe_deliveries.return_value = {
            "deliveries": [{"deliverySourceName": "other-source"}]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "gateway-1"}]
        }

        findings = agentcore_app.check_agentcore_log_delivery_configuration()

        gateway = [f for f in findings if "gateway-1" in f["Finding_Details"]]
        assert gateway[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.logs_client")
    def test_services_without_a_readable_delivery_are_reported_unassessed(
        self, mock_logs, mock_ac
    ):
        mock_logs.describe_delivery_sources.return_value = self._sources()
        mock_logs.describe_deliveries.return_value = {"deliveries": []}
        _empty_agentcore_inventory(mock_ac)

        findings = agentcore_app.check_agentcore_log_delivery_configuration()

        residual = [f for f in findings if "not assessed" in f["Finding_Details"]]
        assert len(residual) == 1, findings
        assert residual[0]["Status"] == "N/A"
        # The residual has to name why each service is out of scope, because
        # "configured in the console" was wrong for all three: identity
        # delivery is configured on the runtime or gateway resource, policy
        # engines have no log destination, and only built-in tools are both
        # configurable and unassessable from the inventory.
        details = residual[0]["Finding_Details"]
        assert "Built-in tool log delivery is not assessed" in details
        assert "configured on the associated runtime or gateway resource" in details
        assert "policy engines have no log-destination configuration" in details

    def test_no_logs_client_is_na(self):
        with patch("agentcore_app.logs_client", None):
            findings = agentcore_app.check_agentcore_log_delivery_configuration()
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.logs_client")
    def test_delivery_read_failure_is_na(self, mock_logs):
        mock_logs.describe_delivery_sources.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )
        findings = agentcore_app.check_agentcore_log_delivery_configuration()
        assert findings[0]["Status"] == "N/A"
        assert "logs:DescribeDeliverySources" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    @patch("agentcore_app.logs_client")
    def test_every_delivery_source_page_is_read(self, mock_logs, mock_ac):
        mock_logs.describe_delivery_sources.side_effect = [
            {
                "deliverySources": [self._gateway_source(name="page-1-source")],
                "nextToken": "page-2",
            },
            {"deliverySources": [self._gateway_source()]},
        ]
        mock_logs.describe_deliveries.return_value = {
            "deliveries": [{"deliverySourceName": "gw-logs-source"}]
        }
        _empty_agentcore_inventory(mock_ac)
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "gateway-1"}]
        }

        findings = agentcore_app.check_agentcore_log_delivery_configuration()

        assert mock_logs.describe_delivery_sources.call_count == 2
        assert mock_logs.describe_delivery_sources.call_args_list[1].kwargs == {
            "nextToken": "page-2"
        }
        gateway = [f for f in findings if "gateway-1" in f["Finding_Details"]]
        assert gateway[0]["Status"] == "Passed"


# ===================================================================
# AC-20: check_agentcore_log_group_data_protection
# ===================================================================
def _log_group_side_effect(groups_by_prefix):
    """describe_log_groups stub that answers per logGroupNamePrefix.

    One return_value would hand the same groups back for both AgentCore
    prefixes and double every finding, so a test could not tell one prefix's
    results from the other's.
    """

    def describe(**kwargs):
        prefix = kwargs.get("logGroupNamePrefix")
        return {"logGroups": groups_by_prefix.get(prefix, [])}

    return describe


class TestAC20LogDataProtection:
    """AC-20: Masking and CMK encryption on AgentCore log groups."""

    _MASKING_POLICY = (
        '{"Name": "p", "Statement": [{"Sid": "mask", '
        '"DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"], '
        '"Operation": {"Deidentify": {"MaskConfig": {}}}}]}'
    )
    _AUDIT_ONLY_POLICY = (
        '{"Name": "p", "Statement": [{"Sid": "audit", '
        '"DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"], '
        '"Operation": {"Audit": {"FindingsDestination": {}}}}]}'
    )
    _KMS_KEY = "arn:aws:kms:us-east-1:123456789012:key/k1"

    @patch("agentcore_app.logs_client")
    def test_masked_and_cmk_log_group_passes(self, mock_logs):
        mock_logs.describe_account_policies.return_value = {"accountPolicies": []}
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1",
                        "kmsKeyId": self._KMS_KEY,
                        "dataProtectionStatus": "ACTIVATED",
                    }
                ]
            }
        )
        mock_logs.get_data_protection_policy.return_value = {
            "policyDocument": self._MASKING_POLICY
        }

        findings = agentcore_app.check_agentcore_log_group_data_protection()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-20"
        assert findings[0]["Status"] == "Passed"
        assert_finding_schema(findings[0])

    @patch("agentcore_app.logs_client")
    def test_missing_cmk_fails_and_names_only_that_leg(self, mock_logs):
        mock_logs.describe_account_policies.return_value = {"accountPolicies": []}
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1",
                        "dataProtectionStatus": "ACTIVATED",
                    }
                ]
            }
        )
        mock_logs.get_data_protection_policy.return_value = {
            "policyDocument": self._MASKING_POLICY
        }

        findings = agentcore_app.check_agentcore_log_group_data_protection()

        assert findings[0]["Status"] == "Failed"
        assert "no customer managed encryption key" in findings[0]["Finding_Details"]
        assert "data-protection policy" not in findings[0]["Finding_Details"]

    @patch("agentcore_app.logs_client")
    def test_both_legs_missing_are_named_together(self, mock_logs):
        mock_logs.describe_account_policies.return_value = {"accountPolicies": []}
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {"logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1"}
                ]
            }
        )

        findings = agentcore_app.check_agentcore_log_group_data_protection()

        assert findings[0]["Status"] == "Failed"
        assert " and " in findings[0]["Finding_Details"]

    @patch("agentcore_app.logs_client")
    def test_audit_only_policy_is_not_masking(self, mock_logs):
        mock_logs.describe_account_policies.return_value = {"accountPolicies": []}
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1",
                        "kmsKeyId": self._KMS_KEY,
                        "dataProtectionStatus": "ACTIVATED",
                    }
                ]
            }
        )
        mock_logs.get_data_protection_policy.return_value = {
            "policyDocument": self._AUDIT_ONLY_POLICY
        }

        findings = agentcore_app.check_agentcore_log_group_data_protection()

        assert findings[0]["Status"] == "Failed"
        assert "de-identifies" in findings[0]["Finding_Details"]

    @patch("agentcore_app.logs_client")
    def test_account_policy_covers_a_group_with_no_policy_of_its_own(self, mock_logs):
        mock_logs.describe_account_policies.return_value = {
            "accountPolicies": [
                {
                    "policyName": "account-wide",
                    "policyType": "DATA_PROTECTION_POLICY",
                    "policyDocument": self._MASKING_POLICY,
                }
            ]
        }
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/vendedlogs/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/vendedlogs/bedrock-agentcore/gw-1",
                        "kmsKeyId": self._KMS_KEY,
                    }
                ]
            }
        )

        findings = agentcore_app.check_agentcore_log_group_data_protection()

        assert findings[0]["Status"] == "Passed"
        assert "account-wide data-protection policy" in findings[0]["Finding_Details"]
        mock_logs.get_data_protection_policy.assert_not_called()

    @patch("agentcore_app.logs_client")
    def test_group_policy_is_read_only_when_one_is_attached(self, mock_logs):
        mock_logs.describe_account_policies.return_value = {"accountPolicies": []}
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1",
                        "kmsKeyId": self._KMS_KEY,
                    }
                ]
            }
        )

        findings = agentcore_app.check_agentcore_log_group_data_protection()

        mock_logs.get_data_protection_policy.assert_not_called()
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.logs_client")
    def test_unreadable_group_policy_is_na(self, mock_logs):
        mock_logs.describe_account_policies.return_value = {"accountPolicies": []}
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1",
                        "kmsKeyId": self._KMS_KEY,
                        "dataProtectionStatus": "ACTIVATED",
                    }
                ]
            }
        )
        mock_logs.get_data_protection_policy.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )

        findings = agentcore_app.check_agentcore_log_group_data_protection()

        assert findings[0]["Status"] == "N/A"
        assert "logs:GetDataProtectionPolicy" in findings[0]["Resolution"]

    @patch("agentcore_app.logs_client")
    def test_both_prefixes_are_inventoried(self, mock_logs):
        mock_logs.describe_account_policies.return_value = {"accountPolicies": []}
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {"logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1"}
                ],
                "/aws/vendedlogs/bedrock-agentcore/": [
                    {"logGroupName": "/aws/vendedlogs/bedrock-agentcore/gw-1"}
                ],
            }
        )

        findings = agentcore_app.check_agentcore_log_group_data_protection()

        assert len({finding["Finding_Details"] for finding in findings}) == 2

    @patch("agentcore_app.logs_client")
    def test_no_agentcore_log_groups_is_na(self, mock_logs):
        mock_logs.describe_account_policies.return_value = {"accountPolicies": []}
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect({})

        findings = agentcore_app.check_agentcore_log_group_data_protection()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_no_logs_client_is_na(self):
        with patch("agentcore_app.logs_client", None):
            findings = agentcore_app.check_agentcore_log_group_data_protection()
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.logs_client")
    def test_account_policy_read_failure_is_na(self, mock_logs):
        mock_logs.describe_account_policies.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )
        findings = agentcore_app.check_agentcore_log_group_data_protection()
        assert findings[0]["Status"] == "N/A"
        assert "logs:DescribeAccountPolicies" in findings[0]["Resolution"]


# ===================================================================
# AC-21: check_agentcore_log_unmask_restriction
# ===================================================================
class TestAC21LogUnmaskRestriction:
    """AC-21: Who can read masked values back out of AgentCore logs."""

    @staticmethod
    def _cache(actions, resource="*", principal="analyst-role"):
        return {
            "role_permissions": {
                principal: {
                    "attached_policies": [
                        {
                            "name": "p",
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": actions,
                                        "Resource": resource,
                                    }
                                ]
                            },
                        }
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

    def test_unscoped_unmask_fails(self):
        findings = agentcore_app.check_agentcore_log_unmask_restriction(
            self._cache(["logs:Unmask"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Check_ID"] == "AC-21"
        assert "role analyst-role" in findings[0]["Finding_Details"]
        for finding in findings:
            assert_finding_schema(finding)

    def test_scoped_unmask_passes(self):
        findings = agentcore_app.check_agentcore_log_unmask_restriction(
            self._cache(
                ["logs:Unmask"],
                resource=(
                    "arn:aws:logs:us-east-1:123456789012:"
                    "log-group:/aws/bedrock-agentcore/*"
                ),
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "role analyst-role" in findings[0]["Finding_Details"]

    def test_no_unmask_grant_passes(self):
        findings = agentcore_app.check_agentcore_log_unmask_restriction(
            self._cache(["logs:DescribeLogGroups"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_bare_wildcard_action_is_ignored(self):
        findings = agentcore_app.check_agentcore_log_unmask_restriction(
            self._cache(["*"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_logs_namespace_wildcard_is_detected(self):
        findings = agentcore_app.check_agentcore_log_unmask_restriction(
            self._cache(["logs:*"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_a_different_namespace_unmask_is_ignored(self):
        findings = agentcore_app.check_agentcore_log_unmask_restriction(
            self._cache(["macie2:Unmask"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_users_are_evaluated_alongside_roles(self):
        cache = self._cache(["logs:Unmask"])
        cache["user_permissions"] = cache["role_permissions"]
        cache["role_permissions"] = {}

        findings = agentcore_app.check_agentcore_log_unmask_restriction(cache)

        assert [f["Status"] for f in findings] == ["Failed"]
        assert "user analyst-role" in findings[0]["Finding_Details"]

    def test_scoped_and_unscoped_principals_are_reported_separately(self):
        cache = self._cache(["logs:Unmask"])
        cache["role_permissions"]["scoped-role"] = {
            "attached_policies": [
                {
                    "name": "p",
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "logs:Unmask",
                                "Resource": (
                                    "arn:aws:logs:us-east-1:123456789012:log-group:/x"
                                ),
                            }
                        ]
                    },
                }
            ],
            "inline_policies": [],
        }

        findings = agentcore_app.check_agentcore_log_unmask_restriction(cache)

        assert {finding["Status"] for finding in findings} == {"Failed", "Passed"}

    def test_findings_are_tagged_global(self):
        findings = agentcore_app.check_agentcore_log_unmask_restriction(
            self._cache(["logs:Unmask"])
        )
        assert all(
            finding["Region"] == agentcore_app.GLOBAL_REGION_LABEL
            for finding in findings
        )

    def test_empty_cache_is_na(self):
        findings = agentcore_app.check_agentcore_log_unmask_restriction(
            {"role_permissions": {}, "user_permissions": {}}
        )
        assert findings[0]["Status"] == "N/A"

    def test_unparseable_policy_does_not_hide_a_sibling_grant(self):
        cache = self._cache(["logs:Unmask"])
        cache["role_permissions"]["analyst-role"]["inline_policies"] = [
            {"name": "broken", "document": "{not json"}
        ]

        findings = agentcore_app.check_agentcore_log_unmask_restriction(cache)

        assert [f["Status"] for f in findings] == ["Failed"]


# ===================================================================
# AC-22: check_agentcore_telemetry_sink_scope
# ===================================================================
class TestAC22TelemetrySinkScope:
    """AC-22: Whether each observability sink is scoped to known callers."""

    _SINK = {
        "Arn": "arn:aws:oam:us-east-1:123456789012:sink/s-1",
        "Id": "s-1",
        "Name": "central-sink",
    }

    @patch("agentcore_app.oam_client")
    def test_org_id_condition_passes(self, mock_oam):
        mock_oam.list_sinks.return_value = {"Items": [self._SINK]}
        mock_oam.get_sink_policy.return_value = {
            "Policy": (
                '{"Statement": [{"Effect": "Allow", "Principal": "*", '
                '"Action": "oam:CreateLink", "Resource": "*", '
                '"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}]}'
            )
        }

        findings = agentcore_app.check_agentcore_telemetry_sink_scope()

        assert findings[0]["Check_ID"] == "AC-22"
        assert findings[0]["Status"] == "Passed"
        assert_finding_schema(findings[0])

    @patch("agentcore_app.oam_client")
    def test_prefixed_condition_operator_passes(self, mock_oam):
        mock_oam.list_sinks.return_value = {"Items": [self._SINK]}
        mock_oam.get_sink_policy.return_value = {
            "Policy": (
                '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, '
                '"Action": "oam:CreateLink", "Resource": "*", '
                '"Condition": {"ForAnyValue:StringLike": '
                '{"aws:PrincipalOrgPaths": "o-1/r-1/ou-1/"}}}]}'
            )
        }

        findings = agentcore_app.check_agentcore_telemetry_sink_scope()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.oam_client")
    def test_named_account_principal_passes(self, mock_oam):
        mock_oam.list_sinks.return_value = {"Items": [self._SINK]}
        mock_oam.get_sink_policy.return_value = {
            "Policy": (
                '{"Statement": [{"Effect": "Allow", '
                '"Principal": {"AWS": ["arn:aws:iam::111122223333:root"]}, '
                '"Action": "oam:CreateLink", "Resource": "*"}]}'
            )
        }

        findings = agentcore_app.check_agentcore_telemetry_sink_scope()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.oam_client")
    def test_open_principal_without_condition_fails(self, mock_oam):
        mock_oam.list_sinks.return_value = {"Items": [self._SINK]}
        mock_oam.get_sink_policy.return_value = {
            "Policy": (
                '{"Statement": [{"Effect": "Allow", "Principal": "*", '
                '"Action": "oam:CreateLink", "Resource": "*"}]}'
            )
        }

        findings = agentcore_app.check_agentcore_telemetry_sink_scope()

        assert findings[0]["Status"] == "Failed"
        assert "central-sink" in findings[0]["Finding_Details"]

    @patch("agentcore_app.oam_client")
    def test_an_unrelated_condition_key_does_not_scope_the_sink(self, mock_oam):
        mock_oam.list_sinks.return_value = {"Items": [self._SINK]}
        mock_oam.get_sink_policy.return_value = {
            "Policy": (
                '{"Statement": [{"Effect": "Allow", "Principal": "*", '
                '"Action": "oam:CreateLink", "Resource": "*", '
                '"Condition": {"ForAllValues:StringEquals": '
                '{"oam:ResourceTypes": "AWS::Logs::LogGroup"}}}]}'
            )
        }

        findings = agentcore_app.check_agentcore_telemetry_sink_scope()

        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.oam_client")
    def test_one_open_statement_among_scoped_ones_fails(self, mock_oam):
        mock_oam.list_sinks.return_value = {"Items": [self._SINK]}
        mock_oam.get_sink_policy.return_value = {
            "Policy": (
                '{"Statement": ['
                '{"Effect": "Allow", "Principal": "*", "Action": "oam:CreateLink", '
                '"Resource": "*", '
                '"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}, '
                '{"Effect": "Allow", "Principal": "*", "Action": "oam:UpdateLink", '
                '"Resource": "*"}]}'
            )
        }

        findings = agentcore_app.check_agentcore_telemetry_sink_scope()

        assert findings[0]["Status"] == "Failed"
        assert "1 Allow statement" in findings[0]["Finding_Details"]

    @patch("agentcore_app.oam_client")
    def test_no_sinks_is_na(self, mock_oam):
        mock_oam.list_sinks.return_value = {"Items": []}
        findings = agentcore_app.check_agentcore_telemetry_sink_scope()
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.oam_client")
    def test_sink_without_a_policy_is_na(self, mock_oam):
        mock_oam.list_sinks.return_value = {"Items": [self._SINK]}
        mock_oam.get_sink_policy.side_effect = _make_client_error(
            "ResourceNotFoundException", "no policy"
        )
        findings = agentcore_app.check_agentcore_telemetry_sink_scope()
        assert findings[0]["Status"] == "N/A"
        assert "no policy attached" in findings[0]["Finding_Details"]

    @patch("agentcore_app.oam_client")
    def test_sink_policy_access_denied_is_na(self, mock_oam):
        mock_oam.list_sinks.return_value = {"Items": [self._SINK]}
        mock_oam.get_sink_policy.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )
        findings = agentcore_app.check_agentcore_telemetry_sink_scope()
        assert findings[0]["Status"] == "N/A"
        assert "oam:GetSinkPolicy" in findings[0]["Resolution"]

    def test_no_oam_client_is_na(self):
        with patch("agentcore_app.oam_client", None):
            findings = agentcore_app.check_agentcore_telemetry_sink_scope()
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.oam_client")
    def test_list_sinks_failure_is_na(self, mock_oam):
        mock_oam.list_sinks.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )
        findings = agentcore_app.check_agentcore_telemetry_sink_scope()
        assert findings[0]["Status"] == "N/A"
        assert "oam:ListSinks" in findings[0]["Resolution"]

    @patch("agentcore_app.oam_client")
    def test_every_sink_page_is_read(self, mock_oam):
        second = dict(self._SINK, Arn="arn:aws:oam:us-east-1:123456789012:sink/s-2")
        mock_oam.list_sinks.side_effect = [
            {"Items": [self._SINK], "NextToken": "page-2"},
            {"Items": [second]},
        ]
        mock_oam.get_sink_policy.return_value = {
            "Policy": (
                '{"Statement": [{"Effect": "Allow", "Principal": "*", '
                '"Action": "oam:CreateLink", "Resource": "*"}]}'
            )
        }

        findings = agentcore_app.check_agentcore_telemetry_sink_scope()

        assert len(findings) == 2
        assert mock_oam.list_sinks.call_args_list[1].kwargs == {"NextToken": "page-2"}


# ===================================================================
# AC-23: check_agentcore_memory_record_access_scope
# ===================================================================
class TestAC23MemoryRecordAccessScope:
    """AC-23: Who can read memory records across every actor."""

    _MEMORY_ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:memory/mem-1"

    @staticmethod
    def _cache(
        actions,
        condition=None,
        resource="*",
        principal="agent-role",
        effect="Allow",
    ):
        statement = {"Effect": effect, "Action": actions, "Resource": resource}
        if condition:
            statement["Condition"] = condition
        return {
            "role_permissions": {
                principal: {
                    "attached_policies": [
                        {"name": "p", "document": {"Statement": [statement]}}
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

    def test_unscoped_record_read_fails(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(["bedrock-agentcore:RetrieveMemoryRecords"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Check_ID"] == "AC-23"
        assert findings[0]["Severity"] == "High"
        assert "role agent-role" in findings[0]["Finding_Details"]
        for finding in findings:
            assert_finding_schema(finding)

    def test_namespace_condition_passes(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(
                ["bedrock-agentcore:RetrieveMemoryRecords"],
                condition={
                    "StringLike": {
                        "bedrock-agentcore:namespace": (
                            "/actors/${aws:PrincipalTag/actorId}/*"
                        )
                    }
                },
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "role agent-role" in findings[0]["Finding_Details"]

    def test_actor_condition_on_event_read_passes(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(
                ["bedrock-agentcore:ListEvents", "bedrock-agentcore:GetEvent"],
                condition={
                    "StringEquals": {
                        "bedrock-agentcore:actorId": "${aws:PrincipalTag/actorId}"
                    }
                },
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]

    def test_devguide_namespace_variable_key_counts_as_scope(self):
        # namespaceVariable/<key> is published in the devguide tenant-isolation
        # example but is absent from the IAM service authorization reference. The
        # verdict is the same either way: the key scopes the read if it exists,
        # and the condition can never match if it does not.
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(
                ["bedrock-agentcore:ListMemoryRecords"],
                condition={
                    "StringEquals": {
                        "bedrock-agentcore:namespaceVariable/tenantId": (
                            "${aws:PrincipalTag/tenantId}"
                        )
                    }
                },
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]

    def test_memory_arn_resource_without_a_condition_still_fails(self):
        # The only resource type these actions accept is the memory itself, so
        # naming the ARN still reads every actor's records inside it.
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(
                ["bedrock-agentcore:RetrieveMemoryRecords"], resource=self._MEMORY_ARN
            )
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_agentcore_namespace_wildcard_is_detected(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(["bedrock-agentcore:*"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_bare_wildcard_action_is_ignored(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(["*"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_actions_iam_cannot_scope_are_not_assessed(self):
        # IAM publishes no namespace, actor, session or strategy condition key
        # for GetMemoryRecord or ListActors, so a Failed verdict on them would
        # demand a policy that cannot be written.
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(
                [
                    "bedrock-agentcore:GetMemoryRecord",
                    "bedrock-agentcore:ListActors",
                ]
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_deny_statement_is_ignored(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(["bedrock-agentcore:RetrieveMemoryRecords"], effect="Deny")
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_another_service_read_is_ignored(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(["qbusiness:ListEvents"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_a_scoped_statement_does_not_excuse_an_unscoped_one(self):
        cache = self._cache(
            ["bedrock-agentcore:ListMemoryRecords"],
            condition={"StringEquals": {"bedrock-agentcore:strategyId": "strat-1"}},
        )
        cache["role_permissions"]["agent-role"]["inline_policies"] = [
            {
                "name": "wide",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "bedrock-agentcore:RetrieveMemoryRecords",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]

        findings = agentcore_app.check_agentcore_memory_record_access_scope(cache)

        assert [f["Status"] for f in findings] == ["Failed"]

    def test_users_are_evaluated_alongside_roles(self):
        cache = self._cache(["bedrock-agentcore:RetrieveMemoryRecords"])
        cache["user_permissions"] = cache["role_permissions"]
        cache["role_permissions"] = {}

        findings = agentcore_app.check_agentcore_memory_record_access_scope(cache)

        assert [f["Status"] for f in findings] == ["Failed"]
        assert "user agent-role" in findings[0]["Finding_Details"]

    def test_scoped_and_unscoped_principals_are_reported_separately(self):
        cache = self._cache(["bedrock-agentcore:RetrieveMemoryRecords"])
        cache["role_permissions"]["scoped-role"] = {
            "attached_policies": [
                {
                    "name": "p",
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "bedrock-agentcore:RetrieveMemoryRecords",
                                "Resource": "*",
                                "Condition": {
                                    "StringLike": {
                                        "bedrock-agentcore:namespace": "/actors/a-1/*"
                                    }
                                },
                            }
                        ]
                    },
                }
            ],
            "inline_policies": [],
        }

        findings = agentcore_app.check_agentcore_memory_record_access_scope(cache)

        assert {finding["Status"] for finding in findings} == {"Failed", "Passed"}

    def test_findings_are_tagged_global(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            self._cache(["bedrock-agentcore:RetrieveMemoryRecords"])
        )
        assert all(
            finding["Region"] == agentcore_app.GLOBAL_REGION_LABEL
            for finding in findings
        )

    def test_empty_cache_is_na(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(
            {"role_permissions": {}, "user_permissions": {}}
        )
        assert findings[0]["Status"] == "N/A"

    def test_unparseable_policy_does_not_hide_a_sibling_grant(self):
        cache = self._cache(["bedrock-agentcore:RetrieveMemoryRecords"])
        cache["role_permissions"]["agent-role"]["inline_policies"] = [
            {"name": "broken", "document": "{not json"}
        ]

        findings = agentcore_app.check_agentcore_memory_record_access_scope(cache)

        assert [f["Status"] for f in findings] == ["Failed"]

    def test_unusable_cache_is_reported_incomplete(self):
        findings = agentcore_app.check_agentcore_memory_record_access_scope(None)

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Finding"].endswith("Incomplete")

    def test_read_actions_name_real_api_operations(self):
        # A typo in this tuple would silently narrow the check to nothing.
        model = agentcore_app.boto3.client(
            "bedrock-agentcore",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        operations = {name.lower() for name in model.operation_names}
        assert set(agentcore_app.MEMORY_RECORD_READ_ACTIONS) <= operations
        # The two deliberately excluded reads exist as well, so their absence
        # from the tuple is a scoping decision and not a misspelling.
        assert {"getmemoryrecord", "listactors"} <= operations
        assert {"getmemoryrecord", "listactors"}.isdisjoint(
            agentcore_app.MEMORY_RECORD_READ_ACTIONS
        )


# ===================================================================
# AC-18..AC-22 registration and API contracts
# ===================================================================
class TestObservabilityCheckRegistration:
    """The new ids must reach the backfill paths and the API must answer them."""

    def test_regional_ids_are_registered_for_timeout_backfill(self):
        for check_id in ("AC-18", "AC-19", "AC-20", "AC-22"):
            assert check_id in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
            assert check_id in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_the_global_iam_checks_are_not_in_the_regional_tuples(self):
        # A regional registration would report the same IAM grant once per
        # scanned region.
        for check_id in ("AC-21", "AC-23"):
            assert check_id not in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
            assert check_id not in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_timeout_backfill_emits_the_new_regional_ids(self):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        emitted = {finding["Check_ID"] for finding in findings}
        assert {"AC-18", "AC-19", "AC-20", "AC-22"}.issubset(emitted)

    def test_data_event_families_cover_runtime_memory_and_tools(self):
        keys = {family["key"] for family in agentcore_app.AGENTCORE_DATA_EVENT_FAMILIES}
        assert keys == {"runtime", "memory", "tools"}
        memory = next(
            family
            for family in agentcore_app.AGENTCORE_DATA_EVENT_FAMILIES
            if family["key"] == "memory"
        )
        assert memory["resource_types"] == ("AWS::BedrockAgentCore::Memory",)

    def test_observability_operation_contracts_exist(self):
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        expected = {
            "cloudtrail": ["ListTrails", "GetEventSelectors"],
            "logs": [
                "DescribeLogGroups",
                "DescribeAccountPolicies",
                "GetDataProtectionPolicy",
                "DescribeDeliverySources",
                "DescribeDeliveries",
            ],
            "oam": ["ListSinks", "GetSinkPolicy"],
        }
        for service, operations in expected.items():
            model = agentcore_app.boto3.client(
                service, **credentials
            ).meta.service_model
            for operation in operations:
                assert model.operation_model(operation)


# ===================================================================
# AC-08 endpoint scope plus AC-24..AC-27
# ===================================================================
_GUARDED_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
        }
    ],
}
_UNGUARDED_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
        },
        {
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
        },
    ],
}


class TestAC08EndpointScope:
    """AC-08 now judges each AgentCore endpoint's policy and inbound scope."""

    _DEFAULT_POLICY = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        }
    )
    _SCOPED_POLICY = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
                    "Action": "bedrock-agentcore:InvokeAgentRuntime",
                    "Resource": "*",
                }
            ]
        }
    )

    def _endpoints(self):
        return [
            {
                "VpcEndpointId": "vpce-default",
                "VpcId": "vpc-1",
                "State": "available",
                "ServiceName": "com.amazonaws.us-east-1.bedrock-agentcore",
                "PolicyDocument": self._DEFAULT_POLICY,
                "Groups": [{"GroupId": "sg-open"}],
            },
            {
                "VpcEndpointId": "vpce-scoped",
                "VpcId": "vpc-1",
                "State": "available",
                "ServiceName": "com.amazonaws.us-east-1.bedrock-agentcore-control",
                "PolicyDocument": self._SCOPED_POLICY,
                "Groups": [{"GroupId": "sg-closed"}],
            },
        ]

    def _wire(self, mock_ec2):
        mock_ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
        mock_ec2.describe_vpc_endpoints.return_value = {
            "VpcEndpoints": self._endpoints()
        }
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-open",
                    "IpPermissions": [
                        {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                        {"Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
                    ],
                },
                {
                    "GroupId": "sg-closed",
                    "IpPermissions": [{"IpRanges": [{"CidrIp": "10.0.0.0/16"}]}],
                },
            ]
        }

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_both_verdicts_are_reached_within_one_account(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1"}]
        }
        self._wire(mock_ec2)

        findings = agentcore_app.check_agentcore_vpc_endpoints()
        by_name = {}
        for finding in findings:
            by_name.setdefault(finding["Finding"], []).append(finding)
            assert finding["Check_ID"] == "AC-08"
            assert_finding_schema(finding)

        assert len(by_name["AgentCore VPC Endpoint Policy Unrestricted"]) == 1
        assert len(by_name["AgentCore VPC Endpoint Policy"]) == 1
        assert by_name["AgentCore VPC Endpoint Policy"][0]["Status"] == "Passed"
        assert len(by_name["AgentCore VPC Endpoint Network Scope Unrestricted"]) == 1
        assert by_name["AgentCore VPC Endpoint Network Scope"][0]["Status"] == "Passed"
        # The default-policy endpoint is named, not just counted, so a reader can
        # act on the right one of the two.
        assert (
            "vpce-default"
            in by_name["AgentCore VPC Endpoint Policy Unrestricted"][0][
                "Finding_Details"
            ]
        )
        assert (
            "vpce-scoped"
            in by_name["AgentCore VPC Endpoint Policy"][0]["Finding_Details"]
        )

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_both_open_ranges_are_reported(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1"}]
        }
        self._wire(mock_ec2)

        findings = agentcore_app.check_agentcore_vpc_endpoints()
        open_finding = next(
            finding
            for finding in findings
            if finding["Finding"].endswith("Network Scope Unrestricted")
        )
        assert "0.0.0.0/0" in open_finding["Finding_Details"]
        assert "::/0" in open_finding["Finding_Details"]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_security_group_read_failure_is_na_not_passed(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1"}]
        }
        self._wire(mock_ec2)
        mock_ec2.describe_security_groups.side_effect = Exception("denied")

        findings = agentcore_app.check_agentcore_vpc_endpoints()
        network = [
            finding for finding in findings if "Network Scope" in finding["Finding"]
        ]
        assert len(network) == 2
        assert {finding["Status"] for finding in network} == {"N/A"}

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_endpoints_are_read_from_every_page(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1"}]
        }
        mock_ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
        first, second = self._endpoints()
        mock_ec2.describe_vpc_endpoints.side_effect = [
            {"VpcEndpoints": [first], "NextToken": "page-2"},
            {"VpcEndpoints": [second]},
        ]
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}

        findings = agentcore_app.check_agentcore_vpc_endpoints()

        assert mock_ec2.describe_vpc_endpoints.call_count == 2
        mock_ec2.describe_vpc_endpoints.assert_any_call(NextToken="page-2")
        details = " ".join(finding["Finding_Details"] for finding in findings)
        assert "vpce-default" in details and "vpce-scoped" in details

    def test_the_default_endpoint_document_is_the_only_full_access_shape(self):
        assert agentcore_app._vpc_endpoint_policy_is_full_access(self._DEFAULT_POLICY)
        assert not agentcore_app._vpc_endpoint_policy_is_full_access(
            self._SCOPED_POLICY
        )
        # A conditioned allow-everything statement is a scoping decision.
        assert not agentcore_app._vpc_endpoint_policy_is_full_access(
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "*",
                            "Resource": "*",
                            "Condition": {
                                "StringEquals": {"aws:PrincipalOrgID": "o-1"}
                            },
                        }
                    ]
                }
            )
        )
        assert not agentcore_app._vpc_endpoint_policy_is_full_access("not json")
        assert not agentcore_app._vpc_endpoint_policy_is_full_access(None)


class TestAC24GatewayRateLimiting:
    """AC-24: an active rate limit that bounds a throughput value."""

    _GATEWAYS = [
        {"gatewayId": "gw-bounded", "name": "Bounded"},
        {"gatewayId": "gw-none", "name": "Unbounded"},
        {"gatewayId": "gw-creating", "name": "Creating"},
    ]

    def _rate_limits(self, gatewayIdentifier, **kwargs):
        if gatewayIdentifier == "gw-bounded":
            return {
                "rateLimits": [
                    {
                        "rateLimitId": "rl-1",
                        "status": "ACTIVE",
                        "dimensionKeys": ["$.context.iam.principal"],
                        "entries": [{"requests": [{"rate": 100, "period": "MINUTE"}]}],
                    }
                ]
            }
        if gatewayIdentifier == "gw-creating":
            return {
                "rateLimits": [
                    {
                        "rateLimitId": "rl-2",
                        "status": "CREATING",
                        "dimensionKeys": ["$.context.iam.principal"],
                        "entries": [{"requests": [{"rate": 100, "period": "MINUTE"}]}],
                    }
                ]
            }
        return {"rateLimits": []}

    @patch("agentcore_app.agentcore_client")
    def test_each_gateway_gets_its_own_verdict(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.list_gateway_rate_limits.side_effect = self._rate_limits

        findings = agentcore_app.check_agentcore_gateway_rate_limiting()

        assert len(findings) == 3
        by_gateway = {}
        for finding in findings:
            assert finding["Check_ID"] == "AC-24"
            assert_finding_schema(finding)
            for gateway in self._GATEWAYS:
                if gateway["gatewayId"] in finding["Finding_Details"]:
                    by_gateway[gateway["gatewayId"]] = finding
        assert by_gateway["gw-bounded"]["Status"] == "Passed"
        assert by_gateway["gw-none"]["Status"] == "Failed"
        assert by_gateway["gw-none"]["Finding"].endswith("Missing")
        assert by_gateway["gw-creating"]["Status"] == "Failed"
        assert by_gateway["gw-creating"]["Finding"].endswith("Ineffective")

    @patch("agentcore_app.agentcore_client")
    def test_a_limit_with_no_bounded_value_is_not_a_limit(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.list_gateway_rate_limits.return_value = {
            "rateLimits": [
                {
                    "rateLimitId": "rl-3",
                    "status": "ACTIVE",
                    "dimensionKeys": ["$.context.iam.principal"],
                    "entries": [{}],
                }
            ]
        }

        findings = agentcore_app.check_agentcore_gateway_rate_limiting()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Ineffective")

    @patch("agentcore_app.agentcore_client")
    def test_the_passed_detail_names_the_rate_and_the_dimension(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.list_gateway_rate_limits.side_effect = self._rate_limits

        findings = agentcore_app.check_agentcore_gateway_rate_limiting()

        assert "100 requests per MINUTE" in findings[0]["Finding_Details"]
        assert "$.context.iam.principal" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_rate_limits_are_read_from_every_page(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.list_gateway_rate_limits.side_effect = [
            {"rateLimits": [], "nextToken": "rl-page-2"},
            {
                "rateLimits": [
                    {
                        "rateLimitId": "rl-4",
                        "status": "ACTIVE",
                        "entries": [{"tokens": [{"rate": 5, "period": "HOUR"}]}],
                    }
                ]
            },
        ]

        findings = agentcore_app.check_agentcore_gateway_rate_limiting()

        assert findings[0]["Status"] == "Passed"
        assert mock_ac.list_gateway_rate_limits.call_count == 2

    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_gateway_does_not_hide_the_others(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS[:2]}

        def rate_limits(gatewayIdentifier, **kwargs):
            if gatewayIdentifier == "gw-bounded":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "ListGatewayRateLimits",
                )
            return {"rateLimits": []}

        mock_ac.list_gateway_rate_limits.side_effect = rate_limits

        findings = agentcore_app.check_agentcore_gateway_rate_limiting()

        assert {finding["Status"] for finding in findings} == {"N/A", "Failed"}
        assert len(findings) == 2

    @patch("agentcore_app.agentcore_client")
    def test_no_gateways_is_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        findings = agentcore_app.check_agentcore_gateway_rate_limiting()
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_gateway_rate_limiting()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-24"


class TestAC25GatewayTargetAuthorization:
    """AC-25: every gateway target declares an outbound credential provider."""

    @patch("agentcore_app.agentcore_client")
    def test_each_target_gets_its_own_verdict(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "One"}]
        }
        mock_ac.list_gateway_targets.return_value = {
            "items": [
                {"targetId": "t-auth", "name": "Authenticated"},
                {"targetId": "t-open", "name": "Open"},
            ]
        }

        def detail(gatewayIdentifier, targetId):
            if targetId == "t-auth":
                return {
                    "credentialProviderConfigurations": [
                        {"credentialProviderType": "GATEWAY_IAM_ROLE"}
                    ]
                }
            return {}

        mock_ac.get_gateway_target.side_effect = detail

        findings = agentcore_app.check_agentcore_gateway_target_authorization()

        assert len(findings) == 2
        by_status = {finding["Status"]: finding for finding in findings}
        assert by_status["Passed"]["Finding_Details"].count("GATEWAY_IAM_ROLE") == 1
        assert "t-open" in by_status["Failed"]["Finding_Details"]
        assert by_status["Failed"]["Severity"] == "High"
        for finding in findings:
            assert finding["Check_ID"] == "AC-25"
            assert_finding_schema(finding)

    @patch("agentcore_app.agentcore_client")
    def test_targets_are_read_from_every_page(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "One"}]
        }
        mock_ac.list_gateway_targets.side_effect = [
            {"items": [], "nextToken": "t-page-2"},
            {"items": [{"targetId": "t-2", "name": "Second"}]},
        ]
        mock_ac.get_gateway_target.return_value = {}

        findings = agentcore_app.check_agentcore_gateway_target_authorization()

        assert len(findings) == 1
        assert mock_ac.list_gateway_targets.call_count == 2

    @patch("agentcore_app.agentcore_client")
    def test_a_gateway_with_no_target_does_not_read_as_compliant(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "One"}]
        }
        mock_ac.list_gateway_targets.return_value = {"items": []}

        findings = agentcore_app.check_agentcore_gateway_target_authorization()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_an_unreadable_target_is_na_not_failed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "One"}]
        }
        mock_ac.list_gateway_targets.return_value = {
            "items": [{"targetId": "t-1", "name": "One"}]
        }
        mock_ac.get_gateway_target.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "GetGatewayTarget",
        )

        findings = agentcore_app.check_agentcore_gateway_target_authorization()

        assert findings[0]["Status"] == "N/A"
        assert "GetGatewayTarget" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_gateway_target_authorization()
        assert findings[0]["Check_ID"] == "AC-25"
        assert findings[0]["Status"] == "N/A"


class TestAC26LogRetentionAndKeyScope:
    """AC-26: retention on every AgentCore log group, scoped key policy on its CMK."""

    _KEY = "arn:aws:kms:us-east-1:123456789012:key/k1"
    _SCOPED_KEY_POLICY = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
                    "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                    "Resource": "*",
                }
            ]
        }
    )
    _OPEN_KEY_POLICY = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ]
        }
    )

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.logs_client")
    def test_retention_verdicts_are_per_log_group(self, mock_logs, mock_kms):
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1",
                        "retentionInDays": 90,
                    },
                    {"logGroupName": "/aws/bedrock-agentcore/runtimes/rt-2"},
                ]
            }
        )

        findings = agentcore_app.check_agentcore_log_retention_and_key_scope()

        assert len(findings) == 2
        statuses = {
            finding["Finding_Details"].split("'")[1]: finding["Status"]
            for finding in findings
        }
        assert statuses["/aws/bedrock-agentcore/runtimes/rt-1"] == "Passed"
        assert statuses["/aws/bedrock-agentcore/runtimes/rt-2"] == "Failed"
        for finding in findings:
            assert finding["Check_ID"] == "AC-26"
            assert_finding_schema(finding)

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.logs_client")
    def test_an_open_key_policy_fails_a_retained_log_group(self, mock_logs, mock_kms):
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1",
                        "retentionInDays": 90,
                        "kmsKeyId": self._KEY,
                    }
                ]
            }
        )
        mock_kms.get_key_policy.return_value = {"Policy": self._OPEN_KEY_POLICY}

        findings = agentcore_app.check_agentcore_log_retention_and_key_scope()

        assert findings[0]["Status"] == "Failed"
        assert "every principal to decrypt" in findings[0]["Finding_Details"]

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.logs_client")
    def test_a_scoped_key_policy_passes_and_is_read_once_per_key(
        self, mock_logs, mock_kms
    ):
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1",
                        "retentionInDays": 30,
                        "kmsKeyId": self._KEY,
                    },
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-2",
                        "retentionInDays": 30,
                        "kmsKeyId": self._KEY,
                    },
                ]
            }
        )
        mock_kms.get_key_policy.return_value = {"Policy": self._SCOPED_KEY_POLICY}

        findings = agentcore_app.check_agentcore_log_retention_and_key_scope()

        assert [finding["Status"] for finding in findings] == ["Passed", "Passed"]
        assert mock_kms.get_key_policy.call_count == 1

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.logs_client")
    def test_an_unreadable_key_policy_is_na_beside_the_retention_verdict(
        self, mock_logs, mock_kms
    ):
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect(
            {
                "/aws/bedrock-agentcore/": [
                    {
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/rt-1",
                        "retentionInDays": 30,
                        "kmsKeyId": self._KEY,
                    }
                ]
            }
        )
        mock_kms.get_key_policy.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "GetKeyPolicy",
        )

        findings = agentcore_app.check_agentcore_log_retention_and_key_scope()

        statuses = sorted(finding["Status"] for finding in findings)
        assert statuses == ["N/A", "Passed"]
        na = next(finding for finding in findings if finding["Status"] == "N/A")
        assert "kms:GetKeyPolicy" in na["Resolution"]

    def test_the_open_decrypt_predicate_discriminates(self):
        assert agentcore_app._kms_key_policy_allows_open_decrypt(self._OPEN_KEY_POLICY)
        assert not agentcore_app._kms_key_policy_allows_open_decrypt(
            self._SCOPED_KEY_POLICY
        )
        # A wildcard action reaches Decrypt, and a wildcard within the namespace
        # does too.
        for actions in ("*", "kms:*", "kms:Decry*"):
            assert agentcore_app._kms_key_policy_allows_open_decrypt(
                json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "*"},
                                "Action": actions,
                                "Resource": "*",
                            }
                        ]
                    }
                )
            )
        # A non-decrypt action to everybody is a different control's problem.
        assert not agentcore_app._kms_key_policy_allows_open_decrypt(
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "kms:DescribeKey",
                            "Resource": "*",
                        }
                    ]
                }
            )
        )
        # A condition on the wildcard principal is the scoping this asks for.
        assert not agentcore_app._kms_key_policy_allows_open_decrypt(
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "kms:Decrypt",
                            "Resource": "*",
                            "Condition": {
                                "StringEquals": {
                                    "kms:ViaService": "logs.us-east-1.amazonaws.com"
                                }
                            },
                        }
                    ]
                }
            )
        )
        assert not agentcore_app._kms_key_policy_allows_open_decrypt("")

    @patch("agentcore_app.logs_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_log_retention_and_key_scope()
        assert findings[0]["Check_ID"] == "AC-26"
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.logs_client")
    def test_no_log_groups_is_na(self, mock_logs, mock_kms):
        mock_logs.describe_log_groups.side_effect = _log_group_side_effect({})
        findings = agentcore_app.check_agentcore_log_retention_and_key_scope()
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"


class TestAC27GatewayPolicyConditions:
    """AC-27: confused-deputy and network-path conditions on gateway policies."""

    _GUARDED_RESOURCE_POLICY = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                    "Action": "bedrock-agentcore:InvokeGateway",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": "123456789012",
                            "aws:SourceVpce": "vpce-1",
                        }
                    },
                }
            ]
        }
    )
    _UNGUARDED_RESOURCE_POLICY = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                    "Action": "bedrock-agentcore:InvokeGateway",
                    "Resource": "*",
                }
            ]
        }
    )

    def _wire(self, mock_ac, mock_iam):
        mock_ac.list_gateways.return_value = {
            "items": [
                {"gatewayId": "gw-guarded", "name": "Guarded"},
                {"gatewayId": "gw-open", "name": "Open"},
            ]
        }

        def get_gateway(gatewayIdentifier):
            return {
                "gatewayArn": f"arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/{gatewayIdentifier}",
                "roleArn": (
                    "arn:aws:iam::123456789012:role/GuardedRole"
                    if gatewayIdentifier == "gw-guarded"
                    else "arn:aws:iam::123456789012:role/OpenRole"
                ),
            }

        mock_ac.get_gateway.side_effect = get_gateway

        def get_resource_policy(resourceArn):
            if resourceArn.endswith("gw-guarded"):
                return {"policy": self._GUARDED_RESOURCE_POLICY}
            return {"policy": self._UNGUARDED_RESOURCE_POLICY}

        mock_ac.get_resource_policy.side_effect = get_resource_policy

        def get_role(RoleName):
            document = _GUARDED_TRUST if RoleName == "GuardedRole" else _UNGUARDED_TRUST
            return {"Role": {"AssumeRolePolicyDocument": document}}

        mock_iam.get_role.side_effect = get_role

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_both_verdicts_are_reached_on_all_three_legs(self, mock_ac, mock_iam):
        self._wire(mock_ac, mock_iam)

        findings = agentcore_app.check_agentcore_gateway_policy_conditions()

        # Three legs per gateway, two gateways.
        assert len(findings) == 6
        for finding in findings:
            assert finding["Check_ID"] == "AC-27"
            assert_finding_schema(finding)

        guarded = [f for f in findings if "gw-guarded" in f["Finding_Details"]]
        opened = [f for f in findings if "gw-open" in f["Finding_Details"]]
        assert {f["Status"] for f in guarded} == {"Passed"}
        assert {f["Status"] for f in opened} == {"Failed"}

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_guarded_statement_does_not_excuse_an_unguarded_sibling(
        self, mock_ac, mock_iam
    ):
        self._wire(mock_ac, mock_iam)

        findings = agentcore_app.check_agentcore_gateway_policy_conditions()
        trust = next(
            finding
            for finding in findings
            if "Role Trust" in finding["Finding"]
            and "OpenRole" in finding["Finding_Details"]
        )
        assert trust["Status"] == "Failed"
        assert "1 of 2 Allow statement(s)" in trust["Finding_Details"]

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_one_role_is_read_once_for_two_gateways(self, mock_ac, mock_iam):
        mock_ac.list_gateways.return_value = {
            "items": [
                {"gatewayId": "gw-1", "name": "One"},
                {"gatewayId": "gw-2", "name": "Two"},
            ]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw",
            "roleArn": "arn:aws:iam::123456789012:role/Shared",
        }
        mock_ac.get_resource_policy.return_value = {
            "policy": self._GUARDED_RESOURCE_POLICY
        }
        mock_iam.get_role.return_value = {
            "Role": {"AssumeRolePolicyDocument": _GUARDED_TRUST}
        }

        findings = agentcore_app.check_agentcore_gateway_policy_conditions()

        assert len(findings) == 6
        assert mock_iam.get_role.call_count == 1

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_gateway_without_a_resource_policy_is_na_on_that_leg_only(
        self, mock_ac, mock_iam
    ):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "One"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1",
            "roleArn": "arn:aws:iam::123456789012:role/GuardedRole",
        }
        mock_ac.get_resource_policy.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "none"}},
            "GetResourcePolicy",
        )
        mock_iam.get_role.return_value = {
            "Role": {"AssumeRolePolicyDocument": _GUARDED_TRUST}
        }

        findings = agentcore_app.check_agentcore_gateway_policy_conditions()

        statuses = {finding["Finding"]: finding["Status"] for finding in findings}
        assert (
            statuses["AgentCore Gateway Resource Policy Confused Deputy Guard"] == "N/A"
        )
        # No resource policy still means no network restriction.
        assert statuses["AgentCore Gateway Network Path Unrestricted"] == "Failed"
        assert (
            statuses["AgentCore Gateway Role Trust Confused Deputy Guard"] == "Passed"
        )

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_unreadable_trust_policy_is_na_not_passed(self, mock_ac, mock_iam):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "One"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1",
            "roleArn": "arn:aws:iam::123456789012:role/Hidden",
        }
        mock_ac.get_resource_policy.return_value = {
            "policy": self._GUARDED_RESOURCE_POLICY
        }
        mock_iam.get_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetRole"
        )

        findings = agentcore_app.check_agentcore_gateway_policy_conditions()
        trust = next(
            finding for finding in findings if "Role Trust" in finding["Finding"]
        )
        assert trust["Status"] == "N/A"
        assert "iam:GetRole" in trust["Resolution"]

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_gateways_are_read_from_every_page(self, mock_ac, mock_iam):
        mock_ac.list_gateways.side_effect = [
            {"items": [], "nextToken": "gw-page-2"},
            {"items": [{"gatewayId": "gw-2", "name": "Two"}]},
        ]
        mock_ac.get_gateway.return_value = {
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-2",
            "roleArn": "arn:aws:iam::123456789012:role/GuardedRole",
        }
        mock_ac.get_resource_policy.return_value = {
            "policy": self._GUARDED_RESOURCE_POLICY
        }
        mock_iam.get_role.return_value = {
            "Role": {"AssumeRolePolicyDocument": _GUARDED_TRUST}
        }

        findings = agentcore_app.check_agentcore_gateway_policy_conditions()

        assert len(findings) == 3
        assert mock_ac.list_gateways.call_count == 2

    def test_the_confused_deputy_predicate_only_fires_on_borrowed_principals(self):
        exposed = agentcore_app._statement_is_confused_deputy_exposed
        assert exposed(
            {
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        )
        assert exposed({"Principal": "*", "Action": "sts:AssumeRole"})
        assert exposed({"Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})
        # aws:SourceArn alone is enough; the two keys are alternatives.
        assert not exposed(
            {
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:*"}},
            }
        )
        # A named account principal is a trust the account owner wrote down.
        assert not exposed(
            {
                "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                "Action": "sts:AssumeRole",
            }
        )
        assert not exposed({"Action": "sts:AssumeRole"})

    @patch("agentcore_app.agentcore_client")
    def test_no_gateways_is_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        findings = agentcore_app.check_agentcore_gateway_policy_conditions()
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_gateway_policy_conditions()
        assert findings[0]["Check_ID"] == "AC-27"
        assert findings[0]["Status"] == "N/A"


def _scp(statements):
    """Return an Organizations DescribePolicy response body for one SCP."""
    return {
        "Policy": {
            "Content": json.dumps({"Version": "2012-10-17", "Statement": statements})
        }
    }


_GATEWAY_WRITE = ["bedrock-agentcore:CreateGateway", "bedrock-agentcore:UpdateGateway"]


class TestAC28GatewayAuthorizerSCP:
    """AC-28: an SCP has to deny gateway writes when the authorizer type is NONE."""

    def _wire(self, mock_orgs, documents):
        """Serve one named SCP per entry in `documents`."""
        mock_orgs.list_policies.return_value = {
            "Policies": [
                {"Id": f"p-{index}", "Name": name}
                for index, name in enumerate(documents)
            ]
        }
        by_id = {
            f"p-{index}": statements
            for index, statements in enumerate(documents.values())
        }

        def describe_policy(PolicyId):
            return _scp(by_id[PolicyId])

        mock_orgs.describe_policy.side_effect = describe_policy

    @patch("agentcore_app.organizations_client")
    def test_an_equals_deny_on_both_writes_passes(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "DenyOpenGateway": [
                    {
                        "Effect": "Deny",
                        "Action": _GATEWAY_WRITE,
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-28"
        assert findings[0]["Status"] == "Passed"
        assert "DenyOpenGateway" in findings[0]["Finding_Details"]
        assert "attachment targets" in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.organizations_client")
    def test_a_not_equals_allow_list_that_omits_none_passes(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "RequireApprovedAuthorizer": [
                    {
                        "Effect": "Deny",
                        "Action": _GATEWAY_WRITE,
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": [
                                    "AWS_IAM",
                                    "CUSTOM_JWT",
                                ]
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.organizations_client")
    def test_a_not_equals_list_that_includes_none_leaves_none_allowed(self, mock_orgs):
        # StringNotEquals NONE denies every authorizer type except NONE, which is
        # the opposite of the control. A check that only looked for the key and
        # the two actions would call this compliant.
        self._wire(
            mock_orgs,
            {
                "Inverted": [
                    {
                        "Effect": "Deny",
                        "Action": _GATEWAY_WRITE,
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Ineffective")

    @patch("agentcore_app.organizations_client")
    def test_a_deny_on_create_only_is_reported_as_partial(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "CreateOnly": [
                    {
                        "Effect": "Deny",
                        "Action": "bedrock-agentcore:CreateGateway",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Partial")
        assert "CreateGateway" in findings[0]["Finding_Details"]
        assert "UpdateGateway" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_a_null_condition_is_reported_as_ineffective(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "NullTest": [
                    {
                        "Effect": "Deny",
                        "Action": _GATEWAY_WRITE,
                        "Resource": "*",
                        "Condition": {
                            "Null": {"bedrock-agentcore:GatewayAuthorizerType": "true"}
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Ineffective")
        assert "required member" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_an_organization_with_no_matching_policy_is_reported_missing(
        self, mock_orgs
    ):
        self._wire(
            mock_orgs,
            {
                "FullAWSAccess": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                "DenyOtherThings": [
                    {
                        "Effect": "Deny",
                        "Action": "s3:DeleteBucket",
                        "Resource": "*",
                    }
                ],
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Missing")
        assert "2 service control policy(s)" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_an_allow_statement_carrying_the_condition_is_not_coverage(self, mock_orgs):
        # Only a Deny prevents the call; an Allow with the same condition is the
        # SCP allow-list half and blocks nothing on its own.
        self._wire(
            mock_orgs,
            {
                "AllowShaped": [
                    {
                        "Effect": "Allow",
                        "Action": _GATEWAY_WRITE,
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Missing")

    @patch("agentcore_app.organizations_client")
    def test_a_deny_of_all_but_a_read_allow_list_covers_both_writes(self, mock_orgs):
        # A Deny written with NotAction denies everything the list omits, so a
        # gateway write absent from the exclusions is denied under the
        # condition as surely as if it had been named in Action.
        self._wire(
            mock_orgs,
            {
                "DenyAllButReads": [
                    {
                        "Effect": "Deny",
                        "NotAction": ["bedrock-agentcore:GetGateway"],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Passed"
        assert "DenyAllButReads" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_a_not_action_that_exempts_the_writes_is_not_coverage(self, mock_orgs):
        # The same shape with the writes inside NotAction exempts them from the
        # Deny, which is the opposite outcome from the same policy grammar.
        self._wire(
            mock_orgs,
            {
                "DenyAllButTheWrites": [
                    {
                        "Effect": "Deny",
                        "NotAction": [
                            "bedrock-agentcore:CreateGateway",
                            "bedrock-agentcore:UpdateGateway",
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Ineffective")

    @patch("agentcore_app.organizations_client")
    def test_a_not_action_wildcard_over_the_namespace_is_not_coverage(self, mock_orgs):
        # A namespace wildcard in NotAction exempts every gateway write.
        self._wire(
            mock_orgs,
            {
                "DenyAllButAgentCore": [
                    {
                        "Effect": "Deny",
                        "NotAction": ["bedrock-agentcore:*"],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Ineffective")

    @patch("agentcore_app.organizations_client")
    def test_a_statement_naming_neither_action_key_is_not_coverage(self, mock_orgs):
        # A Deny with no Action and no NotAction reaches nothing, however
        # exactly its condition describes the authorizer type.
        self._wire(
            mock_orgs,
            {
                "ConditionOnly": [
                    {
                        "Effect": "Deny",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Ineffective")

    @patch("agentcore_app.organizations_client")
    def test_a_wildcard_action_covers_both_writes(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "WildcardShaped": [
                    {
                        "Effect": "Deny",
                        "Action": "bedrock-agentcore:*Gateway",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.organizations_client")
    def test_the_key_name_is_matched_case_insensitively(self, mock_orgs):
        # IAM condition key names are not case-sensitive, so a lower-cased
        # spelling in the policy document is the same control.
        self._wire(
            mock_orgs,
            {
                "LowerCased": [
                    {
                        "Effect": "Deny",
                        "Action": _GATEWAY_WRITE,
                        "Resource": "*",
                        "Condition": {
                            "ForAnyValue:StringEquals": {
                                "bedrock-agentcore:gatewayauthorizertype": "none"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.organizations_client")
    def test_two_policies_together_cover_both_writes(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "DenyCreate": [
                    {
                        "Effect": "Deny",
                        "Action": "bedrock-agentcore:CreateGateway",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ],
                "DenyUpdate": [
                    {
                        "Effect": "Deny",
                        "Action": "bedrock-agentcore:UpdateGateway",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ],
            },
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Passed"
        assert "DenyCreate, DenyUpdate" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_policies_are_read_from_every_page(self, mock_orgs):
        mock_orgs.list_policies.side_effect = [
            {"Policies": [{"Id": "p-1", "Name": "First"}], "NextToken": "page-2"},
            {"Policies": [{"Id": "p-2", "Name": "Second"}]},
        ]
        mock_orgs.describe_policy.return_value = _scp(
            [
                {
                    "Effect": "Deny",
                    "Action": _GATEWAY_WRITE,
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                        }
                    },
                }
            ]
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert mock_orgs.list_policies.call_count == 2
        assert findings[0]["Status"] == "Passed"
        assert "First, Second" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_a_member_account_denial_reads_na(self, mock_orgs):
        mock_orgs.list_policies.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListPolicies",
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Check_ID"] == "AC-28"
        assert findings[0]["Status"] == "N/A"
        assert "AccessDeniedException" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_an_account_outside_an_organization_reads_na(self, mock_orgs):
        mock_orgs.list_policies.side_effect = ClientError(
            {"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "no"}},
            "ListPolicies",
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.organizations_client")
    def test_a_throttled_list_is_incomplete_not_failed(self, mock_orgs):
        mock_orgs.list_policies.side_effect = ClientError(
            {"Error": {"Code": "TooManyRequestsException", "Message": "slow down"}},
            "ListPolicies",
        )

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding"].endswith("Incomplete")

    @patch("agentcore_app.organizations_client")
    def test_one_unreadable_policy_does_not_hide_the_population_verdict(
        self, mock_orgs
    ):
        mock_orgs.list_policies.return_value = {
            "Policies": [
                {"Id": "p-1", "Name": "Unreadable"},
                {"Id": "p-2", "Name": "DenyOpenGateway"},
            ]
        }

        def describe_policy(PolicyId):
            if PolicyId == "p-1":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "DescribePolicy",
                )
            return _scp(
                [
                    {
                        "Effect": "Deny",
                        "Action": _GATEWAY_WRITE,
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            )

        mock_orgs.describe_policy.side_effect = describe_policy

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert len(findings) == 2
        assert findings[0]["Status"] == "N/A"
        assert "Unreadable" in findings[0]["Finding_Details"]
        assert findings[1]["Status"] == "Passed"
        for finding in findings:
            assert_finding_schema(finding)

    @patch("agentcore_app.organizations_client")
    def test_a_policy_that_is_not_json_does_not_stop_the_check(self, mock_orgs):
        mock_orgs.list_policies.return_value = {
            "Policies": [{"Id": "p-1", "Name": "Corrupt"}]
        }
        mock_orgs.describe_policy.return_value = {"Policy": {"Content": "not json"}}

        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Missing")

    @patch("agentcore_app.organizations_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_gateway_authorizer_scp()
        assert findings[0]["Check_ID"] == "AC-28"
        assert findings[0]["Status"] == "N/A"


class TestGatewayCheckRegistration:
    """AC-24..AC-27 must reach the backfill paths, and the API must answer them."""

    def test_regional_ids_are_registered_for_timeout_backfill(self):
        for check_id in ("AC-24", "AC-25", "AC-26", "AC-27"):
            assert check_id in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
            assert check_id in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_timeout_backfill_emits_the_new_regional_ids(self):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        emitted = {finding["Check_ID"] for finding in findings}
        assert {"AC-24", "AC-25", "AC-26", "AC-27"}.issubset(emitted)

    def test_gateway_operation_contracts_exist(self):
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        expected = {
            "bedrock-agentcore-control": [
                "ListGatewayRateLimits",
                "ListGatewayTargets",
                "GetGatewayTarget",
                "GetGateway",
            ],
            "ec2": ["DescribeSecurityGroups", "DescribeVpcEndpoints"],
            "kms": ["GetKeyPolicy"],
            "iam": ["GetRole"],
        }
        for service, operations in expected.items():
            model = agentcore_app.boto3.client(
                service, **credentials
            ).meta.service_model
            for operation in operations:
                assert model.operation_model(operation)

    def test_the_rate_limit_value_keys_are_the_ones_the_api_models(self):
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control", **credentials
        ).meta.service_model
        output = model.operation_model("ListGatewayRateLimits").output_shape
        entry = output.members["rateLimits"].member.members["entries"].member
        assert set(agentcore_app.GATEWAY_RATE_LIMIT_VALUE_KEYS) <= set(entry.members)
        # dimensions is the only required member, which is why presence of an
        # entry cannot stand in for a bounded value.
        assert entry.required_members == ["dimensions"]

    def test_the_credential_provider_types_are_the_modelled_enum(self):
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control", **credentials
        ).meta.service_model
        output = model.operation_model("GetGatewayTarget").output_shape
        configuration = output.members["credentialProviderConfigurations"].member
        provider_type = configuration.members["credentialProviderType"]
        assert set(agentcore_app.GATEWAY_TARGET_CREDENTIAL_PROVIDER_TYPES) == set(
            provider_type.enum
        )


class TestAC28CheckRegistration:
    """AC-28 is organization-wide, so it runs once and not per scanned region."""

    def test_the_scp_check_is_not_in_the_regional_tuples(self):
        assert "AC-28" not in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-28" not in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_the_handler_registers_the_scp_check_on_both_cache_paths(self):
        # The check reads Organizations and not the IAM permission cache, so a
        # missing cache must not skip it. Without this assertion the check can
        # exist, pass its own tests, and never run.
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        registrations = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "global_checks"
                for target in node.targets
            )
        ]
        assert len(registrations) == 2
        for registration in registrations:
            assert "check_agentcore_gateway_authorizer_scp" in ast.unparse(
                registration.value
            )

    def test_the_organizations_operation_contracts_exist(self):
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        model = agentcore_app.boto3.client(
            "organizations", **credentials
        ).meta.service_model
        list_policies = model.operation_model("ListPolicies")
        assert list_policies.input_shape.required_members == ["Filter"]
        assert "SERVICE_CONTROL_POLICY" in (
            list_policies.input_shape.members["Filter"].enum
        )
        assert "NextToken" in list_policies.input_shape.members
        assert "NextToken" in list_policies.output_shape.members
        assert "Content" in (
            model.operation_model("DescribePolicy")
            .output_shape.members["Policy"]
            .members
        )

    def test_the_authorizer_type_is_a_required_member_of_create_gateway(self):
        # This is what makes a Null condition on the key inert, which AC-28
        # reports as an ineffective guardrail rather than as coverage.
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control", **credentials
        ).meta.service_model
        create_gateway = model.operation_model("CreateGateway").input_shape
        assert "authorizerType" in create_gateway.required_members
        enum = create_gateway.members["authorizerType"].enum
        assert agentcore_app.GATEWAY_AUTHORIZER_UNAUTHENTICATED_VALUE in enum

    def test_organizations_resolves_to_one_global_endpoint(self):
        # The handler builds this client without a region because Organizations
        # answers from a single endpoint; a region-scoped client would read the
        # same policies twice under a multi-region scan.
        credentials = {
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        endpoints = {
            agentcore_app.boto3.client(
                "organizations", region_name=region, **credentials
            ).meta.endpoint_url
            for region in ("us-east-1", "us-west-2", "eu-west-1")
        }
        assert len(endpoints) == 1


_RUNTIME_WRITE = [
    "bedrock-agentcore:CreateAgentRuntime",
    "bedrock-agentcore:UpdateAgentRuntime",
]
_RUNTIME_KEY = "bedrock-agentcore:RuntimeAuthorizerType"


class TestAC29RuntimeAuthorizerSCP:
    """AC-29: an SCP has to deny runtime writes when the authorizer is AWS_IAM."""

    def _wire(self, mock_orgs, documents):
        """Serve one named SCP per entry in `documents`."""
        mock_orgs.list_policies.return_value = {
            "Policies": [
                {"Id": f"p-{index}", "Name": name}
                for index, name in enumerate(documents)
            ]
        }
        by_id = {
            f"p-{index}": statements
            for index, statements in enumerate(documents.values())
        }

        def describe_policy(PolicyId):
            return _scp(by_id[PolicyId])

        mock_orgs.describe_policy.side_effect = describe_policy

    @patch("agentcore_app.organizations_client")
    def test_an_equals_deny_on_both_writes_passes(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "DenySigV4Runtime": [
                    {
                        "Effect": "Deny",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: "AWS_IAM"}},
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-29"
        assert findings[0]["Status"] == "Passed"
        assert "DenySigV4Runtime" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_a_not_equals_allow_list_that_omits_aws_iam_passes(self, mock_orgs):
        # Deny unless the authorizer type is CUSTOM_JWT denies AWS_IAM, which is
        # the same guardrail written from the approved side.
        self._wire(
            mock_orgs,
            {
                "OnlyJwtRuntimes": [
                    {
                        "Effect": "Deny",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {"StringNotEquals": {_RUNTIME_KEY: "CUSTOM_JWT"}},
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.organizations_client")
    def test_a_deny_on_create_alone_is_partial(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "DenyCreateOnly": [
                    {
                        "Effect": "Deny",
                        "Action": ["bedrock-agentcore:CreateAgentRuntime"],
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: "AWS_IAM"}},
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Partial")
        assert "UpdateAgentRuntime" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_a_deny_of_the_jwt_mode_is_reported_as_inverted(self, mock_orgs):
        # The guardrail exists, conditions on the right key, and forbids the one
        # mode that proves the end user's identity.
        self._wire(
            mock_orgs,
            {
                "NoJwtRuntimes": [
                    {
                        "Effect": "Deny",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: "CUSTOM_JWT"}},
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Inverted")
        assert "NoJwtRuntimes" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_a_not_equals_on_aws_iam_is_reported_as_inverted(self, mock_orgs):
        # Deny unless the authorizer type is AWS_IAM admits only SigV4, the
        # inverse of the intended guardrail written from the approved side.
        self._wire(
            mock_orgs,
            {
                "OnlySigV4Runtimes": [
                    {
                        "Effect": "Deny",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {"StringNotEquals": {_RUNTIME_KEY: "AWS_IAM"}},
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Inverted")

    @patch("agentcore_app.organizations_client")
    def test_a_policy_denying_both_modes_still_passes(self, mock_orgs):
        # A blanket prohibition on runtimes does prevent the SigV4 deployment
        # this control is about, so it earns the pass and the detail names the
        # policy for a reader who wants to know the JWT mode is blocked too.
        self._wire(
            mock_orgs,
            {
                "NoRuntimesAtAll": [
                    {
                        "Effect": "Deny",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {_RUNTIME_KEY: ["AWS_IAM", "CUSTOM_JWT"]}
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.organizations_client")
    def test_a_null_condition_is_reported_as_ineffective(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "NullTest": [
                    {
                        "Effect": "Deny",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {"Null": {_RUNTIME_KEY: "true"}},
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Ineffective")

    @patch("agentcore_app.organizations_client")
    def test_an_allow_carrying_the_condition_is_not_coverage(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "AllowShaped": [
                    {
                        "Effect": "Allow",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: "AWS_IAM"}},
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Missing")

    @patch("agentcore_app.organizations_client")
    def test_the_gateway_key_does_not_satisfy_the_runtime_control(self, mock_orgs):
        # AC-28's guardrail is a different key on different actions. Without this
        # a gateway SCP would close the runtime row for free.
        self._wire(
            mock_orgs,
            {
                "DenyOpenGateway": [
                    {
                        "Effect": "Deny",
                        "Action": _GATEWAY_WRITE,
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "bedrock-agentcore:GatewayAuthorizerType": "NONE"
                            }
                        },
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Missing")

    @patch("agentcore_app.organizations_client")
    def test_a_wildcard_action_covers_both_writes(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "DenyAllAgentCore": [
                    {
                        "Effect": "Deny",
                        "Action": "bedrock-agentcore:*",
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: "AWS_IAM"}},
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.organizations_client")
    def test_two_policies_can_cover_one_write_each(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "DenyCreate": [
                    {
                        "Effect": "Deny",
                        "Action": ["bedrock-agentcore:CreateAgentRuntime"],
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: "AWS_IAM"}},
                    }
                ],
                "DenyUpdate": [
                    {
                        "Effect": "Deny",
                        "Action": ["bedrock-agentcore:UpdateAgentRuntime"],
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: "AWS_IAM"}},
                    }
                ],
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Passed"
        assert "DenyCreate, DenyUpdate" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_the_value_match_ignores_case_and_padding(self, mock_orgs):
        self._wire(
            mock_orgs,
            {
                "LowerCaseValue": [
                    {
                        "Effect": "Deny",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: " aws_iam "}},
                    }
                ]
            },
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.organizations_client")
    def test_policies_are_read_from_every_page(self, mock_orgs):
        # The guardrail sits on the second page, so an unpaginated read reports
        # the organization as unguarded.
        mock_orgs.list_policies.side_effect = [
            {"Policies": [{"Id": "p-1", "Name": "Unrelated"}], "NextToken": "page-2"},
            {"Policies": [{"Id": "p-2", "Name": "DenySigV4Runtime"}]},
        ]

        def describe_policy(PolicyId):
            if PolicyId == "p-1":
                return _scp([{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}])
            return _scp(
                [
                    {
                        "Effect": "Deny",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: "AWS_IAM"}},
                    }
                ]
            )

        mock_orgs.describe_policy.side_effect = describe_policy

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert mock_orgs.list_policies.call_count == 2
        assert mock_orgs.list_policies.call_args_list[1].kwargs["NextToken"] == "page-2"
        assert findings[0]["Status"] == "Passed"
        assert "DenySigV4Runtime" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_no_policies_at_all_fails_as_missing(self, mock_orgs):
        mock_orgs.list_policies.return_value = {"Policies": []}

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Missing")

    @patch("agentcore_app.organizations_client", None)
    def test_a_missing_client_is_not_applicable(self):
        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Check_ID"] == "AC-29"
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.organizations_client")
    def test_a_member_account_denial_is_not_applicable(self, mock_orgs):
        mock_orgs.list_policies.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListPolicies",
        )

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert findings[0]["Status"] == "N/A"
        assert "member" in findings[0]["Finding_Details"]

    @patch("agentcore_app.organizations_client")
    def test_an_unreadable_single_policy_is_reported_and_the_rest_judged(
        self, mock_orgs
    ):
        mock_orgs.list_policies.return_value = {
            "Policies": [
                {"Id": "p-broken", "Name": "Unreadable"},
                {"Id": "p-good", "Name": "DenySigV4Runtime"},
            ]
        }

        def describe_policy(PolicyId):
            if PolicyId == "p-broken":
                raise ClientError(
                    {"Error": {"Code": "ServiceException", "Message": "boom"}},
                    "DescribePolicy",
                )
            return _scp(
                [
                    {
                        "Effect": "Deny",
                        "Action": _RUNTIME_WRITE,
                        "Resource": "*",
                        "Condition": {"StringEquals": {_RUNTIME_KEY: "AWS_IAM"}},
                    }
                ]
            )

        mock_orgs.describe_policy.side_effect = describe_policy

        findings = agentcore_app.check_agentcore_runtime_authorizer_scp()

        assert [finding["Status"] for finding in findings] == ["N/A", "Passed"]
        assert "Unreadable" in findings[0]["Finding_Details"]


class TestAC29CheckRegistration:
    """AC-29 is organization-wide, so it runs once and not per scanned region."""

    def test_the_scp_check_is_not_in_the_regional_tuples(self):
        assert "AC-29" not in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-29" not in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_the_handler_registers_the_scp_check_on_both_cache_paths(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        registrations = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "global_checks"
                for target in node.targets
            )
        ]
        assert len(registrations) == 2
        for registration in registrations:
            assert "check_agentcore_runtime_authorizer_scp" in ast.unparse(
                registration.value
            )

    def test_the_condition_key_is_wired_to_both_runtime_writes(self):
        # The key carries no documented value set, so the two spellings the check
        # matches are taken from the enums that do name these modes. If the
        # service ever models a runtime authorizer type, this is where the
        # vocabulary should come from instead.
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control", **credentials
        ).meta.service_model
        for operation in ("CreateAgentRuntime", "UpdateAgentRuntime"):
            assert "authorizerConfiguration" in (
                model.operation_model(operation).input_shape.members
            )
        enums = {
            shape: set(model.shape_for(shape).enum)
            for shape in (
                "AuthorizerType",
                "PaymentsAuthorizerType",
                "RegistryAuthorizerType",
            )
        }
        for values in enums.values():
            assert agentcore_app.RUNTIME_AUTHORIZER_UNVERIFIED_USER_VALUE in values
            assert agentcore_app.RUNTIME_AUTHORIZER_VERIFIED_USER_VALUE in values
        # The runtime's own authorizer configuration models no type member, which
        # is why the SCP key is the only surface that can answer this control.
        authorizer = model.operation_model("GetAgentRuntime").output_shape.members[
            "authorizerConfiguration"
        ]
        assert set(authorizer.members) == {"customJWTAuthorizer"}


def _jwt_runtime(**authorizer):
    return {"authorizerConfiguration": {"customJWTAuthorizer": authorizer}}


class TestAC30RuntimeInboundAuthorization:
    """AC-30: a runtime's inbound authorizer has to constrain the tokens it takes."""

    _RUNTIMES = [
        {"agentRuntimeId": "rt-sigv4", "agentRuntimeName": "Signed"},
        {"agentRuntimeId": "rt-pinned", "agentRuntimeName": "Pinned"},
        {"agentRuntimeId": "rt-open", "agentRuntimeName": "Open"},
    ]

    def _details(self, agentRuntimeId, **kwargs):
        if agentRuntimeId == "rt-pinned":
            return _jwt_runtime(
                discoveryUrl="https://idp.example/.well-known/openid-configuration",
                allowedAudience=["agent-api"],
            )
        if agentRuntimeId == "rt-open":
            return _jwt_runtime(
                discoveryUrl="https://idp.example/.well-known/openid-configuration"
            )
        return {"agentRuntimeId": agentRuntimeId}

    @patch("agentcore_app.agentcore_client")
    def test_each_runtime_gets_its_own_verdict(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": self._RUNTIMES}
        mock_ac.get_agent_runtime.side_effect = self._details

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert len(findings) == 3
        by_runtime = {}
        for finding in findings:
            assert finding["Check_ID"] == "AC-30"
            assert_finding_schema(finding)
            for runtime in self._RUNTIMES:
                if runtime["agentRuntimeId"] in finding["Finding_Details"]:
                    by_runtime[runtime["agentRuntimeId"]] = finding
        assert by_runtime["rt-sigv4"]["Status"] == "Passed"
        assert by_runtime["rt-pinned"]["Status"] == "Passed"
        assert by_runtime["rt-open"]["Status"] == "Failed"
        assert by_runtime["rt-open"]["Finding"].endswith("Unbounded")

    @patch("agentcore_app.agentcore_client")
    def test_a_runtime_with_no_authorizer_enforces_sigv4(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[0]]
        }
        mock_ac.get_agent_runtime.side_effect = self._details

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert findings[0]["Status"] == "Passed"
        assert "SigV4-signed" in findings[0]["Finding_Details"]
        assert "InvokeAgentRuntime" in findings[0]["Resolution"]

    @pytest.mark.parametrize(
        "member,label,status",
        [
            ("allowedAudience", "audience", "Passed"),
            ("allowedClients", "client id", "Passed"),
            ("allowedScopes", "scope", "Failed"),
            ("customClaims", "custom claim", "Failed"),
        ],
    )
    @patch("agentcore_app.agentcore_client")
    def test_only_audience_or_client_binds_the_calling_application(
        self, mock_ac, member, label, status
    ):
        # The inbound-authorizer guide requires at least one of the four, so a
        # count of pinned claims cannot separate these cases: a scope-only
        # authorizer validates a claim and still takes a token minted for
        # another application at the same issuer.
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[1]]
        }
        mock_ac.get_agent_runtime.return_value = _jwt_runtime(
            discoveryUrl="https://idp.example/.well-known/openid-configuration",
            **{member: ["pinned"]},
        )

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert findings[0]["Status"] == status
        assert label in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_scope_only_detail_credits_the_claim_it_does_validate(self, mock_ac):
        # This is the live shape of one runtime in the probe estate: a scope
        # list, no audience and no client.
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[2]]
        }
        mock_ac.get_agent_runtime.return_value = _jwt_runtime(
            discoveryUrl="https://idp.example/.well-known/openid-configuration",
            allowedScopes=["agent/invoke"],
        )

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert findings[0]["Status"] == "Failed"
        assert (
            "validates the scope claim(s) but neither the audience"
            in (findings[0]["Finding_Details"])
        )

    @patch("agentcore_app.agentcore_client")
    def test_the_passed_detail_names_every_validated_claim(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[1]]
        }
        mock_ac.get_agent_runtime.return_value = _jwt_runtime(
            discoveryUrl="https://idp.example/.well-known/openid-configuration",
            allowedAudience=["agent-api"],
            allowedScopes=["agent/invoke"],
        )

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert findings[0]["Status"] == "Passed"
        assert "audience, scope" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_empty_allow_list_is_not_a_constraint(self, mock_ac):
        # A present-but-empty list accepts every value of that claim, so a
        # membership test on the key alone would score this as coverage.
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[2]]
        }
        mock_ac.get_agent_runtime.return_value = _jwt_runtime(
            discoveryUrl="https://idp.example/.well-known/openid-configuration",
            allowedAudience=[],
            allowedClients=[],
        )

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Unbounded")

    @patch("agentcore_app.agentcore_client")
    def test_an_authorizer_that_pins_nothing_reads_as_unbounded(self, mock_ac):
        # The guide says the service requires one of the four, so this state
        # should not exist. It gets the same verdict as a scope-only authorizer
        # instead of a branch of its own that nothing can reach.
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[2]]
        }
        mock_ac.get_agent_runtime.side_effect = self._details

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert findings[0]["Status"] == "Failed"
        assert "validates neither the audience" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_failed_detail_names_the_issuer_it_trusts(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[2]]
        }
        mock_ac.get_agent_runtime.side_effect = self._details

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert (
            "https://idp.example/.well-known/openid-configuration"
            in (findings[0]["Finding_Details"])
        )
        assert "rt-open" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_claim_constraint_is_not_read_from_the_wrong_level(self, mock_ac):
        # The four constraints live inside customJWTAuthorizer. Reading them off
        # authorizerConfiguration would score this runtime as pinned.
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[2]]
        }
        mock_ac.get_agent_runtime.return_value = {
            "authorizerConfiguration": {
                "allowedAudience": ["agent-api"],
                "customJWTAuthorizer": {
                    "discoveryUrl": "https://idp.example/.well-known/openid-configuration"
                },
            }
        }

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_an_authorizer_member_this_botocore_cannot_read_is_na(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[1]]
        }
        mock_ac.get_agent_runtime.return_value = {
            "authorizerConfiguration": {"mtlsAuthorizer": {"trustStoreArn": "arn:x"}}
        }

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert findings[0]["Status"] == "N/A"
        assert "mtlsAuthorizer" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_runtime_does_not_hide_the_others(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": self._RUNTIMES[1:]}

        def details(agentRuntimeId, **kwargs):
            if agentRuntimeId == "rt-pinned":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "GetAgentRuntime",
                )
            return self._details(agentRuntimeId)

        mock_ac.get_agent_runtime.side_effect = details

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert len(findings) == 2
        assert [finding["Status"] for finding in findings] == ["N/A", "Failed"]
        assert "GetAgentRuntime" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_runtimes_are_read_from_every_page(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = [
            {"agentRuntimes": [self._RUNTIMES[0]], "nextToken": "rt-page-2"},
            {"agentRuntimes": [self._RUNTIMES[2]]},
        ]
        mock_ac.get_agent_runtime.side_effect = self._details

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert mock_ac.list_agent_runtimes.call_count == 2
        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_reported_as_incomplete(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListAgentRuntimes",
        )

        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding"].endswith("Incomplete")

    @patch("agentcore_app.agentcore_client")
    def test_no_runtimes_is_na(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_runtime_inbound_authorization()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-30"


class TestAC30CheckRegistration:
    """AC-30 reads a regional resource, so it runs in every scanned region."""

    def test_the_runtime_check_is_in_both_regional_tuples(self):
        assert "AC-30" in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-30" in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_timeout_backfill_emits_the_runtime_check(self):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        assert "AC-30" in {finding["Check_ID"] for finding in findings}

    def test_the_handler_registers_the_runtime_check_once(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count("check_agentcore_runtime_inbound_authorization") == 1

    def test_the_claim_members_the_check_reads_are_modelled(self):
        # A constraint the API does not model would never be found, and the
        # check would report every JWT runtime as unbounded.
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control", **credentials
        ).meta.service_model
        authorizer = model.operation_model("GetAgentRuntime").output_shape.members[
            "authorizerConfiguration"
        ]
        jwt = authorizer.members["customJWTAuthorizer"]
        claims = set(agentcore_app.JWT_AUTHORIZER_CALLER_CLAIMS) | set(
            agentcore_app.JWT_AUTHORIZER_OTHER_CLAIMS
        )
        assert claims <= set(jwt.members)
        assert not set(agentcore_app.JWT_AUTHORIZER_CALLER_CLAIMS) & set(
            agentcore_app.JWT_AUTHORIZER_OTHER_CLAIMS
        )
        # discoveryUrl alone is required in both machine-readable surfaces, the
        # service model here and the AWS::BedrockAgentCore::Runtime resource
        # schema, which is why the guide's "at least one of the four" cannot be
        # read off either one.
        assert jwt.required_members == ["discoveryUrl"]
        # And the whole authorizer is optional on create, which is what makes
        # an absent configuration mean SigV4 instead of no authentication.
        create = model.operation_model("CreateAgentRuntime").input_shape
        assert "authorizerConfiguration" not in create.required_members


def _jwt_gateway(**authorizer):
    return {
        "authorizerType": "CUSTOM_JWT",
        "authorizerConfiguration": {"customJWTAuthorizer": authorizer},
    }


_ISSUER = "https://idp.example/.well-known/openid-configuration"


class TestAC31GatewayInboundAllowLists:
    """AC-31: a gateway's JWT authorizer has to name the applications it serves."""

    _GATEWAYS = [
        {"gatewayId": "gw-iam", "name": "Signed"},
        {"gatewayId": "gw-pinned", "name": "Pinned"},
        {"gatewayId": "gw-open", "name": "Open"},
        {"gatewayId": "gw-none", "name": "Unauthenticated"},
    ]

    def _details(self, gatewayIdentifier, **kwargs):
        if gatewayIdentifier == "gw-pinned":
            return _jwt_gateway(discoveryUrl=_ISSUER, allowedClients=["client-a"])
        if gatewayIdentifier == "gw-open":
            return _jwt_gateway(discoveryUrl=_ISSUER, allowedScopes=["tools/read"])
        if gatewayIdentifier == "gw-none":
            return {"authorizerType": "NONE"}
        return {"authorizerType": "AWS_IAM"}

    @patch("agentcore_app.agentcore_client")
    def test_each_gateway_gets_its_own_verdict(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._details

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert len(findings) == 4
        by_gateway = {}
        for finding in findings:
            assert finding["Check_ID"] == "AC-31"
            assert_finding_schema(finding)
            for gateway in self._GATEWAYS:
                if gateway["gatewayId"] in finding["Finding_Details"]:
                    by_gateway[gateway["gatewayId"]] = finding
        assert by_gateway["gw-iam"]["Status"] == "Passed"
        assert by_gateway["gw-pinned"]["Status"] == "Passed"
        assert by_gateway["gw-open"]["Status"] == "Failed"
        assert by_gateway["gw-none"]["Status"] == "Failed"
        assert by_gateway["gw-open"]["Finding"].endswith("Absent")

    @pytest.mark.parametrize("authorizer_type", ["AWS_IAM", "AUTHENTICATE_ONLY"])
    @patch("agentcore_app.agentcore_client")
    def test_a_sigv4_gateway_has_no_issuer_to_allow_list(
        self, mock_ac, authorizer_type
    ):
        # AG-24 fails AUTHENTICATE_ONLY without a policy engine in ENFORCE mode,
        # which is the authorization question. This check asks who the caller is
        # allowed to be, and a SigV4 caller carries no token to pin.
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.get_gateway.return_value = {"authorizerType": authorizer_type}

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert findings[0]["Status"] == "Passed"
        assert authorizer_type in findings[0]["Finding_Details"]
        assert "no bearer token" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_no_inbound_authentication_has_no_allow_list_to_hold(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[3]]}
        mock_ac.get_gateway.side_effect = self._details

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Absent")
        assert "passthrough" in findings[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "member,label,status",
        [
            ("allowedAudience", "audience", "Passed"),
            ("allowedClients", "client id", "Passed"),
            ("allowedScopes", "scope", "Failed"),
            ("customClaims", "custom claim", "Failed"),
        ],
    )
    @patch("agentcore_app.agentcore_client")
    def test_only_audience_or_client_names_the_calling_application(
        self, mock_ac, member, label, status
    ):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[1]]}
        mock_ac.get_gateway.return_value = _jwt_gateway(
            discoveryUrl=_ISSUER, **{member: ["pinned"]}
        )

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert findings[0]["Status"] == status
        assert label in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_scope_only_detail_credits_the_claim_it_does_bound(self, mock_ac):
        # One gateway in the live probe estate has exactly this shape: a scope
        # list, no audience and no client.
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[2]]}
        mock_ac.get_gateway.side_effect = self._details

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert findings[0]["Status"] == "Failed"
        assert (
            "allow-lists the scope claim(s) but neither the audience"
            in (findings[0]["Finding_Details"])
        )
        assert _ISSUER in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_passed_detail_names_every_allow_listed_claim(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[1]]}
        mock_ac.get_gateway.return_value = _jwt_gateway(
            discoveryUrl=_ISSUER,
            allowedAudience=["gateway-api"],
            allowedClients=["client-a"],
            allowedScopes=["tools/read"],
        )

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert findings[0]["Status"] == "Passed"
        assert "audience, client id, scope" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_empty_allow_list_is_not_a_constraint(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[2]]}
        mock_ac.get_gateway.return_value = _jwt_gateway(
            discoveryUrl=_ISSUER, allowedAudience=[], allowedClients=[]
        )

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert findings[0]["Status"] == "Failed"
        assert "allow-lists neither the audience" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_allow_list_is_not_read_from_the_wrong_level(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[2]]}
        mock_ac.get_gateway.return_value = {
            "authorizerType": "CUSTOM_JWT",
            "authorizerConfiguration": {
                "allowedClients": ["client-a"],
                "customJWTAuthorizer": {"discoveryUrl": _ISSUER},
            },
        }

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_jwt_gateway_with_no_authorizer_configuration_is_na(self, mock_ac):
        # Not a pass: CUSTOM_JWT with no readable authorizer means the
        # allow-lists were not returned, not that they are empty.
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[1]]}
        mock_ac.get_gateway.return_value = {"authorizerType": "CUSTOM_JWT"}

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert findings[0]["Status"] == "N/A"
        assert "customJWTAuthorizer" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_authorizer_type_this_botocore_cannot_judge_is_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[1]]}
        mock_ac.get_gateway.return_value = {"authorizerType": "CUSTOM_MTLS"}

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert findings[0]["Status"] == "N/A"
        assert "CUSTOM_MTLS" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_gateway_does_not_hide_the_others(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS[1:3]}

        def details(gatewayIdentifier, **kwargs):
            if gatewayIdentifier == "gw-pinned":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "GetGateway",
                )
            return self._details(gatewayIdentifier)

        mock_ac.get_gateway.side_effect = details

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert len(findings) == 2
        assert [finding["Status"] for finding in findings] == ["N/A", "Failed"]
        assert "GetGateway" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_gateways_are_read_from_every_page(self, mock_ac):
        mock_ac.list_gateways.side_effect = [
            {"items": [self._GATEWAYS[1]], "nextToken": "gw-page-2"},
            {"items": [self._GATEWAYS[2]]},
        ]
        mock_ac.get_gateway.side_effect = self._details

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert mock_ac.list_gateways.call_count == 2
        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_reported_as_incomplete(self, mock_ac):
        mock_ac.list_gateways.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListGateways",
        )

        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding"].endswith("Incomplete")

    @patch("agentcore_app.agentcore_client")
    def test_no_gateways_is_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_gateway_inbound_allow_lists()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-31"


class TestAC31CheckRegistration:
    """AC-31 reads a regional resource, so it runs in every scanned region."""

    def test_the_gateway_check_is_in_both_regional_tuples(self):
        assert "AC-31" in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-31" in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_timeout_backfill_emits_the_gateway_check(self):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        assert "AC-31" in {finding["Check_ID"] for finding in findings}

    def test_the_handler_registers_the_gateway_check_once(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count("check_agentcore_gateway_inbound_allow_lists") == 1

    def test_the_check_judges_every_authorizer_type_the_api_models(self):
        # A fifth value would fall through to the N/A branch, so the three
        # groups have to account for all four the model carries today.
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control", **credentials
        ).meta.service_model
        output = model.operation_model("GetGateway").output_shape
        modelled = set(output.members["authorizerType"].metadata["enum"])
        judged = set(agentcore_app.GATEWAY_AUTHORIZER_SIGV4_VALUES) | {
            agentcore_app.GATEWAY_AUTHORIZER_UNAUTHENTICATED_VALUE,
            agentcore_app.GATEWAY_AUTHORIZER_JWT_VALUE,
        }
        assert judged == modelled
        assert agentcore_app.GATEWAY_AUTHORIZER_JWT_VALUE not in (
            agentcore_app.GATEWAY_AUTHORIZER_SIGV4_VALUES
        )
        # The type is required on the response, so "unspecified" can only come
        # from a truncated read; the allow-lists are optional under it.
        assert "authorizerType" in output.required_members
        jwt = output.members["authorizerConfiguration"].members["customJWTAuthorizer"]
        claims = set(agentcore_app.JWT_AUTHORIZER_CALLER_CLAIMS) | set(
            agentcore_app.JWT_AUTHORIZER_OTHER_CLAIMS
        )
        assert claims <= set(jwt.members)
        assert jwt.required_members == ["discoveryUrl"]


class TestAC32InboundJwtIssuerConditions:
    """AC-32: who can trade a JWT from any issuer for a workload access token."""

    _WORKLOAD_ARN = (
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity-directory/"
        "default/workload-identity/agent-1"
    )

    @staticmethod
    def _cache(
        actions,
        condition=None,
        resource="*",
        principal="agent-role",
        effect="Allow",
    ):
        statement = {"Effect": effect, "Action": actions, "Resource": resource}
        if condition:
            statement["Condition"] = condition
        return {
            "role_permissions": {
                principal: {
                    "attached_policies": [
                        {"name": "p", "document": {"Statement": [statement]}}
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

    def test_an_unpinned_exchange_fails(self):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(["bedrock-agentcore:GetWorkloadAccessTokenForJWT"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Check_ID"] == "AC-32"
        assert findings[0]["Severity"] == "High"
        assert "role agent-role" in findings[0]["Finding_Details"]
        for finding in findings:
            assert_finding_schema(finding)

    @pytest.mark.parametrize(
        "condition_key",
        [
            "bedrock-agentcore:InboundJwtClaim/iss",
            "bedrock-agentcore:InboundJwtClaim/aud",
            "bedrock-agentcore:InboundJwtClaim/client_id",
        ],
    )
    def test_an_issuer_or_application_condition_passes(self, condition_key):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(
                ["bedrock-agentcore:GetWorkloadAccessTokenForJWT"],
                condition={"StringEquals": {condition_key: "https://idp.example/"}},
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "role agent-role" in findings[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "condition_key",
        [
            "bedrock-agentcore:InboundJwtClaim/scope",
            "bedrock-agentcore:InboundJwtClaim/sub",
        ],
    )
    def test_a_claim_that_is_not_the_issuer_or_the_application_fails(
        self, condition_key
    ):
        # Both keys are real and both bound the exchange, so a check that counted
        # any InboundJwtClaim condition would read these as coverage. Neither
        # keeps a token from an unapproved issuer out.
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(
                ["bedrock-agentcore:CompleteResourceTokenAuth"],
                condition={"StringEquals": {condition_key: "agent/invoke"}},
            )
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_the_second_exchange_action_is_assessed(self):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(["bedrock-agentcore:CompleteResourceTokenAuth"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_the_agentcore_namespace_wildcard_is_detected(self):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(["bedrock-agentcore:*"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_a_bare_wildcard_action_is_left_to_ac_02(self):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(["*"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_the_token_actions_that_take_no_inbound_jwt_are_not_assessed(self):
        # IAM publishes no InboundJwtClaim key for these two, so a Failed verdict
        # on them would demand a condition that can never match. ID-10 is where
        # holding them at all is judged.
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(
                [
                    "bedrock-agentcore:GetWorkloadAccessToken",
                    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                ]
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_a_deny_statement_is_ignored(self):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(
                ["bedrock-agentcore:GetWorkloadAccessTokenForJWT"], effect="Deny"
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_another_service_is_ignored(self):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(["sts:GetWorkloadAccessTokenForJWT"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]

    def test_a_workload_identity_arn_without_a_condition_still_fails(self):
        # The workload identity is the only resource type these actions accept,
        # so naming it narrows which agent exchanges tokens and not which issuer
        # minted them.
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(
                ["bedrock-agentcore:GetWorkloadAccessTokenForJWT"],
                resource=self._WORKLOAD_ARN,
            )
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_a_pinned_statement_does_not_excuse_an_unpinned_one(self):
        cache = self._cache(
            ["bedrock-agentcore:GetWorkloadAccessTokenForJWT"],
            condition={
                "StringEquals": {
                    "bedrock-agentcore:InboundJwtClaim/iss": "https://idp.example/"
                }
            },
        )
        cache["role_permissions"]["agent-role"]["inline_policies"] = [
            {
                "name": "wide",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "bedrock-agentcore:CompleteResourceTokenAuth",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]

        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(cache)

        assert [f["Status"] for f in findings] == ["Failed"]

    def test_the_unpinned_statement_still_decides_when_it_is_read_first(self):
        # The mirror of the case above. A walker that records the last statement
        # it saw instead of latching the unpinned one gets the right answer in one
        # order and the wrong answer in the other.
        cache = self._cache(["bedrock-agentcore:GetWorkloadAccessTokenForJWT"])
        cache["role_permissions"]["agent-role"]["inline_policies"] = [
            {
                "name": "narrow",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "bedrock-agentcore:CompleteResourceTokenAuth",
                            "Resource": "*",
                            "Condition": {
                                "StringEquals": {
                                    "bedrock-agentcore:InboundJwtClaim/iss": (
                                        "https://idp.example/"
                                    )
                                }
                            },
                        }
                    ]
                },
            }
        ]

        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(cache)

        assert [f["Status"] for f in findings] == ["Failed"]

    def test_users_are_evaluated_alongside_roles(self):
        cache = self._cache(["bedrock-agentcore:GetWorkloadAccessTokenForJWT"])
        cache["user_permissions"] = cache["role_permissions"]
        cache["role_permissions"] = {}

        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(cache)

        assert [f["Status"] for f in findings] == ["Failed"]
        assert "user agent-role" in findings[0]["Finding_Details"]

    def test_pinned_and_unpinned_principals_are_reported_separately(self):
        cache = self._cache(["bedrock-agentcore:GetWorkloadAccessTokenForJWT"])
        cache["role_permissions"]["pinned-role"] = {
            "attached_policies": [
                {
                    "name": "p",
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": (
                                    "bedrock-agentcore:GetWorkloadAccessTokenForJWT"
                                ),
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "bedrock-agentcore:InboundJwtClaim/iss": (
                                            "https://idp.example/"
                                        )
                                    }
                                },
                            }
                        ]
                    },
                }
            ],
            "inline_policies": [],
        }

        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(cache)

        assert {finding["Status"] for finding in findings} == {"Failed", "Passed"}

    def test_findings_are_tagged_global(self):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            self._cache(["bedrock-agentcore:GetWorkloadAccessTokenForJWT"])
        )
        assert all(
            finding["Region"] == agentcore_app.GLOBAL_REGION_LABEL
            for finding in findings
        )

    def test_an_empty_cache_is_na(self):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(
            {"role_permissions": {}, "user_permissions": {}}
        )
        assert findings[0]["Status"] == "N/A"

    def test_an_unparseable_policy_does_not_hide_a_sibling_grant(self):
        cache = self._cache(["bedrock-agentcore:GetWorkloadAccessTokenForJWT"])
        cache["role_permissions"]["agent-role"]["inline_policies"] = [
            {"name": "broken", "document": "{not json"}
        ]

        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(cache)

        assert [f["Status"] for f in findings] == ["Failed"]

    def test_an_unusable_cache_is_reported_incomplete(self):
        findings = agentcore_app.check_agentcore_inbound_jwt_issuer_conditions(None)

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Finding"].endswith("Incomplete")


class TestAC32CheckRegistration:
    """AC-32 reads the global IAM cache, so it runs once and not per region."""

    def test_the_cache_check_is_not_in_the_regional_tuples(self):
        assert "AC-32" not in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-32" not in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_the_handler_registers_the_check_on_the_cached_path_only(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        registrations = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "global_checks"
                for target in node.targets
            )
        ]
        assert len(registrations) == 2
        registered = [
            "check_agentcore_inbound_jwt_issuer_conditions"
            in ast.unparse(registration.value)
            for registration in registrations
        ]
        # The first list is the path taken when the cache is missing, where this
        # check has nothing to read; the second is the cached path.
        assert registered == [False, True]

    def test_a_missing_cache_reports_the_check_incomplete(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert '("AC-32", "AgentCore Inbound JWT Issuer Conditions")' in source

    def test_the_exchange_actions_name_real_api_operations(self):
        # A typo here would narrow the check to nothing and report every account
        # as having no token-exchange grant.
        model = agentcore_app.boto3.client(
            "bedrock-agentcore",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        operations = {name.lower() for name in model.operation_names}
        assert set(agentcore_app.INBOUND_JWT_EXCHANGE_ACTIONS) <= operations
        # The two token actions that accept no inbound JWT exist as well, so
        # their absence from the tuple is a scoping decision and not a typo.
        assert {
            "getworkloadaccesstoken",
            "getworkloadaccesstokenforuserid",
        } <= operations
        assert {
            "getworkloadaccesstoken",
            "getworkloadaccesstokenforuserid",
        }.isdisjoint(agentcore_app.INBOUND_JWT_EXCHANGE_ACTIONS)

    def test_the_condition_keys_are_matchable_and_exclude_the_weaker_claims(self):
        # _statement_condition_keys lowercases, so an uppercased entry here would
        # never match and every grant would read as unpinned.
        keys = agentcore_app.INBOUND_JWT_ISSUER_CONDITION_KEYS
        assert keys == tuple(key.lower() for key in keys)
        assert "bedrock-agentcore:inboundjwtclaim/scope" not in keys
        assert "bedrock-agentcore:inboundjwtclaim/sub" not in keys


_DIRECTORY_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
    "workload-identity-directory/default"
)
_IDENTITY_ARN = f"{_DIRECTORY_ARN}/workload-identity/agent-1"
_VAULT_ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:token-vault/default"
_PROVIDER_ARN = f"{_VAULT_ARN}/oauth2-credential-provider/my-provider"


class TestAC33TokenIssuanceScope:
    """AC-33: which resources a principal may mint an agent token against."""

    @staticmethod
    def _cache(actions, resource="*", principal="agent-role", effect="Allow"):
        return {
            "role_permissions": {
                principal: {
                    "attached_policies": [
                        {
                            "name": "p",
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": effect,
                                        "Action": actions,
                                        "Resource": resource,
                                    }
                                ]
                            },
                        }
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

    def test_a_wildcard_resource_fails(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(["bedrock-agentcore:GetWorkloadAccessToken"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Check_ID"] == "AC-33"
        assert findings[0]["Severity"] == "High"
        assert "role agent-role" in findings[0]["Finding_Details"]
        for finding in findings:
            assert_finding_schema(finding)

    def test_the_published_scoped_policy_passes(self):
        # The four ARNs AWS's own scoped example lists in one Resource array. A
        # rule demanding that every element name a workload identity would fail
        # the policy the service's own documentation tells a customer to write.
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(
                [
                    "bedrock-agentcore:GetWorkloadAccessToken",
                    "bedrock-agentcore:GetResourceOauth2Token",
                ],
                resource=[_DIRECTORY_ARN, _IDENTITY_ARN, _VAULT_ARN, _PROVIDER_ARN],
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "role agent-role" in findings[0]["Finding_Details"]

    def test_a_grant_naming_no_workload_identity_is_undecidable_and_fails(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(
                ["bedrock-agentcore:GetWorkloadAccessToken"],
                resource=[_DIRECTORY_ARN],
            )
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        # Only one of the two readings of a two-required-resource action is a
        # widening, so this leg is not scored alongside a wildcard grant.
        assert findings[0]["Severity"] == "Medium"
        assert "authorizes nothing" in findings[0]["Finding_Details"]

    def test_a_trailing_wildcard_under_the_directory_is_the_wildcard_leg(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(
                ["bedrock-agentcore:GetWorkloadAccessToken"],
                resource=[f"{_DIRECTORY_ARN}/workload-identity/*"],
            )
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Severity"] == "High"
        assert "wildcard resource" in findings[0]["Finding_Details"]

    def test_a_wildcard_inside_the_identity_name_is_not_a_named_identity(self):
        # This ARN does not end in a wildcard, so it reaches the name test rather
        # than the trailing-wildcard test, and prod-*-agent is not one identity.
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(
                ["bedrock-agentcore:GetWorkloadAccessToken"],
                resource=[f"{_DIRECTORY_ARN}/workload-identity/prod-*-agent"],
            )
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_a_region_wildcard_leaves_the_identity_named(self):
        # A multi-region policy wildcards the region, which widens where the
        # identity lives and not which identity it is.
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(
                ["bedrock-agentcore:GetWorkloadAccessToken"],
                resource=[_IDENTITY_ARN.replace("us-east-1", "*")],
            )
        )
        assert [f["Status"] for f in findings] == ["Passed"]

    def test_the_directory_arn_is_not_read_as_an_identity_arn(self):
        # workload-identity-directory/ does not contain workload-identity/, which
        # is the whole reason the substring parse is safe.
        assert not agentcore_app._resource_names_one_workload_identity(_DIRECTORY_ARN)
        assert agentcore_app._resource_names_one_workload_identity(_IDENTITY_ARN)

    @pytest.mark.parametrize(
        "action",
        [
            "CompleteResourceTokenAuth",
            "GetResourceOauth2Token",
            "GetWorkloadAccessToken",
            "GetWorkloadAccessTokenForJWT",
            "GetWorkloadAccessTokenForUserId",
        ],
    )
    def test_every_token_issuance_action_is_assessed(self, action):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache([f"bedrock-agentcore:{action}"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_the_payment_token_action_is_left_to_the_payments_control(self):
        # GetResourcePaymentToken takes the same workload-identity resource, so
        # its absence is a scoping decision: PAY-01 judges the payments roles.
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(["bedrock-agentcore:GetResourcePaymentToken"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_the_agentcore_namespace_wildcard_is_detected(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(["bedrock-agentcore:Get*"])
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    def test_a_bare_wildcard_action_is_left_to_ac_02(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(["*"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_a_deny_statement_is_ignored(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(["bedrock-agentcore:GetWorkloadAccessToken"], effect="Deny")
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "No cached IAM role or user" in findings[0]["Finding_Details"]

    def test_another_service_is_ignored(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(["sts:GetWorkloadAccessToken"])
        )
        assert [f["Status"] for f in findings] == ["Passed"]

    def test_the_widest_statement_decides(self):
        cache = self._cache(
            ["bedrock-agentcore:GetWorkloadAccessToken"], resource=[_IDENTITY_ARN]
        )
        cache["role_permissions"]["agent-role"]["inline_policies"] = [
            {
                "name": "wide",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "bedrock-agentcore:GetResourceOauth2Token",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]

        findings = agentcore_app.check_agentcore_token_issuance_scope(cache)

        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Severity"] == "High"

    def test_the_widest_statement_still_decides_when_it_is_read_first(self):
        # The mirror of the case above, so a walker that records the last verdict
        # it saw cannot pass by getting one statement order right.
        cache = self._cache(["bedrock-agentcore:GetWorkloadAccessToken"])
        cache["role_permissions"]["agent-role"]["inline_policies"] = [
            {
                "name": "narrow",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "bedrock-agentcore:GetResourceOauth2Token",
                            "Resource": [_IDENTITY_ARN],
                        }
                    ]
                },
            }
        ]

        findings = agentcore_app.check_agentcore_token_issuance_scope(cache)

        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Severity"] == "High"

    def test_the_directory_arn_and_the_identity_arn_may_sit_in_two_statements(self):
        # The same grant as the published example, split in two. Ranking the
        # undecidable leg above the scoped one would fail this.
        cache = self._cache(
            ["bedrock-agentcore:GetWorkloadAccessToken"], resource=[_DIRECTORY_ARN]
        )
        cache["role_permissions"]["agent-role"]["inline_policies"] = [
            {
                "name": "identity",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                            "Resource": [_IDENTITY_ARN],
                        }
                    ]
                },
            }
        ]

        findings = agentcore_app.check_agentcore_token_issuance_scope(cache)

        assert [f["Status"] for f in findings] == ["Passed"]

    def test_users_are_evaluated_alongside_roles(self):
        cache = self._cache(["bedrock-agentcore:GetWorkloadAccessToken"])
        cache["user_permissions"] = cache["role_permissions"]
        cache["role_permissions"] = {}

        findings = agentcore_app.check_agentcore_token_issuance_scope(cache)

        assert [f["Status"] for f in findings] == ["Failed"]
        assert "user agent-role" in findings[0]["Finding_Details"]

    def test_all_three_groups_are_reported_separately(self):
        cache = self._cache(["bedrock-agentcore:GetWorkloadAccessToken"])
        for principal, resource in (
            ("directory-role", [_DIRECTORY_ARN]),
            ("scoped-role", [_DIRECTORY_ARN, _IDENTITY_ARN]),
        ):
            cache["role_permissions"][principal] = self._cache(
                ["bedrock-agentcore:GetWorkloadAccessToken"], resource=resource
            )["role_permissions"]["agent-role"]

        findings = agentcore_app.check_agentcore_token_issuance_scope(cache)

        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Passed"]
        assert [f["Severity"] for f in findings] == ["High", "Medium", "High"]

    def test_findings_are_tagged_global(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            self._cache(["bedrock-agentcore:GetWorkloadAccessToken"])
        )
        assert all(
            finding["Region"] == agentcore_app.GLOBAL_REGION_LABEL
            for finding in findings
        )

    def test_an_empty_cache_is_na(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(
            {"role_permissions": {}, "user_permissions": {}}
        )
        assert findings[0]["Status"] == "N/A"

    def test_an_unparseable_policy_does_not_hide_a_sibling_grant(self):
        cache = self._cache(["bedrock-agentcore:GetWorkloadAccessToken"])
        cache["role_permissions"]["agent-role"]["inline_policies"] = [
            {"name": "broken", "document": "{not json"}
        ]

        findings = agentcore_app.check_agentcore_token_issuance_scope(cache)

        assert [f["Status"] for f in findings] == ["Failed"]

    def test_an_unusable_cache_is_reported_incomplete(self):
        findings = agentcore_app.check_agentcore_token_issuance_scope(None)

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Finding"].endswith("Incomplete")


class TestAC33CheckRegistration:
    """AC-33 reads the global IAM cache, so it runs once and not per region."""

    def test_the_cache_check_is_not_in_the_regional_tuples(self):
        assert "AC-33" not in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-33" not in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_the_handler_registers_the_check_on_the_cached_path_only(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        registrations = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "global_checks"
                for target in node.targets
            )
        ]
        assert len(registrations) == 2
        registered = [
            "check_agentcore_token_issuance_scope" in ast.unparse(registration.value)
            for registration in registrations
        ]
        # The first list is the path taken when the cache is missing, where this
        # check has nothing to read; the second is the cached path.
        assert registered == [False, True]

    def test_a_missing_cache_reports_the_check_incomplete(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert '("AC-33", "AgentCore Token Issuance Scope")' in source

    def test_the_issuance_actions_name_real_api_operations(self):
        # A typo here would narrow the check to nothing and report every account
        # as having no token-issuance grant.
        model = agentcore_app.boto3.client(
            "bedrock-agentcore",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        operations = {name.lower() for name in model.operation_names}
        assert set(agentcore_app.TOKEN_ISSUANCE_ACTIONS) <= operations
        # The payment token action exists too, so its absence is deliberate.
        assert "getresourcepaymenttoken" in operations
        assert "getresourcepaymenttoken" not in agentcore_app.TOKEN_ISSUANCE_ACTIONS

    def test_the_actions_are_matchable_against_a_lowercased_pattern(self):
        actions = agentcore_app.TOKEN_ISSUANCE_ACTIONS
        assert actions == tuple(action.lower() for action in actions)
        # The devguide spells the last one GetWorkloadAccessTokenForJwt while the
        # IAM action name is ...ForJWT; lowercasing absorbs the difference.
        assert "getworkloadaccesstokenforjwt" in actions


_SECRET_VALUE = "wJalrXUtnFEMI-K7MDENG-bPxRfiCY"  # pragma: allowlist secret - synthetic


class TestAC34RuntimeInlineCredentials:
    """AC-34: a credential pasted into a runtime's definition never reaches a vault."""

    _RUNTIMES = [
        {"agentRuntimeId": "rt-clean", "agentRuntimeName": "Clean"},
        {"agentRuntimeId": "rt-inline", "agentRuntimeName": "Inline"},
    ]

    @staticmethod
    def _details(agentRuntimeId, **kwargs):
        if agentRuntimeId == "rt-inline":
            return {"environmentVariables": {"API_KEY": _SECRET_VALUE}}
        return {
            "environmentVariables": {
                "LOG_LEVEL": "INFO",
                "TOKEN_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:t-AbC",
            }
        }

    @patch("agentcore_app.agentcore_client")
    def test_each_runtime_gets_its_own_verdict(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": self._RUNTIMES}
        mock_ac.get_agent_runtime.side_effect = self._details

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert len(findings) == 2
        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]
        for finding in findings:
            assert finding["Check_ID"] == "AC-34"
            assert_finding_schema(finding)
        assert findings[1]["Finding"].endswith("Found")
        assert findings[1]["Severity"] == "High"
        assert "rt-inline" in findings[1]["Finding_Details"]
        assert "API_KEY" in findings[1]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_value_never_reaches_the_finding(self, mock_ac):
        # environmentVariables is modelled sensitive, so the report may name the
        # variable and must not carry what it holds.
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[1]]
        }
        mock_ac.get_agent_runtime.side_effect = self._details

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert findings[0]["Status"] == "Failed"
        for value in findings[0].values():
            assert _SECRET_VALUE not in str(value)

    @pytest.mark.parametrize(
        "name,value,status",
        [
            # A credential-named variable holding a literal.
            ("API_KEY", "abc123def456", "Failed"),
            ("DB_PASSWORD", "hunter2hunter2", "Failed"),
            ("CLIENT_SECRET", "s3cr3tvalue", "Failed"),
            ("OAUTH_TOKEN", "eyJhbGciOiJIUzI1NiJ9.e30.abc", "Failed"),
            ("SIGNING_PRIVATEKEY", "MIIEvQIBADANBg", "Failed"),
            # The same variable pointing at where the credential lives.
            (
                "API_KEY_ARN",
                "arn:aws:secretsmanager:us-east-1:1:secret:k-AbC",
                "Passed",
            ),
            ("DB_PASSWORD_PARAM", "/prod/agent/db-password", "Passed"),
            ("CLIENT_SECRET_NAME", "prod/agent/client-secret", "Passed"),
            ("TOKEN_ENDPOINT", "https://idp.example/oauth2/token", "Passed"),
            # A setting whose name contains a credential noun.
            ("TOKEN_TTL", "3600", "Passed"),
            ("CACHE_TOKENS", "true", "Passed"),
            ("API_KEY_HEADER", "", "Passed"),
            # A variable that names no credential and holds no credential shape.
            ("LOG_LEVEL", "DEBUG", "Passed"),
            ("MODEL_ID", "global.anthropic.claude-opus-5", "Passed"),
        ],
    )
    @patch("agentcore_app.agentcore_client")
    def test_a_credential_name_is_judged_on_its_value(
        self, mock_ac, name, value, status
    ):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[0]]
        }
        mock_ac.get_agent_runtime.return_value = {"environmentVariables": {name: value}}

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert [finding["Status"] for finding in findings] == [status]

    @pytest.mark.parametrize(
        "value",
        [
            "AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret - AWS's documented example id
            "ASIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret - the same id, STS prefix
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",  # pragma: allowlist secret - a 4-character body, not a key
        ],
    )
    @patch("agentcore_app.agentcore_client")
    def test_a_credential_shape_fails_under_an_innocent_name(self, mock_ac, value):
        # The name leg cannot catch these: nothing in BUILD_USER or PEM_BLOB
        # names a credential, and both values are credential material.
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[0]]
        }
        mock_ac.get_agent_runtime.return_value = {
            "environmentVariables": {"BUILD_USER": value}
        }

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert [finding["Status"] for finding in findings] == ["Failed"]
        assert "BUILD_USER" in findings[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "value",
        [
            "AKIAIOSFODNN7EXAMPL",
            "AKIAIOSFODNN7EXAMPLE1",
            "AKIAiosfodnn7example",
            "AKIA-OSFODNN7EXAMPLE",
            "BKIAIOSFODNN7EXAMPLE",
            "-----BEGIN CERTIFICATE-----",
        ],
    )
    @patch("agentcore_app.agentcore_client")
    def test_a_near_miss_on_the_key_shape_is_not_a_credential(self, mock_ac, value):
        # Wrong length, lowercase body, a punctuation character, the wrong
        # prefix, and a PEM block that is a certificate and not a key.
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[0]]
        }
        mock_ac.get_agent_runtime.return_value = {
            "environmentVariables": {"BUILD_USER": value}
        }

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert [finding["Status"] for finding in findings] == ["Passed"]

    @patch("agentcore_app.agentcore_client")
    def test_one_inline_credential_condemns_the_runtime(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[0]]
        }
        mock_ac.get_agent_runtime.return_value = {
            "environmentVariables": {
                "LOG_LEVEL": "INFO",
                "TOKEN_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:t-AbC",
                "SLACK_API_KEY": "xoxb-not-a-real-token",  # pragma: allowlist secret - synthetic test credential
            }
        }

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert [finding["Status"] for finding in findings] == ["Failed"]
        assert "SLACK_API_KEY" in findings[0]["Finding_Details"]
        assert "TOKEN_SECRET_ARN" not in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_passing_detail_credits_the_pointers_it_found(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[0]]
        }
        mock_ac.get_agent_runtime.side_effect = self._details

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert findings[0]["Status"] == "Passed"
        assert "2 environment variable(s)" in findings[0]["Finding_Details"]
        assert "TOKEN_SECRET_ARN" in findings[0]["Finding_Details"]
        # The passing finding has to say what the scan cannot see.
        assert "slash" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_a_runtime_with_no_environment_variables_passes(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [self._RUNTIMES[0]]
        }
        mock_ac.get_agent_runtime.return_value = {"agentRuntimeId": "rt-clean"}

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert [finding["Status"] for finding in findings] == ["Passed"]
        assert "no environment variables" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_runtime_does_not_hide_the_others(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": self._RUNTIMES}

        def details(agentRuntimeId, **kwargs):
            if agentRuntimeId == "rt-clean":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "GetAgentRuntime",
                )
            return self._details(agentRuntimeId)

        mock_ac.get_agent_runtime.side_effect = details

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert [finding["Status"] for finding in findings] == ["N/A", "Failed"]
        assert "GetAgentRuntime" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_runtimes_are_read_from_every_page(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = [
            {"agentRuntimes": [self._RUNTIMES[0]], "nextToken": "rt-page-2"},
            {"agentRuntimes": [self._RUNTIMES[1]]},
        ]
        mock_ac.get_agent_runtime.side_effect = self._details

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert mock_ac.list_agent_runtimes.call_count == 2
        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_reported_as_incomplete(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListAgentRuntimes",
        )

        findings = agentcore_app.check_agentcore_runtime_inline_credentials()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert findings[0]["Finding"].endswith("Incomplete")

    @patch("agentcore_app.agentcore_client")
    def test_no_runtimes_is_na(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        findings = agentcore_app.check_agentcore_runtime_inline_credentials()
        assert [finding["Status"] for finding in findings] == ["N/A"]

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_runtime_inline_credentials()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-34"


class TestAC34CheckRegistration:
    """AC-34 reads a regional resource, so it runs in every scanned region."""

    def test_the_runtime_check_is_in_both_regional_tuples(self):
        assert "AC-34" in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-34" in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_timeout_backfill_emits_the_runtime_check(self):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        assert "AC-34" in {finding["Check_ID"] for finding in findings}

    def test_the_handler_registers_the_runtime_check_once(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count("check_agentcore_runtime_inline_credentials") == 1

    def test_the_scanned_field_is_modelled_and_marked_sensitive(self):
        # A field the API does not return would make every runtime pass, and the
        # sensitive marker is why the finding names variables and not values.
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        environment = model.operation_model("GetAgentRuntime").output_shape.members[
            "environmentVariables"
        ]
        assert environment.type_name == "map"
        assert environment.metadata.get("sensitive") is True
        # The variables are optional on create, so an absent map is a real state
        # and not a truncated read.
        create = model.operation_model("CreateAgentRuntime").input_shape
        assert "environmentVariables" not in create.required_members


# ---------------------------------------------------------------------------
# Policy engine controls (AC-35 through AC-38)
# ---------------------------------------------------------------------------
_ENGINE_ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/pe-1"


def _policy_engine_gateway(mode="ENFORCE", arn=_ENGINE_ARN, **extra):
    detail = {"policyEngineConfiguration": {"arn": arn, "mode": mode}}
    detail.update(extra)
    return detail


def _cedar_policy(name, statement, status="ACTIVE", enforcement_mode="ACTIVE"):
    return {
        "policyId": f"{name}-id",
        "name": name,
        "status": status,
        "enforcementMode": enforcement_mode,
        "definition": {"cedar": {"statement": statement}},
    }


# Verbatim from the live probe estate: the one policy of 31 whose permit leaves
# the action position unconstrained, and which does carry a condition.
_LIVE_TAG_PERMIT = (
    "permit(\n"
    "  principal,\n"
    "  action,\n"
    "  resource is AgentCore::Gateway\n"
    ") when {\n"
    '  (principal.hasTag("AgentCoreApproved")) && '
    '((principal.getTag("AgentCoreApproved")) == "true")\n'
    "};"
)
_SCOPED_PERMIT = (
    "permit(\n"
    "  principal is AgentCore::OAuthUser,\n"
    '  action == AgentCore::Action::"payments___listPayees",\n'
    '  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:'
    '123456789012:gateway/gw-1"\n'
    ");"
)
_UNCONDITIONED_PERMIT = "permit(principal, action, resource);"
_FORBID_ONLY = (
    "forbid(\n"
    "  principal,\n"
    '  action == AgentCore::Action::"payments___transfer",\n'
    "  resource is AgentCore::Gateway\n"
    ");"
)
_TEMPORAL_PERMIT = (
    "permit(\n"
    "  principal,\n"
    '  action == AgentCore::Action::"payments___transfer",\n'
    "  resource is AgentCore::Gateway\n"
    ") when temporal {\n"
    '  context.session.count("payments___verifyPayee") > 0\n'
    "};"
)
_GUARDRAIL_FORBID = (
    "forbid(\n"
    "  principal,\n"
    '  action == AgentCore::Action::"support___reply",\n'
    "  resource is AgentCore::Gateway\n"
    ") when guardrails {\n"
    "  PromptAttack\n"
    "};"
)


class TestAC35PolicyToolScope:
    """AC-35: an enforcing permit has to name the tools it authorizes."""

    _GATEWAYS = [
        {"gatewayId": "gw-scoped", "name": "Scoped"},
        {"gatewayId": "gw-tagged", "name": "Tagged"},
        {"gatewayId": "gw-open", "name": "Open"},
        {"gatewayId": "gw-log-only", "name": "LogOnly"},
    ]

    def _details(self, gatewayIdentifier, **kwargs):
        if gatewayIdentifier == "gw-log-only":
            return _policy_engine_gateway(mode="LOG_ONLY")
        return _policy_engine_gateway(arn=f"{_ENGINE_ARN}-{gatewayIdentifier}")

    def _policies(self, policyEngineId, **kwargs):
        statements = {
            "pe-1-gw-scoped": _SCOPED_PERMIT,
            "pe-1-gw-tagged": _LIVE_TAG_PERMIT,
            "pe-1-gw-open": _UNCONDITIONED_PERMIT,
        }
        return {"policies": [_cedar_policy("p", statements[policyEngineId])]}

    @patch("agentcore_app.agentcore_client")
    def test_each_gateway_gets_its_own_verdict(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._details
        mock_ac.list_policies.side_effect = self._policies

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert len(findings) == 4
        by_gateway = {}
        for finding in findings:
            assert finding["Check_ID"] == "AC-35"
            assert_finding_schema(finding)
            for gateway in self._GATEWAYS:
                if gateway["gatewayId"] in finding["Finding_Details"]:
                    by_gateway[gateway["gatewayId"]] = finding
        assert by_gateway["gw-scoped"]["Status"] == "Passed"
        assert by_gateway["gw-tagged"]["Status"] == "Failed"
        assert by_gateway["gw-tagged"]["Severity"] == "Medium"
        assert by_gateway["gw-open"]["Status"] == "Failed"
        assert by_gateway["gw-open"]["Severity"] == "High"
        assert by_gateway["gw-log-only"]["Status"] == "N/A"
        assert "AG-25" in by_gateway["gw-log-only"]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_live_tag_permit_gates_every_tool_with_one_condition(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[1]]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("abac_permit", _LIVE_TAG_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Unbounded")
        assert "abac_permit" in findings[0]["Finding_Details"]
        assert "every tool added to it later" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_unconditioned_permit_is_high(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[2]]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("allow_all", _UNCONDITIONED_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert "default-deny decides nothing" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_unbounded_permit_outranks_a_scoped_one_on_the_same_engine(
        self, mock_ac
    ):
        # A scoped permit beside an allow-all permit is still allow-all: Cedar
        # unions permits, so the widest one decides.
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.return_value = {
            "policies": [
                _cedar_policy("scoped", _SCOPED_PERMIT),
                _cedar_policy("allow_all", _UNCONDITIONED_PERMIT),
            ]
        }

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert [finding["Status"] for finding in findings] == ["Failed"]
        assert "policy allow_all permits" in findings[0]["Finding_Details"]
        assert "policy scoped permits" not in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_forbid_only_engine_passes_with_no_permit_to_read(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("deny_transfer", _FORBID_ONLY)]
        }

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert [finding["Status"] for finding in findings] == ["Passed"]
        assert (
            "none of its 1 readable enforcing policies permits an action at all"
            in findings[0]["Finding_Details"]
        )

    @pytest.mark.parametrize(
        "status,enforcement_mode",
        [("ACTIVE", "LOG_ONLY"), ("CREATING", "ACTIVE"), ("DELETING", "ACTIVE")],
    )
    @patch("agentcore_app.agentcore_client")
    def test_a_policy_that_changes_no_response_is_not_read(
        self, mock_ac, status, enforcement_mode
    ):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[2]]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.return_value = {
            "policies": [
                _cedar_policy(
                    "allow_all",
                    _UNCONDITIONED_PERMIT,
                    status=status,
                    enforcement_mode=enforcement_mode,
                )
            ]
        }

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "holds no active enforcing policy" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_policy_still_being_generated_is_na_and_never_passes(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-generating",
                    "name": "generating",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                    "definition": {
                        "policyGeneration": {
                            "policyGenerationId": "pg-1",
                            "policyGenerationAssetId": "pga-1",
                        }
                    },
                }
            ]
        }

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "carries no policy text to read" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_generating_policy_beside_a_scoped_permit_reports_both(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.return_value = {
            "policies": [
                _cedar_policy("scoped", _SCOPED_PERMIT),
                {
                    "policyId": "p-generating",
                    "name": "generating",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                    "definition": {"policyGeneration": {"policyGenerationId": "pg-1"}},
                },
            ]
        }

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert [finding["Status"] for finding in findings] == ["Passed", "N/A"]
        assert (
            "every one of its 1 enforcing permit policies"
            in findings[0]["Finding_Details"]
        )

    @patch("agentcore_app.agentcore_client")
    def test_policies_are_read_once_per_engine_across_gateways(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS[:2]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("scoped", _SCOPED_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert [finding["Status"] for finding in findings] == ["Passed", "Passed"]
        assert mock_ac.list_policies.call_count == 1

    @patch("agentcore_app.agentcore_client")
    def test_policies_are_read_from_every_page(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.side_effect = [
            {
                "policies": [_cedar_policy("scoped", _SCOPED_PERMIT)],
                "nextToken": "page-2",
            },
            {"policies": [_cedar_policy("allow_all", _UNCONDITIONED_PERMIT)]},
        ]

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert mock_ac.list_policies.call_count == 2
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_gateways_are_read_from_every_page(self, mock_ac):
        mock_ac.list_gateways.side_effect = [
            {"items": [self._GATEWAYS[0]], "nextToken": "gw-page-2"},
            {"items": [self._GATEWAYS[2]]},
        ]
        mock_ac.get_gateway.side_effect = self._details
        mock_ac.list_policies.side_effect = self._policies

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert mock_ac.list_gateways.call_count == 2
        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_gateway_does_not_hide_the_others(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS[:2]}

        def details(gatewayIdentifier, **kwargs):
            if gatewayIdentifier == "gw-scoped":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "GetGateway",
                )
            return _policy_engine_gateway()

        mock_ac.get_gateway.side_effect = details
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("allow_all", _UNCONDITIONED_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert [finding["Status"] for finding in findings] == ["N/A", "Failed"]
        assert "bedrock-agentcore:ListPolicies" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_an_unreadable_policy_list_is_na_for_that_gateway(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": [self._GATEWAYS[0]]}
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListPolicies",
        )

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "could not be read" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_reported_as_incomplete(self, mock_ac):
        mock_ac.list_gateways.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListGateways",
        )

        findings = agentcore_app.check_agentcore_policy_tool_scope()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert findings[0]["Finding"].endswith("Incomplete")

    @patch("agentcore_app.agentcore_client")
    def test_no_gateways_is_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        findings = agentcore_app.check_agentcore_policy_tool_scope()
        assert [finding["Status"] for finding in findings] == ["N/A"]

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_policy_tool_scope()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-35"


class TestCedarStatementReader:
    """The Cedar reader the three policy checks share."""

    def test_a_comment_holding_a_semicolon_does_not_split_a_policy(self):
        statement = (
            "// forbid(principal, action, resource); this is prose, not a policy\n"
            + _SCOPED_PERMIT
        )
        parsed = agentcore_app._cedar_policies(statement)
        assert len(parsed) == 1
        assert parsed[0][0] == "permit"

    def test_a_semicolon_inside_a_string_literal_does_not_split_a_policy(self):
        statement = (
            "permit(\n"
            "  principal,\n"
            '  action == AgentCore::Action::"a;b",\n'
            "  resource\n"
            ");"
        )
        parsed = agentcore_app._cedar_policies(statement)
        assert len(parsed) == 1
        assert parsed[0][1][1] == 'action == AgentCore::Action::"a;b"'

    def test_two_policies_in_one_statement_are_both_read(self):
        parsed = agentcore_app._cedar_policies(
            f"{_SCOPED_PERMIT}\n{_UNCONDITIONED_PERMIT}"
        )
        assert [effect for effect, _, _ in parsed] == ["permit", "permit"]

    def test_every_live_statement_reads_as_three_scope_positions(self):
        for statement in (
            _SCOPED_PERMIT,
            _LIVE_TAG_PERMIT,
            _UNCONDITIONED_PERMIT,
            _FORBID_ONLY,
            _TEMPORAL_PERMIT,
            _GUARDRAIL_FORBID,
        ):
            parsed = agentcore_app._cedar_policies(statement)
            assert len(parsed) == 1
            assert len(parsed[0][1]) == len(agentcore_app.CEDAR_SCOPE_POSITIONS)

    def test_the_scope_predicate_reads_a_position_and_not_a_substring(self):
        # `resource` is bare here and `action` is not, so an implementation
        # searching the whole scope for the keyword would score this unbounded.
        parsed = agentcore_app._cedar_policies(
            'permit(principal, action == AgentCore::Action::"a", resource);'
        )
        scope = parsed[0][1]
        assert not agentcore_app._cedar_scope_is_unconstrained(scope, "action")
        assert agentcore_app._cedar_scope_is_unconstrained(scope, "resource")
        assert agentcore_app._cedar_scope_is_unconstrained(scope, "principal")

    def test_a_truncated_scope_is_not_read_as_unconstrained(self):
        # A scope with fewer parts than the grammar has cannot be scored by
        # position, and searching it for the keyword instead would read the
        # second of these as an unbounded action.
        assert not agentcore_app._cedar_scope_is_unconstrained(["principal"], "action")
        assert not agentcore_app._cedar_scope_is_unconstrained(
            ["action", "resource"], "action"
        )

    def test_a_comma_inside_a_string_literal_does_not_add_a_scope_position(self):
        parsed = agentcore_app._cedar_policies(
            'permit(principal, action == AgentCore::Action::"a,b", resource);'
        )
        scope = parsed[0][1]
        assert len(scope) == len(agentcore_app.CEDAR_SCOPE_POSITIONS)
        assert scope[1] == 'action == AgentCore::Action::"a,b"'
        assert agentcore_app._cedar_scope_is_unconstrained(scope, "resource")

    def test_the_condition_qualifier_separates_the_three_block_kinds(self):
        plain = agentcore_app._cedar_policies(_LIVE_TAG_PERMIT)[0][2]
        temporal = agentcore_app._cedar_policies(_TEMPORAL_PERMIT)[0][2]
        guardrails = agentcore_app._cedar_policies(_GUARDRAIL_FORBID)[0][2]
        assert agentcore_app._cedar_condition_qualifiers(plain) == {""}
        assert agentcore_app._cedar_condition_qualifiers(temporal) == {
            agentcore_app.CEDAR_TEMPORAL_QUALIFIER
        }
        assert agentcore_app._cedar_condition_qualifiers(guardrails) == {
            agentcore_app.CEDAR_GUARDRAIL_QUALIFIER
        }
        assert agentcore_app._cedar_condition_qualifiers("") == set()

    def test_an_unless_block_carries_its_qualifier_too(self):
        assert agentcore_app._cedar_condition_qualifiers(
            'unless temporal {\n  context.session.count("x") > 3\n}'
        ) == {agentcore_app.CEDAR_TEMPORAL_QUALIFIER}

    def test_a_dogwood_definition_is_read_from_its_own_key(self):
        assert (
            agentcore_app._policy_statement_text(
                {"definition": {"policy": {"statement": _SCOPED_PERMIT}}}
            )
            == _SCOPED_PERMIT
        )
        assert (
            agentcore_app._policy_statement_text(
                {"definition": {"policyGeneration": {"policyGenerationId": "pg-1"}}}
            )
            == ""
        )
        assert agentcore_app._policy_statement_text({}) == ""

    def test_a_log_only_engine_configuration_names_no_engine(self):
        assert (
            agentcore_app._gateway_policy_engine_id(_policy_engine_gateway()) == "pe-1"
        )
        assert (
            agentcore_app._gateway_policy_engine_id(
                _policy_engine_gateway(mode="LOG_ONLY")
            )
            == ""
        )
        assert agentcore_app._gateway_policy_engine_id({}) == ""


class TestAC35CheckRegistration:
    """AC-35 reads a regional resource, so it runs in every scanned region."""

    def test_the_policy_check_is_in_both_regional_tuples(self):
        assert "AC-35" in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-35" in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_timeout_backfill_emits_the_policy_check(self):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        assert "AC-35" in {finding["Check_ID"] for finding in findings}

    def test_the_handler_registers_the_policy_check_once(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count("check_agentcore_policy_tool_scope") == 1

    def test_the_filtered_values_are_the_ones_the_api_models(self):
        # A value the model does not carry would filter every policy out and pass
        # every gateway, and a fourth definition member would read as unreadable.
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        policy = (
            model.operation_model("ListPolicies")
            .output_shape.members["policies"]
            .member
        )
        assert (
            agentcore_app.POLICY_ACTIVE_STATUS
            in policy.members["status"].metadata["enum"]
        )
        assert (
            agentcore_app.POLICY_ENFORCING_MODE
            in policy.members["enforcementMode"].metadata["enum"]
        )
        assert set(policy.members["definition"].members) == {
            "cedar",
            "policy",
            "policyGeneration",
        }
        assert "definition" in policy.required_members
        configuration = model.operation_model("GetGateway").output_shape.members[
            "policyEngineConfiguration"
        ]
        assert (
            agentcore_app.POLICY_ENGINE_ENFORCE_MODE
            in configuration.members["mode"].metadata["enum"]
        )
        # The configuration carries no id, which is why the id comes off the ARN.
        assert set(configuration.members) == {"arn", "mode"}
        assert (
            "policyEngineId"
            in model.operation_model("ListPolicies").input_shape.required_members
        )


class TestAC36PolicyEngineKeyScope:
    """AC-36: who may decrypt a policy engine's key, and who may take it away."""

    _KEY = "arn:aws:kms:us-east-1:123456789012:key/pe-key"
    _ENGINES = [
        {"policyEngineId": "pe-1", "name": "Payments"},
        {"policyEngineId": "pe-2", "name": "Support"},
    ]
    _SCOPED = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                    "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/KeyAdministrator"
                    },
                    "Action": "kms:*",
                    "Resource": "*",
                },
            ]
        }
    )
    _OPEN_DECRYPT = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ]
        }
    )
    _OPEN_DELETE = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": ["kms:ScheduleKeyDeletion", "kms:DisableKey"],
                    "Resource": "*",
                }
            ]
        }
    )

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_scoped_key_policy_passes(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.return_value = {"Policy": self._SCOPED}

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-36"
        assert findings[0]["Status"] == "Passed"
        assert self._KEY in findings[0]["Finding_Details"]
        assert "alarm" in findings[0]["Resolution"]
        assert "break-glass" in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_open_decrypt_grant_fails(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.return_value = {"Policy": self._OPEN_DECRYPT}

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert findings[0]["Finding"].endswith("Unbounded")
        assert "every principal decrypt" in findings[0]["Finding_Details"]
        assert "kms:ViaService" in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_open_destroy_grant_fails_on_its_own(self, mock_ac, mock_kms):
        # Nobody can read the Cedar policies, and anybody can make them
        # unreadable: AC-11's CMK is present and the key is still the whole guard.
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.return_value = {"Policy": self._OPEN_DELETE}

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert findings[0]["Status"] == "Failed"
        assert "disablekey, schedulekeydeletion" in findings[0]["Finding_Details"]
        assert "every principal decrypt" not in findings[0]["Finding_Details"]
        assert "cannot be repointed at a new key" in findings[0]["Finding_Details"]

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_both_problems_are_reported_in_one_finding(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    ]
                }
            )
        }

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        details = findings[0]["Finding_Details"]
        assert "every principal decrypt" in details
        assert " and lets every principal call " in details
        assert "disablekey, disablekeyrotation, putkeypolicy, schedulekeydeletion" in (
            details
        )

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_action_wildcard_with_no_namespace_reaches_every_action(
        self, mock_ac, mock_kms
    ):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                }
            )
        }

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert findings[0]["Status"] == "Failed"
        details = findings[0]["Finding_Details"]
        assert "every principal decrypt" in details
        assert "disablekey, disablekeyrotation, putkeypolicy, schedulekeydeletion" in (
            details
        )

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_conditioned_wildcard_grant_is_not_reported(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["kms:Decrypt", "kms:ScheduleKeyDeletion"],
                            "Resource": "*",
                            "Condition": {
                                "StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}
                            },
                        }
                    ]
                }
            )
        }

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_grant_in_another_service_namespace_is_not_a_kms_grant(
        self, mock_ac, mock_kms
    ):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "secretsmanager:DisableKey",
                            "Resource": "*",
                        }
                    ]
                }
            )
        }

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_deny_statement_is_not_read_as_a_grant(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "kms:ScheduleKeyDeletion",
                            "Resource": "*",
                        }
                    ]
                }
            )
        }

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_engine_with_no_key_defers_to_ac11(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"policyEngineId": "pe-1"}

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "AC-11" in findings[0]["Finding_Details"]
        assert mock_kms.get_key_policy.call_count == 0

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_one_key_shared_by_two_engines_is_read_once(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.return_value = {"Policy": self._OPEN_DECRYPT}

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert [finding["Status"] for finding in findings] == ["Failed", "Failed"]
        assert mock_kms.get_key_policy.call_count == 1

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_engines_are_read_from_every_page(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.side_effect = [
            {"policyEngines": self._ENGINES[:1], "nextToken": "page-2"},
            {"policyEngines": self._ENGINES[1:]},
        ]
        mock_ac.get_policy_engine.side_effect = [
            {"encryptionKeyArn": self._KEY},
            {"encryptionKeyArn": f"{self._KEY}-2"},
        ]
        mock_kms.get_key_policy.side_effect = [
            {"Policy": self._SCOPED},
            {"Policy": self._OPEN_DELETE},
        ]

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert mock_ac.list_policy_engines.call_count == 2
        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_unreadable_key_policy_is_na_and_does_not_pass(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES[:1]}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "GetKeyPolicy",
        )

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "kms:GetKeyPolicy" in findings[0]["Resolution"]

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_unreadable_key_policy_is_not_retried_per_engine(
        self, mock_ac, mock_kms
    ):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES}
        mock_ac.get_policy_engine.return_value = {"encryptionKeyArn": self._KEY}
        mock_kms.get_key_policy.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "GetKeyPolicy",
        )

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert [finding["Status"] for finding in findings] == ["N/A", "N/A"]
        assert mock_kms.get_key_policy.call_count == 1

    @patch("agentcore_app.kms_client")
    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_engine_does_not_hide_the_others(self, mock_ac, mock_kms):
        mock_ac.list_policy_engines.return_value = {"policyEngines": self._ENGINES}

        def detail(policyEngineId, **kwargs):
            if policyEngineId == "pe-1":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "GetPolicyEngine",
                )
            return {"encryptionKeyArn": self._KEY}

        mock_ac.get_policy_engine.side_effect = detail
        mock_kms.get_key_policy.return_value = {"Policy": self._OPEN_DECRYPT}

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert [finding["Status"] for finding in findings] == ["N/A", "Failed"]
        assert "bedrock-agentcore:GetPolicyEngine" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_reported_as_incomplete(self, mock_ac):
        mock_ac.list_policy_engines.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListPolicyEngines",
        )

        findings = agentcore_app.check_agentcore_policy_engine_key_scope()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert findings[0]["Finding"].endswith("Incomplete")

    @patch("agentcore_app.agentcore_client")
    def test_no_engines_is_na(self, mock_ac):
        mock_ac.list_policy_engines.return_value = {"policyEngines": []}
        findings = agentcore_app.check_agentcore_policy_engine_key_scope()
        assert [finding["Status"] for finding in findings] == ["N/A"]

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_policy_engine_key_scope()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-36"


class TestAC36CheckRegistration:
    """AC-36 reads regional policy engines and their regional keys."""

    def test_the_key_scope_check_is_in_both_regional_tuples(self):
        assert "AC-36" in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-36" in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_timeout_backfill_emits_the_key_scope_check(self):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        assert "AC-36" in {finding["Check_ID"] for finding in findings}

    def test_the_handler_registers_the_key_scope_check_once(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count("check_agentcore_policy_engine_key_scope") == 1

    def test_the_key_can_be_named_at_creation_and_never_changed(self):
        # The check asserts the key policy because the key itself is immutable:
        # if UpdatePolicyEngine took a key, a wrong key would be remediable
        # without touching the key policy at all.
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        assert (
            "encryptionKeyArn"
            in model.operation_model("CreatePolicyEngine").input_shape.members
        )
        assert (
            "encryptionKeyArn"
            not in model.operation_model("UpdatePolicyEngine").input_shape.members
        )
        assert (
            "encryptionKeyArn"
            in model.operation_model("GetPolicyEngine").output_shape.members
        )

    def test_every_destroying_action_is_one_kms_models(self):
        # A misspelled action here would silently never match a key policy.
        model = agentcore_app.boto3.client(
            "kms",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        operations = {name.lower() for name in model.operation_names}
        assert set(agentcore_app.KMS_KEY_DISABLING_ACTIONS) <= operations


class TestAC37PolicyGuardrailWiring:
    """AC-37: a guardrail policy needs a gateway role that can call the guardrail."""

    _GATEWAYS = [{"gatewayId": "gw-1", "name": "Support"}]
    _ROLE_ARN = "arn:aws:iam::123456789012:role/GatewayExecution"
    # The API spells the action with capitals; the module lowercases patterns to
    # compare them, so a role written the way the console writes it must match.
    _GRANTING_ROLE = {
        "role_permissions": {
            "GatewayExecution": {
                "attached_policies": [
                    {
                        "policy_name": "GuardrailChecks",
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["bedrock:InvokeGuardrailChecks"],
                                    "Resource": (
                                        "arn:aws:bedrock:us-east-1:123456789012:"
                                        "guardrail/gr-1"
                                    ),
                                }
                            ]
                        },
                    }
                ]
            }
        }
    }
    _SILENT_ROLE = {
        "role_permissions": {
            "GatewayExecution": {
                "inline_policies": [
                    {
                        "policy_name": "InvokeOnly",
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "bedrock:InvokeModel",
                                    "Resource": "*",
                                }
                            ]
                        },
                    }
                ]
            }
        }
    }

    def _gateway_detail(self, **kwargs):
        return _policy_engine_gateway(roleArn=self._ROLE_ARN)

    @patch("agentcore_app.agentcore_client")
    def test_a_granted_role_passes(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._gateway_detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("block_injection", _GUARDRAIL_FORBID)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._GRANTING_ROLE
        )

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-37"
        assert findings[0]["Status"] == "Passed"
        assert "block_injection" in findings[0]["Finding_Details"]
        assert "bedrock:InvokeGuardrailChecks" in findings[0]["Finding_Details"]
        assert "non-deterministic" in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_a_role_without_the_grant_fails(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._gateway_detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("block_injection", _GUARDRAIL_FORBID)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._SILENT_ROLE
        )

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert findings[0]["Finding"].endswith("Incomplete")
        assert "forward access session" in findings[0]["Finding_Details"]
        assert "fails open or closed" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_a_wildcard_grant_reaches_the_guardrail_call(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._gateway_detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("block_injection", _GUARDRAIL_FORBID)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            {
                "role_permissions": {
                    "GatewayExecution": {
                        "inline_policies": [
                            {
                                "policy_name": "InvokeAnything",
                                "document": {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "bedrock:Invoke*",
                                            "Resource": "*",
                                        }
                                    ]
                                },
                            }
                        ]
                    }
                }
            }
        )

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_a_gateway_with_no_guardrail_policy_is_na_and_names_the_owner(
        self, mock_ac
    ):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._gateway_detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("scoped", _SCOPED_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._SILENT_ROLE
        )

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "which no API reports" in findings[0]["Finding_Details"]
        assert "record the decision either way" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_a_temporal_condition_is_not_a_guardrail_condition(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._gateway_detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("spend_cap", _TEMPORAL_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._GRANTING_ROLE
        )

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert (
            "enforces no policy with a guardrails condition"
            in (findings[0]["Finding_Details"])
        )

    @patch("agentcore_app.agentcore_client")
    def test_a_role_outside_the_snapshot_is_na_and_does_not_fail(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            roleArn="arn:aws:iam::210987654321:role/CrossAccountGateway"
        )
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("block_injection", _GUARDRAIL_FORBID)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._GRANTING_ROLE
        )

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "not in the IAM permissions snapshot" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_unparseable_role_document_is_na_and_never_fails(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._gateway_detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("block_injection", _GUARDRAIL_FORBID)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            {
                "role_permissions": {
                    "GatewayExecution": {
                        "attached_policies": [{"document": "{not json"}]
                    }
                }
            }
        )

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "1 of the 1 policy document(s)" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_later_document_without_the_grant_does_not_undo_an_earlier_one(
        self, mock_ac
    ):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._gateway_detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("block_injection", _GUARDRAIL_FORBID)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            {
                "role_permissions": {
                    "GatewayExecution": {
                        "attached_policies": self._GRANTING_ROLE["role_permissions"][
                            "GatewayExecution"
                        ]["attached_policies"],
                        "inline_policies": self._SILENT_ROLE["role_permissions"][
                            "GatewayExecution"
                        ]["inline_policies"],
                    }
                }
            }
        )

        assert [finding["Status"] for finding in findings] == ["Passed"]

    @patch("agentcore_app.agentcore_client")
    def test_a_grant_in_a_readable_document_outranks_an_unreadable_one(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.side_effect = self._gateway_detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("block_injection", _GUARDRAIL_FORBID)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            {
                "role_permissions": {
                    "GatewayExecution": {
                        "attached_policies": [
                            {"document": "{not json"},
                            *self._GRANTING_ROLE["role_permissions"][
                                "GatewayExecution"
                            ]["attached_policies"],
                        ]
                    }
                }
            }
        )

        assert [finding["Status"] for finding in findings] == ["Passed"]

    @patch("agentcore_app.agentcore_client")
    def test_a_log_only_engine_reads_no_guardrail_policy(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            mode="LOG_ONLY", roleArn=self._ROLE_ARN
        )

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._SILENT_ROLE
        )

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert mock_ac.list_policies.call_count == 0

    @patch("agentcore_app.agentcore_client")
    def test_gateways_are_read_from_every_page(self, mock_ac):
        mock_ac.list_gateways.side_effect = [
            {"items": self._GATEWAYS, "nextToken": "page-2"},
            {"items": [{"gatewayId": "gw-2", "name": "Payments"}]},
        ]
        mock_ac.get_gateway.side_effect = self._gateway_detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("block_injection", _GUARDRAIL_FORBID)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._SILENT_ROLE
        )

        assert mock_ac.list_gateways.call_count == 2
        assert [finding["Status"] for finding in findings] == ["Failed", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_gateway_does_not_hide_the_others(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [*self._GATEWAYS, {"gatewayId": "gw-2", "name": "Payments"}]
        }

        def detail(gatewayIdentifier, **kwargs):
            if gatewayIdentifier == "gw-1":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "GetGateway",
                )
            return _policy_engine_gateway(roleArn=self._ROLE_ARN)

        mock_ac.get_gateway.side_effect = detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("block_injection", _GUARDRAIL_FORBID)]
        }

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._SILENT_ROLE
        )

        assert [finding["Status"] for finding in findings] == ["N/A", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_reported_as_incomplete(self, mock_ac):
        mock_ac.list_gateways.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListGateways",
        )

        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._GRANTING_ROLE
        )

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert findings[0]["Finding"].endswith("Incomplete")

    @patch("agentcore_app.agentcore_client")
    def test_no_gateways_is_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._GRANTING_ROLE
        )
        assert [finding["Status"] for finding in findings] == ["N/A"]

    @pytest.mark.parametrize("cache", [None, {}, {"role_permissions": {}}])
    @patch("agentcore_app.agentcore_client")
    def test_an_empty_permission_cache_is_na_before_any_api_call(self, mock_ac, cache):
        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(cache)

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert (
            "No IAM role permissions are in the cache"
            in (findings[0]["Finding_Details"])
        )
        assert mock_ac.list_gateways.call_count == 0

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_policy_guardrail_wiring(
            self._GRANTING_ROLE
        )
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-37"


class TestAC37CheckRegistration:
    """AC-37 reads regional gateways, and takes the handler's IAM cache."""

    def test_the_guardrail_check_is_in_both_regional_tuples(self):
        assert "AC-37" in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-37" in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_timeout_backfill_emits_the_guardrail_check(self):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        assert "AC-37" in {finding["Check_ID"] for finding in findings}

    def test_the_handler_passes_the_permission_cache_to_the_check(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count("check_agentcore_policy_guardrail_wiring") == 1
        assert (
            "lambda: check_agentcore_policy_guardrail_wiring(permission_cache)"
            in source
        )

    def test_the_guardrail_action_is_one_bedrock_models(self):
        model = agentcore_app.boto3.client(
            "bedrock-runtime",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        assert "ApplyGuardrail" in model.operation_names
        namespace, _, action = agentcore_app.GUARDRAIL_CHECK_ACTION.partition(":")
        assert namespace == "bedrock"
        assert action == "InvokeGuardrailChecks"
        assert (
            agentcore_app.GUARDRAIL_CHECK_ACTION_LOOKUP
            == agentcore_app.GUARDRAIL_CHECK_ACTION.lower()
        )

    def test_the_action_is_matched_in_the_spelling_the_console_writes(self):
        statement = {
            "Effect": "Allow",
            "Action": "bedrock:InvokeGuardrailChecks",
            "Resource": "*",
        }
        assert agentcore_app._statement_matches_action(
            statement, agentcore_app.GUARDRAIL_CHECK_ACTION_LOOKUP
        )
        assert not agentcore_app._statement_matches_action(
            statement, agentcore_app.GUARDRAIL_CHECK_ACTION
        )


class TestAC38PolicySessionBinding:
    """AC-38: a temporal policy only isolates sessions on an authenticated gateway."""

    _GATEWAYS = [{"gatewayId": "gw-1", "name": "Payments"}]

    @pytest.mark.parametrize("authorizer", ["CUSTOM_JWT", "AWS_IAM"])
    @patch("agentcore_app.agentcore_client")
    def test_a_temporal_policy_on_an_authenticated_gateway_passes(
        self, mock_ac, authorizer
    ):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            authorizerType=authorizer
        )
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("verify_payee", _TEMPORAL_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-38"
        assert findings[0]["Status"] == "Passed"
        assert "verify_payee" in findings[0]["Finding_Details"]
        assert authorizer in findings[0]["Finding_Details"]
        assert "x-amzn-bedrock-agentcore-policy-session-id" in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @pytest.mark.parametrize("authorizer", ["NONE", "AUTHENTICATE_ONLY", None])
    @patch("agentcore_app.agentcore_client")
    def test_a_temporal_policy_on_an_unauthenticated_gateway_fails(
        self, mock_ac, authorizer
    ):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            authorizerType=authorizer
        )
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("verify_payee", _TEMPORAL_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert findings[0]["Finding"].endswith("Unauthenticated")
        assert (authorizer or "unspecified") in findings[0]["Finding_Details"]
        assert "inherits it" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_the_authorizer_is_read_from_the_list_entry_when_the_detail_omits_it(
        self, mock_ac
    ):
        mock_ac.list_gateways.return_value = {
            "items": [{**self._GATEWAYS[0], "authorizerType": "CUSTOM_JWT"}]
        }
        mock_ac.get_gateway.return_value = _policy_engine_gateway()
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("verify_payee", _TEMPORAL_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_no_temporal_policy_is_a_medium_failure(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            authorizerType="CUSTOM_JWT"
        )
        mock_ac.list_policies.return_value = {
            "policies": [
                _cedar_policy("scoped", _SCOPED_PERMIT),
                _cedar_policy("deny_transfer", _FORBID_ONLY),
            ]
        }

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert findings[0]["Finding"].endswith("Absent")
        assert "2 active enforcing policy or policies" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_plain_condition_block_is_not_session_aware(self, mock_ac):
        # The live tag permit carries a `when { ... }` block with no qualifier,
        # which is evaluated against one request and holds no session history.
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            authorizerType="CUSTOM_JWT"
        )
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("abac_permit", _LIVE_TAG_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Absent")

    @patch("agentcore_app.agentcore_client")
    def test_a_temporal_forbid_is_session_aware_too(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            authorizerType="AWS_IAM"
        )
        mock_ac.list_policies.return_value = {
            "policies": [
                _cedar_policy(
                    "spend_cap",
                    "forbid(\n"
                    "  principal,\n"
                    '  action == AgentCore::Action::"payments___transfer",\n'
                    "  resource\n"
                    ") when temporal {\n"
                    '  context.session.sum("amount") > 1000\n'
                    "};",
                )
            ]
        }

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert findings[0]["Status"] == "Passed"
        assert "spend_cap" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_suppress_output_policy_is_not_an_authorizing_decision(self, mock_ac):
        # suppressOutput decides no request, so a temporal condition on it does
        # not make the gateway's authorization session-aware.
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            authorizerType="CUSTOM_JWT"
        )
        mock_ac.list_policies.return_value = {
            "policies": [
                _cedar_policy(
                    "redact_after_first",
                    "suppressOutput(\n"
                    "  principal,\n"
                    '  action == AgentCore::Action::"payments___listPayees",\n'
                    "  resource\n"
                    ") when temporal {\n"
                    '  context.session.count("payments___listPayees") > 1\n'
                    "};",
                )
            ]
        }

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Finding"].endswith("Absent")

    @patch("agentcore_app.agentcore_client")
    def test_a_gateway_with_no_engine_defers_to_ag25(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = {"authorizerType": "CUSTOM_JWT"}

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "AG-25" in findings[0]["Finding_Details"]
        assert mock_ac.list_policies.call_count == 0

    @patch("agentcore_app.agentcore_client")
    def test_a_log_only_engine_defers_to_ag25(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            mode="LOG_ONLY", authorizerType="CUSTOM_JWT"
        )

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert "enforces no policy engine" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_policies_are_read_from_every_page(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": self._GATEWAYS}
        mock_ac.get_gateway.return_value = _policy_engine_gateway(
            authorizerType="CUSTOM_JWT"
        )
        mock_ac.list_policies.side_effect = [
            {
                "policies": [_cedar_policy("scoped", _SCOPED_PERMIT)],
                "nextToken": "page-2",
            },
            {"policies": [_cedar_policy("verify_payee", _TEMPORAL_PERMIT)]},
        ]

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert mock_ac.list_policies.call_count == 2
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_gateways_are_read_from_every_page(self, mock_ac):
        mock_ac.list_gateways.side_effect = [
            {"items": self._GATEWAYS, "nextToken": "page-2"},
            {"items": [{"gatewayId": "gw-2", "name": "Support"}]},
        ]

        def detail(gatewayIdentifier, **kwargs):
            if gatewayIdentifier == "gw-1":
                return _policy_engine_gateway(authorizerType="CUSTOM_JWT")
            return _policy_engine_gateway(authorizerType="NONE")

        mock_ac.get_gateway.side_effect = detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("verify_payee", _TEMPORAL_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert mock_ac.list_gateways.call_count == 2
        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_gateway_does_not_hide_the_others(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [*self._GATEWAYS, {"gatewayId": "gw-2", "name": "Support"}]
        }

        def detail(gatewayIdentifier, **kwargs):
            if gatewayIdentifier == "gw-1":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "GetGateway",
                )
            return _policy_engine_gateway(authorizerType="NONE")

        mock_ac.get_gateway.side_effect = detail
        mock_ac.list_policies.return_value = {
            "policies": [_cedar_policy("verify_payee", _TEMPORAL_PERMIT)]
        }

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert [finding["Status"] for finding in findings] == ["N/A", "Failed"]
        assert "bedrock-agentcore:ListPolicies" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_reported_as_incomplete(self, mock_ac):
        mock_ac.list_gateways.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListGateways",
        )

        findings = agentcore_app.check_agentcore_policy_session_binding()

        assert [finding["Status"] for finding in findings] == ["N/A"]
        assert findings[0]["Finding"].endswith("Incomplete")

    @patch("agentcore_app.agentcore_client")
    def test_no_gateways_is_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        findings = agentcore_app.check_agentcore_policy_session_binding()
        assert [finding["Status"] for finding in findings] == ["N/A"]

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_policy_session_binding()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-38"


class TestAC38CheckRegistration:
    """AC-38 reads a regional gateway and its regional policy engine."""

    def test_the_session_binding_check_is_in_both_regional_tuples(self):
        assert "AC-38" in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert "AC-38" in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    def test_timeout_backfill_emits_the_session_binding_check(self):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        assert "AC-38" in {finding["Check_ID"] for finding in findings}

    def test_the_handler_registers_the_session_binding_check_once(self):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count("check_agentcore_policy_session_binding") == 1

    def test_the_binding_authorizers_are_modelled_authorizer_types(self):
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        modelled = set(
            model.operation_model("GetGateway")
            .output_shape.members["authorizerType"]
            .metadata["enum"]
        )
        assert set(agentcore_app.GATEWAY_SESSION_BINDING_AUTHORIZERS) <= modelled
        # The failing legs are the authorizer types left over, so the check has
        # something to fail on.
        assert modelled - set(agentcore_app.GATEWAY_SESSION_BINDING_AUTHORIZERS)


# ===================================================================
# AC-39 to AC-44: online evaluation checks
# ===================================================================
_EVALUATION_ROLE_ARN = "arn:aws:iam::123456789012:role/EvaluationRole"
_EVALUATION_RESULTS_GROUP = "/aws/bedrock-agentcore/evaluations/results/oec-1"


def _online_evaluation_summary(config_id="oec-1", name="continuous"):
    return {
        "onlineEvaluationConfigId": config_id,
        "onlineEvaluationConfigName": name,
    }


def _online_evaluation_detail(**overrides):
    """A configuration that satisfies every leg of AC-39, AC-40 and AC-41."""
    detail = {
        "onlineEvaluationConfigId": "oec-1",
        "onlineEvaluationConfigName": "continuous",
        "status": "ACTIVE",
        "executionStatus": "ENABLED",
        "rule": {"samplingConfig": {"samplingPercentage": 100.0}},
        "dataSourceConfig": {
            "cloudWatchLogs": {
                "logGroupNames": ["/aws/bedrock-agentcore/runtimes/agent-DEFAULT"],
                "serviceNames": ["agent"],
            }
        },
        "evaluators": [
            {"evaluatorId": "Builtin.Harmfulness"},
            {"evaluatorId": "Builtin.ToolSelectionAccuracy"},
        ],
        "outputConfig": {
            "cloudWatchConfig": {"logGroupName": _EVALUATION_RESULTS_GROUP}
        },
        "evaluationExecutionRoleArn": _EVALUATION_ROLE_ARN,
    }
    detail.update(overrides)
    return detail


def _evaluator_catalogue():
    """The three classes the live catalogue holds, in their live spellings."""
    return [
        {
            "evaluatorId": "Builtin.Harmfulness",
            "evaluatorType": "Builtin",
            "level": "TRACE",
            "description": "Safety Metric. Evaluates whether the response contains harmful content",
        },
        {
            "evaluatorId": "Builtin.ToolSelectionAccuracy",
            "evaluatorType": "Builtin",
            "level": "TOOL_CALL",
            "description": "Component Level Metric. Evaluates whether the agent selected the tool",
        },
        {
            "evaluatorId": "Builtin.Helpfulness",
            "evaluatorType": "Builtin",
            "level": "TRACE",
            "description": "Quality Metric. Evaluates how helpful the response is",
        },
        {
            "evaluatorId": "custom_tool_fidelity-abc",
            "evaluatorType": "Custom",
            "level": "TOOL_CALL",
            "description": "Safety Metric. Written in this account",
        },
    ]


def _online_evaluation_client(mock_ac, details=None, catalogue=None):
    details = details or [_online_evaluation_detail()]
    mock_ac.list_online_evaluation_configs.return_value = {
        "onlineEvaluationConfigs": [
            _online_evaluation_summary(
                detail["onlineEvaluationConfigId"],
                detail.get("onlineEvaluationConfigName", "continuous"),
            )
            for detail in details
        ]
    }
    by_id = {detail["onlineEvaluationConfigId"]: detail for detail in details}
    mock_ac.get_online_evaluation_config.side_effect = lambda onlineEvaluationConfigId: (
        by_id[onlineEvaluationConfigId]
    )
    mock_ac.list_evaluators.return_value = {
        "evaluators": catalogue if catalogue is not None else _evaluator_catalogue()
    }
    return mock_ac


class TestAC39OnlineEvaluationOperation:
    """AC-39: a configuration that exists is judged whatever the scanner was told."""

    @patch("agentcore_app.agentcore_client")
    def test_a_running_evaluation_passes(self, mock_ac):
        _online_evaluation_client(mock_ac)

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-39"
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "Medium"
        assert "samples 100.0 percent" in findings[0]["Finding_Details"]
        assert "1 log group(s) and 1 service(s)" in findings[0]["Finding_Details"]
        assert "2 evaluator(s)" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @pytest.mark.parametrize(
        ("overrides", "expected"),
        [
            ({"status": "CREATE_FAILED"}, "rather than ACTIVE"),
            ({"executionStatus": "DISABLED"}, "it scores no traffic"),
            ({"rule": {"samplingConfig": {"samplingPercentage": 0}}}, "above zero"),
            ({"rule": {}}, "above zero"),
            ({"rule": {"samplingConfig": {"samplingPercentage": "100"}}}, "above zero"),
            ({"dataSourceConfig": {"cloudWatchLogs": {}}}, "no traffic to read"),
            ({"outputConfig": {}}, "writes its results to no log group"),
            ({"evaluators": []}, "attaches no evaluator"),
        ],
        ids=[
            "not-built",
            "disabled",
            "zero-sampling",
            "no-sampling",
            "string-sampling",
            "no-input",
            "no-output",
            "no-evaluator",
        ],
    )
    @patch("agentcore_app.agentcore_client")
    def test_each_setting_that_stops_it_running_fails(
        self, mock_ac, overrides, expected
    ):
        _online_evaluation_client(mock_ac, [_online_evaluation_detail(**overrides)])

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert findings[0]["Finding"].endswith("Not Running")
        assert expected in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_a_failure_reason_is_reported_with_the_status(self, mock_ac):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(
                    status="ERROR", failureReason="evaluator deleted"
                )
            ],
        )

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert "evaluator deleted" in findings[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "cloud_watch_logs",
        [
            {"logGroupNames": ["/aws/bedrock-agentcore/runtimes/agent-DEFAULT"]},
            {"serviceNames": ["agent"]},
        ],
        ids=["log-groups-only", "services-only"],
    )
    @patch("agentcore_app.agentcore_client")
    def test_either_input_source_alone_is_traffic_to_read(
        self, mock_ac, cloud_watch_logs
    ):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(
                    dataSourceConfig={"cloudWatchLogs": cloud_watch_logs}
                )
            ],
        )

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_every_configuration_unreadable_reports_the_read_failure(self, mock_ac):
        # Zero readable configurations is not zero configurations: the absence
        # branch would report nothing to judge for an account that has two.
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [_online_evaluation_summary()]
        }
        mock_ac.get_online_evaluation_config.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "GetOnlineEvaluationConfig"
        )

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "could not be read" in findings[0]["Finding_Details"]
        assert (
            "AC-17 reports whether one is expected"
            not in (findings[0]["Finding_Details"])
        )

    @patch("agentcore_app.agentcore_client")
    def test_every_failing_setting_is_named_not_only_the_first(self, mock_ac):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(
                    executionStatus="DISABLED", evaluators=[], outputConfig={}
                )
            ],
        )

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        details = findings[0]["Finding_Details"]
        assert "it scores no traffic" in details
        assert "attaches no evaluator" in details
        assert "writes its results to no log group" in details

    @patch.dict(os.environ, {}, clear=True)
    @patch("agentcore_app.agentcore_client")
    def test_a_disabled_evaluation_fails_where_ac17_abstains(self, mock_ac):
        # AC-17 reports N/A for the same configuration unless the environment
        # sets REQUIRE_AGENTCORE_ONLINE_EVALUATION, which is the verdict gap
        # AC-39 closes.
        _online_evaluation_client(
            mock_ac, [_online_evaluation_detail(executionStatus="DISABLED")]
        )

        incumbent = agentcore_app.check_agentcore_online_evaluation_coverage()
        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert incumbent[0]["Status"] == "N/A"
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_every_configuration_is_judged_not_only_the_first(self, mock_ac):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(),
                _online_evaluation_detail(
                    onlineEvaluationConfigId="oec-2",
                    onlineEvaluationConfigName="second",
                    executionStatus="DISABLED",
                ),
            ],
        )

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]
        assert "second" in findings[1]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_configuration_list_is_paginated(self, mock_ac):
        mock_ac.list_online_evaluation_configs.side_effect = [
            {
                "onlineEvaluationConfigs": [_online_evaluation_summary("oec-1")],
                "nextToken": "page-2",
            },
            {
                "onlineEvaluationConfigs": [
                    _online_evaluation_summary("oec-2", "second")
                ]
            },
        ]
        mock_ac.get_online_evaluation_config.side_effect = (
            lambda onlineEvaluationConfigId: _online_evaluation_detail(
                onlineEvaluationConfigId=onlineEvaluationConfigId
            )
        )

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert len(findings) == 2

    @patch("agentcore_app.agentcore_client")
    def test_no_configuration_is_na(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": []
        }

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "AC-17 reports whether one is expected" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_configuration_does_not_hide_the_rest(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                _online_evaluation_summary("oec-1"),
                _online_evaluation_summary("oec-2", "second"),
            ]
        }

        def _detail(onlineEvaluationConfigId):
            if onlineEvaluationConfigId == "oec-1":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException"}},
                    "GetOnlineEvaluationConfig",
                )
            return _online_evaluation_detail(
                onlineEvaluationConfigId="oec-2", onlineEvaluationConfigName="second"
            )

        mock_ac.get_online_evaluation_config.side_effect = _detail

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert [finding["Status"] for finding in findings] == ["N/A", "Passed"]
        assert "could not be read" in findings[0]["Finding_Details"]
        assert "GetOnlineEvaluationConfig" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_incomplete(self, mock_ac):
        mock_ac.list_online_evaluation_configs.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListOnlineEvaluationConfigs"
        )

        findings = agentcore_app.check_agentcore_online_evaluation_operation()

        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-39"

    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_online_evaluation_operation()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-39"

    def test_the_judged_statuses_are_modelled_enum_values(self):
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        members = model.operation_model(
            "GetOnlineEvaluationConfig"
        ).output_shape.members
        built = set(members["status"].metadata["enum"])
        running = set(members["executionStatus"].metadata["enum"])
        assert agentcore_app.ONLINE_EVALUATION_BUILT_STATUS in built
        assert agentcore_app.ONLINE_EVALUATION_RUNNING_STATUS in running
        # The other values are what the check fails on, so it has something to
        # fail on in both dimensions.
        assert built - {agentcore_app.ONLINE_EVALUATION_BUILT_STATUS}
        assert running - {agentcore_app.ONLINE_EVALUATION_RUNNING_STATUS}


class TestAC40EvaluationSafetyCoverage:
    """AC-40: what the attached evaluators score, read from the catalogue."""

    @patch("agentcore_app.agentcore_client")
    def test_safety_and_tool_call_evaluators_pass(self, mock_ac):
        _online_evaluation_client(mock_ac)

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-40"
        assert findings[0]["Status"] == "Passed"
        assert "Builtin.Harmfulness" in findings[0]["Finding_Details"]
        assert "Builtin.ToolSelectionAccuracy" in findings[0]["Finding_Details"]
        assert agentcore_app.EVALUATION_SCORE_ALARM_NOTE in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_quality_evaluators_alone_fail_on_both_legs(self, mock_ac):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(
                    evaluators=[{"evaluatorId": "Builtin.Helpfulness"}]
                )
            ],
        )

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert findings[0]["Finding"].endswith("Incomplete")
        assert "safety metric" in findings[0]["Finding_Details"]
        assert "TOOL_CALL level" in findings[0]["Finding_Details"]
        assert agentcore_app.EVALUATION_SCORE_ALARM_NOTE in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_a_safety_evaluator_without_a_tool_call_one_fails_on_one_leg(self, mock_ac):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(
                    evaluators=[{"evaluatorId": "Builtin.Harmfulness"}]
                )
            ],
        )

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert findings[0]["Status"] == "Failed"
        assert "TOOL_CALL level" in findings[0]["Finding_Details"]
        assert "no evaluator the catalogue marks" not in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_customer_authored_evaluator_is_named_for_its_owner_to_classify(
        self, mock_ac
    ):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(
                    evaluators=[
                        {"evaluatorId": "Builtin.Harmfulness"},
                        {"evaluatorId": "Builtin.ToolSelectionAccuracy"},
                        {"evaluatorId": "custom_tool_fidelity-abc"},
                    ]
                )
            ],
        )

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert findings[0]["Status"] == "Passed"
        assert "custom_tool_fidelity-abc" in findings[0]["Finding_Details"]
        assert "workload owner's to state" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_customer_authored_safety_description_does_not_count_as_safety(
        self, mock_ac
    ):
        # custom_tool_fidelity-abc carries both the safety marker and TOOL_CALL
        # level, and neither counts: its description is prose this check cannot
        # verify.
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(
                    evaluators=[{"evaluatorId": "custom_tool_fidelity-abc"}]
                )
            ],
        )

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert findings[0]["Status"] == "Failed"
        assert "safety metric" in findings[0]["Finding_Details"]
        assert "TOOL_CALL level" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_third_party_evaluator_is_service_authored(self, mock_ac):
        # The catalogue's third-party entries carry the same service-written
        # descriptions as the built-in ones, so a workload scoring safety with a
        # third-party judge is covered.
        catalogue = [
            {
                "evaluatorId": "ThirdParty.DeepEval.Toxicity",
                "evaluatorType": "ThirdParty",
                "level": "TRACE",
                "description": "Safety Metric. Evaluates toxic content",
            },
            {
                "evaluatorId": "Builtin.ToolSelectionAccuracy",
                "evaluatorType": "Builtin",
                "level": "TOOL_CALL",
                "description": "Component Level Metric.",
            },
        ]
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(
                    evaluators=[
                        {"evaluatorId": "ThirdParty.DeepEval.Toxicity"},
                        {"evaluatorId": "Builtin.ToolSelectionAccuracy"},
                    ]
                )
            ],
            catalogue=catalogue,
        )

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert findings[0]["Status"] == "Passed"
        assert "ThirdParty.DeepEval.Toxicity" in findings[0]["Finding_Details"]
        assert "workload owner's to state" not in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_safety_marker_is_matched_case_insensitively(self, mock_ac):
        catalogue = [
            {
                "evaluatorId": "Builtin.Harmfulness",
                "evaluatorType": "Builtin",
                "level": "TRACE",
                "description": "SAFETY METRIC. Harmful content",
            },
            {
                "evaluatorId": "Builtin.ToolSelectionAccuracy",
                "evaluatorType": "Builtin",
                "level": "TOOL_CALL",
                "description": "Component Level Metric.",
            },
        ]
        _online_evaluation_client(mock_ac, catalogue=catalogue)

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        "catalogue",
        [
            [
                {
                    "evaluatorId": "Builtin.ToolSelectionAccuracy",
                    "evaluatorType": "Builtin",
                    "level": "TOOL_CALL",
                    "description": "Component Level Metric.",
                }
            ],
            [
                {
                    "evaluatorId": "Builtin.Harmfulness",
                    "evaluatorType": "Builtin",
                    "level": "TRACE",
                    "description": "Safety Metric.",
                }
            ],
            [],
        ],
        ids=["no-safety-class", "no-tool-call-class", "empty"],
    )
    @patch("agentcore_app.agentcore_client")
    def test_a_catalogue_missing_a_category_reports_drift_and_judges_nobody(
        self, mock_ac, catalogue
    ):
        _online_evaluation_client(mock_ac, catalogue=catalogue)

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "no configuration is judged here" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_catalogue_read_failure_is_na(self, mock_ac):
        _online_evaluation_client(mock_ac)
        mock_ac.list_evaluators.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListEvaluators"
        )

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "ListEvaluators" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_the_catalogue_is_paginated(self, mock_ac):
        _online_evaluation_client(mock_ac)
        mock_ac.list_evaluators.side_effect = [
            {"evaluators": _evaluator_catalogue()[:1], "nextToken": "page-2"},
            {"evaluators": _evaluator_catalogue()[1:]},
        ]

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_every_configuration_is_judged_not_only_the_first(self, mock_ac):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(),
                _online_evaluation_detail(
                    onlineEvaluationConfigId="oec-2",
                    onlineEvaluationConfigName="second",
                    evaluators=[{"evaluatorId": "Builtin.Helpfulness"}],
                ),
            ],
        )

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_no_configuration_is_na(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": []
        }

        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_evaluation_safety_coverage()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-40"

    def test_the_read_classes_are_modelled_enum_values(self):
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        members = (
            model.operation_model("ListEvaluators")
            .output_shape.members["evaluators"]
            .member.members
        )
        types = set(members["evaluatorType"].metadata["enum"])
        levels = set(members["level"].metadata["enum"])
        assert set(agentcore_app.SERVICE_AUTHORED_EVALUATOR_TYPES) <= types
        assert agentcore_app.EVALUATOR_TOOL_CALL_LEVEL in levels
        # The customer-authored types are the ones left over, so the owner note
        # has a population to describe.
        assert types - set(agentcore_app.SERVICE_AUTHORED_EVALUATOR_TYPES)


class TestAC41EvaluationResultProtection:
    """AC-41: the results log group the configuration names, not one swept by prefix."""

    @staticmethod
    def _log_group(name=_EVALUATION_RESULTS_GROUP, **overrides):
        group = {
            "logGroupName": name,
            "retentionInDays": 365,
            "kmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abcd",
        }
        group.update(overrides)
        return group

    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_retained_encrypted_prefixed_group_passes(self, mock_ac, mock_logs):
        _online_evaluation_client(mock_ac)
        mock_logs.describe_log_groups.return_value = {"logGroups": [self._log_group()]}

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-41"
        assert findings[0]["Status"] == "Passed"
        assert "expires results after 365 day(s)" in findings[0]["Finding_Details"]
        assert "AC-20 judges its masking policy" in findings[0]["Finding_Details"]
        assert "Tag values" in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @pytest.mark.parametrize(
        ("overrides", "expected"),
        [
            ({"retentionInDays": None}, "kept indefinitely"),
            ({"kmsKeyId": None}, "no customer managed encryption key"),
        ],
        ids=["no-retention", "no-key"],
    )
    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_unprotected_group_fails(self, mock_ac, mock_logs, overrides, expected):
        _online_evaluation_client(mock_ac)
        group = self._log_group()
        for key, value in overrides.items():
            if value is None:
                group.pop(key)
        mock_logs.describe_log_groups.return_value = {"logGroups": [group]}

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert findings[0]["Finding"].endswith("Unprotected")
        assert expected in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_group_outside_the_agentcore_prefixes_fails(self, mock_ac, mock_logs):
        # AC-20 and AC-26 sweep log groups by name, so a customer-chosen results
        # group is judged by neither however well it is configured.
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(
                    outputConfig={"cloudWatchConfig": {"logGroupName": "/team/results"}}
                )
            ],
        )
        mock_logs.describe_log_groups.return_value = {
            "logGroups": [self._log_group("/team/results")]
        }

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert findings[0]["Status"] == "Failed"
        assert (
            "sits outside the AgentCore log group prefixes"
            in (findings[0]["Finding_Details"])
        )
        for prefix in agentcore_app.AGENTCORE_LOG_GROUP_PREFIXES:
            assert prefix in findings[0]["Finding_Details"]

    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_absent_group_fails(self, mock_ac, mock_logs):
        _online_evaluation_client(mock_ac)
        mock_logs.describe_log_groups.return_value = {"logGroups": []}

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert findings[0]["Status"] == "Failed"
        assert "does not exist in this region" in findings[0]["Finding_Details"]
        assert (
            "no encryption key and no retention period"
            in (findings[0]["Finding_Details"])
        )

    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_longer_group_sharing_the_prefix_is_not_the_named_group(
        self, mock_ac, mock_logs
    ):
        # DescribeLogGroups filters by prefix, so the named group is the one that
        # matches exactly.
        _online_evaluation_client(mock_ac)
        mock_logs.describe_log_groups.return_value = {
            "logGroups": [self._log_group(f"{_EVALUATION_RESULTS_GROUP}-other")]
        }

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert findings[0]["Status"] == "Failed"
        assert "does not exist in this region" in findings[0]["Finding_Details"]

    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_no_output_group_defers_to_ac39(self, mock_ac, mock_logs):
        _online_evaluation_client(mock_ac, [_online_evaluation_detail(outputConfig={})])

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert findings[0]["Status"] == "N/A"
        assert "Resolve AC-39" in findings[0]["Resolution"]
        mock_logs.describe_log_groups.assert_not_called()

    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_describe_failure_is_na(self, mock_ac, mock_logs):
        _online_evaluation_client(mock_ac)
        mock_logs.describe_log_groups.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "DescribeLogGroups"
        )

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert findings[0]["Status"] == "N/A"
        assert "DescribeLogGroups" in findings[0]["Resolution"]

    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_the_group_lookup_is_paginated(self, mock_ac, mock_logs):
        _online_evaluation_client(mock_ac)
        mock_logs.describe_log_groups.side_effect = [
            {
                "logGroups": [self._log_group(f"{_EVALUATION_RESULTS_GROUP}-other")],
                "nextToken": "page-2",
            },
            {"logGroups": [self._log_group()]},
        ]

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_every_configuration_is_judged_not_only_the_first(self, mock_ac, mock_logs):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(),
                _online_evaluation_detail(
                    onlineEvaluationConfigId="oec-2",
                    onlineEvaluationConfigName="second",
                    outputConfig={
                        "cloudWatchConfig": {
                            "logGroupName": "/aws/bedrock-agentcore/evaluations/results/oec-2"
                        }
                    },
                ),
            ],
        )
        mock_logs.describe_log_groups.side_effect = lambda logGroupNamePrefix: {
            "logGroups": [
                self._log_group(
                    logGroupNamePrefix,
                    **(
                        {} if logGroupNamePrefix.endswith("oec-1") else {"kmsKeyId": ""}
                    ),
                )
            ]
        }

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_no_configuration_is_na(self, mock_ac, mock_logs):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": []
        }

        findings = agentcore_app.check_agentcore_evaluation_result_protection()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.logs_client", None)
    @patch("agentcore_app.agentcore_client")
    def test_no_logs_client_is_na(self, mock_ac):
        findings = agentcore_app.check_agentcore_evaluation_result_protection()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-41"

    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_evaluation_result_protection()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-41"


def _pass_role_policy(resource, condition=None, action="iam:PassRole"):
    statement = {"Effect": "Allow", "Action": action, "Resource": resource}
    if condition:
        statement["Condition"] = condition
    return {"name": "PassRolePolicy", "document": {"Statement": statement}}


_PASSED_TO_SERVICE = {
    "StringEquals": {"iam:PassedToService": "bedrock-agentcore.amazonaws.com"}
}


class TestAC42EvaluationPassRoleScope:
    """AC-42: who can hand the evaluation service a role, and which role."""

    @patch("agentcore_app.agentcore_client")
    def test_a_bounded_grant_passes(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationDeployer": {
                    "attached_policies": [
                        _pass_role_policy(_EVALUATION_ROLE_ARN, _PASSED_TO_SERVICE)
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(cache)

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-42"
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "High"
        assert "role EvaluationDeployer" in findings[0]["Finding_Details"]
        assert _EVALUATION_ROLE_ARN in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @pytest.mark.parametrize(
        ("resource", "condition", "expected"),
        [
            ("*", None, ["also reaches other roles", "no iam:PassedToService"]),
            (
                "arn:aws:iam::123456789012:role/*",
                _PASSED_TO_SERVICE,
                ["also reaches other roles"],
            ),
            (_EVALUATION_ROLE_ARN, None, ["no iam:PassedToService"]),
        ],
        ids=["all-roles", "wide-pattern", "no-condition"],
    )
    @patch("agentcore_app.agentcore_client")
    def test_an_unbounded_grant_fails_on_the_leg_it_is_missing(
        self, mock_ac, resource, condition, expected
    ):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationDeployer": {
                    "attached_policies": [_pass_role_policy(resource, condition)],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(cache)

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert findings[0]["Finding"].endswith("Unbounded")
        for phrase in expected:
            assert phrase in findings[0]["Finding_Details"]
        if "no iam:PassedToService" not in expected:
            assert "no iam:PassedToService" not in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_a_user_holding_the_grant_is_reported_as_a_user(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {},
            "user_permissions": {
                "Deployer": {
                    "attached_policies": [],
                    "inline_policies": [_pass_role_policy("*")],
                }
            },
        }

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(cache)

        assert findings[0]["Status"] == "Failed"
        assert "user Deployer" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_the_widest_statement_decides_the_verdict(self, mock_ac):
        # A narrow statement elsewhere in the same policy set does not narrow a
        # wide one, so the principal is reported on the wide grant.
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationDeployer": {
                    "attached_policies": [
                        _pass_role_policy(_EVALUATION_ROLE_ARN, _PASSED_TO_SERVICE)
                    ],
                    "inline_policies": [_pass_role_policy("*")],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_wildcard_action_reaching_passrole_is_judged(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationDeployer": {
                    "attached_policies": [
                        _pass_role_policy(_EVALUATION_ROLE_ARN, action="iam:Pass*")
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(cache)

        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_grant_on_another_role_is_not_reported(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "OtherDeployer": {
                    "attached_policies": [
                        _pass_role_policy("arn:aws:iam::123456789012:role/Unrelated")
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert "No cached IAM role or user can pass" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_both_verdicts_are_reported_when_principals_differ(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "BoundedDeployer": {
                    "attached_policies": [
                        _pass_role_policy(_EVALUATION_ROLE_ARN, _PASSED_TO_SERVICE)
                    ],
                    "inline_policies": [],
                },
                "WideDeployer": {
                    "attached_policies": [_pass_role_policy("*")],
                    "inline_policies": [],
                },
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(cache)

        assert [finding["Status"] for finding in findings] == ["Failed", "Passed"]
        assert "WideDeployer" in findings[0]["Finding_Details"]
        assert "BoundedDeployer" in findings[1]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_malformed_document_is_reported_without_a_verdict(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationDeployer": {
                    "attached_policies": [{"document": "{not-json"}],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(cache)

        statuses = [finding["Status"] for finding in findings]
        assert statuses == ["Passed", "N/A"]
        assert "1 cached policy document(s)" in findings[1]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_empty_cache_is_na(self, mock_ac):
        _online_evaluation_client(mock_ac)

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(
            {"role_permissions": {}, "user_permissions": {}}
        )

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "1 evaluation execution role(s)" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_configuration_with_no_execution_role_is_na(self, mock_ac):
        _online_evaluation_client(
            mock_ac, [_online_evaluation_detail(evaluationExecutionRoleArn="")]
        )

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope(
            {"role_permissions": {"Any": {}}}
        )

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_incomplete(self, mock_ac):
        mock_ac.list_online_evaluation_configs.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListOnlineEvaluationConfigs"
        )

        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope({})

        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-42"

    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_evaluation_pass_role_scope({})
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-42"


class TestAC43EvaluationRoleTrust:
    """AC-43: the evaluation execution role's own trust policy."""

    _GUARDED_TRUST = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
            }
        ],
    }
    _OPEN_TRUST = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "bedrock.amazonaws.com",
                        "bedrock-agentcore.amazonaws.com",
                    ]
                },
                "Action": "sts:AssumeRole",
            }
        ],
    }

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_guarded_trust_policy_passes(self, mock_ac, mock_iam):
        _online_evaluation_client(mock_ac)
        mock_iam.get_role.return_value = {
            "Role": {"AssumeRolePolicyDocument": self._GUARDED_TRUST}
        }

        findings = agentcore_app.check_agentcore_evaluation_role_trust()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-43"
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "High"
        assert "EvaluationRole" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_unguarded_trust_policy_fails(self, mock_ac, mock_iam):
        _online_evaluation_client(mock_ac)
        mock_iam.get_role.return_value = {
            "Role": {"AssumeRolePolicyDocument": self._OPEN_TRUST}
        }

        findings = agentcore_app.check_agentcore_evaluation_role_trust()

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert findings[0]["Finding"].endswith("Guard Missing")
        assert "1 of 1 Allow statement(s)" in findings[0]["Finding_Details"]
        assert "aws:SourceArn" in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_the_role_name_is_read_from_the_arn(self, mock_ac, mock_iam):
        _online_evaluation_client(mock_ac)
        mock_iam.get_role.return_value = {
            "Role": {"AssumeRolePolicyDocument": self._GUARDED_TRUST}
        }

        agentcore_app.check_agentcore_evaluation_role_trust()

        mock_iam.get_role.assert_called_once_with(RoleName="EvaluationRole")

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_two_configurations_sharing_a_role_read_the_trust_policy_once(
        self, mock_ac, mock_iam
    ):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(),
                _online_evaluation_detail(
                    onlineEvaluationConfigId="oec-2",
                    onlineEvaluationConfigName="second",
                ),
            ],
        )
        mock_iam.get_role.return_value = {
            "Role": {"AssumeRolePolicyDocument": self._OPEN_TRUST}
        }

        findings = agentcore_app.check_agentcore_evaluation_role_trust()

        assert [finding["Status"] for finding in findings] == ["Failed", "Failed"]
        assert mock_iam.get_role.call_count == 1

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_trust_read_failure_is_na(self, mock_ac, mock_iam):
        _online_evaluation_client(mock_ac)
        mock_iam.get_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "GetRole"
        )

        findings = agentcore_app.check_agentcore_evaluation_role_trust()

        assert findings[0]["Status"] == "N/A"
        assert "iam:GetRole" in findings[0]["Resolution"]

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_configuration_with_no_execution_role_is_na(self, mock_ac, mock_iam):
        _online_evaluation_client(
            mock_ac, [_online_evaluation_detail(evaluationExecutionRoleArn="")]
        )

        findings = agentcore_app.check_agentcore_evaluation_role_trust()

        assert findings[0]["Status"] == "N/A"
        mock_iam.get_role.assert_not_called()

    @patch("agentcore_app.agentcore_client")
    def test_no_configuration_is_na(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": []
        }

        findings = agentcore_app.check_agentcore_evaluation_role_trust()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_incomplete(self, mock_ac):
        mock_ac.list_online_evaluation_configs.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListOnlineEvaluationConfigs"
        )

        findings = agentcore_app.check_agentcore_evaluation_role_trust()

        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-43"

    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_evaluation_role_trust()
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-43"


def _model_policy(resource, action=None):
    return {
        "name": "EvaluationPolicy",
        "document": {
            "Statement": {
                "Effect": "Allow",
                "Action": action
                or ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                "Resource": resource,
            }
        },
    }


class TestAC44EvaluationJudgeModelScope:
    """AC-44: which models the judge can be pointed at."""

    @patch("agentcore_app.agentcore_client")
    def test_a_named_model_passes(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        _model_policy(
                            "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3"
                        )
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-44"
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "Medium"
        assert "anthropic.claude-3" in findings[0]["Finding_Details"]
        assert "this check does not make" in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @pytest.mark.parametrize(
        "resource",
        [
            "*",
            "arn:aws:bedrock:*::foundation-model/*",
            "arn:aws:bedrock:*:123456789012:inference-profile/*",
        ],
        ids=["all", "all-foundation-models", "all-inference-profiles"],
    )
    @patch("agentcore_app.agentcore_client")
    def test_an_unbounded_model_grant_fails(self, mock_ac, resource):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationRole": {
                    "attached_policies": [_model_policy(resource)],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert findings[0]["Finding"].endswith("Unbounded")
        assert resource in findings[0]["Finding_Details"]
        assert "attacker-influenced text" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_a_partial_model_id_is_bounded(self, mock_ac):
        # A pattern naming part of a model id is narrower than every model, and
        # which models belong inside it is the workload owner's decision.
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationRole": {
                    "attached_policies": [
                        _model_policy(
                            "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"
                        )
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        "action",
        ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
        ids=["invoke", "invoke-stream"],
    )
    @patch("agentcore_app.agentcore_client")
    def test_either_invocation_action_alone_is_judged(self, mock_ac, action):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationRole": {
                    "attached_policies": [_model_policy("*", action=action)],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_wildcard_action_reaching_invoke_model_is_judged(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationRole": {
                    "attached_policies": [_model_policy("*", action="bedrock:*")],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_an_unbounded_pattern_decides_even_beside_a_named_one(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationRole": {
                    "attached_policies": [
                        _model_policy(
                            [
                                "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3",
                                "*",
                            ]
                        )
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_role_with_no_model_grant_passes(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationRole": {
                    "attached_policies": [
                        _model_policy("*", action="logs:PutLogEvents")
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        assert findings[0]["Status"] == "Passed"
        assert "holds no model-invocation grant" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_role_outside_the_snapshot_is_na(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {"role_permissions": {"SomeOtherRole": {}}}

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        assert findings[0]["Status"] == "N/A"
        assert "not in the IAM permissions cache" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_malformed_document_is_reported_without_a_verdict(self, mock_ac):
        _online_evaluation_client(mock_ac)
        cache = {
            "role_permissions": {
                "EvaluationRole": {
                    "attached_policies": [{"document": "{not-json"}],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        statuses = [finding["Status"] for finding in findings]
        assert statuses == ["N/A", "Passed"]
        assert "1 cached policy document(s)" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_every_execution_role_is_judged_not_only_the_first(self, mock_ac):
        _online_evaluation_client(
            mock_ac,
            [
                _online_evaluation_detail(),
                _online_evaluation_detail(
                    onlineEvaluationConfigId="oec-2",
                    onlineEvaluationConfigName="second",
                    evaluationExecutionRoleArn="arn:aws:iam::123456789012:role/SecondRole",
                ),
            ],
        )
        cache = {
            "role_permissions": {
                "EvaluationRole": {
                    "attached_policies": [
                        _model_policy(
                            "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3"
                        )
                    ],
                    "inline_policies": [],
                },
                "SecondRole": {
                    "attached_policies": [_model_policy("*")],
                    "inline_policies": [],
                },
            }
        }

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(cache)

        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    @patch("agentcore_app.agentcore_client")
    def test_an_empty_cache_is_na(self, mock_ac):
        _online_evaluation_client(mock_ac)

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(
            {"role_permissions": {}}
        )

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_a_configuration_with_no_execution_role_is_na(self, mock_ac):
        _online_evaluation_client(
            mock_ac, [_online_evaluation_detail(evaluationExecutionRoleArn="")]
        )

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope(
            {"role_permissions": {"Any": {}}}
        )

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_a_list_failure_is_incomplete(self, mock_ac):
        mock_ac.list_online_evaluation_configs.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListOnlineEvaluationConfigs"
        )

        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope({})

        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-44"

    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_evaluation_judge_model_scope({})
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-44"

    @pytest.mark.parametrize(
        ("resource", "unbounded"),
        [
            ("*", True),
            ("arn:aws:bedrock:*::foundation-model/*", True),
            ("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3", False),
            ("arn:aws:bedrock:*::foundation-model/anthropic.*", False),
            ("arn:aws:bedrock:*:123456789012:inference-profile/global.claude", False),
        ],
    )
    def test_the_model_scope_predicate(self, resource, unbounded):
        assert agentcore_app._bedrock_model_resource_is_unbounded(resource) is unbounded

    def test_the_model_invocation_actions_are_the_two_that_exist(self):
        model = agentcore_app.boto3.client(
            "bedrock-runtime",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        ).meta.service_model
        operations = set(model.operation_names)
        assert {
            action.split(":", 1)[1]
            for action in agentcore_app.BEDROCK_MODEL_INVOCATION_ACTIONS
        } == {"invokemodel", "invokemodelwithresponsestream"}
        assert {"InvokeModel", "InvokeModelWithResponseStream"} <= operations
        # Converse is an operation of the same client and not an IAM action: it
        # authorizes against InvokeModel, which Access Analyzer confirms by
        # rejecting bedrock:Converse as an action that does not exist.
        assert "Converse" in operations
        assert "bedrock:converse" not in agentcore_app.BEDROCK_MODEL_INVOCATION_ACTIONS

    def test_the_lookup_actions_are_lowercase_for_statement_matching(self):
        for action in agentcore_app.BEDROCK_MODEL_INVOCATION_ACTIONS:
            assert action == action.lower()


class TestEvaluationCheckRegistration:
    """AC-39 to AC-44 read regional evaluation configurations."""

    _CHECKS = {
        "AC-39": "check_agentcore_online_evaluation_operation",
        "AC-40": "check_agentcore_evaluation_safety_coverage",
        "AC-41": "check_agentcore_evaluation_result_protection",
        "AC-42": "check_agentcore_evaluation_pass_role_scope",
        "AC-43": "check_agentcore_evaluation_role_trust",
        "AC-44": "check_agentcore_evaluation_judge_model_scope",
    }

    @pytest.mark.parametrize("check_id", sorted(_CHECKS))
    def test_the_evaluation_checks_are_in_both_regional_tuples(self, check_id):
        assert check_id in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert check_id in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    @pytest.mark.parametrize("check_id", sorted(_CHECKS))
    def test_timeout_backfill_emits_the_evaluation_checks(self, check_id):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        assert check_id in {finding["Check_ID"] for finding in findings}

    @pytest.mark.parametrize("function_name", sorted(_CHECKS.values()))
    def test_the_handler_registers_each_evaluation_check_once(self, function_name):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count(function_name) == 1


# ===================================================================
# Runtime isolation: AC-01's egress leg, AC-08's private DNS leg, AC-45 to AC-47
# ===================================================================
_OPEN_V4_EGRESS = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
_OPEN_V6_EGRESS = {"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
_NAMED_EGRESS = {"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}


def _security_group(group_id, egress=(), ingress=()):
    return {
        "GroupId": group_id,
        "IpPermissions": list(ingress),
        "IpPermissionsEgress": list(egress),
    }


def _runtime_arn(runtime_id):
    return f"arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/{runtime_id}"


def _vpc_runtime(runtime_id="rt-1", security_groups=("sg-runtime",), **detail):
    """Return one VPC-mode runtime as a (summary, detail) pair.

    networkModeConfig is where the API reports a runtime's security groups.
    subnetIds is left out: it drives the incumbent public-subnet leg, and a
    fixture that sets both would make one assertion answer for two legs.
    """
    network = {"networkMode": "VPC"}
    if security_groups is not None:
        network["networkModeConfig"] = {
            "securityGroups": list(security_groups),
            "subnets": ["subnet-runtime"],
        }
    return (
        {"agentRuntimeId": runtime_id, "agentRuntimeName": runtime_id},
        {
            "agentRuntimeArn": _runtime_arn(runtime_id),
            "networkConfiguration": network,
            **detail,
        },
    )


def _wire_runtimes(mock_ac, runtimes):
    """Stub list_agent_runtimes and get_agent_runtime from (summary, detail)."""
    mock_ac.list_agent_runtimes.return_value = {
        "agentRuntimes": [summary for summary, _ in runtimes]
    }
    details = {summary["agentRuntimeId"]: detail for summary, detail in runtimes}
    mock_ac.get_agent_runtime.side_effect = lambda agentRuntimeId: details[
        agentRuntimeId
    ]


def _code_interpreter(
    interpreter_id="ci-1",
    network_mode="VPC",
    security_groups=("sg-tool",),
    **detail,
):
    """Return one custom Code Interpreter detail. Tools report vpcConfig."""
    network = {"networkMode": network_mode}
    if security_groups is not None:
        network["vpcConfig"] = {
            "securityGroups": list(security_groups),
            "subnets": ["subnet-tool"],
        }
    return {
        "codeInterpreterId": interpreter_id,
        "name": interpreter_id,
        "networkConfiguration": network,
        **detail,
    }


def _browser(
    browser_id="br-1",
    network_mode="VPC",
    security_groups=("sg-tool",),
    **detail,
):
    """Return one custom Browser detail."""
    network = {"networkMode": network_mode}
    if security_groups is not None:
        network["vpcConfig"] = {
            "securityGroups": list(security_groups),
            "subnets": ["subnet-tool"],
        }
    return {
        "browserId": browser_id,
        "name": browser_id,
        "networkConfiguration": network,
        **detail,
    }


def _wire_tools(mock_ac, interpreters=(), browsers=()):
    """Stub both custom built-in tool inventories.

    An unstubbed list API returns a MagicMock the paginator reads as an empty
    page, so a test that means "no tools" has to say so here for the same
    reason `_empty_agentcore_inventory` exists.
    """
    interpreters = list(interpreters)
    browsers = list(browsers)
    mock_ac.list_code_interpreters.return_value = {
        "codeInterpreterSummaries": [
            {"codeInterpreterId": item["codeInterpreterId"], "name": item["name"]}
            for item in interpreters
        ]
    }
    by_interpreter = {item["codeInterpreterId"]: item for item in interpreters}
    mock_ac.get_code_interpreter.side_effect = lambda codeInterpreterId: by_interpreter[
        codeInterpreterId
    ]
    mock_ac.list_browsers.return_value = {
        "browserSummaries": [
            {"browserId": item["browserId"], "name": item["name"]} for item in browsers
        ]
    }
    by_browser = {item["browserId"]: item for item in browsers}
    mock_ac.get_browser.side_effect = lambda browserId: by_browser[browserId]


class TestAC01EgressFiltering:
    """AC-01 judges what each VPC-mode agent resource reaches outbound."""

    def _egress(self, result):
        return [
            finding
            for finding in extract_csv_data(result)
            if finding["Finding"].startswith("AgentCore Egress")
        ]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_open_outbound_rule_on_a_runtime_fails(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [_vpc_runtime()])
        _wire_tools(mock_ac)
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [_security_group("sg-runtime", [_OPEN_V4_EGRESS])]
        }

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Check_ID"] == "AC-01"
        assert egress[0]["Status"] == "Failed"
        assert egress[0]["Severity"] == "High"
        assert egress[0]["Finding"] == "AgentCore Egress Unrestricted"
        assert "0.0.0.0/0" in egress[0]["Finding_Details"]
        assert "rt-1" in egress[0]["Finding_Details"]
        assert_finding_schema(egress[0])

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_open_ipv6_outbound_rule_fails(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [_vpc_runtime()])
        _wire_tools(mock_ac)
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [_security_group("sg-runtime", [_OPEN_V6_EGRESS])]
        }

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert egress[0]["Status"] == "Failed"
        assert "::/0" in egress[0]["Finding_Details"]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_named_outbound_destinations_pass(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [_vpc_runtime()])
        _wire_tools(mock_ac)
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [_security_group("sg-runtime", [_NAMED_EGRESS])]
        }

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Status"] == "Passed"
        assert egress[0]["Severity"] == "High"
        assert_finding_schema(egress[0])

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_open_inbound_rule_does_not_fail_the_egress_leg(self, mock_ac, mock_ec2):
        # The devguide states inbound rules are not required because the
        # runtime only initiates outbound connections. A group open inbound and
        # closed outbound has to read as a pass here, or this leg is a second
        # copy of the endpoint inbound leg under a different name.
        _wire_runtimes(mock_ac, [_vpc_runtime()])
        _wire_tools(mock_ac)
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                _security_group(
                    "sg-runtime", egress=[_NAMED_EGRESS], ingress=[_OPEN_V4_EGRESS]
                )
            ]
        }

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert [finding["Status"] for finding in egress] == ["Passed"]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_public_mode_tool_fails_with_no_group_to_read(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [])
        _wire_tools(
            mock_ac,
            interpreters=[
                _code_interpreter(network_mode="PUBLIC", security_groups=None)
            ],
        )

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Status"] == "Failed"
        assert egress[0]["Severity"] == "High"
        assert "Code Interpreter 'ci-1'" in egress[0]["Finding_Details"]
        assert mock_ec2.describe_security_groups.call_count == 0

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_sandbox_code_interpreter_passes(self, mock_ac, mock_ec2):
        # SANDBOX is the service-managed environment with limited external
        # network access and no customer security group, so there is no
        # outbound rule to name and nothing for the customer to fix.
        _wire_runtimes(mock_ac, [])
        _wire_tools(
            mock_ac,
            interpreters=[
                _code_interpreter(network_mode="SANDBOX", security_groups=None)
            ],
        )

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Status"] == "Passed"
        assert egress[0]["Severity"] == "Medium"
        assert "SANDBOX" in egress[0]["Finding_Details"]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_browsers_outbound_rules_are_judged_too(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [])
        _wire_tools(mock_ac, browsers=[_browser(security_groups=["sg-browser"])])
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [_security_group("sg-browser", [_OPEN_V4_EGRESS])]
        }

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Status"] == "Failed"
        assert "Browser 'br-1'" in egress[0]["Finding_Details"]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_every_target_is_judged_from_one_describe_call(self, mock_ac, mock_ec2):
        _wire_runtimes(
            mock_ac,
            [
                _vpc_runtime("rt-open", security_groups=["sg-open"]),
                _vpc_runtime("rt-closed", security_groups=["sg-closed"]),
            ],
        )
        _wire_tools(
            mock_ac, interpreters=[_code_interpreter(security_groups=["sg-open"])]
        )
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                _security_group("sg-open", [_OPEN_V4_EGRESS]),
                _security_group("sg-closed", [_NAMED_EGRESS]),
            ]
        }

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert sorted(finding["Status"] for finding in egress) == [
            "Failed",
            "Failed",
            "Passed",
        ]
        assert mock_ec2.describe_security_groups.call_count == 1
        assert mock_ec2.describe_security_groups.call_args.kwargs["GroupIds"] == [
            "sg-closed",
            "sg-open",
        ]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_the_security_group_pages_are_followed(self, mock_ac, mock_ec2):
        _wire_runtimes(
            mock_ac, [_vpc_runtime(security_groups=["sg-first", "sg-second"])]
        )
        _wire_tools(mock_ac)
        mock_ec2.describe_security_groups.side_effect = [
            {
                "SecurityGroups": [_security_group("sg-first", [_NAMED_EGRESS])],
                "NextToken": "page-2",
            },
            {"SecurityGroups": [_security_group("sg-second", [_OPEN_V4_EGRESS])]},
        ]

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        # Without the second page sg-second reads as a group that was not
        # returned, which reports N/A instead of the open rule it holds.
        assert egress[0]["Status"] == "Failed"
        assert mock_ec2.describe_security_groups.call_count == 2

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_vpc_runtime_with_no_security_group_is_na(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [_vpc_runtime(security_groups=None)])
        _wire_tools(mock_ac)

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Status"] == "N/A"
        assert egress[0]["Severity"] == "Informational"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_unreadable_security_group_is_na(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [_vpc_runtime()])
        _wire_tools(mock_ac)
        mock_ec2.describe_security_groups.side_effect = _make_client_error(
            "UnauthorizedOperation", "not authorized"
        )

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Status"] == "N/A"
        assert "ec2:DescribeSecurityGroups" in egress[0]["Resolution"]
        # A denied describe and a group the describe did not return produce the
        # same resolution, so the details have to say which one happened.
        assert "could not be read" in egress[0]["Finding_Details"]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_group_that_was_not_returned_is_na(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [_vpc_runtime()])
        _wire_tools(mock_ac)
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Status"] == "N/A"
        assert "sg-runtime" in egress[0]["Finding_Details"]
        assert "were not returned" in egress[0]["Finding_Details"]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_open_rule_beside_a_missing_group_still_fails(self, mock_ac, mock_ec2):
        # A stale group id on a resource that also has an open rule is the case
        # where an unknown group must not downgrade a rule that was read.
        _wire_runtimes(mock_ac, [_vpc_runtime(security_groups=["sg-open", "sg-gone"])])
        _wire_tools(mock_ac)
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [_security_group("sg-open", [_OPEN_V4_EGRESS])]
        }

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Status"] == "Failed"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_unlistable_tool_inventory_is_na(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [])
        _wire_tools(mock_ac)
        mock_ac.list_code_interpreters.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert len(egress) == 1
        assert egress[0]["Status"] == "N/A"
        assert "ListCodeInterpreters" in egress[0]["Resolution"]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_one_unreadable_tool_does_not_hide_the_others(self, mock_ac, mock_ec2):
        _wire_runtimes(mock_ac, [])
        _wire_tools(
            mock_ac,
            interpreters=[
                _code_interpreter("ci-broken"),
                _code_interpreter("ci-open"),
            ],
        )
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [_security_group("sg-tool", [_OPEN_V4_EGRESS])]
        }
        broken = _make_client_error("AccessDeniedException", "denied")
        mock_ac.get_code_interpreter.side_effect = lambda codeInterpreterId: (
            _code_interpreter("ci-open")
            if codeInterpreterId == "ci-open"
            else _raise(broken)
        )

        egress = self._egress(agentcore_app.check_agentcore_vpc_configuration())

        assert sorted(finding["Status"] for finding in egress) == ["Failed", "N/A"]
        unreadable = next(f for f in egress if f["Status"] == "N/A")
        assert "GetCodeInterpreter" in unreadable["Resolution"]
        assert "ci-broken" in unreadable["Finding_Details"]

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_public_runtime_is_not_judged_twice(self, mock_ac, mock_ec2):
        # The incumbent leg already fails a PUBLIC runtime, and it carries no
        # security group, so a second finding would report one setting twice.
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1", "agentRuntimeName": "rt-1"}]
        }
        mock_ac.get_agent_runtime.return_value = {
            "networkConfiguration": {"networkMode": "PUBLIC"}
        }
        _wire_tools(mock_ac)

        result = agentcore_app.check_agentcore_vpc_configuration()

        assert self._egress(result) == []
        assert extract_csv_data(result)[0]["Status"] == "Failed"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_the_handlers_browser_inventory_is_reused(self, mock_ac, mock_ec2):
        # The handler lists custom browsers once and passes the inventory down.
        # A check that ignored it would list them again per check.
        _wire_runtimes(mock_ac, [])
        _wire_tools(mock_ac)
        inventory = {
            "items": [
                {
                    "summary": {"browserId": "br-9", "name": "br-9"},
                    "detail": _browser("br-9", network_mode="PUBLIC"),
                }
            ],
            "errors": [],
            "list_error": None,
        }

        egress = self._egress(
            agentcore_app.check_agentcore_vpc_configuration(browser_inventory=inventory)
        )

        assert len(egress) == 1
        assert "br-9" in egress[0]["Finding_Details"]
        assert mock_ac.list_browsers.call_count == 0


def _raise(error):
    """Raise from inside a lambda, so one side_effect can mix outcomes."""
    raise error


class TestAC08EndpointPrivateDns:
    """AC-08 reports whether callers reach AgentCore through the endpoint."""

    def _run(self, mock_ac, mock_ec2, endpoint):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1"}]
        }
        mock_ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
        mock_ec2.describe_vpc_endpoints.return_value = {"VpcEndpoints": [endpoint]}
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        return [
            finding
            for finding in extract_csv_data(
                agentcore_app.check_agentcore_vpc_endpoints()
            )
            if "Private DNS" in finding["Finding"]
        ]

    def _interface_endpoint(self, **extra):
        return {
            "VpcEndpointId": "vpce-1",
            "VpcId": "vpc-1",
            "State": "available",
            "VpcEndpointType": "Interface",
            "ServiceName": "com.amazonaws.us-east-1.bedrock-agentcore",
            "PolicyDocument": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:role/a"},
                            "Action": "bedrock-agentcore:InvokeAgentRuntime",
                            "Resource": "*",
                        }
                    ]
                }
            ),
            **extra,
        }

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_private_dns_enabled_passes(self, mock_ac, mock_ec2):
        findings = self._run(
            mock_ac, mock_ec2, self._interface_endpoint(PrivateDnsEnabled=True)
        )

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-08"
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "Medium"
        assert_finding_schema(findings[0])

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_private_dns_disabled_fails(self, mock_ac, mock_ec2):
        findings = self._run(
            mock_ac, mock_ec2, self._interface_endpoint(PrivateDnsEnabled=False)
        )

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert findings[0]["Finding"].endswith("Disabled")
        assert "public endpoint" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_an_unreported_private_dns_setting_is_na(self, mock_ac, mock_ec2):
        # An absent field is not a disabled setting: publishing it as one
        # reports a failure the account may not have.
        findings = self._run(mock_ac, mock_ec2, self._interface_endpoint())

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_a_gateway_endpoint_reports_no_private_dns_finding(self, mock_ac, mock_ec2):
        # Gateway endpoints have no private DNS setting and report the field as
        # False, which would otherwise read as a misconfiguration.
        endpoint = self._interface_endpoint(
            VpcEndpointType="Gateway", PrivateDnsEnabled=False
        )

        assert self._run(mock_ac, mock_ec2, endpoint) == []


def _tool_policy(name, document):
    return {"name": name, "document": document}


def _tool_cache(role_name, policies, inline=None):
    return {
        "role_permissions": {
            role_name: {
                "attached_policies": list(policies),
                "inline_policies": list(inline or []),
            }
        }
    }


class TestAC45ToolExecutionRoleScope:
    """AC-45: the role code written by the model runs with."""

    _ROLE_ARN = "arn:aws:iam::123456789012:role/ToolRole"

    def _statement(self, action, resource=None, **extra):
        statement = {"Effect": "Allow", "Action": action}
        if resource is not None:
            statement["Resource"] = resource
        statement.update(extra)
        return {"Statement": [statement]}

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_tool_execution_role_scope({})

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-45"
        assert findings[0]["Status"] == "N/A"
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_no_custom_tool_is_na(self, mock_ac):
        _wire_tools(mock_ac)

        findings = agentcore_app.check_agentcore_tool_execution_role_scope({})

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "no tool execution role was assessed" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_tool_with_no_execution_role_passes(self, mock_ac):
        _wire_tools(mock_ac, interpreters=[_code_interpreter()])

        findings = agentcore_app.check_agentcore_tool_execution_role_scope({})

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "High"
        assert "no AWS credentials" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @pytest.mark.parametrize(
        "document,leg",
        [
            (
                {
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                    ]
                },
                "grants an action on every resource",
            ),
            (
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "NotResource": "arn:aws:s3:::secrets/*",
                        }
                    ]
                },
                "grants every resource except the ones it names",
            ),
            (
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": "arn:aws:s3:::app-bucket/*",
                        }
                    ]
                },
                "grants every action of a service",
            ),
            (
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "arn:aws:s3:::app-bucket/*",
                        }
                    ]
                },
                "grants every action of a service",
            ),
        ],
        ids=["every-resource", "not-resource", "service-wildcard", "action-star"],
    )
    @patch("agentcore_app.agentcore_client")
    def test_an_unscoped_grant_fails(self, mock_ac, document, leg):
        _wire_tools(
            mock_ac,
            interpreters=[_code_interpreter(executionRoleArn=self._ROLE_ARN)],
        )
        cache = _tool_cache("ToolRole", [_tool_policy("ToolPolicy", document)])

        findings = agentcore_app.check_agentcore_tool_execution_role_scope(cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert findings[0]["Finding"].endswith("Unscoped")
        assert leg in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_an_unscoped_inline_grant_fails(self, mock_ac):
        # Inline and attached policies are both read: a role whose only wide
        # grant is inline is the case where reading one list is enough to pass.
        _wire_tools(
            mock_ac,
            interpreters=[_code_interpreter(executionRoleArn=self._ROLE_ARN)],
        )
        cache = _tool_cache(
            "ToolRole",
            [],
            inline=[_tool_policy("ToolInline", self._statement("s3:GetObject", "*"))],
        )

        findings = agentcore_app.check_agentcore_tool_execution_role_scope(cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_named_resource_and_action_passes(self, mock_ac):
        _wire_tools(
            mock_ac,
            interpreters=[_code_interpreter(executionRoleArn=self._ROLE_ARN)],
        )
        cache = _tool_cache(
            "ToolRole",
            [],
            inline=[
                _tool_policy(
                    "ToolInline",
                    self._statement("s3:GetObject", "arn:aws:s3:::app-bucket/*"),
                )
            ],
        )

        findings = agentcore_app.check_agentcore_tool_execution_role_scope(cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "High"
        assert "ToolRole" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_deny_of_every_resource_is_not_a_grant(self, mock_ac):
        # Only Allow statements grant anything, so a Deny on every resource is
        # the opposite of the finding this check reports.
        _wire_tools(
            mock_ac,
            interpreters=[_code_interpreter(executionRoleArn=self._ROLE_ARN)],
        )
        cache = _tool_cache(
            "ToolRole",
            [
                _tool_policy(
                    "ToolPolicy",
                    {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "s3:*",
                                "Resource": "*",
                            }
                        ]
                    },
                )
            ],
        )

        findings = agentcore_app.check_agentcore_tool_execution_role_scope(cache)

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_a_role_outside_the_cache_is_na(self, mock_ac):
        _wire_tools(
            mock_ac,
            interpreters=[_code_interpreter(executionRoleArn=self._ROLE_ARN)],
        )

        findings = agentcore_app.check_agentcore_tool_execution_role_scope(
            {"role_permissions": {}}
        )

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "permissions cache" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_unparseable_document_is_reported_beside_the_verdict(self, mock_ac):
        _wire_tools(
            mock_ac,
            interpreters=[_code_interpreter(executionRoleArn=self._ROLE_ARN)],
        )
        cache = _tool_cache(
            "ToolRole",
            [
                _tool_policy("Broken", "{not json"),
                _tool_policy(
                    "Wide",
                    {
                        "Statement": [
                            {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}
                        ]
                    },
                ),
            ],
        )

        findings = agentcore_app.check_agentcore_tool_execution_role_scope(cache)

        assert len(findings) == 2
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding"].endswith("Scope Incomplete")
        assert findings[1]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_browser_role_is_judged_as_well(self, mock_ac):
        _wire_tools(mock_ac, browsers=[_browser(executionRoleArn=self._ROLE_ARN)])
        cache = _tool_cache(
            "ToolRole",
            [
                _tool_policy(
                    "ToolPolicy",
                    self._statement("bedrock:InvokeModel", "*"),
                )
            ],
        )

        findings = agentcore_app.check_agentcore_tool_execution_role_scope(cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert "Browser 'br-1'" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_every_tool_is_judged(self, mock_ac):
        _wire_tools(
            mock_ac,
            interpreters=[
                _code_interpreter("ci-wide", executionRoleArn=self._ROLE_ARN)
            ],
            browsers=[_browser("br-scoped")],
        )
        cache = _tool_cache(
            "ToolRole", [_tool_policy("ToolPolicy", self._statement("s3:*", "*"))]
        )

        findings = agentcore_app.check_agentcore_tool_execution_role_scope(cache)

        assert sorted(finding["Status"] for finding in findings) == [
            "Failed",
            "Passed",
        ]

    @patch("agentcore_app.agentcore_client")
    def test_an_unlistable_inventory_is_reported(self, mock_ac):
        _wire_tools(mock_ac)
        mock_ac.list_browsers.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )

        findings = agentcore_app.check_agentcore_tool_execution_role_scope({})

        assert [finding["Status"] for finding in findings] == ["N/A", "N/A"]
        assert "ListBrowsers" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_an_unlistable_interpreter_inventory_does_not_end_the_check(self, mock_ac):
        # Each inventory is listed separately, so a denied ListCodeInterpreters
        # still leaves the browsers to judge.
        _wire_tools(mock_ac, browsers=[_browser(executionRoleArn=self._ROLE_ARN)])
        mock_ac.list_code_interpreters.side_effect = TypeError("boom")
        cache = _tool_cache(
            "ToolRole", [_tool_policy("ToolPolicy", self._statement("s3:*", "*"))]
        )

        findings = agentcore_app.check_agentcore_tool_execution_role_scope(cache)

        assert [finding["Status"] for finding in findings] == ["N/A", "Failed"]
        assert "ListCodeInterpreters" in findings[0]["Resolution"]


class TestAC46RuntimeSessionLimits:
    """AC-46: how long one runtime session can hold its microVM."""

    def _lifecycle(self, **fields):
        summary, detail = _vpc_runtime()
        detail["lifecycleConfiguration"] = fields
        return [(summary, detail)]

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-46"
        assert findings[0]["Status"] == "N/A"
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_no_runtimes_is_na(self, mock_ac):
        _wire_runtimes(mock_ac, [])

        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_an_unlistable_region_is_na(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )

        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client")
    def test_the_documented_defaults_pass(self, mock_ac):
        _wire_runtimes(
            mock_ac, self._lifecycle(idleRuntimeSessionTimeout=900, maxLifetime=28800)
        )

        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "Medium"
        assert "900s" in findings[0]["Finding_Details"]
        assert "28800s" in findings[0]["Finding_Details"]
        assert "memory" in findings[0]["Resolution"]
        assert "spend" in findings[0]["Resolution"]
        assert_finding_schema(findings[0])

    @pytest.mark.parametrize(
        "field,name",
        [
            ("idleRuntimeSessionTimeout", "idle session timeout"),
            ("maxLifetime", "maximum session lifetime"),
        ],
    )
    @patch("agentcore_app.agentcore_client")
    def test_either_field_at_the_ceiling_fails(self, mock_ac, field, name):
        _wire_runtimes(
            mock_ac,
            self._lifecycle(
                **{field: agentcore_app.AGENTCORE_LIFECYCLE_CEILING_SECONDS}
            ),
        )

        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert findings[0]["Finding"].endswith("Unbounded")
        assert name in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_one_second_below_the_ceiling_passes(self, mock_ac):
        # The assertion is the service ceiling itself, not a duration this
        # check would prefer: a shorter limit is the workload's decision.
        _wire_runtimes(
            mock_ac,
            self._lifecycle(
                maxLifetime=agentcore_app.AGENTCORE_LIFECYCLE_CEILING_SECONDS - 1
            ),
        )

        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_an_absent_lifecycle_block_is_na(self, mock_ac):
        _wire_runtimes(mock_ac, [_vpc_runtime()])

        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "could not be judged" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_non_integer_value_is_na(self, mock_ac):
        _wire_runtimes(mock_ac, self._lifecycle(maxLifetime="28800"))

        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_an_unreadable_runtime_is_na(self, mock_ac):
        _wire_runtimes(mock_ac, [_vpc_runtime()])
        mock_ac.get_agent_runtime.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )

        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "GetAgentRuntime" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_every_runtime_is_judged(self, mock_ac):
        bounded_summary, bounded = _vpc_runtime("rt-bounded")
        bounded["lifecycleConfiguration"] = {"maxLifetime": 3600}
        unbounded_summary, unbounded = _vpc_runtime("rt-unbounded")
        unbounded["lifecycleConfiguration"] = {
            "maxLifetime": agentcore_app.AGENTCORE_LIFECYCLE_CEILING_SECONDS
        }
        _wire_runtimes(
            mock_ac,
            [(bounded_summary, bounded), (unbounded_summary, unbounded)],
        )

        findings = agentcore_app.check_agentcore_runtime_session_limits()

        assert [finding["Status"] for finding in findings] == ["Passed", "Failed"]

    def test_the_ceiling_is_the_one_the_api_models(self):
        # A ceiling that drifts from the service would either fail every
        # runtime or be unreachable, and the check would read as clean.
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control", **credentials
        ).meta.service_model
        lifecycle = model.operation_model("GetAgentRuntime").output_shape.members[
            "lifecycleConfiguration"
        ]
        assert set(lifecycle.members) == {
            field for field, _ in agentcore_app.AGENTCORE_LIFECYCLE_FIELDS
        }
        for member in lifecycle.members.values():
            assert (
                member.metadata["max"]
                == agentcore_app.AGENTCORE_LIFECYCLE_CEILING_SECONDS
            )


class TestAC47RuntimeInvocationPath:
    """AC-47: which callers and which network paths reach a runtime."""

    def _legs(self, findings):
        return {
            finding["Finding"].replace("AgentCore Runtime ", ""): finding
            for finding in findings
        }

    def _wire(self, mock_ac, policy=None, **detail):
        summary, runtime = _vpc_runtime(**detail)
        _wire_runtimes(mock_ac, [(summary, runtime)])
        mock_ac.get_resource_policy.return_value = {
            "policy": json.dumps(policy) if policy is not None else ""
        }

    @patch("agentcore_app.agentcore_client", None)
    def test_no_client_is_na(self):
        findings = agentcore_app.check_agentcore_runtime_invocation_path()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-47"
        assert findings[0]["Status"] == "N/A"
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_no_runtimes_is_na(self, mock_ac):
        _wire_runtimes(mock_ac, [])

        findings = agentcore_app.check_agentcore_runtime_invocation_path()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_an_unlistable_region_is_na(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )

        findings = agentcore_app.check_agentcore_runtime_invocation_path()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client")
    def test_no_policy_and_no_allowed_workload_fails_both_legs(self, mock_ac):
        self._wire(mock_ac)

        findings = agentcore_app.check_agentcore_runtime_invocation_path()
        legs = self._legs(findings)

        assert len(findings) == 2
        assert legs["Network Path Unrestricted"]["Status"] == "Failed"
        assert legs["Network Path Unrestricted"]["Severity"] == "Medium"
        assert legs["Caller Unrestricted"]["Status"] == "Failed"
        assert legs["Caller Unrestricted"]["Severity"] == "High"
        for finding in findings:
            assert_finding_schema(finding)

    @pytest.mark.parametrize(
        "condition_key",
        ["aws:SourceVpc", "aws:SourceVpce", "aws:VpcSourceIp", "aws:SourceIp"],
    )
    @patch("agentcore_app.agentcore_client")
    def test_a_deny_network_condition_passes_the_network_leg(
        self, mock_ac, condition_key
    ):
        # "Deny unless aws:SourceVpce is the approved endpoint" is the documented
        # form of this restriction. Reading Allow statements only would report
        # the account that wrote it as having no restriction at all.
        self._wire(
            mock_ac,
            policy={
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "bedrock-agentcore:InvokeAgentRuntime",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {condition_key: "vpce-123"},
                        },
                    }
                ]
            },
        )

        legs = self._legs(agentcore_app.check_agentcore_runtime_invocation_path())

        assert legs["Network Path Scope"]["Status"] == "Passed"
        assert condition_key.lower() in legs["Network Path Scope"]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_unrelated_condition_does_not_pass_the_network_leg(self, mock_ac):
        self._wire(
            mock_ac,
            policy={
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/gw"},
                        "Action": "bedrock-agentcore:InvokeAgentRuntime",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:PrincipalOrgID": "o-123"},
                        },
                    }
                ]
            },
        )

        legs = self._legs(agentcore_app.check_agentcore_runtime_invocation_path())

        assert legs["Network Path Unrestricted"]["Status"] == "Failed"
        assert legs["Caller Scope"]["Status"] == "Passed"

    @pytest.mark.parametrize(
        "allowed",
        [
            {"hostingEnvironments": ["arn:aws:bedrock-agentcore:us-east-1::gw/g"]},
            {"workloadIdentities": ["arn:aws:bedrock-agentcore:us-east-1::wi/w"]},
        ],
        ids=["hosting-environments", "workload-identities"],
    )
    @patch("agentcore_app.agentcore_client")
    def test_an_allowed_workload_configuration_passes_the_caller_leg(
        self, mock_ac, allowed
    ):
        self._wire(
            mock_ac,
            authorizerConfiguration={
                "customJWTAuthorizer": {
                    "discoveryUrl": "https://example.com/.well-known/openid-configuration",
                    "allowedWorkloadConfiguration": allowed,
                }
            },
        )

        legs = self._legs(agentcore_app.check_agentcore_runtime_invocation_path())

        assert legs["Caller Scope"]["Status"] == "Passed"
        assert legs["Caller Scope"]["Severity"] == "High"
        assert "allowedWorkloadConfiguration" in legs["Caller Scope"]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_an_empty_allowed_workload_configuration_restricts_nothing(self, mock_ac):
        self._wire(
            mock_ac,
            authorizerConfiguration={
                "customJWTAuthorizer": {
                    "allowedWorkloadConfiguration": {
                        "hostingEnvironments": [],
                        "workloadIdentities": [],
                    }
                }
            },
        )

        legs = self._legs(agentcore_app.check_agentcore_runtime_invocation_path())

        assert legs["Caller Unrestricted"]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_named_principal_passes_the_caller_leg(self, mock_ac):
        self._wire(
            mock_ac,
            policy={
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/gw"},
                        "Action": "bedrock-agentcore:InvokeAgentRuntime",
                        "Resource": "*",
                    }
                ]
            },
        )

        legs = self._legs(agentcore_app.check_agentcore_runtime_invocation_path())

        assert legs["Caller Scope"]["Status"] == "Passed"
        assert "1 principal" in legs["Caller Scope"]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_a_wildcard_principal_fails_the_caller_leg(self, mock_ac):
        self._wire(
            mock_ac,
            policy={
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "bedrock-agentcore:InvokeAgentRuntime",
                        "Resource": "*",
                    }
                ]
            },
        )

        legs = self._legs(agentcore_app.check_agentcore_runtime_invocation_path())

        assert legs["Caller Unrestricted"]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_deny_principal_is_not_a_caller_restriction(self, mock_ac):
        # A Deny naming one principal leaves every other principal allowed, so
        # it does not name who may invoke the runtime.
        self._wire(
            mock_ac,
            policy={
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/other"},
                        "Action": "bedrock-agentcore:InvokeAgentRuntime",
                        "Resource": "*",
                    }
                ]
            },
        )

        legs = self._legs(agentcore_app.check_agentcore_runtime_invocation_path())

        assert legs["Caller Unrestricted"]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_a_missing_resource_policy_is_read_as_no_policy(self, mock_ac):
        summary, runtime = _vpc_runtime()
        _wire_runtimes(mock_ac, [(summary, runtime)])
        mock_ac.get_resource_policy.side_effect = _make_client_error(
            "ResourceNotFoundException", "no policy"
        )

        legs = self._legs(agentcore_app.check_agentcore_runtime_invocation_path())

        assert legs["Network Path Unrestricted"]["Status"] == "Failed"
        assert legs["Caller Unrestricted"]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_an_unreadable_resource_policy_is_na(self, mock_ac):
        summary, runtime = _vpc_runtime()
        _wire_runtimes(mock_ac, [(summary, runtime)])
        mock_ac.get_resource_policy.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )

        findings = agentcore_app.check_agentcore_runtime_invocation_path()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "GetResourcePolicy" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_an_unreadable_runtime_is_na(self, mock_ac):
        _wire_runtimes(mock_ac, [_vpc_runtime()])
        mock_ac.get_agent_runtime.side_effect = _make_client_error(
            "AccessDeniedException", "denied"
        )

        findings = agentcore_app.check_agentcore_runtime_invocation_path()

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "GetAgentRuntime" in findings[0]["Resolution"]

    @patch("agentcore_app.agentcore_client")
    def test_a_runtime_with_no_arn_is_judged_without_a_policy_call(self, mock_ac):
        summary, runtime = _vpc_runtime()
        del runtime["agentRuntimeArn"]
        _wire_runtimes(mock_ac, [(summary, runtime)])

        legs = self._legs(agentcore_app.check_agentcore_runtime_invocation_path())

        assert legs["Network Path Unrestricted"]["Status"] == "Failed"
        assert mock_ac.get_resource_policy.call_count == 0

    @patch("agentcore_app.agentcore_client")
    def test_every_runtime_is_judged(self, mock_ac):
        open_summary, open_runtime = _vpc_runtime("rt-open")
        scoped_summary, scoped_runtime = _vpc_runtime(
            "rt-scoped",
            authorizerConfiguration={
                "customJWTAuthorizer": {
                    "allowedWorkloadConfiguration": {
                        "hostingEnvironments": ["arn:aws:bedrock-agentcore:::gw/g"]
                    }
                }
            },
        )
        _wire_runtimes(
            mock_ac,
            [(open_summary, open_runtime), (scoped_summary, scoped_runtime)],
        )
        mock_ac.get_resource_policy.return_value = {"policy": ""}

        findings = agentcore_app.check_agentcore_runtime_invocation_path()

        assert len(findings) == 4
        assert [finding["Status"] for finding in findings] == [
            "Failed",
            "Failed",
            "Failed",
            "Passed",
        ]

    def test_the_allowed_workload_fields_are_the_ones_the_api_models(self):
        credentials = {
            "region_name": "us-east-1",
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",  # pragma: allowlist secret - synthetic test credential
        }
        model = agentcore_app.boto3.client(
            "bedrock-agentcore-control", **credentials
        ).meta.service_model
        authorizer = model.operation_model("GetAgentRuntime").output_shape.members[
            "authorizerConfiguration"
        ]
        allowed = authorizer.members["customJWTAuthorizer"].members[
            "allowedWorkloadConfiguration"
        ]
        assert set(allowed.members) == {"hostingEnvironments", "workloadIdentities"}
        assert "GetResourcePolicy" in model.operation_names


class TestRuntimeIsolationCheckRegistration:
    """AC-45 to AC-47 are regional runtime checks."""

    _CHECKS = {
        "AC-45": "check_agentcore_tool_execution_role_scope",
        "AC-46": "check_agentcore_runtime_session_limits",
        "AC-47": "check_agentcore_runtime_invocation_path",
    }

    @pytest.mark.parametrize("check_id", sorted(_CHECKS))
    def test_the_checks_are_in_both_regional_tuples(self, check_id):
        assert check_id in agentcore_app.REGIONAL_AGENTCORE_CHECK_IDS
        assert check_id in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS

    @pytest.mark.parametrize("check_id", sorted(_CHECKS))
    def test_timeout_backfill_emits_the_checks(self, check_id):
        findings = agentcore_app.build_agentcore_timeout_findings("us-east-1", [])
        assert check_id in {finding["Check_ID"] for finding in findings}

    @pytest.mark.parametrize("function_name", sorted(_CHECKS.values()))
    def test_the_handler_registers_each_check_once(self, function_name):
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count(function_name) == 1

    def test_the_handler_lists_custom_browsers_once_for_every_check(self):
        # AC-01 and AC-45 both read the custom browser inventory. The handler
        # takes it once and passes it down, so a new check that called
        # get_custom_browser_inventory() itself would double the list calls.
        source = textwrap.dedent(inspect.getsource(agentcore_app.lambda_handler))
        assert source.count("get_custom_browser_inventory()") == 1
        assert source.count("browser_inventory") >= 3
