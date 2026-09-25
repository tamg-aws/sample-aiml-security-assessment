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

import sys
import os
import importlib.util
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
