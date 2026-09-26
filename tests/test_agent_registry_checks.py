"""Tests for the standalone AWS Agent Registry assessment Lambda."""

import csv
import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
import pytest

from tests.test_helpers import assert_finding_schema

_REGISTRY_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/agent_registry_assessments",
    )
)
if _REGISTRY_DIR not in sys.path:
    sys.path.insert(0, _REGISTRY_DIR)

_SPEC = importlib.util.spec_from_file_location(
    "agent_registry_app", os.path.join(_REGISTRY_DIR, "app.py")
)
agent_registry_app = importlib.util.module_from_spec(_SPEC)
sys.modules["agent_registry_app"] = agent_registry_app
_SPEC.loader.exec_module(agent_registry_app)


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
        agent_registry_app._caller_identity_partition(caller_identity)
        == expected_partition
    )


def _registry_inventory():
    return {
        "items": [],
        "errors": [],
        "list_error": None,
        "unavailable": False,
        "timed_out": False,
    }


def _record_inventory(registry_inventory=None):
    return {
        "items": [],
        "errors": [],
        "list_errors": [],
        "registry_inventory": registry_inventory or _registry_inventory(),
        "timed_out": False,
        "truncated": False,
    }


def _ready_registry_inventory(detail=None):
    inventory = _registry_inventory()
    inventory["items"] = [
        {
            "summary": {"registryId": "registry-123", "name": "inventory"},
            "detail": {
                "registryId": "registry-123",
                "name": "inventory",
                "status": "READY",
                **(detail or {}),
            },
        }
    ]
    return inventory


def _access_denied_registry_inventory():
    inventory = _registry_inventory()
    inventory["list_error"] = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
        "ListRegistries",
    )
    return inventory


def _registry_permission_cache():
    return {
        "role_permissions": {
            "registry-reader": {
                "attached_policies": [],
                "inline_policies": [
                    {
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": {
                                "Effect": "Allow",
                                "Action": "agent-registry:*",
                                "Resource": "*",
                            },
                        }
                    }
                ],
            }
        },
        "user_permissions": {},
    }


def test_provenance_uses_botocore_source_id_shape():
    provenance = [
        {
            "relation": "DETECTED_FROM",
            "sourceId": (
                "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-123"
            ),
            "sourceType": "AWS::BedrockAgentCore::Runtime",
        }
    ]

    assert agent_registry_app._valid_provenance(provenance) is True


def test_provenance_rejects_missing_or_mismatched_source_id():
    assert (
        agent_registry_app._valid_provenance(
            [
                {
                    "relation": "DETECTED_FROM",
                    "sourceId": (
                        "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
                        "gateway/gateway-123"
                    ),
                    "sourceType": "AWS::BedrockAgentCore::Runtime",
                }
            ]
        )
        is False
    )
    assert (
        agent_registry_app._valid_provenance(
            [
                {
                    "relation": "DETECTED_FROM",
                    "sourceId": (
                        "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
                        "runtime/runtime-123"
                    ),
                }
            ]
        )
        is None
    )


def test_provenance_check_passes_for_correctly_provenanced_record():
    registry_inventory = _registry_inventory()
    registry_inventory["items"] = [
        {
            "summary": {"registryId": "registry-123", "name": "inventory"},
            "detail": {
                "registryId": "registry-123",
                "name": "inventory",
                "status": "READY",
            },
        }
    ]
    inventory = _record_inventory(registry_inventory)
    inventory["items"] = [
        {
            "detail": {
                "displayName": "inventory-runtime",
                "createdByAutoDetection": True,
                "provenanceSummaryList": [
                    {
                        "relation": "DETECTED_FROM",
                        "sourceId": (
                            "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
                            "runtime/runtime-123"
                        ),
                        "sourceType": "AWS::BedrockAgentCore::Runtime",
                    }
                ],
            }
        }
    ]

    finding = agent_registry_app.check_agent_registry_record_provenance(inventory)[0]

    assert finding["Check_ID"] == "AR-08"
    assert finding["Status"] == "Passed"
    assert_finding_schema(finding)


def test_handler_uses_execution_name_for_cache_and_registry_csv_key():
    captured = {}

    def fake_write(execution_id, csv_content, region):
        captured["execution_id"] = execution_id
        captured["region"] = region
        return "s3://test-assessment-bucket/agent_registry_security_report_exec-123_us-east-1.csv"

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            return_value={"role_permissions": {}, "user_permissions": {}},
        ) as get_cache,
        patch.object(
            agent_registry_app, "check_agent_registry_stale_access", return_value=[]
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "generate_csv_report", return_value="csv"),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {
                "Execution": {"Name": "exec-123"},
                "Region": "us-east-1",
                "RegionIndex": 0,
            },
            None,
        )

    assert response["statusCode"] == 200
    get_cache.assert_called_once_with("exec-123")
    assert captured == {"execution_id": "exec-123", "region": "us-east-1"}


def test_registry_inventory_access_denied_is_indeterminate():
    client = MagicMock()
    client.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
        "ListRegistries",
    )

    with patch.object(agent_registry_app, "agent_registry_control_client", client):
        inventory = agent_registry_app.get_agent_registry_inventory()

    finding = agent_registry_app.check_agent_registry_approval_governance(inventory)[0]
    assert finding["Check_ID"] == "AR-03"
    assert finding["Status"] == "N/A"
    assert "agent-registry:ListRegistries" in finding["Resolution"]


def test_agentic_registry_mapping_uses_ar_source_ids():
    findings = agent_registry_app.build_agentic_agent_registry_findings(
        [
            {
                "Check_ID": "AR-08",
                "Finding_Details": "Provenance is valid.",
                "Severity": "Medium",
                "Status": "Passed",
                "Region": "us-east-1",
            }
        ]
    )

    assert len(findings) == 1
    assert findings[0]["Check_ID"] == "AG-38"
    assert findings[0]["Status"] == "Passed"
    assert_finding_schema(findings[0])


def test_single_statement_policy_is_evaluated_for_registry_wildcards():
    findings = agent_registry_app.check_agent_registry_full_access(
        _registry_permission_cache()
    )

    assert any(finding["Status"] == "Failed" for finding in findings)
    assert "registry-reader" in findings[0]["Finding_Details"]


def test_ar01_passes_for_scoped_permissions_and_is_na_without_cached_roles():
    scoped_cache = _registry_permission_cache()
    scoped_cache["role_permissions"]["registry-reader"]["inline_policies"][0][
        "document"
    ]["Statement"]["Action"] = "agent-registry:GetRegistry"
    scoped_cache["role_permissions"]["registry-reader"]["inline_policies"][0][
        "document"
    ]["Statement"][
        "Resource"
    ] = "arn:aws:agent-registry:us-east-1:123456789012:registry/registry-123"

    assert (
        agent_registry_app.check_agent_registry_full_access(scoped_cache)[0]["Status"]
        == "Passed"
    )
    assert (
        agent_registry_app.check_agent_registry_full_access(
            {"role_permissions": {}, "user_permissions": {}}
        )[0]["Status"]
        == "N/A"
    )


def test_ar01_reports_permission_cache_access_denied_as_indeterminate():
    captured = {}

    def fake_write(_execution_id, csv_content, _region):
        captured["csv"] = csv_content
        return "s3://test-assessment-bucket/report.csv"

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            side_effect=ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
                "GetObject",
            ),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
            None,
        )

    assert response["statusCode"] == 200
    assert "AR-01" in captured["csv"]
    assert "IAM permission cache" in captured["csv"]


def test_ar04_matrix_covers_constrained_unconstrained_empty_and_access_denied():
    constrained = _ready_registry_inventory(
        {
            "discoveryConfiguration": {
                "authorizerType": "CUSTOM_JWT",
                "authorizerConfiguration": {
                    "customJWTAuthorizer": {
                        "discoveryUrl": "https://issuer.example.com/.well-known/openid-configuration",
                        "allowedAudience": ["registry-consumer"],
                    }
                },
            }
        }
    )
    unconstrained = _ready_registry_inventory(
        {
            "discoveryConfiguration": {
                "authorizerType": "CUSTOM_JWT",
                "authorizerConfiguration": {"customJWTAuthorizer": {}},
            }
        }
    )

    assert (
        agent_registry_app.check_agent_registry_discovery_authorization(constrained)[0][
            "Status"
        ]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_discovery_authorization(unconstrained)[
            0
        ]["Status"]
        == "Failed"
    )
    assert (
        agent_registry_app.check_agent_registry_discovery_authorization(
            _registry_inventory()
        )[0]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_discovery_authorization(
            _access_denied_registry_inventory()
        )[0]["Status"]
        == "N/A"
    )


def test_ar05_matrix_covers_cmk_default_empty_and_access_denied(monkeypatch):
    encrypted = _ready_registry_inventory(
        {
            "encryptionConfiguration": {
                "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-123"
            }
        }
    )
    default_key = _ready_registry_inventory({"encryptionConfiguration": {}})
    monkeypatch.setenv("REQUIRE_AGENT_REGISTRY_CMK", "true")

    assert (
        agent_registry_app.check_agent_registry_cmk_encryption(encrypted)[0]["Status"]
        == "Passed"
    )
    assert (
        agent_registry_app.check_agent_registry_cmk_encryption(default_key)[0]["Status"]
        == "Failed"
    )
    assert (
        agent_registry_app.check_agent_registry_cmk_encryption(_registry_inventory())[
            0
        ]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_cmk_encryption(
            _access_denied_registry_inventory()
        )[0]["Status"]
        == "N/A"
    )


def test_ar06_matrix_covers_active_advisory_empty_and_access_denied():
    active = _ready_registry_inventory(
        {
            "autoDetection": {
                "configuration": {"enabled": True, "scope": "ORGANIZATION"},
                "status": "ACTIVE",
            }
        }
    )
    disabled = _ready_registry_inventory(
        {
            "autoDetection": {
                "configuration": {"enabled": False, "scope": "ACCOUNT"},
                "status": "INACTIVE",
            }
        }
    )

    assert (
        agent_registry_app.check_agent_registry_auto_detection(active)[0]["Status"]
        == "Passed"
    )
    assert (
        agent_registry_app.check_agent_registry_auto_detection(disabled)[0]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_auto_detection(_registry_inventory())[
            0
        ]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_auto_detection(
            _access_denied_registry_inventory()
        )[0]["Status"]
        == "N/A"
    )


def test_ar07_matrix_covers_record_observation_empty_and_access_denied():
    registry_inventory = _ready_registry_inventory()
    observed = _record_inventory(registry_inventory)
    observed["items"] = [
        {
            "detail": {
                "displayName": "approved-record",
                "status": "APPROVED",
            }
        }
    ]
    denied = _record_inventory(registry_inventory)
    denied["list_errors"] = [
        (
            registry_inventory["items"][0],
            ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
                "ListRegistryRecords",
            ),
        )
    ]

    assert (
        agent_registry_app.check_agent_registry_record_lifecycle(observed)[0]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_record_lifecycle(
            _record_inventory(registry_inventory)
        )[0]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_record_lifecycle(denied)[0]["Status"]
        == "N/A"
    )


def test_stale_access_uses_service_last_accessed_data():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-123"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [
            {
                "ServiceNamespace": "agent-registry",
                "LastAuthenticated": datetime.now(timezone.utc) - timedelta(days=61),
            }
        ],
    }
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=sts),
        patch.object(agent_registry_app, "iam_client", iam),
    ):
        findings = agent_registry_app.check_agent_registry_stale_access(
            _registry_permission_cache()
        )

    assert iam.generate_service_last_accessed_details.called
    assert any(finding["Status"] == "Failed" for finding in findings)
    assert "61 days" in findings[-1]["Finding_Details"]


def test_stale_access_sts_error_does_not_recommend_an_iam_grant():
    sts = MagicMock()
    sts.get_caller_identity.side_effect = ClientError(
        {"Error": {"Code": "InvalidClientTokenId", "Message": "Invalid token"}},
        "GetCallerIdentity",
    )

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=sts),
        patch.object(agent_registry_app, "iam_client", MagicMock()),
    ):
        finding = agent_registry_app.check_agent_registry_stale_access(
            _registry_permission_cache()
        )[0]

    assert finding["Status"] == "N/A"
    assert "does not require an IAM Allow permission" in finding["Resolution"]
    assert "Grant sts:GetCallerIdentity" not in finding["Resolution"]


def test_provenance_missing_origin_mode_is_indeterminate():
    registry_inventory = _ready_registry_inventory()
    inventory = _record_inventory(registry_inventory)
    inventory["items"] = [{"detail": {"displayName": "record-123"}}]

    finding = agent_registry_app.check_agent_registry_record_provenance(inventory)[0]

    assert finding["Status"] == "N/A"
    assert "origin-mode metadata" in finding["Finding_Details"]


def test_provenance_reports_record_listing_errors_when_no_records_are_returned():
    registry_inventory = _ready_registry_inventory()
    inventory = _record_inventory(registry_inventory)
    inventory["list_errors"] = [
        (
            registry_inventory["items"][0],
            ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
                "ListRegistryRecords",
            ),
        )
    ]

    findings = agent_registry_app.check_agent_registry_record_provenance(inventory)

    assert len(findings) == 1
    assert findings[0]["Check_ID"] == "AR-08"
    assert findings[0]["Status"] == "N/A"
    assert "ListRegistryRecords" in findings[0]["Resolution"]


def test_record_truncation_keeps_collected_records_and_adds_incomplete_notice():
    registry_inventory = _ready_registry_inventory()
    inventory = _record_inventory(registry_inventory)
    inventory["truncated"] = True
    inventory["items"] = [
        {
            "detail": {
                "displayName": "manual-record",
                "createdByAutoDetection": False,
                "createdBy": "123456789012",
            }
        }
    ]

    findings = agent_registry_app.check_agent_registry_record_provenance(inventory)

    assert {finding["Status"] for finding in findings} == {"N/A", "Passed"}
    assert any("safety limit" in finding["Finding_Details"] for finding in findings)


def test_unknown_discovery_authorizer_is_not_labeled_as_custom_jwt():
    findings = agent_registry_app.check_agent_registry_discovery_authorization(
        _ready_registry_inventory(
            {"discoveryConfiguration": {"authorizerType": "FUTURE_AUTHORIZER"}}
        )
    )

    assert findings[0]["Status"] == "N/A"
    assert "unsupported discovery authorizer type" in findings[0]["Finding_Details"]
    assert "custom JWT" not in findings[0]["Finding_Details"]


def test_missing_auto_detection_metadata_is_indeterminate_not_absent():
    findings = agent_registry_app.check_agent_registry_auto_detection(
        _ready_registry_inventory()
    )

    assert findings[0]["Status"] == "N/A"
    assert (
        "did not return optional auto-detection metadata"
        in findings[0]["Finding_Details"]
    )


def test_handler_isolates_check_failure_and_writes_csv():
    captured = {}

    def fake_write(_execution_id, csv_content, _region):
        captured["csv"] = csv_content
        return "s3://test-assessment-bucket/agent_registry_security_report_exec-123_us-east-1.csv"

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            return_value={"role_permissions": {}, "user_permissions": {}},
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_full_access", return_value=[]
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_stale_access", return_value=[]
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "check_agent_registry_approval_governance",
            side_effect=RuntimeError("boom"),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
            None,
        )

    assert response["statusCode"] == 200
    assert "AR-03" in captured["csv"]
    assert "Publication Approval Governance Incomplete" in captured["csv"]


def test_handler_reraises_unrecoverable_csv_write_failures():
    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            return_value={"role_permissions": {}, "user_permissions": {}},
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_full_access", return_value=[]
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_stale_access", return_value=[]
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "write_to_s3",
            side_effect=RuntimeError("S3 unavailable"),
        ),
    ):
        with pytest.raises(RuntimeError, match="S3 unavailable"):
            agent_registry_app.lambda_handler(
                {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
                None,
            )


def test_handler_does_not_fetch_records_after_registry_inventory_timeout():
    inventory = _ready_registry_inventory()
    inventory["timed_out"] = True

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=inventory,
        ),
        patch.object(
            agent_registry_app, "get_agent_registry_record_inventory"
        ) as record_inventory,
        patch.object(
            agent_registry_app,
            "write_to_s3",
            return_value="s3://test-assessment-bucket/report.csv",
        ),
    ):
        response = agent_registry_app.lambda_handler(
            {
                "Execution": {"Name": "exec-123"},
                "Region": "us-east-1",
                "RegionIndex": 1,
            },
            None,
        )

    assert response["statusCode"] == 200
    record_inventory.assert_not_called()


# ===================================================================
# AR-09: check_agent_registry_approval_separation
# ===================================================================
_SEPARATION_FINDING = "AWS Agent Registry Approval Authority Separation"
_REGISTRY_NAMESPACES = ("agent-registry", "bedrock-agentcore")
_PUBLISH_ACTIONS = (
    "CreateRegistryRecord",
    "UpdateRegistryRecord",
    "SubmitRegistryRecordForApproval",
)
_APPROVAL_ACTION = "UpdateRegistryRecordStatus"


def _allow(actions, resource="*"):
    return {"Effect": "Allow", "Action": actions, "Resource": resource}


def _deny(actions, resource="*", **extra):
    return {"Effect": "Deny", "Action": actions, "Resource": resource, **extra}


def _principal(inline=None, attached=None):
    def _policy(name, statements):
        return {
            "name": name,
            "document": {"Version": "2012-10-17", "Statement": statements},
        }

    return {
        "attached_policies": [_policy("attached", attached)] if attached else [],
        "inline_policies": [_policy("inline", inline)] if inline else [],
    }


def _separation_cache(statements, principal_kind="role", principal_name="publisher"):
    """A permission cache holding one principal with one inline policy."""
    cache = {"role_permissions": {}, "user_permissions": {}}
    cache[f"{principal_kind}_permissions"] = {
        principal_name: _principal(inline=statements)
    }
    return cache


def _separation_finding(cache):
    findings = agent_registry_app.check_agent_registry_approval_separation(cache)
    assert len(findings) == 1
    assert findings[0]["Check_ID"] == "AR-09"
    assert findings[0]["Finding"].startswith(_SEPARATION_FINDING)
    assert_finding_schema(findings[0])
    return findings[0]


def _listed_publish_actions(finding):
    """The publish actions the finding names for its one reported principal."""
    return finding["Finding_Details"].rsplit("(", 1)[-1].rstrip(")").split(", ")


@pytest.mark.parametrize("namespace", _REGISTRY_NAMESPACES)
@pytest.mark.parametrize("publish_action", _PUBLISH_ACTIONS)
def test_ar09_reports_each_publish_action_held_beside_approval(
    namespace, publish_action
):
    finding = _separation_finding(
        _separation_cache(
            [
                _allow(
                    [
                        f"{namespace}:{publish_action}",
                        f"{namespace}:{_APPROVAL_ACTION}",
                    ]
                )
            ]
        )
    )

    assert finding["Status"] == "Failed"
    assert finding["Severity"] == "High"
    assert "role 'publisher'" in finding["Finding_Details"]
    assert _listed_publish_actions(finding) == [f"{namespace}:{publish_action}"]


@pytest.mark.parametrize(
    "actions",
    [
        pytest.param(
            ["agent-registry:CreateRegistryRecord"], id="publish-without-approval"
        ),
        pytest.param(
            [f"agent-registry:{_APPROVAL_ACTION}"], id="approval-without-publish"
        ),
        pytest.param(
            ["agent-registry:GetRegistryRecord", "agent-registry:ListRegistryRecords"],
            id="reads-only",
        ),
        pytest.param(
            [
                "agent-registry:DeleteRegistryRecord",
                f"agent-registry:{_APPROVAL_ACTION}",
            ],
            id="delete-is-not-a-publish-authority",
        ),
    ],
)
def test_ar09_passes_a_principal_holding_one_authority(actions):
    finding = _separation_finding(_separation_cache([_allow(actions)]))

    assert finding["Status"] == "Passed"
    assert finding["Severity"] == "High"
    assert "1 cached IAM identities" in finding["Finding_Details"]


def test_ar09_reads_a_collision_that_spans_the_two_namespaces():
    """The preview namespace grants the same two authorities as the new one."""
    finding = _separation_finding(
        _separation_cache(
            [
                _allow(
                    [
                        "agent-registry:CreateRegistryRecord",
                        f"bedrock-agentcore:{_APPROVAL_ACTION}",
                    ]
                )
            ]
        )
    )

    assert finding["Status"] == "Failed"
    assert _listed_publish_actions(finding) == ["agent-registry:CreateRegistryRecord"]


def test_ar09_reads_a_wildcard_pattern_as_every_authority_it_reaches():
    finding = _separation_finding(
        _separation_cache([_allow(["agent-registry:*RegistryRecord*"])])
    )

    assert finding["Status"] == "Failed"
    assert _listed_publish_actions(finding) == sorted(
        f"agent-registry:{action}" for action in _PUBLISH_ACTIONS
    )


@pytest.mark.parametrize(
    "actions",
    [
        pytest.param(["*"], id="bare-wildcard"),
        pytest.param(["*:*"], id="wildcard-service"),
    ],
)
def test_ar09_leaves_a_service_agnostic_grant_to_the_full_access_check(actions):
    """AR-01 reports an administrator once; AR-09 does not report it again."""
    finding = _separation_finding(_separation_cache([_allow(actions)]))

    assert finding["Status"] == "Passed"


def _colliding_statements(*extra):
    return [
        _allow(
            [
                f"{namespace}:{action}"
                for namespace in _REGISTRY_NAMESPACES
                for action in ("CreateRegistryRecord", _APPROVAL_ACTION)
            ]
        ),
        *extra,
    ]


@pytest.mark.parametrize(
    "deny",
    [
        pytest.param(
            _deny([f"{ns}:{_APPROVAL_ACTION}" for ns in _REGISTRY_NAMESPACES]),
            id="both-namespaces-named",
        ),
        pytest.param(
            _deny(["agent-registry:*", "bedrock-agentcore:*"]), id="namespaces"
        ),
        pytest.param(_deny(["*"]), id="service-agnostic"),
        pytest.param(
            {"Effect": "Deny", "NotAction": ["s3:*"], "Resource": "*"},
            id="not-action-spares-nothing-registry",
        ),
    ],
)
def test_ar09_an_account_wide_deny_excuses_the_principal(deny):
    finding = _separation_finding(_separation_cache(_colliding_statements(deny)))

    assert finding["Status"] == "Passed"


@pytest.mark.parametrize(
    "deny",
    [
        pytest.param(
            _deny([f"agent-registry:{_APPROVAL_ACTION}"]), id="one-namespace-only"
        ),
        pytest.param(
            _deny(
                [f"{ns}:{_APPROVAL_ACTION}" for ns in _REGISTRY_NAMESPACES],
                resource="arn:aws:agent-registry:us-east-1:123456789012:registry/abc",
            ),
            id="scoped-to-one-registry",
        ),
        pytest.param(
            _deny(
                [f"{ns}:{_APPROVAL_ACTION}" for ns in _REGISTRY_NAMESPACES],
                Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            ),
            id="conditioned",
        ),
        pytest.param(
            {
                "Effect": "Deny",
                "NotAction": ["agent-registry:*", "bedrock-agentcore:*"],
                "Resource": "*",
            },
            id="not-action-spares-both-namespaces",
        ),
    ],
)
def test_ar09_a_narrower_deny_does_not_excuse_the_principal(deny):
    finding = _separation_finding(_separation_cache(_colliding_statements(deny)))

    assert finding["Status"] == "Failed"


def test_ar09_reads_a_deny_from_a_different_policy_document():
    cache = {
        "role_permissions": {
            "publisher": _principal(
                inline=[_allow([f"agent-registry:{_APPROVAL_ACTION}"])],
                attached=[
                    _deny([f"{ns}:{_APPROVAL_ACTION}" for ns in _REGISTRY_NAMESPACES]),
                    _allow(["agent-registry:CreateRegistryRecord"]),
                ],
            )
        },
        "user_permissions": {},
    }

    assert _separation_finding(cache)["Status"] == "Passed"


def test_ar09_reads_a_collision_that_spans_attached_and_inline_policies():
    cache = {
        "role_permissions": {
            "publisher": _principal(
                inline=[_allow(["agent-registry:SubmitRegistryRecordForApproval"])],
                attached=[_allow([f"agent-registry:{_APPROVAL_ACTION}"])],
            )
        },
        "user_permissions": {},
    }
    finding = _separation_finding(cache)

    assert finding["Status"] == "Failed"
    assert _listed_publish_actions(finding) == [
        "agent-registry:SubmitRegistryRecordForApproval"
    ]


def test_ar09_judges_every_principal_not_only_the_first():
    cache = {
        "role_permissions": {
            "reader": _principal(inline=[_allow(["agent-registry:GetRegistryRecord"])]),
            "self-approver": _principal(
                inline=[
                    _allow(
                        [
                            "agent-registry:UpdateRegistryRecord",
                            f"agent-registry:{_APPROVAL_ACTION}",
                        ]
                    )
                ]
            ),
        },
        "user_permissions": {},
    }
    finding = _separation_finding(cache)

    assert finding["Status"] == "Failed"
    assert "role 'self-approver'" in finding["Finding_Details"]
    assert "reader" not in finding["Finding_Details"]


def test_ar09_judges_iam_users_beside_roles():
    cache = _separation_cache(
        [
            _allow(
                [
                    "agent-registry:CreateRegistryRecord",
                    f"agent-registry:{_APPROVAL_ACTION}",
                ]
            )
        ],
        principal_kind="user",
        principal_name="ci-publisher",
    )
    finding = _separation_finding(cache)

    assert finding["Status"] == "Failed"
    assert "user 'ci-publisher'" in finding["Finding_Details"]


def test_ar09_passes_when_the_publisher_and_the_curator_are_separate_principals():
    cache = {
        "role_permissions": {
            "publisher": _principal(
                inline=[
                    _allow(
                        [
                            "agent-registry:CreateRegistryRecord",
                            "agent-registry:SubmitRegistryRecordForApproval",
                        ]
                    )
                ]
            ),
            "curator": _principal(
                inline=[_allow([f"agent-registry:{_APPROVAL_ACTION}"])]
            ),
        },
        "user_permissions": {"auditor": _principal()},
    }
    finding = _separation_finding(cache)

    assert finding["Status"] == "Passed"
    assert "3 cached IAM identities" in finding["Finding_Details"]


def test_ar09_is_indeterminate_without_a_cached_principal():
    finding = _separation_finding({"role_permissions": {}, "user_permissions": {}})

    assert finding["Status"] == "N/A"
    assert finding["Severity"] == "Informational"


def test_ar09_watches_both_namespace_spellings_of_every_authority():
    allowed, denied = agent_registry_app._registry_authority_actions(
        _principal(inline=[_allow([f"{ns}:*" for ns in _REGISTRY_NAMESPACES])])
    )

    assert allowed == {
        f"{namespace}:{action}"
        for namespace in _REGISTRY_NAMESPACES
        for action in (*_PUBLISH_ACTIONS, _APPROVAL_ACTION)
    }
    assert denied == set()
    assert agent_registry_app.REGISTRY_IAM_NAMESPACES == _REGISTRY_NAMESPACES
    assert agent_registry_app.REGISTRY_PUBLISH_ACTIONS == _PUBLISH_ACTIONS
    assert agent_registry_app.REGISTRY_APPROVAL_ACTION == _APPROVAL_ACTION


def test_ar09_authorities_are_the_modelled_registry_record_operations():
    """The two authorities are named after real control-plane operations."""
    model = agent_registry_app.boto3.client(
        "agent-registry-control",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
    ).meta.service_model
    operations = set(model.operation_names)

    assert set(_PUBLISH_ACTIONS) | {_APPROVAL_ACTION} <= operations
    # Backward leg: no other modelled operation can set a record's status, so the
    # approval authority really is this one action.
    assert {
        name
        for name in operations
        if "status" in (model.operation_model(name).input_shape.members or {})
    } == {_APPROVAL_ACTION}
    # Backward leg: the publish set is every record write except the two that do
    # not put content into the approval workflow.
    record_operations = {
        name
        for name in operations
        if name.endswith("RegistryRecord") or name == "SubmitRegistryRecordForApproval"
    }
    assert record_operations - {"GetRegistryRecord", "DeleteRegistryRecord"} == set(
        _PUBLISH_ACTIONS
    )
    # APPROVED is the status that makes a record discoverable, which is what makes
    # holding the approval action beside a record write a self-approval path.
    assert (
        "APPROVED"
        in model.operation_model(_APPROVAL_ACTION).input_shape.members["status"].enum
    )


def test_handler_emits_ar09_as_a_global_row():
    captured = {}

    def fake_write(_execution_id, csv_content, _region):
        captured["csv"] = csv_content
        return "s3://test-assessment-bucket/report.csv"

    cache = _separation_cache(
        [
            _allow(
                [
                    "agent-registry:CreateRegistryRecord",
                    f"agent-registry:{_APPROVAL_ACTION}",
                ]
            )
        ]
    )
    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(agent_registry_app, "_get_permissions_cache", return_value=cache),
        patch.object(
            agent_registry_app, "check_agent_registry_stale_access", return_value=[]
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
            None,
        )

    assert response["statusCode"] == 200
    rows = [
        row
        for row in csv.DictReader(StringIO(captured["csv"]))
        if row["Check_ID"] == "AR-09"
    ]
    assert [(row["Status"], row["Region"]) for row in rows] == [("Failed", "Global")]


def test_ar09_reports_a_permission_cache_failure_as_indeterminate():
    captured = {}

    def fake_write(_execution_id, csv_content, _region):
        captured["csv"] = csv_content
        return "s3://test-assessment-bucket/report.csv"

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            side_effect=ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
                "GetObject",
            ),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
            None,
        )

    assert response["statusCode"] == 200
    rows = [
        row
        for row in csv.DictReader(StringIO(captured["csv"]))
        if row["Check_ID"] == "AR-09"
    ]
    assert [(row["Status"], row["Region"]) for row in rows] == [("N/A", "Global")]
    assert "IAM permission cache" in rows[0]["Finding_Details"]
