"""
Tests for Bedrock security assessment checks (BR-01 through BR-13).

Each check is tested for:
- No resources / empty cache -> N/A status
- Compliant resources -> Passed status
- Non-compliant resources -> Failed with correct severity
- Exception handling -> returns could-not-assess finding (csv_data not empty)
- Output schema validity
"""

import contextlib
import json
import sys
import os
import importlib.util
from unittest.mock import patch, MagicMock
from botocore.exceptions import (
    EndpointConnectionError,
    ClientError,
    UnknownServiceError,
)

import pytest

from tests.test_helpers import extract_csv_data, assert_finding_schema

# Load bedrock app module directly to avoid name collisions with other app.py files
_bedrock_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/bedrock_assessments",
    )
)
if _bedrock_dir not in sys.path:
    sys.path.insert(0, _bedrock_dir)

_spec = importlib.util.spec_from_file_location(
    "bedrock_app", os.path.join(_bedrock_dir, "app.py")
)
bedrock_app = importlib.util.module_from_spec(_spec)
sys.modules["bedrock_app"] = bedrock_app
_spec.loader.exec_module(bedrock_app)


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
    assert bedrock_app._caller_identity_partition(caller_identity) == expected_partition


def assert_could_not_assess_finding(finding):
    assert finding["Status"] == "N/A"
    assert finding["Severity"] == "Informational"
    assert "Could not assess this check" in finding["Finding_Details"]
    assert "Error during check" not in finding["Finding_Details"]


class TestPaginationHelper:
    def test_list_all_items_stops_on_repeated_token(self):
        client = MagicMock()
        client.list_items.return_value = {
            "Items": [{"id": "item-1"}],
            "nextToken": "repeated",
        }

        items = bedrock_app._list_all_items(
            client, "list_items", "Items", max_results=100
        )

        assert items == [{"id": "item-1"}, {"id": "item-1"}]
        assert client.list_items.call_count == 2


# ===================================================================
# BR-01: check_bedrock_full_access_roles
# ===================================================================
class TestBR01FullAccessRoles:
    """BR-01: Check for roles with AmazonBedrockFullAccess policy."""

    def test_br01_no_roles_with_full_access_returns_passed(
        self, empty_permission_cache
    ):
        check = bedrock_app.check_bedrock_full_access_roles
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-01"

    def test_br01_role_with_full_access_returns_failed(
        self, permission_cache_with_full_access
    ):
        check = bedrock_app.check_bedrock_full_access_roles
        result = check(permission_cache_with_full_access)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert "FullAccessRole" in findings[0]["Finding_Details"]

    def test_br01_compliant_roles_returns_passed(self, permission_cache_compliant):
        check = bedrock_app.check_bedrock_full_access_roles
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    def test_br01_schema_valid(self, permission_cache_with_full_access):
        check = bedrock_app.check_bedrock_full_access_roles
        result = check(permission_cache_with_full_access)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-02: check_bedrock_access_and_vpc_endpoints
# ===================================================================
class TestBR02VPCEndpoints:
    """BR-02: Check Bedrock access and VPC endpoints."""

    def test_br02_no_bedrock_access_returns_no_findings(self, empty_permission_cache):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        result = check(empty_permission_cache)
        # When no bedrock access found, csv_data may be empty or have info finding
        assert "csv_data" in result

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br02_bedrock_access_with_endpoints_returns_passed(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        mock_vpc.return_value = {
            "has_endpoints": True,
            "found_endpoints": [
                {
                    "vpc_id": "vpc-123",
                    "service": "com.amazonaws.us-east-1.bedrock-runtime",
                }
            ],
            "all_vpcs": ["vpc-123"],
        }
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-02"

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br02_bedrock_access_no_endpoints_returns_failed(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        mock_vpc.return_value = {
            "has_endpoints": False,
            "found_endpoints": [],
            "all_vpcs": ["vpc-123"],
        }
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    def test_br02_no_regional_footprint_returns_na(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        result = check(permission_cache_compliant, region="eu-west-3")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == (
            "No regional Bedrock resources found to assess private connectivity"
        )
        mock_vpc.assert_not_called()

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br02_exception_returns_error_finding(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        mock_vpc.side_effect = Exception("VPC check failed")
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br02_schema_valid(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        mock_vpc.return_value = {
            "has_endpoints": True,
            "found_endpoints": [{"vpc_id": "vpc-1", "service": "bedrock"}],
            "all_vpcs": ["vpc-1"],
        }
        result = check(permission_cache_compliant)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-03: check_marketplace_subscription_access
# ===================================================================
class TestBR03MarketplaceAccess:
    """BR-03: Check marketplace subscription access."""

    def test_br03_no_overpermissive_returns_passed(self, permission_cache_compliant):
        check = bedrock_app.check_marketplace_subscription_access
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-03"

    def test_br03_overpermissive_returns_failed(
        self, permission_cache_marketplace_overpermissive
    ):
        check = bedrock_app.check_marketplace_subscription_access
        result = check(permission_cache_marketplace_overpermissive)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    def test_br03_empty_cache_returns_passed(self, empty_permission_cache):
        check = bedrock_app.check_marketplace_subscription_access
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    def test_br03_schema_valid(self, permission_cache_marketplace_overpermissive):
        check = bedrock_app.check_marketplace_subscription_access
        result = check(permission_cache_marketplace_overpermissive)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-04: check_bedrock_logging_configuration
# ===================================================================
class TestBR04LoggingConfiguration:
    """BR-04: Check model invocation logging."""

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_logging_enabled_s3_returns_passed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "s3Config": {"bucketName": "my-log-bucket"},
                "cloudWatchConfig": {},
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-04"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_logging_disabled_returns_failed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {}, "cloudWatchConfig": {}}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    def test_br04_no_regional_footprint_returns_na(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        result = check(region="eu-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == (
            "No regional Bedrock resources found to monitor with invocation logging"
        )
        mock_client.assert_not_called()

    @patch("boto3.client")
    def test_br04_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_client.side_effect = Exception("Service unavailable")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_schema_valid(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "s3Config": {"bucketName": "bucket"},
                "cloudWatchConfig": {},
            }
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("boto3.client")
    def test_br04_logging_enabled_s3_legacy_key_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "s3Config": {"s3BucketName": "legacy-log-bucket"},
                "cloudWatchConfig": {},
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    # --- Retention leg: AIR-BDR-MDL-02 -------------------------------------
    RETENTION_FINDING = "Bedrock Invocation Log Retention"

    @staticmethod
    def _retention_clients(logging_config, log_group_pages=None, lifecycle=None):
        """Dispatch the bedrock, logs and s3 clients the retention leg reads."""
        mock_bedrock = MagicMock()
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": logging_config
        }

        mock_logs = MagicMock()
        pages = list(log_group_pages or [{"logGroups": []}])

        def describe_log_groups(**kwargs):
            index = 1 if kwargs.get("nextToken") else 0
            return pages[index] if index < len(pages) else {"logGroups": []}

        mock_logs.describe_log_groups.side_effect = describe_log_groups

        mock_s3 = MagicMock()
        if lifecycle is None:
            mock_s3.get_bucket_lifecycle_configuration.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "NoSuchLifecycleConfiguration",
                        "Message": "The lifecycle configuration does not exist",
                    }
                },
                "GetBucketLifecycleConfiguration",
            )
        else:
            mock_s3.get_bucket_lifecycle_configuration.return_value = lifecycle

        clients = {"bedrock": mock_bedrock, "logs": mock_logs, "s3": mock_s3}
        return (lambda service_name, **kwargs: clients[service_name]), clients

    def _retention_findings(self, findings):
        return [f for f in findings if f["Finding"] == self.RETENTION_FINDING]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_retention_is_judged_per_destination(
        self, mock_footprint, mock_client
    ):
        # Two destinations, one with a stated period and one without: the
        # bucket lifecycle expires objects, the log group never expires events.
        mock_client.side_effect, _ = self._retention_clients(
            {
                "s3Config": {"bucketName": "log-bucket"},
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
            },
            log_group_pages=[
                {"logGroups": [{"logGroupName": "/aws/bedrock/invocations"}]}
            ],
            lifecycle={
                "Rules": [
                    {
                        "ID": "expire-logs",
                        "Status": "Enabled",
                        "Expiration": {"Days": 90},
                    }
                ]
            },
        )

        retention = self._retention_findings(
            extract_csv_data(bedrock_app.check_bedrock_logging_configuration())
        )

        failed = [f for f in retention if f["Status"] == "Failed"]
        passed = [f for f in retention if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert failed[0]["Check_ID"] == "BR-04"
        assert (
            "'/aws/bedrock/invocations' has no retentionInDays"
            in (failed[0]["Finding_Details"])
        )
        assert len(passed) == 1
        assert (
            "expire-logs expires objects after 90 day(s)"
            in (passed[0]["Finding_Details"])
        )
        assert "log-bucket" in passed[0]["Finding_Details"]
        assert "1 destination(s)" in passed[0]["Finding_Details"]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_bucket_without_lifecycle_fails_while_log_group_passes(
        self, mock_footprint, mock_client
    ):
        mock_client.side_effect, _ = self._retention_clients(
            {
                "s3Config": {"bucketName": "forever-bucket"},
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
            },
            log_group_pages=[
                {
                    "logGroups": [
                        {
                            "logGroupName": "/aws/bedrock/invocations",
                            "retentionInDays": 365,
                        }
                    ]
                }
            ],
            lifecycle=None,
        )

        retention = self._retention_findings(
            extract_csv_data(bedrock_app.check_bedrock_logging_configuration())
        )

        failed = [f for f in retention if f["Status"] == "Failed"]
        passed = [f for f in retention if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert (
            "'forever-bucket' has no enabled lifecycle rule"
            in (failed[0]["Finding_Details"])
        )
        assert len(passed) == 1
        assert "expires events after 365 day(s)" in passed[0]["Finding_Details"]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_disabled_lifecycle_rule_is_not_a_retention_period(
        self, mock_footprint, mock_client
    ):
        mock_client.side_effect, _ = self._retention_clients(
            {"s3Config": {"bucketName": "log-bucket"}, "cloudWatchConfig": {}},
            lifecycle={
                "Rules": [
                    {"ID": "draft", "Status": "Disabled", "Expiration": {"Days": 30}}
                ]
            },
        )

        retention = self._retention_findings(
            extract_csv_data(bedrock_app.check_bedrock_logging_configuration())
        )

        assert [f["Status"] for f in retention] == ["Failed"]
        assert "no enabled lifecycle rule" in retention[0]["Finding_Details"]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_log_group_not_visible_is_not_a_missing_period(
        self, mock_footprint, mock_client
    ):
        mock_client.side_effect, _ = self._retention_clients(
            {
                "s3Config": {},
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
            },
            log_group_pages=[{"logGroups": [{"logGroupName": "/aws/bedrock/other"}]}],
        )

        retention = self._retention_findings(
            extract_csv_data(bedrock_app.check_bedrock_logging_configuration())
        )

        assert [f["Status"] for f in retention] == ["N/A"]
        assert (
            "was not returned by DescribeLogGroups" in (retention[0]["Finding_Details"])
        )

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_reads_log_groups_from_all_pages(self, mock_footprint, mock_client):
        mock_client.side_effect, clients = self._retention_clients(
            {
                "s3Config": {},
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
            },
            log_group_pages=[
                {
                    "logGroups": [{"logGroupName": "/aws/bedrock/invocations-other"}],
                    "nextToken": "page-2",
                },
                {
                    "logGroups": [
                        {
                            "logGroupName": "/aws/bedrock/invocations",
                            "retentionInDays": 30,
                        }
                    ]
                },
            ],
        )

        retention = self._retention_findings(
            extract_csv_data(bedrock_app.check_bedrock_logging_configuration())
        )

        clients["logs"].describe_log_groups.assert_any_call(
            limit=50,
            logGroupNamePrefix="/aws/bedrock/invocations",
            nextToken="page-2",
        )
        assert [f["Status"] for f in retention] == ["Passed"]
        assert "expires events after 30 day(s)" in retention[0]["Finding_Details"]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_unreadable_lifecycle_is_not_a_missing_period(
        self, mock_footprint, mock_client
    ):
        factory, clients = self._retention_clients(
            {"s3Config": {"bucketName": "log-bucket"}, "cloudWatchConfig": {}}
        )
        clients["s3"].get_bucket_lifecycle_configuration.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetBucketLifecycleConfiguration",
        )
        mock_client.side_effect = factory

        retention = self._retention_findings(
            extract_csv_data(bedrock_app.check_bedrock_logging_configuration())
        )

        assert [f["Status"] for f in retention] == ["N/A"]
        assert "log-bucket" in retention[0]["Finding_Details"]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_retention_findings_schema_valid(self, mock_footprint, mock_client):
        mock_client.side_effect, _ = self._retention_clients(
            {
                "s3Config": {"bucketName": "log-bucket"},
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
            },
            log_group_pages=[
                {"logGroups": [{"logGroupName": "/aws/bedrock/invocations"}]}
            ],
            lifecycle={"Rules": [{"Status": "Enabled", "Expiration": {"Days": 7}}]},
        )

        findings = extract_csv_data(bedrock_app.check_bedrock_logging_configuration())
        assert self._retention_findings(findings)
        for finding in findings:
            assert_finding_schema(finding)


# ===================================================================
# BR-05: check_bedrock_guardrails
# ===================================================================
class TestBR05Guardrails:
    """BR-05: Check Bedrock guardrails exist."""

    @patch("boto3.client")
    def test_br05_guardrails_exist_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {
            "guardrails": [{"name": "content-filter", "guardrailId": "gr-123"}]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-05"

    @patch("boto3.client")
    def test_br05_no_guardrails_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        with patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True):
            result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("boto3.client")
    def test_br05_no_guardrails_and_no_regional_footprint_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        with patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False):
            result = check(region="eu-west-3")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == (
            "No regional Bedrock resources found to protect with guardrails"
        )

    @patch("boto3.client")
    def test_br05_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_client.side_effect = Exception("Access denied")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    def test_br05_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        with patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True):
            result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-06: check_bedrock_cloudtrail_logging
# ===================================================================
class TestBR06CloudTrailLogging:
    """BR-06: Check CloudTrail logging for Bedrock."""

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_trail_is_logging_returns_passed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_ct = MagicMock()
        mock_client.return_value = mock_ct
        mock_ct.list_trails.return_value = {
            "Trails": [
                {
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main",
                    "Name": "main",
                }
            ]
        }
        mock_ct.get_trail.return_value = {"Trail": {"IsMultiRegionTrail": True}}
        mock_ct.get_trail_status.return_value = {"IsLogging": True}
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [
                {"IncludeManagementEvents": True, "ReadWriteType": "All"}
            ],
            "AdvancedEventSelectors": [],
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-06"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_reads_trails_from_all_pages(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_ct = MagicMock()
        mock_client.return_value = mock_ct
        mock_ct.list_trails.side_effect = [
            {"Trails": [], "NextToken": "trail-page-2"},
            {
                "Trails": [
                    {
                        "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main",
                        "Name": "main",
                    }
                ]
            },
        ]
        mock_ct.get_trail.return_value = {"Trail": {"IsMultiRegionTrail": True}}
        mock_ct.get_trail_status.return_value = {"IsLogging": True}
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [
                {"IncludeManagementEvents": True, "ReadWriteType": "All"}
            ],
            "AdvancedEventSelectors": [],
        }

        findings = extract_csv_data(check())

        assert findings[0]["Status"] == "Passed"
        assert mock_ct.list_trails.call_count == 2
        mock_ct.list_trails.assert_any_call(NextToken="trail-page-2")

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_no_trails_returns_failed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_ct = MagicMock()
        mock_client.return_value = mock_ct
        mock_ct.list_trails.return_value = {"Trails": []}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_trail_not_logging_returns_failed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_ct = MagicMock()
        mock_client.return_value = mock_ct
        mock_ct.list_trails.return_value = {
            "Trails": [{"TrailARN": "arn:trail", "Name": "trail1"}]
        }
        mock_ct.get_trail.return_value = {"Trail": {"IsMultiRegionTrail": True}}
        mock_ct.get_trail_status.return_value = {"IsLogging": False}
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [],
            "AdvancedEventSelectors": [],
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    def test_br06_no_regional_footprint_returns_na(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        result = check(region="eu-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == (
            "No regional Bedrock resources found to audit with Bedrock-specific CloudTrail coverage"
        )
        mock_client.assert_not_called()

    @patch("boto3.client")
    def test_br06_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_client.side_effect = Exception("CloudTrail error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_schema_valid(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_ct = MagicMock()
        mock_client.return_value = mock_ct
        mock_ct.list_trails.return_value = {"Trails": []}
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    # --- Data-event legs: AIR-BDR-KB-06 and AIR-BDR-MDL-07 -----------------
    KB_TYPE = "AWS::Bedrock::KnowledgeBase"
    MODEL_TYPE = "AWS::Bedrock::Model"

    @staticmethod
    def _data_event_selector(resource_types):
        return {
            "Name": "bedrock data events",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": list(resource_types)},
            ],
        }

    @staticmethod
    def _trail_client(trails, knowledge_bases=()):
        """trails: {name: {"logging": bool, "selectors": [...]}}."""

        def trail_name(arn):
            return arn.rsplit("/", 1)[-1]

        mock_ct = MagicMock()
        mock_ct.list_trails.return_value = {
            "Trails": [
                {
                    "TrailARN": f"arn:aws:cloudtrail:us-east-1:123:trail/{name}",
                    "Name": name,
                }
                for name in trails
            ]
        }
        mock_ct.get_trail.side_effect = lambda Name: {
            "Trail": {"IsMultiRegionTrail": True}
        }
        mock_ct.get_trail_status.side_effect = lambda Name: {
            "IsLogging": trails[trail_name(Name)]["logging"]
        }
        mock_ct.get_event_selectors.side_effect = lambda TrailName: {
            "EventSelectors": [],
            "AdvancedEventSelectors": trails[trail_name(TrailName)]["selectors"],
        }
        mock_ct.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": list(knowledge_bases)
        }
        return mock_ct

    @staticmethod
    def _by_finding_name(findings, name):
        matches = [f for f in findings if f["Finding"] == name]
        assert len(matches) == 1, f"{name}: {[f['Finding'] for f in findings]}"
        return matches[0]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_named_data_event_types_pass_per_resource_type(
        self, mock_footprint, mock_client
    ):
        mock_client.return_value = self._trail_client(
            {
                "kb-trail": {
                    "logging": True,
                    "selectors": [self._data_event_selector([self.KB_TYPE])],
                },
                "model-trail": {
                    "logging": True,
                    "selectors": [self._data_event_selector([self.MODEL_TYPE])],
                },
            },
            knowledge_bases=[{"knowledgeBaseId": "kb-1"}, {"knowledgeBaseId": "kb-2"}],
        )

        findings = extract_csv_data(bedrock_app.check_bedrock_cloudtrail_logging())

        kb = self._by_finding_name(
            findings, "Bedrock Knowledge Base Retrieval Data Event Logging"
        )
        assert kb["Status"] == "Passed"
        assert kb["Check_ID"] == "BR-06"
        assert "kb-trail" in kb["Finding_Details"]
        assert "model-trail" not in kb["Finding_Details"]
        assert "2 knowledge base(s)" in kb["Finding_Details"]

        model = self._by_finding_name(
            findings, "Bedrock Model Invocation Data Event Logging"
        )
        assert model["Status"] == "Passed"
        assert "model-trail" in model["Finding_Details"]
        assert "kb-trail" not in model["Finding_Details"]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_knowledge_base_selector_does_not_cover_model_invocation(
        self, mock_footprint, mock_client
    ):
        mock_client.return_value = self._trail_client(
            {
                "kb-only": {
                    "logging": True,
                    "selectors": [self._data_event_selector([self.KB_TYPE])],
                }
            },
            knowledge_bases=[{"knowledgeBaseId": "kb-1"}],
        )

        findings = extract_csv_data(bedrock_app.check_bedrock_cloudtrail_logging())

        assert (
            self._by_finding_name(
                findings, "Bedrock Knowledge Base Retrieval Data Event Logging"
            )["Status"]
            == "Passed"
        )
        model = self._by_finding_name(
            findings, "Bedrock Model Invocation Data Event Logging"
        )
        assert model["Status"] == "Failed"
        assert self.MODEL_TYPE in model["Finding_Details"]
        assert (
            f"observed data-event resource types: {self.KB_TYPE}"
            in (model["Finding_Details"])
        )
        assert self.MODEL_TYPE in model["Resolution"]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_no_knowledge_base_makes_the_retrieval_leg_not_applicable(
        self, mock_footprint, mock_client
    ):
        mock_client.return_value = self._trail_client(
            {
                "management-only": {
                    "logging": True,
                    "selectors": [
                        {
                            "Name": "management",
                            "FieldSelectors": [
                                {"Field": "eventCategory", "Equals": ["Management"]}
                            ],
                        }
                    ],
                }
            },
            knowledge_bases=[],
        )

        findings = extract_csv_data(bedrock_app.check_bedrock_cloudtrail_logging())

        kb = self._by_finding_name(
            findings, "Bedrock Knowledge Base Retrieval Data Event Logging"
        )
        assert kb["Status"] == "N/A"
        assert kb["Severity"] == "Informational"
        assert "No knowledge base exists in this region" in kb["Finding_Details"]

        model = self._by_finding_name(
            findings, "Bedrock Model Invocation Data Event Logging"
        )
        assert model["Status"] == "Failed"
        assert "observed data-event resource types: none" in model["Finding_Details"]

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_stopped_trail_data_events_are_not_coverage(
        self, mock_footprint, mock_client
    ):
        mock_client.return_value = self._trail_client(
            {
                "stopped-trail": {
                    "logging": False,
                    "selectors": [
                        self._data_event_selector([self.KB_TYPE, self.MODEL_TYPE])
                    ],
                }
            },
            knowledge_bases=[{"knowledgeBaseId": "kb-1"}],
        )

        findings = extract_csv_data(bedrock_app.check_bedrock_cloudtrail_logging())

        for name in (
            "Bedrock Knowledge Base Retrieval Data Event Logging",
            "Bedrock Model Invocation Data Event Logging",
        ):
            finding = self._by_finding_name(findings, name)
            assert finding["Status"] == "Failed"
            assert (
                "observed data-event resource types: none"
                in (finding["Finding_Details"])
            )
        for finding in findings:
            assert_finding_schema(finding)


# ===================================================================
# BR-07: check_bedrock_prompt_management
# ===================================================================
class TestBR07PromptManagement:
    """BR-07: Check Bedrock Prompt Management usage."""

    @patch("boto3.client")
    def test_br07_prompts_exist_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"promptSummaries": [{"name": "prompt1", "id": "p1"}]}
        ]
        mock_agent.get_prompt.return_value = {"variants": ["v1", "v2"]}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-07"
        mock_agent.get_prompt.assert_called_once_with(promptIdentifier="p1")

    @patch("boto3.client")
    def test_br07_legacy_prompt_id_fallback_still_supported(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"promptSummaries": [{"name": "prompt1", "promptId": "p1"}]}
        ]
        mock_agent.get_prompt.return_value = {"variants": ["v1", "v2"]}

        result = check()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_agent.get_prompt.assert_called_once_with(promptIdentifier="p1")

    @patch("boto3.client")
    def test_br07_no_prompts_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"promptSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"

    @patch("boto3.client")
    def test_br07_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_client.side_effect = Exception("Agent error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    def test_br07_list_prompts_api_error_returns_na(self, mock_client):
        # An API error (e.g. InternalServerErrorException after retries) is not a
        # security failure; it should surface as N/A, not Failed (matches BR-11).
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.list_prompts.side_effect = Exception("InternalServerErrorException")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-07"

    @patch("boto3.client")
    def test_br07_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"promptSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-08: check_bedrock_agent_roles
# ===================================================================
class TestBR08AgentRoles:
    """BR-08: Check Bedrock agent IAM roles."""

    @patch("boto3.client")
    def test_br08_no_agents_returns_na(self, mock_client, empty_permission_cache):
        check = bedrock_app.check_bedrock_agent_roles
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"agentSummaries": []}]
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-08"

    @patch("boto3.client")
    def test_br08_agent_with_compliant_role_returns_passed(
        self, mock_client, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_agent_roles
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"agentSummaries": [{"agentId": "a1", "agentName": "TestAgent"}]}
        ]
        mock_agent.get_agent.return_value = {
            "agent": {
                "agentResourceRoleArn": "arn:aws:iam::123456789012:role/LeastPrivilegeRole"
            }
        }
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        mock_agent.get_agent.assert_called_once_with(agentId="a1")

    @patch("boto3.client")
    def test_br08_legacy_role_arn_shape_still_supported(
        self, mock_client, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_agent_roles
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"agentSummaries": [{"agentId": "a1", "agentName": "TestAgent"}]}
        ]
        mock_agent.get_agent.return_value = {
            "agentResourceRoleArn": "arn:aws:iam::123456789012:role/LeastPrivilegeRole"
        }

        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        mock_agent.get_agent.assert_called_once_with(agentId="a1")

    @patch("boto3.client")
    def test_br08_exception_returns_error_finding(
        self, mock_client, empty_permission_cache
    ):
        check = bedrock_app.check_bedrock_agent_roles
        mock_client.side_effect = Exception("Agent service error")
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    def test_br08_schema_valid(self, mock_client, empty_permission_cache):
        check = bedrock_app.check_bedrock_agent_roles
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"agentSummaries": []}]
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-09: check_bedrock_knowledge_base_encryption
# ===================================================================
class TestBR09KBEncryption:
    """BR-09: Check Knowledge Base encryption."""

    @patch("boto3.client")
    def test_br09_no_kbs_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"knowledgeBaseSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-09"

    @patch("boto3.client")
    def test_br09_kb_exists_returns_findings(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "TestKB"}]}
        ]
        mock_agent.get_knowledge_base.return_value = {
            "knowledgeBase": {"storageConfiguration": {"type": "OPENSEARCH_SERVERLESS"}}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "BR-09"

    @patch("boto3.client")
    def test_br09_access_denied_in_region_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "missing permission",
                }
            },
            "ListKnowledgeBases",
        )
        result = check(region="eu-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert (
            "access to Knowledge Base metadata was denied"
            in findings[0]["Finding_Details"]
        )
        assert findings[0]["Region"] == "eu-west-1"

    @patch("boto3.client")
    def test_br09_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_client.side_effect = Exception("KB error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    def test_br09_access_denied_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListKnowledgeBases",
        )
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("boto3.client")
    def test_br09_region_unsupported_returns_na(self, mock_client):
        # Knowledge Bases API absent in the region -> N/A, not ERROR/Failed.
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.side_effect = ClientError(
            {
                "Error": {
                    "Code": "UnknownOperationException",
                    "Message": "Unknown operation ListKnowledgeBases",
                }
            },
            "ListKnowledgeBases",
        )
        result = check(region="ap-southeast-3")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-09"
        assert "not available" in findings[0]["Finding_Details"]

    @patch("boto3.client")
    def test_br09_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"knowledgeBaseSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-10: check_bedrock_guardrail_iam_enforcement
# ===================================================================
class TestBR10GuardrailIAMEnforcement:
    """BR-10: Check guardrail IAM condition enforcement."""

    @patch("boto3.client")
    def test_br10_no_guardrails_returns_na(
        self, mock_client, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_guardrail_iam_enforcement
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "BR-10"

    @patch("boto3.client")
    def test_br10_guardrails_with_enforcement_returns_passed(
        self, mock_client, permission_cache_with_guardrail_condition
    ):
        check = bedrock_app.check_bedrock_guardrail_iam_enforcement
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {
            "guardrails": [{"guardrailId": "gr1", "name": "test-guardrail"}]
        }
        result = check(permission_cache_with_guardrail_condition)
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("boto3.client")
    def test_br10_exception_returns_error_finding(
        self, mock_client, empty_permission_cache
    ):
        check = bedrock_app.check_bedrock_guardrail_iam_enforcement
        mock_client.side_effect = Exception("IAM error")
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    def test_br10_schema_valid(self, mock_client, empty_permission_cache):
        check = bedrock_app.check_bedrock_guardrail_iam_enforcement
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-11: check_bedrock_custom_model_encryption
# ===================================================================
class TestBR11CustomModelEncryption:
    """BR-11: Check custom model CMK encryption."""

    @patch("boto3.client")
    def test_br11_no_custom_models_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        paginator = MagicMock()
        mock_bedrock.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"modelSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-11"

    @patch("boto3.client")
    def test_br11_model_without_cmk_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        paginator = MagicMock()
        mock_bedrock.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"modelSummaries": [{"modelArn": "arn:model:1", "modelName": "my-model"}]}
        ]
        mock_bedrock.get_custom_model.return_value = {
            "jobArn": "arn:job:1",
            "baseModelArn": "arn:base:1",
        }
        mock_bedrock.get_model_customization_job.return_value = {"outputDataConfig": {}}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("boto3.client")
    def test_br11_model_with_cmk_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        paginator = MagicMock()
        mock_bedrock.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"modelSummaries": [{"modelArn": "arn:model:1", "modelName": "my-model"}]}
        ]
        mock_bedrock.get_custom_model.return_value = {
            "jobArn": "arn:job:1",
            "baseModelArn": "arn:base:1",
        }
        mock_bedrock.get_model_customization_job.return_value = {
            "outputDataConfig": {"kmsKeyId": "arn:aws:kms:us-east-1:123:key/abc"}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("boto3.client")
    def test_br11_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_client.side_effect = Exception("Model error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    def test_br11_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        paginator = MagicMock()
        mock_bedrock.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"modelSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("boto3.client")
    def test_br11_unknown_operation_returns_clean_message(self, mock_client):
        # Regions without the custom model API surface "Unknown operation
        # ListCustomModels" / UnknownOperationException; report a clean message
        # instead of leaking the raw boto3 exception text.
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_paginator.side_effect = Exception(
            "ValidationException: Unknown operation ListCustomModels"
        )
        result = check(region="us-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "Custom model API not available in us-west-1"
        )

    @patch("boto3.client")
    def test_br11_other_list_error_preserves_raw_message(self, mock_client):
        # Genuine errors (e.g. permissions) keep the raw text so they stay
        # diagnosable.
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_paginator.side_effect = Exception("AccessDeniedException")
        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert "AccessDeniedException" in findings[0]["Finding_Details"]


# ===================================================================
# BR-12: check_bedrock_invocation_log_encryption
# ===================================================================
class TestBR12InvocationLogEncryption:
    """BR-12: Check invocation log bucket encryption."""

    @patch("boto3.client")
    def test_br12_no_s3_logging_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_s3 = MagicMock()

        def client_factory(service, **kwargs):
            if service == "bedrock":
                return mock_bedrock
            return mock_s3

        mock_client.side_effect = client_factory
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {}}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-12"

    @patch("boto3.client")
    def test_br12_bucket_with_cmk_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_s3 = MagicMock()

        def client_factory(service, **kwargs):
            if service == "bedrock":
                return mock_bedrock
            return mock_s3

        mock_client.side_effect = client_factory
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {"bucketName": "log-bucket"}}
        }
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "arn:aws:kms:us-east-1:123:key/custom-key",
                        }
                    }
                ]
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("boto3.client")
    def test_br12_bucket_without_cmk_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_s3 = MagicMock()

        def client_factory(service, **kwargs):
            if service == "bedrock":
                return mock_bedrock
            return mock_s3

        mock_client.side_effect = client_factory
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {"bucketName": "log-bucket"}}
        }
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("boto3.client")
    def test_br12_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_client.side_effect = Exception("S3 error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    def test_br12_access_denied_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_s3 = MagicMock()

        def client_factory(service, **kwargs):
            if service == "bedrock":
                return mock_bedrock
            return mock_s3

        mock_client.side_effect = client_factory
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {"bucketName": "log-bucket"}}
        }
        mock_s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetBucketEncryption",
        )
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("boto3.client")
    def test_br12_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {}}
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-13: check_bedrock_flows_guardrails
# ===================================================================
class TestBR13FlowsGuardrails:
    """BR-13: Check Bedrock Flows have guardrails."""

    @patch("boto3.client")
    def test_br13_no_flows_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"flowSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-13"

    @patch("boto3.client")
    def test_br13_flow_with_guardrails_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"flowSummaries": [{"id": "f1", "name": "TestFlow"}]}
        ]
        mock_agent.get_flow.return_value = {
            "definition": {
                "nodes": [
                    {
                        "name": "PromptNode",
                        "type": "Prompt",
                        "configuration": {
                            "prompt": {
                                "guardrailConfiguration": {
                                    "guardrailIdentifier": "gr-123"
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("boto3.client")
    def test_br13_flow_without_guardrails_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"flowSummaries": [{"id": "f1", "name": "TestFlow"}]}
        ]
        mock_agent.get_flow.return_value = {
            "definition": {
                "nodes": [
                    {
                        "name": "PromptNode",
                        "type": "Prompt",
                        "configuration": {"prompt": {}},
                    }
                ]
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("boto3.client")
    def test_br13_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_client.side_effect = Exception("Flow error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("boto3.client")
    def test_br13_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"flowSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("boto3.client")
    def test_br13_unknown_operation_returns_clean_message(self, mock_client):
        # Regions without the Flows API surface an "Unknown operation" error;
        # report a clean message instead of leaking the raw boto3 text.
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.side_effect = Exception("UnknownOperationException")
        result = check(region="us-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "Bedrock Flows API not available in us-west-1"
        )


# ===================================================================
# describe_api_error helper
# ===================================================================
class TestDescribeApiError:
    """Shared helper that maps region-unavailability errors to clean text."""

    def test_unknown_operation_phrase_returns_clean_message(self):
        msg = bedrock_app.describe_api_error(
            Exception("ValidationException: Unknown operation ListPrompts"),
            "Bedrock Prompt Management API",
            "us-east-2",
        )
        assert msg == "Bedrock Prompt Management API not available in us-east-2"

    def test_unknown_operation_exception_returns_clean_message(self):
        msg = bedrock_app.describe_api_error(
            Exception("UnknownOperationException"), "Custom model API", "us-west-1"
        )
        assert msg == "Custom model API not available in us-west-1"

    def test_missing_region_falls_back_to_generic_location(self):
        msg = bedrock_app.describe_api_error(
            Exception("Unknown operation Foo"), "Custom model API"
        )
        assert msg == "Custom model API not available in this region"

    def test_other_error_preserves_raw_text(self):
        msg = bedrock_app.describe_api_error(
            Exception("AccessDeniedException"), "Custom model API", "us-east-1"
        )
        assert msg == "Unable to check Custom model API: AccessDeniedException"


# ===================================================================
# lambda_handler: multi-region gating and availability probe
# ===================================================================
def _make_client_error(code, message="error"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "operation")


def _bedrock_event(region="us-east-1", region_index=0):
    return {
        "Region": region,
        "RegionIndex": region_index,
        "Execution": {"Name": "test-execution-1"},
        "StateMachine": {"Name": "test-sm"},
    }


class TestBedrockHandlerMultiRegion:
    """lambda_handler primary-region gating + availability probe (BR-00/BR-01/BR-03)."""

    def _run_handler_unavailable(self, mock_client, event, cache_missing=False):
        """Drive the handler down the 'Bedrock unavailable' early-return path and
        return the findings captured via generate_csv_report. The availability
        probe raises EndpointConnectionError so no regional checks run."""
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.get_model_invocation_logging_configuration.side_effect = (
            EndpointConnectionError(endpoint_url="https://bedrock.invalid")
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                bedrock_app,
                "get_permissions_cache",
                return_value=(
                    None
                    if cache_missing
                    else {"role_permissions": {}, "user_permissions": {}}
                ),
            ),
            patch.object(bedrock_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(
                bedrock_app, "write_to_s3", return_value="s3://bucket/report.csv"
            ),
        ):
            resp = bedrock_app.lambda_handler(event, None)

        return resp, captured.get("findings", [])

    @patch("bedrock_app.boto3.client")
    def test_primary_region_emits_global_iam_checks_tagged_global(self, mock_client):
        # On the primary region, BR-01 and BR-03 (IAM-global) must be emitted and
        # tagged "Global", even when Bedrock itself is unavailable in the region.
        resp, findings = self._run_handler_unavailable(
            mock_client, _bedrock_event(region="ap-south-2", region_index=0)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        assert "BR-01" in check_ids
        assert "BR-03" in check_ids
        # Every global IAM finding is tagged Global, not the scanned region.
        for r in rows:
            if r["Check_ID"] in ("BR-01", "BR-03"):
                assert r["Region"] == "Global"
        # The availability finding itself is tagged with the scanned region.
        br00 = [r for r in rows if r["Check_ID"] == "BR-00"]
        assert br00 and br00[0]["Region"] == "ap-south-2"

    @patch("bedrock_app.boto3.client")
    def test_missing_cache_emits_incomplete_global_rows_not_passes(self, mock_client):
        resp, findings = self._run_handler_unavailable(
            mock_client,
            _bedrock_event(region="ap-south-2", region_index=0),
            cache_missing=True,
        )
        assert resp["statusCode"] == 200

        rows = [row for finding in findings for row in finding.get("csv_data", [])]
        cache_rows = [row for row in rows if row["Check_ID"] in {"BR-01", "BR-03"}]
        assert {row["Check_ID"] for row in cache_rows} == {"BR-01", "BR-03"}
        assert all(row["Status"] == "N/A" for row in cache_rows)
        assert all(row["Severity"] == "Informational" for row in cache_rows)
        assert all("permissions cache" in row["Finding_Details"] for row in cache_rows)

    @patch("bedrock_app.boto3.client")
    def test_non_primary_region_skips_global_iam_checks(self, mock_client):
        # On a non-primary region (index > 0), the IAM-global checks must NOT run,
        # so they are not duplicated once per scanned region.
        resp, findings = self._run_handler_unavailable(
            mock_client, _bedrock_event(region="eu-west-1", region_index=1)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        assert "BR-01" not in check_ids
        assert "BR-03" not in check_ids
        # Only the BR-00 availability finding should be present.
        assert check_ids == {"BR-00"}

    @patch("bedrock_app.boto3.client")
    def test_optin_region_error_treated_as_unavailable(self, mock_client):
        # A region-not-enabled error code (e.g. UnrecognizedClientException) is
        # treated like an endpoint failure: emit a single BR-00 N/A finding.
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.get_model_invocation_logging_configuration.side_effect = (
            _make_client_error("UnrecognizedClientException")
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                bedrock_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(bedrock_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(bedrock_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = bedrock_app.lambda_handler(
                _bedrock_event(region="me-south-1", region_index=1), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        br00 = [r for r in rows if r["Check_ID"] == "BR-00"]
        assert br00 and br00[0]["Status"] == "N/A"
        assert "me-south-1" in br00[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_validation_exception_proceeds_with_checks(self, mock_client):
        # A ValidationException from the probe means logging simply isn't
        # configured — the service IS reachable, so the handler must NOT short
        # circuit; it should run the regional checks (no BR-00 finding emitted).
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.get_model_invocation_logging_configuration.side_effect = (
            _make_client_error("ValidationException")
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                bedrock_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(bedrock_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(bedrock_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = bedrock_app.lambda_handler(
                _bedrock_event(region="us-east-1", region_index=0), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        # Service reachable => no availability (BR-00) finding, and regional
        # checks ran (e.g. BR-04 logging, BR-05 guardrails are present).
        assert "BR-00" not in check_ids
        assert len(check_ids) > 3

    # Regional checks BR-26..33 (function name -> check id) that the handler must
    # invoke once per scanned region, passing region=region.
    NEW_REGIONAL_CHECKS = {
        "check_bedrock_guardrail_pii_filters": "BR-26",
        "check_bedrock_guardrail_contextual_grounding": "BR-27",
        "check_bedrock_agent_guardrail_association": "BR-28",
        "check_bedrock_agent_idle_session_ttl": "BR-29",
        "check_bedrock_imported_model_kms_encryption": "BR-30",
        "check_bedrock_batch_inference_output_encryption": "BR-31",
        "check_bedrock_cloudwatch_alarms": "BR-32",
        "check_inspector_lambda_code_scanning": "BR-33",
    }

    # Checks that read a global surface (the IAM permissions cache or the
    # organization's policy documents) and so run once, tagged Global.
    GLOBAL_CHECKS = (
        "check_bedrock_central_guardrail_enforcement",  # BR-41
        "check_bedrock_model_allow_list",  # BR-42
        "check_bedrock_region_invocation_control",  # BR-43
        "check_bedrock_marketplace_model_control",  # BR-44
        "check_bedrock_api_key_governance",  # BR-45
    )

    def _run_handler_with_check_spies(self, event):
        """Drive the handler down the full regional path with every check function
        replaced by a spy that records the region it was called with. The probe
        raises ValidationException (service reachable) so all regional checks run.
        Returns {check_function_name: region_passed} plus whether BR-15 ran."""
        recorded = {}

        def make_spy(name):
            def spy(*args, region="", **kwargs):
                recorded[name] = region
                return {
                    "check_name": name,
                    "status": "PASS",
                    "details": "",
                    "csv_data": [],
                }

            return spy

        test_client = MagicMock()
        test_client.get_model_invocation_logging_configuration.side_effect = (
            _make_client_error("ValidationException")
        )

        # Spy on every check the handler calls so it runs cleanly end-to-end.
        spied = [
            "check_bedrock_full_access_roles",
            "check_marketplace_subscription_access",
            "check_bedrock_access_and_vpc_endpoints",
            "check_bedrock_logging_configuration",
            "check_bedrock_guardrails",
            "check_bedrock_cloudtrail_logging",
            "check_bedrock_prompt_management",
            "check_bedrock_agent_roles",
            "check_bedrock_knowledge_base_encryption",
            "check_bedrock_guardrail_iam_enforcement",
            "check_bedrock_custom_model_encryption",
            "check_bedrock_invocation_log_encryption",
            "check_bedrock_flows_guardrails",
            "check_bedrock_cross_account_guardrails",  # BR-15 (global)
            "check_bedrock_central_guardrail_enforcement",  # BR-41 (global)
            "check_bedrock_model_allow_list",  # BR-42 (global)
            "check_bedrock_region_invocation_control",  # BR-43 (global)
            "check_bedrock_marketplace_model_control",  # BR-44 (global)
            "check_bedrock_api_key_governance",  # BR-45 (global)
            "check_bedrock_knowledge_base_source_classification",  # BR-46
            "check_bedrock_guardrail_tier",
            "check_bedrock_custom_model_kms_encryption",
            "check_bedrock_model_evaluations",
            "check_bedrock_prompt_flow_validation",
            "check_bedrock_knowledge_base_kms_encryption",
            "check_bedrock_agent_action_group_iam",
            "check_bedrock_service_quotas_throttling",
            "check_bedrock_guardrail_content_filters",
            "check_bedrock_automated_reasoning_policy",
            "check_bedrock_rag_evaluation_jobs",
            *self.NEW_REGIONAL_CHECKS.keys(),
        ]

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(bedrock_app.boto3, "client", return_value=test_client)
            )
            stack.enter_context(
                patch.object(
                    bedrock_app,
                    "get_permissions_cache",
                    return_value={"role_permissions": {}, "user_permissions": {}},
                )
            )
            stack.enter_context(
                patch.object(bedrock_app, "generate_csv_report", return_value="csv")
            )
            stack.enter_context(
                patch.object(bedrock_app, "write_to_s3", return_value="s3://b/r.csv")
            )
            for name in spied:
                stack.enter_context(
                    patch.object(bedrock_app, name, side_effect=make_spy(name))
                )
            resp = bedrock_app.lambda_handler(event, None)

        return resp, recorded

    def test_new_regional_checks_run_per_region_non_primary(self):
        # On a non-primary region, BR-26..32 must each run with region=<scanned>,
        # and the global BR-15 check must NOT run.
        resp, recorded = self._run_handler_with_check_spies(
            _bedrock_event(region="eu-west-3", region_index=2)
        )
        assert resp["statusCode"] == 200
        for fn_name in self.NEW_REGIONAL_CHECKS:
            assert recorded.get(fn_name) == "eu-west-3", (
                f"{fn_name} not run with scanned region: {recorded.get(fn_name)}"
            )
        # BR-15 (cross-account guardrails) is global -> skipped on non-primary.
        assert "check_bedrock_cross_account_guardrails" not in recorded
        # BR-41, BR-43 and BR-45 read organization policy documents and BR-42 and
        # BR-44 read the IAM permissions cache, so all five are global.
        for fn_name in self.GLOBAL_CHECKS:
            assert fn_name not in recorded
        # BR-46 is regional: it reads the knowledge bases in the scanned region.
        assert (
            recorded.get("check_bedrock_knowledge_base_source_classification")
            == "eu-west-3"
        )

    def test_new_regional_checks_run_per_region_primary(self):
        # On the primary region, BR-26..32 run with region=<scanned> and the
        # global BR-15 check runs tagged Global.
        resp, recorded = self._run_handler_with_check_spies(
            _bedrock_event(region="us-east-1", region_index=0)
        )
        assert resp["statusCode"] == 200
        for fn_name in self.NEW_REGIONAL_CHECKS:
            assert recorded.get(fn_name) == "us-east-1", (
                f"{fn_name} not run with scanned region: {recorded.get(fn_name)}"
            )
        # Global check runs once, tagged Global.
        assert recorded.get("check_bedrock_cross_account_guardrails") == "Global"
        for fn_name in self.GLOBAL_CHECKS:
            assert recorded.get(fn_name) == "Global", (
                f"{fn_name} not run as a global check: {recorded.get(fn_name)}"
            )
        assert (
            recorded.get("check_bedrock_knowledge_base_source_classification")
            == "us-east-1"
        )


# ===================================================================
# BR-15: check_bedrock_cross_account_guardrails
# ===================================================================
class TestBR15CrossAccountGuardrails:
    """BR-15: Check AWS Organizations Bedrock Guardrails policies."""

    @patch("bedrock_app.boto3.client")
    def test_br15_organizations_not_enabled_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_cross_account_guardrails

        org_client = MagicMock()
        org_client.describe_organization.side_effect = ClientError(
            {"Error": {"Code": "AWSOrganizationsNotInUseException"}},
            "DescribeOrganization",
        )
        mock_client.return_value = org_client

        result = check(region="Global")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-15"
        assert "not in use" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br15_member_account_with_local_enforcement_returns_na(self, mock_client):
        bedrock_client = MagicMock()
        bedrock_client.list_enforced_guardrails_configuration.return_value = {
            "guardrailsConfig": [{"guardrailIdentifier": "guardrail-1"}]
        }
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "111111111111"}
        }
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "222222222222"}

        def client_factory(service, **kwargs):
            return {
                "bedrock": bedrock_client,
                "organizations": org_client,
                "sts": sts_client,
            }[service]

        mock_client.side_effect = client_factory

        finding = extract_csv_data(
            bedrock_app.check_bedrock_cross_account_guardrails(region="Global")
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "Found 1 account-level" in finding["Finding_Details"]
        assert "cannot be fully established" in finding["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br15_member_account_does_not_claim_absence_after_probe_error(
        self, mock_client
    ):
        bedrock_client = MagicMock()
        bedrock_client.list_enforced_guardrails_configuration.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}},
            "ListEnforcedGuardrailsConfiguration",
        )
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "111111111111"}
        }
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "222222222222"}

        def client_factory(service, **kwargs):
            return {
                "bedrock": bedrock_client,
                "organizations": org_client,
                "sts": sts_client,
            }[service]

        mock_client.side_effect = client_factory

        finding = extract_csv_data(
            bedrock_app.check_bedrock_cross_account_guardrails(region="Global")
        )[0]

        assert finding["Status"] == "N/A"
        assert "could not be assessed" in finding["Finding_Details"]
        assert "No account-level" not in finding["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br15_organizations_not_in_use_does_not_claim_absence_after_probe_error(
        self, mock_client
    ):
        bedrock_client = MagicMock()
        bedrock_client.list_enforced_guardrails_configuration.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}},
            "ListEnforcedGuardrailsConfiguration",
        )
        org_client = MagicMock()
        org_client.describe_organization.side_effect = ClientError(
            {"Error": {"Code": "AWSOrganizationsNotInUseException"}},
            "DescribeOrganization",
        )

        def client_factory(service, **kwargs):
            return bedrock_client if service == "bedrock" else org_client

        mock_client.side_effect = client_factory

        finding = extract_csv_data(
            bedrock_app.check_bedrock_cross_account_guardrails(region="Global")
        )[0]

        assert finding["Status"] == "N/A"
        assert "could not be assessed" in finding["Finding_Details"]
        assert "no account-level" not in finding["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br15_policy_type_not_enabled_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_cross_account_guardrails

        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        org_client.list_roots.return_value = {
            "Roots": [
                {
                    "Id": "r-abc123",
                    "Arn": "arn:aws:organizations::123456789012:root/o-xyz/r-abc123",
                }
            ]
        }
        # No policies returned = policy type not enabled
        org_client.list_policies.return_value = {"Policies": []}

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

        def client_factory(service, **kwargs):
            if service == "organizations":
                return org_client
            return sts_client

        mock_client.side_effect = client_factory

        result = check(region="Global")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-15"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br15_policies_configured_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_cross_account_guardrails

        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        org_client.list_roots.return_value = {
            "Roots": [
                {
                    "Id": "r-abc123",
                    "Arn": "arn:aws:organizations::123456789012:root/o-xyz/r-abc123",
                    "PolicyTypes": [{"Type": "BEDROCK_POLICY", "Status": "ENABLED"}],
                }
            ]
        }
        org_client.list_policies.return_value = {
            "Policies": [{"Id": "p-123", "Name": "BedrockGuardrailPolicy"}]
        }
        org_client.list_targets_for_policy.return_value = {
            "Targets": [{"TargetId": "r-abc123", "Type": "ROOT"}]
        }

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

        def client_factory(service, **kwargs):
            if service == "organizations":
                return org_client
            return sts_client

        mock_client.side_effect = client_factory

        result = check(region="Global")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        passed_findings = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed_findings) >= 1
        assert passed_findings[0]["Check_ID"] == "BR-15"

    @patch("bedrock_app.boto3.client")
    def test_br15_reads_organization_roots_from_all_pages(self, mock_client):
        check = bedrock_app.check_bedrock_cross_account_guardrails

        bedrock_client = MagicMock()
        bedrock_client.list_enforced_guardrails_configuration.return_value = {
            "guardrailsConfig": []
        }
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        org_client.list_roots.side_effect = [
            {
                "Roots": [{"Id": "r-first", "PolicyTypes": []}],
                "NextToken": "root-page-2",
            },
            {
                "Roots": [
                    {
                        "Id": "r-second",
                        "PolicyTypes": [
                            {"Type": "BEDROCK_POLICY", "Status": "ENABLED"}
                        ],
                    }
                ]
            },
        ]
        org_client.list_policies.return_value = {
            "Policies": [{"Id": "p-123", "Name": "BedrockGuardrailPolicy"}]
        }
        org_client.list_targets_for_policy.return_value = {
            "Targets": [{"TargetId": "r-second", "Type": "ROOT"}]
        }
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_client.side_effect = lambda service, **kwargs: {
            "bedrock": bedrock_client,
            "organizations": org_client,
            "sts": sts_client,
        }[service]

        findings = extract_csv_data(check(region="Global"))

        assert any(finding["Status"] == "Passed" for finding in findings)
        assert org_client.list_roots.call_count == 2
        org_client.list_roots.assert_any_call(MaxResults=20, NextToken="root-page-2")

    @patch("bedrock_app.boto3.client")
    def test_br15_access_denied_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_cross_account_guardrails

        org_client = MagicMock()
        org_client.describe_organization.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "DescribeOrganization"
        )
        mock_client.return_value = org_client

        result = check(region="Global")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Access-denied paths resolve to N/A (CLAUDE.md status semantics),
        # not Failed — a permission gap is not a security misconfiguration.
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-15"
        for action in (
            "organizations:DescribeOrganization",
            "organizations:ListRoots",
            "organizations:ListPolicies",
            "organizations:ListTargetsForPolicy",
        ):
            assert action in findings[0]["Resolution"]

    def test_br15_schema_valid(self):
        check = bedrock_app.check_bedrock_cross_account_guardrails
        with patch("bedrock_app.boto3.client") as mock_client:
            org_client = MagicMock()
            org_client.describe_organization.side_effect = ClientError(
                {"Error": {"Code": "AWSOrganizationsNotInUseException"}},
                "DescribeOrganization",
            )
            mock_client.return_value = org_client
            result = check(region="Global")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-41: check_bedrock_central_guardrail_enforcement
# ===================================================================
class TestBR41CentralGuardrailEnforcement:
    """BR-41: Read the enforced guardrail version out of the policy document."""

    GUARDRAIL_ARN = "arn:aws:bedrock:us-east-1:123456789012:guardrail/abcd1234efgh"
    OTHER_GUARDRAIL_ARN = (
        "arn:aws:bedrock:us-east-1:123456789012:guardrail/zzzz9999yyyy"
    )

    @staticmethod
    def _bedrock_policy_document(guardrail_arn, guardrail_version):
        return {
            "bedrock": {
                "guardrails_configuration": {
                    "@@assign": {
                        "guardrail_identifier": guardrail_arn,
                        "guardrail_version": guardrail_version,
                    }
                }
            }
        }

    @staticmethod
    def _deny_without_guardrail(operator, condition_value):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireApprovedGuardrail",
                    "Effect": "Deny",
                    "Action": [
                        "bedrock:InvokeModel",
                        "bedrock:InvokeModelWithResponseStream",
                    ],
                    "Resource": "*",
                    "Condition": {
                        operator: {"bedrock:GuardrailIdentifier": condition_value}
                    },
                }
            ],
        }

    # A configuration whose includedModels names ALL, with no exclusion and both
    # content modes COMPREHENSIVE, is the only account-level shape that covers
    # every invocation.
    @staticmethod
    def _account_config(
        config_id,
        included=("ALL",),
        excluded=(),
        system="COMPREHENSIVE",
        messages="COMPREHENSIVE",
        version="3",
        guardrail_arn=None,
        omit_model_enforcement=False,
    ):
        config = {
            "configId": config_id,
            "guardrailArn": guardrail_arn
            or TestBR41CentralGuardrailEnforcement.GUARDRAIL_ARN,
            "guardrailVersion": version,
            "owner": "ACCOUNT",
            "selectiveContentGuarding": {"system": system, "messages": messages},
        }
        if not omit_model_enforcement:
            config["modelEnforcement"] = {
                "includedModels": list(included),
                "excludedModels": list(excluded),
            }
        return config

    def _client_factory(
        self,
        bedrock_policies,
        scps,
        targets,
        contents,
        account,
        account_configs,
        account_pages,
        account_error,
    ):
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }

        def list_policies(**kwargs):
            if kwargs.get("Filter") == "BEDROCK_POLICY":
                return {"Policies": list(bedrock_policies)}
            return {"Policies": list(scps)}

        org_client.list_policies.side_effect = list_policies
        org_client.list_targets_for_policy.side_effect = lambda **kwargs: {
            "Targets": targets.get(kwargs["PolicyId"], [])
        }
        org_client.describe_policy.side_effect = lambda **kwargs: {
            "Policy": {"Content": json.dumps(contents.get(kwargs["PolicyId"], {}))}
        }

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": account}

        bedrock_client = MagicMock()
        if account_error is not None:
            bedrock_client.get_paginator.side_effect = account_error
        else:
            bedrock_client.get_paginator.return_value.paginate.return_value = (
                account_pages
                if account_pages is not None
                else [{"guardrailsConfig": list(account_configs)}]
            )

        return (
            org_client,
            bedrock_client,
            lambda service, **kwargs: {
                "organizations": org_client,
                "sts": sts_client,
                "bedrock": bedrock_client,
            }[service],
        )

    def _run_clients(
        self,
        bedrock_policies=(),
        scps=(),
        targets=None,
        contents=None,
        account="123456789012",
        account_configs=(),
        account_pages=None,
        account_error=None,
    ):
        org_client, bedrock_client, factory = self._client_factory(
            bedrock_policies,
            scps,
            targets or {},
            contents or {},
            account,
            account_configs,
            account_pages,
            account_error,
        )
        with patch("bedrock_app.boto3.client", side_effect=factory):
            result = bedrock_app.check_bedrock_central_guardrail_enforcement(
                region="Global", api_region="us-east-1"
            )
        return org_client, bedrock_client, extract_csv_data(result)

    def _run(self, **kwargs):
        org_client, _, findings = self._run_clients(**kwargs)
        return org_client, findings

    def test_br41_draft_version_fails_while_published_version_passes(self):
        org_client, findings = self._run(
            bedrock_policies=[
                {"Id": "p-published", "Name": "PublishedGuardrail"},
                {"Id": "p-draft", "Name": "DraftGuardrail"},
            ],
            targets={
                "p-published": [{"TargetId": "r-abc123", "Type": "ROOT"}],
                "p-draft": [{"TargetId": "ou-1234", "Type": "ORGANIZATIONAL_UNIT"}],
            },
            contents={
                "p-published": self._bedrock_policy_document(self.GUARDRAIL_ARN, "3"),
                "p-draft": self._bedrock_policy_document(
                    self.OTHER_GUARDRAIL_ARN, "DRAFT"
                ),
            },
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]

        assert len(failed) == 1
        assert failed[0]["Check_ID"] == "BR-41"
        assert "DraftGuardrail" in failed[0]["Finding_Details"]
        assert "p-draft" in failed[0]["Finding_Details"]
        assert "DRAFT guardrail version" in failed[0]["Finding_Details"]
        assert self.OTHER_GUARDRAIL_ARN in failed[0]["Finding_Details"]

        assert len(passed) == 1
        assert "PublishedGuardrail" in passed[0]["Finding_Details"]
        assert "ROOT r-abc123" in passed[0]["Finding_Details"]
        assert "version 3" in passed[0]["Finding_Details"]
        assert "aws:PrincipalOrgID" in passed[0]["Finding_Details"]
        # An enforcing Bedrock policy short-circuits the SCP fallback.
        assert all(
            call.kwargs.get("Filter") == "BEDROCK_POLICY"
            for call in org_client.list_policies.call_args_list
        )

    def test_br41_unattached_policy_is_not_enforcement(self):
        _, findings = self._run(
            bedrock_policies=[{"Id": "p-orphan", "Name": "OrphanGuardrail"}],
            targets={"p-orphan": []},
            contents={
                "p-orphan": self._bedrock_policy_document(self.GUARDRAIL_ARN, "2")
            },
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "OrphanGuardrail" in failed[0]["Finding_Details"]
        assert "no attached root" in failed[0]["Finding_Details"]
        assert not [f for f in findings if f["Status"] == "Passed"]

    def test_br41_policy_naming_no_guardrail_is_not_enforcement(self):
        _, findings = self._run(
            bedrock_policies=[{"Id": "p-empty", "Name": "EmptyGuardrailPolicy"}],
            targets={"p-empty": [{"TargetId": "r-abc123", "Type": "ROOT"}]},
            contents={"p-empty": {"bedrock": {"guardrails_configuration": {}}}},
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "names no guardrail ARN" in failed[0]["Finding_Details"]
        assert "attached to ROOT r-abc123" in failed[0]["Finding_Details"]

    def test_br41_negated_scp_condition_is_enforcement(self):
        _, findings = self._run(
            scps=[
                {"Id": "p-unrelated", "Name": "DenyRegions"},
                {"Id": "p-guardrail", "Name": "RequireGuardrail"},
            ],
            contents={
                "p-unrelated": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": "ec2:*",
                            "Resource": "*",
                        }
                    ],
                },
                "p-guardrail": self._deny_without_guardrail(
                    "StringNotEquals", self.GUARDRAIL_ARN
                ),
            },
        )

        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) == 1
        assert "RequireGuardrail" in passed[0]["Finding_Details"]
        assert "DenyRegions" not in passed[0]["Finding_Details"]
        assert not [f for f in findings if f["Status"] == "Failed"]

    def test_br41_stringequals_deny_is_not_enforcement(self):
        _, findings = self._run(
            scps=[{"Id": "p-backwards", "Name": "BackwardsGuardrailDeny"}],
            contents={
                "p-backwards": self._deny_without_guardrail(
                    "StringEquals", self.GUARDRAIL_ARN
                )
            },
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "bedrock:guardrailidentifier" in failed[0]["Finding_Details"]
        assert not [f for f in findings if f["Status"] == "Passed"]

    def test_br41_null_condition_on_wildcard_action_is_enforcement(self):
        document = self._deny_without_guardrail("Null", "true")
        document["Statement"][0]["Action"] = "bedrock:Invoke*"
        _, findings = self._run(
            scps=[{"Id": "p-null", "Name": "RequireGuardrailPresent"}],
            contents={"p-null": document},
        )

        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) == 1
        assert "RequireGuardrailPresent" in passed[0]["Finding_Details"]

    def test_br41_no_policy_of_either_kind_returns_failed(self):
        _, findings = self._run()

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert (
            "each application chooses its own guardrail"
            in (findings[0]["Finding_Details"])
        )
        assert "bedrock:GuardrailIdentifier" in findings[0]["Resolution"]

    def test_br41_unreadable_policies_are_not_absence(self):
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        org_client.list_policies.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListPolicies"
        )
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        bedrock_client = MagicMock()
        bedrock_client.get_paginator.return_value.paginate.return_value = [
            {"guardrailsConfig": []}
        ]

        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "organizations": org_client,
                "sts": sts_client,
                "bedrock": bedrock_client,
            }[service],
        ):
            findings = extract_csv_data(
                bedrock_app.check_bedrock_central_guardrail_enforcement(region="Global")
            )

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "undetermined" in findings[0]["Finding_Details"]
        assert "organizations:DescribePolicy" in findings[0]["Resolution"]

    def test_br41_reads_policies_from_all_pages(self):
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        org_client.list_policies.side_effect = [
            {
                "Policies": [{"Id": "p-draft", "Name": "DraftGuardrail"}],
                "NextToken": "policy-page-2",
            },
            {"Policies": [{"Id": "p-published", "Name": "PublishedGuardrail"}]},
        ]
        org_client.list_targets_for_policy.side_effect = lambda **kwargs: {
            "Targets": [{"TargetId": "r-abc123", "Type": "ROOT"}]
        }
        org_client.describe_policy.side_effect = lambda **kwargs: {
            "Policy": {
                "Content": json.dumps(
                    self._bedrock_policy_document(
                        self.GUARDRAIL_ARN,
                        "DRAFT" if kwargs["PolicyId"] == "p-draft" else "4",
                    )
                )
            }
        }
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        bedrock_client = MagicMock()
        bedrock_client.get_paginator.return_value.paginate.return_value = [
            {"guardrailsConfig": []}
        ]

        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "organizations": org_client,
                "sts": sts_client,
                "bedrock": bedrock_client,
            }[service],
        ):
            findings = extract_csv_data(
                bedrock_app.check_bedrock_central_guardrail_enforcement(region="Global")
            )

        assert org_client.list_policies.call_count == 2
        org_client.list_policies.assert_any_call(
            MaxResults=20, Filter="BEDROCK_POLICY", NextToken="policy-page-2"
        )
        assert [f["Status"] for f in findings].count("Failed") == 1
        assert [f["Status"] for f in findings].count("Passed") == 1

    def test_br41_member_account_returns_na(self):
        _, findings = self._run(account="222222222222")

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert "222222222222" in findings[0]["Finding_Details"]
        assert "management account" in findings[0]["Finding_Details"]

    def _run_without_organizations(self, account_configs):
        """A standalone account: DescribeOrganization fails, so the account-enforced
        configuration list is the only evidence there is."""
        org_client = MagicMock()
        org_client.describe_organization.side_effect = ClientError(
            {"Error": {"Code": "AWSOrganizationsNotInUseException"}},
            "DescribeOrganization",
        )
        bedrock_client = MagicMock()
        bedrock_client.get_paginator.return_value.paginate.return_value = [
            {"guardrailsConfig": list(account_configs)}
        ]
        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "organizations": org_client,
                "sts": MagicMock(),
                "bedrock": bedrock_client,
            }[service],
        ):
            return extract_csv_data(
                bedrock_app.check_bedrock_central_guardrail_enforcement(
                    region="Global", api_region="us-east-1"
                )
            )

    def test_br41_no_organization_and_no_account_config_is_failed(self):
        # Without an organization there is nothing to inherit from, so an empty
        # account-enforced list is an absence of enforcement and not an
        # unreadable surface.
        findings = self._run_without_organizations([])

        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert (
            "No account-enforced guardrail configuration exists"
            in findings[0]["Finding_Details"]
        )
        assert "AWS Organizations is not in use" in findings[0]["Finding_Details"]
        assert "PutEnforcedGuardrailConfiguration" in findings[0]["Resolution"]

    def test_br41_no_organization_but_account_config_is_passed(self):
        findings = self._run_without_organizations(
            [self._account_config("cfgstandalone")]
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "cfgstandalone" in findings[0]["Finding_Details"]
        assert "includedModels names ALL" in findings[0]["Finding_Details"]

    def test_br41_all_models_config_passes_while_narrowed_sibling_is_covered(self):
        # Two configurations, one covering every model and one covering two named
        # models. The narrow one is not a gap because the broad one already
        # applies, so the check must report exactly one mechanism and no failure.
        _, bedrock_client, findings = self._run_clients(
            account_configs=[
                self._account_config("cfgcoversall1"),
                self._account_config(
                    "cfgtwomodels1",
                    included=["anthropic.claude-3-sonnet", "amazon.titan-text-lite"],
                    guardrail_arn=self.OTHER_GUARDRAIL_ARN,
                ),
            ]
        )

        bedrock_client.get_paginator.assert_called_once_with(
            "list_enforced_guardrails_configuration"
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        detail = findings[0]["Finding_Details"]
        assert "1 mechanism(s)" in detail
        assert "cfgcoversall1" in detail
        assert "all models, because includedModels names ALL" in detail
        assert "system=COMPREHENSIVE, messages=COMPREHENSIVE" in detail
        assert "cfgtwomodels1" not in detail

    def test_br41_narrowed_configs_fail_with_their_own_reason(self):
        # Each configuration is judged on its own fields: one is narrowed by the
        # model list, the other by selective system guarding.
        _, _, findings = self._run_clients(
            account_configs=[
                self._account_config(
                    "cfgtwomodels1",
                    included=["anthropic.claude-3-sonnet", "amazon.titan-text-lite"],
                ),
                self._account_config("cfgselective1", system="SELECTIVE"),
            ]
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 2
        assert not [f for f in findings if f["Status"] == "Passed"]

        by_config = {
            next(
                config_id
                for config_id in ("cfgtwomodels1", "cfgselective1")
                if config_id in f["Finding_Details"]
            ): f
            for f in failed
        }
        assert set(by_config) == {"cfgtwomodels1", "cfgselective1"}

        models_detail = by_config["cfgtwomodels1"]["Finding_Details"]
        assert "includedModels does not name ALL" in models_detail
        assert "amazon.titan-text-lite" in models_detail
        assert "anthropic.claude-3-sonnet" in models_detail
        assert "SELECTIVE" not in models_detail

        guarding_detail = by_config["cfgselective1"]["Finding_Details"]
        assert (
            "system content is guarded SELECTIVE, so it is evaluated only when the "
            "caller tags it" in guarding_detail
        )
        assert "includedModels does not name ALL" not in guarding_detail
        assert "PutEnforcedGuardrailConfiguration" in failed[0]["Resolution"]

    def test_br41_absent_model_enforcement_covers_every_model(self):
        # PutEnforcedGuardrailConfiguration documents an absent modelEnforcement
        # block as enforcement on all models.
        _, _, findings = self._run_clients(
            account_configs=[
                self._account_config("cfgnoscope01", omit_model_enforcement=True)
            ]
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "carries no modelEnforcement block" in findings[0]["Finding_Details"]

    def test_br41_excluded_model_is_a_gap_even_when_included_is_all(self):
        _, _, findings = self._run_clients(
            account_configs=[
                self._account_config(
                    "cfgexcluded1", excluded=["anthropic.claude-3-haiku"]
                )
            ]
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert (
            "1 model(s) are excluded from enforcement" in failed[0]["Finding_Details"]
        )
        assert "anthropic.claude-3-haiku" in failed[0]["Finding_Details"]
        assert not [f for f in findings if f["Status"] == "Passed"]

    def test_br41_reads_enforced_configurations_from_every_page(self):
        _, _, findings = self._run_clients(
            account_pages=[
                {
                    "guardrailsConfig": [
                        self._account_config("cfgpageone01", included=["amazon.titan"])
                    ],
                    "nextToken": "page-2",
                },
                {"guardrailsConfig": [self._account_config("cfgpagetwo01")]},
            ]
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "cfgpagetwo01" in findings[0]["Finding_Details"]

    def test_br41_unreadable_enforced_configurations_are_not_absence(self):
        _, _, findings = self._run_clients(
            account_error=ClientError(
                {"Error": {"Code": "AccessDeniedException"}},
                "ListEnforcedGuardrailsConfiguration",
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        detail = findings[0]["Finding_Details"]
        assert "AccessDeniedException" in detail
        assert "bedrock:ListEnforcedGuardrailsConfiguration" in detail
        assert "owner field reports ACCOUNT only" in detail
        assert (
            "bedrock:ListEnforcedGuardrailsConfiguration" in findings[0]["Resolution"]
        )

    def test_br41_account_config_is_read_from_a_member_account(self):
        # The organization view is unreadable from a member account, but the
        # account-enforced configuration list is not, so the check still decides.
        _, _, findings = self._run_clients(
            account="222222222222",
            account_configs=[self._account_config("cfgmember0001")],
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "cfgmember0001" in findings[0]["Finding_Details"]

    def test_br41_schema_valid(self):
        _, findings = self._run(
            bedrock_policies=[
                {"Id": "p-published", "Name": "PublishedGuardrail"},
                {"Id": "p-draft", "Name": "DraftGuardrail"},
            ],
            targets={
                "p-published": [{"TargetId": "r-abc123", "Type": "ROOT"}],
                "p-draft": [{"TargetId": "ou-1234", "Type": "ORGANIZATIONAL_UNIT"}],
            },
            contents={
                "p-published": self._bedrock_policy_document(self.GUARDRAIL_ARN, "3"),
                "p-draft": self._bedrock_policy_document(self.GUARDRAIL_ARN, "DRAFT"),
            },
        )

        assert findings
        for finding in findings:
            assert_finding_schema(finding)

    def test_br41_account_leg_schema_valid(self):
        for kwargs in (
            {"account_configs": [self._account_config("cfgcoversall1")]},
            {
                "account_configs": [
                    self._account_config("cfgexcluded1", excluded=["x.y"])
                ]
            },
            {
                "account_error": ClientError(
                    {"Error": {"Code": "AccessDeniedException"}},
                    "ListEnforcedGuardrailsConfiguration",
                )
            },
        ):
            _, _, findings = self._run_clients(**kwargs)
            assert findings
            for finding in findings:
                assert_finding_schema(finding)


def _identity_cache(roles=None, users=None):
    """Build a permission cache from {identity: [(policy_name, document)]}."""

    def entry(policies):
        return {
            "attached_policies": [
                {
                    "name": name,
                    "arn": f"arn:aws:iam::123456789012:policy/{name}",
                    "document": document,
                }
                for name, document in policies
            ],
            "inline_policies": [],
            "permission_boundary": None,
        }

    return {
        "role_permissions": {
            name: entry(policies) for name, policies in (roles or {}).items()
        },
        "user_permissions": {
            name: entry(policies) for name, policies in (users or {}).items()
        },
    }


def _allow(actions, resources, condition=None):
    statement = {"Effect": "Allow", "Action": actions, "Resource": resources}
    if condition:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


# ===================================================================
# BR-42: check_bedrock_model_allow_list
# ===================================================================
class TestBR42ModelAllowList:
    """BR-42: Model invocation must name the model ARNs it allows."""

    MODEL_ARN = (
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-v1:0"
    )

    def _run(self, cache):
        return extract_csv_data(
            bedrock_app.check_bedrock_model_allow_list(cache, region="Global")
        )

    def test_br42_named_arn_passes_while_wildcard_fails(self):
        findings = self._run(
            _identity_cache(
                roles={
                    "ScopedRole": [
                        ("ScopedInvoke", _allow("bedrock:InvokeModel", self.MODEL_ARN))
                    ],
                    "OpenRole": [
                        ("OpenInvoke", _allow("bedrock:InvokeModel", "*")),
                    ],
                }
            )
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]

        assert len(failed) == 1
        assert failed[0]["Check_ID"] == "BR-42"
        assert "Role 'OpenRole'" in failed[0]["Finding_Details"]
        assert "policy 'OpenInvoke'" in failed[0]["Finding_Details"]
        assert "every model available in the account" in failed[0]["Finding_Details"]

        assert len(passed) == 1
        assert "ScopedRole" in passed[0]["Finding_Details"]
        assert self.MODEL_ARN in passed[0]["Finding_Details"]
        assert (
            "confirm these ARNs are the approved list" in (passed[0]["Finding_Details"])
        )

    def test_br42_foundation_model_wildcard_arn_is_not_an_allow_list(self):
        findings = self._run(
            _identity_cache(
                roles={
                    "WildcardArnRole": [
                        (
                            "WildcardArn",
                            _allow(
                                ["bedrock:InvokeModel"],
                                ["arn:aws:bedrock:*::foundation-model/*"],
                            ),
                        )
                    ]
                }
            )
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "arn:aws:bedrock:*::foundation-model/*" in failed[0]["Finding_Details"]
        assert not [f for f in findings if f["Status"] == "Passed"]

    def test_br42_model_arn_condition_does_not_scope_the_streaming_action(self):
        condition = {"StringEquals": {"bedrock:ModelArn": self.MODEL_ARN}}
        findings = self._run(
            _identity_cache(
                roles={
                    "StreamingRole": [
                        (
                            "StreamingCondition",
                            _allow(
                                [
                                    "bedrock:InvokeModel",
                                    "bedrock:InvokeModelWithResponseStream",
                                ],
                                "*",
                                condition,
                            ),
                        )
                    ],
                    "NonStreamingRole": [
                        (
                            "NonStreamingCondition",
                            _allow("bedrock:InvokeModel", "*", condition),
                        )
                    ],
                }
            )
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "StreamingRole" in failed[0]["Finding_Details"]
        assert "bedrock:invokemodelwithresponsestream" in failed[0]["Finding_Details"]
        assert "which that operation does not support" in failed[0]["Finding_Details"]
        assert len(passed) == 1
        assert "NonStreamingRole" in passed[0]["Finding_Details"]

    def test_br42_wildcard_action_on_all_resources_fails(self):
        findings = self._run(
            _identity_cache(
                users={"AdminUser": [("Admin", _allow("*", "*"))]},
            )
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "User 'AdminUser'" in failed[0]["Finding_Details"]

    def test_br42_no_invocation_grant_returns_na(self):
        findings = self._run(
            _identity_cache(
                roles={
                    "ReadOnlyRole": [
                        ("ReadOnly", _allow("bedrock:ListFoundationModels", "*"))
                    ]
                }
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "no model invocation grant to restrict" in findings[0]["Finding_Details"]

    def test_br42_schema_valid(self):
        findings = self._run(
            _identity_cache(
                roles={
                    "ScopedRole": [
                        ("ScopedInvoke", _allow("bedrock:InvokeModel", self.MODEL_ARN))
                    ],
                    "OpenRole": [("OpenInvoke", _allow("bedrock:InvokeModel", "*"))],
                }
            )
        )
        assert findings
        for finding in findings:
            assert_finding_schema(finding)


# ===================================================================
# BR-43: check_bedrock_region_invocation_control
# ===================================================================
class TestBR43RegionInvocationControl:
    """BR-43: A Region condition on Bedrock invocation, read from the SCPs."""

    @staticmethod
    def _region_scp(operator, regions, action="bedrock:InvokeModel"):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": action,
                    "Resource": "*",
                    "Condition": {operator: {"aws:RequestedRegion": regions}},
                }
            ],
        }

    @staticmethod
    def _inventory(policies):
        return {
            "items": [
                {"name": name, "id": f"p-{name}", "content": json.dumps(document)}
                for name, document in policies
            ],
            "errors": [],
            "list_error": None,
        }

    # A geographic profile enumerates its destination Regions; a global profile
    # also lists the Region-agnostic ARN form, whose Region segment is empty.
    BOUNDED_PROFILE = {
        "inferenceProfileId": "us.anthropic.claude-3-sonnet-20240229-v1:0",
        "inferenceProfileName": "US Claude 3 Sonnet",
        "type": "SYSTEM_DEFINED",
        "status": "ACTIVE",
        "models": [
            {
                "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0"
            },
            {
                "modelArn": "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0"
            },
        ],
    }
    UNBOUNDED_PROFILE = {
        "inferenceProfileId": "global.cohere.embed-v4:0",
        "inferenceProfileName": "Global Cohere Embed v4",
        "type": "SYSTEM_DEFINED",
        "status": "ACTIVE",
        "models": [
            {"modelArn": "arn:aws:bedrock:::foundation-model/cohere.embed-v4:0"},
            {
                "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/cohere.embed-v4:0"
            },
        ],
    }

    def _run(
        self,
        inventory,
        account="123456789012",
        profiles=None,
        profile_pages=None,
        profile_error=None,
    ):
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": account}
        bedrock_client = MagicMock()
        if profile_error is not None:
            bedrock_client.get_paginator.side_effect = profile_error
        else:
            bedrock_client.get_paginator.return_value.paginate.return_value = (
                profile_pages
                if profile_pages is not None
                else [
                    {
                        "inferenceProfileSummaries": list(
                            profiles if profiles is not None else [self.BOUNDED_PROFILE]
                        )
                    }
                ]
            )
        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "organizations": org_client,
                "sts": sts_client,
                "bedrock": bedrock_client,
            }[service],
        ):
            return extract_csv_data(
                bedrock_app.check_bedrock_region_invocation_control(
                    region="Global",
                    api_region="us-east-1",
                    scp_inventory=inventory,
                )
            )

    def test_br43_region_allow_list_passes_and_names_the_global_literal(self):
        findings = self._run(
            self._inventory(
                [
                    (
                        "ApprovedRegions",
                        self._region_scp(
                            "StringNotEquals", ["us-east-1", "unspecified"]
                        ),
                    ),
                    (
                        "UnrelatedDeny",
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Deny", "Action": "ec2:*", "Resource": "*"}
                            ],
                        },
                    ),
                ]
            )
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert findings[0]["Check_ID"] == "BR-43"
        assert "ApprovedRegions" in findings[0]["Finding_Details"]
        assert "UnrelatedDeny" not in findings[0]["Finding_Details"]
        assert "includes the literal 'unspecified'" in findings[0]["Finding_Details"]

    def test_br43_allow_list_without_the_global_literal_says_so(self):
        findings = self._run(
            self._inventory(
                [
                    (
                        "ApprovedRegions",
                        self._region_scp("StringNotEquals", ["us-east-1"]),
                    )
                ]
            )
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "omits the literal 'unspecified'" in findings[0]["Finding_Details"]
        assert (
            "every global inference profile call is denied"
            in (findings[0]["Finding_Details"])
        )

    def test_br43_no_region_condition_returns_failed(self):
        findings = self._run(
            self._inventory(
                [
                    (
                        "GuardrailOnly",
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Deny",
                                    "Action": "bedrock:InvokeModel",
                                    "Resource": "*",
                                    "Condition": {
                                        "Null": {"bedrock:GuardrailIdentifier": "true"}
                                    },
                                }
                            ],
                        },
                    )
                ]
            )
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        assert "1 service control policy document(s)" in findings[0]["Finding_Details"]
        assert "aws:RequestedRegion" in findings[0]["Resolution"]

    def test_br43_batch_inference_action_counts_as_control(self):
        findings = self._run(
            self._inventory(
                [
                    (
                        "BatchRegions",
                        self._region_scp(
                            "StringNotEquals",
                            ["eu-west-1", "unspecified"],
                            action="bedrock:CreateModelInvocationJob",
                        ),
                    )
                ]
            )
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "bedrock:createmodelinvocationjob" in findings[0]["Finding_Details"]

    def test_br43_unreadable_policies_are_not_absence(self):
        inventory = {
            "items": [],
            "errors": ["policy 'Secret': AccessDenied"],
            "list_error": None,
        }
        findings = self._run(inventory)

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "undetermined" in findings[0]["Finding_Details"]
        assert "policy 'Secret'" in findings[0]["Finding_Details"]

    def test_br43_member_account_returns_na(self):
        findings = self._run(self._inventory([]), account="222222222222")

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "222222222222" in findings[0]["Finding_Details"]

    def test_br43_builds_its_own_inventory_when_not_given_one(self):
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        org_client.list_policies.return_value = {
            "Policies": [{"Id": "p-1", "Name": "ApprovedRegions"}]
        }
        org_client.describe_policy.return_value = {
            "Policy": {
                "Content": json.dumps(
                    self._region_scp("StringNotEquals", ["us-east-1", "unspecified"])
                )
            }
        }
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        bedrock_client = MagicMock()
        bedrock_client.get_paginator.return_value.paginate.return_value = [
            {"inferenceProfileSummaries": [self.BOUNDED_PROFILE]}
        ]

        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "organizations": org_client,
                "sts": sts_client,
                "bedrock": bedrock_client,
            }[service],
        ):
            findings = extract_csv_data(
                bedrock_app.check_bedrock_region_invocation_control(region="Global")
            )

        org_client.list_policies.assert_called_once_with(
            MaxResults=20, Filter="SERVICE_CONTROL_POLICY"
        )
        assert [f["Status"] for f in findings] == ["Passed"]

    def test_br43_global_profile_passes_the_region_allow_list_when_unspecified_is_allowed(
        self,
    ):
        # Two profiles, one bounded to named Regions and one routing anywhere. The
        # allow-list permits the literal 'unspecified', which is the value a global
        # profile call presents, so the Region control does not bound it.
        findings = self._run(
            self._inventory(
                [
                    (
                        "ApprovedRegions",
                        self._region_scp(
                            "StringNotEquals", ["us-east-1", "unspecified"]
                        ),
                    )
                ]
            ),
            profiles=[self.BOUNDED_PROFILE, self.UNBOUNDED_PROFILE],
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        detail = findings[0]["Finding_Details"]
        assert "1 of the 2 inference profile(s) available in us-east-1" in detail
        assert "global.cohere.embed-v4:0" in detail
        assert "us.anthropic.claude-3-sonnet-20240229-v1:0" not in detail
        assert "name only us-east-1, us-west-2" in detail
        assert "denies aws:RequestedRegion 'unspecified'" in detail
        assert "accepted data-residency exception" in findings[0]["Resolution"]

    def test_br43_allow_list_excluding_unspecified_bounds_a_global_profile(self):
        findings = self._run(
            self._inventory(
                [
                    (
                        "ApprovedRegions",
                        self._region_scp("StringNotEquals", ["us-east-1"]),
                    )
                ]
            ),
            profiles=[self.BOUNDED_PROFILE, self.UNBOUNDED_PROFILE],
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        detail = findings[0]["Finding_Details"]
        assert "omits the literal 'unspecified'" in detail
        assert "global.cohere.embed-v4:0" in detail

    def test_br43_deny_list_does_not_bound_a_global_profile(self):
        # A positive Region test is a deny-list: it never denies 'unspecified'
        # unless that literal is one of the denied values.
        findings = self._run(
            self._inventory(
                [("BlockedRegions", self._region_scp("StringEquals", ["eu-west-1"]))]
            ),
            profiles=[self.UNBOUNDED_PROFILE],
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        assert "BlockedRegions" in findings[0]["Finding_Details"]
        assert "bounds direct invocation only" in findings[0]["Finding_Details"]

    def test_br43_reads_inference_profiles_from_every_page(self):
        findings = self._run(
            self._inventory(
                [
                    (
                        "ApprovedRegions",
                        self._region_scp(
                            "StringNotEquals", ["us-east-1", "unspecified"]
                        ),
                    )
                ]
            ),
            profile_pages=[
                {
                    "inferenceProfileSummaries": [self.BOUNDED_PROFILE],
                    "nextToken": "page-2",
                },
                {"inferenceProfileSummaries": [self.UNBOUNDED_PROFILE]},
            ],
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        assert "1 of the 2 inference profile(s)" in findings[0]["Finding_Details"]
        assert "global.cohere.embed-v4:0" in findings[0]["Finding_Details"]

    def test_br43_unreadable_profile_list_keeps_the_policy_verdict(self):
        findings = self._run(
            self._inventory(
                [
                    (
                        "ApprovedRegions",
                        self._region_scp(
                            "StringNotEquals", ["us-east-1", "unspecified"]
                        ),
                    )
                ]
            ),
            profile_error=ClientError(
                {"Error": {"Code": "AccessDeniedException"}}, "ListInferenceProfiles"
            ),
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert (
            "could not be listed (AccessDeniedException), so the default routing "
            "behavior was not observed" in findings[0]["Finding_Details"]
        )

    def test_br43_no_region_condition_names_the_default_routing(self):
        findings = self._run(
            self._inventory([]),
            profiles=[self.BOUNDED_PROFILE, self.UNBOUNDED_PROFILE],
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        detail = findings[0]["Finding_Details"]
        assert "follows the default inference-profile behavior" in detail
        assert "1 of the 2 inference profile(s) available in us-east-1" in detail

    def test_br43_model_reference_that_is_not_an_arn_is_not_global(self):
        # A value that is not an ARN has no Region segment to read, so it must not
        # be counted as Region-agnostic routing.
        findings = self._run(
            self._inventory(
                [
                    (
                        "ApprovedRegions",
                        self._region_scp(
                            "StringNotEquals", ["us-east-1", "unspecified"]
                        ),
                    )
                ]
            ),
            profiles=[
                {
                    "inferenceProfileId": "us.custom.profile",
                    "type": "APPLICATION",
                    "status": "ACTIVE",
                    "models": [{"modelArn": "cohere.embed-v4:0"}],
                }
            ],
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        detail = findings[0]["Finding_Details"]
        assert "0 of the 1 inference profile(s)" in detail
        assert "1 model reference(s) were not in ARN form" in detail

    def test_br43_schema_valid(self):
        for kwargs in (
            {"profiles": [self.BOUNDED_PROFILE, self.UNBOUNDED_PROFILE]},
            {"profiles": []},
            {
                "profile_error": ClientError(
                    {"Error": {"Code": "AccessDeniedException"}},
                    "ListInferenceProfiles",
                )
            },
        ):
            findings = self._run(
                self._inventory(
                    [
                        (
                            "ApprovedRegions",
                            self._region_scp("StringEquals", ["cn-north-1"]),
                        )
                    ]
                ),
                **kwargs,
            )
            assert findings
            for finding in findings:
                assert_finding_schema(finding)


# ===================================================================
# BR-44: check_bedrock_marketplace_model_control
# ===================================================================
class TestBR44MarketplaceModelControl:
    """BR-44: Marketplace subscription must be scoped by product."""

    PRODUCT_ID = "prod-abcdefghijklm"

    def _run(self, cache):
        return extract_csv_data(
            bedrock_app.check_bedrock_marketplace_model_control(cache, region="Global")
        )

    def test_br44_product_condition_passes_while_bare_subscribe_fails(self):
        findings = self._run(
            _identity_cache(
                roles={
                    "ScopedRole": [
                        (
                            "ScopedSubscribe",
                            _allow(
                                "aws-marketplace:Subscribe",
                                "*",
                                {
                                    "StringEquals": {
                                        "aws-marketplace:ProductId": self.PRODUCT_ID
                                    }
                                },
                            ),
                        )
                    ],
                    "OpenRole": [
                        ("OpenSubscribe", _allow("aws-marketplace:Subscribe", "*"))
                    ],
                }
            )
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]

        assert len(failed) == 1
        assert failed[0]["Check_ID"] == "BR-44"
        assert "Role 'OpenRole'" in failed[0]["Finding_Details"]
        assert (
            "without an aws-marketplace:productid condition"
            in (failed[0]["Finding_Details"])
        )
        assert "BR-42" in failed[0]["Resolution"]

        assert len(passed) == 1
        assert "ScopedRole" in passed[0]["Finding_Details"]
        assert self.PRODUCT_ID in passed[0]["Finding_Details"]
        assert "BR-42" in passed[0]["Finding_Details"]

    def test_br44_deny_naming_products_positively_fails_open(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws-marketplace:ProductId": self.PRODUCT_ID}
                    },
                },
                {
                    "Effect": "Deny",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws-marketplace:ProductId": "prod-blocked"}
                    },
                },
            ],
        }
        findings = self._run(
            _identity_cache(roles={"DenyListRole": [("DenyList", document)]})
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert (
            "leaves every product that is not named allowed"
            in (failed[0]["Finding_Details"])
        )
        assert not [f for f in findings if f["Status"] == "Passed"]

    def test_br44_negated_deny_is_an_allow_list(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws-marketplace:ProductId": self.PRODUCT_ID
                        }
                    },
                }
            ],
        }
        findings = self._run(
            _identity_cache(roles={"AllowListRole": [("AllowList", document)]})
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "Deny scoped by stringnotequals" in findings[0]["Finding_Details"]

    def test_br44_qualified_operator_is_the_form_iam_accepts(self):
        # aws-marketplace:ProductId is multi-valued, so IAM Access Analyzer
        # rejects a bare StringEquals on it with MISSING_QUALIFIER. The
        # qualified operator must therefore read as scoping, and its negated
        # form must still read as a Deny allow-list.
        findings = self._run(
            _identity_cache(
                roles={
                    "QualifiedAllowRole": [
                        (
                            "QualifiedAllow",
                            _allow(
                                "aws-marketplace:Subscribe",
                                "*",
                                {
                                    "ForAllValues:StringEquals": {
                                        "aws-marketplace:ProductId": [self.PRODUCT_ID]
                                    }
                                },
                            ),
                        )
                    ],
                    "QualifiedDenyRole": [
                        (
                            "QualifiedDeny",
                            {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Deny",
                                        "Action": "aws-marketplace:Subscribe",
                                        "Resource": "*",
                                        "Condition": {
                                            "ForAnyValue:StringNotEquals": {
                                                "aws-marketplace:ProductId": [
                                                    self.PRODUCT_ID
                                                ]
                                            }
                                        },
                                    }
                                ],
                            },
                        )
                    ],
                }
            )
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "forallvalues:stringequals" in findings[0]["Finding_Details"]
        assert "foranyvalue:stringnotequals" in findings[0]["Finding_Details"]

    def test_br44_resolution_names_the_multi_value_qualifier(self):
        findings = self._run(
            _identity_cache(
                roles={
                    "OpenRole": [
                        ("OpenSubscribe", _allow("aws-marketplace:Subscribe", "*"))
                    ]
                }
            )
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "ForAllValues:StringEquals" in failed[0]["Resolution"]

    def test_br44_no_subscribe_grant_returns_na(self):
        findings = self._run(
            _identity_cache(
                roles={
                    "ReadOnlyRole": [("ReadOnly", _allow("bedrock:ListAgents", "*"))]
                }
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "no identity can subscribe" in findings[0]["Finding_Details"]

    def test_br44_schema_valid(self):
        findings = self._run(
            _identity_cache(
                roles={
                    "OpenRole": [
                        ("OpenSubscribe", _allow("aws-marketplace:Subscribe", "*"))
                    ]
                },
                users={
                    "ScopedUser": [
                        (
                            "ScopedSubscribe",
                            _allow(
                                "aws-marketplace:Subscribe",
                                "*",
                                {
                                    "StringEquals": {
                                        "aws-marketplace:ProductId": self.PRODUCT_ID
                                    }
                                },
                            ),
                        )
                    ]
                },
            )
        )
        assert findings
        for finding in findings:
            assert_finding_schema(finding)


# ===================================================================
# BR-45: check_bedrock_api_key_governance
# ===================================================================
class TestBR45ApiKeyGovernance:
    """BR-45: Bedrock API key inventory and the preventive age/token control."""

    INVENTORY_FINDING = "Bedrock API Key Inventory"
    PREVENTION_FINDING = "Bedrock API Key Age And Token Type Control"

    @staticmethod
    def _age_scp(operator="NumericGreaterThan", value="7"):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "iam:CreateServiceSpecificCredential",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "iam:ServiceSpecificCredentialServiceName": "bedrock.amazonaws.com"
                        },
                        operator: {"iam:ServiceSpecificCredentialAgeDays": value},
                    },
                }
            ],
        }

    @staticmethod
    def _bearer_token_scp():
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "bedrock:CallWithBearerToken",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"bedrock:BearerTokenType": "LONG_TERM"}
                    },
                }
            ],
        }

    def _run(self, credentials, inventory=None, account="123456789012", users=None):
        """credentials: {user_name: [credential dicts]}."""
        iam_client = MagicMock()

        def list_credentials(**kwargs):
            return {
                "ServiceSpecificCredentials": list(
                    credentials.get(kwargs["UserName"], [])
                )
            }

        iam_client.list_service_specific_credentials.side_effect = list_credentials

        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": account}

        cache = _identity_cache(
            users={name: [] for name in (users or credentials.keys())}
        )
        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "iam": iam_client,
                "organizations": org_client,
                "sts": sts_client,
            }[service],
        ):
            findings = extract_csv_data(
                bedrock_app.check_bedrock_api_key_governance(
                    cache,
                    region="Global",
                    scp_inventory=inventory
                    if inventory is not None
                    else {"items": [], "errors": [], "list_error": None},
                )
            )
        return iam_client, findings

    def _by_name(self, findings, name):
        return [f for f in findings if f["Finding"] == name]

    def test_br45_key_without_expiry_fails_while_expiring_key_passes(self):
        iam_client, findings = self._run(
            {
                "StandingKeyUser": [
                    {
                        "ServiceSpecificCredentialId": "ACCA-standing",
                        "Status": "Active",
                    }
                ],
                "ExpiringKeyUser": [
                    {
                        "ServiceSpecificCredentialId": "ACCA-expiring",
                        "Status": "Active",
                        "ExpirationDate": "2026-01-01T00:00:00Z",
                    }
                ],
            }
        )

        inventory_rows = self._by_name(findings, self.INVENTORY_FINDING)
        failed = [f for f in inventory_rows if f["Status"] == "Failed"]
        passed = [f for f in inventory_rows if f["Status"] == "Passed"]

        assert len(failed) == 1
        assert failed[0]["Check_ID"] == "BR-45"
        assert "StandingKeyUser" in failed[0]["Finding_Details"]
        assert "ACCA-standing" in failed[0]["Finding_Details"]
        assert "no expiration date" in failed[0]["Finding_Details"]

        assert len(passed) == 1
        assert "ACCA-expiring" in passed[0]["Finding_Details"]
        assert "2026-01-01" in passed[0]["Finding_Details"]

        iam_client.list_service_specific_credentials.assert_any_call(
            UserName="StandingKeyUser", ServiceName="bedrock.amazonaws.com"
        )

    def test_br45_inactive_credential_is_not_a_standing_key(self):
        _, findings = self._run(
            {
                "RetiredKeyUser": [
                    {
                        "ServiceSpecificCredentialId": "ACCA-retired",
                        "Status": "Inactive",
                    }
                ]
            }
        )

        inventory_rows = self._by_name(findings, self.INVENTORY_FINDING)
        assert [f["Status"] for f in inventory_rows] == ["N/A"]
        assert "no Bedrock API key is in use" in inventory_rows[0]["Finding_Details"]

    def test_br45_age_cap_scp_passes_the_prevention_leg(self):
        _, findings = self._run(
            {},
            inventory={
                "items": [
                    {
                        "name": "CapKeyAge",
                        "id": "p-1",
                        "content": json.dumps(self._age_scp()),
                    }
                ],
                "errors": [],
                "list_error": None,
            },
        )

        prevention = self._by_name(findings, self.PREVENTION_FINDING)
        assert [f["Status"] for f in prevention] == ["Passed"]
        assert "CapKeyAge" in prevention[0]["Finding_Details"]
        assert (
            "iam:servicespecificcredentialagedays" in prevention[0]["Finding_Details"]
        )

    def test_br45_bearer_token_type_deny_passes_the_prevention_leg(self):
        _, findings = self._run(
            {},
            inventory={
                "items": [
                    {
                        "name": "DenyLongTermToken",
                        "id": "p-2",
                        "content": json.dumps(self._bearer_token_scp()),
                    }
                ],
                "errors": [],
                "list_error": None,
            },
        )

        prevention = self._by_name(findings, self.PREVENTION_FINDING)
        assert [f["Status"] for f in prevention] == ["Passed"]
        assert "bedrock:bearertokentype" in prevention[0]["Finding_Details"]

    def test_br45_no_preventive_policy_returns_failed(self):
        _, findings = self._run(
            {},
            inventory={
                "items": [
                    {
                        "name": "UnrelatedDeny",
                        "id": "p-3",
                        "content": json.dumps(
                            {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Deny",
                                        "Action": "iam:CreateUser",
                                        "Resource": "*",
                                    }
                                ],
                            }
                        ),
                    }
                ],
                "errors": [],
                "list_error": None,
            },
        )

        prevention = self._by_name(findings, self.PREVENTION_FINDING)
        assert [f["Status"] for f in prevention] == ["Failed"]
        assert (
            "1 service control policy document(s)" in (prevention[0]["Finding_Details"])
        )
        assert "LONG_TERM" in prevention[0]["Resolution"]

    def test_br45_unreadable_credentials_are_not_absence(self):
        iam_client = MagicMock()
        iam_client.list_service_specific_credentials.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "ListServiceSpecificCredentials"
        )
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "iam": iam_client,
                "organizations": org_client,
                "sts": sts_client,
            }[service],
        ):
            findings = extract_csv_data(
                bedrock_app.check_bedrock_api_key_governance(
                    _identity_cache(users={"KeyUser": []}),
                    region="Global",
                    scp_inventory={"items": [], "errors": [], "list_error": None},
                )
            )

        inventory_rows = self._by_name(findings, self.INVENTORY_FINDING)
        assert [f["Status"] for f in inventory_rows] == ["N/A"]
        assert "could not be inventoried" in inventory_rows[0]["Finding_Details"]
        assert "iam:ListServiceSpecificCredentials" in inventory_rows[0]["Resolution"]

    def test_br45_member_account_still_inventories_keys(self):
        _, findings = self._run(
            {
                "StandingKeyUser": [
                    {"ServiceSpecificCredentialId": "ACCA-x", "Status": "Active"}
                ]
            },
            account="222222222222",
        )

        assert [
            f["Status"] for f in self._by_name(findings, self.INVENTORY_FINDING)
        ] == ["Failed"]
        prevention = self._by_name(findings, self.PREVENTION_FINDING)
        assert [f["Status"] for f in prevention] == ["N/A"]
        assert "222222222222" in prevention[0]["Finding_Details"]

    def test_br45_reads_credentials_from_all_pages(self):
        iam_client = MagicMock()
        iam_client.list_service_specific_credentials.side_effect = [
            {
                "ServiceSpecificCredentials": [
                    {"ServiceSpecificCredentialId": "ACCA-1", "Status": "Inactive"}
                ],
                "Marker": "page-2",
            },
            {
                "ServiceSpecificCredentials": [
                    {"ServiceSpecificCredentialId": "ACCA-2", "Status": "Active"}
                ]
            },
        ]
        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "iam": iam_client,
                "organizations": org_client,
                "sts": sts_client,
            }[service],
        ):
            findings = extract_csv_data(
                bedrock_app.check_bedrock_api_key_governance(
                    _identity_cache(users={"KeyUser": []}),
                    region="Global",
                    scp_inventory={"items": [], "errors": [], "list_error": None},
                )
            )

        iam_client.list_service_specific_credentials.assert_any_call(
            UserName="KeyUser",
            ServiceName="bedrock.amazonaws.com",
            Marker="page-2",
        )
        inventory_rows = self._by_name(findings, self.INVENTORY_FINDING)
        assert [f["Status"] for f in inventory_rows] == ["Failed"]
        assert "ACCA-2" in inventory_rows[0]["Finding_Details"]

    def test_br45_schema_valid(self):
        _, findings = self._run(
            {
                "StandingKeyUser": [
                    {"ServiceSpecificCredentialId": "ACCA-x", "Status": "Active"}
                ],
                "ExpiringKeyUser": [
                    {
                        "ServiceSpecificCredentialId": "ACCA-y",
                        "Status": "Active",
                        "ExpirationDate": "2026-05-05T00:00:00Z",
                    }
                ],
            },
            inventory={
                "items": [
                    {
                        "name": "CapKeyAge",
                        "id": "p-1",
                        "content": json.dumps(self._age_scp()),
                    }
                ],
                "errors": [],
                "list_error": None,
            },
        )
        assert findings
        for finding in findings:
            assert_finding_schema(finding)


# ===================================================================
# BR-46: check_bedrock_knowledge_base_source_classification
# ===================================================================
class TestBR46KnowledgeBaseSourceClassification:
    """BR-46: every knowledge base source bucket must be monitored by Macie."""

    def _run(
        self,
        knowledge_bases=(),
        data_sources=None,
        data_source_detail=None,
        macie_buckets=(),
        session_status="ENABLED",
        discovery_status="ENABLED",
        session_error=None,
        discovery_error=None,
        describe_buckets_error=None,
        data_source_error=None,
    ):
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": list(knowledge_bases)
        }
        data_sources = data_sources or {}
        agent_client.list_data_sources.side_effect = (
            data_source_error
            if data_source_error
            else lambda **kwargs: {
                "dataSourceSummaries": data_sources.get(kwargs["knowledgeBaseId"], [])
            }
        )
        detail = data_source_detail or {}
        agent_client.get_data_source.side_effect = lambda **kwargs: detail[
            kwargs["dataSourceId"]
        ]
        # Exposed so the describe cap can be asserted on the call count.
        self.last_agent_client = agent_client

        macie_client = MagicMock()
        if session_error:
            macie_client.get_macie_session.side_effect = session_error
        else:
            macie_client.get_macie_session.return_value = {"status": session_status}
        if discovery_error:
            macie_client.get_automated_discovery_configuration.side_effect = (
                discovery_error
            )
        else:
            macie_client.get_automated_discovery_configuration.return_value = {
                "status": discovery_status,
                "classificationScopeId": "scope-1",
            }
        if describe_buckets_error:
            macie_client.get_paginator.return_value.paginate.side_effect = (
                describe_buckets_error
            )
        else:
            macie_client.get_paginator.return_value.paginate.return_value = [
                {"buckets": list(macie_buckets)}
            ]

        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "bedrock-agent": agent_client,
                "macie2": macie_client,
            }[service],
        ):
            return extract_csv_data(
                bedrock_app.check_bedrock_knowledge_base_source_classification(
                    region="us-east-1"
                )
            )

    @staticmethod
    def _s3_source(data_source_id, name, bucket, owner=None):
        configuration = {
            "type": "S3",
            "s3Configuration": {"bucketArn": f"arn:aws:s3:::{bucket}"},
        }
        if owner:
            configuration["s3Configuration"]["bucketOwnerAccountId"] = owner
        return {
            "dataSource": {
                "dataSourceId": data_source_id,
                "name": name,
                "dataSourceConfiguration": configuration,
            }
        }

    def _two_bucket_estate(self, **overrides):
        """Two knowledge bases, one bucket each: the fixture that discriminates."""
        kwargs = {
            "knowledge_bases": [
                {"knowledgeBaseId": "kb-1", "name": "support-kb"},
                {"knowledgeBaseId": "kb-2", "name": "hr-kb"},
            ],
            "data_sources": {
                "kb-1": [{"dataSourceId": "ds-1", "name": "support-docs"}],
                "kb-2": [{"dataSourceId": "ds-2", "name": "hr-docs"}],
            },
            "data_source_detail": {
                "ds-1": self._s3_source("ds-1", "support-docs", "support-bucket"),
                "ds-2": self._s3_source("ds-2", "hr-docs", "hr-bucket"),
            },
        }
        kwargs.update(overrides)
        return self._run(**kwargs)

    def test_br46_monitored_and_unmonitored_buckets_discriminate(self):
        findings = self._two_bucket_estate(
            macie_buckets=[
                {
                    "bucketName": "support-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                    "lastAutomatedDiscoveryTime": "2026-09-01T00:00:00Z",
                    "sensitivityScore": 42,
                },
                {
                    "bucketName": "hr-bucket",
                    "automatedDiscoveryMonitoringStatus": "NOT_MONITORED",
                },
            ]
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert failed[0]["Check_ID"] == "BR-46"
        assert "hr-bucket is NOT_MONITORED" in failed[0]["Finding_Details"]
        assert (
            "data source 'hr-docs' in knowledge base 'hr-kb'"
            in (failed[0]["Finding_Details"])
        )
        assert len(passed) == 1
        assert "support-bucket is MONITORED" in passed[0]["Finding_Details"]
        assert "sensitivity score 42" in passed[0]["Finding_Details"]
        assert "1 of 2 knowledge base source bucket(s)" in passed[0]["Finding_Details"]

    def test_br46_monitored_account_bucket_no_knowledge_base_uses_is_not_counted(self):
        """The Macie inventory is wider than the source set on any real account."""
        findings = self._two_bucket_estate(
            macie_buckets=[
                {
                    "bucketName": "support-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                },
                {
                    "bucketName": "hr-bucket",
                    "automatedDiscoveryMonitoringStatus": "NOT_MONITORED",
                },
                {
                    "bucketName": "unrelated-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                },
            ]
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "hr-bucket is NOT_MONITORED" in failed[0]["Finding_Details"]
        assert len(passed) == 1
        # The denominator counts knowledge base source buckets, not the account's
        # buckets, so a third monitored bucket cannot inflate it.
        assert "1 of 2 knowledge base source bucket(s)" in passed[0]["Finding_Details"]
        assert not any("unrelated-bucket" in f["Finding_Details"] for f in findings)

    def test_br46_unmonitored_source_fails_while_another_bucket_is_monitored(self):
        findings = self._run(
            knowledge_bases=[{"knowledgeBaseId": "kb-2", "name": "hr-kb"}],
            data_sources={"kb-2": [{"dataSourceId": "ds-2", "name": "hr-docs"}]},
            data_source_detail={
                "ds-2": self._s3_source("ds-2", "hr-docs", "hr-bucket")
            },
            macie_buckets=[
                {
                    "bucketName": "unrelated-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                },
                {
                    "bucketName": "hr-bucket",
                    "automatedDiscoveryMonitoringStatus": "NOT_MONITORED",
                },
            ],
        )

        # Discovery being on and some bucket being monitored is not coverage of the
        # one bucket a knowledge base ingests from, so there is no Passed here.
        assert [f["Status"] for f in findings] == ["Failed"]
        assert "hr-bucket is NOT_MONITORED" in findings[0]["Finding_Details"]
        assert (
            "data source 'hr-docs' in knowledge base 'hr-kb'"
            in (findings[0]["Finding_Details"])
        )
        assert "unrelated-bucket" not in findings[0]["Finding_Details"]

    def test_br46_macie_not_enabled_is_not_a_bucket_failure(self):
        findings = self._two_bucket_estate(
            session_error=_make_client_error(
                "AccessDeniedException", "Macie is not enabled"
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "Amazon Macie is not enabled" in findings[0]["Finding_Details"]
        assert "FS-44" in findings[0]["Finding_Details"]
        assert "support-bucket" in findings[0]["Finding_Details"]

    def test_br46_missing_macie_grant_is_a_permissions_finding(self):
        findings = self._two_bucket_estate(
            session_error=_make_client_error(
                "AccessDeniedException", "User is not authorized to perform this action"
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "permissions or availability problem" in findings[0]["Finding_Details"]
        assert "FS-44" not in findings[0]["Finding_Details"]
        assert "macie2:GetMacieSession" in findings[0]["Resolution"]

    def test_br46_discovery_disabled_is_not_a_bucket_failure(self):
        findings = self._two_bucket_estate(discovery_status="DISABLED")

        assert [f["Status"] for f in findings] == ["N/A"]
        assert (
            "automated sensitive data discovery is DISABLED"
            in findings[0]["Finding_Details"]
        )
        assert "FS-44" in findings[0]["Finding_Details"]

    def test_br46_bucket_error_code_is_indeterminate_not_failed(self):
        findings = self._two_bucket_estate(
            macie_buckets=[
                {
                    "bucketName": "support-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                },
                {
                    "bucketName": "hr-bucket",
                    "automatedDiscoveryMonitoringStatus": "NOT_MONITORED",
                    "errorCode": "ACCESS_DENIED",
                },
            ]
        )

        assert not [f for f in findings if f["Status"] == "Failed"]
        indeterminate = [f for f in findings if f["Status"] == "N/A"]
        assert len(indeterminate) == 1
        assert (
            "hr-bucket reports Macie errorCode ACCESS_DENIED"
            in (indeterminate[0]["Finding_Details"])
        )

    def test_br46_bucket_absent_from_inventory_is_not_compliant(self):
        findings = self._run(
            knowledge_bases=[{"knowledgeBaseId": "kb-1", "name": "support-kb"}],
            data_sources={"kb-1": [{"dataSourceId": "ds-1", "name": "support-docs"}]},
            data_source_detail={
                "ds-1": self._s3_source(
                    "ds-1", "support-docs", "other-account-bucket", owner="210987654321"
                )
            },
            macie_buckets=[
                {
                    "bucketName": "unrelated-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                }
            ],
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert (
            "other-account-bucket is absent from this Region's Macie bucket"
            in (findings[0]["Finding_Details"])
        )
        assert "bucket owner account 210987654321" in findings[0]["Finding_Details"]

    def test_br46_non_s3_data_source_is_out_of_macie_scope(self):
        findings = self._run(
            knowledge_bases=[{"knowledgeBaseId": "kb-1", "name": "web-kb"}],
            data_sources={"kb-1": [{"dataSourceId": "ds-1", "name": "crawler"}]},
            data_source_detail={
                "ds-1": {
                    "dataSource": {
                        "dataSourceId": "ds-1",
                        "name": "crawler",
                        "dataSourceConfiguration": {"type": "WEB"},
                    }
                }
            },
        )

        assert [f["Status"] for f in findings] == ["N/A", "N/A"]
        assert "ingests from WEB" in findings[0]["Finding_Details"]
        assert (
            "none of them ingests from an S3 bucket" in findings[1]["Finding_Details"]
        )

    def test_br46_data_source_read_failure_is_reported_as_partial(self):
        findings = self._two_bucket_estate(
            data_source_error=_make_client_error("AccessDeniedException"),
        )

        assert [f["Status"] for f in findings] == ["N/A", "N/A"]
        assert "data source read(s) failed" in findings[0]["Finding_Details"]
        assert "bedrock:ListDataSources" in findings[0]["Resolution"]

    def test_br46_describe_buckets_failure_is_not_absence(self):
        findings = self._two_bucket_estate(
            describe_buckets_error=_make_client_error("AccessDeniedException"),
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert (
            "Macie bucket inventory could not be read"
            in (findings[0]["Finding_Details"])
        )
        assert "macie2:DescribeBuckets" in findings[0]["Resolution"]

    def test_br46_no_knowledge_base_returns_na(self):
        findings = self._run()

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "no source bucket to classify" in findings[0]["Finding_Details"]

    def test_br46_unknown_monitoring_status_is_indeterminate(self):
        findings = self._two_bucket_estate(
            macie_buckets=[
                {
                    "bucketName": "support-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                },
                {"bucketName": "hr-bucket"},
            ]
        )

        indeterminate = [f for f in findings if f["Status"] == "N/A"]
        assert not [f for f in findings if f["Status"] == "Failed"]
        assert (
            "automatedDiscoveryMonitoringStatus 'unset'"
            in (indeterminate[0]["Finding_Details"])
        )

    def test_br46_describe_cap_bounds_the_fan_out_and_still_reports(self):
        """55 data sources across two knowledge bases, one GetDataSource each."""
        cap = bedrock_app.MAX_KNOWLEDGE_BASE_DATA_SOURCE_DESCRIBES
        first_kb, second_kb = 30, 25
        assert first_kb + second_kb > cap

        summaries = {"kb-1": [], "kb-2": []}
        detail = {}
        for index in range(first_kb + second_kb):
            data_source_id = f"ds-{index:03d}"
            kb_id = "kb-1" if index < first_kb else "kb-2"
            summaries[kb_id].append(
                {"dataSourceId": data_source_id, "name": f"docs-{index:03d}"}
            )
            detail[data_source_id] = self._s3_source(
                data_source_id, f"docs-{index:03d}", f"bucket-{index:03d}"
            )

        findings = self._run(
            knowledge_bases=[
                {"knowledgeBaseId": "kb-1", "name": "first-kb"},
                {"knowledgeBaseId": "kb-2", "name": "second-kb"},
            ],
            data_sources=summaries,
            data_source_detail=detail,
            macie_buckets=[
                {
                    "bucketName": f"bucket-{index:03d}",
                    "automatedDiscoveryMonitoringStatus": (
                        "NOT_MONITORED" if index == 0 else "MONITORED"
                    ),
                }
                for index in range(first_kb + second_kb)
            ],
        )

        assert self.last_agent_client.get_data_source.call_count == cap

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        truncation = [
            f
            for f in findings
            if f"stopped after {cap} data sources" in (f["Finding_Details"])
        ]
        # The cap bounds the walk without dropping the verdict for what was walked.
        assert len(failed) == 1
        assert "bucket-000 is NOT_MONITORED" in failed[0]["Finding_Details"]
        assert len(passed) == 1
        assert (
            f"{cap - 1} of {cap} knowledge base source bucket(s)"
            in (passed[0]["Finding_Details"])
        )
        assert len(truncation) == 1
        assert truncation[0]["Status"] == "N/A"
        # A source past the cap was never resolved, so it appears nowhere.
        assert not any("bucket-054" in f["Finding_Details"] for f in findings)

    def test_br46_schema_valid(self):
        findings = self._two_bucket_estate(
            macie_buckets=[
                {
                    "bucketName": "support-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                },
                {
                    "bucketName": "hr-bucket",
                    "automatedDiscoveryMonitoringStatus": "NOT_MONITORED",
                },
            ]
        )
        assert findings
        for finding in findings:
            assert_finding_schema(finding)


# ===================================================================
# BR-16: check_bedrock_guardrail_tier
# ===================================================================
class TestBR16GuardrailTier:
    """BR-16: Verify guardrails use Standard tier."""

    @patch("bedrock_app.boto3.client")
    def test_br16_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-16"

    @patch("bedrock_app.boto3.client")
    def test_br16_standard_tier_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr-123", "name": "test-guardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {"contentPolicy": {"tier": {"tierName": "STANDARD"}}}
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        passed_findings = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed_findings) >= 1
        assert passed_findings[0]["Check_ID"] == "BR-16"

    @patch("bedrock_app.boto3.client")
    def test_br16_absent_tier_returns_na_without_assuming_classic(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr-123", "name": "tierless-guardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {"contentPolicy": {"filters": []}}
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "tier unknown" in findings[0]["Finding_Details"]
        assert "not assumed to be CLASSIC" in findings[0]["Finding_Details"]
        assert (
            "is using the 'CLASSIC' content-filter tier"
            not in findings[0]["Finding_Details"]
        )

    @patch("bedrock_app.boto3.client")
    def test_br16_non_standard_tier_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr-123", "name": "classic-guardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {"contentPolicy": {"tier": {"tierName": "CLASSIC"}}}
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-16"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.boto3.client")
    def test_br16_access_denied_returns_incomplete_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListGuardrails"
        )
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert findings[0]["Check_ID"] == "BR-16"

    @patch("bedrock_app.boto3.client")
    def test_br16_paginates_and_continues_when_one_guardrail_detail_fails(
        self, mock_client
    ):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.side_effect = [
            {
                "guardrails": [{"id": "gr-error", "name": "DeletedGuardrail"}],
                "nextToken": "page-2",
            },
            {
                "guardrails": [{"id": "gr-ok", "name": "StandardGuardrail"}],
            },
        ]
        bedrock_client.get_guardrail.side_effect = [
            ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}},
                "GetGuardrail",
            ),
            {"guardrail": {"contentPolicy": {"tier": {"tierName": "STANDARD"}}}},
        ]
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        statuses = [f["Status"] for f in findings]

        assert bedrock_client.list_guardrails.call_count == 2
        assert "N/A" in statuses
        assert "Passed" in statuses
        unassessed = [f for f in findings if "DeletedGuardrail" in f["Finding_Details"]]
        assert unassessed
        assert unassessed[0]["Severity"] == "Informational"

    def test_br16_schema_valid(self):
        check = bedrock_app.check_bedrock_guardrail_tier
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-17: check_bedrock_custom_model_kms_encryption
# ===================================================================
class TestBR17CustomModelKMSEncryption:
    """BR-17: Verify custom models use customer-managed KMS keys."""

    @patch("bedrock_app.boto3.client")
    def test_br17_no_custom_models_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption

        bedrock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"modelSummaries": []}]
        bedrock_client.get_paginator.return_value = paginator
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-17"

    @patch("bedrock_app.boto3.client")
    def test_br17_customer_managed_kms_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption

        bedrock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "modelSummaries": [
                    {
                        "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/my-model",
                        "modelName": "my-model",
                    }
                ]
            }
        ]
        bedrock_client.get_paginator.return_value = paginator
        bedrock_client.get_custom_model.return_value = {
            "modelKmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc-123"
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        passed_findings = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed_findings) >= 1
        assert passed_findings[0]["Check_ID"] == "BR-17"

    @patch("bedrock_app.boto3.client")
    def test_br17_aws_owned_keys_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption

        bedrock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "modelSummaries": [
                    {
                        "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/my-model",
                        "modelName": "my-model",
                    }
                ]
            }
        ]
        bedrock_client.get_paginator.return_value = paginator
        # No KMS key ID = AWS-owned key
        bedrock_client.get_custom_model.return_value = {}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-17"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br17_access_denied_returns_incomplete_na(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption

        bedrock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListCustomModels"
        )
        bedrock_client.get_paginator.return_value = paginator
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert findings[0]["Check_ID"] == "BR-17"

    def test_br17_schema_valid(self):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [{"modelSummaries": []}]
            bedrock_client.get_paginator.return_value = paginator
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-18: check_bedrock_model_evaluations
# ===================================================================
class TestBR18ModelEvaluations:
    """BR-18: Check if model evaluation jobs exist."""

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br18_no_evaluations_with_footprint_returns_failed(
        self, mock_client, mock_footprint
    ):
        check = bedrock_app.check_bedrock_model_evaluations

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.return_value = {"jobSummaries": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-18"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    @patch("bedrock_app.boto3.client")
    def test_br18_no_evaluations_no_footprint_returns_na(
        self, mock_client, mock_footprint
    ):
        check = bedrock_app.check_bedrock_model_evaluations

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.return_value = {"jobSummaries": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-18"

    @patch("bedrock_app.boto3.client")
    def test_br18_recent_evaluations_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_model_evaluations

        from datetime import datetime, timezone, timedelta

        recent_time = datetime.now(timezone.utc) - timedelta(days=10)

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.return_value = {
            "jobSummaries": [
                {
                    "jobName": "eval-job-1",
                    "status": "Completed",
                    "creationTime": recent_time,
                }
            ]
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        passed_findings = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed_findings) >= 1
        assert passed_findings[0]["Check_ID"] == "BR-18"

    @patch("bedrock_app.boto3.client")
    def test_br18_stale_evaluations_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_model_evaluations

        from datetime import datetime, timezone, timedelta

        stale_time = datetime.now(timezone.utc) - timedelta(days=60)

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.return_value = {
            "jobSummaries": [
                {
                    "jobName": "eval-job-old",
                    "status": "Completed",
                    "creationTime": stale_time,
                }
            ]
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-18"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.boto3.client")
    def test_br18_unknown_operation_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_model_evaluations

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.side_effect = ClientError(
            {"Error": {"Code": "UnknownOperation", "Message": "Unknown operation"}},
            "ListEvaluationJobs",
        )
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-18"

    @patch("bedrock_app.boto3.client")
    def test_br18_access_denied_returns_incomplete_na(self, mock_client):
        check = bedrock_app.check_bedrock_model_evaluations

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListEvaluationJobs"
        )
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert findings[0]["Check_ID"] == "BR-18"

    @patch("bedrock_app.boto3.client")
    def test_br18_account_not_authorized_returns_na(self, mock_client):
        # Account/feature-gate denial (model evaluation not enabled) must be N/A.
        check = bedrock_app.check_bedrock_model_evaluations

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Your account is not authorized to invoke this API operation.",
                }
            },
            "ListEvaluationJobs",
        )
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-18"

    def test_br18_schema_valid(self):
        check = bedrock_app.check_bedrock_model_evaluations
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_evaluation_jobs.return_value = {"jobSummaries": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-19: check_bedrock_prompt_flow_validation
# ===================================================================
class TestBR19PromptFlowValidation:
    """BR-19: Verify prompt flows are validated using GetFlow validations."""

    @patch("bedrock_app.boto3.client")
    def test_br19_no_flows_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        agent_client = MagicMock()
        agent_client.list_flows.return_value = {"flowSummaries": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-19"

    @patch("bedrock_app.boto3.client")
    def test_br19_prepared_flow_no_errors_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        agent_client = MagicMock()
        agent_client.list_flows.return_value = {
            "flowSummaries": [{"id": "f1", "name": "GoodFlow", "status": "Prepared"}]
        }
        agent_client.get_flow.return_value = {"validations": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-19"

    @patch("bedrock_app.boto3.client")
    def test_br19_flow_with_error_validation_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        agent_client = MagicMock()
        agent_client.list_flows.return_value = {
            "flowSummaries": [{"id": "f1", "name": "BadFlow", "status": "Prepared"}]
        }
        agent_client.get_flow.return_value = {
            "validations": [{"severity": "ERROR", "message": "Node X is not connected"}]
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-19"
        assert "Node X is not connected" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br19_unprepared_flow_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        agent_client = MagicMock()
        agent_client.list_flows.return_value = {
            "flowSummaries": [
                {"id": "f1", "name": "DraftFlow", "status": "NotPrepared"}
            ]
        }
        agent_client.get_flow.return_value = {"validations": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-19"

    def test_br19_schema_valid(self):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        with patch("bedrock_app.boto3.client") as mock_client:
            agent_client = MagicMock()
            agent_client.list_flows.return_value = {"flowSummaries": []}
            mock_client.return_value = agent_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-20: check_bedrock_knowledge_base_kms_encryption
# ===================================================================
class TestBR20KnowledgeBaseKMS:
    """BR-20: Verify managed KB customer-managed KMS encryption."""

    @patch("bedrock_app.boto3.client")
    def test_br20_no_kbs_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-20"

    @patch("bedrock_app.boto3.client")
    def test_br20_managed_kb_with_cmk_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "ManagedKB"}]
        }
        agent_client.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "knowledgeBaseConfiguration": {
                    "type": "MANAGED",
                    "managedKnowledgeBaseConfiguration": {
                        "serverSideEncryptionConfiguration": {
                            "kmsKeyArn": "arn:aws:kms:us-east-1:123:key/abc"
                        }
                    },
                }
            }
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-20"

    @patch("bedrock_app.boto3.client")
    def test_br20_managed_kb_without_cmk_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "ManagedKB"}]
        }
        agent_client.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "knowledgeBaseConfiguration": {
                    "type": "MANAGED",
                    "managedKnowledgeBaseConfiguration": {},
                }
            }
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-20"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br20_managed_kb_sdk_gap_returns_na(self, mock_client):
        # A MANAGED knowledge base whose managedKnowledgeBaseConfiguration block is
        # absent (bundled botocore predates the field, < 1.43.32) must surface as
        # N/A "indeterminate", not a false-positive Failed.
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "ManagedKB"}]
        }
        agent_client.get_knowledge_base.return_value = {
            "knowledgeBase": {"knowledgeBaseConfiguration": {"type": "MANAGED"}}
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        na = [f for f in findings if f["Status"] == "N/A"]
        assert len(na) >= 1
        assert na[0]["Check_ID"] == "BR-20"
        assert "1.43.32" in na[0]["Finding_Details"]
        # Must NOT be reported as a failure on incomplete data.
        assert all(f["Status"] != "Failed" for f in findings)

    @patch("bedrock_app.boto3.client")
    def test_br20_custom_vector_store_returns_na_review(self, mock_client):
        # Custom vector stores (no managed config) cannot be validated from the
        # KB API; they are flagged for manual review, not failed.
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "VectorKB"}]
        }
        agent_client.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "knowledgeBaseConfiguration": {
                    "type": "VECTOR",
                    "vectorKnowledgeBaseConfiguration": {},
                },
                "storageConfiguration": {"type": "OPENSEARCH_SERVERLESS"},
            }
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        na = [f for f in findings if f["Status"] == "N/A"]
        assert len(na) >= 1
        assert na[0]["Check_ID"] == "BR-20"
        assert "storage layer" in na[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br20_region_unsupported_returns_na(self, mock_client):
        # Knowledge Bases API absent in the region -> N/A, not ERROR.
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.side_effect = ClientError(
            {
                "Error": {
                    "Code": "UnknownOperationException",
                    "Message": "Unknown operation ListKnowledgeBases",
                }
            },
            "ListKnowledgeBases",
        )
        mock_client.return_value = agent_client

        result = check(region="ap-southeast-3")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-20"
        assert "not available" in findings[0]["Finding_Details"]

    def test_br20_schema_valid(self):
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        with patch("bedrock_app.boto3.client") as mock_client:
            agent_client = MagicMock()
            agent_client.list_knowledge_bases.return_value = {
                "knowledgeBaseSummaries": []
            }
            mock_client.return_value = agent_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-20, S3 Vectors leg: the vector bucket behind an S3_VECTORS
# knowledge base is readable, so the check asserts on it instead of
# deferring to manual review.
#
# What motivated the branch: while S3_VECTORS fell through to manual
# review, a read-only probe found 9 of 9 knowledge bases on S3_VECTORS
# and BR-20 emitted 9 findings, all 9 N/A -- a covered control
# producing a verdict for zero resources. The cases below pin what the
# check does with each input shape. What an account holds is measured
# in aisf-parity/LIVE-FIXTURES.md and is not asserted here; the
# previous version of this header described one account's vector
# buckets in the present tense, and a case below now contradicts it.
# ===================================================================
class TestBR20S3VectorsStore:
    """BR-20: assess the S3 Vectors bucket holding a knowledge base."""

    _BUCKET_ARN = "arn:aws:s3vectors:us-east-1:123456789012:bucket/kb-vectors"
    _CMK = {
        "sseType": "aws:kms",
        "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc",
    }

    @staticmethod
    def _client_error(code, operation):
        return ClientError({"Error": {"Code": code, "Message": code}}, operation)

    @staticmethod
    def _s3_vectors_kb_body(bucket_arn):
        """A VECTOR knowledge base whose storage is an S3 Vectors bucket."""
        storage = {"type": "S3_VECTORS"}
        if bucket_arn is not None:
            storage["s3VectorsConfiguration"] = {"vectorBucketArn": bucket_arn}
        return {
            "knowledgeBaseConfiguration": {
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {},
            },
            "storageConfiguration": storage,
        }

    @staticmethod
    def _agent_client_for(bodies):
        """bodies: {kb_id: knowledgeBase body}, answered per knowledgeBaseId."""
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": kb_id, "name": f"KB-{kb_id}"} for kb_id in bodies
            ]
        }
        agent_client.get_knowledge_base.side_effect = lambda **kwargs: {
            "knowledgeBase": bodies[kwargs["knowledgeBaseId"]]
        }
        return agent_client

    @staticmethod
    def _vectors_client(
        encryption=None, bucket_error=None, policy="", policy_error=None
    ):
        vectors_client = MagicMock()
        if bucket_error is not None:
            vectors_client.get_vector_bucket.side_effect = bucket_error
        else:
            # GetVectorBucket nests the encryption under `vectorBucket`, and
            # echoes the ARN it was asked for. Answering from the keyword also
            # asserts the call passes `vectorBucketArn` rather than a positional.
            vectors_client.get_vector_bucket.side_effect = lambda **kwargs: {
                "vectorBucket": {
                    "vectorBucketArn": kwargs["vectorBucketArn"],
                    "encryptionConfiguration": encryption or {},
                }
            }
        if policy_error is not None:
            vectors_client.get_vector_bucket_policy.side_effect = policy_error
        else:
            vectors_client.get_vector_bucket_policy.return_value = {"policy": policy}
        return vectors_client

    @staticmethod
    def _by_service(agent_client, vectors_client, clients_built):
        """Dispatch boto3.client by service name, recording each construction.

        Every other test in this file hands one MagicMock to every boto3.client
        call, which cannot express "bedrock-agent answers while s3vectors
        raises", and cannot show which region the s3vectors client was built
        for. `vectors_client` may be an Exception, for the case where the
        deployed SDK has no s3vectors model at all.
        """

        def factory(service_name, *_args, **kwargs):
            clients_built.append((service_name, kwargs.get("region_name")))
            if service_name != "s3vectors":
                return agent_client
            if isinstance(vectors_client, Exception):
                raise vectors_client
            return vectors_client

        return factory

    def _run_one(
        self, mock_client, *, bucket_arn=_BUCKET_ARN, scan_region="us-east-1", **vectors
    ):
        """Run BR-20 over a single S3 Vectors knowledge base.

        Returns (findings, clients_built).
        """
        clients_built = []
        mock_client.side_effect = self._by_service(
            self._agent_client_for({"kb1": self._s3_vectors_kb_body(bucket_arn)}),
            self._vectors_client(**vectors),
            clients_built,
        )
        result = bedrock_app.check_bedrock_knowledge_base_kms_encryption(
            region=scan_region
        )
        return extract_csv_data(result), clients_built

    def _run_population(self, mock_client, stores):
        """Run BR-20 over several S3 Vectors knowledge bases at once.

        `stores` is an ordered list of (kb_id, bucket_arn, encryption, policy),
        answered per bucket ARN. A policy that is an Exception is raised, which
        is how "no bucket policy exists" arrives. The order is preserved in the
        findings, so a case can place a chosen verdict last.
        """
        encryption = {arn: enc for _, arn, enc, _ in stores}
        policies = {arn: policy for _, arn, _, policy in stores}

        def get_policy(**kwargs):
            answer = policies[kwargs["vectorBucketArn"]]
            if isinstance(answer, Exception):
                raise answer
            return answer

        vectors_client = MagicMock()
        vectors_client.get_vector_bucket.side_effect = lambda **kwargs: {
            "vectorBucket": {
                "vectorBucketArn": kwargs["vectorBucketArn"],
                "encryptionConfiguration": encryption[kwargs["vectorBucketArn"]],
            }
        }
        vectors_client.get_vector_bucket_policy.side_effect = get_policy
        mock_client.side_effect = self._by_service(
            self._agent_client_for(
                {kb: self._s3_vectors_kb_body(arn) for kb, arn, _, _ in stores}
            ),
            vectors_client,
            [],
        )
        return extract_csv_data(
            bedrock_app.check_bedrock_knowledge_base_kms_encryption(region="us-east-1")
        )

    @staticmethod
    def _sse_s3_stores(policy, count=9):
        """`count` stores on SSE-S3, each answered with the same policy result."""
        return [
            (
                f"kb{i}",
                f"arn:aws:s3vectors:us-east-1:123456789012:bucket/b{i}",
                {"sseType": "AES256"},
                policy,
            )
            for i in range(1, count + 1)
        ]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_sse_s3_without_a_policy_returns_failed(self, mock_client):
        # The live shape. AES256 is SSE-S3: encrypted, but not with a
        # customer-managed key, which is the bar every other BR-20 storage type
        # is held to. NotFoundException means no bucket policy exists.
        findings, _ = self._run_one(
            mock_client,
            encryption={"sseType": "AES256"},
            policy_error=self._client_error(
                "NotFoundException", "GetVectorBucketPolicy"
            ),
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Check_ID"] == "BR-20"
        assert findings[0]["Severity"] == "High"
        assert "sseType=AES256" in findings[0]["Finding_Details"]
        assert "no vector bucket policy is attached" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_cmk_with_a_policy_returns_passed(self, mock_client):
        findings, _ = self._run_one(
            mock_client, encryption=self._CMK, policy='{"Statement": []}'
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert findings[0]["Severity"] == "Medium"
        assert self._CMK["kmsKeyArn"] in findings[0]["Finding_Details"]
        # The index carries its own encryptionConfiguration, which this check
        # does not read. A Passed row that did not say so would overclaim.
        assert "Index-level encryption overrides" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_missing_policy_fails_and_is_never_na(self, mock_client):
        # Encryption passes, so the verdict turns entirely on the policy leg:
        # if NotFoundException were laundered into N/A, this row would be N/A.
        # It is not a could-not-assess -- the answer was read successfully and
        # the answer is "no policy".
        findings, _ = self._run_one(
            mock_client,
            encryption=self._CMK,
            policy_error=self._client_error(
                "NotFoundException", "GetVectorBucketPolicy"
            ),
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Severity"] == "High"
        assert "customer-managed key" in findings[0]["Finding_Details"]
        assert "NotFoundException" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_empty_policy_response_returns_failed(self, mock_client):
        findings, _ = self._run_one(mock_client, encryption=self._CMK, policy="")
        assert [f["Status"] for f in findings] == ["Failed"]
        assert "empty policy" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_bucket_access_denied_names_the_permission(
        self, mock_client
    ):
        # A permission gap is neither a pass nor a fail. It must stay visible as
        # a could-not-assess that names the action, or the deployment looks
        # compliant because it cannot see.
        findings, _ = self._run_one(
            mock_client,
            bucket_error=self._client_error("AccessDeniedException", "GetVectorBucket"),
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Severity"] == "Informational"
        assert "s3vectors:GetVectorBucket" in findings[0]["Finding_Details"]
        assert findings[0]["Finding"].endswith("Review")

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_policy_access_denied_does_not_pass_on_one_leg(
        self, mock_client
    ):
        findings, _ = self._run_one(
            mock_client,
            encryption=self._CMK,
            policy_error=self._client_error(
                "AccessDeniedException", "GetVectorBucketPolicy"
            ),
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "s3vectors:GetVectorBucketPolicy" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_failed_encryption_outranks_an_unreadable_policy(
        self, mock_client
    ):
        # One leg read and failing is a verdict. Downgrading it to N/A because
        # the second leg was unreadable would hide a confirmed failure behind a
        # permission gap.
        findings, _ = self._run_one(
            mock_client,
            encryption={"sseType": "AES256"},
            policy_error=self._client_error(
                "AccessDeniedException", "GetVectorBucketPolicy"
            ),
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_client_is_built_for_the_bucket_region(self, mock_client):
        # A knowledge base can point at a vector bucket in another region. A
        # client built for the scan region fails on a perfectly readable bucket.
        findings, clients_built = self._run_one(
            mock_client,
            bucket_arn="arn:aws:s3vectors:eu-west-1:123456789012:bucket/kb-vectors",
            scan_region="us-east-1",
            encryption=self._CMK,
            policy='{"Statement": []}',
        )
        assert ("s3vectors", "eu-west-1") in clients_built
        assert ("s3vectors", "us-east-1") not in clients_built
        assert ("bedrock-agent", "us-east-1") in clients_built
        assert [f["Status"] for f in findings] == ["Passed"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_without_a_bucket_arn_returns_na(self, mock_client):
        findings, clients_built = self._run_one(mock_client, bucket_arn=None)
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "vectorBucketArn" in findings[0]["Finding_Details"]
        assert not [c for c in clients_built if c[0] == "s3vectors"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_unreadable_bucket_arn_returns_na(self, mock_client):
        findings, clients_built = self._run_one(mock_client, bucket_arn="kb-vectors")
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "readable region" in findings[0]["Finding_Details"]
        assert not [c for c in clients_built if c[0] == "s3vectors"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_does_not_defer_to_storage_layer_review(self, mock_client):
        # The regression this change fixes: S3_VECTORS used to fall through to
        # the generic "verify it at the storage layer" row, which is an N/A.
        findings, _ = self._run_one(
            mock_client,
            encryption={"sseType": "AES256"},
            policy_error=self._client_error(
                "NotFoundException", "GetVectorBucketPolicy"
            ),
        )
        assert all("storage layer" not in f["Finding_Details"] for f in findings)
        assert all(f["Status"] != "N/A" for f in findings)

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_emits_one_row_per_knowledge_base(self, mock_client):
        # Three knowledge bases, three verdicts. A single summary row, or a loop
        # that emitted only the first entry, would lose two of them, and the loss
        # grows with the population. How many knowledge bases an account holds is
        # measured in aisf-parity/LIVE-FIXTURES.md and is not claimed here.
        arns = {
            kb: f"arn:aws:s3vectors:us-east-1:123456789012:bucket/{kb}"
            for kb in ("kb1", "kb2", "kb3")
        }
        encryption = {
            arns["kb1"]: {"sseType": "AES256"},
            arns["kb2"]: self._CMK,
            arns["kb3"]: self._CMK,
        }
        policies = {
            arns["kb1"]: self._client_error(
                "NotFoundException", "GetVectorBucketPolicy"
            ),
            arns["kb2"]: {"policy": '{"Statement": []}'},
            arns["kb3"]: self._client_error(
                "AccessDeniedException", "GetVectorBucketPolicy"
            ),
        }

        def get_policy(**kwargs):
            answer = policies[kwargs["vectorBucketArn"]]
            if isinstance(answer, Exception):
                raise answer
            return answer

        vectors_client = MagicMock()
        vectors_client.get_vector_bucket.side_effect = lambda **kwargs: {
            "vectorBucket": {
                "encryptionConfiguration": encryption[kwargs["vectorBucketArn"]]
            }
        }
        vectors_client.get_vector_bucket_policy.side_effect = get_policy
        mock_client.side_effect = self._by_service(
            self._agent_client_for(
                {kb: self._s3_vectors_kb_body(arn) for kb, arn in arns.items()}
            ),
            vectors_client,
            [],
        )

        findings = extract_csv_data(
            bedrock_app.check_bedrock_knowledge_base_kms_encryption(region="us-east-1")
        )
        assert [f["Status"] for f in findings] == ["Failed", "Passed", "N/A"]
        for kb, finding in zip(arns, findings, strict=True):
            assert kb in finding["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_reaches_both_verdicts_over_one_population(
        self, mock_client
    ):
        # Ten stores in one account and region: nine on SSE-S3 with no bucket
        # policy, and one on a customer-managed key with a policy attached. What
        # this pins is one pass of the check's own loop reaching BOTH verdicts,
        # which no single-store case can show. The live counterpart of this mix,
        # the fixture that produces the Passed store, and its teardown are
        # recorded in aisf-parity/LIVE-FIXTURES.md, the file whose job is to be
        # re-measured; a fixture here cannot verify what any account holds.
        #
        # The Passed store is last on purpose. A consumer that keeps one status
        # per check id per account and region reads the trailing Passed and
        # drops the nine Failed rows, so this ordering is the one that tells
        # that collapse apart from a correct aggregation.
        stores = self._sse_s3_stores(
            self._client_error("NotFoundException", "GetVectorBucketPolicy")
        )
        stores.append(
            (
                "kb10",
                "arn:aws:s3vectors:us-east-1:123456789012:bucket/b10",
                self._CMK,
                {"policy": '{"Statement": []}'},
            )
        )

        findings = self._run_population(mock_client, stores)
        assert len(findings) == 10
        assert {f["Status"] for f in findings} == {"Failed", "Passed"}
        assert [f["Status"] for f in findings] == ["Failed"] * 9 + ["Passed"]
        cmk_rows = [
            f for f in findings if self._CMK["kmsKeyArn"] in f["Finding_Details"]
        ]
        assert len(cmk_rows) == 1
        assert cmk_rows[0] is findings[-1]
        assert "KB-kb10" in cmk_rows[0]["Finding_Details"]
        assert (
            len([f for f in findings if "sseType=AES256" in f["Finding_Details"]]) == 9
        )
        assert (
            len(
                [
                    f
                    for f in findings
                    if "no vector bucket policy is attached" in f["Finding_Details"]
                ]
            )
            == 9
        )

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_a_customer_managed_key_with_no_policy_is_failed(
        self, mock_client
    ):
        # The access leg is independent of the encryption leg across a whole
        # population: with no bucket policy anywhere, the customer-managed key
        # buys nothing, because a customer-managed key satisfies half of this
        # control and half is not a pass. Same mix as the case above, with the
        # tenth store's policy removed.
        no_policy = self._client_error("NotFoundException", "GetVectorBucketPolicy")
        stores = self._sse_s3_stores(no_policy)
        stores.append(
            (
                "kb10",
                "arn:aws:s3vectors:us-east-1:123456789012:bucket/b10",
                self._CMK,
                no_policy,
            )
        )

        findings = self._run_population(mock_client, stores)
        assert len(findings) == 10
        assert {f["Status"] for f in findings} == {"Failed"}
        assert all(
            "no vector bucket policy is attached" in f["Finding_Details"]
            for f in findings
        )
        cmk_rows = [
            f for f in findings if self._CMK["kmsKeyArn"] in f["Finding_Details"]
        ]
        assert len(cmk_rows) == 1
        assert (
            len([f for f in findings if "sseType=AES256" in f["Finding_Details"]]) == 9
        )

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_sdk_gap_costs_one_kb_not_the_region(self, mock_client):
        # An SDK with no s3vectors model raises at client construction. Without
        # the per-KB guard the outer handler replaces every row for the region
        # with one ERROR, including the managed knowledge base it could assess.
        bodies = {
            "kb1": self._s3_vectors_kb_body(self._BUCKET_ARN),
            "kb2": {
                "knowledgeBaseConfiguration": {
                    "type": "MANAGED",
                    "managedKnowledgeBaseConfiguration": {
                        "serverSideEncryptionConfiguration": {
                            "kmsKeyArn": self._CMK["kmsKeyArn"]
                        }
                    },
                }
            },
        }
        mock_client.side_effect = self._by_service(
            self._agent_client_for(bodies),
            UnknownServiceError(
                service_name="s3vectors", known_service_names=["s3", "s3control"]
            ),
            [],
        )

        findings = extract_csv_data(
            bedrock_app.check_bedrock_knowledge_base_kms_encryption(region="us-east-1")
        )
        statuses = [f["Status"] for f in findings]
        assert statuses.count("N/A") == 1
        assert statuses.count("Passed") == 1
        assert "Error during check" not in " ".join(
            f["Finding_Details"] for f in findings
        )

    @pytest.mark.parametrize(
        ("bucket_arn", "expected"),
        [
            ("arn:aws:s3vectors:us-east-1:123456789012:bucket/v", "us-east-1"),
            (
                "arn:aws-us-gov:s3vectors:us-gov-west-1:123456789012:bucket/v",
                "us-gov-west-1",
            ),
            ("arn:aws:s3:us-east-1:123456789012:bucket/v", ""),
            ("arn:aws:s3vectors::123456789012:bucket/v", ""),
            ("bucket/v", ""),
            ("", ""),
        ],
    )
    def test_vector_bucket_region_reads_the_arn(self, bucket_arn, expected):
        assert bedrock_app._vector_bucket_region(bucket_arn) == expected

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_schema_valid(self, mock_client):
        findings, _ = self._run_one(
            mock_client,
            encryption={"sseType": "AES256"},
            policy_error=self._client_error(
                "NotFoundException", "GetVectorBucketPolicy"
            ),
        )
        assert findings
        for f in findings:
            assert_finding_schema(f)


# ===================================================================
# BR-21: check_bedrock_agent_action_group_iam
# ===================================================================
class TestBR21AgentActionGroupIAM:
    """BR-21: Verify action-group Lambda roles follow least privilege."""

    @staticmethod
    def _agent_client_with_lambda_role(role_name):
        agent_client = MagicMock()
        agent_client.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "TestAgent"}]
        }
        agent_client.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {"actionGroupId": "ag1", "actionGroupName": "ActionGroup1"}
            ]
        }
        agent_client.get_agent_action_group.return_value = {
            "agentActionGroup": {
                "actionGroupExecutor": {
                    "lambda": "arn:aws:lambda:us-east-1:123:function:my-func"
                }
            }
        }
        lambda_client = MagicMock()
        lambda_client.get_function.return_value = {
            "Configuration": {"Role": f"arn:aws:iam::123456789012:role/{role_name}"}
        }
        return agent_client, lambda_client

    @patch("bedrock_app.boto3.client")
    def test_br21_no_agents_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        agent_client = MagicMock()
        agent_client.list_agents.return_value = {"agentSummaries": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1", permission_cache={"role_permissions": {}})
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-21"

    @patch("bedrock_app.boto3.client")
    def test_br21_admin_access_role_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        agent_client, lambda_client = self._agent_client_with_lambda_role("AdminRole")

        def factory(service, **kwargs):
            return lambda_client if service == "lambda" else agent_client

        mock_client.side_effect = factory

        cache = {
            "role_permissions": {
                "AdminRole": {
                    "attached_policies": [{"name": "AdministratorAccess"}],
                    "inline_policies": [],
                }
            }
        }
        result = check(region="us-east-1", permission_cache=cache)
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-21"
        assert "AdministratorAccess" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br21_wildcard_inline_policy_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        agent_client, lambda_client = self._agent_client_with_lambda_role("WildRole")

        def factory(service, **kwargs):
            return lambda_client if service == "lambda" else agent_client

        mock_client.side_effect = factory

        cache = {
            "role_permissions": {
                "WildRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "inline-wild",
                            "document": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "*",
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                }
            }
        }
        result = check(region="us-east-1", permission_cache=cache)
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-21"

    @patch("bedrock_app.boto3.client")
    def test_br21_scoped_role_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        agent_client, lambda_client = self._agent_client_with_lambda_role("ScopedRole")

        def factory(service, **kwargs):
            return lambda_client if service == "lambda" else agent_client

        mock_client.side_effect = factory

        cache = {
            "role_permissions": {
                "ScopedRole": {
                    "attached_policies": [{"name": "CustomScopedPolicy"}],
                    "inline_policies": [],
                }
            }
        }
        result = check(region="us-east-1", permission_cache=cache)
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-21"

    @patch("bedrock_app.boto3.client")
    def test_br21_region_unsupported_returns_na(self, mock_client):
        # Bedrock Agents API absent in the region -> N/A, not ERROR.
        check = bedrock_app.check_bedrock_agent_action_group_iam
        agent_client = MagicMock()
        agent_client.list_agents.side_effect = ClientError(
            {
                "Error": {
                    "Code": "UnknownOperationException",
                    "Message": "Unknown operation ListAgents",
                }
            },
            "ListAgents",
        )
        mock_client.return_value = agent_client

        result = check(
            region="ap-southeast-3", permission_cache={"role_permissions": {}}
        )
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-21"
        assert "not available" in findings[0]["Finding_Details"]

    def test_br21_schema_valid(self):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        with patch("bedrock_app.boto3.client") as mock_client:
            agent_client = MagicMock()
            agent_client.list_agents.return_value = {"agentSummaries": []}
            mock_client.return_value = agent_client
            result = check(
                region="us-east-1", permission_cache={"role_permissions": {}}
            )

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-23: check_bedrock_guardrail_content_filters
# ===================================================================
class TestBR23ContentFilters:
    """BR-23: Verify all content filters are enabled via contentPolicy.filters."""

    @staticmethod
    def _filters(types):
        return [
            {"type": t, "inputStrength": "HIGH", "outputStrength": "HIGH"}
            for t in types
        ]

    @patch("bedrock_app.boto3.client")
    def test_br23_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_content_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-23"

    @patch("bedrock_app.boto3.client")
    def test_br23_all_filters_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_content_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "FullGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "contentPolicy": {
                    "filters": self._filters(["HATE", "INSULTS", "SEXUAL", "VIOLENCE"])
                }
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-23"

    @patch("bedrock_app.boto3.client")
    def test_br23_missing_filters_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_content_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PartialGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "contentPolicy": {"filters": self._filters(["HATE", "VIOLENCE"])}
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-23"
        assert "INSULTS" in findings[0]["Finding_Details"]

    def test_br23_schema_valid(self):
        check = bedrock_app.check_bedrock_guardrail_content_filters
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-24: check_bedrock_automated_reasoning_policy
# ===================================================================
class TestBR24AutomatedReasoning:
    """BR-24: Verify Automated Reasoning policies via automatedReasoningPolicy."""

    @patch("bedrock_app.boto3.client")
    def test_br24_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_automated_reasoning_policy
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-24"

    @patch("bedrock_app.boto3.client")
    def test_br24_with_ar_policy_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_automated_reasoning_policy
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "VerifiedGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "automatedReasoningPolicy": {
                    "policies": [
                        "arn:aws:bedrock:us-east-1:123:automated-reasoning-policy/p1"
                    ]
                }
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-24"

    @patch("bedrock_app.boto3.client")
    def test_br24_without_ar_policy_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_automated_reasoning_policy
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PlainGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {"guardrail": {}}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-24"

    def test_br24_schema_valid(self):
        check = bedrock_app.check_bedrock_automated_reasoning_policy
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-25: check_bedrock_rag_evaluation_jobs
# ===================================================================
class TestBR25RAGEvaluationJobs:
    """BR-25: Verify RAG applications have evaluation jobs configured."""

    @patch("bedrock_app.boto3.client")
    def test_br25_no_kbs_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_rag_evaluation_jobs
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-25"

    @patch("bedrock_app.boto3.client")
    def test_br25_region_unsupported_returns_na(self, mock_client):
        # Knowledge Bases / evaluation API absent in the region -> N/A, not ERROR.
        check = bedrock_app.check_bedrock_rag_evaluation_jobs
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.side_effect = ClientError(
            {
                "Error": {
                    "Code": "UnknownOperationException",
                    "Message": "Unknown operation ListKnowledgeBases",
                }
            },
            "ListKnowledgeBases",
        )
        mock_client.return_value = agent_client

        result = check(region="ap-southeast-3")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-25"
        assert "not available" in findings[0]["Finding_Details"]

    def test_br25_schema_valid(self):
        check = bedrock_app.check_bedrock_rag_evaluation_jobs
        with patch("bedrock_app.boto3.client") as mock_client:
            agent_client = MagicMock()
            agent_client.list_knowledge_bases.return_value = {
                "knowledgeBaseSummaries": []
            }
            mock_client.return_value = agent_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-26: check_bedrock_guardrail_pii_filters
# ===================================================================
class TestBR26GuardrailPIIFilters:
    """BR-26: Verify guardrails configure sensitive-information (PII) filters."""

    @patch("bedrock_app.boto3.client")
    def test_br26_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-26"

    @patch("bedrock_app.boto3.client")
    def test_br26_pii_configured_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PiiGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "sensitiveInformationPolicy": {
                    "piiEntities": [{"type": "EMAIL", "action": "ANONYMIZE"}],
                    "regexes": [],
                }
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-26"

    @patch("bedrock_app.boto3.client")
    def test_br26_no_pii_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PlainGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "sensitiveInformationPolicy": {"piiEntities": [], "regexes": []}
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-26"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br26_access_denied_returns_incomplete_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListGuardrails"
        )
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert findings[0]["Check_ID"] == "BR-26"

    def test_br26_schema_valid(self):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-27: check_bedrock_guardrail_contextual_grounding
# ===================================================================
class TestBR27ContextualGrounding:
    """BR-27: Verify guardrails enable contextual grounding checks."""

    @patch("bedrock_app.boto3.client")
    def test_br27_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-27"

    @patch("bedrock_app.boto3.client")
    def test_br27_grounding_enabled_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "GroundedGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "contextualGroundingPolicy": {
                    "filters": [
                        {
                            "type": "GROUNDING",
                            "threshold": 0.75,
                            "action": "BLOCK",
                            "enabled": True,
                        },
                        {
                            "type": "RELEVANCE",
                            "threshold": 0.75,
                            "action": "BLOCK",
                            "enabled": True,
                        },
                    ]
                }
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-27"

    @patch("bedrock_app.boto3.client")
    def test_br27_no_grounding_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PlainGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {"contextualGroundingPolicy": {"filters": []}}
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-27"

    @staticmethod
    def _grounding_filters(grounding, relevance):
        filters = []
        if grounding is not None:
            filters.append(dict(grounding, type="GROUNDING", enabled=True))
        if relevance is not None:
            filters.append(dict(relevance, type="RELEVANCE", enabled=True))
        return {"guardrail": {"contextualGroundingPolicy": {"filters": filters}}}

    @patch("bedrock_app.boto3.client")
    def test_br27_reports_the_threshold_and_action_it_observed(self, mock_client):
        """AIR-BDR-GRD-09: both filter types must block inside the 0-0.99 range."""
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [
                {"id": "gr1", "name": "BlockingBoth"},
                {"id": "gr2", "name": "DetectOnlyRelevance"},
                {"id": "gr3", "name": "GroundingOnly"},
                {"id": "gr4", "name": "ZeroThreshold"},
            ]
        }
        bedrock_client.get_guardrail.side_effect = [
            self._grounding_filters(
                {"threshold": 0.85, "action": "BLOCK"},
                {"threshold": 0.7, "action": "BLOCK"},
            ),
            self._grounding_filters(
                {"threshold": 0.85, "action": "BLOCK"},
                {"threshold": 0.7, "action": "NONE"},
            ),
            self._grounding_filters({"threshold": 0.85, "action": "BLOCK"}, None),
            self._grounding_filters(
                {"threshold": 0.0, "action": "BLOCK"},
                {"threshold": 0.7, "action": "BLOCK"},
            ),
        ]
        mock_client.return_value = bedrock_client

        findings = extract_csv_data(check(region="us-east-1"))
        by_status = {}
        for finding in findings:
            by_status.setdefault(finding["Status"], []).append(finding)

        passed = by_status["Passed"]
        assert len(passed) == 1
        assert (
            "1 guardrails block on both GROUNDING and RELEVANCE"
            in passed[0]["Finding_Details"]
        )

        failed_details = {finding["Finding_Details"] for finding in by_status["Failed"]}
        assert len(failed_details) == 3
        detect_only = next(d for d in failed_details if "DetectOnlyRelevance" in d)
        assert "does not block on RELEVANCE" in detect_only
        assert "RELEVANCE threshold=0.7 action=NONE" in detect_only
        grounding_only = next(d for d in failed_details if "GroundingOnly" in d)
        assert "does not block on RELEVANCE" in grounding_only
        zero_threshold = next(d for d in failed_details if "ZeroThreshold" in d)
        assert "does not block on GROUNDING" in zero_threshold
        assert "GROUNDING threshold=0.0 action=BLOCK" in zero_threshold
        for finding in findings:
            assert_finding_schema(finding)

    @patch("bedrock_app.boto3.client")
    def test_br27_omitted_action_is_read_as_block(self, mock_client):
        """action postdates the filter, so an omitted action still blocks."""
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "LegacyGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = self._grounding_filters(
            {"threshold": 0.8}, {"threshold": 0.8}
        )
        mock_client.return_value = bedrock_client

        findings = extract_csv_data(check(region="us-east-1"))
        assert [f["Status"] for f in findings] == ["Passed"]

    def test_br27_schema_valid(self):
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-28: check_bedrock_agent_guardrail_association
# ===================================================================
class TestBR28AgentGuardrailAssociation:
    """BR-28: Verify agents have an associated guardrail."""

    @staticmethod
    def _agent_client(summaries):
        agent_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"agentSummaries": summaries}]
        agent_client.get_paginator.return_value = paginator
        return agent_client

    @patch("bedrock_app.boto3.client")
    def test_br28_no_agents_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_agent_guardrail_association
        mock_client.return_value = self._agent_client([])

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-28"

    @patch("bedrock_app.boto3.client")
    def test_br28_agent_with_guardrail_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_guardrail_association
        mock_client.return_value = self._agent_client(
            [
                {
                    "agentId": "a1",
                    "agentName": "SafeAgent",
                    "guardrailConfiguration": {
                        "guardrailIdentifier": "gr-1",
                        "guardrailVersion": "1",
                    },
                }
            ]
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-28"

    @patch("bedrock_app.boto3.client")
    def test_br28_agent_without_guardrail_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_guardrail_association
        mock_client.return_value = self._agent_client(
            [{"agentId": "a1", "agentName": "OpenAgent"}]
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-28"
        assert findings[0]["Severity"] == "High"

    def test_br28_schema_valid(self):
        check = bedrock_app.check_bedrock_agent_guardrail_association
        with patch("bedrock_app.boto3.client") as mock_client:
            mock_client.return_value = self._agent_client([])
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-29: check_bedrock_agent_idle_session_ttl
# ===================================================================
class TestBR29AgentIdleSessionTTL:
    """BR-29: Verify agent idle session TTL is within the recommended bound."""

    @staticmethod
    def _agent_client(summaries, get_agent_return=None):
        agent_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"agentSummaries": summaries}]
        agent_client.get_paginator.return_value = paginator
        if get_agent_return is not None:
            agent_client.get_agent.return_value = get_agent_return
        return agent_client

    @patch("bedrock_app.boto3.client")
    def test_br29_no_agents_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_agent_idle_session_ttl
        mock_client.return_value = self._agent_client([])

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-29"

    @patch("bedrock_app.boto3.client")
    def test_br29_short_ttl_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_idle_session_ttl
        mock_client.return_value = self._agent_client(
            [{"agentId": "a1", "agentName": "ShortAgent"}],
            {"agent": {"idleSessionTTLInSeconds": 600}},
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-29"

    @patch("bedrock_app.boto3.client")
    def test_br29_long_ttl_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_idle_session_ttl
        mock_client.return_value = self._agent_client(
            [{"agentId": "a1", "agentName": "LongAgent"}],
            {"agent": {"idleSessionTTLInSeconds": 7200}},
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-29"

    def test_br29_schema_valid(self):
        check = bedrock_app.check_bedrock_agent_idle_session_ttl
        with patch("bedrock_app.boto3.client") as mock_client:
            mock_client.return_value = self._agent_client([])
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-30: check_bedrock_imported_model_kms_encryption
# ===================================================================
class TestBR30ImportedModelKMS:
    """BR-30: Verify imported models use customer-managed KMS keys."""

    @staticmethod
    def _bedrock_client(summaries, get_return=None, list_side_effect=None):
        bedrock_client = MagicMock()
        paginator = MagicMock()
        if list_side_effect is not None:
            paginator.paginate.side_effect = list_side_effect
        else:
            paginator.paginate.return_value = [{"modelSummaries": summaries}]
        bedrock_client.get_paginator.return_value = paginator
        if get_return is not None:
            bedrock_client.get_imported_model.return_value = get_return
        return bedrock_client

    @patch("bedrock_app.boto3.client")
    def test_br30_no_models_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        mock_client.return_value = self._bedrock_client([])

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-30"

    @patch("bedrock_app.boto3.client")
    def test_br30_customer_key_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        mock_client.return_value = self._bedrock_client(
            [{"modelArn": "arn:model:1", "modelName": "imported-1"}],
            {"modelKmsKeyArn": "arn:aws:kms:us-east-1:123:key/abc"},
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-30"

    @patch("bedrock_app.boto3.client")
    def test_br30_aws_owned_key_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        mock_client.return_value = self._bedrock_client(
            [{"modelArn": "arn:model:1", "modelName": "imported-1"}],
            {},
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-30"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br30_access_denied_returns_incomplete_na(self, mock_client):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        mock_client.return_value = self._bedrock_client(
            [],
            list_side_effect=ClientError(
                {"Error": {"Code": "AccessDeniedException"}}, "ListImportedModels"
            ),
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert findings[0]["Check_ID"] == "BR-30"

    @patch("bedrock_app.boto3.client")
    def test_br30_account_not_authorized_returns_na(self, mock_client):
        # Account/feature-gate denial (Custom Model Import not enabled) must be
        # N/A, not a Failed finding telling the user to grant IAM permissions.
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        mock_client.return_value = self._bedrock_client(
            [],
            list_side_effect=ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "Your account is not authorized to invoke this API operation.",
                    }
                },
                "ListImportedModels",
            ),
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-30"

    def test_br30_schema_valid(self):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        with patch("bedrock_app.boto3.client") as mock_client:
            mock_client.return_value = self._bedrock_client([])
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-31: check_bedrock_batch_inference_output_encryption
# ===================================================================
class TestBR31BatchInferenceOutputEncryption:
    """BR-31: Verify batch inference jobs encrypt output with customer KMS."""

    @staticmethod
    def _bedrock_client(summaries, list_side_effect=None):
        bedrock_client = MagicMock()
        paginator = MagicMock()
        if list_side_effect is not None:
            paginator.paginate.side_effect = list_side_effect
        else:
            paginator.paginate.return_value = [{"invocationJobSummaries": summaries}]
        bedrock_client.get_paginator.return_value = paginator
        return bedrock_client

    @patch("bedrock_app.boto3.client")
    def test_br31_no_jobs_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_batch_inference_output_encryption
        mock_client.return_value = self._bedrock_client([])

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-31"

    @patch("bedrock_app.boto3.client")
    def test_br31_job_with_cmk_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_batch_inference_output_encryption
        mock_client.return_value = self._bedrock_client(
            [
                {
                    "jobName": "batch-1",
                    "outputDataConfig": {
                        "s3OutputDataConfig": {
                            "s3Uri": "s3://out/",
                            "s3EncryptionKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                        }
                    },
                }
            ]
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-31"

    @patch("bedrock_app.boto3.client")
    def test_br31_job_without_cmk_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_batch_inference_output_encryption
        mock_client.return_value = self._bedrock_client(
            [
                {
                    "jobName": "batch-1",
                    "outputDataConfig": {"s3OutputDataConfig": {"s3Uri": "s3://out/"}},
                }
            ]
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-31"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.boto3.client")
    def test_br31_account_not_authorized_returns_na(self, mock_client):
        # Account/feature-gate denial (batch inference not enabled) must be N/A.
        check = bedrock_app.check_bedrock_batch_inference_output_encryption
        mock_client.return_value = self._bedrock_client(
            [],
            list_side_effect=ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "Your account is not authorized to invoke this API operation.",
                    }
                },
                "ListModelInvocationJobs",
            ),
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-31"

    def test_br31_schema_valid(self):
        check = bedrock_app.check_bedrock_batch_inference_output_encryption
        with patch("bedrock_app.boto3.client") as mock_client:
            mock_client.return_value = self._bedrock_client([])
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-32: check_bedrock_cloudwatch_alarms
# ===================================================================
class TestBR32CloudWatchAlarms:
    """BR-32: Verify CloudWatch alarms exist on AWS/Bedrock metrics."""

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    @patch("bedrock_app.boto3.client")
    def test_br32_no_footprint_returns_na(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        result = check(region="eu-west-3")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-32"

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_bedrock_alarm_returns_passed(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        cw_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {"AlarmName": "bedrock-throttle", "Namespace": "AWS/Bedrock"}
                ]
            }
        ]
        cw_client.get_paginator.return_value = paginator
        mock_client.return_value = cw_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-32"

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_metric_math_alarm_returns_passed(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        cw_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "bedrock-tpm",
                        "Metrics": [
                            {"MetricStat": {"Metric": {"Namespace": "AWS/Bedrock"}}}
                        ],
                    }
                ]
            }
        ]
        cw_client.get_paginator.return_value = paginator
        mock_client.return_value = cw_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-32"

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_no_bedrock_alarm_returns_failed(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        cw_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"MetricAlarms": [{"AlarmName": "ec2-cpu", "Namespace": "AWS/EC2"}]}
        ]
        cw_client.get_paginator.return_value = paginator
        mock_client.return_value = cw_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-32"
        assert findings[0]["Severity"] == "Medium"

    @staticmethod
    def _alarm_clients(alarms, logging_config=None, metric_filters=None):
        """Build cloudwatch/bedrock/logs mocks for the intervention-signal leg."""
        cw_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"MetricAlarms": alarms}]
        cw_client.get_paginator.return_value = paginator

        bedrock_client = MagicMock()
        bedrock_client.get_model_invocation_logging_configuration.return_value = (
            {"loggingConfig": logging_config} if logging_config is not None else {}
        )

        logs_client = MagicMock()
        logs_client.describe_metric_filters.return_value = {
            "metricFilters": metric_filters or []
        }

        def client_factory(service, **kwargs):
            if service == "bedrock":
                return bedrock_client
            if service == "logs":
                return logs_client
            return cw_client

        return client_factory, logs_client

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_guardrail_namespace_alarm_reports_the_signal(
        self, mock_client, mock_footprint
    ):
        """AIR-BDR-GRD-04: an intervention alarm is a distinct signal from AWS/Bedrock."""
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        client_factory, _ = self._alarm_clients(
            [
                {"AlarmName": "bedrock-throttle", "Namespace": "AWS/Bedrock"},
                {
                    "AlarmName": "guardrail-intervened",
                    "Namespace": "AWS/Bedrock/Guardrails",
                },
            ]
        )
        mock_client.side_effect = client_factory

        findings = extract_csv_data(check(region="us-east-1"))
        signal = [
            f
            for f in findings
            if f["Finding"] == "Guardrail Intervention Monitoring Signal"
        ]
        assert len(signal) == 1
        assert signal[0]["Status"] == "Passed"
        assert (
            "1 CloudWatch alarm(s) on the AWS/Bedrock/Guardrails namespace "
            "(guardrail-intervened)" in signal[0]["Finding_Details"]
        )
        for finding in findings:
            assert_finding_schema(finding)

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_intervention_metric_filter_reports_the_signal(
        self, mock_client, mock_footprint
    ):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        client_factory, logs_client = self._alarm_clients(
            [{"AlarmName": "bedrock-throttle", "Namespace": "AWS/Bedrock"}],
            logging_config={
                "cloudWatchConfig": {
                    "logGroupName": "/aws/bedrock/invocations",
                    "roleArn": "arn:aws:iam::123456789012:role/BedrockLogs",
                }
            },
            metric_filters=[
                {
                    "filterName": "GuardrailIntervened",
                    "filterPattern": '{ $.["amazon-bedrock-guardrailAction"] = "INTERVENED" }',
                },
                {"filterName": "Unrelated", "filterPattern": "{ $.errorCode = * }"},
            ],
        )
        mock_client.side_effect = client_factory

        findings = extract_csv_data(check(region="us-east-1"))
        signal = [
            f
            for f in findings
            if f["Finding"] == "Guardrail Intervention Monitoring Signal"
        ]
        assert signal[0]["Status"] == "Passed"
        assert (
            "1 metric filter(s) on log group '/aws/bedrock/invocations' matching a "
            "guardrail intervention field (GuardrailIntervened)"
            in signal[0]["Finding_Details"]
        )
        logs_client.describe_metric_filters.assert_called_once_with(
            logGroupName="/aws/bedrock/invocations"
        )

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_no_intervention_signal_names_what_was_missing(
        self, mock_client, mock_footprint
    ):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        client_factory, _ = self._alarm_clients(
            [{"AlarmName": "bedrock-throttle", "Namespace": "AWS/Bedrock"}],
            logging_config={
                "cloudWatchConfig": {
                    "logGroupName": "/aws/bedrock/invocations",
                    "roleArn": "arn:aws:iam::123456789012:role/BedrockLogs",
                }
            },
            metric_filters=[
                {"filterName": "Unrelated", "filterPattern": "{ $.errorCode = * }"}
            ],
        )
        mock_client.side_effect = client_factory

        findings = extract_csv_data(check(region="us-east-1"))
        assert findings[0]["Status"] == "Passed"
        signal = findings[1]
        assert signal["Finding"] == "Guardrail Intervention Monitoring Signal"
        assert signal["Status"] == "Failed"
        assert (
            "no metric filter on invocation log group '/aws/bedrock/invocations' "
            "matches an intervention field" in signal["Finding_Details"]
        )

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_s3_only_logging_names_the_missing_destination(
        self, mock_client, mock_footprint
    ):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        client_factory, logs_client = self._alarm_clients(
            [{"AlarmName": "bedrock-throttle", "Namespace": "AWS/Bedrock"}],
            logging_config={"s3Config": {"bucketName": "bedrock-logs"}},
        )
        mock_client.side_effect = client_factory

        findings = extract_csv_data(check(region="us-east-1"))
        signal = findings[1]
        assert signal["Status"] == "Failed"
        assert (
            "model invocation logging has no CloudWatch Logs destination"
            in signal["Finding_Details"]
        )
        logs_client.describe_metric_filters.assert_not_called()

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_unreadable_metric_filters_are_not_absence(
        self, mock_client, mock_footprint
    ):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        client_factory, logs_client = self._alarm_clients(
            [{"AlarmName": "bedrock-throttle", "Namespace": "AWS/Bedrock"}],
            logging_config={
                "cloudWatchConfig": {
                    "logGroupName": "/aws/bedrock/invocations",
                    "roleArn": "arn:aws:iam::123456789012:role/BedrockLogs",
                }
            },
        )
        logs_client.describe_metric_filters.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "DescribeMetricFilters",
        )
        mock_client.side_effect = client_factory

        findings = extract_csv_data(check(region="us-east-1"))
        signal = findings[1]
        assert signal["Status"] == "N/A"
        assert signal["Severity"] == "Informational"
        assert "AccessDeniedException" in signal["Finding_Details"]
        assert "logs:DescribeMetricFilters" in signal["Resolution"]

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_schema_valid(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        cw_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"MetricAlarms": []}]
        cw_client.get_paginator.return_value = paginator
        mock_client.return_value = cw_client

        result = check(region="us-east-1")
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-33: check_inspector_lambda_code_scanning
# ===================================================================
class TestBR33InspectorLambdaCodeScanning:
    """BR-33: Verify Amazon Inspector Lambda + Lambda code scanning is enabled."""

    def _inspector_response(self, lambda_status, lambda_code_status):
        return {
            "accounts": [
                {
                    "accountId": "123456789012",
                    "resourceState": {
                        "lambda": {"status": lambda_status},
                        "lambdaCode": {"status": lambda_code_status},
                    },
                }
            ]
        }

    def _bedrock_lambda(self, name="bedrock-chat-handler"):
        return {
            "FunctionName": name,
            "FunctionArn": f"arn:aws:lambda:us-east-1:123456789012:function:{name}",
            "Description": "Invokes Amazon Bedrock models",
            "Environment": {"Variables": {"BEDROCK_MODEL_ID": "anthropic.test"}},
        }

    def _wire_clients(
        self,
        mock_client,
        *,
        lambda_functions=None,
        lambda_error=None,
        inspector_response=None,
        inspector_error=None,
    ):
        lambda_client = MagicMock()
        if lambda_error is not None:
            lambda_client.list_functions.side_effect = lambda_error
        else:
            lambda_client.list_functions.return_value = {
                "Functions": lambda_functions
                if lambda_functions is not None
                else [self._bedrock_lambda()]
            }

        inspector_client = MagicMock()
        if inspector_error is not None:
            inspector_client.batch_get_account_status.side_effect = inspector_error
        else:
            inspector_client.batch_get_account_status.return_value = (
                inspector_response
                if inspector_response is not None
                else self._inspector_response("ENABLED", "ENABLED")
            )

        def client(service_name, *args, **kwargs):
            if service_name == "lambda":
                return lambda_client
            if service_name == "inspector2":
                return inspector_client
            return MagicMock()

        mock_client.side_effect = client
        return lambda_client, inspector_client

    @patch("bedrock_app.boto3.client")
    def test_br33_both_enabled_returns_passed(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        self._wire_clients(
            mock_client,
            inspector_response=self._inspector_response("ENABLED", "ENABLED"),
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Check_ID"] == "BR-33"
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.boto3.client")
    def test_br33_code_scanning_disabled_returns_failed(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        self._wire_clients(
            mock_client,
            inspector_response=self._inspector_response("ENABLED", "DISABLED"),
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Check_ID"] == "BR-33"
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.boto3.client")
    def test_br33_lambda_disabled_returns_failed(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        self._wire_clients(
            mock_client,
            inspector_response=self._inspector_response("DISABLED", "DISABLED"),
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Check_ID"] == "BR-33"
        assert findings[0]["Status"] == "Failed"

    @patch("bedrock_app.boto3.client")
    def test_br33_region_unavailable_returns_na(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        self._wire_clients(
            mock_client,
            inspector_error=_make_client_error("UnrecognizedClientException"),
        )

        result = check(region="ap-south-2")
        findings = extract_csv_data(result)
        assert findings[0]["Check_ID"] == "BR-33"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("bedrock_app.boto3.client")
    def test_br33_access_denied_returns_na_informational(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        self._wire_clients(
            mock_client,
            inspector_error=_make_client_error("AccessDeniedException"),
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Check_ID"] == "BR-33"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("bedrock_app.boto3.client")
    def test_br33_endpoint_connection_error_returns_na(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        self._wire_clients(
            mock_client,
            inspector_error=EndpointConnectionError(
                endpoint_url="https://inspector2.example/"
            ),
        )

        result = check(region="us-gov-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Check_ID"] == "BR-33"
        assert findings[0]["Status"] == "N/A"

    @patch("bedrock_app.boto3.client")
    def test_br33_empty_accounts_returns_na(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        self._wire_clients(mock_client, inspector_response={"accounts": []})

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Check_ID"] == "BR-33"
        assert findings[0]["Status"] == "N/A"

    @patch("bedrock_app.boto3.client")
    def test_br33_no_bedrock_related_lambdas_returns_na(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        _, inspector_client = self._wire_clients(
            mock_client,
            lambda_functions=[
                {
                    "FunctionName": "ordinary-worker",
                    "Description": "generic background task",
                    "Environment": {"Variables": {"QUEUE_NAME": "jobs"}},
                }
            ],
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Check_ID"] == "BR-33"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        inspector_client.batch_get_account_status.assert_not_called()

    @patch("bedrock_app.boto3.client")
    def test_br33_lambda_list_access_denied_returns_na(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        self._wire_clients(
            mock_client,
            lambda_error=_make_client_error("AccessDeniedException"),
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Check_ID"] == "BR-33"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("bedrock_app.boto3.client")
    def test_br33_schema_valid(self, mock_client):
        check = bedrock_app.check_inspector_lambda_code_scanning
        self._wire_clients(
            mock_client,
            inspector_response=self._inspector_response("ENABLED", "ENABLED"),
        )

        result = check(region="us-east-1")
        for f in extract_csv_data(result):
            assert_finding_schema(f)


class TestBR22ServiceQuotas:
    """BR-22: Verify throttling quotas are compared against AWS defaults."""

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    @patch("bedrock_app.boto3.client")
    def test_br22_no_regional_footprint_returns_na(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_service_quotas_throttling

        result = check(region="sa-east-1")
        findings = extract_csv_data(result)

        assert findings[0]["Check_ID"] == "BR-22"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert findings[0]["Finding_Details"] == (
            "No regional Bedrock resources found to assess model invocation throttling quotas"
        )
        mock_client.assert_not_called()

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br22_custom_quota_uses_aws_default_comparison(
        self, mock_client, mock_footprint
    ):
        check = bedrock_app.check_bedrock_service_quotas_throttling

        quotas_client = MagicMock()
        quotas_client.list_service_quotas.side_effect = [
            {
                "Quotas": [
                    {
                        "QuotaName": "Tokens per minute for model invocations",
                        "QuotaCode": "L-123",
                        "Value": 200,
                    }
                ],
                "NextToken": "page-2",
            },
            {"Quotas": []},
        ]
        quotas_client.get_service_quota.return_value = {
            "Quota": {"QuotaName": "Tokens per minute", "Value": 200}
        }
        quotas_client.get_aws_default_service_quota.return_value = {
            "Quota": {"QuotaName": "Tokens per minute", "Value": 100}
        }
        mock_client.return_value = quotas_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)

        assert quotas_client.list_service_quotas.call_count == 2
        assert findings[0]["Check_ID"] == "BR-22"
        assert findings[0]["Status"] == "Passed"
        assert "custom throttling quotas" in findings[0]["Finding_Details"]


class TestAgenticBedrockMapping:
    """Agentic AI AG-* rows are generated from API-backed Bedrock checks."""

    EXPECTED_AGENTIC_MAPPINGS = {
        "BR-04": "AG-07",
        "BR-06": "AG-08",
        "BR-15": "AG-09",
        "BR-18": "AG-10",
        "BR-19": "AG-11",
        "BR-21": "AG-06",
        "BR-22": "AG-12",
        "BR-23": "AG-02",
        "BR-24": "AG-04",
        "BR-26": "AG-03",
        "BR-27": "AG-05",
        "BR-28": "AG-01",
        "BR-29": "AG-13",
        "BR-32": "AG-14",
        "BR-34": "AG-30",
    }

    def test_all_bedrock_agentic_mappings_emit_expected_rows(self):
        source_rows = []
        for source_check_id in self.EXPECTED_AGENTIC_MAPPINGS:
            source_rows.append(
                {
                    "Check_ID": source_check_id,
                    "Finding": f"{source_check_id} source finding",
                    "Finding_Details": f"{source_check_id} source details",
                    "Resolution": "No action required.",
                    "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    "Severity": "Medium",
                    "Status": "Passed",
                    "Region": "us-east-1",
                }
            )

        source_findings = [
            {
                "check_name": "Bedrock Agentic Mapping Sources",
                "csv_data": source_rows,
            }
        ]

        result = bedrock_app.build_agentic_bedrock_security_findings(source_findings)
        findings = extract_csv_data(result)

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


class TestProposedBedrockChecks:
    """BR-34 through BR-40 proposal checks."""

    @staticmethod
    def _guardrail_inventory(filters):
        return {
            "items": [
                {
                    "summary": {"id": "gr-1", "name": "TestGuardrail"},
                    "detail": {
                        "contentPolicy": {
                            "filters": filters,
                            "tier": {"tierName": "STANDARD"},
                        }
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }

    def test_br34_preventive_prompt_attack_passes(self):
        result = bedrock_app.check_bedrock_guardrail_prompt_attack_filter(
            region="us-east-1",
            guardrail_inventory=self._guardrail_inventory(
                [
                    {
                        "type": "PROMPT_ATTACK",
                        "inputEnabled": True,
                        "inputAction": "BLOCK",
                        "inputStrength": "HIGH",
                    }
                ]
            ),
        )
        finding = extract_csv_data(result)[0]
        assert finding["Check_ID"] == "BR-34"
        assert finding["Status"] == "Passed"

    def test_br34_detect_only_prompt_attack_fails(self):
        result = bedrock_app.check_bedrock_guardrail_prompt_attack_filter(
            region="us-east-1",
            guardrail_inventory=self._guardrail_inventory(
                [
                    {
                        "type": "PROMPT_ATTACK",
                        "inputEnabled": True,
                        "inputAction": "NONE",
                        "inputStrength": "HIGH",
                    }
                ]
            ),
        )
        assert extract_csv_data(result)[0]["Status"] == "Failed"

    @staticmethod
    def _two_guardrail_inventory(first_filters, second_filters):
        def entry(guardrail_id, name, filters):
            return {
                "summary": {"id": guardrail_id, "name": name},
                "detail": {
                    "contentPolicy": {
                        "filters": filters,
                        "tier": {"tierName": "STANDARD"},
                    }
                },
            }

        return {
            "items": [
                entry("gr-1", "HighStrengthGuardrail", first_filters),
                entry("gr-2", "MediumStrengthGuardrail", second_filters),
            ],
            "errors": [],
            "list_error": None,
        }

    def test_br34_requires_high_input_strength(self):
        """AIR-BDR-GRD-02: a blocking filter below HIGH strength is not preventive."""
        result = bedrock_app.check_bedrock_guardrail_prompt_attack_filter(
            region="us-east-1",
            guardrail_inventory=self._two_guardrail_inventory(
                [
                    {
                        "type": "PROMPT_ATTACK",
                        "inputEnabled": True,
                        "inputAction": "BLOCK",
                        "inputStrength": "HIGH",
                    }
                ],
                [
                    {
                        "type": "PROMPT_ATTACK",
                        "inputEnabled": True,
                        "inputAction": "BLOCK",
                        "inputStrength": "MEDIUM",
                    }
                ],
            ),
        )
        findings = extract_csv_data(result)
        assert [f["Status"] for f in findings] == ["Passed", "Failed"]
        assert (
            "has a preventive PROMPT_ATTACK input filter at HIGH strength"
            in findings[0]["Finding_Details"]
        )
        assert (
            "does not have a preventive PROMPT_ATTACK input filter at HIGH strength "
            "(observed strength/action/state: MEDIUM/BLOCK/enabled)"
        ) in findings[1]["Finding_Details"]
        assert findings[1]["Resolution"].endswith("inputStrength=HIGH.")
        for finding in findings:
            assert_finding_schema(finding)

    def test_br34_names_a_missing_prompt_attack_filter(self):
        result = bedrock_app.check_bedrock_guardrail_prompt_attack_filter(
            region="us-east-1",
            guardrail_inventory=self._two_guardrail_inventory(
                [
                    {
                        "type": "PROMPT_ATTACK",
                        "inputEnabled": True,
                        "inputAction": "BLOCK",
                        "inputStrength": "HIGH",
                    }
                ],
                [{"type": "HATE", "inputStrength": "HIGH"}],
            ),
        )
        findings = extract_csv_data(result)
        assert findings[1]["Status"] == "Failed"
        assert "no PROMPT_ATTACK filter is configured" in findings[1]["Finding_Details"]

    def test_br35_image_gap_is_advisory(self):
        result = bedrock_app.check_bedrock_guardrail_image_content_filters(
            region="us-east-1",
            guardrail_inventory=self._guardrail_inventory(
                [
                    {
                        "type": "HATE",
                        "inputModalities": ["TEXT"],
                        "outputModalities": ["TEXT"],
                    }
                ]
            ),
        )
        finding = extract_csv_data(result)[0]
        assert finding["Check_ID"] == "BR-35"
        assert finding["Severity"] == "Informational"
        assert finding["Status"] == "N/A"

    def test_br35_misconduct_is_not_required_when_absent(self):
        filters = [
            {
                "type": filter_type,
                "inputModalities": ["TEXT", "IMAGE"],
                "outputModalities": ["TEXT", "IMAGE"],
            }
            for filter_type in ("HATE", "INSULTS", "SEXUAL", "VIOLENCE")
        ]
        result = bedrock_app.check_bedrock_guardrail_image_content_filters(
            region="us-east-1",
            guardrail_inventory=self._guardrail_inventory(filters),
        )
        finding = extract_csv_data(result)[0]
        assert "reports IMAGE input/output coverage" in finding["Finding_Details"]
        assert "MISCONDUCT" not in finding["Finding_Details"]

    def test_br35_assesses_misconduct_modalities_when_configured(self):
        filters = [
            {
                "type": filter_type,
                "inputModalities": ["TEXT", "IMAGE"],
                "outputModalities": ["TEXT", "IMAGE"],
            }
            for filter_type in ("HATE", "INSULTS", "SEXUAL", "VIOLENCE")
        ]
        filters.append(
            {
                "type": "MISCONDUCT",
                "inputModalities": ["TEXT"],
                "outputModalities": ["TEXT"],
            }
        )
        result = bedrock_app.check_bedrock_guardrail_image_content_filters(
            region="us-east-1",
            guardrail_inventory=self._guardrail_inventory(filters),
        )
        finding = extract_csv_data(result)[0]
        assert "image-modality gaps for: MISCONDUCT" in finding["Finding_Details"]
        assert finding["Severity"] == "Informational"
        assert finding["Status"] == "N/A"

    @patch("bedrock_app.boto3.client")
    def test_br36_untagged_profile_fails_low(self, mock_client):
        client = MagicMock()
        client.list_inference_profiles.return_value = {
            "inferenceProfileSummaries": [
                {
                    "inferenceProfileArn": "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/p-1",
                    "inferenceProfileName": "profile-1",
                }
            ]
        }
        client.list_tags_for_resource.return_value = {"tags": []}
        mock_client.return_value = client
        finding = extract_csv_data(
            bedrock_app.check_bedrock_inference_profile_governance("us-east-1")
        )[0]
        assert finding["Check_ID"] == "BR-36"
        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "Low"

    @patch("bedrock_app.boto3.client")
    def test_br36_tagged_profile_passes(self, mock_client):
        client = MagicMock()
        client.list_inference_profiles.return_value = {
            "inferenceProfileSummaries": [
                {
                    "inferenceProfileArn": "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/p-1",
                    "inferenceProfileName": "profile-1",
                }
            ]
        }
        client.list_tags_for_resource.return_value = {
            "tags": [{"key": "owner", "value": "ml-team"}]
        }
        mock_client.return_value = client
        finding = extract_csv_data(
            bedrock_app.check_bedrock_inference_profile_governance("us-east-1")
        )[0]
        assert finding["Status"] == "Passed"

    @patch("bedrock_app.boto3.client")
    def test_br37_provider_sharing_fails(self, mock_client):
        mock_client.return_value.get_account_data_retention.return_value = {
            "mode": "provider_data_share"
        }
        finding = extract_csv_data(
            bedrock_app.check_bedrock_account_data_retention("us-east-1")
        )[0]
        assert finding["Check_ID"] == "BR-37"
        assert finding["Status"] == "Failed"

    @patch("bedrock_app.boto3.client")
    def test_br37_zero_retention_passes(self, mock_client):
        mock_client.return_value.get_account_data_retention.return_value = {
            "mode": "none"
        }
        finding = extract_csv_data(
            bedrock_app.check_bedrock_account_data_retention("us-east-1")
        )[0]
        assert finding["Status"] == "Passed"

    @patch.dict(
        os.environ,
        {"REQUIRE_BEDROCK_ZERO_DATA_RETENTION": "false"},
        clear=False,
    )
    @patch("bedrock_app.boto3.client")
    def test_br37_default_retention_is_advisory_na(self, mock_client):
        mock_client.return_value.get_account_data_retention.return_value = {
            "mode": "default"
        }

        finding = extract_csv_data(
            bedrock_app.check_bedrock_account_data_retention("us-east-1")
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Resolution"].startswith("Review the inherited/default")

    @patch.dict(
        os.environ,
        {"REQUIRE_BEDROCK_ZERO_DATA_RETENTION": "true"},
        clear=False,
    )
    @patch("bedrock_app.boto3.client")
    def test_br37_default_retention_fails_when_required(self, mock_client):
        mock_client.return_value.get_account_data_retention.return_value = {
            "mode": "default"
        }

        finding = extract_csv_data(
            bedrock_app.check_bedrock_account_data_retention("us-east-1")
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br38_policy_without_cmk_fails(self, mock_client):
        client = MagicMock()
        client.list_automated_reasoning_policies.return_value = {
            "automatedReasoningPolicySummaries": [
                {
                    "policyArn": "arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/p-1",
                    "policyId": "p-1",
                    "name": "policy-1",
                }
            ]
        }
        client.get_automated_reasoning_policy.return_value = {"kmsKeyArn": None}
        mock_client.return_value = client
        finding = extract_csv_data(
            bedrock_app.check_bedrock_automated_reasoning_policy_encryption("us-east-1")
        )[0]
        assert finding["Check_ID"] == "BR-38"
        assert finding["Status"] == "Failed"

    @patch("bedrock_app.boto3.client")
    def test_br38_policy_with_cmk_passes(self, mock_client):
        client = MagicMock()
        client.list_automated_reasoning_policies.return_value = {
            "automatedReasoningPolicySummaries": [
                {
                    "policyArn": "arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/p-1",
                    "policyId": "p-1",
                    "name": "policy-1",
                }
            ]
        }
        client.get_automated_reasoning_policy.return_value = {
            "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-1"
        }
        mock_client.return_value = client
        finding = extract_csv_data(
            bedrock_app.check_bedrock_automated_reasoning_policy_encryption("us-east-1")
        )[0]
        assert finding["Status"] == "Passed"

    def test_br39_and_br40_share_marketplace_inventory(self):
        kms_client = MagicMock()
        kms_client.describe_key.return_value = {
            "KeyMetadata": {"KeyManager": "CUSTOMER"}
        }
        inventory = {
            "items": [
                {
                    "summary": {"endpointArn": "arn:endpoint-1"},
                    "detail": {
                        "endpointConfig": {
                            "sageMaker": {
                                "vpc": {
                                    "subnetIds": ["subnet-1"],
                                    "securityGroupIds": ["sg-1"],
                                },
                                "kmsEncryptionKey": "arn:kms:key-1",
                            }
                        }
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        br39 = extract_csv_data(
            bedrock_app.check_bedrock_marketplace_endpoint_vpc("us-east-1", inventory)
        )[0]
        br40 = extract_csv_data(
            bedrock_app.check_bedrock_marketplace_endpoint_cmk(
                "us-east-1", inventory, kms_client
            )
        )[0]
        assert br39["Status"] == "Passed"
        assert br40["Status"] == "Passed"
        assert "customer-managed KMS key" in br40["Finding_Details"]
        kms_client.describe_key.assert_called_once_with(KeyId="arn:kms:key-1")

    def test_br39_and_br40_missing_controls_fail_under_default_cmk_baseline(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REQUIRE_MARKETPLACE_ENDPOINT_CMK", None)
            inventory = {
                "items": [
                    {
                        "summary": {"endpointArn": "arn:endpoint-1"},
                        "detail": {"endpointConfig": {"sageMaker": {}}},
                    }
                ],
                "errors": [],
                "list_error": None,
            }
            br39 = extract_csv_data(
                bedrock_app.check_bedrock_marketplace_endpoint_vpc(
                    "us-east-1", inventory
                )
            )[0]
            br40 = extract_csv_data(
                bedrock_app.check_bedrock_marketplace_endpoint_cmk(
                    "us-east-1", inventory
                )
            )[0]

        assert br39["Status"] == "Failed"
        assert br40["Status"] == "Failed"
        assert br40["Severity"] == "Medium"
        assert br40["Resolution"] == (
            "Register the endpoint with a customer-managed KMS key."
        )

    @patch.dict(
        os.environ,
        {"REQUIRE_MARKETPLACE_ENDPOINT_CMK": "false"},
        clear=False,
    )
    def test_br40_missing_optional_cmk_is_advisory_na(self):
        inventory = {
            "items": [
                {
                    "summary": {"endpointArn": "arn:endpoint-1"},
                    "detail": {"endpointConfig": {"sageMaker": {}}},
                }
            ],
            "errors": [],
            "list_error": None,
        }
        finding = extract_csv_data(
            bedrock_app.check_bedrock_marketplace_endpoint_cmk("us-east-1", inventory)
        )[0]
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Resolution"].startswith("No action required")

    def test_br40_aws_managed_key_fails_required_baseline(self):
        kms_client = MagicMock()
        kms_client.describe_key.return_value = {"KeyMetadata": {"KeyManager": "AWS"}}
        inventory = {
            "items": [
                {
                    "summary": {"endpointArn": "arn:endpoint-1"},
                    "detail": {
                        "endpointConfig": {
                            "sageMaker": {
                                "kmsEncryptionKey": "alias/aws/sagemaker",
                            }
                        }
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }

        finding = extract_csv_data(
            bedrock_app.check_bedrock_marketplace_endpoint_cmk(
                "us-east-1", inventory, kms_client
            )
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "Medium"
        assert "uses AWS-managed KMS key" in finding["Finding_Details"]
        assert "uses customer-managed KMS key" not in finding["Finding_Details"]

    @patch.dict(
        os.environ,
        {"REQUIRE_MARKETPLACE_ENDPOINT_CMK": "false"},
        clear=False,
    )
    def test_br40_aws_managed_key_is_advisory_when_baseline_optional(self):
        kms_client = MagicMock()
        kms_client.describe_key.return_value = {"KeyMetadata": {"KeyManager": "AWS"}}
        inventory = {
            "items": [
                {
                    "summary": {"endpointArn": "arn:endpoint-1"},
                    "detail": {
                        "endpointConfig": {
                            "sageMaker": {
                                "kmsEncryptionKey": "alias/aws/sagemaker",
                            }
                        }
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }

        finding = extract_csv_data(
            bedrock_app.check_bedrock_marketplace_endpoint_cmk(
                "us-east-1", inventory, kms_client
            )
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Resolution"].startswith("No action required")

    def test_br40_describe_key_error_returns_na(self):
        kms_client = MagicMock()
        kms_client.describe_key.side_effect = _make_client_error(
            "AccessDeniedException"
        )
        inventory = {
            "items": [
                {
                    "summary": {"endpointArn": "arn:endpoint-1"},
                    "detail": {
                        "endpointConfig": {
                            "sageMaker": {
                                "kmsEncryptionKey": "arn:kms:key-1",
                            }
                        }
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }

        finding = extract_csv_data(
            bedrock_app.check_bedrock_marketplace_endpoint_cmk(
                "us-east-1", inventory, kms_client
            )
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "AccessDeniedException" in finding["Finding_Details"]
        assert finding["Resolution"] == (
            "Grant kms:DescribeKey for the configured key and retry."
        )

    def test_br40_unknown_key_manager_returns_na(self):
        kms_client = MagicMock()
        kms_client.describe_key.return_value = {"KeyMetadata": {}}
        inventory = {
            "items": [
                {
                    "summary": {"endpointArn": "arn:endpoint-1"},
                    "detail": {
                        "endpointConfig": {
                            "sageMaker": {
                                "kmsEncryptionKey": "arn:kms:key-1",
                            }
                        }
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }

        finding = extract_csv_data(
            bedrock_app.check_bedrock_marketplace_endpoint_cmk(
                "us-east-1", inventory, kms_client
            )
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "did not return a recognized key manager" in finding["Finding_Details"]

    def test_new_guardrail_checks_access_denied_return_na(self):
        inventory = {
            "items": [],
            "errors": [],
            "list_error": _make_client_error("AccessDeniedException"),
        }
        for check in (
            bedrock_app.check_bedrock_guardrail_prompt_attack_filter,
            bedrock_app.check_bedrock_guardrail_image_content_filters,
        ):
            finding = extract_csv_data(check("us-east-1", inventory))[0]
            assert finding["Status"] == "N/A"
            assert finding["Severity"] == "Informational"

    @patch("bedrock_app.boto3.client")
    def test_br36_access_denied_returns_na(self, mock_client):
        mock_client.return_value.list_inference_profiles.side_effect = (
            _make_client_error("AccessDeniedException")
        )
        finding = extract_csv_data(
            bedrock_app.check_bedrock_inference_profile_governance("us-east-1")
        )[0]
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"

    @patch("bedrock_app.boto3.client")
    def test_br37_access_denied_returns_na(self, mock_client):
        mock_client.return_value.get_account_data_retention.side_effect = (
            _make_client_error("AccessDeniedException")
        )
        finding = extract_csv_data(
            bedrock_app.check_bedrock_account_data_retention("us-east-1")
        )[0]
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"

    @patch("bedrock_app.boto3.client")
    def test_br38_access_denied_returns_na(self, mock_client):
        mock_client.return_value.list_automated_reasoning_policies.side_effect = (
            _make_client_error("AccessDeniedException")
        )
        finding = extract_csv_data(
            bedrock_app.check_bedrock_automated_reasoning_policy_encryption("us-east-1")
        )[0]
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"

    def test_marketplace_checks_access_denied_return_na(self):
        inventory = {
            "items": [],
            "errors": [],
            "list_error": _make_client_error("AccessDeniedException"),
        }
        for check in (
            bedrock_app.check_bedrock_marketplace_endpoint_vpc,
            bedrock_app.check_bedrock_marketplace_endpoint_cmk,
        ):
            finding = extract_csv_data(check("us-east-1", inventory))[0]
            assert finding["Status"] == "N/A"
            assert finding["Severity"] == "Informational"

    def test_new_bedrock_operation_contracts_exist(self):
        client = bedrock_app.boto3.client(
            "bedrock",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        )
        model = client.meta.service_model
        for operation in [
            "ListInferenceProfiles",
            "ListTagsForResource",
            "GetAccountDataRetention",
            "ListAutomatedReasoningPolicies",
            "GetAutomatedReasoningPolicy",
            "ListMarketplaceModelEndpoints",
            "GetMarketplaceModelEndpoint",
            "ListEnforcedGuardrailsConfiguration",
        ]:
            assert model.operation_model(operation)

    def test_br22_na_generates_ag12_informational_na(self):
        source_findings = [
            {
                "check_name": "Model Invocation Throttling Limits Check",
                "csv_data": [
                    {
                        "Check_ID": "BR-22",
                        "Finding": "Model Invocation Throttling Limits Check",
                        "Finding_Details": "No regional Bedrock resources found to assess model invocation throttling quotas",
                        "Resolution": "No action required",
                        "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                        "Severity": "Informational",
                        "Status": "N/A",
                        "Region": "sa-east-1",
                    }
                ],
            }
        ]

        result = bedrock_app.build_agentic_bedrock_security_findings(source_findings)
        findings = extract_csv_data(result)

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AG-12"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert findings[0]["Region"] == "sa-east-1"
        assert "Source check BR-22" in findings[0]["Finding_Details"]
        assert "No regional Bedrock resources found" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    def test_br28_generates_ag01_mapping(self):
        source_findings = [
            {
                "check_name": "Bedrock Agent Guardrail Association",
                "csv_data": [
                    {
                        "Check_ID": "BR-28",
                        "Finding": "Bedrock Agent Guardrail Association",
                        "Finding_Details": "Agent has a guardrail associated.",
                        "Resolution": "No action required.",
                        "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use.html",
                        "Severity": "High",
                        "Status": "Passed",
                        "Region": "us-east-1",
                    }
                ],
            }
        ]

        result = bedrock_app.build_agentic_bedrock_security_findings(source_findings)
        findings = extract_csv_data(result)

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AG-01"
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Region"] == "us-east-1"
        assert "Source check BR-28" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])
