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
import time
import sys
import os
import importlib.util
from unittest.mock import call, patch, MagicMock
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


class TestBR02VPCEndpointHardening:
    """
    BR-02 hardening legs: an endpoint existing is not private connectivity.

    Private DNS decides whether an unmodified client uses the endpoint at all,
    and the endpoint policy decides which principals may use it once traffic
    reaches it. Every case fixes one endpoint and varies one of the two.
    """

    _ORG_POLICY = json.dumps(
        {
            "Statement": [
                {
                    "Sid": "OrgOnly",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "bedrock:InvokeModel",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
                }
            ]
        }
    )

    _OPEN_POLICY = json.dumps(
        {
            "Statement": [
                {
                    "Sid": "default",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        }
    )

    @classmethod
    def _endpoint(
        cls,
        endpoint_id="vpce-1",
        service="com.amazonaws.us-east-1.bedrock-runtime",
        vpc_id="vpc-1",
        private_dns=True,
        policy=None,
    ):
        return {
            "vpc_id": vpc_id,
            "service": service,
            "endpoint_id": endpoint_id,
            "private_dns": private_dns,
            "policy": cls._ORG_POLICY if policy is None else policy,
        }

    def _run(self, endpoints, permission_cache):
        with (
            patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True),
            patch(
                "bedrock_app.check_bedrock_vpc_endpoints",
                return_value={
                    "has_endpoints": True,
                    "found_endpoints": list(endpoints),
                    "all_vpcs": ["vpc-1"],
                },
            ),
        ):
            self.result = bedrock_app.check_bedrock_access_and_vpc_endpoints(
                permission_cache, region="us-east-1"
            )
        return extract_csv_data(self.result)

    @staticmethod
    def _dns_rows(findings):
        return [
            finding
            for finding in findings
            if finding["Finding"] == bedrock_app.VPC_ENDPOINT_PRIVATE_DNS_FINDING
        ]

    @staticmethod
    def _policy_rows(findings):
        return [
            finding
            for finding in findings
            if finding["Finding"] == bedrock_app.VPC_ENDPOINT_POLICY_FINDING
        ]

    def test_br02_private_dns_disabled_fails_and_names_the_endpoint(
        self, permission_cache_compliant
    ):
        findings = self._run(
            [self._endpoint(private_dns=False)], permission_cache_compliant
        )

        dns_rows = self._dns_rows(findings)
        assert len(dns_rows) == 1
        assert dns_rows[0]["Status"] == "Failed"
        assert dns_rows[0]["Check_ID"] == "BR-02"
        assert "1 of 1" in dns_rows[0]["Finding_Details"]
        assert (
            "vpce-1 (com.amazonaws.us-east-1.bedrock-runtime in vpc-1)"
            in (dns_rows[0]["Finding_Details"])
        )
        assert "still resolves the public endpoint" in dns_rows[0]["Finding_Details"]
        assert self.result["status"] == "WARN"

    def test_br02_private_dns_enabled_passes(self, permission_cache_compliant):
        findings = self._run([self._endpoint()], permission_cache_compliant)

        dns_rows = self._dns_rows(findings)
        assert len(dns_rows) == 1
        assert dns_rows[0]["Status"] == "Passed"
        assert "1 of 1" in dns_rows[0]["Finding_Details"]
        assert self.result["status"] == "PASS"

    def test_br02_unreported_private_dns_is_na_not_disabled(
        self, permission_cache_compliant
    ):
        findings = self._run(
            [self._endpoint(private_dns=None)], permission_cache_compliant
        )

        dns_rows = self._dns_rows(findings)
        assert len(dns_rows) == 1
        assert dns_rows[0]["Status"] == "N/A"
        assert dns_rows[0]["Severity"] == "Informational"
        assert "did not report PrivateDnsEnabled" in dns_rows[0]["Finding_Details"]

    def test_br02_two_endpoints_reach_both_dns_verdicts(
        self, permission_cache_compliant
    ):
        findings = self._run(
            [
                self._endpoint(endpoint_id="vpce-on", private_dns=True),
                self._endpoint(endpoint_id="vpce-off", private_dns=False),
            ],
            permission_cache_compliant,
        )

        dns_rows = self._dns_rows(findings)
        failed = [row for row in dns_rows if row["Status"] == "Failed"]
        passed = [row for row in dns_rows if row["Status"] == "Passed"]
        assert len(failed) == 1
        assert len(passed) == 1
        assert "1 of 2" in failed[0]["Finding_Details"]
        assert "vpce-off" in failed[0]["Finding_Details"]
        # One endpoint's setting cannot speak for the other.
        assert "vpce-on" not in failed[0]["Finding_Details"]
        assert "vpce-off" not in passed[0]["Finding_Details"]

    def test_br02_default_endpoint_policy_fails_with_the_scope_it_grants(
        self, permission_cache_compliant
    ):
        findings = self._run(
            [self._endpoint(policy=self._OPEN_POLICY)], permission_cache_compliant
        )

        policy_rows = self._policy_rows(findings)
        assert len(policy_rows) == 1
        assert policy_rows[0]["Status"] == "Failed"
        assert (
            "statement 'default' allows any principal to call * on *"
            in (policy_rows[0]["Finding_Details"])
        )
        assert "a peered VPC" in policy_rows[0]["Finding_Details"]
        assert self.result["status"] == "WARN"

    def test_br02_org_condition_scopes_the_endpoint_policy(
        self, permission_cache_compliant
    ):
        findings = self._run([self._endpoint()], permission_cache_compliant)

        policy_rows = self._policy_rows(findings)
        assert len(policy_rows) == 1
        assert policy_rows[0]["Status"] == "Passed"
        assert (
            "statement 'OrgOnly' requires aws:principalorgid"
            in (policy_rows[0]["Finding_Details"])
        )

    def test_br02_source_vpce_condition_scopes_the_endpoint_policy(
        self, permission_cache_compliant
    ):
        """aws:SourceVpce and aws:SourceVpc are one family, so both must count."""
        policy = json.dumps(
            {
                "Statement": [
                    {
                        "Sid": "FromThisVpce",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "bedrock:InvokeModel",
                        "Resource": "*",
                        "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}},
                    }
                ]
            }
        )
        findings = self._run(
            [self._endpoint(policy=policy)], permission_cache_compliant
        )

        policy_rows = self._policy_rows(findings)
        assert policy_rows[0]["Status"] == "Passed"
        assert "requires aws:sourcevpce" in policy_rows[0]["Finding_Details"]

    def test_br02_named_principal_scopes_the_endpoint_policy(
        self, permission_cache_compliant
    ):
        policy = json.dumps(
            {
                "Statement": [
                    {
                        "Sid": "AppOnly",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": [
                                "arn:aws:iam::123456789012:role/app",
                                "arn:aws:iam::123456789012:role/batch",
                            ]
                        },
                        "Action": "bedrock:InvokeModel",
                        "Resource": "*",
                    }
                ]
            }
        )
        findings = self._run(
            [self._endpoint(policy=policy)], permission_cache_compliant
        )

        policy_rows = self._policy_rows(findings)
        assert policy_rows[0]["Status"] == "Passed"
        assert (
            "statement 'AppOnly' names 2 principal(s)"
            in (policy_rows[0]["Finding_Details"])
        )

    def test_br02_wildcard_inside_a_principal_block_is_not_a_bound(
        self, permission_cache_compliant
    ):
        """Principal {"AWS": "*"} is the default policy written the long way."""
        policy = json.dumps(
            {
                "Statement": [
                    {
                        "Sid": "LooksNamed",
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "bedrock:*",
                        "Resource": "*",
                    }
                ]
            }
        )
        findings = self._run(
            [self._endpoint(policy=policy)], permission_cache_compliant
        )

        policy_rows = self._policy_rows(findings)
        assert policy_rows[0]["Status"] == "Failed"
        assert (
            "statement 'LooksNamed' allows any principal to call bedrock:* on *"
            in (policy_rows[0]["Finding_Details"])
        )

    def test_br02_action_narrowing_alone_does_not_scope_the_endpoint(
        self, permission_cache_compliant
    ):
        """Naming the actions bounds what, not who, so the endpoint is still open."""
        policy = json.dumps(
            {
                "Statement": [
                    {
                        "Sid": "InvokeOnly",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["bedrock:InvokeModel"],
                        "Resource": "*",
                    }
                ]
            }
        )
        findings = self._run(
            [self._endpoint(policy=policy)], permission_cache_compliant
        )

        policy_rows = self._policy_rows(findings)
        assert policy_rows[0]["Status"] == "Failed"
        assert (
            "statement 'InvokeOnly' allows any principal to call "
            "bedrock:InvokeModel on *" in (policy_rows[0]["Finding_Details"])
        )

    def test_br02_deny_outside_the_org_scopes_a_wide_allow(
        self, permission_cache_compliant
    ):
        policy = json.dumps(
            {
                "Statement": [
                    {
                        "Sid": "default",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "OrgBoundary",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}
                        },
                    },
                ]
            }
        )
        findings = self._run(
            [self._endpoint(policy=policy)], permission_cache_compliant
        )

        policy_rows = self._policy_rows(findings)
        assert policy_rows[0]["Status"] == "Passed"
        assert (
            "a Deny statement rejects every request outside aws:principalorgid"
            in (policy_rows[0]["Finding_Details"])
        )

    def test_br02_string_equals_deny_does_not_scope_the_endpoint(
        self, permission_cache_compliant
    ):
        """A Deny testing the key as equal denies the org and allows everyone else."""
        policy = json.dumps(
            {
                "Statement": [
                    {
                        "Sid": "default",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "Inverted",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:PrincipalOrgID": "o-abc123"}
                        },
                    },
                ]
            }
        )
        findings = self._run(
            [self._endpoint(policy=policy)], permission_cache_compliant
        )

        policy_rows = self._policy_rows(findings)
        assert policy_rows[0]["Status"] == "Failed"
        assert "statement 'default'" in policy_rows[0]["Finding_Details"]

    def test_br02_not_principal_allow_is_unbounded(self, permission_cache_compliant):
        policy = json.dumps(
            {
                "Statement": [
                    {
                        "Sid": "AllButOne",
                        "Effect": "Allow",
                        "NotPrincipal": {
                            "AWS": "arn:aws:iam::123456789012:role/blocked"
                        },
                        "Action": "*",
                        "Resource": "*",
                    }
                ]
            }
        )
        findings = self._run(
            [self._endpoint(policy=policy)], permission_cache_compliant
        )

        policy_rows = self._policy_rows(findings)
        assert policy_rows[0]["Status"] == "Failed"
        assert (
            "statement 'AllButOne' allows every principal except the ones it names"
            in (policy_rows[0]["Finding_Details"])
        )

    def test_br02_policy_with_no_allow_statement_is_reported_as_unusable(
        self, permission_cache_compliant
    ):
        findings = self._run(
            [self._endpoint(policy=json.dumps({"Statement": []}))],
            permission_cache_compliant,
        )

        policy_rows = self._policy_rows(findings)
        assert policy_rows[0]["Status"] == "Passed"
        assert (
            "carries no Allow statement, so no principal can reach Bedrock through it"
            in (policy_rows[0]["Finding_Details"])
        )

    def test_br02_unparsable_policy_is_na_not_a_failure(
        self, permission_cache_compliant
    ):
        findings = self._run(
            [self._endpoint(policy="{not json")], permission_cache_compliant
        )

        policy_rows = self._policy_rows(findings)
        assert len(policy_rows) == 1
        assert policy_rows[0]["Status"] == "N/A"
        assert (
            "its endpoint policy could not be parsed"
            in (policy_rows[0]["Finding_Details"])
        )
        assert self.result["status"] == "PASS"

    def test_br02_absent_policy_is_na_not_scoped(self, permission_cache_compliant):
        findings = self._run([self._endpoint(policy="")], permission_cache_compliant)

        policy_rows = self._policy_rows(findings)
        assert len(policy_rows) == 1
        assert policy_rows[0]["Status"] == "N/A"
        assert (
            "no endpoint policy document was returned for it"
            in (policy_rows[0]["Finding_Details"])
        )

    def test_br02_two_endpoints_reach_both_policy_verdicts(
        self, permission_cache_compliant
    ):
        findings = self._run(
            [
                self._endpoint(endpoint_id="vpce-scoped"),
                self._endpoint(endpoint_id="vpce-open", policy=self._OPEN_POLICY),
            ],
            permission_cache_compliant,
        )

        policy_rows = self._policy_rows(findings)
        failed = [row for row in policy_rows if row["Status"] == "Failed"]
        passed = [row for row in policy_rows if row["Status"] == "Passed"]
        assert len(failed) == 1
        assert len(passed) == 1
        assert "1 of 2" in failed[0]["Finding_Details"]
        assert "vpce-open" in failed[0]["Finding_Details"]
        assert "vpce-scoped" not in failed[0]["Finding_Details"]
        assert "vpce-scoped" in passed[0]["Finding_Details"]

    def test_br02_hardening_rows_pass_the_finding_schema(
        self, permission_cache_compliant
    ):
        findings = self._run(
            [
                self._endpoint(endpoint_id="vpce-open", policy=self._OPEN_POLICY),
                self._endpoint(endpoint_id="vpce-off", private_dns=False),
                self._endpoint(endpoint_id="vpce-unknown", private_dns=None, policy=""),
            ],
            permission_cache_compliant,
        )

        rows = self._dns_rows(findings) + self._policy_rows(findings)
        # Three endpoints in three states: both legs report all three verdicts.
        assert sorted(row["Status"] for row in rows) == [
            "Failed",
            "Failed",
            "N/A",
            "N/A",
            "Passed",
            "Passed",
        ]
        for finding in rows:
            assert_finding_schema(finding)

    def test_br02_collector_captures_private_dns_and_the_policy_document(self):
        """The two fields the legs judge must survive the endpoint walk."""
        ec2_client = MagicMock()
        ec2_client.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
        ec2_client.get_paginator.return_value.paginate.return_value = [
            {
                "VpcEndpoints": [
                    {
                        "VpcEndpointId": "vpce-1",
                        "VpcId": "vpc-1",
                        "ServiceName": "com.amazonaws.us-east-1.bedrock-runtime",
                        "PrivateDnsEnabled": False,
                        "PolicyDocument": self._OPEN_POLICY,
                    },
                    {
                        "VpcEndpointId": "vpce-2",
                        "VpcId": "vpc-1",
                        "ServiceName": "com.amazonaws.us-east-1.s3",
                        "PrivateDnsEnabled": True,
                    },
                ]
            }
        ]

        with patch("bedrock_app.boto3.client", return_value=ec2_client):
            result = bedrock_app.check_bedrock_vpc_endpoints(region="us-east-1")

        assert result["has_endpoints"] is True
        assert len(result["found_endpoints"]) == 1
        endpoint = result["found_endpoints"][0]
        assert endpoint["endpoint_id"] == "vpce-1"
        assert endpoint["private_dns"] is False
        assert endpoint["policy"] == self._OPEN_POLICY


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
        # ListPrompts without an identifier reports the DRAFT of each prompt, and
        # version is a required member of PromptSummary.
        paginator.paginate.return_value = [
            {"promptSummaries": [{"name": "prompt1", "id": "p1", "version": "DRAFT"}]}
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
            {
                "promptSummaries": [
                    {"name": "prompt1", "promptId": "p1", "version": "DRAFT"}
                ]
            }
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


class TestBR07PromptProductionVersion:
    """BR-07 / AIR-BDR-MDL-08: production must run a pinned, encrypted prompt."""

    _CMK_ARN = "arn:aws:kms:us-east-1:123456789012:key/prompt-key"
    _PROMPT_ARN = "arn:aws:bedrock:us-east-1:123456789012:prompt/ABCDEFGHIJ"

    @staticmethod
    def _summary(prompt_id, version, name=None):
        return {
            "id": prompt_id,
            "name": name or prompt_id,
            "arn": f"arn:aws:bedrock:us-east-1:123456789012:prompt/{prompt_id}",
            "version": version,
        }

    @classmethod
    def _client(
        cls,
        prompts=(),
        versions=None,
        version_details=None,
        flows=(),
        flow_definitions=None,
        flows_error=None,
    ):
        """
        A bedrock-agent client whose ListPrompts answers per promptIdentifier.

        Without an identifier the API returns the DRAFT summary of every prompt;
        with one it returns that prompt's versions, so a single shared page would
        let a DRAFT-only estate read as versioned.
        """
        versions = versions or {}
        version_details = version_details or {}
        flow_definitions = flow_definitions or {}

        def list_prompts_pages(**kwargs):
            identifier = kwargs.get("promptIdentifier")
            if identifier is None:
                return [{"promptSummaries": list(prompts)}]
            entry = versions.get(identifier, [])
            if isinstance(entry, Exception):
                raise entry
            return [{"promptSummaries": list(entry)}]

        prompts_paginator = MagicMock()
        prompts_paginator.paginate.side_effect = list_prompts_pages

        flows_paginator = MagicMock()
        if flows_error is not None:
            flows_paginator.paginate.side_effect = flows_error
        else:
            flows_paginator.paginate.return_value = [{"flowSummaries": list(flows)}]

        client = MagicMock()
        client.get_paginator.side_effect = lambda operation: {
            "list_prompts": prompts_paginator,
            "list_flows": flows_paginator,
        }[operation]

        def get_prompt(**kwargs):
            version = kwargs.get("promptVersion")
            if version is None:
                # The variants leg reads the DRAFT of each prompt.
                return {"variants": ["v1", "v2"]}
            entry = version_details.get((kwargs["promptIdentifier"], version))
            if isinstance(entry, Exception):
                raise entry
            return entry or {}

        client.get_prompt.side_effect = get_prompt

        def get_flow(flowIdentifier):
            entry = flow_definitions.get(flowIdentifier)
            if isinstance(entry, Exception):
                raise entry
            return entry or {}

        client.get_flow.side_effect = get_flow
        return client

    def _run(self, client):
        with patch("boto3.client", return_value=client):
            self.result = bedrock_app.check_bedrock_prompt_management("us-east-1")
        return extract_csv_data(self.result)

    @staticmethod
    def _rows(findings, finding_name):
        return [finding for finding in findings if finding["Finding"] == finding_name]

    @classmethod
    def _version_rows(cls, findings):
        return cls._rows(findings, bedrock_app.PROMPT_VERSION_FINDING)

    @classmethod
    def _encryption_rows(cls, findings):
        return cls._rows(findings, bedrock_app.PROMPT_VERSION_ENCRYPTION_FINDING)

    @classmethod
    def _flow_rows(cls, findings):
        return cls._rows(findings, bedrock_app.FLOW_PROMPT_VERSION_FINDING)

    @staticmethod
    def _flow(nodes):
        return {"definition": {"nodes": list(nodes)}}

    @classmethod
    def _prompt_node(cls, name, prompt_arn):
        return {
            "name": name,
            "type": "Prompt",
            "configuration": {
                "prompt": {
                    "sourceConfiguration": {"resource": {"promptArn": prompt_arn}}
                }
            },
        }

    # ------------------------------------------------------------------
    # Leg A: does a numbered version exist at all
    # ------------------------------------------------------------------
    def test_br07_numbered_version_passes_the_pinning_leg(self):
        rows = self._version_rows(
            self._run(
                self._client(
                    prompts=[self._summary("p1", "DRAFT")],
                    versions={
                        "p1": [self._summary("p1", "DRAFT"), self._summary("p1", "1")]
                    },
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Passed"]
        assert "1 of 1 prompt(s)" in rows[0]["Finding_Details"]
        assert "latest version 1" in rows[0]["Finding_Details"]

    def test_br07_draft_only_prompt_fails_the_pinning_leg(self):
        rows = self._version_rows(
            self._run(
                self._client(
                    prompts=[self._summary("p1", "DRAFT", name="greeting")],
                    versions={"p1": [self._summary("p1", "DRAFT")]},
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Failed"]
        assert rows[0]["Severity"] == "Medium"
        assert "greeting" in rows[0]["Finding_Details"]
        assert self.result["status"] == "WARN"

    def test_br07_two_prompts_reach_both_pinning_verdicts(self):
        rows = self._version_rows(
            self._run(
                self._client(
                    prompts=[
                        self._summary("p1", "DRAFT", name="pinned"),
                        self._summary("p2", "DRAFT", name="draft-only"),
                    ],
                    versions={
                        "p1": [self._summary("p1", "1")],
                        "p2": [self._summary("p2", "DRAFT")],
                    },
                    version_details={("p1", "1"): {}},
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Failed", "Passed"]
        assert "1 of 2 prompt(s)" in rows[0]["Finding_Details"]
        assert "draft-only" in rows[0]["Finding_Details"]
        assert "1 of 2 prompt(s)" in rows[1]["Finding_Details"]
        assert "pinned" in rows[1]["Finding_Details"]

    def test_br07_version_list_error_is_na_not_draft_only(self):
        findings = self._run(
            self._client(
                prompts=[self._summary("p1", "DRAFT")],
                versions={
                    "p1": _client_error("AccessDeniedException", "no", "ListPrompts")
                },
            )
        )

        rows = self._version_rows(findings)
        assert [row["Status"] for row in rows] == ["N/A"]
        assert "AccessDeniedException" in rows[0]["Finding_Details"]
        assert "bedrock:ListPrompts" in rows[0]["Resolution"]
        assert self._encryption_rows(findings) == []

    def test_br07_latest_version_is_the_highest_number_not_the_last_listed(self):
        rows = self._version_rows(
            self._run(
                self._client(
                    prompts=[self._summary("p1", "DRAFT")],
                    versions={
                        "p1": [
                            self._summary("p1", "DRAFT"),
                            self._summary("p1", "10"),
                            self._summary("p1", "9"),
                        ]
                    },
                    version_details={("p1", "10"): {}},
                )
            )
        )

        assert "latest version 10" in rows[0]["Finding_Details"]

    # ------------------------------------------------------------------
    # Leg B: the encryption key of the version production would pin
    # ------------------------------------------------------------------
    def test_br07_cmk_on_the_latest_version_passes_the_encryption_leg(self):
        rows = self._encryption_rows(
            self._run(
                self._client(
                    prompts=[self._summary("p1", "DRAFT")],
                    versions={"p1": [self._summary("p1", "1")]},
                    version_details={
                        ("p1", "1"): {"customerEncryptionKeyArn": self._CMK_ARN}
                    },
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Passed"]
        assert "1 of 1 versioned prompt(s)" in rows[0]["Finding_Details"]

    def test_br07_version_without_a_cmk_fails_the_encryption_leg(self):
        rows = self._encryption_rows(
            self._run(
                self._client(
                    prompts=[self._summary("p1", "DRAFT", name="greeting")],
                    versions={"p1": [self._summary("p1", "4")]},
                    version_details={("p1", "4"): {}},
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Failed"]
        assert rows[0]["Severity"] == "Medium"
        assert "greeting (version 4)" in rows[0]["Finding_Details"]
        assert self.result["status"] == "WARN"

    def test_br07_encryption_leg_reads_the_latest_version_only(self):
        client = self._client(
            prompts=[self._summary("p1", "DRAFT")],
            versions={"p1": [self._summary("p1", "1"), self._summary("p1", "2")]},
            version_details={
                ("p1", "1"): {},
                ("p1", "2"): {"customerEncryptionKeyArn": self._CMK_ARN},
            },
        )
        rows = self._encryption_rows(self._run(client))

        assert [row["Status"] for row in rows] == ["Passed"]
        assert client.get_prompt.call_args_list == [
            call(promptIdentifier="p1"),
            call(promptIdentifier="p1", promptVersion="2"),
        ]

    def test_br07_get_prompt_error_on_the_version_is_na_not_unencrypted(self):
        rows = self._encryption_rows(
            self._run(
                self._client(
                    prompts=[self._summary("p1", "DRAFT")],
                    versions={"p1": [self._summary("p1", "1")]},
                    version_details={
                        ("p1", "1"): _client_error(
                            "AccessDeniedException", "no", "GetPrompt"
                        )
                    },
                )
            )
        )

        assert [row["Status"] for row in rows] == ["N/A"]
        assert "bedrock:GetPrompt" in rows[0]["Resolution"]
        assert "AccessDeniedException" in rows[0]["Finding_Details"]

    def test_br07_draft_only_prompt_stays_out_of_the_encryption_denominator(self):
        rows = self._encryption_rows(
            self._run(
                self._client(
                    prompts=[
                        self._summary("p1", "DRAFT"),
                        self._summary("p2", "DRAFT"),
                    ],
                    versions={
                        "p1": [self._summary("p1", "DRAFT")],
                        "p2": [self._summary("p2", "1")],
                    },
                    version_details={
                        ("p2", "1"): {"customerEncryptionKeyArn": self._CMK_ARN}
                    },
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Passed"]
        assert "1 of 1 versioned prompt(s)" in rows[0]["Finding_Details"]

    # ------------------------------------------------------------------
    # Leg C: what the flows of the Region actually reference
    # ------------------------------------------------------------------
    def _flow_client(self, flows, flow_definitions, **kwargs):
        return self._client(
            prompts=[self._summary("p1", "DRAFT")],
            versions={"p1": [self._summary("p1", "1")]},
            version_details={("p1", "1"): {"customerEncryptionKeyArn": self._CMK_ARN}},
            flows=flows,
            flow_definitions=flow_definitions,
            **kwargs,
        )

    def test_br07_flow_node_pinning_a_version_passes(self):
        rows = self._flow_rows(
            self._run(
                self._flow_client(
                    [{"id": "f1", "name": "support"}],
                    {
                        "f1": self._flow(
                            [self._prompt_node("classify", f"{self._PROMPT_ARN}:3")]
                        )
                    },
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Passed"]
        assert "1 of 1 prompt reference(s)" in rows[0]["Finding_Details"]
        assert (
            "flow 'support' node 'classify' pins version 3"
            in (rows[0]["Finding_Details"])
        )

    def test_br07_flow_node_without_a_version_suffix_fails(self):
        rows = self._flow_rows(
            self._run(
                self._flow_client(
                    [{"id": "f1", "name": "support"}],
                    {
                        "f1": self._flow(
                            [self._prompt_node("classify", self._PROMPT_ARN)]
                        )
                    },
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Failed"]
        assert rows[0]["Severity"] == "Medium"
        details = rows[0]["Finding_Details"]
        assert "flow 'support' node 'classify'" in details
        assert self._PROMPT_ARN in details
        assert self.result["status"] == "WARN"

    def test_br07_prompt_node_inside_a_loop_is_walked(self):
        """A DoWhile loop carries its own definition, and a prompt node is legal there."""
        loop_node = {
            "name": "retry",
            "type": "Loop",
            "configuration": {
                "loop": {
                    "definition": {
                        "nodes": [self._prompt_node("looped", self._PROMPT_ARN)]
                    }
                }
            },
        }
        rows = self._flow_rows(
            self._run(
                self._flow_client(
                    [{"id": "f1", "name": "support"}], {"f1": self._flow([loop_node])}
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Failed"]
        assert "node 'looped'" in rows[0]["Finding_Details"]

    def test_br07_inline_prompt_node_is_not_a_managed_reference(self):
        inline_node = {
            "name": "inline",
            "type": "Prompt",
            "configuration": {
                "prompt": {
                    "sourceConfiguration": {
                        "inline": {
                            "templateType": "TEXT",
                            "modelId": "anthropic.claude-v2",
                            "templateConfiguration": {"text": {"text": "hello"}},
                        }
                    }
                }
            },
        }
        findings = self._run(
            self._flow_client(
                [{"id": "f1", "name": "support"}], {"f1": self._flow([inline_node])}
            )
        )

        assert self._flow_rows(findings) == []

    def test_br07_five_digit_version_suffix_is_pinned(self):
        rows = self._flow_rows(
            self._run(
                self._flow_client(
                    [{"id": "f1", "name": "support"}],
                    {
                        "f1": self._flow(
                            [self._prompt_node("classify", f"{self._PROMPT_ARN}:12345")]
                        )
                    },
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Passed"]
        assert "pins version 12345" in rows[0]["Finding_Details"]

    def test_br07_flow_list_error_is_na_not_pinned(self):
        rows = self._flow_rows(
            self._run(
                self._flow_client(
                    [],
                    {},
                    flows_error=_client_error(
                        "AccessDeniedException", "no", "ListFlows"
                    ),
                )
            )
        )

        assert [row["Status"] for row in rows] == ["N/A"]
        assert "bedrock:ListFlows" in rows[0]["Resolution"]
        assert "AccessDeniedException" in rows[0]["Finding_Details"]

    def test_br07_flow_detail_error_keeps_the_other_flow_and_is_na(self):
        rows = self._flow_rows(
            self._run(
                self._flow_client(
                    [{"id": "f1", "name": "support"}, {"id": "f2", "name": "closed"}],
                    {
                        "f1": self._flow(
                            [self._prompt_node("classify", f"{self._PROMPT_ARN}:3")]
                        ),
                        "f2": _client_error("AccessDeniedException", "no", "GetFlow"),
                    },
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Passed", "N/A"]
        assert "closed" in rows[1]["Finding_Details"]
        assert "bedrock:GetFlow" in rows[1]["Resolution"]

    def test_br07_two_flow_nodes_reach_both_reference_verdicts(self):
        rows = self._flow_rows(
            self._run(
                self._flow_client(
                    [{"id": "f1", "name": "support"}],
                    {
                        "f1": self._flow(
                            [
                                self._prompt_node("pinned", f"{self._PROMPT_ARN}:3"),
                                self._prompt_node("unpinned", self._PROMPT_ARN),
                            ]
                        )
                    },
                )
            )
        )

        assert [row["Status"] for row in rows] == ["Failed", "Passed"]
        assert "1 of 2 prompt reference(s)" in rows[0]["Finding_Details"]
        assert "1 of 2 prompt reference(s)" in rows[1]["Finding_Details"]

    def test_br07_flow_without_a_prompt_node_emits_no_flow_row(self):
        lambda_node = {
            "name": "enrich",
            "type": "LambdaFunction",
            "configuration": {
                "lambdaFunction": {
                    "lambdaArn": "arn:aws:lambda:us-east-1:123456789012:function:f"
                }
            },
        }
        findings = self._run(
            self._flow_client(
                [{"id": "f1", "name": "support"}], {"f1": self._flow([lambda_node])}
            )
        )

        assert self._flow_rows(findings) == []

    def test_br07_a_pinned_encrypted_estate_keeps_the_check_passing(self):
        findings = self._run(
            self._flow_client(
                [{"id": "f1", "name": "support"}],
                {
                    "f1": self._flow(
                        [self._prompt_node("classify", f"{self._PROMPT_ARN}:1")]
                    )
                },
            )
        )

        assert self.result["status"] == "PASS"
        assert [finding["Status"] for finding in findings] == [
            "Passed",
            "Passed",
            "Passed",
            "Passed",
        ]

    def test_br07_version_rows_pass_the_finding_schema(self):
        findings = self._run(
            self._client(
                prompts=[
                    self._summary("p1", "DRAFT", name="pinned"),
                    self._summary("p2", "DRAFT", name="draft-only"),
                    self._summary("p3", "DRAFT", name="closed"),
                ],
                versions={
                    "p1": [self._summary("p1", "1")],
                    "p2": [self._summary("p2", "DRAFT")],
                    "p3": _client_error("AccessDeniedException", "no", "ListPrompts"),
                },
                version_details={("p1", "1"): {}},
                flows=[{"id": "f1", "name": "support"}],
                flow_definitions={
                    "f1": self._flow([self._prompt_node("classify", self._PROMPT_ARN)])
                },
            )
        )

        rows = (
            self._version_rows(findings)
            + self._encryption_rows(findings)
            + self._flow_rows(findings)
        )
        assert sorted(row["Status"] for row in rows) == [
            "Failed",
            "Failed",
            "Failed",
            "N/A",
            "Passed",
        ]
        for finding in rows:
            assert_finding_schema(finding)
            assert finding["Check_ID"] == "BR-07"
            assert finding["Region"] == "us-east-1"


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
        """A job that names an output key passes.

        This branch was covered before, by a fixture that set
        outputDataConfig.kmsKeyId, the same key the predicate read. Neither
        exists: GetModelCustomizationJob returns an outputDataConfig holding
        s3Uri alone and reports the key as a top-level outputModelKmsKeyArn. The
        test and the code agreed with each other and with nothing else, so the
        coverage was real and the assertion was vacuous -- against a live job
        the check could only ever report every custom model as needing review.
        The fixture below is the shape the API documents.
        """
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
            "outputDataConfig": {"s3Uri": "s3://out/"},
            "outputModelKmsKeyArn": (
                "arn:aws:kms:us-east-1:123456789012:key/"
                "11111111-2222-3333-4444-555555555555"
            ),
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-11"

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

    def test_br42_wildcard_inside_the_resource_segment_is_not_an_allow_list(self):
        """foundation-model* has no "/*" or ":*" ending yet names every model."""
        findings = self._run(
            _identity_cache(
                roles={
                    "ScopedRole": [
                        ("ScopedInvoke", _allow("bedrock:InvokeModel", self.MODEL_ARN))
                    ],
                    "StarSegmentRole": [
                        (
                            "StarSegment",
                            _allow(
                                "bedrock:InvokeModel",
                                ["arn:aws:bedrock:*::foundation-model*"],
                            ),
                        )
                    ],
                    "ProfileRole": [
                        (
                            "ProfileStar",
                            _allow(
                                "bedrock:InvokeModel",
                                ["arn:aws:bedrock:us-east-1:*:inference-profile/?*"],
                            ),
                        )
                    ],
                }
            )
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        failed_text = " ".join(f["Finding_Details"] for f in failed)
        assert len(failed) == 2
        assert "Role 'StarSegmentRole'" in failed_text
        assert "Role 'ProfileRole'" in failed_text
        assert len(passed) == 1
        assert "ScopedRole" in passed[0]["Finding_Details"]

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
        classification_jobs=(),
        classification_jobs_error=None,
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
        # Two paginators are read, so each one answers under its own operation
        # name: a single shared mock would let the bucket inventory answer the
        # classification job list with buckets and vice versa.
        buckets_paginator = MagicMock()
        if describe_buckets_error:
            buckets_paginator.paginate.side_effect = describe_buckets_error
        else:
            buckets_paginator.paginate.return_value = [{"buckets": list(macie_buckets)}]
        jobs_paginator = MagicMock()
        if classification_jobs_error:
            jobs_paginator.paginate.side_effect = classification_jobs_error
        else:
            jobs_paginator.paginate.return_value = [
                {"items": list(classification_jobs)}
            ]
        macie_client.get_paginator.side_effect = lambda operation: {
            "describe_buckets": buckets_paginator,
            "list_classification_jobs": jobs_paginator,
        }[operation]
        # Exposed so a case can assert which macie2 operations were reached.
        self.macie_client = macie_client

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


class TestBR46ClassificationJobCoverage:
    """
    BR-46 job leg: a targeted Macie classification job is the other mechanism.

    Automated sensitive data discovery reporting NOT_MONITORED is not the whole
    answer, because a classification job can inspect the same bucket. Only a
    scheduled job that will run again counts, so every case below fixes the
    bucket inventory and varies the job.
    """

    _BUCKETS = [
        {
            "bucketName": "support-bucket",
            "automatedDiscoveryMonitoringStatus": "MONITORED",
        },
        {
            "bucketName": "hr-bucket",
            "automatedDiscoveryMonitoringStatus": "NOT_MONITORED",
        },
    ]

    _BOTH_UNMONITORED = [
        {
            "bucketName": "support-bucket",
            "automatedDiscoveryMonitoringStatus": "NOT_MONITORED",
        },
        {
            "bucketName": "hr-bucket",
            "automatedDiscoveryMonitoringStatus": "NOT_MONITORED",
        },
    ]

    def _run(self, **kwargs):
        """Reuse the two-bucket estate so only the job list varies."""
        estate = TestBR46KnowledgeBaseSourceClassification()
        kwargs.setdefault("macie_buckets", self._BUCKETS)
        findings = estate._two_bucket_estate(**kwargs)
        self.macie_client = estate.macie_client
        return findings

    @staticmethod
    def _job(
        name,
        buckets=(),
        job_type="SCHEDULED",
        status="IDLE",
        last_run_error=None,
        criteria=None,
    ):
        job = {
            "jobId": f"job-{name}",
            "name": name,
            "jobType": job_type,
            "jobStatus": status,
        }
        if buckets:
            job["bucketDefinitions"] = [
                {"accountId": "123456789012", "buckets": list(buckets)}
            ]
        if criteria:
            job["bucketCriteria"] = criteria
        if last_run_error:
            job["lastRunErrorStatus"] = {"code": last_run_error}
        return job

    @staticmethod
    def _job_rows(findings):
        return [
            finding
            for finding in findings
            if finding["Finding"] == bedrock_app.CLASSIFICATION_JOB_FINDING
        ]

    def test_br46_scheduled_job_clears_an_unmonitored_bucket(self):
        findings = self._run(
            classification_jobs=[self._job("nightly-hr", ["hr-bucket"])]
        )

        assert not [f for f in findings if f["Status"] == "Failed"]
        job_rows = self._job_rows(findings)
        assert len(job_rows) == 1
        assert job_rows[0]["Status"] == "Passed"
        assert job_rows[0]["Check_ID"] == "BR-46"
        assert (
            "hr-bucket is classified by scheduled Macie job 'nightly-hr' (IDLE)"
            in (job_rows[0]["Finding_Details"])
        )
        assert (
            "1 of 2 knowledge base source bucket(s)" in job_rows[0]["Finding_Details"]
        )

    def test_br46_running_scheduled_job_also_clears_the_bucket(self):
        """RUNNING and IDLE both mean the schedule is live, so both count."""
        findings = self._run(
            classification_jobs=[
                self._job("nightly-hr", ["hr-bucket"], status="RUNNING")
            ]
        )

        assert not [f for f in findings if f["Status"] == "Failed"]
        assert "(RUNNING)" in self._job_rows(findings)[0]["Finding_Details"]

    def test_br46_one_time_job_does_not_clear_an_unmonitored_bucket(self):
        findings = self._run(
            classification_jobs=[
                self._job(
                    "one-shot", ["hr-bucket"], job_type="ONE_TIME", status="COMPLETE"
                )
            ]
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "hr-bucket is NOT_MONITORED" in failed[0]["Finding_Details"]
        assert (
            "Macie job 'one-shot' is ONE_TIME and COMPLETE"
            in (failed[0]["Finding_Details"])
        )
        assert (
            "nothing ingested since that run is classified"
            in (failed[0]["Finding_Details"])
        )
        assert not self._job_rows(findings)

    def test_br46_paused_scheduled_job_does_not_clear_the_bucket(self):
        findings = self._run(
            classification_jobs=[
                self._job("nightly-hr", ["hr-bucket"], status="USER_PAUSED")
            ]
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert (
            "the scheduled Macie job naming it, 'nightly-hr', is USER_PAUSED"
            in (failed[0]["Finding_Details"])
        )
        assert not self._job_rows(findings)

    def test_br46_scheduled_job_whose_last_run_errored_does_not_clear_the_bucket(self):
        """A live schedule whose run failed classified nothing on that run."""
        findings = self._run(
            classification_jobs=[
                self._job(
                    "nightly-hr",
                    ["hr-bucket"],
                    status="RUNNING",
                    last_run_error="ERROR",
                )
            ]
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "lastRunErrorStatus ERROR" in failed[0]["Finding_Details"]
        assert not self._job_rows(findings)

    def test_br46_last_run_error_code_none_still_clears_the_bucket(self):
        """lastRunErrorStatus is present on a healthy job with code NONE."""
        findings = self._run(
            classification_jobs=[
                self._job("nightly-hr", ["hr-bucket"], last_run_error="NONE")
            ]
        )

        assert not [f for f in findings if f["Status"] == "Failed"]
        assert self._job_rows(findings)[0]["Status"] == "Passed"

    def test_br46_job_naming_another_bucket_does_not_clear_this_one(self):
        findings = self._run(
            classification_jobs=[self._job("nightly-other", ["unrelated-bucket"])]
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert (
            "No Macie classification job in this Region names hr-bucket either."
            in (failed[0]["Finding_Details"])
        )
        assert "nightly-other" not in failed[0]["Finding_Details"]
        assert not self._job_rows(findings)

    def test_br46_two_unmonitored_buckets_reach_both_verdicts(self):
        findings = self._run(
            macie_buckets=self._BOTH_UNMONITORED,
            classification_jobs=[self._job("nightly-support", ["support-bucket"])],
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        job_rows = self._job_rows(findings)
        assert len(failed) == 1
        assert "hr-bucket is NOT_MONITORED" in failed[0]["Finding_Details"]
        assert len(job_rows) == 1
        assert job_rows[0]["Status"] == "Passed"
        assert "support-bucket" in job_rows[0]["Finding_Details"]
        # One bucket's job cannot speak for the other.
        assert "hr-bucket" not in job_rows[0]["Finding_Details"]

    def test_br46_a_live_job_after_a_cancelled_one_still_clears_the_bucket(self):
        findings = self._run(
            classification_jobs=[
                self._job("old-hr", ["hr-bucket"], status="CANCELLED"),
                self._job("nightly-hr", ["hr-bucket"]),
            ]
        )

        assert not [f for f in findings if f["Status"] == "Failed"]
        assert "'nightly-hr'" in self._job_rows(findings)[0]["Finding_Details"]

    def test_br46_bucket_criteria_job_is_indeterminate_not_coverage(self):
        findings = self._run(
            classification_jobs=[
                self._job(
                    "by-tag",
                    criteria={
                        "includes": {
                            "and": [
                                {
                                    "tagCriterion": {
                                        "comparator": "EQ",
                                        "tagValues": [{"key": "pii", "value": "yes"}],
                                    }
                                }
                            ]
                        }
                    },
                )
            ]
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        job_rows = self._job_rows(findings)
        assert len(failed) == 1
        assert len(job_rows) == 1
        assert job_rows[0]["Status"] == "N/A"
        assert job_rows[0]["Severity"] == "Informational"
        assert (
            "select their buckets with bucketCriteria instead of naming them"
            in (job_rows[0]["Finding_Details"])
        )
        assert "by-tag" in job_rows[0]["Finding_Details"]
        assert "hr-bucket" in job_rows[0]["Finding_Details"]

    def test_br46_job_list_failure_is_na_not_coverage_and_not_absence(self):
        findings = self._run(
            classification_jobs_error=_make_client_error("AccessDeniedException"),
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        job_rows = self._job_rows(findings)
        assert len(failed) == 1
        # The monitoring verdict stands, but the check must not claim no job
        # names the bucket when it could not read the job list.
        assert "No Macie classification job" not in failed[0]["Finding_Details"]
        assert len(job_rows) == 1
        assert job_rows[0]["Status"] == "N/A"
        assert (
            "The Macie classification job list could not be read"
            in (job_rows[0]["Finding_Details"])
        )
        assert "hr-bucket" in job_rows[0]["Finding_Details"]
        assert "macie2:ListClassificationJobs" in job_rows[0]["Resolution"]

    def test_br46_job_list_is_not_read_when_every_bucket_is_monitored(self):
        """Nothing is failing, so the second Macie call buys nothing."""
        findings = self._run(
            macie_buckets=[
                {
                    "bucketName": "support-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                },
                {
                    "bucketName": "hr-bucket",
                    "automatedDiscoveryMonitoringStatus": "MONITORED",
                },
            ],
            classification_jobs=[self._job("nightly-hr", ["hr-bucket"])],
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert not self._job_rows(findings)
        self.macie_client.get_paginator.assert_called_once_with("describe_buckets")

    def test_br46_job_coverage_reads_the_job_list_only(self):
        """One macie2 job action: DescribeClassificationJob is never called."""
        self._run(classification_jobs=[self._job("nightly-hr", ["hr-bucket"])])

        assert [
            call.args[0] for call in self.macie_client.get_paginator.call_args_list
        ] == ["describe_buckets", "list_classification_jobs"]
        assert self.macie_client.describe_classification_job.call_count == 0
        assert self.macie_client.list_classification_jobs.call_count == 0

    def test_br46_job_rows_pass_the_finding_schema(self):
        covered = self._run(
            classification_jobs=[self._job("nightly-hr", ["hr-bucket"])]
        )
        criteria = self._run(
            classification_jobs=[
                self._job("by-tag", criteria={"includes": {"and": []}})
            ]
        )
        unreadable = self._run(
            classification_jobs_error=_make_client_error("AccessDeniedException")
        )

        rows = (
            self._job_rows(covered)
            + self._job_rows(criteria)
            + self._job_rows(unreadable)
        )
        assert len(rows) == 3
        for finding in rows:
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
        agent_client.list_data_sources.return_value = {"dataSourceSummaries": []}
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
        agent_client.list_data_sources.return_value = {"dataSourceSummaries": []}
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
        agent_client.list_data_sources.return_value = {"dataSourceSummaries": []}
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
        agent_client.list_data_sources.return_value = {"dataSourceSummaries": []}
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
    def _index_arn(bucket_arn, index_name="kb-index"):
        """The index ARN a knowledge base on `bucket_arn` reports."""
        return f"{bucket_arn}/index/{index_name}"

    @classmethod
    def _s3_vectors_kb_body(cls, bucket_arn, index="arn"):
        """A VECTOR knowledge base whose storage is an S3 Vectors bucket.

        `index` chooses which index identifiers the knowledge base reports, the
        three shapes s3VectorsConfiguration allows: "arn" for indexArn plus
        indexName, "name" for indexName alone (GetIndex then needs the bucket
        name), and None for neither, which is the shape that cannot be assessed.
        """
        storage = {"type": "S3_VECTORS"}
        if bucket_arn is not None:
            config = {"vectorBucketArn": bucket_arn}
            if index == "arn":
                config["indexArn"] = cls._index_arn(bucket_arn)
                config["indexName"] = "kb-index"
            elif index == "name":
                config["indexName"] = "kb-index"
            storage["s3VectorsConfiguration"] = config
        return {
            "knowledgeBaseConfiguration": {
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {},
            },
            "storageConfiguration": storage,
        }

    @staticmethod
    def _agent_client_for(bodies):
        """bodies: {kb_id: knowledgeBase body}, answered per knowledgeBaseId.

        These knowledge bases hold no data source, which is what keeps the
        data-source-bucket encryption leg out of the rows a case below asserts.
        """
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": kb_id, "name": f"KB-{kb_id}"} for kb_id in bodies
            ]
        }
        agent_client.list_data_sources.return_value = {"dataSourceSummaries": []}
        agent_client.get_knowledge_base.side_effect = lambda **kwargs: {
            "knowledgeBase": bodies[kwargs["knowledgeBaseId"]]
        }
        return agent_client

    @staticmethod
    def _vectors_client(
        encryption=None,
        bucket_error=None,
        policy="",
        policy_error=None,
        index_encryption=None,
        index_error=None,
        index_calls=None,
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
        if index_error is not None:
            vectors_client.get_index.side_effect = index_error
        else:
            # Every index read live on 2026-09-25 echoed its bucket's
            # encryption configuration, so that is the default here and a case
            # has to ask for an override. `index_calls` records the lookup
            # keywords, which is the only way to see WHICH index was read.
            def get_index(**kwargs):
                if index_calls is not None:
                    index_calls.append(kwargs)
                inherited = encryption or {}
                return {
                    "index": {
                        "encryptionConfiguration": (
                            inherited if index_encryption is None else index_encryption
                        )
                    }
                }

            vectors_client.get_index.side_effect = get_index
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
        self,
        mock_client,
        *,
        bucket_arn=_BUCKET_ARN,
        scan_region="us-east-1",
        index="arn",
        **vectors,
    ):
        """Run BR-20 over a single S3 Vectors knowledge base.

        Returns (findings, clients_built).
        """
        clients_built = []
        mock_client.side_effect = self._by_service(
            self._agent_client_for(
                {"kb1": self._s3_vectors_kb_body(bucket_arn, index=index)}
            ),
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

        index_encryption = {self._index_arn(arn): enc for _, arn, enc, _ in stores}

        vectors_client = MagicMock()
        vectors_client.get_vector_bucket.side_effect = lambda **kwargs: {
            "vectorBucket": {
                "vectorBucketArn": kwargs["vectorBucketArn"],
                "encryptionConfiguration": encryption[kwargs["vectorBucketArn"]],
            }
        }
        # Each index inherits its own bucket's configuration, so the index leg
        # adds no verdict of its own to a population case. Keyed by index ARN,
        # not bucket ARN, so a check that passed the wrong ARN would KeyError.
        vectors_client.get_index.side_effect = lambda **kwargs: {
            "index": {"encryptionConfiguration": index_encryption[kwargs["indexArn"]]}
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
        # Both encryption legs are named in the Passed row: the bucket's and the
        # index's. The row used to disclaim the index leg instead of reading it,
        # so the old sentence must be gone rather than merely joined.
        assert "vector bucket encryption is SSE-KMS" in findings[0]["Finding_Details"]
        assert (
            "vector index 'kb-index' encryption is SSE-KMS"
            in findings[0]["Finding_Details"]
        )
        assert "are not read by this check" not in findings[0]["Finding_Details"]

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
    def test_br20_s3_vectors_index_override_fails_a_cmk_bucket(self, mock_client):
        # The gap the index leg closes. The bucket is SSE-KMS with a
        # customer-managed key and carries a policy, so both of the other legs
        # pass; the index the knowledge base names was created with its own
        # AES256 encryptionConfiguration, which is what the embeddings are
        # actually encrypted with. Without this leg the store reads as compliant.
        findings, _ = self._run_one(
            mock_client,
            encryption=self._CMK,
            policy='{"Statement": []}',
            index_encryption={"sseType": "AES256"},
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Check_ID"] == "BR-20"
        assert findings[0]["Severity"] == "High"
        assert "vector bucket encryption is SSE-KMS" in findings[0]["Finding_Details"]
        assert (
            "vector index 'kb-index' encryption is sseType=AES256"
            in findings[0]["Finding_Details"]
        )
        assert (
            "an index encryptionConfiguration overrides the bucket's"
            in findings[0]["Finding_Details"]
        )

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_reads_the_index_each_knowledge_base_names(
        self, mock_client
    ):
        # Two knowledge bases on ONE vector bucket, each naming its own index:
        # kb1's is customer-managed, kb2's is AES256. Three implementations this
        # separates, all of which the single-store cases above accept:
        # a loop truncated to the first knowledge base (one row, Passed), a leg
        # that reads one index per bucket instead of per knowledge base (two
        # identical verdicts), and a leg that assessed every index in the bucket
        # (two Failed rows, attributing kb2's index to kb1).
        bucket = self._BUCKET_ARN
        indexes = {
            "kb1": self._index_arn(bucket, "kb1-index"),
            "kb2": self._index_arn(bucket, "kb2-index"),
        }
        index_encryption = {
            indexes["kb1"]: self._CMK,
            indexes["kb2"]: {"sseType": "AES256"},
        }

        def body(index_arn):
            return {
                "knowledgeBaseConfiguration": {
                    "type": "VECTOR",
                    "vectorKnowledgeBaseConfiguration": {},
                },
                "storageConfiguration": {
                    "type": "S3_VECTORS",
                    "s3VectorsConfiguration": {
                        "vectorBucketArn": bucket,
                        "indexArn": index_arn,
                    },
                },
            }

        index_calls = []

        def get_index(**kwargs):
            index_calls.append(kwargs["indexArn"])
            return {
                "index": {
                    "encryptionConfiguration": index_encryption[kwargs["indexArn"]]
                }
            }

        vectors_client = MagicMock()
        vectors_client.get_vector_bucket.side_effect = lambda **kwargs: {
            "vectorBucket": {"encryptionConfiguration": self._CMK}
        }
        vectors_client.get_index.side_effect = get_index
        vectors_client.get_vector_bucket_policy.return_value = {
            "policy": '{"Statement": []}'
        }
        mock_client.side_effect = self._by_service(
            self._agent_client_for({kb: body(arn) for kb, arn in indexes.items()}),
            vectors_client,
            [],
        )

        findings = extract_csv_data(
            bedrock_app.check_bedrock_knowledge_base_kms_encryption(region="us-east-1")
        )
        assert [f["Status"] for f in findings] == ["Passed", "Failed"]
        assert index_calls == [indexes["kb1"], indexes["kb2"]]
        assert "kb1-index' encryption is SSE-KMS" in findings[0]["Finding_Details"]
        assert (
            "kb2-index' encryption is sseType=AES256" in findings[1]["Finding_Details"]
        )
        assert "kb2-index" not in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_index_inheriting_the_bucket_is_not_a_failure(
        self, mock_client
    ):
        # An index created without an encryptionConfiguration inherits the
        # bucket's, which the service model documents as the default. Requiring
        # the field to be present would fail every index that never overrode it,
        # which is the shape a compliant store has.
        findings, _ = self._run_one(
            mock_client,
            encryption=self._CMK,
            policy='{"Statement": []}',
            index_encryption={},
        )
        assert [f["Status"] for f in findings] == ["Passed"]
        assert (
            "carries no encryptionConfiguration of its own and inherits the bucket's"
            in findings[0]["Finding_Details"]
        )

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_index_access_denied_names_the_permission(
        self, mock_client
    ):
        # Same convention as the GetVectorBucketPolicy leg: a permission gap is
        # neither a pass nor a fail, and the row names the action to grant.
        findings, _ = self._run_one(
            mock_client,
            encryption=self._CMK,
            policy='{"Statement": []}',
            index_error=self._client_error("AccessDeniedException", "GetIndex"),
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Severity"] == "Informational"
        assert "s3vectors:GetIndex" in findings[0]["Finding_Details"]
        assert findings[0]["Finding"].endswith("Review")

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_index_not_found_is_not_a_failure(self, mock_client):
        # NotFoundException on GetIndex is a broken knowledge base, not evidence
        # that its embeddings are unencrypted. The policy leg treats the same
        # error code as an answer about the workload because a missing policy IS
        # the finding there; a missing index is not.
        findings, _ = self._run_one(
            mock_client,
            encryption=self._CMK,
            policy='{"Statement": []}',
            index_error=self._client_error("NotFoundException", "GetIndex"),
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "could not be read" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_failed_bucket_encryption_outranks_an_unreadable_index(
        self, mock_client
    ):
        findings, _ = self._run_one(
            mock_client,
            encryption={"sseType": "AES256"},
            policy='{"Statement": []}',
            index_error=self._client_error("AccessDeniedException", "GetIndex"),
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_index_failure_outranks_an_unreadable_policy(
        self, mock_client
    ):
        findings, _ = self._run_one(
            mock_client,
            encryption=self._CMK,
            index_encryption={"sseType": "AES256"},
            policy_error=self._client_error(
                "AccessDeniedException", "GetVectorBucketPolicy"
            ),
        )
        assert [f["Status"] for f in findings] == ["Failed"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_index_lookup_prefers_the_arn(self, mock_client):
        index_calls = []
        self._run_one(
            mock_client,
            encryption=self._CMK,
            policy='{"Statement": []}',
            index_calls=index_calls,
        )
        assert index_calls == [{"indexArn": self._index_arn(self._BUCKET_ARN)}]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_index_lookup_falls_back_to_the_bucket_and_index_name(
        self, mock_client
    ):
        # GetIndex accepts the index ARN, or the bucket NAME with the index name.
        # It does not accept the bucket ARN, so a knowledge base that reports
        # only indexName needs the name parsed out of the bucket ARN. Abstaining
        # on this shape would be a self-inflicted could-not-assess.
        index_calls = []
        findings, _ = self._run_one(
            mock_client,
            index="name",
            encryption=self._CMK,
            policy='{"Statement": []}',
            index_calls=index_calls,
        )
        assert index_calls == [
            {"vectorBucketName": "kb-vectors", "indexName": "kb-index"}
        ]
        assert [f["Status"] for f in findings] == ["Passed"]

    @patch("bedrock_app.boto3.client")
    def test_br20_s3_vectors_without_an_index_identifier_cannot_pass(self, mock_client):
        # A knowledge base that reports a vector bucket but neither indexArn nor
        # indexName: an index-level override cannot be ruled out, so the store
        # does not pass on the bucket alone. Same treatment as the missing
        # vectorBucketArn above, and no GetIndex call is made.
        index_calls = []
        findings, _ = self._run_one(
            mock_client,
            index=None,
            encryption=self._CMK,
            policy='{"Statement": []}',
            index_calls=index_calls,
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert index_calls == []
        assert "neither" in findings[0]["Finding_Details"]
        assert "indexArn nor indexName" in findings[0]["Finding_Details"]

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
        vectors_client.get_index.side_effect = lambda **kwargs: {
            "index": {
                "encryptionConfiguration": encryption[
                    kwargs["indexArn"].rsplit("/index/", 1)[0]
                ]
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
        # BR-39 resolves each registered subnet to its route table, so the ec2
        # client is supplied here for the same reason kms_client is.
        privacy_helper = TestBR39MarketplaceSubnetPrivacy
        ec2_client = privacy_helper._ec2(
            [{"SubnetId": "subnet-1", "VpcId": "vpc-1"}],
            [
                privacy_helper._table(
                    "rtb-1", privacy_helper._PRIVATE_TABLE["Routes"], main=True
                )
            ],
        )
        br39_rows = extract_csv_data(
            bedrock_app.check_bedrock_marketplace_endpoint_vpc(
                "us-east-1", inventory, ec2_client
            )
        )
        br39 = br39_rows[0]
        assert [row["Status"] for row in br39_rows] == ["Passed", "Passed"]
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


# ===================================================================
# BR-47: check_bedrock_data_path_bucket_tls
# ===================================================================
def _client_error(code, message="denied", operation="GetBucketPolicy"):
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _tls_deny_statement(
    buckets,
    sid="DenyInsecureTransport",
    principal="*",
    actions="s3:*",
    operator="Bool",
    value="false",
    resources=None,
):
    """The documented TLS-only statement, with one element parameterised per test."""
    if resources is None:
        resources = []
        for bucket in buckets:
            resources.extend([f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"])
    statement = {
        "Sid": sid,
        "Effect": "Deny",
        "Action": actions,
        "Resource": resources,
        "Condition": {operator: {"aws:SecureTransport": value}},
    }
    if principal is not None:
        statement["Principal"] = principal
    return statement


def _bucket_policy(*statements):
    return {
        "Policy": json.dumps({"Version": "2012-10-17", "Statement": list(statements)})
    }


class TestBR47DataPathBucketTLS:
    """BR-47: every Bedrock data path bucket must deny plaintext requests."""

    def _run(
        self,
        knowledge_bases=(),
        data_sources=None,
        data_source_detail=None,
        logging_config=None,
        logging_error=None,
        bucket_policies=None,
        list_knowledge_bases_error=None,
        get_data_source_error=None,
        customization_jobs=None,
        list_customization_jobs_error=None,
        customization_pages=None,
    ):
        agent_client = MagicMock()
        if list_knowledge_bases_error:
            agent_client.list_knowledge_bases.side_effect = list_knowledge_bases_error
        else:
            agent_client.list_knowledge_bases.return_value = {
                "knowledgeBaseSummaries": list(knowledge_bases)
            }
        data_sources = data_sources or {}
        agent_client.list_data_sources.side_effect = lambda **kwargs: {
            "dataSourceSummaries": data_sources.get(kwargs["knowledgeBaseId"], [])
        }
        detail = data_source_detail or {}

        def get_data_source(**kwargs):
            if (
                get_data_source_error
                and kwargs["dataSourceId"] in get_data_source_error
            ):
                raise get_data_source_error[kwargs["dataSourceId"]]
            return detail[kwargs["dataSourceId"]]

        agent_client.get_data_source.side_effect = get_data_source

        bedrock_client = MagicMock()
        self.bedrock_client = bedrock_client
        if logging_error:
            bedrock_client.get_model_invocation_logging_configuration.side_effect = (
                logging_error
            )
        else:
            bedrock_client.get_model_invocation_logging_configuration.return_value = (
                logging_config or {}
            )
        jobs = customization_jobs or {}
        if list_customization_jobs_error:
            bedrock_client.list_model_customization_jobs.side_effect = (
                list_customization_jobs_error
            )
        elif customization_pages:
            bedrock_client.list_model_customization_jobs.side_effect = (
                customization_pages
            )
        else:
            bedrock_client.list_model_customization_jobs.return_value = {
                "modelCustomizationJobSummaries": [
                    {
                        "jobArn": f"arn:aws:bedrock:us-east-1:111122223333:model-customization-job/{name}",
                        "jobName": name,
                    }
                    for name in jobs
                ]
            }

        def get_job(jobIdentifier):
            detail = jobs[jobIdentifier.rsplit("/", 1)[-1]]
            if isinstance(detail, Exception):
                raise detail
            return detail

        bedrock_client.get_model_customization_job.side_effect = get_job

        s3_client = MagicMock()
        policies = bucket_policies or {}

        def get_bucket_policy(Bucket):
            entry = policies.get(Bucket, _client_error("NoSuchBucketPolicy"))
            if isinstance(entry, Exception):
                raise entry
            return entry

        s3_client.get_bucket_policy.side_effect = get_bucket_policy
        self.last_s3_client = s3_client

        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "bedrock-agent": agent_client,
                "bedrock": bedrock_client,
                "s3": s3_client,
            }[service],
        ):
            return extract_csv_data(
                bedrock_app.check_bedrock_data_path_bucket_tls(region="us-east-1")
            )

    @staticmethod
    def _s3_source(data_source_id, name, bucket):
        return {
            "dataSource": {
                "dataSourceId": data_source_id,
                "name": name,
                "dataSourceConfiguration": {
                    "type": "S3",
                    "s3Configuration": {"bucketArn": f"arn:aws:s3:::{bucket}"},
                },
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

    def test_br47_enforced_and_plaintext_buckets_discriminate(self):
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _bucket_policy(
                    _tls_deny_statement(["support-bucket"])
                ),
                "hr-bucket": _bucket_policy(
                    {
                        "Sid": "AllowRead",
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/ingest"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::hr-bucket/*",
                    }
                ),
            }
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert failed[0]["Check_ID"] == "BR-47"
        assert failed[0]["Severity"] == "High"
        assert "Bucket hr-bucket" in failed[0]["Finding_Details"]
        assert (
            "data source 'hr-docs' in knowledge base 'hr-kb'"
            in failed[0]["Finding_Details"]
        )
        assert (
            "no Deny statement conditioned on aws:SecureTransport being false"
            in failed[0]["Finding_Details"]
        )
        assert len(passed) == 1
        assert "1 of 2 Bedrock data path bucket(s)" in passed[0]["Finding_Details"]
        assert "support-bucket" in passed[0]["Finding_Details"]
        for finding in findings:
            assert_finding_schema(finding)

    def test_br47_a_deny_narrowed_by_another_condition_key_is_not_credited(self):
        """A second condition key limits the Deny to the requests that match it.

        With aws:SourceVpce under StringNotEquals beside aws:SecureTransport, a
        plaintext request through the named endpoint is not denied, so the
        statement does not close the bucket.
        """
        narrowed = _tls_deny_statement(["hr-bucket"])
        narrowed["Condition"]["StringNotEquals"] = {"aws:SourceVpce": "vpce-1a2b3c4d"}
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _bucket_policy(
                    _tls_deny_statement(["support-bucket"])
                ),
                "hr-bucket": _bucket_policy(narrowed),
            }
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "Bucket hr-bucket" in failed[0]["Finding_Details"]
        assert "aws:sourcevpce" in failed[0]["Finding_Details"].lower()
        assert [f["Status"] for f in findings] == ["Failed", "Passed"]

    def test_br47_missing_bucket_policy_is_failed_not_unassessed(self):
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _client_error("NoSuchBucketPolicy"),
                "hr-bucket": _bucket_policy(_tls_deny_statement(["hr-bucket"])),
            }
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "no bucket policy at all" in failed[0]["Finding_Details"]
        assert [f["Status"] for f in findings] == ["Failed", "Passed"]

    def test_br47_access_denied_is_na_and_not_a_failure(self):
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _client_error("AccessDenied"),
                "hr-bucket": _client_error("AccessDenied"),
            }
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Severity"] == "Informational"
        assert (
            "neither proven to enforce TLS nor proven to accept plaintext"
            in findings[0]["Finding_Details"]
        )
        assert "support-bucket" in findings[0]["Finding_Details"]

    def test_br47_no_data_path_bucket_returns_na(self):
        findings = self._run()

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Check_ID"] == "BR-47"
        assert (
            "no data path bucket whose transport can be assessed"
            in findings[0]["Finding_Details"]
        )

    def test_br47_knowledge_base_list_error_still_assesses_the_log_bucket(self):
        findings = self._run(
            list_knowledge_bases_error=_client_error(
                "AccessDeniedException", operation="ListKnowledgeBases"
            ),
            logging_config={
                "loggingConfig": {"s3Config": {"bucketName": "log-bucket"}}
            },
            bucket_policies={
                "log-bucket": _bucket_policy(_tls_deny_statement(["log-bucket"]))
            },
        )

        statuses = [f["Status"] for f in findings]
        assert statuses == ["N/A", "N/A"]
        assert "data path read(s) failed" in findings[0]["Finding_Details"]
        assert "knowledge base data sources" in findings[0]["Finding_Details"]
        assert "log-bucket" in findings[1]["Finding_Details"]
        assert "the model invocation log destination" in findings[1]["Finding_Details"]
        assert "the bucket list is incomplete" in findings[1]["Finding_Details"]

    def test_br47_per_data_source_error_still_assesses_the_other_bucket(self):
        findings = self._two_bucket_estate(
            get_data_source_error={
                "ds-2": _client_error(
                    "AccessDeniedException", operation="GetDataSource"
                )
            },
            bucket_policies={
                "support-bucket": _bucket_policy(
                    _tls_deny_statement(["support-bucket"])
                )
            },
        )

        assert [f["Status"] for f in findings] == ["N/A", "N/A"]
        assert "1 data path read(s) failed" in findings[0]["Finding_Details"]
        assert (
            "data source 'hr-docs' in knowledge base 'hr-kb'"
            in findings[0]["Finding_Details"]
        )
        assert "support-bucket" in findings[1]["Finding_Details"]
        assert (
            "1 of the 1 Bedrock data path bucket(s) read"
            in findings[1]["Finding_Details"]
        )

    def test_br47_customization_job_buckets_are_on_the_data_path(self):
        """Training, validation and output buckets of a job are each judged.

        Without the customization leg this estate has no data path bucket and
        reports N/A, though the training corpus bucket accepts plaintext.
        """
        findings = self._run(
            customization_jobs={
                "tune-1": {
                    "trainingDataConfig": {"s3Uri": "s3://train-bucket/corpus/"},
                    "validationDataConfig": {
                        "validators": [{"s3Uri": "s3://valid-bucket/set.jsonl"}]
                    },
                    "outputDataConfig": {"s3Uri": "s3://out-bucket/"},
                }
            },
            bucket_policies={
                "valid-bucket": _bucket_policy(_tls_deny_statement(["valid-bucket"])),
                "out-bucket": _bucket_policy(_tls_deny_statement(["out-bucket"])),
            },
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "Bucket train-bucket" in failed[0]["Finding_Details"]
        assert (
            "the training data of customization job 'tune-1'"
            in failed[0]["Finding_Details"]
        )
        assert len(passed) == 1
        assert "2 of 3 Bedrock data path bucket(s)" in passed[0]["Finding_Details"]
        for finding in findings:
            assert_finding_schema(finding)

    def test_br47_customization_job_list_error_is_an_incomplete_inventory(self):
        findings = self._run(
            list_customization_jobs_error=_client_error(
                "AccessDeniedException", operation="ListModelCustomizationJobs"
            ),
            logging_config={
                "loggingConfig": {"s3Config": {"bucketName": "log-bucket"}}
            },
            bucket_policies={
                "log-bucket": _bucket_policy(_tls_deny_statement(["log-bucket"]))
            },
        )

        assert [f["Status"] for f in findings] == ["N/A", "N/A"]
        assert "model customization jobs" in findings[0]["Finding_Details"]
        assert "bedrock:ListModelCustomizationJobs" in findings[0]["Resolution"]
        assert "the bucket list is incomplete" in findings[1]["Finding_Details"]

    def test_br47_one_unreadable_job_still_assesses_the_others(self):
        findings = self._run(
            customization_jobs={
                "tune-1": _client_error(
                    "AccessDeniedException", operation="GetModelCustomizationJob"
                ),
                "tune-2": {
                    "trainingDataConfig": {"s3Uri": "s3://train-bucket/"},
                    "outputDataConfig": {"s3Uri": "s3://train-bucket/out/"},
                },
            },
            bucket_policies={
                "train-bucket": _bucket_policy(_tls_deny_statement(["train-bucket"]))
            },
        )

        assert [f["Status"] for f in findings] == ["N/A", "N/A"]
        assert "customization job 'tune-1'" in findings[0]["Finding_Details"]
        assert "train-bucket" in findings[1]["Finding_Details"]
        assert "the bucket list is incomplete" in findings[1]["Finding_Details"]

    def test_br47_more_jobs_than_the_cap_is_an_incomplete_inventory(self):
        """51 jobs over two pages: the newest 50 are read, the 51st is reported."""
        summaries = [
            {
                "jobArn": f"arn:aws:bedrock:us-east-1:111122223333:model-customization-job/j{i}",
                "jobName": f"j{i}",
            }
            for i in range(51)
        ]
        pages = [
            {"modelCustomizationJobSummaries": summaries[:30], "nextToken": "p2"},
            {"modelCustomizationJobSummaries": summaries[30:]},
        ]
        detail = {"trainingDataConfig": {"s3Uri": "s3://train-bucket/"}}
        findings = self._run(
            customization_jobs={f"j{i}": detail for i in range(51)},
            bucket_policies={
                "train-bucket": _bucket_policy(_tls_deny_statement(["train-bucket"]))
            },
            customization_pages=pages,
        )

        assert [f["Status"] for f in findings] == ["N/A", "N/A"]
        assert "only the newest 50 were read" in findings[0]["Finding_Details"]
        assert "stopped at a read cap" in findings[0]["Finding_Details"]
        assert "the bucket list is incomplete" in findings[1]["Finding_Details"]
        assert self.bedrock_client.get_model_customization_job.call_count == 50
        assert (
            self.bedrock_client.list_model_customization_jobs.call_args_list[1][1][
                "nextToken"
            ]
            == "p2"
        )

    def test_br47_data_source_cap_withholds_the_pass(self):
        """51 data sources over two knowledge bases: 50 are read, none passes.

        Every bucket read enforces TLS, so without the truncation leg the check
        reports "50 of 50" as Passed while the 51st source went unread.
        """
        data_sources = {
            "kb-1": [
                {"dataSourceId": f"ds-{i}", "name": f"docs-{i}"} for i in range(30)
            ],
            "kb-2": [
                {"dataSourceId": f"ds-{i}", "name": f"docs-{i}"} for i in range(30, 51)
            ],
        }
        detail = {
            f"ds-{i}": self._s3_source(f"ds-{i}", f"docs-{i}", f"bucket-{i}")
            for i in range(51)
        }
        findings = self._run(
            knowledge_bases=[
                {"knowledgeBaseId": "kb-1", "name": "support-kb"},
                {"knowledgeBaseId": "kb-2", "name": "hr-kb"},
            ],
            data_sources=data_sources,
            data_source_detail=detail,
            bucket_policies={
                f"bucket-{i}": _bucket_policy(_tls_deny_statement([f"bucket-{i}"]))
                for i in range(51)
            },
        )

        assert [f["Status"] for f in findings] == ["N/A", "N/A"]
        assert "stopped at a read cap" in findings[0]["Finding_Details"]
        assert "stopped after 50 data sources" in findings[0]["Finding_Details"]
        assert (
            "50 of the 50 Bedrock data path bucket(s) read"
            in findings[1]["Finding_Details"]
        )
        assert self.last_s3_client.get_bucket_policy.call_count == 50
        for finding in findings:
            assert_finding_schema(finding)

    def test_br47_large_data_log_bucket_is_on_the_data_path(self):
        """CloudWatch delivery moves payloads over 100 KB to a second bucket."""
        findings = self._run(
            logging_config={
                "loggingConfig": {
                    "s3Config": {"bucketName": "log-bucket"},
                    "cloudWatchConfig": {
                        "logGroupName": "bedrock-invocations",
                        "largeDataDeliveryS3Config": {"bucketName": "large-bucket"},
                    },
                }
            },
            bucket_policies={
                "log-bucket": _bucket_policy(_tls_deny_statement(["log-bucket"]))
            },
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "Bucket large-bucket" in failed[0]["Finding_Details"]
        assert (
            "the large-data destination of CloudWatch model invocation logging"
            in failed[0]["Finding_Details"]
        )
        assert len(passed) == 1
        assert "1 of 2 Bedrock data path bucket(s)" in passed[0]["Finding_Details"]
        assert "log-bucket" in passed[0]["Finding_Details"]

    def test_br47_large_data_bucket_shared_with_the_s3_destination_is_read_once(self):
        findings = self._run(
            logging_config={
                "loggingConfig": {
                    "s3Config": {"bucketName": "log-bucket"},
                    "cloudWatchConfig": {
                        "logGroupName": "bedrock-invocations",
                        "largeDataDeliveryS3Config": {"bucketName": "log-bucket"},
                    },
                }
            },
            bucket_policies={
                "log-bucket": _bucket_policy(_tls_deny_statement(["log-bucket"]))
            },
        )

        assert self.last_s3_client.get_bucket_policy.call_count == 1
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "the model invocation log destination" in findings[0]["Finding_Details"]
        assert (
            "the large-data destination of CloudWatch model invocation logging"
            in findings[0]["Finding_Details"]
        )

    def test_br47_distillation_invocation_log_sources_are_on_the_data_path(self):
        """Two distillation jobs, each reading prompts from its own log bucket."""
        findings = self._run(
            customization_jobs={
                "distill-1": {
                    "customizationType": "DISTILLATION",
                    "trainingDataConfig": {
                        "invocationLogsConfig": {
                            "usePromptResponse": True,
                            "invocationLogSource": {"s3Uri": "s3://logs-a/AWSLogs/"},
                        }
                    },
                    "outputDataConfig": {"s3Uri": "s3://out-bucket/"},
                },
                "distill-2": {
                    "customizationType": "DISTILLATION",
                    "trainingDataConfig": {
                        "invocationLogsConfig": {
                            "invocationLogSource": {"s3Uri": "s3://logs-b"}
                        }
                    },
                    "outputDataConfig": {"s3Uri": "s3://out-bucket/two/"},
                },
            },
            bucket_policies={
                "logs-a": _bucket_policy(_tls_deny_statement(["logs-a"])),
                "out-bucket": _bucket_policy(_tls_deny_statement(["out-bucket"])),
            },
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "Bucket logs-b" in failed[0]["Finding_Details"]
        assert (
            "the invocation log source of customization job 'distill-2'"
            in failed[0]["Finding_Details"]
        )
        assert len(passed) == 1
        assert "2 of 3 Bedrock data path bucket(s)" in passed[0]["Finding_Details"]
        assert (
            "the invocation log source of customization job 'distill-1'"
            in passed[0]["Finding_Details"]
        )

    def test_br47_log_destination_read_by_a_distillation_job_is_read_once(self):
        """One bucket as log destination and job input keeps both labels."""
        findings = self._run(
            logging_config={
                "loggingConfig": {"s3Config": {"bucketName": "log-bucket"}}
            },
            customization_jobs={
                "distill-1": {
                    "trainingDataConfig": {
                        "invocationLogsConfig": {
                            "invocationLogSource": {"s3Uri": "s3://log-bucket/logs/"}
                        }
                    }
                }
            },
        )

        assert self.last_s3_client.get_bucket_policy.call_count == 1
        assert [f["Status"] for f in findings] == ["Failed"]
        assert "the model invocation log destination" in findings[0]["Finding_Details"]
        assert (
            "the invocation log source of customization job 'distill-1'"
            in findings[0]["Finding_Details"]
        )

    def test_br47_deny_over_the_bucket_only_leaves_objects_plaintext(self):
        """AIR-FND-DAT-02: a Deny without the /* ARN leaves GetObject over HTTP."""
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _bucket_policy(
                    _tls_deny_statement(
                        ["support-bucket"], resources=["arn:aws:s3:::support-bucket"]
                    )
                ),
                "hr-bucket": _bucket_policy(_tls_deny_statement(["hr-bucket"])),
            }
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "Bucket support-bucket" in failed[0]["Finding_Details"]
        assert (
            "its Resource entries do not cover the objects"
            in failed[0]["Finding_Details"]
        )
        assert [f["Status"] for f in findings] == ["Failed", "Passed"]

    def test_br47_deny_naming_principals_reports_which_ones_it_reaches(self):
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _bucket_policy(
                    _tls_deny_statement(
                        ["support-bucket"],
                        principal={"AWS": "arn:aws:iam::123456789012:role/ingest"},
                    )
                ),
                "hr-bucket": _bucket_policy(_tls_deny_statement(["hr-bucket"])),
            }
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert (
            "it reaches only arn:aws:iam::123456789012:role/ingest"
            in failed[0]["Finding_Details"]
        )

    def test_br47_notprincipal_deny_names_the_principal_it_misses(self):
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _bucket_policy(
                    {
                        "Sid": "DenyInsecureExceptIngest",
                        "Effect": "Deny",
                        "NotPrincipal": {
                            "AWS": "arn:aws:iam::123456789012:role/ingest"
                        },
                        "Action": "s3:*",
                        "Resource": [
                            "arn:aws:s3:::support-bucket",
                            "arn:aws:s3:::support-bucket/*",
                        ],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ),
                "hr-bucket": _bucket_policy(_tls_deny_statement(["hr-bucket"])),
            }
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert (
            "it reaches every principal except arn:aws:iam::123456789012:role/ingest"
        ) in failed[0]["Finding_Details"]

    def test_br47_deny_on_securetransport_true_is_not_credited(self):
        """A Deny on aws:SecureTransport true blocks HTTPS, not HTTP."""
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _bucket_policy(
                    _tls_deny_statement(["support-bucket"], value="true")
                ),
                "hr-bucket": _bucket_policy(_tls_deny_statement(["hr-bucket"])),
            }
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert "Bucket support-bucket" in failed[0]["Finding_Details"]
        assert (
            "no Deny statement conditioned on aws:SecureTransport being false"
            in failed[0]["Finding_Details"]
        )

    def test_br47_set_operator_prefix_on_the_condition_is_stripped(self):
        """ForAnyValue:Bool is a Bool test; matching the raw operator reds a pass."""
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _bucket_policy(
                    _tls_deny_statement(["support-bucket"], operator="ForAnyValue:Bool")
                ),
                "hr-bucket": _bucket_policy(_tls_deny_statement(["hr-bucket"])),
            }
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "2 of 2 Bedrock data path bucket(s)" in findings[0]["Finding_Details"]

    def test_br47_deny_on_one_action_does_not_cover_the_s3_family(self):
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": _bucket_policy(
                    _tls_deny_statement(["support-bucket"], actions="s3:GetObject")
                ),
                "hr-bucket": _bucket_policy(_tls_deny_statement(["hr-bucket"])),
            }
        )

        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 1
        assert (
            "its Action entries do not cover the whole s3 family"
            in failed[0]["Finding_Details"]
        )
        assert (
            "'DenyInsecureTransport' does not enforce" in failed[0]["Finding_Details"]
        )

    def test_br47_wildcard_resource_deny_covers_every_bucket(self):
        findings = self._two_bucket_estate(
            bucket_policies={
                bucket: _bucket_policy(_tls_deny_statement([bucket], resources=["*"]))
                for bucket in ("support-bucket", "hr-bucket")
            }
        )

        assert [f["Status"] for f in findings] == ["Passed"]

    def test_br47_one_bucket_serving_two_knowledge_bases_is_read_once(self):
        findings = self._run(
            knowledge_bases=[
                {"knowledgeBaseId": "kb-1", "name": "support-kb"},
                {"knowledgeBaseId": "kb-2", "name": "hr-kb"},
            ],
            data_sources={
                "kb-1": [{"dataSourceId": "ds-1", "name": "support-docs"}],
                "kb-2": [{"dataSourceId": "ds-2", "name": "hr-docs"}],
            },
            data_source_detail={
                "ds-1": self._s3_source("ds-1", "support-docs", "shared-bucket"),
                "ds-2": self._s3_source("ds-2", "hr-docs", "shared-bucket"),
            },
            bucket_policies={
                "shared-bucket": _bucket_policy(_tls_deny_statement(["shared-bucket"]))
            },
        )

        assert self.last_s3_client.get_bucket_policy.call_count == 1
        assert [f["Status"] for f in findings] == ["Passed"]
        assert "1 of 1 Bedrock data path bucket(s)" in findings[0]["Finding_Details"]

    def test_br47_unparseable_bucket_policy_is_na(self):
        findings = self._two_bucket_estate(
            bucket_policies={
                "support-bucket": {"Policy": "{not json"},
                "hr-bucket": _bucket_policy(_tls_deny_statement(["hr-bucket"])),
            }
        )

        statuses = [f["Status"] for f in findings]
        assert statuses == ["Passed", "N/A"]
        assert "not readable JSON" in findings[1]["Finding_Details"]

    def test_br47_exception_returns_could_not_assess(self):
        """The bucket walk swallows its own errors, so the S3 client is the path."""
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb-1", "name": "kb"}]
        }
        agent_client.list_data_sources.return_value = {
            "dataSourceSummaries": [{"dataSourceId": "ds-1", "name": "docs"}]
        }
        agent_client.get_data_source.return_value = self._s3_source(
            "ds-1", "docs", "support-bucket"
        )
        bedrock_client = MagicMock()
        bedrock_client.get_model_invocation_logging_configuration.return_value = {}

        def build(service, **kwargs):
            if service == "s3":
                raise RuntimeError("boom")
            return {"bedrock-agent": agent_client, "bedrock": bedrock_client}[service]

        with patch("bedrock_app.boto3.client", side_effect=build):
            findings = extract_csv_data(
                bedrock_app.check_bedrock_data_path_bucket_tls(region="us-east-1")
            )

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "BR-47"
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# BR-48: check_bedrock_ai_services_opt_out
# ===================================================================
class TestBR48AIServicesOptOut:
    """BR-48: an AI services opt-out policy must resolve for the account."""

    ACCOUNT = "123456789012"

    def _run(
        self,
        effective_content=None,
        effective_error=None,
        target_id="o-a1b2c3d4e5",
        caller_account=None,
        source_policies=None,
        source_documents=None,
        list_policies_error=None,
        describe_policy_error=None,
        describe_organization_error=None,
    ):
        orgs_client = MagicMock()
        if effective_error:
            orgs_client.describe_effective_policy.side_effect = effective_error
        else:
            orgs_client.describe_effective_policy.return_value = {
                "EffectivePolicy": {
                    "PolicyContent": effective_content
                    if isinstance(effective_content, str)
                    else json.dumps(effective_content),
                    "TargetId": target_id,
                    "PolicyType": "AISERVICES_OPT_OUT_POLICY",
                }
            }

        if describe_organization_error:
            orgs_client.describe_organization.side_effect = describe_organization_error
        else:
            orgs_client.describe_organization.return_value = {
                "Organization": {"MasterAccountId": self.ACCOUNT}
            }

        if list_policies_error:
            orgs_client.list_policies.side_effect = list_policies_error
        else:
            orgs_client.list_policies.return_value = {
                "Policies": list(source_policies or [])
            }

        documents = source_documents or {}

        def describe_policy(PolicyId):
            if describe_policy_error and PolicyId in describe_policy_error:
                raise describe_policy_error[PolicyId]
            content = documents[PolicyId]
            return {
                "Policy": {
                    "Content": content
                    if isinstance(content, str)
                    else json.dumps(content)
                }
            }

        orgs_client.describe_policy.side_effect = describe_policy

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {
            "Account": caller_account or self.ACCOUNT
        }

        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: {
                "organizations": orgs_client,
                "sts": sts_client,
            }[service],
        ):
            return extract_csv_data(
                bedrock_app.check_bedrock_ai_services_opt_out(region="Global")
            )

    def test_br48_default_optout_passes(self):
        findings = self._run(
            effective_content={"services": {"default": {"opt_out_policy": "optOut"}}}
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert findings[0]["Check_ID"] == "BR-48"
        assert findings[0]["Region"] == "Global"
        assert (
            "sets services.default.opt_out_policy to optOut and no service section "
            "opts back in" in findings[0]["Finding_Details"]
        )
        assert "o-a1b2c3d4e5" in findings[0]["Finding_Details"]
        assert (
            "No source policy delegates the value to a child policy"
            in findings[0]["Finding_Details"]
        )
        assert_finding_schema(findings[0])

    def test_br48_service_section_opting_back_in_fails_and_names_it(self):
        """AIR-FND-DAT-09: an optIn section re-enables content use for that service."""
        findings = self._run(
            effective_content={
                "services": {
                    "default": {"opt_out_policy": "optOut"},
                    "bedrock": {"opt_out_policy": "optIn"},
                    "rekognition": {"opt_out_policy": "optIn"},
                }
            }
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Severity"] == "High"
        assert (
            "2 service section(s) opt back in: bedrock, rekognition"
            in findings[0]["Finding_Details"]
        )

    def test_br48_absent_default_fails_and_reports_partial_coverage(self):
        findings = self._run(
            effective_content={"services": {"bedrock": {"opt_out_policy": "optOut"}}}
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        assert (
            "services.default.opt_out_policy is absent"
            in findings[0]["Finding_Details"]
        )
        assert (
            "1 service section(s) opt out individually: bedrock"
            in findings[0]["Finding_Details"]
        )

    def test_br48_no_effective_policy_is_failed_not_unassessed(self):
        findings = self._run(
            effective_error=_client_error(
                "EffectivePolicyNotFoundException",
                operation="DescribeEffectivePolicy",
            )
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Severity"] == "High"
        assert (
            "No AI services opt-out policy resolves for this account"
            in findings[0]["Finding_Details"]
        )
        assert "opted-in default" in findings[0]["Finding_Details"]

    def test_br48_outside_an_organization_is_na(self):
        findings = self._run(
            effective_error=_client_error(
                "AWSOrganizationsNotInUseException",
                operation="DescribeEffectivePolicy",
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Severity"] == "Informational"
        assert "was not established" in findings[0]["Finding_Details"]

    def test_br48_access_denied_is_na(self):
        findings = self._run(
            effective_error=_client_error(
                "AccessDeniedException", operation="DescribeEffectivePolicy"
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Severity"] == "Informational"
        assert "organizations:DescribeEffectivePolicy" in findings[0]["Resolution"]

    def test_br48_child_operator_delegation_is_reported_on_the_verdict_row(self):
        """The effective document has no operators left, so the source answers this."""
        findings = self._run(
            effective_content={"services": {"default": {"opt_out_policy": "optOut"}}},
            source_policies=[{"Id": "p-1", "Name": "ai-opt-out"}],
            source_documents={
                "p-1": {
                    "services": {
                        "@@operators_allowed_for_child_policies": ["@@assign"],
                        "default": {"opt_out_policy": {"@@assign": "optOut"}},
                    }
                }
            },
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert (
            "'ai-opt-out' delegates @@assign to child policies"
            in findings[0]["Finding_Details"]
        )

    def test_br48_absent_child_operator_is_reported_as_open_to_children(self):
        """An absent @@operators_allowed_for_child_policies defaults to @@all.

        The text used to read absence as "no source policy delegates", which is
        the locked state, and named any explicit value including @@none as a
        delegation.
        """
        findings = self._run(
            effective_content={"services": {"default": {"opt_out_policy": "optOut"}}},
            source_policies=[{"Id": "p-1", "Name": "ai-opt-out"}],
            source_documents={
                "p-1": {
                    "services": {"default": {"opt_out_policy": {"@@assign": "optOut"}}}
                }
            },
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        details = findings[0]["Finding_Details"]
        assert "No source policy delegates the value" not in details
        assert "'ai-opt-out' delegates @@all to child policies" in details

    def test_br48_none_child_operator_locks_the_value(self):
        findings = self._run(
            effective_content={"services": {"default": {"opt_out_policy": "optOut"}}},
            source_policies=[{"Id": "p-1", "Name": "ai-opt-out"}],
            source_documents={
                "p-1": {
                    "services": {
                        "default": {
                            "opt_out_policy": {
                                "@@operators_allowed_for_child_policies": ["@@none"],
                                "@@assign": "optOut",
                            }
                        }
                    }
                }
            },
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        details = findings[0]["Finding_Details"]
        assert "delegates @@none" not in details
        assert "No source policy delegates the value to a child policy" in details

    def test_br48_member_account_says_the_child_leg_was_not_assessed(self):
        findings = self._run(
            effective_content={"services": {"default": {"opt_out_policy": "optOut"}}},
            caller_account="111122223333",
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert (
            "Whether a child policy may change the value was not assessed"
            in findings[0]["Finding_Details"]
        )

    def test_br48_source_policy_read_error_keeps_the_effective_verdict(self):
        findings = self._run(
            effective_content={"services": {"default": {"opt_out_policy": "optOut"}}},
            source_policies=[{"Id": "p-1", "Name": "ai-opt-out"}],
            describe_policy_error={
                "p-1": _client_error(
                    "AccessDeniedException", operation="DescribePolicy"
                )
            },
        )

        assert [f["Status"] for f in findings] == ["Passed", "N/A"]
        assert "policy 'ai-opt-out'" in findings[1]["Finding_Details"]
        assert "organizations:DescribePolicy" in findings[1]["Resolution"]

    def test_br48_unreadable_service_value_adds_an_na_row(self):
        findings = self._run(
            effective_content={
                "services": {
                    "default": {"opt_out_policy": "optOut"},
                    "comprehend": {"opt_out_policy": 42},
                }
            }
        )

        assert [f["Status"] for f in findings] == ["Passed", "N/A"]
        assert (
            "comprehend carries opt_out_policy 'nothing readable'"
            in findings[1]["Finding_Details"]
        )

    def test_br48_missing_services_section_is_na(self):
        findings = self._run(effective_content={"something_else": {}})

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "carries no services section" in findings[0]["Finding_Details"]

    def test_br48_unparseable_effective_policy_is_na(self):
        findings = self._run(effective_content="{not json")

        assert [f["Status"] for f in findings] == ["N/A"]
        assert "is not readable JSON" in findings[0]["Finding_Details"]

    def test_br48_exception_returns_could_not_assess(self):
        with patch("bedrock_app.boto3.client", side_effect=RuntimeError("boom")):
            findings = extract_csv_data(
                bedrock_app.check_bedrock_ai_services_opt_out(region="Global")
            )

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "BR-48"
        assert_could_not_assess_finding(findings[0])

    @pytest.mark.parametrize(
        ("node", "expected"),
        [
            ("optOut", {"value": "optout", "wrapped": False}),
            ({"@@assign": "optOut"}, {"value": "optout", "wrapped": True}),
            ({"@@append": "optIn"}, {"value": "optin", "wrapped": True}),
            (None, {"value": "", "wrapped": False}),
            ({}, {"value": "", "wrapped": False}),
        ],
    )
    def test_ai_services_opt_out_value_reads_both_document_shapes(self, node, expected):
        """DescribeEffectivePolicy resolves the operator; DescribePolicy keeps it."""
        assert bedrock_app._ai_services_opt_out_value(node) == expected

    def test_br48_effective_policy_type_is_a_modelled_enum_value(self):
        client = bedrock_app.boto3.client(
            "organizations",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        )
        model = client.meta.service_model
        assert (
            bedrock_app.AI_SERVICES_OPT_OUT_POLICY_TYPE
            in model.shape_for("EffectivePolicyType").enum
        )
        assert model.operation_model("DescribeEffectivePolicy")


# ===================================================================
# BR-49: check_bedrock_guardrail_invocation_deny
# ===================================================================
def _guardrail_deny_statement(
    actions=None,
    operator="Null",
    value="true",
    resources="*",
):
    return {
        "Effect": "Deny",
        "Action": actions
        or [
            "bedrock:InvokeModel",
            "bedrock:InvokeModelWithResponseStream",
        ],
        "Resource": resources,
        "Condition": {operator: {"bedrock:GuardrailIdentifier": value}},
    }


def _invoke_cache(*statements, role="AppRole", policy_name="BedrockInvoke", users=None):
    return {
        "role_permissions": {
            role: {
                "attached_policies": [
                    {
                        "name": policy_name,
                        "arn": f"arn:aws:iam::123456789012:policy/{policy_name}",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": list(statements),
                        },
                    }
                ],
                "inline_policies": [],
                "permission_boundary": None,
            }
        },
        "user_permissions": users or {},
    }


_ALLOW_ALL_BEDROCK = {
    "Effect": "Allow",
    "Action": "bedrock:*",
    "Resource": "*",
}


class TestResourceIsUnscoped:
    """Which Resource entries grant every model, for BR-42 and BR-49."""

    @pytest.mark.parametrize(
        "resource",
        [
            "*",
            "arn:aws:bedrock:*::foundation-model/*",
            "arn:aws:bedrock:us-west-2::foundation-model/*",
            "arn:aws:bedrock:::foundation-model/*",
            "arn:${Partition}:bedrock:*::foundation-model/*",
            "arn:aws:bedrock:*:*:*",
            "arn:*:bedrock:*",
            "arn:aws:bedrock:us-east-1:111122223333:inference-profile/*",
            " arn:aws:bedrock:eu-west-1::foundation-model/* ",
        ],
    )
    def test_forms_already_read_as_unscoped_stay_unscoped(self, resource):
        assert bedrock_app._resource_is_unscoped(resource)

    @pytest.mark.parametrize(
        "resource",
        [
            "arn:aws:bedrock:*::foundation-model*",
            "arn:aws:bedrock:us-east-1::foundation-model/**",
            "arn:aws:bedrock:::foundation-model/?*",
            "arn:aws-us-gov:bedrock:us-gov-west-1::f*",
            "arn:aws:bedrock:*::?oundation-model*",
            "arn:aws:bedrock*",
            "arn:aws:bed*",
            "arn:*:bedrock:*:*:inference-profile*",
            "arn:aws:bedrock:us-east-1:111122223333:inference-profile/?*",
        ],
    )
    def test_wildcard_inside_a_segment_is_unscoped(self, resource):
        assert bedrock_app._resource_is_unscoped(resource)

    @pytest.mark.parametrize(
        "resource",
        [
            "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2",
            "arn:aws:bedrock:*::foundation-model/anthropic.*",
            "arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.*",
            "arn:aws:bedrock:us-east-1::foundation-model",
            "arn:aws:s3:::foundation-model*",
            "arn:aws:bedrock:*::custom-model*",
            "arn:aws:bedrock:*::foundation-model/a*",
            "",
            None,
            {"Fn::Sub": "arn:aws:bedrock:*::foundation-model*"},
        ],
    )
    def test_named_models_and_families_are_scoped(self, resource):
        assert not bedrock_app._resource_is_unscoped(resource)

    @pytest.mark.parametrize(
        "resource",
        [
            "arn:aws:bedrock:*::" + "*a" * 50000 + "*",
            "arn:aws:bedrock:*::" + "*?" * 9 + "*b" * 20000 + "*",
            "arn:aws:bedrock:*::" + "*" * 100000 + "f" + "*" * 100000,
            "arn:aws:bedrock:*::" + "*?" * 9 + "*",
            "*" + "*a" * 50000,
            "a" * 100000 + "*",
        ],
    )
    def test_pathological_patterns_finish_fast(self, resource):
        """A backtracking matcher hung on a 31-character input; these are longer."""
        started = time.monotonic()
        bedrock_app._resource_is_unscoped(resource)
        assert time.monotonic() - started < 0.5


class TestBR49GuardrailInvocationDeny:
    """BR-49: every invoke permission must be paired with a conditioned Deny."""

    def _run(self, cache):
        return extract_csv_data(
            bedrock_app.check_bedrock_guardrail_invocation_deny(cache, region="Global")
        )

    def test_br49_deny_over_both_invoke_actions_passes(self):
        findings = self._run(
            _invoke_cache(_ALLOW_ALL_BEDROCK, _guardrail_deny_statement())
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert findings[0]["Check_ID"] == "BR-49"
        assert findings[0]["Region"] == "Global"
        assert "1 of 1 identity/identities" in findings[0]["Finding_Details"]
        assert "role 'AppRole'" in findings[0]["Finding_Details"]
        assert (
            "bedrock:InvokeModel, bedrock:InvokeModelWithResponseStream"
            in findings[0]["Finding_Details"]
        )
        assert_finding_schema(findings[0])

    def test_br49_deny_on_invoke_wildcard_passes(self):
        """
        Regression: Converse and ConverseStream are authorized by the two Invoke
        actions and have no IAM action of their own, so a Deny over bedrock:Invoke*
        guards all four APIs and must not be reported as leaving Converse open.
        """
        findings = self._run(
            _invoke_cache(
                _ALLOW_ALL_BEDROCK,
                _guardrail_deny_statement(actions="bedrock:Invoke*"),
            )
        )

        assert [f["Status"] for f in findings] == ["Passed"]
        assert "Converse" not in findings[0]["Finding_Details"]

    def test_br49_deny_on_invoke_model_alone_leaves_streaming_unguarded(self):
        """A Deny that omits InvokeModelWithResponseStream leaves ConverseStream open."""
        findings = self._run(
            _invoke_cache(
                _ALLOW_ALL_BEDROCK,
                _guardrail_deny_statement(actions=["bedrock:InvokeModel"]),
            )
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        assert findings[0]["Severity"] == "High"
        assert (
            "role 'AppRole' may call bedrock:InvokeModel, "
            "bedrock:InvokeModelWithResponseStream" in findings[0]["Finding_Details"]
        )
        assert (
            "no policy on it denies bedrock:InvokeModelWithResponseStream unless"
            in findings[0]["Finding_Details"]
        )
        assert "bedrock:Converse and" not in findings[0]["Resolution"]
        assert "bedrock:InvokeModelWithResponseStream" in findings[0]["Resolution"]

    def test_br49_failed_row_names_the_policy_types_it_does_not_read(self):
        """The check reads role and user policies only.

        It used to recommend a permissions boundary, a surface it never reads,
        so following the advice would leave the row Failed.
        """
        findings = self._run(_invoke_cache(_ALLOW_ALL_BEDROCK))

        assert [f["Status"] for f in findings] == ["Failed"]
        details = findings[0]["Finding_Details"]
        assert "Group policies" in details
        assert "permissions boundaries" in details
        assert "service control policies" in details
        assert "boundary" not in findings[0]["Resolution"]

    def test_br49_allow_on_converse_name_grants_nothing_to_assess(self):
        """bedrock:Converse is not an IAM action, so allowing it grants no invocation."""
        findings = self._run(
            _invoke_cache(
                {
                    "Effect": "Allow",
                    "Action": ["bedrock:Converse", "bedrock:ConverseStream"],
                    "Resource": "*",
                }
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]

    def test_br49_allow_side_guardrail_condition_alone_fails(
        self, permission_cache_with_guardrail_condition
    ):
        """BR-10 passes this cache: an Allow condition is not a Deny."""
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr-1", "name": "TestGuardrail"}]
        }
        with patch("bedrock_app.boto3.client", return_value=bedrock_client):
            br10 = extract_csv_data(
                bedrock_app.check_bedrock_guardrail_iam_enforcement(
                    permission_cache_with_guardrail_condition, region="us-east-1"
                )
            )
        findings = self._run(permission_cache_with_guardrail_condition)

        assert [f["Status"] for f in br10] == ["Passed"]
        assert [f["Status"] for f in findings] == ["Failed"]
        assert "role 'GuardrailEnforcedRole'" in findings[0]["Finding_Details"]
        assert (
            "bedrock:InvokeModel, bedrock:InvokeModelWithResponseStream"
            in findings[0]["Finding_Details"]
        )

    def test_br49_no_invoke_permission_returns_na(self):
        findings = self._run(
            _invoke_cache(
                {
                    "Effect": "Allow",
                    "Action": ["bedrock:ListFoundationModels", "s3:GetObject"],
                    "Resource": "*",
                }
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Severity"] == "Informational"
        assert (
            "no identity whose guardrail enforcement can be assessed"
            in findings[0]["Finding_Details"]
        )

    def test_br49_empty_cache_returns_na(self, empty_permission_cache):
        findings = self._run(empty_permission_cache)

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Check_ID"] == "BR-49"

    def test_br49_missing_cache_is_reported_as_incomplete(self):
        findings = extract_csv_data(
            bedrock_app._permission_cache_unavailable_result(
                "BR-49", "Guardrail Invocation Deny Enforcement", "Global"
            )
        )

        assert [f["Status"] for f in findings] == ["N/A"]
        assert findings[0]["Check_ID"] == "BR-49"
        assert findings[0]["Severity"] == "Informational"

    def test_br49_two_identities_reach_both_verdicts(self):
        """One identity cannot tell a per-identity verdict from an aggregate one."""
        cache = _invoke_cache(_ALLOW_ALL_BEDROCK, _guardrail_deny_statement())
        cache["role_permissions"]["UnguardedRole"] = {
            "attached_policies": [
                {
                    "name": "BedrockOpen",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [_ALLOW_ALL_BEDROCK],
                    },
                }
            ],
            "inline_policies": [],
            "permission_boundary": None,
        }

        findings = self._run(cache)

        assert [f["Status"] for f in findings] == ["Failed", "Passed"]
        assert "role 'UnguardedRole'" in findings[0]["Finding_Details"]
        assert "1 of 2 identity/identities" in findings[1]["Finding_Details"]
        assert "role 'AppRole'" in findings[1]["Finding_Details"]

    def test_br49_user_policies_are_assessed_too(self):
        cache = _invoke_cache(
            {
                "Effect": "Allow",
                "Action": "bedrock:ListFoundationModels",
                "Resource": "*",
            },
            users={
                "BatchUser": {
                    "attached_policies": [
                        {
                            "name": "BedrockOpen",
                            "document": {
                                "Version": "2012-10-17",
                                "Statement": [_ALLOW_ALL_BEDROCK],
                            },
                        }
                    ],
                    "inline_policies": [],
                }
            },
        )

        findings = self._run(cache)

        assert [f["Status"] for f in findings] == ["Failed"]
        assert "user 'BatchUser'" in findings[0]["Finding_Details"]

    def test_br49_stringequals_deny_is_not_credited(self):
        """StringEquals on a Deny rejects the approved guardrail, not the absent one."""
        findings = self._run(
            _invoke_cache(
                _ALLOW_ALL_BEDROCK,
                _guardrail_deny_statement(
                    operator="StringEquals",
                    value="arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123",
                ),
            )
        )

        assert [f["Status"] for f in findings] == ["Failed"]

    def test_br49_null_false_deny_is_not_credited(self):
        """Null false denies exactly the calls that do name a guardrail."""
        findings = self._run(
            _invoke_cache(_ALLOW_ALL_BEDROCK, _guardrail_deny_statement(value="false"))
        )

        assert [f["Status"] for f in findings] == ["Failed"]

    def test_br49_stringnotequals_deny_passes(self):
        findings = self._run(
            _invoke_cache(
                _ALLOW_ALL_BEDROCK,
                _guardrail_deny_statement(
                    operator="StringNotEquals",
                    value=["arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123"],
                ),
            )
        )

        assert [f["Status"] for f in findings] == ["Passed"]

    def test_br49_set_operator_prefix_on_the_condition_is_stripped(self):
        """ForAllValues:StringNotEquals is a StringNotEquals test."""
        findings = self._run(
            _invoke_cache(
                _ALLOW_ALL_BEDROCK,
                _guardrail_deny_statement(
                    operator="ForAllValues:StringNotEquals",
                    value=["arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123"],
                ),
            )
        )

        assert [f["Status"] for f in findings] == ["Passed"]

    def test_br49_deny_scoped_to_one_model_reports_the_scoping(self):
        findings = self._run(
            _invoke_cache(
                _ALLOW_ALL_BEDROCK,
                _guardrail_deny_statement(
                    resources=[
                        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2"
                    ]
                ),
            )
        )

        assert [f["Status"] for f in findings] == ["Failed"]
        assert (
            "is scoped to arn:aws:bedrock:us-east-1::foundation-model/"
            "anthropic.claude-v2" in findings[0]["Finding_Details"]
        )
        assert (
            "leaves every other model invocable without a guardrail"
            in findings[0]["Finding_Details"]
        )

    def test_br49_deny_on_a_model_prefix_is_credited(self):
        findings = self._run(
            _invoke_cache(
                _ALLOW_ALL_BEDROCK,
                _guardrail_deny_statement(
                    resources=["arn:aws:bedrock:us-east-1::foundation-model/*"]
                ),
            )
        )

        assert [f["Status"] for f in findings] == ["Passed"]

    def test_br49_deny_with_a_star_inside_the_resource_segment_is_credited(self):
        """foundation-model/?* denies every model, so the identity is guarded.

        A second identity whose Deny names one model family is not credited,
        so the two verdicts cannot both come from one reading of the cache.
        """
        cache = _invoke_cache(
            _ALLOW_ALL_BEDROCK,
            _guardrail_deny_statement(
                resources=["arn:aws:bedrock:*::foundation-model/?*"]
            ),
        )
        cache["role_permissions"]["FamilyRole"] = {
            "attached_policies": [
                {
                    "name": "FamilyDeny",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            _ALLOW_ALL_BEDROCK,
                            _guardrail_deny_statement(
                                resources=[
                                    "arn:aws:bedrock:*::foundation-model/anthropic.*"
                                ]
                            ),
                        ],
                    },
                }
            ],
            "inline_policies": [],
            "permission_boundary": None,
        }

        findings = self._run(cache)

        assert [f["Status"] for f in findings] == ["Failed", "Passed"]
        assert "role 'FamilyRole'" in findings[0]["Finding_Details"]
        assert "1 of 2 identity/identities" in findings[1]["Finding_Details"]
        assert "role 'AppRole'" in findings[1]["Finding_Details"]

    def test_br49_unparseable_policy_document_adds_an_na_row(self):
        cache = _invoke_cache(_ALLOW_ALL_BEDROCK, _guardrail_deny_statement())
        cache["role_permissions"]["AppRole"]["inline_policies"] = [
            {"name": "Broken", "document": "{not json"}
        ]

        findings = self._run(cache)

        assert [f["Status"] for f in findings] == ["Passed", "N/A"]
        assert "role 'AppRole': policy 'Broken'" in findings[1]["Finding_Details"]
        assert (
            "may deny unguarded invocation in a statement this check did not read"
            in findings[1]["Finding_Details"]
        )

    def test_br49_exception_returns_could_not_assess(self):
        findings = self._run({"role_permissions": "not-a-dict"})

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "BR-49"
        assert_could_not_assess_finding(findings[0])

    def test_br49_reported_identities_are_capped(self):
        cache = {"role_permissions": {}, "user_permissions": {}}
        for index in range(bedrock_app.MAX_REPORTED_UNGUARDED_IDENTITIES + 3):
            cache["role_permissions"][f"OpenRole{index:02d}"] = {
                "attached_policies": [
                    {
                        "name": "BedrockOpen",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [_ALLOW_ALL_BEDROCK],
                        },
                    }
                ],
                "inline_policies": [],
            }

        findings = self._run(cache)

        assert len(findings) == bedrock_app.MAX_REPORTED_UNGUARDED_IDENTITIES + 1
        assert findings[-1]["Status"] == "Failed"
        assert "3 further identity/identities" in findings[-1]["Finding_Details"]
        assert "OpenRole10" in findings[-1]["Finding_Details"]

    def test_br49_overflow_row_does_not_recommend_a_permissions_boundary(self):
        cache = {"role_permissions": {}, "user_permissions": {}}
        for index in range(bedrock_app.MAX_REPORTED_UNGUARDED_IDENTITIES + 1):
            cache["role_permissions"][f"OpenRole{index:02d}"] = {
                "attached_policies": [
                    {
                        "name": "BedrockOpen",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [_ALLOW_ALL_BEDROCK],
                        },
                    }
                ],
                "inline_policies": [],
            }

        findings = self._run(cache)

        assert "further identity" in findings[-1]["Finding_Details"]
        assert "boundary" not in findings[-1]["Resolution"]
        assert "permissions boundaries" in findings[-1]["Finding_Details"]


# ===================================================================
# BR-04 extension: _invocation_log_coverage_findings (AIR-FND-DET-01)
# ===================================================================
class TestBR04InvocationLogDataCoverage:
    """BR-04: what an enabled invocation log actually records."""

    COVERAGE_FINDING = "Bedrock Invocation Log Data Coverage"

    ALL_MODALITIES = {
        "textDataDeliveryEnabled": True,
        "imageDataDeliveryEnabled": True,
        "embeddingDataDeliveryEnabled": True,
        "videoDataDeliveryEnabled": True,
        "audioDataDeliveryEnabled": True,
    }

    def _run(self, logging_config):
        """Run BR-04 over one logging configuration and keep the coverage rows."""
        bedrock_client = MagicMock()
        bedrock_client.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": logging_config
        }

        logs_client = MagicMock()
        logs_client.describe_log_groups.return_value = {"logGroups": []}

        s3_client = MagicMock()
        s3_client.get_bucket_lifecycle_configuration.side_effect = _client_error(
            "NoSuchLifecycleConfiguration",
            "no lifecycle",
            "GetBucketLifecycleConfiguration",
        )

        clients = {"bedrock": bedrock_client, "logs": logs_client, "s3": s3_client}
        with (
            patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True),
            patch(
                "bedrock_app.boto3.client",
                side_effect=lambda service, **kwargs: clients[service],
            ),
        ):
            self.result = bedrock_app.check_bedrock_logging_configuration(
                region="us-east-1"
            )
            self.all_findings = extract_csv_data(self.result)
        return [f for f in self.all_findings if f["Finding"] == self.COVERAGE_FINDING]

    def test_br04_all_five_data_types_delivered_passes(self):
        # PASS reachability: a real S3-only configuration with every delivery
        # flag set produces exactly one coverage row and it is Passed.
        coverage = self._run(
            {"s3Config": {"bucketName": "log-bucket"}, **self.ALL_MODALITIES}
        )

        assert [f["Status"] for f in coverage] == ["Passed"]
        assert "all 5 data types" in coverage[0]["Finding_Details"]
        assert "text, image, embedding, video, audio" in coverage[0]["Finding_Details"]
        assert "log-bucket" in coverage[0]["Finding_Details"]

    def test_br04_disabled_data_types_fail_and_are_named(self):
        # Three flags true and two false: a check that read any() of the flags,
        # or that judged only the first one, would call this configuration
        # covered. The row has to name the two that are off.
        config = dict(self.ALL_MODALITIES)
        config["imageDataDeliveryEnabled"] = False
        config["videoDataDeliveryEnabled"] = False

        coverage = self._run({"s3Config": {"bucketName": "log-bucket"}, **config})

        assert [f["Status"] for f in coverage] == ["Failed"]
        details = coverage[0]["Finding_Details"]
        assert "2 of 5 data types are excluded" in details
        assert "image, video" in details
        assert "log-bucket" in details
        assert (
            coverage[0]["Resolution"]
            == "Set imageDataDeliveryEnabled, videoDataDeliveryEnabled to true in "
            "PutModelInvocationLoggingConfiguration so the log carries the "
            "content of every data type this account invokes."
        )

    def test_br04_s3_only_delivery_is_not_failed_for_large_data_delivery(self):
        # largeDataDeliveryS3Config is a member of cloudWatchConfig. An S3-only
        # configuration delivers the whole payload, so the absent field is not a
        # gap and must not cost this account a Failed row.
        coverage = self._run(
            {"s3Config": {"bucketName": "log-bucket"}, **self.ALL_MODALITIES}
        )

        assert [f["Status"] for f in coverage] == ["Passed"]
        assert all(
            "largeDataDeliveryS3Config" not in f["Finding_Details"] for f in coverage
        )

    def test_br04_cloudwatch_delivery_without_large_data_bucket_fails(self):
        coverage = self._run(
            {
                "s3Config": {},
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
                **self.ALL_MODALITIES,
            }
        )

        assert [f["Status"] for f in coverage] == ["Failed"]
        details = coverage[0]["Finding_Details"]
        assert "'/aws/bedrock/invocations'" in details
        assert "no cloudWatchConfig.largeDataDeliveryS3Config" in details
        assert "over 100 KB" in details

    def test_br04_cloudwatch_large_data_bucket_passes_and_is_named(self):
        coverage = self._run(
            {
                "s3Config": {},
                "cloudWatchConfig": {
                    "logGroupName": "/aws/bedrock/invocations",
                    "largeDataDeliveryS3Config": {"bucketName": "overflow-bucket"},
                },
                **self.ALL_MODALITIES,
            }
        )

        assert [f["Status"] for f in coverage] == ["Passed"]
        assert "overflow-bucket" in coverage[0]["Finding_Details"]
        assert "over 100 KB" in coverage[0]["Finding_Details"]

    def test_br04_legacy_bucket_key_in_large_data_config_is_credited(self):
        coverage = self._run(
            {
                "s3Config": {},
                "cloudWatchConfig": {
                    "logGroupName": "/aws/bedrock/invocations",
                    "largeDataDeliveryS3Config": {"s3BucketName": "legacy-overflow"},
                },
                **self.ALL_MODALITIES,
            }
        )

        assert [f["Status"] for f in coverage] == ["Passed"]
        assert "legacy-overflow" in coverage[0]["Finding_Details"]

    def test_br04_unreported_flags_are_na_not_a_disabled_data_type(self):
        # A flag the API did not return is indeterminate. Reading it as false
        # would fail every configuration the API reports without the flags.
        coverage = self._run(
            {"s3Config": {"bucketName": "log-bucket"}, "cloudWatchConfig": {}}
        )

        assert [f["Status"] for f in coverage] == ["N/A"]
        assert coverage[0]["Severity"] == "Informational"
        details = coverage[0]["Finding_Details"]
        assert "did not report textDataDeliveryEnabled" in details
        assert "audioDataDeliveryEnabled" in details
        assert "could not be assessed" in details

    def test_br04_partially_reported_flags_report_both_sides(self):
        coverage = self._run(
            {
                "s3Config": {"bucketName": "log-bucket"},
                "textDataDeliveryEnabled": True,
                "imageDataDeliveryEnabled": True,
                "embeddingDataDeliveryEnabled": True,
            }
        )

        assert [f["Status"] for f in coverage] == ["N/A"]
        details = coverage[0]["Finding_Details"]
        assert "Delivery is enabled for text, image, embedding." in details
        assert "videoDataDeliveryEnabled, audioDataDeliveryEnabled" in details

    def test_br04_both_gap_kinds_are_reported_separately(self):
        config = dict(self.ALL_MODALITIES)
        config["audioDataDeliveryEnabled"] = False

        coverage = self._run(
            {
                "s3Config": {"bucketName": "log-bucket"},
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
                **config,
            }
        )

        assert [f["Status"] for f in coverage] == ["Failed", "Failed"]
        assert "1 of 5 data types are excluded" in coverage[0]["Finding_Details"]
        assert "audio" in coverage[0]["Finding_Details"]
        assert "largeDataDeliveryS3Config" in coverage[1]["Finding_Details"]

    def test_br04_disabled_logging_emits_no_coverage_row(self):
        # The logging switch row already carries a disabled configuration. A
        # coverage row on top of it would double-count the same gap.
        coverage = self._run({"s3Config": {}, "cloudWatchConfig": {}})

        assert coverage == []
        assert [f["Status"] for f in self.all_findings] == ["Failed"]

    def test_br04_a_coverage_gap_moves_the_check_roll_up_to_warn(self):
        # The logging switch is on, so the legacy rows are all Passed and the
        # roll-up would stay PASS while the CSV carries a Failed row.
        config = dict(self.ALL_MODALITIES)
        config["audioDataDeliveryEnabled"] = False

        coverage = self._run({"s3Config": {"bucketName": "log-bucket"}, **config})

        assert [f["Status"] for f in coverage] == ["Failed"]
        assert self.result["status"] == "WARN"

    def test_br04_full_coverage_leaves_the_check_roll_up_at_pass(self):
        # Negative control for the row above: a leg that set WARN
        # unconditionally, or on any row rather than on a Failed one, would
        # fail this.
        coverage = self._run(
            {"s3Config": {"bucketName": "log-bucket"}, **self.ALL_MODALITIES}
        )

        assert [f["Status"] for f in coverage] == ["Passed"]
        assert self.result["status"] == "PASS"

    def test_br04_indeterminate_coverage_leaves_the_check_roll_up_at_pass(self):
        # An N/A row is not a gap, so it must not move the roll-up either.
        coverage = self._run({"s3Config": {"bucketName": "log-bucket"}})

        assert [f["Status"] for f in coverage] == ["N/A"]
        assert self.result["status"] == "PASS"

    def test_br04_disabled_logging_keeps_the_fail_roll_up(self):
        # With no destination the coverage leg returns nothing, so the switch
        # verdict stands. A leg that overwrote the roll-up would downgrade this
        # FAIL to WARN.
        coverage = self._run({"s3Config": {}, "cloudWatchConfig": {}})

        assert coverage == []
        assert self.result["status"] == "FAIL"

    def test_br04_coverage_rows_pass_the_finding_schema(self):
        config = dict(self.ALL_MODALITIES)
        config["videoDataDeliveryEnabled"] = False
        coverage = self._run(
            {
                "s3Config": {"bucketName": "log-bucket"},
                "cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"},
                **config,
            }
        )

        assert coverage
        for finding in self.all_findings:
            assert_finding_schema(finding)
            assert finding["Check_ID"] == "BR-04"


# ===================================================================
# BR-20 extension: the S3 bucket a knowledge base ingests from carries
# its own encryption configuration (AIR-FND-DAT-01)
# ===================================================================
class TestBR20KnowledgeBaseDataSourceEncryption:
    """BR-20: encryption at rest on knowledge base data source buckets."""

    SOURCE_FINDING = "Knowledge Base Data Source Bucket Encryption"
    _CMK_ARN = "arn:aws:kms:us-east-1:123456789012:key/abc"

    @staticmethod
    def _sse(algorithm, key=None):
        """A GetBucketEncryption response with one default-encryption rule."""
        rule = {"SSEAlgorithm": algorithm}
        if key is not None:
            rule["KMSMasterKeyID"] = key
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": rule}]
            }
        }

    def _run(self, sources, encryption=None, list_error=None):
        """Run BR-20 over one MANAGED knowledge base with the given data sources.

        The knowledge base itself holds a customer-managed key, so the vector
        store leg contributes one Passed row and every row this returns comes
        from the data source leg.
        """
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "CorpusKB"}]
        }
        agent_client.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "knowledgeBaseConfiguration": {
                    "type": "MANAGED",
                    "managedKnowledgeBaseConfiguration": {
                        "serverSideEncryptionConfiguration": {
                            "kmsKeyArn": self._CMK_ARN
                        }
                    },
                }
            }
        }

        if list_error is not None:
            agent_client.list_data_sources.side_effect = list_error
        else:
            agent_client.list_data_sources.return_value = {
                "dataSourceSummaries": [
                    {"dataSourceId": source["id"], "name": source["name"]}
                    for source in sources
                ]
            }

        details = {source["id"]: source for source in sources}

        def get_data_source(**kwargs):
            source = details[kwargs["dataSourceId"]]
            configuration = {"type": source.get("type", "S3")}
            if source.get("bucket"):
                s3_configuration = {"bucketArn": f"arn:aws:s3:::{source['bucket']}"}
                if source.get("owner"):
                    s3_configuration["bucketOwnerAccountId"] = source["owner"]
                configuration["s3Configuration"] = s3_configuration
            return {
                "dataSource": {
                    "name": source["name"],
                    "dataSourceConfiguration": configuration,
                }
            }

        agent_client.get_data_source.side_effect = get_data_source

        s3_client = MagicMock()
        answers = encryption or {}

        def get_bucket_encryption(Bucket):
            answer = answers[Bucket]
            if isinstance(answer, Exception):
                raise answer
            return answer

        s3_client.get_bucket_encryption.side_effect = get_bucket_encryption
        self.s3_client = s3_client

        clients = {"bedrock-agent": agent_client, "s3": s3_client}
        with patch(
            "bedrock_app.boto3.client",
            side_effect=lambda service, **kwargs: clients[service],
        ):
            self.all_findings = extract_csv_data(
                bedrock_app.check_bedrock_knowledge_base_kms_encryption(
                    region="us-east-1"
                )
            )
        return [f for f in self.all_findings if f["Finding"] == self.SOURCE_FINDING]

    def test_br20_source_bucket_with_a_customer_key_passes(self):
        # PASS reachability: a real data source bucket on SSE-KMS with the
        # account's own key produces one Passed row and nothing else.
        source = self._run(
            [{"id": "ds1", "name": "docs", "bucket": "corpus-bucket"}],
            {"corpus-bucket": self._sse("aws:kms", self._CMK_ARN)},
        )

        assert [f["Status"] for f in source] == ["Passed"]
        assert "1 of 1" in source[0]["Finding_Details"]
        assert "corpus-bucket" in source[0]["Finding_Details"]
        assert self._CMK_ARN in source[0]["Finding_Details"]

    def test_br20_sse_s3_source_bucket_fails_and_names_the_data_source(self):
        source = self._run(
            [{"id": "ds1", "name": "docs", "bucket": "corpus-bucket"}],
            {"corpus-bucket": self._sse("AES256")},
        )

        assert [f["Status"] for f in source] == ["Failed"]
        assert source[0]["Severity"] == "High"
        details = source[0]["Finding_Details"]
        assert "'corpus-bucket' uses AES256 instead of SSE-KMS" in details
        assert "data source 'docs' in knowledge base 'CorpusKB'" in details

    def test_br20_aws_managed_key_is_not_a_customer_managed_key(self):
        source = self._run(
            [{"id": "ds1", "name": "docs", "bucket": "corpus-bucket"}],
            {"corpus-bucket": self._sse("aws:kms", "alias/aws/s3")},
        )

        assert [f["Status"] for f in source] == ["Failed"]
        assert "AWS-managed key alias/aws/s3" in source[0]["Finding_Details"]

    def test_br20_aws_managed_key_in_arn_form_is_not_credited(self):
        # KMSMasterKeyID arrives as a key id, a key ARN, an alias name or an
        # alias ARN. A match on the bare alias alone credits this ARN as a
        # customer-managed key and passes an AWS-managed bucket.
        source = self._run(
            [{"id": "ds1", "name": "docs", "bucket": "corpus-bucket"}],
            {
                "corpus-bucket": self._sse(
                    "aws:kms", "arn:aws:kms:us-east-1:123456789012:alias/aws/s3"
                )
            },
        )

        assert [f["Status"] for f in source] == ["Failed"]
        assert "alias/aws/s3" in source[0]["Finding_Details"]

    def test_br20_dual_layer_kms_with_a_customer_key_passes(self):
        source = self._run(
            [{"id": "ds1", "name": "docs", "bucket": "corpus-bucket"}],
            {"corpus-bucket": self._sse("aws:kms:dsse", self._CMK_ARN)},
        )

        assert [f["Status"] for f in source] == ["Passed"]
        assert "aws:kms:dsse" in source[0]["Finding_Details"]

    def test_br20_two_source_buckets_reach_both_verdicts(self):
        # Two buckets with different configurations: an aggregate row for the
        # region would have to pick one verdict and lose the other.
        source = self._run(
            [
                {"id": "ds1", "name": "docs", "bucket": "plain-bucket"},
                {"id": "ds2", "name": "hr", "bucket": "cmk-bucket"},
            ],
            {
                "plain-bucket": self._sse("AES256"),
                "cmk-bucket": self._sse("aws:kms", self._CMK_ARN),
            },
        )

        assert [f["Status"] for f in source] == ["Failed", "Passed"]
        assert "plain-bucket" in source[0]["Finding_Details"]
        assert "1 of 2" in source[1]["Finding_Details"]
        assert "cmk-bucket" in source[1]["Finding_Details"]
        assert "plain-bucket" not in source[1]["Finding_Details"]

    def test_br20_one_bucket_serving_two_data_sources_is_read_once(self):
        source = self._run(
            [
                {"id": "ds1", "name": "docs", "bucket": "shared-bucket"},
                {"id": "ds2", "name": "hr", "bucket": "shared-bucket"},
            ],
            {"shared-bucket": self._sse("AES256")},
        )

        assert [f["Status"] for f in source] == ["Failed"]
        assert self.s3_client.get_bucket_encryption.call_count == 1
        details = source[0]["Finding_Details"]
        assert "data source 'docs' in knowledge base 'CorpusKB'" in details
        assert "data source 'hr' in knowledge base 'CorpusKB'" in details

    def test_br20_source_bucket_access_denied_is_na_not_a_failure(self):
        source = self._run(
            [{"id": "ds1", "name": "docs", "bucket": "corpus-bucket"}],
            {
                "corpus-bucket": _client_error(
                    "AccessDenied", "denied", "GetBucketEncryption"
                )
            },
        )

        assert [f["Status"] for f in source] == ["N/A"]
        assert source[0]["Severity"] == "Informational"
        assert "corpus-bucket" in source[0]["Finding_Details"]
        assert "s3:GetEncryptionConfiguration" in source[0]["Resolution"]

    def test_br20_bucket_without_default_encryption_is_failed(self):
        source = self._run(
            [{"id": "ds1", "name": "docs", "bucket": "corpus-bucket"}],
            {
                "corpus-bucket": _client_error(
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "not found",
                    "GetBucketEncryption",
                )
            },
        )

        assert [f["Status"] for f in source] == ["Failed"]
        assert (
            "has no default encryption configuration at all"
            in source[0]["Finding_Details"]
        )

    def test_br20_cross_account_source_bucket_names_its_owner(self):
        source = self._run(
            [
                {
                    "id": "ds1",
                    "name": "docs",
                    "bucket": "partner-bucket",
                    "owner": "210987654321",
                }
            ],
            {"partner-bucket": self._sse("AES256")},
        )

        assert [f["Status"] for f in source] == ["Failed"]
        assert "owned by account 210987654321" in source[0]["Finding_Details"]

    def test_br20_non_s3_data_source_emits_no_encryption_row(self):
        # A knowledge base on a WEB connector has no bucket to judge, so the leg
        # has to stay silent instead of reporting a gap it cannot name.
        source = self._run([{"id": "ds1", "name": "site", "type": "WEB"}])

        assert source == []
        assert [f["Status"] for f in self.all_findings] == ["Passed"]
        self.s3_client.get_bucket_encryption.assert_not_called()

    def test_br20_data_source_walk_error_keeps_the_vector_store_verdict(self):
        source = self._run(
            [{"id": "ds1", "name": "docs", "bucket": "corpus-bucket"}],
            list_error=_client_error(
                "AccessDeniedException", "denied", "ListDataSources"
            ),
        )

        assert [f["Status"] for f in source] == ["N/A"]
        assert "knowledge base 'CorpusKB' data sources" in source[0]["Finding_Details"]
        # The managed knowledge base was still assessed on its own key.
        assert [f["Status"] for f in self.all_findings] == ["Passed", "N/A"]

    def test_br20_source_encryption_rows_pass_the_finding_schema(self):
        source = self._run(
            [
                {"id": "ds1", "name": "docs", "bucket": "plain-bucket"},
                {"id": "ds2", "name": "hr", "bucket": "cmk-bucket"},
                {"id": "ds3", "name": "denied", "bucket": "closed-bucket"},
            ],
            {
                "plain-bucket": self._sse("AES256"),
                "cmk-bucket": self._sse("aws:kms", self._CMK_ARN),
                "closed-bucket": _client_error(
                    "AccessDenied", "denied", "GetBucketEncryption"
                ),
            },
        )

        assert [f["Status"] for f in source] == ["Failed", "Passed", "N/A"]
        for finding in self.all_findings:
            assert_finding_schema(finding)
            assert finding["Check_ID"] == "BR-20"


class TestBR39MarketplaceSubnetPrivacy:
    """BR-39 / AIR-FND-NET-01: the registered subnets must not route to an IGW."""

    _PRIVATE_TABLE = {
        "RouteTableId": "rtb-private",
        "VpcId": "vpc-1",
        "Associations": [{"Main": False, "SubnetId": "subnet-private"}],
        "Routes": [
            {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"},
        ],
    }
    _PUBLIC_TABLE = {
        "RouteTableId": "rtb-public",
        "VpcId": "vpc-1",
        "Associations": [{"Main": False, "SubnetId": "subnet-public"}],
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
    }

    @staticmethod
    def _subnet(subnet_id, vpc_id="vpc-1"):
        return {"SubnetId": subnet_id, "VpcId": vpc_id}

    @staticmethod
    def _table(
        table_id,
        routes,
        subnet_id=None,
        main=False,
        vpc_id="vpc-1",
    ):
        associations = [{"Main": True}] if main else []
        if subnet_id:
            associations.append({"Main": False, "SubnetId": subnet_id})
        return {
            "RouteTableId": table_id,
            "VpcId": vpc_id,
            "Associations": associations,
            "Routes": list(routes),
        }

    @staticmethod
    def _ec2(subnets=(), tables=(), subnets_error=None, tables_error=None):
        """An ec2 client whose two paginators answer under their own names."""
        subnets_paginator = MagicMock()
        if subnets_error is not None:
            subnets_paginator.paginate.side_effect = subnets_error
        else:
            subnets_paginator.paginate.return_value = [{"Subnets": list(subnets)}]

        tables_paginator = MagicMock()
        if tables_error is not None:
            tables_paginator.paginate.side_effect = tables_error
        else:
            tables_paginator.paginate.return_value = [{"RouteTables": list(tables)}]

        ec2_client = MagicMock()
        ec2_client.get_paginator.side_effect = lambda operation: {
            "describe_subnets": subnets_paginator,
            "describe_route_tables": tables_paginator,
        }[operation]
        ec2_client.subnets_paginator = subnets_paginator
        ec2_client.tables_paginator = tables_paginator
        return ec2_client

    @staticmethod
    def _endpoint(arn, subnet_ids=(), security_group_ids=("sg-1",)):
        return {
            "summary": {"endpointArn": arn},
            "detail": {
                "endpointConfig": {
                    "sageMaker": {
                        "vpc": {
                            "subnetIds": list(subnet_ids),
                            "securityGroupIds": list(security_group_ids),
                        }
                    }
                }
            },
        }

    @classmethod
    def _inventory(cls, *endpoints):
        return {"items": list(endpoints), "errors": [], "list_error": None}

    def _run(self, inventory, ec2_client):
        return extract_csv_data(
            bedrock_app.check_bedrock_marketplace_endpoint_vpc(
                "us-east-1", inventory, ec2_client
            )
        )

    @staticmethod
    def _privacy_rows(findings):
        return [
            finding
            for finding in findings
            if finding["Finding"] == bedrock_app.MARKETPLACE_SUBNET_PRIVACY_FINDING
        ]

    def test_br39_private_subnet_passes(self):
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-private"])),
                self._ec2([self._subnet("subnet-private")], [self._PRIVATE_TABLE]),
            )
        )

        assert len(rows) == 1
        assert rows[0]["Status"] == "Passed"
        assert rows[0]["Severity"] == "High"
        assert "subnet-private" in rows[0]["Finding_Details"]
        assert "arn:endpoint-1" in rows[0]["Finding_Details"]

    def test_br39_public_subnet_fails_and_names_the_route(self):
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-public"])),
                self._ec2([self._subnet("subnet-public")], [self._PUBLIC_TABLE]),
            )
        )

        assert len(rows) == 1
        assert rows[0]["Status"] == "Failed"
        assert rows[0]["Severity"] == "High"
        details = rows[0]["Finding_Details"]
        assert "subnet-public" in details
        assert "rtb-public" in details
        assert "0.0.0.0/0" in details
        assert "igw-1" in details

    def test_br39_main_route_table_is_used_when_no_explicit_association(self):
        """A subnet with no explicit association inherits the VPC main table."""
        main_public = self._table(
            "rtb-main",
            [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-main"}],
            main=True,
        )
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-orphan"])),
                self._ec2([self._subnet("subnet-orphan")], [main_public]),
            )
        )

        assert [row["Status"] for row in rows] == ["Failed"]
        assert "rtb-main" in rows[0]["Finding_Details"]
        assert "igw-main" in rows[0]["Finding_Details"]

    def test_br39_explicit_association_wins_over_a_public_main_table(self):
        main_public = self._table(
            "rtb-main",
            [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-main"}],
            main=True,
        )
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-private"])),
                self._ec2(
                    [self._subnet("subnet-private")],
                    [main_public, self._PRIVATE_TABLE],
                ),
            )
        )

        assert [row["Status"] for row in rows] == ["Passed"]

    def test_br39_egress_only_internet_gateway_stays_private(self):
        egress_only = self._table(
            "rtb-eigw",
            [
                {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
                {
                    "DestinationIpv6CidrBlock": "::/0",
                    "EgressOnlyInternetGatewayId": "eigw-1",
                },
            ],
            subnet_id="subnet-v6",
        )
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-v6"])),
                self._ec2([self._subnet("subnet-v6")], [egress_only]),
            )
        )

        assert [row["Status"] for row in rows] == ["Passed"]

    def test_br39_blackhole_internet_gateway_route_stays_private(self):
        """A route whose internet gateway was deleted carries no traffic."""
        blackhole = self._table(
            "rtb-blackhole",
            [
                {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-deleted",
                    "State": "blackhole",
                },
            ],
            subnet_id="subnet-orphaned-igw",
        )
        rows = self._privacy_rows(
            self._run(
                self._inventory(
                    self._endpoint("arn:endpoint-1", ["subnet-orphaned-igw"])
                ),
                self._ec2([self._subnet("subnet-orphaned-igw")], [blackhole]),
            )
        )

        assert [row["Status"] for row in rows] == ["Passed"]

    def test_br39_route_read_timeout_is_na_and_does_not_escape(self):
        """A non-ClientError used to escape the check and abort the region."""
        from botocore.exceptions import ReadTimeoutError

        ec2_client = self._ec2(
            [self._subnet("subnet-private")],
            tables_error=ReadTimeoutError(endpoint_url="https://ec2.us-east-1"),
        )
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-private"])),
                ec2_client,
            )
        )

        assert [row["Status"] for row in rows] == ["N/A"]

    def test_br39_two_endpoints_reach_both_verdicts(self):
        findings = self._run(
            self._inventory(
                self._endpoint("arn:endpoint-private", ["subnet-private"]),
                self._endpoint("arn:endpoint-public", ["subnet-public"]),
            ),
            self._ec2(
                [self._subnet("subnet-private"), self._subnet("subnet-public")],
                [self._PRIVATE_TABLE, self._PUBLIC_TABLE],
            ),
        )

        rows = self._privacy_rows(findings)
        assert [row["Status"] for row in rows] == ["Passed", "Failed"]
        assert "arn:endpoint-private" in rows[0]["Finding_Details"]
        assert "arn:endpoint-public" in rows[1]["Finding_Details"]

    def test_br39_one_public_subnet_fails_an_otherwise_private_endpoint(self):
        """The endpoint verdict is any-public, not all-public."""
        rows = self._privacy_rows(
            self._run(
                self._inventory(
                    self._endpoint(
                        "arn:endpoint-1", ["subnet-private", "subnet-public"]
                    )
                ),
                self._ec2(
                    [self._subnet("subnet-private"), self._subnet("subnet-public")],
                    [self._PRIVATE_TABLE, self._PUBLIC_TABLE],
                ),
            )
        )

        assert [row["Status"] for row in rows] == ["Failed"]
        assert "1 of 2 subnet(s)" in rows[0]["Finding_Details"]

    def test_br39_missing_subnet_is_indeterminate_not_private(self):
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-gone"])),
                self._ec2([], []),
            )
        )

        assert [row["Status"] for row in rows] == ["N/A"]
        assert rows[0]["Severity"] == "Informational"
        assert "not present in this Region" in rows[0]["Finding_Details"]

    def test_br39_subnet_without_any_route_table_is_indeterminate(self):
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-lonely"])),
                self._ec2([self._subnet("subnet-lonely", vpc_id="vpc-9")], []),
            )
        )

        assert [row["Status"] for row in rows] == ["N/A"]
        assert "vpc-9" in rows[0]["Finding_Details"]

    def test_br39_a_public_subnet_outranks_an_unresolved_one(self):
        rows = self._privacy_rows(
            self._run(
                self._inventory(
                    self._endpoint("arn:endpoint-1", ["subnet-public", "subnet-gone"])
                ),
                self._ec2([self._subnet("subnet-public")], [self._PUBLIC_TABLE]),
            )
        )

        assert [row["Status"] for row in rows] == ["Failed"]

    def test_br39_one_nonexistent_subnet_does_not_hide_the_others(self):
        """DescribeSubnets fails the whole request when one id does not exist.

        Without the per-subnet retry the public subnet beside the missing one
        reads as an error and the row asks for ec2:DescribeSubnets.
        """
        ec2_client = self._ec2([self._subnet("subnet-public")], [self._PUBLIC_TABLE])

        def paginate(SubnetIds):
            if "subnet-gone" in SubnetIds:
                raise _client_error(
                    "InvalidSubnetID.NotFound", "not found", "DescribeSubnets"
                )
            return [{"Subnets": [self._subnet(s) for s in SubnetIds]}]

        ec2_client.subnets_paginator.paginate.side_effect = paginate
        rows = self._privacy_rows(
            self._run(
                self._inventory(
                    self._endpoint("arn:endpoint-1", ["subnet-public", "subnet-gone"]),
                    self._endpoint("arn:endpoint-2", ["subnet-gone"]),
                ),
                ec2_client,
            )
        )

        assert [row["Status"] for row in rows] == ["Failed", "N/A"]
        assert "subnet-public" in rows[0]["Finding_Details"]
        assert "subnet-gone" in rows[1]["Finding_Details"]
        assert "not present in this Region" in rows[1]["Finding_Details"]
        assert "ec2:DescribeSubnets" not in rows[1]["Resolution"]

    def test_br39_describe_subnets_denied_is_na_not_private(self):
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-private"])),
                self._ec2(
                    subnets_error=_client_error(
                        "AccessDenied", "denied", "DescribeSubnets"
                    )
                ),
            )
        )

        assert [row["Status"] for row in rows] == ["N/A"]
        assert "AccessDenied" in rows[0]["Finding_Details"]
        assert "ec2:DescribeSubnets" in rows[0]["Resolution"]
        assert "ec2:DescribeRouteTables" in rows[0]["Resolution"]

    def test_br39_describe_route_tables_denied_is_na_not_private(self):
        ec2_client = self._ec2(
            [self._subnet("subnet-private")],
            tables_error=_client_error(
                "UnauthorizedOperation", "denied", "DescribeRouteTables"
            ),
        )
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", ["subnet-private"])),
                ec2_client,
            )
        )

        assert [row["Status"] for row in rows] == ["N/A"]
        assert "UnauthorizedOperation" in rows[0]["Finding_Details"]

    def test_br39_endpoint_without_subnets_reaches_no_ec2_call(self):
        ec2_client = self._ec2()
        findings = self._run(
            {
                "items": [
                    {
                        "summary": {"endpointArn": "arn:endpoint-1"},
                        "detail": {"endpointConfig": {"sageMaker": {}}},
                    }
                ],
                "errors": [],
                "list_error": None,
            },
            ec2_client,
        )

        assert self._privacy_rows(findings) == []
        assert [finding["Status"] for finding in findings] == ["Failed"]
        ec2_client.get_paginator.assert_not_called()

    def test_br39_subnets_of_every_endpoint_are_resolved_in_one_pass(self):
        ec2_client = self._ec2(
            [self._subnet("subnet-private"), self._subnet("subnet-public")],
            [self._PRIVATE_TABLE, self._PUBLIC_TABLE],
        )
        self._run(
            self._inventory(
                self._endpoint("arn:endpoint-1", ["subnet-public", "subnet-private"]),
                self._endpoint("arn:endpoint-2", ["subnet-private"]),
            ),
            ec2_client,
        )

        ec2_client.subnets_paginator.paginate.assert_called_once_with(
            SubnetIds=["subnet-private", "subnet-public"]
        )
        ec2_client.tables_paginator.paginate.assert_called_once_with(
            Filters=[{"Name": "vpc-id", "Values": ["vpc-1"]}]
        )

    def test_br39_subnet_walk_is_capped_and_reports_the_remainder(self):
        subnet_ids = [f"subnet-{index:03d}" for index in range(60)]
        cap = bedrock_app.MAX_MARKETPLACE_SUBNETS_CHECKED
        ec2_client = self._ec2(
            [self._subnet(subnet_id) for subnet_id in subnet_ids[:cap]],
            [self._table("rtb-shared", self._PRIVATE_TABLE["Routes"], main=True)],
        )
        rows = self._privacy_rows(
            self._run(
                self._inventory(self._endpoint("arn:endpoint-1", subnet_ids)),
                ec2_client,
            )
        )

        assert [row["Status"] for row in rows] == ["N/A"]
        assert f"{cap} of 60 subnet(s)" in rows[0]["Finding_Details"]
        assert f"stopped after {cap} subnets" in rows[0]["Finding_Details"]
        assert (
            len(ec2_client.subnets_paginator.paginate.call_args.kwargs["SubnetIds"])
            == cap
        )

    def test_br39_privacy_rows_pass_the_finding_schema(self):
        findings = self._run(
            self._inventory(
                self._endpoint("arn:endpoint-private", ["subnet-private"]),
                self._endpoint("arn:endpoint-public", ["subnet-public"]),
                self._endpoint("arn:endpoint-unknown", ["subnet-gone"]),
            ),
            self._ec2(
                [self._subnet("subnet-private"), self._subnet("subnet-public")],
                [self._PRIVATE_TABLE, self._PUBLIC_TABLE],
            ),
        )

        rows = self._privacy_rows(findings)
        assert [row["Status"] for row in rows] == ["Passed", "Failed", "N/A"]
        for finding in rows:
            assert_finding_schema(finding)
            assert finding["Check_ID"] == "BR-39"
            assert finding["Region"] == "us-east-1"
