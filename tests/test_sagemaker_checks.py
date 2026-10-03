"""
Tests for SageMaker security assessment checks (SM-01 through SM-25).

Each check is tested for:
- No resources found -> N/A status
- Compliant resources -> Passed status
- Non-compliant resources -> Failed with correct severity
- Exception handling -> returns could-not-assess finding (csv_data not empty)
- Output schema validity
"""

import sys
import os
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import call, patch, MagicMock

from botocore.exceptions import EndpointConnectionError, ClientError
import pytest

from tests.test_helpers import extract_csv_data, assert_finding_schema

# Load sagemaker app module directly to avoid name collisions
_sm_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/sagemaker_assessments",
    )
)
if _sm_dir not in sys.path:
    sys.path.insert(0, _sm_dir)

_spec = importlib.util.spec_from_file_location(
    "sagemaker_app", os.path.join(_sm_dir, "app.py")
)
sagemaker_app = importlib.util.module_from_spec(_spec)
sys.modules["sagemaker_app"] = sagemaker_app
_spec.loader.exec_module(sagemaker_app)


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
        sagemaker_app._caller_identity_partition(caller_identity) == expected_partition
    )


def assert_could_not_assess_finding(finding):
    assert finding["Status"] == "N/A"
    assert finding["Severity"] == "Informational"
    assert "Could not assess this check" in finding["Finding_Details"]
    assert "Error during check" not in finding["Finding_Details"]


# ===================================================================
# SM-01: check_sagemaker_internet_access
# ===================================================================
class TestSM01InternetAccess:
    """SM-01: Check SageMaker direct internet access."""

    @patch("sagemaker_app.boto3.client")
    def test_sm01_no_resources_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        domain_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            nb_paginator if x == "list_notebook_instances" else domain_paginator
        )
        nb_paginator.paginate.return_value = [{"NotebookInstances": []}]
        domain_paginator.paginate.return_value = [{"Domains": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "SM-01"

    @patch("sagemaker_app.boto3.client")
    def test_sm01_notebook_with_internet_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        domain_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            nb_paginator if x == "list_notebook_instances" else domain_paginator
        )
        nb_paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "test-nb"}]}
        ]
        domain_paginator.paginate.return_value = [{"Domains": []}]
        mock_sm.describe_notebook_instance.return_value = {
            "DirectInternetAccess": "Enabled",
            "SubnetId": "subnet-123",
            "VpcId": "vpc-123",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("sagemaker_app.boto3.client")
    def test_sm01_all_vpc_only_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        domain_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            nb_paginator if x == "list_notebook_instances" else domain_paginator
        )
        nb_paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "test-nb"}]}
        ]
        domain_paginator.paginate.return_value = [{"Domains": []}]
        # A notebook passes only when it is placed in a VPC subnet as well.
        mock_sm.describe_notebook_instance.return_value = {
            "DirectInternetAccess": "Disabled",
            "SubnetId": "subnet-123",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm01_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_client.side_effect = Exception("SageMaker error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm01_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        domain_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            nb_paginator if x == "list_notebook_instances" else domain_paginator
        )
        nb_paginator.paginate.return_value = [{"NotebookInstances": []}]
        domain_paginator.paginate.return_value = [{"Domains": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-02: check_sagemaker_iam_permissions
# ===================================================================
class TestSM02IAMPermissions:
    """SM-02: Check SageMaker IAM permissions and SSO."""

    def test_sm02_empty_cache_returns_findings(self, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-02"

    def test_sm02_full_access_returns_failed(
        self, permission_cache_sagemaker_full_access
    ):
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(permission_cache_sagemaker_full_access)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Should flag full access as an issue
        has_failed = any(f["Status"] == "Failed" for f in findings)
        assert has_failed

    def test_sm02_schema_valid(self, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    def test_sm02_iam_check_does_not_query_domains(
        self, permission_cache_sagemaker_full_access
    ):
        # The IAM-global SM-02 check must NOT call regional SageMaker domain APIs;
        # domain/SSO inspection lives in check_sagemaker_sso_configuration so it is
        # not duplicated per region. Only IAM findings should be produced here.
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(permission_cache_sagemaker_full_access, region="Global")
        findings = extract_csv_data(result)
        # No SSO finding should be emitted from the IAM-global check
        assert all("SSO" not in f["Finding"] for f in findings)


# ===================================================================
# SM-02b: check_sagemaker_sso_configuration (regional)
# ===================================================================
class TestSM02SSOConfiguration:
    """SM-02: Regional SageMaker domain SSO configuration check."""

    @patch("sagemaker_app.boto3.client")
    def test_sso_no_domains_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_sso_configuration
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Domains": []}]
        mock_sm.get_paginator.return_value = mock_paginator
        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-02"
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sso_non_sso_domain_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_sso_configuration
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Domains": [{"DomainId": "d-123"}]}]
        mock_sm.get_paginator.return_value = mock_paginator
        mock_sm.describe_domain.return_value = {
            "DomainName": "test-domain",
            "AuthMode": "IAM",
        }
        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert "SSO" in findings[0]["Finding"]

    @patch("sagemaker_app.boto3.client")
    def test_sso_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_sso_configuration
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Domains": []}]
        mock_sm.get_paginator.return_value = mock_paginator
        result = check(region="us-east-1")
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-03: check_sagemaker_data_protection
# ===================================================================
class TestSM03DataProtection:
    """SM-03: Check SageMaker data protection / encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm03_no_resources_returns_na_or_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_protection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        # Mock paginators for notebooks, endpoints, training jobs
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [], "EndpointConfigs": [], "TrainingJobSummaries": []}
        ]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-03"

    @patch("sagemaker_app.boto3.client")
    def test_sm03_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_protection
        mock_client.side_effect = Exception("Data protection error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm03_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_protection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-04: check_guardduty_enabled
# ===================================================================
class TestSM04GuardDuty:
    """SM-04: Check GuardDuty is enabled."""

    @patch("sagemaker_app.boto3.client")
    def test_sm04_guardduty_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_gd = MagicMock()
        mock_client.return_value = mock_gd
        mock_gd.list_detectors.return_value = {"DetectorIds": ["d-123"]}
        mock_gd.get_detector.return_value = {"Status": "ENABLED"}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "SM-04"

    @patch("sagemaker_app.boto3.client")
    def test_sm04_guardduty_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_gd = MagicMock()
        mock_client.return_value = mock_gd
        mock_gd.list_detectors.return_value = {"DetectorIds": []}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm04_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_client.side_effect = Exception("GuardDuty error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm04_schema_valid(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_gd = MagicMock()
        mock_client.return_value = mock_gd
        mock_gd.list_detectors.return_value = {"DetectorIds": []}
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


class TestSM04SecurityHubRouting:
    """AIR-FND-DET-02: GuardDuty findings reach Security Hub."""

    GUARDDUTY = (
        "arn:aws:securityhub:us-east-1:111122223333:product-subscription/aws/guardduty"
    )

    def _rows(self, mock_client, pages=None, error=None, status="ENABLED"):
        client = MagicMock()
        if error is not None:
            client.get_paginator.side_effect = error
        else:
            client.get_paginator.side_effect = _pager(
                {"list_enabled_products_for_import": pages, "list_rules": []}
            )
        mock_client.return_value = client
        inventory = {
            "detector_id": "d-1",
            "detail": {"Status": status},
            "error": None,
        }
        return extract_csv_data(
            sagemaker_app.check_guardduty_enabled("us-east-1", inventory)
        )

    @patch("sagemaker_app.boto3.client")
    def test_passed_text_claims_only_the_detector_status(self, mock_client):
        rows = self._rows(mock_client, [{"ProductSubscriptions": [self.GUARDDUTY]}])
        assert rows[0]["Status"] == "Passed"
        assert "monitoring for security threats" not in rows[0]["Finding_Details"]
        assert "Status ENABLED" in rows[0]["Finding_Details"]
        # AIR-FND-DET-02: Security Hub Workflow.Status does record review.
        assert "not recorded by any" not in rows[0]["Finding_Details"]
        assert (
            "Workflow.Status, which this check does not read"
            in (rows[0]["Finding_Details"])
        )

    @patch("sagemaker_app.boto3.client")
    def test_guardduty_integration_on_a_later_page_passes(self, mock_client):
        rows = self._rows(
            mock_client,
            [
                {
                    "ProductSubscriptions": [
                        self.GUARDDUTY.replace("aws/guardduty", "aws/inspector")
                    ]
                },
                {"ProductSubscriptions": [self.GUARDDUTY]},
            ],
        )
        assert [r["Finding"] for r in rows] == [
            "GuardDuty Enabled",
            sagemaker_app.GUARDDUTY_ROUTING_FINDING,
            sagemaker_app.GUARDDUTY_EVENTBRIDGE_FINDING,
        ]
        assert rows[1]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_lookalike_subscription_does_not_count(self, mock_client):
        rows = self._rows(
            mock_client,
            [
                {
                    "ProductSubscriptions": [
                        self.GUARDDUTY.replace("aws/guardduty", "partner/guardduty"),
                        self.GUARDDUTY + "-archive",
                    ]
                }
            ],
        )
        assert rows[1]["Status"] == "Failed"
        assert "2 enabled product integration(s)" in rows[1]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_read_failure_is_incomplete_not_failed_or_passed(self, mock_client):
        rows = self._rows(
            mock_client, error=_make_client_error("InvalidAccessException")
        )
        assert rows[1]["Status"] == "N/A"
        assert rows[1]["Finding"].endswith("Incomplete")
        assert "ListEnabledProductsForImport" in rows[1]["Finding_Details"]

    GUARDDUTY_PATTERN = (
        '{"source": ["aws.guardduty"], "detail-type": ["GuardDuty Finding"]}'
    )

    def _eventbridge(self, mock_client, rules, targets=None, errors=None):
        errors = errors or {}
        targets = targets or {}
        client = MagicMock()

        def list_rules():
            if "list_rules" in errors:
                raise errors["list_rules"]
            return [{"Rules": rules[:1]}, {"Rules": rules[1:]}]

        def list_targets_by_rule(Rule):
            if Rule in errors:
                raise errors[Rule]
            return [{"Targets": targets.get(Rule, [])}]

        client.get_paginator.side_effect = _pager(
            {
                "list_enabled_products_for_import": [
                    {"ProductSubscriptions": [self.GUARDDUTY]}
                ],
                "list_rules": list_rules,
                "list_targets_by_rule": list_targets_by_rule,
            }
        )
        mock_client.return_value = client
        inventory = {
            "detector_id": "d-1",
            "detail": {"Status": "ENABLED"},
            "error": None,
        }
        rows = extract_csv_data(
            sagemaker_app.check_guardduty_enabled("us-east-1", inventory)
        )
        assert rows[2]["Check_ID"] == "SM-04"
        return rows[2]

    def _rule(self, name, pattern=None, state="ENABLED"):
        return {
            "Name": name,
            "State": state,
            "EventPattern": pattern or self.GUARDDUTY_PATTERN,
        }

    @patch("sagemaker_app.boto3.client")
    def test_targeted_guardduty_rule_on_a_later_page_passes(self, mock_client):
        row = self._eventbridge(
            mock_client,
            [
                self._rule("hub", '{"source": ["aws.securityhub"]}'),
                self._rule("gd"),
            ],
            targets={"hub": [{"Id": "t"}], "gd": [{"Id": "sns"}]},
        )
        assert row["Finding"] == sagemaker_app.GUARDDUTY_EVENTBRIDGE_FINDING
        assert row["Status"] == "Passed"
        assert "'gd'" in row["Finding_Details"]

    @pytest.mark.parametrize(
        "rule,targets",
        [
            ({"state": "DISABLED"}, [{"Id": "sns"}]),
            ({"pattern": '{"source": ["aws.securityhub"]}'}, [{"Id": "sns"}]),
            ({"pattern": '{"source": [{"prefix": "aws.guard"}]}'}, [{"Id": "sns"}]),
            ({"pattern": "not json"}, [{"Id": "sns"}]),
            ({}, []),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_rule_that_cannot_alert_on_guardduty_fails(
        self, mock_client, rule, targets
    ):
        row = self._eventbridge(
            mock_client, [self._rule("gd", **rule)], targets={"gd": targets}
        )
        assert row["Status"] == "Failed"
        assert "none has a target" in row["Finding_Details"]

    @pytest.mark.parametrize(
        "detail_type",
        [["AWS API Call via CloudTrail"], "AWS API Call via CloudTrail", []],
    )
    @pytest.mark.parametrize("wrong_first", [True, False])
    @patch("sagemaker_app.boto3.client")
    def test_a_rule_on_another_detail_type_does_not_route_findings(
        self, mock_client, detail_type, wrong_first
    ):
        wrong = json.dumps({"source": ["aws.guardduty"], "detail-type": detail_type})
        rules = [self._rule("api", wrong), self._rule("gd")]
        if not wrong_first:
            rules.reverse()
        row = self._eventbridge(mock_client, rules, targets={"api": [{"Id": "sns"}]})
        assert row["Status"] == "Failed"
        assert "none has a target" in row["Finding_Details"]
        assert "GuardDuty Finding" in row["Finding_Details"]

    @pytest.mark.parametrize(
        "pattern",
        [
            '{"source": ["aws.guardduty"]}',
            '{"source": "aws.guardduty", "detail-type": "GuardDuty Finding"}',
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_a_rule_admitting_the_finding_detail_type_passes(
        self, mock_client, pattern
    ):
        row = self._eventbridge(
            mock_client, [self._rule("gd", pattern)], targets={"gd": [{"Id": "sns"}]}
        )
        assert row["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_list_rules_failure_is_incomplete(self, mock_client):
        row = self._eventbridge(
            mock_client, [], errors={"list_rules": _make_client_error("AccessDenied")}
        )
        assert row["Status"] == "N/A"
        assert "events:ListRules" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_unread_targets_are_incomplete_not_failed(self, mock_client):
        row = self._eventbridge(
            mock_client,
            [self._rule("gd-a"), self._rule("gd-b")],
            errors={"gd-b": _make_client_error("AccessDenied")},
        )
        assert row["Status"] == "N/A"
        assert "rule 'gd-b'" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_disabled_detector_reads_no_routing(self, mock_client):
        rows = self._rows(mock_client, [], status="DISABLED")
        assert [r["Status"] for r in rows] == ["Failed"]


class TestProposedSageMakerChecks:
    """SM-26 through SM-30 proposal checks (SM-29 remains reserved/deferred)."""

    # SM-26 reads the organization auto-enable configuration once the detector
    # is ENABLED, so boto3 is patched here to keep these tests off the network.
    @patch("sagemaker_app.boto3.client")
    def test_sm26_ai_protection_enabled_passes(self, mock_client):
        inventory = {
            "detector_id": "detector-1",
            "detail": {
                "Status": "ENABLED",
                "Features": [{"Name": "AI_PROTECTION", "Status": "ENABLED"}],
            },
            "error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_guardduty_ai_protection("us-east-1", inventory)
        )[0]
        assert finding["Check_ID"] == "SM-26"
        assert finding["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm26_ai_protection_disabled_fails(self, mock_client):
        inventory = {
            "detector_id": "detector-1",
            "detail": {"Status": "ENABLED", "Features": []},
            "error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_guardduty_ai_protection("us-east-1", inventory)
        )[0]
        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "High"

    def test_sm26_a_suspended_detector_fails_despite_the_feature(self):
        inventory = {
            "detector_id": "detector-1",
            "detail": {
                "Status": "DISABLED",
                "Features": [{"Name": "AI_PROTECTION", "Status": "ENABLED"}],
            },
            "error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_guardduty_ai_protection("us-east-1", inventory)
        )[0]
        assert finding["Status"] == "Failed"
        assert "detector-1" in finding["Finding_Details"]
        assert "DISABLED" in finding["Finding_Details"]
        assert "AI Protection is enabled" not in finding["Finding_Details"]

    ENABLED_INVENTORY = {
        "detector_id": "detector-1",
        "detail": {
            "Status": "ENABLED",
            "Features": [{"Name": "AI_PROTECTION", "Status": "ENABLED"}],
        },
        "error": None,
    }

    def _org_rows(self, mock_client, pages=None, error=None, inventory=None):
        client = mock_client.return_value
        if error is not None:
            client.describe_organization_configuration.side_effect = error
        else:
            client.describe_organization_configuration.side_effect = list(pages)
        rows = extract_csv_data(
            sagemaker_app.check_guardduty_ai_protection(
                "us-east-1", inventory or self.ENABLED_INVENTORY
            )
        )
        return [
            r
            for r in rows
            if r["Finding"] == sagemaker_app.GUARDDUTY_ORG_AUTO_ENABLE_FINDING
        ]

    @staticmethod
    def _org_page(members="ALL", ai="ALL", token=None, others=("S3_DATA_EVENTS",)):
        features = [{"Name": name, "AutoEnable": "NONE"} for name in others]
        if ai is not None:
            features.append({"Name": "AI_PROTECTION", "AutoEnable": ai})
        page = {"AutoEnableOrganizationMembers": members, "Features": features}
        if token:
            page["NextToken"] = token
        return page

    @patch("sagemaker_app.boto3.client")
    def test_sm26_org_auto_enable_all_passes(self, mock_client):
        rows = self._org_rows(mock_client, [self._org_page()])
        assert [r["Status"] for r in rows] == ["Passed"]
        mock_client.return_value.describe_organization_configuration.assert_called_once_with(
            DetectorId="detector-1"
        )

    @pytest.mark.parametrize(
        "members,ai",
        [("ALL", "NEW"), ("ALL", "NONE"), ("NEW", "ALL"), ("NONE", "ALL")],
    )
    @patch("sagemaker_app.boto3.client")
    def test_sm26_org_auto_enable_short_of_all_fails(self, mock_client, members, ai):
        rows = self._org_rows(mock_client, [self._org_page(members=members, ai=ai)])
        assert [r["Status"] for r in rows] == ["Failed"]
        assert (
            f"AutoEnableOrganizationMembers is {members}" in rows[0]["Finding_Details"]
        )
        assert f"AI_PROTECTION feature AutoEnable is {ai}" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_sm26_org_without_an_ai_protection_entry_fails(self, mock_client):
        rows = self._org_rows(mock_client, [self._org_page(ai=None)])
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "AutoEnable is not returned" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_sm26_org_ai_protection_on_a_later_page_is_read(self, mock_client):
        rows = self._org_rows(
            mock_client,
            [
                self._org_page(ai=None, token="t1"),
                self._org_page(ai="ALL", others=("EKS_AUDIT_LOGS",)),
            ],
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert (
            mock_client.return_value.describe_organization_configuration.call_args_list[
                1
            ].kwargs
            == {"DetectorId": "detector-1", "NextToken": "t1"}
        )

    @patch("sagemaker_app.boto3.client")
    def test_sm26_org_read_error_is_na_naming_the_delegated_admin(self, mock_client):
        rows = self._org_rows(
            mock_client, error=_make_client_error("BadRequestException")
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "DescribeOrganizationConfiguration" in rows[0]["Finding_Details"]
        assert "delegated administrator" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_sm26_org_leg_is_not_read_for_a_suspended_detector(self, mock_client):
        inventory = {
            "detector_id": "detector-1",
            "detail": {"Status": "DISABLED", "Features": []},
            "error": None,
        }
        assert self._org_rows(mock_client, [], inventory=inventory) == []
        mock_client.return_value.describe_organization_configuration.assert_not_called()

    def test_sm26_no_detector_fails(self):
        finding = extract_csv_data(
            sagemaker_app.check_guardduty_ai_protection(
                "us-east-1", {"detector_id": None, "detail": None, "error": None}
            )
        )[0]
        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "High"
        assert "No GuardDuty detector" in finding["Finding_Details"]

    # SM-28 now reads the route tables of the effective VPC subnets, so boto3 is
    # patched here to keep this unit test off the network.
    @patch("sagemaker_app.boto3.client")
    def test_sm27_and_sm28_share_hyperpod_inventory(self, mock_client):
        # SM-27 credits a key only when kms:DescribeKey reports CUSTOMER.
        mock_client.return_value.describe_key.return_value = {
            "KeyMetadata": {"KeyManager": "CUSTOMER"}
        }
        inventory = {
            "items": [
                {
                    "summary": {"ClusterName": "cluster-1"},
                    "detail": {
                        "ClusterName": "cluster-1",
                        "VpcConfig": {
                            "Subnets": ["subnet-1"],
                            "SecurityGroupIds": ["sg-1"],
                        },
                        "InstanceGroups": [
                            {
                                "InstanceGroupName": "workers",
                                "InstanceStorageConfigs": [
                                    {
                                        "EbsVolumeConfig": {
                                            "RootVolume": True,
                                            "VolumeKmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                                        }
                                    },
                                    {
                                        "EbsVolumeConfig": {
                                            "RootVolume": False,
                                            "VolumeKmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/key-2",
                                        }
                                    },
                                ],
                            }
                        ],
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        sm27 = extract_csv_data(
            sagemaker_app.check_hyperpod_ebs_cmk_encryption("us-east-1", inventory)
        )[0]
        sm28 = extract_csv_data(
            sagemaker_app.check_hyperpod_vpc_configuration("us-east-1", inventory)
        )[0]
        assert sm27["Status"] == "Passed"
        assert sm28["Status"] == "Passed"

    def test_sm27_missing_root_volume_config_fails(self):
        inventory = {
            "items": [
                {
                    "summary": {"ClusterName": "cluster-1"},
                    "detail": {
                        "ClusterName": "cluster-1",
                        "InstanceGroups": [
                            {
                                "InstanceGroupName": "workers",
                                "InstanceStorageConfigs": [],
                            }
                        ],
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_hyperpod_ebs_cmk_encryption("us-east-1", inventory)
        )[0]
        assert finding["Status"] == "Failed"
        assert "root volume" in finding["Finding_Details"]
        assert finding["Finding_Details"].count("root volume") == 1

    def test_sm27_deduplicates_unencrypted_volume_labels(self):
        inventory = {
            "items": [
                {
                    "summary": {"ClusterName": "cluster-1"},
                    "detail": {
                        "ClusterName": "cluster-1",
                        "InstanceGroups": [
                            {
                                "InstanceGroupName": "workers",
                                "InstanceStorageConfigs": [
                                    {
                                        "EbsVolumeConfig": {
                                            "RootVolume": True,
                                        }
                                    },
                                    {
                                        "EbsVolumeConfig": {
                                            "RootVolume": True,
                                        }
                                    },
                                ],
                            }
                        ],
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_hyperpod_ebs_cmk_encryption("us-east-1", inventory)
        )[0]
        assert finding["Finding_Details"].count("root volume") == 1

    def test_sm28_incomplete_vpc_fails(self):
        inventory = {
            "items": [
                {
                    "summary": {"ClusterName": "cluster-1"},
                    "detail": {
                        "ClusterName": "cluster-1",
                        "InstanceGroups": [
                            {
                                "InstanceGroupName": "workers",
                            }
                        ],
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_hyperpod_vpc_configuration("us-east-1", inventory)
        )[0]
        assert finding["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_public_resource_policy_fails(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Principal":"*",'
                '"Action":"sagemaker:CreateModelPackage","Resource":"*"}]}'
            )
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Check_ID"] == "SM-30"
        assert finding["Status"] == "Failed"

    def test_sm30_condition_boundaries_accept_supported_patterns(self):
        boundaries = sagemaker_app._policy_condition_boundaries(
            {
                "Condition": {
                    "StringLike": {
                        "aws:PrincipalOrgID": "o-a1b2c3d4e5",
                    },
                    "ArnLike": {
                        "aws:PrincipalArn": "arn:aws:iam::111122223333:role/ml-*",
                    },
                    "ForAnyValue:StringLike": {
                        "aws:PrincipalOrgPaths": "o-f6g7h8i9j0/r-ab12/ou-ab12-11111111/*",
                    },
                }
            }
        )
        assert boundaries["accounts"] == {"111122223333"}
        assert boundaries["organizations"] == {
            "o-a1b2c3d4e5",
            "o-f6g7h8i9j0",
        }

    def test_sm30_condition_boundaries_reject_unbounded_patterns(self):
        boundaries = sagemaker_app._policy_condition_boundaries(
            {
                "Condition": {
                    "StringLike": {
                        "aws:PrincipalOrgID": "o-*",
                    },
                    "ArnLike": {
                        "aws:PrincipalArn": "arn:aws:iam::*:role/ml-*",
                    },
                    "ForAllValues:StringLike": {
                        "aws:PrincipalOrgPaths": "o-a1b2c3d4e5/*",
                    },
                }
            }
        )
        assert boundaries == {"accounts": set(), "organizations": set()}

    def test_sm30_for_all_org_paths_requires_non_null_condition(self):
        boundaries = sagemaker_app._policy_condition_boundaries(
            {
                "Condition": {
                    "ForAllValues:StringLike": {
                        "aws:PrincipalOrgPaths": "o-a1b2c3d4e5/*",
                    },
                    "Null": {
                        "aws:PrincipalOrgPaths": "false",
                    },
                }
            }
        )
        assert boundaries["organizations"] == {"o-a1b2c3d4e5"}

    @patch.dict(
        os.environ,
        {"AIML_APPROVED_ORG_IDS": "o-a1b2c3d4e5"},
        clear=False,
    )
    @patch("sagemaker_app.boto3.client")
    def test_sm30_org_path_condition_is_not_public(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                    "Condition": {
                        "ForAnyValue:StringLike": {
                            "aws:PrincipalOrgPaths": (
                                "o-a1b2c3d4e5/r-ab12/ou-ab12-11111111/*"
                            )
                        }
                    },
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "Passed"
        assert finding["Finding"] == "Model Package Group Resource Policy Exposure"

    @pytest.mark.parametrize(
        ("principal_account", "expected_status"),
        [
            ("111122223333", "Passed"),
            ("444455556666", "Failed"),
        ],
        ids=["approved-account", "unapproved-account"],
    )
    @patch("sagemaker_app.boto3.client")
    def test_sm30_external_account_allowlist_is_enforced(
        self, mock_client, principal_account, expected_status
    ):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{principal_account}:root",
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        with patch.dict(
            os.environ,
            {
                "AIML_APPROVED_EXTERNAL_ACCOUNT_IDS": "111122223333",
                "AIML_APPROVED_ORG_IDS": "",
            },
            clear=False,
        ):
            finding = extract_csv_data(
                sagemaker_app.check_model_package_group_policy_exposure(
                    "us-east-1",
                    [{"ModelPackageGroupName": "group-1"}],
                )
            )[0]

        assert finding["Status"] == expected_status
        assert finding["Severity"] == "High"

    @patch.dict(
        os.environ,
        {"AIML_APPROVED_ORG_IDS": "o-a1b2c3d4e5"},
        clear=False,
    )
    @patch("sagemaker_app.boto3.client")
    def test_sm30_unapproved_org_path_fails_configured_boundary(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                    "Condition": {
                        "ForAnyValue:StringLike": {
                            "aws:PrincipalOrgPaths": (
                                "o-f6g7h8i9j0/r-ab12/ou-ab12-11111111/*"
                            )
                        }
                    },
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "High"
        assert "o-f6g7h8i9j0" in finding["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_sm30_allow_notprincipal_is_unsupported(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotPrincipal": {
                        "AWS": "arn:aws:iam::111122223333:root",
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Finding"] == ("Unsupported Model Package Group Resource Policy")

    @patch("sagemaker_app.boto3.client")
    def test_sm30_deny_notprincipal_does_not_create_exposure(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "NotPrincipal": {
                        "AWS": "arn:aws:iam::123456789012:role/approved",
                    },
                    "Action": "sagemaker:*",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/approved",
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                },
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "Passed"
        assert finding["Finding"] == "Model Package Group Resource Policy Exposure"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_public_allow_precedes_unsupported_statement(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotPrincipal": {
                        "AWS": "arn:aws:iam::111122223333:root",
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                },
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "Failed"
        assert finding["Finding"] == "Public Model Package Group Resource Policy"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_unknown_caller_account_returns_na(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.side_effect = RuntimeError("STS unavailable")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/registry-writer"
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "Account Context Unavailable" in finding["Finding"]

    @patch("sagemaker_app.boto3.client")
    def test_sm30_public_policy_fails_even_when_sts_unavailable(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.side_effect = RuntimeError("STS unavailable")
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Principal":"*",'
                '"Action":"sagemaker:CreateModelPackage","Resource":"*"}]}'
            )
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "Failed"
        assert finding["Finding"] == "Public Model Package Group Resource Policy"

    def test_new_sagemaker_checks_access_denied_return_na(self):
        error = _make_client_error("AccessDeniedException")
        sm26 = extract_csv_data(
            sagemaker_app.check_guardduty_ai_protection(
                "us-east-1",
                {"detector_id": None, "detail": None, "error": error},
            )
        )[0]
        inventory = {"items": [], "errors": [], "list_error": error}
        sm27 = extract_csv_data(
            sagemaker_app.check_hyperpod_ebs_cmk_encryption("us-east-1", inventory)
        )[0]
        sm28 = extract_csv_data(
            sagemaker_app.check_hyperpod_vpc_configuration("us-east-1", inventory)
        )[0]
        for finding in (sm26, sm27, sm28):
            assert finding["Status"] == "N/A"
            assert finding["Severity"] == "Informational"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_policy_access_denied_returns_na_and_continues(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        sagemaker_client.get_model_package_group_policy.side_effect = [
            {"ResourcePolicy": "{}"},
            _make_client_error("AccessDeniedException"),
            {
                "ResourcePolicy": (
                    '{"Version":"2012-10-17","Statement":'
                    '[{"Effect":"Allow","Principal":"*",'
                    '"Action":"sagemaker:CreateModelPackage","Resource":"*"}]}'
                )
            },
        ]

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        findings = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [
                    {"ModelPackageGroupName": "group-1"},
                    {"ModelPackageGroupName": "group-2"},
                    {"ModelPackageGroupName": "group-3"},
                ],
            )
        )

        assert [finding["Status"] for finding in findings] == [
            "Passed",
            "N/A",
            "Failed",
        ]
        assert findings[1]["Severity"] == "Informational"
        assert "group-2" in findings[1]["Finding_Details"]
        assert "AccessDeniedException" in findings[1]["Finding_Details"]
        assert sagemaker_client.get_model_package_group_policy.call_args_list == [
            call(ModelPackageGroupName="group-1"),
            call(ModelPackageGroupName="group-2"),
            call(ModelPackageGroupName="group-3"),
        ]

    def test_new_sagemaker_operation_contracts_exist(self):
        client = sagemaker_app.boto3.client(
            "sagemaker",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        )
        model = client.meta.service_model
        for operation in [
            "ListClusters",
            "DescribeCluster",
            "GetModelPackageGroupPolicy",
        ]:
            assert model.operation_model(operation)


# ===================================================================
# SM-05: check_sagemaker_mlops_utilization
# ===================================================================
class TestSM05MLOps:
    """SM-05: Check SageMaker MLOps features utilization."""

    @patch("sagemaker_app.boto3.client")
    def test_sm05_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_packages.return_value = {"ModelPackageSummaryList": []}
        mock_sm.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        mock_sm.list_pipelines.return_value = {"PipelineSummaries": []}
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-05"

    @patch("sagemaker_app.boto3.client")
    def test_sm05_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_client.side_effect = Exception("MLOps error")
        result = check(empty_permission_cache)
        # SM-05 returns empty csv_data on outer exception but sets status=ERROR
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm05_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_packages.return_value = {"ModelPackageSummaryList": []}
        mock_sm.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        mock_sm.list_pipelines.return_value = {"PipelineSummaries": []}
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_sm05_paginates_model_packages(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {"ModelPackageSummaryList": [{"ModelPackageArn": "arn:package-1"}]},
            {"ModelPackageSummaryList": [{"ModelPackageArn": "arn:package-2"}]},
        ]
        feature_group_paginator = MagicMock()
        feature_group_paginator.paginate.return_value = [{"FeatureGroupSummaries": []}]
        pipeline_paginator = MagicMock()
        pipeline_paginator.paginate.return_value = [{"PipelineSummaries": []}]
        paginators = {
            "list_model_package_groups": group_paginator,
            "list_model_packages": package_paginator,
            "list_feature_groups": feature_group_paginator,
            "list_pipelines": pipeline_paginator,
        }
        mock_sm.get_paginator.side_effect = paginators.__getitem__

        result = check(empty_permission_cache)
        findings = extract_csv_data(result)

        assert not any("minimal versioning" in f["Finding_Details"] for f in findings)
        package_paginator.paginate.assert_called_once_with(
            ModelPackageGroupName="group-a"
        )


# ===================================================================
# SM-06: check_sagemaker_clarify_usage
# ===================================================================
class TestSM06Clarify:
    """SM-06: Check SageMaker Clarify usage."""

    @patch("sagemaker_app.boto3.client")
    def test_sm06_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_clarify_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-06"

    @patch("sagemaker_app.boto3.client")
    def test_sm06_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_clarify_usage
        mock_client.side_effect = Exception("Clarify error")
        result = check(empty_permission_cache)
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm06_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_clarify_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-07: check_sagemaker_model_monitor_usage
# ===================================================================
class TestSM07ModelMonitor:
    """SM-07: Check SageMaker Model Monitor usage."""

    @patch("sagemaker_app.boto3.client")
    def test_sm07_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_model_monitor_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-07"

    @patch("sagemaker_app.boto3.client")
    def test_sm07_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_model_monitor_usage
        mock_client.side_effect = Exception("Monitor error")
        result = check(empty_permission_cache)
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm07_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_model_monitor_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-08: check_model_registry_usage
# ===================================================================
class TestSM08ModelRegistry:
    """SM-08: Check Model Registry usage."""

    @patch("sagemaker_app.boto3.client")
    def test_sm08_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_model_registry_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-08"

    @patch("sagemaker_app.boto3.client")
    def test_sm08_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_model_registry_usage
        mock_client.side_effect = Exception("Registry error")
        result = check(empty_permission_cache)
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm08_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_model_registry_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_sm08_paginates_model_packages(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_model_registry_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {
                "ModelPackageSummaryList": [
                    {"ModelApprovalStatus": "PendingManualApproval"}
                ]
            },
            {"ModelPackageSummaryList": [{"ModelApprovalStatus": "Approved"}]},
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        result = check(empty_permission_cache)
        findings = extract_csv_data(result)

        assert not any("No Approved Models" in f["Finding"] for f in findings)
        package_paginator.paginate.assert_called_once_with(
            ModelPackageGroupName="group-a"
        )


# ===================================================================
# SM-09: check_sagemaker_notebook_root_access
# ===================================================================
class TestSM09NotebookRootAccess:
    """SM-09: Check notebook root access."""

    @patch("sagemaker_app.boto3.client")
    def test_sm09_no_notebooks_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-09"

    @patch("sagemaker_app.boto3.client")
    def test_sm09_root_enabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "RootAccess": "Enabled",
            "NotebookInstanceName": "nb-1",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm09_root_disabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "RootAccess": "Disabled",
            "NotebookInstanceName": "nb-1",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm09_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_client.side_effect = Exception("Root access error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm09_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-10: check_sagemaker_notebook_vpc_deployment
# ===================================================================
class TestSM10NotebookVPC:
    """SM-10: Check notebook VPC deployment."""

    @patch("sagemaker_app.boto3.client")
    def test_sm10_no_notebooks_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-10"

    @patch("sagemaker_app.boto3.client")
    def test_sm10_no_vpc_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "NotebookInstanceName": "nb-1",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm10_with_vpc_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "NotebookInstanceName": "nb-1",
            "SubnetId": "subnet-123",
            "DirectInternetAccess": "Disabled",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize("direct_access", ["Enabled", None])
    @patch("sagemaker_app.boto3.client")
    def test_sm10_vpc_notebook_with_direct_internet_access_fails(
        self, mock_client, direct_access
    ):
        # AIR-FND-NET-01: a VPC notebook with DirectInternetAccess Enabled has a
        # SageMaker-managed internet path. One bad notebook of two withholds the
        # Passed row, and an absent field is not read as Disabled.
        notebooks = {
            "nb-open": {"NotebookInstanceName": "nb-open", "SubnetId": "subnet-1"},
            "nb-closed": {
                "NotebookInstanceName": "nb-closed",
                "SubnetId": "subnet-2",
                "DirectInternetAccess": "Disabled",
            },
        }
        if direct_access:
            notebooks["nb-open"]["DirectInternetAccess"] = direct_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": n} for n in notebooks]}
        ]
        mock_sm.describe_notebook_instance.side_effect = lambda NotebookInstanceName: (
            notebooks[NotebookInstanceName]
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_notebook_vpc_deployment(region="us-east-1")
        )
        direct = [
            f
            for f in findings
            if f["Finding"] == "SageMaker Notebook Direct Internet Access in VPC"
        ]
        assert [f["Status"] for f in direct] == ["Failed"]
        assert "'nb-open'" in direct[0]["Finding_Details"]
        assert "nb-closed" not in direct[0]["Finding_Details"]
        assert not [
            f
            for f in findings
            if f["Finding"] == "SageMaker Notebook VPC Deployment Check"
            and f["Status"] == "Passed"
        ]

    @patch("sagemaker_app.boto3.client")
    def test_sm10_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_client.side_effect = Exception("VPC error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm10_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-11: check_sagemaker_model_network_isolation
# ===================================================================
class TestSM11ModelNetworkIsolation:
    """SM-11: Check model network isolation."""

    @patch("sagemaker_app.boto3.client")
    def test_sm11_no_models_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-11"

    @patch("sagemaker_app.boto3.client")
    def test_sm11_isolation_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": [{"ModelName": "model-1"}]}]
        mock_sm.describe_model.return_value = {
            "ModelName": "model-1",
            "EnableNetworkIsolation": False,
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm11_isolation_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": [{"ModelName": "model-1"}]}]
        mock_sm.describe_model.return_value = {
            "ModelName": "model-1",
            "EnableNetworkIsolation": True,
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm11_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_client.side_effect = Exception("Network isolation error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-12: check_sagemaker_endpoint_instance_count
# ===================================================================
class TestSM12EndpointInstanceCount:
    """SM-12: Check endpoint instance count for availability."""

    @patch("sagemaker_app.boto3.client")
    def test_sm12_no_endpoints_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Endpoints": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-12"

    @patch("sagemaker_app.boto3.client")
    def test_sm12_single_instance_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Endpoints": [{"EndpointName": "ep-1", "EndpointStatus": "InService"}]}
        ]
        mock_sm.describe_endpoint.return_value = {
            "ProductionVariants": [{"CurrentInstanceCount": 1, "VariantName": "v1"}]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm12_multi_instance_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Endpoints": [{"EndpointName": "ep-1", "EndpointStatus": "InService"}]}
        ]
        mock_sm.describe_endpoint.return_value = {
            "ProductionVariants": [{"CurrentInstanceCount": 3, "VariantName": "v1"}]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm12_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_client.side_effect = Exception("Endpoint error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-13: check_sagemaker_monitoring_network_isolation
# ===================================================================
class TestSM13MonitoringNetworkIsolation:
    """SM-13: Check monitoring schedule network isolation."""

    @patch("sagemaker_app.boto3.client")
    def test_sm13_no_schedules_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_monitoring_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"MonitoringScheduleSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-13"

    @patch("sagemaker_app.boto3.client")
    def test_sm13_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_monitoring_network_isolation
        mock_client.side_effect = Exception("Monitoring error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-14: check_sagemaker_model_container_repository
# ===================================================================
class TestSM14ContainerRepository:
    """SM-14: Check model container repository access."""

    @patch("sagemaker_app.boto3.client")
    def test_sm14_no_models_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_container_repository
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-14"

    @patch("sagemaker_app.boto3.client")
    def test_sm14_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_container_repository
        mock_client.side_effect = Exception("Container error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


def _sm14_rows(models, pages=None, endpoints=None):
    """Run SM-14 over {model name: DescribeModel response or exception}.

    endpoints is {endpoint name: [model names]}; by default one endpoint
    serves every model.
    """
    if endpoints is None:
        endpoints = {"ep": list(models)}

    def describe_model(ModelName):
        value = models[ModelName]
        if isinstance(value, Exception):
            raise value
        return value

    def describe_endpoint(EndpointName):
        if isinstance(endpoints[EndpointName], Exception):
            raise endpoints[EndpointName]
        return {
            "EndpointName": EndpointName,
            "EndpointConfigName": f"cfg-{EndpointName}",
        }

    listing = {
        "list_models": [{"Models": [{"ModelName": n} for n in models]}],
        "list_endpoints": [
            {
                "Endpoints": [
                    {"EndpointName": n, "EndpointStatus": "InService"}
                    for n in endpoints
                ]
            }
        ],
    }
    listing.update(pages or {})
    sm = _pages_client(
        listing,
        describe_model=MagicMock(side_effect=describe_model),
        describe_endpoint=MagicMock(side_effect=describe_endpoint),
        describe_endpoint_config=MagicMock(
            side_effect=lambda EndpointConfigName: {
                "ProductionVariants": [
                    {"VariantName": f"v{i}", "ModelName": m}
                    for i, m in enumerate(endpoints[EndpointConfigName[4:]])
                ]
            }
        ),
    )
    with patch("sagemaker_app.boto3.client", return_value=sm):
        return extract_csv_data(
            sagemaker_app.check_sagemaker_model_container_repository("us-east-1")
        )


def _sm14_model(mode):
    return {
        "PrimaryContainer": {
            "Image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/m:1",
            "ImageConfig": {"RepositoryAccessMode": mode},
        }
    }


class TestSM14UnreadModels:
    """EP-03: a model whose description failed is not counted as passing."""

    def test_every_model_in_vpc_mode_passes(self):
        rows = _sm14_rows({"a": _sm14_model("Vpc"), "b": _sm14_model("Vpc")})
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "All 2 models" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize("broken_first", [True, False])
    def test_a_failed_describe_withholds_passed_and_is_named(self, broken_first):
        models = [
            ("good", _sm14_model("Vpc")),
            ("broken", _make_client_error("AccessDeniedException")),
        ]
        if broken_first:
            models.reverse()
        rows = _sm14_rows(dict(models))
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "sagemaker:DescribeModel broken" in rows[0]["Finding_Details"]
        assert "AccessDenied" in rows[0]["Finding_Details"]

    def test_a_failed_describe_beside_a_platform_model_keeps_both_rows(self):
        rows = _sm14_rows(
            {
                "open": _sm14_model("Platform"),
                "broken": _make_client_error("ThrottlingException"),
            }
        )
        assert sorted(r["Status"] for r in rows) == ["Failed", "N/A"]
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert "'open'" in failed[0]["Finding_Details"]
        unread = [r for r in rows if r["Status"] == "N/A"]
        assert "sagemaker:DescribeModel broken" in unread[0]["Finding_Details"]

    def test_a_failed_list_is_not_reported_as_no_models(self):
        # The population is now the models endpoints serve, so the list that
        # can fail is ListEndpoints.
        rows = _sm14_rows(
            {}, pages={"list_endpoints": _make_client_error("AccessDeniedException")}
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "sagemaker:ListEndpoints" in rows[0]["Finding_Details"]
        assert "No models found" not in rows[0]["Finding_Details"]
        assert "serves a model" not in rows[0]["Finding_Details"]

    def test_only_models_an_endpoint_serves_are_judged(self):
        rows = _sm14_rows(
            {
                "served": _sm14_model("Vpc"),
                "idle": _sm14_model("Platform"),
            },
            endpoints={"ep": ["served"]},
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "All 1 models served" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize("platform_first", [True, False])
    def test_a_platform_container_of_a_multi_container_model_fails(
        self, platform_first
    ):
        containers = [
            {"Image": "img-vpc", "ImageConfig": {"RepositoryAccessMode": "Vpc"}},
            {"Image": "img-ecr"},
        ]
        if platform_first:
            containers.reverse()
        rows = _sm14_rows(
            {"good": _sm14_model("Vpc"), "multi": {"Containers": containers}}
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "Model 'multi', served by endpoint(s) ep" in details
        assert "img-ecr" in details
        assert "hosted in Amazon ECR" in details
        assert "public/external" not in details

    def test_a_multi_container_model_all_in_vpc_mode_passes(self):
        vpc = {"Image": "i", "ImageConfig": {"RepositoryAccessMode": "Vpc"}}
        rows = _sm14_rows({"multi": {"Containers": [vpc, dict(vpc)]}})
        assert [r["Status"] for r in rows] == ["Passed"]

    @pytest.mark.parametrize("broken_first", [True, False])
    def test_an_unread_endpoint_withholds_passed(self, broken_first):
        endpoints = [
            ("ep", ["good"]),
            ("broken", _make_client_error("ThrottlingException")),
        ]
        if broken_first:
            endpoints.reverse()
        rows = _sm14_rows({"good": _sm14_model("Vpc")}, endpoints=dict(endpoints))
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "endpoint 'broken'" in rows[0]["Finding_Details"]


# ===================================================================
# SM-15: check_sagemaker_feature_store_encryption
# ===================================================================
class TestSM15FeatureStoreEncryption:
    """SM-15: Check Feature Store encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm15_no_feature_groups_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"FeatureGroupSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-15"

    @patch("sagemaker_app.boto3.client")
    def test_sm15_no_encryption_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "FeatureGroupName": "fg-1",
            "OfflineStoreConfig": {"S3StorageConfig": {"S3Uri": "s3://bucket"}},
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm15_with_kms_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "FeatureGroupName": "fg-1",
            "OfflineStoreConfig": {
                "S3StorageConfig": {
                    "S3Uri": "s3://bucket",
                    "KmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                }
            },
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm15_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_client.side_effect = Exception("Feature store error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-16: check_sagemaker_data_quality_encryption
# ===================================================================
class TestSM16DataQualityEncryption:
    """SM-16: Check data quality job encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm16_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"JobDefinitionSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-16"

    @patch("sagemaker_app.boto3.client")
    def test_sm16_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_encryption
        mock_client.side_effect = Exception("Data quality error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm16_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"JobDefinitionSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-17: check_sagemaker_processing_job_encryption
# ===================================================================
class TestSM17ProcessingJobEncryption:
    """SM-17: Check processing job volume encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm17_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ProcessingJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-17"

    @patch("sagemaker_app.boto3.client")
    def test_sm17_no_encryption_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"ProcessingJobSummaries": [{"ProcessingJobName": "pj-1"}]}
        ]
        mock_sm.describe_processing_job.return_value = {
            "ProcessingJobName": "pj-1",
            "ProcessingResources": {
                "ClusterConfig": {"InstanceCount": 1, "InstanceType": "ml.m5.large"}
            },
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm17_with_encryption_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"ProcessingJobSummaries": [{"ProcessingJobName": "pj-1"}]}
        ]
        mock_sm.describe_processing_job.return_value = {
            "ProcessingJobName": "pj-1",
            "ProcessingResources": {
                "ClusterConfig": {
                    "InstanceCount": 1,
                    "InstanceType": "ml.m5.large",
                    "VolumeKmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                }
            },
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm17_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_client.side_effect = Exception("Processing error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-18: check_sagemaker_transform_job_encryption
# ===================================================================
class TestSM18TransformJobEncryption:
    """SM-18: Check transform job volume encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm18_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_transform_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"TransformJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-18"

    @patch("sagemaker_app.boto3.client")
    def test_sm18_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_transform_job_encryption
        mock_client.side_effect = Exception("Transform error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm18_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_transform_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"TransformJobSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-19: check_sagemaker_hyperparameter_tuning_encryption
# ===================================================================
class TestSM19HPTuningEncryption:
    """SM-19: Check hyperparameter tuning job encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm19_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_hyperparameter_tuning_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"HyperParameterTuningJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-19"

    @patch("sagemaker_app.boto3.client")
    def test_sm19_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_hyperparameter_tuning_encryption
        mock_client.side_effect = Exception("HP tuning error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm19_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_hyperparameter_tuning_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"HyperParameterTuningJobSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-20: check_sagemaker_compilation_job_encryption
# ===================================================================
class TestSM20CompilationJobEncryption:
    """SM-20: Check compilation job encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm20_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_compilation_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"CompilationJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-20"

    @patch("sagemaker_app.boto3.client")
    def test_sm20_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_compilation_job_encryption
        mock_client.side_effect = Exception("Compilation error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm20_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_compilation_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"CompilationJobSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-21: check_sagemaker_automl_network_isolation
# ===================================================================
class TestSM21AutoMLNetworkIsolation:
    """SM-21: Check AutoML network isolation."""

    @patch("sagemaker_app.boto3.client")
    def test_sm21_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_automl_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_auto_ml_jobs.return_value = {"AutoMLJobSummaries": []}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-21"

    @patch("sagemaker_app.boto3.client")
    def test_sm21_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_automl_network_isolation
        mock_client.side_effect = Exception("AutoML error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm21_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_automl_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_auto_ml_jobs.return_value = {"AutoMLJobSummaries": []}
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-22: check_model_approval_workflow
# ===================================================================
class TestSM22ModelApproval:
    """SM-22: Check model approval workflow."""

    @patch("sagemaker_app.boto3.client")
    def test_sm22_no_model_packages_returns_na(self, mock_client):
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-22"

    @patch("sagemaker_app.boto3.client")
    def test_sm22_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_model_approval_workflow
        mock_client.side_effect = Exception("Approval error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm22_schema_valid(self, mock_client):
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @staticmethod
    def _wire_sm22_paginators(mock_sm, group_page, package_pages):
        """Wire both paginators used by check_model_approval_workflow.

        group_page:  single page dict for list_model_package_groups
        package_pages: list of page dicts for list_model_packages
        """
        group_paginator = MagicMock()
        package_paginator = MagicMock()
        group_paginator.paginate.return_value = [group_page]
        package_paginator.paginate.return_value = package_pages
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

    @patch("sagemaker_app.boto3.client")
    def test_sm22_paginates_model_packages_across_pages(self, mock_client):
        """Regression: a group with >100 model packages must be scored on the
        FULL population, not the first page. The bug was a single MaxResults=100
        list_model_packages call that silently truncated the sample, skewing
        the auto-approval / stale-pending ratios computed downstream."""
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm

        # 100 Approved packages on page 1 (newest first, as SageMaker returns).
        # 20 Pending + 5 Rejected on page 2. Under the old truncating code the
        # check saw only page 1 and (wrongly) fired "Auto-Approval Suspected"
        # for a group that actually has pending and rejected packages.
        page_1_approved = [{"ModelApprovalStatus": "Approved"} for _ in range(100)]
        page_2_mixed = [
            {"ModelApprovalStatus": "PendingManualApproval"} for _ in range(20)
        ] + [{"ModelApprovalStatus": "Rejected"} for _ in range(5)]
        self._wire_sm22_paginators(
            mock_sm,
            group_page={
                "ModelPackageGroupSummaryList": [
                    {"ModelPackageGroupName": "grp-active"}
                ]
            },
            package_pages=[
                {"ModelPackageSummaryList": page_1_approved},
                {"ModelPackageSummaryList": page_2_mixed},
            ],
        )

        result = check()
        findings = extract_csv_data(result)

        # With the fix, both pages are considered — the group has pending +
        # rejected packages, so "Auto-Approval Suspected" must NOT fire.
        names_all = " | ".join(f["Finding"] for f in findings)
        assert "Auto-Approval Suspected" not in names_all, (
            "SM-22 misfired 'Auto-Approval Suspected' when list_model_packages "
            "was truncated to the first page (approved-only) and hid the older "
            "Pending/Rejected packages."
        )
        # And "Stale Pending Models" should fire because pending_count=20 > 5.
        assert any("Stale Pending Models" in f["Finding"] for f in findings), (
            "SM-22 missed 'Stale Pending Models' — the 20 pending packages on "
            "page 2 were invisible before pagination was fixed."
        )
        # Cross-check the accumulated count reached page 2's contribution.
        stale_row = next(f for f in findings if "Stale Pending Models" in f["Finding"])
        assert "20 models pending" in stale_row["Finding_Details"], (
            f"Expected pending count of 20 in details; got: {stale_row['Finding_Details']!r}"
        )

    @patch("sagemaker_app.boto3.client")
    def test_sm22_auto_approval_detected_only_when_full_population_is_approved(
        self, mock_client
    ):
        """Full-population Approved case: page 1 = 100 Approved, page 2 = 10
        Approved, no Pending/Rejected. Must still fire 'Auto-Approval Suspected'
        because the fix does not change the true-positive path."""
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm

        self._wire_sm22_paginators(
            mock_sm,
            group_page={
                "ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "grp-auto"}]
            },
            package_pages=[
                {
                    "ModelPackageSummaryList": [
                        {"ModelApprovalStatus": "Approved"} for _ in range(100)
                    ]
                },
                {
                    "ModelPackageSummaryList": [
                        {"ModelApprovalStatus": "Approved"} for _ in range(10)
                    ]
                },
            ],
        )

        result = check()
        findings = extract_csv_data(result)
        assert any("Auto-Approval Suspected" in f["Finding"] for f in findings), (
            "SM-22 must still detect the true-positive auto-approval case"
        )
        # Details should reference the actual full-population total (110), not 100.
        auto_row = next(
            f for f in findings if "Auto-Approval Suspected" in f["Finding"]
        )
        assert "110 models" in auto_row["Finding_Details"], (
            f"Expected full-population count '110 models' in details; "
            f"got: {auto_row['Finding_Details']!r}"
        )


# ===================================================================
# SM-23: check_model_drift_detection
# ===================================================================
class TestSM23DriftDetection:
    """SM-23: Check model drift detection."""

    @patch("sagemaker_app.boto3.client")
    def test_sm23_no_schedules_returns_na(self, mock_client):
        check = sagemaker_app.check_model_drift_detection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-23"

    @patch("sagemaker_app.boto3.client")
    def test_sm23_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_model_drift_detection
        mock_client.side_effect = Exception("Drift error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm23_schema_valid(self, mock_client):
        check = sagemaker_app.check_model_drift_detection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


class TestSM23NoEndpointToJudge:
    """EP-06: a Region with no InService endpoint has nothing drift can pass on."""

    @staticmethod
    def _rows(endpoints):
        sm = _pages_client(
            {
                "list_endpoints": [{"Endpoints": endpoints}],
                "list_monitoring_schedules": [{"MonitoringScheduleSummaries": []}],
            }
        )
        with patch("sagemaker_app.boto3.client", return_value=sm):
            return extract_csv_data(
                sagemaker_app.check_model_drift_detection(region="us-east-1")
            )

    @pytest.mark.parametrize(
        "endpoints",
        [
            [],
            [
                {"EndpointName": "a", "EndpointStatus": "Creating"},
                {"EndpointName": "b", "EndpointStatus": "Failed"},
            ],
        ],
    )
    def test_no_in_service_endpoint_is_na(self, endpoints):
        rows = self._rows(endpoints)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "No InService endpoints" in rows[0]["Finding_Details"]

    def test_an_in_service_endpoint_without_a_schedule_fails(self):
        rows = self._rows(
            [
                {"EndpointName": "a", "EndpointStatus": "Creating"},
                {"EndpointName": "live", "EndpointStatus": "InService"},
            ]
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'live'" in rows[0]["Finding_Details"]


# ===================================================================
# SM-24: check_ab_testing_shadow_deployment
# ===================================================================
class TestSM24ABTesting:
    """SM-24: Check A/B testing and shadow deployment."""

    @patch("sagemaker_app.boto3.client")
    def test_sm24_no_endpoints_returns_na(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Endpoints": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-24"

    @patch("sagemaker_app.boto3.client")
    def test_sm24_single_variant_returns_failed(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Endpoints": [{"EndpointName": "ep-1", "EndpointConfigName": "ec-1"}]}
        ]
        mock_sm.describe_endpoint.return_value = {
            "EndpointName": "ep-1",
            "ProductionVariants": [{"VariantName": "v1"}],
        }
        mock_sm.describe_endpoint_config.return_value = {
            "ProductionVariants": [{"VariantName": "v1"}],
            "ShadowProductionVariants": [],
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Single variant without shadow should be flagged

    @patch("sagemaker_app.boto3.client")
    def test_sm24_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_client.side_effect = Exception("AB testing error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm24_schema_valid(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Endpoints": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-25: check_ml_lineage_tracking
# ===================================================================
class TestSM25LineageTracking:
    """SM-25: Check ML lineage tracking."""

    @patch("sagemaker_app.boto3.client")
    def test_sm25_no_experiments_returns_na(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ModelPackageGroupSummaryList": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-25"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm25_experiments_with_trials_returns_passed(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {
            "ExperimentSummaries": [{"ExperimentName": "exp-1"}]
        }
        mock_sm.list_trials.return_value = {
            "TrialSummaries": [{"TrialName": "trial-1"}]
        }
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ModelPackageGroupSummaryList": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm25_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_client.side_effect = Exception("Lineage error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm25_schema_valid(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ModelPackageGroupSummaryList": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_sm25_paginates_model_groups_and_packages(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        mock_sm.list_artifacts.side_effect = [
            {
                "ArtifactSummaries": [
                    {
                        "ArtifactArn": "arn:aws:sagemaker:us-east-1:123456789012:artifact/package-a"
                    }
                ]
            },
            {
                "ArtifactSummaries": [
                    {
                        "ArtifactArn": "arn:aws:sagemaker:us-east-1:123456789012:artifact/package-b"
                    }
                ]
            },
        ]
        mock_sm.list_associations.return_value = {"AssociationSummaries": []}

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]},
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-b"}]},
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.side_effect = [
            [
                {
                    "ModelPackageSummaryList": [
                        {
                            "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/1",
                            "ModelPackageName": "package-a",
                        }
                    ]
                }
            ],
            [
                {
                    "ModelPackageSummaryList": [
                        {
                            "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123456789012:model-package/group-b/1",
                            "ModelPackageName": "package-b",
                        }
                    ]
                }
            ],
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        result = check()
        findings = extract_csv_data(result)

        lineage_findings = [f for f in findings if "Missing Lineage" in f["Finding"]]
        assert len(lineage_findings) == 2
        assert package_paginator.paginate.call_count == 2
        assert mock_sm.list_artifacts.call_args_list == [
            call(
                SourceUri="arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/1",
                MaxResults=1,
            ),
            call(
                SourceUri="arn:aws:sagemaker:us-east-1:123456789012:model-package/group-b/1",
                MaxResults=1,
            ),
        ]
        assert mock_sm.list_associations.call_args_list == [
            call(
                SourceArn="arn:aws:sagemaker:us-east-1:123456789012:artifact/package-a",
                MaxResults=1,
            ),
            call(
                DestinationArn="arn:aws:sagemaker:us-east-1:123456789012:artifact/package-a",
                MaxResults=1,
            ),
            call(
                SourceArn="arn:aws:sagemaker:us-east-1:123456789012:artifact/package-b",
                MaxResults=1,
            ),
            call(
                DestinationArn="arn:aws:sagemaker:us-east-1:123456789012:artifact/package-b",
                MaxResults=1,
            ),
        ]

    @patch("sagemaker_app.boto3.client")
    def test_sm25_accepts_destination_lineage_association(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        mock_sm.list_artifacts.return_value = {
            "ArtifactSummaries": [
                {
                    "ArtifactArn": "arn:aws:sagemaker:us-east-1:123456789012:artifact/package-a"
                }
            ]
        }
        mock_sm.list_associations.side_effect = [
            {"AssociationSummaries": []},
            {"AssociationSummaries": [{"AssociationType": "Produced"}]},
        ]

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {
                "ModelPackageSummaryList": [
                    {
                        "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/1",
                        "ModelPackageName": "package-a",
                    }
                ]
            }
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        findings = extract_csv_data(check())

        assert not any("Missing Lineage" in f["Finding"] for f in findings)

    @patch("sagemaker_app.boto3.client")
    def test_sm25_stops_after_five_lineage_findings(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        mock_sm.list_artifacts.side_effect = lambda SourceUri, MaxResults: {
            "ArtifactSummaries": [
                {
                    "ArtifactArn": SourceUri.replace(
                        ":model-package/group-a/", ":artifact/package-"
                    )
                }
            ]
        }
        mock_sm.list_associations.return_value = {"AssociationSummaries": []}

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {
                "ModelPackageSummaryList": [
                    {
                        "ModelPackageArn": f"arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/{version}",
                        "ModelPackageName": f"package-{version}",
                    }
                    for version in range(1, 7)
                ]
            }
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        findings = extract_csv_data(check())
        lineage_findings = [f for f in findings if "Missing Lineage" in f["Finding"]]

        assert len(lineage_findings) == 5
        assert mock_sm.list_artifacts.call_count == 5

    @patch("sagemaker_app.boto3.client")
    def test_sm25_lineage_access_denied_is_na_not_missing(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        mock_sm.list_artifacts.side_effect = _make_client_error("AccessDeniedException")

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {
                "ModelPackageSummaryList": [
                    {
                        "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/1",
                        "ModelPackageName": "package-a",
                    }
                ]
            }
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        findings = extract_csv_data(check())

        assert not any("Missing Lineage" in f["Finding"] for f in findings)
        assessment_findings = [
            f for f in findings if "Model Package Assessment" in f["Finding"]
        ]
        assert len(assessment_findings) == 1
        assert_could_not_assess_finding(assessment_findings[0])


# ===================================================================
# lambda_handler: multi-region gating and availability probe
# ===================================================================
def _make_client_error(code, message="error"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "operation")


def _sagemaker_event(region="us-east-1", region_index=0):
    return {
        "Region": region,
        "RegionIndex": region_index,
        "Execution": {"Name": "test-execution-1"},
        "StateMachine": {"Name": "test-sm"},
    }


class TestSageMakerHandlerMultiRegion:
    """lambda_handler primary-region gating (SM-02) + availability probe (SM-00)."""

    def _run_handler_unavailable(self, mock_client, event, cache_missing=False):
        """Drive the handler down the 'SageMaker unavailable' early-return path.
        The availability probe raises EndpointConnectionError so no regional
        checks run; only global IAM checks (if primary) plus SM-00 are emitted."""
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.list_notebook_instances.side_effect = EndpointConnectionError(
            endpoint_url="https://sagemaker.invalid"
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                sagemaker_app,
                "get_permissions_cache",
                return_value=(
                    None
                    if cache_missing
                    else {"role_permissions": {}, "user_permissions": {}}
                ),
            ),
            patch.object(sagemaker_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(sagemaker_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = sagemaker_app.lambda_handler(event, None)

        return resp, captured.get("findings", [])

    @patch("sagemaker_app.boto3.client")
    def test_primary_region_emits_global_iam_check_tagged_global(self, mock_client):
        # On the primary region, the IAM-global SM-02 check must be emitted and
        # tagged "Global", even when SageMaker is unavailable in the region.
        resp, findings = self._run_handler_unavailable(
            mock_client, _sagemaker_event(region="ap-south-2", region_index=0)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        sm02 = [r for r in rows if r["Check_ID"] == "SM-02"]
        assert sm02, "SM-02 IAM-global finding should be present on primary region"
        for r in sm02:
            assert r["Region"] == "Global"
        # The availability finding is tagged with the scanned region.
        sm00 = [r for r in rows if r["Check_ID"] == "SM-00"]
        assert sm00 and sm00[0]["Region"] == "ap-south-2"

    @patch("sagemaker_app.boto3.client")
    def test_missing_cache_emits_incomplete_sm02_not_passed(self, mock_client):
        resp, findings = self._run_handler_unavailable(
            mock_client,
            _sagemaker_event(region="ap-south-2", region_index=0),
            cache_missing=True,
        )
        assert resp["statusCode"] == 200

        rows = [row for finding in findings for row in finding.get("csv_data", [])]
        sm02 = [row for row in rows if row["Check_ID"] == "SM-02"]
        assert len(sm02) == 1
        assert sm02[0]["Status"] == "N/A"
        assert sm02[0]["Severity"] == "Informational"
        assert "permissions cache" in sm02[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_non_primary_region_skips_global_iam_check(self, mock_client):
        # On a non-primary region the IAM-global SM-02 check must NOT run.
        resp, findings = self._run_handler_unavailable(
            mock_client, _sagemaker_event(region="eu-west-1", region_index=2)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        assert "SM-02" not in check_ids
        assert check_ids == {"SM-00"}

    @patch("sagemaker_app.boto3.client")
    def test_optin_region_error_treated_as_unavailable(self, mock_client):
        # A region-not-enabled error code is treated like an endpoint failure:
        # emit a single SM-00 N/A finding (no regional checks).
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.list_notebook_instances.side_effect = _make_client_error(
            "OptInRequired"
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                sagemaker_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(sagemaker_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(sagemaker_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = sagemaker_app.lambda_handler(
                _sagemaker_event(region="ap-east-1", region_index=1), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        sm00 = [r for r in rows if r["Check_ID"] == "SM-00"]
        assert sm00 and sm00[0]["Status"] == "N/A"
        assert "ap-east-1" in sm00[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_access_denied_probe_proceeds_with_checks(self, mock_client):
        # AccessDenied is NOT in REGION_UNAVAILABLE_ERROR_CODES: the service is
        # reachable, so the handler must proceed and run regional checks rather
        # than short-circuiting with SM-00.
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.list_notebook_instances.side_effect = _make_client_error(
            "AccessDeniedException"
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                sagemaker_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(sagemaker_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(sagemaker_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = sagemaker_app.lambda_handler(
                _sagemaker_event(region="us-east-1", region_index=0), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        # Reachable => no SM-00, and many regional checks ran.
        assert "SM-00" not in check_ids
        assert len(check_ids) > 3


# ===================================================================
# Phase 3 AISF parity: SageMaker rows
# ===================================================================
def _sm_client_factory(**clients):
    """Dispatch boto3.client by service name for a multi-service check."""

    def factory(service_name, *args, **kwargs):
        if service_name not in clients:
            raise AssertionError(f"unexpected boto3 client: {service_name}")
        return clients[service_name]

    return factory


def _identity_policy(actions, resources, condition=None):
    statement = {"Effect": "Allow", "Action": actions, "Resource": resources}
    if condition:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


def _role_cache(roles):
    """Build a permission cache from {role_name: [(policy_name, document)]}."""
    return {
        "role_permissions": {
            name: {
                "attached_policies": [
                    {
                        "name": policy_name,
                        "arn": f"arn:aws:iam::123456789012:policy/{policy_name}",
                        "document": document,
                    }
                    for policy_name, document in policies
                ],
                "inline_policies": [],
            }
            for name, policies in roles.items()
        },
        "user_permissions": {},
    }


class TestSM11ModelVpcAttachment:
    """AIR-SGM-EP-01: SM-11 reports the VpcConfig leg per model."""

    @staticmethod
    def _models(mock_client, details):
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Models": [{"ModelName": name} for name in details]}
        ]
        mock_sm.describe_model.side_effect = lambda ModelName: details[ModelName]
        return mock_sm

    @patch("sagemaker_app.boto3.client")
    def test_model_without_vpc_config_is_failed_and_one_with_is_passed(
        self, mock_client
    ):
        self._models(
            mock_client,
            {
                "private-model": {
                    "EnableNetworkIsolation": True,
                    "VpcConfig": {
                        "Subnets": ["subnet-aaa", "subnet-bbb"],
                        "SecurityGroupIds": ["sg-1"],
                    },
                },
                "open-model": {"EnableNetworkIsolation": True},
            },
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_model_network_isolation(region="us-east-1")
        )
        vpc_rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.MODEL_VPC_ATTACHMENT_FINDING
        ]
        failed = [f for f in vpc_rows if f["Status"] == "Failed"]
        passed = [f for f in vpc_rows if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "open-model" in failed[0]["Finding_Details"]
        assert "no VpcConfig" in failed[0]["Finding_Details"]
        assert len(passed) == 1
        assert "private-model" in passed[0]["Finding_Details"]
        assert "subnet-aaa" in passed[0]["Finding_Details"]
        assert "interface VPC" in passed[0]["Finding_Details"]
        for f in vpc_rows:
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_vpc_leg_is_independent_of_network_isolation(self, mock_client):
        # A model can be isolated and still have no VpcConfig: the isolation leg
        # passing must not suppress the VPC leg failing.
        self._models(
            mock_client,
            {
                "isolated-no-vpc": {"EnableNetworkIsolation": True},
                "isolated-no-vpc-2": {"EnableNetworkIsolation": True},
            },
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_model_network_isolation(region="us-east-1")
        )
        isolation_passed = [
            f
            for f in findings
            if f["Status"] == "Passed"
            and f["Finding"] != sagemaker_app.MODEL_VPC_ATTACHMENT_FINDING
        ]
        vpc_failed = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.MODEL_VPC_ATTACHMENT_FINDING
            and f["Status"] == "Failed"
        ]
        assert isolation_passed
        assert len(vpc_failed) == 2

    @patch("sagemaker_app.boto3.client")
    def test_more_than_twenty_models_without_vpc_are_summarised(self, mock_client):
        details = {
            f"model-{index}": {"EnableNetworkIsolation": True} for index in range(25)
        }
        self._models(mock_client, details)
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_model_network_isolation(region="us-east-1")
        )
        vpc_failed = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.MODEL_VPC_ATTACHMENT_FINDING
            and f["Status"] == "Failed"
        ]
        assert len(vpc_failed) == 21
        assert "25 models have no VpcConfig" in vpc_failed[-1]["Finding_Details"]


class TestSM02EndpointInvocationScoping:
    """AIR-SGM-EP-02: SM-02 reports wildcard sagemaker:InvokeEndpoint grants."""

    @staticmethod
    def _scoping_rows(cache):
        with patch("sagemaker_app.boto3.client") as mock_client:
            mock_client.return_value = MagicMock()
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_iam_permissions(cache, region="Global")
            )
        return [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        ]

    def test_wildcard_grant_is_failed_and_named_endpoint_is_passed(self):
        cache = _role_cache(
            {
                "WildcardInvokeRole": [
                    (
                        "InvokeAnything",
                        _identity_policy("sagemaker:InvokeEndpoint", "*"),
                    )
                ],
                "ScopedInvokeRole": [
                    (
                        "InvokeOne",
                        _identity_policy(
                            "sagemaker:InvokeEndpoint",
                            "arn:aws:sagemaker:us-east-1:123456789012:endpoint/fraud",
                        ),
                    )
                ],
            }
        )
        rows = self._scoping_rows(cache)
        failed = [f for f in rows if f["Status"] == "Failed"]
        passed = [f for f in rows if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "WildcardInvokeRole" in failed[0]["Finding_Details"]
        assert "InvokeAnything" in failed[0]["Finding_Details"]
        assert "no endpoint ARN" in failed[0]["Finding_Details"]
        assert len(passed) == 1
        assert "ScopedInvokeRole" in passed[0]["Finding_Details"]
        assert "workload decision" in passed[0]["Finding_Details"]
        for f in rows:
            assert_finding_schema(f)

    def test_endpoint_arn_with_trailing_wildcard_is_failed(self):
        cache = _role_cache(
            {
                "PrefixRole": [
                    (
                        "InvokePrefix",
                        _identity_policy(
                            "sagemaker:InvokeEndpoint",
                            "arn:aws:sagemaker:us-east-1:123456789012:endpoint/*",
                        ),
                    )
                ]
            }
        )
        rows = self._scoping_rows(cache)
        assert [f["Status"] for f in rows] == ["Failed"]
        assert "endpoint/*" in rows[0]["Finding_Details"]

    def test_resource_tag_condition_counts_as_scoping(self):
        cache = _role_cache(
            {
                "TaggedRole": [
                    (
                        "InvokeTagged",
                        _identity_policy(
                            "sagemaker:InvokeEndpoint",
                            "*",
                            {"StringEquals": {"aws:ResourceTag/project": "alpha"}},
                        ),
                    )
                ]
            }
        )
        rows = self._scoping_rows(cache)
        assert [f["Status"] for f in rows] == ["Passed"]

    def test_identity_without_invoke_permission_produces_no_row(self):
        cache = _role_cache(
            {
                "ReadOnlyRole": [
                    (
                        "DescribeOnly",
                        _identity_policy("sagemaker:DescribeEndpoint", "*"),
                    )
                ]
            }
        )
        assert self._scoping_rows(cache) == []

    def test_service_wildcard_action_reaches_the_invoke_grant(self):
        cache = _role_cache(
            {"AdminRole": [("Everything", _identity_policy("sagemaker:*", "*"))]}
        )
        rows = self._scoping_rows(cache)
        assert [f["Status"] for f in rows] == ["Failed"]


class TestSM03TrainingVolumeEncryption:
    """AIR-SGM-TRN-02: SM-03 reports ResourceConfig.VolumeKmsKeyId per job."""

    @staticmethod
    def _jobs(mock_client, jobs):
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        empty = MagicMock()
        empty.paginate.return_value = [{}]
        training = MagicMock()
        training.paginate.return_value = [
            {"TrainingJobSummaries": [{"TrainingJobName": name} for name in jobs]}
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            training if name == "list_training_jobs" else empty
        )
        mock_sm.describe_training_job.side_effect = lambda TrainingJobName: jobs[
            TrainingJobName
        ]
        # One mock stands in for every service, so kms:DescribeKey answers
        # for the customer managed keys these fixtures name.
        mock_sm.describe_key.return_value = {"KeyMetadata": {"KeyManager": "CUSTOMER"}}
        return mock_sm

    @patch("sagemaker_app.boto3.client")
    def test_job_without_volume_key_is_failed_and_one_with_is_passed(self, mock_client):
        self._jobs(
            mock_client,
            {
                "encrypted-job": {
                    "OutputDataConfig": {"KmsKeyId": "arn:aws:kms:::key/out"},
                    "EnableInterContainerTrafficEncryption": True,
                    "ResourceConfig": {
                        "VolumeKmsKeyId": "arn:aws:kms:::key/vol",
                        "InstanceType": "ml.m5.large",
                    },
                },
                "plain-job": {
                    "OutputDataConfig": {"KmsKeyId": "arn:aws:kms:::key/out"},
                    "EnableInterContainerTrafficEncryption": True,
                    "ResourceConfig": {"InstanceType": "ml.m5.large"},
                },
            },
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_data_protection(region="us-east-1")
        )
        volume_rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.TRAINING_VOLUME_ENCRYPTION_FINDING
        ]
        failed = [f for f in volume_rows if f["Status"] == "Failed"]
        passed = [f for f in volume_rows if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "plain-job" in failed[0]["Finding_Details"]
        assert "ResourceConfig.VolumeKmsKeyId" in failed[0]["Finding_Details"]
        assert len(passed) == 1
        assert "encrypted-job" in passed[0]["Finding_Details"]
        assert "arn:aws:kms:::key/vol" in passed[0]["Finding_Details"]
        for f in volume_rows:
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_aggregate_passed_row_is_withheld_when_a_volume_key_is_missing(
        self, mock_client
    ):
        # The incumbent aggregate row claims every resource is encrypted, so it
        # must not be emitted alongside a volume-key failure.
        self._jobs(
            mock_client,
            {
                "plain-job": {
                    "OutputDataConfig": {"KmsKeyId": "arn:aws:kms:::key/out"},
                    "EnableInterContainerTrafficEncryption": True,
                    "ResourceConfig": {"InstanceType": "ml.m5.large"},
                }
            },
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_data_protection(region="us-east-1")
        )
        assert not [
            f
            for f in findings
            if "All resources use appropriate encryption" in f["Finding_Details"]
        ]


class TestSM22ApproverAttribution:
    """AIR-SGM-GOV-01: SM-22 reports who approved each model version."""

    @staticmethod
    def _registry(mock_client, packages):
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        groups = MagicMock()
        groups.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "fraud"}]}
        ]
        versions = MagicMock()
        versions.paginate.return_value = [
            {
                "ModelPackageSummaryList": [
                    {
                        "ModelPackageArn": arn,
                        "ModelApprovalStatus": "Approved",
                    }
                    for arn in packages
                ]
            }
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            groups if name == "list_model_package_groups" else versions
        )
        mock_sm.describe_model_package.side_effect = lambda ModelPackageName: packages[
            ModelPackageName
        ]
        return mock_sm

    @patch("sagemaker_app.boto3.client")
    def test_the_workflow_pass_claims_only_the_counts_it_read(self, mock_client):
        # AIR-SGM-GOV-01: this row said approval workflows "appear to be
        # properly configured", which no field read here establishes.
        self._registry(
            mock_client,
            {
                f"arn:aws:sagemaker:::model-package/fraud/{n}": {
                    "ModelPackageName": f"fraud/{n}",
                    "LastModifiedBy": {"UserProfileName": "risk-reviewer"},
                }
                for n in (1, 2)
            },
        )
        rows = [
            f
            for f in extract_csv_data(
                sagemaker_app.check_model_approval_workflow(region="us-east-1")
            )
            if f["Finding"] == "Model Approval Workflow Check"
        ]
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert "properly configured" not in details
        assert "Checked 1 model package group(s)" in details
        assert "each of the 2 Approved version(s) records an approver" in details
        assert "not established by these counts" in details

    @patch("sagemaker_app.boto3.client")
    def test_unattributed_approval_is_failed_and_attributed_one_is_passed(
        self, mock_client
    ):
        self._registry(
            mock_client,
            {
                "arn:aws:sagemaker:::model-package/fraud/1": {
                    "ModelPackageName": "fraud/1",
                    "LastModifiedBy": {"UserProfileName": "risk-reviewer"},
                    "ApprovalDescription": "",
                },
                "arn:aws:sagemaker:::model-package/fraud/2": {
                    "ModelPackageName": "fraud/2",
                    "LastModifiedBy": {},
                    "CreatedBy": {},
                    "ApprovalDescription": "   ",
                },
            },
        )
        findings = extract_csv_data(
            sagemaker_app.check_model_approval_workflow(region="us-east-1")
        )
        rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.APPROVER_ATTRIBUTION_FINDING
        ]
        failed = [f for f in rows if f["Status"] == "Failed"]
        passed = [f for f in rows if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "fraud/2" in failed[0]["Finding_Details"]
        assert "records no approver" in failed[0]["Finding_Details"]
        assert len(passed) == 1
        assert "fraud/1" in passed[0]["Finding_Details"]
        assert "risk-reviewer" in passed[0]["Finding_Details"]
        for f in rows:
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_approval_description_alone_is_not_attribution(self, mock_client):
        self._registry(
            mock_client,
            {
                "arn:aws:sagemaker:::model-package/fraud/3": {
                    "ModelPackageName": "fraud/3",
                    "LastModifiedBy": {},
                    "ApprovalDescription": "approved at CAB-4412 by the risk board",
                }
            },
        )
        findings = extract_csv_data(
            sagemaker_app.check_model_approval_workflow(region="us-east-1")
        )
        rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.APPROVER_ATTRIBUTION_FINDING
        ]
        assert [f["Status"] for f in rows] == ["Failed"]
        assert "CAB-4412" in rows[0]["Finding_Details"]
        assert "free text, not an identity" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_iam_role_arn_counts_as_attribution(self, mock_client):
        self._registry(
            mock_client,
            {
                "arn:aws:sagemaker:::model-package/fraud/4": {
                    "ModelPackageName": "fraud/4",
                    "LastModifiedBy": {
                        "IamIdentity": {
                            "Arn": "arn:aws:sts::123456789012:assumed-role/Approver/j"
                        }
                    },
                }
            },
        )
        rows = [
            f
            for f in extract_csv_data(
                sagemaker_app.check_model_approval_workflow(region="us-east-1")
            )
            if f["Finding"] == sagemaker_app.APPROVER_ATTRIBUTION_FINDING
        ]
        assert [f["Status"] for f in rows] == ["Passed"]
        assert "assumed-role/Approver" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_every_approved_version_is_described(self, mock_client):
        packages = {
            f"arn:aws:sagemaker:::model-package/fraud/{index}": {
                "ModelPackageName": f"fraud/{index}",
                "LastModifiedBy": {},
                "ApprovalDescription": "",
            }
            for index in range(40)
        }
        mock_sm = self._registry(mock_client, packages)
        extract_csv_data(
            sagemaker_app.check_model_approval_workflow(region="us-east-1")
        )
        assert mock_sm.describe_model_package.call_count == 40
        failed = [
            f
            for f in extract_csv_data(
                sagemaker_app.check_model_approval_workflow(region="us-east-1")
            )
            if f["Finding"] == sagemaker_app.APPROVER_ATTRIBUTION_FINDING
            and f["Status"] == "Failed"
        ]
        assert "40 approved model package versions record no approver" in " ".join(
            f["Finding_Details"] for f in failed
        )


class TestSM22RegistryLegs:
    """AIR-SGM-GOV-01: SM-22 reads the approver, the lifecycle stage, the
    serving models' registry origin and RAM sharing, and never passes on an
    unread leg."""

    APPROVER = {"IamIdentity": {"Arn": "arn:aws:sts::123456789012:assumed-role/A/x"}}
    STAGED = {"Stage": "Production", "StageStatus": "Approved"}

    @staticmethod
    def _client(
        mock_client,
        packages,
        groups=("fraud",),
        endpoints=None,
        models=None,
        components=None,
        ram=None,
        errors=None,
        transform_jobs=None,
    ):
        errors = errors or {}
        endpoints = endpoints or {}
        transform_jobs = transform_jobs or {}
        models = models or {}
        components = components or {}
        ram = ram if ram is not None else {"SELF": ["arn:grp"], "OTHER-ACCOUNTS": []}
        mock_sm = MagicMock()
        mock_ram = MagicMock()
        mock_client.side_effect = lambda service, **_: (
            mock_ram if service == "ram" else mock_sm
        )

        def fail(name):
            if name in errors:
                raise _make_client_error(errors[name], name)

        def sm_paginator(name):
            pager = MagicMock()

            def paginate(**kwargs):
                fail(name)
                if name == "list_model_package_groups":
                    return [
                        {
                            "ModelPackageGroupSummaryList": [
                                {"ModelPackageGroupName": g} for g in groups
                            ]
                        }
                    ]
                if name == "list_model_packages":
                    group = kwargs["ModelPackageGroupName"]
                    return [
                        {
                            "ModelPackageSummaryList": [
                                {
                                    "ModelPackageArn": arn,
                                    "ModelApprovalStatus": detail.get(
                                        "ModelApprovalStatus", "Approved"
                                    ),
                                }
                                for arn, detail in packages.items()
                                if detail.get("ModelPackageGroupName", "fraud") == group
                            ]
                        }
                    ]
                if name == "list_endpoints":
                    return [{"Endpoints": [{"EndpointName": e} for e in endpoints]}]
                if name == "list_inference_components":
                    key = (kwargs["EndpointNameEquals"], kwargs["VariantNameEquals"])
                    return [
                        {
                            "InferenceComponents": [
                                {"InferenceComponentName": c}
                                for c in components.get(key, {})
                            ]
                        }
                    ]
                if name == "list_transform_jobs":
                    return [
                        {
                            "TransformJobSummaries": [
                                {"TransformJobName": j} for j in transform_jobs
                            ]
                        }
                    ]
                return [{}]

            pager.paginate.side_effect = paginate
            return pager

        mock_sm.get_paginator.side_effect = sm_paginator

        def describe_model_package(ModelPackageName):
            fail("describe_model_package")
            return packages[ModelPackageName]

        mock_sm.describe_model_package.side_effect = describe_model_package
        mock_sm.describe_endpoint.side_effect = lambda EndpointName: {
            "EndpointConfigName": f"{EndpointName}-config"
        }
        mock_sm.describe_endpoint_config.side_effect = lambda EndpointConfigName: {
            "ProductionVariants": endpoints[EndpointConfigName[: -len("-config")]]
        }

        def describe_model(ModelName):
            fail("describe_model")
            return models[ModelName]

        mock_sm.describe_model.side_effect = describe_model

        def describe_transform_job(TransformJobName):
            fail("describe_transform_job")
            return {"ModelName": transform_jobs[TransformJobName]}

        mock_sm.describe_transform_job.side_effect = describe_transform_job
        mock_sm.describe_inference_component.side_effect = (
            lambda InferenceComponentName: {
                "Specification": {
                    "ModelName": {
                        c: m for v in components.values() for c, m in v.items()
                    }[InferenceComponentName]
                }
            }
        )

        ram_pager = MagicMock()

        def ram_paginate(resourceOwner, resourceType):
            fail("ram_list_resources")
            assert resourceType == "sagemaker:ModelPackageGroup"
            return [{"resources": [{"arn": a} for a in ram[resourceOwner]]}]

        ram_pager.paginate.side_effect = ram_paginate
        mock_ram.get_paginator.return_value = ram_pager
        return mock_sm

    @classmethod
    def _good_package(cls, **extra):
        detail = {
            "ModelPackageName": "fraud/1",
            "ModelPackageGroupName": "fraud",
            "ModelApprovalStatus": "Approved",
            "LastModifiedBy": cls.APPROVER,
            "ModelLifeCycle": cls.STAGED,
        }
        detail.update(extra)
        return detail

    @staticmethod
    def _rows(finding=None):
        rows = extract_csv_data(
            sagemaker_app.check_model_approval_workflow(region="us-east-1")
        )
        for row in rows:
            assert_finding_schema(row)
        if finding is None:
            return rows
        return [r for r in rows if r["Finding"].startswith(finding)]

    @patch("sagemaker_app.boto3.client")
    def test_clean_registry_passes_every_leg(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints={"ep": [{"VariantName": "v", "ModelName": "m1"}]},
            models={"m1": {"PrimaryContainer": {"ModelPackageName": "p1"}}},
        )
        rows = self._rows()
        assert not [r for r in rows if r["Status"] not in ("Passed",)], [
            (r["Finding"], r["Status"], r["Finding_Details"]) for r in rows
        ]
        names = {r["Finding"] for r in rows}
        assert {
            sagemaker_app.MODEL_LIFECYCLE_FINDING,
            sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING,
            sagemaker_app.REGISTRY_SHARING_FINDING,
            sagemaker_app.APPROVER_ATTRIBUTION_FINDING,
        } <= names

    @patch("sagemaker_app.boto3.client")
    def test_created_by_only_is_failed_and_names_the_registrant(self, mock_client):
        self._client(
            mock_client,
            {
                "p1": self._good_package(),
                "p2": self._good_package(
                    ModelPackageName="fraud/2",
                    LastModifiedBy={},
                    CreatedBy={"UserProfileName": "registrant-bob"},
                ),
            },
        )
        rows = self._rows(sagemaker_app.APPROVER_ATTRIBUTION_FINDING)
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "fraud/2" in failed[0]["Finding_Details"]
        assert "registrant-bob" in failed[0]["Finding_Details"]
        assert "records no approver" in failed[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_one_unstaged_version_among_staged_fails_lifecycle(self, mock_client):
        self._client(
            mock_client,
            {
                "p1": self._good_package(),
                "p2": self._good_package(ModelPackageName="fraud/2"),
                "p3": self._good_package(
                    ModelPackageName="fraud/3", ModelLifeCycle={"Stage": "Dev"}
                ),
            },
        )
        rows = self._rows(sagemaker_app.MODEL_LIFECYCLE_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "1 of 3" in rows[0]["Finding_Details"]
        assert "fraud/3" in rows[0]["Finding_Details"]
        assert "fraud/2" not in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_one_unregistered_model_among_registered_fails(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints={
                "ep1": [{"VariantName": "v", "ModelName": "m1"}],
                "ep2": [
                    {"VariantName": "a", "ModelName": "m1"},
                    {"VariantName": "b", "ModelName": "m2"},
                ],
            },
            models={
                "m1": {"PrimaryContainer": {"ModelPackageName": "p1"}},
                "m2": {
                    "Containers": [
                        {"ModelPackageName": "p1"},
                        {"Image": "123.dkr.ecr/x", "ModelDataUrl": "s3://b/k"},
                    ]
                },
            },
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'m2'" in rows[0]["Finding_Details"]
        assert "ep2/b" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_model_from_unapproved_package_fails(self, mock_client):
        self._client(
            mock_client,
            {
                "p1": self._good_package(),
                "p2": self._good_package(
                    ModelPackageName="fraud/2",
                    ModelApprovalStatus="PendingManualApproval",
                ),
            },
            endpoints={
                "ep": [
                    {"VariantName": "a", "ModelName": "m1"},
                    {"VariantName": "b", "ModelName": "m2"},
                ]
            },
            models={
                "m1": {"PrimaryContainer": {"ModelPackageName": "p1"}},
                "m2": {"PrimaryContainer": {"ModelPackageName": "p2"}},
            },
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "PendingManualApproval" in rows[0]["Finding_Details"]
        assert "'m2'" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_inference_component_model_is_followed(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints={"ep": [{"VariantName": "v"}]},
            components={("ep", "v"): {"ic-good": "m1", "ic-bad": "m2"}},
            models={
                "m1": {"PrimaryContainer": {"ModelPackageName": "p1"}},
                "m2": {"PrimaryContainer": {"Image": "img"}},
            },
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "ep/v/ic-bad" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_inference_component_list_denied_is_not_a_pass(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints={"ep": [{"VariantName": "v"}]},
            errors={"list_inference_components": "AccessDeniedException"},
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "ep/v" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_describe_model_denied_withholds_the_pass(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints={"ep": [{"VariantName": "v", "ModelName": "m1"}]},
            models={"m1": {"PrimaryContainer": {"ModelPackageName": "p1"}}},
            errors={"describe_model": "AccessDeniedException"},
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "m1" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_list_endpoints_denied_is_not_read(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            errors={"list_endpoints": "AccessDeniedException"},
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]

    @patch("sagemaker_app.boto3.client")
    def test_no_endpoints_adds_no_deployment_row(self, mock_client):
        self._client(mock_client, {"p1": self._good_package()})
        assert self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING) == []

    REGISTERED = {"PrimaryContainer": {"ModelPackageName": "p1"}}
    UNREGISTERED = {"PrimaryContainer": {"Image": "img"}}

    @patch("sagemaker_app.boto3.client")
    def test_registered_endpoint_and_transform_models_pass(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints={"ep": [{"VariantName": "v", "ModelName": "m1"}]},
            transform_jobs={"batch-1": "m2"},
            models={"m1": self.REGISTERED, "m2": self.REGISTERED},
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "1 batch transform job(s)" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize("bad", ["batch-1", "batch-2"])
    @patch("sagemaker_app.boto3.client")
    def test_one_unregistered_transform_model_fails_only_its_job(
        self, mock_client, bad
    ):
        jobs = {"batch-1": "m1", "batch-2": "m1"}
        jobs[bad] = "m2"
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints={"ep": [{"VariantName": "v", "ModelName": "m1"}]},
            transform_jobs=jobs,
            models={"m1": self.REGISTERED, "m2": self.UNREGISTERED},
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        good = "batch-2" if bad == "batch-1" else "batch-1"
        assert "'m2'" in rows[0]["Finding_Details"]
        assert f"transform job {bad}" in rows[0]["Finding_Details"]
        assert good not in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_transform_model_is_judged_without_any_endpoint(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            transform_jobs={"batch-1": "m2"},
            models={"m2": self.UNREGISTERED},
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "transform job batch-1" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_a_model_on_an_endpoint_and_a_job_names_both(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints={"ep": [{"VariantName": "v", "ModelName": "m2"}]},
            transform_jobs={"batch-1": "m2"},
            models={"m2": self.UNREGISTERED},
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "ep/v" in rows[0]["Finding_Details"]
        assert "transform job batch-1" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_undescribed_transform_job_withholds_the_pass(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints={"ep": [{"VariantName": "v", "ModelName": "m1"}]},
            transform_jobs={"batch-1": "m1"},
            models={"m1": self.REGISTERED},
            errors={"describe_transform_job": "AccessDeniedException"},
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "batch-1" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize("with_endpoint", [True, False])
    @patch("sagemaker_app.boto3.client")
    def test_transform_list_denied_withholds_the_pass(self, mock_client, with_endpoint):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            endpoints=(
                {"ep": [{"VariantName": "v", "ModelName": "m1"}]}
                if with_endpoint
                else None
            ),
            models={"m1": self.REGISTERED},
            errors={"list_transform_jobs": "AccessDeniedException"},
        )
        rows = self._rows(sagemaker_app.DEPLOYED_MODEL_REGISTRATION_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "ListTransformJobs" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_describe_package_denied_withholds_the_aggregate_pass(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            errors={"describe_model_package": "AccessDeniedException"},
        )
        rows = self._rows("Model Approval Workflow Check")
        assert "Passed" not in [r["Status"] for r in rows]
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "p1" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_list_packages_denied_withholds_the_aggregate_pass(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            errors={"list_model_packages": "AccessDeniedException"},
        )
        rows = self._rows("Model Approval Workflow Check")
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "fraud" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_group_list_denied_is_not_read(self, mock_client):
        self._client(
            mock_client,
            {},
            errors={"list_model_package_groups": "AccessDeniedException"},
        )
        rows = self._rows("Model Approval Workflow Check")
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "ListModelPackageGroups" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_no_groups_and_nothing_shared_is_failed(self, mock_client):
        self._client(mock_client, {}, groups=(), ram={"SELF": [], "OTHER-ACCOUNTS": []})
        rows = self._rows("Model Approval Workflow Check")
        assert [r["Status"] for r in rows] == ["Failed"]

    @patch("sagemaker_app.boto3.client")
    def test_no_groups_with_shared_in_group_passes(self, mock_client):
        self._client(
            mock_client,
            {},
            groups=(),
            ram={"SELF": [], "OTHER-ACCOUNTS": ["arn:aws:sagemaker:::grp/central"]},
        )
        rows = self._rows("Model Approval Workflow Check")
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "central" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_no_groups_and_ram_denied_is_not_read(self, mock_client):
        self._client(
            mock_client,
            {},
            groups=(),
            errors={"ram_list_resources": "AccessDeniedException"},
        )
        rows = self._rows("Model Approval Workflow Check")
        assert [r["Status"] for r in rows] == ["N/A"]

    @patch("sagemaker_app.boto3.client")
    def test_unshared_registry_fails_sharing(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            ram={"SELF": [], "OTHER-ACCOUNTS": []},
        )
        rows = self._rows(sagemaker_app.REGISTRY_SHARING_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]

    @patch("sagemaker_app.boto3.client")
    def test_ram_denied_sharing_is_not_read(self, mock_client):
        self._client(
            mock_client,
            {"p1": self._good_package()},
            errors={"ram_list_resources": "AccessDeniedException"},
        )
        rows = self._rows(sagemaker_app.REGISTRY_SHARING_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]


class TestSM31EndpointDataCapture:
    """AIR-SGM-EP-06: SM-31 asserts inference data capture per endpoint."""

    @staticmethod
    def _disk_alarm(endpoint, variant="AllTraffic", **overrides):
        alarm = {
            "AlarmName": f"{endpoint}-disk",
            "ActionsEnabled": True,
            "AlarmActions": ["arn:aws:sns:us-east-1:123456789012:ops"],
            "Namespace": "/aws/sagemaker/Endpoints",
            "MetricName": "DiskUtilization",
            "Dimensions": [
                {"Name": "EndpointName", "Value": endpoint},
                {"Name": "VariantName", "Value": variant},
            ],
            "ComparisonOperator": "GreaterThanThreshold",
            "Threshold": 75.0,
        }
        alarm.update(overrides)
        return alarm

    @classmethod
    def _endpoints(cls, mock_client, endpoints, alarms=None, alarm_error=None):
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        for detail in endpoints.values():
            detail.setdefault("ProductionVariants", [{"VariantName": "AllTraffic"}])
        if alarms is None:
            alarms = [cls._disk_alarm(name) for name in endpoints]
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Endpoints": [{"EndpointName": name} for name in endpoints]}
        ]
        alarm_pager = MagicMock()

        def alarm_pages(**kwargs):
            if alarm_error:
                raise _make_client_error(alarm_error, "DescribeAlarms")
            return [{"MetricAlarms": alarms}]

        alarm_pager.paginate.side_effect = alarm_pages
        mock_sm.get_paginator.side_effect = lambda name: (
            alarm_pager if name == "describe_alarms" else paginator
        )
        mock_sm.describe_endpoint.side_effect = lambda EndpointName: endpoints[
            EndpointName
        ]
        return mock_sm

    @patch("sagemaker_app.boto3.client")
    def test_capturing_endpoint_passes_and_disabled_and_stopped_ones_fail(
        self, mock_client
    ):
        self._endpoints(
            mock_client,
            {
                "capturing": {
                    "DataCaptureConfig": {
                        "EnableCapture": True,
                        "CaptureStatus": "Started",
                        "DestinationS3Uri": "s3://audit/capture",
                        "CurrentSamplingPercentage": 100,
                    }
                },
                "disabled": {
                    "DataCaptureConfig": {
                        "EnableCapture": False,
                        "CaptureStatus": "Stopped",
                    }
                },
                "stopped": {
                    "DataCaptureConfig": {
                        "EnableCapture": True,
                        "CaptureStatus": "Stopped",
                    }
                },
                "unconfigured": {},
            },
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_endpoint_data_capture(region="us-east-1")
        )
        disk = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.CAPTURE_DISK_ALARM_FINDING
        ]
        assert [f["Status"] for f in disk] == ["Passed"]
        findings = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.ENDPOINT_DATA_CAPTURE_FINDING
        ]
        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        details = " | ".join(f["Finding_Details"] for f in failed)
        assert len(failed) == 3
        assert "EnableCapture is false" in details
        assert "CaptureStatus is Stopped" in details
        assert "no DataCaptureConfig is attached" in details
        assert len(passed) == 1
        assert "s3://audit/capture" in passed[0]["Finding_Details"]
        assert "1 of 4 endpoint(s)" in passed[0]["Finding_Details"]
        for f in findings:
            assert f["Check_ID"] == "SM-31"
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_no_endpoints_returns_na(self, mock_client):
        self._endpoints(mock_client, {})
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_endpoint_data_capture(region="us-east-1")
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "No SageMaker endpoints found" in findings[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_describe_failure_is_reported_as_na_not_as_compliant(self, mock_client):
        mock_sm = self._endpoints(
            mock_client,
            {
                "capturing": {
                    "DataCaptureConfig": {
                        "EnableCapture": True,
                        "CaptureStatus": "Started",
                        "DestinationS3Uri": "s3://audit/capture",
                    }
                },
                "denied": {},
            },
        )
        mock_sm.describe_endpoint.side_effect = lambda EndpointName: (
            {
                "DataCaptureConfig": {
                    "EnableCapture": True,
                    "CaptureStatus": "Started",
                    "DestinationS3Uri": "s3://audit/capture",
                },
                "ProductionVariants": [{"VariantName": "AllTraffic"}],
            }
            if EndpointName == "capturing"
            else _raise(_make_client_error("AccessDeniedException"))
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_endpoint_data_capture(region="us-east-1")
        )
        na_rows = [f for f in findings if f["Status"] == "N/A"]
        assert len(na_rows) == 1
        assert "denied" in na_rows[0]["Finding_Details"]
        assert "AccessDeniedException" in na_rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_exception_returns_could_not_assess(self, mock_client):
        mock_client.side_effect = Exception("boom")
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_endpoint_data_capture(region="us-east-1")
        )
        assert len(findings) == 1
        assert_could_not_assess_finding(findings[0])


class TestSM31CaptureDiskAlarm:
    """AIR-SGM-EP-06: a capturing variant needs a DiskUtilization alarm at 75%
    or lower, because Data Capture stops at high disk usage."""

    CAPTURE = {"EnableCapture": True, "CaptureStatus": "Started"}

    def _rows(self, mock_client, endpoints, **kwargs):
        TestSM31EndpointDataCapture._endpoints(mock_client, endpoints, **kwargs)
        rows = extract_csv_data(
            sagemaker_app.check_sagemaker_endpoint_data_capture(region="us-east-1")
        )
        for row in rows:
            assert_finding_schema(row)
        return [
            r
            for r in rows
            if r["Finding"].startswith(sagemaker_app.CAPTURE_DISK_ALARM_FINDING)
        ]

    def _two_variant_endpoint(self):
        return {
            "ep": {
                "DataCaptureConfig": dict(self.CAPTURE),
                "ProductionVariants": [{"VariantName": "a"}, {"VariantName": "b"}],
            }
        }

    @patch("sagemaker_app.boto3.client")
    def test_every_variant_alarmed_passes(self, mock_client):
        alarm = TestSM31EndpointDataCapture._disk_alarm
        rows = self._rows(
            mock_client,
            self._two_variant_endpoint(),
            alarms=[alarm("ep", "a"), alarm("ep", "b", Threshold=70.0)],
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "All 2" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_one_unalarmed_variant_among_alarmed_fails(self, mock_client):
        alarm = TestSM31EndpointDataCapture._disk_alarm
        rows = self._rows(
            mock_client, self._two_variant_endpoint(), alarms=[alarm("ep", "a")]
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'ep/b'" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "override",
        [
            {"Threshold": 90.0},
            {"ActionsEnabled": False},
            {"AlarmActions": []},
            {"ComparisonOperator": "LessThanThreshold"},
            {"MetricName": "CPUUtilization"},
            {"Namespace": "AWS/SageMaker"},
            {"Dimensions": [{"Name": "EndpointName", "Value": "ep"}]},
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_alarm_that_cannot_fire_in_time_does_not_count(self, mock_client, override):
        alarm = TestSM31EndpointDataCapture._disk_alarm
        rows = self._rows(
            mock_client,
            self._two_variant_endpoint(),
            alarms=[alarm("ep", "a"), alarm("ep", "b", **override)],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'ep/b'" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_alarm_read_denied_is_not_read(self, mock_client):
        rows = self._rows(
            mock_client,
            self._two_variant_endpoint(),
            alarm_error="AccessDenied",
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "DescribeAlarms" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_serverless_variant_is_not_counted(self, mock_client):
        alarm = TestSM31EndpointDataCapture._disk_alarm
        endpoints = {
            "ep": {
                "DataCaptureConfig": dict(self.CAPTURE),
                "ProductionVariants": [
                    {"VariantName": "a"},
                    {
                        "VariantName": "sl",
                        "CurrentServerlessConfig": {"MemorySizeInMB": 2048},
                    },
                ],
            }
        }
        rows = self._rows(mock_client, endpoints, alarms=[alarm("ep", "a")])
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "All 1" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_non_capturing_endpoint_needs_no_disk_alarm(self, mock_client):
        rows = self._rows(
            mock_client,
            {"ep": {"DataCaptureConfig": {"EnableCapture": False}}},
            alarms=[],
        )
        assert rows == []


class TestSM23MonitorReportAndAlarm:
    """AIR-SGM-EP-06: each Model Monitor schedule needs a current report and an
    alarm with an action on its metrics; an unread list is never a pass."""

    @staticmethod
    def _client(
        mock_client,
        schedules,
        details,
        alarms=(),
        errors=None,
        endpoints=("ep",),
        job_definitions=None,
        executions=None,
    ):
        """executions maps a schedule to its ListMonitoringExecutions summaries,
        newest first, or to an error code; an unnamed schedule is denied."""
        errors = errors or {}
        job_definitions = job_definitions or {}
        executions = executions or {}
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm

        def pager(name):
            p = MagicMock()

            def paginate(**kwargs):
                if name in errors:
                    raise _make_client_error(errors[name], name)
                if name == "list_monitoring_executions":
                    assert kwargs["SortBy"] == "ScheduledTime"
                    assert kwargs["SortOrder"] == "Descending"
                    value = executions.get(
                        kwargs["MonitoringScheduleName"], "AccessDeniedException"
                    )
                    if isinstance(value, str):
                        raise _make_client_error(value, name)
                    return [
                        {"MonitoringExecutionSummaries": value[:1]},
                        {"MonitoringExecutionSummaries": value[1:]},
                    ]
                if name == "list_endpoints":
                    return [
                        {
                            "Endpoints": [
                                {"EndpointName": e, "EndpointStatus": "InService"}
                                for e in endpoints
                            ]
                        }
                    ]
                if name == "list_monitoring_schedules":
                    return [{"MonitoringScheduleSummaries": schedules}]
                return [{"MetricAlarms": list(alarms)}]

            p.paginate.side_effect = paginate
            return p

        mock_sm.get_paginator.side_effect = pager

        def describe(MonitoringScheduleName):
            if "describe_monitoring_schedule" in errors:
                raise _make_client_error(errors["describe_monitoring_schedule"], "x")
            return details[MonitoringScheduleName]

        mock_sm.describe_monitoring_schedule.side_effect = describe

        def describer(operation):
            def describe_definition(JobDefinitionName):
                value = job_definitions[JobDefinitionName]
                if isinstance(value, str):
                    raise _make_client_error(value, operation)
                return value

            return describe_definition

        for kind, method in (
            ("DataQuality", "describe_data_quality_job_definition"),
            ("ModelQuality", "describe_model_quality_job_definition"),
            ("ModelBias", "describe_model_bias_job_definition"),
            ("ModelExplainability", "describe_model_explainability_job_definition"),
        ):
            getattr(mock_sm, method).side_effect = describer(
                f"Describe{kind}JobDefinition"
            )
        return mock_sm

    @staticmethod
    def _schedule(name, kind, endpoint="ep"):
        return {
            "MonitoringScheduleName": name,
            "MonitoringType": kind,
            "MonitoringScheduleStatus": "Scheduled",
            "EndpointName": endpoint,
        }

    @staticmethod
    def _detail(age_hours, status="Completed", expression="cron(0 * ? * * *)"):
        return {
            "MonitoringScheduleConfig": {
                "ScheduleConfig": {"ScheduleExpression": expression}
            },
            "LastMonitoringExecutionSummary": {
                "MonitoringExecutionStatus": status,
                "ScheduledTime": datetime.now(timezone.utc)
                - timedelta(hours=age_hours),
            },
        }

    @staticmethod
    def _alarm(schedule, namespace="aws/sagemaker/Endpoints/data-metrics"):
        return {
            "ActionsEnabled": True,
            "AlarmActions": ["arn:aws:sns:us-east-1:123456789012:ops"],
            "Namespace": namespace,
            "MetricName": "feature_baseline_drift_age",
            "ComparisonOperator": "GreaterThanThreshold",
            "Threshold": 0.1,
            "Dimensions": [
                {"Name": "Endpoint", "Value": "ep"},
                {"Name": "MonitoringSchedule", "Value": schedule},
            ],
        }

    def _rows(self, mock_client, finding, **kwargs):
        self._client(mock_client, **kwargs)
        rows = extract_csv_data(
            sagemaker_app.check_model_drift_detection(region="us-east-1")
        )
        for row in rows:
            assert_finding_schema(row)
        return [r for r in rows if r["Finding"].startswith(finding)]

    def _two(self):
        return [
            self._schedule("dq", "DataQuality"),
            self._schedule("mq", "ModelQuality"),
        ]

    @patch("sagemaker_app.boto3.client")
    def test_fresh_reports_pass(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_REPORT_FINDING,
            schedules=self._two(),
            details={
                "dq": self._detail(1),
                "mq": self._detail(2, "CompletedWithViolations"),
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_one_stale_report_among_fresh_fails(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_REPORT_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(5)},
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'mq'" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_daily_cadence_allows_a_day_old_report(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_REPORT_FINDING,
            schedules=self._two(),
            details={
                "dq": self._detail(30, expression="cron(0 0 ? * * *)"),
                "mq": self._detail(60, expression="cron(0 0 ? * * *)"),
            },
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'mq'" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize("status", ["Failed", "Stopped"])
    @patch("sagemaker_app.boto3.client")
    def test_failed_latest_execution_fails(self, mock_client, status):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_REPORT_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(1, status)},
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert status in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_never_run_schedule_fails(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_REPORT_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": {}},
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "never run" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_running_execution_withholds_the_pass(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_REPORT_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(0, "InProgress")},
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "sagemaker:ListMonitoringExecutions" in rows[0]["Finding_Details"]

    @staticmethod
    def _execution(age_hours, status="Completed"):
        return {
            "MonitoringExecutionStatus": status,
            "ScheduledTime": datetime.now(timezone.utc) - timedelta(hours=age_hours),
        }

    @patch("sagemaker_app.boto3.client")
    def test_a_running_execution_is_judged_by_the_one_before_it(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_REPORT_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(0, "InProgress")},
            executions={
                "mq": [
                    self._execution(0, "InProgress"),
                    self._execution(1, "CompletedWithViolations"),
                    self._execution(2, "Failed"),
                ]
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @pytest.mark.parametrize(
        "earlier, text",
        [
            ([], "no execution before it has finished"),
            ([(0, "Pending")], "no execution before it has finished"),
            ([(1, "Failed")], "its latest finished execution is Failed"),
            ([(9, "Completed")], "older than twice its cadence"),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_a_running_execution_after_no_current_report_fails(
        self, mock_client, earlier, text
    ):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_REPORT_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(0, "InProgress")},
            executions={
                "mq": [self._execution(0, "InProgress")]
                + [self._execution(age, status) for age, status in earlier]
            },
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'mq'" in rows[0]["Finding_Details"]
        assert "'dq'" not in rows[0]["Finding_Details"]
        assert text in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_describe_denied_is_not_read(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_REPORT_FINDING,
            schedules=self._two(),
            details={},
            errors={"describe_monitoring_schedule": "AccessDeniedException"},
        )
        assert [r["Status"] for r in rows] == ["N/A"]

    @patch("sagemaker_app.boto3.client")
    def test_every_schedule_alarmed_passes(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_ALARM_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(1)},
            alarms=[
                self._alarm("dq"),
                self._alarm("mq", "aws/sagemaker/Endpoints/model-metrics"),
            ],
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_the_alarm_pass_names_the_unjudged_metric_and_threshold(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_ALARM_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(1)},
            alarms=[
                self._alarm("dq"),
                self._alarm("mq", "aws/sagemaker/Endpoints/model-metrics"),
            ],
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert (
            "For ModelQuality, ModelBias and ModelExplainability schedules, and for "
            "metric math, which metric the alarm evaluates and whether its "
            "threshold marks a violation are not judged."
        ) in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_a_data_quality_namespace_alarm_does_not_credit_model_quality(
        self, mock_client
    ):
        # AIR-SGM-EP-06: this pair passed before, because any Model Monitor
        # namespace on the schedule's dimension credited it.
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_ALARM_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(1)},
            alarms=[self._alarm("dq"), self._alarm("mq")],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "ModelQuality metric of schedule 'mq'" in rows[0]["Finding_Details"]
        assert "'dq'" not in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "overrides",
        [
            {"MetricName": "feature_non_null_age"},
            {"ComparisonOperator": "LessThanThreshold"},
            {"Threshold": 1.0},
            {"Threshold": 4.0},
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_a_data_quality_alarm_that_cannot_mark_drift_does_not_credit(
        self, mock_client, overrides
    ):
        weak = dict(self._alarm("dq"), **overrides)
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_ALARM_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(1)},
            alarms=[weak, self._alarm("mq", "aws/sagemaker/Endpoints/model-metrics")],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "DataQuality metric of schedule 'dq'" in rows[0]["Finding_Details"]
        assert "'mq'" not in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_an_alarm_on_another_schedule_of_the_endpoint_does_not_credit(
        self, mock_client
    ):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_ALARM_FINDING,
            schedules=[
                self._schedule("dq", "DataQuality"),
                self._schedule("dq2", "DataQuality"),
            ],
            details={"dq": self._detail(1), "dq2": self._detail(1)},
            alarms=[self._alarm("dq")],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'dq2'" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_one_unalarmed_schedule_among_alarmed_fails(self, mock_client):
        other = self._alarm("mq", "AWS/SageMaker")
        other["Dimensions"] = [{"Name": "MonitoringSchedule", "Value": "mq"}]
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_ALARM_FINDING,
            schedules=[
                self._schedule("dq", "DataQuality"),
                self._schedule("mq", "ModelQuality", endpoint="ep2"),
            ],
            endpoints=("ep", "ep2"),
            details={"dq": self._detail(1), "mq": self._detail(1)},
            alarms=[self._alarm("dq"), other],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'mq'" in rows[0]["Finding_Details"]

    DOC_DATA_NAMESPACE = "/aws/sagemaker/Endpoints/data-metric"

    def _doc_alarm(self, schedule, endpoint, namespace=DOC_DATA_NAMESPACE):
        alarm = self._alarm(schedule, namespace)
        alarm["Dimensions"] = [
            {"Name": "EndpointName", "Value": endpoint},
            {"Name": "ScheduleName", "Value": schedule},
        ]
        return alarm

    def _split_rows(self, mock_client, alarms):
        return self._rows(
            mock_client,
            sagemaker_app.MONITOR_ALARM_FINDING,
            schedules=[
                self._schedule("dq", "DataQuality"),
                self._schedule("mq", "ModelQuality", endpoint="ep2"),
            ],
            endpoints=("ep", "ep2"),
            details={"dq": self._detail(1), "mq": self._detail(1)},
            alarms=alarms,
        )

    @pytest.mark.parametrize("doc_first", [True, False])
    @patch("sagemaker_app.boto3.client")
    def test_the_data_quality_doc_spelling_credits_its_schedule(
        self, mock_client, doc_first
    ):
        # One schedule alarmed under each documented spelling.
        existing = self._alarm("mq", "aws/sagemaker/Endpoints/model-metrics")
        existing["Dimensions"] = [
            {"Name": "Endpoint", "Value": "ep2"},
            {"Name": "MonitoringSchedule", "Value": "mq"},
        ]
        alarms = [self._doc_alarm("dq", "ep"), existing]
        if not doc_first:
            alarms.reverse()
        rows = self._split_rows(mock_client, alarms)
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_the_byoc_doc_spelling_credits_only_its_schedule(self, mock_client):
        alarm = self._alarm("dq", "/aws/sagemaker/Endpoint/data-metrics")
        alarm["Dimensions"] = [
            {"Name": "Endpoint", "Value": "ep"},
            {"Name": "MonitoringSchedule", "Value": "dq"},
        ]
        rows = self._split_rows(mock_client, [alarm])
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'mq'" in rows[0]["Finding_Details"]
        assert "'dq'" not in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "dimensions",
        [
            [{"Name": "ScheduleName", "Value": "dq"}],
            [{"Name": "EndpointName", "Value": "ep"}],
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_either_doc_dimension_alone_credits_no_schedule(
        self, mock_client, dimensions
    ):
        # Stricter than before: Model Monitor publishes under both dimensions,
        # so an alarm naming one of them reads a series that never exists.
        alarm = self._doc_alarm("dq", "ep")
        alarm["Dimensions"] = dimensions
        rows = self._split_rows(mock_client, [alarm])
        assert [r["Status"] for r in rows] == ["Failed", "Failed"]
        assert "'dq'" in rows[0]["Finding_Details"]
        assert "'mq'" in rows[1]["Finding_Details"]

    @pytest.mark.parametrize(
        "namespace",
        [
            "/aws/sagemaker/Endpoints",
            "/aws/sagemaker/Endpoint",
            "AWS/SageMaker",
            "/aws/sagemaker/Endpoints/x",
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_an_endpoint_name_on_another_namespace_does_not_credit(
        self, mock_client, namespace
    ):
        rows = self._split_rows(
            mock_client,
            [self._doc_alarm("dq", "ep"), self._doc_alarm("mq", "ep2", namespace)],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'mq'" in rows[0]["Finding_Details"]
        assert "'dq'" not in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_alarm_without_action_does_not_count(self, mock_client):
        silent = self._alarm("mq")
        silent["AlarmActions"] = []
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_ALARM_FINDING,
            schedules=[self._schedule("mq", "ModelQuality", endpoint="ep2")],
            endpoints=("ep2",),
            details={"mq": self._detail(1)},
            alarms=[silent],
        )
        assert [r["Status"] for r in rows] == ["Failed"]

    @patch("sagemaker_app.boto3.client")
    def test_alarm_read_denied_is_not_read(self, mock_client):
        rows = self._rows(
            mock_client,
            sagemaker_app.MONITOR_ALARM_FINDING,
            schedules=self._two(),
            details={"dq": self._detail(1), "mq": self._detail(1)},
            errors={"describe_alarms": "AccessDenied"},
        )
        assert [r["Status"] for r in rows] == ["N/A"]

    @pytest.mark.parametrize("failing", ["list_endpoints", "list_monitoring_schedules"])
    @patch("sagemaker_app.boto3.client")
    def test_list_denied_is_not_a_pass(self, mock_client, failing):
        self._client(
            mock_client,
            schedules=[],
            details={},
            errors={failing: "AccessDeniedException"},
        )
        rows = extract_csv_data(
            sagemaker_app.check_model_drift_detection(region="us-east-1")
        )
        assert "Passed" not in [r["Status"] for r in rows]
        assert [r["Status"] for r in rows] == ["N/A"]

    CONSTRAINTS = {"S3Uri": "s3://baselines/constraints.json"}

    def _inline(self, baseline):
        detail = self._detail(1)
        definition = {} if baseline is None else {"BaselineConfig": baseline}
        detail["MonitoringScheduleConfig"]["MonitoringJobDefinition"] = definition
        return detail

    def _named(self, name, kind):
        detail = self._detail(1)
        detail["MonitoringScheduleConfig"].update(
            {"MonitoringJobDefinitionName": name, "MonitoringType": kind}
        )
        return detail

    def _baseline_rows(self, mock_client, **kwargs):
        return self._rows(
            mock_client,
            sagemaker_app.MONITOR_BASELINE_FINDING,
            schedules=kwargs.pop("schedules", self._two()),
            **kwargs,
        )

    @patch("sagemaker_app.boto3.client")
    def test_inline_constraints_on_every_schedule_pass(self, mock_client):
        rows = self._baseline_rows(
            mock_client,
            details={
                "dq": self._inline({"ConstraintsResource": self.CONSTRAINTS}),
                "mq": self._inline({"ConstraintsResource": self.CONSTRAINTS}),
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @pytest.mark.parametrize(
        "baseline",
        [
            None,
            {},
            {"StatisticsResource": {"S3Uri": "s3://b/s.json"}},
            {"ConstraintsResource": {"S3Uri": ""}},
        ],
    )
    @pytest.mark.parametrize("bare", ["dq", "mq"])
    @patch("sagemaker_app.boto3.client")
    def test_one_schedule_without_constraints_fails_only_itself(
        self, mock_client, bare, baseline
    ):
        details = {
            name: self._inline({"ConstraintsResource": self.CONSTRAINTS})
            for name in ("dq", "mq")
        }
        details[bare] = self._inline(baseline)
        rows = self._baseline_rows(mock_client, details=details)
        assert [r["Status"] for r in rows] == ["Failed"]
        other = "mq" if bare == "dq" else "dq"
        assert f"'{bare}'" in rows[0]["Finding_Details"]
        assert f"'{other}'" not in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_each_schedule_without_constraints_gets_a_row(self, mock_client):
        rows = self._baseline_rows(
            mock_client,
            details={"dq": self._inline(None), "mq": self._inline({})},
        )
        assert [r["Status"] for r in rows] == ["Failed", "Failed"]
        assert "'dq'" in rows[0]["Finding_Details"]
        assert "'mq'" in rows[1]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_named_data_quality_definition_is_read(self, mock_client):
        rows = self._baseline_rows(
            mock_client,
            schedules=[self._schedule("dq", "DataQuality")],
            details={"dq": self._named("dq-def", "DataQuality")},
            job_definitions={
                "dq-def": {
                    "DataQualityBaselineConfig": {
                        "ConstraintsResource": self.CONSTRAINTS
                    }
                }
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_named_data_quality_definition_without_constraints_fails(self, mock_client):
        rows = self._baseline_rows(
            mock_client,
            details={
                "dq": self._named("dq-def", "DataQuality"),
                "mq": self._inline({"ConstraintsResource": self.CONSTRAINTS}),
            },
            job_definitions={"dq-def": {"DataQualityBaselineConfig": {}}},
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'dq'" in rows[0]["Finding_Details"]
        assert "dq-def" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_unread_data_quality_definition_withholds_the_pass(self, mock_client):
        rows = self._baseline_rows(
            mock_client,
            details={
                "dq": self._named("dq-def", "DataQuality"),
                "mq": self._inline({"ConstraintsResource": self.CONSTRAINTS}),
            },
            job_definitions={"dq-def": "AccessDeniedException"},
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "dq-def" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "kind,method",
        [
            ("ModelQuality", "describe_model_quality_job_definition"),
            ("ModelBias", "describe_model_bias_job_definition"),
            ("ModelExplainability", "describe_model_explainability_job_definition"),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_other_named_definitions_are_read_with_their_own_describe(
        self, mock_client, kind, method
    ):
        rows = self._baseline_rows(
            mock_client,
            schedules=[self._schedule("dq", "DataQuality"), self._schedule("mq", kind)],
            details={
                "dq": self._inline({"ConstraintsResource": self.CONSTRAINTS}),
                "mq": self._named("other-def", kind),
            },
            job_definitions={
                "other-def": {
                    f"{kind}BaselineConfig": {"ConstraintsResource": self.CONSTRAINTS}
                }
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        getattr(mock_client.return_value, method).assert_called_once_with(
            JobDefinitionName="other-def"
        )

    @pytest.mark.parametrize(
        "kind", ["ModelQuality", "ModelBias", "ModelExplainability"]
    )
    @pytest.mark.parametrize(
        "baseline_key",
        ["", "DataQualityBaselineConfig"],
        ids=["no-baseline", "another-type's-key"],
    )
    @patch("sagemaker_app.boto3.client")
    def test_other_named_definition_without_constraints_fails_only_itself(
        self, mock_client, kind, baseline_key
    ):
        definition = (
            {baseline_key: {"ConstraintsResource": self.CONSTRAINTS}}
            if baseline_key
            else {}
        )
        rows = self._baseline_rows(
            mock_client,
            schedules=[
                self._schedule("dq", "DataQuality"),
                self._schedule("mq", kind),
                self._schedule("ok", kind),
            ],
            details={
                "dq": self._inline({"ConstraintsResource": self.CONSTRAINTS}),
                "mq": self._named("bare-def", kind),
                "ok": self._named("good-def", kind),
            },
            job_definitions={
                "bare-def": definition,
                "good-def": {
                    f"{kind}BaselineConfig": {"ConstraintsResource": self.CONSTRAINTS}
                },
            },
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'mq'" in rows[0]["Finding_Details"]
        assert "bare-def" in rows[0]["Finding_Details"]
        assert "good-def" not in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "kind", ["ModelQuality", "ModelBias", "ModelExplainability"]
    )
    @patch("sagemaker_app.boto3.client")
    def test_unread_other_definition_is_named_and_withholds_the_pass(
        self, mock_client, kind
    ):
        rows = self._baseline_rows(
            mock_client,
            schedules=[self._schedule("dq", "DataQuality"), self._schedule("mq", kind)],
            details={
                "dq": self._inline({"ConstraintsResource": self.CONSTRAINTS}),
                "mq": self._named("other-def", kind),
            },
            job_definitions={"other-def": "AccessDeniedException"},
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert (
            f"sagemaker:Describe{kind}JobDefinition other-def"
            in (rows[0]["Finding_Details"])
        )

    @patch("sagemaker_app.boto3.client")
    def test_an_unread_definition_does_not_hide_a_bare_one(self, mock_client):
        rows = self._baseline_rows(
            mock_client,
            schedules=[
                self._schedule("mq", "ModelQuality"),
                self._schedule("mb", "ModelBias"),
            ],
            details={
                "mq": self._named("mq-def", "ModelQuality"),
                "mb": self._named("mb-def", "ModelBias"),
            },
            job_definitions={
                "mq-def": "AccessDeniedException",
                "mb-def": {"ModelBiasBaselineConfig": {}},
            },
        )
        assert sorted(r["Status"] for r in rows) == ["Failed", "N/A"]

    @patch("sagemaker_app.boto3.client")
    def test_baselining_job_without_constraints_file_is_not_a_pass(self, mock_client):
        rows = self._baseline_rows(
            mock_client,
            details={
                "dq": self._inline({"ConstraintsResource": self.CONSTRAINTS}),
                "mq": self._inline({"BaseliningJobName": "baseline-job"}),
            },
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "baseline-job" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_schedule_naming_no_definition_is_not_a_pass(self, mock_client):
        rows = self._baseline_rows(
            mock_client,
            details={
                "dq": self._inline({"ConstraintsResource": self.CONSTRAINTS}),
                "mq": self._detail(1),
            },
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "'mq'" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_undescribed_schedule_withholds_the_baseline_pass(self, mock_client):
        rows = self._baseline_rows(
            mock_client,
            details={},
            errors={"describe_monitoring_schedule": "AccessDeniedException"},
        )
        assert [r["Status"] for r in rows] == ["N/A"]


def _raise(error):
    raise error


_SM32_REQUIRED_RULES = [
    {
        "ConfigRuleName": "sm-endpoint-kms",
        "ConfigRuleState": "ACTIVE",
        "Source": {
            "Owner": "AWS",
            "SourceIdentifier": "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED",
        },
        "InputParameters": json.dumps(
            {"kmsKeyArns": "arn:aws:kms:us-east-1:123456789012:key/approved"}
        ),
    },
    {
        "ConfigRuleName": "sm-notebook-kms",
        "ConfigRuleState": "ACTIVE",
        "Source": {
            "Owner": "AWS",
            "SourceIdentifier": "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED",
        },
    },
    {
        "ConfigRuleName": "sm-notebook-internet",
        "ConfigRuleState": "ACTIVE",
        "Source": {
            "Owner": "AWS",
            "SourceIdentifier": "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS",
        },
    },
]
_SM32_REQUIRED_RULE_NAMES = [rule["ConfigRuleName"] for rule in _SM32_REQUIRED_RULES]
_SM32_ORG_PACK = {
    "ConformancePackName": "org-sagemaker",
    "CreatedBy": "config-multiaccountsetup.amazonaws.com",
}


class TestSM32ConfigComplianceEvaluation:
    """AIR-SGM-GOV-10: SM-32 asserts Config recording and rule evaluation."""

    @staticmethod
    def _config(
        mock_client,
        recorders,
        rules,
        compliance,
        summaries=(),
        packs=(),
        pack_rules=None,
        statuses=None,
    ):
        """
        Every covered recorder records unless statuses says otherwise, and each
        Config paginator gets its own page set.
        """
        config_client = MagicMock()
        config_client.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": recorders
        }
        config_client.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": (
                statuses
                if statuses is not None
                else [{"name": r.get("name"), "recording": True} for r in recorders]
            )
        }
        pages = {
            "describe_config_rules": [{"ConfigRules": rules}],
            "describe_compliance_by_config_rule": [
                {"ComplianceByConfigRules": compliance}
            ],
            "list_configuration_recorders": [
                {"ConfigurationRecorderSummaries": list(summaries)}
            ],
            "describe_conformance_packs": [{"ConformancePackDetails": list(packs)}],
        }
        paginators = {}
        for name, value in pages.items():
            paginator = MagicMock()
            if isinstance(value, Exception):
                paginator.paginate.side_effect = value
            else:
                paginator.paginate.return_value = value
            paginators[name] = paginator
        pack_paginator = MagicMock()

        def pack_pages(ConformancePackName):
            value = (pack_rules or {}).get(ConformancePackName, [])
            if isinstance(value, Exception):
                raise value
            return [
                {
                    "ConformancePackRuleComplianceList": [
                        {"ConfigRuleName": rule_name} for rule_name in value
                    ]
                }
            ]

        pack_paginator.paginate.side_effect = pack_pages
        paginators["describe_conformance_pack_compliance"] = pack_paginator
        config_client.get_paginator.side_effect = lambda name: paginators[name]
        mock_client.return_value = config_client
        return config_client

    def test_recorder_and_compliant_rule_pass(self):
        # A Passed-only result now needs the three required rules, pinned, in
        # an organization conformance pack, and a recorder that is recording.
        with patch("sagemaker_app.boto3.client") as mock_client:
            self._config(
                mock_client,
                [
                    {
                        "name": "default",
                        "recordingGroup": {
                            "recordingStrategy": {
                                "useOnly": "ALL_SUPPORTED_RESOURCE_TYPES"
                            }
                        },
                    }
                ],
                _SM32_REQUIRED_RULES,
                [
                    {
                        "ConfigRuleName": rule["ConfigRuleName"],
                        "Compliance": {"ComplianceType": "COMPLIANT"},
                    }
                    for rule in _SM32_REQUIRED_RULES
                ],
                packs=[_SM32_ORG_PACK],
                pack_rules={"org-sagemaker": _SM32_REQUIRED_RULE_NAMES},
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        assert {f["Status"] for f in findings} == {"Passed"}
        recording = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.CONFIG_RECORDING_FINDING
        ]
        assert "all supported resource types" in recording[0]["Finding_Details"]
        for f in findings:
            assert f["Check_ID"] == "SM-32"
            assert_finding_schema(f)

    def test_no_recorder_is_failed_once_the_full_list_is_read_and_no_rule_fails(
        self,
    ):
        # An empty no-arg DescribeConfigurationRecorders hides a service-linked
        # recorder. ListConfigurationRecorders lists those too, so an empty
        # customer-managed set is now decidable and fails.
        with patch("sagemaker_app.boto3.client") as mock_client:
            self._config(
                mock_client,
                [],
                [],
                [],
                summaries=[
                    {
                        "name": "AWSConfigurationRecorderForSecurityHubCSPM",
                        "servicePrincipal": "cspm.securityhub.amazonaws.com",
                    }
                ],
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        recording = _by_finding(findings, sagemaker_app.CONFIG_RECORDING_FINDING)
        assert [f["Status"] for f in recording] == ["Failed"]
        assert (
            "No customer-managed AWS Config recorder" in recording[0]["Finding_Details"]
        )
        assert "cspm.securityhub.amazonaws.com" in recording[0]["Finding_Details"]
        rule_rows = self._rule_rows(findings)
        assert [f["Status"] for f in rule_rows] == ["Failed"]
        assert "No ACTIVE AWS Config rule" in rule_rows[0]["Finding_Details"]

    def test_recorder_recording_other_services_only_is_failed(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            self._config(
                mock_client,
                [
                    {
                        "name": "partial",
                        "recordingGroup": {
                            "allSupported": False,
                            "resourceTypes": ["AWS::S3::Bucket", "AWS::IAM::Role"],
                            "recordingStrategy": {
                                "useOnly": "INCLUSION_BY_RESOURCE_TYPES"
                            },
                        },
                    }
                ],
                [],
                [],
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        recording = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.CONFIG_RECORDING_FINDING
        ]
        assert [f["Status"] for f in recording] == ["Failed"]
        assert "none of them AWS::SageMaker::*" in recording[0]["Finding_Details"]

    def test_recorder_including_a_sagemaker_type_is_passed(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            self._config(
                mock_client,
                [
                    {
                        "name": "scoped",
                        "recordingGroup": {
                            "allSupported": False,
                            "resourceTypes": [
                                "AWS::S3::Bucket",
                                "AWS::SageMaker::Domain",
                            ],
                            "recordingStrategy": {
                                "useOnly": "INCLUSION_BY_RESOURCE_TYPES"
                            },
                        },
                    }
                ],
                [],
                [],
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        recording = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.CONFIG_RECORDING_FINDING
        ]
        assert [f["Status"] for f in recording] == ["Passed"]
        assert "AWS::SageMaker::Domain" in recording[0]["Finding_Details"]

    def test_excluding_a_sagemaker_type_is_failed(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            self._config(
                mock_client,
                [
                    {
                        "name": "excluding",
                        "recordingGroup": {
                            "recordingStrategy": {
                                "useOnly": "EXCLUSION_BY_RESOURCE_TYPES"
                            },
                            "exclusionByResourceTypes": {
                                "resourceTypes": ["AWS::SageMaker::Model"]
                            },
                        },
                    }
                ],
                [],
                [],
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        recording = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.CONFIG_RECORDING_FINDING
        ]
        assert [f["Status"] for f in recording] == ["Failed"]
        assert "AWS::SageMaker::Model" in recording[0]["Finding_Details"]

    def test_non_compliant_rule_reports_the_resource_count(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            self._config(
                mock_client,
                [
                    {
                        "name": "default",
                        "recordingGroup": {"allSupported": True},
                    }
                ],
                [
                    {
                        "ConfigRuleName": "sagemaker-endpoint-kms",
                        "ConfigRuleState": "ACTIVE",
                        "Scope": {"ComplianceResourceTypes": ["AWS::SageMaker::Model"]},
                        "Source": {"Owner": "AWS", "SourceIdentifier": "OTHER"},
                    }
                ],
                [
                    {
                        "ConfigRuleName": "sagemaker-endpoint-kms",
                        "Compliance": {
                            "ComplianceType": "NON_COMPLIANT",
                            "ComplianceContributorCount": {"CappedCount": 4},
                        },
                    }
                ],
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        rule_rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.CONFIG_RULE_COMPLIANCE_FINDING
        ]
        assert [f["Status"] for f in rule_rows] == ["Failed"]
        assert "4 non-compliant resource(s)" in rule_rows[0]["Finding_Details"]
        assert "sagemaker-endpoint-kms" in rule_rows[0]["Finding_Details"]

    def test_rule_in_deleting_state_does_not_count_as_active(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            self._config(
                mock_client,
                [{"name": "default", "recordingGroup": {"allSupported": True}}],
                [
                    {
                        "ConfigRuleName": "sagemaker-endpoint-kms",
                        "ConfigRuleState": "DELETING",
                        "Source": {"SourceIdentifier": "SAGEMAKER_SOMETHING"},
                    }
                ],
                [],
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        rule_rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.CONFIG_RULE_COMPLIANCE_FINDING
        ]
        assert [f["Status"] for f in rule_rows] == ["Failed"]
        assert "1 SageMaker-related rule(s)" in rule_rows[0]["Finding_Details"]

    def test_non_sagemaker_rules_are_not_counted(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            self._config(
                mock_client,
                [{"name": "default", "recordingGroup": {"allSupported": True}}],
                [
                    {
                        "ConfigRuleName": "s3-bucket-ssl-requests-only",
                        "ConfigRuleState": "ACTIVE",
                        "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
                        "Source": {"SourceIdentifier": "S3_BUCKET_SSL_REQUESTS_ONLY"},
                    }
                ],
                [],
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        rule_rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.CONFIG_RULE_COMPLIANCE_FINDING
        ]
        assert [f["Status"] for f in rule_rows] == ["Failed"]
        assert "0 SageMaker-related rule(s)" in rule_rows[0]["Finding_Details"]

    @staticmethod
    def _rule(name, created_by=None):
        rule = {
            "ConfigRuleName": name,
            "ConfigRuleState": "ACTIVE",
            "Scope": {"ComplianceResourceTypes": ["AWS::SageMaker::NotebookInstance"]},
            "Source": {"Owner": "AWS", "SourceIdentifier": "OTHER"},
        }
        if created_by:
            rule["CreatedBy"] = created_by
        return rule

    @staticmethod
    def _rule_rows(findings):
        return [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.CONFIG_RULE_COMPLIANCE_FINDING
        ]

    def test_service_linked_rules_only_are_na_naming_the_owner(self):
        # Live 2026-09-26: every SageMaker rule in the account carried
        # CreatedBy securityhub.amazonaws.com, and DescribeComplianceByConfigRule
        # on them was AccessDeniedException for admin too.
        with patch("sagemaker_app.boto3.client") as mock_client:
            config_client = self._config(
                mock_client,
                [{"name": "default", "recordingGroup": {"allSupported": True}}],
                [
                    self._rule(
                        "securityhub-sagemaker-a-1", "securityhub.amazonaws.com"
                    ),
                    self._rule(
                        "securityhub-sagemaker-b-2", "securityhub.amazonaws.com"
                    ),
                ],
                [],
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        rule_rows = self._rule_rows(findings)
        assert [f["Status"] for f in rule_rows] == ["N/A"]
        assert "2 ACTIVE SageMaker Config rule(s)" in rule_rows[0]["Finding_Details"]
        assert "securityhub.amazonaws.com" in rule_rows[0]["Finding_Details"]
        assert "Grant" not in rule_rows[0]["Resolution"]
        requested = [c.args[0] for c in config_client.get_paginator.call_args_list]
        assert "describe_compliance_by_config_rule" not in requested

    def test_mixed_rules_read_only_the_customer_rule_and_count_it(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            config_client = self._config(
                mock_client,
                [{"name": "default", "recordingGroup": {"allSupported": True}}],
                [
                    self._rule(
                        "securityhub-sagemaker-a-1", "securityhub.amazonaws.com"
                    ),
                    self._rule("customer-sagemaker-rule"),
                ],
                [
                    {
                        "ConfigRuleName": "customer-sagemaker-rule",
                        "Compliance": {"ComplianceType": "COMPLIANT"},
                    }
                ],
            )
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        rule_rows = self._rule_rows(findings)
        assert [f["Status"] for f in rule_rows] == ["N/A", "Passed"]
        assert "1 ACTIVE SageMaker Config rule(s)" in rule_rows[0]["Finding_Details"]
        assert "1 ACTIVE AWS Config rule(s) evaluate" in rule_rows[1]["Finding_Details"]
        compliance_paginator = config_client.get_paginator(
            "describe_compliance_by_config_rule"
        )
        compliance_paginator.paginate.assert_called_once_with(
            ConfigRuleNames=["customer-sagemaker-rule"]
        )

    def test_a_read_error_on_the_customer_rule_keeps_the_grant_advice(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            config_client = self._config(
                mock_client,
                [{"name": "default", "recordingGroup": {"allSupported": True}}],
                [
                    self._rule(
                        "securityhub-sagemaker-a-1", "securityhub.amazonaws.com"
                    ),
                    self._rule("customer-sagemaker-rule"),
                ],
                [],
            )
            config_client.get_paginator(
                "describe_compliance_by_config_rule"
            ).paginate.side_effect = _make_client_error("AccessDeniedException")
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        rule_rows = self._rule_rows(findings)
        assert [f["Status"] for f in rule_rows] == ["N/A", "N/A"]
        assert "securityhub.amazonaws.com" in rule_rows[0]["Finding_Details"]
        assert (
            "1 ACTIVE SageMaker Config rule(s) were" in rule_rows[1]["Finding_Details"]
        )
        assert "AccessDeniedException" in rule_rows[1]["Finding_Details"]
        assert (
            "Grant config:DescribeComplianceByConfigRule" in rule_rows[1]["Resolution"]
        )

    def test_exception_returns_could_not_assess(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            mock_client.side_effect = Exception("boom")
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        assert len(findings) == 1
        assert_could_not_assess_finding(findings[0])


class TestSM33TrainingJobNetworkBoundary:
    """AIR-SGM-TRN-01: SM-33 asserts training jobs run in a customer VPC."""

    @staticmethod
    def _jobs(mock_client, jobs):
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"TrainingJobSummaries": [{"TrainingJobName": name} for name in jobs]}
        ]
        mock_sm.describe_training_job.side_effect = lambda TrainingJobName: jobs[
            TrainingJobName
        ]
        return mock_sm, paginator

    @patch("sagemaker_app.boto3.client")
    def test_job_without_vpc_is_failed_and_one_in_a_vpc_is_passed(self, mock_client):
        self._jobs(
            mock_client,
            {
                "vpc-job": {
                    "VpcConfig": {
                        "Subnets": ["subnet-a", "subnet-b"],
                        "SecurityGroupIds": ["sg-1"],
                    },
                    "EnableNetworkIsolation": True,
                },
                "open-job": {"EnableNetworkIsolation": False},
            },
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_training_job_network_boundary(
                region="us-east-1"
            )
        )
        failed = [f for f in findings if f["Status"] == "Failed"]
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(failed) == 1
        assert "open-job" in failed[0]["Finding_Details"]
        assert "no VpcConfig" in failed[0]["Finding_Details"]
        assert "Network isolation is off as well" in failed[0]["Finding_Details"]
        assert len(passed) == 1
        assert "subnet-a" in passed[0]["Finding_Details"]
        assert "of the 2 training jobs" in passed[0]["Finding_Details"]
        assert "most recent" not in passed[0]["Finding_Details"]
        for f in findings:
            assert f["Check_ID"] == "SM-33"
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_isolated_job_without_vpc_still_fails_and_says_so(self, mock_client):
        self._jobs(
            mock_client,
            {"isolated-job": {"EnableNetworkIsolation": True}},
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_training_job_network_boundary(
                region="us-east-1"
            )
        )
        assert [f["Status"] for f in findings] == ["Failed"]
        assert "Network isolation is on" in findings[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_every_training_job_is_read_not_a_sample(self, mock_client):
        # AIR-SGM-TRN-01 full grade: the 50-job sample hid every older job.
        mock_sm, paginator = self._jobs(mock_client, {})
        sagemaker_app.check_sagemaker_training_job_network_boundary(region="us-east-1")
        # The processing-job leg shares this mock paginator, so the training
        # list is picked out by its operation name and its sort arguments.
        operations = [c.args[0] for c in mock_sm.get_paginator.call_args_list]
        assert operations.count("list_training_jobs") == 1
        training_call = paginator.paginate.call_args_list[
            operations.index("list_training_jobs")
        ]
        assert training_call == call(SortBy="CreationTime", SortOrder="Descending")
        assert not hasattr(sagemaker_app, "MAX_TRAINING_JOBS_SAMPLED")

    @patch("sagemaker_app.boto3.client")
    def test_every_training_job_is_listed_with_no_item_cap(self, mock_client):
        """The list used to stop at the 50 most recent jobs, so an older job
        with no VpcConfig was never read."""
        mock_sm, paginator = self._jobs(mock_client, {})
        ok = {"VpcConfig": {"Subnets": ["subnet-a"]}}
        paginator.paginate.return_value = [
            {
                "TrainingJobSummaries": [
                    {"TrainingJobName": f"job-{i:02d}"} for i in range(50)
                ]
            },
            {"TrainingJobSummaries": [{"TrainingJobName": "old-open-job"}]},
        ]
        mock_sm.describe_training_job.side_effect = lambda TrainingJobName: (
            {} if TrainingJobName == "old-open-job" else ok
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_training_job_network_boundary(
                region="us-east-1"
            )
        )
        for paginate_call in paginator.paginate.call_args_list:
            assert "PaginationConfig" not in paginate_call.kwargs
        failed = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.TRAINING_NETWORK_BOUNDARY_FINDING
            and f["Status"] == "Failed"
        ]
        assert [f["Finding_Details"].split("'")[1] for f in failed] == ["old-open-job"]
        assert mock_sm.describe_training_job.call_count == 51

    @patch("sagemaker_app.boto3.client")
    def test_no_training_jobs_returns_na(self, mock_client):
        self._jobs(mock_client, {})
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_training_job_network_boundary(
                region="us-east-1"
            )
        )
        assert [f["Status"] for f in findings] == ["N/A"]

    @patch("sagemaker_app.boto3.client")
    def test_exception_returns_could_not_assess(self, mock_client):
        mock_client.side_effect = Exception("boom")
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_training_job_network_boundary(
                region="us-east-1"
            )
        )
        assert len(findings) == 1
        assert_could_not_assess_finding(findings[0])


def _scp_deny(action, operator, key, value, resource="*"):
    return {
        "Effect": "Deny",
        "Action": action,
        "Resource": resource,
        "Condition": {operator: {key: value}},
    }


APPROVED_KEY = "arn:aws:kms:us-east-1:123456789012:key/approved"
SCP_ENCRYPTION_DENIES = [
    _scp_deny(
        ["sagemaker:CreateTrainingJob", "sagemaker:CreateTransformJob"],
        "ArnNotEquals",
        "sagemaker:VolumeKmsKeyArn",
        [APPROVED_KEY],
    ),
    _scp_deny(
        ["sagemaker:CreateTrainingJob", "sagemaker:CreateTransformJob"],
        "ArnNotEquals",
        "sagemaker:OutputKmsKeyArn",
        [APPROVED_KEY],
    ),
    _scp_deny(
        "sagemaker:CreateTrainingJob",
        "BoolIfExists",
        "sagemaker:InterContainerTrafficEncryption",
        "false",
    ),
    _scp_deny(
        ["sagemaker:CreateEndpointConfig", "sagemaker:CreateNotebookInstance"],
        "ArnNotEqualsIfExists",
        "sagemaker:VolumeKmsKeyArn",
        [APPROVED_KEY],
    ),
]
SCP_NETWORK_DENIES = [
    _scp_deny("sagemaker:Create*", "Null", "sagemaker:VpcSubnets", "true"),
    _scp_deny(
        "sagemaker:Create*",
        "ForAnyValue:StringNotEquals",
        "sagemaker:VpcSubnets",
        ["subnet-1"],
    ),
]
SCP_INTERNET_DENIES = [
    _scp_deny(
        [
            "sagemaker:CreateTrainingJob",
            "sagemaker:CreateEndpointConfig",
            "sagemaker:CreateModel",
        ],
        "BoolIfExists",
        "sagemaker:NetworkIsolation",
        "false",
    ),
    _scp_deny(
        "sagemaker:CreateNotebookInstance",
        "StringNotEquals",
        "sagemaker:DirectInternetAccess",
        "Disabled",
    ),
]
OPEN_SAGEMAKER_ALLOW = {"Effect": "Allow", "Action": "sagemaker:*", "Resource": "*"}
GUARDED_CREATE_ALLOWS = [
    {
        "Effect": "Allow",
        "Action": "sagemaker:CreateTrainingJob",
        "Resource": "*",
        "Condition": {
            "ArnEquals": {
                "sagemaker:VolumeKmsKeyArn": APPROVED_KEY,
                "sagemaker:OutputKmsKeyArn": APPROVED_KEY,
            },
            "Bool": {
                "sagemaker:InterContainerTrafficEncryption": "true",
                "sagemaker:NetworkIsolation": "true",
            },
            "ForAllValues:StringEquals": {"sagemaker:VpcSubnets": ["subnet-1"]},
            "Null": {"sagemaker:VpcSubnets": "false"},
        },
    },
    {
        "Effect": "Allow",
        "Action": "sagemaker:CreateEndpointConfig",
        "Resource": "*",
        "Condition": {
            "ArnEquals": {"sagemaker:VolumeKmsKeyArn": APPROVED_KEY},
            "Bool": {"sagemaker:NetworkIsolation": "true"},
            "ForAllValues:StringEquals": {"sagemaker:VpcSecurityGroupIds": ["sg-1"]},
            "Null": {"sagemaker:VpcSecurityGroupIds": "false"},
        },
    },
    {
        "Effect": "Allow",
        "Action": "sagemaker:CreateNotebookInstance",
        "Resource": "*",
        "Condition": {
            "ArnEquals": {"sagemaker:VolumeKmsKeyArn": APPROVED_KEY},
            "StringEquals": {"sagemaker:DirectInternetAccess": "Disabled"},
            "ForAllValues:StringEquals": {"sagemaker:VpcSubnets": ["subnet-1"]},
            "Null": {"sagemaker:VpcSubnets": "false"},
        },
    },
    {
        "Effect": "Allow",
        "Action": "sagemaker:CreateModel",
        "Resource": "*",
        "Condition": {
            "Bool": {"sagemaker:NetworkIsolation": "true"},
            "ForAllValues:StringEquals": {"sagemaker:VpcSubnets": ["subnet-1"]},
            "Null": {"sagemaker:VpcSubnets": "false"},
        },
    },
    {
        "Effect": "Allow",
        "Action": "sagemaker:CreateTransformJob",
        "Resource": "*",
        "Condition": {
            "ArnEquals": {
                "sagemaker:VolumeKmsKeyArn": APPROVED_KEY,
                "sagemaker:OutputKmsKeyArn": APPROVED_KEY,
            },
        },
    },
]
ORG_PATH = {
    "123456789012": [{"Id": "ou-workloads", "Type": "ORGANIZATIONAL_UNIT"}],
    "ou-workloads": [{"Id": "r-root", "Type": "ROOT"}],
}


def _creation_cache(roles, boundaries=None, principal_errors=None, version=2):
    """A v2 IAM cache from {role: [statements]}; version=1 drops the error list."""
    cache = _role_cache(
        {
            name: [(f"{name}-policy", {"Version": "2012-10-17", "Statement": stmts})]
            for name, stmts in roles.items()
        }
    )
    for name, boundary in (boundaries or {}).items():
        cache["role_permissions"][name]["permissions_boundary"] = {
            "Version": "2012-10-17",
            "Statement": boundary,
        }
    if version >= 2:
        cache["cache_schema_version"] = 2
        cache["principal_errors"] = principal_errors or []
    return cache


OPEN_CACHE = _creation_cache({"Admin": [OPEN_SAGEMAKER_ALLOW]})


def _orgs_path_client(master="999999999999", parents=None, parents_error=None):
    orgs = MagicMock()
    orgs.describe_organization.return_value = {
        "Organization": {"MasterAccountId": master}
    }
    tree = ORG_PATH if parents is None else parents

    def get_paginator(operation_name):
        if operation_name != "list_parents":
            raise AssertionError(
                f"unexpected organizations paginator: {operation_name}"
            )
        paginator = MagicMock()

        def paginate(**kwargs):
            if parents_error is not None:
                raise parents_error
            return [{"Parents": tree.get(kwargs["ChildId"], [])}]

        paginator.paginate.side_effect = paginate
        return paginator

    orgs.get_paginator.side_effect = get_paginator
    return orgs


# AIR-SGM-TRN-08: identity policies bind roles and users, never the account
# root user, so an identity-only guard leaves the requirement open. Tests that
# passed on identity policies alone now fail on the root user, and name no role.
ROOT_USER_OPEN = "the account root user is bound by no identity policy"


def _assert_open_only_to_root(row):
    assert row["Status"] == "Failed"
    assert ROOT_USER_OPEN in row["Finding_Details"]
    assert "Role '" not in row["Finding_Details"]


class TestSM34CreationGuardrails:
    """AIR-SGM-TRN-08: SM-34 asserts creation of non-compliant resources is denied."""

    @staticmethod
    def _management_account_clients():
        orgs = MagicMock()
        orgs.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        return _sm_client_factory(organizations=orgs, sts=sts)

    @staticmethod
    def _member_account_clients(**kwargs):
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        return _sm_client_factory(organizations=_orgs_path_client(**kwargs), sts=sts)

    def _run(self, inventory, cache=OPEN_CACHE, management=False, **org_kwargs):
        clients = (
            self._management_account_clients()
            if management
            else self._member_account_clients(**org_kwargs)
        )
        with patch("sagemaker_app.boto3.client", side_effect=clients):
            return extract_csv_data(
                sagemaker_app.check_sagemaker_creation_guardrails(
                    region="Global", scp_inventory=inventory, permission_cache=cache
                )
            )

    @staticmethod
    def _inventory(*documents, targets=None):
        attached = (
            [{"TargetId": "r-root", "Type": "ROOT", "Name": "Root"}]
            if targets is None
            else targets
        )
        return {
            "items": [
                {
                    "name": name,
                    "id": f"p-{index}",
                    "content": json.dumps(document),
                    "targets": attached,
                }
                for index, (name, document) in enumerate(documents)
            ],
            "errors": [],
            "list_error": None,
        }

    @staticmethod
    def _scp(name, statements):
        return (name, {"Version": "2012-10-17", "Statement": statements})

    @staticmethod
    def _by_category(findings):
        rows = {}
        for f in findings:
            for category in (
                "encryption",
                "approved network",
                "no direct internet access",
            ):
                if f" {category} requirements" in f["Finding_Details"]:
                    rows[category] = f
        return rows

    def test_encryption_guard_passes_while_network_and_internet_fail(self):
        findings = self._run(
            self._inventory(self._scp("RequireTrainingKeys", SCP_ENCRYPTION_DENIES))
        )
        by_status = {}
        for f in findings:
            by_status.setdefault(f["Status"], []).append(f["Finding_Details"])
        assert len(by_status["Passed"]) == 1
        assert "encryption" in by_status["Passed"][0]
        assert "RequireTrainingKeys" in by_status["Passed"][0]
        assert len(by_status["Failed"]) == 2
        failed = " | ".join(by_status["Failed"])
        assert "approved network" in failed
        assert "no direct internet access" in failed
        assert "Role 'Admin'" in failed
        for f in findings:
            assert f["Check_ID"] == "SM-34"
            assert_finding_schema(f)

    def test_all_three_guardrails_can_pass(self):
        findings = self._run(
            self._inventory(
                self._scp(
                    "SageMakerCreationGuardrails",
                    SCP_ENCRYPTION_DENIES + SCP_NETWORK_DENIES + SCP_INTERNET_DENIES,
                )
            )
        )
        assert [f["Status"] for f in findings] == ["Passed", "Passed", "Passed"]

    def test_positive_value_deny_is_reported_as_indeterminate(self):
        findings = self._run(
            self._inventory(
                self._scp(
                    "DenyOneSubnet",
                    [
                        _scp_deny(
                            [
                                "sagemaker:CreateTrainingJob",
                                "sagemaker:CreateEndpointConfig",
                                "sagemaker:CreateNotebookInstance",
                                "sagemaker:CreateModel",
                            ],
                            "StringEquals",
                            "sagemaker:VpcSubnets",
                            "subnet-legacy",
                        )
                    ],
                )
            )
        )
        indeterminate = [f for f in findings if f["Status"] == "N/A"]
        assert len(indeterminate) == 1
        assert "depends on that value" in indeterminate[0]["Finding_Details"]
        assert "DenyOneSubnet" in indeterminate[0]["Finding_Details"]

    def test_allow_statement_does_not_count_as_a_guardrail(self):
        findings = self._run(
            self._inventory(
                self._scp(
                    "AllowWithCondition",
                    [
                        {
                            "Effect": "Allow",
                            "Action": "sagemaker:CreateTrainingJob",
                            "Resource": "*",
                            "Condition": {
                                "Null": {"sagemaker:VolumeKmsKeyArn": "true"}
                            },
                        }
                    ],
                )
            )
        )
        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Failed"]

    def test_deny_on_an_unrelated_service_does_not_count(self):
        findings = self._run(
            self._inventory(
                self._scp(
                    "DenyBedrock",
                    [
                        _scp_deny(
                            "bedrock:InvokeModel",
                            "Null",
                            "sagemaker:VolumeKmsKeyArn",
                            "true",
                        )
                    ],
                )
            )
        )
        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Failed"]

    def test_member_account_run_reports_unassessed(self):
        findings = self._run(
            {"items": [], "errors": [], "list_error": "AccessDenied"}, cache=None
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "management account" in findings[0]["Finding_Details"]
        assert "delegated administrator" in findings[0]["Finding_Details"]

    def test_organizations_not_in_use_reports_unassessed(self):
        orgs = MagicMock()
        orgs.describe_organization.side_effect = _make_client_error(
            "AWSOrganizationsNotInUseException"
        )
        with patch(
            "sagemaker_app.boto3.client",
            side_effect=_sm_client_factory(organizations=orgs),
        ):
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_creation_guardrails(region="Global")
            )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "Organizations is not in use" in findings[0]["Finding_Details"]

    def test_list_failure_reports_unassessed(self):
        findings = self._run(
            {"items": [], "errors": [], "list_error": "AccessDeniedException"},
            cache=None,
            management=True,
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "could not be listed" in findings[0]["Finding_Details"]

    def test_short_key_names_enforce_nothing(self):
        findings = self._run(
            self._inventory(
                self._scp(
                    "ShortNames",
                    [
                        _scp_deny(
                            "sagemaker:Create*",
                            "Null",
                            "sagemaker:VolumeKmsKey",
                            "true",
                        ),
                        _scp_deny(
                            "sagemaker:Create*",
                            "Null",
                            "sagemaker:OutputKmsKey",
                            "true",
                        ),
                    ],
                )
            )
        )
        row = self._by_category(findings)["encryption"]
        assert row["Status"] == "Failed"
        assert "7 of 7 encryption requirements" in row["Finding_Details"]

    def test_a_key_guards_only_the_actions_it_is_paired_with(self):
        findings = self._run(
            self._inventory(
                self._scp(
                    "NotebookKeyOnly",
                    [
                        _scp_deny(
                            "sagemaker:CreateNotebookInstance",
                            "Null",
                            "sagemaker:VolumeKmsKeyArn",
                            "true",
                        )
                    ],
                )
            )
        )
        row = self._by_category(findings)["encryption"]
        assert row["Status"] == "Failed"
        assert "7 of 7 encryption requirements" in row["Finding_Details"]
        assert (
            "CreateTrainingJob on sagemaker:VolumeKmsKeyArn" in row["Finding_Details"]
        )
        assert "CreateNotebookInstance" not in row["Finding_Details"]

    def test_an_unattached_scp_does_not_guard_the_account(self):
        findings = self._run(
            self._inventory(
                self._scp("SageMakerNetwork", SCP_NETWORK_DENIES),
                targets=[{"TargetId": "ou-sandbox", "Type": "ORGANIZATIONAL_UNIT"}],
            )
        )
        row = self._by_category(findings)["approved network"]
        assert row["Status"] == "Failed"
        assert "not attached to this account" in row["Finding_Details"]

    def test_an_scp_attached_to_an_ou_above_the_account_guards_it(self):
        findings = self._run(
            self._inventory(
                self._scp("SageMakerNetwork", SCP_NETWORK_DENIES),
                targets=[{"TargetId": "ou-workloads", "Type": "ORGANIZATIONAL_UNIT"}],
            )
        )
        row = self._by_category(findings)["approved network"]
        assert row["Status"] == "Passed"
        assert "SageMakerNetwork" in row["Finding_Details"]

    def test_an_unread_account_path_is_not_read_not_failed(self):
        findings = self._run(
            self._inventory(self._scp("SageMakerNetwork", SCP_NETWORK_DENIES)),
            parents_error=_make_client_error("AccessDeniedException"),
        )
        assert [f["Status"] for f in findings] == ["N/A", "N/A", "N/A"]
        assert "organizations:ListParents" in findings[1]["Finding_Details"]

    def test_an_unread_attachment_is_not_read(self):
        inventory = self._inventory(self._scp("SageMakerNetwork", SCP_NETWORK_DENIES))
        del inventory["items"][0]["targets"]
        inventory["items"][0]["targets_error"] = "AccessDeniedException"
        row = self._by_category(self._run(inventory))["approved network"]
        assert row["Status"] == "N/A"
        assert "attachment of service control policy" in row["Finding_Details"]

    def test_an_unread_policy_document_blocks_the_failed_and_passed(self):
        inventory = self._inventory()
        inventory["errors"] = ["policy 'Hidden': AccessDenied"]
        findings = self._run(inventory)
        assert [f["Status"] for f in findings] == ["N/A", "N/A", "N/A"]
        assert "policy 'Hidden'" in findings[0]["Finding_Details"]

    def test_bool_false_without_ifexists_leaves_an_omitted_key_open(self):
        findings = self._run(
            self._inventory(
                self._scp(
                    "IsolationBool",
                    [
                        _scp_deny(
                            "sagemaker:Create*",
                            "Bool",
                            "sagemaker:NetworkIsolation",
                            "false",
                        )
                    ],
                )
            )
        )
        row = self._by_category(findings)["no direct internet access"]
        assert row["Status"] == "Failed"
        assert "does not deny a request that omits the key" in row["Finding_Details"]

    def test_neither_set_operator_alone_enforces_a_subnet_list(self):
        # ForAllValues admits a request that mixes subnet-1 with another
        # subnet, and ForAnyValue does not fire when the key is omitted.
        def network_row(*operators):
            return self._by_category(
                self._run(
                    self._inventory(
                        self._scp(
                            "SubnetAllowList",
                            [
                                _scp_deny(
                                    "sagemaker:Create*",
                                    operator,
                                    "sagemaker:VpcSubnets",
                                    ["subnet-1"] if operator != "Null" else "true",
                                )
                                for operator in operators
                            ],
                        )
                    )
                )
            )["approved network"]

        mixed = network_row("ForAllValues:StringNotEquals")
        assert mixed["Status"] == "Failed"
        assert "admits any value" in mixed["Finding_Details"]
        assert network_row("ForAnyValue:StringNotEquals")["Status"] == "Failed"
        assert network_row("Null")["Status"] == "Failed"
        paired = network_row("Null", "ForAnyValue:StringNotEquals")
        assert paired["Status"] == "Passed"
        assert "SubnetAllowList" in paired["Finding_Details"]

    @pytest.mark.parametrize(
        "operator,values",
        [
            ("StringNotEquals", ["subnet-1"]),
            ("StringNotLike", ["subnet-1"]),
            ("StringNotLike", ["subnet-*"]),
        ],
    )
    @pytest.mark.parametrize(
        "key", ["sagemaker:VpcSubnets", "sagemaker:VpcSecurityGroupIds"]
    )
    def test_a_bare_negated_operator_on_a_multivalued_key_earns_no_credit(
        self, operator, values, key
    ):
        # IAM defines a multivalued key only under ForAllValues or ForAnyValue.
        for statements in (
            [_scp_deny("sagemaker:Create*", operator, key, values)],
            [
                _scp_deny("sagemaker:Create*", "Null", key, "true"),
                _scp_deny("sagemaker:Create*", operator, key, values),
            ],
        ):
            row = self._by_category(
                self._run(self._inventory(self._scp("BareNegated", statements)))
            )["approved network"]
            assert row["Status"] == "N/A"
            assert (
                "operator IAM does not define for a multivalued key"
                in (row["Finding_Details"])
            )
            assert "BareNegated" in row["Finding_Details"]

    def test_the_documented_set_operator_pair_beside_a_bare_one_still_passes(self):
        documented = self._scp("Documented", SCP_NETWORK_DENIES)
        bare = self._scp(
            "BareNegated",
            [
                _scp_deny(
                    "sagemaker:Create*",
                    "StringNotEquals",
                    "sagemaker:VpcSubnets",
                    ["subnet-1"],
                )
            ],
        )
        for order in ((documented, bare), (bare, documented)):
            row = self._by_category(self._run(self._inventory(*order)))[
                "approved network"
            ]
            assert row["Status"] == "Passed"
            assert "'Documented'" in row["Finding_Details"]

    def test_a_deny_with_a_second_condition_or_narrow_resource_is_not_enforcing(self):
        conjunctive = _scp_deny(
            "sagemaker:Create*", "Null", "sagemaker:VpcSubnets", "true"
        )
        conjunctive["Condition"]["ArnNotLike"] = {
            "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlass"
        }
        narrow = _scp_deny(
            "sagemaker:Create*",
            "StringNotEquals",
            "sagemaker:VpcSubnets",
            ["subnet-1"],
            resource="arn:aws:sagemaker:*:*:training-job/team-a-*",
        )
        for statement in (conjunctive, narrow):
            row = self._by_category(
                self._run(self._inventory(self._scp("Scoped", [statement])))
            )["approved network"]
            assert row["Status"] == "N/A"
            assert "alongside other conditions" in row["Finding_Details"]

    def test_identity_conditions_on_every_principal_leave_the_root_user_open(self):
        cache = _creation_cache({"Builder": GUARDED_CREATE_ALLOWS})
        findings = self._run(self._inventory(), cache=cache)
        for finding in findings:
            _assert_open_only_to_root(finding)
        assert "every IAM role and user" in findings[0]["Finding_Details"]
        assert "not evaluated per principal" in findings[0]["Finding_Details"]

    def test_one_open_principal_among_two_fails_and_is_named(self):
        cache = _creation_cache(
            {"Builder": GUARDED_CREATE_ALLOWS, "Admin": [OPEN_SAGEMAKER_ALLOW]}
        )
        findings = self._run(self._inventory(), cache=cache)
        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Failed"]
        assert "Role 'Admin'" in findings[0]["Finding_Details"]
        assert "Role 'Builder'" not in findings[0]["Finding_Details"]

    def test_an_ifexists_allow_condition_does_not_guard(self):
        allow = {
            "Effect": "Allow",
            "Action": "sagemaker:CreateNotebookInstance",
            "Resource": "*",
            "Condition": {
                "StringEqualsIfExists": {"sagemaker:DirectInternetAccess": "Disabled"}
            },
        }
        cache = _creation_cache({"Builder": GUARDED_CREATE_ALLOWS[:2] + [allow]})
        row = self._by_category(self._run(self._inventory(), cache=cache))[
            "no direct internet access"
        ]
        assert row["Status"] == "Failed"
        assert "CreateNotebookInstance" in row["Finding_Details"]

    def test_a_guarding_permissions_boundary_intersects_an_open_policy(self):
        cache = _creation_cache(
            {"Admin": [OPEN_SAGEMAKER_ALLOW]},
            boundaries={"Admin": GUARDED_CREATE_ALLOWS},
        )
        findings = self._run(self._inventory(), cache=cache)
        for finding in findings:
            _assert_open_only_to_root(finding)

    def test_an_open_boundary_does_not_hide_an_open_policy(self):
        cache = _creation_cache(
            {"Admin": [OPEN_SAGEMAKER_ALLOW]},
            boundaries={"Admin": [OPEN_SAGEMAKER_ALLOW]},
        )
        findings = self._run(self._inventory(), cache=cache)
        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Failed"]

    def test_unread_principals_block_the_identity_pass_and_are_named(self):
        cache = _creation_cache(
            {"Builder": GUARDED_CREATE_ALLOWS},
            principal_errors=[
                {
                    "type": "role",
                    "name": "Hidden",
                    "stage": "list_attached_role_policies",
                    "error": "AccessDenied",
                }
            ],
        )
        findings = self._run(self._inventory(), cache=cache)
        assert [f["Status"] for f in findings] == ["N/A", "N/A", "N/A"]
        assert "role 'Hidden'" in findings[0]["Finding_Details"]

    def test_a_v1_cache_says_errors_were_not_recorded(self):
        cache = _creation_cache({"Builder": GUARDED_CREATE_ALLOWS}, version=1)
        findings = self._run(self._inventory(), cache=cache)
        for finding in findings:
            _assert_open_only_to_root(finding)
        assert (
            sagemaker_app.UNRECORDED_PRINCIPAL_ERRORS_NOTE
            in findings[0]["Finding_Details"]
        )

    def test_management_account_is_not_guarded_by_any_scp(self):
        inventory = self._inventory(
            self._scp(
                "SageMakerCreationGuardrails",
                SCP_ENCRYPTION_DENIES + SCP_NETWORK_DENIES + SCP_INTERNET_DENIES,
            )
        )
        findings = self._run(inventory, management=True)
        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Failed"]
        assert (
            "do not apply to the organization management account"
            in (findings[0]["Finding_Details"])
        )
        guarded = self._run(
            inventory,
            cache=_creation_cache({"Builder": GUARDED_CREATE_ALLOWS}),
            management=True,
        )
        for finding in guarded:
            _assert_open_only_to_root(finding)

    def test_inventory_reads_attachment_targets_for_every_policy(self):
        orgs = MagicMock()
        calls = []

        def get_paginator(operation_name):
            paginator = MagicMock()

            def paginate(**kwargs):
                calls.append((operation_name, kwargs))
                if operation_name == "list_policies":
                    return [
                        {"Policies": [{"Id": "p-1", "Name": "One"}]},
                        {"Policies": [{"Id": "p-2", "Name": "Two"}]},
                    ]
                if kwargs["PolicyId"] == "p-2":
                    raise _make_client_error("AccessDeniedException")
                return [
                    {"Targets": [{"TargetId": "ou-a", "Type": "ORGANIZATIONAL_UNIT"}]},
                    {"Targets": [{"TargetId": "r-root", "Type": "ROOT"}]},
                ]

            paginator.paginate.side_effect = paginate
            return paginator

        orgs.get_paginator.side_effect = get_paginator
        orgs.describe_policy.return_value = {"Policy": {"Content": "{}"}}
        with patch(
            "sagemaker_app.boto3.client",
            side_effect=_sm_client_factory(organizations=orgs),
        ):
            inventory = sagemaker_app.get_sagemaker_scp_inventory()
        first, second = inventory["items"]
        assert [t["TargetId"] for t in first["targets"]] == ["ou-a", "r-root"]
        assert second["targets_error"] == "AccessDeniedException"
        assert ("list_targets_for_policy", {"PolicyId": "p-2"}) in calls

    def test_account_path_walks_every_ou_to_the_root(self):
        tree = {
            "123456789012": [{"Id": "ou-inner", "Type": "ORGANIZATIONAL_UNIT"}],
            "ou-inner": [{"Id": "ou-outer", "Type": "ORGANIZATIONAL_UNIT"}],
            "ou-outer": [{"Id": "r-root", "Type": "ROOT"}],
        }
        with patch(
            "sagemaker_app.boto3.client",
            side_effect=_sm_client_factory(
                organizations=_orgs_path_client(parents=tree)
            ),
        ):
            path = sagemaker_app._sm_account_policy_path("123456789012")
        assert path == ["123456789012", "ou-inner", "ou-outer", "r-root"]


# ===================================================================
# AIR-FND-NET-01: a subnet id is not a privacy claim
# ===================================================================
def _subnet(subnet_id, vpc_id="vpc-1"):
    return {"SubnetId": subnet_id, "VpcId": vpc_id, "AvailabilityZone": "us-east-1a"}


def _route_table(route_table_id, routes, associations, vpc_id="vpc-1"):
    return {
        "RouteTableId": route_table_id,
        "VpcId": vpc_id,
        "OwnerId": "123456789012",
        "Associations": associations,
        "Routes": routes,
        "PropagatingVgws": [],
    }


LOCAL_ROUTE = {
    "DestinationCidrBlock": "10.0.0.0/16",
    "GatewayId": "local",
    "State": "active",
    "Origin": "CreateRouteTable",
}
IGW_ROUTE = {
    "DestinationCidrBlock": "0.0.0.0/0",
    "GatewayId": "igw-public1",
    "State": "active",
    "Origin": "CreateRoute",
}
NAT_ROUTE = {
    "DestinationCidrBlock": "0.0.0.0/0",
    "NatGatewayId": "nat-0abc",
    "State": "active",
    "Origin": "CreateRoute",
}


def _explicit(subnet_id, association_id="rtbassoc-1"):
    return [
        {
            "RouteTableAssociationId": association_id,
            "SubnetId": subnet_id,
            "Main": False,
            "AssociationState": {"State": "associated"},
        }
    ]


def _main_association():
    return [
        {
            "RouteTableAssociationId": "rtbassoc-main",
            "Main": True,
            "AssociationState": {"State": "associated"},
        }
    ]


def _ec2_exposure_client(subnets, route_tables):
    """An EC2 client whose paginators return DescribeSubnets/DescribeRouteTables."""
    ec2 = MagicMock()
    calls = {"describe_subnets": [], "describe_route_tables": []}

    def get_paginator(operation_name):
        if operation_name not in calls:
            raise AssertionError(f"unexpected ec2 paginator: {operation_name}")
        paginator = MagicMock()

        def paginate(**kwargs):
            calls[operation_name].append(kwargs)
            if operation_name == "describe_subnets":
                return [{"Subnets": subnets}]
            return [{"RouteTables": route_tables}]

        paginator.paginate.side_effect = paginate
        return paginator

    ec2.get_paginator.side_effect = get_paginator
    ec2.paginate_calls = calls
    return ec2


PUBLIC_SUBNET_FIXTURE = (
    [_subnet("subnet-public")],
    [_route_table("rtb-public", [LOCAL_ROUTE, IGW_ROUTE], _explicit("subnet-public"))],
)
PRIVATE_SUBNET_FIXTURE = (
    [_subnet("subnet-private")],
    [
        _route_table(
            "rtb-private", [LOCAL_ROUTE, NAT_ROUTE], _explicit("subnet-private")
        )
    ],
)


class TestResolveSubnetInternetExposure:
    """The route-table leg behind SM-10, SM-11, SM-28 and SM-33."""

    @patch("sagemaker_app.boto3.client")
    def test_no_subnets_makes_no_ec2_call(self, mock_client):
        exposure = sagemaker_app.resolve_subnet_internet_exposure([], "us-east-1")
        assert exposure == {
            "public": {},
            "private": set(),
            "unresolved": set(),
            "error": None,
        }
        mock_client.assert_not_called()

    @patch("sagemaker_app.boto3.client")
    def test_explicitly_associated_igw_route_is_public(self, mock_client):
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(*PUBLIC_SUBNET_FIXTURE)
        )
        exposure = sagemaker_app.resolve_subnet_internet_exposure(
            ["subnet-public"], "us-east-1"
        )
        assert exposure["public"] == {
            "subnet-public": {
                "gateway": "igw-public1",
                "destination": "0.0.0.0/0",
                "route_table": "rtb-public",
            }
        }
        assert exposure["private"] == set()
        assert exposure["unresolved"] == set()

    @patch("sagemaker_app.boto3.client")
    def test_unassociated_subnet_uses_the_vpc_main_route_table(self, mock_client):
        # A subnet with no explicit association routes through the main table, so
        # reading only explicit associations would call this subnet unresolved.
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(
                [_subnet("subnet-implicit")],
                [
                    _route_table(
                        "rtb-main", [LOCAL_ROUTE, IGW_ROUTE], _main_association()
                    )
                ],
            )
        )
        exposure = sagemaker_app.resolve_subnet_internet_exposure(
            ["subnet-implicit"], "us-east-1"
        )
        assert set(exposure["public"]) == {"subnet-implicit"}
        assert exposure["public"]["subnet-implicit"]["route_table"] == "rtb-main"

    @patch("sagemaker_app.boto3.client")
    def test_explicit_association_wins_over_the_main_route_table(self, mock_client):
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(
                [_subnet("subnet-private")],
                [
                    _route_table(
                        "rtb-main", [LOCAL_ROUTE, IGW_ROUTE], _main_association()
                    ),
                    _route_table(
                        "rtb-private",
                        [LOCAL_ROUTE, NAT_ROUTE],
                        _explicit("subnet-private"),
                    ),
                ],
            )
        )
        exposure = sagemaker_app.resolve_subnet_internet_exposure(
            ["subnet-private"], "us-east-1"
        )
        assert exposure["private"] == {"subnet-private"}
        assert exposure["public"] == {}

    @pytest.mark.parametrize(
        ("route", "label"),
        [
            (NAT_ROUTE, "nat gateway"),
            (
                {
                    "DestinationIpv6CidrBlock": "::/0",
                    "EgressOnlyInternetGatewayId": "eigw-0abc",
                    "State": "active",
                },
                "egress-only gateway",
            ),
            (
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-deleted",
                    "State": "blackhole",
                },
                "blackhole igw route",
            ),
            (
                {
                    "DestinationCidrBlock": "192.168.0.0/16",
                    "VpcPeeringConnectionId": "pcx-0abc",
                    "State": "active",
                },
                "peering connection",
            ),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_non_internet_gateway_routes_stay_private(self, mock_client, route, label):
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(
                [_subnet("subnet-private")],
                [
                    _route_table(
                        "rtb-private", [LOCAL_ROUTE, route], _explicit("subnet-private")
                    )
                ],
            )
        )
        exposure = sagemaker_app.resolve_subnet_internet_exposure(
            ["subnet-private"], "us-east-1"
        )
        assert exposure["private"] == {"subnet-private"}, label
        assert exposure["public"] == {}, label

    @patch("sagemaker_app.boto3.client")
    def test_ipv6_default_route_to_an_igw_is_public(self, mock_client):
        # The exposing route family is "any route to an igw-", not the one
        # 0.0.0.0/0 member of it.
        ipv6_route = {
            "DestinationIpv6CidrBlock": "::/0",
            "GatewayId": "igw-public1",
            "State": "active",
        }
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(
                [_subnet("subnet-v6")],
                [
                    _route_table(
                        "rtb-v6", [LOCAL_ROUTE, ipv6_route], _explicit("subnet-v6")
                    )
                ],
            )
        )
        exposure = sagemaker_app.resolve_subnet_internet_exposure(
            ["subnet-v6"], "us-east-1"
        )
        assert exposure["public"]["subnet-v6"]["destination"] == "::/0"

    @patch("sagemaker_app.boto3.client")
    def test_subnet_that_no_longer_exists_is_unresolved(self, mock_client):
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(*PUBLIC_SUBNET_FIXTURE)
        )
        exposure = sagemaker_app.resolve_subnet_internet_exposure(
            ["subnet-public", "subnet-deleted"], "us-east-1"
        )
        assert exposure["unresolved"] == {"subnet-deleted"}
        assert set(exposure["public"]) == {"subnet-public"}

    @patch("sagemaker_app.boto3.client")
    def test_subnet_with_no_applicable_route_table_is_unresolved(self, mock_client):
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client([_subnet("subnet-orphan")], [])
        )
        exposure = sagemaker_app.resolve_subnet_internet_exposure(
            ["subnet-orphan"], "us-east-1"
        )
        assert exposure["unresolved"] == {"subnet-orphan"}
        assert exposure["private"] == set()

    @patch("sagemaker_app.boto3.client")
    def test_access_denied_is_reported_as_an_error_label(self, mock_client):
        ec2 = MagicMock()
        ec2.get_paginator.side_effect = _make_client_error("AccessDeniedException")
        mock_client.side_effect = _sm_client_factory(ec2=ec2)
        exposure = sagemaker_app.resolve_subnet_internet_exposure(
            ["subnet-a"], "us-east-1"
        )
        assert exposure["error"] == "AccessDeniedException"
        assert exposure["public"] == {}

    @patch("sagemaker_app.boto3.client")
    def test_lookups_are_batched_not_one_call_per_subnet(self, mock_client):
        subnet_ids = [f"subnet-{index:04d}" for index in range(150)]
        ec2 = _ec2_exposure_client(
            [_subnet(subnet_id) for subnet_id in subnet_ids],
            [_route_table("rtb-main", [LOCAL_ROUTE], _main_association())],
        )
        mock_client.side_effect = _sm_client_factory(ec2=ec2)
        exposure = sagemaker_app.resolve_subnet_internet_exposure(
            subnet_ids, "us-east-1"
        )
        subnet_calls = ec2.paginate_calls["describe_subnets"]
        assert len(subnet_calls) == 2
        assert [len(call["Filters"][0]["Values"]) for call in subnet_calls] == [100, 50]
        assert ec2.paginate_calls["describe_route_tables"] == [
            {"Filters": [{"Name": "vpc-id", "Values": ["vpc-1"]}]}
        ]
        assert len(exposure["private"]) == 150


class TestSubnetExposureFindings:
    """One public resource must not cost the private ones their Passed row."""

    @patch("sagemaker_app.boto3.client")
    def test_public_resource_does_not_suppress_the_passed_row(self, mock_client):
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(
                [_subnet("subnet-public"), _subnet("subnet-private")],
                [
                    _route_table(
                        "rtb-public",
                        [LOCAL_ROUTE, IGW_ROUTE],
                        _explicit("subnet-public"),
                    ),
                    _route_table(
                        "rtb-private",
                        [LOCAL_ROUTE, NAT_ROUTE],
                        _explicit("subnet-private", "rtbassoc-2"),
                    ),
                ],
            )
        )
        findings = sagemaker_app._subnet_exposure_findings(
            check_id="SM-11",
            finding_name="SageMaker Model Subnet Internet Exposure",
            resources=[
                {"name": "Model 'open'", "subnets": ["subnet-public"]},
                {"name": "Model 'closed'", "subnets": ["subnet-private"]},
            ],
            region="us-east-1",
            reference=sagemaker_app.MODEL_VPC_ATTACHMENT_REFERENCE,
            resolution="Move it",
            severity="Medium",
        )
        statuses = [f["Status"] for f in findings]
        assert statuses.count("Failed") == 1
        assert statuses.count("Passed") == 1
        failed = next(f for f in findings if f["Status"] == "Failed")
        passed = next(f for f in findings if f["Status"] == "Passed")
        assert "Model 'open'" in failed["Finding_Details"]
        assert "igw-public1" in failed["Finding_Details"]
        assert "Model 'closed'" in passed["Finding_Details"]
        for finding in findings:
            assert_finding_schema(finding)

    @patch("sagemaker_app.boto3.client")
    def test_more_than_twenty_public_resources_are_summarised(self, mock_client):
        subnet_ids = [f"subnet-p{index:02d}" for index in range(25)]
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(
                [_subnet(subnet_id) for subnet_id in subnet_ids],
                [
                    _route_table(
                        "rtb-main", [LOCAL_ROUTE, IGW_ROUTE], _main_association()
                    )
                ],
            )
        )
        findings = sagemaker_app._subnet_exposure_findings(
            check_id="SM-33",
            finding_name=sagemaker_app.TRAINING_SUBNET_EXPOSURE_FINDING,
            resources=[
                {"name": f"Training job 'job-{index}'", "subnets": [subnet_id]}
                for index, subnet_id in enumerate(subnet_ids)
            ],
            region="us-east-1",
            reference=sagemaker_app.TRAINING_NETWORK_BOUNDARY_REFERENCE,
            resolution="Move it",
            severity="Medium",
        )
        failed = [f for f in findings if f["Status"] == "Failed"]
        assert len(failed) == 21
        assert "25 resource(s)" in failed[-1]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_unreadable_route_tables_are_na_not_passed(self, mock_client):
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client([_subnet("subnet-orphan")], [])
        )
        findings = sagemaker_app._subnet_exposure_findings(
            check_id="SM-10",
            finding_name="SageMaker Notebook Subnet Internet Exposure",
            resources=[
                {"name": "Notebook instance 'nb'", "subnets": ["subnet-orphan"]}
            ],
            region="us-east-1",
            reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
            resolution="Move it",
            severity="High",
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "subnet-orphan" in findings[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_ec2_failure_reports_one_incomplete_row(self, mock_client):
        ec2 = MagicMock()
        ec2.get_paginator.side_effect = _make_client_error("AccessDeniedException")
        mock_client.side_effect = _sm_client_factory(ec2=ec2)
        findings = sagemaker_app._subnet_exposure_findings(
            check_id="SM-28",
            finding_name="HyperPod Subnet Internet Exposure",
            resources=[
                {
                    "name": "HyperPod cluster 'c' instance group 'g'",
                    "subnets": ["subnet-a"],
                }
            ],
            region="us-east-1",
            reference="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-hyperpod-security.html",
            resolution="Move it",
            severity="Medium",
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "AccessDeniedException" in findings[0]["Finding_Details"]
        assert "ec2:DescribeRouteTables" in findings[0]["Resolution"]


class TestSubnetExposurePerCheck:
    """Each of SM-10, SM-11, SM-28 and SM-33 reads the route tables itself."""

    @staticmethod
    def _notebooks(mock_client, notebooks, ec2):
        mock_sm = MagicMock()
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "NotebookInstances": [
                    {"NotebookInstanceName": name} for name in notebooks
                ]
            }
        ]
        mock_sm.describe_notebook_instance.side_effect = lambda NotebookInstanceName: (
            notebooks[NotebookInstanceName]
        )
        mock_client.side_effect = _sm_client_factory(sagemaker=mock_sm, ec2=ec2)

    @patch("sagemaker_app.boto3.client")
    def test_sm10_notebook_in_a_public_subnet_is_failed(self, mock_client):
        self._notebooks(
            mock_client,
            {
                "nb-public": {
                    "NotebookInstanceName": "nb-public",
                    "SubnetId": "subnet-public",
                    "VpcId": "vpc-1",
                    "DirectInternetAccess": "Disabled",
                }
            },
            _ec2_exposure_client(*PUBLIC_SUBNET_FIXTURE),
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_notebook_vpc_deployment(region="us-east-1")
        )
        exposure_rows = [
            f
            for f in findings
            if f["Finding"] == "SageMaker Notebook Subnet Internet Exposure"
        ]
        assert [f["Status"] for f in exposure_rows] == ["Failed"]
        assert "nb-public" in exposure_rows[0]["Finding_Details"]
        assert "subnet-public" in exposure_rows[0]["Finding_Details"]
        assert "igw-public1" in exposure_rows[0]["Finding_Details"]
        for f in findings:
            assert f["Check_ID"] == "SM-10"
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_sm10_notebook_in_a_private_subnet_passes_both_legs(self, mock_client):
        self._notebooks(
            mock_client,
            {
                "nb-private": {
                    "NotebookInstanceName": "nb-private",
                    "SubnetId": "subnet-private",
                    "VpcId": "vpc-1",
                    "DirectInternetAccess": "Disabled",
                }
            },
            _ec2_exposure_client(*PRIVATE_SUBNET_FIXTURE),
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_notebook_vpc_deployment(region="us-east-1")
        )
        assert [f["Status"] for f in findings] == ["Passed", "Passed"]

    @staticmethod
    def _models(mock_client, details, ec2):
        mock_sm = MagicMock()
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Models": [{"ModelName": name} for name in details]}
        ]
        mock_sm.describe_model.side_effect = lambda ModelName: details[ModelName]
        mock_client.side_effect = _sm_client_factory(sagemaker=mock_sm, ec2=ec2)

    @patch("sagemaker_app.boto3.client")
    def test_sm11_model_in_a_public_subnet_is_failed(self, mock_client):
        self._models(
            mock_client,
            {
                "public-model": {
                    "EnableNetworkIsolation": True,
                    "VpcConfig": {
                        "Subnets": ["subnet-public"],
                        "SecurityGroupIds": ["sg-1"],
                    },
                }
            },
            _ec2_exposure_client(*PUBLIC_SUBNET_FIXTURE),
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_model_network_isolation(region="us-east-1")
        )
        exposure_rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.MODEL_SUBNET_EXPOSURE_FINDING
        ]
        assert [f["Status"] for f in exposure_rows] == ["Failed"]
        assert "Model 'public-model'" in exposure_rows[0]["Finding_Details"]
        assert "igw-public1" in exposure_rows[0]["Finding_Details"]
        attachment_rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.MODEL_VPC_ATTACHMENT_FINDING
        ]
        assert [f["Status"] for f in attachment_rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_sm11_passed_attachment_row_no_longer_asks_the_reader_to_confirm(
        self, mock_client
    ):
        self._models(
            mock_client,
            {
                "private-model": {
                    "EnableNetworkIsolation": True,
                    "VpcConfig": {
                        "Subnets": ["subnet-private"],
                        "SecurityGroupIds": ["sg-1"],
                    },
                }
            },
            _ec2_exposure_client(*PRIVATE_SUBNET_FIXTURE),
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_model_network_isolation(region="us-east-1")
        )
        attachment = next(
            f
            for f in findings
            if f["Finding"] == sagemaker_app.MODEL_VPC_ATTACHMENT_FINDING
        )
        exposure = next(
            f
            for f in findings
            if f["Finding"] == sagemaker_app.MODEL_SUBNET_EXPOSURE_FINDING
        )
        assert "Confirm those subnets are private" not in attachment["Finding_Details"]
        assert (
            "Confirm the subnets have no route to an internet gateway"
            not in attachment["Resolution"]
        )
        assert (
            sagemaker_app.MODEL_SUBNET_EXPOSURE_FINDING in attachment["Finding_Details"]
        )
        assert exposure["Status"] == "Passed"

    @staticmethod
    def _hyperpod_inventory(subnets, override=None):
        group = {"InstanceGroupName": "workers"}
        if override is not None:
            group["OverrideVpcConfig"] = override
        return {
            "items": [
                {
                    "summary": {"ClusterName": "cluster-1"},
                    "detail": {
                        "ClusterName": "cluster-1",
                        "VpcConfig": {
                            "Subnets": subnets,
                            "SecurityGroupIds": ["sg-1"],
                        },
                        "InstanceGroups": [group],
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }

    @patch("sagemaker_app.boto3.client")
    def test_sm28_instance_group_in_a_public_subnet_is_failed(self, mock_client):
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(*PUBLIC_SUBNET_FIXTURE)
        )
        findings = extract_csv_data(
            sagemaker_app.check_hyperpod_vpc_configuration(
                "us-east-1", self._hyperpod_inventory(["subnet-public"])
            )
        )
        exposure_rows = [
            f for f in findings if f["Finding"] == "HyperPod Subnet Internet Exposure"
        ]
        assert [f["Status"] for f in exposure_rows] == ["Failed"]
        assert "instance group 'workers'" in exposure_rows[0]["Finding_Details"]
        assert "igw-public1" in exposure_rows[0]["Finding_Details"]
        assert [
            f["Status"]
            for f in findings
            if f["Finding"] == "HyperPod VPC Configuration"
        ] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_sm28_reads_the_override_subnets_not_the_cluster_subnets(self, mock_client):
        mock_client.side_effect = _sm_client_factory(
            ec2=_ec2_exposure_client(
                [_subnet("subnet-public"), _subnet("subnet-private")],
                [
                    _route_table(
                        "rtb-public",
                        [LOCAL_ROUTE, IGW_ROUTE],
                        _explicit("subnet-public"),
                    ),
                    _route_table(
                        "rtb-private",
                        [LOCAL_ROUTE, NAT_ROUTE],
                        _explicit("subnet-private", "rtbassoc-2"),
                    ),
                ],
            )
        )
        findings = extract_csv_data(
            sagemaker_app.check_hyperpod_vpc_configuration(
                "us-east-1",
                self._hyperpod_inventory(
                    ["subnet-private"],
                    override={
                        "Subnets": ["subnet-public"],
                        "SecurityGroupIds": ["sg-2"],
                    },
                ),
            )
        )
        exposure_rows = [
            f for f in findings if f["Finding"] == "HyperPod Subnet Internet Exposure"
        ]
        assert [f["Status"] for f in exposure_rows] == ["Failed"]
        assert "subnet-public" in exposure_rows[0]["Finding_Details"]

    @staticmethod
    def _jobs(mock_client, jobs, ec2):
        mock_sm = MagicMock()
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"TrainingJobSummaries": [{"TrainingJobName": name} for name in jobs]}
        ]
        mock_sm.describe_training_job.side_effect = lambda TrainingJobName: jobs[
            TrainingJobName
        ]
        mock_client.side_effect = _sm_client_factory(sagemaker=mock_sm, ec2=ec2)

    @patch("sagemaker_app.boto3.client")
    def test_sm33_training_job_in_a_public_subnet_is_failed(self, mock_client):
        self._jobs(
            mock_client,
            {
                "public-job": {
                    "VpcConfig": {
                        "Subnets": ["subnet-public"],
                        "SecurityGroupIds": ["sg-1"],
                    },
                    "EnableNetworkIsolation": True,
                }
            },
            _ec2_exposure_client(*PUBLIC_SUBNET_FIXTURE),
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_training_job_network_boundary(
                region="us-east-1"
            )
        )
        exposure_rows = [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.TRAINING_SUBNET_EXPOSURE_FINDING
        ]
        assert [f["Status"] for f in exposure_rows] == ["Failed"]
        assert "Training job 'public-job'" in exposure_rows[0]["Finding_Details"]
        assert "igw-public1" in exposure_rows[0]["Finding_Details"]
        for f in findings:
            assert f["Check_ID"] == "SM-33"
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_sm33_passed_boundary_row_no_longer_asks_the_reader_to_confirm(
        self, mock_client
    ):
        self._jobs(
            mock_client,
            {
                "private-job": {
                    "VpcConfig": {
                        "Subnets": ["subnet-private"],
                        "SecurityGroupIds": ["sg-1"],
                    },
                    "EnableNetworkIsolation": True,
                }
            },
            _ec2_exposure_client(*PRIVATE_SUBNET_FIXTURE),
        )
        findings = extract_csv_data(
            sagemaker_app.check_sagemaker_training_job_network_boundary(
                region="us-east-1"
            )
        )
        boundary = next(
            f
            for f in findings
            if f["Finding"] == sagemaker_app.TRAINING_NETWORK_BOUNDARY_FINDING
        )
        exposure = next(
            f
            for f in findings
            if f["Finding"] == sagemaker_app.TRAINING_SUBNET_EXPOSURE_FINDING
        )
        assert "Whether those subnets are private" not in boundary["Finding_Details"]
        assert (
            "Confirm the subnets have no route to an internet gateway"
            not in boundary["Resolution"]
        )
        assert exposure["Status"] == "Passed"
        assert "Training job 'private-job'" in exposure["Finding_Details"]


# ===================================================================
# AISF scope-27: SM-02 service-wide grant leg and SM-35..SM-41
# ===================================================================
def _pager(pages_by_operation):
    """Build a get_paginator side effect from {operation: pages or callable}.

    A callable receives the paginate kwargs and returns the pages, so a
    per-resource paginator can return different pages per resource. A raised
    exception inside the callable surfaces from paginate().
    """

    def get_paginator(operation):
        source = pages_by_operation[operation]
        paginator = MagicMock()

        def paginate(**kwargs):
            pages = source(**kwargs) if callable(source) else source
            return iter(pages)

        paginator.paginate.side_effect = paginate
        return paginator

    return get_paginator


def _rows(result):
    rows = extract_csv_data(result)
    for row in rows:
        assert_finding_schema(row)
    return rows


class TestSM02ServiceWideGrant:
    """AIR-FND-IAM-09: SM-02 reports sagemaker:* and NotAction Allow grants."""

    @staticmethod
    def _grant_rows(cache):
        with patch("sagemaker_app.boto3.client") as mock_client:
            mock_client.return_value = MagicMock()
            # The stale-user leg polls this job once a second until COMPLETED.
            mock_client.return_value.get_service_last_accessed_details.return_value = {
                "JobStatus": "COMPLETED",
                "ServicesLastAccessed": [],
            }
            findings = _rows(
                sagemaker_app.check_sagemaker_iam_permissions(cache, region="Global")
            )
        return [
            f
            for f in findings
            if f["Finding"] == sagemaker_app.SERVICE_WIDE_GRANT_FINDING
        ]

    def test_scoped_role_first_and_service_wide_role_second_fails_only_second(self):
        cache = _role_cache(
            {
                "ReadOnlyRole": [
                    ("DescribeOnly", _identity_policy("sagemaker:Describe*", "*"))
                ],
                "EverythingRole": [
                    ("AllSageMaker", _identity_policy("sagemaker:*", "*"))
                ],
            }
        )
        rows = self._grant_rows(cache)
        assert [f["Status"] for f in rows] == ["Failed"]
        assert "Role 'EverythingRole'" in rows[0]["Finding_Details"]
        assert "AllSageMaker" in rows[0]["Finding_Details"]
        assert "Action 'sagemaker:*'" in rows[0]["Finding_Details"]
        assert rows[0]["Severity"] == "High"
        assert rows[0]["Region"] == "Global"

    def test_only_scoped_grants_is_passed_with_policy_count(self):
        cache = _role_cache(
            {
                "RoleA": [("A", _identity_policy("sagemaker:DescribeEndpoint", "*"))],
                "RoleB": [("B", _identity_policy("s3:GetObject", "*"))],
            }
        )
        rows = self._grant_rows(cache)
        assert [f["Status"] for f in rows] == ["Passed"]
        assert (
            "None of the 2 customer-managed, inline or group"
            in rows[0]["Finding_Details"]
        )

    def test_notaction_allow_reaches_sagemaker_and_fails(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}],
        }
        rows = self._grant_rows(_role_cache({"NotActionRole": [("NA", document)]}))
        assert [f["Status"] for f in rows] == ["Failed"]
        assert "NotAction ['iam:*']" in rows[0]["Finding_Details"]

    def test_notaction_excluding_sagemaker_is_not_a_grant(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "NotAction": "sagemaker:*", "Resource": "*"}
            ],
        }
        rows = self._grant_rows(_role_cache({"ExcludesRole": [("EX", document)]}))
        assert [f["Status"] for f in rows] == ["Passed"]

    def test_bare_star_grants_every_sagemaker_action(self):
        rows = self._grant_rows(
            _role_cache({"AdminRole": [("Admin", _identity_policy("*", "*"))]})
        )
        assert [f["Status"] for f in rows] == ["Failed"]
        assert "Role 'AdminRole'" in rows[0]["Finding_Details"]
        assert "Action '*'" in rows[0]["Finding_Details"]

    def test_aws_managed_policy_is_excluded(self):
        cache = {
            "role_permissions": {
                "ManagedRole": {
                    "attached_policies": [
                        {
                            "name": "AmazonSageMakerFullAccess",
                            "arn": "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
                            "document": _identity_policy("sagemaker:*", "*"),
                        }
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }
        rows = self._grant_rows(cache)
        assert [f["Status"] for f in rows] == ["Passed"]
        assert "None of the 0 customer-managed" in rows[0]["Finding_Details"]

    def test_inline_user_policy_with_mixed_case_and_prefix_wildcard_fails(self):
        cache = {
            "role_permissions": {},
            "user_permissions": {
                "alice": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "scoped",
                            "document": _identity_policy("sagemaker:List*", "*"),
                        },
                        {
                            "name": "prefix",
                            "document": _identity_policy("SageMaker*", "*"),
                        },
                    ],
                }
            },
        }
        rows = self._grant_rows(cache)
        assert [f["Status"] for f in rows] == ["Failed"]
        assert "User 'alice'" in rows[0]["Finding_Details"]
        assert "'prefix'" in rows[0]["Finding_Details"]

    def test_deny_sagemaker_star_is_not_a_grant(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "sagemaker:*", "Resource": "*"}],
        }
        rows = self._grant_rows(_role_cache({"DenyRole": [("D", document)]}))
        assert [f["Status"] for f in rows] == ["Passed"]

    def test_more_than_twenty_violations_adds_an_overflow_row(self):
        cache = _role_cache(
            {
                f"Role{index:02d}": [("All", _identity_policy("sagemaker:*", "*"))]
                for index in range(21)
            }
        )
        rows = self._grant_rows(cache)
        assert len(rows) == 21
        assert all(f["Status"] == "Failed" for f in rows)
        assert rows[-1]["Finding_Details"].startswith("21 customer-managed")


class TestSM35SecurityServiceDelegatedAdmin:
    """AIR-FND-ACC-09: one row per security service, from a fixed list."""

    MANAGEMENT = "111122223333"
    SECURITY = "444455556666"

    def _client(self, pages_by_principal, trusted_access=None):
        client = MagicMock()
        client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": self.MANAGEMENT}
        }

        def pages(ServicePrincipal):
            value = pages_by_principal[ServicePrincipal]
            if isinstance(value, Exception):
                raise value
            return value

        if trusted_access is None:
            trusted_access = [
                {
                    "EnabledServicePrincipals": [
                        {"ServicePrincipal": principal}
                        for _, principal in sagemaker_app.SECURITY_SERVICE_PRINCIPALS
                    ]
                }
            ]

        def enabled_pages():
            if isinstance(trusted_access, Exception):
                raise trusted_access
            return trusted_access

        client.get_paginator.side_effect = _pager(
            {
                "list_delegated_administrators": pages,
                "list_aws_service_access_for_organization": enabled_pages,
            }
        )
        return client

    @patch("sagemaker_app.boto3.client")
    def test_one_row_per_service_across_every_outcome(self, mock_client):
        active = {"Id": self.SECURITY, "Status": "ACTIVE"}
        mock_client.return_value = self._client(
            {
                "guardduty.amazonaws.com": [{"DelegatedAdministrators": [active]}],
                "securityhub.amazonaws.com": [{"DelegatedAdministrators": []}],
                "inspector2.amazonaws.com": _make_client_error("AccessDeniedException"),
                "macie.amazonaws.com": [
                    {
                        "DelegatedAdministrators": [
                            {"Id": self.MANAGEMENT, "Status": "ACTIVE"}
                        ]
                    }
                ],
                "config.amazonaws.com": [
                    {
                        "DelegatedAdministrators": [
                            {"Id": self.SECURITY, "Status": "PENDING_ACTIVATION"}
                        ]
                    }
                ],
                "config-multiaccountsetup.amazonaws.com": [
                    {"DelegatedAdministrators": [active]}
                ],
                # The active admin arrives on the second page.
                "access-analyzer.amazonaws.com": [
                    {"DelegatedAdministrators": []},
                    {"DelegatedAdministrators": [active]},
                ],
                "cloudtrail.amazonaws.com": [{"DelegatedAdministrators": [active]}],
                "detective.amazonaws.com": [{"DelegatedAdministrators": [active]}],
                "securitylake.amazonaws.com": [{"DelegatedAdministrators": []}],
                "fms.amazonaws.com": [{"DelegatedAdministrators": [active]}],
                "auditmanager.amazonaws.com": [
                    {
                        "DelegatedAdministrators": [
                            {"Id": self.MANAGEMENT, "Status": "ACTIVE"}
                        ]
                    }
                ],
            }
        )
        rows = _rows(
            sagemaker_app.check_security_service_delegated_admin(region="Global")
        )
        assert [r["Status"] for r in rows] == [
            "Passed",
            "Failed",
            "N/A",
            "Failed",
            "Failed",
            "Passed",
            "Passed",
            "Passed",
            "Passed",
            "Failed",
            "Passed",
            "Failed",
            "Failed",
        ]
        assert "config-multiaccountsetup.amazonaws.com" in rows[5]["Finding_Details"]
        assert all(r["Check_ID"] == "SM-35" for r in rows)
        assert all(
            "Services checked (fixed list): Amazon GuardDuty" in r["Finding_Details"]
            for r in rows[:-1]
        )
        assert rows[-1]["Finding"] == (
            sagemaker_app.DELEGATED_ADMIN_CONSOLIDATION_FINDING
        )
        assert self.SECURITY in rows[0]["Finding_Details"]
        assert "No active delegated administrator" in rows[1]["Finding_Details"]
        assert "readable only from the management account" in rows[2]["Finding_Details"]
        assert rows[2]["Severity"] == "Informational"
        assert "is the organization management account" in rows[3]["Finding_Details"]
        assert "No active delegated administrator" in rows[4]["Finding_Details"]
        assert rows[1]["Severity"] == "High"

    @patch("sagemaker_app.boto3.client")
    def test_dedicated_admin_beside_management_account_passes(self, mock_client):
        both = [
            {"Id": self.MANAGEMENT, "Status": "ACTIVE"},
            {"Id": self.SECURITY, "Status": "ACTIVE"},
        ]
        mock_client.return_value = self._client(
            {
                principal: [{"DelegatedAdministrators": both}]
                for _, principal in sagemaker_app.SECURITY_SERVICE_PRINCIPALS
            }
        )
        rows = _rows(sagemaker_app.check_security_service_delegated_admin())
        assert [r["Status"] for r in rows] == ["Passed"] * 13
        assert self.MANAGEMENT not in rows[0]["Finding_Details"].split(".")[0]
        assert (
            f"one non-management account {self.SECURITY}"
            in (rows[-1]["Finding_Details"])
        )

    @patch("sagemaker_app.boto3.client")
    def test_non_access_error_is_could_not_assess_without_access_reason(
        self, mock_client
    ):
        pages = {
            principal: [{"DelegatedAdministrators": []}]
            for _, principal in sagemaker_app.SECURITY_SERVICE_PRINCIPALS
        }
        pages["guardduty.amazonaws.com"] = _make_client_error("TooManyRequests")
        mock_client.return_value = self._client(pages)
        rows = _rows(sagemaker_app.check_security_service_delegated_admin())
        assert len(rows) == 13
        assert_could_not_assess_finding(rows[0])
        assert "readable only from" not in rows[0]["Finding_Details"]
        assert rows[1]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_organizations_not_in_use_is_one_na_row(self, mock_client):
        client = MagicMock()
        client.describe_organization.side_effect = _make_client_error(
            "AWSOrganizationsNotInUseException"
        )
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_security_service_delegated_admin())
        assert len(rows) == 1
        assert rows[0]["Status"] == "N/A"
        assert "not in use" in rows[0]["Finding_Details"]
        client.get_paginator.assert_not_called()

    @patch("sagemaker_app.boto3.client")
    def test_describe_organization_access_denied_is_could_not_assess(self, mock_client):
        client = MagicMock()
        client.describe_organization.side_effect = _make_client_error(
            "AccessDeniedException"
        )
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_security_service_delegated_admin())
        assert len(rows) == 1
        assert_could_not_assess_finding(rows[0])


class TestSM35TrustedAccess:
    """AIR-FND-ACC-09: a delegated administrator passes only with trusted access."""

    MANAGEMENT = TestSM35SecurityServiceDelegatedAdmin.MANAGEMENT
    SECURITY = TestSM35SecurityServiceDelegatedAdmin.SECURITY

    def _rows(self, mock_client, trusted_access, admin_overrides=None):
        pages = {
            principal: [
                {"DelegatedAdministrators": [{"Id": self.SECURITY, "Status": "ACTIVE"}]}
            ]
            for _, principal in sagemaker_app.SECURITY_SERVICE_PRINCIPALS
        }
        pages.update(admin_overrides or {})
        mock_client.return_value = TestSM35SecurityServiceDelegatedAdmin()._client(
            pages, trusted_access
        )
        return _rows(sagemaker_app.check_security_service_delegated_admin())

    @staticmethod
    def _enabled(*excluded):
        return [
            {
                "EnabledServicePrincipals": [
                    {"ServicePrincipal": principal}
                    for _, principal in sagemaker_app.SECURITY_SERVICE_PRINCIPALS
                    if principal not in excluded
                ]
            }
        ]

    @staticmethod
    def _service_rows(rows):
        return {
            principal: [
                r for r in rows[:-1] if f"({principal})" in r["Finding_Details"]
            ]
            for _, principal in sagemaker_app.SECURITY_SERVICE_PRINCIPALS
        }

    @patch("sagemaker_app.boto3.client")
    def test_an_administrator_without_trusted_access_fails(self, mock_client):
        rows = self._rows(mock_client, self._enabled("guardduty.amazonaws.com"))
        by_principal = self._service_rows(rows)
        guardduty = by_principal.pop("guardduty.amazonaws.com")
        assert [r["Status"] for r in guardduty] == ["Failed"]
        assert (
            "Trusted access for guardduty.amazonaws.com is not enabled"
            in guardduty[0]["Finding_Details"]
        )
        assert self.SECURITY in guardduty[0]["Finding_Details"]
        assert "Enable trusted access" in guardduty[0]["Resolution"]
        assert all(
            [r["Status"] for r in v] == ["Passed"] for v in by_principal.values()
        )

    @patch("sagemaker_app.boto3.client")
    def test_an_unconfirmed_principal_name_is_named_on_its_failure(self, mock_client):
        unconfirmed = (
            "macie.amazonaws.com",
            "detective.amazonaws.com",
            "fms.amazonaws.com",
            "auditmanager.amazonaws.com",
        )
        rows = self._rows(
            mock_client, self._enabled("guardduty.amazonaws.com", *unconfirmed)
        )
        by_principal = self._service_rows(rows)
        for principal in unconfirmed:
            (row,) = by_principal[principal]
            assert row["Status"] == "Failed"
            assert (
                f"The trusted-access principal name {principal} is not confirmed "
                "by a live read" in row["Finding_Details"]
            )
        (guardduty,) = by_principal["guardduty.amazonaws.com"]
        assert guardduty["Status"] == "Failed"
        assert "not confirmed by a live read" not in guardduty["Finding_Details"]
        # A principal the read returned is confirmed by that read.
        passed = self._service_rows(self._rows(mock_client, self._enabled()))
        assert (
            "not confirmed" not in passed["macie.amazonaws.com"][0]["Finding_Details"]
        )

    @patch("sagemaker_app.boto3.client")
    def test_each_service_without_trusted_access_fails_on_its_own_row(
        self, mock_client
    ):
        off = ("guardduty.amazonaws.com", "cloudtrail.amazonaws.com")
        rows = self._rows(mock_client, self._enabled(*off))
        statuses = {
            p: [r["Status"] for r in v] for p, v in self._service_rows(rows).items()
        }
        assert {p for p, s in statuses.items() if s == ["Failed"]} == set(off)
        assert all(s == ["Passed"] for p, s in statuses.items() if p not in off)

    @patch("sagemaker_app.boto3.client")
    def test_a_principal_enabled_on_the_second_page_passes(self, mock_client):
        pages = self._enabled("guardduty.amazonaws.com") + [
            {
                "EnabledServicePrincipals": [
                    {"ServicePrincipal": "guardduty.amazonaws.com"}
                ]
            }
        ]
        rows = self._rows(mock_client, pages)
        assert [r["Status"] for r in rows[:-1]] == ["Passed"] * 12

    @patch("sagemaker_app.boto3.client")
    def test_the_passed_row_states_trusted_access_is_enabled(self, mock_client):
        rows = self._rows(mock_client, self._enabled())
        assert (
            "Trusted access for guardduty.amazonaws.com is enabled"
            in rows[0]["Finding_Details"]
        )

    @patch("sagemaker_app.boto3.client")
    def test_unread_trusted_access_withholds_every_pass(self, mock_client):
        rows = self._rows(
            mock_client,
            _make_client_error("AccessDeniedException"),
            {
                "securityhub.amazonaws.com": [{"DelegatedAdministrators": []}],
                "macie.amazonaws.com": [
                    {
                        "DelegatedAdministrators": [
                            {"Id": self.MANAGEMENT, "Status": "ACTIVE"}
                        ]
                    }
                ],
            },
        )
        by_principal = self._service_rows(rows)
        assert [r["Status"] for r in by_principal.pop("securityhub.amazonaws.com")] == [
            "Failed"
        ]
        assert [r["Status"] for r in by_principal.pop("macie.amazonaws.com")] == [
            "Failed"
        ]
        for service_rows in by_principal.values():
            assert [r["Status"] for r in service_rows] == ["N/A"]
            details = service_rows[0]["Finding_Details"]
            assert "organizations:ListAWSServiceAccessForOrganization" in details
            assert "AccessDeniedException" in details
            assert self.SECURITY in details

    @patch("sagemaker_app.boto3.client")
    def test_no_administrator_and_no_trusted_access_keeps_the_admin_failure(
        self, mock_client
    ):
        rows = self._rows(
            mock_client,
            self._enabled("detective.amazonaws.com"),
            {"detective.amazonaws.com": [{"DelegatedAdministrators": []}]},
        )
        detective = self._service_rows(rows)["detective.amazonaws.com"]
        assert [r["Status"] for r in detective] == ["Failed"]
        assert "No active delegated administrator" in detective[0]["Finding_Details"]


class TestSM35DelegatedAdminConsolidation:
    """AIR-FND-ACC-09: every security service shares one tooling account."""

    MANAGEMENT = "111122223333"
    SECURITY = "444455556666"
    OTHER = "777788889999"

    def _rows(self, mock_client, overrides=None):
        pages = {
            principal: [
                {"DelegatedAdministrators": [{"Id": self.SECURITY, "Status": "ACTIVE"}]}
            ]
            for _, principal in sagemaker_app.SECURITY_SERVICE_PRINCIPALS
        }
        pages.update(overrides or {})
        mock_client.return_value = TestSM35SecurityServiceDelegatedAdmin()._client(
            pages
        )
        return _rows(sagemaker_app.check_security_service_delegated_admin())

    def test_cloudtrail_is_a_checked_service(self):
        assert ("AWS CloudTrail", "cloudtrail.amazonaws.com") in (
            sagemaker_app.SECURITY_SERVICE_PRINCIPALS
        )

    @pytest.mark.parametrize(
        "service",
        [
            ("Amazon Detective", "detective.amazonaws.com"),
            ("Amazon Security Lake", "securitylake.amazonaws.com"),
            ("AWS Firewall Manager", "fms.amazonaws.com"),
            ("AWS Audit Manager", "auditmanager.amazonaws.com"),
        ],
    )
    def test_acc09_services_are_checked(self, service):
        assert service in sagemaker_app.SECURITY_SERVICE_PRINCIPALS

    def test_config_multi_account_setup_is_a_checked_service(self):
        # Config rules and conformance packs are delegated through their own
        # principal, apart from the aggregator's config.amazonaws.com.
        assert (
            "AWS Config multi-account setup",
            "config-multiaccountsetup.amazonaws.com",
        ) in sagemaker_app.SECURITY_SERVICE_PRINCIPALS

    @pytest.mark.parametrize(
        "management, dedicated",
        [
            ("config-multiaccountsetup.amazonaws.com", "config.amazonaws.com"),
            ("config.amazonaws.com", "config-multiaccountsetup.amazonaws.com"),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_each_config_principal_is_judged_on_its_own_administrator(
        self, mock_client, management, dedicated
    ):
        rows = self._rows(
            mock_client,
            {
                management: [
                    {
                        "DelegatedAdministrators": [
                            {"Id": self.MANAGEMENT, "Status": "ACTIVE"}
                        ]
                    }
                ]
            },
        )
        by_principal = {
            principal: [r for r in rows if f"({principal})" in r["Finding_Details"]]
            for principal in (management, dedicated)
        }
        assert [r["Status"] for r in by_principal[management]] == ["Failed"]
        assert [r["Status"] for r in by_principal[dedicated]] == ["Passed"]
        assert rows[-1]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_a_management_administered_audit_manager_fails(self, mock_client):
        rows = self._rows(
            mock_client,
            {
                "auditmanager.amazonaws.com": [
                    {
                        "DelegatedAdministrators": [
                            {"Id": self.MANAGEMENT, "Status": "ACTIVE"}
                        ]
                    }
                ]
            },
        )
        audit = [r for r in rows if "AWS Audit Manager (" in r["Finding_Details"]]
        assert [r["Status"] for r in audit] == ["Failed"]
        assert rows[-1]["Status"] == "Failed"
        assert "AWS Audit Manager" in rows[-1]["Finding_Details"].split(".")[0]

    @patch("sagemaker_app.boto3.client")
    def test_one_shared_administrator_passes(self, mock_client):
        rows = self._rows(mock_client)
        assert rows[-1]["Status"] == "Passed"
        assert "12 security services" in rows[-1]["Finding_Details"]
        assert "not recorded by any Organizations API" in rows[-1]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_one_service_on_a_different_account_fails(self, mock_client):
        rows = self._rows(
            mock_client,
            {
                "inspector2.amazonaws.com": [
                    {
                        "DelegatedAdministrators": [
                            {"Id": self.OTHER, "Status": "ACTIVE"}
                        ]
                    }
                ]
            },
        )
        # Every per-service row passes; only the cross-service row sees the split.
        assert [r["Status"] for r in rows[:-1]] == ["Passed"] * 12
        assert rows[-1]["Status"] == "Failed"
        assert f"account {self.OTHER}: Amazon Inspector" in rows[-1]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_split_on_a_later_page_fails(self, mock_client):
        rows = self._rows(
            mock_client,
            {
                "cloudtrail.amazonaws.com": [
                    {"DelegatedAdministrators": []},
                    {
                        "DelegatedAdministrators": [
                            {"Id": self.OTHER, "Status": "ACTIVE"}
                        ]
                    },
                ]
            },
        )
        assert rows[-1]["Status"] == "Failed"
        assert f"account {self.OTHER}: AWS CloudTrail" in rows[-1]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_unread_service_is_incomplete_not_passed(self, mock_client):
        rows = self._rows(
            mock_client,
            {"cloudtrail.amazonaws.com": _make_client_error("AccessDeniedException")},
        )
        assert rows[-1]["Status"] == "N/A"
        assert rows[-1]["Finding"].endswith("Incomplete")
        assert "AWS CloudTrail" in rows[-1]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_service_with_only_the_management_account_fails(self, mock_client):
        rows = self._rows(
            mock_client,
            {
                "macie.amazonaws.com": [
                    {
                        "DelegatedAdministrators": [
                            {"Id": self.MANAGEMENT, "Status": "ACTIVE"}
                        ]
                    }
                ]
            },
        )
        assert rows[-1]["Status"] == "Failed"
        assert "Amazon Macie" in rows[-1]["Finding_Details"]


class TestSM36SecurityHubAIStandard:
    """AIR-FND-DET-02: the AI Security Best Practices v1.0.0 standard."""

    AI_ARN = (
        "arn:aws:securityhub:us-east-1::standards/ai-security-best-practices/v/1.0.0"
    )
    FSBP_ARN = (
        "arn:aws:securityhub:us-east-1::standards/"
        "aws-foundational-security-best-practices/v/1.0.0"
    )

    def _run(
        self, mock_client, pages=None, error=None, configuration=None, association=None
    ):
        client = MagicMock()
        if association is not None:
            client.get_caller_identity.return_value = {"Account": "123456789012"}
            if isinstance(association, Exception):
                client.get_configuration_policy_association.side_effect = association
            else:
                client.get_configuration_policy_association.return_value = association
        if error is not None:
            client.get_paginator.side_effect = error
        else:
            client.get_paginator.side_effect = _pager({"get_enabled_standards": pages})
        if isinstance(configuration, Exception):
            client.describe_organization_configuration.side_effect = configuration
        else:
            client.describe_organization_configuration.return_value = {
                "OrganizationConfiguration": configuration
                or {"ConfigurationType": "LOCAL", "Status": "ENABLED"}
            }
        mock_client.return_value = client
        return _rows(sagemaker_app.check_security_hub_ai_standard(region="us-east-1"))

    def _central(self, mock_client, configuration, association=None):
        rows = self._run(
            mock_client,
            [
                {
                    "StandardsSubscriptions": [
                        {"StandardsArn": self.AI_ARN, "StandardsStatus": "READY"}
                    ]
                }
            ],
            configuration=configuration,
            association=association,
        )
        assert rows[0]["Status"] == "Passed"
        assert len(rows) == 2
        assert rows[1]["Check_ID"] == "SM-36"
        return rows[1]

    @patch("sagemaker_app.boto3.client")
    def test_local_configuration_fails(self, mock_client):
        row = self._central(
            mock_client, {"ConfigurationType": "LOCAL", "Status": "ENABLED"}
        )
        assert row["Finding"] == sagemaker_app.CENTRAL_CONFIGURATION_FINDING
        assert row["Status"] == "Failed"
        assert "ConfigurationType LOCAL" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_central_enabled_is_incomplete_while_the_association_is_unread(
        self, mock_client
    ):
        row = self._central(
            mock_client, {"ConfigurationType": "CENTRAL", "Status": "ENABLED"}
        )
        assert row["Status"] == "N/A"
        assert row["Finding"].endswith("Incomplete")
        assert "GetConfigurationPolicyAssociation" in row["Finding_Details"]

    def _association(self, mock_client, association):
        row = self._central(
            mock_client,
            {"ConfigurationType": "CENTRAL", "Status": "ENABLED"},
            association=association,
        )
        call = mock_client.return_value.get_configuration_policy_association
        assert call.call_args.kwargs == {"Target": {"AccountId": "123456789012"}}
        return row

    @pytest.mark.parametrize("how", ["APPLIED", "INHERITED"])
    @patch("sagemaker_app.boto3.client")
    def test_self_managed_association_fails(self, mock_client, how):
        row = self._association(
            mock_client,
            {
                "ConfigurationPolicyId": "SELF_MANAGED_SECURITY_HUB",
                "AssociationType": how,
                "AssociationStatus": "SUCCESS",
            },
        )
        assert row["Status"] == "Failed"
        assert "self-managed" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_failed_association_fails(self, mock_client):
        row = self._association(
            mock_client,
            {
                "ConfigurationPolicyId": "a1b2",
                "AssociationType": "APPLIED",
                "AssociationStatus": "FAILED",
                "AssociationStatusMessage": "boom",
            },
        )
        assert row["Status"] == "Failed"
        assert "AssociationStatus FAILED" in row["Finding_Details"]
        assert "boom" in row["Finding_Details"]

    @pytest.mark.parametrize("status", ["SUCCESS", "PENDING"])
    @patch("sagemaker_app.boto3.client")
    def test_policy_association_names_the_unread_policy(self, mock_client, status):
        row = self._association(
            mock_client,
            {
                "ConfigurationPolicyId": "a1b2",
                "AssociationType": "INHERITED",
                "AssociationStatus": status,
            },
        )
        assert row["Status"] == "N/A"
        assert row["Finding"].endswith("Incomplete")
        assert "configuration policy a1b2" in row["Finding_Details"]
        assert "securityhub:GetConfigurationPolicy," in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_the_unread_policy_names_the_field_only_the_admin_can_read(
        self, mock_client
    ):
        row = self._association(
            mock_client,
            {
                "ConfigurationPolicyId": "a1b2",
                "AssociationType": "APPLIED",
                "AssociationStatus": "SUCCESS",
            },
        )
        details = row["Finding_Details"]
        assert "enabled standards and controls" in details
        assert "only the Security Hub delegated administrator can call" in details
        assert "not granted" not in details
        assert not row["Resolution"].startswith("Grant")
        assert "configuration policy a1b2" in row["Resolution"]

    @patch("sagemaker_app.boto3.client")
    def test_association_access_denied_is_incomplete(self, mock_client):
        row = self._association(
            mock_client, _make_client_error("AccessDeniedException")
        )
        assert row["Status"] == "N/A"
        assert row["Finding"].endswith("Incomplete")
        assert "GetConfigurationPolicyAssociation failed" in row["Finding_Details"]
        assert "AccessDeniedException" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_central_not_enabled_fails(self, mock_client):
        row = self._central(
            mock_client, {"ConfigurationType": "CENTRAL", "Status": "FAILED"}
        )
        assert row["Status"] == "Failed"
        assert "Status FAILED" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_configuration_read_failure_is_incomplete(self, mock_client):
        row = self._central(mock_client, _make_client_error("InvalidAccessException"))
        assert row["Status"] == "N/A"
        assert row["Finding"].endswith("Incomplete")
        assert "delegated administrator" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_ai_standard_on_second_page_after_another_standard_passes(
        self, mock_client
    ):
        rows = self._run(
            mock_client,
            [
                {
                    "StandardsSubscriptions": [
                        {"StandardsArn": self.FSBP_ARN, "StandardsStatus": "READY"}
                    ]
                },
                {
                    "StandardsSubscriptions": [
                        {"StandardsArn": self.AI_ARN, "StandardsStatus": "READY"}
                    ]
                },
            ],
        )
        assert [r["Status"] for r in rows] == ["Passed", "Failed"]
        assert rows[0]["Check_ID"] == "SM-36"
        assert "status READY" in rows[0]["Finding_Details"]
        assert rows[1]["Finding"] == sagemaker_app.CENTRAL_CONFIGURATION_FINDING

    @patch("sagemaker_app.boto3.client")
    def test_incomplete_passes_with_a_status_reason_note(self, mock_client):
        rows = self._run(
            mock_client,
            [
                {
                    "StandardsSubscriptions": [
                        {"StandardsArn": self.AI_ARN, "StandardsStatus": "INCOMPLETE"}
                    ]
                }
            ],
        )
        assert rows[0]["Status"] == "Passed"
        assert "StatusReason" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize("status", ["PENDING", "DELETING", "FAILED"])
    @patch("sagemaker_app.boto3.client")
    def test_subscription_not_ready_fails(self, mock_client, status):
        rows = self._run(
            mock_client,
            [
                {
                    "StandardsSubscriptions": [
                        {"StandardsArn": self.AI_ARN, "StandardsStatus": status}
                    ]
                }
            ],
        )
        assert rows[0]["Status"] == "Failed"
        assert f"status {status}" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_other_standards_only_fails_with_count(self, mock_client):
        rows = self._run(
            mock_client,
            [
                {
                    "StandardsSubscriptions": [
                        {"StandardsArn": self.FSBP_ARN, "StandardsStatus": "READY"}
                    ]
                }
            ],
        )
        assert rows[0]["Status"] == "Failed"
        assert rows[0]["Severity"] == "High"
        assert "with 1 standard(s)" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_security_hub_not_enabled_is_failed(self, mock_client):
        rows = self._run(
            mock_client, error=_make_client_error("InvalidAccessException")
        )
        assert rows[0]["Status"] == "Failed"
        assert "not enabled in this region" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_access_denied_is_could_not_assess(self, mock_client):
        rows = self._run(mock_client, error=_make_client_error("AccessDeniedException"))
        assert len(rows) == 1
        assert_could_not_assess_finding(rows[0])


def _detector(status="ENABLED", features=None):
    return {
        "detector_id": "12abc34d567e8fa901bc2d34e56789f0",
        "detail": {"Status": status, "Features": features or []},
        "error": None,
    }


class TestSM37EndpointFlowLogAlerting:
    """AIR-FND-NET-07: customer flow logs with an alarm for each endpoint."""

    check = staticmethod(sagemaker_app.check_sagemaker_endpoint_flow_log_alerting)

    def _flow_log(self, resource, group="/flow/a", **overrides):
        flow_log = {
            "ResourceId": resource,
            "FlowLogStatus": "ACTIVE",
            "LogDestinationType": "cloud-watch-logs",
            "TrafficType": "ALL",
            "LogGroupName": group,
        }
        flow_log.update(overrides)
        return flow_log

    def _alarm(self, metric="Egress", namespace="Flow", **overrides):
        alarm = {
            "AlarmName": "egress",
            "MetricName": metric,
            "Namespace": namespace,
            "ActionsEnabled": True,
            "AlarmActions": ["arn:aws:sns:us-east-1:111122223333:alerts"],
        }
        alarm.update(overrides)
        return alarm

    def _run(
        self,
        mock_client,
        endpoints=None,
        models=None,
        flow_logs=None,
        filters=None,
        alarms=None,
        errors=None,
        composites=None,
        history=None,
    ):
        errors = errors or {}
        composites = composites or []
        history = history or {}
        self.history_calls = []
        endpoints = (
            endpoints
            if endpoints is not None
            else {"ep-1": {"models": ["m-1"]}, "ep-2": {"models": ["m-2"]}}
        )
        models = (
            models if models is not None else {"m-1": ["subnet-1"], "m-2": ["subnet-2"]}
        )
        subnet_vpc = {"subnet-1": "vpc-1", "subnet-2": "vpc-2", "subnet-3": "vpc-1"}
        flow_logs = (
            flow_logs
            if flow_logs is not None
            else [self._flow_log("vpc-1"), self._flow_log("vpc-2")]
        )
        filters = (
            filters
            if filters is not None
            else {
                "/flow/a": [
                    {
                        "logGroupName": "/flow/a",
                        "metricTransformations": [
                            {"metricNamespace": "Flow", "metricName": "Egress"}
                        ],
                    }
                ]
            }
        )
        alarms = alarms if alarms is not None else [self._alarm()]

        sagemaker = MagicMock()
        sagemaker.get_paginator.side_effect = _pager(
            {
                "list_endpoints": [
                    {
                        "Endpoints": [
                            {"EndpointName": name, "EndpointStatus": "InService"}
                            for name in endpoints
                        ]
                    }
                ]
            }
        )
        sagemaker.describe_endpoint.side_effect = lambda EndpointName: {
            "EndpointConfigName": f"cfg-{EndpointName}"
        }

        def describe_endpoint_config(EndpointConfigName):
            spec = endpoints[EndpointConfigName[len("cfg-") :]]
            config = {
                "ProductionVariants": [
                    {"VariantName": "v", "ModelName": m} for m in spec["models"]
                ]
            }
            if spec.get("subnets"):
                config["VpcConfig"] = {"Subnets": spec["subnets"]}
            return config

        sagemaker.describe_endpoint_config.side_effect = describe_endpoint_config

        def describe_model(ModelName):
            if "describe_model" in errors:
                raise errors["describe_model"]
            subnets = models[ModelName]
            return {"VpcConfig": {"Subnets": subnets}} if subnets else {}

        sagemaker.describe_model.side_effect = describe_model

        def subnets(SubnetIds):
            if "describe_subnets" in errors:
                raise errors["describe_subnets"]
            # The mock ignores the filter; the check keeps only requested ids.
            return [
                {
                    "Subnets": [
                        {"SubnetId": sid, "VpcId": vpc}
                        for sid, vpc in subnet_vpc.items()
                    ]
                }
            ]

        def describe_flow_logs(Filter):
            if "describe_flow_logs" in errors:
                raise errors["describe_flow_logs"]
            return [{"FlowLogs": flow_logs[:1]}, {"FlowLogs": flow_logs[1:]}]

        ec2 = MagicMock()
        ec2.get_paginator.side_effect = _pager(
            {"describe_subnets": subnets, "describe_flow_logs": describe_flow_logs}
        )

        def metric_filters(logGroupName):
            if "describe_metric_filters" in errors:
                raise errors["describe_metric_filters"]
            return [{"metricFilters": filters.get(logGroupName, [])}]

        logs = MagicMock()
        logs.get_paginator.side_effect = _pager(
            {"describe_metric_filters": metric_filters}
        )

        def describe_alarms(AlarmTypes):
            if "describe_alarms" in errors:
                raise errors["describe_alarms"]
            pages = [{"MetricAlarms": alarms[:1]}, {"MetricAlarms": alarms[1:]}]
            if "CompositeAlarm" in AlarmTypes:
                pages[1]["CompositeAlarms"] = composites
            return pages

        composite_names = {c.get("AlarmName") for c in composites}
        self.history_types = []

        def describe_alarm_history(
            AlarmName, HistoryItemType, ScanBy, AlarmTypes=("MetricAlarm",)
        ):
            self.history_calls.append((AlarmName, HistoryItemType, ScanBy))
            self.history_types.append((AlarmName, list(AlarmTypes)))
            # CloudWatch returns only the alarm types named, metric by default.
            kind = "CompositeAlarm" if AlarmName in composite_names else "MetricAlarm"
            source = history.get(AlarmName, []) if kind in AlarmTypes else []
            if isinstance(source, Exception):
                raise source
            return [
                {"AlarmHistoryItems": source[:1]},
                {"AlarmHistoryItems": source[1:]},
            ]

        cloudwatch = MagicMock()
        cloudwatch.get_paginator.side_effect = _pager(
            {
                "describe_alarms": describe_alarms,
                "describe_alarm_history": describe_alarm_history,
            }
        )
        clients = {
            "sagemaker": sagemaker,
            "ec2": ec2,
            "logs": logs,
            "cloudwatch": cloudwatch,
        }
        mock_client.side_effect = lambda service, **_: clients[service]
        return _rows(self.check(region="us-east-1"))

    @patch("sagemaker_app.boto3.client")
    def test_every_endpoint_alarmed_passes(self, mock_client):
        rows = self._run(mock_client)
        assert [r["Status"] for r in rows] == ["Passed"]
        assert rows[0]["Check_ID"] == "SM-37"
        assert "All 2 endpoint(s)" in rows[0]["Finding_Details"]
        assert "AgentCore Runtime is not read" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_one_endpoint_vpc_without_a_flow_log_fails(self, mock_client):
        rows = self._run(mock_client, flow_logs=[self._flow_log("vpc-1")])
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "endpoint 'ep-2'" in rows[0]["Finding_Details"]
        assert "subnet-2" in rows[0]["Finding_Details"]
        assert "endpoint 'ep-1'" not in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_subnet_level_flow_log_covers_its_subnet(self, mock_client):
        rows = self._run(
            mock_client,
            flow_logs=[self._flow_log("subnet-1"), self._flow_log("vpc-2")],
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_second_subnet_of_one_endpoint_uncovered_fails(self, mock_client):
        rows = self._run(
            mock_client,
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": ["subnet-1", "subnet-2"]},
            flow_logs=[self._flow_log("vpc-1")],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "covers subnet-2" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "overrides",
        [
            {"FlowLogStatus": "INACTIVE"},
            {"LogDestinationType": "s3"},
            {"TrafficType": "REJECT"},
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_flow_log_that_cannot_alert_on_egress_fails(self, mock_client, overrides):
        rows = self._run(
            mock_client,
            flow_logs=[self._flow_log("vpc-1"), self._flow_log("vpc-2", **overrides)],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "endpoint 'ep-2'" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_endpoint_outside_a_vpc_fails(self, mock_client):
        rows = self._run(mock_client, models={"m-1": ["subnet-1"], "m-2": []})
        assert [r["Status"] for r in rows] == ["Failed"]
        assert (
            "endpoint 'ep-2' runs outside any customer VPC"
            in (rows[0]["Finding_Details"])
        )

    @patch("sagemaker_app.boto3.client")
    def test_endpoint_config_vpc_is_read_for_inference_components(self, mock_client):
        rows = self._run(
            mock_client,
            endpoints={"ep-1": {"models": [], "subnets": ["subnet-2"]}},
            flow_logs=[self._flow_log("vpc-1")],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "covers subnet-2" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "alarm",
        [
            {"ActionsEnabled": False},
            {"AlarmActions": []},
            {"MetricName": "Other"},
            {"Namespace": "Other"},
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_alarm_that_does_not_alert_on_the_filter_metric_fails(
        self, mock_client, alarm
    ):
        rows = self._run(mock_client, alarms=[self._alarm(**alarm)])
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "no metric filter whose metric an alarm" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_anomaly_band_alarm_on_a_later_page_passes(self, mock_client):
        band = self._alarm(MetricName=None, Namespace=None)
        band["Metrics"] = [
            {
                "Id": "m1",
                "MetricStat": {"Metric": {"Namespace": "Flow", "MetricName": "Egress"}},
            },
            {"Id": "ad1", "Expression": "ANOMALY_DETECTION_BAND(m1, 2)"},
        ]
        rows = self._run(mock_client, alarms=[self._alarm(MetricName="Other"), band])
        assert [r["Status"] for r in rows] == ["Passed"]

    def _filters(self, *patterns, **extra):
        return {
            "/flow/a": [
                {
                    "logGroupName": "/flow/a",
                    "filterName": f"f{i}",
                    "filterPattern": pattern,
                    "metricTransformations": [
                        {"metricNamespace": "Flow", "metricName": "Egress"}
                    ],
                    **extra,
                }
                for i, pattern in enumerate(patterns)
            ]
        }

    @pytest.mark.parametrize(
        "pattern",
        [
            "",
            "[version, account, eni, source, destination != 10.*, srcport, "
            "destport, protocol, packets, bytes, start, end, action, status]",
            "REJECT",
            '"ACCEPT" 443',
            "?REJECT ?ERROR",
            "-ERROR",
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_pattern_that_matches_flow_log_records_passes(self, mock_client, pattern):
        rows = self._run(mock_client, filters=self._filters(pattern))
        assert [r["Status"] for r in rows] == ["Passed"]

    @pytest.mark.parametrize(
        "pattern",
        ["ERROR", '{ $.action = "REJECT" }', "REJECT Exception", "?ERROR ?Timeout"],
    )
    @patch("sagemaker_app.boto3.client")
    def test_pattern_that_matches_no_flow_log_record_fails(self, mock_client, pattern):
        rows = self._run(mock_client, filters=self._filters(pattern))
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "pattern matches no flow-log record" in rows[0]["Finding_Details"]
        assert "'f0'" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_json_pattern_on_transformed_logs_passes(self, mock_client):
        rows = self._run(
            mock_client,
            filters=self._filters(
                '{ $.action = "REJECT" }', applyOnTransformedLogs=True
            ),
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_one_matching_filter_beside_a_dead_one_passes(self, mock_client):
        rows = self._run(mock_client, filters=self._filters("ERROR", "REJECT"))
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_each_subnet_needs_an_alarmed_flow_log(self, mock_client):
        # subnet-1's VPC log group is alarmed; subnet-2's is not. Before the
        # per-subnet join the alarmed group on subnet-1 passed the endpoint.
        rows = self._run(
            mock_client,
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": ["subnet-1", "subnet-2"]},
            flow_logs=[
                self._flow_log("vpc-1"),
                self._flow_log("vpc-2", group="/flow/b"),
            ],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "/flow/b covering subnet-2" in rows[0]["Finding_Details"]
        assert "/flow/a" not in rows[0]["Finding_Details"].split("SageMaker")[0]

    @patch("sagemaker_app.boto3.client")
    def test_text_names_the_alarm_history_grant(self, mock_client):
        rows = self._run(mock_client)
        details = rows[0]["Finding_Details"]
        assert "cloudwatch:DescribeAlarmHistory" in details
        assert "not recorded by any CloudWatch API and was not assessed" not in details

    @patch("sagemaker_app.boto3.client")
    def test_filter_on_another_log_group_does_not_count(self, mock_client):
        rows = self._run(
            mock_client,
            flow_logs=[
                self._flow_log("vpc-1"),
                self._flow_log("vpc-2", group="/flow/b"),
            ],
            filters={
                "/flow/a": [
                    {
                        "logGroupName": "/flow/a",
                        "metricTransformations": [
                            {"metricNamespace": "Flow", "metricName": "Egress"}
                        ],
                    }
                ],
                "/flow/b": [
                    {
                        "logGroupName": "/flow/a",
                        "metricTransformations": [
                            {"metricNamespace": "Flow", "metricName": "Egress"}
                        ],
                    }
                ],
            },
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "endpoint 'ep-2'" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "operation,action",
        [
            ("describe_flow_logs", "ec2:DescribeFlowLogs"),
            ("describe_subnets", "ec2:DescribeSubnets"),
            ("describe_metric_filters", "logs:DescribeMetricFilters"),
            ("describe_alarms", "cloudwatch:DescribeAlarms"),
            ("describe_model", "model 'm-1'"),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_failed_read_is_incomplete_never_passed(
        self, mock_client, operation, action
    ):
        rows = self._run(
            mock_client, errors={operation: _make_client_error("AccessDenied")}
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert rows[0]["Finding"].endswith("Incomplete")
        assert action in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_endpoint_listing_failure_is_could_not_assess(self, mock_client):
        mock_client.side_effect = _make_client_error("AccessDeniedException")
        rows = _rows(self.check(region="us-east-1"))
        assert len(rows) == 1
        assert_could_not_assess_finding(rows[0])

    @patch("sagemaker_app.boto3.client")
    def test_no_endpoints_is_not_applicable(self, mock_client):
        rows = self._run(mock_client, endpoints={}, models={})
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "No SageMaker endpoints" in rows[0]["Finding_Details"]

    def _composite(self, rule, name="page-oncall", **overrides):
        composite = {
            "AlarmName": name,
            "AlarmRule": rule,
            "ActionsEnabled": True,
            "AlarmActions": ["arn:aws:sns:us-east-1:111122223333:alerts"],
        }
        composite.update(overrides)
        return composite

    def _silent_alarm(self):
        return self._alarm(
            ActionsEnabled=False,
            AlarmActions=[],
            AlarmArn="arn:aws:cloudwatch:us-east-1:111122223333:alarm:egress",
            StateValue="OK",
        )

    @pytest.mark.parametrize(
        "rule",
        [
            'ALARM("egress")',
            "ALARM(egress) OR ALARM(other)",
            '(ALARM("arn:aws:cloudwatch:us-east-1:111122223333:alarm:egress"))',
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_a_silent_alarm_actioned_by_a_composite_passes(self, mock_client, rule):
        rows = self._run(
            mock_client,
            alarms=[self._silent_alarm()],
            composites=[self._composite(rule)],
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert (
            "log group /flow/a, alarm 'egress' in state OK, actioned through "
            "composite alarm 'page-oncall'"
        ) in details
        assert "current StateValue" in details

    @pytest.mark.parametrize(
        "composite",
        [
            {"AlarmRule": "ALARM(egress) AND ALARM(other)"},
            {"AlarmRule": "NOT ALARM(egress)"},
            {"AlarmRule": "ALARM(egress) AND NOT ALARM(deploying)"},
            {"AlarmRule": "(ALARM(egress) OR ALARM(other)) AND OK(network)"},
            {"AlarmRule": "ALARM(egress) OR TRUE"},
            {"AlarmRule": "ALARM(egress)", "ActionsEnabled": False},
            {"AlarmRule": "ALARM(egress)", "AlarmActions": []},
            {"AlarmRule": "ALARM(egress-other)"},
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_a_composite_that_does_not_carry_the_alarm_fails(
        self, mock_client, composite
    ):
        rows = self._run(
            mock_client,
            alarms=[self._silent_alarm()],
            composites=[self._composite(composite.pop("AlarmRule"), **composite)],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert (
            "2 endpoint(s) have no network anomaly alerting"
            in (rows[0]["Finding_Details"])
        )

    @patch("sagemaker_app.boto3.client")
    def test_a_nested_composite_carries_the_action_of_its_parent(self, mock_client):
        rows = self._run(
            mock_client,
            alarms=[self._silent_alarm()],
            composites=[
                self._composite("ALARM(page-oncall)", name="top"),
                self._composite(
                    "ALARM(egress)",
                    ActionsEnabled=False,
                    AlarmActions=[],
                ),
            ],
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "actioned through composite alarm 'top'" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_a_composite_credits_only_the_endpoint_whose_metric_it_names(
        self, mock_client
    ):
        filter_b = {
            "logGroupName": "/flow/b",
            "metricTransformations": [
                {"metricNamespace": "Flow", "metricName": "EgressB"}
            ],
        }
        rows = self._run(
            mock_client,
            flow_logs=[self._flow_log("vpc-1"), self._flow_log("vpc-2", "/flow/b")],
            filters={
                "/flow/a": [
                    {
                        "logGroupName": "/flow/a",
                        "metricTransformations": [
                            {"metricNamespace": "Flow", "metricName": "Egress"}
                        ],
                    }
                ],
                "/flow/b": [filter_b],
            },
            alarms=[
                self._silent_alarm(),
                self._alarm("EgressB", AlarmName="egress-b", ActionsEnabled=False),
            ],
            composites=[self._composite("ALARM(egress)")],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "1 endpoint(s) have no network anomaly alerting" in details
        assert "endpoint 'ep-2': flow log group(s) /flow/b" in details
        assert "endpoint 'ep-1'" not in details

    @patch("sagemaker_app.boto3.client")
    def test_an_alarm_with_its_own_action_names_its_state(self, mock_client):
        rows = self._run(mock_client, alarms=[self._alarm(StateValue="ALARM")])
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert (
            "log group /flow/a, alarm 'egress' in state ALARM, no entry into ALARM "
            "in the alarm history CloudWatch returned)"
        ) in details
        assert "actioned through" not in details

    def _state_update(self, old, new, timestamp, name="egress"):
        return {
            "AlarmName": name,
            "Timestamp": timestamp,
            "HistoryItemType": "StateUpdate",
            "HistoryData": json.dumps(
                {
                    "version": "1.0",
                    "oldState": {"stateValue": old},
                    "newState": {"stateValue": new},
                }
            ),
        }

    @patch("sagemaker_app.boto3.client")
    def test_the_last_entry_into_alarm_is_named_from_the_history(self, mock_client):
        fired = datetime(2026, 9, 22, 2, 22, tzinfo=timezone.utc)
        rows = self._run(
            mock_client,
            history={
                "egress": [
                    self._state_update(
                        "ALARM", "OK", datetime(2026, 9, 22, 2, 27, tzinfo=timezone.utc)
                    ),
                    {"AlarmName": "egress", "HistoryData": "not json"},
                    self._state_update("OK", "ALARM", fired),
                ]
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert "last entered ALARM at 2026-09-22T02:22:00+00:00" in details
        assert "02:27" not in details
        assert self.history_calls == [("egress", "StateUpdate", "TimestampDescending")]

    @patch("sagemaker_app.boto3.client")
    def test_a_denied_history_read_is_named_and_does_not_hold_back_passed(
        self, mock_client
    ):
        rows = self._run(
            mock_client,
            history={"egress": _make_client_error("AccessDenied")},
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert (
            "alarm history not read (cloudwatch:DescribeAlarmHistory: AccessDenied)"
        ) in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_each_endpoint_names_its_own_alarms_history(self, mock_client):
        filter_b = {
            "logGroupName": "/flow/b",
            "metricTransformations": [
                {"metricNamespace": "Flow", "metricName": "EgressB"}
            ],
        }
        rows = self._run(
            mock_client,
            flow_logs=[self._flow_log("vpc-1"), self._flow_log("vpc-2", "/flow/b")],
            filters={
                "/flow/a": [
                    {
                        "logGroupName": "/flow/a",
                        "metricTransformations": [
                            {"metricNamespace": "Flow", "metricName": "Egress"}
                        ],
                    }
                ],
                "/flow/b": [filter_b],
            },
            alarms=[self._alarm(), self._alarm("EgressB", AlarmName="egress-b")],
            history={
                "egress": [
                    self._state_update(
                        "OK", "ALARM", datetime(2026, 9, 1, tzinfo=timezone.utc)
                    )
                ]
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert (
            "endpoint 'ep-1' (log group /flow/a, alarm 'egress' in state not "
            "returned, last entered ALARM at 2026-09-01T00:00:00+00:00)"
        ) in details
        assert (
            "endpoint 'ep-2' (log group /flow/b, alarm 'egress-b' in state not "
            "returned, no entry into ALARM in the alarm history CloudWatch returned)"
        ) in details
        assert sorted(call[0] for call in self.history_calls) == ["egress", "egress-b"]

    @patch("sagemaker_app.boto3.client")
    def test_a_composite_route_reads_the_metric_alarms_own_history(self, mock_client):
        rows = self._run(
            mock_client,
            alarms=[self._silent_alarm()],
            composites=[self._composite("ALARM(egress)")],
            history={
                "egress": [
                    self._state_update(
                        "OK", "ALARM", datetime(2026, 9, 2, tzinfo=timezone.utc)
                    )
                ],
                "page-oncall": _make_client_error("AccessDenied"),
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert (
            "last entered ALARM at 2026-09-02T00:00:00+00:00"
            in (rows[0]["Finding_Details"])
        )
        assert [call[0] for call in self.history_calls] == ["egress", "page-oncall"]
        assert (
            "actioned through composite alarm 'page-oncall', last entered ALARM at "
            "2026-09-02T00:00:00+00:00, composite alarm 'page-oncall' alarm history "
            "not read (cloudwatch:DescribeAlarmHistory: AccessDenied)"
        ) in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_the_composite_history_is_read_as_a_composite(self, mock_client):
        rows = self._run(
            mock_client,
            alarms=[self._silent_alarm()],
            composites=[self._composite("ALARM(egress)")],
            history={
                "page-oncall": [
                    self._state_update(
                        "OK",
                        "ALARM",
                        datetime(2026, 9, 3, tzinfo=timezone.utc),
                        name="page-oncall",
                    )
                ],
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert (
            "alarm 'egress' in state OK, actioned through composite alarm "
            "'page-oncall', no entry into ALARM in the alarm history CloudWatch "
            "returned, composite alarm 'page-oncall' last entered ALARM at "
            "2026-09-03T00:00:00+00:00"
        ) in details
        assert self.history_types == [
            ("egress", ["MetricAlarm"]),
            ("page-oncall", ["CompositeAlarm"]),
        ]

    @patch("sagemaker_app.boto3.client")
    def test_a_nested_composite_reads_the_history_of_the_actioned_parent(
        self, mock_client
    ):
        rows = self._run(
            mock_client,
            alarms=[self._silent_alarm()],
            composites=[
                self._composite("ALARM(page-oncall)", name="top"),
                self._composite("ALARM(egress)", ActionsEnabled=False, AlarmActions=[]),
            ],
            history={
                "top": [
                    self._state_update(
                        "OK",
                        "ALARM",
                        datetime(2026, 9, 4, tzinfo=timezone.utc),
                        name="top",
                    )
                ],
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert (
            "composite alarm 'top' last entered ALARM at 2026-09-04T00:00:00+00:00"
        ) in rows[0]["Finding_Details"]
        assert [call[0] for call in self.history_calls] == ["egress", "top"]

    @patch("sagemaker_app.boto3.client")
    def test_each_endpoint_names_the_history_of_its_own_composite(self, mock_client):
        filter_b = {
            "logGroupName": "/flow/b",
            "metricTransformations": [
                {"metricNamespace": "Flow", "metricName": "EgressB"}
            ],
        }
        rows = self._run(
            mock_client,
            flow_logs=[self._flow_log("vpc-1"), self._flow_log("vpc-2", "/flow/b")],
            filters={
                "/flow/a": [
                    {
                        "logGroupName": "/flow/a",
                        "metricTransformations": [
                            {"metricNamespace": "Flow", "metricName": "Egress"}
                        ],
                    }
                ],
                "/flow/b": [filter_b],
            },
            alarms=[
                self._silent_alarm(),
                self._alarm(
                    "EgressB",
                    AlarmName="egress-b",
                    ActionsEnabled=False,
                    AlarmActions=[],
                ),
            ],
            composites=[
                self._composite("ALARM(egress)", name="page-a"),
                self._composite("ALARM(egress-b)", name="page-b"),
            ],
            history={
                "page-b": [
                    self._state_update(
                        "OK",
                        "ALARM",
                        datetime(2026, 9, 5, tzinfo=timezone.utc),
                        name="page-b",
                    )
                ],
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert (
            "endpoint 'ep-1' (log group /flow/a, alarm 'egress' in state OK, "
            "actioned through composite alarm 'page-a', no entry into ALARM in the "
            "alarm history CloudWatch returned, composite alarm 'page-a' no entry "
            "into ALARM in the alarm history CloudWatch returned)"
        ) in details
        assert (
            "actioned through composite alarm 'page-b', no entry into ALARM in the "
            "alarm history CloudWatch returned, composite alarm 'page-b' last "
            "entered ALARM at 2026-09-05T00:00:00+00:00)"
        ) in details

    @patch("sagemaker_app.boto3.client")
    def test_an_and_composite_credits_no_child_on_either_endpoint(self, mock_client):
        rows = self._run(
            mock_client,
            alarms=[self._silent_alarm()],
            composites=[self._composite("ALARM(egress) AND ALARM(other)")],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "2 endpoint(s) have no network anomaly alerting" in details
        assert self.history_calls == []

    def _split_groups(self, a_filters, b_filters, b_alarms=None):
        """ep-1 on /flow/a, ep-2 on /flow/b, each with its own filters."""
        return {
            "flow_logs": [
                self._flow_log("vpc-1"),
                self._flow_log("vpc-2", group="/flow/b"),
            ],
            "filters": {
                "/flow/a": [dict(f, logGroupName="/flow/a") for f in a_filters],
                "/flow/b": [dict(f, logGroupName="/flow/b") for f in b_filters],
            },
        }

    def _transform(self, pattern="", name="Egress", **transformation):
        return {
            "filterName": f"f-{name}",
            "filterPattern": pattern,
            "metricTransformations": [
                {"metricNamespace": "Flow", "metricName": name, **transformation}
            ],
        }

    FLOW_FIELDS = (
        "[version, account, eni, source, destination, srcport, destport, "
        "protocol, packets, bytes, start, end, {action}, {status}]"
    )

    @pytest.mark.parametrize(
        "action, status",
        [
            ('action="DENY"', "status"),
            ("action=REJECT && action=ERROR", "status"),
            ("action", "status=FAILED"),
        ],
    )
    @pytest.mark.parametrize("dead_first", [True, False])
    @patch("sagemaker_app.boto3.client")
    def test_a_bracketed_condition_no_flow_record_carries_fails_only_its_endpoint(
        self, mock_client, action, status, dead_first
    ):
        dead = self._transform(self.FLOW_FIELDS.format(action=action, status=status))
        other = self._transform("", name="Ingress")
        b_filters = [dead, other] if dead_first else [other, dead]
        alarms = [self._alarm(), self._alarm(metric="Egress", AlarmName="egress-2")]
        rows = self._run(
            mock_client,
            alarms=alarms,
            **self._split_groups([self._transform("REJECT")], b_filters),
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "1 endpoint(s) have no network anomaly alerting" in details
        assert "endpoint 'ep-2'" in details
        assert "endpoint 'ep-1'" not in details
        assert "pattern matches no flow-log record" in details
        assert "'f-Egress'" in details

    @pytest.mark.parametrize(
        "action, status",
        [
            ('action="REJECT"', "status"),
            ("action=ACCEPT || action=DENY", "status"),
            ("action=*EJECT", "status"),
            ("action", "status=-"),
            ("action", "status=NODATA"),
            ("action", "status"),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_a_bracketed_condition_a_flow_record_carries_passes(
        self, mock_client, action, status
    ):
        rows = self._run(
            mock_client,
            filters={
                "/flow/a": [
                    dict(
                        self._transform(
                            self.FLOW_FIELDS.format(action=action, status=status)
                        ),
                        logGroupName="/flow/a",
                    )
                ]
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_a_bracketed_ipv6_source_passes(self, mock_client):
        pattern = (
            "[version, account, eni, source=fe80::1, destination, srcport, "
            "destport, protocol, packets, bytes, start, end, action, status]"
        )
        rows = self._run(
            mock_client,
            filters={
                "/flow/a": [dict(self._transform(pattern), logGroupName="/flow/a")]
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    DEAD_ALARMS = [
        # The alarm reads a dimension the filter never publishes.
        ({}, {"Dimensions": [{"Name": "eni", "Value": "eni-1"}]}, "dimension"),
        # The filter publishes a dimension the alarm does not read.
        ({"dimensions": {"eni": "$eni"}}, {}, "dimension"),
        # The alarm reads a unit the filter never publishes.
        ({}, {"Unit": "Bytes"}, "unit Bytes"),
        ({"unit": "Count"}, {"Unit": "Bytes"}, "unit Bytes"),
        # A count can never fall below zero.
        (
            {"metricValue": "1"},
            {
                "Statistic": "Sum",
                "ComparisonOperator": "LessThanThreshold",
                "Threshold": 0.0,
            },
            "never",
        ),
        (
            {"metricValue": "1"},
            {
                "Statistic": "Sum",
                "ComparisonOperator": "LessThanOrEqualToThreshold",
                "Threshold": -1.0,
            },
            "never",
        ),
        # The largest value the filter publishes is 1.
        (
            {"metricValue": "1"},
            {
                "Statistic": "Maximum",
                "ComparisonOperator": "GreaterThanThreshold",
                "Threshold": 1.0,
            },
            "never",
        ),
        (
            {"metricValue": "1", "defaultValue": 0.0},
            {
                "ExtendedStatistic": "p99",
                "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                "Threshold": 2.0,
            },
            "never",
        ),
        # A filter that publishes only zeros sums to zero.
        (
            {"metricValue": "0"},
            {
                "Statistic": "Sum",
                "ComparisonOperator": "GreaterThanThreshold",
                "Threshold": 0.0,
            },
            "never",
        ),
    ]

    @pytest.mark.parametrize("transformation, alarm, reason", DEAD_ALARMS)
    @patch("sagemaker_app.boto3.client")
    def test_an_alarm_that_can_never_fire_fails_only_its_endpoint(
        self, mock_client, transformation, alarm, reason
    ):
        # ep-1's group publishes Egress, which the live alarm reads. ep-2's
        # group publishes Dead, which only the dead alarm reads.
        alarms = [
            self._alarm(),
            self._alarm(metric="Dead", AlarmName="dead", **alarm),
        ]
        rows = self._run(
            mock_client,
            alarms=alarms,
            **self._split_groups(
                [self._transform()], [self._transform(name="Dead", **transformation)]
            ),
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "1 endpoint(s) have no network anomaly alerting" in details
        assert "endpoint 'ep-2'" in details
        assert "endpoint 'ep-1'" not in details
        assert "alarm 'dead' on Flow/Dead can never fire" in details
        assert reason in details.split("alarm 'dead' on Flow/Dead can never fire")[1]

    @pytest.mark.parametrize("transformation, alarm, reason", DEAD_ALARMS)
    @pytest.mark.parametrize("dead_first", [True, False])
    @patch("sagemaker_app.boto3.client")
    def test_a_live_alarm_beside_a_dead_one_passes(
        self, mock_client, transformation, alarm, reason, dead_first
    ):
        dead = self._alarm(AlarmName="dead", **alarm)
        live_overrides = {
            k: v for k, v in alarm.items() if k not in ("Dimensions", "Unit")
        }
        live_overrides.pop("ComparisonOperator", None)
        live_overrides.pop("Threshold", None)
        live_overrides.pop("Statistic", None)
        live_overrides.pop("ExtendedStatistic", None)
        dims = transformation.get("dimensions")
        if dims:
            live_overrides["Dimensions"] = [
                {"Name": key, "Value": "eni-1"} for key in dims
            ]
        live = self._alarm(AlarmName="live", **live_overrides)
        rows = self._run(
            mock_client,
            alarms=[dead, live] if dead_first else [live, dead],
            filters={
                "/flow/a": [
                    dict(self._transform(**transformation), logGroupName="/flow/a")
                ]
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "alarm 'live'" in rows[0]["Finding_Details"]
        assert "alarm 'dead'" not in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "transformation, alarm",
        [
            (
                {"dimensions": {"eni": "$eni"}},
                {"Dimensions": [{"Name": "eni", "Value": "eni-1"}]},
            ),
            ({}, {"Unit": "None"}),
            ({"unit": "Count"}, {"Unit": "Count"}),
            (
                {"metricValue": "1"},
                {
                    "Statistic": "Sum",
                    "ComparisonOperator": "GreaterThanThreshold",
                    "Threshold": 100.0,
                },
            ),
            (
                {"metricValue": "1"},
                {
                    "Statistic": "Maximum",
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "Threshold": 1.0,
                },
            ),
            (
                {"metricValue": "1", "defaultValue": 5.0},
                {
                    "Statistic": "Maximum",
                    "ComparisonOperator": "GreaterThanThreshold",
                    "Threshold": 1.0,
                },
            ),
            (
                {"metricValue": "0"},
                {
                    "Statistic": "SampleCount",
                    "ComparisonOperator": "GreaterThanThreshold",
                    "Threshold": 0.0,
                },
            ),
            (
                {"metricValue": "$bytes"},
                {
                    "Statistic": "Maximum",
                    "ComparisonOperator": "GreaterThanThreshold",
                    "Threshold": 1e9,
                },
            ),
            (
                {"metricValue": "1"},
                {
                    "Statistic": "Sum",
                    "ComparisonOperator": "LessThanThreshold",
                    "Threshold": 1.0,
                },
            ),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_an_alarm_that_can_fire_passes(self, mock_client, transformation, alarm):
        rows = self._run(
            mock_client,
            alarms=[self._alarm(**alarm)],
            filters={
                "/flow/a": [
                    dict(self._transform(**transformation), logGroupName="/flow/a")
                ]
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_a_dead_alarm_on_an_alarmed_subnet_is_not_named(self, mock_client):
        # subnet-1's group is alarmed by 'live' beside 'dead'; subnet-2's
        # group has no filter. Only subnet-2 is named.
        rows = self._run(
            mock_client,
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": ["subnet-1", "subnet-2"]},
            alarms=[
                self._alarm(AlarmName="dead", Unit="Bytes"),
                self._alarm(AlarmName="live"),
            ],
            flow_logs=[
                self._flow_log("vpc-1"),
                self._flow_log("vpc-2", group="/flow/b"),
            ],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "/flow/b covering subnet-2" in details
        assert "alarm 'dead'" not in details

    @pytest.mark.parametrize(
        "stat",
        [
            {"Dimensions": [{"Name": "eni", "Value": "eni-1"}]},
            {"Unit": "Bytes"},
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_a_metric_math_alarm_on_another_series_fails(self, mock_client, stat):
        band = self._alarm(MetricName=None, Namespace=None)
        metric = {"Namespace": "Flow", "MetricName": "Egress"}
        metric_stat = {"Metric": metric}
        if "Dimensions" in stat:
            metric["Dimensions"] = stat["Dimensions"]
        else:
            metric_stat["Unit"] = stat["Unit"]
        band["Metrics"] = [
            {"Id": "m1", "MetricStat": metric_stat},
            {"Id": "ad1", "Expression": "ANOMALY_DETECTION_BAND(m1, 2)"},
        ]
        rows = self._run(mock_client, alarms=[band])
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "can never fire" in rows[0]["Finding_Details"]


class TestSM37VpcDnsResolver:
    """AIR-FND-NET-07: GuardDuty sees DNS only through the Amazon DNS server."""

    check = staticmethod(sagemaker_app.check_vpc_dns_resolver_visibility)

    @staticmethod
    def _vpc(vpc_id, option_id, cidr="10.0.0.0/16"):
        return {
            "VpcId": vpc_id,
            "DhcpOptionsId": option_id,
            "CidrBlockAssociationSet": [{"CidrBlock": cidr}],
        }

    @staticmethod
    def _options(option_id, *servers):
        configurations = [{"Key": "domain-name", "Values": [{"Value": "corp"}]}]
        if servers:
            configurations.append(
                {
                    "Key": "domain-name-servers",
                    "Values": [{"Value": server} for server in servers],
                }
            )
        return {"DhcpOptionsId": option_id, "DhcpConfigurations": configurations}

    def _run(self, vpcs, options=(), errors=None):
        errors = errors or {}
        self.option_calls = []

        def describe_vpcs():
            if "vpcs" in errors:
                raise errors["vpcs"]
            # One VPC per page, so a reader of only the first page misses the rest.
            return [{"Vpcs": [vpc]} for vpc in vpcs]

        def describe_dhcp_options(DhcpOptionsIds):
            self.option_calls.append(DhcpOptionsIds)
            if "dhcp" in errors:
                raise errors["dhcp"]
            return [
                {
                    "DhcpOptions": [
                        o for o in options if o["DhcpOptionsId"] in DhcpOptionsIds
                    ]
                }
            ]

        ec2 = MagicMock()
        ec2.get_paginator.side_effect = _pager(
            {
                "describe_vpcs": describe_vpcs,
                "describe_dhcp_options": describe_dhcp_options,
            }
        )
        with patch("sagemaker_app.boto3.client", return_value=ec2):
            return _rows(self.check(region="us-east-1"))

    @pytest.mark.parametrize("custom_first", [True, False])
    def test_one_custom_resolver_among_amazon_ones_fails(self, custom_first):
        vpcs = [
            self._vpc("vpc-amazon", "dopt-a"),
            self._vpc("vpc-custom", "dopt-c"),
        ]
        if custom_first:
            vpcs.reverse()
        rows = self._run(
            vpcs,
            [
                self._options("dopt-a", "AmazonProvidedDNS"),
                self._options("dopt-c", "AmazonProvidedDNS", "8.8.8.8"),
            ],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "VPC vpc-custom uses DHCP option set dopt-c" in details
        assert "include 8.8.8.8," in details
        assert "vpc-amazon" not in details

    @pytest.mark.parametrize(
        "server", ["AmazonProvidedDNS", "169.254.169.253", "10.0.0.2", "fd00:ec2::253"]
    )
    def test_the_amazon_dns_server_by_name_or_address_passes(self, server):
        rows = self._run(
            [self._vpc("vpc-1", "dopt-a"), self._vpc("vpc-2", "default")],
            [self._options("dopt-a", server)],
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert "All 2 VPC(s)" in details
        assert "vpc-2 (no DHCP option set)" in details

    def test_the_base_plus_two_of_another_vpc_fails(self):
        # 10.0.0.2 is the Amazon DNS server of 10.0.0.0/16, not of 10.1.0.0/16.
        rows = self._run(
            [self._vpc("vpc-1", "dopt-a", cidr="10.1.0.0/16")],
            [self._options("dopt-a", "10.0.0.2")],
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "include 10.0.0.2," in rows[0]["Finding_Details"]

    def test_an_option_set_with_no_servers_is_not_judged(self):
        rows = self._run(
            [self._vpc("vpc-1", "dopt-a"), self._vpc("vpc-2", "dopt-n")],
            [self._options("dopt-a", "AmazonProvidedDNS"), self._options("dopt-n")],
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "vpc-2 (dopt-n)" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "errors, named",
        [
            ({"vpcs": _make_client_error("UnauthorizedOperation")}, "ec2:DescribeVpcs"),
            (
                {"dhcp": _make_client_error("UnauthorizedOperation")},
                "ec2:DescribeDhcpOptions",
            ),
        ],
    )
    def test_a_failed_read_withholds_the_pass(self, errors, named):
        rows = self._run(
            [self._vpc("vpc-1", "dopt-a")],
            [self._options("dopt-a", "AmazonProvidedDNS")],
            errors=errors,
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert named in rows[0]["Finding_Details"]

    def test_an_option_set_not_returned_withholds_the_pass(self):
        rows = self._run([self._vpc("vpc-1", "dopt-gone")])
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "DHCP option set dopt-gone of vpc-1" in rows[0]["Finding_Details"]

    def test_no_vpcs_is_not_applicable(self):
        rows = self._run([])
        assert [r["Status"] for r in rows] == ["N/A"]
        assert self.option_calls == []


class TestSM37GuardDutyLambdaNetworkLogs:
    """AIR-FND-NET-07: GuardDuty Lambda Protection."""

    check = staticmethod(sagemaker_app.check_guardduty_lambda_network_logs)

    def test_enabled_feature_listed_after_another_passes(self):
        rows = _rows(
            self.check(
                region="us-east-1",
                detector_inventory=_detector(
                    features=[
                        {"Name": "S3_DATA_EVENTS", "Status": "DISABLED"},
                        {"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"},
                    ]
                ),
            )
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert rows[0]["Check_ID"] == "SM-37"
        assert rows[0]["Severity"] == "Medium"

    def test_disabled_feature_after_an_enabled_one_fails(self):
        rows = _rows(
            self.check(
                detector_inventory=_detector(
                    features=[
                        {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
                        {"Name": "LAMBDA_NETWORK_LOGS", "Status": "DISABLED"},
                    ]
                )
            )
        )
        assert rows[0]["Status"] == "Failed"
        assert "feature is DISABLED" in rows[0]["Finding_Details"]

    def test_absent_feature_fails(self):
        rows = _rows(
            self.check(
                detector_inventory=_detector(
                    features=[{"Name": "S3_DATA_EVENTS", "Status": "ENABLED"}]
                )
            )
        )
        assert rows[0]["Status"] == "Failed"
        assert "feature is absent" in rows[0]["Finding_Details"]

    def test_disabled_detector_fails_even_with_feature_enabled(self):
        rows = _rows(
            self.check(
                detector_inventory=_detector(
                    status="DISABLED",
                    features=[{"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"}],
                )
            )
        )
        assert rows[0]["Status"] == "Failed"
        assert "detector is not enabled" in rows[0]["Finding_Details"]

    def test_no_detector_is_na(self):
        rows = _rows(
            self.check(
                detector_inventory={"detector_id": None, "detail": None, "error": None}
            )
        )
        assert rows[0]["Status"] == "N/A"
        assert rows[0]["Severity"] == "Informational"

    def test_inventory_error_is_could_not_assess(self):
        rows = _rows(
            self.check(
                detector_inventory={
                    "detector_id": None,
                    "detail": None,
                    "error": _make_client_error("AccessDeniedException"),
                }
            )
        )
        assert_could_not_assess_finding(rows[0])


class TestSM38GuardDutyRuntimeMonitoring:
    """AIR-SLF-RT-04: RUNTIME_MONITORING, not the EKS-only legacy feature."""

    check = staticmethod(sagemaker_app.check_guardduty_runtime_monitoring)

    def test_runtime_monitoring_enabled_passes_and_lists_agent_management(self):
        # The live detector reports both features; the legacy one DISABLED.
        rows = _rows(
            self.check(
                detector_inventory=_detector(
                    features=[
                        {"Name": "EKS_RUNTIME_MONITORING", "Status": "DISABLED"},
                        {
                            "Name": "RUNTIME_MONITORING",
                            "Status": "ENABLED",
                            "AdditionalConfiguration": [
                                {"Name": "EKS_ADDON_MANAGEMENT", "Status": "ENABLED"},
                                {
                                    "Name": "ECS_FARGATE_AGENT_MANAGEMENT",
                                    "Status": "DISABLED",
                                },
                            ],
                        },
                    ]
                )
            )
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert "EKS_ADDON_MANAGEMENT ENABLED" in details
        assert "ECS_FARGATE_AGENT_MANAGEMENT DISABLED" in details
        assert "EC2_AGENT_MANAGEMENT not reported" in details

    def test_legacy_eks_only_feature_fails(self):
        rows = _rows(
            self.check(
                detector_inventory=_detector(
                    features=[
                        {"Name": "EKS_RUNTIME_MONITORING", "Status": "ENABLED"},
                        {"Name": "RUNTIME_MONITORING", "Status": "DISABLED"},
                    ]
                )
            )
        )
        assert rows[0]["Status"] == "Failed"
        assert rows[0]["Severity"] == "High"
        assert "covers EKS only" in rows[0]["Finding_Details"]

    def test_both_features_absent_fails(self):
        rows = _rows(self.check(detector_inventory=_detector(features=[])))
        assert rows[0]["Status"] == "Failed"
        assert "feature is absent" in rows[0]["Finding_Details"]

    def test_disabled_detector_fails(self):
        rows = _rows(
            self.check(
                detector_inventory=_detector(
                    status="DISABLED",
                    features=[{"Name": "RUNTIME_MONITORING", "Status": "ENABLED"}],
                )
            )
        )
        assert rows[0]["Status"] == "Failed"

    def test_no_detector_is_na(self):
        rows = _rows(
            self.check(
                detector_inventory={"detector_id": None, "detail": None, "error": None}
            )
        )
        assert rows[0]["Status"] == "N/A"

    def test_inventory_error_is_could_not_assess(self):
        rows = _rows(
            self.check(
                detector_inventory={
                    "detector_id": None,
                    "detail": None,
                    "error": RuntimeError("boom"),
                }
            )
        )
        assert_could_not_assess_finding(rows[0])


class TestSM38RuntimeCoverageAndLambdaTier:
    """AIR-SLF-RT-04: per-resource coverage and the Lambda detection tier."""

    check = staticmethod(sagemaker_app.check_guardduty_runtime_monitoring_coverage)

    AGENTS_ON = [
        {"Name": name, "Status": "ENABLED"}
        for name in sagemaker_app.RUNTIME_MONITORING_AGENT_CONFIGS
    ]

    def _detail(self, runtime="ENABLED", agents=None, lambda_logs="ENABLED"):
        return _detector(
            features=[
                {
                    "Name": "RUNTIME_MONITORING",
                    "Status": runtime,
                    "AdditionalConfiguration": (
                        self.AGENTS_ON if agents is None else agents
                    ),
                },
                {"Name": "LAMBDA_NETWORK_LOGS", "Status": lambda_logs},
            ]
        )

    @staticmethod
    def _eks(name, covered=3, compatible=3, status="HEALTHY", issue=None):
        resource = {
            "ResourceId": name,
            "CoverageStatus": status,
            "ResourceDetails": {
                "ResourceType": "EKS",
                "EksClusterDetails": {
                    "ClusterName": name,
                    "CoveredNodes": covered,
                    "CompatibleNodes": compatible,
                },
            },
        }
        if issue:
            resource["Issue"] = issue
        return resource

    @staticmethod
    def _ecs(name, status="HEALTHY"):
        return {
            "ResourceId": name,
            "CoverageStatus": status,
            "ResourceDetails": {
                "ResourceType": "ECS",
                "EcsClusterDetails": {"ClusterName": name},
            },
        }

    @staticmethod
    def _fn_cov(name, scan_type="PACKAGE", code="ACTIVE", reason="SUCCESSFUL"):
        return {
            "resourceId": f"arn:aws:lambda:us-east-1:111122223333:function:{name}",
            "scanType": scan_type,
            "scanStatus": {"statusCode": code, "reason": reason},
            "resourceMetadata": {"lambdaFunction": {"functionName": name}},
        }

    @staticmethod
    def _ec2(instance_id, status="HEALTHY"):
        return {
            "ResourceId": f"arn:aws:ec2:us-east-1:111122223333:instance/{instance_id}",
            "CoverageStatus": status,
            "ResourceDetails": {
                "ResourceType": "EC2",
                "Ec2InstanceDetails": {"InstanceId": instance_id},
            },
        }

    @staticmethod
    def _instance(instance_id, tags=None, platform=None):
        instance = {"InstanceId": instance_id, "State": {"Name": "running"}}
        if tags:
            instance["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
        if platform:
            instance["Platform"] = platform
        return instance

    def _run(
        self,
        detector,
        coverage=None,
        eks=None,
        ecs=None,
        functions=None,
        fn_coverage=None,
        lambda_state=None,
        errors=None,
        instances=None,
        fargate=None,
    ):
        """fargate maps an EKS cluster to its Fargate profile names or an
        exception; an unnamed cluster has none."""
        errors = errors or {}
        fargate = fargate or {}
        self.ec2_calls = []
        coverage = coverage or []
        functions = functions if functions is not None else [{"FunctionName": "fn"}]
        fn_coverage = (
            fn_coverage
            if fn_coverage is not None
            else [
                self._fn_cov(f["FunctionName"], t)
                for f in functions
                for t in ("PACKAGE", "CODE")
            ]
        )
        state = lambda_state or {
            "lambda": {"status": "ENABLED"},
            "lambdaCode": {"status": "ENABLED"},
        }

        def source(key, pages):
            def paginate(**kwargs):
                if key in errors:
                    raise errors[key]
                return pages

            return paginate

        def factory(service, **kwargs):
            client = MagicMock()
            if service == "guardduty":
                client.get_paginator.side_effect = _pager(
                    {"list_coverage": source("gd", [{"Resources": coverage}])}
                )
            elif service == "eks":

                def fargate_profiles(clusterName):
                    value = fargate.get(clusterName, [])
                    if isinstance(value, Exception):
                        raise value
                    return [
                        {"fargateProfileNames": value[:1]},
                        {"fargateProfileNames": value[1:]},
                    ]

                client.get_paginator.side_effect = _pager(
                    {
                        "list_clusters": source("eks", [{"clusters": eks or []}]),
                        "list_fargate_profiles": fargate_profiles,
                    }
                )
            elif service == "ecs":
                arns = [
                    f"arn:aws:ecs:us-east-1:111122223333:cluster/{n}" for n in ecs or []
                ]
                client.get_paginator.side_effect = _pager(
                    {"list_clusters": source("ecs", [{"clusterArns": arns}])}
                )
            elif service == "inspector2":
                if "status" in errors:
                    client.batch_get_account_status.side_effect = errors["status"]
                else:
                    client.batch_get_account_status.return_value = {
                        "accounts": [{"resourceState": state}]
                    }
                client.get_paginator.side_effect = _pager(
                    {
                        "list_coverage": source(
                            "inspector", [{"coveredResources": fn_coverage}]
                        )
                    }
                )
            elif service == "lambda":
                client.get_paginator.side_effect = _pager(
                    {"list_functions": source("lambda", [{"Functions": functions}])}
                )
            elif service == "ec2":

                def describe_instances(**kwargs):
                    self.ec2_calls.append(kwargs)
                    if "ec2" in errors:
                        raise errors["ec2"]
                    return [{"Reservations": [{"Instances": instances or []}]}]

                client.get_paginator.side_effect = _pager(
                    {"describe_instances": describe_instances}
                )
            return client

        with patch("sagemaker_app.boto3.client", side_effect=factory):
            return _rows(self.check(region="us-east-1", detector_inventory=detector))

    @staticmethod
    def _named(rows, name):
        return [r for r in rows if r["Finding"].startswith(name)]

    def _coverage_rows(self, **kwargs):
        rows = self._run(self._detail(), **kwargs)
        return self._named(rows, sagemaker_app.RUNTIME_COVERAGE_FINDING)

    @pytest.mark.parametrize("bad_first", [True, False])
    def test_a_healthy_cluster_with_no_compatible_node_fails(self, bad_first):
        coverage = [self._eks("good"), self._eks("empty", covered=0, compatible=0)]
        if bad_first:
            coverage.reverse()
        cov = self._coverage_rows(coverage=coverage, eks=["good", "empty"])
        assert [r["Status"] for r in cov] == ["Failed"]
        assert (
            "EKS empty is HEALTHY with 0 compatible nodes"
            in (cov[0]["Finding_Details"])
        )
        assert "good" not in cov[0]["Finding_Details"]

    def test_a_fargate_profile_fails_a_cluster_whose_nodes_are_covered(self):
        cov = self._coverage_rows(
            coverage=[self._eks("good"), self._eks("mixed")],
            eks=["good", "mixed"],
            fargate={"mixed": ["batch", "web"]},
        )
        assert [r["Status"] for r in cov] == ["Failed"]
        details = cov[0]["Finding_Details"]
        assert "EKS cluster mixed has Fargate profile(s) batch, web" in details
        assert "good" not in details

    @pytest.mark.parametrize(
        "case",
        ["fargate_error", "no_counts"],
    )
    def test_an_unread_cluster_leg_withholds_the_pass(self, case):
        coverage = [self._eks("good"), self._eks("other")]
        fargate = {}
        if case == "fargate_error":
            fargate = {"other": _make_client_error("AccessDeniedException")}
            text = "eks:ListFargateProfiles other"
        else:
            del coverage[1]["ResourceDetails"]["EksClusterDetails"]["CompatibleNodes"]
            text = "EKS other reports no CompatibleNodes or CoveredNodes"
        cov = self._coverage_rows(
            coverage=coverage, eks=["good", "other"], fargate=fargate
        )
        assert [r["Status"] for r in cov] == ["N/A"]
        assert text in cov[0]["Finding_Details"]

    def _audit(self, status, runtime="ENABLED", detector_status="ENABLED"):
        detector = self._detail(runtime=runtime)
        detector["detail"]["Status"] = detector_status
        if status is not None:
            detector["detail"]["Features"].append(
                {"Name": "EKS_AUDIT_LOGS", "Status": status}
            )
        return detector

    def test_eks_audit_logs_enabled_passes(self):
        rows = self._run(
            self._audit("ENABLED"),
            coverage=[self._eks("a"), self._eks("b")],
            eks=["a", "b"],
        )
        audit = self._named(rows, sagemaker_app.EKS_AUDIT_LOGS_FINDING)
        assert [r["Status"] for r in audit] == ["Passed"]
        assert "2 EKS cluster(s)" in audit[0]["Finding_Details"]

    @pytest.mark.parametrize("status", ["DISABLED", None])
    def test_eks_audit_logs_off_fails_with_clusters(self, status):
        rows = self._run(
            self._audit(status),
            coverage=[self._eks("a"), self._eks("b")],
            eks=["a", "b"],
        )
        audit = self._named(rows, sagemaker_app.EKS_AUDIT_LOGS_FINDING)
        assert [r["Status"] for r in audit] == ["Failed"]
        assert "a, b" in audit[0]["Finding_Details"]
        assert (status or "absent") in audit[0]["Finding_Details"]

    def test_eks_audit_logs_are_judged_when_runtime_monitoring_is_off(self):
        rows = self._run(self._audit("DISABLED", runtime="DISABLED"), eks=["a"])
        audit = self._named(rows, sagemaker_app.EKS_AUDIT_LOGS_FINDING)
        assert [r["Status"] for r in audit] == ["Failed"]

    def test_eks_audit_logs_on_a_disabled_detector_fails(self):
        rows = self._run(
            self._audit("ENABLED", detector_status="DISABLED"),
            coverage=[self._eks("a")],
            eks=["a"],
        )
        audit = self._named(rows, sagemaker_app.EKS_AUDIT_LOGS_FINDING)
        assert [r["Status"] for r in audit] == ["Failed"]
        assert "detector" in audit[0]["Finding_Details"]

    def test_no_eks_cluster_adds_no_audit_log_row(self):
        rows = self._run(self._audit("DISABLED"))
        assert self._named(rows, sagemaker_app.EKS_AUDIT_LOGS_FINDING) == []

    @pytest.mark.parametrize("status", ["ENABLED", "DISABLED"])
    def test_eks_list_denied_withholds_the_audit_log_verdict(self, status):
        rows = self._run(
            self._audit(status),
            errors={"eks": _make_client_error("AccessDeniedException")},
        )
        audit = self._named(rows, sagemaker_app.EKS_AUDIT_LOGS_FINDING)
        assert [r["Status"] for r in audit] == ["N/A"]
        assert "eks:ListClusters" in audit[0]["Finding_Details"]

    def test_healthy_coverage_for_every_cluster_passes(self):
        rows = self._run(
            self._detail(),
            coverage=[self._eks("prod"), self._ecs("svc")],
            eks=["prod"],
            ecs=["svc"],
        )
        cov = self._named(rows, sagemaker_app.RUNTIME_COVERAGE_FINDING)
        assert [r["Status"] for r in cov] == ["Passed"]
        assert "All 2 resource(s)" in cov[0]["Finding_Details"]
        tier = self._named(rows, sagemaker_app.LAMBDA_RUNTIME_TIER_FINDING)
        assert [r["Status"] for r in tier] == ["Passed"]

    def test_one_unhealthy_cluster_among_healthy_ones_fails(self):
        rows = self._run(
            self._detail(),
            coverage=[
                self._eks("a"),
                self._eks("b", status="UNHEALTHY", issue="Agent not reporting"),
                self._ecs("svc"),
            ],
            eks=["a", "b"],
            ecs=["svc"],
        )
        cov = self._named(rows, sagemaker_app.RUNTIME_COVERAGE_FINDING)
        assert [r["Status"] for r in cov] == ["Failed"]
        assert "EKS b is UNHEALTHY (Agent not reporting)" in cov[0]["Finding_Details"]

    def test_healthy_cluster_hiding_uncovered_nodes_fails(self):
        # CoverageStatus HEALTHY with 2 of 5 nodes covered hides three hosts.
        rows = self._run(
            self._detail(),
            coverage=[self._eks("prod", covered=2, compatible=5)],
            eks=["prod"],
        )
        cov = self._named(rows, sagemaker_app.RUNTIME_COVERAGE_FINDING)
        assert [r["Status"] for r in cov] == ["Failed"]
        assert "covers 2 of 5 compatible nodes" in cov[0]["Finding_Details"]

    def test_cluster_missing_from_coverage_fails(self):
        rows = self._run(
            self._detail(),
            coverage=[self._eks("a")],
            eks=["a", "fargate-only"],
            ecs=["svc"],
        )
        details = [
            r["Finding_Details"]
            for r in self._named(rows, sagemaker_app.RUNTIME_COVERAGE_FINDING)
            if r["Status"] == "Failed"
        ]
        assert len(details) == 2
        assert any("EKS cluster fargate-only has no" in d for d in details)
        assert any("ECS cluster svc has no" in d for d in details)
        assert "EKS on Fargate" in details[0]

    def test_feature_on_with_agent_management_off_and_no_hosts_fails(self):
        rows = self._run(
            self._detail(
                agents=[{"Name": "EKS_ADDON_MANAGEMENT", "Status": "DISABLED"}]
            )
        )
        cov = self._named(rows, sagemaker_app.RUNTIME_COVERAGE_FINDING)
        assert [r["Status"] for r in cov] == ["Failed"]
        assert "EC2_AGENT_MANAGEMENT" in cov[0]["Finding_Details"]

    def test_agent_management_on_and_no_hosts_is_na(self):
        cov = self._named(
            self._run(self._detail()), sagemaker_app.RUNTIME_COVERAGE_FINDING
        )
        assert [r["Status"] for r in cov] == ["N/A"]

    def test_coverage_read_denied_is_incomplete_not_passed(self):
        cov = self._named(
            self._run(
                self._detail(),
                coverage=[self._eks("a")],
                errors={"gd": _make_client_error("AccessDeniedException")},
            ),
            sagemaker_app.RUNTIME_COVERAGE_FINDING,
        )
        assert [r["Status"] for r in cov] == ["N/A"]
        assert "guardduty:ListCoverage" in cov[0]["Finding_Details"]

    def test_cluster_population_unread_withholds_passed(self):
        cov = self._named(
            self._run(
                self._detail(),
                coverage=[self._eks("a")],
                eks=["a"],
                errors={"ecs": _make_client_error("AccessDeniedException")},
            ),
            sagemaker_app.RUNTIME_COVERAGE_FINDING,
        )
        assert [r["Status"] for r in cov] == ["N/A"]
        assert "ecs:ListClusters" in cov[0]["Finding_Details"]

    def test_runtime_disabled_skips_coverage_leg(self):
        rows = self._run(self._detail(runtime="DISABLED"))
        assert self._named(rows, sagemaker_app.RUNTIME_COVERAGE_FINDING) == []

    def test_running_instances_all_in_healthy_coverage_pass(self):
        cov = self._named(
            self._run(
                self._detail(),
                coverage=[self._ec2("i-a"), self._ec2("i-b")],
                instances=[self._instance("i-a"), self._instance("i-b")],
            ),
            sagemaker_app.RUNTIME_COVERAGE_FINDING,
        )
        assert [r["Status"] for r in cov] == ["Passed"]
        assert "every running EC2 instance (2)" in cov[0]["Finding_Details"]
        assert "instance population is not compared" not in cov[0]["Finding_Details"]
        assert self.ec2_calls == [
            {"Filters": [{"Name": "instance-state-name", "Values": ["running"]}]}
        ]

    def test_one_unenrolled_instance_among_covered_ones_fails(self):
        cov = self._named(
            self._run(
                self._detail(),
                coverage=[self._ec2("i-a"), self._eks("prod")],
                eks=["prod"],
                instances=[self._instance("i-a"), self._instance("i-new")],
            ),
            sagemaker_app.RUNTIME_COVERAGE_FINDING,
        )
        assert [r["Status"] for r in cov] == ["Failed"]
        assert (
            "EC2 instance i-new has no Runtime Monitoring coverage"
            in cov[0]["Finding_Details"]
        )

    def test_unenrolled_instance_with_no_coverage_at_all_fails(self):
        # With nothing in coverage the leg used to read as "no host yet".
        cov = self._named(
            self._run(self._detail(), instances=[self._instance("i-new")]),
            sagemaker_app.RUNTIME_COVERAGE_FINDING,
        )
        assert [r["Status"] for r in cov] == ["Failed"]
        assert "EC2 instance i-new has no" in cov[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "tags",
        [{"eks:cluster-name": "prod"}, {"kubernetes.io/cluster/prod": "owned"}],
        ids=["managed-node-group", "self-managed"],
    )
    def test_eks_node_is_judged_by_its_cluster_not_as_an_instance(self, tags):
        cov = self._named(
            self._run(
                self._detail(),
                coverage=[self._eks("prod")],
                eks=["prod"],
                instances=[self._instance("i-node", tags=tags)],
            ),
            sagemaker_app.RUNTIME_COVERAGE_FINDING,
        )
        assert [r["Status"] for r in cov] == ["Passed"]
        assert "1 EKS node instance(s)" in cov[0]["Finding_Details"]

    def test_windows_instance_is_not_compared_and_is_named(self):
        cov = self._named(
            self._run(
                self._detail(),
                coverage=[self._ec2("i-a")],
                instances=[
                    self._instance("i-a"),
                    self._instance("i-win", platform="windows"),
                ],
            ),
            sagemaker_app.RUNTIME_COVERAGE_FINDING,
        )
        assert [r["Status"] for r in cov] == ["Passed"]
        assert "1 Windows instance(s)" in cov[0]["Finding_Details"]

    def test_instance_list_denied_withholds_passed(self):
        cov = self._named(
            self._run(
                self._detail(),
                coverage=[self._ec2("i-a")],
                instances=[self._instance("i-a")],
                errors={"ec2": _make_client_error("UnauthorizedOperation")},
            ),
            sagemaker_app.RUNTIME_COVERAGE_FINDING,
        )
        assert [r["Status"] for r in cov] == ["N/A"]
        assert "ec2:DescribeInstances" in cov[0]["Finding_Details"]

    def test_no_instance_and_no_host_na_names_the_instance_read(self):
        cov = self._named(
            self._run(self._detail()), sagemaker_app.RUNTIME_COVERAGE_FINDING
        )
        assert [r["Status"] for r in cov] == ["N/A"]
        assert "no running EC2 instance" in cov[0]["Finding_Details"]
        assert "instance population is not compared" not in cov[0]["Finding_Details"]

    def test_one_function_missing_from_inspector_coverage_fails(self):
        functions = [
            {"FunctionName": "ok"},
            {"FunctionName": "enc", "KMSKeyArn": "arn:aws:kms:us-east-1:1:key/k"},
        ]
        tier = self._named(
            self._run(
                self._detail(),
                functions=functions,
                fn_coverage=[self._fn_cov("ok"), self._fn_cov("ok", "CODE")],
            ),
            sagemaker_app.LAMBDA_RUNTIME_TIER_FINDING,
        )
        assert [r["Status"] for r in tier] == ["Failed"]
        assert "function enc is not in Inspector coverage" in tier[0]["Finding_Details"]
        assert "KmsKeyArn" in tier[0]["Finding_Details"]

    def test_inactive_code_scan_behind_active_package_scan_fails(self):
        tier = self._named(
            self._run(
                self._detail(),
                fn_coverage=[
                    self._fn_cov("fn"),
                    self._fn_cov("fn", "CODE", "INACTIVE", "EXCLUDED_BY_TAG"),
                ],
            ),
            sagemaker_app.LAMBDA_RUNTIME_TIER_FINDING,
        )
        assert [r["Status"] for r in tier] == ["Failed"]
        assert (
            "CODE scanning is INACTIVE (EXCLUDED_BY_TAG)" in tier[0]["Finding_Details"]
        )

    def test_lambda_protection_and_code_scanning_off_fail(self):
        tier = self._named(
            self._run(
                self._detail(lambda_logs="DISABLED"),
                lambda_state={
                    "lambda": {"status": "ENABLED"},
                    "lambdaCode": {"status": "DISABLED"},
                },
            ),
            sagemaker_app.LAMBDA_RUNTIME_TIER_FINDING,
        )
        details = " ".join(r["Finding_Details"] for r in tier)
        assert {r["Status"] for r in tier} == {"Failed"}
        assert "LAMBDA_NETWORK_LOGS" in details
        assert "Inspector Lambda code scanning is DISABLED" in details

    def test_inspector_status_denied_is_incomplete_not_passed(self):
        tier = self._named(
            self._run(
                self._detail(),
                errors={"status": _make_client_error("AccessDeniedException")},
            ),
            sagemaker_app.LAMBDA_RUNTIME_TIER_FINDING,
        )
        assert [r["Status"] for r in tier] == ["N/A"]
        assert "inspector2:BatchGetAccountStatus" in tier[0]["Finding_Details"]

    def test_function_list_denied_is_incomplete_not_passed(self):
        tier = self._named(
            self._run(
                self._detail(),
                errors={"lambda": _make_client_error("AccessDeniedException")},
            ),
            sagemaker_app.LAMBDA_RUNTIME_TIER_FINDING,
        )
        assert [r["Status"] for r in tier] == ["N/A"]
        assert "lambda:ListFunctions" in tier[0]["Finding_Details"]

    def test_failed_rows_are_capped_with_a_summary(self):
        functions = [{"FunctionName": f"f{i}"} for i in range(25)]
        tier = self._named(
            self._run(self._detail(), functions=functions, fn_coverage=[]),
            sagemaker_app.LAMBDA_RUNTIME_TIER_FINDING,
        )
        assert len(tier) == 21
        assert "25 Lambda runtime tier gaps" in tier[-1]["Finding_Details"]

    def test_inventory_error_is_could_not_assess(self):
        rows = _rows(
            self.check(
                detector_inventory={
                    "detector_id": None,
                    "detail": None,
                    "error": RuntimeError("boom"),
                }
            )
        )
        assert_could_not_assess_finding(rows[0])


class TestSM39EksVpcCniNetworkPolicy:
    """AIR-SLF-RT-05: enableNetworkPolicy in the managed vpc-cni add-on."""

    @pytest.mark.parametrize(
        ("configuration_values", "expected"),
        [
            ('{"enableNetworkPolicy":"true"}', True),  # live shape, a string
            ('{"enableNetworkPolicy": true}', True),
            ('{"enableNetworkPolicy":"false"}', False),
            ("{}", False),
            ('["enableNetworkPolicy"]', False),
            ('enableNetworkPolicy: "true"\n', True),
            ("env:\n  X: 1\nenableNetworkPolicy: true\n", True),
            ("nodeAgent:\n  enableNetworkPolicy: true\n", False),
            ("enableNetworkPolicy: false\n", False),
            ("", False),
            (None, False),
        ],
    )
    def test_configuration_values_parser(self, configuration_values, expected):
        assert (
            sagemaker_app._vpc_cni_network_policy_enabled(configuration_values)
            is expected
        )

    @patch("sagemaker_app.boto3.client")
    def test_clusters_across_pages_each_reported_and_error_isolated(self, mock_client):
        addons_by_cluster = {
            # vpc-cni arrives on the second list_addons page.
            "agents-good": [{"addons": ["coredns"]}, {"addons": ["vpc-cni"]}],
            "agents-open": [{"addons": ["vpc-cni", "kube-proxy"]}],
            "agents-calico": [{"addons": ["coredns"]}],
        }

        def list_addons(clusterName):
            if clusterName == "agents-broken":
                raise _make_client_error("AccessDeniedException")
            return addons_by_cluster[clusterName]

        client = MagicMock()
        client.get_paginator.side_effect = _pager(
            {
                "list_clusters": [
                    {"clusters": ["agents-good"]},
                    {"clusters": ["agents-open", "agents-calico", "agents-broken"]},
                ],
                "list_addons": list_addons,
            }
        )
        client.describe_addon.side_effect = lambda clusterName, addonName: {
            "addon": {
                "configurationValues": (
                    '{"enableNetworkPolicy":"true"}'
                    if clusterName == "agents-good"
                    else ""
                )
            }
        }
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_eks_vpc_cni_network_policy("us-east-1"))
        by_status = {}
        for row in rows:
            by_status.setdefault(row["Status"], []).append(row["Finding_Details"])
        assert len(by_status["Failed"]) == 1
        assert "'agents-open'" in by_status["Failed"][0]
        assert len(by_status["Passed"]) == 1
        assert "agents-good" in by_status["Passed"][0]
        assert len(by_status["N/A"]) == 2
        assert any(
            "agents-calico" in d and "self-managed CNI" in d for d in by_status["N/A"]
        )
        assert any(
            "'agents-broken'" in d and "Could not assess" in d for d in by_status["N/A"]
        )
        assert all(r["Check_ID"] == "SM-39" for r in rows)
        client.describe_addon.assert_any_call(
            clusterName="agents-good", addonName="vpc-cni"
        )

    @staticmethod
    def _cluster_client(clusters, config_by_cluster, compute_by_cluster=None):
        """Every cluster runs the managed vpc-cni add-on with the given value."""
        compute_by_cluster = compute_by_cluster or {}
        client = MagicMock()
        client.get_paginator.side_effect = _pager(
            {
                "list_clusters": [{"clusters": clusters}],
                "list_addons": lambda clusterName: [{"addons": ["vpc-cni"]}],
            }
        )
        client.describe_cluster.side_effect = lambda name: {
            "cluster": {"name": name, **compute_by_cluster.get(name, {})}
        }

        def describe_addon(clusterName, addonName):
            addon = {"addonName": addonName}
            if config_by_cluster.get(clusterName) is not None:
                addon["configurationValues"] = config_by_cluster[clusterName]
            return {"addon": addon}

        client.describe_addon.side_effect = describe_addon
        return client

    @patch("sagemaker_app.boto3.client")
    def test_true_then_missing_configuration_values_is_passed_then_failed(
        self, mock_client
    ):
        mock_client.return_value = self._cluster_client(
            ["agents-a", "agents-b"],
            {"agents-a": '{"enableNetworkPolicy":"true"}', "agents-b": None},
        )
        rows = _rows(sagemaker_app.check_eks_vpc_cni_network_policy("us-east-1"))
        assert sorted(r["Status"] for r in rows) == ["Failed", "Passed"]
        failed = next(r for r in rows if r["Status"] == "Failed")
        passed = next(r for r in rows if r["Status"] == "Passed")
        assert "'agents-b'" in failed["Finding_Details"]
        assert "agents-a" in passed["Finding_Details"]
        assert "agents-b" not in passed["Finding_Details"]
        assert (
            "Network-policy enforcement is enabled on the VPC CNI add-on; whether "
            "NetworkPolicy objects restrict pod traffic is a Kubernetes-API fact "
            "this scan cannot read." in passed["Finding_Details"]
        )

    @patch("sagemaker_app.boto3.client")
    def test_boolean_true_configuration_value_passes(self, mock_client):
        mock_client.return_value = self._cluster_client(
            ["agents-bool"], {"agents-bool": '{"enableNetworkPolicy": true}'}
        )
        rows = _rows(sagemaker_app.check_eks_vpc_cni_network_policy("us-east-1"))
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_auto_mode_cluster_is_na_with_the_nodeclass_reason(self, mock_client):
        client = self._cluster_client(
            ["agents-standard", "agents-auto", "agents-auto-off"],
            {
                "agents-standard": '{"enableNetworkPolicy":"true"}',
                "agents-auto-off": '{"enableNetworkPolicy":"true"}',
            },
            {
                "agents-auto": {"computeConfig": {"enabled": True}},
                # computeConfig present but disabled is a standard cluster.
                "agents-auto-off": {"computeConfig": {"enabled": False}},
            },
        )
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_eks_vpc_cni_network_policy("us-east-1"))
        assert sorted(r["Status"] for r in rows) == ["N/A", "Passed"]
        na = next(r for r in rows if r["Status"] == "N/A")
        passed = next(r for r in rows if r["Status"] == "Passed")
        assert "agents-auto" in na["Finding_Details"]
        assert "agents-auto-off" not in na["Finding_Details"]
        assert (
            "EKS Auto Mode sets network policy on the NodeClass, a Kubernetes "
            "object no AWS API returns" in na["Finding_Details"]
        )
        assert "self-managed CNI" not in na["Finding_Details"]
        assert na["Severity"] == "Informational"
        assert "2 EKS cluster(s)" in passed["Finding_Details"]
        assert "agents-auto-off" in passed["Finding_Details"]
        client.describe_cluster.assert_any_call(name="agents-auto")
        assert all(
            c.kwargs["clusterName"] != "agents-auto"
            for c in client.describe_addon.call_args_list
        )

    @patch("sagemaker_app.boto3.client")
    def test_no_clusters_is_na(self, mock_client):
        client = MagicMock()
        client.get_paginator.side_effect = _pager({"list_clusters": [{"clusters": []}]})
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_eks_vpc_cni_network_policy("us-east-1"))
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "No EKS clusters" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_list_clusters_error_is_could_not_assess(self, mock_client):
        client = MagicMock()
        client.get_paginator.side_effect = _make_client_error("AccessDeniedException")
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_eks_vpc_cni_network_policy("us-east-1"))
        assert len(rows) == 1
        assert_could_not_assess_finding(rows[0])


class TestSM39WorkloadSegmentation:
    """AIR-SLF-RT-05: strict enforcing mode and per-workload security groups."""

    check = staticmethod(sagemaker_app.check_workload_network_segmentation)

    @pytest.mark.parametrize(
        ("values", "expected"),
        [
            ('{"env": {"NETWORK_POLICY_ENFORCING_MODE": "strict"}}', "strict"),
            ('{"env": {"NETWORK_POLICY_ENFORCING_MODE": "standard"}}', "standard"),
            ('{"enableNetworkPolicy": "true"}', None),
            ('{"env": "x"}', None),
            ("env:\n  NETWORK_POLICY_ENFORCING_MODE: 'strict'\nx: 1\n", "strict"),
            ("env:\n  X: 1\nNETWORK_POLICY_ENFORCING_MODE: strict\n", None),
            ("", None),
            (None, None),
        ],
    )
    def test_env_value_parser(self, values, expected):
        assert (
            sagemaker_app._vpc_cni_env_value(values, "NETWORK_POLICY_ENFORCING_MODE")
            == expected
        )

    @staticmethod
    def _sg(group_id, ingress=None, egress=None):
        return {
            "GroupId": group_id,
            "IpPermissions": ingress or [],
            "IpPermissionsEgress": (
                egress
                if egress is not None
                else [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "UserIdGroupPairs": [{"GroupId": "sg-dep"}],
                    }
                ]
            ),
        }

    @staticmethod
    def _open(cidr="0.0.0.0/0", protocol="-1", port=None, v6=False):
        rule = {"IpProtocol": protocol}
        if port is not None:
            rule.update(FromPort=port, ToPort=port)
        if v6:
            rule["Ipv6Ranges"] = [{"CidrIpv6": cidr}]
        else:
            rule["IpRanges"] = [{"CidrIp": cidr}]
        return rule

    def _run(
        self,
        services=None,
        functions=None,
        groups=None,
        eks=None,
        errors=None,
        prefix_lists=None,
        instances=None,
    ):
        """services: {cluster: [service dicts]}; eks: {cluster: config string}.

        prefix_lists: {id: (owner, [cidrs] or an exception the entries read raises)}.
        instances: EC2 instance dicts, one reservation page each.
        """
        instances = instances or []
        prefix_lists = prefix_lists or {}
        errors = errors or {}
        by_cluster = services or {}
        functions = functions or []
        # The dependency groups the fixtures' rules reference, readable unless a
        # test passes its own copy.
        groups = {
            g: {"GroupId": g, "GroupName": g[len("sg-") :]}
            for g in ("sg-dep", "sg-alb")
        } | {g["GroupId"]: g for g in groups or []}
        eks = eks or {}

        def source(key, pages):
            def paginate(**kwargs):
                if key in errors:
                    raise errors[key]
                return pages(**kwargs) if callable(pages) else pages

            return paginate

        def factory(service, **kwargs):
            client = MagicMock()
            if service == "eks":
                client.get_paginator.side_effect = _pager(
                    {
                        "list_clusters": source("eks", [{"clusters": list(eks)}]),
                        "list_addons": lambda clusterName: [{"addons": ["vpc-cni"]}],
                    }
                )
                client.describe_cluster.side_effect = lambda name: {"cluster": {}}
                client.describe_addon.side_effect = lambda clusterName, addonName: {
                    "addon": {"configurationValues": eks[clusterName]}
                }
            elif service == "ecs":
                client.get_paginator.side_effect = _pager(
                    {
                        "list_clusters": source(
                            "ecs",
                            [
                                {
                                    "clusterArns": [
                                        f"arn:c/cluster/{c}" for c in by_cluster
                                    ]
                                }
                            ],
                        ),
                        "list_services": lambda cluster: [
                            {
                                "serviceArns": [
                                    s["serviceName"]
                                    for s in by_cluster[cluster.rsplit("/", 1)[-1]]
                                ]
                            }
                        ],
                    }
                )

                def describe_services(cluster, services):
                    by_name = {
                        s["serviceName"]: s
                        for s in by_cluster[cluster.rsplit("/", 1)[-1]]
                    }
                    return {"services": [by_name[n] for n in services]}

                client.describe_services.side_effect = describe_services
            elif service == "lambda":
                client.get_paginator.side_effect = _pager(
                    {"list_functions": source("lambda", [{"Functions": functions}])}
                )
            elif service == "ec2":

                def describe_security_groups(GroupIds):
                    if "ec2" in errors:
                        raise errors["ec2"]
                    return {
                        "SecurityGroups": [groups[g] for g in GroupIds if g in groups]
                    }

                client.describe_security_groups.side_effect = describe_security_groups

                def describe_prefix_lists(PrefixListIds):
                    if "prefix_lists" in errors:
                        raise errors["prefix_lists"]
                    return [
                        {
                            "PrefixLists": [
                                {"PrefixListId": p, "OwnerId": prefix_lists[p][0]}
                                for p in PrefixListIds
                                if p in prefix_lists
                            ]
                        }
                    ]

                def prefix_list_entries(PrefixListId):
                    entries = prefix_lists[PrefixListId][1]
                    if isinstance(entries, Exception):
                        raise entries
                    # One entry per page, so a reader of only the first page
                    # misses every later entry.
                    return [{"Entries": [{"Cidr": cidr}]} for cidr in entries]

                client.get_paginator.side_effect = _pager(
                    {
                        "describe_managed_prefix_lists": describe_prefix_lists,
                        "get_managed_prefix_list_entries": prefix_list_entries,
                        "describe_instances": source(
                            "instances",
                            lambda Filters: [
                                {"Reservations": [{"Instances": [instance]}]}
                                for instance in instances
                            ],
                        ),
                    }
                )
            return client

        with patch("sagemaker_app.boto3.client", side_effect=factory):
            return _rows(self.check(region="us-east-1"))

    @staticmethod
    def _instance(instance_id, groups, extra_groups=(), asg=None):
        instance = {
            "InstanceId": instance_id,
            "SecurityGroups": [{"GroupId": g} for g in groups],
            "NetworkInterfaces": [
                {"Groups": [{"GroupId": g} for g in groups]},
                {"Groups": [{"GroupId": g} for g in extra_groups]},
            ],
        }
        if asg:
            instance["Tags"] = [{"Key": "aws:autoscaling:groupName", "Value": asg}]
        return instance

    @staticmethod
    def _service(name, groups):
        service = {"serviceName": name}
        if groups is not None:
            service["networkConfiguration"] = {
                "awsvpcConfiguration": {"securityGroups": groups}
            }
        return service

    @staticmethod
    def _function(name, groups):
        function = {"FunctionName": name}
        if groups:
            function["VpcConfig"] = {"SecurityGroupIds": groups}
        return function

    @staticmethod
    def _seg(rows):
        return [
            r
            for r in rows
            if r["Finding"].startswith(sagemaker_app.WORKLOAD_SEGMENTATION_FINDING)
        ]

    @staticmethod
    def _mode(rows):
        return [
            r
            for r in rows
            if r["Finding"].startswith(sagemaker_app.EKS_POLICY_MODE_FINDING)
        ]

    def test_scoped_own_groups_pass(self):
        rows = self._run(
            services={"agents": [self._service("planner", ["sg-a"])]},
            functions=[self._function("tool", ["sg-b"])],
            groups=[
                self._sg(
                    "sg-a",
                    ingress=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 8080,
                            "ToPort": 8080,
                            "UserIdGroupPairs": [{"GroupId": "sg-alb"}],
                        }
                    ],
                ),
                self._sg("sg-b"),
            ],
        )
        seg = self._seg(rows)
        assert [r["Status"] for r in seg] == ["Passed"]
        assert (
            "All 2 ECS service(s) and Lambda function(s)" in seg[0]["Finding_Details"]
        )

    def test_one_open_egress_group_among_scoped_ones_fails(self):
        rows = self._run(
            services={
                "agents": [
                    self._service("planner", ["sg-a"]),
                    self._service("executor", ["sg-b"]),
                ]
            },
            groups=[self._sg("sg-a"), self._sg("sg-b", egress=[self._open()])],
        )
        seg = self._seg(rows)
        assert [r["Status"] for r in seg] == ["Failed"]
        assert "ECS service executor in agents" in seg[0]["Finding_Details"]
        assert (
            "sg-b allows egress all traffic to 0.0.0.0/0" in seg[0]["Finding_Details"]
        )

    def test_vpc_wide_cidr_hides_behind_a_port_scoped_rule(self):
        # One 443 rule to a whole /16 still reaches every host in the VPC.
        rows = self._run(
            services={"agents": [self._service("planner", ["sg-a"])]},
            groups=[
                self._sg(
                    "sg-a",
                    ingress=[self._open("10.0.0.0/16", "tcp", 443)],
                    egress=[self._open("10.0.12.0/24", "tcp", 5432)],
                )
            ],
        )
        seg = self._seg(rows)
        assert [r["Status"] for r in seg] == ["Failed"]
        details = seg[0]["Finding_Details"]
        assert "allows ingress tcp 443 from 10.0.0.0/16" in details
        assert "10.0.12.0/24" not in details

    def _wide_and_narrow(self, cidr, v6, wide_first):
        services = [
            self._service("wide", ["sg-w"]),
            self._service("narrow", ["sg-n"]),
        ]
        if not wide_first:
            services.reverse()
        return self._seg(
            self._run(
                services={"agents": services},
                groups=[
                    self._sg("sg-w", egress=[self._open(cidr, "tcp", 443, v6=v6)]),
                    self._sg(
                        "sg-n",
                        egress=[
                            self._open("10.0.12.0/24", "tcp", 5432),
                            self._open("2001:db8:0:1::/64", "tcp", 5432, v6=True),
                        ],
                    ),
                ],
            )
        )

    @pytest.mark.parametrize(
        ("cidr", "v6"),
        [("10.0.0.0/16", False), ("10.0.0.0/8", False), ("2001:db8::/48", True)],
    )
    @pytest.mark.parametrize("wide_first", [True, False])
    def test_a_cidr_of_16_or_wider_fails_only_its_workload(self, cidr, v6, wide_first):
        seg = self._wide_and_narrow(cidr, v6, wide_first)
        assert [r["Status"] for r in seg] == ["Failed"]
        details = seg[0]["Finding_Details"]
        assert f"sg-w allows egress tcp 443 to {cidr}" in details
        assert "a CIDR of /16 (IPv6 /48) or wider" in details
        assert "narrow" not in details

    @pytest.mark.parametrize(
        ("cidr", "v6"),
        [
            ("10.0.0.0/17", False),
            ("10.0.0.0/23", False),
            ("2001:db8::/49", True),
            ("2001:db8::/63", True),
        ],
    )
    @pytest.mark.parametrize("wide_first", [True, False])
    def test_a_cidr_between_16_and_24_is_not_judged_and_withholds_the_pass(
        self, cidr, v6, wide_first
    ):
        # AIR-SLF-RT-05 names no CIDR width, so neither verdict is claimed.
        seg = self._wide_and_narrow(cidr, v6, wide_first)
        assert [r["Status"] for r in seg] == ["N/A"]
        assert seg[0]["Finding"] == (
            f"{sagemaker_app.WORKLOAD_SEGMENTATION_FINDING} CIDR Width Not Judged"
        )
        details = seg[0]["Finding_Details"]
        assert f"ECS service wide in agents: sg-w allows egress tcp 443 to {cidr}" in (
            details
        )
        assert "narrower than /16 (IPv6 /48) and wider than /24 (IPv6 /64)" in details
        assert "AIR-SLF-RT-05" in details
        assert "names no width" in details
        assert "narrow in agents" not in details

    def test_each_workload_with_an_unjudged_cidr_is_named(self):
        seg = self._seg(
            self._run(
                functions=[
                    self._function("one", ["sg-a"]),
                    self._function("two", ["sg-b"]),
                ],
                groups=[
                    self._sg("sg-a", egress=[self._open("10.0.0.0/20", "tcp", 443)]),
                    self._sg("sg-b", egress=[self._open("10.1.0.0/22", "tcp", 443)]),
                ],
            )
        )
        assert [r["Status"] for r in seg] == ["N/A"]
        details = seg[0]["Finding_Details"]
        assert details.startswith("2 rule(s)")
        assert "Lambda function one: sg-a allows egress tcp 443 to 10.0.0.0/20" in (
            details
        )
        assert "Lambda function two: sg-b allows egress tcp 443 to 10.1.0.0/22" in (
            details
        )

    def test_a_broad_cidr_fails_beside_an_unjudged_one(self):
        seg = self._seg(
            self._run(
                functions=[
                    self._function("broad", ["sg-a"]),
                    self._function("between", ["sg-b"]),
                ],
                groups=[
                    self._sg("sg-a", egress=[self._open("10.0.0.0/16", "tcp", 443)]),
                    self._sg("sg-b", egress=[self._open("10.1.0.0/20", "tcp", 443)]),
                ],
            )
        )
        assert [r["Status"] for r in seg] == ["Failed", "N/A"]
        assert "Lambda function broad:" in seg[0]["Finding_Details"]
        assert "between" not in seg[0]["Finding_Details"]
        assert "Lambda function between:" in seg[1]["Finding_Details"]
        assert "Lambda function broad" not in seg[1]["Finding_Details"]

    def test_the_passed_row_names_the_24_bound(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[
                    self._sg("sg-a", egress=[self._open("10.0.12.0/24", "tcp", 443)])
                ],
            )
        )
        assert [r["Status"] for r in seg] == ["Passed"]
        assert "a CIDR wider than /24 (IPv6 /64)" in seg[0]["Finding_Details"]

    @staticmethod
    def _to_list(*prefix_list_ids):
        return {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "PrefixListIds": [{"PrefixListId": p} for p in prefix_list_ids],
        }

    @pytest.mark.parametrize(
        ("prefix_lists", "errors", "action"),
        [
            (
                {"pl-1": ("111122223333", _make_client_error("AccessDenied"))},
                {},
                "ec2:GetManagedPrefixListEntries: ",
            ),
            (
                {"pl-1": ("111122223333", ["10.0.1.0/24"])},
                {"prefix_lists": _make_client_error("AccessDenied")},
                "ec2:DescribeManagedPrefixLists: ",
            ),
            ({}, {}, "not returned by ec2:DescribeManagedPrefixLists"),
        ],
    )
    def test_an_unread_prefix_list_withholds_the_pass(
        self, prefix_lists, errors, action
    ):
        seg = self._seg(
            self._run(
                functions=[
                    self._function("tool", ["sg-a"]),
                    self._function("other", ["sg-b"]),
                ],
                groups=[
                    self._sg("sg-a", egress=[self._to_list("pl-1")]),
                    self._sg("sg-b"),
                ],
                prefix_lists=prefix_lists,
                errors=errors,
            )
        )
        assert [r["Status"] for r in seg] == ["N/A"]
        details = seg[0]["Finding_Details"]
        assert "prefix list pl-1 in sg-a" in details
        assert action in details
        assert "sg-b" not in details

    def test_an_aws_managed_prefix_list_is_credited(self):
        # AWS's S3 list holds /15 and /16 ranges; they are not judged by width.
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[self._sg("sg-a", egress=[self._to_list("pl-63a5400a")])],
                prefix_lists={"pl-63a5400a": ("AWS", ["52.216.0.0/15"])},
            )
        )
        assert [r["Status"] for r in seg] == ["Passed"]
        assert "customer-managed prefix list" in seg[0]["Finding_Details"]

    def test_a_customer_prefix_list_of_narrow_entries_passes(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[self._sg("sg-a", egress=[self._to_list("pl-1")])],
                prefix_lists={"pl-1": ("111122223333", ["10.0.1.0/24", "10.0.2.9/32"])},
            )
        )
        assert [r["Status"] for r in seg] == ["Passed"]

    @pytest.mark.parametrize("broad_last", [True, False])
    def test_a_broad_entry_in_a_customer_prefix_list_fails_only_its_workload(
        self, broad_last
    ):
        # The broad entry sits on a later page of a later list, and the
        # passing workload uses an AWS-managed list, so neither the first
        # page nor the first list alone decides the verdict.
        entries = ["10.0.1.0/24", "10.0.0.0/16"]
        if not broad_last:
            entries.reverse()
        seg = self._seg(
            self._run(
                functions=[
                    self._function("tool", ["sg-a"]),
                    self._function("other", ["sg-b"]),
                ],
                groups=[
                    self._sg("sg-a", egress=[self._to_list("pl-0", "pl-1")]),
                    self._sg("sg-b", egress=[self._to_list("pl-aws")]),
                ],
                prefix_lists={
                    "pl-0": ("111122223333", ["10.0.9.0/24"]),
                    "pl-1": ("111122223333", entries),
                    "pl-aws": ("AWS", ["52.216.0.0/15"]),
                },
            )
        )
        assert [r["Status"] for r in seg] == ["Failed"]
        details = seg[0]["Finding_Details"]
        assert "10.0.0.0/16 in pl-1" in details
        assert "an entry of a customer-managed prefix list" in details
        assert "tool" in details
        assert "other" not in details
        assert "pl-aws" not in details

    def test_a_broad_ipv6_entry_in_a_customer_prefix_list_fails(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[self._sg("sg-a", egress=[self._to_list("pl-1")])],
                prefix_lists={"pl-1": ("111122223333", ["2600:1f18::/40"])},
            )
        )
        assert [r["Status"] for r in seg] == ["Failed"]
        assert "2600:1f18::/40 in pl-1" in seg[0]["Finding_Details"]

    def test_a_between_width_prefix_list_entry_is_unjudged(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[self._sg("sg-a", egress=[self._to_list("pl-1")])],
                prefix_lists={"pl-1": ("111122223333", ["10.0.0.0/20"])},
            )
        )
        assert [r["Status"] for r in seg] == ["N/A"]
        assert "10.0.0.0/20 in pl-1" in seg[0]["Finding_Details"]

    def test_an_unread_prefix_list_does_not_hide_a_broad_one(self):
        seg = self._seg(
            self._run(
                functions=[
                    self._function("tool", ["sg-a"]),
                    self._function("other", ["sg-b"]),
                ],
                groups=[
                    self._sg("sg-a", egress=[self._to_list("pl-1")]),
                    self._sg("sg-b", egress=[self._to_list("pl-2")]),
                ],
                prefix_lists={
                    "pl-1": ("111122223333", _make_client_error("AccessDenied")),
                    "pl-2": ("111122223333", ["0.0.0.0/0"]),
                },
            )
        )
        assert [r["Status"] for r in seg] == ["Failed", "N/A"]
        assert "0.0.0.0/0 in pl-2" in seg[0]["Finding_Details"]
        assert "pl-1" not in seg[0]["Finding_Details"]
        assert "prefix list pl-1 in sg-a" in seg[1]["Finding_Details"]

    @pytest.mark.parametrize("default_first", [True, False])
    def test_a_rule_to_the_vpc_default_group_fails_only_its_workload(
        self, default_first
    ):
        functions = [
            self._function("loose", ["sg-a"]),
            self._function("scoped", ["sg-b"]),
        ]
        if not default_first:
            functions.reverse()
        seg = self._seg(
            self._run(
                functions=functions,
                groups=[
                    self._sg(
                        "sg-a",
                        egress=[
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "UserIdGroupPairs": [{"GroupId": "sg-def"}],
                            }
                        ],
                    ),
                    self._sg("sg-b"),
                    {"GroupId": "sg-def", "GroupName": "default"},
                ],
            )
        )
        assert [r["Status"] for r in seg] == ["Failed"]
        details = seg[0]["Finding_Details"]
        assert details.startswith("Lambda function loose:")
        assert (
            "sg-a allows egress tcp 443 to sg-def, the default security group of "
            "its VPC"
        ) in details
        assert "scoped" not in details

    def test_an_unread_referenced_group_withholds_the_pass(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[
                    self._sg(
                        "sg-a",
                        egress=[
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "UserIdGroupPairs": [
                                    {"GroupId": "sg-gone"},
                                    {"GroupId": "sg-far", "UserId": "444455556666"},
                                ],
                            }
                        ],
                    )
                ],
            )
        )
        assert [r["Status"] for r in seg] == ["N/A"]
        details = seg[0]["Finding_Details"]
        assert "security group sg-gone referenced by sg-a" in details
        assert "security group sg-far referenced by sg-a" in details

    def test_ipv6_any_egress_fails(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[self._sg("sg-a", egress=[self._open("::/0", v6=True)])],
            )
        )
        assert [r["Status"] for r in seg] == ["Failed"]
        assert "to ::/0" in seg[0]["Finding_Details"]

    def test_lambda_ingress_is_not_graded(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[self._sg("sg-a", ingress=[self._open()])],
            )
        )
        assert [r["Status"] for r in seg] == ["Passed"]

    def test_shared_group_fails_for_each_user(self):
        seg = self._seg(
            self._run(
                functions=[
                    self._function("one", ["sg-a"]),
                    self._function("two", ["sg-a"]),
                ],
                groups=[self._sg("sg-a")],
            )
        )
        assert [r["Status"] for r in seg] == ["Failed", "Failed"]
        assert "sg-a is shared with 1 other workload(s)" in seg[0]["Finding_Details"]

    def test_an_open_ec2_instance_among_scoped_ones_fails(self):
        # The open group is on the instance's second network interface only.
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                instances=[
                    self._instance("i-scoped", ["sg-b"]),
                    self._instance("i-open", ["sg-c"], extra_groups=["sg-d"]),
                ],
                groups=[
                    self._sg("sg-a"),
                    self._sg("sg-b"),
                    self._sg("sg-c"),
                    self._sg("sg-d", ingress=[self._open("0.0.0.0/0", "tcp", 22)]),
                ],
            )
        )
        assert [r["Status"] for r in seg] == ["Failed"]
        details = seg[0]["Finding_Details"]
        assert "EC2 instance i-open: sg-d allows ingress tcp 22 from 0.0.0.0/0" in (
            details
        )
        assert "i-scoped" not in details

    def test_scoped_ec2_instances_pass_and_are_counted(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                instances=[
                    self._instance("i-1", ["sg-b"]),
                    self._instance("i-2", ["sg-c"]),
                ],
                groups=[self._sg("sg-a"), self._sg("sg-b"), self._sg("sg-c")],
            )
        )
        assert [r["Status"] for r in seg] == ["Passed"]
        details = seg[0]["Finding_Details"]
        assert "All 1 ECS service(s) and Lambda function(s)" in details
        assert "all 2 EC2 instance(s) or Auto Scaling group(s)" in details
        assert "not read" not in details

    def test_instances_of_one_auto_scaling_group_are_one_workload(self):
        seg = self._seg(
            self._run(
                instances=[
                    self._instance("i-1", ["sg-a"], asg="agents"),
                    self._instance("i-2", ["sg-a"], asg="agents"),
                ],
                groups=[self._sg("sg-a")],
            )
        )
        assert [r["Status"] for r in seg] == ["Passed"]

    def test_standalone_instances_sharing_a_group_fail(self):
        seg = self._seg(
            self._run(
                instances=[
                    self._instance("i-1", ["sg-a"]),
                    self._instance("i-2", ["sg-a"], asg="agents"),
                ],
                groups=[self._sg("sg-a")],
            )
        )
        assert [r["Status"] for r in seg] == ["Failed", "Failed"]
        assert "sg-a is shared with 1 other workload(s)" in seg[0]["Finding_Details"]

    def test_instance_list_denied_withholds_passed(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[self._sg("sg-a")],
                errors={"instances": _make_client_error("UnauthorizedOperation")},
            )
        )
        assert [r["Status"] for r in seg] == ["N/A"]
        assert "ec2:DescribeInstances" in seg[0]["Finding_Details"]

    def test_bridge_mode_service_and_non_vpc_function_fail(self):
        seg = self._seg(
            self._run(
                services={"agents": [self._service("legacy", None)]},
                functions=[self._function("edge", None)],
            )
        )
        details = " ".join(r["Finding_Details"] for r in seg)
        assert {r["Status"] for r in seg} == {"Failed"}
        assert "legacy in agents has no awsvpc network configuration" in details
        assert "1 Lambda function(s) run outside a VPC" in details

    def test_security_group_read_denied_is_incomplete_not_passed(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[self._sg("sg-a")],
                errors={"ec2": _make_client_error("UnauthorizedOperation")},
            )
        )
        assert [r["Status"] for r in seg] == ["N/A"]
        assert "ec2:DescribeSecurityGroups" in seg[0]["Finding_Details"]

    def test_ecs_list_denied_withholds_passed(self):
        seg = self._seg(
            self._run(
                functions=[self._function("tool", ["sg-a"])],
                groups=[self._sg("sg-a")],
                errors={"ecs": _make_client_error("AccessDeniedException")},
            )
        )
        assert [r["Status"] for r in seg] == ["N/A"]
        assert "ecs:ListClusters" in seg[0]["Finding_Details"]

    def test_lambda_list_denied_withholds_passed(self):
        seg = self._seg(
            self._run(
                services={"agents": [self._service("planner", ["sg-a"])]},
                groups=[self._sg("sg-a")],
                errors={"lambda": _make_client_error("AccessDeniedException")},
            )
        )
        assert [r["Status"] for r in seg] == ["N/A"]
        assert "lambda:ListFunctions" in seg[0]["Finding_Details"]

    def test_no_workloads_is_na(self):
        assert [r["Status"] for r in self._seg(self._run())] == ["N/A"]

    def test_failed_rows_are_capped_with_a_summary(self):
        functions = [self._function(f"f{i}", [f"sg-{i}"]) for i in range(25)]
        groups = [self._sg(f"sg-{i}", egress=[self._open()]) for i in range(25)]
        seg = self._seg(self._run(functions=functions, groups=groups))
        assert len(seg) == 21
        assert "25 workload segmentation gaps" in seg[-1]["Finding_Details"]

    def test_standard_mode_cluster_among_strict_ones_fails(self):
        mode = self._mode(
            self._run(
                eks={
                    "strict-a": json.dumps(
                        {
                            "enableNetworkPolicy": "true",
                            "env": {
                                "NETWORK_POLICY_ENFORCING_MODE": "strict",
                                "ENABLE_POD_ENI": "true",
                            },
                        }
                    ),
                    "default-b": '{"enableNetworkPolicy": "true"}',
                    "off-c": '{"enableNetworkPolicy": "false"}',
                }
            )
        )
        by_status = {r["Status"]: r["Finding_Details"] for r in mode}
        assert sorted(r["Status"] for r in mode) == ["Failed", "Passed"]
        assert "'default-b'" in by_status["Failed"]
        assert "standard (the default)" in by_status["Failed"]
        assert "strict-a (security groups for pods are enabled)" in by_status["Passed"]
        assert "off-c" not in " ".join(by_status.values())

    def test_eks_list_denied_is_incomplete(self):
        mode = self._mode(
            self._run(errors={"eks": _make_client_error("AccessDeniedException")})
        )
        assert [r["Status"] for r in mode] == ["N/A"]
        assert "eks:ListClusters" in mode[0]["Finding_Details"]


class TestSM40SecretsManagerRotation:
    """AIR-SLF-RT-06: automatic rotation that actually happened on schedule."""

    @pytest.mark.parametrize(
        ("rules", "expected"),
        [
            ({"ScheduleExpression": "rate(30 days)"}, 30.0),
            ({"ScheduleExpression": "rate(1 day)"}, 1.0),
            ({"ScheduleExpression": "rate(4 hours)"}, 4 / 24),
            ({"ScheduleExpression": "cron(0 16 1,15 * ? *)"}, 17.0),
            ({"ScheduleExpression": "cron(0 8 ? * SAT *)"}, 7.0),
            ({"ScheduleExpression": "cron(0 8 1 * ? *)"}, 31.0),
            ({"ScheduleExpression": "cron(0 8 L * ? *)"}, 31.0),
            ({"ScheduleExpression": "cron(0 8 ? * MON-FRI *)"}, 3.0),
            ({"ScheduleExpression": "cron(0 8 ? * SUN#1 *)"}, 35.0),
            ({"ScheduleExpression": "cron(0 8 ? * SUNL *)"}, 35.0),
            ({"ScheduleExpression": "cron(0 8 ? 1/3 SUN#1 *)"}, 91.0),
            ({"ScheduleExpression": "cron(0 4/12 * * ? *)"}, 1.0),
            ({"ScheduleExpression": "cron(0 8 15W * ? *)"}, None),
            ({"ScheduleExpression": "cron(0 8 ? * FOO#1 *)"}, None),
            ({"ScheduleExpression": "cron(0 8 1 * ? 2025)"}, None),
            ({"ScheduleExpression": "rate(2 weeks)"}, None),
            ({"AutomaticallyAfterDays": 45}, 45.0),
            ({}, None),
        ],
    )
    def test_rotation_interval_parser(self, rules, expected):
        assert sagemaker_app._rotation_interval_days(rules) == expected

    def _run(self, mock_client, pages):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = iter(pages)
        client.get_paginator.return_value = paginator
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_secrets_manager_rotation("us-east-1"))
        client.get_paginator.assert_called_once_with("list_secrets")
        paginator.paginate.assert_called_once_with()
        return rows

    @staticmethod
    def _ago(days):
        from datetime import datetime, timedelta, timezone

        return datetime.now(timezone.utc) - timedelta(days=days)

    @patch("sagemaker_app.boto3.client")
    def test_every_outcome_across_two_pages(self, mock_client):
        rate30 = {"ScheduleExpression": "rate(30 days)"}
        rows = self._run(
            mock_client,
            [
                {
                    "SecretList": [
                        {
                            "Name": "on-time",
                            "RotationEnabled": True,
                            "LastRotatedDate": self._ago(10),
                            "RotationRules": rate30,
                        },
                        # RotationEnabled is absent when rotation was never set up.
                        {"Name": "never-configured"},
                    ]
                },
                {
                    "SecretList": [
                        {
                            "Name": "never-rotated",
                            "RotationEnabled": True,
                            "RotationRules": rate30,
                        },
                        {
                            "Name": "overdue",
                            "RotationEnabled": True,
                            "LastRotatedDate": self._ago(60),
                            "RotationRules": rate30,
                        },
                        {
                            "Name": "agentcore-owned",
                            "OwningService": "bedrock-agentcore-identity",
                        },
                        {
                            "Name": "weekday-schedule",
                            "RotationEnabled": True,
                            "LastRotatedDate": self._ago(1),
                            "RotationRules": {
                                "ScheduleExpression": "cron(0 8 15W * ? *)"
                            },
                        },
                    ]
                },
            ],
        )
        failed = [r["Finding_Details"] for r in rows if r["Status"] == "Failed"]
        passed = [r["Finding_Details"] for r in rows if r["Status"] == "Passed"]
        na = [r["Finding_Details"] for r in rows if r["Status"] == "N/A"]
        assert len(failed) == 3
        assert "'never-configured' has no automatic rotation" in failed[0]
        assert "'never-rotated'" in failed[1] and "never rotated" in failed[1]
        assert "'overdue' last rotated 60 days ago" in failed[2]
        assert len(passed) == 1
        assert "on-time" in passed[0]
        assert "1 secret(s) managed by another AWS service" in passed[0]
        assert "agentcore-owned" not in " ".join(failed + passed + na)
        assert len(na) == 1 and "weekday-schedule" in na[0]
        assert all(r["Check_ID"] == "SM-40" for r in rows)

    @pytest.mark.parametrize(
        ("age_days", "expected"), [(1.5, "Passed"), (2.5, "Failed")]
    )
    @patch("sagemaker_app.boto3.client")
    def test_one_day_grace_beyond_the_schedule(self, mock_client, age_days, expected):
        rows = self._run(
            mock_client,
            [
                {
                    "SecretList": [
                        {
                            "Name": "daily",
                            "RotationEnabled": True,
                            "LastRotatedDate": self._ago(age_days),
                            "RotationRules": {"ScheduleExpression": "rate(1 day)"},
                        }
                    ]
                }
            ],
        )
        assert [r["Status"] for r in rows] == [expected]

    @pytest.mark.parametrize(
        "rules",
        [
            {"ScheduleExpression": "rate(365 days)"},
            {"ScheduleExpression": "rate(2184 hours)"},
            {"AutomaticallyAfterDays": 91},
            {"ScheduleExpression": "cron(0 0 1 1 ? *)"},
        ],
    )
    @pytest.mark.parametrize("long_first", [True, False])
    @patch("sagemaker_app.boto3.client")
    def test_a_schedule_longer_than_90_days_fails_only_its_secret(
        self, mock_client, rules, long_first
    ):
        secrets = [
            {
                "Name": "yearly",
                "RotationEnabled": True,
                "LastRotatedDate": self._ago(1),
                "RotationRules": rules,
            },
            {
                "Name": "monthly",
                "RotationEnabled": True,
                "LastRotatedDate": self._ago(1),
                "RotationRules": {"ScheduleExpression": "rate(30 days)"},
            },
        ]
        if not long_first:
            secrets.reverse()
        rows = self._run(mock_client, [{"SecretList": secrets}])
        assert [r["Status"] for r in rows] == ["Failed", "Passed"]
        assert "Secret 'yearly'" in rows[0]["Finding_Details"]
        assert "longer than 90 days" in rows[0]["Finding_Details"]
        assert "SecretsManager.4" in rows[0]["Finding_Details"]
        assert "monthly" in rows[1]["Finding_Details"]
        assert "yearly" not in rows[1]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_a_90_day_schedule_passes(self, mock_client):
        rows = self._run(
            mock_client,
            [
                {
                    "SecretList": [
                        {
                            "Name": "quarterly",
                            "RotationEnabled": True,
                            "LastRotatedDate": self._ago(1),
                            "RotationRules": {"AutomaticallyAfterDays": 90},
                        }
                    ]
                }
            ],
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_naive_last_rotated_date_is_read_as_utc(self, mock_client):
        rows = self._run(
            mock_client,
            [
                {
                    "SecretList": [
                        {
                            "Name": "naive",
                            "RotationEnabled": True,
                            "LastRotatedDate": self._ago(3).replace(tzinfo=None),
                            "RotationRules": {"AutomaticallyAfterDays": 30},
                        }
                    ]
                }
            ],
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_only_service_owned_secrets_is_na_with_skip_note(self, mock_client):
        rows = self._run(
            mock_client,
            [{"SecretList": [{"Name": "x", "OwningService": "appflow"}]}],
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert (
            "1 secret(s) managed by another AWS service" in rows[0]["Finding_Details"]
        )

    @patch("sagemaker_app.boto3.client")
    def test_no_secrets_is_na(self, mock_client):
        rows = self._run(mock_client, [{"SecretList": []}])
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "were skipped" not in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_list_error_is_could_not_assess(self, mock_client):
        client = MagicMock()
        client.get_paginator.side_effect = _make_client_error("AccessDeniedException")
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_secrets_manager_rotation("us-east-1"))
        assert len(rows) == 1
        assert_could_not_assess_finding(rows[0])


_IOT_TOPIC = "arn:aws:iot:us-east-1:123456789012:topic/"
_IOT_CLIENT = "arn:aws:iot:us-east-1:123456789012:client/"
_ATTACHED = {"Bool": {"iot:Connection.Thing.IsAttached": "true"}}


def _iot_document(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _scoped_iot_document():
    return _iot_document(
        {
            "Effect": "Allow",
            "Action": "iot:Connect",
            "Resource": _IOT_CLIENT + "${iot:Connection.Thing.ThingName}",
            "Condition": _ATTACHED,
        },
        {
            "Effect": "Allow",
            "Action": ["iot:Publish", "iot:Receive"],
            "Resource": _IOT_TOPIC + "devices/${iot:Connection.Thing.ThingName}/*",
        },
    )


class TestSM40RotationHistoryAndPropagation:
    """AIR-SLF-RT-06: rotation outcomes, propagation to ECS, plaintext credentials."""

    check = staticmethod(sagemaker_app.check_secret_rotation_history_and_propagation)
    ARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:db-AbCdEf"
    NOW = datetime.now(timezone.utc)

    def _secret(self, name="db", arn=None, rotating=True, last_days=2):
        secret = {"Name": name, "ARN": arn or self.ARN, "RotationEnabled": rotating}
        if last_days is not None:
            secret["LastRotatedDate"] = self.NOW - timedelta(days=last_days)
        return secret

    def _event(self, name, days_ago, secret=None):
        return {
            "EventName": name,
            "EventTime": self.NOW - timedelta(days=days_ago),
            "CloudTrailEvent": json.dumps(
                {"additionalEventData": {"SecretId": secret or self.ARN}}
            ),
        }

    @staticmethod
    def _task(containers):
        return {"containerDefinitions": containers}

    def _run(
        self,
        secrets=None,
        events=None,
        services=None,
        task_defs=None,
        functions=None,
        rules=None,
        errors=None,
        models=None,
    ):
        """services: [(cluster, name, task def arn)]; rules: [(pattern, targets)].

        models: {name: DescribeModel response, or an exception it raises}.
        """
        errors = errors or {}
        models = models or {}
        secrets = secrets if secrets is not None else [self._secret()]
        events = events or []
        services = services or []
        task_defs = task_defs or {}
        functions = functions or []
        rules = rules or []
        # describe_services receives its own services kwarg.
        service_rows = services

        def source(key, pages):
            def paginate(**kwargs):
                if key in errors:
                    raise errors[key]
                return pages(**kwargs) if callable(pages) else pages

            return paginate

        def factory(service, **kwargs):
            client = MagicMock()
            if service == "secretsmanager":
                client.get_paginator.side_effect = _pager(
                    {"list_secrets": source("sm", [{"SecretList": secrets}])}
                )
            elif service == "cloudtrail":
                client.get_paginator.side_effect = _pager(
                    {
                        "lookup_events": source(
                            "ct",
                            lambda LookupAttributes: [
                                {
                                    "Events": [
                                        e
                                        for e in events
                                        if e["EventName"]
                                        == LookupAttributes[0]["AttributeValue"]
                                    ]
                                }
                            ],
                        )
                    }
                )
            elif service == "ecs":
                clusters = sorted({c for c, _, _ in services})
                client.get_paginator.side_effect = _pager(
                    {
                        "list_clusters": source(
                            "ecs",
                            [{"clusterArns": [f"arn:c/cluster/{c}" for c in clusters]}],
                        ),
                        "list_services": lambda cluster: [
                            {
                                "serviceArns": [
                                    n
                                    for c, n, _ in services
                                    if c == cluster.rsplit("/", 1)[-1]
                                ]
                            }
                        ],
                    }
                )
                client.describe_services.side_effect = lambda cluster, services: {
                    "services": [
                        {"serviceName": n, "status": "ACTIVE", "taskDefinition": t}
                        for c, n, t in service_rows
                        if n in services
                    ]
                }

                def describe_task_definition(taskDefinition):
                    if "td" in errors:
                        raise errors["td"]
                    return {"taskDefinition": task_defs[taskDefinition]}

                client.describe_task_definition.side_effect = describe_task_definition
            elif service == "lambda":
                client.get_paginator.side_effect = _pager(
                    {"list_functions": source("lambda", [{"Functions": functions}])}
                )
            elif service == "sagemaker":
                # One model per page, so a reader of only the first page misses
                # every later model.
                client.get_paginator.side_effect = _pager(
                    {
                        "list_models": source(
                            "models",
                            [{"Models": [{"ModelName": n}]} for n in models],
                        )
                    }
                )

                def describe_model(ModelName):
                    if isinstance(models[ModelName], Exception):
                        raise models[ModelName]
                    return models[ModelName]

                client.describe_model.side_effect = describe_model
            elif service == "events":
                client.get_paginator.side_effect = _pager(
                    {
                        "list_rules": source(
                            "events",
                            [
                                {
                                    "Rules": [
                                        {
                                            "Name": f"r{i}",
                                            "State": "ENABLED",
                                            "EventPattern": json.dumps(p),
                                        }
                                        for i, (p, _) in enumerate(rules)
                                    ]
                                }
                            ],
                        ),
                        "list_targets_by_rule": lambda Rule: [
                            {"Targets": rules[int(Rule[1:])][1]}
                        ],
                    }
                )
            return client

        with patch("sagemaker_app.boto3.client", side_effect=factory):
            return _rows(self.check(region="us-east-1"))

    @staticmethod
    def _named(rows, name):
        return [r for r in rows if r["Finding"].startswith(name)]

    def _history(self, rows):
        return self._named(rows, sagemaker_app.SECRET_HISTORY_FINDING)

    def _propagation(self, rows):
        return self._named(rows, sagemaker_app.SECRET_PROPAGATION_FINDING)

    def _plaintext(self, rows):
        return self._named(rows, sagemaker_app.PLAINTEXT_CREDENTIAL_FINDING)

    def test_completed_rotation_passes_history(self):
        rows = self._run(events=[self._event("RotationStarted", 2.01)])
        history = self._history(rows)
        assert [r["Status"] for r in history] == ["Passed"]
        assert "1 recorded a RotationStarted event" in history[0]["Finding_Details"]

    def test_failure_after_last_rotation_fails_among_healthy_secrets(self):
        other = "arn:aws:secretsmanager:us-east-1:111122223333:secret:api-XyZ123"
        rows = self._run(
            secrets=[self._secret(), self._secret("api", other)],
            events=[
                self._event("RotationFailed", 1),
                # A failure before the last rotation was recovered from.
                self._event("RotationFailed", 3, other),
            ],
        )
        history = self._history(rows)
        assert [r["Status"] for r in history] == ["Failed"]
        assert (
            "Secret 'db' recorded a rotation failure" in history[0]["Finding_Details"]
        )

    def test_started_rotation_that_never_completed_fails(self):
        # RotationEnabled and a recent-enough LastRotatedDate hide the stall.
        history = self._history(self._run(events=[self._event("RotationStarted", 1.5)]))
        assert [r["Status"] for r in history] == ["Failed"]
        assert "has not completed" in history[0]["Finding_Details"]

    def test_rotation_started_within_a_day_is_incomplete(self):
        history = self._history(self._run(events=[self._event("RotationStarted", 0.1)]))
        assert [r["Status"] for r in history] == ["N/A"]

    def test_event_history_denied_is_incomplete_not_passed(self):
        history = self._history(
            self._run(errors={"ct": _make_client_error("AccessDeniedException")})
        )
        assert [r["Status"] for r in history] == ["N/A"]
        assert "cloudtrail:LookupEvents" in history[0]["Finding_Details"]

    def test_non_rotating_secrets_get_no_history_row(self):
        rows = self._run(secrets=[self._secret(rotating=False)])
        assert self._history(rows) == []

    def _ecs_injecting(self, value_from):
        return {
            "services": [("agents", "planner", "td:1"), ("agents", "tools", "td:2")],
            "task_defs": {
                "td:1": self._task([{"name": "app", "secrets": []}]),
                "td:2": self._task(
                    [
                        {
                            "name": "app",
                            "secrets": [{"name": "DB", "valueFrom": value_from}],
                        }
                    ]
                ),
            },
        }

    def test_injected_rotating_secret_without_redeploy_rule_fails(self):
        prop = self._propagation(
            self._run(**self._ecs_injecting(self.ARN + ":password::"))
        )
        assert [r["Status"] for r in prop] == ["Failed"]
        assert (
            "ECS service tools in agents, container app injects rotating secret 'db'"
            in prop[0]["Finding_Details"]
        )

    @pytest.mark.parametrize(
        "value_from",
        [
            "arn:aws:secretsmanager:us-east-1:111122223333:secret:db",
            "arn:aws:secretsmanager:us-east-1:111122223333:secret:db:password::",
        ],
    )
    def test_a_partial_arn_injection_of_a_rotating_secret_fails(self, value_from):
        prop = self._propagation(self._run(**self._ecs_injecting(value_from)))
        assert [r["Status"] for r in prop] == ["Failed"]
        assert "injects rotating secret 'db'" in prop[0]["Finding_Details"]
        assert "planner" not in prop[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "value_from",
        [
            "arn:aws:secretsmanager:us-east-1:444455556666:secret:shared-AbCdEf",
            "arn:aws:secretsmanager:us-west-2:111122223333:secret:db-AbCdEf",
        ],
    )
    def test_a_secret_from_another_account_or_region_is_not_read(self, value_from):
        prop = self._propagation(self._run(**self._ecs_injecting(value_from)))
        assert [r["Status"] for r in prop] == ["N/A"]
        details = prop[0]["Finding_Details"]
        assert f"injects secret {value_from}" in details
        assert "whether it rotates was not read" in details
        assert "No ECS task injects a rotating secret" not in details

    def test_a_non_rotating_secret_by_partial_arn_is_not_a_gap(self):
        other = "arn:aws:secretsmanager:us-east-1:111122223333:secret:cfg-QwErTy"
        prop = self._propagation(
            self._run(
                secrets=[self._secret(), self._secret("cfg", other, rotating=False)],
                **self._ecs_injecting(
                    "arn:aws:secretsmanager:us-east-1:111122223333:secret:cfg"
                ),
            )
        )
        assert [r["Status"] for r in prop] == ["Passed"]

    def test_rotation_rule_with_a_target_covers_injection(self):
        prop = self._propagation(
            self._run(
                rules=[
                    ({"source": ["aws.guardduty"]}, [{"Id": "t"}]),
                    (
                        {
                            "source": ["aws.secretsmanager"],
                            "detail": {"eventName": ["RotationSucceeded"]},
                        },
                        [{"Id": "t"}],
                    ),
                ],
                **self._ecs_injecting(self.ARN),
            )
        )
        # A target is listed, never read for what it does, so it earns no Passed.
        assert [r["Status"] for r in prop] == ["N/A"]
        assert "1 injection(s) of a rotating secret" in prop[0]["Finding_Details"]
        assert "rule(s) r1" in prop[0]["Finding_Details"]
        assert "r0" not in prop[0]["Finding_Details"]
        assert "whether a target redeploys" in prop[0]["Finding_Details"]

    def test_a_rotation_rule_target_does_not_hide_a_parameter_store_injection(self):
        ecs = self._ecs_injecting(self.ARN)
        ecs["task_defs"]["td:1"] = self._task(
            [
                {
                    "name": "app",
                    "secrets": [
                        {
                            "name": "KEY",
                            "valueFrom": "arn:aws:ssm:us-east-1:111122223333:"
                            "parameter/key",
                        }
                    ],
                }
            ]
        )
        prop = self._propagation(
            self._run(
                rules=[({"source": ["aws.secretsmanager"]}, [{"Id": "t"}])], **ecs
            )
        )
        assert [r["Status"] for r in prop] == ["Failed", "N/A"]
        assert "ECS service planner" in prop[0]["Finding_Details"]
        assert "from Parameter Store" in prop[0]["Finding_Details"]
        assert "ECS service tools" in prop[1]["Finding_Details"]

    def test_rotation_rule_without_targets_or_on_other_events_does_not_cover(self):
        prop = self._propagation(
            self._run(
                rules=[
                    ({"source": ["aws.secretsmanager"]}, []),
                    (
                        {
                            "source": ["aws.secretsmanager"],
                            "detail": {"eventName": ["DeleteSecret"]},
                        },
                        [{"Id": "t"}],
                    ),
                ],
                **self._ecs_injecting(self.ARN),
            )
        )
        assert [r["Status"] for r in prop] == ["Failed"]

    def test_parameter_store_injection_fails(self):
        prop = self._propagation(
            self._run(
                **self._ecs_injecting(
                    "arn:aws:ssm:us-east-1:111122223333:parameter/db-password"
                )
            )
        )
        assert [r["Status"] for r in prop] == ["Failed"]
        assert "from Parameter Store" in prop[0]["Finding_Details"]

    def test_rule_read_denied_is_incomplete_not_passed(self):
        prop = self._propagation(
            self._run(
                errors={"events": _make_client_error("AccessDeniedException")},
                **self._ecs_injecting(self.ARN),
            )
        )
        assert [r["Status"] for r in prop] == ["N/A"]
        assert "events:ListRules" in prop[0]["Finding_Details"]

    def test_task_definition_denied_is_incomplete_not_passed(self):
        prop = self._propagation(
            self._run(
                errors={"td": _make_client_error("AccessDeniedException")},
                **self._ecs_injecting(self.ARN),
            )
        )
        assert [r["Status"] for r in prop] == ["N/A"]
        assert "task definition td:1" in prop[0]["Finding_Details"]

    def test_function_list_denied_is_incomplete_not_passed(self):
        prop = self._propagation(
            self._run(errors={"lambda": _make_client_error("AccessDeniedException")})
        )
        assert [r["Status"] for r in prop] == ["N/A"]
        assert "lambda:ListFunctions" in prop[0]["Finding_Details"]

    def test_no_injection_passes_and_counts_extension_users(self):
        prop = self._propagation(
            self._run(
                functions=[
                    {
                        "FunctionName": "a",
                        "Layers": [
                            {
                                "Arn": "arn:aws:lambda:us-east-1:177933569100:layer:"
                                "AWS-Parameters-and-Secrets-Lambda-Extension:12"
                            }
                        ],
                    },
                    {"FunctionName": "b"},
                ]
            )
        )
        assert [r["Status"] for r in prop] == ["Passed"]
        assert (
            "1 of 2 use the Parameters and Secrets extension"
            in prop[0]["Finding_Details"]
        )

    def test_one_plaintext_credential_among_references_fails(self):
        rows = self._run(
            functions=[
                {
                    "FunctionName": "tool",
                    "Environment": {
                        "Variables": {
                            "DB_PASSWORD": "hunter2",
                            "API_SECRET_ARN": self.ARN,
                            "CLIENT_SECRET": self.ARN,
                            "SECRET_NAME": "db",
                            "PASSWORD_LENGTH": "32",
                            "TOKEN_ENDPOINT": "https://idp/token",
                            "SECRETS_MANAGER_TTL": "300",
                        }
                    },
                }
            ]
        )
        plaintext = self._plaintext(rows)
        assert [r["Status"] for r in plaintext] == ["Failed"]
        assert (
            "Lambda function tool sets DB_PASSWORD" in plaintext[0]["Finding_Details"]
        )
        assert "hunter2" not in plaintext[0]["Finding_Details"]

    def test_ecs_plaintext_credential_fails(self):
        plaintext = self._plaintext(
            self._run(
                services=[("agents", "planner", "td:1")],
                task_defs={
                    "td:1": self._task(
                        [
                            {
                                "name": "app",
                                "environment": [
                                    {"name": "OPENAI_API_KEY", "value": "sk-x"},
                                    {"name": "LOG_LEVEL", "value": "info"},
                                ],
                            }
                        ]
                    )
                },
            )
        )
        assert [r["Status"] for r in plaintext] == ["Failed"]
        assert "container app sets OPENAI_API_KEY" in plaintext[0]["Finding_Details"]

    @staticmethod
    def _model(primary_env=None, container_envs=()):
        model = {"Containers": [{"Environment": env} for env in container_envs]}
        if primary_env is not None:
            model["PrimaryContainer"] = {"Environment": primary_env}
        return model

    @pytest.mark.parametrize("in_primary", [True, False])
    def test_a_sagemaker_model_plaintext_credential_fails(self, in_primary):
        clean = {"HF_MODEL_ID": "org/model", "SM_SECRET_ARN": self.ARN}
        leaked = {"HF_TOKEN": "hf_x", "LOG_LEVEL": "info"}
        plaintext = self._plaintext(
            self._run(
                models={
                    "clean": self._model(clean),
                    "leaky": (
                        self._model(leaked)
                        if in_primary
                        else self._model(container_envs=[clean, leaked])
                    ),
                }
            )
        )
        assert [r["Status"] for r in plaintext] == ["Failed"]
        details = plaintext[0]["Finding_Details"]
        container = 1 if in_primary else 2
        assert f"SageMaker model leaky, container {container} sets HF_TOKEN" in (
            details
        )
        assert "hf_x" not in details
        assert "clean" not in details

    @pytest.mark.parametrize(
        "errors, models, named",
        [
            (
                {"models": _make_client_error("AccessDeniedException")},
                {},
                "sagemaker:ListModels",
            ),
            (
                {},
                {"broken": _make_client_error("ValidationException")},
                "SageMaker model broken",
            ),
        ],
    )
    def test_an_unread_model_withholds_the_propagation_pass(
        self, errors, models, named
    ):
        propagation = self._propagation(self._run(errors=errors, models=models))
        assert [r["Status"] for r in propagation] == ["N/A"]
        assert named in propagation[0]["Finding_Details"]

    def test_list_secrets_denied_is_incomplete(self):
        rows = self._run(errors={"sm": _make_client_error("AccessDeniedException")})
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "secretsmanager:ListSecrets" in rows[0]["Finding_Details"]


def _audit_task(scheduled, started, run_status="COMPLETED_COMPLIANT"):
    return {
        "taskStatus": "COMPLETED",
        "taskType": "SCHEDULED_AUDIT_TASK",
        "taskStartTime": started,
        "scheduledAuditName": scheduled,
        "auditDetails": {
            sagemaker_app.IOT_SHARED_CERTIFICATE_CHECK: {"checkRunStatus": run_status}
        },
    }


class TestSM41IoTDeviceScopedPolicies:
    """AIR-PHY-EDG-01: thing-name scoping plus an attached-thing condition."""

    @pytest.mark.parametrize(
        ("condition", "expected"),
        [
            ({"Bool": {"iot:Connection.Thing.IsAttached": "true"}}, True),
            ({"Bool": {"iot:Connection.Thing.IsAttached": ["true"]}}, True),
            ({"Bool": {"iot:Connection.Thing.IsAttached": True}}, True),
            ({"Bool": {"iot:Connection.Thing.IsAttached": "false"}}, False),
            ({"BoolIfExists": {"iot:Connection.Thing.IsAttached": "true"}}, False),
            ({"Null": {"iot:Connection.Thing.IsAttached": "false"}}, False),
            ({"StringNotEquals": {"iot:Connection.Thing.IsAttached": "true"}}, False),
            ({"Bool": {"iot:Connection.Thing.IsOnline": "true"}}, False),
            ({}, False),
        ],
    )
    def test_attached_thing_condition(self, condition, expected):
        assert (
            sagemaker_app._iot_requires_attached_thing({"Condition": condition})
            is expected
        )

    def _client(
        self,
        policies_pages,
        targets,
        documents,
        principal_things=None,
        audit_config=None,
        scheduled=None,
        audit_findings=None,
        errors=None,
        group_things=None,
        thing_principals=None,
        audit_tasks=None,
    ):
        client = MagicMock()
        errors = errors or {}
        # {taskId: DescribeAuditTask}; by default one run of "daily" completed
        # the shared-certificate check.
        audit_tasks = (
            audit_tasks
            if audit_tasks is not None
            else {
                "t-1": _audit_task("daily", datetime.now(timezone.utc) - timedelta(1))
            }
        )
        client.audit_findings_calls = []
        principal_things = principal_things or {}
        group_things = group_things or {}
        thing_principals = thing_principals or {}
        client.group_things_calls = []

        def list_targets(policyName):
            return targets[policyName]

        def list_things_in_thing_group(thingGroupName, recursive=False):
            client.group_things_calls.append((thingGroupName, recursive))
            if thingGroupName in errors:
                raise errors[thingGroupName]
            things = group_things.get(thingGroupName, [])
            # Two pages, so a reader that keeps only the first page misses one.
            return [{"things": things[:1]}, {"things": things[1:]}]

        def list_thing_principals(thingName):
            if thingName in errors:
                raise errors[thingName]
            principals = thing_principals.get(thingName, [])
            return [{"principals": principals[:1]}, {"principals": principals[1:]}]

        def list_principal_things(principal):
            if principal in errors:
                raise errors[principal]
            return [{"things": principal_things.get(principal, ["thing-1"])}]

        def raising(operation, pages):
            def paginate(**kwargs):
                if operation in errors:
                    raise errors[operation]
                return pages

            return paginate

        client.get_paginator.side_effect = _pager(
            {
                "list_policies": policies_pages,
                "list_targets_for_policy": list_targets,
                "list_principal_things": list_principal_things,
                "list_things_in_thing_group": list_things_in_thing_group,
                "list_thing_principals": list_thing_principals,
                "list_scheduled_audits": raising(
                    "list_scheduled_audits",
                    [
                        {"scheduledAudits": []},
                        {
                            "scheduledAudits": [
                                {"scheduledAuditName": n}
                                for n in (
                                    scheduled
                                    or {
                                        "daily": [
                                            sagemaker_app.IOT_SHARED_CERTIFICATE_CHECK
                                        ]
                                    }
                                )
                            ]
                        },
                    ],
                ),
                "list_audit_findings": lambda **kwargs: (
                    client.audit_findings_calls.append(kwargs)
                    or raising(
                        "list_audit_findings", [{"findings": audit_findings or []}]
                    )()
                ),
                "list_audit_tasks": raising(
                    "list_audit_tasks",
                    [{"tasks": []}, {"tasks": [{"taskId": t} for t in audit_tasks]}],
                ),
                "list_role_aliases": [{"roleAliases": []}],
            }
        )

        def describe_audit_task(taskId):
            if taskId in errors:
                raise errors[taskId]
            return audit_tasks[taskId]

        client.describe_audit_task.side_effect = describe_audit_task

        def describe_config():
            if "describe_account_audit_configuration" in errors:
                raise errors["describe_account_audit_configuration"]
            return {
                "auditCheckConfigurations": audit_config
                if audit_config is not None
                else {sagemaker_app.IOT_SHARED_CERTIFICATE_CHECK: {"enabled": True}}
            }

        client.describe_account_audit_configuration.side_effect = describe_config

        def describe_scheduled_audit(scheduledAuditName):
            if scheduledAuditName in errors:
                raise errors[scheduledAuditName]
            checks = (
                scheduled or {"daily": [sagemaker_app.IOT_SHARED_CERTIFICATE_CHECK]}
            )[scheduledAuditName]
            return {
                "scheduledAuditName": scheduledAuditName,
                "targetCheckNames": checks,
            }

        client.describe_scheduled_audit.side_effect = describe_scheduled_audit

        def get_policy(policyName):
            value = documents[policyName]
            if isinstance(value, Exception):
                raise value
            return {"policyName": policyName, "policyDocument": value}

        client.get_policy.side_effect = get_policy
        return client

    @patch("sagemaker_app.boto3.client")
    def test_policies_across_pages_each_judged(self, mock_client):
        cert = [
            "arn:aws:iot:us-east-1:123456789012:cert/"
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        ]
        attached = [{"targets": cert}]
        client = self._client(
            [
                {"policies": [{"policyName": "scoped"}, {"policyName": "broad"}]},
                {
                    "policies": [
                        {"policyName": "unattached"},
                        {"policyName": "no-attach-condition"},
                        {"policyName": "not-action"},
                        {"policyName": "broken"},
                    ]
                },
            ],
            {
                # The target arrives on the second list_targets_for_policy page.
                "scoped": [{"targets": []}, {"targets": cert}],
                "broad": attached,
                "unattached": [{"targets": []}],
                "no-attach-condition": attached,
                "not-action": attached,
                "broken": attached,
            },
            {
                "scoped": _scoped_iot_document(),
                "broad": _iot_document(
                    {
                        "Effect": "Allow",
                        "Action": "iot:Publish",
                        "Resource": _IOT_TOPIC + "*",
                    }
                ),
                "unattached": _iot_document(
                    {"Effect": "Allow", "Action": "iot:*", "Resource": "*"}
                ),
                "no-attach-condition": _iot_document(
                    {
                        "Effect": "Allow",
                        "Action": "iot:Connect",
                        "Resource": _IOT_CLIENT + "${iot:Connection.Thing.ThingName}",
                    }
                ),
                "not-action": _iot_document(
                    {
                        "Effect": "Allow",
                        "NotAction": "iot:DescribeEndpoint",
                        "Resource": "*",
                        "Condition": _ATTACHED,
                    }
                ),
                "broken": _make_client_error("AccessDeniedException"),
            },
        )
        mock_client.return_value = client
        all_rows = _rows(sagemaker_app.check_iot_device_scoped_policies("us-east-1"))
        assert [(r["Finding"], r["Status"]) for r in all_rows[-2:]] == [
            (sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING, "Passed"),
            (sagemaker_app.IOT_AUDIT_FINDING, "Passed"),
        ]
        rows = all_rows[:-2]
        assert all(
            r["Finding"] == sagemaker_app.IOT_DEVICE_POLICY_FINDING for r in rows
        )
        failed = [r["Finding_Details"] for r in rows if r["Status"] == "Failed"]
        passed = [r["Finding_Details"] for r in rows if r["Status"] == "Passed"]
        na = [r["Finding_Details"] for r in rows if r["Status"] == "N/A"]
        assert len(failed) == 3
        assert "'broad' allows Publish on '" + _IOT_TOPIC + "*'" in failed[0]
        assert "'no-attach-condition'" in failed[1]
        assert "without requiring the certificate to be attached" in failed[1]
        assert "'not-action' allows Publish, Subscribe, Receive, Connect" in failed[2]
        assert len(passed) == 1 and "scoped" in passed[0]
        assert len(na) == 1 and "'broken'" in na[0]
        assert "unattached" not in " ".join(failed + passed + na)
        fetched = [c.kwargs["policyName"] for c in client.get_policy.call_args_list]
        assert "unattached" not in fetched
        assert all(r["Check_ID"] == "SM-41" for r in rows)
        assert all(r["Severity"] == "High" for r in rows if r["Status"] != "N/A")

    @patch("sagemaker_app.boto3.client")
    def test_deny_and_non_device_statements_are_ignored(self, mock_client):
        document = _iot_document(
            {"Effect": "Deny", "Action": "iot:*", "Resource": "*"},
            {"Effect": "Allow", "Action": "iot:DescribeEndpoint", "Resource": "*"},
            json.loads(_scoped_iot_document())["Statement"][0],
        )
        client = self._client(
            [{"policies": [{"policyName": "p"}]}],
            {"p": [{"targets": ["arn:aws:iot:us-east-1:123456789012:thinggroup/g"]}]},
            {"p": document},
        )
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_iot_device_scoped_policies("us-east-1"))
        # The only target is a thing group, so no certificate is assessed.
        assert [r["Status"] for r in rows] == ["Passed", "N/A", "Passed"]
        assert rows[1]["Finding"] == sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING

    @patch("sagemaker_app.boto3.client")
    def test_no_attached_policies_is_na(self, mock_client):
        client = self._client(
            [{"policies": [{"policyName": "idle"}]}],
            {"idle": [{"targets": []}]},
            {},
        )
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_iot_device_scoped_policies("us-east-1"))
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "None of the 1 AWS IoT policies" in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_list_error_is_could_not_assess(self, mock_client):
        client = MagicMock()
        client.get_paginator.side_effect = _make_client_error("AccessDeniedException")
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_iot_device_scoped_policies("us-east-1"))
        assert len(rows) == 1
        assert_could_not_assess_finding(rows[0])


_ALIAS_ROLE = "arn:aws:iam::123456789012:role/"
_THING_SCOPED = {
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::telemetry/${credentials-iot:ThingName}/*",
}
_FLEET_WIDE = {
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::telemetry/*",
}


class TestSM41RoleAliasDeviceScope:
    """AIR-PHY-EDG-01: a credentials-provider role alias scoped per device."""

    def _run(self, aliases, cache, errors=None, policies=None):
        errors = errors or {}
        self.described = []
        client = MagicMock()

        def list_role_aliases(**kwargs):
            if "list" in errors:
                raise errors["list"]
            return [{"roleAliases": []}, {"roleAliases": list(aliases)}]

        client.get_paginator.side_effect = _pager(
            {
                "list_policies": [{"policies": policies or []}],
                "list_role_aliases": list_role_aliases,
            }
        )

        def describe_role_alias(roleAlias):
            self.described.append(roleAlias)
            if roleAlias in errors:
                raise errors[roleAlias]
            description = {"roleAlias": roleAlias}
            if aliases[roleAlias]:
                description["roleArn"] = _ALIAS_ROLE + aliases[roleAlias]
            return {"roleAliasDescription": description}

        client.describe_role_alias.side_effect = describe_role_alias
        with patch("sagemaker_app.boto3.client", return_value=client):
            rows = _rows(
                sagemaker_app.check_iot_device_scoped_policies(
                    "us-east-1", permission_cache=cache
                )
            )
        return [
            r
            for r in rows
            if r["Finding"].startswith(sagemaker_app.IOT_ROLE_ALIAS_FINDING)
        ]

    @staticmethod
    def _cache(**roles):
        return _environment_cache(
            {
                name: [(name, f"arn:aws:iam::123456789012:policy/{name}", stmts)]
                for name, stmts in roles.items()
            }
        )

    def test_every_alias_role_scoped_by_a_device_variable_passes(self):
        condition_scoped = {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::telemetry",
            "Condition": {
                "StringLike": {"s3:prefix": "${credentials-iot:AwsCertificateId}/*"}
            },
        }
        rows = self._run(
            {"a": "role-a", "b": "role-b"},
            self._cache(**{"role-a": [_THING_SCOPED], "role-b": [condition_scoped]}),
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "2 role alias(es)" in rows[0]["Finding_Details"]
        assert self.described == ["a", "b"]

    def test_one_fleet_wide_alias_role_among_scoped_ones_fails(self):
        rows = self._run(
            {"a": "role-a", "b": "role-b"},
            self._cache(**{"role-a": [_THING_SCOPED], "role-b": [_FLEET_WIDE]}),
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "role alias 'b'" in rows[0]["Finding_Details"]
        assert "role-b" in rows[0]["Finding_Details"]

    def test_one_fleet_wide_statement_beside_a_scoped_one_fails(self):
        # AIR-PHY-EDG-01: one scoped Allow used to pass the whole role.
        rows = self._run(
            {"a": "role-a"},
            self._cache(**{"role-a": [_THING_SCOPED, dict(_FLEET_WIDE, Sid="Fleet")]}),
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "Allow statement(s) Fleet" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "statement",
        [
            dict(_THING_SCOPED, Resource="arn:aws:s3:::*/${credentials-iot:ThingName}"),
            dict(
                _THING_SCOPED,
                Resource=[
                    "arn:aws:s3:::telemetry/${credentials-iot:ThingName}/*",
                    "arn:aws:s3:::shared/*",
                ],
            ),
            dict(
                _FLEET_WIDE,
                Condition={
                    "StringNotEquals": {"s3:prefix": "${credentials-iot:ThingName}"}
                },
            ),
            dict(
                _FLEET_WIDE,
                Condition={
                    "StringLikeIfExists": {"s3:prefix": "${credentials-iot:ThingName}"}
                },
            ),
            dict(
                _FLEET_WIDE,
                Condition={
                    "ForAllValues:StringLike": {
                        "s3:prefix": "${credentials-iot:ThingName}/*"
                    }
                },
            ),
            dict(
                _FLEET_WIDE,
                Condition={
                    "StringLike": {"s3:prefix": "*/${credentials-iot:ThingName}"}
                },
            ),
        ],
    )
    def test_a_variable_that_does_not_bound_the_grant_does_not_scope(self, statement):
        # Each of these held the 'credentials-iot:' substring and passed.
        rows = self._run({"a": "role-a"}, self._cache(**{"role-a": [statement]}))
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_variable_only_in_a_deny_statement_does_not_scope(self):
        deny = dict(_THING_SCOPED, Effect="Deny")
        rows = self._run(
            {"a": "role-a"}, self._cache(**{"role-a": [_FLEET_WIDE, deny]})
        )
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_role_alias_is_judged_with_no_iot_policy_in_the_region(self):
        rows = self._run({"a": "role-a"}, self._cache(**{"role-a": [_FLEET_WIDE]}))
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_no_role_alias_adds_no_row(self):
        assert self._run({}, self._cache()) == []

    @pytest.mark.parametrize(
        "case", ["no-cache", "role-missing", "describe-denied", "no-role-arn"]
    )
    def test_unread_alias_withholds_passed(self, case):
        aliases = {"a": "role-a", "b": "role-b"}
        cache = self._cache(**{"role-a": [_THING_SCOPED], "role-b": [_THING_SCOPED]})
        errors = {}
        if case == "no-cache":
            cache = None
        elif case == "role-missing":
            cache = self._cache(**{"role-a": [_THING_SCOPED]})
        elif case == "describe-denied":
            errors = {"b": _make_client_error("AccessDeniedException")}
        else:
            aliases["b"] = None
        rows = self._run(aliases, cache, errors=errors)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "role alias 'b'" in rows[0]["Finding_Details"]

    def test_role_alias_list_denied_is_na(self):
        rows = self._run(
            {"a": "role-a"},
            self._cache(**{"role-a": [_THING_SCOPED]}),
            errors={"list": _make_client_error("AccessDeniedException")},
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "iot:ListRoleAliases" in rows[0]["Finding_Details"]


class TestSM41DeviceIdentityAndAudit:
    """AIR-PHY-EDG-01: per-device resources, unique certificates, audit."""

    CERT_A = "arn:aws:iot:us-east-1:123456789012:cert/" + "a" * 64
    CERT_B = "arn:aws:iot:us-east-1:123456789012:cert/" + "b" * 64

    def _run(self, mock_client, document=None, targets=None, **kwargs):
        client = TestSM41IoTDeviceScopedPolicies()._client(
            [{"policies": [{"policyName": "p"}, {"policyName": "q"}]}],
            targets
            or {
                "p": [{"targets": [self.CERT_A]}],
                "q": [{"targets": []}, {"targets": [self.CERT_B]}],
            },
            {"p": document or _scoped_iot_document(), "q": _scoped_iot_document()},
            **kwargs,
        )
        mock_client.return_value = client
        rows = _rows(sagemaker_app.check_iot_device_scoped_policies("us-east-1"))
        by_name = {}
        for row in rows:
            # Policy "p" is read first, so its row is the one kept.
            by_name.setdefault(row["Finding"].replace(" Incomplete", ""), row)
        return by_name, rows

    @pytest.mark.parametrize(
        "resource",
        [
            _IOT_TOPIC + "fleet/*",
            _IOT_TOPIC + "fleet/telemetry",
            _IOT_TOPIC + "devices/${iot:Connection.Thing.ThingName}*",
            _IOT_TOPIC + "devices/${iot:Connection.Thing.ThingName}-x/*",
            _IOT_TOPIC + "dev?ces/*",
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_resource_not_bounded_to_the_thing_fails(self, mock_client, resource):
        by_name, _ = self._run(
            mock_client,
            _iot_document(
                json.loads(_scoped_iot_document())["Statement"][0],
                {"Effect": "Allow", "Action": "iot:Publish", "Resource": resource},
            ),
        )
        row = by_name[sagemaker_app.IOT_DEVICE_POLICY_FINDING]
        assert row["Status"] == "Failed"
        assert f"on '{resource}'" in row["Finding_Details"]

    @pytest.mark.parametrize(
        "resource",
        [
            _IOT_TOPIC + "devices/${iot:Connection.Thing.ThingName}",
            _IOT_TOPIC + "devices/${iot:Connection.Thing.ThingName}/*",
            _IOT_TOPIC + "$aws/things/${iot:Connection.Thing.ThingName}/shadow/*",
        ],
    )
    def test_resource_bounded_to_the_thing(self, resource):
        assert sagemaker_app._iot_resource_bounded_to_thing(resource)

    @pytest.mark.parametrize(
        "resource",
        [
            _IOT_TOPIC + "*${iot:Connection.Thing.ThingName}",
            _IOT_TOPIC + "devices/*${iot:Connection.Thing.ThingName}/*",
            _IOT_TOPIC + "devices/x-${iot:Connection.Thing.ThingName}",
            _IOT_CLIENT + "*${iot:Connection.Thing.ThingName}",
            # AIR-PHY-EDG-01: '*' spans segments, so these reach topics under
            # other devices' names. Both passed before.
            _IOT_TOPIC + "*/${iot:Connection.Thing.ThingName}",
            _IOT_TOPIC + "devices/*/${iot:Connection.Thing.ThingName}/*",
            _IOT_TOPIC + "d?vices/${iot:Connection.Thing.ThingName}",
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_a_wildcard_or_text_before_the_variable_is_not_bounded(
        self, mock_client, resource
    ):
        # topic/*${ThingName} matches the topic of every thing whose name ends
        # with this one, so the segment must start at the variable too.
        assert not sagemaker_app._iot_resource_bounded_to_thing(resource)
        by_name, rows = self._run(
            mock_client,
            _iot_document(
                json.loads(_scoped_iot_document())["Statement"][0],
                {"Effect": "Allow", "Action": "iot:Publish", "Resource": resource},
            ),
        )
        failed = [
            r
            for r in rows
            if r["Finding"] == sagemaker_app.IOT_DEVICE_POLICY_FINDING
            and r["Status"] == "Failed"
        ]
        assert len(failed) == 1
        assert "policy 'p'" in failed[0]["Finding_Details"]
        assert f"on '{resource}'" in failed[0]["Finding_Details"]
        passed = [
            r
            for r in rows
            if r["Finding"] == sagemaker_app.IOT_DEVICE_POLICY_FINDING
            and r["Status"] == "Passed"
        ]
        assert "q" in passed[0]["Finding_Details"]

    THING_GROUP = "arn:aws:iot:us-east-1:123456789012:thinggroup/fleet"
    OTHER_GROUP = "arn:aws:iot:us-east-1:123456789012:thinggroup/spare"
    CERT_C = "arn:aws:iot:us-east-1:123456789012:cert/" + "c" * 64
    CERT_D = "arn:aws:iot:us-east-1:123456789012:cert/" + "d" * 64
    COGNITO = "us-east-1:11111111-2222-3333-4444-555555555555"

    def _group_run(self, mock_client, **kwargs):
        kwargs.setdefault(
            "targets",
            {
                "p": [{"targets": [self.CERT_A]}],
                "q": [{"targets": [self.THING_GROUP, self.OTHER_GROUP]}],
            },
        )
        kwargs.setdefault(
            "group_things", {"fleet": ["dev-1", "dev-2"], "spare": ["dev-3"]}
        )
        kwargs.setdefault(
            "thing_principals",
            {
                "dev-1": [self.CERT_C],
                "dev-2": [self.COGNITO, self.CERT_D],
                "dev-3": [self.CERT_A],
            },
        )
        by_name, rows = self._run(mock_client, **kwargs)
        return by_name, rows, mock_client.return_value

    @patch("sagemaker_app.boto3.client")
    def test_a_thing_group_certificate_on_two_things_fails(self, mock_client):
        # CERT_D arrives on the second ListThingPrincipals page of the second
        # thing of the first group, behind a Cognito identity.
        by_name, _, client = self._group_run(
            mock_client,
            principal_things={self.CERT_D: ["dev-2", "dev-9"]},
        )
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "Failed"
        assert "1 of 3 device certificate(s)" in row["Finding_Details"]
        assert "d" * 64 in row["Finding_Details"]
        assert "c" * 64 not in row["Finding_Details"]
        assert self.COGNITO not in row["Finding_Details"]
        assert client.group_things_calls == [("fleet", True), ("spare", True)]

    @patch("sagemaker_app.boto3.client")
    def test_thing_group_certificates_on_one_thing_each_pass(self, mock_client):
        by_name, _, _ = self._group_run(mock_client)
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "Passed"
        # CERT_A is both a direct target and a principal of dev-3: counted once.
        assert "Each of the 3 certificate(s)" in row["Finding_Details"]
        assert "through 2 thing group(s) (fleet, spare)" in row["Finding_Details"]
        assert "not granted" not in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_an_unread_thing_group_is_incomplete(self, mock_client):
        by_name, _, _ = self._group_run(
            mock_client, errors={"spare": _make_client_error("AccessDeniedException")}
        )
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "N/A"
        assert "thing group spare (AccessDeniedException)" in row["Finding_Details"]
        assert "thing group fleet (" not in row["Finding_Details"]
        assert "1 read(s) failed" in row["Finding_Details"]
        assert "3 certificate(s) read" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_an_unread_thing_principal_list_is_incomplete(self, mock_client):
        by_name, _, _ = self._group_run(
            mock_client, errors={"dev-2": _make_client_error("AccessDeniedException")}
        )
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "N/A"
        assert (
            "thing dev-2 in thing group fleet (AccessDeniedException)"
            in row["Finding_Details"]
        )
        assert "thing dev-1" not in row["Finding_Details"]
        assert "2 certificate(s) read" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_unread_group_and_certificate_count_apart(self, mock_client):
        by_name, _, _ = self._group_run(
            mock_client,
            errors={
                "dev-1": _make_client_error("AccessDeniedException"),
                self.CERT_D: _make_client_error("AccessDeniedException"),
            },
        )
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "N/A"
        assert "2 read(s) failed" in row["Finding_Details"]
        # CERT_A and CERT_D are listed, and CERT_D's things were not read.
        assert "1 certificate(s) read" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_a_thing_group_does_not_hide_a_shared_certificate(self, mock_client):
        by_name, _ = self._run(
            mock_client,
            targets={
                "p": [{"targets": [self.THING_GROUP]}],
                "q": [{"targets": [self.CERT_B]}],
            },
            principal_things={self.CERT_B: ["thing-1", "thing-2"]},
        )
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "Failed"
        assert "b" * 64 in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_empty_thing_groups_leave_no_certificate(self, mock_client):
        by_name, _ = self._run(
            mock_client,
            targets={
                "p": [{"targets": [self.THING_GROUP]}],
                "q": [{"targets": []}],
            },
            group_things={"fleet": ["dev-1"]},
            thing_principals={"dev-1": [self.COGNITO]},
        )
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "N/A"
        assert "no certificate" in row["Finding_Details"]
        assert "1 thing group(s) (fleet)" in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_every_certificate_on_one_thing_passes(self, mock_client):
        by_name, rows = self._run(mock_client)
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "Passed"
        assert "Each of the 2 certificate(s)" in row["Finding_Details"]
        assert "not an API field" in row["Finding_Details"]
        assert all(r["Check_ID"] == "SM-41" for r in rows)

    @patch("sagemaker_app.boto3.client")
    def test_one_certificate_on_two_things_fails(self, mock_client):
        by_name, _ = self._run(
            mock_client,
            principal_things={self.CERT_B: ["thing-1", "thing-2"]},
        )
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "Failed"
        assert "1 of 2 device certificate(s)" in row["Finding_Details"]
        assert "b" * 64 in row["Finding_Details"]
        assert "a" * 64 not in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_unread_certificate_is_incomplete(self, mock_client):
        by_name, _ = self._run(
            mock_client, errors={self.CERT_A: _make_client_error("AccessDenied")}
        )
        row = by_name[sagemaker_app.IOT_UNIQUE_CERTIFICATE_FINDING]
        assert row["Status"] == "N/A"
        assert "a" * 64 in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_clean_scheduled_audit_passes(self, mock_client):
        by_name, _ = self._run(mock_client)
        row = by_name[sagemaker_app.IOT_AUDIT_FINDING]
        assert row["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_the_latest_completed_run_is_the_one_judged(self, mock_client):
        # AIR-PHY-EDG-01: findings are read for the latest completed run of a
        # covering scheduled audit, not a 31-day window.
        now = datetime.now(timezone.utc)
        tasks = {
            "t-old": _audit_task("daily", now - timedelta(3)),
            "t-new": _audit_task("daily", now - timedelta(1)),
            "t-other": _audit_task("other", now - timedelta(hours=1)),
            "t-failed": _audit_task("daily", now - timedelta(hours=2), "FAILED"),
        }
        by_name, _ = self._run(mock_client, audit_tasks=tasks)
        row = by_name[sagemaker_app.IOT_AUDIT_FINDING]
        assert row["Status"] == "Passed"
        assert "latest run (t-new," in row["Finding_Details"]
        calls = mock_client.return_value.audit_findings_calls
        assert calls and all(c.get("taskId") == "t-new" for c in calls)

    @pytest.mark.parametrize(
        "tasks",
        [
            {},
            {"t-1": _audit_task("other", datetime.now(timezone.utc))},
            {"t-1": _audit_task("daily", datetime.now(timezone.utc), "FAILED")},
            {"t-1": _audit_task("daily", datetime.now(timezone.utc), "CANCELED")},
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_a_schedule_with_no_completed_run_fails(self, mock_client, tasks):
        by_name, _ = self._run(mock_client, audit_tasks=tasks)
        row = by_name[sagemaker_app.IOT_AUDIT_FINDING]
        assert row["Status"] == "Failed"
        assert (
            "no run of the scheduled audit(s) daily completed"
            in (row["Finding_Details"])
        )

    @pytest.mark.parametrize(
        "kwargs,text",
        [
            (
                {
                    "audit_config": {
                        "DEVICE_CERTIFICATE_SHARED_CHECK": {"enabled": False}
                    }
                },
                "audit check is not enabled",
            ),
            ({"audit_config": {}}, "audit check is not enabled"),
            (
                {"scheduled": {"weekly": ["CA_CERTIFICATE_EXPIRING_CHECK"]}},
                "none of the 1 scheduled audit(s)",
            ),
            (
                {
                    "audit_findings": [
                        {
                            "checkName": "CA_CERTIFICATE_EXPIRING_CHECK",
                            "isSuppressed": True,
                        },
                        {
                            "checkName": "DEVICE_CERTIFICATE_SHARED_CHECK",
                            "isSuppressed": False,
                        },
                    ]
                },
                "1 unsuppressed audit finding(s): DEVICE_CERTIFICATE_SHARED_CHECK (1)",
            ),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_audit_that_is_not_clean_and_scheduled_fails(
        self, mock_client, kwargs, text
    ):
        by_name, _ = self._run(mock_client, **kwargs)
        row = by_name[sagemaker_app.IOT_AUDIT_FINDING]
        assert row["Status"] == "Failed"
        assert text in row["Finding_Details"]

    @pytest.mark.parametrize(
        "operation,label",
        [
            (
                "describe_account_audit_configuration",
                "iot:DescribeAccountAuditConfiguration",
            ),
            ("list_scheduled_audits", "iot:ListScheduledAudits"),
            ("list_audit_findings", "iot:ListAuditFindings"),
            ("daily", "scheduled audit 'daily'"),
            ("list_audit_tasks", "iot:ListAuditTasks"),
            ("t-1", "audit task t-1"),
        ],
    )
    @patch("sagemaker_app.boto3.client")
    def test_unread_audit_leg_is_incomplete(self, mock_client, operation, label):
        by_name, _ = self._run(
            mock_client, errors={operation: _make_client_error("AccessDenied")}
        )
        row = by_name[sagemaker_app.IOT_AUDIT_FINDING]
        assert row["Status"] == "N/A"
        assert label in row["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_known_audit_failure_stands_beside_an_unread_leg(self, mock_client):
        by_name, _ = self._run(
            mock_client,
            audit_config={},
            errors={"list_audit_findings": _make_client_error("AccessDenied")},
        )
        row = by_name[sagemaker_app.IOT_AUDIT_FINDING]
        assert row["Status"] == "Failed"
        assert "Not read: iot:ListAuditFindings" in row["Finding_Details"]


class TestScope27HandlerWiring:
    """SM-35 is global (primary region only); SM-36..SM-41 are regional."""

    @patch("sagemaker_app.boto3.client")
    def test_sm35_emitted_once_on_primary_tagged_global(self, mock_client):
        resp, findings = TestSageMakerHandlerMultiRegion()._run_handler_unavailable(
            mock_client, _sagemaker_event(region="ap-south-2", region_index=0)
        )
        assert resp["statusCode"] == 200
        rows = [r for f in findings for r in f.get("csv_data", [])]
        sm35 = [r for r in rows if r["Check_ID"] == "SM-35"]
        assert len(sm35) == len(sagemaker_app.SECURITY_SERVICE_PRINCIPALS) + 1
        assert {r["Region"] for r in sm35} == {"Global"}

    @patch("sagemaker_app.boto3.client")
    def test_sm35_absent_on_non_primary(self, mock_client):
        _, findings = TestSageMakerHandlerMultiRegion()._run_handler_unavailable(
            mock_client, _sagemaker_event(region="eu-west-1", region_index=1)
        )
        rows = [r for f in findings for r in f.get("csv_data", [])]
        assert "SM-35" not in {r["Check_ID"] for r in rows}

    def test_regional_checks_are_called_with_the_shared_detector_inventory(self):
        source = open(os.path.join(_sm_dir, "app.py"), encoding="utf-8").read()
        handler = source[source.index("def lambda_handler") :]
        for name in (
            "check_security_hub_ai_standard",
            "check_eks_vpc_cni_network_policy",
            "check_secrets_manager_rotation",
        ):
            assert f"{name}(region)" in handler or f"{name}(region=region)" in handler
        # SM-41 judges each role alias's IAM role from the permissions cache.
        assert (
            "check_iot_device_scoped_policies(\n"
            "                region=region, permission_cache=permission_cache\n"
            "            )" in handler
        )
        for name in (
            "check_guardduty_lambda_network_logs",
            "check_guardduty_runtime_monitoring",
        ):
            call_at = handler.index(name)
            assert (
                "detector_inventory=guardduty_inventory"
                in handler[call_at : call_at + 200]
            )


# ===================================================================
# IAM permissions cache contract (schema version 2) on the SM-02 legs
# ===================================================================
def _v2_cache(roles, principal_errors=None, boundaries=None, users=None):
    """Build a version-2 cache from {role: [(policy_name, document)]}."""
    cache = _role_cache(roles)
    for name, entry in cache["role_permissions"].items():
        entry["permissions_boundary"] = (boundaries or {}).get(name)
    cache["user_permissions"] = users or {}
    cache["principal_errors"] = list(principal_errors or [])
    cache["cache_schema_version"] = 2
    return cache


def _sm02_rows(cache):
    with patch("sagemaker_app.boto3.client") as mock_client:
        mock_client.return_value.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [],
        }
        return _rows(
            sagemaker_app.check_sagemaker_iam_permissions(cache, region="Global")
        )


def _by_finding(rows, name):
    return [r for r in rows if r["Finding"].startswith(name)]


_ROLE_ERROR = {
    "type": "role",
    "name": "UnreadRole",
    "stage": "list_attached_policies",
    "error": "AccessDenied",
}


class TestSM02EndpointInvocationScopingFullGrade:
    """AIR-SGM-EP-02: wildcard segments, NotAction, NotResource, tags, boundary."""

    @pytest.mark.parametrize(
        "resource",
        [
            "arn:aws:sagemaker:us-east-1:123456789012:*",
            "arn:aws:sagemaker:*:*:endpoint/prod",
            "arn:aws:sagemaker:us-east-1:123456789012:end*",
            "arn:aws:sagemaker:*",
            "arn:aws:sage*:us-east-1:123456789012:endpoint/prod",
        ],
    )
    def test_wildcard_in_any_segment_is_unscoped(self, resource):
        # Before the fix, only a wildcard inside the endpoint name failed.
        assert sagemaker_app._resource_scopes_endpoint(resource) is False

    @pytest.mark.parametrize(
        "resource",
        [
            "arn:aws:sagemaker:us-east-1:123456789012:endpoint/prod",
            "arn:aws:sagemaker:us-east-1:123456789012:model/*",
            "arn:aws:sagemaker:us-east-1:123456789012:endpoint-config/*",
            "arn:aws:s3:::bucket/*",
            "arn:aws:sagemaker-geospatial:us-east-1:123456789012:*",
        ],
    )
    def test_resources_that_name_or_miss_endpoints_are_scoped(self, resource):
        assert sagemaker_app._resource_scopes_endpoint(resource) is True

    def test_account_wide_sagemaker_arn_fails_and_named_role_passes(self):
        cache = _v2_cache(
            {
                "NamedRole": [
                    (
                        "InvokeOne",
                        _identity_policy(
                            "sagemaker:InvokeEndpoint",
                            "arn:aws:sagemaker:us-east-1:123456789012:endpoint/a",
                        ),
                    )
                ],
                "AccountWideRole": [
                    (
                        "InvokeAccount",
                        _identity_policy(
                            "sagemaker:InvokeEndpoint",
                            "arn:aws:sagemaker:us-east-1:123456789012:*",
                        ),
                    )
                ],
            }
        )
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "AccountWideRole" in failed[0]["Finding_Details"]
        assert "NamedRole" not in failed[0]["Finding_Details"]
        assert (
            "Service control policies were not evaluated"
            in (failed[0]["Finding_Details"])
        )

    def test_notaction_allow_reaches_invocation(self):
        statement = {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}
        cache = _v2_cache({"NotActionRole": [("Broad", {"Statement": [statement]})]})
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "NotActionRole" in rows[0]["Finding_Details"]

    def test_notaction_listing_invoke_does_not_reach_invocation(self):
        statement = {
            "Effect": "Allow",
            "NotAction": "sagemaker:Invoke*",
            "Resource": "*",
        }
        cache = _v2_cache({"Excluded": [("Broad", {"Statement": [statement]})]})
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert rows == []

    def test_notresource_allow_is_unscoped(self):
        statement = {
            "Effect": "Allow",
            "Action": "sagemaker:InvokeEndpoint",
            "NotResource": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/x",
        }
        cache = _v2_cache({"NotResourceRole": [("Inv", {"Statement": [statement]})]})
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "NotResource" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "operator",
        ["StringEqualsIfExists", "StringNotEquals", "ForAllValues:StringEquals"],
    )
    def test_tag_condition_that_passes_untagged_endpoints_does_not_scope(
        self, operator
    ):
        policy = _identity_policy(
            "sagemaker:InvokeEndpoint",
            "*",
            condition={operator: {"aws:ResourceTag/team": "fraud"}},
        )
        cache = _v2_cache({"TagRole": [("Inv", policy)]})
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_string_equals_tag_condition_scopes(self):
        policy = _identity_policy(
            "sagemaker:InvokeEndpoint",
            "*",
            condition={"StringEquals": {"aws:ResourceTag/team": "fraud"}},
        )
        cache = _v2_cache({"TagRole": [("Inv", policy)]})
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @pytest.mark.parametrize("value", ["*", "?*", ["fraud", "*"]])
    def test_a_like_tag_condition_that_matches_any_value_does_not_scope(self, value):
        policy = _identity_policy(
            "sagemaker:InvokeEndpoint",
            "*",
            condition={"StringLike": {"aws:ResourceTag/team": value}},
        )
        cache = _v2_cache({"TagRole": [("Inv", policy)]})
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_a_like_tag_condition_on_a_value_prefix_scopes(self):
        policy = _identity_policy(
            "sagemaker:InvokeEndpoint",
            "*",
            condition={"StringLike": {"aws:ResourceTag/team": "fraud-*"}},
        )
        cache = _v2_cache({"TagRole": [("Inv", policy)]})
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    @pytest.mark.parametrize("any_value_first", [True, False])
    def test_only_the_role_whose_tag_matches_any_value_fails(self, any_value_first):
        scoped = _identity_policy(
            "sagemaker:InvokeEndpoint",
            "*",
            condition={"StringLike": {"aws:ResourceTag/team": "fraud-*"}},
        )
        open_tag = _identity_policy(
            "sagemaker:InvokeEndpoint",
            "*",
            condition={"StringLike": {"aws:ResourceTag/team": "*"}},
        )
        roles = [("ScopedRole", [("Inv", scoped)]), ("AnyTagRole", [("Inv", open_tag)])]
        if any_value_first:
            roles.reverse()
        rows = _by_finding(
            _sm02_rows(_v2_cache(dict(roles))),
            sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING,
        )
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "AnyTagRole" in failed[0]["Finding_Details"]
        assert "ScopedRole" not in failed[0]["Finding_Details"]

    def test_boundary_on_named_endpoint_scopes_a_wildcard_grant(self):
        boundary = _identity_policy(
            "sagemaker:InvokeEndpoint",
            "arn:aws:sagemaker:us-east-1:123456789012:endpoint/a",
        )
        cache = _v2_cache(
            {
                "BoundedRole": [
                    ("Inv", _identity_policy("sagemaker:InvokeEndpoint", "*"))
                ],
                "UnboundedRole": [
                    ("Inv", _identity_policy("sagemaker:InvokeEndpoint", "*"))
                ],
            },
            boundaries={"BoundedRole": boundary},
        )
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "UnboundedRole" in failed[0]["Finding_Details"]
        passed = [r for r in rows if r["Status"] == "Passed"]
        assert len(passed) == 1 and "BoundedRole" in passed[0]["Finding_Details"]

    def test_boundary_without_invoke_removes_the_grant(self):
        boundary = _identity_policy("s3:GetObject", "*")
        cache = _v2_cache(
            {"BoundedRole": [("Inv", _identity_policy("sagemaker:*", "*"))]},
            boundaries={"BoundedRole": boundary},
        )
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert rows == []

    def test_boundary_allowing_everything_keeps_the_wildcard_failed(self):
        boundary = _identity_policy("*", "*")
        cache = _v2_cache(
            {"BoundedRole": [("Inv", _identity_policy("sagemaker:Invoke*", "*"))]},
            boundaries={"BoundedRole": boundary},
        )
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "permissions boundary also allows" in rows[0]["Finding_Details"]

    def test_principal_error_blocks_the_scoped_pass_and_names_the_principal(self):
        cache = _v2_cache(
            {
                "NamedRole": [
                    (
                        "InvokeOne",
                        _identity_policy(
                            "sagemaker:InvokeEndpoint",
                            "arn:aws:sagemaker:us-east-1:123456789012:endpoint/a",
                        ),
                    )
                ]
            },
            principal_errors=[_ROLE_ERROR],
        )
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "UnreadRole" in rows[0]["Finding_Details"]
        assert "list_attached_policies" in rows[0]["Finding_Details"]

    def test_principal_error_with_no_grant_read_still_reports_incomplete(self):
        cache = _v2_cache(
            {"ReadOnly": [("R", _identity_policy("s3:GetObject", "*"))]},
            principal_errors=[_ROLE_ERROR],
        )
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["N/A"]

    def test_version_one_cache_passes_and_says_errors_were_not_recorded(self):
        cache = _role_cache(
            {
                "NamedRole": [
                    (
                        "InvokeOne",
                        _identity_policy(
                            "sagemaker:InvokeEndpoint",
                            "arn:aws:sagemaker:us-east-1:123456789012:endpoint/a",
                        ),
                    )
                ]
            }
        )
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert (
            sagemaker_app.UNRECORDED_PRINCIPAL_ERRORS_NOTE in rows[0]["Finding_Details"]
        )

    def test_version_two_cache_without_errors_omits_the_version_note(self):
        cache = _v2_cache(
            {
                "NamedRole": [
                    (
                        "InvokeOne",
                        _identity_policy(
                            "sagemaker:InvokeEndpoint",
                            "arn:aws:sagemaker:us-east-1:123456789012:endpoint/a",
                        ),
                    )
                ]
            }
        )
        rows = _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert (
            sagemaker_app.UNRECORDED_PRINCIPAL_ERRORS_NOTE
            not in rows[0]["Finding_Details"]
        )


class TestSM02CacheContractOtherLegs:
    """The service-wide and full-access legs honor errors and boundaries."""

    def test_service_wide_pass_is_incomplete_when_a_user_was_not_read(self):
        cache = _v2_cache(
            {"ReadOnly": [("R", _identity_policy("sagemaker:Describe*", "*"))]},
            principal_errors=[
                {
                    "type": "user",
                    "name": "alice",
                    "stage": "inline_policy",
                    "error": "x",
                }
            ],
        )
        rows = _by_finding(_sm02_rows(cache), sagemaker_app.SERVICE_WIDE_GRANT_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "alice" in rows[0]["Finding_Details"]

    def test_service_wide_grant_narrowed_by_boundary_is_not_failed(self):
        cache = _v2_cache(
            {
                "Bounded": [("All", _identity_policy("sagemaker:*", "*"))],
                "Unbounded": [("All", _identity_policy("sagemaker:*", "*"))],
            },
            boundaries={"Bounded": _identity_policy("sagemaker:Describe*", "*")},
        )
        rows = _by_finding(_sm02_rows(cache), sagemaker_app.SERVICE_WIDE_GRANT_FINDING)
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "Unbounded" in failed[0]["Finding_Details"]

    @staticmethod
    def _allow_all_with_deny(denied_action):
        return {
            "Statement": [
                {"Effect": "Allow", "Action": "sagemaker:*", "Resource": "*"},
                {"Effect": "Deny", "Action": denied_action, "Resource": "*"},
            ]
        }

    def test_service_wide_grant_stripped_by_account_wide_deny_is_not_failed(self):
        cache = _v2_cache(
            {
                "Denied": [("All", self._allow_all_with_deny("sagemaker:*"))],
                "Open": [("All", _identity_policy("sagemaker:*", "*"))],
            }
        )
        rows = _by_finding(_sm02_rows(cache), sagemaker_app.SERVICE_WIDE_GRANT_FINDING)
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "Role 'Open'" in failed[0]["Finding_Details"]
        assert all("Denied" not in r["Finding_Details"] for r in rows)

    def test_deny_on_another_service_leaves_the_grant_failed(self):
        cache = _v2_cache(
            {
                "Denied": [("All", self._allow_all_with_deny("s3:*"))],
                "Open": [("All", _identity_policy("sagemaker:*", "*"))],
            }
        )
        rows = _by_finding(_sm02_rows(cache), sagemaker_app.SERVICE_WIDE_GRANT_FINDING)
        failed = sorted(
            r["Finding_Details"].split("'")[1] for r in rows if r["Status"] == "Failed"
        )
        assert failed == ["Denied", "Open"]

    @pytest.mark.parametrize("separate_policy", [False, True])
    def test_partial_account_wide_deny_leaves_not_every_action(self, separate_policy):
        # Deny sagemaker:Delete* on "*" removes every delete, so the role no
        # longer holds every SageMaker action, whichever policy carries it.
        if separate_policy:
            policies = [
                ("All", _identity_policy("sagemaker:*", "*")),
                (
                    "NoDelete",
                    {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "sagemaker:Delete*",
                                "Resource": "*",
                            }
                        ]
                    },
                ),
            ]
        else:
            policies = [("All", self._allow_all_with_deny("sagemaker:Delete*"))]
        cache = _v2_cache(
            {
                "Denied": policies,
                "Open": [("All", _identity_policy("sagemaker:*", "*"))],
            }
        )
        rows = _by_finding(_sm02_rows(cache), sagemaker_app.SERVICE_WIDE_GRANT_FINDING)
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "Role 'Open'" in failed[0]["Finding_Details"]
        assert all("Denied" not in r["Finding_Details"] for r in rows)

    def test_deny_scoped_to_one_resource_leaves_the_grant_failed(self):
        # A Deny on one endpoint ARN removes the deletes on that endpoint only.
        # On every other SageMaker resource the sagemaker:* statement still
        # grants read and delete together, so the role stays Failed.
        scoped = {
            "Statement": [
                {"Effect": "Allow", "Action": "sagemaker:*", "Resource": "*"},
                {
                    "Effect": "Deny",
                    "Action": "sagemaker:Delete*",
                    "Resource": (
                        "arn:aws:sagemaker:us-east-1:123456789012:endpoint/prod"
                    ),
                },
            ]
        }
        cache = _v2_cache(
            {
                "Scoped": [("All", scoped)],
                "Open": [("All", _identity_policy("sagemaker:*", "*"))],
            }
        )
        rows = _by_finding(_sm02_rows(cache), sagemaker_app.SERVICE_WIDE_GRANT_FINDING)
        failed = sorted(
            r["Finding_Details"].split("'")[1] for r in rows if r["Status"] == "Failed"
        )
        assert failed == ["Open", "Scoped"]

    def test_boundary_with_notaction_listing_sagemaker_narrows(self):
        boundary = {
            "Statement": [
                {"Effect": "Allow", "NotAction": "sagemaker:Delete*", "Resource": "*"}
            ]
        }
        assert sagemaker_app._boundary_allows_every_sagemaker_action(boundary) is False
        broad = {
            "Statement": [{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}]
        }
        assert sagemaker_app._boundary_allows_every_sagemaker_action(broad) is True

    def test_full_access_role_under_narrow_boundary_is_not_failed(self):
        cache = _v2_cache(
            {
                "Bounded": [("AmazonSageMakerFullAccess", {"Statement": []})],
                "Unbounded": [("AmazonSageMakerFullAccess", {"Statement": []})],
            },
            boundaries={"Bounded": _identity_policy("sagemaker:Describe*", "*")},
        )
        rows = _by_finding(_sm02_rows(cache), "SageMaker Full Access Policy Used")
        assert len(rows) == 1
        assert "Unbounded" in rows[0]["Finding_Details"]

    def test_iam_permissions_pass_is_incomplete_when_a_role_was_not_read(self):
        cache = _v2_cache({}, principal_errors=[_ROLE_ERROR])
        rows = _by_finding(_sm02_rows(cache), "SageMaker IAM Permissions Check")
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "UnreadRole" in rows[0]["Finding_Details"]

    def test_stale_access_read_error_blocks_the_pass(self):
        cache = _v2_cache(
            {},
            users={
                "bob": {
                    "attached_policies": [
                        {"name": "SM", "document": _identity_policy("sagemaker:*", "*")}
                    ],
                    "inline_policies": [],
                    "group_policies": [],
                    "permissions_boundary": None,
                }
            },
        )
        with patch("sagemaker_app.boto3.client") as mock_client:
            mock_client.return_value.generate_service_last_accessed_details.side_effect = _make_client_error(
                "AccessDenied"
            )
            rows = _rows(
                sagemaker_app.check_sagemaker_iam_permissions(cache, region="Global")
            )
        summary = _by_finding(rows, "SageMaker IAM Permissions Check")
        assert [r["Status"] for r in summary] == ["N/A"]
        assert "bob" in summary[0]["Finding_Details"]


# ===================================================================
# SM-11 full grade: AIR-SGM-EP-01 and AIR-SGM-EP-03
# ===================================================================
def _pages_client(pages, calls=None, **methods):
    """A client whose paginators return pages[operation] and whose methods are given."""
    client = MagicMock()

    def get_paginator(operation_name):
        paginator = MagicMock()

        def paginate(**kwargs):
            if calls is not None:
                calls.setdefault(operation_name, []).append(kwargs)
            value = pages.get(operation_name, [])
            if isinstance(value, Exception):
                raise value
            limit = (kwargs.get("PaginationConfig") or {}).get("MaxItems")
            if limit is None:
                return value
            # Honour MaxItems the way botocore does, so a capped sweep is visible.
            capped = []
            for page in value:
                page = dict(page)
                for key, items in page.items():
                    if isinstance(items, list):
                        page[key] = items[:limit]
                        limit -= len(page[key])
                capped.append(page)
            return capped

        paginator.paginate.side_effect = paginate
        return paginator

    client.get_paginator.side_effect = get_paginator
    for name, value in methods.items():
        setattr(client, name, value)
    return client


_ISOLATED_VPC_MODEL = {
    "EnableNetworkIsolation": True,
    "VpcConfig": {"Subnets": ["subnet-private"], "SecurityGroupIds": ["sg-1"]},
}
_PRIVATE_RUNTIME_VPCE = {
    "VpcEndpointId": "vpce-good",
    "VpcId": "vpc-1",
    "VpcEndpointType": "Interface",
    "State": "available",
    "PrivateDnsEnabled": True,
}


def _sm11_rows(
    models,
    endpoints=None,
    configs=None,
    vpces=None,
    extra_pages=None,
    permission_cache=None,
    key_managers=None,
    components=None,
    subnet_fixtures=(PRIVATE_SUBNET_FIXTURE,),
):
    """Run SM-11 against models {name: DescribeModel}, endpoints {name: config}.

    kms:DescribeKey reports CUSTOMER for any key not in key_managers.
    components is {name: (endpoint, DescribeInferenceComponent)}, listed on
    one page.
    """
    endpoints = endpoints or {}
    key_managers = key_managers or {}
    configs = configs or {}
    pages = {
        "list_models": [{"Models": [{"ModelName": n} for n in models]}],
        "list_endpoints": [
            {
                "Endpoints": [
                    {"EndpointName": n, "EndpointStatus": "InService"}
                    for n in endpoints
                ]
            }
        ],
    }
    pages.update(extra_pages or {})

    def describe_model(ModelName):
        value = models[ModelName]
        if isinstance(value, Exception):
            raise value
        return value

    def describe_endpoint(EndpointName):
        value = endpoints[EndpointName]
        if isinstance(value, Exception):
            raise value
        return {"EndpointName": EndpointName, "EndpointConfigName": value}

    def describe_endpoint_config(EndpointConfigName):
        return configs[EndpointConfigName]

    components = components or {}
    if components:
        # The mock ignores EndpointNameEquals; the check keeps its own.
        pages["list_inference_components"] = [
            {
                "InferenceComponents": [
                    {"InferenceComponentName": name, "EndpointName": endpoint}
                    for name, (endpoint, _) in components.items()
                ]
            }
        ]

    def describe_inference_component(InferenceComponentName):
        value = components[InferenceComponentName][1]
        if isinstance(value, Exception):
            raise value
        return value

    sm = _pages_client(
        pages,
        describe_model=MagicMock(side_effect=describe_model),
        describe_endpoint=MagicMock(side_effect=describe_endpoint),
        describe_endpoint_config=MagicMock(side_effect=describe_endpoint_config),
        describe_inference_component=MagicMock(
            side_effect=describe_inference_component
        ),
    )
    ec2_pages = {
        "describe_subnets": [{"Subnets": [s for f in subnet_fixtures for s in f[0]]}],
        "describe_route_tables": [
            {"RouteTables": [t for f in subnet_fixtures for t in f[1]]}
        ],
        "describe_vpc_endpoints": vpces
        if isinstance(vpces, Exception)
        else [{"VpcEndpoints": vpces or []}],
    }
    ec2_calls = {}
    ec2 = _pages_client(ec2_pages, calls=ec2_calls)

    def describe_key(KeyId):
        value = key_managers.get(KeyId, "CUSTOMER")
        if isinstance(value, Exception):
            raise value
        return {"KeyMetadata": {"KeyId": KeyId, "KeyManager": value}}

    kms = MagicMock()
    kms.describe_key.side_effect = describe_key
    with patch("sagemaker_app.boto3.client") as mock_client:
        mock_client.side_effect = _sm_client_factory(sagemaker=sm, ec2=ec2, kms=kms)
        rows = _rows(
            sagemaker_app.check_sagemaker_model_network_isolation(
                region="us-east-1", permission_cache=permission_cache
            )
        )
    return rows, ec2_calls


def _config(model_names, kms=None, instance_type="ml.m5.large", **extra):
    config = {
        "ProductionVariants": [
            {"VariantName": f"v{i}", "ModelName": name, "InstanceType": instance_type}
            for i, name in enumerate(model_names)
        ]
    }
    if kms:
        config["KmsKeyId"] = kms
    config.update(extra)
    return config


class TestSM11ModelInventoryReadErrors:
    """EP-01: a failed model read never yields a clean result."""

    def test_list_models_error_is_could_not_assess_not_no_models(self):
        pages = {"list_models": _make_client_error("AccessDeniedException")}
        rows, _ = _sm11_rows({}, extra_pages=pages)
        isolation = _by_finding(rows, "SageMaker Model Network Isolation Check")
        assert [r["Status"] for r in isolation] == ["N/A"]
        assert "No models found" not in isolation[0]["Finding_Details"]
        assert "AccessDeniedException" in isolation[0]["Finding_Details"]

    def test_describe_error_on_one_model_blocks_both_passes(self):
        rows, _ = _sm11_rows(
            {
                "good": _ISOLATED_VPC_MODEL,
                "unread": _make_client_error("ThrottlingException"),
            }
        )
        assert not [
            r
            for r in rows
            if r["Status"] == "Passed"
            and r["Finding"]
            in (
                "SageMaker Model Network Isolation Check",
                sagemaker_app.MODEL_VPC_ATTACHMENT_FINDING,
            )
        ]
        incomplete = _by_finding(
            rows, "SageMaker Model Network Isolation Check Incomplete"
        )
        assert len(incomplete) == 1
        assert "unread" in incomplete[0]["Finding_Details"]
        vpc_incomplete = _by_finding(
            rows, f"{sagemaker_app.MODEL_VPC_ATTACHMENT_FINDING} Incomplete"
        )
        assert len(vpc_incomplete) == 1

    def test_vpc_pass_names_the_runtime_leg_instead_of_disclaiming_it(self):
        rows, _ = _sm11_rows({"good": _ISOLATED_VPC_MODEL})
        passed = _by_finding(rows, sagemaker_app.MODEL_VPC_ATTACHMENT_FINDING)
        assert [r["Status"] for r in passed] == ["Passed"]
        assert "does not record" not in passed[0]["Finding_Details"]
        assert (
            sagemaker_app.RUNTIME_PRIVATE_PATH_FINDING in passed[0]["Finding_Details"]
        )


class TestSM11EndpointModelNetworkPath:
    """EP-01: the population is the models behind endpoints."""

    def test_one_bad_endpoint_among_two_is_failed_and_blocks_the_pass(self):
        rows, _ = _sm11_rows(
            {
                "good": _ISOLATED_VPC_MODEL,
                "open": {"EnableNetworkIsolation": False},
            },
            endpoints={"ep-good": "cfg-good", "ep-open": "cfg-open"},
            configs={"cfg-good": _config(["good"]), "cfg-open": _config(["open"])},
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "ep-open" in rows[0]["Finding_Details"]
        assert "EnableNetworkIsolation off" in rows[0]["Finding_Details"]
        assert "no VpcConfig" in rows[0]["Finding_Details"]

    def test_shadow_variant_model_is_in_the_population(self):
        config = _config(["good"])
        config["ShadowProductionVariants"] = [
            {"VariantName": "shadow", "ModelName": "open", "InstanceType": "ml.m5"}
        ]
        rows, _ = _sm11_rows(
            {"good": _ISOLATED_VPC_MODEL, "open": {"EnableNetworkIsolation": True}},
            endpoints={"ep": "cfg"},
            configs={"cfg": config},
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'open' has no VpcConfig" in rows[0]["Finding_Details"]

    def test_every_endpoint_compliant_is_passed(self):
        rows, _ = _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL, "b": _ISOLATED_VPC_MODEL},
            endpoints={"ep-a": "cfg-a", "ep-b": "cfg-b"},
            configs={"cfg-a": _config(["a"]), "cfg-b": _config(["b"])},
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "2 endpoint(s)" in rows[0]["Finding_Details"]

    def test_model_missing_from_inventory_leaves_endpoint_unread(self):
        rows, _ = _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL},
            endpoints={"ep-a": "cfg-a", "ep-gone": "cfg-gone"},
            configs={"cfg-a": _config(["a"]), "cfg-gone": _config(["deleted"])},
        )
        rows = _by_finding(
            rows, f"{sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING} Incomplete"
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "deleted" in rows[0]["Finding_Details"]

    def test_describe_endpoint_error_blocks_the_pass(self):
        rows, _ = _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL},
            endpoints={
                "ep-a": "cfg-a",
                "ep-denied": _make_client_error("AccessDeniedException"),
            },
            configs={"cfg-a": _config(["a"], kms="key")},
        )
        for name in (
            sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING,
            sagemaker_app.ENDPOINT_CONFIG_KMS_FINDING,
        ):
            assert not [r for r in _by_finding(rows, name) if r["Status"] == "Passed"]
            incomplete = _by_finding(rows, f"{name} Incomplete")
            assert len(incomplete) == 1
            assert "ep-denied" in incomplete[0]["Finding_Details"]

    def test_inference_component_variant_reads_the_endpoint_config(self):
        config = {
            "ProductionVariants": [{"VariantName": "ic", "InstanceType": "ml.g5"}],
            "EnableNetworkIsolation": False,
        }
        rows, _ = _sm11_rows(
            {}, endpoints={"ep-ic": "cfg-ic"}, configs={"cfg-ic": config}
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "inference-component" in rows[0]["Finding_Details"]

    IC_CONFIG = {
        "ProductionVariants": [{"VariantName": "ic", "InstanceType": "ml.g5"}],
        "EnableNetworkIsolation": True,
        "VpcConfig": {"Subnets": ["subnet-private"], "SecurityGroupIds": ["sg-1"]},
    }

    def _component(self, endpoint, model=None, specifications=None):
        component = {"EndpointName": endpoint, "VariantName": "ic"}
        if not model and not specifications:
            return endpoint, component
        if model:
            component["Specification"] = {"ModelName": model}
        if specifications:
            component["Specifications"] = [
                {"InstanceType": "ml.g5", "ModelName": m} for m in specifications
            ]
        return endpoint, component

    def _ic_rows(self, models, components):
        rows, _ = _sm11_rows(
            models,
            endpoints={"ep-a": "cfg", "ep-b": "cfg"},
            configs={"cfg": self.IC_CONFIG},
            components=components,
        )
        return rows

    @pytest.mark.parametrize(
        "open_model, gap",
        [
            (
                {"EnableNetworkIsolation": False, "VpcConfig": {"Subnets": ["s"]}},
                "EnableNetworkIsolation off",
            ),
            ({"EnableNetworkIsolation": True}, "no VpcConfig"),
        ],
    )
    @pytest.mark.parametrize("open_first", [True, False])
    def test_an_inference_component_model_fails_only_its_endpoint(
        self, open_model, gap, open_first
    ):
        components = [
            ("ic-a", self._component("ep-a", "good")),
            ("ic-b", self._component("ep-b", "open")),
        ]
        if open_first:
            components.reverse()
        rows = self._ic_rows(
            {"good": _ISOLATED_VPC_MODEL, "open": open_model}, dict(components)
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "Endpoint 'ep-b'" in details
        assert "ep-a" not in details
        assert f"model 'open' of inference component 'ic-b' has {gap}" in details

    def test_a_second_specification_model_is_judged(self):
        rows = self._ic_rows(
            {"good": _ISOLATED_VPC_MODEL, "open": {"EnableNetworkIsolation": False}},
            {
                "ic-a": self._component("ep-a", "good"),
                "ic-b": self._component("ep-b", specifications=["good", "open"]),
            },
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert (
            "model 'open' of inference component 'ic-b'" in (rows[0]["Finding_Details"])
        )

    def test_an_inference_component_config_in_a_public_subnet_fails_alone(self):
        public_config = dict(
            self.IC_CONFIG,
            VpcConfig={"Subnets": ["subnet-public"], "SecurityGroupIds": ["sg-1"]},
        )
        rows, _ = _sm11_rows(
            {"good": _ISOLATED_VPC_MODEL},
            endpoints={"ep-a": "cfg-private", "ep-b": "cfg-public"},
            configs={"cfg-private": self.IC_CONFIG, "cfg-public": public_config},
            components={
                "ic-a": self._component("ep-a", "good"),
                "ic-b": self._component("ep-b", "good"),
            },
            subnet_fixtures=(PRIVATE_SUBNET_FIXTURE, PUBLIC_SUBNET_FIXTURE),
        )
        exposure = _by_finding(
            rows, sagemaker_app.ENDPOINT_CONFIG_SUBNET_EXPOSURE_FINDING
        )
        failed = [r for r in exposure if r["Status"] == "Failed"]
        assert len(failed) == 1
        details = failed[0]["Finding_Details"]
        assert "Endpoint config 'cfg-public' of endpoint 'ep-b'" in details
        assert "subnet-public" in details
        assert "cfg-private" not in details
        assert not [
            r
            for r in exposure
            if r["Status"] == "Passed" and "cfg-public" in r["Finding_Details"]
        ]

    @pytest.mark.parametrize(
        "vpc_config",
        [
            {"Subnets": ["subnet-private"]},
            {"Subnets": [], "SecurityGroupIds": ["sg-1"]},
            None,
        ],
    )
    def test_an_inference_component_config_without_subnets_and_groups_fails(
        self, vpc_config
    ):
        bare = dict(self.IC_CONFIG)
        bare.pop("VpcConfig")
        if vpc_config is not None:
            bare["VpcConfig"] = vpc_config
        rows, _ = _sm11_rows(
            {"good": _ISOLATED_VPC_MODEL},
            endpoints={"ep-a": "cfg", "ep-b": "cfg-bare"},
            configs={"cfg": self.IC_CONFIG, "cfg-bare": bare},
            components={
                "ic-a": self._component("ep-a", "good"),
                "ic-b": self._component("ep-b", "good"),
            },
        )
        network = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in network] == ["Failed"]
        assert (
            "endpoint config 'cfg-bare' (inference-component variants) has no "
            "VpcConfig with subnets and security groups"
        ) in network[0]["Finding_Details"]
        assert "ep-a" not in network[0]["Finding_Details"]
        exposure = _by_finding(
            rows, sagemaker_app.ENDPOINT_CONFIG_SUBNET_EXPOSURE_FINDING
        )
        assert [r["Status"] for r in exposure] == ["Passed"]

    def test_inference_components_on_isolated_models_pass(self):
        rows = self._ic_rows(
            {"good": _ISOLATED_VPC_MODEL},
            {
                "ic-a": self._component("ep-a", "good"),
                "ic-b": self._component("ep-b", "good"),
            },
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "2 endpoint(s)" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "component_b, named",
        [
            (("ep-b", _make_client_error("ThrottlingException")), "ic-b"),
            (("ep-b", {"Specification": {"ModelName": "gone"}}), "gone"),
        ],
    )
    def test_an_unread_inference_component_model_withholds_the_pass(
        self, component_b, named
    ):
        rows = self._ic_rows(
            {"good": _ISOLATED_VPC_MODEL},
            {"ic-a": self._component("ep-a", "good"), "ic-b": component_b},
        )
        assert not [
            r
            for r in _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
            if r["Status"] == "Passed"
        ]
        incomplete = _by_finding(
            rows, f"{sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING} Incomplete"
        )
        assert [r["Status"] for r in incomplete] == ["N/A"]
        assert named in incomplete[0]["Finding_Details"]
        assert "1 endpoint(s) serve" in incomplete[0]["Finding_Details"]

    def test_an_unlisted_inference_component_withholds_the_pass(self):
        rows, _ = _sm11_rows(
            {"good": _ISOLATED_VPC_MODEL},
            endpoints={"ep-a": "cfg-a", "ep-b": "cfg"},
            configs={"cfg-a": _config(["good"]), "cfg": self.IC_CONFIG},
            extra_pages={
                "list_inference_components": _make_client_error("AccessDenied")
            },
        )
        assert not [
            r
            for r in _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
            if r["Status"] == "Passed"
        ]
        incomplete = _by_finding(
            rows, f"{sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING} Incomplete"
        )
        assert (
            "inference components of endpoint 'ep-b'"
            in (incomplete[0]["Finding_Details"])
        )
        assert "1 endpoint(s) serve" in incomplete[0]["Finding_Details"]

    def test_list_endpoints_error_is_not_no_endpoints(self):
        pages = {"list_endpoints": _make_client_error("AccessDeniedException")}
        rows, _ = _sm11_rows({"a": _ISOLATED_VPC_MODEL}, extra_pages=pages)
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "AccessDeniedException" in rows[0]["Finding_Details"]

    def test_second_page_of_endpoints_is_read(self):
        pages = {
            "list_endpoints": [
                {"Endpoints": [{"EndpointName": "ep-a"}]},
                {"Endpoints": [{"EndpointName": "ep-open"}]},
            ]
        }
        rows, _ = _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL, "open": {"EnableNetworkIsolation": False}},
            endpoints={"ep-a": "cfg-a", "ep-open": "cfg-open"},
            configs={"cfg-a": _config(["a"]), "cfg-open": _config(["open"])},
            extra_pages=pages,
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_MODEL_NETWORK_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "ep-open" in rows[0]["Finding_Details"]


class TestSM11EndpointConfigKms:
    """EP-03: the endpoint config KmsKeyId leg, with the inter-container ceiling."""

    def test_one_unkeyed_config_among_two_is_failed(self):
        rows, _ = _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL},
            endpoints={"ep-keyed": "cfg-keyed", "ep-bare": "cfg-bare"},
            configs={
                "cfg-keyed": _config(["a"], kms="arn:aws:kms:us-east-1:1:key/k"),
                "cfg-bare": _config(["a"]),
            },
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_CONFIG_KMS_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "ep-bare" in rows[0]["Finding_Details"]
        assert "inter-container" in rows[0]["Finding_Details"]

    def test_all_keyed_is_passed_and_names_the_unread_hop(self):
        rows, _ = _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL},
            endpoints={"ep-1": "cfg-1", "ep-2": "cfg-2"},
            configs={
                "cfg-1": _config(["a"], kms="k1"),
                "cfg-2": _config(["a"], kms="k2"),
            },
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_CONFIG_KMS_FINDING)
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "inter-container traffic encryption" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize("aws_key", ["k-aws", "alias/aws/sagemaker"])
    def test_aws_managed_key_beside_a_customer_key_is_failed(self, aws_key):
        rows, _ = _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL},
            endpoints={"ep-cmk": "cfg-cmk", "ep-aws": "cfg-aws"},
            configs={
                "cfg-cmk": _config(["a"], kms="k-cmk"),
                "cfg-aws": _config(["a"], kms=aws_key),
            },
            key_managers={"k-aws": "AWS"},
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_CONFIG_KMS_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "ep-aws" in rows[0]["Finding_Details"]
        assert "AWS managed key" in rows[0]["Finding_Details"]
        assert "ep-cmk" not in rows[0]["Finding_Details"]

    def test_describe_key_error_holds_back_passed(self):
        rows, _ = _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL},
            endpoints={"ep-1": "cfg-1", "ep-2": "cfg-2"},
            configs={
                "cfg-1": _config(["a"], kms="k1"),
                "cfg-2": _config(["a"], kms="k2"),
            },
            key_managers={"k2": _make_client_error("AccessDeniedException")},
        )
        rows = _by_finding(rows, sagemaker_app.ENDPOINT_CONFIG_KMS_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "kms:DescribeKey k2" in rows[0]["Finding_Details"]
        assert "1 instance-backed endpoint(s)" in rows[0]["Finding_Details"]

    def test_serverless_only_config_is_not_judged(self):
        config = {
            "ProductionVariants": [
                {"VariantName": "s", "ModelName": "a", "ServerlessConfig": {}}
            ]
        }
        rows, _ = _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL},
            endpoints={"ep-sl": "cfg-sl"},
            configs={"cfg-sl": config},
        )
        assert _by_finding(rows, sagemaker_app.ENDPOINT_CONFIG_KMS_FINDING) == []


class TestSM11RuntimePrivatePath:
    """EP-01: an available sagemaker.runtime interface endpoint with private DNS."""

    _ENDPOINTS = {"ep-a": "cfg-a"}
    _CONFIGS = {"cfg-a": _config(["a"], kms="k")}

    def _run(self, vpces):
        return _sm11_rows(
            {"a": _ISOLATED_VPC_MODEL},
            endpoints=self._ENDPOINTS,
            configs=self._CONFIGS,
            vpces=vpces,
        )

    def test_no_runtime_endpoint_is_failed(self):
        rows, calls = self._run([])
        rows = _by_finding(rows, sagemaker_app.RUNTIME_PRIVATE_PATH_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        filters = calls["describe_vpc_endpoints"][0]["Filters"]
        assert "com.amazonaws.us-east-1.sagemaker.runtime" in filters[0]["Values"]

    def test_endpoints_without_private_dns_or_not_available_are_failed(self):
        rows, _ = self._run(
            [
                dict(
                    _PRIVATE_RUNTIME_VPCE,
                    VpcEndpointId="vpce-nodns",
                    PrivateDnsEnabled=False,
                ),
                dict(
                    _PRIVATE_RUNTIME_VPCE, VpcEndpointId="vpce-pending", State="pending"
                ),
            ]
        )
        rows = _by_finding(rows, sagemaker_app.RUNTIME_PRIVATE_PATH_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "vpce-nodns" in rows[0]["Finding_Details"]
        assert "vpce-pending" in rows[0]["Finding_Details"]

    def test_one_good_endpoint_is_passed(self):
        rows, _ = self._run(
            [
                dict(
                    _PRIVATE_RUNTIME_VPCE,
                    VpcEndpointId="vpce-nodns",
                    PrivateDnsEnabled=False,
                ),
                _PRIVATE_RUNTIME_VPCE,
            ]
        )
        rows = _by_finding(rows, sagemaker_app.RUNTIME_PRIVATE_PATH_FINDING)
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "vpce-good" in rows[0]["Finding_Details"]
        assert "public" in rows[0]["Finding_Details"]

    def test_access_denied_is_not_read_not_failed_or_passed(self):
        rows, _ = self._run(_make_client_error("UnauthorizedOperation"))
        rows = _by_finding(rows, sagemaker_app.RUNTIME_PRIVATE_PATH_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "ec2:DescribeVpcEndpoints" in rows[0]["Finding_Details"]

    def test_no_endpoints_asks_nothing(self):
        rows, calls = _sm11_rows({"a": _ISOLATED_VPC_MODEL}, vpces=[])
        assert _by_finding(rows, sagemaker_app.RUNTIME_PRIVATE_PATH_FINDING) == []
        assert "describe_vpc_endpoints" not in calls


class TestSM02RuntimeVpcEndpointPolicy:
    """EP-02: the sagemaker.runtime VPC endpoint policy layer."""

    _SCOPED = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sagemaker:InvokeEndpoint",
                    "Resource": "arn:aws:sagemaker:us-east-1:111122223333:endpoint/prod",
                }
            ]
        }
    )
    _DEFAULT = json.dumps(
        {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}
            ]
        }
    )

    def _run(self, vpces):
        ec2 = _pages_client(
            {
                "describe_vpc_endpoints": vpces
                if isinstance(vpces, Exception)
                else [{"VpcEndpoints": vpces}]
            }
        )
        with patch("sagemaker_app.boto3.client") as mock_client:
            mock_client.side_effect = _sm_client_factory(ec2=ec2)
            return _rows(
                sagemaker_app.check_sagemaker_runtime_endpoint_policy("us-east-1")
            )

    def test_default_policy_among_two_is_failed(self):
        rows = self._run(
            [
                dict(
                    _PRIVATE_RUNTIME_VPCE,
                    VpcEndpointId="vpce-scoped",
                    PolicyDocument=self._SCOPED,
                ),
                dict(
                    _PRIVATE_RUNTIME_VPCE,
                    VpcEndpointId="vpce-open",
                    PolicyDocument=self._DEFAULT,
                ),
            ]
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert rows[0]["Check_ID"] == "SM-02"
        assert "vpce-open" in rows[0]["Finding_Details"]

    def test_account_wide_resource_is_failed(self):
        policy = json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sagemaker:Invoke*",
                        "Resource": "arn:aws:sagemaker:us-east-1:111122223333:*",
                    }
                ]
            }
        )
        rows = self._run([dict(_PRIVATE_RUNTIME_VPCE, PolicyDocument=policy)])
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_all_scoped_is_passed(self):
        rows = self._run(
            [
                dict(
                    _PRIVATE_RUNTIME_VPCE,
                    VpcEndpointId="vpce-1",
                    PolicyDocument=self._SCOPED,
                ),
                dict(
                    _PRIVATE_RUNTIME_VPCE,
                    VpcEndpointId="vpce-2",
                    PolicyDocument=self._SCOPED,
                ),
            ]
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "vpce-1" in rows[0]["Finding_Details"]

    @staticmethod
    def _tag_policy(value):
        return json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sagemaker:InvokeEndpoint",
                        "Resource": "*",
                        "Condition": {"StringLike": {"aws:ResourceTag/team": value}},
                    }
                ]
            }
        )

    @pytest.mark.parametrize("any_tag_first", [True, False])
    def test_a_tag_condition_matching_any_value_fails_only_its_endpoint(
        self, any_tag_first
    ):
        vpces = [
            dict(
                _PRIVATE_RUNTIME_VPCE,
                VpcEndpointId="vpce-prefix",
                PolicyDocument=self._tag_policy("fraud-*"),
            ),
            dict(
                _PRIVATE_RUNTIME_VPCE,
                VpcEndpointId="vpce-anytag",
                PolicyDocument=self._tag_policy("*"),
            ),
        ]
        if any_tag_first:
            vpces.reverse()
        rows = self._run(vpces)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "vpce-anytag" in rows[0]["Finding_Details"]
        assert "vpce-prefix" not in rows[0]["Finding_Details"]

    def test_a_tag_condition_on_a_value_prefix_passes(self):
        rows = self._run(
            [dict(_PRIVATE_RUNTIME_VPCE, PolicyDocument=self._tag_policy("fraud-*"))]
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    def test_unparsable_policy_blocks_the_pass(self):
        rows = self._run(
            [
                dict(
                    _PRIVATE_RUNTIME_VPCE,
                    VpcEndpointId="vpce-1",
                    PolicyDocument=self._SCOPED,
                ),
                dict(
                    _PRIVATE_RUNTIME_VPCE,
                    VpcEndpointId="vpce-bad",
                    PolicyDocument="{not json",
                ),
            ]
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "vpce-bad" in rows[0]["Finding_Details"]

    def test_read_error_is_not_read(self):
        rows = self._run(_make_client_error("UnauthorizedOperation"))
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "UnauthorizedOperation" in rows[0]["Finding_Details"]

    def test_handler_calls_the_policy_leg_per_region(self):
        source = open(os.path.join(_sm_dir, "app.py"), encoding="utf-8").read()
        handler = source[source.index("def lambda_handler") :]
        assert "check_sagemaker_runtime_endpoint_policy(region=region)" in handler


def _invoke_allow(condition=None, resource="*"):
    return _identity_policy("sagemaker:InvokeEndpoint", resource, condition)


def _invoke_deny(operator, key="aws:SourceVpce", value="vpce-1", **extra):
    statement = {
        "Effect": "Deny",
        "Action": "sagemaker:InvokeEndpoint",
        "Resource": extra.pop("resource", "*"),
        "Condition": {operator: {key: value}, **extra.pop("more", {})},
    }
    if "not_resource" in extra:
        del statement["Resource"]
        statement["NotResource"] = extra.pop("not_resource")
    return statement


class TestSM11InvokeSourceNetwork:
    """AIR-SGM-EP-01: invoke grants held to aws:SourceVpce or aws:SourceVpc."""

    INVENTORY = {"endpoints": [{"name": "ep-1"}]}
    PINNED = {"StringEquals": {"aws:SourceVpce": "vpce-1"}}

    def _rows(self, cache, inventory=None):
        return _rows(
            {
                "csv_data": sagemaker_app._invoke_source_network_findings(
                    cache, inventory or self.INVENTORY, "us-east-1"
                )
            }
        )

    def test_open_role_fails_beside_a_pinned_one(self):
        rows = self._rows(
            _v2_cache(
                {
                    "Pinned": [("PinnedInvoke", _invoke_allow(self.PINNED))],
                    "Open": [("OpenInvoke", _invoke_allow())],
                }
            )
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert rows[0]["Check_ID"] == "SM-11"
        assert "Role 'Open' (policy 'OpenInvoke')" in rows[0]["Finding_Details"]
        assert "Pinned" not in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "condition",
        [
            {"StringEquals": {"aws:SourceVpce": "vpce-1"}},
            {"StringEquals": {"aws:SourceVpc": ["vpc-1", "vpc-2"]}},
            {"StringLike": {"aws:SourceVpce": "vpce-1"}},
            {"ForAnyValue:StringEquals": {"aws:SourceVpce": "vpce-1"}},
        ],
    )
    def test_pinned_allow_passes(self, condition):
        rows = self._rows(_v2_cache({"R": [("P", _invoke_allow(condition))]}))
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "Role 'R'" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "condition",
        [
            {"StringEqualsIfExists": {"aws:SourceVpce": "vpce-1"}},
            {"StringNotEquals": {"aws:SourceVpce": "vpce-1"}},
            {"Null": {"aws:SourceVpce": "false"}},
            {"StringLike": {"aws:SourceVpce": "vpce-*"}},
            {"ForAllValues:StringEquals": {"aws:SourceVpce": "vpce-1"}},
            {"StringEquals": {"aws:SourceAccount": "123456789012"}},
        ],
    )
    def test_allow_that_admits_a_public_call_fails(self, condition):
        rows = self._rows(_v2_cache({"R": [("P", _invoke_allow(condition))]}))
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_second_unpinned_statement_fails_the_principal(self):
        rows = self._rows(
            _v2_cache(
                {
                    "R": [
                        ("Pinned", _invoke_allow(self.PINNED)),
                        ("Async", _identity_policy("sagemaker:Invoke*", "*")),
                    ]
                }
            )
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "policy 'Async'" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "deny",
        [
            _invoke_deny("StringNotEquals"),
            _invoke_deny("StringNotEqualsIfExists", key="aws:SourceVpc", value="v"),
            _invoke_deny(
                "StringNotEquals",
                resource="arn:aws:sagemaker:*:*:endpoint/*",
            ),
        ],
    )
    def test_identity_deny_outside_the_vpce_passes(self, deny):
        policy = _invoke_allow()
        policy["Statement"].append(deny)
        rows = self._rows(_v2_cache({"R": [("P", policy)]}))
        assert [r["Status"] for r in rows] == ["Passed"]

    @pytest.mark.parametrize(
        "deny",
        [
            _invoke_deny("ForAnyValue:StringNotEquals"),
            _invoke_deny("StringNotLike", value="vpce-*"),
            _invoke_deny(
                "StringNotEquals", more={"Bool": {"aws:ViaAWSService": "false"}}
            ),
            _invoke_deny(
                "StringNotEquals",
                resource="arn:aws:sagemaker:us-east-1:123456789012:endpoint/a",
            ),
            _invoke_deny("StringNotEquals", not_resource="arn:aws:s3:::b"),
            _invoke_deny("StringEquals"),
        ],
    )
    def test_deny_that_misses_a_public_call_fails(self, deny):
        policy = _invoke_allow()
        policy["Statement"].append(deny)
        rows = self._rows(_v2_cache({"R": [("P", policy)]}))
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_group_grant_is_read(self):
        rows = self._rows(
            _v2_cache({}, users={"G": _group_user("GroupInvoke", _invoke_allow())})
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "User 'G' (policy 'GroupInvoke')" in rows[0]["Finding_Details"]

    def test_pinning_boundary_passes_and_a_boundary_without_invoke_is_skipped(self):
        cache = _v2_cache(
            {"Bounded": [("P", _invoke_allow())], "NoInvoke": [("P", _invoke_allow())]},
            boundaries={
                "Bounded": _invoke_allow(self.PINNED),
                "NoInvoke": _identity_policy("s3:GetObject", "*"),
            },
        )
        rows = self._rows(cache)
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "1 principal(s)" in rows[0]["Finding_Details"]
        assert "NoInvoke" not in rows[0]["Finding_Details"]

    def test_unread_principal_holds_back_passed(self):
        cache = _v2_cache(
            {"R": [("P", _invoke_allow(self.PINNED))]},
            principal_errors=[
                {"type": "Role", "name": "Hidden", "stage": "attached_policies"}
            ],
        )
        rows = self._rows(cache)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert rows[0]["Finding"].endswith("Incomplete")
        assert "Role 'Hidden'" in rows[0]["Finding_Details"]

    def test_unread_boundary_is_incomplete_not_failed(self):
        cache = _v2_cache(
            {"R": [("P", _invoke_allow())]},
            principal_errors=[
                {"type": "Role", "name": "R", "stage": "permissions_boundary"}
            ],
        )
        rows = self._rows(cache)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "permissions boundary not read" in rows[0]["Finding_Details"]

    def test_no_endpoints_emits_nothing(self):
        cache = _v2_cache({"R": [("P", _invoke_allow())]})
        assert self._rows(cache, inventory={"endpoints": []}) == []

    def test_missing_cache_is_incomplete(self):
        rows = self._rows(None)
        assert [r["Status"] for r in rows] == ["N/A"]

    def test_check_reads_the_cache_it_is_given(self):
        rows, _ = _sm11_rows(
            {"m": _ISOLATED_VPC_MODEL},
            endpoints={"ep-1": "cfg"},
            configs={"cfg": _config(["m"])},
            vpces=[_PRIVATE_RUNTIME_VPCE],
            permission_cache=_v2_cache({"Open": [("OpenInvoke", _invoke_allow())]}),
        )
        source = [
            r
            for r in rows
            if r["Finding"] == sagemaker_app.INVOKE_SOURCE_NETWORK_FINDING
        ]
        assert [r["Status"] for r in source] == ["Failed"]
        assert "Role 'Open'" in source[0]["Finding_Details"]

    def test_handler_passes_the_cache(self):
        source = open(os.path.join(_sm_dir, "app.py"), encoding="utf-8").read()
        handler = source[source.index("def lambda_handler") :]
        assert (
            "check_sagemaker_model_network_isolation(\n"
            "            region=region, permission_cache=permission_cache"
        ) in handler


# ===================================================================
# SM-33 full grade: AIR-SGM-TRN-01
# ===================================================================
# The job subnet and its route tables in each fixture VPC, so a default
# endpoint serves the subnet the SM-18 and SM-33 fixtures place jobs in.
_VPCE_REACH = {
    "vpc-1": (["subnet-a"], ["rtb-a", "rtb-subnet-a"]),
    "vpc-2": (["subnet-b"], ["rtb-subnet-b"]),
}


def _vpce(
    vpc_id,
    service,
    endpoint_type="Interface",
    state="available",
    dns=True,
    subnets=None,
    route_tables=None,
):
    vpce = {
        "VpcEndpointId": f"vpce-{vpc_id}-{service}",
        "VpcId": vpc_id,
        "ServiceName": f"com.amazonaws.us-east-1.{service}",
        "VpcEndpointType": endpoint_type,
        "State": state,
        "PrivateDnsEnabled": dns,
    }
    default_subnets, default_tables = _VPCE_REACH.get(vpc_id, ([], []))
    if endpoint_type == "Gateway":
        vpce["RouteTableIds"] = (
            route_tables if route_tables is not None else default_tables
        )
    else:
        vpce["SubnetIds"] = subnets if subnets is not None else default_subnets
    return vpce


def _full_training_vpces(vpc_id):
    return [_vpce(vpc_id, "s3", endpoint_type="Gateway", dns=None)] + [
        _vpce(vpc_id, service)
        for service in ("logs", "sagemaker.api", "ecr.api", "ecr.dkr")
    ]


def _in_vpc_job(subnet, isolated=True):
    return {
        "VpcConfig": {"Subnets": [subnet], "SecurityGroupIds": ["sg-1"]},
        "EnableNetworkIsolation": isolated,
    }


def _sm33_rows(jobs, subnets=None, vpces=None, job_pages=None):
    """Run SM-33 over jobs {name: DescribeTrainingJob or exception}."""
    subnets = subnets or [_subnet("subnet-a", "vpc-1"), _subnet("subnet-b", "vpc-2")]
    tables = [
        _route_table(
            f"rtb-{s['SubnetId']}",
            [LOCAL_ROUTE],
            _explicit(s["SubnetId"]),
            vpc_id=s["VpcId"],
        )
        for s in subnets
    ]

    def describe_training_job(TrainingJobName):
        value = jobs[TrainingJobName]
        if isinstance(value, Exception):
            raise value
        return value

    sm = _pages_client(
        {
            "list_training_jobs": job_pages
            or [{"TrainingJobSummaries": [{"TrainingJobName": n} for n in jobs]}]
        },
        describe_training_job=MagicMock(side_effect=describe_training_job),
    )
    ec2 = _pages_client(
        {
            "describe_subnets": [{"Subnets": subnets}],
            "describe_route_tables": [{"RouteTables": tables}],
            "describe_vpc_endpoints": vpces
            if isinstance(vpces, Exception)
            else [{"VpcEndpoints": vpces or []}],
        }
    )
    with patch("sagemaker_app.boto3.client") as mock_client:
        mock_client.side_effect = _sm_client_factory(sagemaker=sm, ec2=ec2)
        return _rows(
            sagemaker_app.check_sagemaker_training_job_network_boundary(
                region="us-east-1"
            )
        )


class TestSM33WholePopulation:
    def test_a_job_on_the_second_page_past_fifty_is_read(self):
        names = [f"job-{i}" for i in range(60)]
        jobs = {n: _in_vpc_job("subnet-a") for n in names}
        jobs["job-55"] = {"EnableNetworkIsolation": True}
        pages = [
            {"TrainingJobSummaries": [{"TrainingJobName": n} for n in names[:50]]},
            {"TrainingJobSummaries": [{"TrainingJobName": n} for n in names[50:]]},
        ]
        rows = _sm33_rows(jobs, vpces=_full_training_vpces("vpc-1"), job_pages=pages)
        failed = [
            r
            for r in rows
            if r["Finding"] == sagemaker_app.TRAINING_NETWORK_BOUNDARY_FINDING
            and r["Status"] == "Failed"
        ]
        assert len(failed) == 1
        assert "job-55" in failed[0]["Finding_Details"]

    def test_describe_error_replaces_the_pass_with_incomplete(self):
        rows = _sm33_rows(
            {
                "good": _in_vpc_job("subnet-a"),
                "denied": _make_client_error("AccessDeniedException"),
            },
            vpces=_full_training_vpces("vpc-1"),
        )
        boundary = _by_finding(rows, sagemaker_app.TRAINING_NETWORK_BOUNDARY_FINDING)
        assert [r["Status"] for r in boundary] == ["N/A"]
        assert "denied" in boundary[0]["Finding_Details"]


class TestSM33NetworkIsolation:
    def test_in_vpc_job_with_isolation_off_is_failed_and_isolated_one_is_not(self):
        rows = _sm33_rows(
            {
                "isolated": _in_vpc_job("subnet-a"),
                "open": _in_vpc_job("subnet-a", isolated=False),
            },
            vpces=_full_training_vpces("vpc-1"),
        )
        rows = _by_finding(rows, sagemaker_app.TRAINING_NETWORK_ISOLATION_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'open'" in rows[0]["Finding_Details"]


class TestSM33VpcEndpointCoverage:
    def test_one_vpc_missing_an_endpoint_among_two_is_failed(self):
        vpces = _full_training_vpces("vpc-1") + [
            v
            for v in _full_training_vpces("vpc-2")
            if "ecr.dkr" not in v["ServiceName"]
        ]
        rows = _sm33_rows(
            {"a": _in_vpc_job("subnet-a"), "b": _in_vpc_job("subnet-b")}, vpces=vpces
        )
        rows = _by_finding(rows, sagemaker_app.TRAINING_VPC_ENDPOINTS_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "vpc-2" in rows[0]["Finding_Details"]
        assert "ecr.dkr" in rows[0]["Finding_Details"]
        assert "ecr.api" not in rows[0]["Finding_Details"]

    def test_interface_without_private_dns_or_pending_does_not_count(self):
        vpces = [
            v
            for v in _full_training_vpces("vpc-1")
            if "logs" not in v["ServiceName"]
            and "sagemaker.api" not in v["ServiceName"]
        ] + [
            _vpce("vpc-1", "logs", dns=False),
            _vpce("vpc-1", "sagemaker.api", state="pending"),
        ]
        rows = _sm33_rows({"a": _in_vpc_job("subnet-a")}, vpces=vpces)
        rows = _by_finding(rows, sagemaker_app.TRAINING_VPC_ENDPOINTS_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "logs" in rows[0]["Finding_Details"]
        assert "sagemaker.api" in rows[0]["Finding_Details"]

    def test_every_vpc_complete_is_passed(self):
        rows = _sm33_rows(
            {"a": _in_vpc_job("subnet-a"), "b": _in_vpc_job("subnet-b")},
            vpces=_full_training_vpces("vpc-1") + _full_training_vpces("vpc-2"),
        )
        rows = _by_finding(rows, sagemaker_app.TRAINING_VPC_ENDPOINTS_FINDING)
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "vpc-1" in rows[0]["Finding_Details"]
        assert "vpc-2" in rows[0]["Finding_Details"]

    def test_s3_gateway_not_associated_with_the_job_route_table_fails(self):
        # AIR-SGM-TRN-01: an S3 gateway endpoint on another route table carries
        # none of the job subnet's traffic, and this passed before.
        vpces = [
            v for v in _full_training_vpces("vpc-1") if "s3" not in v["ServiceName"]
        ] + [_vpce("vpc-1", "s3", "Gateway", dns=None, route_tables=["rtb-other"])]
        rows = _sm33_rows({"a": _in_vpc_job("subnet-a")}, vpces=vpces)
        rows = _by_finding(rows, sagemaker_app.TRAINING_VPC_ENDPOINTS_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert (
            "com.amazonaws.us-east-1.s3 endpoint(s) vpce-vpc-1-s3"
            in (rows[0]["Finding_Details"])
        )
        assert (
            "subnet-a (route table rtb-subnet-a, us-east-1a)"
            in (rows[0]["Finding_Details"])
        )
        assert "logs" not in rows[0]["Finding_Details"]

    def test_interface_endpoint_without_an_interface_in_the_job_zone_fails(self):
        subnets = [
            _subnet("subnet-a", "vpc-1"),
            dict(_subnet("subnet-c", "vpc-1"), AvailabilityZone="us-east-1c"),
            dict(_subnet("subnet-e", "vpc-1"), AvailabilityZone="us-east-1e"),
        ]
        vpces = [
            v for v in _full_training_vpces("vpc-1") if "logs" not in v["ServiceName"]
        ] + [_vpce("vpc-1", "logs", subnets=["subnet-a", "subnet-e"])]
        rows = _sm33_rows(
            {"a": _in_vpc_job("subnet-a"), "c": _in_vpc_job("subnet-c")},
            subnets=subnets,
            vpces=[
                dict(v, RouteTableIds=["rtb-subnet-a", "rtb-subnet-c"])
                if v["VpcEndpointType"] == "Gateway"
                else dict(v, SubnetIds=v["SubnetIds"] + ["subnet-c"])
                if "logs" not in v["ServiceName"]
                else v
                for v in vpces
            ],
        )
        rows = _by_finding(rows, sagemaker_app.TRAINING_VPC_ENDPOINTS_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "com.amazonaws.us-east-1.logs endpoint(s)" in details
        assert "subnet-c (route table rtb-subnet-c, us-east-1c)" in details
        assert "subnet-a (" not in details
        assert "ecr.api" not in details

    def test_unread_endpoint_subnet_withholds_the_pass(self):
        vpces = [
            v for v in _full_training_vpces("vpc-1") if "logs" not in v["ServiceName"]
        ] + [_vpce("vpc-1", "logs", subnets=["subnet-gone"])]
        rows = _sm33_rows({"a": _in_vpc_job("subnet-a")}, vpces=vpces)
        rows = _by_finding(rows, sagemaker_app.TRAINING_VPC_ENDPOINTS_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "logs endpoint reaches subnet subnet-a" in rows[0]["Finding_Details"]

    def test_endpoint_read_denied_is_incomplete(self):
        rows = _sm33_rows(
            {"a": _in_vpc_job("subnet-a")},
            vpces=_make_client_error("UnauthorizedOperation"),
        )
        rows = _by_finding(rows, sagemaker_app.TRAINING_VPC_ENDPOINTS_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "UnauthorizedOperation" in rows[0]["Finding_Details"]

    def test_subnet_not_found_blocks_the_pass(self):
        rows = _sm33_rows(
            {"a": _in_vpc_job("subnet-a"), "gone": _in_vpc_job("subnet-deleted")},
            vpces=_full_training_vpces("vpc-1"),
        )
        rows = _by_finding(rows, sagemaker_app.TRAINING_VPC_ENDPOINTS_FINDING)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "subnet-deleted" in rows[0]["Finding_Details"]


# ===================================================================
# AIR-SGM-EP-08: SM-18 transform job output key, model boundary, buckets
# ===================================================================
_CMK = "arn:aws:kms:us-east-1:123456789012:key/1111"
_AWS_KEY = "arn:aws:kms:us-east-1:123456789012:key/2222"
_ISOLATED_MODEL = {
    "VpcConfig": {"Subnets": ["subnet-a"], "SecurityGroupIds": ["sg-1"]},
    "EnableNetworkIsolation": True,
}
_KMS_BUCKET = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": _CMK,
                }
            }
        ]
    }
}


def _transform_job(model="m", volume=_CMK, output=_CMK, bucket="data"):
    return {
        "ModelName": model,
        "TransformResources": {"InstanceType": "ml.m5.large", "VolumeKmsKeyId": volume},
        "TransformInput": {
            "DataSource": {"S3DataSource": {"S3Uri": f"s3://{bucket}/in/"}}
        },
        "TransformOutput": {"S3OutputPath": f"s3://{bucket}/out/", "KmsKeyId": output},
    }


def _tls_statement(bucket="data", **overrides):
    statement = {
        "Sid": "TLSOnly",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
    statement.update(overrides)
    return statement


def _tls_policy(bucket="data", **overrides):
    return json.dumps(
        {"Version": "2012-10-17", "Statement": [_tls_statement(bucket, **overrides)]}
    )


def _s3_endpoint_policy(resource, principal="*", condition=None, sid="Data"):
    statement = {
        "Sid": sid,
        "Effect": "Allow",
        "Principal": principal,
        "Action": ["s3:GetObject", "s3:PutObject"],
        "Resource": resource,
    }
    if condition:
        statement["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


def _scoped_s3_gateway(vpc_id, policy=None, suffix=""):
    vpce = _vpce(vpc_id, "s3", endpoint_type="Gateway", dns=None)
    vpce["VpcEndpointId"] += suffix
    vpce["PolicyDocument"] = (
        policy if policy is not None else _s3_endpoint_policy("arn:aws:s3:::data/*")
    )
    return vpce


def _sm18_rows(
    jobs,
    models=None,
    keys=None,
    buckets=None,
    vpces=None,
    job_pages=None,
    calls=None,
):
    """Run SM-18 over jobs {name: DescribeTransformJob or exception}."""
    models = models if models is not None else {"m": _ISOLATED_MODEL}
    keys = keys or {}
    buckets = buckets or {}
    calls = calls if calls is not None else {}

    def lookup(table, name):
        value = table[name]
        if isinstance(value, Exception):
            raise value
        return value

    def describe_model(ModelName):
        if ModelName not in models:
            raise _make_client_error(
                "ValidationException", f'Could not find model "{ModelName}".'
            )
        return lookup(models, ModelName)

    def describe_key(KeyId):
        calls.setdefault("describe_key", []).append(KeyId)
        value = keys.get(KeyId, "CUSTOMER")
        if isinstance(value, Exception):
            raise value
        return {"KeyMetadata": {"KeyId": KeyId, "KeyManager": value}}

    def bucket_part(part, Bucket):
        value = buckets.get(Bucket, {}).get(part)
        if value is None:
            value = (
                _KMS_BUCKET if part == "encryption" else {"Policy": _tls_policy(Bucket)}
            )
        if isinstance(value, Exception):
            raise value
        return value

    sm = _pages_client(
        {
            "list_transform_jobs": job_pages
            or [{"TransformJobSummaries": [{"TransformJobName": n} for n in jobs]}]
        },
        describe_transform_job=MagicMock(
            side_effect=lambda TransformJobName: lookup(jobs, TransformJobName)
        ),
        describe_model=MagicMock(side_effect=describe_model),
    )
    ec2 = _pages_client(
        {
            "describe_subnets": [{"Subnets": [_subnet("subnet-a", "vpc-1")]}],
            "describe_route_tables": [
                {
                    "RouteTables": [
                        _route_table("rtb-a", [LOCAL_ROUTE], _explicit("subnet-a"))
                    ]
                }
            ],
            "describe_vpc_endpoints": [
                {
                    "VpcEndpoints": vpces
                    if vpces is not None
                    else [_scoped_s3_gateway("vpc-1")]
                }
            ],
        }
    )
    kms = MagicMock()
    kms.describe_key.side_effect = describe_key
    s3 = MagicMock()
    s3.get_bucket_encryption.side_effect = lambda Bucket: bucket_part(
        "encryption", Bucket
    )
    s3.get_bucket_policy.side_effect = lambda Bucket: bucket_part("policy", Bucket)
    with patch("sagemaker_app.boto3.client") as mock_client:
        mock_client.side_effect = _sm_client_factory(
            sagemaker=sm, ec2=ec2, kms=kms, s3=s3
        )
        return _rows(
            sagemaker_app.check_sagemaker_transform_job_encryption(region="us-east-1")
        )


def _statuses(rows, name):
    return [r["Status"] for r in rows if r["Finding"].startswith(name)]


class TestSM18TransformJobBoundary:
    """AIR-SGM-EP-08: output key, customer managed keys, model network, buckets."""

    def test_clean_job_passes_every_leg(self):
        rows = _sm18_rows({"good": _transform_job()})
        assert _statuses(rows, "SageMaker Transform Job Encryption Check") == ["Passed"]
        for name in (
            sagemaker_app.TRANSFORM_JOB_BOUNDARY_FINDING,
            sagemaker_app.TRANSFORM_SUBNET_EXPOSURE_FINDING,
            sagemaker_app.TRANSFORM_S3_ENDPOINT_FINDING,
            sagemaker_app.TRANSFORM_BUCKET_FINDING,
        ):
            assert _statuses(rows, name) == ["Passed"], name
        assert all(r["Check_ID"] == "SM-18" for r in rows)

    @pytest.mark.parametrize(
        "job,models,text",
        [
            (_transform_job(output=None), None, "TransformOutput.KmsKeyId is not set"),
            # AIR-SGM-EP-08: a job with no volume key was counted in the Passed
            # row that claims customer managed keys for the volume.
            (
                _transform_job(volume=None),
                None,
                "TransformResources.VolumeKmsKeyId is not set",
            ),
            (
                _transform_job(model="open"),
                {"open": {"EnableNetworkIsolation": True}},
                "model 'open' has no VpcConfig",
            ),
            (
                _transform_job(model="leaky"),
                {"leaky": dict(_ISOLATED_MODEL, EnableNetworkIsolation=False)},
                "model 'leaky' does not set EnableNetworkIsolation",
            ),
            (
                _transform_job(output="alias/aws/sagemaker"),
                None,
                "TransformOutput.KmsKeyId alias/aws/sagemaker is an AWS managed key",
            ),
            (
                _transform_job(volume=_AWS_KEY),
                None,
                f"TransformResources.VolumeKmsKeyId {_AWS_KEY} is an AWS managed key",
            ),
        ],
    )
    def test_one_bad_job_among_good_ones_fails_alone(self, job, models, text):
        all_models = {"m": _ISOLATED_MODEL, **(models or {})}
        rows = _sm18_rows(
            {"good-1": _transform_job(), "bad": job, "good-2": _transform_job()},
            models=all_models,
            keys={_AWS_KEY: "AWS"},
        )
        boundary = _by_finding(rows, sagemaker_app.TRANSFORM_JOB_BOUNDARY_FINDING)
        assert [r["Status"] for r in boundary] == ["Failed"]
        assert text in boundary[0]["Finding_Details"]
        assert "'bad'" in boundary[0]["Finding_Details"]
        assert "good-" not in boundary[0]["Finding_Details"]

    def test_aws_managed_alias_is_judged_without_a_describe_call(self):
        calls = {}
        rows = _sm18_rows(
            {"j": _transform_job(output="alias/aws/sagemaker")}, calls=calls
        )
        assert _statuses(rows, sagemaker_app.TRANSFORM_JOB_BOUNDARY_FINDING) == [
            "Failed"
        ]
        assert "alias/aws/sagemaker" not in calls["describe_key"]
        assert set(calls["describe_key"]) == {_CMK}

    @pytest.mark.parametrize(
        "jobs,models,keys,text",
        [
            (
                {"j": _transform_job()},
                None,
                {_CMK: _make_client_error("AccessDeniedException")},
                f"kms:DescribeKey {_CMK} (AccessDeniedException)",
            ),
            (
                {"j": _transform_job(model="gone")},
                {},
                None,
                "model 'gone' no longer exists",
            ),
            (
                {"j": _transform_job()},
                {"m": _make_client_error("AccessDeniedException")},
                None,
                "sagemaker:DescribeModel m (AccessDeniedException)",
            ),
        ],
    )
    def test_unread_leg_is_incomplete_not_passed(self, jobs, models, keys, text):
        rows = _sm18_rows(jobs, models=models, keys=keys)
        boundary = _by_finding(rows, sagemaker_app.TRANSFORM_JOB_BOUNDARY_FINDING)
        assert [r["Status"] for r in boundary] == ["N/A"]
        assert text in boundary[0]["Finding_Details"]

    def test_describe_job_error_leaves_no_pass_on_either_leg(self):
        rows = _sm18_rows(
            {"good": _transform_job(), "denied": _make_client_error("AccessDenied")}
        )
        assert _statuses(rows, "SageMaker Transform Job Encryption Check") == ["N/A"]
        boundary = _by_finding(rows, sagemaker_app.TRANSFORM_JOB_BOUNDARY_FINDING)
        assert [r["Status"] for r in boundary] == ["N/A"]
        assert "denied" in boundary[0]["Finding_Details"]
        assert not any(
            r["Status"] == "Passed"
            and r["Finding"]
            in (
                "SageMaker Transform Job Encryption Check",
                sagemaker_app.TRANSFORM_JOB_BOUNDARY_FINDING,
            )
            for r in rows
        )

    def test_known_failure_stands_beside_an_unread_job(self):
        rows = _sm18_rows(
            {
                "bad": _transform_job(output=None),
                "unread": _transform_job(model="gone"),
            }
        )
        assert _statuses(rows, sagemaker_app.TRANSFORM_JOB_BOUNDARY_FINDING) == [
            "Failed",
            "N/A",
        ]

    def test_list_error_is_not_reported_as_no_jobs(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            sm = _pages_client(
                {"list_transform_jobs": _make_client_error("AccessDeniedException")}
            )
            mock_client.return_value = sm
            rows = extract_csv_data(
                sagemaker_app.check_sagemaker_transform_job_encryption("us-east-1")
            )
        assert len(rows) == 1
        assert_could_not_assess_finding(rows[0])
        assert "No transform jobs found" not in rows[0]["Finding_Details"]

    def test_job_on_a_later_page_is_read(self):
        jobs = {f"j{i}": _transform_job() for i in range(3)}
        jobs["j2"] = _transform_job(output=None)
        rows = _sm18_rows(
            jobs,
            job_pages=[
                {"TransformJobSummaries": [{"TransformJobName": "j0"}]},
                {"TransformJobSummaries": [{"TransformJobName": "j1"}]},
                {"TransformJobSummaries": [{"TransformJobName": "j2"}]},
            ],
        )
        boundary = _by_finding(rows, sagemaker_app.TRANSFORM_JOB_BOUNDARY_FINDING)
        assert [r["Status"] for r in boundary] == ["Failed"]
        assert "'j2'" in boundary[0]["Finding_Details"]

    def test_vpc_without_s3_endpoint_fails(self):
        rows = _sm18_rows({"j": _transform_job()}, vpces=[_vpce("vpc-1", "logs")])
        row = _by_finding(rows, sagemaker_app.TRANSFORM_S3_ENDPOINT_FINDING)
        assert [r["Status"] for r in row] == ["Failed"]
        assert "com.amazonaws.us-east-1.s3" in row[0]["Finding_Details"]
        assert "transform job(s) j" in row[0]["Finding_Details"]

    DEFAULT_ENDPOINT_POLICY = json.dumps(
        {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}
            ]
        }
    )

    @pytest.mark.parametrize(
        "policy",
        [
            DEFAULT_ENDPOINT_POLICY,
            _s3_endpoint_policy("arn:aws:s3:::*/*"),
            _s3_endpoint_policy("*", principal={"AWS": "123456789012"}),
            _s3_endpoint_policy(
                "*", principal={"AWS": "arn:aws:iam::123456789012:root"}
            ),
            _s3_endpoint_policy(
                "*", principal={"AWS": "arn:aws:iam::123456789012:role/*"}
            ),
            _s3_endpoint_policy(
                "*",
                condition={
                    "StringLike": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/*"
                    }
                },
            ),
            _s3_endpoint_policy(
                "*",
                condition={
                    "StringNotEquals": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/x"
                    }
                },
            ),
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:*",
                            "NotResource": "arn:aws:s3:::secret/*",
                        }
                    ]
                }
            ),
        ],
    )
    def test_s3_endpoint_policy_open_to_every_bucket_fails(self, policy):
        rows = _sm18_rows(
            {"j": _transform_job()}, vpces=[_scoped_s3_gateway("vpc-1", policy)]
        )
        row = _by_finding(rows, sagemaker_app.TRANSFORM_S3_ENDPOINT_FINDING)
        assert [r["Status"] for r in row] == ["Failed"]
        assert "on every bucket to any principal" in row[0]["Finding_Details"]

    # AIR-SGM-EP-08: these two passed before because the principal was named.
    # Every bucket through the endpoint leaves no bucket boundary, so they fail.
    @pytest.mark.parametrize(
        "policy",
        [
            _s3_endpoint_policy(
                "*", principal={"AWS": "arn:aws:iam::123456789012:role/exec"}
            ),
            _s3_endpoint_policy(
                "*",
                condition={
                    "ArnEquals": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/exec"
                    }
                },
            ),
        ],
    )
    def test_named_principal_on_every_bucket_fails(self, policy):
        rows = _sm18_rows(
            {"j": _transform_job()}, vpces=[_scoped_s3_gateway("vpc-1", policy)]
        )
        row = _by_finding(rows, sagemaker_app.TRANSFORM_S3_ENDPOINT_FINDING)
        assert [r["Status"] for r in row] == ["Failed"]
        assert "on every bucket" in row[0]["Finding_Details"]
        assert "any principal" not in row[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "resource",
        ["arn:aws:s3:::data-*/*", "arn:aws:s3:::dat?/*", "arn:aws:s3:::*a/*"],
    )
    def test_any_principal_on_a_wildcard_bucket_pattern_fails(self, resource):
        rows = _sm18_rows(
            {"j": _transform_job()},
            vpces=[_scoped_s3_gateway("vpc-1", _s3_endpoint_policy(resource))],
        )
        row = _by_finding(rows, sagemaker_app.TRANSFORM_S3_ENDPOINT_FINDING)
        assert [r["Status"] for r in row] == ["Failed"]
        assert (
            f"bucket pattern(s) with a wildcard: {resource}"
            in (row[0]["Finding_Details"])
        )

    @pytest.mark.parametrize(
        "policy",
        [
            _s3_endpoint_policy(["arn:aws:s3:::data", "arn:aws:s3:::data/*"]),
            _s3_endpoint_policy(
                "arn:aws:s3:::data-*/*",
                principal={"AWS": "arn:aws:iam::123456789012:role/exec"},
            ),
        ],
    )
    def test_s3_endpoint_policy_scoped_by_bucket_or_role_passes(self, policy):
        rows = _sm18_rows(
            {"j": _transform_job()}, vpces=[_scoped_s3_gateway("vpc-1", policy)]
        )
        row = _by_finding(rows, sagemaker_app.TRANSFORM_S3_ENDPOINT_FINDING)
        assert [r["Status"] for r in row] == ["Passed"]
        assert "workload decision" in row[0]["Finding_Details"]

    def test_one_open_s3_endpoint_beside_a_scoped_one_fails(self):
        rows = _sm18_rows(
            {"j": _transform_job()},
            vpces=[
                _scoped_s3_gateway("vpc-1"),
                _scoped_s3_gateway("vpc-1", self.DEFAULT_ENDPOINT_POLICY, "-open"),
            ],
        )
        row = _by_finding(rows, sagemaker_app.TRANSFORM_S3_ENDPOINT_FINDING)
        assert [r["Status"] for r in row] == ["Failed"]
        assert "-open" in row[0]["Finding_Details"]

    @pytest.mark.parametrize("policy", ["", "{not json"])
    def test_unread_s3_endpoint_policy_is_incomplete(self, policy):
        vpce = _scoped_s3_gateway("vpc-1", policy)
        if not policy:
            del vpce["PolicyDocument"]
        rows = _sm18_rows({"j": _transform_job()}, vpces=[vpce])
        row = _by_finding(rows, sagemaker_app.TRANSFORM_S3_ENDPOINT_FINDING)
        assert [r["Status"] for r in row] == ["N/A"]
        assert "policy of S3 endpoint" in row[0]["Finding_Details"]

    def test_model_outside_a_vpc_gets_no_endpoint_or_subnet_pass(self):
        rows = _sm18_rows(
            {"j": _transform_job(model="open")},
            models={"open": {"EnableNetworkIsolation": True}},
        )
        assert _statuses(rows, sagemaker_app.TRANSFORM_S3_ENDPOINT_FINDING) == []
        assert _statuses(rows, sagemaker_app.TRANSFORM_SUBNET_EXPOSURE_FINDING) == []


class TestSM18BucketProtection:
    """The source and output buckets: SSE-KMS with a CMK and a TLS-only Deny."""

    def _bucket_rows(self, bucket_reads, keys=None):
        rows = _sm18_rows(
            {
                "clean": _transform_job(bucket="clean"),
                "target": _transform_job(bucket="target"),
            },
            buckets={"target": bucket_reads},
            keys=keys,
        )
        return _by_finding(rows, sagemaker_app.TRANSFORM_BUCKET_FINDING)

    @pytest.mark.parametrize(
        "reads,text",
        [
            (
                {
                    "encryption": {
                        "ServerSideEncryptionConfiguration": {
                            "Rules": [
                                {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "AES256"
                                    }
                                }
                            ]
                        }
                    }
                },
                "default encryption is not SSE-KMS (AES256)",
            ),
            (
                {
                    "encryption": {
                        "ServerSideEncryptionConfiguration": {
                            "Rules": [
                                {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "aws:kms"
                                    }
                                }
                            ]
                        }
                    }
                },
                "uses the AWS managed key aws/s3",
            ),
            (
                {
                    "encryption": _make_client_error(
                        "ServerSideEncryptionConfigurationNotFoundError"
                    )
                },
                "no default encryption configuration",
            ),
            (
                {"policy": _make_client_error("NoSuchBucketPolicy")},
                "has no bucket policy",
            ),
            (
                {
                    "policy": {
                        "Policy": _tls_policy(
                            "target",
                            Condition={"Bool": {"aws:SecureTransport": "true"}},
                        )
                    }
                },
                "has no Deny on aws:SecureTransport false",
            ),
            (
                {
                    "policy": {
                        "Policy": _tls_policy(
                            "target",
                            Principal={"AWS": "arn:aws:iam::123456789012:root"},
                        )
                    }
                },
                "it does not apply to every principal",
            ),
            (
                {
                    "policy": {
                        "Policy": _tls_policy("target", Resource="arn:aws:s3:::target")
                    }
                },
                "its Resource does not cover every object",
            ),
            (
                {
                    "policy": {
                        "Policy": _tls_policy(
                            "target", Resource="arn:aws:s3:::target/public/*"
                        )
                    }
                },
                "its Resource does not cover the bucket",
            ),
            (
                {"policy": {"Policy": _tls_policy("target", Action="s3:GetObject")}},
                "its Action does not cover s3:*",
            ),
            (
                {
                    "policy": {
                        "Policy": _tls_policy(
                            "target",
                            Condition={
                                "Bool": {"aws:SecureTransport": "false"},
                                "StringEquals": {"aws:PrincipalAccount": "111"},
                            },
                        )
                    }
                },
                "its Condition also tests StringEquals aws:principalaccount",
            ),
            (
                {"policy": {"Policy": _tls_policy("target", Effect="Allow")}},
                "has no Deny on aws:SecureTransport false",
            ),
        ],
    )
    def test_one_unprotected_bucket_fails_alone(self, reads, text):
        rows = self._bucket_rows(reads)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "Bucket 'target', used by target" in rows[0]["Finding_Details"]
        assert text in rows[0]["Finding_Details"]
        assert "'clean'" not in rows[0]["Finding_Details"]

    def test_bucket_default_key_that_aws_manages_fails(self):
        rows = self._bucket_rows(
            {
                "encryption": {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "aws:kms",
                                    "KMSMasterKeyID": _AWS_KEY,
                                }
                            }
                        ]
                    }
                }
            },
            keys={_AWS_KEY: "AWS"},
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert (
            f"default encryption key {_AWS_KEY} is an AWS managed key"
            in (rows[0]["Finding_Details"])
        )

    @pytest.mark.parametrize(
        "overrides",
        [
            {"Resource": "*"},
            {"Resource": ["arn:aws:s3:::tar*"]},
            {"Resource": ["arn:aws:s3:::target", "arn:aws:s3:::target*"]},
            {"Principal": {"AWS": "*"}},
            {"Action": "*"},
            {"Condition": {"BoolIfExists": {"aws:SecureTransport": ["false"]}}},
        ],
    )
    def test_equivalent_tls_deny_passes(self, overrides):
        rows = self._bucket_rows(
            {"policy": {"Policy": _tls_policy("target", **overrides)}}
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "2 bucket(s)" in rows[0]["Finding_Details"]

    def test_second_statement_can_carry_the_deny(self):
        document = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    _tls_statement("target", Sid="Partial", Action="s3:GetObject"),
                    _tls_statement("target", Sid="Full"),
                ],
            }
        )
        rows = self._bucket_rows({"policy": {"Policy": document}})
        assert [r["Status"] for r in rows] == ["Passed"]

    @pytest.mark.parametrize(
        "reads,text",
        [
            (
                {"encryption": _make_client_error("AccessDenied")},
                "bucket target: s3:GetEncryptionConfiguration (AccessDenied)",
            ),
            (
                {"policy": _make_client_error("AccessDenied")},
                "bucket target: s3:GetBucketPolicy (AccessDenied)",
            ),
        ],
    )
    def test_unread_bucket_is_incomplete(self, reads, text):
        rows = self._bucket_rows(reads)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert text in rows[0]["Finding_Details"]
        assert "1 bucket(s)" in rows[0]["Finding_Details"]

    def test_unread_bucket_key_is_incomplete(self):
        rows = self._bucket_rows(
            {},
            keys={_CMK: _make_client_error("AccessDeniedException")},
        )
        assert [r["Status"] for r in rows] == ["N/A"]

    def test_covers_objects_needs_a_trailing_wildcard_over_the_bucket(self):
        arn = "arn:aws:s3:::target"
        assert sagemaker_app._s3_resource_covers_objects("arn:aws:s3:::target/*", arn)
        assert sagemaker_app._s3_resource_covers_objects("arn:aws:s3:::*", arn)
        assert sagemaker_app._s3_resource_covers_objects("arn:aws:s3:::t?rget/*", arn)
        assert not sagemaker_app._s3_resource_covers_objects(
            "arn:aws:s3:::target/a*", arn
        )
        assert not sagemaker_app._s3_resource_covers_objects(
            "arn:aws:s3:::other/*", arn
        )
        assert not sagemaker_app._s3_resource_covers_objects("arn:aws:s3:::target", arn)


# ===================================================================
# AIR-SGM-TRN-02: SM-03 key managers, unread legs and training buckets
# ===================================================================
def _training_job(output=_CMK, volume=_CMK, bucket="data"):
    return {
        "OutputDataConfig": {"KmsKeyId": output, "S3OutputPath": f"s3://{bucket}/out/"},
        "EnableInterContainerTrafficEncryption": True,
        "ResourceConfig": {"InstanceType": "ml.m5.large", "VolumeKmsKeyId": volume},
        "InputDataConfig": [
            {
                "ChannelName": "train",
                "DataSource": {"S3DataSource": {"S3Uri": f"s3://{bucket}/in/"}},
            }
        ],
    }


def _sm03_rows(
    jobs,
    keys=None,
    buckets=None,
    pages=None,
    notebooks=None,
    file_systems=None,
    endpoint_configs=None,
):
    """Run SM-03 over training jobs {name: DescribeTrainingJob or exception}.

    endpoint_configs maps an endpoint name to the DescribeEndpointConfig of
    its config, named cfg-<endpoint>, or to an exception.

    file_systems maps a file system id to its EFS or FSx description, or an
    exception; an id it does not name is denied.
    """
    keys = keys or {}
    buckets = buckets or {}
    notebooks = notebooks or {}
    file_systems = file_systems or {}
    endpoint_configs = endpoint_configs or {}
    file_system_calls = []

    def describe_file_system(file_system_id):
        file_system_calls.append(file_system_id)
        value = file_systems.get(
            file_system_id, _make_client_error("AccessDeniedException")
        )
        if isinstance(value, Exception):
            raise value
        return {"FileSystems": [dict(value, FileSystemId=file_system_id)]}

    def lookup(table, name):
        value = table[name]
        if isinstance(value, Exception):
            raise value
        return value

    def describe_key(KeyId):
        value = keys.get(KeyId, "CUSTOMER")
        if isinstance(value, Exception):
            raise value
        if isinstance(value, dict):
            return {"KeyMetadata": dict(value, KeyId=KeyId)}
        return {"KeyMetadata": {"KeyId": KeyId, "KeyManager": value}}

    def bucket_part(part, Bucket):
        value = buckets.get(Bucket, {}).get(part)
        if value is None:
            value = (
                _KMS_BUCKET if part == "encryption" else {"Policy": _tls_policy(Bucket)}
            )
        if isinstance(value, Exception):
            raise value
        return value

    listing = {
        "list_training_jobs": [
            {"TrainingJobSummaries": [{"TrainingJobName": n} for n in jobs]}
        ],
        "list_notebook_instances": [
            {"NotebookInstances": [{"NotebookInstanceName": n} for n in notebooks]}
        ],
        "list_domains": [{"Domains": []}],
        "list_endpoints": [
            {
                "Endpoints": [
                    {"EndpointName": n, "EndpointStatus": "InService"}
                    for n in endpoint_configs
                ]
            }
        ],
    }
    listing.update(pages or {})

    def describe_endpoint(EndpointName):
        lookup(endpoint_configs, EndpointName)
        return {
            "EndpointName": EndpointName,
            "EndpointConfigName": f"cfg-{EndpointName}",
        }

    sm = _pages_client(
        listing,
        describe_endpoint=MagicMock(side_effect=describe_endpoint),
        describe_endpoint_config=MagicMock(
            side_effect=lambda EndpointConfigName: lookup(
                endpoint_configs, EndpointConfigName[4:]
            )
        ),
        describe_training_job=MagicMock(
            side_effect=lambda TrainingJobName: lookup(jobs, TrainingJobName)
        ),
        describe_notebook_instance=MagicMock(
            side_effect=lambda NotebookInstanceName: lookup(
                notebooks, NotebookInstanceName
            )
        ),
    )
    kms = MagicMock()
    kms.describe_key.side_effect = describe_key
    s3 = MagicMock()
    s3.get_bucket_encryption.side_effect = lambda Bucket: bucket_part(
        "encryption", Bucket
    )
    s3.get_bucket_policy.side_effect = lambda Bucket: bucket_part("policy", Bucket)
    efs = MagicMock()
    efs.describe_file_systems.side_effect = lambda FileSystemId: describe_file_system(
        FileSystemId
    )
    fsx = MagicMock()
    fsx.describe_file_systems.side_effect = lambda FileSystemIds: describe_file_system(
        FileSystemIds[0]
    )
    with patch("sagemaker_app.boto3.client") as mock_client:
        mock_client.side_effect = _sm_client_factory(
            sagemaker=sm, kms=kms, s3=s3, efs=efs, fsx=fsx
        )
        rows = extract_csv_data(
            sagemaker_app.check_sagemaker_data_protection(region="us-east-1")
        )
    _sm03_rows.file_system_calls = file_system_calls
    return rows


def _plain_job(**resource_config):
    job = _training_job()
    job["EnableInterContainerTrafficEncryption"] = False
    job["ResourceConfig"].update(resource_config)
    return job


class TestSM03InterContainerAndSources:
    """AIR-SGM-TRN-02: distributed jobs only, and every input source read."""

    @pytest.mark.parametrize(
        "config",
        [
            {"InstanceCount": 1},
            {"InstanceGroups": [{"InstanceGroupName": "g", "InstanceCount": 1}]},
        ],
    )
    def test_single_instance_job_without_ice_passes(self, config):
        rows = _sm03_rows({"solo": _plain_job(**config)})
        assert not _by_finding(rows, "Missing VPC Encryption")
        assert [r["Status"] for r in _by_finding(rows, "Data Protection Check")] == [
            "Passed"
        ]

    @pytest.mark.parametrize(
        "config",
        [
            {"InstanceCount": 2},
            {
                "InstanceGroups": [
                    {"InstanceGroupName": "a", "InstanceCount": 1},
                    {"InstanceGroupName": "b", "InstanceCount": 1},
                ]
            },
            {},
        ],
    )
    def test_distributed_or_unrecorded_job_without_ice_fails(self, config):
        rows = _sm03_rows(
            {"solo": _plain_job(InstanceCount=1), "multi": _plain_job(**config)}
        )
        missing = _by_finding(rows, "Missing VPC Encryption")
        assert [r["Status"] for r in missing] == ["Failed"]
        assert "'multi'" in missing[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "source,text",
        [
            (
                {
                    "FileSystemDataSource": {
                        "FileSystemId": "fs-1",
                        "FileSystemType": "EFS",
                        "FileSystemAccessMode": "ro",
                        "DirectoryPath": "/d",
                    }
                },
                "EFS file system fs-1",
            ),
            (
                {
                    "FileSystemDataSource": {
                        "FileSystemId": "fs-2",
                        "FileSystemType": "FSxLustre",
                        "FileSystemAccessMode": "ro",
                        "DirectoryPath": "/d",
                    }
                },
                "whose encryption at rest was not read (fsx:DescribeFileSystems: "
                "AccessDeniedException)",
            ),
            (
                {"DatasetSource": {"DatasetArn": "arn:aws:x:::dataset/d"}},
                "dataset arn:aws:x:::dataset/d",
            ),
        ],
    )
    def test_non_s3_source_holds_back_passed(self, source, text):
        job = _training_job()
        job["InputDataConfig"].append({"ChannelName": "extra", "DataSource": source})
        rows = _sm03_rows({"clean": _training_job(), "fs": job})
        assert not _by_finding(rows, "Data Protection Check")
        unread = [r for r in rows if r["Finding"].endswith("Incomplete")]
        assert len(unread) == 1
        assert "training job 'fs' channel 'extra'" in unread[0]["Finding_Details"]
        assert text in unread[0]["Finding_Details"]
        assert "'clean'" not in unread[0]["Finding_Details"]


def _sm03_endpoint_config(**extra):
    config = {
        "ProductionVariants": [
            {"VariantName": "v", "ModelName": "m", "InstanceType": "ml.m5.large"}
        ],
        "KmsKeyId": _CMK,
    }
    config.update(extra)
    return config


class TestSM03EndpointConfigEncryption:
    """AIR-FND-DAT-01: SM-03 reads each endpoint config's keys."""

    @pytest.mark.parametrize(
        "bad, issue",
        [
            (_sm03_endpoint_config(KmsKeyId=None), "No KmsKeyId"),
            (
                _sm03_endpoint_config(
                    DataCaptureConfig={
                        "EnableCapture": True,
                        "DestinationS3Uri": "s3://c",
                    }
                ),
                "DataCaptureConfig.KmsKeyId is not set",
            ),
            (
                _sm03_endpoint_config(
                    AsyncInferenceConfig={"OutputConfig": {"S3OutputPath": "s3://o"}}
                ),
                "AsyncInferenceConfig.OutputConfig.KmsKeyId is not set",
            ),
        ],
    )
    @pytest.mark.parametrize("bad_first", [True, False])
    def test_one_unkeyed_endpoint_config_fails_alone(self, bad, issue, bad_first):
        configs = [
            (
                "good",
                _sm03_endpoint_config(
                    DataCaptureConfig={"EnableCapture": True, "KmsKeyId": _CMK}
                ),
            ),
            ("bad", bad),
        ]
        if bad_first:
            configs.reverse()
        rows = _sm03_rows({"job": _training_job()}, endpoint_configs=dict(configs))
        assert not _by_finding(rows, "Data Protection Check")
        missing = _by_finding(rows, "Missing Encryption Configuration")
        assert len(missing) == 1
        assert "'cfg-bad' of endpoint 'bad'" in missing[0]["Finding_Details"]
        assert issue in missing[0]["Finding_Details"]

    def test_an_aws_managed_capture_key_fails(self):
        rows = _sm03_rows(
            {"job": _training_job()},
            keys={"alias/aws/s3": "AWS"},
            endpoint_configs={
                "ep": _sm03_endpoint_config(
                    DataCaptureConfig={
                        "EnableCapture": True,
                        "KmsKeyId": "alias/aws/s3",
                    }
                )
            },
        )
        managed = _by_finding(rows, "AWS Managed Key Usage")
        assert len(managed) == 1
        assert "Endpoint Config data capture 'cfg-ep'" in managed[0]["Finding_Details"]

    def test_keyed_and_serverless_endpoint_configs_pass(self):
        serverless = {
            "ProductionVariants": [
                {
                    "VariantName": "v",
                    "ModelName": "m",
                    "ServerlessConfig": {"MemorySizeInMB": 2048, "MaxConcurrency": 1},
                }
            ],
            "DataCaptureConfig": {"EnableCapture": False},
        }
        rows = _sm03_rows(
            {"job": _training_job()},
            endpoint_configs={"keyed": _sm03_endpoint_config(), "sls": serverless},
        )
        assert [r["Status"] for r in _by_finding(rows, "Data Protection Check")] == [
            "Passed"
        ]

    def test_an_unread_endpoint_withholds_passed(self):
        rows = _sm03_rows(
            {"job": _training_job()},
            endpoint_configs={
                "keyed": _sm03_endpoint_config(),
                "broken": _make_client_error("ThrottlingException"),
            },
        )
        assert not _by_finding(rows, "Data Protection Check")
        unread = [r for r in rows if r["Finding"].endswith("Incomplete")]
        assert "endpoint 'broken'" in unread[0]["Finding_Details"]


def _file_system_job(file_system_id, system_type="EFS"):
    job = _training_job()
    job["InputDataConfig"].append(
        {
            "ChannelName": "fs",
            "DataSource": {
                "FileSystemDataSource": {
                    "FileSystemId": file_system_id,
                    "FileSystemType": system_type,
                    "FileSystemAccessMode": "ro",
                    "DirectoryPath": "/d",
                }
            },
        }
    )
    return job


class TestSM03TrainingFileSystemEncryption:
    """AIR-SGM-TRN-02: an EFS or FSx for Lustre training source is read."""

    @pytest.mark.parametrize(
        "system_type, description",
        [
            ("EFS", {"Encrypted": True, "KmsKeyId": _CMK}),
            (
                "FSxLustre",
                {
                    "KmsKeyId": _CMK,
                    "LustreConfiguration": {"DeploymentType": "PERSISTENT_2"},
                },
            ),
        ],
    )
    def test_a_file_system_under_a_customer_key_passes(self, system_type, description):
        rows = _sm03_rows(
            {"fs": _file_system_job("fs-1", system_type)},
            file_systems={"fs-1": description},
        )
        assert [r["Status"] for r in _by_finding(rows, "Data Protection Check")] == [
            "Passed"
        ]
        assert not [r for r in rows if r["Status"] in ("Failed", "N/A")]

    def test_an_unencrypted_file_system_fails_and_only_it_is_named(self):
        rows = _sm03_rows(
            {
                "good": _file_system_job("fs-good"),
                "bad": _file_system_job("fs-bad"),
                "also-bad": _file_system_job("fs-bad"),
            },
            file_systems={
                "fs-good": {"Encrypted": True, "KmsKeyId": _CMK},
                "fs-bad": {"Encrypted": False},
            },
        )
        missing = _by_finding(rows, "Missing Encryption Configuration")
        assert [r["Status"] for r in missing] == ["Failed"]
        details = missing[0]["Finding_Details"]
        assert "EFS file system 'fs-bad' - Encryption at rest is not enabled" in details
        assert "training job 'also-bad' channel 'fs'" in details
        assert "training job 'bad' channel 'fs'" in details
        assert "fs-good" not in details
        assert not _by_finding(rows, "Data Protection Check")
        assert sorted(_sm03_rows.file_system_calls) == ["fs-bad", "fs-good"]

    def test_an_aws_managed_key_on_a_file_system_fails(self):
        rows = _sm03_rows(
            {"fs": _file_system_job("fs-1")},
            keys={_AWS_KEY: "AWS"},
            file_systems={"fs-1": {"Encrypted": True, "KmsKeyId": _AWS_KEY}},
        )
        managed = _by_finding(rows, "AWS Managed Key Usage")
        assert [r["Status"] for r in managed] == ["Failed"]
        assert (
            "EFS file system 'fs-1' uses AWS managed key"
            in (managed[0]["Finding_Details"])
        )

    @pytest.mark.parametrize("deployment", ["SCRATCH_1", "SCRATCH_2"])
    def test_a_scratch_lustre_file_system_uses_the_service_key(self, deployment):
        rows = _sm03_rows(
            {"fs": _file_system_job("fs-1", "FSxLustre")},
            file_systems={
                "fs-1": {"LustreConfiguration": {"DeploymentType": deployment}}
            },
        )
        managed = _by_finding(rows, "AWS Managed Key Usage")
        assert [r["Status"] for r in managed] == ["Failed"]
        assert (
            "the Amazon FSx service key of the account"
            in (managed[0]["Finding_Details"])
        )

    @pytest.mark.parametrize(
        "system_type, value, text",
        [
            (
                "EFS",
                _make_client_error("FileSystemNotFound"),
                "(elasticfilesystem:DescribeFileSystems: FileSystemNotFound)",
            ),
            (
                "EFS",
                {"Encrypted": True},
                "(elasticfilesystem:DescribeFileSystems returned no KmsKeyId)",
            ),
            (
                "FSxLustre",
                {"LustreConfiguration": {"DeploymentType": "PERSISTENT_1"}},
                "(fsx:DescribeFileSystems returned no KmsKeyId)",
            ),
        ],
    )
    def test_an_unread_file_system_holds_back_passed(self, system_type, value, text):
        rows = _sm03_rows(
            {"clean": _training_job(), "fs": _file_system_job("fs-1", system_type)},
            file_systems={"fs-1": value},
        )
        assert not _by_finding(rows, "Data Protection Check")
        assert not [r for r in rows if r["Status"] == "Failed"]
        unread = [r for r in rows if r["Finding"].endswith("Incomplete")]
        assert len(unread) == 1
        assert text in unread[0]["Finding_Details"]
        assert "training job 'fs' channel 'fs'" in unread[0]["Finding_Details"]
        assert "'clean'" not in unread[0]["Finding_Details"]


class TestSM03KeyManagerAndUnreadLegs:
    """A key ARN's manager is read, and a failed read never yields Passed."""

    def test_clean_jobs_pass(self):
        rows = _sm03_rows({"a": _training_job(), "b": _training_job()})
        assert [r["Status"] for r in _by_finding(rows, "Data Protection Check")] == [
            "Passed"
        ]
        assert not [r for r in rows if r["Status"] in ("Failed", "N/A")]

    @pytest.mark.parametrize("leg", ["output", "volume"])
    def test_aws_managed_key_named_by_arn_fails_on_one_job(self, leg):
        # The ARN does not contain aws/sagemaker; only DescribeKey tells.
        bad = _training_job(**{leg: _AWS_KEY})
        rows = _sm03_rows({"good": _training_job(), "bad": bad}, keys={_AWS_KEY: "AWS"})
        managed = _by_finding(rows, "AWS Managed Key Usage")
        assert len(managed) == 1
        assert "'bad'" in managed[0]["Finding_Details"]
        assert _AWS_KEY in managed[0]["Finding_Details"]
        assert not _by_finding(rows, "Data Protection Check")

    def test_aws_managed_volume_key_is_not_listed_as_a_passing_volume(self):
        rows = _sm03_rows(
            {"good": _training_job(), "bad": _training_job(volume=_AWS_KEY)},
            keys={_AWS_KEY: "AWS"},
        )
        volume = _by_finding(rows, sagemaker_app.TRAINING_VOLUME_ENCRYPTION_FINDING)
        passed = [r for r in volume if r["Status"] == "Passed"]
        assert passed and all("bad" not in r["Finding_Details"] for r in passed)

    def test_unreadable_key_manager_is_incomplete_not_passed(self):
        rows = _sm03_rows(
            {"a": _training_job()},
            keys={_CMK: _make_client_error("AccessDeniedException")},
        )
        incomplete = _by_finding(rows, "SageMaker Data Protection Check Incomplete")
        assert [r["Status"] for r in incomplete] == ["N/A"]
        assert "kms:DescribeKey" in incomplete[0]["Finding_Details"]
        assert not _by_finding(rows, "Data Protection Check")
        volume = _by_finding(rows, sagemaker_app.TRAINING_VOLUME_ENCRYPTION_FINDING)
        assert not [r for r in volume if r["Status"] == "Passed"]

    def test_one_describe_error_does_not_end_the_sweep(self):
        rows = _sm03_rows(
            {
                "broken": _make_client_error("ThrottlingException"),
                "bad": _training_job(output=_AWS_KEY),
            },
            keys={_AWS_KEY: "AWS"},
        )
        incomplete = _by_finding(rows, "SageMaker Data Protection Check Incomplete")
        assert (
            "sagemaker:DescribeTrainingJob broken" in incomplete[0]["Finding_Details"]
        )
        assert (
            "'bad'" in _by_finding(rows, "AWS Managed Key Usage")[0]["Finding_Details"]
        )
        assert not _by_finding(rows, "Data Protection Check")

    @pytest.mark.parametrize(
        "operation", ["list_training_jobs", "list_notebook_instances", "list_domains"]
    )
    def test_list_error_is_incomplete_and_withholds_passed(self, operation):
        rows = _sm03_rows(
            {"a": _training_job()},
            pages={operation: _make_client_error("AccessDeniedException")},
        )
        incomplete = _by_finding(rows, "SageMaker Data Protection Check Incomplete")
        assert [r["Status"] for r in incomplete] == ["N/A"]
        assert not _by_finding(rows, "Data Protection Check")

    def test_notebook_describe_error_is_incomplete(self):
        rows = _sm03_rows(
            {"a": _training_job()},
            notebooks={"nb": _make_client_error("AccessDeniedException")},
        )
        incomplete = _by_finding(rows, "SageMaker Data Protection Check Incomplete")
        assert (
            "sagemaker:DescribeNotebookInstance nb" in incomplete[0]["Finding_Details"]
        )
        assert not _by_finding(rows, "Data Protection Check")


_PENDING_CMK = "arn:aws:kms:us-east-1:123456789012:key/3333"


class TestSM03KeyState:
    """DAT-01: a customer managed key that cannot be used protects nothing."""

    @pytest.mark.parametrize("state", ["PendingDeletion", "Disabled"])
    @pytest.mark.parametrize("leg", ["output", "volume"])
    @pytest.mark.parametrize("bad_first", [True, False])
    def test_a_key_not_enabled_fails_only_its_job(self, state, leg, bad_first):
        jobs = [
            ("good", _training_job()),
            ("bad", _training_job(**{leg: _PENDING_CMK})),
        ]
        if bad_first:
            jobs.reverse()
        rows = _sm03_rows(
            dict(jobs),
            keys={_PENDING_CMK: {"KeyManager": "CUSTOMER", "KeyState": state}},
        )
        unusable = _by_finding(rows, sagemaker_app.KEY_NOT_ENABLED_FINDING)
        assert [r["Status"] for r in unusable] == ["Failed"]
        assert "'bad'" in unusable[0]["Finding_Details"]
        assert "'good'" not in unusable[0]["Finding_Details"]
        assert _PENDING_CMK in unusable[0]["Finding_Details"]
        assert state in unusable[0]["Finding_Details"]
        assert not _by_finding(rows, "Data Protection Check")
        if leg == "volume":
            volume = _by_finding(rows, sagemaker_app.TRAINING_VOLUME_ENCRYPTION_FINDING)
            passed = [r for r in volume if r["Status"] == "Passed"]
            assert passed and all("bad" not in r["Finding_Details"] for r in passed)

    def test_an_enabled_customer_key_still_passes(self):
        rows = _sm03_rows(
            {"a": _training_job(output=_PENDING_CMK, volume=_PENDING_CMK)},
            keys={_PENDING_CMK: {"KeyManager": "CUSTOMER", "KeyState": "Enabled"}},
        )
        assert [r["Status"] for r in _by_finding(rows, "Data Protection Check")] == [
            "Passed"
        ]
        assert not _by_finding(rows, sagemaker_app.KEY_NOT_ENABLED_FINDING)

    def test_a_bucket_default_key_not_enabled_fails_the_bucket(self):
        pending_bucket = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": _PENDING_CMK,
                        }
                    }
                ]
            }
        }
        rows = _sm03_rows(
            {"a": _training_job(bucket="one"), "b": _training_job(bucket="two")},
            keys={
                _PENDING_CMK: {"KeyManager": "CUSTOMER", "KeyState": "PendingDeletion"}
            },
            buckets={"two": {"encryption": pending_bucket}},
        )
        bucket_rows = _by_finding(rows, sagemaker_app.TRAINING_BUCKET_FINDING)
        failed = [r for r in bucket_rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "Bucket 'two'" in failed[0]["Finding_Details"]
        assert "PendingDeletion" in failed[0]["Finding_Details"]
        assert "Bucket 'one'" not in failed[0]["Finding_Details"]


class TestSM03TrainingBucketProtection:
    """Training source and output buckets: SSE-KMS with a CMK and TLS-only."""

    def test_clean_buckets_pass(self):
        rows = _sm03_rows(
            {"a": _training_job(bucket="one"), "b": _training_job(bucket="two")}
        )
        bucket = _by_finding(rows, sagemaker_app.TRAINING_BUCKET_FINDING)
        assert [r["Status"] for r in bucket] == ["Passed"]

    def test_one_aes256_bucket_fails_and_withholds_aggregate(self):
        rows = _sm03_rows(
            {"a": _training_job(bucket="clean"), "b": _training_job(bucket="plain")},
            buckets={
                "plain": {
                    "encryption": {
                        "ServerSideEncryptionConfiguration": {
                            "Rules": [
                                {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "AES256"
                                    }
                                }
                            ]
                        }
                    }
                }
            },
        )
        bucket = _by_finding(rows, sagemaker_app.TRAINING_BUCKET_FINDING)
        failed = [r for r in bucket if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "plain" in failed[0]["Finding_Details"]
        assert "clean" not in failed[0]["Finding_Details"]
        assert not [r for r in bucket if r["Status"] == "Passed"]
        assert not _by_finding(rows, "Data Protection Check")

    def test_bucket_without_tls_policy_fails(self):
        rows = _sm03_rows(
            {"a": _training_job(bucket="open")},
            buckets={"open": {"policy": _make_client_error("NoSuchBucketPolicy")}},
        )
        bucket = _by_finding(rows, sagemaker_app.TRAINING_BUCKET_FINDING)
        assert [r["Status"] for r in bucket] == ["Failed"]

    def test_unreadable_bucket_is_incomplete(self):
        rows = _sm03_rows(
            {"a": _training_job(bucket="hidden")},
            buckets={"hidden": {"encryption": _make_client_error("AccessDenied")}},
        )
        bucket = _by_finding(rows, sagemaker_app.TRAINING_BUCKET_FINDING)
        assert [r["Status"] for r in bucket] == ["N/A"]
        assert not _by_finding(rows, "Data Protection Check")

    def test_input_channel_bucket_is_read_even_when_output_bucket_differs(self):
        job = _training_job(bucket="out")
        job["InputDataConfig"][0]["DataSource"]["S3DataSource"]["S3Uri"] = (
            "s3://source/in/"
        )
        rows = _sm03_rows(
            {"a": job},
            buckets={"source": {"policy": _make_client_error("NoSuchBucketPolicy")}},
        )
        failed = [
            r
            for r in _by_finding(rows, sagemaker_app.TRAINING_BUCKET_FINDING)
            if r["Status"] == "Failed"
        ]
        assert len(failed) == 1 and "source" in failed[0]["Finding_Details"]


# ===================================================================
# AIR-SGM-TRN-05: SM-01 notebook VPC placement and unread reads
# ===================================================================
def _sm01_rows(notebooks, domains=None, pages=None):
    """Run SM-01 over {name: DescribeNotebookInstance or exception}."""
    domains = domains or {}

    def lookup(table, name):
        value = table[name]
        if isinstance(value, Exception):
            raise value
        return value

    listing = {
        "list_notebook_instances": [
            {"NotebookInstances": [{"NotebookInstanceName": n} for n in notebooks]}
        ],
        "list_domains": [{"Domains": [{"DomainId": d} for d in domains]}],
    }
    listing.update(pages or {})
    sm = _pages_client(
        listing,
        describe_notebook_instance=MagicMock(
            side_effect=lambda NotebookInstanceName: lookup(
                notebooks, NotebookInstanceName
            )
        ),
        describe_domain=MagicMock(
            side_effect=lambda DomainId: lookup(domains, DomainId)
        ),
    )
    with patch("sagemaker_app.boto3.client", return_value=sm):
        return extract_csv_data(
            sagemaker_app.check_sagemaker_internet_access(region="us-east-1")
        )


_VPC_NOTEBOOK = {"DirectInternetAccess": "Disabled", "SubnetId": "subnet-1"}


class TestSM01NotebookVpcPlacement:
    """The Passed text claims VPC placement, so a notebook needs a SubnetId."""

    def test_notebook_without_subnet_fails_among_vpc_notebooks(self):
        rows = _sm01_rows(
            {
                "in-vpc": _VPC_NOTEBOOK,
                "no-vpc": {"DirectInternetAccess": "Disabled"},
            }
        )
        outside = _by_finding(rows, "Notebook Instance Outside VPC")
        assert len(outside) == 1
        assert "'no-vpc'" in outside[0]["Finding_Details"]
        assert outside[0]["Status"] == "Failed"
        assert not _by_finding(rows, "SageMaker Internet Access Check")

    def test_vpc_notebooks_and_vpc_only_domain_pass(self):
        rows = _sm01_rows(
            {"a": _VPC_NOTEBOOK, "b": _VPC_NOTEBOOK},
            domains={"d-1": {"AppNetworkAccessType": "VpcOnly"}},
        )
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "3 SageMaker notebook" in rows[0]["Finding_Details"]

    def test_describe_error_is_incomplete_and_not_passed(self):
        rows = _sm01_rows(
            {"a": _VPC_NOTEBOOK, "broken": _make_client_error("AccessDeniedException")}
        )
        incomplete = _by_finding(rows, "SageMaker Internet Access Check Incomplete")
        assert [r["Status"] for r in incomplete] == ["N/A"]
        assert "broken" in incomplete[0]["Finding_Details"]
        assert [r["Status"] for r in rows] == ["N/A"]

    @pytest.mark.parametrize("operation", ["list_notebook_instances", "list_domains"])
    def test_list_error_is_incomplete(self, operation):
        rows = _sm01_rows(
            {"a": _VPC_NOTEBOOK},
            pages={operation: _make_client_error("AccessDeniedException")},
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "Incomplete" in rows[0]["Finding"]

    def test_domain_describe_error_is_incomplete(self):
        rows = _sm01_rows(
            {"a": _VPC_NOTEBOOK},
            domains={"d-x": _make_client_error("ThrottlingException")},
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "sagemaker:DescribeDomain d-x" in rows[0]["Finding_Details"]


# ===================================================================
# AIR-SGM-TRN-05: SM-09 execution roles, API logging and Config rules
# ===================================================================
_NB_ROLE = "arn:aws:iam::123456789012:role/service-role/nb-role"
_GOOD_TRAIL = {
    "Name": "org",
    "TrailARN": "arn:aws:cloudtrail:us-east-1:999999999999:trail/org",
    "HomeRegion": "us-east-1",
    "IsMultiRegionTrail": True,
    "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:999999999999:log-group:ct:*",
}
_ALL_MANAGEMENT = {
    "EventSelectors": [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
            "DataResources": [],
            "ExcludeManagementEventSources": [],
        }
    ]
}
_NOTEBOOK_RULES = [
    {
        "ConfigRuleName": "nb-internet",
        "ConfigRuleState": "ACTIVE",
        "Source": {
            "Owner": "AWS",
            "SourceIdentifier": "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS",
        },
    },
    {
        "ConfigRuleName": "nb-kms",
        "ConfigRuleState": "ACTIVE",
        "Source": {
            "Owner": "AWS",
            "SourceIdentifier": "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED",
        },
        "InputParameters": json.dumps({"kmsKeyArns": APPROVED_KEY}),
    },
]
_LEAST_PRIVILEGE = {
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::data/*",
}


def _environment_cache(roles):
    """A v2 IAM cache from {role: [(policy name, arn, statements)]}."""
    return {
        "cache_schema_version": 2,
        "principal_errors": [],
        "role_permissions": {
            name: {
                "attached_policies": [
                    {
                        "name": policy,
                        "arn": arn,
                        "document": {"Version": "2012-10-17", "Statement": stmts},
                    }
                    for policy, arn, stmts in policies
                ],
                "inline_policies": [],
            }
            for name, policies in roles.items()
        },
        "user_permissions": {},
    }


_CLEAN_CACHE = _environment_cache(
    {
        "nb-role": [
            ("scoped", "arn:aws:iam::123456789012:policy/scoped", [_LEAST_PRIVILEGE])
        ]
    }
)


_DELIVERING_STATUS = {
    "IsLogging": True,
    "LatestCloudWatchLogsDeliveryTime": datetime(2026, 1, 1, tzinfo=timezone.utc),
}


def _sm09_rows(
    notebooks=None,
    domains=None,
    profiles=None,
    cache=_CLEAN_CACHE,
    trails=None,
    statuses=None,
    selectors=None,
    rules=None,
    sm_pages=None,
    trail_error=None,
    rules_error=None,
):
    """Run SM-09 regionally; tables map names to responses or exceptions."""
    notebooks = (
        {"nb": {"RootAccess": "Disabled", "RoleArn": _NB_ROLE}}
        if notebooks is None
        else notebooks
    )
    domains = domains or {}
    profiles = profiles or {}
    statuses = statuses or {}
    selectors = selectors or {}

    def lookup(table, name, default=None):
        value = table.get(name, default)
        if isinstance(value, Exception):
            raise value
        return value

    listing = {
        "list_notebook_instances": [
            {"NotebookInstances": [{"NotebookInstanceName": n} for n in notebooks]}
        ],
        "list_domains": [{"Domains": [{"DomainId": d} for d in domains]}],
    }
    listing.update(sm_pages or {})
    sm = _pages_client(
        listing,
        describe_notebook_instance=MagicMock(
            side_effect=lambda NotebookInstanceName: lookup(
                notebooks, NotebookInstanceName
            )
        ),
        describe_domain=MagicMock(
            side_effect=lambda DomainId: lookup(domains, DomainId)
        ),
        describe_user_profile=MagicMock(
            side_effect=lambda DomainId, UserProfileName: lookup(
                profiles, f"{DomainId}/{UserProfileName}"
            )
        ),
    )
    base_get_paginator = sm.get_paginator.side_effect

    def get_paginator(operation_name):
        if operation_name != "list_user_profiles":
            return base_get_paginator(operation_name)
        paginator = MagicMock()

        def paginate(DomainIdEquals):
            value = profiles.get(f"{DomainIdEquals}/*")
            if isinstance(value, Exception):
                raise value
            return [
                {
                    "UserProfiles": [
                        {"UserProfileName": key.split("/", 1)[1]}
                        for key in profiles
                        if key.startswith(f"{DomainIdEquals}/")
                        and not key.endswith("/*")
                    ]
                }
            ]

        paginator.paginate.side_effect = paginate
        return paginator

    sm.get_paginator.side_effect = get_paginator
    cloudtrail = MagicMock()
    if trail_error is not None:
        cloudtrail.describe_trails.side_effect = trail_error
    else:
        cloudtrail.describe_trails.return_value = {
            "trailList": [_GOOD_TRAIL] if trails is None else trails
        }
    cloudtrail.get_trail_status.side_effect = lambda Name: lookup(
        statuses, Name, _DELIVERING_STATUS
    )
    cloudtrail.get_event_selectors.side_effect = lambda TrailName: lookup(
        selectors, TrailName, _ALL_MANAGEMENT
    )
    config = _pages_client(
        {
            "describe_config_rules": rules_error
            or [{"ConfigRules": _NOTEBOOK_RULES if rules is None else rules}]
        }
    )
    with patch("sagemaker_app.boto3.client") as mock_client:
        mock_client.side_effect = _sm_client_factory(
            sagemaker=sm, cloudtrail=cloudtrail, config=config
        )
        return extract_csv_data(
            sagemaker_app.check_sagemaker_notebook_root_access(
                region="us-east-1", permission_cache=cache
            )
        )


def _statuses_of(rows, name):
    return [r["Status"] for r in _by_finding(rows, name)]


class TestSM09RootAccessUnreadLegs:
    def test_clean_environment_passes_every_leg(self):
        rows = _sm09_rows()
        assert {r["Status"] for r in rows} == {"Passed"}
        assert len(rows) == 4

    def test_one_unreadable_notebook_withholds_root_passed(self):
        rows = _sm09_rows(
            notebooks={
                "nb": {"RootAccess": "Disabled", "RoleArn": _NB_ROLE},
                "hidden": _make_client_error("AccessDeniedException"),
            }
        )
        assert _statuses_of(rows, "SageMaker Notebook Root Access Check") == ["N/A"]
        assert (
            "hidden"
            in _by_finding(rows, "SageMaker Notebook Root Access Check")[0][
                "Finding_Details"
            ]
        )

    def test_root_enabled_with_unread_names_both(self):
        rows = _sm09_rows(
            notebooks={
                "open": {"RootAccess": "Enabled", "RoleArn": _NB_ROLE},
                "hidden": _make_client_error("ThrottlingException"),
            }
        )
        assert _statuses_of(rows, "SageMaker Notebook Root Access Enabled") == [
            "Failed"
        ]
        assert _statuses_of(rows, "SageMaker Notebook Root Access Check") == ["N/A"]

    def test_list_error_is_could_not_assess(self):
        rows = _sm09_rows(
            sm_pages={
                "list_notebook_instances": _make_client_error("AccessDeniedException")
            }
        )
        assert len(rows) == 1
        assert_could_not_assess_finding(rows[0])

    def test_no_environments_skips_monitoring_legs(self):
        rows = _sm09_rows(notebooks={})
        assert [r["Finding"] for r in rows] == ["SageMaker Notebook Root Access Check"]


class TestSM09ExecutionRolePrivilege:
    ROLE = sagemaker_app.NOTEBOOK_ROLE_PRIVILEGE_FINDING

    @pytest.mark.parametrize(
        "policy,arn,statements",
        [
            (
                "AmazonSageMakerFullAccess",
                "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
                [],
            ),
            (
                "AdministratorAccess",
                "arn:aws:iam::aws:policy/AdministratorAccess",
                [],
            ),
            (
                "custom",
                "arn:aws:iam::123456789012:policy/custom",
                [{"Effect": "Allow", "Action": "sagemaker:*", "Resource": "*"}],
            ),
            (
                "custom",
                "arn:aws:iam::123456789012:policy/custom",
                [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            ),
            # AIR-SGM-TRN-05: partial wildcards on every resource passed before.
            (
                "custom",
                "arn:aws:iam::123456789012:policy/custom",
                [
                    {
                        "Effect": "Allow",
                        "Action": ["sagemaker:Create*", "sagemaker:Delete*"],
                        "Resource": "*",
                    }
                ],
            ),
            (
                "custom",
                "arn:aws:iam::123456789012:policy/custom",
                [
                    {
                        "Effect": "Allow",
                        "Action": "sagemaker:*Endpoint*",
                        "Resource": "arn:aws:sagemaker:*:*:*",
                    }
                ],
            ),
            (
                "custom",
                "arn:aws:iam::123456789012:policy/custom",
                [
                    {
                        "Effect": "Allow",
                        "Action": "sagemaker:Update?otebookInstance",
                        "NotResource": "arn:aws:sagemaker:*:*:domain/*",
                    }
                ],
            ),
        ],
    )
    def test_broad_grant_on_one_of_two_notebook_roles_fails(
        self, policy, arn, statements
    ):
        cache = _environment_cache(
            {
                "nb-role": [("scoped", "arn:aws:iam::1:policy/s", [_LEAST_PRIVILEGE])],
                "wide-role": [(policy, arn, statements)],
            }
        )
        rows = _sm09_rows(
            notebooks={
                "good": {"RootAccess": "Disabled", "RoleArn": _NB_ROLE},
                "bad": {
                    "RootAccess": "Disabled",
                    "RoleArn": "arn:aws:iam::123456789012:role/wide-role",
                },
            },
            cache=cache,
        )
        role_rows = _by_finding(rows, self.ROLE)
        assert [r["Status"] for r in role_rows] == ["Failed"]
        assert "'bad'" in role_rows[0]["Finding_Details"]
        assert "wide-role" in role_rows[0]["Finding_Details"]

    def test_a_partial_wildcard_on_named_resources_is_not_broad(self):
        statement = {
            "Effect": "Allow",
            "Action": "sagemaker:Describe*",
            "Resource": "arn:aws:sagemaker:*:123456789012:notebook-instance/team-a-*",
        }
        literal = {
            "Effect": "Allow",
            "Action": "sagemaker:DescribeNotebookInstance",
            "Resource": "*",
        }
        for document in (statement, literal):
            permissions = {
                "attached_policies": [
                    {
                        "name": "p",
                        "arn": "arn:aws:iam::123456789012:policy/p",
                        "document": {"Statement": [document]},
                    }
                ]
            }
            assert sagemaker_app._broad_role_grant(permissions) is None

    def test_boundary_that_caps_sagemaker_passes(self):
        cache = _environment_cache(
            {
                "nb-role": [
                    (
                        "AmazonSageMakerFullAccess",
                        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
                        [],
                    )
                ]
            }
        )
        cache["role_permissions"]["nb-role"]["permissions_boundary"] = {
            "Version": "2012-10-17",
            "Statement": [_LEAST_PRIVILEGE],
        }
        rows = _sm09_rows(cache=cache)
        assert _statuses_of(rows, self.ROLE) == ["Passed"]

    def test_studio_profile_override_is_read(self):
        # The domain default role is clean; the profile's own role is not.
        cache = _environment_cache(
            {
                "nb-role": [("scoped", "arn:aws:iam::1:policy/s", [_LEAST_PRIVILEGE])],
                "wide-role": [
                    (
                        "AmazonSageMakerFullAccess",
                        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
                        [],
                    )
                ],
            }
        )
        rows = _sm09_rows(
            notebooks={},
            domains={"d-1": {"DefaultUserSettings": {"ExecutionRole": _NB_ROLE}}},
            profiles={
                "d-1/alice": {
                    "UserSettings": {
                        "ExecutionRole": "arn:aws:iam::123456789012:role/wide-role"
                    }
                }
            },
            cache=cache,
        )
        role_rows = _by_finding(rows, self.ROLE)
        assert [r["Status"] for r in role_rows] == ["Failed"]
        assert "d-1/alice" in role_rows[0]["Finding_Details"]

    WIDE_ROLE = "arn:aws:iam::123456789012:role/wide-role"

    def _space_cache(self):
        return _environment_cache(
            {
                "nb-role": [("scoped", "arn:aws:iam::1:policy/s", [_LEAST_PRIVILEGE])],
                "wide-role": [
                    (
                        "AmazonSageMakerFullAccess",
                        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
                        [],
                    )
                ],
            }
        )

    @pytest.mark.parametrize("wide", ["user", "space"])
    def test_domain_default_space_role_is_read(self, wide):
        user_role = self.WIDE_ROLE if wide == "user" else _NB_ROLE
        space_role = self.WIDE_ROLE if wide == "space" else _NB_ROLE
        rows = _sm09_rows(
            notebooks={},
            domains={
                "d-1": {
                    "DefaultUserSettings": {"ExecutionRole": user_role},
                    "DefaultSpaceSettings": {"ExecutionRole": space_role},
                }
            },
            cache=self._space_cache(),
        )
        role_rows = _by_finding(rows, self.ROLE)
        assert [r["Status"] for r in role_rows] == ["Failed"]
        details = role_rows[0]["Finding_Details"]
        assert ("default space" in details) == (wide == "space")

    def test_clean_default_space_role_passes(self):
        rows = _sm09_rows(
            notebooks={},
            domains={
                "d-1": {
                    "DefaultUserSettings": {"ExecutionRole": _NB_ROLE},
                    "DefaultSpaceSettings": {"ExecutionRole": _NB_ROLE},
                }
            },
            cache=self._space_cache(),
        )
        assert _statuses_of(rows, self.ROLE) == ["Passed"]

    def test_role_missing_from_cache_is_incomplete(self):
        rows = _sm09_rows(cache=_environment_cache({}))
        assert _statuses_of(rows, self.ROLE) == ["N/A"]

    def test_no_cache_is_incomplete(self):
        rows = _sm09_rows(cache=None)
        assert _statuses_of(rows, self.ROLE) == ["N/A"]

    @pytest.mark.parametrize(
        "domains,profiles,text",
        [
            (
                {"d-1": _make_client_error("AccessDeniedException")},
                {},
                "sagemaker:DescribeDomain d-1",
            ),
            (
                {"d-1": {"DefaultUserSettings": {"ExecutionRole": _NB_ROLE}}},
                {"d-1/*": _make_client_error("AccessDeniedException")},
                "sagemaker:ListUserProfiles d-1",
            ),
            (
                {"d-1": {"DefaultUserSettings": {"ExecutionRole": _NB_ROLE}}},
                {"d-1/bob": _make_client_error("ThrottlingException")},
                "sagemaker:DescribeUserProfile d-1/bob",
            ),
        ],
    )
    def test_studio_read_error_withholds_role_passed(self, domains, profiles, text):
        rows = _sm09_rows(domains=domains, profiles=profiles)
        role_rows = _by_finding(rows, self.ROLE)
        assert [r["Status"] for r in role_rows] == ["N/A"]
        assert text in role_rows[0]["Finding_Details"]


class TestSM09ApiLogging:
    TRAIL = sagemaker_app.NOTEBOOK_TRAIL_FINDING

    @pytest.mark.parametrize(
        "change,status",
        [
            ({"CloudWatchLogsLogGroupArn": None}, "Failed"),
            ({"IsMultiRegionTrail": False, "HomeRegion": "eu-west-1"}, "Failed"),
            ({"IsMultiRegionTrail": False, "HomeRegion": "us-east-1"}, "Passed"),
        ],
    )
    def test_trail_shape(self, change, status):
        rows = _sm09_rows(trails=[{**_GOOD_TRAIL, **change}])
        assert _statuses_of(rows, self.TRAIL) == [status]

    @pytest.mark.parametrize(
        "status,text",
        [
            (
                dict(
                    _DELIVERING_STATUS,
                    LatestCloudWatchLogsDeliveryError="AccessDeniedException",
                ),
                "CloudWatch Logs delivery error AccessDeniedException",
            ),
            ({"IsLogging": True}, "no recorded CloudWatch Logs delivery"),
        ],
    )
    def test_a_trail_that_does_not_deliver_to_cloudwatch_logs_fails(self, status, text):
        # AIR-SGM-TRN-05: these logged and passed before, whatever delivery said.
        rows = _sm09_rows(statuses={_GOOD_TRAIL["TrailARN"]: status})
        assert _statuses_of(rows, self.TRAIL) == ["Failed"]
        assert text in _by_finding(rows, self.TRAIL)[0]["Finding_Details"]

    def test_stopped_trail_fails(self):
        rows = _sm09_rows(statuses={_GOOD_TRAIL["TrailARN"]: {"IsLogging": False}})
        assert _statuses_of(rows, self.TRAIL) == ["Failed"]
        assert "not logging" in _by_finding(rows, self.TRAIL)[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "selector",
        [
            {
                "EventSelectors": [
                    {"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}
                ]
            },
            {
                "EventSelectors": [
                    {"ReadWriteType": "All", "IncludeManagementEvents": False}
                ]
            },
            {
                "AdvancedEventSelectors": [
                    {
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Management"]},
                            {
                                "Field": "eventSource",
                                "NotEquals": ["sagemaker.amazonaws.com"],
                            },
                        ]
                    }
                ]
            },
            {
                "AdvancedEventSelectors": [
                    {
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Management"]},
                            {"Field": "readOnly", "Equals": ["false"]},
                        ]
                    }
                ]
            },
        ],
    )
    def test_selectors_that_miss_sagemaker_calls_fail(self, selector):
        rows = _sm09_rows(selectors={_GOOD_TRAIL["TrailARN"]: selector})
        assert _statuses_of(rows, self.TRAIL) == ["Failed"]

    @pytest.mark.parametrize(
        "selector",
        [
            {
                "EventSelectors": [
                    {"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True},
                    {"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True},
                ]
            },
            {
                "AdvancedEventSelectors": [
                    {
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Management"]}
                        ]
                    }
                ]
            },
        ],
    )
    def test_selectors_that_record_both_pass(self, selector):
        rows = _sm09_rows(selectors={_GOOD_TRAIL["TrailARN"]: selector})
        assert _statuses_of(rows, self.TRAIL) == ["Passed"]

    def test_one_good_trail_among_bad_passes(self):
        bad = {**_GOOD_TRAIL, "Name": "bad", "TrailARN": "arn:bad"}
        rows = _sm09_rows(
            trails=[bad, _GOOD_TRAIL], statuses={"arn:bad": {"IsLogging": False}}
        )
        assert _statuses_of(rows, self.TRAIL) == ["Passed"]

    def test_describe_trails_error_is_incomplete(self):
        rows = _sm09_rows(trail_error=_make_client_error("AccessDeniedException"))
        assert _statuses_of(rows, self.TRAIL) == ["N/A"]

    def test_unreadable_trail_status_is_incomplete_not_passed(self):
        rows = _sm09_rows(
            statuses={_GOOD_TRAIL["TrailARN"]: _make_client_error("AccessDenied")}
        )
        assert _statuses_of(rows, self.TRAIL) == ["N/A"]


class TestSM09NotebookConfigRules:
    RULES = sagemaker_app.NOTEBOOK_CONFIG_RULES_FINDING

    def _with(self, index, **change):
        rules = [dict(rule) for rule in _NOTEBOOK_RULES]
        rules[index].update(change)
        return rules

    @pytest.mark.parametrize(
        "index,change,text",
        [
            (1, {"InputParameters": "{}"}, "no kmsKeyArns"),
            (1, {"InputParameters": json.dumps({"kmsKeyArns": " "})}, "no kmsKeyArns"),
            (0, {"ConfigRuleState": "DELETING"}, "no ACTIVE rule"),
            (0, {"Scope": {"ComplianceResourceId": "nb"}}, "scoped"),
            (1, {"Scope": {"TagKey": "env"}}, "scoped"),
            (0, {"Source": {"Owner": "CUSTOM_LAMBDA"}}, "no ACTIVE rule"),
        ],
    )
    def test_missing_or_narrowed_rule_fails(self, index, change, text):
        rows = _sm09_rows(rules=self._with(index, **change))
        config_rows = _by_finding(rows, self.RULES)
        assert [r["Status"] for r in config_rows] == ["Failed"]
        assert text in config_rows[0]["Finding_Details"]

    def test_both_rules_pass(self):
        rows = _sm09_rows()
        assert _statuses_of(rows, self.RULES) == ["Passed"]

    def test_second_unpinned_copy_does_not_hide_a_pinned_one(self):
        unpinned = dict(_NOTEBOOK_RULES[1], ConfigRuleName="nb-kms-any")
        unpinned["InputParameters"] = "{}"
        rows = _sm09_rows(rules=[unpinned] + _NOTEBOOK_RULES)
        assert _statuses_of(rows, self.RULES) == ["Passed"]

    def test_describe_error_is_incomplete(self):
        rows = _sm09_rows(rules_error=_make_client_error("AccessDeniedException"))
        assert _statuses_of(rows, self.RULES) == ["N/A"]


# ===================================================================
# AIR-SGM-TRN-05: SM-09 notebook creation and presigned-URL guardrails
# ===================================================================
SCP_NOTEBOOK_ACCESS_DENIES = [
    _scp_deny(
        "sagemaker:CreateNotebookInstance",
        "StringNotEquals",
        "sagemaker:RootAccess",
        "Disabled",
    ),
    _scp_deny(
        "sagemaker:CreateNotebookInstance",
        "StringNotEquals",
        "sagemaker:DirectInternetAccess",
        "Disabled",
    ),
    _scp_deny(
        "sagemaker:CreateNotebookInstance",
        "ForAnyValue:StringNotEquals",
        "sagemaker:VpcSubnets",
        ["subnet-1"],
    ),
    _scp_deny(
        "sagemaker:CreateNotebookInstance", "Null", "sagemaker:VpcSubnets", "true"
    ),
    _scp_deny(
        "sagemaker:CreateNotebookInstance",
        "ArnNotEquals",
        "sagemaker:VolumeKmsKeyArn",
        [APPROVED_KEY],
    ),
    _scp_deny(
        [
            "sagemaker:CreatePresignedNotebookInstanceUrl",
            "sagemaker:CreatePresignedDomainUrl",
        ],
        "NotIpAddress",
        "aws:SourceIp",
        ["203.0.113.0/24"],
    ),
]


class TestSM09NotebookAccessGuardrails:
    def _run(self, statements, cache=OPEN_CACHE):
        inventory = TestSM34CreationGuardrails._inventory(
            ("NotebookBar", {"Version": "2012-10-17", "Statement": statements})
        )
        with patch(
            "sagemaker_app.boto3.client",
            side_effect=TestSM34CreationGuardrails._member_account_clients(),
        ):
            return extract_csv_data(
                sagemaker_app.check_sagemaker_notebook_access_guardrails(
                    region="Global", scp_inventory=inventory, permission_cache=cache
                )
            )

    def test_attached_scp_holding_all_six_passes(self):
        rows = self._run(SCP_NOTEBOOK_ACCESS_DENIES)
        assert [r["Status"] for r in rows] == ["Passed"]
        assert "All 6 notebook access requirements" in rows[0]["Finding_Details"]
        assert rows[0]["Check_ID"] == "SM-09"

    @pytest.mark.parametrize("dropped", range(6))
    def test_each_missing_deny_fails_with_an_open_principal(self, dropped):
        statements = [
            s for i, s in enumerate(SCP_NOTEBOOK_ACCESS_DENIES) if i != dropped
        ]
        rows = self._run(statements)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "Role 'Admin'" in rows[0]["Finding_Details"]

    def test_presigned_ip_deny_alongside_another_condition_is_incomplete(self):
        conjunctive = dict(SCP_NOTEBOOK_ACCESS_DENIES[-1])
        conjunctive["Condition"] = {
            "NotIpAddress": {"aws:SourceIp": ["203.0.113.0/24"]},
            "Bool": {"aws:ViaAWSService": "false"},
        }
        rows = self._run(SCP_NOTEBOOK_ACCESS_DENIES[:-1] + [conjunctive])
        assert [r["Status"] for r in rows] == ["N/A"]

    @staticmethod
    def _ip_deny(ranges):
        return _scp_deny(
            [
                "sagemaker:CreatePresignedNotebookInstanceUrl",
                "sagemaker:CreatePresignedDomainUrl",
            ],
            "NotIpAddress",
            "aws:SourceIp",
            ranges,
        )

    @pytest.mark.parametrize(
        "ranges",
        [
            ["0.0.0.0/0"],
            ["203.0.113.0/24", "0.0.0.0/0"],
            ["0.0.0.0/1", "128.0.0.0/1"],
            ["203.0.113.0/24", "::/0"],
        ],
    )
    def test_an_ip_deny_that_admits_every_address_does_not_hold(self, ranges):
        rows = self._run(SCP_NOTEBOOK_ACCESS_DENIES[:-1] + [self._ip_deny(ranges)])
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "Role 'Admin'" in rows[0]["Finding_Details"]

    def test_an_ip_deny_on_bounded_v4_and_v6_ranges_holds(self):
        deny = self._ip_deny(["203.0.113.0/24", "2001:db8::/32"])
        rows = self._run(SCP_NOTEBOOK_ACCESS_DENIES[:-1] + [deny])
        assert [r["Status"] for r in rows] == ["Passed"]

    @pytest.mark.parametrize(
        ("ranges", "expected"),
        [
            ("0.0.0.0/0", "Failed"),
            (["::/0", "203.0.113.0/24"], "Failed"),
            ("203.0.113.0/24", "root only"),
        ],
    )
    def test_an_ip_allow_is_judged_on_its_ranges(self, ranges, expected):
        cache = _creation_cache(
            {
                "DataScientist": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "sagemaker:CreatePresignedNotebookInstanceUrl",
                            "sagemaker:CreatePresignedDomainUrl",
                        ],
                        "Resource": "*",
                        "Condition": {"IpAddress": {"aws:SourceIp": ranges}},
                    }
                ]
            }
        )
        rows = self._run(SCP_NOTEBOOK_ACCESS_DENIES[:-1], cache=cache)
        if expected == "root only":
            _assert_open_only_to_root(rows[0])
        else:
            assert [r["Status"] for r in rows] == [expected]
            assert "Role 'DataScientist'" in rows[0]["Finding_Details"]

    def test_source_vpce_deny_on_profile_arns_passes(self):
        vpce = _scp_deny(
            [
                "sagemaker:CreatePresignedNotebookInstanceUrl",
                "sagemaker:CreatePresignedDomainUrl",
            ],
            "StringNotEquals",
            "aws:SourceVpce",
            ["vpce-1"],
            resource=[
                "arn:aws:sagemaker:*:*:notebook-instance/*",
                "arn:aws:sagemaker:*:*:user-profile/*/*",
            ],
        )
        rows = self._run(SCP_NOTEBOOK_ACCESS_DENIES[:-1] + [vpce])
        assert [r["Status"] for r in rows] == ["Passed"]

    def test_root_access_deny_for_enabled_only_fails_open(self):
        # StringEquals Enabled does not fire when the request omits the key.
        weak = _scp_deny(
            "sagemaker:CreateNotebookInstance",
            "StringEquals",
            "sagemaker:RootAccess",
            "Enabled",
        )
        rows = self._run([weak] + SCP_NOTEBOOK_ACCESS_DENIES[1:])
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_identity_conditions_alone_leave_the_root_user_open(self):
        cache = _creation_cache(
            {
                "DataScientist": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "sagemaker:CreatePresignedNotebookInstanceUrl",
                            "sagemaker:CreatePresignedDomainUrl",
                        ],
                        "Resource": "*",
                        "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
                    },
                    {
                        "Effect": "Allow",
                        "Action": "sagemaker:CreateNotebookInstance",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "sagemaker:RootAccess": "Disabled",
                                "sagemaker:DirectInternetAccess": "Disabled",
                            },
                            "ArnEquals": {"sagemaker:VolumeKmsKeyArn": APPROVED_KEY},
                            "ForAllValues:StringEquals": {
                                "sagemaker:VpcSubnets": ["subnet-1"]
                            },
                            "Null": {"sagemaker:VpcSubnets": "false"},
                        },
                    },
                ]
            }
        )
        rows = self._run([], cache=cache)
        assert len(rows) == 1
        _assert_open_only_to_root(rows[0])

    def test_scp_unread_and_no_cache_is_na(self):
        inventory = {"items": [], "errors": [], "list_error": "AccessDenied"}
        with patch(
            "sagemaker_app.boto3.client",
            side_effect=TestSM34CreationGuardrails._member_account_clients(),
        ):
            rows = extract_csv_data(
                sagemaker_app.check_sagemaker_notebook_access_guardrails(
                    region="Global", scp_inventory=inventory, permission_cache=None
                )
            )
        assert [r["Status"] for r in rows] == ["N/A"]


# ===================================================================
# AIR-SGM-GOV-10: SM-32 recorder status, required rules, conformance pack
# ===================================================================
_SM32_RECORDER = {"name": "default", "recordingGroup": {"allSupported": True}}


def _sm32_rows(
    recorders=(_SM32_RECORDER,),
    rules=None,
    compliance=None,
    **kwargs,
):
    rules = _SM32_REQUIRED_RULES if rules is None else rules
    if compliance is None:
        compliance = [
            {
                "ConfigRuleName": rule["ConfigRuleName"],
                "Compliance": {"ComplianceType": "COMPLIANT"},
            }
            for rule in rules
        ]
    kwargs.setdefault("packs", [_SM32_ORG_PACK])
    kwargs.setdefault("pack_rules", {"org-sagemaker": _SM32_REQUIRED_RULE_NAMES})
    extra = kwargs.pop("configure", None)
    with patch("sagemaker_app.boto3.client") as mock_client:
        config_client = TestSM32ConfigComplianceEvaluation._config(
            mock_client, list(recorders), rules, compliance, **kwargs
        )
        if extra:
            extra(config_client)
        return extract_csv_data(
            sagemaker_app.check_sagemaker_config_compliance_evaluation(
                region="us-east-1"
            )
        )


class TestSM32RecorderStatus:
    RECORDING = sagemaker_app.CONFIG_RECORDING_FINDING

    def test_clean_environment_passes_every_row(self):
        rows = _sm32_rows()
        assert {r["Status"] for r in rows} == {"Passed"}
        assert len(rows) == 4

    def test_one_stopped_recorder_of_two_fails_only_that_one(self):
        second = {"name": "second", "recordingGroup": {"allSupported": True}}
        rows = _sm32_rows(
            recorders=[_SM32_RECORDER, second],
            statuses=[
                {"name": "default", "recording": True},
                {"name": "second", "recording": False},
            ],
        )
        recording = _by_finding(rows, self.RECORDING)
        assert [r["Status"] for r in recording] == ["Passed", "Failed"]
        assert "'second'" in recording[1]["Finding_Details"]
        assert "stopped" in recording[1]["Finding_Details"]

    def test_failed_last_status_fails(self):
        rows = _sm32_rows(
            statuses=[
                {
                    "name": "default",
                    "recording": True,
                    "lastStatus": "Failure",
                    "lastErrorCode": "AccessDenied",
                }
            ]
        )
        recording = _by_finding(rows, self.RECORDING)
        assert [r["Status"] for r in recording] == ["Failed"]
        assert "AccessDenied" in recording[0]["Finding_Details"]

    def test_status_read_error_withholds_passed(self):
        def configure(client):
            client.describe_configuration_recorder_status.side_effect = (
                _make_client_error("AccessDeniedException")
            )

        rows = _sm32_rows(configure=configure)
        recording = _by_finding(rows, self.RECORDING)
        assert [r["Status"] for r in recording] == ["N/A"]
        assert "AccessDeniedException" in recording[0]["Finding_Details"]

    def test_status_missing_for_the_recorder_is_na(self):
        rows = _sm32_rows(statuses=[{"name": "other", "recording": True}])
        assert [r["Status"] for r in _by_finding(rows, self.RECORDING)] == ["N/A"]

    def test_no_recorder_of_any_kind_fails(self):
        rows = _sm32_rows(recorders=[])
        recording = _by_finding(rows, self.RECORDING)
        assert [r["Status"] for r in recording] == ["Failed"]
        assert "0 service-linked" in recording[0]["Finding_Details"]

    def test_list_recorders_error_is_na(self):
        rows = _sm32_rows(
            recorders=[],
            configure=lambda client: setattr(
                client.get_paginator("list_configuration_recorders").paginate,
                "side_effect",
                _make_client_error("AccessDeniedException"),
            ),
        )
        recording = _by_finding(rows, self.RECORDING)
        assert [r["Status"] for r in recording] == ["N/A"]
        assert "ListConfigurationRecorders" in recording[0]["Finding_Details"]


class TestSM32RequiredRules:
    REQUIRED = sagemaker_app.REQUIRED_CONFIG_RULES_FINDING

    def _rules(self, index=None, **change):
        rules = [dict(rule) for rule in _SM32_REQUIRED_RULES]
        if index is not None:
            rules[index].update(change)
        return rules

    def _status(self, rules):
        return [
            r["Status"] for r in _by_finding(_sm32_rows(rules=rules), self.REQUIRED)
        ]

    def test_all_three_pass(self):
        assert self._status(self._rules()) == ["Passed"]

    @pytest.mark.parametrize("dropped", range(3))
    def test_each_missing_rule_fails(self, dropped):
        rules = [r for i, r in enumerate(self._rules()) if i != dropped]
        rows = _by_finding(_sm32_rows(rules=rules), self.REQUIRED)
        assert [r["Status"] for r in rows] == ["Failed"]
        identifier = _SM32_REQUIRED_RULES[dropped]["Source"]["SourceIdentifier"]
        assert f"{identifier}: no ACTIVE rule" in rows[0]["Finding_Details"]

    def test_endpoint_rule_without_kms_key_arns_fails(self):
        assert self._status(self._rules(0, InputParameters="{}")) == ["Failed"]

    def test_unpinned_copy_does_not_hide_a_pinned_one(self):
        rules = self._rules()
        unpinned = dict(
            rules[0], ConfigRuleName="sm-endpoint-any", InputParameters="{}"
        )
        assert self._status([unpinned] + rules) == ["Passed"]

    def test_scoped_rule_fails(self):
        rules = self._rules(2, Scope={"ComplianceResourceId": "nb-1"})
        assert self._status(rules) == ["Failed"]

    def test_inactive_rule_fails(self):
        assert self._status(self._rules(1, ConfigRuleState="EVALUATING")) == ["Failed"]


class TestSM32ConformancePack:
    PACK = sagemaker_app.CONFORMANCE_PACK_FINDING

    def _rows(self, packs, pack_rules, **kwargs):
        return _by_finding(
            _sm32_rows(packs=packs, pack_rules=pack_rules, **kwargs), self.PACK
        )

    def test_organization_pack_with_all_three_passes(self):
        rows = self._rows(
            [_SM32_ORG_PACK], {"org-sagemaker": _SM32_REQUIRED_RULE_NAMES}
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    def test_account_pack_with_all_three_fails(self):
        rows = self._rows(
            [{"ConformancePackName": "local"}], {"local": _SM32_REQUIRED_RULE_NAMES}
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "this account only" in rows[0]["Finding_Details"]

    def test_organization_pack_missing_a_rule_fails(self):
        rows = self._rows(
            [_SM32_ORG_PACK], {"org-sagemaker": _SM32_REQUIRED_RULE_NAMES[1:]}
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert (
            "lacks SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED"
            in rows[0]["Finding_Details"]
        )

    def test_good_pack_after_a_bad_pack_passes(self):
        bad = {**_SM32_ORG_PACK, "ConformancePackName": "partial"}
        rows = self._rows(
            [bad, _SM32_ORG_PACK],
            {"partial": [], "org-sagemaker": _SM32_REQUIRED_RULE_NAMES},
        )
        assert [r["Status"] for r in rows] == ["Passed"]

    def test_no_pack_fails(self):
        rows = self._rows([], {})
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "no conformance pack is deployed" in rows[0]["Finding_Details"]

    def test_pack_list_error_is_na(self):
        rows = self._rows(
            [],
            {},
            configure=lambda client: setattr(
                client.get_paginator("describe_conformance_packs").paginate,
                "side_effect",
                _make_client_error("AccessDeniedException"),
            ),
        )
        assert [r["Status"] for r in rows] == ["N/A"]

    def test_unreadable_pack_with_no_good_pack_is_na(self):
        rows = self._rows(
            [_SM32_ORG_PACK],
            {"org-sagemaker": _make_client_error("AccessDeniedException")},
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "org-sagemaker" in rows[0]["Finding_Details"]

    def test_unreadable_pack_beside_a_good_one_passes(self):
        other = {**_SM32_ORG_PACK, "ConformancePackName": "hidden"}
        rows = self._rows(
            [other, _SM32_ORG_PACK],
            {
                "hidden": _make_client_error("AccessDeniedException"),
                "org-sagemaker": _SM32_REQUIRED_RULE_NAMES,
            },
        )
        assert [r["Status"] for r in rows] == ["Passed"]


class TestSM32UnevaluatedRules:
    RULES = sagemaker_app.CONFIG_RULE_COMPLIANCE_FINDING

    def _compliance(self, *types):
        return [
            {"ConfigRuleName": name, "Compliance": {"ComplianceType": kind}}
            for name, kind in zip(_SM32_REQUIRED_RULE_NAMES, types)
            if kind
        ]

    def test_the_pass_claims_no_config_coverage_of_jobs(self):
        # AIR-SGM-GOV-10: this row said training jobs "are covered by periodic
        # rules"; Config's ResourceType enum has no SageMaker job type.
        rows = _by_finding(_sm32_rows(), self.RULES)
        assert [r["Status"] for r in rows] == ["Passed"]
        details = rows[0]["Finding_Details"]
        assert "training jobs are covered" not in details
        assert "no Config rule evaluates a job" in details

    def test_insufficient_data_withholds_passed(self):
        rows = _by_finding(
            _sm32_rows(
                compliance=self._compliance(
                    "COMPLIANT", "INSUFFICIENT_DATA", "COMPLIANT"
                )
            ),
            self.RULES,
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "sm-notebook-kms" in rows[0]["Finding_Details"]

    def test_rule_with_no_compliance_entry_withholds_passed(self):
        rows = _by_finding(
            _sm32_rows(compliance=self._compliance("COMPLIANT", "COMPLIANT", None)),
            self.RULES,
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "sm-notebook-internet" in rows[0]["Finding_Details"]

    def test_one_non_compliant_rule_leaves_no_passed_row(self):
        rows = _by_finding(
            _sm32_rows(
                compliance=self._compliance("COMPLIANT", "NON_COMPLIANT", "COMPLIANT")
            ),
            self.RULES,
        )
        assert [r["Status"] for r in rows] == ["Failed"]

    def test_not_applicable_counts_as_evaluated(self):
        rows = _by_finding(
            _sm32_rows(
                compliance=self._compliance("COMPLIANT", "NOT_APPLICABLE", "COMPLIANT")
            ),
            self.RULES,
        )
        assert [r["Status"] for r in rows] == ["Passed"]


# ===================================================================
# IAM cache v2: a null boundary with a permissions_boundary read error is
# unknown, so the principal is not read, never Failed (SM-02, SM-09, SM-34)
# ===================================================================
def _boundary_error(name, identity_type="role", stage="permissions_boundary"):
    return {
        "type": identity_type,
        "name": name,
        "stage": stage,
        "error": "AccessDenied",
    }


_ACCOUNT_WIDE_INVOKE = _identity_policy(
    "sagemaker:InvokeEndpoint", "arn:aws:sagemaker:us-east-1:123456789012:*"
)
_WIDE_ROLE_ARN = "arn:aws:iam::123456789012:role/wide-role"
_OTHER_WIDE_ROLE_ARN = "arn:aws:iam::123456789012:role/other-wide-role"
_FULL_ACCESS = (
    "AmazonSageMakerFullAccess",
    "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    [],
)


class TestCacheV2BoundaryUnread:
    def _sm02_scoping(self, cache):
        return _by_finding(
            _sm02_rows(cache), sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING
        )

    def test_sm02_unread_boundary_is_not_read_not_failed(self):
        cache = _v2_cache(
            {"Hidden": [("InvokeAccount", _ACCOUNT_WIDE_INVOKE)]},
            principal_errors=[_boundary_error("Hidden")],
        )
        rows = self._sm02_scoping(cache)
        assert [r["Status"] for r in rows] == ["N/A"]
        assert rows[0]["Finding"].endswith("Incomplete")
        assert "role 'Hidden'" in rows[0]["Finding_Details"]

    def test_sm02_one_read_and_one_unknown_boundary(self):
        cache = _v2_cache(
            {
                "Open": [("InvokeAccount", _ACCOUNT_WIDE_INVOKE)],
                "Hidden": [("InvokeAccount", _ACCOUNT_WIDE_INVOKE)],
            },
            principal_errors=[_boundary_error("Hidden")],
        )
        rows = self._sm02_scoping(cache)
        failed = [r for r in rows if r["Status"] == "Failed"]
        unread = [r for r in rows if r["Status"] == "N/A"]
        assert len(failed) == 1
        assert "Role 'Open'" in failed[0]["Finding_Details"]
        assert "Hidden" not in failed[0]["Finding_Details"]
        assert len(unread) == 1
        assert "Role 'Hidden'" in unread[0]["Finding_Details"]
        assert "permissions boundary was not read" in unread[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "error",
        [
            _boundary_error("Hidden", stage="list_attached_policies"),
            _boundary_error("SomeoneElse"),
            _boundary_error("Hidden", identity_type="user"),
        ],
    )
    def test_sm02_error_elsewhere_does_not_hide_a_read_boundary(self, error):
        # Only this role's own boundary error makes its null boundary unknown.
        cache = _v2_cache(
            {"Hidden": [("InvokeAccount", _ACCOUNT_WIDE_INVOKE)]},
            principal_errors=[error],
        )
        rows = self._sm02_scoping(cache)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "Role 'Hidden'" in rows[0]["Finding_Details"]

    def _sm09_role_rows(self, cache, notebooks):
        return _by_finding(
            _sm09_rows(notebooks=notebooks, cache=cache),
            sagemaker_app.NOTEBOOK_ROLE_PRIVILEGE_FINDING,
        )

    def test_sm09_unread_boundary_is_not_read_not_failed(self):
        cache = _environment_cache({"wide-role": [_FULL_ACCESS]})
        cache["principal_errors"] = [_boundary_error("wide-role")]
        rows = self._sm09_role_rows(
            cache, {"nb": {"RootAccess": "Disabled", "RoleArn": _WIDE_ROLE_ARN}}
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert "wide-role" in rows[0]["Finding_Details"]
        assert "permissions boundary was not read" in rows[0]["Finding_Details"]

    def test_sm09_one_read_and_one_unknown_boundary(self):
        cache = _environment_cache(
            {"wide-role": [_FULL_ACCESS], "other-wide-role": [_FULL_ACCESS]}
        )
        cache["principal_errors"] = [_boundary_error("other-wide-role")]
        rows = self._sm09_role_rows(
            cache,
            {
                "bad": {"RootAccess": "Disabled", "RoleArn": _WIDE_ROLE_ARN},
                "unknown": {"RootAccess": "Disabled", "RoleArn": _OTHER_WIDE_ROLE_ARN},
            },
        )
        failed = [r for r in rows if r["Status"] == "Failed"]
        unread = [r for r in rows if r["Status"] == "N/A"]
        assert len(failed) == 1
        assert "'wide-role'" in failed[0]["Finding_Details"]
        assert "other-wide-role" not in failed[0]["Finding_Details"]
        assert len(unread) == 1
        assert "other-wide-role" in unread[0]["Finding_Details"]

    def test_sm09_error_for_another_role_does_not_hide_a_broad_grant(self):
        cache = _environment_cache({"wide-role": [_FULL_ACCESS]})
        cache["principal_errors"] = [_boundary_error("other-wide-role")]
        rows = self._sm09_role_rows(
            cache, {"nb": {"RootAccess": "Disabled", "RoleArn": _WIDE_ROLE_ARN}}
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "'wide-role'" in rows[0]["Finding_Details"]

    def _sm34(self, cache):
        suite = TestSM34CreationGuardrails()
        return suite._run(suite._inventory(), cache=cache)

    def test_sm34_unread_boundary_is_not_read_not_failed(self):
        cache = _creation_cache(
            {"Admin": [OPEN_SAGEMAKER_ALLOW]},
            principal_errors=[_boundary_error("Admin")],
        )
        findings = self._sm34(cache)
        assert [f["Status"] for f in findings] == ["N/A", "N/A", "N/A"]
        assert "role 'Admin'" in findings[0]["Finding_Details"]

    def test_sm34_one_read_and_one_unknown_boundary(self):
        cache = _creation_cache(
            {"Admin": [OPEN_SAGEMAKER_ALLOW], "Hidden": [OPEN_SAGEMAKER_ALLOW]},
            principal_errors=[_boundary_error("Hidden")],
        )
        findings = self._sm34(cache)
        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Failed"]
        assert "Role 'Admin'" in findings[0]["Finding_Details"]
        assert "Role 'Hidden'" not in findings[0]["Finding_Details"]

    def test_sm34_error_for_another_principal_does_not_hide_an_open_one(self):
        cache = _creation_cache(
            {"Admin": [OPEN_SAGEMAKER_ALLOW]},
            principal_errors=[_boundary_error("SomeoneElse")],
        )
        findings = self._sm34(cache)
        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Failed"]
        assert "Role 'Admin'" in findings[0]["Finding_Details"]

    _FULL_ACCESS_FINDING = "SageMaker Full Access Policy Used"
    _FULL_ACCESS_DOC = [("AmazonSageMakerFullAccess", {"Statement": []})]

    def test_full_access_unread_boundary_is_not_read_not_failed(self):
        cache = _v2_cache(
            {"Hidden": self._FULL_ACCESS_DOC},
            principal_errors=[_boundary_error("Hidden")],
        )
        rows = _sm02_rows(cache)
        assert _by_finding(rows, self._FULL_ACCESS_FINDING) == []
        check = _by_finding(rows, "SageMaker IAM Permissions Check")
        assert [r["Status"] for r in check] == ["N/A"]
        assert "Hidden" in check[0]["Finding_Details"]

    def test_full_access_one_read_and_one_unknown_boundary(self):
        cache = _v2_cache(
            {"Open": self._FULL_ACCESS_DOC, "Hidden": self._FULL_ACCESS_DOC},
            principal_errors=[_boundary_error("Hidden")],
        )
        rows = _by_finding(_sm02_rows(cache), self._FULL_ACCESS_FINDING)
        failed = [r for r in rows if r["Status"] == "Failed"]
        unread = [r for r in rows if r["Status"] == "N/A"]
        assert len(failed) == 1
        assert "Role 'Open'" in failed[0]["Finding_Details"]
        assert len(unread) == 1
        assert unread[0]["Finding"].endswith("Incomplete")
        assert "Role 'Hidden'" in unread[0]["Finding_Details"]
        assert "Open" not in unread[0]["Finding_Details"].split("For what")[0]
        assert "permissions boundary was not read" in unread[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "error",
        [
            _boundary_error("Hidden", stage="inline_policy"),
            _boundary_error("SomeoneElse"),
            _boundary_error("Hidden", identity_type="user"),
        ],
    )
    def test_full_access_error_elsewhere_does_not_hide_a_read_boundary(self, error):
        cache = _v2_cache({"Hidden": self._FULL_ACCESS_DOC}, principal_errors=[error])
        rows = _by_finding(_sm02_rows(cache), self._FULL_ACCESS_FINDING)
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "Role 'Hidden'" in rows[0]["Finding_Details"]


MIXED_SUBNET_FIXTURE = (
    [_subnet("subnet-public"), _subnet("subnet-private")],
    [
        _route_table(
            "rtb-public", [LOCAL_ROUTE, IGW_ROUTE], _explicit("subnet-public", "a-1")
        ),
        _route_table(
            "rtb-private", [LOCAL_ROUTE, NAT_ROUTE], _explicit("subnet-private", "a-2")
        ),
    ],
)


def _sagemaker_pages(pages, **describes):
    """A SageMaker client whose paginators are keyed by operation name and
    whose describe calls read from ``describes``."""
    sm = MagicMock()

    def get_paginator(operation_name):
        paginator = MagicMock()
        outcome = pages.get(operation_name, [{}])
        if isinstance(outcome, Exception):
            paginator.paginate.side_effect = outcome
        else:
            paginator.paginate.return_value = outcome
        return paginator

    sm.get_paginator.side_effect = get_paginator
    for operation, table in describes.items():

        def describe(_table=table, **kwargs):
            (key,) = kwargs.values()
            outcome = _table[key]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        setattr(sm, operation, MagicMock(side_effect=describe))
    return sm


_ACCESS_DENIED = ClientError(
    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "Describe"
)


class TestNet01ProcessingJobs:
    """AIR-FND-NET-01: SM-33 reads every processing job's NetworkConfig and the
    route tables of the subnets it names."""

    @staticmethod
    def _run(mock_client, processing, ec2=None, pages=None):
        sm = _sagemaker_pages(
            pages
            or {
                "list_training_jobs": [{"TrainingJobSummaries": []}],
                "list_processing_jobs": [
                    {
                        "ProcessingJobSummaries": [
                            {"ProcessingJobName": name} for name in processing
                        ]
                    }
                ],
            },
            describe_processing_job=processing,
        )
        mock_client.side_effect = _sm_client_factory(
            sagemaker=sm, ec2=ec2 or _ec2_exposure_client(*MIXED_SUBNET_FIXTURE)
        )
        rows = extract_csv_data(
            sagemaker_app.check_sagemaker_training_job_network_boundary(
                region="us-east-1"
            )
        )
        for row in rows:
            assert row["Check_ID"] == "SM-33"
            assert_finding_schema(row)
        return rows

    @patch("sagemaker_app.boto3.client")
    def test_one_processing_job_without_a_vpc_among_vpc_jobs_is_failed(
        self, mock_client
    ):
        vpc = {"NetworkConfig": {"VpcConfig": {"Subnets": ["subnet-private"]}}}
        rows = self._run(
            mock_client,
            {
                "p-vpc-1": vpc,
                "p-vpc-2": vpc,
                "p-open": {"NetworkConfig": {"EnableNetworkIsolation": True}},
            },
        )
        boundary = [
            r
            for r in rows
            if r["Finding"] == sagemaker_app.PROCESSING_NETWORK_BOUNDARY_FINDING
        ]
        assert [r["Status"] for r in boundary] == ["Failed", "Passed"]
        assert "'p-open'" in boundary[0]["Finding_Details"]
        assert "Network isolation is on" in boundary[0]["Finding_Details"]
        assert boundary[1]["Finding_Details"].startswith(
            "2 of the 3 processing jobs ran in customer subnets"
        )
        exposure = [
            r
            for r in rows
            if r["Finding"] == sagemaker_app.PROCESSING_SUBNET_EXPOSURE_FINDING
        ]
        assert [r["Status"] for r in exposure] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_a_processing_job_in_a_public_subnet_is_failed(self, mock_client):
        rows = self._run(
            mock_client,
            {
                "p-private": {
                    "NetworkConfig": {"VpcConfig": {"Subnets": ["subnet-private"]}}
                },
                "p-public": {
                    "NetworkConfig": {"VpcConfig": {"Subnets": ["subnet-public"]}}
                },
            },
        )
        exposure = [
            r
            for r in rows
            if r["Finding"] == sagemaker_app.PROCESSING_SUBNET_EXPOSURE_FINDING
        ]
        assert [r["Status"] for r in exposure] == ["Failed", "Passed"]
        assert "Processing job 'p-public'" in exposure[0]["Finding_Details"]
        assert "igw-public1" in exposure[0]["Finding_Details"]
        assert "p-private" not in exposure[0]["Finding_Details"]
        assert "p-public" not in exposure[1]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_a_processing_list_error_is_na_and_never_the_none_found_row(
        self, mock_client
    ):
        rows = self._run(
            mock_client,
            {},
            pages={
                "list_training_jobs": [{"TrainingJobSummaries": []}],
                "list_processing_jobs": _ACCESS_DENIED,
            },
        )
        assert [r["Status"] for r in rows] == ["N/A"]
        assert rows[0]["Finding"] == sagemaker_app.PROCESSING_NETWORK_BOUNDARY_FINDING
        assert "could not be listed" in rows[0]["Finding_Details"]
        assert "No SageMaker training" not in rows[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_a_processing_describe_error_is_na_beside_the_passed(self, mock_client):
        rows = self._run(
            mock_client,
            {
                "p-private": {
                    "NetworkConfig": {"VpcConfig": {"Subnets": ["subnet-private"]}}
                },
                "p-unread": _ACCESS_DENIED,
            },
        )
        unread = [r for r in rows if "'p-unread'" in r["Finding_Details"]]
        assert [r["Status"] for r in unread] == ["N/A"]

    @patch("sagemaker_app.boto3.client")
    def test_processing_jobs_alone_suppress_the_none_found_row(self, mock_client):
        rows = self._run(
            mock_client,
            {"p-open": {}},
        )
        assert [r["Status"] for r in rows] == ["Failed"]
        assert "no NetworkConfig.VpcConfig" in rows[0]["Finding_Details"]


class TestNet01StudioDomains:
    """AIR-FND-NET-01: SM-10 reads each Studio domain's AppNetworkAccessType and
    the route tables of its SubnetIds."""

    @staticmethod
    def _run(mock_client, domains, notebook_pages=None, domain_pages=None):
        sm = _sagemaker_pages(
            {
                "list_notebook_instances": notebook_pages
                or [{"NotebookInstances": []}],
                "list_domains": domain_pages
                or [
                    {
                        "Domains": [
                            {"DomainId": domain_id, "DomainName": domain_id}
                            for domain_id in domains
                        ]
                    }
                ],
            },
            describe_domain=domains,
        )
        mock_client.side_effect = _sm_client_factory(
            sagemaker=sm, ec2=_ec2_exposure_client(*MIXED_SUBNET_FIXTURE)
        )
        rows = extract_csv_data(
            sagemaker_app.check_sagemaker_notebook_vpc_deployment(region="us-east-1")
        )
        for row in rows:
            assert row["Check_ID"] == "SM-10"
            assert_finding_schema(row)
        return rows

    @staticmethod
    def _domain_rows(rows):
        return [
            r
            for r in rows
            if r["Finding"]
            in (
                sagemaker_app.STUDIO_DOMAIN_NETWORK_FINDING,
                sagemaker_app.STUDIO_DOMAIN_SUBNET_EXPOSURE_FINDING,
            )
        ]

    @patch("sagemaker_app.boto3.client")
    def test_a_public_internet_domain_among_vpc_only_domains_is_failed(
        self, mock_client
    ):
        private = {"AppNetworkAccessType": "VpcOnly", "SubnetIds": ["subnet-private"]}
        rows = self._domain_rows(
            self._run(
                mock_client,
                {
                    "d-ok1": private,
                    "d-open": {"AppNetworkAccessType": "PublicInternetOnly"},
                    "d-ok2": private,
                },
            )
        )
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "'d-open'" in failed[0]["Finding_Details"]
        assert "PublicInternetOnly" in failed[0]["Finding_Details"]
        exposure = [
            r
            for r in rows
            if r["Finding"] == sagemaker_app.STUDIO_DOMAIN_SUBNET_EXPOSURE_FINDING
        ]
        assert [r["Status"] for r in exposure] == ["Passed"]

    @patch("sagemaker_app.boto3.client")
    def test_a_domain_that_omits_the_access_type_reads_as_the_public_default(
        self, mock_client
    ):
        rows = self._domain_rows(self._run(mock_client, {"d-default": {}}))
        assert [r["Status"] for r in rows] == ["Failed"]

    @patch("sagemaker_app.boto3.client")
    def test_a_vpc_only_domain_in_a_public_subnet_is_failed(self, mock_client):
        rows = self._domain_rows(
            self._run(
                mock_client,
                {
                    "d-public": {
                        "AppNetworkAccessType": "VpcOnly",
                        "SubnetIds": ["subnet-public"],
                    },
                    "d-private": {
                        "AppNetworkAccessType": "VpcOnly",
                        "SubnetIds": ["subnet-private"],
                    },
                },
            )
        )
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "'d-public'" in failed[0]["Finding_Details"]
        assert "igw-public1" in failed[0]["Finding_Details"]
        assert "d-private" not in failed[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_a_vpc_only_domain_with_no_subnets_is_na(self, mock_client):
        rows = self._domain_rows(
            self._run(mock_client, {"d-empty": {"AppNetworkAccessType": "VpcOnly"}})
        )
        assert [r["Status"] for r in rows] == ["N/A"]

    @patch("sagemaker_app.boto3.client")
    def test_domain_list_and_describe_errors_are_na(self, mock_client):
        listed = self._domain_rows(
            self._run(mock_client, {}, domain_pages=_ACCESS_DENIED)
        )
        assert [r["Status"] for r in listed] == ["N/A"]
        assert "could not be listed" in listed[0]["Finding_Details"]
        described = self._domain_rows(
            self._run(mock_client, {"d-unread": _ACCESS_DENIED})
        )
        assert [r["Status"] for r in described] == ["N/A"]
        assert "'d-unread'" in described[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_a_notebook_list_error_never_yields_the_all_in_vpc_passed(
        self, mock_client
    ):
        rows = self._run(mock_client, {}, notebook_pages=_ACCESS_DENIED)
        notebook = [
            r for r in rows if r["Finding"] == "SageMaker Notebook VPC Deployment Check"
        ]
        assert [r["Status"] for r in notebook] == ["N/A"]
        assert "could not all be read" in notebook[0]["Finding_Details"]
        assert "Passed" not in [r["Status"] for r in rows]


def _group_user(policy_name, document, group="DataScience"):
    """A cached user whose only grant comes from one group policy."""
    return {
        "attached_policies": [],
        "inline_policies": [],
        "group_policies": [
            {
                "name": policy_name,
                "arn": f"arn:aws:iam::123456789012:policy/{policy_name}",
                "group": group,
                "document": document,
            }
        ],
        "permissions_boundary": None,
    }


class TestSageMakerGroupPolicies:
    """A user granted through an IAM group is read like any other user."""

    def test_endpoint_invocation_through_a_group_is_read(self):
        users = {
            "GroupWide": _group_user(
                "InvokeAll", _identity_policy("sagemaker:InvokeEndpoint", "*")
            ),
            "GroupNamed": _group_user(
                "InvokeOne",
                _identity_policy(
                    "sagemaker:InvokeEndpoint",
                    "arn:aws:sagemaker:us-east-1:123456789012:endpoint/a",
                ),
            ),
        }
        rows = _by_finding(
            _sm02_rows(_v2_cache({}, users=users)),
            sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING,
        )
        failed = [r for r in rows if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert "User 'GroupWide'" in failed[0]["Finding_Details"]
        assert "InvokeAll" in failed[0]["Finding_Details"]
        assert "GroupNamed" not in failed[0]["Finding_Details"]

    def test_creation_open_through_a_group_is_open(self):
        users = {
            "GroupOpen": _group_user(
                "AllSageMaker", {"Statement": [OPEN_SAGEMAKER_ALLOW]}
            ),
            "GroupGuarded": _group_user(
                "Guarded", {"Statement": GUARDED_CREATE_ALLOWS}
            ),
        }
        leg = sagemaker_app._creation_identity_leg(
            _v2_cache({}, users=users),
            "sagemaker:CreateTrainingJob",
            ("sagemaker:networkisolation",),
        )
        assert leg["state"] == "open"
        assert leg["principals"] == ["User 'GroupOpen'"]

    def test_group_deny_closes_the_creation_call(self):
        deny = _scp_deny(
            "sagemaker:CreateTrainingJob",
            "BoolIfExists",
            "sagemaker:NetworkIsolation",
            "false",
        )
        user = _group_user("AllSageMaker", {"Statement": [OPEN_SAGEMAKER_ALLOW]})
        user["group_policies"].append(
            {
                "name": "DenyOpen",
                "group": "DataScience",
                "document": {"Statement": [deny]},
            }
        )
        leg = sagemaker_app._creation_identity_leg(
            _v2_cache({}, users={"Denied": user}),
            "sagemaker:CreateTrainingJob",
            ("sagemaker:networkisolation",),
        )
        assert leg["state"] == "guarded"

    def test_stale_access_through_a_group_is_reported(self):
        users = {
            "GroupStale": _group_user(
                "Train", _identity_policy("sagemaker:CreateTrainingJob", "*")
            ),
            "NoSageMaker": _group_user("S3", _identity_policy("s3:GetObject", "*")),
        }
        old = datetime.now(timezone.utc) - timedelta(days=120)
        with patch("sagemaker_app.boto3.client") as mock_client:
            client = mock_client.return_value
            client.get_caller_identity.return_value = {
                "Account": "123456789012",
                "Arn": "arn:aws:sts::123456789012:assumed-role/a/b",
            }
            client.generate_service_last_accessed_details.return_value = {
                "JobId": "job-1"
            }
            client.get_service_last_accessed_details.return_value = {
                "JobStatus": "COMPLETED",
                "ServicesLastAccessed": [
                    {"ServiceName": "Amazon SageMaker", "LastAuthenticated": old}
                ],
            }
            rows = _rows(
                sagemaker_app.check_sagemaker_iam_permissions(
                    _v2_cache({}, users=users), region="Global"
                )
            )
        stale = [r for r in rows if r["Finding"] == "Stale SageMaker Access"]
        assert [r["Status"] for r in stale] == ["Failed"]
        assert "User 'GroupStale'" in stale[0]["Finding_Details"]
        assert client.generate_service_last_accessed_details.call_count == 1


class TestSM34ValuePinning:
    """AIR-SGM-TRN-08: a guard must hold the key to approved values, not only
    require it, and CreateModel and CreateTransformJob are guarded too."""

    _sm34 = TestSM34CreationGuardrails()

    def _rows(self, statements, cache=OPEN_CACHE, **inventory_kwargs):
        inventory = self._sm34._inventory(
            self._sm34._scp("Guard", statements), **inventory_kwargs
        )
        return self._sm34._by_category(self._sm34._run(inventory, cache=cache))

    def test_a_null_deny_on_a_fixed_value_key_admits_enabled(self):
        statements = (
            SCP_ENCRYPTION_DENIES
            + SCP_NETWORK_DENIES
            + [
                SCP_INTERNET_DENIES[0],
                _scp_deny(
                    "sagemaker:CreateNotebookInstance",
                    "Null",
                    "sagemaker:DirectInternetAccess",
                    "true",
                ),
            ]
        )
        rows = self._rows(statements)
        assert rows["encryption"]["Status"] == "Passed"
        assert rows["approved network"]["Status"] == "Passed"
        internet = rows["no direct internet access"]
        assert internet["Status"] == "Failed"
        assert "1 of 4 no direct internet access" in internet["Finding_Details"]
        assert "admits any value" in internet["Finding_Details"]
        assert "CreateNotebookInstance" in internet["Finding_Details"]

    def test_a_null_or_wildcard_deny_on_a_kms_key_does_not_pin_it(self):
        for weak in (
            _scp_deny(
                ["sagemaker:CreateTrainingJob", "sagemaker:CreateTransformJob"],
                "Null",
                "sagemaker:VolumeKmsKeyArn",
                "true",
            ),
            _scp_deny(
                ["sagemaker:CreateTrainingJob", "sagemaker:CreateTransformJob"],
                "ArnNotLike",
                "sagemaker:VolumeKmsKeyArn",
                ["arn:aws:kms:*:123456789012:key/*"],
            ),
        ):
            row = self._rows([weak] + SCP_ENCRYPTION_DENIES[1:])["encryption"]
            assert row["Status"] == "Failed"
            assert "2 of 7 encryption requirements" in row["Finding_Details"]
            assert (
                "CreateTrainingJob on sagemaker:VolumeKmsKeyArn"
                in (row["Finding_Details"])
            )

    @pytest.mark.parametrize(
        "operator", ["ArnNotEquals", "ArnNotEqualsIfExists", "ArnNotLike"]
    )
    def test_a_wildcard_key_arn_under_any_arn_operator_does_not_pin_it(self, operator):
        # ArnEquals and ArnNotEquals match a wildcard exactly as ArnLike does,
        # so a key/* value admits every key in the account.
        wildcard = _scp_deny(
            ["sagemaker:CreateTrainingJob", "sagemaker:CreateTransformJob"],
            operator,
            "sagemaker:VolumeKmsKeyArn",
            ["arn:aws:kms:us-east-1:123456789012:key/*"],
        )
        row = self._rows([wildcard] + SCP_ENCRYPTION_DENIES[1:])["encryption"]
        assert row["Status"] == "Failed"
        assert (
            "CreateTrainingJob on sagemaker:VolumeKmsKeyArn" in (row["Finding_Details"])
        )

    def test_a_literal_key_arn_under_arn_not_equals_still_pins_it(self):
        row = self._rows(SCP_ENCRYPTION_DENIES)["encryption"]
        assert row["Status"] == "Passed"

    @pytest.mark.parametrize("wildcard_first", [True, False])
    def test_an_allow_with_a_wildcard_arn_equals_key_does_not_guard(
        self, wildcard_first
    ):
        loose = json.loads(json.dumps(GUARDED_CREATE_ALLOWS))
        loose[0]["Condition"]["ArnEquals"]["sagemaker:VolumeKmsKeyArn"] = (
            "arn:aws:kms:*:*:key/?*"
        )
        roles = [("Builder", GUARDED_CREATE_ALLOWS), ("Loose", loose)]
        if wildcard_first:
            roles.reverse()
        rows = self._sm34._by_category(
            self._sm34._run(self._sm34._inventory(), cache=_creation_cache(dict(roles)))
        )
        encryption = rows["encryption"]
        assert encryption["Status"] == "Failed"
        assert "Role 'Loose'" in encryption["Finding_Details"]
        assert "Role 'Builder'" not in encryption["Finding_Details"]
        _assert_open_only_to_root(rows["approved network"])

    def test_the_model_and_transform_job_actions_are_guarded(self):
        three_actions = [
            "sagemaker:CreateTrainingJob",
            "sagemaker:CreateEndpointConfig",
            "sagemaker:CreateNotebookInstance",
        ]
        statements = [
            _scp_deny(
                three_actions,
                "ArnNotEquals",
                "sagemaker:VolumeKmsKeyArn",
                [APPROVED_KEY],
            ),
            _scp_deny(
                "sagemaker:CreateTrainingJob",
                "ArnNotEquals",
                "sagemaker:OutputKmsKeyArn",
                [APPROVED_KEY],
            ),
            SCP_ENCRYPTION_DENIES[2],
            _scp_deny(three_actions, "Null", "sagemaker:VpcSubnets", "true"),
            _scp_deny(
                three_actions,
                "ForAnyValue:StringNotEquals",
                "sagemaker:VpcSubnets",
                ["subnet-1"],
            ),
            _scp_deny(
                ["sagemaker:CreateTrainingJob", "sagemaker:CreateEndpointConfig"],
                "BoolIfExists",
                "sagemaker:NetworkIsolation",
                "false",
            ),
            SCP_INTERNET_DENIES[1],
        ]
        rows = self._rows(statements)
        encryption = rows["encryption"]["Finding_Details"]
        assert rows["encryption"]["Status"] == "Failed"
        assert "2 of 7 encryption requirements" in encryption
        assert "CreateTransformJob on sagemaker:VolumeKmsKeyArn" in encryption
        assert "CreateTransformJob on sagemaker:OutputKmsKeyArn" in encryption
        network = rows["approved network"]["Finding_Details"]
        assert rows["approved network"]["Status"] == "Failed"
        assert "1 of 4 approved network requirements" in network
        assert "CreateModel on sagemaker:VpcSubnets" in network
        internet = rows["no direct internet access"]["Finding_Details"]
        assert rows["no direct internet access"]["Status"] == "Failed"
        assert "CreateModel on sagemaker:NetworkIsolation" in internet

    def test_transform_job_is_not_required_to_carry_network_keys(self):
        network = dict(sagemaker_app.SAGEMAKER_CREATION_GUARDRAILS)["approved network"]
        assert "sagemaker:CreateTransformJob" not in [a for a, _ in network]
        assert "sagemaker:CreateModel" in [a for a, _ in network]

    def test_a_pair_is_only_as_attached_as_its_less_attached_half(self):
        inventory = self._sm34._inventory(
            self._sm34._scp("Presence", SCP_NETWORK_DENIES[:1]),
            self._sm34._scp("Values", SCP_NETWORK_DENIES[1:]),
        )
        inventory["items"][1]["targets"] = [
            {"TargetId": "ou-sandbox", "Type": "ORGANIZATIONAL_UNIT"}
        ]
        row = self._sm34._by_category(self._sm34._run(inventory))["approved network"]
        assert row["Status"] == "Failed"
        assert "not attached to this account" in row["Finding_Details"]
        inventory["items"][1]["targets"] = [{"TargetId": "r-root", "Type": "ROOT"}]
        row = self._sm34._by_category(self._sm34._run(inventory))["approved network"]
        assert row["Status"] == "Passed"
        assert "'Presence'" in row["Finding_Details"]
        assert "'Values'" in row["Finding_Details"]

    @pytest.mark.parametrize(
        "condition",
        [
            {"Null": {"sagemaker:VpcSubnets": "false"}},
            {"ForAnyValue:StringEquals": {"sagemaker:VpcSecurityGroupIds": ["sg-1"]}},
            {"ForAllValues:StringEquals": {"sagemaker:VpcSubnets": ["subnet-1"]}},
            {"StringLike": {"sagemaker:VpcSubnets": "subnet-*"}},
        ],
    )
    def test_an_allow_that_does_not_pin_the_subnets_is_open(self, condition):
        pinned = {
            "Effect": "Allow",
            "Action": "sagemaker:CreateModel",
            "Resource": "*",
            "Condition": {
                "ForAllValues:StringEquals": {"sagemaker:VpcSubnets": ["subnet-1"]},
                "Null": {"sagemaker:VpcSubnets": "false"},
            },
        }
        weak = {
            "Effect": "Allow",
            "Action": "sagemaker:CreateModel",
            "Resource": "*",
            "Condition": condition,
        }
        keys = ("sagemaker:vpcsubnets", "sagemaker:vpcsecuritygroupids")
        leg = sagemaker_app._creation_identity_leg(
            _creation_cache({"Pinned": [pinned], "Weak": [weak]}),
            "sagemaker:CreateModel",
            keys,
        )
        assert leg["state"] == "open"
        assert leg["principals"] == ["Role 'Weak'"]

    def test_an_identity_deny_pair_guards_the_call(self):
        cache = _creation_cache(
            {"Admin": [OPEN_SAGEMAKER_ALLOW] + SCP_NETWORK_DENIES},
        )
        leg = sagemaker_app._creation_identity_leg(
            cache,
            "sagemaker:CreateModel",
            ("sagemaker:vpcsubnets", "sagemaker:vpcsecuritygroupids"),
        )
        assert leg["state"] == "guarded"
        half = _creation_cache(
            {"Admin": [OPEN_SAGEMAKER_ALLOW] + SCP_NETWORK_DENIES[:1]}
        )
        assert (
            sagemaker_app._creation_identity_leg(
                half,
                "sagemaker:CreateModel",
                ("sagemaker:vpcsubnets", "sagemaker:vpcsecuritygroupids"),
            )["state"]
            == "open"
        )

    def test_an_identity_deny_with_a_bare_negated_operator_does_not_guard(self):
        keys = ("sagemaker:vpcsubnets", "sagemaker:vpcsecuritygroupids")
        bare = _scp_deny(
            "sagemaker:Create*", "StringNotEquals", "sagemaker:VpcSubnets", ["subnet-1"]
        )
        cache = _creation_cache(
            {
                "Guarded": [OPEN_SAGEMAKER_ALLOW] + SCP_NETWORK_DENIES,
                "Bare": [OPEN_SAGEMAKER_ALLOW, bare],
            }
        )
        leg = sagemaker_app._creation_identity_leg(cache, "sagemaker:CreateModel", keys)
        assert leg["state"] == "open"
        assert leg["principals"] == ["Role 'Bare'"]

    @pytest.mark.parametrize("operator", ["StringEquals", "StringNotEquals"])
    def test_an_allow_with_no_set_operator_on_the_subnets_is_open(self, operator):
        keys = ("sagemaker:vpcsubnets", "sagemaker:vpcsecuritygroupids")
        pinned = {
            "Effect": "Allow",
            "Action": "sagemaker:CreateModel",
            "Resource": "*",
            "Condition": {
                "ForAllValues:StringEquals": {"sagemaker:VpcSubnets": ["subnet-1"]},
                "Null": {"sagemaker:VpcSubnets": "false"},
            },
        }
        bare = {
            "Effect": "Allow",
            "Action": "sagemaker:CreateModel",
            "Resource": "*",
            "Condition": {
                operator: {"sagemaker:VpcSubnets": ["subnet-1"]},
                "Null": {"sagemaker:VpcSubnets": "false"},
            },
        }
        leg = sagemaker_app._creation_identity_leg(
            _creation_cache({"Pinned": [pinned], "Bare": [bare]}),
            "sagemaker:CreateModel",
            keys,
        )
        assert leg["state"] == "open"
        assert leg["principals"] == ["Role 'Bare'"]

    def _wording_cache(self):
        bare = _scp_deny(
            "sagemaker:Create*", "StringNotEquals", "sagemaker:VpcSubnets", ["subnet-1"]
        )
        null_only = _scp_deny(
            "sagemaker:Create*", "Null", "sagemaker:VpcSubnets", "true"
        )
        null_allow = {
            "Effect": "Allow",
            "Action": "sagemaker:*",
            "Resource": "*",
            "Condition": {"Null": {"sagemaker:VpcSubnets": "false"}},
        }
        return _creation_cache(
            {
                "Open": [OPEN_SAGEMAKER_ALLOW],
                "Bare": [OPEN_SAGEMAKER_ALLOW, bare],
                "NullOnly": [OPEN_SAGEMAKER_ALLOW, null_only],
                "NullAllow": [null_allow],
            }
        )

    @pytest.mark.parametrize(
        "scp_statements, status",
        [
            ([], "Failed"),
            (
                [
                    _scp_deny(
                        "sagemaker:Create*",
                        "StringEquals",
                        "sagemaker:VpcSubnets",
                        "subnet-bad",
                    )
                ],
                "N/A",
            ),
        ],
    )
    def test_a_principal_with_a_non_enforcing_condition_is_not_called_unconditioned(
        self, scp_statements, status
    ):
        row = self._rows(scp_statements, cache=self._wording_cache())[
            "approved network"
        ]
        details = row["Finding_Details"]
        assert row["Status"] == status
        assert "Role 'Open' can call it with no condition on that key" in details
        assert (
            "Role 'Bare', Role 'NullOnly', Role 'NullAllow' can call it under a "
            "condition on that key that does not enforce it"
        ) in details
        for name in ("Bare", "NullOnly", "NullAllow"):
            assert f"Role '{name}' can call it with no condition" not in details
            assert f"Role '{name}', Role 'Open'" not in details
        assert "Role 'Open', Role" not in details

    def test_only_conditioned_principals_never_read_as_unconditioned(self):
        cache = self._wording_cache()
        del cache["role_permissions"]["Open"]
        details = self._rows([], cache=cache)["approved network"]["Finding_Details"]
        assert "with no condition on that key" not in details
        assert "that does not enforce it" in details

    def test_six_conditioned_principals_are_truncated_with_a_count(self):
        null_only = _scp_deny(
            "sagemaker:Create*", "Null", "sagemaker:VpcSubnets", "true"
        )
        cache = _creation_cache(
            {f"R{i}": [OPEN_SAGEMAKER_ALLOW, null_only] for i in range(6)}
        )
        details = self._rows([], cache=cache)["approved network"]["Finding_Details"]
        assert (
            "Role 'R4' and 1 more can call it under a condition on that key that "
            "does not enforce it"
        ) in details
        assert "Role 'R5'" not in details


BATCH_SCP_DENIES = [
    _scp_deny(
        "sagemaker:CreateTransformJob",
        "ArnNotEquals",
        "sagemaker:VolumeKmsKeyArn",
        [APPROVED_KEY],
    ),
    _scp_deny(
        "sagemaker:CreateTransformJob",
        "ArnNotEquals",
        "sagemaker:OutputKmsKeyArn",
        [APPROVED_KEY],
    ),
    _scp_deny("sagemaker:CreateModel", "Null", "sagemaker:VpcSubnets", "true"),
    _scp_deny(
        "sagemaker:CreateModel",
        "ForAnyValue:StringNotEquals",
        "sagemaker:VpcSubnets",
        ["subnet-1"],
    ),
    _scp_deny(
        "sagemaker:CreateModel",
        "BoolIfExists",
        "sagemaker:NetworkIsolation",
        "false",
    ),
]


class TestSM42BatchCreationGuardrails:
    """AIR-SGM-EP-08: SM-42 judges CreateModel and CreateTransformJob alone."""

    _sm34 = TestSM34CreationGuardrails()

    def _run(self, inventory, cache=OPEN_CACHE, region="us-east-1", **kwargs):
        clients = (
            self._sm34._management_account_clients()
            if kwargs.get("management")
            else self._sm34._member_account_clients()
        )
        with patch("sagemaker_app.boto3.client", side_effect=clients):
            return extract_csv_data(
                sagemaker_app.check_sagemaker_batch_creation_guardrails(
                    region=region, scp_inventory=inventory, permission_cache=cache
                )
            )

    def _policies(self, *named_statements):
        return self._sm34._inventory(
            *(self._sm34._scp(name, stmts) for name, stmts in named_statements)
        )

    def test_a_training_gap_fails_sm34_but_not_sm42(self):
        inventory = self._policies(("BatchGuard", BATCH_SCP_DENIES))
        batch = self._run(inventory)
        assert [f["Check_ID"] for f in batch] == ["SM-42"] * 3
        assert [f["Status"] for f in batch] == ["Passed"] * 3
        assert all("'BatchGuard'" in f["Finding_Details"] for f in batch)
        sm34 = self._sm34._by_category(self._sm34._run(inventory))
        assert {row["Status"] for row in sm34.values()} == {"Failed"}
        assert "CreateTrainingJob" in sm34["encryption"]["Finding_Details"]

    def test_a_batch_gap_fails_sm42_while_sm34_names_it_too(self):
        # The output key Deny is missing, and the rest of the guard is split
        # across two policies.
        inventory = self._policies(
            ("KeyGuard", BATCH_SCP_DENIES[:1]),
            ("ModelGuard", BATCH_SCP_DENIES[2:]),
        )
        rows = self._sm34._by_category(self._run(inventory))
        encryption = rows["encryption"]
        assert encryption["Status"] == "Failed"
        assert encryption["Check_ID"] == "SM-42"
        assert "1 of 2 encryption requirements" in encryption["Finding_Details"]
        assert (
            "CreateTransformJob on sagemaker:OutputKmsKeyArn"
            in (encryption["Finding_Details"])
        )
        assert "CreateTrainingJob" not in encryption["Finding_Details"]
        assert "batch transform path" in encryption["Finding_Details"]
        assert rows["approved network"]["Status"] == "Passed"
        assert "'ModelGuard'" in rows["approved network"]["Finding_Details"]
        assert rows["no direct internet access"]["Status"] == "Passed"

    def test_a_wildcard_arn_not_equals_key_leaves_the_batch_path_failed(self):
        wildcard = _scp_deny(
            "sagemaker:CreateTransformJob",
            "ArnNotEquals",
            "sagemaker:OutputKmsKeyArn",
            ["arn:aws:kms:us-east-1:123456789012:key/*"],
        )
        inventory = self._policies(
            ("Guard", BATCH_SCP_DENIES[:1] + [wildcard] + BATCH_SCP_DENIES[2:])
        )
        encryption = self._sm34._by_category(self._run(inventory))["encryption"]
        assert encryption["Status"] == "Failed"
        assert "1 of 2 encryption requirements" in encryption["Finding_Details"]
        assert (
            "CreateTransformJob on sagemaker:OutputKmsKeyArn"
            in (encryption["Finding_Details"])
        )
        assert (
            "CreateTransformJob on sagemaker:VolumeKmsKeyArn"
            not in (encryption["Finding_Details"])
        )

    def test_a_guard_on_training_only_leaves_the_batch_path_failed(self):
        training_only = [
            _scp_deny(
                "sagemaker:CreateTrainingJob",
                "ArnNotEquals",
                "sagemaker:VolumeKmsKeyArn",
                [APPROVED_KEY],
            ),
            _scp_deny(
                "sagemaker:CreateTrainingJob",
                "BoolIfExists",
                "sagemaker:NetworkIsolation",
                "false",
            ),
        ]
        batch = self._run(self._policies(("TrainingGuard", training_only)))
        assert [f["Status"] for f in batch] == ["Failed"] * 3

    def test_the_requirements_are_the_batch_subset_of_sm34(self):
        batch = dict(sagemaker_app.SAGEMAKER_BATCH_CREATION_GUARDRAILS)
        full = dict(sagemaker_app.SAGEMAKER_CREATION_GUARDRAILS)
        assert list(batch) == list(full)
        for category, requirements in batch.items():
            assert requirements
            assert {a for a, _ in requirements} <= {
                "sagemaker:CreateModel",
                "sagemaker:CreateTransformJob",
            }
            assert set(requirements) <= set(full[category])
            assert [r for r in full[category] if r[0] in dict(requirements)] == list(
                requirements
            )
        assert len(batch["encryption"]) == 2
        assert len(batch["approved network"]) == 1
        assert len(batch["no direct internet access"]) == 1

    def test_rows_carry_the_scanned_region(self):
        inventory = self._policies(("BatchGuard", BATCH_SCP_DENIES))
        for region in ("us-east-1", "eu-west-1"):
            assert {f["Region"] for f in self._run(inventory, region=region)} == {
                region
            }

    def test_unassessed_when_neither_leg_can_be_read(self):
        rows = self._run(self._policies(), cache=None, management=True)
        assert len(rows) == 1
        assert rows[0]["Check_ID"] == "SM-42"
        assert rows[0]["Status"] == "N/A"
        assert "were not assessed" in rows[0]["Finding_Details"]

    def test_the_handler_runs_it_per_region(self):
        source = open(os.path.join(_sm_dir, "app.py"), encoding="utf-8").read()
        handler = source[source.index("def lambda_handler") :]
        call_at = handler.index("check_sagemaker_batch_creation_guardrails(")
        call = handler[call_at : handler.index(")", call_at)]
        assert "region=region" in call
        assert "permission_cache=permission_cache" in call
        assert call_at > handler.index("check_sagemaker_transform_job_encryption(")


def _hyperpod_inventory(groups):
    return {
        "items": [
            {
                "summary": {"ClusterName": "cluster-1"},
                "detail": {
                    "ClusterName": "cluster-1",
                    "InstanceGroups": [
                        {
                            "InstanceGroupName": name,
                            "InstanceStorageConfigs": [
                                {
                                    "EbsVolumeConfig": {
                                        "RootVolume": root,
                                        "VolumeKmsKeyId": key,
                                    }
                                }
                                for root, key in volumes
                            ],
                        }
                        for name, volumes in groups
                    ],
                },
            }
        ],
        "errors": [],
        "list_error": None,
    }


_HP_CMK = "arn:aws:kms:us-east-1:123456789012:key/cmk-1"
_HP_AWS = "arn:aws:kms:us-east-1:123456789012:key/aws-1"


class TestSM27KeyManager:
    """SM-27 resolves each VolumeKmsKeyId with kms:DescribeKey."""

    def _run(self, inventory, managers):
        kms = MagicMock()

        def describe_key(KeyId):
            value = managers[KeyId]
            if isinstance(value, Exception):
                raise value
            return {"KeyMetadata": {"KeyId": KeyId, "KeyManager": value}}

        kms.describe_key.side_effect = describe_key
        with patch("sagemaker_app.boto3.client", return_value=kms):
            rows = extract_csv_data(
                sagemaker_app.check_hyperpod_ebs_cmk_encryption("us-east-1", inventory)
            )
        return {row["Finding_Details"].split("'")[3]: row for row in rows}

    @pytest.mark.parametrize("key", [_HP_AWS, "alias/aws/sagemaker"])
    def test_aws_managed_secondary_volume_fails(self, key):
        rows = self._run(
            _hyperpod_inventory([("workers", [(True, _HP_CMK), (False, key)])]),
            {_HP_CMK: "CUSTOMER", _HP_AWS: "AWS"},
        )
        assert rows["workers"]["Status"] == "Failed"
        assert "AWS managed key: secondary volume" in rows["workers"]["Finding_Details"]

    def test_aws_managed_group_beside_customer_group(self):
        rows = self._run(
            _hyperpod_inventory(
                [
                    ("good", [(True, _HP_CMK)]),
                    ("bad", [(True, _HP_AWS)]),
                ]
            ),
            {_HP_CMK: "CUSTOMER", _HP_AWS: "AWS"},
        )
        assert rows["good"]["Status"] == "Passed"
        assert rows["bad"]["Status"] == "Failed"
        assert "root volume" in rows["bad"]["Finding_Details"]

    def test_describe_key_error_holds_back_passed(self):
        rows = self._run(
            _hyperpod_inventory([("workers", [(True, _HP_CMK), (False, _HP_AWS)])]),
            {_HP_CMK: "CUSTOMER", _HP_AWS: _make_client_error("AccessDeniedException")},
        )
        assert rows["workers"]["Status"] == "N/A"
        assert f"kms:DescribeKey {_HP_AWS}" in rows["workers"]["Finding_Details"]
        assert "customer-managed" not in rows["workers"]["Finding_Details"]

    def test_unread_key_does_not_hide_a_missing_key(self):
        rows = self._run(
            _hyperpod_inventory([("workers", [(True, _HP_CMK), (False, None)])]),
            {_HP_CMK: _make_client_error("AccessDeniedException")},
        )
        assert rows["workers"]["Status"] == "Failed"
        assert "secondary volume" in rows["workers"]["Finding_Details"]
        assert (
            f"Not read: kms:DescribeKey {_HP_CMK}" in rows["workers"]["Finding_Details"]
        )

    def test_customer_keys_pass(self):
        rows = self._run(
            _hyperpod_inventory([("workers", [(True, _HP_CMK), (False, _HP_CMK)])]),
            {_HP_CMK: "CUSTOMER"},
        )
        assert rows["workers"]["Status"] == "Passed"
        assert "kms:DescribeKey" in rows["workers"]["Finding_Details"]


def _user_without_group_policies(document, error=True):
    """A cached user whose group policies were not read."""
    user = {
        "attached_policies": [
            {
                "name": "Scoped",
                "arn": "arn:aws:iam::123456789012:policy/Scoped",
                "document": document,
            }
        ],
        "inline_policies": [],
        "permissions_boundary": None,
    }
    if error:
        user["group_policies_error"] = "AccessDenied"
    return user


class TestGroupPoliciesContract:
    """A user with no group_policies list is unread, never a pass."""

    SCOPED_INVOKE = _identity_policy(
        "sagemaker:InvokeEndpoint",
        "arn:aws:sagemaker:us-east-1:123456789012:endpoint/a",
    )

    @pytest.mark.parametrize("recorded", [True, False])
    def test_principal_read_errors_names_the_user(self, recorded):
        errors = (
            [{"type": "user", "name": "u", "stage": "group_policies"}]
            if recorded
            else []
        )
        cache = _v2_cache(
            {},
            principal_errors=errors,
            users={"u": _user_without_group_policies(self.SCOPED_INVOKE, recorded)},
        )
        assert sagemaker_app._principal_read_errors(cache) == [
            "user 'u' (group_policies)"
        ]

    def test_a_cache_without_principal_errors_still_names_the_user(self):
        cache = _v2_cache(
            {}, users={"u": _user_without_group_policies(self.SCOPED_INVOKE)}
        )
        del cache["principal_errors"]
        assert sagemaker_app._principal_read_errors(cache) == [
            "user 'u' (group_policies)"
        ]

    def test_an_empty_group_list_is_read(self):
        user = _user_without_group_policies(self.SCOPED_INVOKE, error=False)
        user["group_policies"] = []
        assert (
            sagemaker_app._principal_read_errors(_v2_cache({}, users={"u": user})) == []
        )

    @pytest.mark.parametrize("recorded", [True, False])
    def test_endpoint_scoping_does_not_pass(self, recorded):
        users = {
            "read": _group_user("InvokeOne", self.SCOPED_INVOKE),
            "unread": _user_without_group_policies(self.SCOPED_INVOKE, recorded),
        }
        rows = _by_finding(
            _sm02_rows(_v2_cache({}, users=users)),
            sagemaker_app.ENDPOINT_INVOCATION_SCOPING_FINDING,
        )
        assert "Passed" not in [r["Status"] for r in rows]
        assert any(
            r["Status"] == "N/A" and "user 'unread'" in r["Finding_Details"]
            for r in rows
        )

    def test_invoke_source_network_does_not_pass(self):
        pinned = _invoke_allow({"StringEquals": {"aws:SourceVpce": "vpce-1"}})
        cache = _v2_cache(
            {"R": [("P", pinned)]},
            users={"unread": _user_without_group_policies(pinned, error=False)},
        )
        rows = _rows(
            {
                "csv_data": sagemaker_app._invoke_source_network_findings(
                    cache, {"endpoints": [{"name": "ep-1"}]}, "us-east-1"
                )
            }
        )
        assert "Passed" not in [r["Status"] for r in rows]
        assert any("user 'unread'" in r["Finding_Details"] for r in rows)

    def test_creation_leg_is_incomplete(self):
        users = {
            "guarded": _group_user("Guarded", {"Statement": GUARDED_CREATE_ALLOWS}),
            "unread": _user_without_group_policies(
                {"Statement": GUARDED_CREATE_ALLOWS}, error=False
            ),
        }
        leg = sagemaker_app._creation_identity_leg(
            _v2_cache({}, users=users),
            "sagemaker:CreateTrainingJob",
            ("sagemaker:networkisolation",),
        )
        assert leg["state"] == "incomplete"
        assert leg["principals"] == ["user 'unread' (group_policies)"]

    def test_an_open_grant_still_fails_beside_the_unread_groups(self):
        leg = sagemaker_app._creation_identity_leg(
            _v2_cache(
                {},
                users={
                    "open": _user_without_group_policies(
                        {"Statement": [OPEN_SAGEMAKER_ALLOW]}
                    )
                },
            ),
            "sagemaker:CreateTrainingJob",
            ("sagemaker:networkisolation",),
        )
        assert leg["state"] == "open"
        assert leg["principals"] == ["User 'open'"]


_SM43_ACCOUNT = "111122223333"
_SM43_DIGEST = "sha256:" + "a" * 64


def _sm43_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Operation")


def _sm43_image(repository="serve", tag="v1", digest=None, account=_SM43_ACCOUNT):
    image = f"{account}.dkr.ecr.us-east-1.amazonaws.com/{repository}"
    if tag:
        image += f":{tag}"
    if digest:
        image += f"@{digest}"
    return image


def _sm43_container(image=None, uri="s3://artifacts/m/", etag="e-1", **overrides):
    container = {"Image": image or _sm43_image()}
    if uri:
        source = {"S3Uri": uri, "S3DataType": "S3Prefix"}
        if etag:
            source["ETag"] = etag
        container["ModelDataSource"] = {"S3DataSource": source}
    container.update(overrides)
    return container


def _sm43_rows(
    endpoints=None,
    models=None,
    packages=None,
    repositories=None,
    signing=None,
    statuses=None,
    buckets=None,
    components=None,
    deployed=None,
    keys=None,
):
    """
    Run SM-43 over mocked SageMaker, ECR, S3 and KMS clients.

    endpoints maps a name to {"models": [...], "status": ..., "components":
    [variant names]}. Every other map is keyed by resource name, and an
    Exception value is raised by the matching call.
    """
    endpoints = (
        endpoints
        if endpoints is not None
        else {"ep-1": {"models": ["m-1"]}, "ep-2": {"models": ["m-2"]}}
    )
    models = (
        models
        if models is not None
        else {
            "m-1": {"PrimaryContainer": _sm43_container()},
            "m-2": {"PrimaryContainer": _sm43_container()},
        }
    )
    packages = packages or {}
    repositories = (
        repositories
        if repositories is not None
        else {"serve": {"registryId": _SM43_ACCOUNT, "imageTagMutability": "IMMUTABLE"}}
    )
    signing = (
        signing
        if signing is not None
        else _sm43_error("SigningConfigurationNotFoundException")
    )
    statuses = statuses or {}
    buckets = buckets or {}
    components = components or {}
    deployed = deployed or {}
    _sm43_rows.signing_calls = []

    sagemaker = MagicMock()
    names = list(endpoints)

    def list_components(EndpointNameEquals, VariantNameEquals):
        found = components.get((EndpointNameEquals, VariantNameEquals), [])
        if isinstance(found, Exception):
            raise found
        summaries = [
            n if isinstance(n, dict) else {"InferenceComponentName": n} for n in found
        ]
        return [
            {"InferenceComponents": summaries[:1]},
            {"InferenceComponents": summaries[1:]},
        ]

    sagemaker.get_paginator.side_effect = _pager(
        {
            "list_endpoints": [
                {
                    "Endpoints": [
                        {
                            "EndpointName": n,
                            "EndpointStatus": endpoints[n].get("status", "InService"),
                        }
                        for n in chunk
                    ]
                }
                for chunk in (names[:1], names[1:])
            ],
            "list_inference_components": list_components,
        }
    )
    sagemaker.describe_endpoint.side_effect = lambda EndpointName: {
        "EndpointConfigName": f"cfg-{EndpointName}",
        "ProductionVariants": [
            {
                "VariantName": "v",
                "DeployedImages": [
                    {"SpecifiedImage": specified, "ResolvedImage": resolved}
                    for specified, resolved in deployed.get(EndpointName, {}).items()
                ],
            }
        ],
    }

    def describe_endpoint_config(EndpointConfigName):
        spec = endpoints[EndpointConfigName[len("cfg-") :]]
        return {
            "ProductionVariants": [
                {"VariantName": f"v-{m}", "ModelName": m} for m in spec["models"]
            ]
            + [{"VariantName": v} for v in spec.get("components", [])]
        }

    sagemaker.describe_endpoint_config.side_effect = describe_endpoint_config

    def describe(source, key):
        def call(**kwargs):
            value = source[kwargs[key]]
            if isinstance(value, Exception):
                raise value
            return value

        return call

    sagemaker.describe_model.side_effect = describe(models, "ModelName")
    sagemaker.describe_model_package.side_effect = describe(
        packages, "ModelPackageName"
    )

    def describe_inference_component(InferenceComponentName):
        spec = components[InferenceComponentName]
        if isinstance(spec, Exception):
            raise spec
        if "Specifications" in spec:
            return spec
        return {"Specification": spec}

    sagemaker.describe_inference_component.side_effect = describe_inference_component

    ecr = MagicMock()

    def describe_repositories(registryId, repositoryNames):
        value = repositories[repositoryNames[0]]
        if isinstance(value, Exception):
            raise value
        return {"repositories": [dict(value, repositoryName=repositoryNames[0])]}

    ecr.describe_repositories.side_effect = describe_repositories

    def get_signing_configuration():
        if isinstance(signing, Exception):
            raise signing
        return signing

    ecr.get_signing_configuration.side_effect = get_signing_configuration

    def describe_image_signing_status(registryId, repositoryName, imageId):
        _sm43_rows.signing_calls.append((repositoryName, imageId))
        value = statuses.get(repositoryName, [])
        if isinstance(value, Exception):
            raise value
        return {"signingStatuses": value}

    ecr.describe_image_signing_status.side_effect = describe_image_signing_status

    s3 = MagicMock()

    def get_bucket_encryption(Bucket):
        value = buckets.get(
            Bucket,
            {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "arn:aws:kms:us-east-1:1:key/k",
                        }
                    }
                ]
            },
        )
        if isinstance(value, Exception):
            raise value
        return {"ServerSideEncryptionConfiguration": value}

    s3.get_bucket_encryption.side_effect = get_bucket_encryption
    keys = keys or {}
    kms = MagicMock()

    def describe_key(KeyId):
        value = keys.get(KeyId, {"KeyManager": "CUSTOMER", "KeyState": "Enabled"})
        if isinstance(value, Exception):
            raise value
        return {"KeyMetadata": dict(value, KeyId=KeyId)}

    kms.describe_key.side_effect = describe_key
    clients = {"sagemaker": sagemaker, "ecr": ecr, "s3": s3, "kms": kms}
    with patch("sagemaker_app.boto3.client") as mock_client:
        mock_client.side_effect = lambda service, **_: clients[service]
        return _rows(
            sagemaker_app.check_sagemaker_model_artifact_integrity("us-east-1")
        )


def _sm43_statuses(rows):
    return [r["Status"] for r in rows]


class TestSM43ModelArtifactIntegrity:
    """AIR-SLF-CMP-08: pinned images and recorded model data per endpoint."""

    def test_immutable_tag_and_recorded_etag_pass(self):
        rows = _sm43_rows()
        assert _sm43_statuses(rows) == ["Passed"]
        assert rows[0]["Check_ID"] == "SM-43"
        assert "2 InService endpoint(s)" in rows[0]["Finding_Details"]
        assert "ep-1, ep-2" in rows[0]["Finding_Details"]
        assert "an expected value is recorded" in rows[0]["Finding_Details"]
        assert "load time is not returned" in rows[0]["Finding_Details"]
        assert "on ECS, EKS or EC2" in rows[0]["Finding_Details"]

    def test_only_the_second_endpoint_fails_when_its_model_has_a_bare_url(self):
        rows = _sm43_rows(
            models={
                "m-1": {"PrimaryContainer": _sm43_container()},
                "m-2": {
                    "PrimaryContainer": {
                        "Image": _sm43_image(),
                        "ModelDataUrl": "s3://artifacts/m2/model.tar.gz",
                    }
                },
            }
        )
        assert _sm43_statuses(rows) == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert details.startswith("Endpoint 'ep-2' serves")
        assert (
            "model 'm-2' container 1 loads ModelDataUrl "
            "s3://artifacts/m2/model.tar.gz with no expected value recorded"
        ) in details
        assert "m-1" not in details

    def test_each_failing_endpoint_gets_its_own_row(self):
        bare = {"PrimaryContainer": _sm43_container(etag=None)}
        rows = _sm43_rows(models={"m-1": bare, "m-2": bare})
        assert _sm43_statuses(rows) == ["Failed", "Failed"]
        assert rows[0]["Finding_Details"].startswith("Endpoint 'ep-1'")
        assert rows[1]["Finding_Details"].startswith("Endpoint 'ep-2'")
        assert (
            "s3://artifacts/m/ records no ETag or ManifestEtag"
            in (rows[1]["Finding_Details"])
        )

    def test_a_digest_pin_passes_without_reading_the_repository(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={
                "m-1": {
                    "PrimaryContainer": _sm43_container(
                        image=_sm43_image(tag=None, digest=_SM43_DIGEST)
                    )
                }
            },
            repositories={"serve": _sm43_error("AccessDeniedException")},
        )
        assert _sm43_statuses(rows) == ["Passed"]

    def test_a_mutable_tag_fails_on_the_second_endpoint_only(self):
        rows = _sm43_rows(
            models={
                "m-1": {"PrimaryContainer": _sm43_container()},
                "m-2": {
                    "PrimaryContainer": _sm43_container(
                        image=_sm43_image(repository="loose", tag="latest")
                    )
                },
            },
            repositories={
                "serve": {
                    "registryId": _SM43_ACCOUNT,
                    "imageTagMutability": "IMMUTABLE",
                },
                "loose": {"registryId": _SM43_ACCOUNT, "imageTagMutability": "MUTABLE"},
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert rows[0]["Finding_Details"].startswith("Endpoint 'ep-2'")
        assert (
            "image is pinned by tag 'latest' in repository loose, whose "
            "imageTagMutability MUTABLE lets that tag move"
        ) in rows[0]["Finding_Details"]

    def test_an_untagged_image_is_read_as_latest(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={
                "m-1": {
                    "PrimaryContainer": _sm43_container(image=_sm43_image(tag=None))
                }
            },
            repositories={
                "serve": {"registryId": _SM43_ACCOUNT, "imageTagMutability": "MUTABLE"}
            },
        )
        assert "pinned by tag 'latest'" in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "mutability, filters, status",
        [
            (
                "IMMUTABLE_WITH_EXCLUSION",
                [{"filterType": "WILDCARD", "filter": "dev-*"}],
                "Passed",
            ),
            (
                "IMMUTABLE_WITH_EXCLUSION",
                [{"filterType": "WILDCARD", "filter": "v*"}],
                "Failed",
            ),
            (
                "MUTABLE_WITH_EXCLUSION",
                [{"filterType": "WILDCARD", "filter": "v*"}],
                "Passed",
            ),
            (
                "MUTABLE_WITH_EXCLUSION",
                [{"filterType": "WILDCARD", "filter": "dev-*"}],
                "Failed",
            ),
        ],
    )
    def test_an_exclusion_filter_inverts_the_setting_for_its_tags(
        self, mutability, filters, status
    ):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": _sm43_container()}},
            repositories={
                "serve": {
                    "registryId": _SM43_ACCOUNT,
                    "imageTagMutability": mutability,
                    "imageTagMutabilityExclusionFilters": filters,
                }
            },
        )
        assert _sm43_statuses(rows) == [status]

    def test_a_denied_repository_read_is_na_naming_the_permission(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={
                "m-1": {
                    "PrimaryContainer": _sm43_container(
                        image=_sm43_image(account="763104351884")
                    )
                }
            },
            repositories={"serve": _sm43_error("AccessDeniedException")},
        )
        assert _sm43_statuses(rows) == ["N/A"]
        assert (
            "image repository serve in account 763104351884 was not read "
            "(ecr:DescribeRepositories: AccessDeniedException)"
        ) in rows[0]["Finding_Details"]

    def test_an_unread_endpoint_holds_back_passed_but_not_a_failure(self):
        rows = _sm43_rows(
            models={
                "m-1": _sm43_error("AccessDeniedException"),
                "m-2": {"PrimaryContainer": _sm43_container(etag=None)},
            }
        )
        assert _sm43_statuses(rows) == ["Failed", "N/A"]
        assert rows[0]["Finding_Details"].startswith("Endpoint 'ep-2'")
        assert (
            "endpoint 'ep-1': model 'm-1' was not read (AccessDeniedException)"
        ) in rows[1]["Finding_Details"]

    def test_a_non_ecr_tag_is_na_and_a_non_ecr_digest_passes(self):
        rows = _sm43_rows(
            models={
                "m-1": {
                    "PrimaryContainer": _sm43_container(image="registry.local/serve:v1")
                },
                "m-2": {
                    "PrimaryContainer": _sm43_container(
                        image=f"registry.local/serve@{_SM43_DIGEST}"
                    )
                },
            }
        )
        assert _sm43_statuses(rows) == ["N/A"]
        details = rows[0]["Finding_Details"]
        assert (
            "endpoint 'ep-1': model 'm-1' container 1 image is outside Amazon ECR"
            in details
        )
        assert "endpoint 'ep-2'" not in details.split("For what was read")[0]
        assert "1 InService endpoint(s)" in details and ": ep-2." in details

    def test_hf_model_id_without_model_data_fails_and_names_no_value(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={
                "m-1": {
                    "PrimaryContainer": _sm43_container(
                        uri=None,
                        Environment={
                            "HF_MODEL_ID": "org/secret-model",
                            "HF_TOKEN": "t",
                        },
                    )
                }
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "sets HF_MODEL_ID with no ModelDataUrl or ModelDataSource" in details
        assert "org/secret-model" not in details
        assert "HF_TOKEN" not in details

    def test_hf_model_id_beside_recorded_model_data_passes(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={
                "m-1": {
                    "PrimaryContainer": _sm43_container(
                        Environment={"HF_MODEL_ID": "/opt/ml/model"}
                    )
                }
            },
        )
        assert _sm43_statuses(rows) == ["Passed"]

    def test_hub_content_counts_as_a_verified_source(self):
        container = _sm43_container(etag=None)
        container["ModelDataSource"]["S3DataSource"]["HubAccessConfig"] = {
            "HubContentArn": "arn:aws:sagemaker:us-east-1:aws:hub-content/x"
        }
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": container}},
            buckets={"artifacts": _sm43_error("AccessDeniedException")},
        )
        assert _sm43_statuses(rows) == ["Passed"]

    def test_manifest_etag_counts_as_recorded(self):
        container = _sm43_container(etag=None)
        container["ModelDataSource"]["S3DataSource"]["ManifestEtag"] = "m-e"
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": container}},
        )
        assert _sm43_statuses(rows) == ["Passed"]

    def test_the_second_additional_source_without_an_etag_fails(self):
        container = _sm43_container(
            AdditionalModelDataSources=[
                {
                    "ChannelName": "a",
                    "S3DataSource": {"S3Uri": "s3://artifacts/a/", "ETag": "x"},
                },
                {"ChannelName": "b", "S3DataSource": {"S3Uri": "s3://artifacts/b/"}},
            ]
        )
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": container}},
        )
        assert _sm43_statuses(rows) == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "additional source b s3://artifacts/b/ records no ETag" in details
        assert "additional source a" not in details

    def test_the_second_pipeline_container_is_judged(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={
                "m-1": {
                    "Containers": [
                        _sm43_container(ContainerHostname="pre"),
                        _sm43_container(ContainerHostname="main", etag=None),
                    ]
                }
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert (
            "model 'm-1' container main ModelDataSource" in rows[0]["Finding_Details"]
        )
        assert "container pre" not in rows[0]["Finding_Details"]

    def test_a_model_package_container_with_model_data_etag_passes(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": {"ModelPackageName": "pkg"}}},
            packages={
                "pkg": {
                    "InferenceSpecification": {
                        "Containers": [
                            {
                                "Image": _sm43_image(),
                                "ModelDataUrl": "s3://artifacts/p/model.tar.gz",
                                "ModelDataETag": "p-e",
                            }
                        ]
                    }
                }
            },
        )
        assert _sm43_statuses(rows) == ["Passed"]

    def test_the_second_model_package_container_without_an_etag_fails(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": {"ModelPackageName": "pkg"}}},
            packages={
                "pkg": {
                    "InferenceSpecification": {
                        "Containers": [
                            {
                                "Image": _sm43_image(),
                                "ModelDataUrl": "s3://artifacts/p/one.tar.gz",
                                "ModelDataETag": "p-e",
                            },
                            {
                                "Image": _sm43_image(),
                                "ModelDataUrl": "s3://artifacts/p/two.tar.gz",
                            },
                        ]
                    }
                }
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert (
            "(model package pkg container 2) loads ModelDataUrl s3://artifacts/p/two.tar.gz"
            in details
        )
        assert "one.tar.gz" not in details

    @staticmethod
    def _kms_rules(key_id):
        return {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": key_id,
                    }
                }
            ]
        }

    @pytest.mark.parametrize(
        "key_id, keys",
        [
            ("alias/aws/s3", {}),
            (
                "arn:aws:kms:us-east-1:111122223333:alias/aws/s3",
                {},
            ),
            (
                "arn:aws:kms:us-east-1:111122223333:key/aws-owned",
                {
                    "arn:aws:kms:us-east-1:111122223333:key/aws-owned": {
                        "KeyManager": "AWS",
                        "KeyState": "Enabled",
                    }
                },
            ),
        ],
    )
    @pytest.mark.parametrize("weak_first", [True, False])
    def test_a_named_aws_managed_bucket_key_fails_only_its_endpoint(
        self, key_id, keys, weak_first
    ):
        uris = ["s3://weak/m/", "s3://good/m/"]
        if not weak_first:
            uris.reverse()
        rows = _sm43_rows(
            models={
                "m-1": {"PrimaryContainer": _sm43_container(uri=uris[0])},
                "m-2": {"PrimaryContainer": _sm43_container(uri=uris[1])},
            },
            buckets={"weak": self._kms_rules(key_id)},
            keys=keys,
        )
        weak_endpoint = "ep-1" if weak_first else "ep-2"
        assert _sm43_statuses(rows) == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert details.startswith(f"Endpoint '{weak_endpoint}'")
        assert (
            f"artifact bucket weak: default encryption key {key_id} is an AWS "
            "managed key"
        ) in details
        assert "bucket good" not in details

    def test_a_named_customer_managed_bucket_key_passes(self):
        rows = _sm43_rows(buckets={"artifacts": self._kms_rules("alias/team-key")})
        assert _sm43_statuses(rows) == ["Passed"]

    def test_an_unread_bucket_key_withholds_the_pass(self):
        key_id = "arn:aws:kms:us-east-1:444455556666:key/other"
        rows = _sm43_rows(
            models={
                "m-1": {"PrimaryContainer": _sm43_container(uri="s3://good/m/")},
                "m-2": {"PrimaryContainer": _sm43_container(uri="s3://far/m/")},
            },
            buckets={"far": self._kms_rules(key_id)},
            keys={key_id: _sm43_error("AccessDeniedException")},
        )
        assert _sm43_statuses(rows) == ["N/A"]
        assert (
            f"artifact bucket far encryption was not read (kms:DescribeKey on "
            f"{key_id}: AccessDeniedException)"
        ) in rows[0]["Finding_Details"]

    def test_an_unread_model_package_is_na(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": {"ModelPackageName": "pkg"}}},
            packages={"pkg": _sm43_error("AccessDeniedException")},
        )
        assert _sm43_statuses(rows) == ["N/A"]
        assert (
            "model package pkg was not read (sagemaker:DescribeModelPackage: "
            "AccessDeniedException)"
        ) in rows[0]["Finding_Details"]

    @pytest.mark.parametrize(
        "rules, detail",
        [
            (
                [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}],
                "default encryption is not SSE-KMS (AES256)",
            ),
            (
                [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}],
                "default encryption is SSE-KMS with no KMSMasterKeyID, so it uses "
                "the AWS managed key aws/s3",
            ),
        ],
    )
    def test_the_second_bucket_without_a_named_kms_key_fails(self, rules, detail):
        rows = _sm43_rows(
            models={
                "m-1": {"PrimaryContainer": _sm43_container(uri="s3://good/m/")},
                "m-2": {"PrimaryContainer": _sm43_container(uri="s3://weak/m/")},
            },
            buckets={"weak": {"Rules": rules}},
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert rows[0]["Finding_Details"].startswith("Endpoint 'ep-2'")
        assert f"artifact bucket weak: {detail}" in rows[0]["Finding_Details"]

    def test_a_bucket_with_no_encryption_configuration_fails(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": _sm43_container()}},
            buckets={
                "artifacts": _sm43_error(
                    "ServerSideEncryptionConfigurationNotFoundError"
                )
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert "no default encryption configuration" in rows[0]["Finding_Details"]

    def test_a_denied_bucket_read_is_na(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": _sm43_container()}},
            buckets={"artifacts": _sm43_error("AccessDeniedException")},
        )
        assert _sm43_statuses(rows) == ["N/A"]
        assert (
            "artifact bucket artifacts encryption was not read "
            "(s3:GetEncryptionConfiguration: AccessDeniedException)"
        ) in rows[0]["Finding_Details"]

    def _signing(self, filters=None):
        rule = {"signingProfileArn": "arn:aws:signer:us-east-1:1:/signing-profiles/p"}
        if filters is not None:
            rule["repositoryFilters"] = [
                {"filterType": "WILDCARD_MATCH", "filter": f} for f in filters
            ]
        return {"registryId": _SM43_ACCOUNT, "signingConfiguration": {"rules": [rule]}}

    def test_a_signed_image_passes_and_is_read_by_its_resolved_digest(self):
        image = _sm43_image()
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": _sm43_container(image=image)}},
            signing=self._signing(),
            statuses={"serve": [{"status": "COMPLETE"}]},
            deployed={"ep-1": {image: f"{image.split(':v1')[0]}@{_SM43_DIGEST}"}},
        )
        assert _sm43_statuses(rows) == ["Passed"]
        assert _sm43_rows.signing_calls == [("serve", {"imageDigest": _SM43_DIGEST})]

    def test_an_unsigned_image_under_a_covering_rule_fails(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": _sm43_container()}},
            signing=self._signing(["other", "ser*"]),
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert (
            "image has no managed signing status, though a signing rule covers "
            "repository serve"
        ) in rows[0]["Finding_Details"]
        assert _sm43_rows.signing_calls == [("serve", {"imageTag": "v1"})]

    def test_a_failed_signature_names_its_code(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": _sm43_container()}},
            signing=self._signing(),
            statuses={"serve": [{"status": "FAILED", "failureCode": "KMS_ERROR"}]},
        )
        assert "image failed managed signing (KMS_ERROR)" in rows[0]["Finding_Details"]

    def test_a_rule_that_does_not_cover_the_repository_reads_no_status(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": _sm43_container()}},
            signing=self._signing(["prod/*"]),
        )
        assert _sm43_statuses(rows) == ["Passed"]
        assert _sm43_rows.signing_calls == []

    def test_another_registrys_rule_does_not_cover_the_image(self):
        signing = self._signing()
        signing["registryId"] = "444455556666"
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": _sm43_container()}},
            signing=signing,
        )
        assert _sm43_statuses(rows) == ["Passed"]
        assert _sm43_rows.signing_calls == []

    @pytest.mark.parametrize(
        "signing, statuses, detail",
        [
            (
                _sm43_error("AccessDeniedException"),
                {},
                "image signing rules were not read (ecr:GetSigningConfiguration: "
                "AccessDeniedException)",
            ),
            (
                None,
                {"serve": _sm43_error("AccessDeniedException")},
                "image signing status was not read (ecr:DescribeImageSigningStatus: "
                "AccessDeniedException)",
            ),
            (
                None,
                {"serve": [{"status": "IN_PROGRESS"}]},
                "image signing is IN_PROGRESS",
            ),
        ],
    )
    def test_an_unread_signing_leg_is_na(self, signing, statuses, detail):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"]}},
            models={"m-1": {"PrimaryContainer": _sm43_container()}},
            signing=signing if signing is not None else self._signing(),
            statuses=statuses,
        )
        assert _sm43_statuses(rows) == ["N/A"]
        assert detail in rows[0]["Finding_Details"]

    def test_an_inference_component_model_is_judged(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={"m-ic": {"PrimaryContainer": _sm43_container(etag=None)}},
            components={
                ("ep-1", "ic-variant"): ["ic-1"],
                "ic-1": {"ModelName": "m-ic"},
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert "model 'm-ic' container 1 ModelDataSource" in rows[0]["Finding_Details"]

    def test_an_inference_component_container_artifact_url_fails(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={},
            components={
                ("ep-1", "ic-variant"): ["ic-1"],
                "ic-1": {
                    "Container": {
                        "DeployedImage": {
                            "SpecifiedImage": _sm43_image(tag=None, digest=_SM43_DIGEST)
                        },
                        "ArtifactUrl": "s3://artifacts/ic/model.tar.gz",
                    }
                },
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert (
            "inference component 'ic-1' container loads ModelDataUrl "
            "s3://artifacts/ic/model.tar.gz with no expected value recorded"
        ) in rows[0]["Finding_Details"]

    def _ic_container(self, url=None, image=None):
        container = {"DeployedImage": {"SpecifiedImage": image or _sm43_image()}}
        if url:
            container["ArtifactUrl"] = url
        return {"Container": container}

    def test_only_the_second_component_on_a_variant_fails(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={},
            components={
                ("ep-1", "ic-variant"): ["ic-1", "ic-2"],
                "ic-1": self._ic_container(),
                "ic-2": self._ic_container(url="s3://artifacts/ic2/model.tar.gz"),
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert (
            "inference component 'ic-2' container loads ModelDataUrl "
            "s3://artifacts/ic2/model.tar.gz with no expected value recorded"
        ) in details
        assert "'ic-1'" not in details

    def test_component_endpoints_are_judged_each_on_their_own(self):
        rows = _sm43_rows(
            endpoints={
                "ep-1": {"models": [], "components": ["ic-variant"]},
                "ep-2": {"models": [], "components": ["ic-variant"]},
            },
            models={
                "m-good": {"PrimaryContainer": _sm43_container()},
                "m-bad": {"PrimaryContainer": _sm43_container(etag=None)},
            },
            components={
                ("ep-1", "ic-variant"): ["ic-1"],
                ("ep-2", "ic-variant"): ["ic-2"],
                "ic-1": {"ModelName": "m-good"},
                "ic-2": {"ModelName": "m-bad"},
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert rows[0]["Finding_Details"].startswith("Endpoint 'ep-2' serves")
        assert "model 'm-bad' container 1" in rows[0]["Finding_Details"]

    def test_passing_components_on_two_endpoints_pass(self):
        rows = _sm43_rows(
            endpoints={
                "ep-1": {"models": [], "components": ["ic-variant"]},
                "ep-2": {"models": ["m-1"], "components": ["ic-variant"]},
            },
            models={
                "m-1": {"PrimaryContainer": _sm43_container()},
                "m-ic": {"PrimaryContainer": _sm43_container()},
            },
            components={
                ("ep-1", "ic-variant"): ["ic-1"],
                ("ep-2", "ic-variant"): ["ic-2"],
                "ic-1": {"ModelName": "m-ic"},
                "ic-2": {"ModelName": "m-ic"},
            },
        )
        assert _sm43_statuses(rows) == ["Passed"]
        assert "2 InService endpoint(s)" in rows[0]["Finding_Details"]

    def test_every_specification_of_a_multi_spec_component_is_judged(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={
                "m-gpu": {"PrimaryContainer": _sm43_container()},
                "m-cpu": {"PrimaryContainer": _sm43_container(etag=None)},
            },
            components={
                ("ep-1", "ic-variant"): ["ic-1"],
                "ic-1": {
                    "Specifications": [
                        {"InstanceType": "ml.g5.xlarge", "ModelName": "m-gpu"},
                        {"InstanceType": "ml.c5.xlarge", "ModelName": "m-cpu"},
                    ]
                },
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        details = rows[0]["Finding_Details"]
        assert "model 'm-cpu' container 1" in details
        assert "m-gpu" not in details

    def test_a_component_with_nothing_to_judge_is_na(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={},
            components={
                ("ep-1", "ic-variant"): ["ic-1"],
                "ic-1": {"BaseInferenceComponentName": "base"},
            },
        )
        assert _sm43_statuses(rows) == ["N/A"]
        assert (
            "inference component 'ic-1' returned no model name, image or artifact "
            "URL to judge"
        ) in rows[0]["Finding_Details"]

    def test_a_component_of_another_endpoint_is_not_charged_to_this_one(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={
                "m-good": {"PrimaryContainer": _sm43_container()},
                "m-bad": {"PrimaryContainer": _sm43_container(etag=None)},
            },
            components={
                ("ep-1", "ic-variant"): [
                    {"InferenceComponentName": "ic-1", "EndpointName": "ep-1"},
                    {"InferenceComponentName": "ic-x", "EndpointName": "ep-other"},
                ],
                "ic-1": {"ModelName": "m-good"},
                "ic-x": {"ModelName": "m-bad"},
            },
        )
        assert _sm43_statuses(rows) == ["Passed"]

    @pytest.mark.parametrize("status", ["Failed", "Deleting", "Creating"])
    def test_a_component_not_in_service_is_not_judged(self, status):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={
                "m-good": {"PrimaryContainer": _sm43_container()},
                "m-bad": {"PrimaryContainer": _sm43_container(etag=None)},
            },
            components={
                ("ep-1", "ic-variant"): [
                    {
                        "InferenceComponentName": "ic-1",
                        "InferenceComponentStatus": "InService",
                    },
                    {
                        "InferenceComponentName": "ic-2",
                        "InferenceComponentStatus": status,
                    },
                ],
                "ic-1": {"ModelName": "m-good"},
                "ic-2": {"ModelName": "m-bad"},
            },
        )
        assert _sm43_statuses(rows) == ["Passed"]

    def test_an_in_service_component_listed_second_is_judged(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={
                "m-good": {"PrimaryContainer": _sm43_container()},
                "m-bad": {"PrimaryContainer": _sm43_container(etag=None)},
            },
            components={
                ("ep-1", "ic-variant"): [
                    {
                        "InferenceComponentName": "ic-1",
                        "InferenceComponentStatus": "Failed",
                    },
                    {
                        "InferenceComponentName": "ic-2",
                        "InferenceComponentStatus": "InService",
                    },
                ],
                "ic-1": {"ModelName": "m-good"},
                "ic-2": {"ModelName": "m-bad"},
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert "model 'm-bad' container 1" in rows[0]["Finding_Details"]

    def test_a_component_artifact_url_failure_says_to_deploy_from_a_model(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={},
            components={
                ("ep-1", "ic-variant"): ["ic-1"],
                "ic-1": self._ic_container(url="s3://artifacts/ic/model.tar.gz"),
            },
        )
        assert _sm43_statuses(rows) == ["Failed"]
        assert (
            "An inference component whose container names an S3 ArtifactUrl has no "
            "ETag field to record one, so create the component from a model "
            "(ModelName) whose container loads its data through ModelDataSource "
            "with the ETag recorded."
        ) in rows[0]["Resolution"]

    def test_unread_inference_components_are_na(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={},
            components={("ep-1", "ic-variant"): _sm43_error("AccessDeniedException")},
        )
        assert _sm43_statuses(rows) == ["N/A"]
        assert (
            "inference components of variant ic-variant were not read "
            "(sagemaker:ListInferenceComponents: AccessDeniedException)"
        ) in rows[0]["Finding_Details"]

    def test_a_denied_component_describe_names_its_permission(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": [], "components": ["ic-variant"]}},
            models={},
            components={
                ("ep-1", "ic-variant"): ["ic-1"],
                "ic-1": _sm43_error("AccessDeniedException"),
            },
        )
        assert _sm43_statuses(rows) == ["N/A"]
        assert (
            "(sagemaker:DescribeInferenceComponent: AccessDeniedException)"
        ) in rows[0]["Finding_Details"]

    def test_endpoints_not_in_service_are_skipped(self):
        rows = _sm43_rows(
            endpoints={"ep-1": {"models": ["m-1"], "status": "Creating"}},
        )
        assert _sm43_statuses(rows) == ["N/A"]
        assert "No InService SageMaker endpoints" in rows[0]["Finding_Details"]

    def test_no_endpoints_is_na(self):
        rows = _sm43_rows(endpoints={})
        assert _sm43_statuses(rows) == ["N/A"]

    def test_a_failed_inventory_is_could_not_assess(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            mock_client.return_value.get_paginator.side_effect = _sm43_error(
                "AccessDeniedException"
            )
            rows = _rows(
                sagemaker_app.check_sagemaker_model_artifact_integrity("us-east-1")
            )
        assert _sm43_statuses(rows) == ["N/A"]
        assert rows[0]["Check_ID"] == "SM-43"

    def test_rows_match_the_schema(self):
        for row in _sm43_rows(
            models={
                "m-1": {"PrimaryContainer": _sm43_container(etag=None)},
                "m-2": _sm43_error("AccessDeniedException"),
            }
        ):
            assert_finding_schema(row)

    def test_the_handler_runs_sm43(self):
        source = open(os.path.join(_sm_dir, "app.py")).read()
        handler = source[source.index("def lambda_handler") :]
        assert "check_sagemaker_model_artifact_integrity(region=region)" in handler
