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
        mock_sm.describe_notebook_instance.return_value = {
            "DirectInternetAccess": "Disabled",
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


class TestProposedSageMakerChecks:
    """SM-26 through SM-30 proposal checks (SM-29 remains reserved/deferred)."""

    def test_sm26_ai_protection_enabled_passes(self):
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

    def test_sm26_ai_protection_disabled_fails(self):
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

    # SM-28 now reads the route tables of the effective VPC subnets, so boto3 is
    # patched here to keep this unit test off the network.
    @patch("sagemaker_app.boto3.client")
    def test_sm27_and_sm28_share_hyperpod_inventory(self, mock_client):
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
                                            "VolumeKmsKeyId": "arn:kms:key-1",
                                        }
                                    },
                                    {
                                        "EbsVolumeConfig": {
                                            "RootVolume": False,
                                            "VolumeKmsKeyId": "arn:kms:key-2",
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
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

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
    def test_approval_description_alone_counts_as_attribution(self, mock_client):
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
        assert [f["Status"] for f in rows] == ["Passed"]
        assert "CAB-4412" in rows[0]["Finding_Details"]

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
    def test_describe_count_is_capped(self, mock_client):
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
        assert (
            mock_sm.describe_model_package.call_count
            == sagemaker_app.MAX_APPROVAL_ATTRIBUTION_DESCRIBES
        )


class TestSM31EndpointDataCapture:
    """AIR-SGM-EP-06: SM-31 asserts inference data capture per endpoint."""

    @staticmethod
    def _endpoints(mock_client, endpoints):
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Endpoints": [{"EndpointName": name} for name in endpoints]}
        ]
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
                }
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


def _raise(error):
    raise error


class TestSM32ConfigComplianceEvaluation:
    """AIR-SGM-GOV-10: SM-32 asserts Config recording and rule evaluation."""

    @staticmethod
    def _config(mock_client, recorders, rules, compliance):
        config_client = MagicMock()
        config_client.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": recorders
        }
        rule_paginator = MagicMock()
        rule_paginator.paginate.return_value = [{"ConfigRules": rules}]
        compliance_paginator = MagicMock()
        compliance_paginator.paginate.return_value = [
            {"ComplianceByConfigRules": compliance}
        ]
        config_client.get_paginator.side_effect = lambda name: (
            rule_paginator if name == "describe_config_rules" else compliance_paginator
        )
        mock_client.return_value = config_client
        return config_client

    def test_recorder_and_compliant_rule_pass(self):
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
                [
                    {
                        "ConfigRuleName": "sagemaker-notebook-no-direct-internet",
                        "ConfigRuleState": "ACTIVE",
                        "Source": {
                            "Owner": "AWS",
                            "SourceIdentifier": (
                                "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS"
                            ),
                        },
                    }
                ],
                [
                    {
                        "ConfigRuleName": "sagemaker-notebook-no-direct-internet",
                        "Compliance": {"ComplianceType": "COMPLIANT"},
                    }
                ],
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

    def test_no_recorder_is_indeterminate_and_no_rule_still_fails(self):
        with patch("sagemaker_app.boto3.client") as mock_client:
            self._config(mock_client, [], [], [])
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_config_compliance_evaluation(
                    region="us-east-1"
                )
            )
        # An empty no-arg DescribeConfigurationRecorders hides a service-linked
        # recorder, so it cannot carry a Failed on its own. The rule leg is
        # independent and still fails.
        assert [f["Status"] for f in findings] == ["N/A", "Failed"]
        assert (
            "no customer-managed AWS Config recorder" in findings[0]["Finding_Details"]
        )
        assert (
            "returned only when the call names its ServicePrincipal"
            in findings[0]["Finding_Details"]
        )
        assert "No ACTIVE AWS Config rule" in findings[1]["Finding_Details"]

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
        assert "2 most recent" in passed[0]["Finding_Details"]
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
    def test_sample_is_bounded_to_the_most_recent_jobs(self, mock_client):
        _, paginator = self._jobs(mock_client, {})
        sagemaker_app.check_sagemaker_training_job_network_boundary(region="us-east-1")
        paginator.paginate.assert_called_once_with(
            SortBy="CreationTime",
            SortOrder="Descending",
            PaginationConfig={"MaxItems": sagemaker_app.MAX_TRAINING_JOBS_SAMPLED},
        )

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


class TestSM34CreationGuardrails:
    """AIR-SGM-TRN-08: SM-34 asserts an SCP blocks non-compliant creation."""

    @staticmethod
    def _management_account_clients():
        orgs = MagicMock()
        orgs.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        return _sm_client_factory(organizations=orgs, sts=sts)

    def _run(self, inventory):
        with patch(
            "sagemaker_app.boto3.client",
            side_effect=self._management_account_clients(),
        ):
            return extract_csv_data(
                sagemaker_app.check_sagemaker_creation_guardrails(
                    region="Global", scp_inventory=inventory
                )
            )

    @staticmethod
    def _inventory(*documents):
        return {
            "items": [
                {"name": name, "id": f"p-{index}", "content": json.dumps(document)}
                for index, (name, document) in enumerate(documents)
            ],
            "errors": [],
            "list_error": None,
        }

    def test_encryption_guard_passes_while_network_and_internet_fail(self):
        findings = self._run(
            self._inventory(
                (
                    "RequireTrainingVolumeKey",
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "sagemaker:CreateTrainingJob",
                                "Resource": "*",
                                "Condition": {
                                    "Null": {"sagemaker:VolumeKmsKey": "true"}
                                },
                            }
                        ],
                    },
                )
            )
        )
        by_status = {}
        for f in findings:
            by_status.setdefault(f["Status"], []).append(f["Finding_Details"])
        assert len(by_status["Passed"]) == 1
        assert "encryption" in by_status["Passed"][0]
        assert "RequireTrainingVolumeKey" in by_status["Passed"][0]
        assert len(by_status["Failed"]) == 2
        failed = " | ".join(by_status["Failed"])
        assert "approved network" in failed
        assert "no direct internet access" in failed
        for f in findings:
            assert f["Check_ID"] == "SM-34"
            assert_finding_schema(f)

    def test_all_three_guardrails_can_pass(self):
        findings = self._run(
            self._inventory(
                (
                    "SageMakerCreationGuardrails",
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "sagemaker:Create*",
                                "Resource": "*",
                                "Condition": {
                                    "Null": {
                                        "sagemaker:VolumeKmsKey": "true",
                                        "sagemaker:VpcSubnets": "true",
                                    },
                                    "StringNotEquals": {
                                        "sagemaker:DirectInternetAccess": "Disabled"
                                    },
                                },
                            }
                        ],
                    },
                )
            )
        )
        assert [f["Status"] for f in findings] == ["Passed", "Passed", "Passed"]

    def test_positive_value_deny_is_reported_as_indeterminate(self):
        findings = self._run(
            self._inventory(
                (
                    "DenyOneKey",
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "sagemaker:CreateTrainingJob",
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "sagemaker:VolumeKmsKey": (
                                            "arn:aws:kms:::key/legacy"
                                        )
                                    }
                                },
                            }
                        ],
                    },
                )
            )
        )
        indeterminate = [f for f in findings if f["Status"] == "N/A"]
        assert len(indeterminate) == 1
        assert "depends on that value" in indeterminate[0]["Finding_Details"]
        assert "DenyOneKey" in indeterminate[0]["Finding_Details"]

    def test_allow_statement_does_not_count_as_a_guardrail(self):
        findings = self._run(
            self._inventory(
                (
                    "AllowWithCondition",
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sagemaker:CreateTrainingJob",
                                "Resource": "*",
                                "Condition": {
                                    "Null": {"sagemaker:VolumeKmsKey": "true"}
                                },
                            }
                        ],
                    },
                )
            )
        )
        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Failed"]

    def test_deny_on_an_unrelated_service_does_not_count(self):
        findings = self._run(
            self._inventory(
                (
                    "DenyBedrock",
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "bedrock:InvokeModel",
                                "Resource": "*",
                                "Condition": {
                                    "Null": {"sagemaker:VolumeKmsKey": "true"}
                                },
                            }
                        ],
                    },
                )
            )
        )
        assert [f["Status"] for f in findings] == ["Failed", "Failed", "Failed"]

    def test_member_account_run_reports_unassessed(self):
        orgs = MagicMock()
        orgs.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "999999999999"}
        }
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        with patch(
            "sagemaker_app.boto3.client",
            side_effect=_sm_client_factory(organizations=orgs, sts=sts),
        ):
            findings = extract_csv_data(
                sagemaker_app.check_sagemaker_creation_guardrails(region="Global")
            )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "management account" in findings[0]["Finding_Details"]

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
            {"items": [], "errors": [], "list_error": "AccessDeniedException"}
        )
        assert [f["Status"] for f in findings] == ["N/A"]
        assert "could not be listed" in findings[0]["Finding_Details"]


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
