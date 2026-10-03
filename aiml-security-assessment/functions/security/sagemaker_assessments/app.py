import boto3
import csv
import fnmatch
import ipaddress
import os
import logging
from datetime import datetime, timedelta, timezone
import time
from typing import Dict, List, Any, Optional, Iterator, Tuple
from io import StringIO
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError
import random
import json
from functools import lru_cache
import re

# TO DO PYDANTIC SUPPORT
from schema import create_finding

# Configure boto3 with retries
boto3_config = Config(
    retries=dict(
        max_attempts=10,  # Maximum number of retries
        mode="adaptive",  # Exponential backoff with adaptive mode
    )
)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

# IAM is a global service. Findings derived purely from the IAM permission cache
# (e.g. the SM-02 full-access and stale-access checks) are identical across
# regions, so they are produced only on the primary region (Map index 0) and
# tagged with this region label to avoid duplicate findings when scanning
# multiple regions.
GLOBAL_REGION_LABEL = "Global"


def _caller_identity_partition(caller_identity: Dict[str, Any]) -> str:
    """Return the STS ARN partition, defaulting safely for incomplete identities."""
    arn = caller_identity.get("Arn")
    if not isinstance(arn, str):
        return "aws"
    parts = arn.split(":", 2)
    if len(parts) < 3 or parts[0] != "arn" or not parts[1]:
        return "aws"
    return parts[1]


# Error codes returned when a region exists but is not enabled/usable for the
# account (opt-in regions, disabled regions). The availability probe treats
# these the same as an endpoint connection failure.
REGION_UNAVAILABLE_ERROR_CODES = {
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "AuthFailure",
    "OptInRequired",
}

ACCESS_DENIED_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
}

COULD_NOT_ASSESS_RESOLUTION = (
    "No action required on the assessed workload. Resolve the assessment "
    "prerequisite or permission issue and rerun the assessment."
)

MAX_LINEAGE_FINDINGS = 5


def get_assessment_error_label(error: Exception) -> str:
    """Return a report-safe error label without leaking raw exception text."""
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        if code:
            return code
    if isinstance(error, EndpointConnectionError):
        return "EndpointConnectionError"
    return type(error).__name__


def build_could_not_assess_detail(error: Exception, region: str = "") -> str:
    """Build a standardized N/A detail for scanner/tooling failures."""
    location = f" in {region}" if region else ""
    return (
        f"Could not assess this check{location}. Assessment error: "
        f"{get_assessment_error_label(error)}."
    )


def _unread_resources_finding(
    check_id: str,
    finding_name: str,
    unread: List[str],
    read_details: str,
    reference: str,
    region: str,
) -> Dict[str, Any]:
    """
    Report a population claim as N/A because some of its members were not read.

    A Passed row over a partly read population would hide exactly the members
    the scan could not see, so the row names them instead.
    """
    shown = "; ".join(unread[:10])
    if len(unread) > 10:
        shown += f"; and {len(unread) - 10} more"
    return create_finding(
        check_id=check_id,
        finding_name=f"{finding_name} Incomplete",
        finding_details=(
            f"{len(unread)} read(s) failed, so this result was not established "
            f"for them: {shown}. For what was read: {read_details}"
        ),
        resolution=COULD_NOT_ASSESS_RESOLUTION,
        reference=reference,
        severity="Informational",
        status="N/A",
        region=region,
    )


# DescribeSubnets and DescribeRouteTables accept up to 200 filter values; 100
# keeps each request well inside that bound while still batching.
SUBNET_LOOKUP_BATCH_SIZE = 100
MAX_SUBNET_EXPOSURE_FINDINGS = 20


def _chunked(values: List[str], size: int) -> Iterator[List[str]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _route_reaches_internet_gateway(route: Dict[str, Any]) -> bool:
    """Whether one route table entry hands traffic to an internet gateway.

    An egress-only gateway (``eigw-``), a NAT gateway or a peering connection is
    not an internet gateway: none of them accepts inbound connections, and AWS
    calls a subnet private exactly when no route reaches an ``igw-``. A blackhole
    route names a deleted gateway and carries no traffic.
    """
    if route.get("State") == "blackhole":
        return False
    return str(route.get("GatewayId") or "").startswith("igw-")


def _route_destination(route: Dict[str, Any]) -> str:
    return (
        route.get("DestinationCidrBlock")
        or route.get("DestinationIpv6CidrBlock")
        or route.get("DestinationPrefixListId")
        or "an unnamed destination"
    )


def resolve_subnet_internet_exposure(
    subnet_ids: List[str], region: str = ""
) -> Dict[str, Any]:
    """Classify subnets by whether their route table reaches an internet gateway.

    A subnet id in a workload's VpcConfig says the workload is attached to a
    customer network; it does not say that network is private. This resolves the
    route table that actually applies to each subnet, preferring an explicit
    subnet association and falling back to the VPC main route table, which is
    what an unassociated subnet uses.

    Returns ``public`` as subnet id -> the route that exposes it, ``private`` as
    the subnet ids whose applicable route table was read and has no such route,
    ``unresolved`` as the subnet ids no route table could be found for, and
    ``error`` as a report-safe label when the EC2 sweep itself failed.
    """
    unique = sorted({subnet_id for subnet_id in subnet_ids if subnet_id})
    exposure = {
        "public": {},
        "private": set(),
        "unresolved": set(unique),
        "error": None,
    }
    if not unique:
        return exposure

    try:
        ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)

        subnet_vpcs = {}
        subnet_paginator = ec2_client.get_paginator("describe_subnets")
        for chunk in _chunked(unique, SUBNET_LOOKUP_BATCH_SIZE):
            # Filters tolerate an id that no longer exists; SubnetIds= raises
            # InvalidSubnetID.NotFound and loses the whole batch with it.
            for page in subnet_paginator.paginate(
                Filters=[{"Name": "subnet-id", "Values": chunk}]
            ):
                for subnet in page.get("Subnets", []):
                    if subnet.get("SubnetId"):
                        subnet_vpcs[subnet["SubnetId"]] = subnet.get("VpcId")

        vpc_ids = sorted({vpc_id for vpc_id in subnet_vpcs.values() if vpc_id})
        explicit_tables = {}
        main_tables = {}
        route_paginator = ec2_client.get_paginator("describe_route_tables")
        for chunk in _chunked(vpc_ids, SUBNET_LOOKUP_BATCH_SIZE):
            for page in route_paginator.paginate(
                Filters=[{"Name": "vpc-id", "Values": chunk}]
            ):
                for table in page.get("RouteTables", []):
                    for association in table.get("Associations", []):
                        if association.get("SubnetId"):
                            explicit_tables[association["SubnetId"]] = table
                        elif association.get("Main") is True and table.get("VpcId"):
                            main_tables[table["VpcId"]] = table

        for subnet_id, vpc_id in subnet_vpcs.items():
            table = explicit_tables.get(subnet_id) or main_tables.get(vpc_id)
            if table is None:
                continue
            exposure["unresolved"].discard(subnet_id)
            exposing = next(
                (
                    route
                    for route in table.get("Routes", [])
                    if _route_reaches_internet_gateway(route)
                ),
                None,
            )
            if exposing is None:
                exposure["private"].add(subnet_id)
            else:
                exposure["public"][subnet_id] = {
                    "gateway": exposing.get("GatewayId"),
                    "destination": _route_destination(exposing),
                    "route_table": table.get("RouteTableId", "unknown"),
                }
    except Exception as error:
        logger.warning(f"Error resolving subnet internet exposure: {str(error)}")
        exposure["error"] = get_assessment_error_label(error)

    return exposure


def _subnet_exposure_findings(
    check_id: str,
    finding_name: str,
    resources: List[Dict[str, Any]],
    region: str,
    reference: str,
    resolution: str,
    severity: str,
) -> List[Dict[str, Any]]:
    """Report AIR-FND-NET-01 for resources already known to be in a VPC.

    ``resources`` entries carry ``name``, a phrase naming the resource as the
    report should read, and ``subnets``. Public, private and unreadable
    resources are reported separately, so one public resource cannot suppress
    the passing verdict the private ones earned.
    """
    emitted: List[Dict[str, Any]] = []
    if not resources:
        return emitted

    exposure = resolve_subnet_internet_exposure(
        [subnet for resource in resources for subnet in resource.get("subnets", [])],
        region,
    )
    if exposure["error"]:
        return [
            create_finding(
                check_id=check_id,
                finding_name=f"{finding_name} Incomplete",
                finding_details=(
                    f"The subnets of {len(resources)} resource(s) could not be "
                    "checked for an internet gateway route. Assessment error: "
                    f"{exposure['error']}."
                ),
                resolution=(
                    "Grant ec2:DescribeSubnets and ec2:DescribeRouteTables to the "
                    "assessment role and rerun the assessment."
                ),
                reference=reference,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]

    public_resources = []
    private_resources = []
    unresolved_resources = []
    for resource in resources:
        subnets = list(resource.get("subnets", []))
        exposed = {
            subnet: exposure["public"][subnet]
            for subnet in subnets
            if subnet in exposure["public"]
        }
        if exposed:
            public_resources.append((resource, exposed))
        elif all(subnet in exposure["private"] for subnet in subnets):
            private_resources.append(resource)
        else:
            unresolved_resources.append(resource)

    for resource, exposed in public_resources[:MAX_SUBNET_EXPOSURE_FINDINGS]:
        described = "; ".join(
            f"{subnet} routes {route['destination']} to {route['gateway']} "
            f"through route table {route['route_table']}"
            for subnet, route in sorted(exposed.items())
        )
        emitted.append(
            create_finding(
                check_id=check_id,
                finding_name=finding_name,
                finding_details=(
                    f"{resource['name']} runs in a public subnet: {described}. The "
                    "VPC attachment alone is not a privacy claim while a subnet "
                    "carrying the workload has a route to an internet gateway."
                ),
                resolution=resolution,
                reference=reference,
                severity=severity,
                status="Failed",
                region=region,
            )
        )

    if len(public_resources) > MAX_SUBNET_EXPOSURE_FINDINGS:
        emitted.append(
            create_finding(
                check_id=check_id,
                finding_name=finding_name,
                finding_details=(
                    f"{len(public_resources)} resource(s) run in subnets with a "
                    f"route to an internet gateway (the first "
                    f"{MAX_SUBNET_EXPOSURE_FINDINGS} are reported individually "
                    "above)."
                ),
                resolution=resolution,
                reference=reference,
                severity=severity,
                status="Failed",
                region=region,
            )
        )

    if private_resources:
        named = ", ".join(resource["name"] for resource in private_resources[:3])
        remainder = (
            f" and {len(private_resources) - 3} more"
            if len(private_resources) > 3
            else ""
        )
        emitted.append(
            create_finding(
                check_id=check_id,
                finding_name=finding_name,
                finding_details=(
                    f"{len(private_resources)} resource(s) run only in subnets "
                    "whose route tables have no route to an internet gateway: "
                    f"{named}{remainder}."
                ),
                resolution="No action required",
                reference=reference,
                severity=severity,
                status="Passed",
                region=region,
            )
        )

    if unresolved_resources:
        unreadable = sorted(
            {
                subnet
                for resource in unresolved_resources
                for subnet in resource.get("subnets", [])
                if subnet in exposure["unresolved"]
            }
        )
        emitted.append(
            create_finding(
                check_id=check_id,
                finding_name=f"{finding_name} Incomplete",
                finding_details=(
                    f"{len(unresolved_resources)} resource(s) could not be checked "
                    "for an internet gateway route because no route table was "
                    f"found for subnet(s) {', '.join(unreadable) or 'they reference'}."
                ),
                resolution=(
                    "Confirm those subnets still exist and that the assessment "
                    "role holds ec2:DescribeSubnets and ec2:DescribeRouteTables, "
                    "then rerun the assessment."
                ),
                reference=reference,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )

    return emitted


def iter_model_packages(sagemaker_client, group_name: str) -> Iterator[Dict[str, Any]]:
    """Yield every model package in a SageMaker model package group."""
    paginator = sagemaker_client.get_paginator("list_model_packages")
    for page in paginator.paginate(ModelPackageGroupName=group_name):
        yield from page.get("ModelPackageSummaryList", [])


def list_all_model_packages(sagemaker_client, group_name: str) -> List[Dict[str, Any]]:
    """Return every model package in a SageMaker model package group."""
    return list(iter_model_packages(sagemaker_client, group_name))


def get_model_package_lineage_artifact_arn(
    sagemaker_client, model_package_arn: str
) -> Optional[str]:
    """Resolve a model package ARN to its SageMaker lineage artifact ARN."""
    response = sagemaker_client.list_artifacts(
        SourceUri=model_package_arn, MaxResults=1
    )
    artifacts = response.get("ArtifactSummaries", [])
    if not artifacts:
        return None
    return artifacts[0].get("ArtifactArn")


def has_lineage_associations(sagemaker_client, artifact_arn: str) -> bool:
    """Return whether a lineage artifact participates in any association."""
    source_response = sagemaker_client.list_associations(
        SourceArn=artifact_arn, MaxResults=1
    )
    if source_response.get("AssociationSummaries"):
        return True

    destination_response = sagemaker_client.list_associations(
        DestinationArn=artifact_arn, MaxResults=1
    )
    return bool(destination_response.get("AssociationSummaries"))


def get_guardduty_detector_inventory(region: str = "") -> Dict[str, Any]:
    """Retrieve the regional GuardDuty detector and detail once."""
    inventory = {"detector_id": None, "detail": None, "error": None}
    try:
        client = boto3.client("guardduty", config=boto3_config, region_name=region)
        detector_ids = client.list_detectors(MaxResults=1).get("DetectorIds", [])
        if not detector_ids:
            return inventory
        inventory["detector_id"] = detector_ids[0]
        inventory["detail"] = client.get_detector(DetectorId=detector_ids[0])
    except Exception as error:
        inventory["error"] = error
    return inventory


def get_hyperpod_cluster_inventory(region: str = "") -> Dict[str, Any]:
    """List HyperPod clusters once and isolate per-cluster detail failures."""
    inventory = {"items": [], "errors": [], "list_error": None}
    try:
        client = boto3.client("sagemaker", config=boto3_config, region_name=region)
        paginator = client.get_paginator("list_clusters")
        summaries = []
        for page in paginator.paginate():
            summaries.extend(page.get("ClusterSummaries", []))
        for summary in summaries:
            cluster_name = summary.get("ClusterName")
            if not cluster_name:
                continue
            try:
                inventory["items"].append(
                    {
                        "summary": summary,
                        "detail": client.describe_cluster(ClusterName=cluster_name),
                    }
                )
            except Exception as error:
                inventory["errors"].append({"summary": summary, "error": error})
    except Exception as error:
        inventory["list_error"] = error
    return inventory


def list_model_package_group_summaries(
    sagemaker_client,
) -> List[Dict[str, Any]]:
    """Return every SageMaker model package group summary."""
    groups = []
    paginator = sagemaker_client.get_paginator("list_model_package_groups")
    for page in paginator.paginate():
        groups.extend(page.get("ModelPackageGroupSummaryList", []))
    return groups


def _is_valid_permissions_cache(cache: Any) -> bool:
    """Return whether cache has the IAM inventory shape produced upstream."""
    return (
        isinstance(cache, dict)
        and isinstance(cache.get("role_permissions"), dict)
        and isinstance(cache.get("user_permissions"), dict)
    )


def get_permissions_cache(execution_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve and parse the permissions cache JSON file from S3

    Args:
        execution_id (str): Step Functions execution ID

    Returns:
        Optional[Dict[str, Any]]: Parsed permissions cache as dictionary, None if not found or error
    """
    try:
        s3_client = boto3.client("s3", config=boto3_config)
        s3_key = f"permissions_cache_{execution_id}.json"
        s3_bucket = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")

        logger.info(f"Retrieving permissions cache from s3://{s3_bucket}/{s3_key}")

        try:
            # Get the JSON file from S3
            response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)

            # Read and parse the JSON content
            json_content = response["Body"].read().decode("utf-8")
            permissions_cache = json.loads(json_content)

            if not _is_valid_permissions_cache(permissions_cache):
                logger.error(
                    "Permissions cache has an invalid schema for execution "
                    f"{execution_id}"
                )
                return None

            logger.info(
                f"Successfully retrieved permissions cache for execution {execution_id}"
            )
            return permissions_cache

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                logger.warning(
                    f"Permissions cache not found: s3://{s3_bucket}/{s3_key}"
                )
            elif e.response["Error"]["Code"] == "NoSuchBucket":
                logger.error(f"Bucket not found: {s3_bucket}")
            else:
                logger.error(
                    f"AWS error retrieving permissions cache: {str(e)}", exc_info=True
                )
            return None

    except json.JSONDecodeError as e:
        logger.error(f"Error parsing permissions cache JSON: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error retrieving permissions cache: {str(e)}", exc_info=True
        )
        return None


def _permission_cache_unavailable_result(region: str) -> Dict[str, Any]:
    """Emit an explicit incomplete row for the cache-dependent SageMaker control."""
    details = (
        "The IAM permissions cache is missing, unreadable, or malformed, so the "
        "SageMaker IAM permissions and stale-access control could not be assessed."
    )
    return {
        "check_name": "SageMaker IAM Permissions Check",
        "status": "N/A",
        "details": details,
        "csv_data": [
            create_finding(
                check_id="SM-02",
                finding_name="SageMaker IAM Permissions Check Incomplete",
                finding_details=details,
                resolution=(
                    "Review the IAM Permission Caching task and the execution-scoped "
                    "permissions_cache_<execution-id>.json object, then rerun the "
                    "assessment."
                ),
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
                severity="Informational",
                status="N/A",
                region=region,
            )
        ],
    }


def _iam_action_matches(pattern: str, action: str) -> bool:
    """Return whether an IAM action pattern (with * and ?) matches an action."""
    return fnmatch.fnmatchcase(action.lower(), pattern.strip().lower())


def _statement_allows_action(statement: Dict[str, Any], action: str) -> bool:
    """Return whether an Allow statement's Action or NotAction reaches action."""
    if str(statement.get("Effect", "")).upper() != "ALLOW":
        return False
    if "Action" in statement:
        return any(
            _iam_action_matches(p, action) for p in _policy_values(statement["Action"])
        )
    if "NotAction" in statement:
        return not any(
            _iam_action_matches(p, action)
            for p in _policy_values(statement["NotAction"])
        )
    return False


def _boundary_allows_every_sagemaker_action(boundary: Any) -> bool:
    """
    Return whether a permissions boundary leaves every SageMaker action granted.

    A boundary is an intersection with the identity policy. No boundary leaves
    the identity policy as it is. Boundary Deny statements are ignored, which can
    only overstate a grant.
    """
    if boundary is None:
        return True
    for statement in _sm_policy_statements(boundary):
        if str(statement.get("Effect", "")).upper() != "ALLOW":
            continue
        if any(
            _pattern_covers_all_sagemaker_actions(p)
            for p in _policy_values(statement.get("Action"))
        ):
            return True
        if "NotAction" in statement and not any(
            _pattern_may_match_sagemaker(p)
            for p in _policy_values(statement.get("NotAction"))
        ):
            return True
    return False


def _literal_prefix(pattern: str) -> str:
    """Return the part of an IAM pattern before its first wildcard, lowercased."""
    return re.split(r"[*?]", pattern.strip().lower(), maxsplit=1)[0]


def _pattern_may_match_sagemaker(pattern: str) -> bool:
    """Return whether an action pattern can match at least one sagemaker: action."""
    prefix = _literal_prefix(pattern)
    return "sagemaker:".startswith(prefix) or prefix.startswith("sagemaker:")


def check_sagemaker_internet_access(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker notebook instances and domains have direct internet access
    """
    logger.debug("Starting check for SageMaker direct internet access")
    try:
        findings = {"csv_data": []}

        instances_with_direct_access = []
        instances_outside_vpc = []
        domains_with_direct_access = []
        total_resources_checked = 0
        # AIR-SGM-TRN-05: a failed read is named in an Incomplete row and
        # withholds the Passed row.
        unread = []

        # Create SageMaker client
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        # Check Notebook Instances
        try:
            paginator = sagemaker_client.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for instance in page.get("NotebookInstances", []):
                    instance_name = instance.get("NotebookInstanceName")
                    if instance_name:
                        # Get detailed information about the notebook instance
                        try:
                            instance_details = (
                                sagemaker_client.describe_notebook_instance(
                                    NotebookInstanceName=instance_name
                                )
                            )
                        except Exception as e:
                            unread.append(
                                f"sagemaker:DescribeNotebookInstance {instance_name} "
                                f"({get_assessment_error_label(e)})"
                            )
                            continue

                        # The Passed text claims VPC placement, so it is read:
                        # a notebook without SubnetId runs on SageMaker's network.
                        if not instance_details.get("SubnetId"):
                            instances_outside_vpc.append(instance_name)

                        # Check if direct internet access is enabled
                        if instance_details.get("DirectInternetAccess") == "Enabled":
                            instances_with_direct_access.append(
                                {
                                    "name": instance_name,
                                    "subnet_id": instance_details.get(
                                        "SubnetId", "N/A"
                                    ),
                                    "vpc_id": instance_details.get("VpcId", "N/A"),
                                }
                            )
                        total_resources_checked += 1
        except Exception as e:
            logger.error(f"Error checking notebook instances: {str(e)}")
            unread.append(
                f"sagemaker:ListNotebookInstances ({get_assessment_error_label(e)})"
            )

        # Check SageMaker Domains
        try:
            paginator = sagemaker_client.get_paginator("list_domains")
            for page in paginator.paginate():
                for domain in page.get("Domains", []):
                    domain_id = domain.get("DomainId")
                    if domain_id:
                        # Get detailed information about the domain
                        try:
                            domain_details = sagemaker_client.describe_domain(
                                DomainId=domain_id
                            )
                        except Exception as e:
                            unread.append(
                                f"sagemaker:DescribeDomain {domain_id} "
                                f"({get_assessment_error_label(e)})"
                            )
                            continue

                        vpc_id = domain_details.get("DomainSettings", {}).get(
                            "SecurityGroupIds", ["N/A"]
                        )[0]
                        domain_name = domain_details.get("DomainName", "N/A")

                        # Check network access type
                        if domain_details.get("AppNetworkAccessType") != "VpcOnly":
                            domains_with_direct_access.append(
                                {
                                    "domain_id": domain_id,
                                    "name": domain_name,
                                    "vpc_id": vpc_id,
                                }
                            )
                        total_resources_checked += 1
        except Exception as e:
            logger.error(f"Error checking domains: {str(e)}")
            unread.append(f"sagemaker:ListDomains ({get_assessment_error_label(e)})")

        # Generate findings
        if (
            instances_with_direct_access
            or domains_with_direct_access
            or instances_outside_vpc
        ):
            findings["status"] = "WARN"

            # Add findings for notebook instances
            for instance in instances_with_direct_access:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
                        finding_name="Direct Internet Access Enabled",
                        finding_details=f"SageMaker notebook instance '{instance['name']}' has direct internet access enabled",
                        resolution="Configure the notebook instance to use VPC connectivity and disable direct internet access",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )

            for instance_name in instances_outside_vpc:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
                        finding_name="Notebook Instance Outside VPC",
                        finding_details=(
                            f"SageMaker notebook instance '{instance_name}' has no "
                            "SubnetId, so it runs outside a customer VPC and none "
                            "of the VPC's security groups or endpoints governs its "
                            "traffic"
                        ),
                        resolution="Recreate the notebook instance with SubnetId and SecurityGroupIds in a private subnet",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )

            # Add findings for domains
            for domain in domains_with_direct_access:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
                        finding_name="Non-VPC Only Network Access",
                        finding_details=f"SageMaker domain '{domain['domain_id']}' ({domain['name']}) is not configured for VPC-only access",
                        resolution="Configure the SageMaker domain to use VPC-only network access type",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        elif not unread:
            findings["details"] = (
                "No SageMaker resources found with direct internet access"
            )
            if total_resources_checked > 0:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
                        finding_name="SageMaker Internet Access Check",
                        finding_details=(
                            f"All {total_resources_checked} SageMaker notebook "
                            "instances and domains read use VPC connectivity: "
                            "each notebook has a SubnetId and DirectInternetAccess "
                            "Disabled, and each domain is VpcOnly"
                        ),
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
                        finding_name="SageMaker Internet Access Check",
                        finding_details="No SageMaker notebook instances or domains found to check",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        if unread:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-01",
                    "SageMaker Internet Access Check",
                    unread,
                    f"{total_resources_checked} notebook instance(s) and domain(s) "
                    "were described.",
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                    region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_internet_access: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-01",
                    finding_name="SageMaker Internet Access Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_guardduty_enabled(
    region: str = "", detector_inventory: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Check if GuardDuty is enabled in the account to monitor SageMaker security issues

    Returns:
        Dict[str, Any]: Finding details including status and recommendations
    """
    findings = {
        "check_name": "GuardDuty Enablement Check",
        "status": "PASS",
        "details": "",
        "csv_data": [],
    }

    try:
        inventory = detector_inventory or get_guardduty_detector_inventory(region)
        if inventory.get("error"):
            raise inventory["error"]

        if not inventory.get("detector_id"):
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-04",
                    finding_name="GuardDuty Not Enabled",
                    finding_details="Amazon GuardDuty is not enabled in this account. GuardDuty can help detect security threats in SageMaker workloads.",
                    resolution="Enable Amazon GuardDuty to monitor for potential security threats in your SageMaker environment, including anomalous model access patterns and potential data exfiltration attempts.",
                    reference="https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )
        elif (inventory.get("detail") or {}).get("Status") == "ENABLED":
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-04",
                    finding_name="GuardDuty Enabled",
                    finding_details=(
                        "The GuardDuty detector in this region has Status ENABLED. "
                        "Only the detector status was read here: the AI Protection "
                        "plan is reported by SM-26. Security Hub records each "
                        "finding's review in its Workflow.Status, which this check "
                        "does not read, so whether the findings are reviewed was "
                        "not assessed."
                    ),
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
            findings["csv_data"].append(_guardduty_security_hub_routing_finding(region))
            findings["csv_data"].append(_guardduty_eventbridge_routing_finding(region))
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-04",
                    finding_name="GuardDuty Detector Disabled",
                    finding_details="A GuardDuty detector exists but is not enabled.",
                    resolution="Enable the GuardDuty detector in this region.",
                    reference="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )
    except ClientError as e:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-04",
                finding_name="GuardDuty Check Error",
                finding_details=build_could_not_assess_detail(e, region),
                resolution=COULD_NOT_ASSESS_RESOLUTION,
                reference="https://docs.aws.amazon.com/guardduty/latest/ug/security-iam.html",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    except Exception as e:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-04",
                finding_name="GuardDuty Check Error",
                finding_details=build_could_not_assess_detail(e, region),
                resolution=COULD_NOT_ASSESS_RESOLUTION,
                reference="https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )

    return findings


GUARDDUTY_ROUTING_FINDING = "GuardDuty Findings Routed to Security Hub"
GUARDDUTY_ROUTING_REFERENCE = (
    "https://docs.aws.amazon.com/securityhub/latest/userguide/"
    "securityhub-internal-providers.html"
)
GUARDDUTY_PRODUCT_SUBSCRIPTION_SUFFIX = ":product-subscription/aws/guardduty"


def _guardduty_security_hub_routing_finding(region: str) -> Dict[str, Any]:
    """SM-04: GuardDuty findings reach Security Hub only through its integration."""

    def _row(details, resolution, severity, status, name=GUARDDUTY_ROUTING_FINDING):
        return create_finding(
            check_id="SM-04",
            finding_name=name,
            finding_details=details,
            resolution=resolution,
            reference=GUARDDUTY_ROUTING_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        client = boto3.client("securityhub", config=boto3_config, region_name=region)
        subscriptions = []
        for page in client.get_paginator("list_enabled_products_for_import").paginate():
            subscriptions.extend(page.get("ProductSubscriptions", []))
    except Exception as error:
        return _row(
            "Whether GuardDuty findings are imported into Security Hub was not "
            "read: ListEnabledProductsForImport failed. "
            + build_could_not_assess_detail(error, region),
            COULD_NOT_ASSESS_RESOLUTION,
            "Informational",
            "N/A",
            name=f"{GUARDDUTY_ROUTING_FINDING} Incomplete",
        )
    if any(
        str(arn).endswith(GUARDDUTY_PRODUCT_SUBSCRIPTION_SUFFIX)
        for arn in subscriptions
    ):
        return _row(
            "Security Hub in this region imports GuardDuty findings (product "
            "subscription aws/guardduty is enabled).",
            "No action required",
            "Medium",
            "Passed",
        )
    return _row(
        f"Security Hub in this region has {len(subscriptions)} enabled product "
        "integration(s), none of them GuardDuty, so GuardDuty findings do not "
        "reach the Security Hub view.",
        "Enable the GuardDuty integration in Security Hub for this region.",
        "Medium",
        "Failed",
    )


GUARDDUTY_EVENTBRIDGE_FINDING = "GuardDuty Findings Routed to Alerting"
GUARDDUTY_EVENTBRIDGE_REFERENCE = (
    "https://docs.aws.amazon.com/guardduty/latest/ug/"
    "guardduty_findings_eventbridge.html"
)


GUARDDUTY_FINDING_DETAIL_TYPE = "GuardDuty Finding"


def _rule_matches_guardduty(rule: Dict[str, Any]) -> bool:
    """
    True for an ENABLED rule whose pattern names the aws.guardduty source and
    either sets no detail-type or lists the GuardDuty Finding detail-type.
    """
    if rule.get("State") != "ENABLED":
        return False
    try:
        pattern = json.loads(rule.get("EventPattern") or "{}")
    except ValueError:
        return False
    sources = pattern.get("source") if isinstance(pattern, dict) else None
    if isinstance(sources, str):
        sources = [sources]
    if not isinstance(sources, list) or "aws.guardduty" not in sources:
        return False
    if "detail-type" not in pattern:
        return True
    detail_types = pattern["detail-type"]
    if isinstance(detail_types, str):
        detail_types = [detail_types]
    return (
        isinstance(detail_types, list) and GUARDDUTY_FINDING_DETAIL_TYPE in detail_types
    )


def _guardduty_eventbridge_routing_finding(region: str) -> Dict[str, Any]:
    """SM-04: an ENABLED default-bus rule on aws.guardduty with a target."""

    def _row(details, resolution, severity, status, name=GUARDDUTY_EVENTBRIDGE_FINDING):
        return create_finding(
            check_id="SM-04",
            finding_name=name,
            finding_details=details,
            resolution=resolution,
            reference=GUARDDUTY_EVENTBRIDGE_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        client = boto3.client("events", config=boto3_config, region_name=region)
        rules = []
        for page in client.get_paginator("list_rules").paginate():
            rules.extend(page.get("Rules", []))
    except Exception as error:
        return _row(
            "Whether GuardDuty findings reach an alerting target was not read: "
            "events:ListRules failed. " + build_could_not_assess_detail(error, region),
            COULD_NOT_ASSESS_RESOLUTION,
            "Informational",
            "N/A",
            name=f"{GUARDDUTY_EVENTBRIDGE_FINDING} Incomplete",
        )
    matching = [rule for rule in rules if _rule_matches_guardduty(rule)]
    unread = []
    for rule in matching:
        try:
            targets = []
            for page in client.get_paginator("list_targets_by_rule").paginate(
                Rule=rule.get("Name")
            ):
                targets.extend(page.get("Targets", []))
        except Exception as error:
            unread.append(
                f"rule '{rule.get('Name')}' ({get_assessment_error_label(error)})"
            )
            continue
        if targets:
            return _row(
                f"The ENABLED EventBridge rule '{rule.get('Name')}' matches source "
                f"aws.guardduty and sends to {len(targets)} target(s).",
                "No action required",
                "Medium",
                "Passed",
            )
    if unread:
        return _unread_resources_finding(
            "SM-04",
            GUARDDUTY_EVENTBRIDGE_FINDING,
            unread,
            "no rule read so far sends GuardDuty findings to a target.",
            GUARDDUTY_EVENTBRIDGE_REFERENCE,
            region,
        )
    return _row(
        f"Of {len(rules)} EventBridge rule(s) on the default event bus, "
        f"{len(matching)} ENABLED rule(s) match GuardDuty findings and none "
        "has a target, so no GuardDuty finding raises an alert. Only a rule whose "
        "pattern lists aws.guardduty under source, and sets no detail-type or "
        f"lists {GUARDDUTY_FINDING_DETAIL_TYPE} under it, is credited.",
        "Create an ENABLED EventBridge rule with the pattern "
        '{"source": ["aws.guardduty"]} and an alerting target such as an SNS topic.',
        "Medium",
        "Failed",
    )


GUARDDUTY_ORG_AUTO_ENABLE_FINDING = "GuardDuty AI Protection Organization Auto-Enable"


def _guardduty_org_auto_enable_finding(region: str, detector_id: str) -> Dict[str, Any]:
    """GuardDuty and its AI_PROTECTION plan auto-enabled for ALL member accounts."""
    reference = "https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html"
    try:
        client = boto3.client("guardduty", config=boto3_config, region_name=region)
        response = client.describe_organization_configuration(DetectorId=detector_id)
        features = list(response.get("Features") or [])
        token = response.get("NextToken")
        while isinstance(token, str) and token:
            page = client.describe_organization_configuration(
                DetectorId=detector_id, NextToken=token
            )
            features.extend(page.get("Features") or [])
            token = page.get("NextToken")
    except Exception as error:
        return create_finding(
            check_id="SM-26",
            finding_name=GUARDDUTY_ORG_AUTO_ENABLE_FINDING,
            finding_details=(
                "guardduty:DescribeOrganizationConfiguration failed "
                f"({get_assessment_error_label(error)}). Only the GuardDuty "
                "delegated administrator account can read whether GuardDuty and "
                "AI Protection are auto-enabled for member accounts, so this leg "
                "is judged when the assessment runs there."
            ),
            resolution=(
                "Run the assessment in the GuardDuty delegated administrator "
                "account to judge organization auto-enable."
            ),
            reference=reference,
            severity="Informational",
            status="N/A",
            region=region,
        )
    members = response.get("AutoEnableOrganizationMembers")
    ai_protection = next(
        (
            feature.get("AutoEnable")
            for feature in features
            if feature.get("Name") == "AI_PROTECTION"
        ),
        None,
    )
    if members == "ALL" and ai_protection == "ALL":
        return create_finding(
            check_id="SM-26",
            finding_name=GUARDDUTY_ORG_AUTO_ENABLE_FINDING,
            finding_details=(
                "The organization configuration auto-enables GuardDuty "
                "(AutoEnableOrganizationMembers ALL) and the AI_PROTECTION feature "
                "(AutoEnable ALL) for every existing and new member account. Each "
                "member's own detector is not read."
            ),
            resolution="No action required",
            reference=reference,
            severity="High",
            status="Passed",
            region=region,
        )
    return create_finding(
        check_id="SM-26",
        finding_name=GUARDDUTY_ORG_AUTO_ENABLE_FINDING,
        finding_details=(
            f"AutoEnableOrganizationMembers is {members or 'not returned'} and the "
            f"AI_PROTECTION feature AutoEnable is {ai_protection or 'not returned'}. "
            "Both must be ALL: NEW enables only accounts that join later, and NONE "
            "enables none, so a member account can host AI workloads without AI "
            "Protection."
        ),
        resolution=(
            "From the GuardDuty delegated administrator, set auto-enable to ALL for "
            "the organization and for the AI Protection plan."
        ),
        reference=reference,
        severity="High",
        status="Failed",
        region=region,
    )


def check_guardduty_ai_protection(
    region: str = "", detector_inventory: Dict[str, Any] = None
) -> Dict[str, Any]:
    """SM-26: Verify GuardDuty AI Protection is enabled."""
    findings = {"csv_data": []}
    try:
        inventory = detector_inventory or get_guardduty_detector_inventory(region)
        if inventory.get("error"):
            raise inventory["error"]
        if not inventory.get("detector_id"):
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-26",
                    finding_name="GuardDuty AI Protection",
                    finding_details="No GuardDuty detector exists in this region, so GuardDuty AI Protection produces no findings.",
                    resolution="Enable GuardDuty first, then enable the AI Protection feature.",
                    reference="https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )
            return findings

        detector_status = (inventory.get("detail") or {}).get("Status")
        if detector_status != "ENABLED":
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-26",
                    finding_name="GuardDuty AI Protection",
                    finding_details=(
                        f"GuardDuty detector {inventory['detector_id']} has status "
                        f"{detector_status}, so it produces no AI Protection "
                        "findings whatever its AI_PROTECTION feature status."
                    ),
                    resolution="Re-enable the GuardDuty detector, then enable the AI Protection feature.",
                    reference="https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )
            return findings

        features = (inventory.get("detail") or {}).get("Features", [])
        enabled = any(
            feature.get("Name") == "AI_PROTECTION"
            and feature.get("Status") == "ENABLED"
            for feature in features
        )
        findings["csv_data"].append(
            create_finding(
                check_id="SM-26",
                finding_name="GuardDuty AI Protection",
                finding_details=(
                    "GuardDuty AI Protection is enabled for this detector."
                    if enabled
                    else "GuardDuty is enabled, but the AI Protection detector feature is not enabled."
                ),
                resolution=(
                    "No action required"
                    if enabled
                    else "Enable the GuardDuty AI_PROTECTION detector feature for this region."
                ),
                reference="https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html",
                severity="High",
                status="Passed" if enabled else "Failed",
                region=region,
            )
        )
        findings["csv_data"].append(
            _guardduty_org_auto_enable_finding(region, inventory["detector_id"])
        )
    except Exception as error:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-26",
                finding_name="GuardDuty AI Protection",
                finding_details=build_could_not_assess_detail(error, region),
                resolution=COULD_NOT_ASSESS_RESOLUTION,
                reference="https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    return findings


ENDPOINT_INVOCATION_SCOPING_FINDING = "Endpoint Invocation Policy Scoping"
ENDPOINT_INVOCATION_SCOPING_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/api-permissions-reference.html"
)
ENDPOINT_INVOCATION_SCOPING_RESOLUTION = (
    "Replace the wildcard resource on sagemaker:InvokeEndpoint with the ARNs of "
    "the endpoints that identity is authorized to call "
    "(arn:aws:sagemaker:<region>:<account>:endpoint/<name>), or add an "
    "aws:ResourceTag condition that selects them. A SageMaker endpoint accepts "
    "no resource-based policy, so the identity policy is the only place this can "
    "be scoped."
)

ENDPOINT_INVOKE_ACTIONS = (
    "sagemaker:invokeendpoint",
    "sagemaker:invokeendpointasync",
    "sagemaker:invokeendpointwithresponsestream",
)


def _sm_policy_statements(document: Any) -> List[Dict[str, Any]]:
    """Return the statement list of a policy document given as JSON or text."""
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return []
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _statement_invoke_actions(statement: Dict[str, Any]) -> List[str]:
    """Return the endpoint invocation actions an Allow statement reaches."""
    return [
        action
        for action in ENDPOINT_INVOKE_ACTIONS
        if _statement_allows_action(statement, action)
    ]


def _statement_grants_endpoint_invocation(statement: Dict[str, Any]) -> bool:
    """Return whether an Allow statement reaches sagemaker:InvokeEndpoint."""
    return bool(_statement_invoke_actions(statement))


def _segment_may_match(value: str, literal: str, exact: bool) -> bool:
    """Return whether one lowercased ARN segment pattern can match literal."""
    if "*" not in value and "?" not in value:
        return value == literal if exact else value.startswith(literal)
    prefix = _literal_prefix(value)
    return literal.startswith(prefix) or (not exact and prefix.startswith(literal))


def _resource_scopes_endpoint(resource: str) -> bool:
    """
    Return whether one Resource element stops short of every endpoint.

    An element that cannot match a SageMaker endpoint ARN authorizes no
    invocation, so it is not a wildcard grant either. In an element that can
    match one, a wildcard in any segment is unbounded.
    """
    normalized = resource.strip().lower()
    wildcard = "*" in normalized or "?" in normalized
    parts = normalized.split(":", 5)
    if len(parts) >= 3 and not _segment_may_match(parts[2], "sagemaker", True):
        return True
    if len(parts) == 6 and not _segment_may_match(parts[5], "endpoint/", False):
        return True
    return not wildcard


def _statement_has_resource_tag_condition(statement: Dict[str, Any]) -> bool:
    """
    Return whether a statement narrows its resources by tag.

    An IfExists or ForAllValues operator passes a resource that lacks the tag,
    a negated operator passes every resource without the named value, and a
    Like value made only of wildcards, such as "*", matches every value, so
    none of them narrows the grant.
    """
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict):
        return False
    for operator, condition_keys in condition.items():
        if not isinstance(condition_keys, dict):
            continue
        normalized = str(operator).lower()
        if (
            normalized.endswith("null")
            or normalized.endswith("ifexists")
            or normalized.startswith("forallvalues:")
            or "not" in normalized
        ):
            continue
        for key, values in condition_keys.items():
            if not str(key).lower().startswith("aws:resourcetag/"):
                continue
            if "like" in normalized and any(
                "*" in str(value) and not str(value).strip("*?")
                for value in _policy_values(values)
            ):
                continue
            return True
    return False


def _unscoped_endpoint_invocation_statement(
    statement: Dict[str, Any],
) -> Optional[str]:
    """
    Return the wildcard resource element that makes an invoke grant account-wide.

    AIR-SGM-EP-02 is workload-specific: which endpoints an identity should reach
    is a workload decision. The workload-independent invariant is that the grant
    names its endpoints at all, so only the wildcard is reported. A NotResource
    Allow reaches every endpoint it does not list.
    """
    if not _statement_grants_endpoint_invocation(statement):
        return None
    if _statement_has_resource_tag_condition(statement):
        return None
    if "NotResource" in statement:
        return f"NotResource {_policy_values(statement.get('NotResource'))}"
    for resource in _policy_values(statement.get("Resource")):
        if not _resource_scopes_endpoint(resource):
            return resource
    return None


def _boundary_invocation_reach(boundary: Any, actions: List[str]) -> str:
    """
    Return how far a permissions boundary lets the given invoke actions reach.

    "unbounded" when there is no boundary or it allows one of the actions on
    every endpoint, "scoped" when it allows them only on named endpoints, and
    "none" when it allows none of them. Boundary Deny statements are ignored,
    which can only overstate a grant.
    """
    if boundary is None:
        return "unbounded"
    reach = "none"
    for statement in _sm_policy_statements(boundary):
        if not any(_statement_allows_action(statement, a) for a in actions):
            continue
        if _unscoped_endpoint_invocation_statement(statement):
            return "unbounded"
        reach = "scoped"
    return reach


def _endpoint_invocation_scoping_findings(
    permission_cache: Dict[str, Any], region: str
) -> List[Dict[str, Any]]:
    """Report the AIR-SGM-EP-02 leg of SM-02, per identity."""
    unscoped = []
    scoped = []
    boundary_unknown = []

    identities = []
    for identity_type, cache_key in (
        ("Role", "role_permissions"),
        ("User", "user_permissions"),
    ):
        for name, permissions in (permission_cache.get(cache_key) or {}).items():
            identities.append((identity_type, name, permissions))

    for identity_type, name, permissions in identities:
        boundary = permissions.get("permissions_boundary")
        policies = [
            *(permissions.get("attached_policies") or []),
            *(permissions.get("inline_policies") or []),
            *(permissions.get("group_policies") or []),
        ]
        grants_invocation = False
        wildcard = None
        wildcard_policy = None
        for policy in policies:
            for statement in _sm_policy_statements(policy.get("document")):
                actions = _statement_invoke_actions(statement)
                if not actions:
                    continue
                reach = _boundary_invocation_reach(boundary, actions)
                if reach == "none":
                    continue
                grants_invocation = True
                resource = _unscoped_endpoint_invocation_statement(statement)
                if resource and reach == "unbounded" and wildcard is None:
                    wildcard = resource
                    wildcard_policy = policy.get("name") or "inline policy"
        if not grants_invocation:
            continue
        if wildcard is None:
            scoped.append(f"{identity_type} '{name}'")
        elif boundary is None and (identity_type.lower(), name) in _boundary_unread(
            permission_cache
        ):
            boundary_unknown.append(
                f"{identity_type} '{name}' (policy '{wildcard_policy}' allows "
                "every endpoint; its permissions boundary was not read)"
            )
        else:
            unscoped.append(
                {
                    "label": f"{identity_type} '{name}'",
                    "policy": wildcard_policy,
                    "resource": wildcard,
                    "boundary": boundary is not None,
                }
            )

    emitted = []
    for entry in unscoped[:20]:
        boundary_text = (
            " Its permissions boundary also allows invocation on every endpoint."
            if entry["boundary"]
            else " It has no permissions boundary."
        )
        emitted.append(
            create_finding(
                check_id="SM-02",
                finding_name=ENDPOINT_INVOCATION_SCOPING_FINDING,
                finding_details=(
                    f"{entry['label']} can invoke any SageMaker endpoint in the "
                    f"account: policy '{entry['policy']}' allows endpoint "
                    f"invocation on resource '{entry['resource']}' with no "
                    "endpoint ARN and no aws:ResourceTag condition that narrows "
                    "it: a Like value made only of wildcards matches every tag "
                    "value."
                    f"{boundary_text} {SCP_NOT_EVALUATED_NOTE}"
                ),
                resolution=ENDPOINT_INVOCATION_SCOPING_RESOLUTION,
                reference=ENDPOINT_INVOCATION_SCOPING_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )

    if len(unscoped) > 20:
        emitted.append(
            create_finding(
                check_id="SM-02",
                finding_name=ENDPOINT_INVOCATION_SCOPING_FINDING,
                finding_details=(
                    f"{len(unscoped)} identities can invoke any SageMaker endpoint "
                    "in the account (the first 20 are reported individually above)."
                ),
                resolution=ENDPOINT_INVOCATION_SCOPING_RESOLUTION,
                reference=ENDPOINT_INVOCATION_SCOPING_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )

    scoped_details = (
        f"{len(scoped)} identity/identities that can invoke a SageMaker "
        "endpoint name the endpoints, select them by tag, or are held to "
        "named endpoints by a permissions boundary: "
        f"{', '.join(sorted(scoped)[:5])}. Whether those are the "
        "endpoints each caller should reach is a workload decision the "
        "owner still has to confirm."
    )
    if unscoped and scoped:
        emitted.append(
            create_finding(
                check_id="SM-02",
                finding_name=ENDPOINT_INVOCATION_SCOPING_FINDING,
                finding_details=scoped_details,
                resolution=(
                    "No action required on the wildcard. Confirm with the workload "
                    "owner that each named endpoint belongs in that identity's "
                    "scope."
                ),
                reference=ENDPOINT_INVOCATION_SCOPING_REFERENCE,
                severity="High",
                status="Passed",
                region=region,
            )
        )
    if unscoped and boundary_unknown:
        emitted.append(
            _unread_resources_finding(
                "SM-02",
                ENDPOINT_INVOCATION_SCOPING_FINDING,
                boundary_unknown,
                f"{len(unscoped)} identity/identities are reported above.",
                ENDPOINT_INVOCATION_SCOPING_REFERENCE,
                region,
            )
        )

    # With no invocation grant at all the leg emits nothing, unless a principal
    # could not be read and might hold one.
    if not unscoped and (scoped or _principal_read_errors(permission_cache)):
        if scoped:
            passed_details = scoped_details
        else:
            passed_details = (
                f"None of the {len(identities)} roles and users read holds a "
                "grant to invoke a SageMaker endpoint."
            )
        emitted.append(
            create_finding(
                check_id="SM-02",
                finding_name=ENDPOINT_INVOCATION_SCOPING_FINDING,
                finding_details=passed_details,
                resolution="No action required",
                reference=ENDPOINT_INVOCATION_SCOPING_REFERENCE,
                severity="High",
                status="Passed",
                region=region,
            )
        )

    return emitted


# Per resource type, the actions that read it and the actions that write it, as
# the service authorization reference publishes them, generated by
# generate_iam_access_levels.py.
with open(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "iam_access_levels.json"),
    encoding="utf-8",
) as _levels:
    IAM_ACCESS_LEVELS: Dict[str, Dict[str, Dict[str, List[str]]]] = json.load(_levels)[
        "services"
    ]
IAM_ACCESS_LEVEL_ACTIONS = frozenset(
    f"{namespace}:{action}".lower()
    for namespace, types in IAM_ACCESS_LEVELS.items()
    for levels in types.values()
    for action in levels["read"] + levels["write"]
)
UNRECORDED_PRINCIPAL_ERRORS_NOTE = (
    "The IAM permissions cache predates schema version 2 and did not record "
    "per-principal read errors, so a principal whose policies could not be read "
    "looks the same as one with no policies."
)
SCP_NOT_EVALUATED_NOTE = (
    "Service control policies were not evaluated per principal. They only remove "
    "permissions, so an SCP can make this finding a false Failed but cannot hide "
    "a grant it reports."
)


def _merged_patterns(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value.strip().lower()]
    if isinstance(value, list):
        return [str(item).strip().lower() for item in value]
    return []


def _merged_statements(document: Any) -> List[Dict[str, Any]]:
    """Statements of one policy document. A document that is not JSON raises
    ValueError, so the caller reports it as unread instead of as no grant."""
    if isinstance(document, str):
        document = json.loads(document)
    if document is None:
        return []
    if not isinstance(document, dict):
        raise ValueError("policy document is not a JSON object")
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _identity_statements(permissions: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Attached, inline and group policy statements of one cached identity."""
    return [
        statement
        for policy in [
            *(permissions.get("attached_policies") or []),
            *(permissions.get("inline_policies") or []),
            *(permissions.get("group_policies") or []),
        ]
        for statement in _merged_statements(policy.get("document"))
    ]


def _merged_statement_matches(statement: Dict[str, Any], action: str) -> bool:
    """Whether one statement's Action or NotAction covers a lowercase action."""
    if "Action" in statement:
        return any(
            fnmatch.fnmatchcase(action, pattern)
            for pattern in _merged_patterns(statement.get("Action"))
        )
    return "NotAction" in statement and not any(
        fnmatch.fnmatchcase(action, pattern)
        for pattern in _merged_patterns(statement.get("NotAction"))
    )


def _merged_account_wide_deny(statement: Dict[str, Any], action: str) -> bool:
    """Whether a Deny removes the action everywhere: no condition, Resource "*".

    A narrower Deny is read as removing nothing, which can only over-report.
    """
    return (
        str(statement.get("Effect", "")).upper() == "DENY"
        and not statement.get("Condition")
        and "*" in _merged_patterns(statement.get("Resource"))
        and _merged_statement_matches(statement, action)
    )


def _granted_actions(
    permissions: Dict[str, Any], statements: List[Dict[str, Any]], actions: Any
) -> set:
    """Return the lowercase ``actions`` one identity is granted.

    An action counts when an identity-policy Allow covers it, no account-wide
    Deny removes it, and the permissions boundary, when there is one, allows it
    too: the effective grant is the intersection of the two. A conditioned or
    resource-scoped boundary Allow still counts as allowing, so an uncertain
    case keeps the grant and can only over-report.
    """
    boundary = permissions.get("permissions_boundary")
    boundary_statements = None if boundary is None else _merged_statements(boundary)
    allows = [s for s in statements if str(s.get("Effect", "")).upper() == "ALLOW"]
    granted = set()
    for action in actions:
        if not any(_merged_statement_matches(s, action) for s in allows):
            continue
        if any(_merged_account_wide_deny(s, action) for s in statements):
            continue
        if boundary_statements is not None and (
            any(_merged_account_wide_deny(s, action) for s in boundary_statements)
            or not any(
                str(s.get("Effect", "")).upper() == "ALLOW"
                and _merged_statement_matches(s, action)
                for s in boundary_statements
            )
        ):
            continue
        granted.add(action)
    return granted


def _boundary_unread(permission_cache: Dict[str, Any]) -> set:
    """Return (type, name) for each principal whose permissions boundary the
    cache failed to read. The cache stores a null boundary both when none is
    set and when the read failed, so only the error entry tells them apart,
    and such a principal is left unassessed: a boundary could remove the grant.
    """
    return {
        (str(error.get("type", "")).lower(), error["name"])
        for error in permission_cache.get("principal_errors") or []
        if isinstance(error, dict)
        and error.get("name")
        and error.get("stage") == "permissions_boundary"
    }


def _merged_resources(statement: Dict[str, Any]) -> List[str]:
    """Lowercase Resource patterns of one statement. A NotResource statement
    reads as "*", which can only over-report."""
    if "Resource" not in statement:
        return ["*"]
    return [
        str(item).strip().lower()
        for item in _merged_patterns_any(statement["Resource"])
    ]


def _merged_patterns_any(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return [value] if value is not None else []


@lru_cache(maxsize=None)
def _globs_overlap(left: str, right: str) -> bool:
    """Whether some string matches both IAM glob patterns ("*" and "?")."""

    @lru_cache(maxsize=None)
    def overlap(i: int, j: int) -> bool:
        if i == len(left):
            return all(char == "*" for char in right[j:])
        if j == len(right):
            return all(char == "*" for char in left[i:])
        if left[i] == "*":
            return overlap(i + 1, j) or overlap(i, j + 1)
        if right[j] == "*":
            return overlap(i, j + 1) or overlap(i + 1, j)
        if "?" in (left[i], right[j]) or left[i] == right[j]:
            return overlap(i + 1, j + 1)
        return False

    return overlap(0, 0)


def _merged_reaches_type(resources: List[str], arns: List[str]) -> bool:
    """Whether a Resource entry can name an ARN of the resource type. A
    variable such as ${aws:username} reads as "*"."""
    return any(
        _globs_overlap(re.sub(r"\$\{[^}]*\}", "*", resource), arn.lower())
        for resource in resources
        for arn in arns
    )


def _merged_read_write_grants(permissions: Dict[str, Any]) -> List[str]:
    """Describe each wildcard or NotAction Allow that grants both a read and a
    write action on one resource type.

    An explicit action list separates read from write however long it is; a
    pattern or a NotAction cannot, because it grants whatever it matches, a
    bare "*" and a partial pattern among them. Only actions the identity is
    granted after Denies and its permissions boundary count. A condition on the Allow applies to the read and the write alike, so
    it is not read. The Resource entries are read only to drop the resource
    types none of them can name.
    """
    statements = _identity_statements(permissions)
    triggers = []
    for statement in statements:
        if str(statement.get("Effect", "")).upper() != "ALLOW":
            continue
        if "Action" in statement:
            triggers += [
                (
                    f"Action '{pattern}'",
                    {"Action": pattern},
                    _merged_resources(statement),
                )
                for pattern in _merged_patterns(statement.get("Action"))
                if "*" in pattern or "?" in pattern
            ]
        elif "NotAction" in statement:
            triggers.append(
                (
                    f"NotAction {_merged_patterns(statement.get('NotAction'))}",
                    {"NotAction": statement.get("NotAction")},
                    _merged_resources(statement),
                )
            )
    if not triggers:
        return []
    effective = _granted_actions(
        permissions,
        statements,
        {
            action
            for action in IAM_ACCESS_LEVEL_ACTIONS
            if any(_merged_statement_matches(t, action) for _, t, _ in triggers)
        },
    )
    grants = []
    for label, trigger, resources in triggers:
        for namespace, types in IAM_ACCESS_LEVELS.items():
            merged = []
            for resource_type, levels in types.items():
                if not _merged_reaches_type(resources, levels["arns"]):
                    continue
                reads, writes = (
                    [
                        f"{namespace}:{action}"
                        for action in levels[level]
                        if f"{namespace}:{action}".lower() in effective
                        and _merged_statement_matches(
                            trigger, f"{namespace}:{action}".lower()
                        )
                    ]
                    for level in ("read", "write")
                )
                if reads and writes:
                    merged.append((resource_type, reads, writes))
            if not merged:
                continue
            resource_type, reads, writes = max(
                merged,
                key=lambda item: any(
                    w.split(":", 1)[1].startswith("Delete") for w in item[2]
                ),
            )
            write = next(
                (w for w in writes if w.split(":", 1)[1].startswith("Delete")),
                writes[0],
            )
            grants.append(
                f"{label} grants read and write on {len(merged)} {namespace} "
                f"resource type(s), for example {reads[0]} and {write} on "
                f"{resource_type}"
            )
    return grants


def _principal_read_errors(permission_cache: Dict[str, Any]) -> Optional[List[str]]:
    """Label each principal whose cache read failed, or None for a cache that
    predates ``principal_errors`` and has no user missing ``group_policies``.

    The cache gives every user either ``group_policies`` or
    ``group_policies_error``, so a user without a ``group_policies`` list is
    unread whether or not principal_errors names it.
    """
    errors = permission_cache.get("principal_errors")
    failed: Dict[str, List[str]] = {}
    for error in errors if isinstance(errors, list) else []:
        if isinstance(error, dict) and error.get("name"):
            label = f"{error.get('type', 'principal')} '{error['name']}'"
            failed.setdefault(label, []).append(str(error.get("stage", "unknown")))
    for name, permissions in (permission_cache.get("user_permissions") or {}).items():
        if not isinstance((permissions or {}).get("group_policies"), list):
            stages = failed.setdefault(f"user '{name}'", [])
            if "group_policies" not in stages:
                stages.append("group_policies")
    if not isinstance(errors, list) and not failed:
        return None
    return [
        f"{label} ({', '.join(stages)})" for label, stages in sorted(failed.items())
    ]


def _unread_principals_detail(unread: List[str]) -> str:
    shown = ", ".join(unread[:10])
    if len(unread) > 10:
        shown += f" and {len(unread) - 10} more"
    return (
        f"{len(unread)} principal(s) could not be fully read into the IAM "
        f"permissions cache, so their grants are unknown: {shown}."
    )


SERVICE_WIDE_GRANT_FINDING = "SageMaker Service-Wide Grant in Customer Policy"
SERVICE_WIDE_GRANT_REFERENCE = "https://docs.aws.amazon.com/sagemaker/latest/dg/security_iam_id-based-policy-examples.html"
SERVICE_WIDE_GRANT_RESOLUTION = (
    "Replace the sagemaker:* grant with the specific SageMaker actions the "
    "identity needs, separating read actions from create, update and delete "
    "actions, and rewrite any NotAction Allow as an explicit Action list."
)


def _pattern_covers_all_sagemaker_actions(pattern: str) -> bool:
    """Return whether one action pattern matches every sagemaker: action."""
    normalized = pattern.lower()
    if not normalized.endswith("*"):
        return False
    return fnmatch.fnmatchcase("sagemaker:", normalized[:-1] + "*")


def _service_wide_sagemaker_grant(statement: Dict[str, Any]) -> Optional[str]:
    """
    Return why an Allow statement grants every SageMaker action, or None.

    A bare "*" grants every SageMaker action too. A NotAction Allow grants every
    action it does not list, so it reaches all of SageMaker unless one of its
    patterns covers the whole sagemaker: prefix.
    """
    if str(statement.get("Effect", "")).upper() != "ALLOW":
        return None
    for action in _policy_values(statement.get("Action")):
        if _pattern_covers_all_sagemaker_actions(action.strip()):
            return f"Action '{action}'"
    if "NotAction" in statement:
        excluded = _policy_values(statement.get("NotAction"))
        if not any(_pattern_covers_all_sagemaker_actions(p) for p in excluded):
            return f"NotAction {excluded}"
    return None


def _service_wide_grant_findings(
    permission_cache: Dict[str, Any], region: str
) -> List[Dict[str, Any]]:
    """
    Report the AIR-FND-IAM-09 leg of SM-02 over customer-managed, inline and
    group policies. AWS managed policies are excluded because the full-access
    leg already reports AmazonSageMakerFullAccess by name, and the merged read
    and write leg reads them. A statement is reported only when, with the
    identity's permissions boundary and account-wide Denies applied, it still
    grants every action in IAM_ACCESS_LEVEL_ACTIONS.
    """
    violations = []
    unreadable = []
    policies_read = 0
    boundary_unread = _boundary_unread(permission_cache)
    for identity_type, cache_key in (
        ("Role", "role_permissions"),
        ("User", "user_permissions"),
    ):
        for name, permissions in (permission_cache.get(cache_key) or {}).items():
            if (identity_type.lower(), name) in boundary_unread and (
                permissions.get("permissions_boundary") is None
            ):
                continue
            policies = [
                policy
                for policy in [
                    *(permissions.get("attached_policies") or []),
                    *(permissions.get("group_policies") or []),
                ]
                if ":iam::aws:policy/" not in (policy.get("arn") or "")
            ] + list(permissions.get("inline_policies") or [])
            # Denies from every policy, AWS managed included. A customer policy
            # that cannot be parsed is reported as unread in the loop below.
            denies = []
            for policy in [
                *(permissions.get("attached_policies") or []),
                *(permissions.get("group_policies") or []),
                *(permissions.get("inline_policies") or []),
            ]:
                try:
                    denies.extend(
                        statement
                        for statement in _merged_statements(policy.get("document"))
                        if str(statement.get("Effect", "")).upper() == "DENY"
                    )
                except (ValueError, TypeError):
                    continue
            for policy in policies:
                try:
                    statements = _merged_statements(policy.get("document"))
                except (ValueError, TypeError):
                    unreadable.append(
                        f"{identity_type.lower()} '{name}' policy "
                        f"'{policy.get('name') or 'inline policy'}'"
                    )
                    continue
                policies_read += 1
                for statement in statements:
                    reason = _service_wide_sagemaker_grant(statement)
                    # The boundary and account-wide Denies can remove any one
                    # action, so the grant counts only if every action survives.
                    if (
                        reason
                        and _granted_actions(
                            permissions, [statement, *denies], IAM_ACCESS_LEVEL_ACTIONS
                        )
                        >= IAM_ACCESS_LEVEL_ACTIONS
                    ):
                        violations.append(
                            {
                                "label": f"{identity_type} '{name}'",
                                "policy": policy.get("name") or "inline policy",
                                "reason": reason,
                            }
                        )
                        break

    emitted = []
    for entry in violations[:20]:
        emitted.append(
            create_finding(
                check_id="SM-02",
                finding_name=SERVICE_WIDE_GRANT_FINDING,
                finding_details=(
                    f"{entry['label']} holds every SageMaker action through "
                    f"customer policy '{entry['policy']}': an Allow statement "
                    f"with {entry['reason']} makes read and delete permissions "
                    "on the same resource inseparable, and neither its "
                    "permissions boundary nor an account-wide Deny removes any "
                    f"of the {len(IAM_ACCESS_LEVEL_ACTIONS)} SageMaker read and "
                    "write actions the service authorization reference lists "
                    f"for SageMaker resources. {SCP_NOT_EVALUATED_NOTE}"
                ),
                resolution=SERVICE_WIDE_GRANT_RESOLUTION,
                reference=SERVICE_WIDE_GRANT_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )
    if len(violations) > 20:
        emitted.append(
            create_finding(
                check_id="SM-02",
                finding_name=SERVICE_WIDE_GRANT_FINDING,
                finding_details=(
                    f"{len(violations)} customer-managed or inline policy "
                    "attachments grant every SageMaker action (the first 20 are "
                    "reported individually above)."
                ),
                resolution=SERVICE_WIDE_GRANT_RESOLUTION,
                reference=SERVICE_WIDE_GRANT_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )
    if unreadable:
        emitted.append(
            create_finding(
                check_id="SM-02",
                finding_name=f"{SERVICE_WIDE_GRANT_FINDING} Incomplete",
                finding_details=(
                    f"{len(unreadable)} cached policy document(s) could not be "
                    f"parsed, so whether they grant every SageMaker action was not "
                    f"assessed: {', '.join(unreadable[:10])}."
                ),
                resolution=(
                    "Review the IAM Permission Caching task output, then rerun "
                    "the assessment."
                ),
                reference=SERVICE_WIDE_GRANT_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    elif not violations:
        emitted.append(
            create_finding(
                check_id="SM-02",
                finding_name=SERVICE_WIDE_GRANT_FINDING,
                finding_details=(
                    f"None of the {policies_read} customer-managed, inline or "
                    'group policies read grants, through sagemaker:*, "*" or a '
                    "NotAction Allow, all of the "
                    f"{len(IAM_ACCESS_LEVEL_ACTIONS)} SageMaker read and write "
                    "actions once the identity's permissions boundary and "
                    "account-wide Denies apply. Whether each identity's action "
                    "list matches its role is a workload decision this check "
                    "does not make."
                ),
                resolution="No action required",
                reference=SERVICE_WIDE_GRANT_REFERENCE,
                severity="High",
                status="Passed",
                region=region,
            )
        )
    return emitted


MERGED_READ_WRITE_FINDING = "SageMaker Read and Write Merged in One Grant"
MERGED_READ_WRITE_REFERENCE = (
    f"{SERVICE_WIDE_GRANT_REFERENCE}\n"
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
)


def _merged_read_write_findings(
    permission_cache: Dict[str, Any], region: str
) -> List[Dict[str, Any]]:
    """AIR-FND-IAM-09 leg of SM-02: a grant that cannot tell read from write,
    read over every policy of every cached role and user, AWS managed included."""
    boundary_unread = _boundary_unread(permission_cache)
    identities = [
        (identity_type, name, permissions)
        for identity_type, cache_key in (
            ("Role", "role_permissions"),
            ("User", "user_permissions"),
        )
        for name, permissions in (permission_cache.get(cache_key) or {}).items()
        if (identity_type.lower(), name) not in boundary_unread
        or permissions.get("permissions_boundary") is not None
    ]
    flagged, unreadable = [], []
    for identity_type, name, permissions in identities:
        try:
            grants = _merged_read_write_grants(permissions)
        except (ValueError, TypeError, AttributeError):
            unreadable.append(f"{identity_type.lower()} '{name}'")
            continue
        if grants:
            flagged.append((identity_type, name, grants))
    resolution = (
        "Replace the wildcard or NotAction grant with the specific SageMaker read "
        "actions the identity needs, and grant create, update and delete actions "
        "separately to the principals that make those changes."
    )
    rows = [
        create_finding(
            check_id="SM-02",
            finding_name=MERGED_READ_WRITE_FINDING,
            finding_details=(
                f"{identity_type} '{name}': {'; '.join(grants[:5])}. An explicit "
                "action list is the only form that grants the read without the "
                "write; a condition or resource scope applies to both alike. "
                + SCP_NOT_EVALUATED_NOTE
            ),
            resolution=resolution,
            reference=MERGED_READ_WRITE_REFERENCE,
            severity="High",
            status="Failed",
            region=region,
        )
        for identity_type, name, grants in flagged[:20]
    ]
    if len(flagged) > 20:
        rows.append(
            create_finding(
                check_id="SM-02",
                finding_name=MERGED_READ_WRITE_FINDING,
                finding_details=(
                    f"{len(flagged)} principals hold a grant that merges SageMaker "
                    "read and write (the first 20 are reported individually)."
                ),
                resolution=resolution,
                reference=MERGED_READ_WRITE_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )
    if unreadable:
        rows.append(
            create_finding(
                check_id="SM-02",
                finding_name=MERGED_READ_WRITE_FINDING,
                finding_details=(
                    "The cached policies of "
                    f"{', '.join(unreadable)} could not be parsed, so whether a "
                    "grant merges read and write was not assessed."
                ),
                resolution=(
                    "Review the IAM Permission Caching task output, then rerun "
                    "the assessment."
                ),
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    if not flagged and not unreadable and identities:
        rows.append(
            create_finding(
                check_id="SM-02",
                finding_name=MERGED_READ_WRITE_FINDING,
                finding_details=(
                    f"None of the {len(identities)} cached role(s) and user(s) "
                    "holds a wildcard or NotAction grant that allows both a read "
                    "and a write action on one SageMaker resource type."
                ),
                resolution="No action required",
                reference=MERGED_READ_WRITE_REFERENCE,
                severity="High",
                status="Passed",
                region=region,
            )
        )
    return rows


def _hold_passed_for_unread_principals(
    permission_cache: Dict[str, Any], rows: List[Dict[str, Any]], region: str
) -> List[Dict[str, Any]]:
    """Hold back a Passed SM-02 row while the cache names an unread principal.

    Each Passed row becomes N/A naming the principals; a failing row is kept.
    A cache without ``principal_errors`` keeps its verdict and says the errors
    were not recorded.
    """
    unread = _principal_read_errors(permission_cache)
    if unread is None:
        for row in rows:
            if row["Status"] == "Passed":
                row["Finding_Details"] += " " + UNRECORDED_PRINCIPAL_ERRORS_NOTE
        return rows
    if not unread:
        return rows
    detail = _unread_principals_detail(unread)

    def incomplete(name: str, details: str) -> Dict[str, Any]:
        return create_finding(
            check_id="SM-02",
            finding_name=f"{name} Incomplete",
            finding_details=details,
            resolution=(
                "Grant the IAM Permission Caching task read access to the listed "
                "principals, then re-run the assessment."
            ),
            reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
            severity="Informational",
            status="N/A",
            region=region,
        )

    kept = [row for row in rows if row["Status"] != "Passed"]
    passed = [row for row in rows if row["Status"] == "Passed"]
    if passed:
        return kept + [
            incomplete(row["Finding"], f"{row['Finding_Details']} {detail}")
            for row in passed
        ]
    return kept + [incomplete("SageMaker IAM Permissions Check", detail)]


def check_sagemaker_iam_permissions(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    """
    Check SageMaker IAM permissions and stale access.

    These checks are derived purely from IAM (a global service) and the cached
    permissions, so they produce identical results in every region. The handler
    runs this check once, on the primary region, tagged with GLOBAL_REGION_LABEL.
    Regional SSO/domain configuration is checked separately by
    check_sagemaker_sso_configuration.
    """
    logger.debug("Starting check for SageMaker IAM permissions")
    try:
        findings = {"csv_data": []}

        # Check for roles with SageMaker full access
        roles_with_full_access = []
        full_access_boundary_unread = []
        boundary_unread = _boundary_unread(permission_cache)
        for role_name, permissions in permission_cache["role_permissions"].items():
            if not _boundary_allows_every_sagemaker_action(
                permissions.get("permissions_boundary")
            ):
                continue
            for policy in permissions["attached_policies"]:
                if policy["name"] == "AmazonSageMakerFullAccess":
                    if permissions.get("permissions_boundary") is None and (
                        ("role", role_name) in boundary_unread
                    ):
                        full_access_boundary_unread.append(role_name)
                    else:
                        roles_with_full_access.append(role_name)
                    break

        # Check for stale access. IAM is a global service, so the client is not
        # region-scoped (region is used only for finding tags).
        stale_users = []
        unread_users = []
        iam_client = boto3.client("iam", config=boto3_config)
        account_id = None
        partition = None
        two_months_ago = datetime.now(timezone.utc) - timedelta(days=60)

        # Check users' last access to SageMaker
        for user_name, permissions in permission_cache["user_permissions"].items():
            has_sagemaker_access = False
            for policy in [
                *permissions["attached_policies"],
                *permissions["inline_policies"],
                *(permissions.get("group_policies") or []),
            ]:
                if has_sagemaker_permissions(policy["document"]):
                    has_sagemaker_access = True
                    break

            if has_sagemaker_access:
                try:
                    if account_id is None or partition is None:
                        caller_identity = boto3.client(
                            "sts", config=boto3_config
                        ).get_caller_identity()
                        account_id = caller_identity["Account"]
                        partition = _caller_identity_partition(caller_identity)
                    response = iam_client.generate_service_last_accessed_details(
                        Arn=f"arn:{partition}:iam::{account_id}:user/{user_name}"
                    )
                    job_id = response["JobId"]

                    # Wait for job completion
                    waiter_time = 0
                    completed = False
                    while waiter_time < 10:
                        details = iam_client.get_service_last_accessed_details(
                            JobId=job_id
                        )
                        if details["JobStatus"] == "COMPLETED":
                            completed = True
                            for service in details["ServicesLastAccessed"]:
                                if service["ServiceName"] == "Amazon SageMaker":
                                    last_accessed = service.get("LastAuthenticated")
                                    if last_accessed and last_accessed < two_months_ago:
                                        stale_users.append(
                                            {
                                                "name": user_name,
                                                "last_accessed": last_accessed,
                                            }
                                        )
                            break
                        time.sleep(1)  # nosemgrep: arbitrary-sleep
                        waiter_time += 1
                    if not completed:
                        unread_users.append(
                            f"User '{user_name}' (last-accessed job not complete)"
                        )
                except Exception as e:
                    logger.error(
                        f"Error checking last access for user {user_name}: {str(e)}"
                    )
                    unread_users.append(
                        f"User '{user_name}' (last accessed: "
                        f"{get_assessment_error_label(e)})"
                    )

        # Generate findings
        if roles_with_full_access or stale_users:
            # Findings for full access roles
            if roles_with_full_access:
                for role_name in roles_with_full_access:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="SM-02",
                            finding_name="SageMaker Full Access Policy Used",
                            finding_details=(
                                f"Role '{role_name}' has AmazonSageMakerFullAccess "
                                "policy attached and no permissions boundary "
                                f"narrows it. {SCP_NOT_EVALUATED_NOTE}"
                            ),
                            resolution="Replace AmazonSageMakerFullAccess with more restrictive custom policies that follow the principle of least privilege",
                            reference="https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )
                # A null boundary that was not read may narrow the grant, so
                # the role is named as not read, never Failed. With no Failed
                # row, the population row below names it instead.
                if full_access_boundary_unread:
                    findings["csv_data"].append(
                        _unread_resources_finding(
                            "SM-02",
                            "SageMaker Full Access Policy Used",
                            [
                                f"Role '{name}' (AmazonSageMakerFullAccess is "
                                "attached; its permissions boundary was not read)"
                                for name in full_access_boundary_unread
                            ],
                            f"{len(roles_with_full_access)} role(s) are reported "
                            "above.",
                            "https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                            region,
                        )
                    )

            # Findings for stale users
            if stale_users:
                for user in stale_users:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="SM-02",
                            finding_name="Stale SageMaker Access",
                            finding_details=f"User '{user['name']}' hasn't accessed SageMaker since {user['last_accessed'].strftime('%Y-%m-%d')}",
                            resolution="Review and remove SageMaker access for inactive users",
                            reference="https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )
        else:
            passed_details = (
                "No role holds AmazonSageMakerFullAccess outside a narrowing "
                "permissions boundary, and no user with a SageMaker grant is "
                "stale by 60 days."
            )
            reference = "https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html"
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-02",
                    "SageMaker IAM Permissions Check",
                    unread_users,
                    passed_details,
                    reference,
                    region,
                )
                if unread_users
                else create_finding(
                    check_id="SM-02",
                    finding_name="SageMaker IAM Permissions Check",
                    finding_details=passed_details,
                    resolution="No action required",
                    reference=reference,
                    severity="High",
                    status="Passed",
                    region=region,
                )
            )

        # AIR-SGM-EP-02 is independent of the full-access and stale-access legs
        # above: an identity can hold neither and still be able to invoke every
        # endpoint in the account.
        findings["csv_data"].extend(
            _endpoint_invocation_scoping_findings(permission_cache, region)
        )
        findings["csv_data"].extend(
            _service_wide_grant_findings(permission_cache, region)
        )
        findings["csv_data"].extend(
            _merged_read_write_findings(permission_cache, region)
        )
        findings["csv_data"] = _hold_passed_for_unread_principals(
            permission_cache, findings["csv_data"], region
        )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_iam_permissions: {str(e)}", exc_info=True
        )
        return {
            "check_name": "SageMaker IAM Permissions Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
        }


def check_sagemaker_sso_configuration(region: str = "") -> Dict[str, Any]:
    """
    Check SageMaker domain SSO / IAM Identity Center configuration.

    SageMaker domains are regional resources, so this check runs once per
    scanned region (unlike the IAM-global checks in
    check_sagemaker_iam_permissions).
    """
    logger.debug("Starting check for SageMaker SSO configuration")
    try:
        findings = {"csv_data": []}

        domains_without_sso = []
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        paginator = sagemaker_client.get_paginator("list_domains")

        for page in paginator.paginate():
            for domain in page["Domains"]:
                domain_id = domain["DomainId"]
                try:
                    domain_details = sagemaker_client.describe_domain(
                        DomainId=domain_id
                    )

                    # Check authentication mode
                    auth_mode = domain_details.get("AuthMode", "")
                    if auth_mode != "SSO":
                        domains_without_sso.append(
                            {
                                "domain_id": domain_id,
                                "domain_name": domain_details.get("DomainName", "N/A"),
                                "auth_mode": auth_mode,
                            }
                        )

                    # Check if SSO is properly configured with Identity Center
                    if auth_mode == "SSO":
                        identity_store_id = domain_details.get("IdentityStoreId")

                        if not identity_store_id:
                            domains_without_sso.append(
                                {
                                    "domain_id": domain_id,
                                    "domain_name": domain_details.get(
                                        "DomainName", "N/A"
                                    ),
                                    "auth_mode": "SSO (Incomplete Configuration)",
                                }
                            )

                except Exception as domain_error:
                    logger.error(
                        f"Error checking domain {domain_id}: {str(domain_error)}"
                    )

        if domains_without_sso:
            for domain in domains_without_sso:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-02",
                        finding_name="SSO Not Properly Configured",
                        finding_details=(
                            f"SageMaker domain '{domain['domain_id']}' ({domain['domain_name']}) "
                            f"is using authentication mode: {domain['auth_mode']}"
                        ),
                        resolution=(
                            "Enable and properly configure AWS IAM Identity Center (successor to AWS SSO) "
                            "for centralized access management. Ensure Identity Store ID is configured."
                        ),
                        reference="https://aws.amazon.com/blogs/machine-learning/team-and-user-management-with-amazon-sagemaker-and-aws-sso/",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-02",
                    finding_name="SageMaker SSO Configuration Check",
                    finding_details="No SageMaker domains found, or all domains use SSO with IAM Identity Center configured",
                    resolution="No action required",
                    reference="https://aws.amazon.com/blogs/machine-learning/team-and-user-management-with-amazon-sagemaker-and-aws-sso/",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_sso_configuration: {str(e)}", exc_info=True
        )
        return {
            "check_name": "SageMaker SSO Configuration Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
        }


def has_sagemaker_permissions(policy_doc: Dict) -> bool:
    """
    Check if a policy document contains SageMaker permissions
    """
    try:
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            effect = statement.get("Effect", "")
            if effect.upper() != "ALLOW":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                if "sagemaker" in action.lower():
                    return True
        return False
    except Exception as e:
        logger.error(f"Error parsing policy document: {str(e)}")
        return False


# A key named by an alias under alias/aws/ is an AWS managed key; any other key
# id or ARN is resolved with kms:DescribeKey, because an AWS managed key can
# also be named by its key ARN and the ARN alone does not say who manages it.
AWS_MANAGED_ALIAS_PREFIX = "alias/aws/"
S3_ENCRYPTION_KMS_ALGORITHMS = ("aws:kms", "aws:kms:dsse")
BUCKET_PROTECTION_REFERENCE = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
)
MAX_BUCKET_PROTECTION_FINDINGS = 20


def _kms_key_alias(key_id: str) -> Optional[str]:
    if key_id.startswith("alias/"):
        return key_id
    if ":alias/" in key_id:
        return "alias/" + key_id.split(":alias/", 1)[1]
    return None


def _kms_key_managers(key_ids: List[str], region: str) -> Dict[str, Dict[str, Any]]:
    """
    Return {key id: {"manager": "AWS" | "CUSTOMER" | None, "state": KeyState,
    "error": label}}. The state is None for a key not described.

    A key ARN is described in the Region the ARN names, since kms:DescribeKey
    answers only for keys in the Region it is called in.
    """
    results: Dict[str, Dict[str, Any]] = {}
    clients: Dict[str, Any] = {}
    for key_id in sorted({str(k) for k in key_ids if k}):
        alias = _kms_key_alias(key_id)
        if alias and alias.startswith(AWS_MANAGED_ALIAS_PREFIX):
            results[key_id] = {"manager": "AWS", "state": None, "error": None}
            continue
        key_region = region
        if key_id.startswith("arn:"):
            key_region = key_id.split(":")[3] or region
        try:
            if key_region not in clients:
                clients[key_region] = boto3.client(
                    "kms", config=boto3_config, region_name=key_region
                )
            metadata = (
                clients[key_region].describe_key(KeyId=key_id).get("KeyMetadata") or {}
            )
            manager = metadata.get("KeyManager")
            results[key_id] = {
                "manager": manager if manager in ("AWS", "CUSTOMER") else None,
                "state": metadata.get("KeyState"),
                "error": None if manager in ("AWS", "CUSTOMER") else "no KeyManager",
            }
        except Exception as error:
            results[key_id] = {
                "manager": None,
                "state": None,
                "error": get_assessment_error_label(error),
            }
    return results


def _s3_uri_bucket(uri: Any) -> Optional[str]:
    """Return the bucket of an s3://bucket/prefix URI, or None for anything else."""
    if not isinstance(uri, str) or not uri.startswith("s3://"):
        return None
    return uri[len("s3://") :].split("/", 1)[0] or None


def _s3_resource_covers_objects(pattern: str, bucket_arn: str) -> bool:
    """
    True when a Resource pattern matches every object key in the bucket.

    IAM wildcards match across "/", so the pattern covers every key when it
    ends in "*" and the text before that "*" matches some prefix of
    "<bucket arn>/".
    """
    if not pattern.endswith("*"):
        return False
    head = pattern[:-1]
    target = bucket_arn + "/"
    return any(
        fnmatch.fnmatchcase(target[:length], head) for length in range(len(target) + 1)
    )


def _plaintext_deny_gaps(statement: Dict[str, Any], bucket: str) -> Optional[List[str]]:
    """
    Return None when the statement is not a Deny on aws:SecureTransport false,
    otherwise the reasons it leaves plaintext requests to the bucket allowed.
    """
    if str(statement.get("Effect", "")).upper() != "DENY":
        return None
    entries = _condition_entries(statement)
    tests_plaintext = any(
        _condition_operator_parts(operator)[1] == "bool"
        and key == "aws:securetransport"
        and values
        and all(value == "false" for value in values)
        for operator, key, values in entries
    )
    if not tests_plaintext:
        return None
    gaps = []
    principal = statement.get("Principal")
    if "NotPrincipal" in statement or "*" not in _policy_values(
        principal if isinstance(principal, (dict, list)) else [principal or ""]
    ):
        gaps.append("it does not apply to every principal")
    bucket_arn = f"arn:aws:s3:::{bucket}"
    if "NotResource" in statement:
        gaps.append("it uses NotResource")
    else:
        # The partition segment is dropped so a GovCloud or China ARN compares
        # the same way as the aws partition.
        resources = [
            re.sub(r"^arn:aws(-[a-z-]+)?:", "arn:aws:", str(r))
            for r in _policy_values(statement.get("Resource"))
        ]
        if not any(r == "*" or fnmatch.fnmatchcase(bucket_arn, r) for r in resources):
            gaps.append("its Resource does not cover the bucket")
        if not any(
            r == "*" or _s3_resource_covers_objects(r, bucket_arn) for r in resources
        ):
            gaps.append("its Resource does not cover every object")
    if "NotAction" in statement or not any(
        _iam_action_matches(pattern, "s3:*")
        for pattern in _policy_values(statement.get("Action"))
    ):
        gaps.append("its Action does not cover s3:*")
    narrowing = sorted(
        {
            f"{operator} {key}"
            for operator, key, _ in entries
            if key != "aws:securetransport"
        }
    )
    if narrowing:
        gaps.append(f"its Condition also tests {', '.join(narrowing)}")
    return gaps


def _bucket_policy_tls_problem(bucket: str, document: Any) -> Optional[str]:
    reasons = []
    for index, statement in enumerate(_sm_policy_statements(document), start=1):
        gaps = _plaintext_deny_gaps(statement, bucket)
        if gaps is None:
            continue
        if not gaps:
            return None
        label = statement.get("Sid") or f"statement {index}"
        reasons.append(f"'{label}': {'; '.join(gaps)}")
    if reasons:
        return (
            "no bucket policy Deny on aws:SecureTransport false closes the bucket ("
            + " | ".join(reasons[:3])
            + ")"
        )
    return "the bucket policy has no Deny on aws:SecureTransport false"


def _bucket_protection_findings(
    check_id: str,
    finding_name: str,
    bucket_users: Dict[str, List[str]],
    region: str,
) -> List[Dict[str, Any]]:
    """
    Read each bucket's default encryption and bucket policy: SSE-KMS with a
    customer managed key, and a Deny on aws:SecureTransport false that reaches
    every principal, the bucket, every object and s3:*.
    """
    if not bucket_users:
        return []
    s3_client = boto3.client("s3", config=boto3_config, region_name=region)
    reads = {}
    for bucket in sorted(bucket_users):
        problems: List[str] = []
        unread: List[str] = []
        key_id = None
        try:
            rules = (
                s3_client.get_bucket_encryption(Bucket=bucket)
                .get("ServerSideEncryptionConfiguration", {})
                .get("Rules", [])
            )
            defaults = [
                r.get("ApplyServerSideEncryptionByDefault") or {} for r in rules
            ]
            kms_defaults = [
                d
                for d in defaults
                if d.get("SSEAlgorithm") in S3_ENCRYPTION_KMS_ALGORITHMS
            ]
            if not kms_defaults:
                algorithms = sorted({str(d.get("SSEAlgorithm")) for d in defaults})
                problems.append(
                    "default encryption is not SSE-KMS "
                    f"({', '.join(algorithms) or 'no default rule'})"
                )
            elif not kms_defaults[0].get("KMSMasterKeyID"):
                problems.append(
                    "default encryption is SSE-KMS with no KMSMasterKeyID, so it "
                    "uses the AWS managed key aws/s3"
                )
            else:
                key_id = kms_defaults[0]["KMSMasterKeyID"]
        except ClientError as error:
            if get_assessment_error_label(error) == (
                "ServerSideEncryptionConfigurationNotFoundError"
            ):
                problems.append("the bucket has no default encryption configuration")
            else:
                unread.append(
                    f"s3:GetEncryptionConfiguration ({get_assessment_error_label(error)})"
                )
        except Exception as error:
            unread.append(
                f"s3:GetEncryptionConfiguration ({get_assessment_error_label(error)})"
            )
        try:
            document = s3_client.get_bucket_policy(Bucket=bucket).get("Policy")
            problem = _bucket_policy_tls_problem(bucket, document)
            if problem:
                problems.append(problem)
        except ClientError as error:
            if get_assessment_error_label(error) == "NoSuchBucketPolicy":
                problems.append(
                    "the bucket has no bucket policy, so no Deny on "
                    "aws:SecureTransport false"
                )
            else:
                unread.append(
                    f"s3:GetBucketPolicy ({get_assessment_error_label(error)})"
                )
        except Exception as error:
            unread.append(f"s3:GetBucketPolicy ({get_assessment_error_label(error)})")
        reads[bucket] = {"problems": problems, "unread": unread, "key": key_id}

    managers = _kms_key_managers(
        [read["key"] for read in reads.values() if read["key"]], region
    )
    for read in reads.values():
        if not read["key"]:
            continue
        manager = managers[read["key"]]
        if manager["manager"] == "AWS":
            read["problems"].append(
                f"default encryption key {read['key']} is an AWS managed key"
            )
        elif manager["manager"] is None:
            read["unread"].append(f"kms:DescribeKey {read['key']} ({manager['error']})")
        elif manager["state"] not in (None, "Enabled"):
            read["problems"].append(
                f"default encryption key {read['key']} has KeyState "
                f"{manager['state']}, not Enabled"
            )

    emitted = []
    clean = []
    unread = []
    failed = [bucket for bucket in sorted(reads) if reads[bucket]["problems"]]
    for bucket in failed[:MAX_BUCKET_PROTECTION_FINDINGS]:
        users = bucket_users[bucket]
        emitted.append(
            create_finding(
                check_id=check_id,
                finding_name=finding_name,
                finding_details=(
                    f"Bucket '{bucket}', used by {', '.join(users[:5])}"
                    f"{' and more' if len(users) > 5 else ''}: "
                    f"{'; '.join(reads[bucket]['problems'])}."
                    + (
                        f" Not read: {', '.join(reads[bucket]['unread'])}."
                        if reads[bucket]["unread"]
                        else ""
                    )
                ),
                resolution=(
                    "Set the bucket's default encryption to SSE-KMS with a customer "
                    "managed key, and add a bucket policy statement that denies "
                    "s3:* on the bucket and bucket/* to every principal when "
                    "aws:SecureTransport is false."
                ),
                reference=BUCKET_PROTECTION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if len(failed) > MAX_BUCKET_PROTECTION_FINDINGS:
        emitted.append(
            create_finding(
                check_id=check_id,
                finding_name=finding_name,
                finding_details=(
                    f"{len(failed)} buckets fail (the first "
                    f"{MAX_BUCKET_PROTECTION_FINDINGS} are reported above): "
                    f"{', '.join(failed[MAX_BUCKET_PROTECTION_FINDINGS:])}."
                ),
                resolution="Apply the same fix to each bucket listed.",
                reference=BUCKET_PROTECTION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    for bucket in sorted(reads):
        if reads[bucket]["problems"]:
            continue
        if reads[bucket]["unread"]:
            unread.extend(
                f"bucket {bucket}: {item}" for item in reads[bucket]["unread"]
            )
        else:
            clean.append(bucket)
    read_details = (
        f"{len(clean)} bucket(s) use SSE-KMS with a customer managed key and deny "
        f"plaintext requests: {', '.join(clean[:10]) or 'none'}."
    )
    if unread:
        emitted.append(
            _unread_resources_finding(
                check_id,
                finding_name,
                unread,
                read_details,
                BUCKET_PROTECTION_REFERENCE,
                region,
            )
        )
    elif clean and not failed:
        emitted.append(
            create_finding(
                check_id=check_id,
                finding_name=finding_name,
                finding_details=read_details,
                resolution="No action required",
                reference=BUCKET_PROTECTION_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return emitted


TRAINING_VOLUME_ENCRYPTION_FINDING = "Training Job Volume Encryption"
KEY_NOT_ENABLED_FINDING = "Customer Managed Key Not Enabled"
TRAINING_BUCKET_FINDING = "Training Job Data Bucket Protection"
TRAINING_VOLUME_ENCRYPTION_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/train-encrypt.html"
)
TRAINING_VOLUME_ENCRYPTION_RESOLUTION = (
    "Set ResourceConfig.VolumeKmsKeyId to a customer managed key when creating "
    "the training job. Without it the ML storage volume that holds the "
    "downloaded training data and the checkpoints is encrypted with the "
    "Amazon EBS default key, which the workload cannot audit or revoke. "
    "Instance types with only local NVMe storage ignore the key, so confirm the "
    "instance family before treating this as remediated."
)


TRAINING_FILE_SYSTEM_READ_ACTIONS = {
    "EFS": "elasticfilesystem:DescribeFileSystems",
    "FSxLustre": "fsx:DescribeFileSystems",
}


def _training_file_system_encryption(system_type: str, file_system_id: str, region):
    """
    Read one training file system's encryption at rest.

    Returns {"state": ...} with "unencrypted", "key" (and "key_id"),
    "service-key" for an FSx for Lustre SCRATCH file system, which FSx encrypts
    with its own service key, or "unread" (and "detail").
    """
    action = TRAINING_FILE_SYSTEM_READ_ACTIONS.get(system_type)
    if action is None:
        return {"state": "unread", "detail": f"file system type {system_type}"}
    try:
        if system_type == "EFS":
            client = boto3.client("efs", config=boto3_config, region_name=region)
            systems = client.describe_file_systems(FileSystemId=file_system_id).get(
                "FileSystems", []
            )
        else:
            client = boto3.client("fsx", config=boto3_config, region_name=region)
            systems = client.describe_file_systems(FileSystemIds=[file_system_id]).get(
                "FileSystems", []
            )
    except Exception as error:
        return {
            "state": "unread",
            "detail": f"{action}: {get_assessment_error_label(error)}",
        }
    system = next(
        (item for item in systems if item.get("FileSystemId") == file_system_id), None
    )
    if system is None:
        return {"state": "unread", "detail": f"{action} did not return it"}
    if system_type == "EFS":
        if system.get("Encrypted") is not True:
            return {"state": "unencrypted"}
    elif str(
        (system.get("LustreConfiguration") or {}).get("DeploymentType") or ""
    ).startswith("SCRATCH"):
        return {"state": "service-key"}
    if system.get("KmsKeyId"):
        return {"state": "key", "key_id": system["KmsKeyId"]}
    return {"state": "unread", "detail": f"{action} returned no KmsKeyId"}


def _training_instance_count(job_details: Dict[str, Any]) -> Optional[int]:
    """Instances a training job ran on, summed over heterogeneous instance
    groups, or None when the job does not record it."""
    resource_config = job_details.get("ResourceConfig") or {}
    if not isinstance(resource_config, dict):
        return None
    groups = resource_config.get("InstanceGroups") or []
    if groups:
        counts = [group.get("InstanceCount") for group in groups]
        if all(isinstance(count, int) for count in counts):
            return sum(counts)
        return None
    count = resource_config.get("InstanceCount")
    return count if isinstance(count, int) else None


def _training_channel_unread_source(
    job_name: str, channel: Dict[str, Any], data_source: Dict[str, Any]
) -> List[str]:
    """
    Name the non-S3 training source whose encryption at rest this check does
    not read: a dataset ARN. File system sources are read separately.
    """
    label = f"training job '{job_name}' channel '{channel.get('ChannelName')}'"
    dataset = data_source.get("DatasetSource") or {}
    if dataset:
        return [
            f"{label} reads dataset {dataset.get('DatasetArn')}, whose encryption "
            "at rest this check does not read"
        ]
    return []


def _training_volume_encryption_findings(
    jobs_with_volume_key: List[Dict[str, Any]],
    jobs_without_volume_key: List[str],
    region: str,
) -> List[Dict[str, Any]]:
    """
    Report the training-volume leg of AIR-SGM-TRN-02.

    The incumbent legs cover OutputDataConfig.KmsKeyId (the model artifact) and
    EnableInterContainerTrafficEncryption (the wire between nodes). The storage
    volume that the training data is downloaded onto is a third stage with its
    own key, and none of the other legs can tell you about it.
    """
    emitted = []

    for job_name in jobs_without_volume_key[:20]:
        emitted.append(
            create_finding(
                check_id="SM-03",
                finding_name=TRAINING_VOLUME_ENCRYPTION_FINDING,
                finding_details=(
                    f"Training job '{job_name}' has no "
                    "ResourceConfig.VolumeKmsKeyId, so the ML storage volume "
                    "holding its training data used the EBS default key."
                ),
                resolution=TRAINING_VOLUME_ENCRYPTION_RESOLUTION,
                reference=TRAINING_VOLUME_ENCRYPTION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )

    if len(jobs_without_volume_key) > 20:
        emitted.append(
            create_finding(
                check_id="SM-03",
                finding_name=TRAINING_VOLUME_ENCRYPTION_FINDING,
                finding_details=(
                    f"{len(jobs_without_volume_key)} training jobs have no "
                    "ResourceConfig.VolumeKmsKeyId (the first 20 are reported "
                    "individually above)."
                ),
                resolution=TRAINING_VOLUME_ENCRYPTION_RESOLUTION,
                reference=TRAINING_VOLUME_ENCRYPTION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )

    if jobs_with_volume_key:
        described = ", ".join(
            "{} ({})".format(job["name"], job["key_id"])
            for job in jobs_with_volume_key[:3]
        )
        emitted.append(
            create_finding(
                check_id="SM-03",
                finding_name=TRAINING_VOLUME_ENCRYPTION_FINDING,
                finding_details=(
                    f"{len(jobs_with_volume_key)} training job(s) encrypt the ML "
                    f"storage volume with a named KMS key: {described}."
                ),
                resolution="No action required.",
                reference=TRAINING_VOLUME_ENCRYPTION_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )

    return emitted


def check_sagemaker_data_protection(region: str = "") -> Dict[str, Any]:
    """
    Check SageMaker data protection configurations including encryption at rest and in transit
    """
    logger.debug("Starting check for SageMaker data protection")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        # Track resources with encryption issues
        resources_with_aws_managed_keys = []
        resources_with_keys_not_enabled = []
        resources_without_encryption = []
        resources_without_vpc_encryption = []
        training_jobs_with_volume_key = []
        training_jobs_without_volume_key = []
        total_resources_checked = 0
        # AIR-SGM-TRN-02: a failed list or describe is named in an Incomplete
        # row, and the aggregate Passed row is withheld while any is unread.
        unread = []
        keyed = []
        bucket_users: Dict[str, List[str]] = {}

        def note_key(resource_type, name, key_id):
            keyed.append({"type": resource_type, "name": name, "key_id": key_id})

        training_file_systems: Dict[tuple, List[str]] = {}

        # Check Notebook Instances
        try:
            paginator = sagemaker_client.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for instance in page.get("NotebookInstances", []):
                    instance_name = instance.get("NotebookInstanceName")
                    if instance_name:
                        try:
                            instance_details = (
                                sagemaker_client.describe_notebook_instance(
                                    NotebookInstanceName=instance_name
                                )
                            )
                        except Exception as e:
                            unread.append(
                                f"sagemaker:DescribeNotebookInstance {instance_name} "
                                f"({get_assessment_error_label(e)})"
                            )
                            continue
                        total_resources_checked += 1

                        # Check KMS key usage
                        kms_key_id = instance_details.get("KmsKeyId")
                        if not kms_key_id:
                            resources_without_encryption.append(
                                {
                                    "type": "Notebook Instance",
                                    "name": instance_name,
                                    "issue": "No KMS key configured",
                                }
                            )
                        else:
                            note_key("Notebook Instance", instance_name, kms_key_id)
        except Exception as e:
            logger.error(f"Error checking notebook instances encryption: {str(e)}")
            unread.append(
                f"sagemaker:ListNotebookInstances ({get_assessment_error_label(e)})"
            )

        # Check SageMaker Domains
        try:
            paginator = sagemaker_client.get_paginator("list_domains")
            for page in paginator.paginate():
                for domain in page.get("Domains", []):
                    domain_id = domain.get("DomainId")
                    if domain_id:
                        try:
                            domain_details = sagemaker_client.describe_domain(
                                DomainId=domain_id
                            )
                        except Exception as e:
                            unread.append(
                                f"sagemaker:DescribeDomain {domain_id} "
                                f"({get_assessment_error_label(e)})"
                            )
                            continue
                        total_resources_checked += 1

                        # Check KMS key usage for domain
                        kms_key_id = domain_details.get("KmsKeyId")
                        if not kms_key_id:
                            resources_without_encryption.append(
                                {
                                    "type": "Domain",
                                    "name": domain_details.get("DomainName", domain_id),
                                    "issue": "No KMS key configured",
                                }
                            )
                        else:
                            note_key(
                                "Domain",
                                domain_details.get("DomainName", domain_id),
                                kms_key_id,
                            )

                        # Check VPC configuration
                        vpc_id = domain_details.get("VpcId")
                        subnet_ids = domain_details.get("SubnetIds", [])
                        if not vpc_id or not subnet_ids:
                            resources_without_vpc_encryption.append(
                                {
                                    "type": "Domain",
                                    "name": domain_details.get("DomainName", domain_id),
                                    "issue": "No VPC configuration",
                                }
                            )
        except Exception as e:
            logger.error(f"Error checking domain encryption: {str(e)}")
            unread.append(f"sagemaker:ListDomains ({get_assessment_error_label(e)})")

        # Check Training Jobs encryption
        try:
            paginator = sagemaker_client.get_paginator("list_training_jobs")
            for page in paginator.paginate():
                for job in page.get("TrainingJobSummaries", []):
                    job_name = job.get("TrainingJobName")
                    if job_name:
                        try:
                            job_details = sagemaker_client.describe_training_job(
                                TrainingJobName=job_name
                            )
                        except Exception as e:
                            unread.append(
                                f"sagemaker:DescribeTrainingJob {job_name} "
                                f"({get_assessment_error_label(e)})"
                            )
                            continue
                        total_resources_checked += 1

                        # Check output encryption
                        output_config = job_details.get("OutputDataConfig", {})
                        kms_key_id = output_config.get("KmsKeyId")

                        if not kms_key_id:
                            resources_without_encryption.append(
                                {
                                    "type": "Training Job",
                                    "name": job_name,
                                    "issue": "No output encryption configured",
                                }
                            )
                        else:
                            note_key("Training Job", job_name, kms_key_id)

                        # Inter-container encryption protects traffic between
                        # instances, so a single-instance job has none to protect.
                        if (
                            job_details.get("EnableInterContainerTrafficEncryption")
                            is not True
                            and _training_instance_count(job_details) != 1
                        ):
                            resources_without_vpc_encryption.append(
                                {
                                    "type": "Training Job",
                                    "name": job_name,
                                    "issue": "Inter-container traffic encryption not enabled",
                                }
                            )

                        # AIR-SGM-TRN-02 also covers the storage volume the
                        # training data is downloaded onto, which carries its own
                        # key separate from the output artifact key above.
                        resource_config = job_details.get("ResourceConfig") or {}
                        volume_key_id = (
                            resource_config.get("VolumeKmsKeyId")
                            if isinstance(resource_config, dict)
                            else None
                        )
                        if volume_key_id:
                            training_jobs_with_volume_key.append(
                                {"name": job_name, "key_id": volume_key_id}
                            )
                        else:
                            training_jobs_without_volume_key.append(job_name)

                        # The source and output buckets are the first and last
                        # stages of the pipeline the recommendation names.
                        for channel in job_details.get("InputDataConfig") or []:
                            data_source = channel.get("DataSource") or {}
                            source = data_source.get("S3DataSource") or {}
                            bucket = _s3_uri_bucket(source.get("S3Uri"))
                            if bucket:
                                bucket_users.setdefault(bucket, []).append(job_name)
                            file_system = data_source.get("FileSystemDataSource") or {}
                            if file_system:
                                training_file_systems.setdefault(
                                    (
                                        file_system.get("FileSystemType"),
                                        file_system.get("FileSystemId"),
                                    ),
                                    [],
                                ).append(
                                    f"training job '{job_name}' channel "
                                    f"'{channel.get('ChannelName')}'"
                                )
                            unread.extend(
                                _training_channel_unread_source(
                                    job_name, channel, data_source
                                )
                            )
                        bucket = _s3_uri_bucket(output_config.get("S3OutputPath"))
                        if bucket:
                            bucket_users.setdefault(bucket, []).append(job_name)
        except Exception as e:
            logger.error(f"Error checking training jobs encryption: {str(e)}")
            unread.append(
                f"sagemaker:ListTrainingJobs ({get_assessment_error_label(e)})"
            )

        # AIR-FND-DAT-01: an endpoint config keys its instance storage volume,
        # its captured requests and responses, and its asynchronous output
        # separately, and each is read.
        try:
            endpoint_inventory = _endpoint_hosting_inventory(sagemaker_client)
        except Exception as e:
            logger.error(f"Error checking endpoint config encryption: {str(e)}")
            unread.append(f"sagemaker:ListEndpoints ({get_assessment_error_label(e)})")
            endpoint_inventory = {"endpoints": [], "unread": []}
        unread.extend(endpoint_inventory["unread"])
        configs_seen = set()
        for endpoint in endpoint_inventory["endpoints"]:
            config_name = endpoint["config_name"]
            if config_name in configs_seen:
                continue
            configs_seen.add(config_name)
            total_resources_checked += 1
            config = endpoint["config"]
            label = f"{config_name}' of endpoint '{endpoint['name']}"
            legs = []
            # Serverless variants have no instance storage volume for the key.
            if any(v.get("InstanceType") for v in endpoint["variants"]):
                legs.append(
                    (
                        "Endpoint Config",
                        config.get("KmsKeyId"),
                        "No KmsKeyId, so the instance storage volume is not "
                        "encrypted with a customer managed key",
                    )
                )
            capture = config.get("DataCaptureConfig") or {}
            if capture.get("EnableCapture"):
                legs.append(
                    (
                        "Endpoint Config data capture",
                        capture.get("KmsKeyId"),
                        "DataCaptureConfig.KmsKeyId is not set, so captured "
                        "requests and responses in S3 are not encrypted with a "
                        "customer managed key",
                    )
                )
            async_config = config.get("AsyncInferenceConfig")
            if async_config:
                legs.append(
                    (
                        "Endpoint Config async output",
                        (async_config.get("OutputConfig") or {}).get("KmsKeyId"),
                        "AsyncInferenceConfig.OutputConfig.KmsKeyId is not set, so "
                        "asynchronous inference output in S3 is not encrypted with "
                        "a customer managed key",
                    )
                )
            for resource_type, key_id, issue in legs:
                if key_id:
                    note_key(resource_type, label, key_id)
                else:
                    resources_without_encryption.append(
                        {"type": resource_type, "name": label, "issue": issue}
                    )

        for (system_type, file_system_id), users in sorted(
            training_file_systems.items(), key=str
        ):
            read = _training_file_system_encryption(system_type, file_system_id, region)
            kind = f"{system_type} file system"
            if read["state"] == "unencrypted":
                resources_without_encryption.append(
                    {
                        "type": kind,
                        "name": file_system_id,
                        "issue": "Encryption at rest is not enabled (read by "
                        f"{', '.join(users[:3])})",
                    }
                )
            elif read["state"] == "service-key":
                resources_with_aws_managed_keys.append(
                    {
                        "type": kind,
                        "name": file_system_id,
                        "key_id": "the Amazon FSx service key of the account, "
                        "because its deployment type is SCRATCH",
                    }
                )
            elif read["state"] == "key":
                note_key(kind, file_system_id, read["key_id"])
            else:
                unread.append(
                    f"{', '.join(users[:3])} reads {kind} {file_system_id}, whose "
                    f"encryption at rest was not read ({read['detail']})"
                )

        # A key named on a resource can still be an AWS managed key, and the
        # key ARN does not say so; kms:DescribeKey returns its KeyManager.
        managers = _kms_key_managers(
            [item["key_id"] for item in keyed]
            + [job["key_id"] for job in training_jobs_with_volume_key],
            region,
        )
        for item in keyed:
            manager = managers[str(item["key_id"])]
            if manager["manager"] == "AWS":
                resources_with_aws_managed_keys.append(item)
            elif manager["manager"] == "CUSTOMER" and manager["state"] not in (
                None,
                "Enabled",
            ):
                resources_with_keys_not_enabled.append(
                    dict(item, state=manager["state"])
                )
            elif manager["manager"] is None:
                unread.append(
                    f"kms:DescribeKey {item['key_id']} for {item['type']} "
                    f"'{item['name']}' ({manager['error']})"
                )
        volume_keys_read = []
        for job in training_jobs_with_volume_key:
            manager = managers[str(job["key_id"])]
            if manager["manager"] == "CUSTOMER" and manager["state"] not in (
                None,
                "Enabled",
            ):
                resources_with_keys_not_enabled.append(
                    {
                        "type": "Training Job volume",
                        "name": job["name"],
                        "key_id": job["key_id"],
                        "state": manager["state"],
                    }
                )
            elif manager["manager"] == "CUSTOMER":
                volume_keys_read.append(job)
            elif manager["manager"] == "AWS":
                resources_with_aws_managed_keys.append(
                    {
                        "type": "Training Job volume",
                        "name": job["name"],
                        "key_id": job["key_id"],
                    }
                )
            else:
                unread.append(
                    f"kms:DescribeKey {job['key_id']} for the volume of training "
                    f"job '{job['name']}' ({manager['error']})"
                )
        training_jobs_with_volume_key = volume_keys_read

        bucket_findings = _bucket_protection_findings(
            "SM-03", TRAINING_BUCKET_FINDING, bucket_users, region
        )

        # Generate findings. The volume-key list is part of this guard so the
        # aggregate "all resources use appropriate encryption" row cannot be
        # emitted alongside a volume-key failure below.
        if (
            resources_without_encryption
            or resources_with_aws_managed_keys
            or resources_with_keys_not_enabled
            or resources_without_vpc_encryption
            or training_jobs_without_volume_key
            or unread
            or any(row["Status"] != "Passed" for row in bucket_findings)
        ):
            # Resources without encryption
            for resource in resources_without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="Missing Encryption Configuration",
                        finding_details=f"{resource['type']} '{resource['name']}' - {resource['issue']}",
                        resolution="Configure encryption using AWS KMS customer managed keys for enhanced security",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )

            # Resources using AWS managed keys
            for resource in resources_with_aws_managed_keys:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="AWS Managed Key Usage",
                        finding_details=f"{resource['type']} '{resource['name']}' uses AWS managed key {resource['key_id']}",
                        resolution="Consider using customer managed keys for better control over encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity="Low",
                        status="Failed",
                        region=region,
                    )
                )

            for resource in resources_with_keys_not_enabled:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name=KEY_NOT_ENABLED_FINDING,
                        finding_details=(
                            f"{resource['type']} '{resource['name']}' uses customer "
                            f"managed key {resource['key_id']}, whose "
                            f"kms:DescribeKey KeyState is {resource['state']}, "
                            "not Enabled."
                        ),
                        resolution=(
                            "Enable the key, or cancel its scheduled deletion, or "
                            "move the resource to an enabled customer managed key."
                        ),
                        reference="https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )

            # Resources without VPC encryption
            for resource in resources_without_vpc_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="Missing VPC Encryption",
                        finding_details=f"{resource['type']} '{resource['name']}' - {resource['issue']}",
                        resolution="Enable encryption for inter-container traffic and VPC communication",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-in-transit.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

        else:
            if total_resources_checked > 0:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="Data Protection Check",
                        finding_details="All resources use appropriate encryption configurations",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="Data Protection Check",
                        finding_details="No SageMaker resources found to check for data protection",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        if unread:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-03",
                    "SageMaker Data Protection Check",
                    unread,
                    f"{total_resources_checked} resource(s) were described.",
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region,
                )
            )

        findings["csv_data"].extend(
            _training_volume_encryption_findings(
                training_jobs_with_volume_key,
                training_jobs_without_volume_key,
                region,
            )
        )
        findings["csv_data"].extend(bucket_findings)

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_data_protection: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-03",
                    finding_name="SageMaker Data Protection Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_mlops_utilization(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    """
    Check if SageMaker MLOps features (Model Registry, Feature Store, and Pipelines)
    are being utilized properly
    """
    logger.debug("Starting check for SageMaker MLOps features utilization")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        issues_found = []

        # Check Model Registry Usage
        try:
            model_packages = []
            paginator = sagemaker_client.get_paginator("list_model_package_groups")
            for page in paginator.paginate():
                model_packages.extend(page.get("ModelPackageGroupSummaryList", []))

            if not model_packages:
                issues_found.append(
                    {
                        "component": "Model Registry",
                        "issue": "No model package groups found",
                        "impact": "Model versioning and governance may not be properly tracked",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )
            else:
                # Check if models are being versioned
                for group in model_packages:
                    group_name = group.get("ModelPackageGroupName")
                    if group_name:
                        packages = list_all_model_packages(sagemaker_client, group_name)
                        if len(packages) <= 1:
                            issues_found.append(
                                {
                                    "component": "Model Registry",
                                    "issue": f"Model group '{group_name}' has minimal versioning",
                                    "impact": "Limited model version tracking detected",
                                    "severity": "Low",
                                    "status": "Failed",
                                }
                            )
        except Exception as e:
            logger.error(f"Error checking Model Registry: {str(e)}")
            issues_found.append(
                {
                    "component": "Model Registry",
                    "issue": f"Error checking configuration: {str(e)}",
                    "impact": "Unable to verify model versioning",
                    "severity": "High",
                    "status": "Failed",
                }
            )

        # Check Feature Store Usage
        try:
            feature_groups = []
            paginator = sagemaker_client.get_paginator("list_feature_groups")
            for page in paginator.paginate():
                feature_groups.extend(page.get("FeatureGroupSummaries", []))

            if not feature_groups:
                issues_found.append(
                    {
                        "component": "Feature Store",
                        "issue": "No feature groups found",
                        "impact": "Feature reuse and sharing may be limited",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )
            else:
                # Check feature group status and configuration
                for group in feature_groups:
                    if group.get("FeatureGroupStatus") != "Created":
                        issues_found.append(
                            {
                                "component": "Feature Store",
                                "issue": f"Feature group '{group.get('FeatureGroupName')}' is not in Created state",
                                "impact": "Feature group may not be properly configured",
                                "severity": "Medium",
                                "status": "Failed",
                            }
                        )
        except Exception as e:
            logger.error(f"Error checking Feature Store: {str(e)}")
            issues_found.append(
                {
                    "component": "Feature Store",
                    "issue": f"Error checking configuration: {str(e)}",
                    "impact": "Unable to verify feature management",
                    "severity": "High",
                    "status": "Failed",
                }
            )

        # Check Pipeline Usage
        try:
            pipelines = []
            paginator = sagemaker_client.get_paginator("list_pipelines")
            for page in paginator.paginate():
                pipelines.extend(page.get("PipelineSummaries", []))

            if not pipelines:
                issues_found.append(
                    {
                        "component": "Pipelines",
                        "issue": "No ML pipelines found",
                        "impact": "Automated ML workflows may not be implemented",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )
            else:
                # Check pipeline status and execution history
                for pipeline in pipelines:
                    pipeline_name = pipeline.get("PipelineName")
                    if pipeline_name:
                        executions = sagemaker_client.list_pipeline_executions(
                            PipelineName=pipeline_name, MaxResults=1
                        )
                        if not executions.get("PipelineExecutionSummaries"):
                            issues_found.append(
                                {
                                    "component": "Pipelines",
                                    "issue": f"Pipeline '{pipeline_name}' has no execution history",
                                    "impact": "Pipeline may be defined but not actively used",
                                    "severity": "Low",
                                    "status": "Failed",
                                }
                            )
        except Exception as e:
            logger.error(f"Error checking Pipelines: {str(e)}")
            issues_found.append(
                {
                    "component": "Pipelines",
                    "issue": f"Error checking configuration: {str(e)}",
                    "impact": "Unable to verify pipeline automation",
                    "severity": "High",
                    "status": "Failed",
                }
            )

        # Generate findings based on issues found
        if issues_found:
            findings["status"] = "WARN"
            findings["details"] = (
                f"Found {len(issues_found)} issues with SageMaker MLOps features"
            )

            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-05",
                        finding_name=f"SageMaker {issue['component']} Issue",
                        finding_details=issue["issue"],
                        resolution=get_resolution_for_component(issue["component"]),
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html",
                        severity=issue["severity"],
                        status=issue["status"],
                        region=region,
                    )
                )
        else:
            findings["details"] = "All SageMaker MLOps features are properly utilized"
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-05",
                    finding_name="SageMaker MLOps Features Check",
                    finding_details="All SageMaker MLOps features are properly utilized",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html",
                    severity="Low",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_mlops_utilization: {str(e)}", exc_info=True
        )
        return {
            "check_name": "SageMaker MLOps Features Utilization Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
        }


def get_resolution_for_component(component: str) -> str:
    """
    Helper function to provide specific resolutions based on the component
    """
    resolutions = {
        "Model Registry": (
            "Implement model versioning using SageMaker Model Registry to track model lineage, "
            "approve model versions, and manage model deployment"
        ),
        "Feature Store": (
            "Utilize SageMaker Feature Store to create, share, and manage features "
            "for machine learning development and production"
        ),
        "Pipelines": (
            "Implement SageMaker Pipelines to automate and manage ML workflows, "
            "including data preparation, training, and model deployment"
        ),
    }
    return resolutions.get(
        component, "Review and implement appropriate SageMaker MLOps features"
    )


def check_sagemaker_clarify_usage(permission_cache, region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker Clarify is being used for bias detection and model explainability
    """
    logger.debug("Starting check for SageMaker Clarify usage")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        issues_found = []

        try:
            # Check Processing Jobs for Clarify
            paginator = sagemaker_client.get_paginator("list_processing_jobs")
            clarify_jobs_found = False

            for page in paginator.paginate():
                for job in page["ProcessingJobSummaries"]:
                    job_name = job["ProcessingJobName"]
                    job_details = sagemaker_client.describe_processing_job(
                        ProcessingJobName=job_name
                    )

                    # Check if it's a Clarify job
                    if (
                        "clarify"
                        in job_details.get("AppSpecification", {})
                        .get("ImageUri", "")
                        .lower()
                    ):
                        clarify_jobs_found = True
                        # Check job status
                        if job_details["ProcessingJobStatus"] == "Failed":
                            issues_found.append(
                                {
                                    "issue_type": "Failed Clarify Job",
                                    "details": f"Clarify job {job_name} failed",
                                    "severity": "High",
                                    "status": "Failed",
                                }
                            )

            if not clarify_jobs_found:
                issues_found.append(
                    {
                        "issue_type": "No Clarify Usage",
                        "details": "No SageMaker Clarify jobs found",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )

        except Exception as e:
            logger.error(f"Error checking Clarify jobs: {str(e)}")
            issues_found.append(
                {
                    "issue_type": "Clarify Check Error",
                    "details": f"Error checking Clarify configuration: {str(e)}",
                    "severity": "High",
                    "status": "Failed",
                }
            )

        if issues_found:
            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-06",
                        finding_name=f"SageMaker Clarify {issue['issue_type']}",
                        finding_details=issue["details"],
                        resolution="Implement SageMaker Clarify for model explainability and bias detection",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-configure-processing-jobs.html",
                        severity=issue["severity"],
                        status=issue["status"],
                        region=region,
                    )
                )
        else:
            findings["details"] = "SageMaker Clarify is properly utilized"
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-06",
                    finding_name="SageMaker Clarify Usage Check",
                    finding_details="SageMaker Clarify is properly utilized",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-configure-processing-jobs.html",
                    severity="Low",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_sagemaker_clarify_usage: {str(e)}", exc_info=True)
        return {
            "check_name": "SageMaker Clarify Usage Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
        }


def check_sagemaker_model_monitor_usage(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    """
    Check if SageMaker Model Monitor is configured and actively monitoring models
    """
    # FinServ extension (FS-17): The FinServ guide (PDF §1.2.14) asks for Model
    # Monitor data-quality baselines to be refreshed on a regulator-aligned cadence
    # (SR 11-7 ongoing monitoring) and for the baseline statistics to be emitted to
    # CloudWatch under namespace /aws/sagemaker/Endpoints/data-metric with
    # emit_metrics=Enabled. See docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md
    # (FS-17 → SM-07 extension note).
    logger.debug("Starting check for SageMaker Model Monitor usage")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        issues_found = []

        try:
            # Check monitoring schedules
            paginator = sagemaker_client.get_paginator("list_monitoring_schedules")
            monitoring_found = False

            for page in paginator.paginate():
                for schedule in page["MonitoringScheduleSummaries"]:
                    monitoring_found = True
                    schedule_name = schedule["MonitoringScheduleName"]
                    schedule_details = sagemaker_client.describe_monitoring_schedule(
                        MonitoringScheduleName=schedule_name
                    )

                    # Check schedule status
                    if schedule_details["MonitoringScheduleStatus"] != "Scheduled":
                        issues_found.append(
                            {
                                "issue_type": "Inactive Monitor",
                                "details": f"Monitoring schedule {schedule_name} is not active",
                                "severity": "Medium",
                                "status": "Failed",
                            }
                        )

            if not monitoring_found:
                issues_found.append(
                    {
                        "issue_type": "No Model Monitoring",
                        "details": "No Model Monitor schedules found",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )

        except Exception as e:
            logger.error(f"Error checking Model Monitor: {str(e)}")
            issues_found.append(
                {
                    "issue_type": "Monitor Check Error",
                    "details": f"Error checking Model Monitor configuration: {str(e)}",
                    "severity": "High",
                    "status": "Failed",
                }
            )

        if issues_found:
            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-07",
                        finding_name=f"SageMaker Model Monitor {issue['issue_type']}",
                        finding_details=issue["details"],
                        resolution="Configure comprehensive model monitoring schedules",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity=issue["severity"],
                        status=issue["status"],
                        region=region,
                    )
                )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-07",
                    finding_name="SageMaker Model Monitor Usage Check",
                    finding_details="SageMaker Model Monitor is actively tracking model performance",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_monitor_usage: {str(e)}", exc_info=True
        )
        return {
            "check_name": "SageMaker Model Monitor Usage Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
        }


NOTEBOOK_ROOT_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html"
)
NOTEBOOK_ROLE_PRIVILEGE_FINDING = "SageMaker Development Environment Execution Role"
NOTEBOOK_ROLE_PRIVILEGE_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html"
)
# AWS managed policies that grant a development environment every SageMaker
# action or more. The recommendation names AmazonSageMakerFullAccess.
BROAD_MANAGED_POLICY_NAMES = (
    "AmazonSageMakerFullAccess",
    "AdministratorAccess",
    "PowerUserAccess",
)
NOTEBOOK_TRAIL_FINDING = "SageMaker Development Environment API Logging"
NOTEBOOK_TRAIL_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/logging-using-cloudtrail.html"
)
NOTEBOOK_CONFIG_RULES_FINDING = "SageMaker Notebook Config Rules"
NOTEBOOK_CONFIG_RULES_REFERENCE = (
    "https://docs.aws.amazon.com/config/latest/developerguide/"
    "sagemaker-notebook-instance-kms-key-configured.html"
)
NOTEBOOK_CONFIG_RULE_IDENTIFIERS = (
    "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS",
    "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED",
)
NOTEBOOK_KMS_RULE_IDENTIFIER = "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED"
SAGEMAKER_EVENT_SOURCE = "sagemaker.amazonaws.com"


def _role_name_from_arn(role_arn: str) -> str:
    return str(role_arn).rsplit("/", 1)[-1]


SAGEMAKER_RESOURCE_PROBE = "arn:aws:sagemaker:us-east-1:123456789012:zz-probe/zz-probe"


def _broad_role_grant(permissions: Dict[str, Any]) -> Optional[str]:
    """
    Return why a role holds every SageMaker action or more, or None.

    A permissions boundary that does not allow every SageMaker action caps the
    role, so it is not reported.
    """
    if not _boundary_allows_every_sagemaker_action(
        permissions.get("permissions_boundary")
    ):
        return None
    for policy in permissions.get("attached_policies") or []:
        arn = str(policy.get("arn") or "")
        for name in BROAD_MANAGED_POLICY_NAMES:
            if re.fullmatch(rf"arn:[^:]+:iam::aws:policy/(.*/)?{name}", arn):
                return f"AWS managed policy {name}"
    for policy in (permissions.get("attached_policies") or []) + (
        permissions.get("inline_policies") or []
    ):
        if ":iam::aws:policy/" in str(policy.get("arn") or ""):
            continue
        for statement in _sm_policy_statements(policy.get("document")):
            if str(statement.get("Effect", "")).upper() != "ALLOW":
                continue
            if any(a.strip() == "*" for a in _policy_values(statement.get("Action"))):
                return f"policy '{policy.get('name') or 'inline'}' allows Action '*'"
            reason = _service_wide_sagemaker_grant(statement)
            if reason:
                return (
                    f"policy '{policy.get('name') or 'inline'}' allows every "
                    f"SageMaker action through {reason}"
                )
            # AIR-SGM-TRN-05: a partial wildcard such as sagemaker:Create* on
            # every resource reaches every experiment's resources as well.
            every_resource = "NotResource" in statement or any(
                fnmatch.fnmatchcase(SAGEMAKER_RESOURCE_PROBE, str(r).lower())
                for r in _policy_values(statement.get("Resource"))
            )
            partial = [
                a
                for a in _policy_values(statement.get("Action"))
                if ("*" in a or "?" in a) and _pattern_may_match_sagemaker(a)
            ]
            if every_resource and partial:
                return (
                    f"policy '{policy.get('name') or 'inline'}' allows wildcard "
                    f"SageMaker action(s) {', '.join(partial[:3])} on every resource"
                )
    return None


def _environment_role_findings(
    environment_roles: List[tuple],
    permission_cache: Optional[Dict[str, Any]],
    region: str,
) -> List[Dict[str, Any]]:
    """
    Judge each development environment's execution role from the IAM cache.

    environment_roles holds (environment label, role ARN) pairs.
    """
    if not environment_roles:
        return []
    broad = []
    unread = []
    if permission_cache is None:
        unread = [
            f"{label} role {role_arn} (the IAM permissions cache was not available)"
            for label, role_arn in environment_roles
        ]
    else:
        cached = permission_cache.get("role_permissions") or {}
        unread_principals = set(_principal_read_errors(permission_cache) or [])
        for label, role_arn in environment_roles:
            name = _role_name_from_arn(role_arn)
            if name not in cached:
                unread.append(f"{label} role {role_arn} (not in the IAM cache)")
                continue
            reason = _broad_role_grant(cached[name])
            if (
                reason
                and cached[name].get("permissions_boundary") is None
                and ("role", name) in _boundary_unread(permission_cache)
            ):
                unread.append(
                    f"{label} role {role_arn} ({reason}; its permissions boundary "
                    "was not read)"
                )
            elif reason:
                broad.append(f"{label} runs as role '{name}', which holds {reason}")
            elif any(p.startswith(f"role '{name}' ") for p in unread_principals):
                unread.append(f"{label} role {role_arn} (IAM cache read error)")
    rows = []
    for entry in broad[:20]:
        rows.append(
            create_finding(
                check_id="SM-09",
                finding_name=NOTEBOOK_ROLE_PRIVILEGE_FINDING,
                finding_details=(
                    f"{entry}. A development environment with this role can act "
                    "on every SageMaker resource, not only its experiment's. "
                    f"{SCP_NOT_EVALUATED_NOTE}"
                ),
                resolution=(
                    "Replace the broad grant with a least-privilege execution role "
                    "scoped to the environment's buckets, keys and resources."
                ),
                reference=NOTEBOOK_ROLE_PRIVILEGE_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )
    if len(broad) > 20:
        rows.append(
            create_finding(
                check_id="SM-09",
                finding_name=NOTEBOOK_ROLE_PRIVILEGE_FINDING,
                finding_details=(
                    f"{len(broad) - 20} more development environment(s) run as a "
                    "role with a service-wide or administrator grant."
                ),
                resolution="Review the remaining execution roles.",
                reference=NOTEBOOK_ROLE_PRIVILEGE_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-09",
                NOTEBOOK_ROLE_PRIVILEGE_FINDING,
                unread,
                f"{len(environment_roles) - len(unread)} execution role(s) were read.",
                NOTEBOOK_ROLE_PRIVILEGE_REFERENCE,
                region,
            )
        )
    elif not broad:
        rows.append(
            create_finding(
                check_id="SM-09",
                finding_name=NOTEBOOK_ROLE_PRIVILEGE_FINDING,
                finding_details=(
                    f"None of the {len(environment_roles)} development environment "
                    "execution role(s) holds AmazonSageMakerFullAccess, an "
                    "administrator policy, Action '*', every SageMaker action, or "
                    "a wildcard SageMaker action on every resource. "
                    f"{SCP_NOT_EVALUATED_NOTE}"
                ),
                resolution="No action required",
                reference=NOTEBOOK_ROLE_PRIVILEGE_REFERENCE,
                severity="High",
                status="Passed",
                region=region,
            )
        )
    return rows


def _advanced_selector_management_coverage(selector: Dict[str, Any]) -> set:
    """Return which of {"read", "write"} management events a selector records."""
    fields = {
        str(field.get("Field")): field for field in selector.get("FieldSelectors") or []
    }
    category = fields.get("eventCategory") or {}
    if "Management" not in (category.get("Equals") or []):
        return set()
    for name, field in fields.items():
        if name in ("eventCategory", "readOnly"):
            continue
        if name != "eventSource":
            # Any other field narrows the selector in a way this check does
            # not judge, so the selector is not counted.
            return set()
        allowed = set(field) - {"Field"}
        if allowed - {"Equals", "NotEquals"}:
            return set()
        if "Equals" in field and SAGEMAKER_EVENT_SOURCE not in field["Equals"]:
            return set()
        if SAGEMAKER_EVENT_SOURCE in (field.get("NotEquals") or []):
            return set()
    read_only = fields.get("readOnly")
    if read_only is None:
        return {"read", "write"}
    if set(read_only) - {"Field", "Equals"}:
        return set()
    values = {str(v).lower() for v in read_only.get("Equals") or []}
    return ({"read"} if "true" in values else set()) | (
        {"write"} if "false" in values else set()
    )


def _selectors_record_sagemaker_management(selectors: Dict[str, Any]) -> bool:
    """Return whether a trail's selectors record read and write SageMaker calls."""
    covered = set()
    for selector in selectors.get("EventSelectors") or []:
        if selector.get("IncludeManagementEvents") is not True:
            continue
        if SAGEMAKER_EVENT_SOURCE in (
            selector.get("ExcludeManagementEventSources") or []
        ):
            continue
        read_write = selector.get("ReadWriteType")
        if read_write == "All":
            covered |= {"read", "write"}
        elif read_write == "ReadOnly":
            covered.add("read")
        elif read_write == "WriteOnly":
            covered.add("write")
    for selector in selectors.get("AdvancedEventSelectors") or []:
        covered |= _advanced_selector_management_coverage(selector)
    return covered == {"read", "write"}


def _environment_trail_finding(region: str) -> Dict[str, Any]:
    """
    Report whether one logging trail sends this Region's SageMaker management
    events, read and write, to CloudWatch Logs.
    """
    cloudtrail_client = boto3.client(
        "cloudtrail", config=boto3_config, region_name=region
    )
    try:
        trails = cloudtrail_client.describe_trails(includeShadowTrails=True).get(
            "trailList", []
        )
    except Exception as error:
        return _unread_resources_finding(
            "SM-09",
            NOTEBOOK_TRAIL_FINDING,
            [f"cloudtrail:DescribeTrails ({get_assessment_error_label(error)})"],
            "no trail was read.",
            NOTEBOOK_TRAIL_REFERENCE,
            region,
        )
    problems = []
    unread = []
    for trail in trails:
        name = trail.get("Name") or trail.get("TrailARN")
        trail_id = trail.get("TrailARN") or name
        if not trail.get("IsMultiRegionTrail") and trail.get("HomeRegion") != region:
            continue
        if not trail.get("CloudWatchLogsLogGroupArn"):
            problems.append(f"trail '{name}' does not deliver to CloudWatch Logs")
            continue
        home_client = boto3.client(
            "cloudtrail",
            config=boto3_config,
            region_name=trail.get("HomeRegion") or region,
        )
        try:
            status = home_client.get_trail_status(Name=trail_id)
            selectors = home_client.get_event_selectors(TrailName=trail_id)
        except Exception as error:
            unread.append(f"trail '{name}' ({get_assessment_error_label(error)})")
            continue
        if status.get("IsLogging") is not True:
            problems.append(f"trail '{name}' is not logging")
            continue
        # AIR-SGM-TRN-05: a trail can log while CloudWatch Logs delivery fails.
        if status.get("LatestCloudWatchLogsDeliveryError"):
            problems.append(
                f"trail '{name}' reports CloudWatch Logs delivery error "
                f"{str(status['LatestCloudWatchLogsDeliveryError'])[:120]}"
            )
            continue
        if not status.get("LatestCloudWatchLogsDeliveryTime"):
            problems.append(f"trail '{name}' has no recorded CloudWatch Logs delivery")
            continue
        if not _selectors_record_sagemaker_management(selectors):
            problems.append(
                f"trail '{name}' does not record both read and write SageMaker "
                "management events"
            )
            continue
        return create_finding(
            check_id="SM-09",
            finding_name=NOTEBOOK_TRAIL_FINDING,
            finding_details=(
                f"Trail '{name}' is logging, covers {region}, records read and "
                "write SageMaker management events and delivers them to CloudWatch "
                f"Logs group {trail['CloudWatchLogsLogGroupArn']}, last at "
                f"{status['LatestCloudWatchLogsDeliveryTime']} with no delivery "
                "error reported."
            ),
            resolution="No action required",
            reference=NOTEBOOK_TRAIL_REFERENCE,
            severity="Medium",
            status="Passed",
            region=region,
        )
    if unread:
        return _unread_resources_finding(
            "SM-09",
            NOTEBOOK_TRAIL_FINDING,
            unread,
            "; ".join(problems[:5]) or "no other trail covers this Region.",
            NOTEBOOK_TRAIL_REFERENCE,
            region,
        )
    return create_finding(
        check_id="SM-09",
        finding_name=NOTEBOOK_TRAIL_FINDING,
        finding_details=(
            "No logging trail records this Region's SageMaker management events "
            "and delivers them to CloudWatch Logs, so notebook and Studio access "
            "(CreatePresignedNotebookInstanceUrl, CreatePresignedDomainUrl) is not "
            f"monitored like production access. {'; '.join(problems[:5])}"
        ).strip(),
        resolution=(
            "Configure a multi-Region trail that records read and write "
            "management events, and set its CloudWatch Logs log group."
        ),
        reference=NOTEBOOK_TRAIL_REFERENCE,
        severity="Medium",
        status="Failed",
        region=region,
    )


def _managed_rule_problems(
    rules: List[Dict[str, Any]], identifiers: Tuple[str, ...], pinned: Tuple[str, ...]
) -> Tuple[List[str], List[str]]:
    """
    Match each AWS managed rule identifier to an ACTIVE rule that is not scoped
    to named or tagged resources, and for a pinned identifier sets kmsKeyArns.
    Returns (problems, passing) as display strings.
    """
    problems = []
    passing = []
    for identifier in identifiers:
        matches = [
            rule
            for rule in rules
            if (rule.get("Source") or {}).get("Owner") == "AWS"
            and (rule.get("Source") or {}).get("SourceIdentifier") == identifier
            and rule.get("ConfigRuleState") == "ACTIVE"
        ]
        reasons = []
        chosen = None
        for rule in matches:
            scope = rule.get("Scope") or {}
            if scope.get("ComplianceResourceId") or scope.get("TagKey"):
                reasons.append(
                    f"rule '{rule.get('ConfigRuleName')}' is scoped to named or "
                    "tagged resources"
                )
                continue
            if identifier in pinned:
                try:
                    parameters = json.loads(rule.get("InputParameters") or "{}")
                except ValueError:
                    parameters = {}
                if not str(parameters.get("kmsKeyArns") or "").strip():
                    reasons.append(
                        f"rule '{rule.get('ConfigRuleName')}' has no kmsKeyArns, so "
                        "any key passes"
                    )
                    continue
            chosen = rule
            break
        if chosen:
            passing.append(f"{identifier} as '{chosen.get('ConfigRuleName')}'")
        elif reasons:
            problems.append(f"{identifier}: {'; '.join(reasons[:3])}")
        else:
            problems.append(f"{identifier}: no ACTIVE rule")
    return problems, passing


def _notebook_config_rules_finding(region: str) -> Dict[str, Any]:
    """Report whether the two notebook Config rules are active and unnarrowed."""
    config_client = boto3.client("config", config=boto3_config, region_name=region)
    rules = []
    try:
        for page in config_client.get_paginator("describe_config_rules").paginate():
            rules.extend(page.get("ConfigRules", []))
    except Exception as error:
        return _unread_resources_finding(
            "SM-09",
            NOTEBOOK_CONFIG_RULES_FINDING,
            [f"config:DescribeConfigRules ({get_assessment_error_label(error)})"],
            "no Config rule was read.",
            NOTEBOOK_CONFIG_RULES_REFERENCE,
            region,
        )
    problems, passing = _managed_rule_problems(
        rules, NOTEBOOK_CONFIG_RULE_IDENTIFIERS, (NOTEBOOK_KMS_RULE_IDENTIFIER,)
    )
    if problems:
        return create_finding(
            check_id="SM-09",
            finding_name=NOTEBOOK_CONFIG_RULES_FINDING,
            finding_details=(
                f"{len(problems)} of {len(NOTEBOOK_CONFIG_RULE_IDENTIFIERS)} notebook "
                f"Config rules are missing or narrowed in {region}: "
                f"{'; '.join(problems)}."
            ),
            resolution=(
                "Deploy sagemaker-notebook-no-direct-internet-access and "
                "sagemaker-notebook-instance-kms-key-configured with kmsKeyArns set "
                "to the approved keys, unscoped by resource id or tag."
            ),
            reference=NOTEBOOK_CONFIG_RULES_REFERENCE,
            severity="Medium",
            status="Failed",
            region=region,
        )
    return create_finding(
        check_id="SM-09",
        finding_name=NOTEBOOK_CONFIG_RULES_FINDING,
        finding_details=(
            f"Both notebook Config rules are active in {region}: "
            f"{'; '.join(passing)}. Both are periodic, so they detect a "
            "non-compliant notebook after it exists."
        ),
        resolution="No action required",
        reference=NOTEBOOK_CONFIG_RULES_REFERENCE,
        severity="Medium",
        status="Passed",
        region=region,
    )


def check_sagemaker_notebook_root_access(
    region: str = "", permission_cache: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Check if SageMaker notebook instances have root access disabled.
    Root access enables privilege escalation and should be disabled for security.
    Aligns with AWS Security Hub control SageMaker.3

    AIR-SGM-TRN-05 also reads each notebook and Studio execution role's
    privilege, the trail that logs their access and the notebook Config rules.
    """
    logger.debug("Starting check for SageMaker notebook root access")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        notebooks_with_root = []
        notebooks_without_root = []
        unread = []
        environment_roles = []
        environments_found = 0

        paginator = sagemaker_client.get_paginator("list_notebook_instances")
        for page in paginator.paginate():
            for instance in page.get("NotebookInstances", []):
                instance_name = instance.get("NotebookInstanceName")
                if not instance_name:
                    continue
                environments_found += 1
                try:
                    instance_details = sagemaker_client.describe_notebook_instance(
                        NotebookInstanceName=instance_name
                    )
                except Exception as e:
                    unread.append(
                        f"sagemaker:DescribeNotebookInstance {instance_name} "
                        f"({get_assessment_error_label(e)})"
                    )
                    continue

                if instance_details.get("RoleArn"):
                    environment_roles.append(
                        (
                            f"Notebook instance '{instance_name}'",
                            instance_details["RoleArn"],
                        )
                    )

                root_access = instance_details.get("RootAccess", "Enabled")

                if root_access == "Enabled":
                    notebooks_with_root.append(
                        {
                            "name": instance_name,
                            "status": instance_details.get(
                                "NotebookInstanceStatus", "Unknown"
                            ),
                        }
                    )
                else:
                    notebooks_without_root.append(instance_name)

        environment_unread = []
        try:
            domains = []
            for page in sagemaker_client.get_paginator("list_domains").paginate():
                domains.extend(page.get("Domains", []))
        except Exception as e:
            domains = []
            environment_unread.append(
                f"sagemaker:ListDomains ({get_assessment_error_label(e)})"
            )
        for domain in domains:
            domain_id = domain.get("DomainId")
            if not domain_id:
                continue
            environments_found += 1
            try:
                domain_details = sagemaker_client.describe_domain(DomainId=domain_id)
            except Exception as e:
                environment_unread.append(
                    f"sagemaker:DescribeDomain {domain_id} "
                    f"({get_assessment_error_label(e)})"
                )
                continue
            default_role = (domain_details.get("DefaultUserSettings") or {}).get(
                "ExecutionRole"
            )
            if default_role:
                environment_roles.append(
                    (f"Studio domain '{domain_id}' default", default_role)
                )
            space_role = (domain_details.get("DefaultSpaceSettings") or {}).get(
                "ExecutionRole"
            )
            if space_role:
                environment_roles.append(
                    (f"Studio domain '{domain_id}' default space", space_role)
                )
            try:
                profiles = []
                for page in sagemaker_client.get_paginator(
                    "list_user_profiles"
                ).paginate(DomainIdEquals=domain_id):
                    profiles.extend(page.get("UserProfiles", []))
            except Exception as e:
                environment_unread.append(
                    f"sagemaker:ListUserProfiles {domain_id} "
                    f"({get_assessment_error_label(e)})"
                )
                continue
            for profile in profiles:
                profile_name = profile.get("UserProfileName")
                if not profile_name:
                    continue
                try:
                    profile_details = sagemaker_client.describe_user_profile(
                        DomainId=domain_id, UserProfileName=profile_name
                    )
                except Exception as e:
                    environment_unread.append(
                        f"sagemaker:DescribeUserProfile {domain_id}/{profile_name} "
                        f"({get_assessment_error_label(e)})"
                    )
                    continue
                profile_role = (profile_details.get("UserSettings") or {}).get(
                    "ExecutionRole"
                )
                if profile_role:
                    environment_roles.append(
                        (
                            f"Studio user profile '{domain_id}/{profile_name}'",
                            profile_role,
                        )
                    )

        if notebooks_with_root:
            for notebook in notebooks_with_root:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-09",
                        finding_name="SageMaker Notebook Root Access Enabled",
                        finding_details=f"Notebook instance '{notebook['name']}' has root access enabled. Root access allows users to install arbitrary software, modify system configurations, and potentially escalate privileges.",
                        resolution="Disable root access by updating the notebook instance with RootAccess=Disabled. Note: Lifecycle configurations will still run with root access.",
                        reference=NOTEBOOK_ROOT_REFERENCE,
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        elif unread:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-09",
                    "SageMaker Notebook Root Access Check",
                    unread,
                    f"{len(notebooks_without_root)} notebook instance(s) have root "
                    "access disabled.",
                    NOTEBOOK_ROOT_REFERENCE,
                    region,
                )
            )
        else:
            if notebooks_without_root:
                # Notebooks exist and all have root access disabled - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-09",
                        finding_name="SageMaker Notebook Root Access Check",
                        finding_details=f"All {len(notebooks_without_root)} notebook instances have root access disabled",
                        resolution="No action required",
                        reference=NOTEBOOK_ROOT_REFERENCE,
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No notebook instances found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-09",
                        finding_name="SageMaker Notebook Root Access Check",
                        finding_details="No notebook instances found",
                        resolution="No action required",
                        reference=NOTEBOOK_ROOT_REFERENCE,
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
        if notebooks_with_root and unread:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-09",
                    "SageMaker Notebook Root Access Check",
                    unread,
                    f"{len(notebooks_with_root)} notebook instance(s) have root "
                    "access enabled.",
                    NOTEBOOK_ROOT_REFERENCE,
                    region,
                )
            )

        role_rows = _environment_role_findings(
            environment_roles, permission_cache, region
        )
        if environment_unread:
            role_rows = [row for row in role_rows if row["Status"] != "Passed"] + [
                _unread_resources_finding(
                    "SM-09",
                    NOTEBOOK_ROLE_PRIVILEGE_FINDING,
                    environment_unread,
                    f"{len(environment_roles)} execution role(s) were found.",
                    NOTEBOOK_ROLE_PRIVILEGE_REFERENCE,
                    region,
                )
            ]
        findings["csv_data"].extend(role_rows)

        # The monitoring half of AIR-SGM-TRN-05 applies where development
        # environments exist, or where the inventory could not rule them out.
        if environments_found or unread or environment_unread:
            findings["csv_data"].append(_environment_trail_finding(region))
            findings["csv_data"].append(_notebook_config_rules_finding(region))

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_notebook_root_access: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-09",
                    finding_name="SageMaker Notebook Root Access Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


STUDIO_DOMAIN_NETWORK_FINDING = "SageMaker Studio Domain Network Boundary"
STUDIO_DOMAIN_SUBNET_EXPOSURE_FINDING = (
    "SageMaker Studio Domain Subnet Internet Exposure"
)
STUDIO_DOMAIN_NETWORK_REFERENCE = "https://docs.aws.amazon.com/sagemaker/latest/dg/studio-notebooks-and-internet-access.html"


def _studio_domain_network_findings(
    sagemaker_client: Any, region: str
) -> List[Dict[str, Any]]:
    """SM-10 Studio domain leg of AIR-FND-NET-01.

    DescribeDomain reports AppNetworkAccessType. PublicInternetOnly, the default,
    sends non-EFS traffic through a SageMaker-managed VPC that allows direct
    internet access. VpcOnly sends all traffic through the domain's SubnetIds,
    whose route tables then decide whether the domain is private. No domain
    yields no row.
    """
    rows: List[Dict[str, Any]] = []
    in_vpc: List[Dict[str, Any]] = []
    public: List[str] = []
    try:
        paginator = sagemaker_client.get_paginator("list_domains")
        domains = [
            domain
            for page in paginator.paginate()
            for domain in page.get("Domains", [])
            if domain.get("DomainId")
        ]
    except Exception as error:
        logger.warning(f"Could not list SageMaker domains: {str(error)}")
        return [
            create_finding(
                check_id="SM-10",
                finding_name=STUDIO_DOMAIN_NETWORK_FINDING,
                finding_details=(
                    "SageMaker Studio domains could not be listed, so their network "
                    "access type was not read. Assessment error: "
                    f"{get_assessment_error_label(error)}."
                ),
                resolution="Grant sagemaker:ListDomains and retry.",
                reference=STUDIO_DOMAIN_NETWORK_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]

    for summary in domains:
        domain_id = summary["DomainId"]
        label = (
            f"Studio domain '{summary.get('DomainName') or domain_id}' ({domain_id})"
        )
        try:
            detail = sagemaker_client.describe_domain(DomainId=domain_id)
        except Exception as error:
            rows.append(
                create_finding(
                    check_id="SM-10",
                    finding_name=STUDIO_DOMAIN_NETWORK_FINDING,
                    finding_details=(
                        f"{label} could not be described, so its network access "
                        "type was not read. Assessment error: "
                        f"{get_assessment_error_label(error)}."
                    ),
                    resolution="Grant sagemaker:DescribeDomain and retry.",
                    reference=STUDIO_DOMAIN_NETWORK_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            continue
        access_type = detail.get("AppNetworkAccessType") or "PublicInternetOnly"
        subnets = [subnet for subnet in detail.get("SubnetIds") or [] if subnet]
        if access_type != "VpcOnly":
            public.append(label)
        elif not subnets:
            rows.append(
                create_finding(
                    check_id="SM-10",
                    finding_name=STUDIO_DOMAIN_NETWORK_FINDING,
                    finding_details=(
                        f"{label} reports AppNetworkAccessType VpcOnly with no "
                        "SubnetIds, so whether it reaches an internet gateway was "
                        "not judged."
                    ),
                    resolution="Grant sagemaker:DescribeDomain and retry.",
                    reference=STUDIO_DOMAIN_NETWORK_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
        else:
            in_vpc.append({"name": label, "subnets": subnets})

    for label in public:
        rows.append(
            create_finding(
                check_id="SM-10",
                finding_name=STUDIO_DOMAIN_NETWORK_FINDING,
                finding_details=(
                    f"{label} uses AppNetworkAccessType PublicInternetOnly, so its "
                    "non-EFS traffic goes through a SageMaker-managed VPC that "
                    "allows direct internet access."
                ),
                resolution=(
                    "Set AppNetworkAccessType to VpcOnly with private SubnetIds, "
                    "and add the VPC endpoints Studio needs."
                ),
                reference=STUDIO_DOMAIN_NETWORK_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )
    rows.extend(
        _subnet_exposure_findings(
            check_id="SM-10",
            finding_name=STUDIO_DOMAIN_SUBNET_EXPOSURE_FINDING,
            resources=in_vpc,
            region=region,
            reference=STUDIO_DOMAIN_NETWORK_REFERENCE,
            resolution=(
                "Point the domain at subnets whose route tables have no internet "
                "gateway route, or remove that route from the subnets' route "
                "tables."
            ),
            severity="High",
        )
    )
    return rows


def check_sagemaker_notebook_vpc_deployment(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker notebook instances are deployed within a custom VPC.
    Notebooks outside VPC use shared infrastructure with less isolation.
    Aligns with AWS Security Hub control SageMaker.2

    Studio domains are read in the same check: a domain's AppNetworkAccessType
    and SubnetIds decide where its notebooks' traffic goes.
    """
    logger.debug("Starting check for SageMaker notebook VPC deployment")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        notebooks_without_vpc = []
        notebooks_with_vpc = []
        notebooks_with_direct_access = []
        notebook_error = None

        try:
            paginator = sagemaker_client.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for instance in page.get("NotebookInstances", []):
                    instance_name = instance.get("NotebookInstanceName")
                    if instance_name:
                        instance_details = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=instance_name
                        )

                        subnet_id = instance_details.get("SubnetId")

                        if not subnet_id:
                            notebooks_without_vpc.append(
                                {
                                    "name": instance_name,
                                    "status": instance_details.get(
                                        "NotebookInstanceStatus", "Unknown"
                                    ),
                                }
                            )
                        else:
                            notebooks_with_vpc.append(
                                {
                                    "name": instance_name,
                                    "subnet_id": subnet_id,
                                    "vpc_id": instance_details.get("VpcId", "N/A"),
                                }
                            )
                            # AIR-FND-NET-01: with DirectInternetAccess Enabled
                            # SageMaker adds its own internet path beside the VPC,
                            # so the subnet alone is no private boundary.
                            direct_access = instance_details.get("DirectInternetAccess")
                            if direct_access != "Disabled":
                                notebooks_with_direct_access.append(
                                    (instance_name, direct_access or "not returned")
                                )

        except Exception as e:
            logger.error(f"Error checking notebook instances VPC: {str(e)}")
            notebook_error = e

        if notebook_error is not None:
            # A failed read never yields the all-in-VPC Passed or the
            # none-found N/A, which would both claim a population not read.
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-10",
                    finding_name="SageMaker Notebook VPC Deployment Check",
                    finding_details=(
                        "Notebook instances could not all be read, so "
                        f"{len(notebooks_with_vpc) + len(notebooks_without_vpc)} "
                        "read so far are reported and the rest were not assessed. "
                        f"Assessment error: {get_assessment_error_label(notebook_error)}."
                    ),
                    resolution=(
                        "Grant sagemaker:ListNotebookInstances and "
                        "sagemaker:DescribeNotebookInstance and retry."
                    ),
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        if notebooks_without_vpc:
            for notebook in notebooks_without_vpc:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-10",
                        finding_name="SageMaker Notebook Not in VPC",
                        finding_details=f"Notebook instance '{notebook['name']}' is not deployed in a custom VPC. This uses SageMaker's service VPC with reduced network isolation.",
                        resolution="Create the notebook instance within a custom VPC by specifying SubnetId and SecurityGroupIds. This provides network isolation and allows use of VPC endpoints.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        for name, direct_access in notebooks_with_direct_access:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-10",
                    finding_name="SageMaker Notebook Direct Internet Access in VPC",
                    finding_details=(
                        f"Notebook instance '{name}' is deployed in a VPC, but its "
                        f"DirectInternetAccess is {direct_access}. SageMaker then "
                        "gives the notebook internet access outside the VPC's "
                        "routing and security groups."
                    ),
                    resolution=(
                        "Recreate the notebook instance with DirectInternetAccess "
                        "set to Disabled, and route any internet traffic it needs "
                        "through the VPC."
                    ),
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )

        if (
            not notebooks_without_vpc
            and not notebooks_with_direct_access
            and notebook_error is None
        ):
            if notebooks_with_vpc:
                # Notebooks exist and all are in VPCs - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-10",
                        finding_name="SageMaker Notebook VPC Deployment Check",
                        finding_details=(
                            f"All {len(notebooks_with_vpc)} notebook instances are "
                            "deployed in custom VPCs with DirectInternetAccess Disabled"
                        ),
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No notebook instances found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-10",
                        finding_name="SageMaker Notebook VPC Deployment Check",
                        finding_details="No notebook instances found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        # AIR-FND-NET-01: a subnet id is not a privacy claim. A notebook in a
        # subnet that routes to an internet gateway reaches the internet
        # whatever DirectInternetAccess says, so the route table decides.
        findings["csv_data"].extend(
            _subnet_exposure_findings(
                check_id="SM-10",
                finding_name="SageMaker Notebook Subnet Internet Exposure",
                resources=[
                    {
                        "name": f"Notebook instance '{notebook['name']}'",
                        "subnets": [notebook["subnet_id"]],
                    }
                    for notebook in notebooks_with_vpc
                ],
                region=region,
                reference="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                resolution=(
                    "Recreate the notebook instance in a subnet whose route table "
                    "has no internet gateway route, or remove that route from the "
                    "subnet's route table."
                ),
                severity="High",
            )
        )
        findings["csv_data"].extend(
            _studio_domain_network_findings(sagemaker_client, region)
        )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_notebook_vpc_deployment: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-10",
                    finding_name="SageMaker Notebook VPC Deployment Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


MODEL_VPC_ATTACHMENT_FINDING = "SageMaker Model VPC Attachment"
RUNTIME_PRIVATE_PATH_FINDING = "SageMaker Runtime Private Invoke Path"
ENDPOINT_MODEL_NETWORK_FINDING = "SageMaker Endpoint Model Network Path"
ENDPOINT_CONFIG_KMS_FINDING = "SageMaker Endpoint Config Storage Encryption"
MODEL_SUBNET_EXPOSURE_FINDING = "SageMaker Model Subnet Internet Exposure"
ENDPOINT_CONFIG_SUBNET_EXPOSURE_FINDING = (
    "SageMaker Endpoint Config Subnet Internet Exposure"
)
MODEL_VPC_ATTACHMENT_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/host-vpc.html"
)
MODEL_VPC_ATTACHMENT_RESOLUTION = (
    "Recreate the model with VpcConfig naming private subnets and security "
    "groups, and reach it through a com.amazonaws.<region>.sagemaker.runtime "
    "interface VPC endpoint with an endpoint policy. VpcConfig alone places the "
    "model containers in the VPC; the caller still resolves the public runtime "
    "endpoint unless an interface endpoint is in place."
)


def _model_vpc_attachment_findings(
    models_in_vpc: List[Dict[str, Any]], models_without_vpc: List[str], region: str
) -> List[Dict[str, Any]]:
    """
    Report the VpcConfig leg of AIR-SGM-EP-01, per model and independently of
    the EnableNetworkIsolation legs above.

    Network isolation and VPC attachment are separate settings: a model can be
    isolated and still have no VpcConfig, so neither verdict can be inferred
    from the other.
    """
    emitted = []

    for model_name in models_without_vpc[:20]:
        emitted.append(
            create_finding(
                check_id="SM-11",
                finding_name=MODEL_VPC_ATTACHMENT_FINDING,
                finding_details=(
                    f"Model '{model_name}' has no VpcConfig, so its containers run "
                    "in the SageMaker-managed network with no customer subnet or "
                    "security group controlling their traffic."
                ),
                resolution=MODEL_VPC_ATTACHMENT_RESOLUTION,
                reference=MODEL_VPC_ATTACHMENT_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )

    if len(models_without_vpc) > 20:
        emitted.append(
            create_finding(
                check_id="SM-11",
                finding_name=MODEL_VPC_ATTACHMENT_FINDING,
                finding_details=(
                    f"{len(models_without_vpc)} models have no VpcConfig "
                    "(the first 20 are reported individually above)."
                ),
                resolution=MODEL_VPC_ATTACHMENT_RESOLUTION,
                reference=MODEL_VPC_ATTACHMENT_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )

    if models_in_vpc:
        described = "; ".join(
            "{} in {}".format(model["name"], ", ".join(model["subnets"][:3]))
            for model in models_in_vpc[:5]
        )
        emitted.append(
            create_finding(
                check_id="SM-11",
                finding_name=MODEL_VPC_ATTACHMENT_FINDING,
                finding_details=(
                    f"{len(models_in_vpc)} model(s) are attached to customer "
                    f"subnets: {described}. Whether those subnets have a route to "
                    "an internet gateway is reported under "
                    f"'{MODEL_SUBNET_EXPOSURE_FINDING}', and whether callers reach "
                    "the runtime through an interface VPC endpoint is reported "
                    f"under '{RUNTIME_PRIVATE_PATH_FINDING}'."
                ),
                resolution=(
                    "No action required on the model. Reach it through a "
                    "com.amazonaws.<region>.sagemaker.runtime interface VPC "
                    "endpoint with an endpoint policy."
                ),
                reference=MODEL_VPC_ATTACHMENT_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )

    # AIR-FND-NET-01: VpcConfig names the subnets but not their route tables, so
    # the privacy the Passed row above used to ask the reader to confirm is
    # asserted here instead.
    emitted.extend(
        _subnet_exposure_findings(
            check_id="SM-11",
            finding_name=MODEL_SUBNET_EXPOSURE_FINDING,
            resources=[
                {"name": f"Model '{model['name']}'", "subnets": model["subnets"]}
                for model in models_in_vpc
            ],
            region=region,
            reference=MODEL_VPC_ATTACHMENT_REFERENCE,
            resolution=(
                "Recreate the model with VpcConfig naming subnets whose route "
                "tables have no internet gateway route, or remove that route from "
                "the subnets' route tables."
            ),
            severity="Medium",
        )
    )

    return emitted


RUNTIME_PRIVATE_PATH_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/interface-vpc-endpoint.html"
)
ENDPOINT_CONFIG_KMS_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/APIReference/"
    "API_CreateEndpointConfig.html"
)


def _endpoint_hosting_inventory(sagemaker_client) -> Dict[str, Any]:
    """
    Resolve every endpoint in the region to its endpoint config and models.

    Returns {"endpoints": [...], "unread": [...]}. Each endpoint carries its
    name, status, the DescribeEndpointConfig output, the model names its
    production and shadow variants serve, and the digest DescribeEndpoint
    reports each specified image resolved to. A variant with no ModelName hosts
    inference components, and the endpoint config's own VpcConfig and
    EnableNetworkIsolation are the settings the scan can read for it. The
    list call is not caught: a failed inventory is the caller's to report.
    """
    endpoints = []
    unread = []
    for page in sagemaker_client.get_paginator("list_endpoints").paginate():
        for summary in page.get("Endpoints", []):
            name = summary.get("EndpointName")
            if not name:
                continue
            try:
                endpoint = sagemaker_client.describe_endpoint(EndpointName=name)
                config_name = endpoint.get("EndpointConfigName")
                config = sagemaker_client.describe_endpoint_config(
                    EndpointConfigName=config_name
                )
            except Exception as e:
                unread.append(f"endpoint '{name}' ({get_assessment_error_label(e)})")
                continue
            variants = list(config.get("ProductionVariants") or []) + list(
                config.get("ShadowProductionVariants") or []
            )
            endpoints.append(
                {
                    "name": name,
                    "status": summary.get("EndpointStatus")
                    or endpoint.get("EndpointStatus"),
                    "config_name": config_name,
                    "config": config,
                    "variants": variants,
                    "models": sorted(
                        {v["ModelName"] for v in variants if v.get("ModelName")}
                    ),
                    "component_variants": [
                        v.get("VariantName") for v in variants if not v.get("ModelName")
                    ],
                    "deployed_images": {
                        image["SpecifiedImage"]: image["ResolvedImage"]
                        for variant in list(endpoint.get("ProductionVariants") or [])
                        + list(endpoint.get("ShadowProductionVariants") or [])
                        for image in variant.get("DeployedImages") or []
                        if image.get("SpecifiedImage") and image.get("ResolvedImage")
                    },
                }
            )
    return {"endpoints": endpoints, "unread": unread}


def _inference_component_models(
    sagemaker_client, inventory: Dict[str, Any]
) -> Dict[str, Any]:
    """
    The models each inference component on an endpoint names.

    Returns {endpoint name: ([(component, model), ...], [unread, ...])}. A
    component that names a Container and no model, or an adapter loaded by a
    base component, contributes no model.
    """
    components = {}
    for endpoint in inventory["endpoints"]:
        if not endpoint["component_variants"]:
            continue
        name = endpoint["name"]
        served, unread = [], []
        try:
            for page in sagemaker_client.get_paginator(
                "list_inference_components"
            ).paginate(EndpointNameEquals=name):
                for summary in page.get("InferenceComponents", []):
                    component = summary.get("InferenceComponentName")
                    if summary.get("EndpointName") != name or not component:
                        continue
                    try:
                        described = sagemaker_client.describe_inference_component(
                            InferenceComponentName=component
                        )
                    except Exception as error:
                        unread.append(
                            f"inference component '{component}' on endpoint "
                            f"'{name}' ({get_assessment_error_label(error)})"
                        )
                        continue
                    specifications = [described.get("Specification") or {}] + list(
                        described.get("Specifications") or []
                    )
                    served.extend(
                        (component, spec["ModelName"])
                        for spec in specifications
                        if spec.get("ModelName")
                    )
        except Exception as error:
            unread.append(
                f"inference components of endpoint '{name}' "
                f"({get_assessment_error_label(error)})"
            )
        components[name] = (served, unread)
    return components


def _endpoint_model_network_findings(
    inventory: Dict[str, Any],
    model_settings: Dict[str, Dict[str, Any]],
    unread_models: Dict[str, str],
    region: str,
    component_models: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    AIR-SGM-EP-01 and EP-03: judge network isolation and VpcConfig on the
    models an endpoint actually serves, not on the model inventory at large.

    An endpoint that hosts inference components is judged on the endpoint
    config's own settings and on the model each component names. A model the
    endpoint names but the scan could not describe, one deleted after the
    endpoint was created, or components that could not be read, leave that
    endpoint unread.
    """
    emitted = []
    unread = list(inventory["unread"])
    compliant = []
    component_models = component_models or {}
    config_networks = []
    for endpoint in inventory["endpoints"]:
        gaps = []
        endpoint_unread = False
        served = [(None, model_name) for model_name in endpoint["models"]]
        components, components_unread = component_models.get(endpoint["name"], ([], []))
        served.extend(components)
        if components_unread:
            unread.extend(components_unread)
            endpoint_unread = True
        for component, model_name in served:
            label = f"model '{model_name}'" + (
                f" of inference component '{component}'" if component else ""
            )
            settings = model_settings.get(model_name)
            if settings is None:
                reason = unread_models.get(model_name, "not in the model inventory")
                unread.append(
                    f"{label} behind endpoint '{endpoint['name']}' ({reason})"
                )
                endpoint_unread = True
                continue
            if not settings["isolation"]:
                gaps.append(f"{label} has EnableNetworkIsolation off")
            if not settings["subnets"]:
                gaps.append(f"{label} has no VpcConfig")
        if endpoint["component_variants"]:
            config = endpoint["config"]
            vpc_config = config.get("VpcConfig")
            subnets = (
                vpc_config.get("Subnets") if isinstance(vpc_config, dict) else None
            )
            if not config.get("EnableNetworkIsolation"):
                gaps.append(
                    "endpoint config "
                    f"'{endpoint['config_name']}' (inference-component variants "
                    f"{', '.join(str(v) for v in endpoint['component_variants'])}) "
                    "has EnableNetworkIsolation off"
                )
            security_groups = (
                vpc_config.get("SecurityGroupIds")
                if isinstance(vpc_config, dict)
                else None
            )
            if not subnets or not security_groups:
                gaps.append(
                    f"endpoint config '{endpoint['config_name']}' "
                    "(inference-component variants) has no VpcConfig with subnets "
                    "and security groups"
                )
            else:
                # AIR-SGM-EP-01: a subnet id is no privacy claim; its route
                # table is resolved below like a model's.
                config_networks.append(
                    {
                        "name": (
                            f"Endpoint config '{endpoint['config_name']}' of "
                            f"endpoint '{endpoint['name']}'"
                        ),
                        "subnets": [s for s in subnets if s],
                    }
                )
        if gaps:
            emitted.append(
                create_finding(
                    check_id="SM-11",
                    finding_name=ENDPOINT_MODEL_NETWORK_FINDING,
                    finding_details=(
                        f"Endpoint '{endpoint['name']}' serves containers with an "
                        f"internet or unmanaged network path: {'; '.join(gaps)}."
                    ),
                    resolution=MODEL_VPC_ATTACHMENT_RESOLUTION
                    + " Set EnableNetworkIsolation=True on the model.",
                    reference=MODEL_VPC_ATTACHMENT_REFERENCE,
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )
        elif not endpoint_unread:
            compliant.append(endpoint["name"])

    read_details = (
        f"{len(compliant)} endpoint(s) serve only models with network isolation "
        f"on and a VpcConfig: {', '.join(compliant[:10]) or 'none'}. The route "
        "tables of those subnets are judged under "
        f"'{MODEL_SUBNET_EXPOSURE_FINDING}' and "
        f"'{ENDPOINT_CONFIG_SUBNET_EXPOSURE_FINDING}'."
    )
    if unread:
        emitted.append(
            _unread_resources_finding(
                "SM-11",
                ENDPOINT_MODEL_NETWORK_FINDING,
                unread,
                read_details,
                MODEL_VPC_ATTACHMENT_REFERENCE,
                region,
            )
        )
    elif compliant and not emitted:
        emitted.append(
            create_finding(
                check_id="SM-11",
                finding_name=ENDPOINT_MODEL_NETWORK_FINDING,
                finding_details=read_details,
                resolution="No action required",
                reference=MODEL_VPC_ATTACHMENT_REFERENCE,
                severity="High",
                status="Passed",
                region=region,
            )
        )
    elif not inventory["endpoints"]:
        emitted.append(
            create_finding(
                check_id="SM-11",
                finding_name=ENDPOINT_MODEL_NETWORK_FINDING,
                finding_details="No endpoints found",
                resolution="No action required",
                reference=MODEL_VPC_ATTACHMENT_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    emitted.extend(
        _subnet_exposure_findings(
            check_id="SM-11",
            finding_name=ENDPOINT_CONFIG_SUBNET_EXPOSURE_FINDING,
            resources=config_networks,
            region=region,
            reference=MODEL_VPC_ATTACHMENT_REFERENCE,
            resolution=(
                "Recreate the endpoint config with VpcConfig naming subnets whose "
                "route tables have no internet gateway route."
            ),
            severity="High",
        )
    )
    return emitted


def _endpoint_config_kms_findings(
    inventory: Dict[str, Any], region: str
) -> List[Dict[str, Any]]:
    """
    AIR-SGM-EP-03: read the endpoint config KmsKeyId, the at-rest leg the
    recommendation names for the co-located inference hop.

    No endpoint API field turns on inter-container traffic encryption:
    EnableInterContainerTrafficEncryption exists only on training, tuning and
    processing jobs. The rows say so rather than implying the hop was read.
    """
    emitted = []
    keyed = []
    for endpoint in inventory["endpoints"]:
        config = endpoint["config"]
        instance_types = sorted(
            {
                str(v.get("InstanceType"))
                for v in endpoint["variants"]
                if v.get("InstanceType")
            }
        )
        if not instance_types:
            # Serverless variants have no instance storage volume for the key.
            continue
        if config.get("KmsKeyId"):
            keyed.append((endpoint, instance_types))
            continue
        emitted.append(
            create_finding(
                check_id="SM-11",
                finding_name=ENDPOINT_CONFIG_KMS_FINDING,
                finding_details=(
                    f"Endpoint '{endpoint['name']}' uses endpoint config "
                    f"'{endpoint['config_name']}' with no KmsKeyId, so the storage "
                    "volume on its instances "
                    f"({', '.join(instance_types)}) is not encrypted with a "
                    "customer managed key. No endpoint API field enables "
                    "inter-container traffic encryption, so that hop was not read."
                ),
                resolution=(
                    "Create a new endpoint config with KmsKeyId set to a customer "
                    "managed key and update the endpoint to use it."
                ),
                reference=ENDPOINT_CONFIG_KMS_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    # A KmsKeyId can name an AWS managed key, so each key is resolved with
    # kms:DescribeKey before the endpoint is credited.
    managers = _kms_key_managers([e["config"]["KmsKeyId"] for e, _ in keyed], region)
    customer = []
    unread = list(inventory["unread"])
    for endpoint, instance_types in keyed:
        key_id = endpoint["config"]["KmsKeyId"]
        manager = managers[key_id]
        if manager["manager"] == "CUSTOMER":
            customer.append(endpoint["name"])
        elif manager["manager"] is None:
            unread.append(f"kms:DescribeKey {key_id} ({manager['error']})")
        else:
            emitted.append(
                create_finding(
                    check_id="SM-11",
                    finding_name=ENDPOINT_CONFIG_KMS_FINDING,
                    finding_details=(
                        f"Endpoint '{endpoint['name']}' uses endpoint config "
                        f"'{endpoint['config_name']}' whose KmsKeyId {key_id} is "
                        "an AWS managed key, so the storage volume on its "
                        f"instances ({', '.join(instance_types)}) is not "
                        "encrypted with a customer managed key."
                    ),
                    resolution=(
                        "Create a new endpoint config with KmsKeyId set to a "
                        "customer managed key and update the endpoint to use it."
                    ),
                    reference=ENDPOINT_CONFIG_KMS_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )
    read_details = (
        f"{len(customer)} instance-backed endpoint(s) name a customer managed "
        "KmsKeyId in their endpoint config, as kms:DescribeKey reports: "
        f"{', '.join(customer[:10]) or 'none'}. The key covers the "
        "attached storage volume; Nitro local instance storage is encrypted by the "
        "instance hardware module, which the field does not record. No endpoint "
        "API field enables inter-container traffic encryption, so that hop was "
        "not read."
    )
    if unread:
        emitted.append(
            _unread_resources_finding(
                "SM-11",
                ENDPOINT_CONFIG_KMS_FINDING,
                unread,
                read_details,
                ENDPOINT_CONFIG_KMS_REFERENCE,
                region,
            )
        )
    elif customer and not emitted:
        emitted.append(
            create_finding(
                check_id="SM-11",
                finding_name=ENDPOINT_CONFIG_KMS_FINDING,
                finding_details=read_details,
                resolution="No action required",
                reference=ENDPOINT_CONFIG_KMS_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return emitted


def _read_runtime_vpc_endpoints(region: str) -> List[Dict[str, Any]]:
    """Every VPC endpoint for the region's sagemaker.runtime service, paginated."""
    service_names = [
        f"com.amazonaws.{region}.sagemaker.runtime",
        f"com.amazonaws.{region}.sagemaker.runtime-fips",
    ]
    ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)
    paginator = ec2_client.get_paginator("describe_vpc_endpoints")
    vpces = []
    for page in paginator.paginate(
        Filters=[{"Name": "service-name", "Values": service_names}]
    ):
        vpces.extend(page.get("VpcEndpoints", []))
    return vpces


RUNTIME_ENDPOINT_POLICY_FINDING = "SageMaker Runtime VPC Endpoint Policy Scoping"


def check_sagemaker_runtime_endpoint_policy(region: str = "") -> Dict[str, Any]:
    """
    AIR-SGM-EP-02: read the endpoint policy on each sagemaker.runtime interface
    VPC endpoint, the layer the recommendation puts in front of the identity
    grants SM-02 reads from the IAM cache.

    A policy fails when an Allow reaches sagemaker:InvokeEndpoint on every
    endpoint, which is what the default full-access policy does. Deny statements
    are not evaluated, which can only overstate what the policy allows. A region
    with no runtime VPC endpoint emits nothing here; SM-11 reports the missing
    private path.
    """
    reference = RUNTIME_PRIVATE_PATH_REFERENCE
    try:
        vpces = _read_runtime_vpc_endpoints(region)
    except Exception as e:
        logger.error(f"Error reading sagemaker.runtime VPC endpoints: {str(e)}")
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-02",
                    finding_name=RUNTIME_ENDPOINT_POLICY_FINDING,
                    finding_details=(
                        "The sagemaker.runtime VPC endpoint policies were not read "
                        f"(ec2:DescribeVpcEndpoints: {get_assessment_error_label(e)})."
                    ),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference=reference,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }
    rows = []
    scoped = []
    unread = []
    for vpce in vpces:
        vpce_id = vpce.get("VpcEndpointId")
        document = vpce.get("PolicyDocument")
        try:
            policy = json.loads(document) if isinstance(document, str) else document
            statements = _sm_policy_statements(policy)
        except (TypeError, ValueError) as e:
            unread.append(f"{vpce_id} (policy document not parsed: {type(e).__name__})")
            continue
        if not isinstance(policy, dict):
            unread.append(f"{vpce_id} (no policy document returned)")
            continue
        wildcards = [
            element
            for statement in statements
            if str(statement.get("Effect", "")).lower() == "allow"
            for element in [_unscoped_endpoint_invocation_statement(statement)]
            if element
        ]
        if wildcards:
            rows.append(
                create_finding(
                    check_id="SM-02",
                    finding_name=RUNTIME_ENDPOINT_POLICY_FINDING,
                    finding_details=(
                        f"VPC endpoint {vpce_id} in {vpce.get('VpcId')} has an "
                        "endpoint policy that allows sagemaker:InvokeEndpoint on "
                        f"every endpoint ({', '.join(wildcards[:3])}). Deny "
                        "statements were not evaluated, so a Deny could narrow it."
                    ),
                    resolution=(
                        "Replace the endpoint policy with one that allows "
                        "sagemaker:InvokeEndpoint only on the named endpoint ARNs "
                        "(arn:aws:sagemaker:<region>:<account>:endpoint/<name>)."
                    ),
                    reference=reference,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )
        else:
            scoped.append(vpce_id)
    read_details = (
        f"{len(scoped)} sagemaker.runtime VPC endpoint(s) have a policy that "
        f"names the endpoints it allows invoking: {', '.join(scoped[:10]) or 'none'}."
    )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-02",
                RUNTIME_ENDPOINT_POLICY_FINDING,
                unread,
                read_details,
                reference,
                region,
            )
        )
    elif scoped and not rows:
        rows.append(
            create_finding(
                check_id="SM-02",
                finding_name=RUNTIME_ENDPOINT_POLICY_FINDING,
                finding_details=read_details,
                resolution="No action required",
                reference=reference,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return {"csv_data": rows}


def _runtime_private_path_findings(
    inventory: Dict[str, Any], region: str
) -> List[Dict[str, Any]]:
    """
    AIR-SGM-EP-01: require an available sagemaker.runtime interface endpoint
    with private DNS, the path the recommendation names for InvokeEndpoint.

    Only asked when the region hosts an endpoint. The scan cannot see where
    callers run, so a Passed row states which VPCs have the path and no more.
    """
    if not inventory["endpoints"]:
        return []
    private = []
    other = []
    try:
        for vpce in _read_runtime_vpc_endpoints(region):
            label = f"{vpce.get('VpcEndpointId')} in {vpce.get('VpcId')}"
            if (
                vpce.get("VpcEndpointType") == "Interface"
                and str(vpce.get("State", "")).lower() == "available"
                and vpce.get("PrivateDnsEnabled") is True
            ):
                private.append(label)
            else:
                other.append(
                    f"{label} (type {vpce.get('VpcEndpointType')}, state "
                    f"{vpce.get('State')}, private DNS "
                    f"{vpce.get('PrivateDnsEnabled')})"
                )
    except Exception as e:
        return [
            create_finding(
                check_id="SM-11",
                finding_name=RUNTIME_PRIVATE_PATH_FINDING,
                finding_details=(
                    "The sagemaker.runtime interface VPC endpoints were not read "
                    f"(ec2:DescribeVpcEndpoints: {get_assessment_error_label(e)}), "
                    "so whether callers have a private invoke path is unknown."
                ),
                resolution=COULD_NOT_ASSESS_RESOLUTION,
                reference=RUNTIME_PRIVATE_PATH_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]
    endpoint_names = ", ".join(e["name"] for e in inventory["endpoints"][:10])
    if not private:
        seen = f" Endpoints found: {'; '.join(other[:5])}." if other else ""
        return [
            create_finding(
                check_id="SM-11",
                finding_name=RUNTIME_PRIVATE_PATH_FINDING,
                finding_details=(
                    f"The region hosts endpoint(s) {endpoint_names}, and no "
                    "available com.amazonaws."
                    f"{region}.sagemaker.runtime interface VPC endpoint has "
                    "private DNS enabled, so InvokeEndpoint calls resolve to the "
                    f"public runtime endpoint.{seen}"
                ),
                resolution=(
                    "Create an interface VPC endpoint for "
                    f"com.amazonaws.{region}.sagemaker.runtime with private DNS "
                    "enabled in each VPC that invokes the endpoints, and attach an "
                    "endpoint policy."
                ),
                reference=RUNTIME_PRIVATE_PATH_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        ]
    return [
        create_finding(
            check_id="SM-11",
            finding_name=RUNTIME_PRIVATE_PATH_FINDING,
            finding_details=(
                "An available sagemaker.runtime interface VPC endpoint with private "
                f"DNS exists: {'; '.join(private[:5])}. Calls from those VPCs "
                "resolve the runtime hostname to it. The scan does not record where "
                "callers run, so calls from other networks can still use the public "
                "runtime endpoint."
            ),
            resolution="No action required",
            reference=RUNTIME_PRIVATE_PATH_REFERENCE,
            severity="Medium",
            status="Passed",
            region=region,
        )
    ]


INVOKE_SOURCE_NETWORK_FINDING = "SageMaker Endpoint Invocation Source Network"
INVOKE_SOURCE_NETWORK_KEYS = ("aws:sourcevpce", "aws:sourcevpc")
INVOKE_SOURCE_NETWORK_RESOLUTION = (
    "Condition each sagemaker:InvokeEndpoint Allow on aws:SourceVpce (the "
    "sagemaker.runtime interface endpoint IDs) or aws:SourceVpc with "
    "StringEquals, or add an identity Deny on sagemaker:InvokeEndpoint for "
    "every endpoint with StringNotEquals on aws:SourceVpce, so a call from "
    "outside the private path is refused."
)


def _allow_pins_invoke_source(statement: Dict[str, Any]) -> bool:
    """
    Return whether an Allow grants only calls that arrive through a named VPC
    endpoint or VPC.

    IfExists, negated and Null operators match a call that carries neither key,
    as does ForAllValues over the empty set; a Like on a wildcard value admits
    any endpoint.
    """
    for operator, key, values in _condition_entries(statement):
        if key not in INVOKE_SOURCE_NETWORK_KEYS or not values:
            continue
        prefix, base, if_exists = _condition_operator_parts(operator)
        if if_exists or "not" in base or base == "null":
            continue
        if prefix == "forallvalues" or _like_values_unbounded(base, values):
            continue
        if base in ("stringequals", "stringlike"):
            return True
    return False


def _deny_pins_invoke_source(statement: Dict[str, Any]) -> bool:
    """
    Return whether a Deny refuses every InvokeEndpoint call from outside a
    named VPC endpoint or VPC.

    The statement must cover every endpoint and hold only the source-network
    condition: another key makes the Deny fire only when both hold. A negated
    operator is true for a call that carries no key, except under ForAnyValue.
    """
    if str(statement.get("Effect", "")).upper() != "DENY":
        return False
    if not any(
        _statement_names_action(statement, action) for action in ENDPOINT_INVOKE_ACTIONS
    ):
        return False
    if not _deny_covers_every_resource(statement, "endpoint"):
        return False
    entries = _condition_entries(statement)
    if len(entries) != 1:
        return False
    operator, key, values = entries[0]
    prefix, base, _ = _condition_operator_parts(operator)
    return (
        key in INVOKE_SOURCE_NETWORK_KEYS
        and bool(values)
        and base in ("stringnotequals", "stringnotlike")
        and prefix != "foranyvalue"
        and not _like_values_unbounded(base, values)
    )


def _invoke_source_network_findings(
    permission_cache: Optional[Dict[str, Any]], inventory: Dict[str, Any], region: str
) -> List[Dict[str, Any]]:
    """
    AIR-SGM-EP-01: an interface endpoint gives callers a private path but does
    not stop a caller elsewhere from using the public runtime endpoint. Only an
    IAM condition on aws:SourceVpce or aws:SourceVpc does, so each principal
    that can invoke an endpoint must be held to one.
    """
    if not inventory["endpoints"]:
        return []

    def _row(details, resolution, severity, status, name=None):
        return create_finding(
            check_id="SM-11",
            finding_name=name or INVOKE_SOURCE_NETWORK_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=RUNTIME_PRIVATE_PATH_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    if permission_cache is None:
        return [
            _row(
                "The IAM permissions cache was not available, so whether "
                "sagemaker:InvokeEndpoint grants are held to aws:SourceVpce or "
                "aws:SourceVpc was not read.",
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
                name=f"{INVOKE_SOURCE_NETWORK_FINDING} Incomplete",
            )
        ]

    boundary_unread = _boundary_unread(permission_cache)
    pinned = []
    open_principals = []
    unread = list(_principal_read_errors(permission_cache) or [])
    for identity_type, cache_key in (
        ("Role", "role_permissions"),
        ("User", "user_permissions"),
    ):
        for name, permissions in (permission_cache.get(cache_key) or {}).items():
            label = f"{identity_type} '{name}'"
            boundary = permissions.get("permissions_boundary")
            boundary_statements = (
                _sm_policy_statements(boundary) if boundary is not None else []
            )
            if boundary is not None and not any(
                _statement_invoke_actions(st) for st in boundary_statements
            ):
                continue
            unpinned = []
            granted = False
            statements = []
            for policy in [
                *(permissions.get("attached_policies") or []),
                *(permissions.get("inline_policies") or []),
                *(permissions.get("group_policies") or []),
            ]:
                for statement in _sm_policy_statements(policy.get("document")):
                    statements.append(statement)
                    if not _statement_invoke_actions(statement):
                        continue
                    granted = True
                    if not _allow_pins_invoke_source(statement):
                        unpinned.append(policy.get("name") or "inline policy")
            if not granted:
                continue
            boundary_pins = boundary is not None and all(
                _allow_pins_invoke_source(st)
                for st in boundary_statements
                if _statement_invoke_actions(st)
            )
            denied = any(_deny_pins_invoke_source(st) for st in statements)
            if not unpinned or boundary_pins or denied:
                pinned.append(label)
            elif boundary is None and (identity_type.lower(), name) in boundary_unread:
                unread.append(f"{label} (permissions boundary not read)")
            else:
                open_principals.append(f"{label} (policy '{sorted(set(unpinned))[0]}')")

    rows = []
    if open_principals:
        shown = "; ".join(open_principals[:10])
        if len(open_principals) > 10:
            shown += f"; and {len(open_principals) - 10} more"
        rows.append(
            _row(
                f"{len(open_principals)} principal(s) can call "
                "sagemaker:InvokeEndpoint from any network: no Allow condition "
                "on aws:SourceVpce or aws:SourceVpc and no identity Deny holds the "
                f"call to a VPC endpoint or VPC: {shown}. {SCP_NOT_EVALUATED_NOTE}",
                INVOKE_SOURCE_NETWORK_RESOLUTION,
                "Medium",
                "Failed",
            )
        )
    read_details = (
        f"{len(pinned)} principal(s) that can invoke an endpoint are held to a "
        "named VPC endpoint or VPC by aws:SourceVpce or aws:SourceVpc"
        + (f": {', '.join(sorted(pinned)[:10])}." if pinned else ".")
    )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-11",
                INVOKE_SOURCE_NETWORK_FINDING,
                unread,
                read_details,
                RUNTIME_PRIVATE_PATH_REFERENCE,
                region,
            )
        )
    elif not open_principals and pinned:
        details = read_details
        if _principal_read_errors(permission_cache) is None:
            details += " " + UNRECORDED_PRINCIPAL_ERRORS_NOTE
        rows.append(_row(details, "No action required", "Medium", "Passed"))
    return rows


AI_LAMBDA_NETWORK_FINDING = "AI Lambda Function Network Boundary"
AI_LAMBDA_NETWORK_REFERENCE = (
    "https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html"
)
AI_LAMBDA_NETWORK_RESOLUTION = (
    "Attach each Lambda function an agent action group or AgentCore gateway "
    "target invokes to private VPC subnets whose route tables have no route to "
    "an internet gateway, and reach AWS services through VPC endpoints."
)


def _ai_lambda_references(region: str) -> Tuple[Dict[str, List[str]], List[str]]:
    """Lambda ARN -> what names it: agent action groups and gateway targets."""
    named, unread = {}, []
    try:
        agent_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )
        agents = []
        for page in agent_client.get_paginator("list_agents").paginate():
            agents.extend(page.get("agentSummaries", []))
    except Exception as error:
        agents = []
        unread.append(f"bedrock:ListAgents ({get_assessment_error_label(error)})")
    for agent in agents:
        agent_id = agent.get("agentId")
        label = f"agent {agent.get('agentName') or agent_id}"
        try:
            versions = []
            for page in agent_client.get_paginator("list_agent_versions").paginate(
                agentId=agent_id
            ):
                versions.extend(
                    v.get("agentVersion") for v in page.get("agentVersionSummaries", [])
                )
            for version in versions:
                for page in agent_client.get_paginator(
                    "list_agent_action_groups"
                ).paginate(agentId=agent_id, agentVersion=version):
                    for group in page.get("actionGroupSummaries", []):
                        detail = agent_client.get_agent_action_group(
                            agentId=agent_id,
                            agentVersion=version,
                            actionGroupId=group.get("actionGroupId"),
                        ).get("agentActionGroup", {})
                        arn = (detail.get("actionGroupExecutor") or {}).get("lambda")
                        if arn:
                            named.setdefault(arn, []).append(
                                f"{label} version {version} action group "
                                f"{group.get('actionGroupName')}"
                            )
        except Exception as error:
            unread.append(
                f"action groups of {label} ({get_assessment_error_label(error)})"
            )
    try:
        gateway_client = boto3.client(
            "bedrock-agentcore-control", config=boto3_config, region_name=region
        )
        gateways = []
        for page in gateway_client.get_paginator("list_gateways").paginate():
            gateways.extend(page.get("items", []))
    except Exception as error:
        gateways = []
        unread.append(
            f"bedrock-agentcore:ListGateways ({get_assessment_error_label(error)})"
        )
    for gateway in gateways:
        gateway_id = gateway.get("gatewayId")
        label = f"gateway {gateway.get('name') or gateway_id}"
        try:
            for page in gateway_client.get_paginator("list_gateway_targets").paginate(
                gatewayIdentifier=gateway_id
            ):
                for target in page.get("items", []):
                    detail = gateway_client.get_gateway_target(
                        gatewayIdentifier=gateway_id, targetId=target.get("targetId")
                    )
                    arn = (
                        (
                            (detail.get("targetConfiguration") or {}).get("mcp") or {}
                        ).get("lambda")
                        or {}
                    ).get("lambdaArn")
                    if arn:
                        named.setdefault(arn, []).append(
                            f"{label} target {target.get('name')}"
                        )
        except Exception as error:
            unread.append(f"targets of {label} ({get_assessment_error_label(error)})")
    return named, unread


AI_API_AUTHORIZATION_FINDING = "AI API Method Authorization"
AI_API_AUTHORIZATION_REFERENCE = (
    "https://docs.aws.amazon.com/apigateway/latest/developerguide/"
    "apigateway-control-access-to-api.html"
)
AI_API_AUTHORIZATION_RESOLUTION = (
    "Require an authorizer on every method that reaches a model or agent, and "
    "give read and write methods on one resource different OAuth scopes, or "
    "separate execute-api:Invoke grants per method."
)
# The service segment of an API Gateway AWS integration URI, or the host of an
# HTTP integration, that reaches a Bedrock, AgentCore or SageMaker runtime.
AI_INTEGRATION_URI = re.compile(
    r"^arn:[^:]+:apigateway:[^:]*:(bedrock|bedrock-runtime|bedrock-agent-runtime"
    r"|bedrock-agentcore|runtime\.sagemaker|sagemaker):"
    r"|^https://(bedrock-runtime|bedrock-agent-runtime|bedrock-agentcore"
    r"|runtime\.sagemaker)\."
)
LAMBDA_IN_URI = re.compile(r"(arn:[^:]+:lambda:[^:]+:\d{12}:function:[^/:]+)")
READ_VERBS = frozenset({"GET", "HEAD"})
WRITE_VERBS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _method_verbs(verb: str) -> set:
    """ANY and an HTTP API $default route serve every verb."""
    return set(READ_VERBS | WRITE_VERBS) if verb in ("ANY", "$default") else {verb}


def _ai_integration_target(uri: Any, ai_functions: set) -> Optional[str]:
    """What an integration URI reaches when it is an AI runtime, else None."""
    text = str(uri or "")
    if AI_INTEGRATION_URI.search(text):
        return text.split("?", 1)[0][:160]
    match = LAMBDA_IN_URI.search(text)
    if match and match.group(1) in ai_functions:
        return f"Lambda function {match.group(1)}"
    return None


def _api_methods(region: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Every REST API method and HTTP API route with its integration URI."""
    methods, unread = [], []
    try:
        rest = boto3.client("apigateway", config=boto3_config, region_name=region)
        apis = []
        for page in rest.get_paginator("get_rest_apis").paginate():
            apis.extend(page.get("items", []))
    except Exception as error:
        apis = []
        unread.append(f"apigateway:GET /restapis ({get_assessment_error_label(error)})")
    for api in apis:
        try:
            for page in rest.get_paginator("get_resources").paginate(
                restApiId=api.get("id"), embed=["methods"]
            ):
                for resource in page.get("items", []):
                    for verb, method in (resource.get("resourceMethods") or {}).items():
                        methods.append(
                            {
                                "api": f"REST API {api.get('name')} ({api.get('id')})",
                                "label": f"{verb} {resource.get('path')}",
                                "verbs": _method_verbs(verb),
                                "type": method.get("authorizationType") or "NONE",
                                "authorizer": method.get("authorizerId"),
                                "scopes": frozenset(
                                    method.get("authorizationScopes") or []
                                ),
                                "uri": (method.get("methodIntegration") or {}).get(
                                    "uri"
                                ),
                            }
                        )
        except Exception as error:
            unread.append(
                f"resources of REST API {api.get('id')} "
                f"({get_assessment_error_label(error)})"
            )
    try:
        http = boto3.client("apigatewayv2", config=boto3_config, region_name=region)
        http_apis = []
        for page in http.get_paginator("get_apis").paginate():
            http_apis.extend(page.get("Items", []))
    except Exception as error:
        http_apis = []
        unread.append(f"apigateway:GET /apis ({get_assessment_error_label(error)})")
    for api in http_apis:
        api_id = api.get("ApiId")
        try:
            integrations = {}
            for page in http.get_paginator("get_integrations").paginate(ApiId=api_id):
                for integration in page.get("Items", []):
                    integrations[integration.get("IntegrationId")] = integration.get(
                        "IntegrationUri"
                    )
            for page in http.get_paginator("get_routes").paginate(ApiId=api_id):
                for route in page.get("Items", []):
                    key = str(route.get("RouteKey") or "")
                    verb = key.split(" ", 1)[0]
                    target = str(route.get("Target") or "")
                    methods.append(
                        {
                            "api": f"HTTP API {api.get('Name')} ({api_id})",
                            "label": f"route {key}",
                            "verbs": _method_verbs(verb),
                            "type": route.get("AuthorizationType") or "NONE",
                            "authorizer": route.get("AuthorizerId"),
                            "scopes": frozenset(route.get("AuthorizationScopes") or []),
                            "uri": integrations.get(target.split("/", 1)[-1]),
                        }
                    )
        except Exception as error:
            unread.append(
                f"routes of HTTP API {api_id} ({get_assessment_error_label(error)})"
            )
    return methods, unread


def check_ai_api_method_authorization(region: str = "") -> Dict[str, Any]:
    """
    SM-02: Verify every API Gateway method that reaches a model or agent is
    authorized, and that read and write methods are authorized separately
    (AIR-FND-IAM-09 request layer).

    A method is in the population when its integration URI names a Bedrock,
    AgentCore or SageMaker runtime, or a Lambda function an agent action group
    or AgentCore gateway target names. A token authorizer separates read from
    write only by scopes; an IAM or Lambda authorizer separates them in policy
    or code this row does not read.
    """
    findings = {"csv_data": []}
    named, unread = _ai_lambda_references(region)
    ai_functions = {
        match.group(1)
        for arn in named
        for match in [LAMBDA_IN_URI.search(arn)]
        if match
    }
    methods, method_unread = _api_methods(region)
    unread.extend(method_unread)
    ai_methods = []
    for method in methods:
        target = _ai_integration_target(method["uri"], ai_functions)
        if target:
            ai_methods.append(dict(method, target=target))

    problems, unjudged, token_methods = [], [], {}
    for method in ai_methods:
        where = f"{method['api']} {method['label']} (reaches {method['target']})"
        kind = method["type"].upper()
        if kind == "NONE":
            problems.append(f"{where} accepts requests with no authorization")
        elif kind in ("COGNITO_USER_POOLS", "JWT"):
            token_methods.setdefault(
                (method["api"], method["authorizer"], method["scopes"]), []
            ).append(method)
        else:
            unjudged.append(f"{where} ({kind})")
    for (api, _, scopes), group in token_methods.items():
        verbs = set().union(*(m["verbs"] for m in group))
        if verbs & READ_VERBS and verbs & WRITE_VERBS:
            shown = ", ".join(m["label"] for m in group[:4])
            problems.append(
                f"{api} authorizes read and write methods ({shown}) with one "
                "authorizer and "
                + (
                    f"the same scopes ({', '.join(sorted(scopes))})"
                    if scopes
                    else "no scopes"
                )
                + ", so a token that may read may also write"
            )

    findings["csv_data"].extend(
        _capped_problem_rows(
            "SM-02",
            AI_API_AUTHORIZATION_FINDING,
            [f"{p}." for p in problems],
            AI_API_AUTHORIZATION_RESOLUTION,
            AI_API_AUTHORIZATION_REFERENCE,
            "High",
            region,
            "AI API authorization gaps",
        )
    )
    if unjudged:
        shown = "; ".join(unjudged[:10])
        if len(unjudged) > 10:
            shown += f"; and {len(unjudged) - 10} more"
        findings["csv_data"].append(
            create_finding(
                check_id="SM-02",
                finding_name=f"{AI_API_AUTHORIZATION_FINDING} Not Judged",
                finding_details=(
                    f"{len(unjudged)} AI method(s) use an IAM or Lambda authorizer: "
                    f"{shown}. Whether read and write are authorized separately is "
                    "held in execute-api:Invoke grants or in the authorizer's code, "
                    "which this row does not read."
                ),
                resolution=AI_API_AUTHORIZATION_RESOLUTION,
                reference=AI_API_AUTHORIZATION_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    if unread:
        findings["csv_data"].append(
            _unread_resources_finding(
                "SM-02",
                AI_API_AUTHORIZATION_FINDING,
                unread,
                f"{len(ai_methods)} AI method(s) were found among {len(methods)} "
                "API method(s) and route(s).",
                AI_API_AUTHORIZATION_REFERENCE,
                region,
            )
        )
    elif not problems and not unjudged:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-02",
                finding_name=AI_API_AUTHORIZATION_FINDING,
                finding_details=(
                    f"All {len(ai_methods)} API method(s) that reach a model or "
                    "agent use a token authorizer, and no read and write methods "
                    "of one API share an authorizer and scopes. A Lambda function "
                    "no agent action group or gateway target names is not "
                    "recognized as AI."
                    if ai_methods
                    else f"None of the {len(methods)} API method(s) and route(s) in "
                    "this region reaches a Bedrock, AgentCore or SageMaker runtime "
                    "or a Lambda function an agent or gateway names."
                ),
                resolution="No action required",
                reference=AI_API_AUTHORIZATION_REFERENCE,
                severity="High" if ai_methods else "Informational",
                status="Passed" if ai_methods else "N/A",
                region=region,
            )
        )
    return findings


def check_ai_lambda_network_boundary(region: str = "") -> Dict[str, Any]:
    """
    SM-11: Verify every Lambda function an agent action group or AgentCore
    gateway target invokes runs in private VPC subnets (AIR-FND-NET-01).

    No Lambda field marks a function as AI compute, so the population is the
    functions an AI resource names as its executor.
    """
    findings = {"csv_data": []}
    named, unread = _ai_lambda_references(region)
    lambda_client = boto3.client("lambda", config=boto3_config, region_name=region)
    outside, attached = [], []
    for arn in sorted(named):
        where = "; ".join(named[arn][:3])
        try:
            configuration = lambda_client.get_function_configuration(FunctionName=arn)
        except Exception as error:
            unread.append(
                f"Lambda function {arn}, named by {where} "
                f"(lambda:GetFunctionConfiguration: {get_assessment_error_label(error)})"
            )
            continue
        subnets = (configuration.get("VpcConfig") or {}).get("SubnetIds") or []
        name = f"Lambda function {arn} (named by {where})"
        if subnets:
            attached.append({"name": name, "subnets": list(subnets)})
        else:
            outside.append(
                f"{name} runs outside a VPC, so it reaches the internet through "
                "the Lambda service network and no subnet route bounds it."
            )
    findings["csv_data"].extend(
        _capped_problem_rows(
            "SM-11",
            AI_LAMBDA_NETWORK_FINDING,
            outside,
            AI_LAMBDA_NETWORK_RESOLUTION,
            AI_LAMBDA_NETWORK_REFERENCE,
            "Medium",
            region,
            "AI Lambda functions outside a VPC",
        )
    )
    exposure_rows = _subnet_exposure_findings(
        "SM-11",
        AI_LAMBDA_NETWORK_FINDING,
        attached,
        region,
        AI_LAMBDA_NETWORK_REFERENCE,
        AI_LAMBDA_NETWORK_RESOLUTION,
        "Medium",
    )
    if unread:
        exposure_rows = [r for r in exposure_rows if r.get("Status") != "Passed"]
        findings["csv_data"].extend(exposure_rows)
        findings["csv_data"].append(
            _unread_resources_finding(
                "SM-11",
                AI_LAMBDA_NETWORK_FINDING,
                unread,
                f"{len(named)} Lambda function(s) named by an agent action group or "
                f"gateway target were found; {len(outside)} run outside a VPC.",
                AI_LAMBDA_NETWORK_REFERENCE,
                region,
            )
        )
    else:
        findings["csv_data"].extend(exposure_rows)
    if not named and not unread:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-11",
                finding_name=AI_LAMBDA_NETWORK_FINDING,
                finding_details=(
                    "No Bedrock agent action group or AgentCore gateway target "
                    "in this region names a Lambda function."
                ),
                resolution="No action required",
                reference=AI_LAMBDA_NETWORK_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    return findings


def check_sagemaker_model_network_isolation(
    region: str = "", permission_cache: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Check if SageMaker hosted models have network isolation enabled.
    Without isolation, model containers can make outbound calls and exfiltrate data.
    Aligns with AWS Security Hub control SageMaker.5
    """
    logger.debug("Starting check for SageMaker model network isolation")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        models_without_isolation = []
        models_with_isolation = []
        models_in_vpc = []
        models_without_vpc = []
        model_settings = {}
        unread_models = {}
        list_error = None

        try:
            paginator = sagemaker_client.get_paginator("list_models")
            for page in paginator.paginate():
                for model in page.get("Models", []):
                    model_name = model.get("ModelName")
                    if model_name:
                        try:
                            model_details = sagemaker_client.describe_model(
                                ModelName=model_name
                            )

                            enable_network_isolation = model_details.get(
                                "EnableNetworkIsolation", False
                            )

                            # AIR-SGM-EP-01 asks about the private network path,
                            # which is VpcConfig rather than network isolation.
                            vpc_config = model_details.get("VpcConfig")
                            subnets = (
                                vpc_config.get("Subnets")
                                if isinstance(vpc_config, dict)
                                else None
                            )
                            model_settings[model_name] = {
                                "isolation": bool(enable_network_isolation),
                                "subnets": list(subnets or []),
                            }
                            if subnets:
                                models_in_vpc.append(
                                    {"name": model_name, "subnets": list(subnets)}
                                )
                            else:
                                models_without_vpc.append(model_name)

                            if not enable_network_isolation:
                                models_without_isolation.append(
                                    {
                                        "name": model_name,
                                        "creation_time": str(
                                            model_details.get("CreationTime", "Unknown")
                                        ),
                                    }
                                )
                            else:
                                models_with_isolation.append(model_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing model {model_name}: {str(e)}"
                            )
                            unread_models[model_name] = get_assessment_error_label(e)

        except Exception as e:
            logger.error(f"Error listing models: {str(e)}")
            list_error = e

        if list_error is not None:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-11",
                    finding_name="SageMaker Model Network Isolation Check",
                    finding_details=build_could_not_assess_detail(list_error, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
        elif models_without_isolation:
            # Limit findings to avoid overwhelming output
            for model in models_without_isolation[:20]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-11",
                        finding_name="SageMaker Model Network Isolation Disabled",
                        finding_details=f"Model '{model['name']}' does not have network isolation enabled. Model containers can make outbound network calls, potentially exfiltrating data.",
                        resolution="Enable network isolation by setting EnableNetworkIsolation=True when creating models. This prevents containers from making outbound network calls.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )

            if len(models_without_isolation) > 20:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-11",
                        finding_name="SageMaker Model Network Isolation Summary",
                        finding_details=f"Found {len(models_without_isolation)} total models without network isolation (showing first 20)",
                        resolution="Review all models and enable network isolation where appropriate",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        elif unread_models:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-11",
                    "SageMaker Model Network Isolation Check",
                    [
                        f"model '{name}' ({label})"
                        for name, label in unread_models.items()
                    ],
                    f"{len(models_with_isolation)} models have network isolation "
                    "enabled.",
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                    region,
                )
            )
        else:
            if models_with_isolation:
                # Models exist and all have network isolation - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-11",
                        finding_name="SageMaker Model Network Isolation Check",
                        finding_details=f"All {len(models_with_isolation)} models have network isolation enabled",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No models found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-11",
                        finding_name="SageMaker Model Network Isolation Check",
                        finding_details="No models found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        attachment_rows = _model_vpc_attachment_findings(
            models_in_vpc, models_without_vpc, region
        )
        if list_error is not None or unread_models:
            # The Passed attachment row speaks for the whole inventory, which was
            # not read in full; Failed rows and the subnet legs still stand.
            unread = (
                [build_could_not_assess_detail(list_error, region)]
                if list_error is not None
                else [f"model '{n}' ({label})" for n, label in unread_models.items()]
            )
            attachment_rows = [
                _unread_resources_finding(
                    "SM-11",
                    MODEL_VPC_ATTACHMENT_FINDING,
                    unread,
                    row["Finding_Details"],
                    MODEL_VPC_ATTACHMENT_REFERENCE,
                    region,
                )
                if row["Finding"] == MODEL_VPC_ATTACHMENT_FINDING
                and row["Status"] == "Passed"
                else row
                for row in attachment_rows
            ]
        findings["csv_data"].extend(attachment_rows)

        try:
            inventory = _endpoint_hosting_inventory(sagemaker_client)
        except Exception as e:
            logger.error(f"Error listing endpoints: {str(e)}")
            for finding_name in (
                ENDPOINT_MODEL_NETWORK_FINDING,
                ENDPOINT_CONFIG_KMS_FINDING,
            ):
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-11",
                        finding_name=finding_name,
                        finding_details=build_could_not_assess_detail(e, region),
                        resolution=COULD_NOT_ASSESS_RESOLUTION,
                        reference=MODEL_VPC_ATTACHMENT_REFERENCE,
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
            return findings

        findings["csv_data"].extend(
            _endpoint_model_network_findings(
                inventory,
                model_settings,
                unread_models,
                region,
                _inference_component_models(sagemaker_client, inventory),
            )
        )
        findings["csv_data"].extend(_endpoint_config_kms_findings(inventory, region))
        findings["csv_data"].extend(_runtime_private_path_findings(inventory, region))
        findings["csv_data"].extend(
            _invoke_source_network_findings(permission_cache, inventory, region)
        )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_network_isolation: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-11",
                    finding_name="SageMaker Model Network Isolation Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_endpoint_instance_count(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker endpoints have more than one instance for availability.
    Single instance creates availability risk and single point of compromise.
    Aligns with AWS Security Hub control SageMaker.4
    """
    logger.debug("Starting check for SageMaker endpoint instance count")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        endpoints_single_instance = []
        endpoints_multi_instance = []

        try:
            paginator = sagemaker_client.get_paginator("list_endpoints")
            for page in paginator.paginate():
                for endpoint in page.get("Endpoints", []):
                    endpoint_name = endpoint.get("EndpointName")
                    endpoint_status = endpoint.get("EndpointStatus")

                    if endpoint_name and endpoint_status == "InService":
                        try:
                            endpoint_details = sagemaker_client.describe_endpoint(
                                EndpointName=endpoint_name
                            )

                            production_variants = endpoint_details.get(
                                "ProductionVariants", []
                            )

                            for variant in production_variants:
                                current_instance_count = variant.get(
                                    "CurrentInstanceCount", 0
                                )
                                variant_name = variant.get("VariantName", "Unknown")

                                if current_instance_count <= 1:
                                    endpoints_single_instance.append(
                                        {
                                            "endpoint_name": endpoint_name,
                                            "variant_name": variant_name,
                                            "instance_count": current_instance_count,
                                        }
                                    )
                                else:
                                    endpoints_multi_instance.append(
                                        {
                                            "endpoint_name": endpoint_name,
                                            "variant_name": variant_name,
                                            "instance_count": current_instance_count,
                                        }
                                    )

                        except Exception as e:
                            logger.warning(
                                f"Error describing endpoint {endpoint_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing endpoints: {str(e)}")

        if endpoints_single_instance:
            for endpoint in endpoints_single_instance:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-12",
                        finding_name="SageMaker Endpoint Single Instance",
                        finding_details=f"Endpoint '{endpoint['endpoint_name']}' variant '{endpoint['variant_name']}' has only {endpoint['instance_count']} instance(s). Single instance creates availability risk and no failover capability.",
                        resolution="Configure production endpoints with at least 2 instances across multiple Availability Zones for high availability and fault tolerance.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/endpoint-auto-scaling.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if endpoints_multi_instance:
                # Endpoints exist and all have multiple instances - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-12",
                        finding_name="SageMaker Endpoint Instance Count Check",
                        finding_details=f"All {len(endpoints_multi_instance)} endpoint variants have multiple instances",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/endpoint-auto-scaling.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No InService endpoints found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-12",
                        finding_name="SageMaker Endpoint Instance Count Check",
                        finding_details="No InService endpoints found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/endpoint-auto-scaling.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_endpoint_instance_count: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-12",
                    finding_name="SageMaker Endpoint Instance Count Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_monitoring_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker monitoring schedules have network isolation enabled.
    Aligns with AWS Security Hub control SageMaker.14
    """
    logger.debug("Starting check for SageMaker monitoring schedule network isolation")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        schedules_without_isolation = []
        schedules_with_isolation = []

        try:
            paginator = sagemaker_client.get_paginator("list_monitoring_schedules")
            for page in paginator.paginate():
                for schedule in page.get("MonitoringScheduleSummaries", []):
                    schedule_name = schedule.get("MonitoringScheduleName")
                    if schedule_name:
                        try:
                            schedule_details = (
                                sagemaker_client.describe_monitoring_schedule(
                                    MonitoringScheduleName=schedule_name
                                )
                            )

                            job_definition = schedule_details.get(
                                "MonitoringScheduleConfig", {}
                            ).get("MonitoringJobDefinition", {})
                            network_config = job_definition.get("NetworkConfig", {})
                            enable_network_isolation = network_config.get(
                                "EnableNetworkIsolation", False
                            )

                            if not enable_network_isolation:
                                schedules_without_isolation.append(
                                    {
                                        "name": schedule_name,
                                        "status": schedule_details.get(
                                            "MonitoringScheduleStatus", "Unknown"
                                        ),
                                    }
                                )
                            else:
                                schedules_with_isolation.append(schedule_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing monitoring schedule {schedule_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing monitoring schedules: {str(e)}")

        if schedules_without_isolation:
            for schedule in schedules_without_isolation:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-13",
                        finding_name="SageMaker Monitoring Network Isolation Disabled",
                        finding_details=f"Monitoring schedule '{schedule['name']}' does not have network isolation enabled. Monitoring jobs can make outbound network calls.",
                        resolution="Enable network isolation in the monitoring job definition NetworkConfig to prevent outbound network access.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_MonitoringNetworkConfig.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if schedules_with_isolation:
                # Monitoring schedules exist and all have network isolation - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-13",
                        finding_name="SageMaker Monitoring Network Isolation Check",
                        finding_details=f"All {len(schedules_with_isolation)} monitoring schedules have network isolation enabled",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_MonitoringNetworkConfig.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No monitoring schedules found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-13",
                        finding_name="SageMaker Monitoring Network Isolation Check",
                        finding_details="No monitoring schedules found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_MonitoringNetworkConfig.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_monitoring_network_isolation: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-13",
                    finding_name="SageMaker Monitoring Network Isolation Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_model_container_repository(region: str = "") -> Dict[str, Any]:
    """
    Check that every model an endpoint serves pulls each container image with
    RepositoryAccessMode=Vpc, from a private Docker registry in the VPC.
    Aligns with AWS Security Hub control SageMaker.16
    """
    logger.debug("Starting check for SageMaker model container repository access")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        models_platform_mode = []
        models_vpc_mode = []
        unread = []
        served = {}

        # AIR-SGM-EP-03 asks about inference endpoints, so the population is
        # the models an endpoint or its inference components serve.
        try:
            inventory = _endpoint_hosting_inventory(sagemaker_client)
        except Exception as e:
            logger.error(f"Error listing endpoints: {str(e)}")
            unread.append(f"sagemaker:ListEndpoints ({get_assessment_error_label(e)})")
            inventory = {"endpoints": [], "unread": []}
        unread.extend(inventory["unread"])
        for endpoint in inventory["endpoints"]:
            for model_name in endpoint["models"]:
                served.setdefault(model_name, []).append(endpoint["name"])
        for endpoint_name, (
            components,
            component_unread,
        ) in _inference_component_models(sagemaker_client, inventory).items():
            unread.extend(component_unread)
            for _, model_name in components:
                served.setdefault(model_name, []).append(endpoint_name)

        for model_name in sorted(served):
            try:
                model_details = sagemaker_client.describe_model(ModelName=model_name)
            except Exception as e:
                logger.warning(f"Error describing model {model_name}: {str(e)}")
                unread.append(
                    f"sagemaker:DescribeModel {model_name} "
                    f"({get_assessment_error_label(e)})"
                )
                continue
            # A model with no PrimaryContainer is a multi-container model,
            # whose images are all in Containers.
            primary_container = model_details.get("PrimaryContainer")
            containers = ([primary_container] if primary_container else []) + list(
                model_details.get("Containers") or []
            )
            platform = [
                container
                for container in containers
                if (container.get("ImageConfig") or {}).get(
                    "RepositoryAccessMode", "Platform"
                )
                == "Platform"
            ]
            for container in platform:
                models_platform_mode.append(
                    {
                        "name": model_name,
                        "endpoints": sorted(set(served[model_name])),
                        "image": str(container.get("Image", "Unknown"))[:80],
                    }
                )
            if not platform:
                models_vpc_mode.append(model_name)

        if models_platform_mode:
            # Limit findings
            for model in models_platform_mode[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Platform Repository Access",
                        finding_details=(
                            f"Model '{model['name']}', served by endpoint(s) "
                            f"{', '.join(model['endpoints'])}, has a container "
                            f"(image {model['image']}) in Platform repository "
                            "access mode, which means the image is hosted in "
                            "Amazon ECR and is not pulled from a private Docker "
                            "registry in the VPC."
                        ),
                        resolution=(
                            "Set ImageConfig.RepositoryAccessMode=Vpc on each "
                            "container to pull its image from a private Docker "
                            "registry in your VPC."
                        ),
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-container-repositories.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(models_platform_mode) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Repository Access Summary",
                        finding_details=f"Found {len(models_platform_mode)} served model containers using Platform repository access (showing first 15)",
                        resolution="Review all models and configure VPC repository access where appropriate",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-container-repositories.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif not unread:
            if models_vpc_mode:
                # Models exist and all use VPC repository access - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Repository Access Check",
                        finding_details=(
                            f"All {len(models_vpc_mode)} models served by an "
                            "endpoint or inference component use VPC repository "
                            "access on every container"
                        ),
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-container-repositories.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No models found or all use default Platform access - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Repository Access Check",
                        finding_details="No endpoint or inference component serves a model",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-container-repositories.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        if unread:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-14",
                    "SageMaker Model Repository Access Check",
                    unread,
                    f"{len(models_vpc_mode)} served model(s) use VPC repository "
                    "access on every container.",
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-container-repositories.html",
                    region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_container_repository: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-14",
                    finding_name="SageMaker Model Container Repository Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_feature_store_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker Feature Store offline stores have KMS encryption.
    Aligns with AWS Security Hub control SageMaker.17
    """
    logger.debug("Starting check for SageMaker Feature Store offline encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        feature_groups_without_encryption = []
        feature_groups_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator("list_feature_groups")
            for page in paginator.paginate():
                for group in page.get("FeatureGroupSummaries", []):
                    group_name = group.get("FeatureGroupName")
                    if group_name:
                        try:
                            group_details = sagemaker_client.describe_feature_group(
                                FeatureGroupName=group_name
                            )

                            offline_config = group_details.get("OfflineStoreConfig", {})

                            if offline_config:
                                s3_storage_config = offline_config.get(
                                    "S3StorageConfig", {}
                                )
                                kms_key_id = s3_storage_config.get("KmsKeyId")

                                if not kms_key_id:
                                    feature_groups_without_encryption.append(
                                        {
                                            "name": group_name,
                                            "s3_uri": s3_storage_config.get(
                                                "S3Uri", "Unknown"
                                            ),
                                        }
                                    )
                                else:
                                    feature_groups_with_encryption.append(
                                        {"name": group_name, "kms_key": kms_key_id}
                                    )

                        except Exception as e:
                            logger.warning(
                                f"Error describing feature group {group_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing feature groups: {str(e)}")

        if feature_groups_without_encryption:
            for group in feature_groups_without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-15",
                        finding_name="SageMaker Feature Store Offline Encryption Missing",
                        finding_details=f"Feature group '{group['name']}' offline store does not have KMS encryption configured. Feature data in S3 may not be encrypted with customer-managed keys.",
                        resolution="Configure KmsKeyId in OfflineStoreConfig.S3StorageConfig when creating feature groups to encrypt offline store data with customer-managed KMS keys.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-security.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if feature_groups_with_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-15",
                        finding_name="SageMaker Feature Store Encryption Check",
                        finding_details=f"All {len(feature_groups_with_encryption)} feature groups with offline stores have KMS encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-security.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No feature groups with offline stores found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-15",
                        finding_name="SageMaker Feature Store Encryption Check",
                        finding_details="No feature groups with offline stores found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-security.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_feature_store_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-15",
                    finding_name="SageMaker Feature Store Encryption Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_data_quality_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker data quality job definitions have inter-container traffic encryption.
    Aligns with AWS Security Hub control SageMaker.9
    """
    logger.debug("Starting check for SageMaker data quality job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator(
                "list_data_quality_job_definitions"
            )
            for page in paginator.paginate():
                for job in page.get("JobDefinitionSummaries", []):
                    job_name = job.get("MonitoringJobDefinitionName")

                    if job_name:
                        try:
                            job_details = (
                                sagemaker_client.describe_data_quality_job_definition(
                                    JobDefinitionName=job_name
                                )
                            )

                            network_config = job_details.get("NetworkConfig", {})
                            enable_inter_container_encryption = network_config.get(
                                "EnableInterContainerTrafficEncryption", False
                            )

                            if not enable_inter_container_encryption:
                                jobs_without_encryption.append({"name": job_name})
                            else:
                                jobs_with_encryption.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing data quality job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing data quality jobs: {str(e)}")

        if jobs_without_encryption:
            for job in jobs_without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-16",
                        finding_name="SageMaker Data Quality Job Encryption Disabled",
                        finding_details=f"Data quality job definition '{job['name']}' does not have inter-container traffic encryption enabled. Data transmitted between containers is not encrypted.",
                        resolution="Enable EnableInterContainerTrafficEncryption in NetworkConfig when creating data quality job definitions.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_encryption:
                # Data quality jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-16",
                        finding_name="SageMaker Data Quality Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} data quality job definitions have inter-container encryption enabled",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No data quality job definitions found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-16",
                        finding_name="SageMaker Data Quality Job Encryption Check",
                        finding_details="No data quality job definitions found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_data_quality_encryption: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-16",
                    finding_name="SageMaker Data Quality Encryption Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_processing_job_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker processing jobs have volume encryption enabled.
    Aligns with AWS Security Hub control SageMaker.10
    """
    logger.debug("Starting check for SageMaker processing job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator("list_processing_jobs")
            for page in paginator.paginate():
                for job in page.get("ProcessingJobSummaries", []):
                    job_name = job.get("ProcessingJobName")
                    job_status = job.get("ProcessingJobStatus")

                    if job_name:
                        try:
                            job_details = sagemaker_client.describe_processing_job(
                                ProcessingJobName=job_name
                            )

                            processing_resources = job_details.get(
                                "ProcessingResources", {}
                            )
                            cluster_config = processing_resources.get(
                                "ClusterConfig", {}
                            )
                            volume_kms_key = cluster_config.get("VolumeKmsKeyId")

                            if not volume_kms_key:
                                jobs_without_encryption.append(
                                    {"name": job_name, "status": job_status}
                                )
                            else:
                                jobs_with_encryption.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing processing job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing processing jobs: {str(e)}")

        if jobs_without_encryption:
            for job in jobs_without_encryption[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-17",
                        finding_name="SageMaker Processing Job Volume Encryption Missing",
                        finding_details=f"Processing job '{job['name']}' does not have volume encryption configured. Data at rest on processing instances is not encrypted with customer-managed keys.",
                        resolution="Configure VolumeKmsKeyId in ProcessingResources.ClusterConfig when creating processing jobs to encrypt attached EBS volumes.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/processing-job.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_encryption) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-17",
                        finding_name="SageMaker Processing Job Encryption Summary",
                        finding_details=f"Found {len(jobs_without_encryption)} total processing jobs without volume encryption (showing first 15)",
                        resolution="Review all processing jobs and configure volume encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/processing-job.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_encryption:
                # Processing jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-17",
                        finding_name="SageMaker Processing Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} processing jobs have volume encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/processing-job.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No processing jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-17",
                        finding_name="SageMaker Processing Job Encryption Check",
                        finding_details="No processing jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/processing-job.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_processing_job_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-17",
                    finding_name="SageMaker Processing Job Encryption Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


TRANSFORM_JOB_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/APIReference/"
    "API_CreateTransformJob.html"
)
TRANSFORM_JOB_BOUNDARY_FINDING = "SageMaker Transform Job Output Key and Model Boundary"
TRANSFORM_SUBNET_EXPOSURE_FINDING = "SageMaker Transform Job Model Subnet Exposure"
TRANSFORM_S3_ENDPOINT_FINDING = "SageMaker Transform Job S3 VPC Endpoint"
TRANSFORM_BUCKET_FINDING = "SageMaker Transform Job Bucket Protection"
MAX_TRANSFORM_JOB_FINDINGS = 20


def _transform_model_network(sagemaker_client, model_name: str) -> Dict[str, Any]:
    """Return {"subnets", "security_groups", "isolated", "error"} for a model."""
    try:
        model = sagemaker_client.describe_model(ModelName=model_name)
    except ClientError as error:
        message = str(error.response.get("Error", {}).get("Message", ""))
        if "Could not find model" in message:
            return {
                "error": (
                    f"model '{model_name}' no longer exists, so the VpcConfig and "
                    "EnableNetworkIsolation the job ran with are not readable "
                    "(DescribeTransformJob does not record them)"
                )
            }
        return {
            "error": (
                f"sagemaker:DescribeModel {model_name} "
                f"({get_assessment_error_label(error)})"
            )
        }
    except Exception as error:
        return {
            "error": (
                f"sagemaker:DescribeModel {model_name} "
                f"({get_assessment_error_label(error)})"
            )
        }
    vpc_config = model.get("VpcConfig") or {}
    return {
        "subnets": [s for s in vpc_config.get("Subnets") or [] if s],
        "security_groups": [g for g in vpc_config.get("SecurityGroupIds") or [] if g],
        "isolated": model.get("EnableNetworkIsolation") is True,
        "error": None,
    }


def _transform_job_boundary_findings(
    jobs: List[Dict[str, Any]],
    sagemaker_client,
    unread: List[str],
    region: str,
) -> List[Dict[str, Any]]:
    """
    AIR-SGM-EP-08: a transform job takes its network posture from the model it
    names, so each job's ModelName is resolved to that model's VpcConfig and
    EnableNetworkIsolation. TransformOutput.KmsKeyId encrypts the results in S3,
    and both job keys must be customer managed.
    """
    models: Dict[str, Dict[str, Any]] = {}
    for job in jobs:
        model_name = job["detail"].get("ModelName")
        if model_name and model_name not in models:
            models[model_name] = _transform_model_network(sagemaker_client, model_name)
    managers = _kms_key_managers(
        [
            key
            for job in jobs
            for key in (
                (job["detail"].get("TransformResources") or {}).get("VolumeKmsKeyId"),
                (job["detail"].get("TransformOutput") or {}).get("KmsKeyId"),
            )
            if key
        ],
        region,
    )

    failed = []
    clean = []
    jobs_in_vpc = []
    bucket_users: Dict[str, List[str]] = {}
    for job in jobs:
        name = job["name"]
        detail = job["detail"]
        problems = []
        job_unread = []
        output = detail.get("TransformOutput") or {}
        output_key = output.get("KmsKeyId")
        if not output_key:
            problems.append(
                "TransformOutput.KmsKeyId is not set, so the results in S3 are not "
                "encrypted with a customer managed key"
            )
        if not (detail.get("TransformResources") or {}).get("VolumeKmsKeyId"):
            problems.append(
                "TransformResources.VolumeKmsKeyId is not set, so the instance "
                "storage volume is not encrypted with a customer managed key"
            )
        for field, key in (
            (
                "TransformResources.VolumeKmsKeyId",
                (detail.get("TransformResources") or {}).get("VolumeKmsKeyId"),
            ),
            ("TransformOutput.KmsKeyId", output_key),
        ):
            if not key:
                continue
            manager = managers[str(key)]
            if manager["manager"] == "AWS":
                problems.append(f"{field} {key} is an AWS managed key")
            elif manager["manager"] is None:
                job_unread.append(f"kms:DescribeKey {key} ({manager['error']})")
        model_name = detail.get("ModelName")
        network = models.get(model_name) if model_name else None
        if network is None:
            job_unread.append("the job names no ModelName")
        elif network["error"]:
            job_unread.append(network["error"])
        else:
            if not network["subnets"] or not network["security_groups"]:
                problems.append(
                    f"model '{model_name}' has no VpcConfig with subnets and "
                    "security groups, so the job ran in the SageMaker-managed network"
                )
            else:
                jobs_in_vpc.append({"name": name, "subnets": network["subnets"]})
            if not network["isolated"]:
                problems.append(
                    f"model '{model_name}' does not set EnableNetworkIsolation, so "
                    "the container can make outbound network calls"
                )
        for uri in (
            ((detail.get("TransformInput") or {}).get("DataSource") or {})
            .get("S3DataSource", {})
            .get("S3Uri"),
            output.get("S3OutputPath"),
        ):
            bucket = _s3_uri_bucket(uri)
            if bucket:
                bucket_users.setdefault(bucket, [])
                if name not in bucket_users[bucket]:
                    bucket_users[bucket].append(name)
        if problems:
            failed.append((name, problems, job_unread))
        elif job_unread:
            unread.extend(f"transform job {name}: {item}" for item in job_unread)
        else:
            clean.append(name)

    emitted = []
    for name, problems, job_unread in failed[:MAX_TRANSFORM_JOB_FINDINGS]:
        emitted.append(
            create_finding(
                check_id="SM-18",
                finding_name=TRANSFORM_JOB_BOUNDARY_FINDING,
                finding_details=(
                    f"Transform job '{name}': {'; '.join(problems)}."
                    + (f" Not read: {'; '.join(job_unread)}." if job_unread else "")
                ),
                resolution=(
                    "Recreate the model with VpcConfig (private subnets and security "
                    "groups) and EnableNetworkIsolation true, and run transform jobs "
                    "against it with TransformResources.VolumeKmsKeyId and "
                    "TransformOutput.KmsKeyId set to customer managed keys."
                ),
                reference=TRANSFORM_JOB_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if len(failed) > MAX_TRANSFORM_JOB_FINDINGS:
        emitted.append(
            create_finding(
                check_id="SM-18",
                finding_name=TRANSFORM_JOB_BOUNDARY_FINDING,
                finding_details=(
                    f"{len(failed)} transform jobs fail (the first "
                    f"{MAX_TRANSFORM_JOB_FINDINGS} are reported above): "
                    f"{', '.join(n for n, _, _ in failed[MAX_TRANSFORM_JOB_FINDINGS:])}."
                ),
                resolution="Apply the same fix to each transform job listed.",
                reference=TRANSFORM_JOB_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    read_details = (
        f"{len(clean)} transform job(s) use customer managed keys for the volume "
        "and the output and name a model that is VPC-attached and network "
        f"isolated: {', '.join(clean[:10]) or 'none'}."
    )
    if unread:
        emitted.append(
            _unread_resources_finding(
                "SM-18",
                TRANSFORM_JOB_BOUNDARY_FINDING,
                unread,
                read_details,
                TRANSFORM_JOB_REFERENCE,
                region,
            )
        )
    elif clean and not failed:
        emitted.append(
            create_finding(
                check_id="SM-18",
                finding_name=TRANSFORM_JOB_BOUNDARY_FINDING,
                finding_details=read_details,
                resolution="No action required",
                reference=TRANSFORM_JOB_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )

    emitted.extend(
        _subnet_exposure_findings(
            check_id="SM-18",
            finding_name=TRANSFORM_SUBNET_EXPOSURE_FINDING,
            resources=[
                {"name": f"Transform job '{job['name']}'", "subnets": job["subnets"]}
                for job in jobs_in_vpc
            ],
            region=region,
            reference=TRANSFORM_JOB_REFERENCE,
            resolution=(
                "Recreate the model with VpcConfig naming subnets whose route "
                "tables have no internet gateway route."
            ),
            severity="Medium",
        )
    )
    emitted.extend(
        _training_vpc_endpoint_findings(
            jobs_in_vpc,
            region,
            check_id="SM-18",
            finding_name=TRANSFORM_S3_ENDPOINT_FINDING,
            services=("s3",),
            subject="transform job",
            resolution=(
                "Create an S3 gateway endpoint in the VPC. Network isolation "
                "removes the container's interface but not the one SageMaker uses "
                "to move the input and output through S3."
            ),
            judge_s3_policy=True,
        )
    )
    emitted.extend(
        _bucket_protection_findings(
            "SM-18", TRANSFORM_BUCKET_FINDING, bucket_users, region
        )
    )
    return emitted


def check_sagemaker_transform_job_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker transform jobs have volume encryption enabled.
    Aligns with AWS Security Hub control SageMaker.11

    AIR-SGM-EP-08 also needs the output key, the model's network posture and
    the buckets, which _transform_job_boundary_findings reports.
    """
    logger.debug("Starting check for SageMaker transform job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []
        described = []
        unread = []

        # A ListTransformJobs failure reaches the outer handler, so it is
        # reported as not assessed instead of "No transform jobs found".
        paginator = sagemaker_client.get_paginator("list_transform_jobs")
        for page in paginator.paginate():
            for job in page.get("TransformJobSummaries", []):
                job_name = job.get("TransformJobName")
                job_status = job.get("TransformJobStatus")

                if job_name:
                    try:
                        job_details = sagemaker_client.describe_transform_job(
                            TransformJobName=job_name
                        )
                    except Exception as e:
                        logger.warning(
                            f"Error describing transform job {job_name}: {str(e)}"
                        )
                        unread.append(
                            f"sagemaker:DescribeTransformJob {job_name} "
                            f"({get_assessment_error_label(e)})"
                        )
                        continue
                    described.append({"name": job_name, "detail": job_details})

                    transform_resources = job_details.get("TransformResources", {})
                    volume_kms_key = transform_resources.get("VolumeKmsKeyId")

                    if not volume_kms_key:
                        jobs_without_encryption.append(
                            {"name": job_name, "status": job_status}
                        )
                    else:
                        jobs_with_encryption.append(job_name)

        if jobs_without_encryption:
            for job in jobs_without_encryption[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-18",
                        finding_name="SageMaker Transform Job Volume Encryption Missing",
                        finding_details=f"Transform job '{job['name']}' does not have volume encryption configured. Data at rest on transform instances is not encrypted with customer-managed keys.",
                        resolution="Configure VolumeKmsKeyId in TransformResources when creating transform jobs to encrypt attached EBS volumes.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/batch-transform.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_encryption) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-18",
                        finding_name="SageMaker Transform Job Encryption Summary",
                        finding_details=f"Found {len(jobs_without_encryption)} total transform jobs without volume encryption (showing first 15)",
                        resolution="Review all transform jobs and configure volume encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/batch-transform.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif unread:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-18",
                    "SageMaker Transform Job Encryption Check",
                    unread,
                    f"{len(jobs_with_encryption)} transform job(s) have volume "
                    "encryption configured.",
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/batch-transform.html",
                    region,
                )
            )
        else:
            if jobs_with_encryption:
                # Transform jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-18",
                        finding_name="SageMaker Transform Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} transform jobs have volume encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/batch-transform.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No transform jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-18",
                        finding_name="SageMaker Transform Job Encryption Check",
                        finding_details="No transform jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/batch-transform.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        if described or unread:
            findings["csv_data"].extend(
                _transform_job_boundary_findings(
                    described, sagemaker_client, list(unread), region
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_transform_job_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-18",
                    finding_name="SageMaker Transform Job Encryption Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_hyperparameter_tuning_encryption(
    region: str = "",
) -> Dict[str, Any]:
    """
    Check if SageMaker hyperparameter tuning jobs have volume encryption enabled.
    Aligns with AWS Security Hub control SageMaker.12
    """
    logger.debug("Starting check for SageMaker hyperparameter tuning job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator(
                "list_hyper_parameter_tuning_jobs"
            )
            for page in paginator.paginate():
                for job in page.get("HyperParameterTuningJobSummaries", []):
                    job_name = job.get("HyperParameterTuningJobName")
                    job_status = job.get("HyperParameterTuningJobStatus")

                    if job_name:
                        try:
                            job_details = (
                                sagemaker_client.describe_hyper_parameter_tuning_job(
                                    HyperParameterTuningJobName=job_name
                                )
                            )

                            training_job_definition = job_details.get(
                                "TrainingJobDefinition", {}
                            )
                            resource_config = training_job_definition.get(
                                "ResourceConfig", {}
                            )
                            volume_kms_key = resource_config.get("VolumeKmsKeyId")

                            if not volume_kms_key:
                                jobs_without_encryption.append(
                                    {"name": job_name, "status": job_status}
                                )
                            else:
                                jobs_with_encryption.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing hyperparameter tuning job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing hyperparameter tuning jobs: {str(e)}")

        if jobs_without_encryption:
            for job in jobs_without_encryption[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-19",
                        finding_name="SageMaker Hyperparameter Tuning Job Encryption Missing",
                        finding_details=f"Hyperparameter tuning job '{job['name']}' does not have volume encryption configured. Training data at rest is not encrypted with customer-managed keys.",
                        resolution="Configure VolumeKmsKeyId in TrainingJobDefinition.ResourceConfig when creating hyperparameter tuning jobs.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_encryption) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-19",
                        finding_name="SageMaker Hyperparameter Tuning Job Encryption Summary",
                        finding_details=f"Found {len(jobs_without_encryption)} total hyperparameter tuning jobs without volume encryption (showing first 15)",
                        resolution="Review all hyperparameter tuning jobs and configure volume encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_encryption:
                # Hyperparameter tuning jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-19",
                        finding_name="SageMaker Hyperparameter Tuning Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} hyperparameter tuning jobs have volume encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No hyperparameter tuning jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-19",
                        finding_name="SageMaker Hyperparameter Tuning Job Encryption Check",
                        finding_details="No hyperparameter tuning jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_hyperparameter_tuning_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-19",
                    finding_name="SageMaker Hyperparameter Tuning Encryption Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_compilation_job_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker compilation jobs have volume encryption enabled.
    Aligns with AWS Security Hub control SageMaker.13
    """
    logger.debug("Starting check for SageMaker compilation job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator("list_compilation_jobs")
            for page in paginator.paginate():
                for job in page.get("CompilationJobSummaries", []):
                    job_name = job.get("CompilationJobName")
                    job_status = job.get("CompilationJobStatus")

                    if job_name:
                        try:
                            job_details = sagemaker_client.describe_compilation_job(
                                CompilationJobName=job_name
                            )

                            output_config = job_details.get("OutputConfig", {})
                            kms_key_id = output_config.get("KmsKeyId")

                            if not kms_key_id:
                                jobs_without_encryption.append(
                                    {"name": job_name, "status": job_status}
                                )
                            else:
                                jobs_with_encryption.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing compilation job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing compilation jobs: {str(e)}")

        if jobs_without_encryption:
            for job in jobs_without_encryption[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-20",
                        finding_name="SageMaker Compilation Job Encryption Missing",
                        finding_details=f"Compilation job '{job['name']}' does not have output encryption configured. Compiled model artifacts are not encrypted with customer-managed keys.",
                        resolution="Configure KmsKeyId in OutputConfig when creating compilation jobs to encrypt compiled model output.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/neo.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_encryption) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-20",
                        finding_name="SageMaker Compilation Job Encryption Summary",
                        finding_details=f"Found {len(jobs_without_encryption)} total compilation jobs without encryption (showing first 15)",
                        resolution="Review all compilation jobs and configure output encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/neo.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_encryption:
                # Compilation jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-20",
                        finding_name="SageMaker Compilation Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} compilation jobs have output encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/neo.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No compilation jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-20",
                        finding_name="SageMaker Compilation Job Encryption Check",
                        finding_details="No compilation jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/neo.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_compilation_job_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-20",
                    finding_name="SageMaker Compilation Job Encryption Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_automl_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker AutoML (Autopilot) jobs have network isolation enabled.
    Aligns with AWS Security Hub control SageMaker.15
    """
    logger.debug("Starting check for SageMaker AutoML job network isolation")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_isolation = []
        jobs_with_isolation = []

        try:
            paginator = sagemaker_client.get_paginator("list_auto_ml_jobs")
            for page in paginator.paginate():
                for job in page.get("AutoMLJobSummaries", []):
                    job_name = job.get("AutoMLJobName")
                    job_status = job.get("AutoMLJobStatus")

                    if job_name:
                        try:
                            job_details = sagemaker_client.describe_auto_ml_job(
                                AutoMLJobName=job_name
                            )

                            security_config = job_details.get(
                                "AutoMLJobConfig", {}
                            ).get("SecurityConfig", {})
                            enable_inter_container_encryption = security_config.get(
                                "EnableInterContainerTrafficEncryption", False
                            )

                            if not enable_inter_container_encryption:
                                jobs_without_isolation.append(
                                    {"name": job_name, "status": job_status}
                                )
                            else:
                                jobs_with_isolation.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing AutoML job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing AutoML jobs: {str(e)}")

        if jobs_without_isolation:
            for job in jobs_without_isolation[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-21",
                        finding_name="SageMaker AutoML Job Network Isolation Disabled",
                        finding_details=f"AutoML job '{job['name']}' does not have inter-container traffic encryption enabled. Data transmitted between containers during training is not encrypted.",
                        resolution="Enable EnableInterContainerTrafficEncryption in AutoMLJobConfig.SecurityConfig when creating AutoML jobs.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AutoMLSecurityConfig.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_isolation) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-21",
                        finding_name="SageMaker AutoML Job Network Isolation Summary",
                        finding_details=f"Found {len(jobs_without_isolation)} total AutoML jobs without network isolation (showing first 15)",
                        resolution="Review all AutoML jobs and enable inter-container traffic encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AutoMLSecurityConfig.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_isolation:
                # AutoML jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-21",
                        finding_name="SageMaker AutoML Job Network Isolation Check",
                        finding_details=f"All {len(jobs_with_isolation)} AutoML jobs have inter-container encryption enabled",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AutoMLSecurityConfig.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No AutoML jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-21",
                        finding_name="SageMaker AutoML Job Network Isolation Check",
                        finding_details="No AutoML jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AutoMLSecurityConfig.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_automl_network_isolation: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-21",
                    finding_name="SageMaker AutoML Network Isolation Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


# ============================================================================
# MODEL GOVERNANCE CHECKS
# ============================================================================


APPROVER_ATTRIBUTION_FINDING = "Model Approval Workflow - Approver Attribution"
APPROVER_ATTRIBUTION_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html"
)
APPROVER_ATTRIBUTION_RESOLUTION = (
    "Approve model packages with UpdateModelPackage called by a named identity "
    "and pass ApprovalDescription recording who approved the version and on what "
    "evidence. SageMaker stores the calling identity in LastModifiedBy, so an "
    "approval made by a shared automation role with no description leaves no "
    "auditable approver."
)

MODEL_LIFECYCLE_FINDING = "Model Registry Lifecycle Stage"
MODEL_LIFECYCLE_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/"
    "model-registry-staging-construct.html"
)
DEPLOYED_MODEL_REGISTRATION_FINDING = "Deployed Model Registration"
DEPLOYED_MODEL_REGISTRATION_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-deploy.html"
)
REGISTRY_SHARING_FINDING = "Model Registry Cross-Account Visibility"
REGISTRY_SHARING_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-ram.html"
)
MODEL_PACKAGE_GROUP_RAM_TYPE = "sagemaker:ModelPackageGroup"
MODEL_APPROVAL_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html"
)


def _user_context_identity(context: Any) -> Optional[str]:
    """Return the identity a SageMaker UserContext names, if there is one."""
    if isinstance(context, dict):
        user_profile = context.get("UserProfileName")
        if user_profile:
            return f"user profile {user_profile}"
        iam_identity = context.get("IamIdentity")
        if isinstance(iam_identity, dict):
            source_identity = iam_identity.get("SourceIdentity")
            if source_identity:
                return f"source identity {source_identity}"
            arn = iam_identity.get("Arn")
            if arn:
                return arn
    return None


def _approver_attribution(model_package_detail: Dict[str, Any]) -> Optional[str]:
    """
    Return the recorded approver of a model package version, if there is one.

    Approval is applied through UpdateModelPackage, so the approver is the last
    modifier. CreatedBy names the registrant and is not read as the approver.
    """
    return _user_context_identity(model_package_detail.get("LastModifiedBy"))


def _unapproved_reason(model_package_detail: Dict[str, Any]) -> str:
    """Say why an approved version records no approver."""
    parts = []
    registrant = _user_context_identity(model_package_detail.get("CreatedBy"))
    if registrant:
        parts.append(
            "LastModifiedBy carries no identity, so no UpdateModelPackage call "
            f"recorded an approver; CreatedBy names only the registrant {registrant}"
        )
    else:
        parts.append(
            "LastModifiedBy and CreatedBy carry no user profile, source identity "
            "or IAM ARN"
        )
    description = (model_package_detail.get("ApprovalDescription") or "").strip()
    if description:
        parts.append(
            f"ApprovalDescription '{description[:60]}' is free text, not an identity"
        )
    else:
        parts.append("ApprovalDescription is empty")
    return ", and ".join(parts)


def _approval_attribution_findings(
    approvals_with_approver: List[Dict[str, Any]],
    approvals_without_approver: List[Dict[str, Any]],
    versions_examined: int,
    region: str,
) -> List[Dict[str, Any]]:
    """
    Report the approver-metadata leg of AIR-SGM-GOV-01.

    The incumbent legs read ModelApprovalStatus, which says a version is
    approved but not by whom, so neither verdict can be derived from them.
    """
    if not versions_examined:
        return []

    emitted = []

    for entry in approvals_without_approver[:20]:
        emitted.append(
            create_finding(
                check_id="SM-22",
                finding_name=APPROVER_ATTRIBUTION_FINDING,
                finding_details=(
                    f"Approved model package '{entry['name']}' in group "
                    f"'{entry['group']}' records no approver: {entry['reason']}."
                ),
                resolution=APPROVER_ATTRIBUTION_RESOLUTION,
                reference=APPROVER_ATTRIBUTION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )

    if len(approvals_without_approver) > 20:
        emitted.append(
            create_finding(
                check_id="SM-22",
                finding_name=APPROVER_ATTRIBUTION_FINDING,
                finding_details=(
                    f"{len(approvals_without_approver)} approved model package "
                    "versions record no approver (the first 20 are reported "
                    "individually above)."
                ),
                resolution=APPROVER_ATTRIBUTION_RESOLUTION,
                reference=APPROVER_ATTRIBUTION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )

    if approvals_with_approver:
        described = "; ".join(
            "{} approved by {}".format(entry["name"], entry["approver"])
            for entry in approvals_with_approver[:3]
        )
        emitted.append(
            create_finding(
                check_id="SM-22",
                finding_name=APPROVER_ATTRIBUTION_FINDING,
                finding_details=(
                    f"{len(approvals_with_approver)} of {versions_examined} "
                    "approved model package versions examined record an approver "
                    f"identity: {described}."
                ),
                resolution="No action required.",
                reference=APPROVER_ATTRIBUTION_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )

    return emitted


def _lifecycle_finding(
    unstaged: List[str], examined: int, region: str
) -> Dict[str, Any]:
    """Report whether each approved version carries a ModelLifeCycle stage."""
    if unstaged:
        return create_finding(
            check_id="SM-22",
            finding_name=MODEL_LIFECYCLE_FINDING,
            finding_details=(
                f"{len(unstaged)} of {examined} approved model package versions "
                "carry no ModelLifeCycle Stage and StageStatus, so the registry "
                "holds their current approval status but no staging history: "
                f"{', '.join(unstaged[:10])}."
            ),
            resolution=(
                "Set ModelLifeCycle (Stage, StageStatus, StageDescription) with "
                "UpdateModelPackage at each promotion so the transition is recorded "
                "on the package and emitted to EventBridge."
            ),
            reference=MODEL_LIFECYCLE_REFERENCE,
            severity="Low",
            status="Failed",
            region=region,
        )
    return create_finding(
        check_id="SM-22",
        finding_name=MODEL_LIFECYCLE_FINDING,
        finding_details=(
            f"All {examined} approved model package versions carry a ModelLifeCycle "
            "Stage and StageStatus."
        ),
        resolution="No action required",
        reference=MODEL_LIFECYCLE_REFERENCE,
        severity="Low",
        status="Passed",
        region=region,
    )


def _registry_sharing(region: str) -> Dict[str, Any]:
    """Read model package groups shared through AWS RAM, in both directions."""
    try:
        ram_client = boto3.client("ram", config=boto3_config, region_name=region)
        result = {}
        for owner, key in (("SELF", "shared_out"), ("OTHER-ACCOUNTS", "shared_in")):
            arns = []
            for page in ram_client.get_paginator("list_resources").paginate(
                resourceOwner=owner, resourceType=MODEL_PACKAGE_GROUP_RAM_TYPE
            ):
                arns.extend(str(item.get("arn")) for item in page.get("resources", []))
            result[key] = sorted(set(arns))
        return result
    except Exception as error:
        return {"error": f"ram:ListResources {get_assessment_error_label(error)}"}


def _registry_sharing_finding(
    sharing: Dict[str, Any], groups: int, region: str
) -> Dict[str, Any]:
    if "error" in sharing:
        return _unread_resources_finding(
            "SM-22",
            REGISTRY_SHARING_FINDING,
            [sharing["error"]],
            f"{groups} model package group(s) were read.",
            REGISTRY_SHARING_REFERENCE,
            region,
        )
    shared = sharing["shared_out"] + sharing["shared_in"]
    if shared:
        return create_finding(
            check_id="SM-22",
            finding_name=REGISTRY_SHARING_FINDING,
            finding_details=(
                f"{len(sharing['shared_out'])} model package group(s) are shared "
                f"from this account and {len(sharing['shared_in'])} are shared with "
                f"it through AWS RAM: {', '.join(shared[:5])}."
            ),
            resolution="No action required",
            reference=REGISTRY_SHARING_REFERENCE,
            severity="Low",
            status="Passed",
            region=region,
        )
    return create_finding(
        check_id="SM-22",
        finding_name=REGISTRY_SHARING_FINDING,
        finding_details=(
            f"None of the {groups} model package group(s) is shared through AWS "
            "RAM, and none is shared with this account, so the registry is visible "
            "only to principals in this account."
        ),
        resolution=(
            "Share the model package groups other accounts deploy from with AWS "
            "RAM so the registry is the record those accounts read."
        ),
        reference=REGISTRY_SHARING_REFERENCE,
        severity="Low",
        status="Failed",
        region=region,
    )


def _endpoint_variant_models(
    sagemaker_client: Any, unread: List[str]
) -> Tuple[Dict[str, List[str]], int]:
    """Map each model serving on an endpoint to the endpoint/variant labels."""
    models = {}
    endpoints = 0
    for page in sagemaker_client.get_paginator("list_endpoints").paginate():
        for summary in page.get("Endpoints", []):
            endpoint = summary.get("EndpointName")
            endpoints += 1
            try:
                config_name = sagemaker_client.describe_endpoint(
                    EndpointName=endpoint
                ).get("EndpointConfigName")
                variants = sagemaker_client.describe_endpoint_config(
                    EndpointConfigName=config_name
                ).get("ProductionVariants", [])
            except Exception as error:
                unread.append(
                    f"endpoint {endpoint} ({get_assessment_error_label(error)})"
                )
                continue
            for variant in variants:
                label = f"{endpoint}/{variant.get('VariantName')}"
                if variant.get("ModelName"):
                    models.setdefault(variant["ModelName"], []).append(label)
                    continue
                # A variant with no ModelName hosts inference components, each of
                # which names its own model.
                try:
                    for ic_page in sagemaker_client.get_paginator(
                        "list_inference_components"
                    ).paginate(
                        EndpointNameEquals=endpoint,
                        VariantNameEquals=variant.get("VariantName"),
                    ):
                        for component in ic_page.get("InferenceComponents", []):
                            name = component.get("InferenceComponentName")
                            spec = (
                                sagemaker_client.describe_inference_component(
                                    InferenceComponentName=name
                                ).get("Specification")
                                or {}
                            )
                            if spec.get("ModelName"):
                                models.setdefault(spec["ModelName"], []).append(
                                    f"{label}/{name}"
                                )
                except Exception as error:
                    unread.append(
                        f"inference components of {label} "
                        f"({get_assessment_error_label(error)})"
                    )
    return models, endpoints


def _transform_job_models(
    sagemaker_client: Any, models: Dict[str, List[str]], unread: List[str]
) -> int:
    """Add the model each batch transform job ran to models; return the job count."""
    jobs = 0
    try:
        for page in sagemaker_client.get_paginator("list_transform_jobs").paginate():
            for summary in page.get("TransformJobSummaries", []):
                name = summary.get("TransformJobName")
                jobs += 1
                try:
                    model_name = sagemaker_client.describe_transform_job(
                        TransformJobName=name
                    ).get("ModelName")
                except Exception as error:
                    unread.append(
                        f"transform job {name} ({get_assessment_error_label(error)})"
                    )
                    continue
                if not model_name:
                    unread.append(f"transform job {name} (no ModelName returned)")
                    continue
                models.setdefault(model_name, []).append(f"transform job {name}")
    except Exception as error:
        unread.append(
            f"sagemaker:ListTransformJobs ({get_assessment_error_label(error)})"
        )
    return jobs


def _deployed_model_registration_findings(
    sagemaker_client: Any, region: str
) -> List[Dict[str, Any]]:
    """
    Report whether every model serving on an endpoint or run by a batch
    transform job was created from an Approved version in a model package group.
    """
    unread = []
    try:
        models, endpoints = _endpoint_variant_models(sagemaker_client, unread)
    except Exception as error:
        return [
            _unread_resources_finding(
                "SM-22",
                DEPLOYED_MODEL_REGISTRATION_FINDING,
                [f"sagemaker:ListEndpoints ({get_assessment_error_label(error)})"],
                "no endpoint was read.",
                DEPLOYED_MODEL_REGISTRATION_REFERENCE,
                region,
            )
        ]
    transform_jobs = _transform_job_models(sagemaker_client, models, unread)
    if not endpoints and not transform_jobs and not unread:
        return []
    problems = []
    registered = 0
    for model_name, labels in sorted(models.items()):
        where = ", ".join(labels[:3])
        try:
            model = sagemaker_client.describe_model(ModelName=model_name)
        except Exception as error:
            unread.append(f"model {model_name} ({get_assessment_error_label(error)})")
            continue
        containers = [model.get("PrimaryContainer")] + list(
            model.get("Containers") or []
        )
        containers = [container for container in containers if container]
        packages = [container.get("ModelPackageName") for container in containers]
        if not containers or not all(packages):
            problems.append(
                f"model '{model_name}' on {where} has a container with no "
                "ModelPackageName, so it was not created from the registry"
            )
            continue
        verdicts = []
        for package in packages:
            try:
                detail = sagemaker_client.describe_model_package(
                    ModelPackageName=package
                )
            except Exception as error:
                unread.append(
                    f"model package {package} ({get_assessment_error_label(error)})"
                )
                verdicts.append(None)
                continue
            if not detail.get("ModelPackageGroupName"):
                verdicts.append(f"package {package} belongs to no model package group")
            elif detail.get("ModelApprovalStatus") != "Approved":
                verdicts.append(
                    f"package {package} is "
                    f"{detail.get('ModelApprovalStatus') or 'without an approval status'}"
                )
            else:
                verdicts.append("")
        failures = [verdict for verdict in verdicts if verdict]
        if failures:
            problems.append(f"model '{model_name}' on {where}: {'; '.join(failures)}")
        elif None not in verdicts:
            registered += 1
    rows = []
    for problem in problems[:20]:
        rows.append(
            create_finding(
                check_id="SM-22",
                finding_name=DEPLOYED_MODEL_REGISTRATION_FINDING,
                finding_details=f"Deployed {problem}.",
                resolution=(
                    "Deploy only models created from an Approved model package "
                    "version (CreateModel with ModelPackageName), so each serving "
                    "model has a registry entry with its approval status and "
                    "approver."
                ),
                reference=DEPLOYED_MODEL_REGISTRATION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if len(problems) > 20:
        rows.append(
            create_finding(
                check_id="SM-22",
                finding_name=DEPLOYED_MODEL_REGISTRATION_FINDING,
                finding_details=(
                    f"{len(problems)} deployed models are unregistered or "
                    "unapproved (the first 20 are reported individually above)."
                ),
                resolution="Deploy only models created from an Approved model package version.",
                reference=DEPLOYED_MODEL_REGISTRATION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-22",
                DEPLOYED_MODEL_REGISTRATION_FINDING,
                unread,
                f"{endpoints} endpoint(s), {transform_jobs} batch transform job(s), "
                f"and {len(models)} model(s) they use were found.",
                DEPLOYED_MODEL_REGISTRATION_REFERENCE,
                region,
            )
        )
    elif not problems:
        rows.append(
            create_finding(
                check_id="SM-22",
                finding_name=DEPLOYED_MODEL_REGISTRATION_FINDING,
                finding_details=(
                    f"All {registered} model(s) serving on the {endpoints} endpoint(s) "
                    f"and run by the {transform_jobs} batch transform job(s) read were "
                    "created from an Approved version in a model package group."
                ),
                resolution="No action required",
                reference=DEPLOYED_MODEL_REGISTRATION_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return rows


def check_model_approval_workflow(region: str = "") -> Dict[str, Any]:
    """
    Check if Model Registry has proper approval workflows configured.
    Validates that models go through approval process before production deployment.
    """
    # FinServ extension (FS-19): The FinServ guide (PDF §1.2.14) expects model
    # package groups to enforce ModelApprovalStatus=PendingManualApproval by default
    # and to flag model packages that are auto-approved as their latest version.
    # See docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md (FS-19 → SM-22
    # extension note) for the detection refinement.
    logger.debug("Starting check for model approval workflow")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        issues_found = []
        groups_checked = 0
        approvals_with_approver = []
        approvals_without_approver = []
        approval_versions_examined = 0
        unstaged_versions = []
        unread = []
        group_list_error = None

        try:
            paginator = sagemaker_client.get_paginator("list_model_package_groups")
            for page in paginator.paginate():
                for group in page.get("ModelPackageGroupSummaryList", []):
                    group_name = group.get("ModelPackageGroupName")
                    groups_checked += 1

                    if group_name:
                        try:
                            model_packages = list_all_model_packages(
                                sagemaker_client, group_name
                            )

                            if not model_packages:
                                continue

                            # Check approval status distribution
                            pending_count = 0
                            approved_count = 0
                            rejected_count = 0

                            for model in model_packages:
                                status = model.get(
                                    "ModelApprovalStatus", "PendingManualApproval"
                                )
                                if status == "PendingManualApproval":
                                    pending_count += 1
                                elif status == "Approved":
                                    approved_count += 1
                                elif status == "Rejected":
                                    rejected_count += 1

                            # Check if any models are approved without going through pending
                            total_models = len(model_packages)

                            # If all models are approved and none are pending/rejected, might indicate auto-approval
                            if approved_count == total_models and total_models > 3:
                                issues_found.append(
                                    {
                                        "type": "Auto-Approval Suspected",
                                        "group": group_name,
                                        "details": f"All {total_models} models in group '{group_name}' are approved with no pending or rejected models. Manual approval workflow may not be enforced.",
                                        "severity": "Medium",
                                    }
                                )

                            # AIR-SGM-GOV-01 asks who approved each version,
                            # which only DescribeModelPackage answers, so every
                            # approved version is described.
                            for model in model_packages:
                                if model.get("ModelApprovalStatus") != "Approved":
                                    continue
                                package_id = model.get("ModelPackageArn") or model.get(
                                    "ModelPackageName"
                                )
                                if not package_id:
                                    continue
                                try:
                                    detail = sagemaker_client.describe_model_package(
                                        ModelPackageName=package_id
                                    )
                                except Exception as error:
                                    logger.warning(
                                        "Error describing model package "
                                        f"{package_id}: {str(error)}"
                                    )
                                    unread.append(
                                        f"sagemaker:DescribeModelPackage {package_id} "
                                        f"({get_assessment_error_label(error)})"
                                    )
                                    continue
                                approval_versions_examined += 1
                                version_label = (
                                    detail.get("ModelPackageName")
                                    or detail.get("ModelPackageArn")
                                    or package_id
                                )
                                approver = _approver_attribution(detail)
                                if approver:
                                    approvals_with_approver.append(
                                        {
                                            "name": version_label,
                                            "group": group_name,
                                            "approver": approver,
                                        }
                                    )
                                else:
                                    approvals_without_approver.append(
                                        {
                                            "name": version_label,
                                            "group": group_name,
                                            "reason": _unapproved_reason(detail),
                                        }
                                    )
                                lifecycle = detail.get("ModelLifeCycle") or {}
                                if not (
                                    lifecycle.get("Stage")
                                    and lifecycle.get("StageStatus")
                                ):
                                    unstaged_versions.append(version_label)

                            # Check for models stuck in pending
                            if pending_count > 5:
                                issues_found.append(
                                    {
                                        "type": "Stale Pending Models",
                                        "group": group_name,
                                        "details": f"Model group '{group_name}' has {pending_count} models pending approval. Review and process pending model approvals.",
                                        "severity": "Low",
                                    }
                                )

                        except Exception as e:
                            logger.warning(
                                f"Error checking model group {group_name}: {str(e)}"
                            )
                            unread.append(
                                f"sagemaker:ListModelPackages {group_name} "
                                f"({get_assessment_error_label(e)})"
                            )

        except Exception as e:
            logger.error(f"Error listing model package groups: {str(e)}")
            group_list_error = get_assessment_error_label(e)
            unread.append(f"sagemaker:ListModelPackageGroups ({group_list_error})")

        sharing = _registry_sharing(region)

        if groups_checked == 0 and group_list_error:
            pass
        elif groups_checked == 0 and sharing.get("shared_in"):
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-22",
                    finding_name="Model Approval Workflow Check",
                    finding_details=(
                        "This account registers no model package group of its own "
                        f"and reads {len(sharing['shared_in'])} group(s) shared "
                        "with it through AWS RAM: "
                        f"{', '.join(sharing['shared_in'][:5])}. The approval "
                        "record for those groups is read in the owning account."
                    ),
                    resolution="No action required",
                    reference=MODEL_APPROVAL_REFERENCE,
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        elif groups_checked == 0:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-22",
                    finding_name="Model Approval Workflow Check",
                    finding_details=(
                        "No model package groups found, and "
                        + (
                            "no group is shared with this account through AWS RAM"
                            if "error" not in sharing
                            else f"AWS RAM sharing was not read ({sharing['error']})"
                        )
                        + ". Model Registry is not being used for model governance, "
                        "so no model version, approval status or approver is "
                        "recorded."
                    ),
                    resolution="Implement Model Registry to track model versions and enforce approval workflows before production deployment.",
                    reference=MODEL_APPROVAL_REFERENCE,
                    severity="Medium",
                    status="Failed" if "error" not in sharing else "N/A",
                    region=region,
                )
            )
        elif issues_found or approvals_without_approver:
            # The unattributed-approval list is part of this guard so the
            # aggregate "approval workflows appear properly configured" row
            # cannot be emitted alongside an attribution failure below.
            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-22",
                        finding_name=f"Model Approval Workflow - {issue['type']}",
                        finding_details=issue["details"],
                        resolution="Configure proper model approval workflows using SageMaker Model Registry. Require manual approval or automated validation before models are approved for production.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html",
                        severity=issue["severity"],
                        status="Failed",
                        region=region,
                    )
                )
        elif not unread:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-22",
                    finding_name="Model Approval Workflow Check",
                    # AIR-SGM-GOV-01: the counts below are all this branch
                    # established; they do not show approval is enforced.
                    finding_details=(
                        f"Checked {groups_checked} model package group(s): none "
                        "with more than 3 versions has every version Approved, "
                        "none has more than 5 versions pending approval, and each "
                        f"of the {approval_versions_examined} Approved version(s) "
                        "records an approver. Whether a version can be approved "
                        "or deployed without review is not established by these "
                        "counts."
                    ),
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        findings["csv_data"].extend(
            _approval_attribution_findings(
                approvals_with_approver,
                approvals_without_approver,
                approval_versions_examined,
                region,
            )
        )
        if approval_versions_examined:
            findings["csv_data"].append(
                _lifecycle_finding(
                    unstaged_versions, approval_versions_examined, region
                )
            )
        findings["csv_data"].extend(
            _deployed_model_registration_findings(sagemaker_client, region)
        )
        if groups_checked:
            findings["csv_data"].append(
                _registry_sharing_finding(sharing, groups_checked, region)
            )
        if unread:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-22",
                    "Model Approval Workflow Check",
                    unread,
                    f"{groups_checked} model package group(s) and "
                    f"{approval_versions_examined} approved version(s) were read.",
                    MODEL_APPROVAL_REFERENCE,
                    region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_model_approval_workflow: {str(e)}", exc_info=True)
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-22",
                    finding_name="Model Approval Workflow Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


MONITOR_REPORT_FINDING = "Model Monitor Recent Report"
MONITOR_ALARM_FINDING = "Model Monitor Violation Alarm"
MONITOR_BASELINE_FINDING = "Model Monitor Baseline Constraints"
MODEL_MONITOR_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html"
)
MONITOR_CLOUDWATCH_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/"
    "model-monitor-interpreting-cloudwatch.html"
)
# Namespaces Model Monitor publishes schedule metrics to, one per monitoring type.
# The AWS data quality page names /aws/sagemaker/Endpoints/data-metric with
# EndpointName and ScheduleName dimensions, the bring-your-own-container page
# names /aws/sagemaker/Endpoint/data-metrics, and the other monitoring pages name
# aws/sagemaker/Endpoints/*-metrics with Endpoint and MonitoringSchedule, so all
# three spellings are credited.
MODEL_MONITOR_METRIC_NAMESPACES = (
    "/aws/sagemaker/Endpoints/data-metric",
    "/aws/sagemaker/Endpoint/data-metrics",
    "aws/sagemaker/Endpoints/data-metrics",
    "aws/sagemaker/Endpoints/model-metrics",
    "aws/sagemaker/Endpoints/bias-metrics",
    "aws/sagemaker/Endpoints/explainability-metrics",
)
# The namespaces each monitoring type publishes to, from the list above.
MODEL_MONITOR_TYPE_NAMESPACES = {
    "DataQuality": MODEL_MONITOR_METRIC_NAMESPACES[:3],
    "ModelQuality": ("aws/sagemaker/Endpoints/model-metrics",),
    "ModelBias": ("aws/sagemaker/Endpoints/bias-metrics",),
    "ModelExplainability": ("aws/sagemaker/Endpoints/explainability-metrics",),
}
# Both dimension spellings the Model Monitor pages document, as (endpoint,
# schedule). A metric is stored under its exact dimension set, so an alarm
# naming only one of the pair reads a series Model Monitor never publishes.
MODEL_MONITOR_DIMENSION_PAIRS = (
    ("Endpoint", "MonitoringSchedule"),
    ("EndpointName", "ScheduleName"),
)
# Data quality publishes each feature's distance from its baseline under this
# prefix. The distance lies between 0 and 1, so a rising alarm at or above 1
# never fires.
DATA_QUALITY_DRIFT_METRIC_PREFIX = "feature_baseline_drift_"
MONITOR_REPORT_STATUSES = ("Completed", "CompletedWithViolations")
MONITOR_RUNNING_STATUSES = ("Pending", "InProgress")
CAPTURE_DISK_ALARM_FINDING = "Data Capture Disk Utilization Alarm"
CAPTURE_DISK_ALARM_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/"
    "model-monitor-data-capture-endpoint.html"
)
# Data Capture stops capturing at high disk usage; AWS recommends keeping
# utilization below 75%, so an alarm must fire at or below that level.
CAPTURE_DISK_ALARM_MAX_THRESHOLD = 75.0
ENDPOINT_METRIC_NAMESPACE = "/aws/sagemaker/Endpoints"
RISING_COMPARISONS = ("GreaterThanThreshold", "GreaterThanOrEqualToThreshold")


def _actionable_metric_alarms(region: str) -> List[Dict[str, Any]]:
    """Every metric alarm in the region that is enabled and has an alarm action."""
    cloudwatch_client = boto3.client(
        "cloudwatch", config=boto3_config, region_name=region
    )
    alarms = []
    for page in cloudwatch_client.get_paginator("describe_alarms").paginate(
        AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm.get("ActionsEnabled") and alarm.get("AlarmActions"):
                alarms.append(alarm)
    return alarms


def _alarm_metric_dimensions(alarm: Dict[str, Any]) -> List[tuple]:
    """Every (namespace, metric name, dimensions) a metric alarm evaluates."""
    metrics = []
    if alarm.get("MetricName"):
        metrics.append(
            (
                alarm.get("Namespace"),
                alarm.get("MetricName"),
                {d.get("Name"): d.get("Value") for d in alarm.get("Dimensions") or []},
            )
        )
    for query in alarm.get("Metrics") or []:
        metric = (query.get("MetricStat") or {}).get("Metric") or {}
        if metric.get("MetricName"):
            metrics.append(
                (
                    metric.get("Namespace"),
                    metric.get("MetricName"),
                    {
                        d.get("Name"): d.get("Value")
                        for d in metric.get("Dimensions") or []
                    },
                )
            )
    return metrics


def _schedule_cadence(expression: str) -> timedelta:
    """The interval a Model Monitor cron expression runs at."""
    match = re.match(r"cron\((\S+) (\S+) ", expression or "")
    if not match:
        return timedelta(days=7)
    hours = match.group(2)
    if hours == "*":
        return timedelta(hours=1)
    step = re.fullmatch(r"(?:\*|\d+)/(\d+)", hours)
    if step:
        return timedelta(hours=int(step.group(1)))
    return timedelta(days=1)


# The describe that returns each monitoring type's {type}BaselineConfig.
MONITORING_JOB_DEFINITION_DESCRIBES = {
    "DataQuality": "describe_data_quality_job_definition",
    "ModelQuality": "describe_model_quality_job_definition",
    "ModelBias": "describe_model_bias_job_definition",
    "ModelExplainability": "describe_model_explainability_job_definition",
}


def _schedule_baseline_constraints(
    sagemaker_client: Any, name: str, detail: Dict[str, Any]
) -> tuple:
    """
    Where a described monitoring schedule's baseline constraints file is.

    Returns ("baselined", uri), ("missing", text) when the job definition
    names no constraints file, or ("unread", text) when that was not read.
    A named job definition is read with the describe of its monitoring type.
    """
    config = detail.get("MonitoringScheduleConfig") or {}
    if "MonitoringJobDefinition" in config:
        baseline = (config.get("MonitoringJobDefinition") or {}).get(
            "BaselineConfig"
        ) or {}
        where = "its inline job definition"
    elif config.get("MonitoringJobDefinitionName"):
        definition = config["MonitoringJobDefinitionName"]
        kind = config.get("MonitoringType") or detail.get("MonitoringType")
        if kind not in MONITORING_JOB_DEFINITION_DESCRIBES:
            return "unread", (
                f"schedule '{name}': its {kind or 'untyped'} job definition "
                f"'{definition}' was not read: no describe is known for that type"
            )
        method = MONITORING_JOB_DEFINITION_DESCRIBES[kind]
        try:
            baseline = (
                getattr(sagemaker_client, method)(JobDefinitionName=definition).get(
                    f"{kind}BaselineConfig"
                )
                or {}
            )
        except Exception as error:
            return "unread", (
                f"sagemaker:Describe{kind}JobDefinition {definition} of "
                f"schedule '{name}' ({get_assessment_error_label(error)})"
            )
        where = f"its job definition '{definition}'"
    else:
        return "unread", f"schedule '{name}' names no job definition"
    uri = (baseline.get("ConstraintsResource") or {}).get("S3Uri")
    if uri:
        return "baselined", uri
    if baseline.get("BaseliningJobName"):
        # Whether monitoring falls back to the baselining job's output for its
        # constraints is not established, so this is neither pass nor fail.
        return "unread", (
            f"schedule '{name}': {where} names baselining job "
            f"'{baseline['BaseliningJobName']}' but no constraints file"
        )
    return "missing", f"schedule '{name}': {where} names no baseline constraints file"


def _latest_finished_monitoring_execution(
    sagemaker_client: Any, schedule_name: str
) -> Dict[str, Any]:
    """The newest execution of a schedule that is not Pending or InProgress."""
    for page in sagemaker_client.get_paginator("list_monitoring_executions").paginate(
        MonitoringScheduleName=schedule_name,
        SortBy="ScheduledTime",
        SortOrder="Descending",
    ):
        for execution in page.get("MonitoringExecutionSummaries", []):
            if execution.get("MonitoringExecutionStatus") not in (
                MONITOR_RUNNING_STATUSES
            ):
                return execution
    return {}


def _monitor_report_and_alarm_findings(
    sagemaker_client: Any, schedules: List[Dict[str, Any]], region: str
) -> List[Dict[str, Any]]:
    """
    For each monitoring schedule on an InService endpoint, require a baseline
    constraints file, a report produced within two cadences, and an alarm with
    an action on its metrics.
    """
    rows = []
    now = datetime.now(timezone.utc)
    stale = []
    fresh = []
    unread = []
    unbaselined = []
    baselined = []
    baseline_unread = []
    for schedule in schedules:
        name = schedule["name"]
        try:
            detail = sagemaker_client.describe_monitoring_schedule(
                MonitoringScheduleName=name
            )
        except Exception as error:
            unread.append(
                f"sagemaker:DescribeMonitoringSchedule {name} "
                f"({get_assessment_error_label(error)})"
            )
            baseline_unread.append(unread[-1])
            continue
        state, text = _schedule_baseline_constraints(sagemaker_client, name, detail)
        if state == "baselined":
            baselined.append(f"{name} ({text})")
        elif state == "missing":
            unbaselined.append(text)
        else:
            baseline_unread.append(text)
        expression = (
            (detail.get("MonitoringScheduleConfig") or {}).get("ScheduleConfig") or {}
        ).get("ScheduleExpression") or ""
        max_age = 2 * _schedule_cadence(expression) + timedelta(hours=1)
        last = detail.get("LastMonitoringExecutionSummary") or {}
        status = last.get("MonitoringExecutionStatus")
        running = None
        if status in MONITOR_RUNNING_STATUSES:
            # AIR-SGM-EP-06: DescribeMonitoringSchedule returns only the running
            # execution, so the newest finished one is listed.
            running = status
            try:
                last = _latest_finished_monitoring_execution(sagemaker_client, name)
            except Exception as error:
                unread.append(
                    f"schedule '{name}': its latest execution is {status}, and "
                    "the execution before it was not read "
                    f"(sagemaker:ListMonitoringExecutions: "
                    f"{get_assessment_error_label(error)})"
                )
                continue
            status = last.get("MonitoringExecutionStatus")
        scheduled = last.get("ScheduledTime")
        if isinstance(scheduled, datetime) and scheduled.tzinfo is None:
            scheduled = scheduled.replace(tzinfo=timezone.utc)
        if not last and running:
            stale.append(
                f"schedule '{name}': its latest execution is {running}, and no "
                "execution before it has finished"
            )
        elif not last:
            stale.append(f"schedule '{name}' has never run")
        elif status not in MONITOR_REPORT_STATUSES:
            reason = last.get("FailureReason")
            stale.append(
                f"schedule '{name}': its latest "
                f"{'finished ' if running else ''}execution is "
                f"{status or 'without a status'}"
                + (f" ({reason[:120]})" if reason else "")
            )
        elif not isinstance(scheduled, datetime) or now - scheduled > max_age:
            stale.append(
                f"schedule '{name}': its latest report was scheduled "
                f"{scheduled.isoformat() if isinstance(scheduled, datetime) else 'at an unreported time'}, "
                f"older than twice its cadence ({expression or 'no expression'})"
            )
        else:
            fresh.append(f"{name} ({status} at {scheduled.isoformat()})")
    for problem in unbaselined[:20]:
        rows.append(
            create_finding(
                check_id="SM-23",
                finding_name=MONITOR_BASELINE_FINDING,
                finding_details=(
                    f"Monitoring {problem}, so its reports have no baseline "
                    "constraints to be validated against and cannot record a "
                    "violation."
                ),
                resolution=(
                    "Run a baselining job on the training data and set its "
                    "constraints.json as the schedule's baseline ConstraintsResource."
                ),
                reference=MODEL_MONITOR_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if baselined and not unbaselined and not baseline_unread:
        rows.append(
            create_finding(
                check_id="SM-23",
                finding_name=MONITOR_BASELINE_FINDING,
                finding_details=(
                    f"All {len(baselined)} monitoring schedule(s) name a baseline "
                    f"constraints file: {', '.join(baselined[:5])}."
                ),
                resolution="No action required",
                reference=MODEL_MONITOR_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    if baseline_unread:
        rows.append(
            _unread_resources_finding(
                "SM-23",
                MONITOR_BASELINE_FINDING,
                baseline_unread,
                f"{len(baselined) + len(unbaselined)} of {len(schedules)} "
                "schedule(s) had their baseline read.",
                MODEL_MONITOR_REFERENCE,
                region,
            )
        )
    for problem in stale[:20]:
        rows.append(
            create_finding(
                check_id="SM-23",
                finding_name=MONITOR_REPORT_FINDING,
                finding_details=f"Monitoring {problem}, so no current drift report exists.",
                resolution=(
                    "Fix the failing monitoring job (baseline, role, capture input) "
                    "so each schedule produces a report every cycle."
                ),
                reference=MODEL_MONITOR_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if fresh and not stale and not unread:
        rows.append(
            create_finding(
                check_id="SM-23",
                finding_name=MONITOR_REPORT_FINDING,
                finding_details=(
                    f"All {len(fresh)} monitoring schedule(s) produced a report "
                    f"within twice their cadence: {', '.join(fresh[:5])}."
                ),
                resolution="No action required",
                reference=MODEL_MONITOR_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-23",
                MONITOR_REPORT_FINDING,
                unread,
                f"{len(fresh) + len(stale)} of {len(schedules)} schedule(s) were read.",
                MODEL_MONITOR_REFERENCE,
                region,
            )
        )

    try:
        alarms = _actionable_metric_alarms(region)
    except Exception as error:
        rows.append(
            _unread_resources_finding(
                "SM-23",
                MONITOR_ALARM_FINDING,
                [f"cloudwatch:DescribeAlarms ({get_assessment_error_label(error)})"],
                f"{len(schedules)} monitoring schedule(s) were found.",
                MONITOR_CLOUDWATCH_REFERENCE,
                region,
            )
        )
        return rows
    # AIR-SGM-EP-06: an alarm credits a schedule only on the namespace of the
    # schedule's own monitoring type and on that schedule's exact dimension
    # pair, so a DataQuality alarm never stands in for ModelQuality. A
    # DataQuality alarm must also read a drift metric with a threshold the
    # distance can cross.
    alarmed = set()
    for alarm in alarms:
        single = bool(alarm.get("MetricName"))
        operator = alarm.get("ComparisonOperator")
        threshold = alarm.get("Threshold")
        for namespace, metric_name, dimensions in _alarm_metric_dimensions(alarm):
            for kind, namespaces in MODEL_MONITOR_TYPE_NAMESPACES.items():
                if namespace not in namespaces:
                    continue
                if kind == "DataQuality" and (
                    not str(metric_name).startswith(DATA_QUALITY_DRIFT_METRIC_PREFIX)
                    or (
                        single
                        and (
                            operator not in RISING_COMPARISONS
                            or not isinstance(threshold, (int, float))
                            or threshold >= 1
                        )
                    )
                ):
                    continue
                for endpoint_key, schedule_key in MODEL_MONITOR_DIMENSION_PAIRS:
                    if set(dimensions) == {endpoint_key, schedule_key}:
                        alarmed.add(
                            (kind, dimensions[endpoint_key], dimensions[schedule_key])
                        )
    unalarmed = [
        schedule
        for schedule in schedules
        if (schedule.get("type"), schedule["endpoint"], schedule["name"]) not in alarmed
    ]
    for schedule in unalarmed[:20]:
        rows.append(
            create_finding(
                check_id="SM-23",
                finding_name=MONITOR_ALARM_FINDING,
                finding_details=(
                    "No enabled CloudWatch alarm with an action evaluates a "
                    f"{schedule.get('type') or 'Model Monitor'} metric of schedule "
                    f"'{schedule['name']}' on endpoint '{schedule['endpoint']}' "
                    "under that schedule's namespace and both its endpoint and "
                    "schedule dimensions"
                    + (
                        ", reading a feature_baseline_drift_ metric with a rising "
                        "threshold below 1"
                        if schedule.get("type") == "DataQuality"
                        else ""
                    )
                    + ", so a violation in its report notifies no one."
                ),
                resolution=(
                    "Publish the schedule's metrics to CloudWatch and alarm on the "
                    "drift metrics in the aws/sagemaker/Endpoints/*-metrics "
                    "namespaces with an action that notifies the model owner."
                ),
                reference=MONITOR_CLOUDWATCH_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if schedules and not unalarmed:
        rows.append(
            create_finding(
                check_id="SM-23",
                finding_name=MONITOR_ALARM_FINDING,
                finding_details=(
                    f"All {len(schedules)} monitoring schedule(s) have an enabled "
                    "alarm with an action on a metric of their own monitoring "
                    "type, endpoint and schedule. A DataQuality alarm reads a "
                    "feature_baseline_drift_ metric, and a single-metric one "
                    "rises past a threshold below 1. For ModelQuality, ModelBias "
                    "and ModelExplainability schedules, and for metric math, which "
                    "metric the alarm evaluates and whether its threshold marks a "
                    "violation are not judged."
                ),
                resolution="No action required",
                reference=MONITOR_CLOUDWATCH_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return rows


def check_model_drift_detection(region: str = "") -> Dict[str, Any]:
    """
    Check if Model Monitor is configured for drift detection with proper baselines.
    Validates that models have data quality and model quality monitoring configured.
    """
    # FinServ extension (FS-18): In addition to ModelQuality drift monitoring, the
    # FinServ guide (PDF §1.2.14) calls out low-entropy classification monitoring
    # as an early-warning indicator of training-data poisoning. See
    # docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md (FS-18 → SM-23
    # extension note) for the remediation step to add.
    logger.debug("Starting check for model drift detection")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        endpoints_without_monitoring = []
        endpoints_with_monitoring = []
        monitoring_issues = []
        monitored_schedules = []
        read_error = None

        try:
            # Get all InService endpoints
            paginator = sagemaker_client.get_paginator("list_endpoints")
            endpoints = []

            for page in paginator.paginate():
                for endpoint in page.get("Endpoints", []):
                    if endpoint.get("EndpointStatus") == "InService":
                        endpoints.append(endpoint.get("EndpointName"))

            # Get all monitoring schedules
            monitoring_schedules = {}
            schedule_paginator = sagemaker_client.get_paginator(
                "list_monitoring_schedules"
            )

            for page in schedule_paginator.paginate():
                for schedule in page.get("MonitoringScheduleSummaries", []):
                    endpoint_name = schedule.get("EndpointName")
                    if endpoint_name:
                        if endpoint_name not in monitoring_schedules:
                            monitoring_schedules[endpoint_name] = []
                        monitoring_schedules[endpoint_name].append(
                            {
                                "name": schedule.get("MonitoringScheduleName"),
                                "type": schedule.get("MonitoringType", "Unknown"),
                                "status": schedule.get("MonitoringScheduleStatus"),
                            }
                        )

            # Check each endpoint for monitoring
            for endpoint_name in endpoints:
                if endpoint_name not in monitoring_schedules:
                    endpoints_without_monitoring.append(endpoint_name)
                else:
                    schedules = monitoring_schedules[endpoint_name]
                    endpoints_with_monitoring.append(endpoint_name)
                    monitored_schedules.extend(
                        {
                            "name": s["name"],
                            "endpoint": endpoint_name,
                            "type": s["type"],
                        }
                        for s in schedules
                        if s["status"] == "Scheduled"
                    )

                    # Check for comprehensive monitoring
                    monitoring_types = [s["type"] for s in schedules]

                    # Check if data quality monitoring is configured
                    if "DataQuality" not in monitoring_types:
                        monitoring_issues.append(
                            {
                                "endpoint": endpoint_name,
                                "issue": "Missing Data Quality Monitoring",
                                "details": f"Endpoint '{endpoint_name}' does not have data quality monitoring configured.",
                            }
                        )

                    # Check if model quality monitoring is configured
                    if "ModelQuality" not in monitoring_types:
                        monitoring_issues.append(
                            {
                                "endpoint": endpoint_name,
                                "issue": "Missing Model Quality Monitoring",
                                "details": f"Endpoint '{endpoint_name}' does not have model quality monitoring configured.",
                            }
                        )

                    # Check for inactive schedules
                    for schedule in schedules:
                        if schedule["status"] != "Scheduled":
                            monitoring_issues.append(
                                {
                                    "endpoint": endpoint_name,
                                    "issue": "Inactive Monitoring Schedule",
                                    "details": f"Monitoring schedule '{schedule['name']}' for endpoint '{endpoint_name}' is {schedule['status']}, not actively scheduled.",
                                }
                            )

        except Exception as e:
            logger.error(f"Error checking model drift detection: {str(e)}")
            read_error = get_assessment_error_label(e)

        if read_error:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-23",
                    "Model Drift Detection Check",
                    [
                        "sagemaker:ListEndpoints or ListMonitoringSchedules "
                        f"({read_error})"
                    ],
                    "the endpoint and schedule lists were not read in full.",
                    MODEL_MONITOR_REFERENCE,
                    region,
                )
            )
            return findings

        # Generate findings
        if endpoints_without_monitoring:
            for endpoint in endpoints_without_monitoring[:10]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name="Model Drift Detection Not Configured",
                        finding_details=(
                            f"Endpoint '{endpoint}' has no Model Monitor schedules "
                            "configured. Model drift and data quality issues will not "
                            "be detected by SageMaker. An open-source SageMaker AI "
                            "MLflow App with Evidently AI reports is not linked to an "
                            "endpoint by any SageMaker API, so that replacement path "
                            "is not read."
                        ),
                        resolution="Configure Model Monitor with data quality, model quality, bias, and feature attribution drift monitoring for production endpoints.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(endpoints_without_monitoring) > 10:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name="Model Drift Detection Summary",
                        finding_details=f"Found {len(endpoints_without_monitoring)} total endpoints without drift detection (showing first 10)",
                        resolution="Configure Model Monitor for all production endpoints",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

        if monitoring_issues:
            for issue in monitoring_issues[:10]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name=f"Model Drift Detection - {issue['issue']}",
                        finding_details=issue["details"],
                        resolution="Configure comprehensive monitoring including data quality, model quality, bias drift, and feature attribution drift monitoring.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Low",
                        status="Failed",
                        region=region,
                    )
                )

        if not endpoints_without_monitoring and not monitoring_issues:
            if endpoints_with_monitoring:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name="Model Drift Detection Check",
                        finding_details=f"All {len(endpoints_with_monitoring)} InService endpoints have drift detection monitoring configured.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name="Model Drift Detection Check",
                        finding_details="No InService endpoints found to monitor.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        if monitored_schedules:
            findings["csv_data"].extend(
                _monitor_report_and_alarm_findings(
                    sagemaker_client, monitored_schedules, region
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_model_drift_detection: {str(e)}", exc_info=True)
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-23",
                    finding_name="Model Drift Detection Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_ab_testing_shadow_deployment(region: str = "") -> Dict[str, Any]:
    """
    Check if endpoints are configured with proper A/B testing or shadow deployment patterns.
    Validates production variant configurations for safe model deployment.
    """
    logger.debug("Starting check for A/B testing and shadow deployment patterns")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        single_variant_endpoints = []
        multi_variant_endpoints = []
        shadow_endpoints = []

        try:
            paginator = sagemaker_client.get_paginator("list_endpoints")
            for page in paginator.paginate():
                for endpoint in page.get("Endpoints", []):
                    endpoint_name = endpoint.get("EndpointName")
                    endpoint_status = endpoint.get("EndpointStatus")

                    if endpoint_name and endpoint_status == "InService":
                        try:
                            endpoint_details = sagemaker_client.describe_endpoint(
                                EndpointName=endpoint_name
                            )

                            production_variants = endpoint_details.get(
                                "ProductionVariants", []
                            )
                            shadow_variants = endpoint_details.get(
                                "ShadowProductionVariants", []
                            )

                            if shadow_variants:
                                shadow_endpoints.append(
                                    {
                                        "name": endpoint_name,
                                        "shadow_variants": len(shadow_variants),
                                        "production_variants": len(production_variants),
                                    }
                                )
                            elif len(production_variants) > 1:
                                # Check if it's A/B testing (multiple variants with traffic split)
                                variant_weights = [
                                    v.get("CurrentWeight", 0)
                                    for v in production_variants
                                ]
                                if all(w > 0 for w in variant_weights):
                                    multi_variant_endpoints.append(
                                        {
                                            "name": endpoint_name,
                                            "variants": len(production_variants),
                                            "weights": variant_weights,
                                        }
                                    )
                                else:
                                    single_variant_endpoints.append(endpoint_name)
                            else:
                                single_variant_endpoints.append(endpoint_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing endpoint {endpoint_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing endpoints: {str(e)}")

        # Generate findings - this is informational, not a failure
        total_endpoints = (
            len(single_variant_endpoints)
            + len(multi_variant_endpoints)
            + len(shadow_endpoints)
        )

        if total_endpoints == 0:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-24",
                    finding_name="A/B Testing and Shadow Deployment Check",
                    finding_details="No InService endpoints found.",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                    severity="Low",
                    status="Passed",
                    region=region,
                )
            )
        else:
            # Report on shadow deployments (best practice)
            if shadow_endpoints:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="Shadow Deployment Pattern Detected",
                        finding_details=f"Found {len(shadow_endpoints)} endpoint(s) using shadow deployment pattern for safe model validation. This is a recommended practice for production deployments.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-shadow-deployment.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

            # Report on A/B testing
            if multi_variant_endpoints:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="A/B Testing Pattern Detected",
                        finding_details=f"Found {len(multi_variant_endpoints)} endpoint(s) using A/B testing with multiple production variants. This enables gradual rollout and comparison of model versions.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

            # Report on single variant endpoints - informational, not necessarily bad
            if single_variant_endpoints and len(single_variant_endpoints) > 5:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="Single Variant Endpoints",
                        finding_details=f"Found {len(single_variant_endpoints)} endpoint(s) with single production variants. Consider using A/B testing or shadow deployments for safer model updates in production.",
                        resolution="For production-critical endpoints, consider implementing A/B testing (multiple production variants) or shadow deployments to validate new model versions before full deployment.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
            elif not shadow_endpoints and not multi_variant_endpoints:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="Safe Deployment Patterns Check",
                        finding_details=f"Found {len(single_variant_endpoints)} endpoint(s) without A/B testing or shadow deployment patterns configured.",
                        resolution="Consider implementing A/B testing or shadow deployments for production endpoints to enable safe model updates.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="Safe Deployment Patterns Check",
                        finding_details=f"Safe deployment patterns are being utilized. {len(shadow_endpoints)} shadow deployments, {len(multi_variant_endpoints)} A/B tests configured.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_ab_testing_shadow_deployment: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-24",
                    finding_name="A/B Testing Shadow Deployment Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_ml_lineage_tracking(region: str = "") -> Dict[str, Any]:
    """
    Check if ML Lineage Tracking is being used to track model artifacts and experiments.
    Validates that experiments, trials, and artifact associations are configured.
    """
    logger.debug("Starting check for ML Lineage Tracking")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        experiments_found = False
        trials_found = False
        lineage_issues = []
        lineage_assessment_error = None

        try:
            # Check for Experiments
            try:
                experiments_response = sagemaker_client.list_experiments(MaxResults=10)
                experiments = experiments_response.get("ExperimentSummaries", [])
                experiments_found = len(experiments) > 0

                if experiments_found:
                    # Check trial status for recent experiments
                    for experiment in experiments[:5]:
                        experiment_name = experiment.get("ExperimentName")
                        try:
                            trials_response = sagemaker_client.list_trials(
                                ExperimentName=experiment_name, MaxResults=10
                            )
                            trials = trials_response.get("TrialSummaries", [])
                            if trials:
                                trials_found = True
                        except Exception as e:
                            logger.warning(
                                f"Error listing trials for experiment {experiment_name}: {str(e)}"
                            )

            except Exception as e:
                logger.warning(f"Error listing experiments: {str(e)}")

            # Check for Model Package lineage
            try:
                model_packages_paginator = sagemaker_client.get_paginator(
                    "list_model_package_groups"
                )
                stop_lineage_scan = False
                for page in model_packages_paginator.paginate(MaxResults=10):
                    for group in page.get("ModelPackageGroupSummaryList", []):
                        if stop_lineage_scan:
                            break
                        group_name = group.get("ModelPackageGroupName")
                        try:
                            for model_pkg in iter_model_packages(
                                sagemaker_client, group_name
                            ):
                                if len(lineage_issues) >= MAX_LINEAGE_FINDINGS:
                                    stop_lineage_scan = True
                                    break

                                model_arn = model_pkg.get("ModelPackageArn")
                                if not model_arn:
                                    continue

                                try:
                                    artifact_arn = (
                                        get_model_package_lineage_artifact_arn(
                                            sagemaker_client, model_arn
                                        )
                                    )
                                    if not artifact_arn or not has_lineage_associations(
                                        sagemaker_client, artifact_arn
                                    ):
                                        lineage_issues.append(
                                            {
                                                "type": "Missing Lineage",
                                                "resource": model_pkg.get(
                                                    "ModelPackageName", model_arn
                                                ),
                                                "details": "Model package has no lineage associations. Training data and experiment lineage not tracked.",
                                            }
                                        )
                                        if len(lineage_issues) >= MAX_LINEAGE_FINDINGS:
                                            stop_lineage_scan = True
                                            break
                                except Exception as e:
                                    logger.warning(
                                        "Error checking lineage for model package "
                                        f"{model_arn}: {str(e)}"
                                    )
                                    if lineage_assessment_error is None:
                                        lineage_assessment_error = e
                                    if (
                                        isinstance(e, ClientError)
                                        and e.response.get("Error", {}).get("Code")
                                        in ACCESS_DENIED_ERROR_CODES
                                    ):
                                        stop_lineage_scan = True
                                        break
                        except Exception as e:
                            logger.warning(
                                f"Error checking model packages in group {group_name}: {str(e)}"
                            )
                            if lineage_assessment_error is None:
                                lineage_assessment_error = e
                    if stop_lineage_scan:
                        break
            except Exception as e:
                logger.warning(f"Error checking model package lineage: {str(e)}")
                if lineage_assessment_error is None:
                    lineage_assessment_error = e

        except Exception as e:
            logger.error(f"Error in lineage tracking check: {str(e)}")

        # Generate findings
        if not experiments_found:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-25",
                    finding_name="ML Lineage Tracking - Experiments Not Used",
                    finding_details="No SageMaker Experiments found. ML Lineage tracking through Experiments is not being utilized.",
                    resolution="Implement SageMaker Experiments to track ML training runs, hyperparameters, metrics, and model artifacts. This enables reproducibility and auditability.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/experiments.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
        elif not trials_found:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-25",
                    finding_name="ML Lineage Tracking - No Active Trials",
                    finding_details="SageMaker Experiments exist but no trials found. Experiments may not be actively used for tracking training runs.",
                    resolution="Create trials within experiments to track individual training runs, their parameters, and results.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/experiments.html",
                    severity="Low",
                    status="Failed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-25",
                    finding_name="ML Lineage Tracking - Experiments Active",
                    finding_details="SageMaker Experiments and Trials are being used for ML lineage tracking.",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/experiments.html",
                    severity="Low",
                    status="Passed",
                    region=region,
                )
            )

        # Add lineage issues if found
        for issue in lineage_issues:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-25",
                    finding_name=f"ML Lineage Tracking - {issue['type']}",
                    finding_details=issue["details"],
                    resolution="Configure lineage associations for model packages to track the full ML pipeline from data to deployed model.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/lineage-tracking.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        if lineage_assessment_error is not None:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-25",
                    finding_name="ML Lineage Tracking - Model Package Assessment",
                    finding_details=build_could_not_assess_detail(
                        lineage_assessment_error, region
                    ),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/lineage-tracking.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_ml_lineage_tracking: {str(e)}", exc_info=True)
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-25",
                    finding_name="ML Lineage Tracking Check",
                    finding_details=build_could_not_assess_detail(e, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_model_registry_usage(
    permission_cache,
    region: str = "",
    model_package_groups: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Check if Amazon Model Registry is being used effectively for model management
    """
    logger.debug("Starting check for Model Registry usage")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        issues_found = []

        try:
            registry_used = False
            groups = (
                model_package_groups
                if model_package_groups is not None
                else list_model_package_group_summaries(sagemaker_client)
            )

            for group in groups:
                registry_used = True
                group_name = group["ModelPackageGroupName"]

                # Check model versions in the group
                try:
                    models = list_all_model_packages(sagemaker_client, group_name)

                    if not models:
                        issues_found.append(
                            {
                                "issue_type": "Empty Model Group",
                                "details": f"Model group {group_name} has no registered models",
                                "severity": "Low",
                                "status": "Failed",
                            }
                        )
                    else:
                        approved_models = [
                            m
                            for m in models
                            if m.get("ModelApprovalStatus") == "Approved"
                        ]
                        if not approved_models:
                            issues_found.append(
                                {
                                    "issue_type": "No Approved Models",
                                    "details": f"Model group {group_name} has no approved models",
                                    "severity": "Low",
                                    "status": "Failed",
                                }
                            )

                except Exception as e:
                    logger.error(
                        f"Error checking models in group {group_name}: {str(e)}"
                    )
                    issues_found.append(
                        {
                            "issue_type": "Model Check Error",
                            "details": f"Error checking models in group {group_name}",
                            "severity": "Medium",
                            "status": "Failed",
                        }
                    )

            if not registry_used:
                issues_found.append(
                    {
                        "issue_type": "Registry Not Used",
                        "details": "Model Registry is not being utilized",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )

        except Exception as e:
            logger.error(f"Error checking Model Registry: {str(e)}")
            issues_found.append(
                {
                    "issue_type": "Registry Check Error",
                    "details": f"Error checking Model Registry configuration: {str(e)}",
                    "severity": "High",
                    "status": "Failed",
                }
            )

        if issues_found:
            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-08",
                        finding_name=f"Model Registry {issue['issue_type']}",
                        finding_details=issue["details"],
                        resolution="Implement proper model versioning and approval workflows",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html",
                        severity=issue["severity"],
                        status=issue["status"],
                        region=region,
                    )
                )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-08",
                    finding_name="Model Registry Usage Check",
                    finding_details="Model Registry is being used effectively",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_model_registry_usage: {str(e)}", exc_info=True)
        return {
            "check_name": "Model Registry Usage Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
        }


def check_hyperpod_ebs_cmk_encryption(
    region: str = "", cluster_inventory: Dict[str, Any] = None
) -> Dict[str, Any]:
    """SM-27: Require CMK encryption for HyperPod root and secondary EBS volumes."""
    findings = {"csv_data": []}
    inventory = cluster_inventory or get_hyperpod_cluster_inventory(region)
    if inventory.get("list_error"):
        error = inventory["list_error"]
        findings["csv_data"].append(
            create_finding(
                check_id="SM-27",
                finding_name="HyperPod EBS CMK Encryption",
                finding_details=build_could_not_assess_detail(error, region),
                resolution=COULD_NOT_ASSESS_RESOLUTION,
                reference="https://aws.amazon.com/about-aws/whats-new/2025/08/sagemaker-hyperpod-customer-managed-kms-ebs-volumes/",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
        return findings

    if not inventory.get("items") and not inventory.get("errors"):
        findings["csv_data"].append(
            create_finding(
                check_id="SM-27",
                finding_name="HyperPod EBS CMK Encryption",
                finding_details="No SageMaker HyperPod clusters found",
                resolution="No action required",
                reference="https://aws.amazon.com/about-aws/whats-new/2025/08/sagemaker-hyperpod-customer-managed-kms-ebs-volumes/",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
        return findings

    groups = []
    for item in inventory.get("items", []):
        detail = item["detail"]
        cluster_name = detail.get(
            "ClusterName", item["summary"].get("ClusterName", "unknown")
        )
        for group in detail.get("InstanceGroups", []):
            group_name = group.get("InstanceGroupName", "unknown")
            ebs_configs = [
                config.get("EbsVolumeConfig") or {}
                for config in group.get("InstanceStorageConfigs", [])
                if config.get("EbsVolumeConfig") is not None
            ]
            root_configs = [
                config for config in ebs_configs if config.get("RootVolume") is True
            ]
            volumes = [("root volume", config) for config in root_configs] + [
                ("secondary volume", config)
                for config in ebs_configs
                if config.get("RootVolume") is not True
            ]
            groups.append((cluster_name, group_name, bool(root_configs), volumes))

    # A VolumeKmsKeyId can name an AWS managed key, so each key is resolved
    # with kms:DescribeKey before a volume is credited as customer managed.
    managers = _kms_key_managers(
        [
            config["VolumeKmsKeyId"]
            for _, _, _, volumes in groups
            for _, config in volumes
            if config.get("VolumeKmsKeyId")
        ],
        region,
    )
    for cluster_name, group_name, has_root, volumes in groups:
        unencrypted = set() if has_root else {"root volume"}
        aws_managed = set()
        unread = set()
        for volume, config in volumes:
            key_id = config.get("VolumeKmsKeyId")
            if not key_id:
                unencrypted.add(volume)
            elif managers[key_id]["manager"] == "AWS":
                aws_managed.add(f"{volume} ({key_id})")
            elif managers[key_id]["manager"] is None:
                unread.add(f"kms:DescribeKey {key_id} ({managers[key_id]['error']})")
        label = f"HyperPod cluster '{cluster_name}' instance group '{group_name}'"
        problems = []
        if unencrypted:
            problems.append(
                "lacks customer-managed KMS encryption for: "
                + ", ".join(sorted(unencrypted))
            )
        if aws_managed:
            problems.append(
                "encrypts with an AWS managed key: " + ", ".join(sorted(aws_managed))
            )
        not_read = f" Not read: {', '.join(sorted(unread))}." if unread else ""
        if problems:
            status = "Failed"
            details = f"{label} {'; '.join(problems)}.{not_read}"
            resolution = (
                "Configure VolumeKmsKeyId with a customer managed key for the root "
                "volume and every secondary EBS volume in the instance group."
            )
            severity = "Medium"
        elif unread:
            status = "N/A"
            details = (
                f"{label} names a VolumeKmsKeyId on every configured EBS volume, "
                f"but who manages the key was not read.{not_read}"
            )
            resolution = "Grant kms:DescribeKey on the volume keys and retry."
            severity = "Informational"
        else:
            status = "Passed"
            details = (
                f"{label} uses customer-managed KMS keys for all configured EBS "
                "volumes, as kms:DescribeKey reports."
            )
            resolution = "No action required"
            severity = "Medium"
        findings["csv_data"].append(
            create_finding(
                check_id="SM-27",
                finding_name="HyperPod EBS CMK Encryption",
                finding_details=details,
                resolution=resolution,
                reference="https://aws.amazon.com/about-aws/whats-new/2025/08/sagemaker-hyperpod-customer-managed-kms-ebs-volumes/",
                severity=severity,
                status=status,
                region=region,
            )
        )

    for item in inventory.get("errors", []):
        findings["csv_data"].append(
            create_finding(
                check_id="SM-27",
                finding_name="HyperPod EBS CMK Encryption",
                finding_details=f"HyperPod cluster '{item['summary'].get('ClusterName', 'unknown')}' could not be assessed: {type(item['error']).__name__}.",
                resolution="Grant sagemaker:DescribeCluster and retry.",
                reference="https://aws.amazon.com/about-aws/whats-new/2025/08/sagemaker-hyperpod-customer-managed-kms-ebs-volumes/",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    return findings


def check_hyperpod_vpc_configuration(
    region: str = "", cluster_inventory: Dict[str, Any] = None
) -> Dict[str, Any]:
    """SM-28: Verify each HyperPod instance group has effective VPC config."""
    findings = {"csv_data": []}
    inventory = cluster_inventory or get_hyperpod_cluster_inventory(region)
    if inventory.get("list_error"):
        findings["csv_data"].append(
            create_finding(
                check_id="SM-28",
                finding_name="HyperPod VPC Configuration",
                finding_details=build_could_not_assess_detail(
                    inventory["list_error"], region
                ),
                resolution=COULD_NOT_ASSESS_RESOLUTION,
                reference="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-hyperpod-security.html",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
        return findings

    if not inventory.get("items") and not inventory.get("errors"):
        findings["csv_data"].append(
            create_finding(
                check_id="SM-28",
                finding_name="HyperPod VPC Configuration",
                finding_details="No SageMaker HyperPod clusters found",
                resolution="No action required",
                reference="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-hyperpod-security.html",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
        return findings

    groups_in_vpc = []
    for item in inventory.get("items", []):
        detail = item["detail"]
        cluster_name = detail.get(
            "ClusterName", item["summary"].get("ClusterName", "unknown")
        )
        cluster_vpc = detail.get("VpcConfig") or {}
        for group in detail.get("InstanceGroups", []):
            group_name = group.get("InstanceGroupName", "unknown")
            effective_vpc = group.get("OverrideVpcConfig") or cluster_vpc
            compliant = bool(effective_vpc.get("Subnets")) and bool(
                effective_vpc.get("SecurityGroupIds")
            )
            if effective_vpc.get("Subnets"):
                groups_in_vpc.append(
                    {
                        "name": (
                            f"HyperPod cluster '{cluster_name}' instance group "
                            f"'{group_name}'"
                        ),
                        "subnets": list(effective_vpc["Subnets"]),
                    }
                )
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-28",
                    finding_name="HyperPod VPC Configuration",
                    finding_details=(
                        f"HyperPod cluster '{cluster_name}' instance group '{group_name}' has effective VPC subnets and security groups."
                        if compliant
                        else f"HyperPod cluster '{cluster_name}' instance group '{group_name}' does not have complete effective VPC configuration."
                    ),
                    resolution=(
                        "No action required"
                        if compliant
                        else "Configure non-empty subnets and security groups at the cluster level or in OverrideVpcConfig."
                    ),
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-hyperpod-security.html",
                    severity="Medium",
                    status="Passed" if compliant else "Failed",
                    region=region,
                )
            )

    for item in inventory.get("errors", []):
        findings["csv_data"].append(
            create_finding(
                check_id="SM-28",
                finding_name="HyperPod VPC Configuration",
                finding_details=f"HyperPod cluster '{item['summary'].get('ClusterName', 'unknown')}' could not be assessed: {type(item['error']).__name__}.",
                resolution="Grant sagemaker:DescribeCluster and retry.",
                reference="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-hyperpod-security.html",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )

    # AIR-FND-NET-01: the subnets above are read from the effective VPC config,
    # which records no route table. One EC2 sweep covers every instance group.
    findings["csv_data"].extend(
        _subnet_exposure_findings(
            check_id="SM-28",
            finding_name="HyperPod Subnet Internet Exposure",
            resources=groups_in_vpc,
            region=region,
            reference="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-hyperpod-security.html",
            resolution=(
                "Point the cluster or the instance group's OverrideVpcConfig at "
                "subnets whose route tables have no internet gateway route, or "
                "remove that route from the subnets' route tables."
            ),
            severity="Medium",
        )
    )
    return findings


def _policy_values(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, dict):
        values = []
        for nested in value.values():
            values.extend(_policy_values(nested))
        return values
    return []


def _policy_condition_boundaries(statement: Dict[str, Any]) -> Dict[str, set]:
    boundaries = {"accounts": set(), "organizations": set()}
    condition = statement.get("Condition") or {}
    null_conditions = condition.get("Null")
    required_condition_keys = set()
    if isinstance(null_conditions, dict):
        for key, value in null_conditions.items():
            if any(item.lower() == "false" for item in _policy_values(value)):
                required_condition_keys.add(key.lower())

    single_value_string_operators = {"StringEquals", "StringLike"}
    principal_arn_operators = {
        "ArnEquals",
        "ArnLike",
        "StringEquals",
        "StringLike",
    }
    org_path_operators = {
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringLike",
    }
    guarded_org_path_operators = {
        "ForAllValues:StringEquals",
        "ForAllValues:StringLike",
    }
    for operator, operator_values in condition.items():
        if not isinstance(operator_values, dict):
            continue
        for key, value in operator_values.items():
            normalized = key.lower()
            values = set(_policy_values(value))
            if (
                normalized == "aws:principalaccount"
                and operator in single_value_string_operators
            ):
                boundaries["accounts"].update(
                    item for item in values if re.fullmatch(r"\d{12}", item)
                )
            elif (
                normalized == "aws:principalorgid"
                and operator in single_value_string_operators
            ):
                boundaries["organizations"].update(
                    item for item in values if re.fullmatch(r"o-[a-z0-9]{10,32}", item)
                )
            elif (
                normalized == "aws:principalarn" and operator in principal_arn_operators
            ):
                for item in values:
                    match = re.fullmatch(r"arn:[^:]+:[^:]*:[^:]*:(\d{12}):.+", item)
                    if match:
                        boundaries["accounts"].add(match.group(1))
            elif normalized == "aws:principalorgpaths":
                operator_is_safe = operator in org_path_operators or (
                    operator in guarded_org_path_operators
                    and normalized in required_condition_keys
                )
                if not operator_is_safe:
                    continue
                for item in values:
                    match = re.match(r"^(o-[a-z0-9]{10,32})/", item)
                    if match:
                        boundaries["organizations"].add(match.group(1))
    return boundaries


def check_model_package_group_policy_exposure(
    region: str = "", model_package_groups: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """SM-30: Heuristically detect public or unapproved registry policies."""
    findings = {"csv_data": []}
    try:
        client = boto3.client("sagemaker", config=boto3_config, region_name=region)
        groups = (
            model_package_groups
            if model_package_groups is not None
            else list_model_package_group_summaries(client)
        )
        if not groups:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-30",
                    finding_name="Model Package Group Resource Policy Exposure",
                    finding_details="No SageMaker model package groups found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_GetModelPackageGroupPolicy.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            return findings

        approved_accounts = {
            item.strip()
            for item in os.environ.get("AIML_APPROVED_EXTERNAL_ACCOUNT_IDS", "").split(
                ","
            )
            if item.strip()
        }
        approved_orgs = {
            item.strip()
            for item in os.environ.get("AIML_APPROVED_ORG_IDS", "").split(",")
            if item.strip()
        }
        trust_boundary_configured = bool(approved_accounts or approved_orgs)
        current_account_error = None
        try:
            current_account = boto3.client(
                "sts", config=boto3_config
            ).get_caller_identity()["Account"]
            if not re.fullmatch(r"\d{12}", current_account):
                raise ValueError("STS returned an invalid account ID")
        except Exception as error:
            current_account = None
            current_account_error = error

        for group in groups:
            group_name = group.get("ModelPackageGroupName", "unknown")
            try:
                response = client.get_model_package_group_policy(
                    ModelPackageGroupName=group_name
                )
            except Exception as error:
                code = (
                    error.response.get("Error", {}).get("Code", "")
                    if isinstance(error, ClientError)
                    else ""
                )
                if code in {
                    "ResourceNotFound",
                    "ResourceNotFoundException",
                    "ValidationException",
                }:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="SM-30",
                            finding_name="Model Package Group Resource Policy Exposure",
                            finding_details=f"Model package group '{group_name}' has no resource policy.",
                            resolution="No action required",
                            reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_GetModelPackageGroupPolicy.html",
                            severity="High",
                            status="Passed",
                            region=region,
                        )
                    )
                    continue
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-30",
                        finding_name="Model Package Group Resource Policy Exposure",
                        finding_details=(
                            f"Model package group '{group_name}' could not be assessed. "
                            f"Assessment error: {get_assessment_error_label(error)}."
                        ),
                        resolution=COULD_NOT_ASSESS_RESOLUTION,
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_GetModelPackageGroupPolicy.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
                continue

            try:
                policy = json.loads(response.get("ResourcePolicy") or "{}")
            except json.JSONDecodeError:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-30",
                        finding_name="Model Package Group Resource Policy Exposure",
                        finding_details=f"Model package group '{group_name}' has a malformed resource policy that could not be evaluated.",
                        resolution="Replace the malformed policy and rerun the assessment.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_GetModelPackageGroupPolicy.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
                continue

            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            public_statements = []
            external_statements = []
            unsupported_statements = []
            indeterminate_account_statements = []
            for index, statement in enumerate(statements):
                if (
                    not isinstance(statement, dict)
                    or statement.get("Effect") != "Allow"
                ):
                    continue
                if "NotPrincipal" in statement:
                    unsupported_statements.append(index)
                    continue
                principals = _policy_values(statement.get("Principal"))
                boundaries = _policy_condition_boundaries(statement)
                constrained_wildcard = bool(
                    boundaries["accounts"] or boundaries["organizations"]
                )
                if "*" in principals and not constrained_wildcard:
                    public_statements.append(index)
                    continue

                accounts = set()
                for principal in principals:
                    accounts.update(re.findall(r"(?<!\d)\d{12}(?!\d)", principal))
                accounts.update(boundaries["accounts"])
                accounts_requiring_classification = accounts - approved_accounts
                if current_account:
                    unapproved_accounts = accounts_requiring_classification - {
                        current_account
                    }
                else:
                    unapproved_accounts = set()
                    if accounts_requiring_classification:
                        indeterminate_account_statements.append(
                            {
                                "index": index,
                                "accounts": sorted(accounts_requiring_classification),
                            }
                        )
                unapproved_orgs = boundaries["organizations"] - approved_orgs
                if unapproved_accounts or unapproved_orgs:
                    external_statements.append(
                        {
                            "index": index,
                            "accounts": sorted(unapproved_accounts),
                            "organizations": sorted(unapproved_orgs),
                        }
                    )

            if public_statements:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-30",
                        finding_name="Public Model Package Group Resource Policy",
                        finding_details=f"Model package group '{group_name}' has public Allow statements at indexes {public_statements}.",
                        resolution="Remove wildcard principals or constrain them to explicitly approved accounts or AWS Organizations.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_GetModelPackageGroupPolicy.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            elif external_statements:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-30",
                        finding_name="External Model Package Group Resource Policy",
                        finding_details=f"Model package group '{group_name}' grants access outside the current account: {external_statements}. This heuristic does not perform full IAM policy evaluation.",
                        resolution=(
                            "Restrict access to the configured approved account and organization boundary."
                            if trust_boundary_configured
                            else "Review the external principals. Configure AIML_APPROVED_EXTERNAL_ACCOUNT_IDS or AIML_APPROVED_ORG_IDS to enforce an explicit trust boundary."
                        ),
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_GetModelPackageGroupPolicy.html",
                        severity="High"
                        if trust_boundary_configured
                        else "Informational",
                        status="Failed" if trust_boundary_configured else "Passed",
                        region=region,
                    )
                )
            elif unsupported_statements:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-30",
                        finding_name="Unsupported Model Package Group Resource Policy",
                        finding_details=f"Model package group '{group_name}' has Allow statements using unsupported NotPrincipal syntax at indexes {unsupported_statements}; their effective access could not be evaluated.",
                        resolution="Replace each Allow with NotPrincipal statement with a supported Principal-based Allow statement, or use NotPrincipal only with an explicit Deny.",
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
            elif indeterminate_account_statements:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-30",
                        finding_name="Model Package Group Policy Account Context Unavailable",
                        finding_details=f"Could not determine the assessment account with sts:GetCallerIdentity, so account principals in statements {indeterminate_account_statements} could not be classified as same-account or external: {type(current_account_error).__name__}.",
                        resolution="Retry the assessment with valid AWS credentials and working STS connectivity.",
                        reference="https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-30",
                        finding_name="Model Package Group Resource Policy Exposure",
                        finding_details=f"Model package group '{group_name}' has no public or unapproved external Allow principals.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_GetModelPackageGroupPolicy.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
    except Exception as error:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-30",
                finding_name="Model Package Group Resource Policy Exposure",
                finding_details=build_could_not_assess_detail(error, region),
                resolution=COULD_NOT_ASSESS_RESOLUTION,
                reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_GetModelPackageGroupPolicy.html",
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    return findings


ENDPOINT_DATA_CAPTURE_FINDING = "Endpoint Inference Data Capture"
ENDPOINT_DATA_CAPTURE_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-capture.html"
)
ENDPOINT_DATA_CAPTURE_RESOLUTION = (
    "Set DataCaptureConfig on the endpoint configuration with EnableCapture "
    "true, CaptureOptions covering Input and Output, a DestinationS3Uri and a "
    "KmsKeyId, then update the endpoint. Without captured inference records a "
    "Model Monitor schedule has no data to compare against its baseline, so "
    "drift and adversarial input cannot be detected after the fact."
)


def _capture_disk_alarm_findings(
    capturing: List[Dict[str, Any]], region: str
) -> List[Dict[str, Any]]:
    """
    Require, for each instance-backed variant of a capturing endpoint, an enabled
    alarm with an action on DiskUtilization that fires at or below 75%.
    """
    try:
        alarms = _actionable_metric_alarms(region)
    except Exception as error:
        return [
            _unread_resources_finding(
                "SM-31",
                CAPTURE_DISK_ALARM_FINDING,
                [f"cloudwatch:DescribeAlarms ({get_assessment_error_label(error)})"],
                f"{len(capturing)} capturing endpoint(s) were found.",
                CAPTURE_DISK_ALARM_REFERENCE,
                region,
            )
        ]
    covered = set()
    for alarm in alarms:
        if alarm.get("ComparisonOperator") not in RISING_COMPARISONS:
            continue
        threshold = alarm.get("Threshold")
        if not isinstance(threshold, (int, float)) or (
            threshold > CAPTURE_DISK_ALARM_MAX_THRESHOLD
        ):
            continue
        if alarm.get("Namespace") != ENDPOINT_METRIC_NAMESPACE:
            continue
        if alarm.get("MetricName") != "DiskUtilization":
            continue
        dimensions = {
            d.get("Name"): d.get("Value") for d in alarm.get("Dimensions") or []
        }
        covered.add((dimensions.get("EndpointName"), dimensions.get("VariantName")))

    uncovered = []
    no_variants = []
    checked = 0
    for entry in capturing:
        variants = [
            v.get("VariantName")
            for v in entry["variants"]
            if not v.get("CurrentServerlessConfig")
        ]
        if not entry["variants"]:
            no_variants.append(
                f"endpoint {entry['name']} reported no ProductionVariants"
            )
            continue
        for variant in variants:
            checked += 1
            if (entry["name"], variant) not in covered:
                uncovered.append(f"{entry['name']}/{variant}")
    rows = []
    for label in uncovered[:20]:
        rows.append(
            create_finding(
                check_id="SM-31",
                finding_name=CAPTURE_DISK_ALARM_FINDING,
                finding_details=(
                    f"Capturing variant '{label}' has no enabled alarm with an "
                    "action on /aws/sagemaker/Endpoints DiskUtilization at a "
                    f"threshold of {CAPTURE_DISK_ALARM_MAX_THRESHOLD:g}% or lower, so "
                    "Data Capture can stop at high disk usage without notice."
                ),
                resolution=(
                    "Create a CloudWatch alarm on DiskUtilization for each variant "
                    "(EndpointName and VariantName dimensions) at 75% or lower with "
                    "an alarm action."
                ),
                reference=CAPTURE_DISK_ALARM_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if no_variants:
        rows.append(
            _unread_resources_finding(
                "SM-31",
                CAPTURE_DISK_ALARM_FINDING,
                no_variants,
                f"{checked} capturing variant(s) were read.",
                CAPTURE_DISK_ALARM_REFERENCE,
                region,
            )
        )
    elif not uncovered and checked:
        rows.append(
            create_finding(
                check_id="SM-31",
                finding_name=CAPTURE_DISK_ALARM_FINDING,
                finding_details=(
                    f"All {checked} instance-backed capturing variant(s) have an "
                    "enabled DiskUtilization alarm with an action at "
                    f"{CAPTURE_DISK_ALARM_MAX_THRESHOLD:g}% or lower. Serverless "
                    "variants report no disk metric and are not counted."
                ),
                resolution="No action required",
                reference=CAPTURE_DISK_ALARM_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return rows


def check_sagemaker_endpoint_data_capture(region: str = "") -> Dict[str, Any]:
    """
    SM-31: Verify each SageMaker endpoint captures inference requests and
    responses (AIR-SGM-EP-06).

    DescribeEndpoint reports the live capture state (EnableCapture plus
    CaptureStatus, which is Started or Stopped), so an endpoint whose
    configuration enables capture but whose capture has stopped is reported as a
    failure and not as compliant.
    """
    logger.debug("Starting check for SageMaker endpoint data capture")
    findings = {"csv_data": []}
    try:
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        capturing = []
        not_capturing = []
        endpoints_seen = 0
        describe_errors = []

        paginator = sagemaker_client.get_paginator("list_endpoints")
        for page in paginator.paginate():
            for endpoint in page.get("Endpoints", []):
                endpoint_name = endpoint.get("EndpointName")
                if not endpoint_name:
                    continue
                endpoints_seen += 1
                try:
                    detail = sagemaker_client.describe_endpoint(
                        EndpointName=endpoint_name
                    )
                except Exception as error:
                    describe_errors.append(
                        {
                            "name": endpoint_name,
                            "label": get_assessment_error_label(error),
                        }
                    )
                    continue

                capture_config = detail.get("DataCaptureConfig") or {}
                if not isinstance(capture_config, dict):
                    capture_config = {}
                enabled = capture_config.get("EnableCapture") is True
                capture_status = capture_config.get("CaptureStatus")
                if enabled and capture_status == "Started":
                    capturing.append(
                        {
                            "name": endpoint_name,
                            "destination": capture_config.get("DestinationS3Uri") or "",
                            "sampling": capture_config.get("CurrentSamplingPercentage"),
                            "variants": detail.get("ProductionVariants") or [],
                        }
                    )
                elif not capture_config:
                    not_capturing.append(
                        {
                            "name": endpoint_name,
                            "reason": "no DataCaptureConfig is attached",
                        }
                    )
                elif not enabled:
                    not_capturing.append(
                        {
                            "name": endpoint_name,
                            "reason": "DataCaptureConfig.EnableCapture is false",
                        }
                    )
                else:
                    not_capturing.append(
                        {
                            "name": endpoint_name,
                            "reason": (
                                "DataCaptureConfig is enabled but CaptureStatus is "
                                f"{capture_status or 'not reported'}"
                            ),
                        }
                    )

        if endpoints_seen == 0:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-31",
                    finding_name=ENDPOINT_DATA_CAPTURE_FINDING,
                    finding_details=(
                        f"No SageMaker endpoints found in {region or 'this region'}, "
                        "so there is no inference traffic to capture."
                    ),
                    resolution="No action required",
                    reference=ENDPOINT_DATA_CAPTURE_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            return findings

        for entry in not_capturing[:20]:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-31",
                    finding_name=ENDPOINT_DATA_CAPTURE_FINDING,
                    finding_details=(
                        f"Endpoint '{entry['name']}' is not capturing inference "
                        f"records: {entry['reason']}."
                    ),
                    resolution=ENDPOINT_DATA_CAPTURE_RESOLUTION,
                    reference=ENDPOINT_DATA_CAPTURE_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )

        if len(not_capturing) > 20:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-31",
                    finding_name=ENDPOINT_DATA_CAPTURE_FINDING,
                    finding_details=(
                        f"{len(not_capturing)} endpoints are not capturing inference "
                        "records (the first 20 are reported individually above)."
                    ),
                    resolution=ENDPOINT_DATA_CAPTURE_RESOLUTION,
                    reference=ENDPOINT_DATA_CAPTURE_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )

        if capturing:
            described = "; ".join(
                "{} to {}".format(entry["name"], entry["destination"] or "S3")
                for entry in capturing[:3]
            )
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-31",
                    finding_name=ENDPOINT_DATA_CAPTURE_FINDING,
                    finding_details=(
                        f"{len(capturing)} of {endpoints_seen} endpoint(s) report "
                        f"CaptureStatus Started: {described}. Whether the captured "
                        "records are reviewed, and at what sampling percentage, is "
                        "not readable from the endpoint."
                    ),
                    resolution=(
                        "No action required on capture. Confirm a Model Monitor "
                        "schedule consumes the captured records."
                    ),
                    reference=ENDPOINT_DATA_CAPTURE_REFERENCE,
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        if capturing:
            findings["csv_data"].extend(_capture_disk_alarm_findings(capturing, region))

        for entry in describe_errors[:5]:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-31",
                    finding_name=ENDPOINT_DATA_CAPTURE_FINDING,
                    finding_details=(
                        f"Endpoint '{entry['name']}' could not be assessed for data "
                        f"capture. Assessment error: {entry['label']}."
                    ),
                    resolution="Grant sagemaker:DescribeEndpoint and retry.",
                    reference=ENDPOINT_DATA_CAPTURE_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as error:
        logger.error(
            f"Error in check_sagemaker_endpoint_data_capture: {str(error)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-31",
                    finding_name=ENDPOINT_DATA_CAPTURE_FINDING,
                    finding_details=build_could_not_assess_detail(error, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference=ENDPOINT_DATA_CAPTURE_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


CONFIG_RECORDING_FINDING = "SageMaker Configuration Recording"
CONFIG_RULE_COMPLIANCE_FINDING = "SageMaker Config Rule Compliance"
CONFIG_REFERENCE = (
    "https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html"
)
CONFIG_RECORDING_RESOLUTION = (
    "Turn on an AWS Config recorder in this region and include the "
    "AWS::SageMaker::* resource types (or record all supported types). Without "
    "recorded configuration items, a change to a domain, model or feature group "
    "leaves no evaluated history to compare against the required controls."
)
CONFIG_RULE_RESOLUTION = (
    "Deploy AWS Config rules covering the SageMaker controls this workload "
    "requires, for example through the Security Hub CSPM SageMaker controls or a "
    "conformance pack, and keep them in the ACTIVE state. A recorder on its own "
    "stores configuration items without evaluating them, so nothing flags a "
    "non-compliant resource."
)
SAGEMAKER_CONFIG_RESOURCE_PREFIX = "AWS::SageMaker::"
REQUIRED_CONFIG_RULES_FINDING = "SageMaker Required Config Rules"
REQUIRED_CONFIG_RULES_REFERENCE = (
    "https://docs.aws.amazon.com/config/latest/developerguide/"
    "sagemaker-endpoint-configuration-kms-key-configured.html"
)
ENDPOINT_CONFIG_KMS_RULE_IDENTIFIER = (
    "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED"
)
REQUIRED_SAGEMAKER_CONFIG_RULES = (
    ENDPOINT_CONFIG_KMS_RULE_IDENTIFIER,
    NOTEBOOK_KMS_RULE_IDENTIFIER,
    "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS",
)
CONFORMANCE_PACK_FINDING = "SageMaker Config Conformance Pack"
CONFORMANCE_PACK_REFERENCE = (
    "https://docs.aws.amazon.com/config/latest/developerguide/"
    "security-and-governance-best-practices-for-amazon-sagemaker-ai.html"
)
# ConformancePackDetail.CreatedBy names the service that created a pack; an
# organization conformance pack is created in each member account by this one.
ORGANIZATION_CONFORMANCE_PACK_CREATOR = "config-multiaccountsetup.amazonaws.com"


def _sagemaker_recording_coverage(recorder: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decide whether one Config recorder records SageMaker resource types.

    recordingStrategy is the current field and allSupported/resourceTypes are the
    older ones, so both are read: a recorder created before recordingStrategy
    existed reports only the latter.
    """
    recording_group = recorder.get("recordingGroup") or {}
    strategy = (recording_group.get("recordingStrategy") or {}).get("useOnly")
    resource_types = [
        str(item) for item in (recording_group.get("resourceTypes") or [])
    ]
    excluded = [
        str(item)
        for item in (
            (recording_group.get("exclusionByResourceTypes") or {}).get("resourceTypes")
            or []
        )
    ]
    sagemaker_included = [
        item
        for item in resource_types
        if item.startswith(SAGEMAKER_CONFIG_RESOURCE_PREFIX)
    ]
    sagemaker_excluded = [
        item for item in excluded if item.startswith(SAGEMAKER_CONFIG_RESOURCE_PREFIX)
    ]

    if strategy == "EXCLUSION_BY_RESOURCE_TYPES":
        return {
            "covered": not sagemaker_excluded,
            "detail": (
                "records all supported resource types except "
                f"{', '.join(sorted(sagemaker_excluded))}"
                if sagemaker_excluded
                else "records all supported resource types by exclusion strategy"
            ),
        }

    if strategy == "ALL_SUPPORTED_RESOURCE_TYPES" or recording_group.get(
        "allSupported"
    ):
        return {
            "covered": True,
            "detail": "records all supported resource types",
        }

    if sagemaker_included:
        return {
            "covered": True,
            "detail": (
                "records the SageMaker resource types "
                f"{', '.join(sorted(sagemaker_included))}"
            ),
        }

    return {
        "covered": False,
        "detail": (
            f"records {len(resource_types)} resource type(s), none of them "
            "AWS::SageMaker::*"
        ),
    }


def _rule_targets_sagemaker(rule: Dict[str, Any]) -> bool:
    """
    Return whether a Config rule evaluates SageMaker.

    Scope is empty on a periodic rule, and the SageMaker managed rules that
    evaluate notebook instances and endpoint configurations are periodic because
    AWS Config records no configuration item for those resource types. Matching
    the rule identifier and name as well as the scope keeps those rules in.
    """
    scope = rule.get("Scope") or {}
    for resource_type in scope.get("ComplianceResourceTypes") or []:
        if str(resource_type).startswith(SAGEMAKER_CONFIG_RESOURCE_PREFIX):
            return True
    source_identifier = str((rule.get("Source") or {}).get("SourceIdentifier") or "")
    if "SAGEMAKER" in source_identifier.upper():
        return True
    return "sagemaker" in str(rule.get("ConfigRuleName") or "").lower()


def _no_customer_recorder_finding(config_client: Any, region: str) -> Dict[str, Any]:
    """
    Decide the recorder leg when DescribeConfigurationRecorders returns nothing.

    Called without arguments it returns only the customer-managed recorder, so
    ListConfigurationRecorders, which lists service-linked recorders as well, is
    what makes an empty result decidable.
    """
    where = region or "this region"
    try:
        summaries = []
        for page in config_client.get_paginator(
            "list_configuration_recorders"
        ).paginate():
            summaries.extend(page.get("ConfigurationRecorderSummaries", []))
    except Exception as error:
        return create_finding(
            check_id="SM-32",
            finding_name=CONFIG_RECORDING_FINDING,
            finding_details=(
                "DescribeConfigurationRecorders returned no customer-managed AWS "
                f"Config recorder in {where}, and ListConfigurationRecorders, which "
                "also lists service-linked recorders, was not read "
                f"({get_assessment_error_label(error)}), so whether SageMaker "
                "configuration items are recorded here could not be determined."
            ),
            resolution="Grant config:ListConfigurationRecorders and retry.",
            reference=CONFIG_REFERENCE,
            severity="Informational",
            status="N/A",
            region=region,
        )
    customer = [item for item in summaries if not item.get("servicePrincipal")]
    if customer:
        return create_finding(
            check_id="SM-32",
            finding_name=CONFIG_RECORDING_FINDING,
            finding_details=(
                f"ListConfigurationRecorders names customer-managed recorder(s) "
                f"{', '.join(str(item.get('name')) for item in customer)} in {where}, "
                "but DescribeConfigurationRecorders returned none, so their "
                "recording scope was not read."
            ),
            resolution="Retry the assessment; the two Config reads disagreed.",
            reference=CONFIG_REFERENCE,
            severity="Informational",
            status="N/A",
            region=region,
        )
    linked = sorted(str(item.get("servicePrincipal")) for item in summaries)
    return create_finding(
        check_id="SM-32",
        finding_name=CONFIG_RECORDING_FINDING,
        finding_details=(
            f"No customer-managed AWS Config recorder exists in {where}. "
            f"ListConfigurationRecorders returned {len(linked)} service-linked "
            "recorder(s)"
            + (f", created by {', '.join(linked)}" if linked else "")
            + ". A service-linked recorder is created and scoped by its owning "
            "service, so nothing here records SageMaker configuration items for "
            "the account's own rules."
        ),
        resolution=CONFIG_RECORDING_RESOLUTION,
        reference=CONFIG_REFERENCE,
        severity="Medium",
        status="Failed",
        region=region,
    )


def _recorder_findings(
    config_client: Any, recorders: List[Dict[str, Any]], region: str
) -> List[Dict[str, Any]]:
    """One row per customer-managed recorder: SageMaker scope and whether it runs."""
    statuses = {}
    status_error = "no status was returned for it"
    try:
        response = config_client.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[
                recorder["name"] for recorder in recorders if recorder.get("name")
            ]
        )
        for status in response.get("ConfigurationRecordersStatus", []):
            statuses[status.get("name")] = status
    except Exception as error:
        status_error = get_assessment_error_label(error)
    rows = []
    for recorder in recorders:
        recorder_name = recorder.get("name") or "default"
        coverage = _sagemaker_recording_coverage(recorder)
        detail = f"AWS Config recorder '{recorder_name}' {coverage['detail']}"
        status = statuses.get(recorder.get("name"))
        if not coverage["covered"]:
            outcome = ("Failed", f"{detail}.", CONFIG_RECORDING_RESOLUTION)
        elif status is None:
            outcome = (
                "N/A",
                f"{detail}, but config:DescribeConfigurationRecorderStatus was not "
                f"read ({status_error}), so whether it is recording could not be "
                "established.",
                "Grant config:DescribeConfigurationRecorderStatus and retry.",
            )
        elif status.get("recording") is not True:
            outcome = (
                "Failed",
                f"{detail}, but it is stopped (recording is false), so no "
                "configuration item is being recorded.",
                "Start the configuration recorder.",
            )
        elif str(status.get("lastStatus") or "").upper() == "FAILURE":
            outcome = (
                "Failed",
                f"{detail}, but its last recording attempt failed "
                f"({status.get('lastErrorCode') or 'no error code'}).",
                "Fix the recorder's delivery role or channel so recording succeeds.",
            )
        else:
            outcome = (
                "Passed",
                f"{detail} and is recording.",
                "No action required",
            )
        rows.append(
            create_finding(
                check_id="SM-32",
                finding_name=CONFIG_RECORDING_FINDING,
                finding_details=outcome[1],
                resolution=outcome[2],
                reference=CONFIG_REFERENCE,
                severity="Informational" if outcome[0] == "N/A" else "Medium",
                status=outcome[0],
                region=region,
            )
        )
    return rows


def _required_config_rules_finding(
    rules: List[Dict[str, Any]], region: str
) -> Dict[str, Any]:
    """Require the three SageMaker managed rules the recommendation names."""
    problems, passing = _managed_rule_problems(
        rules, REQUIRED_SAGEMAKER_CONFIG_RULES, (ENDPOINT_CONFIG_KMS_RULE_IDENTIFIER,)
    )
    where = region or "this region"
    if problems:
        return create_finding(
            check_id="SM-32",
            finding_name=REQUIRED_CONFIG_RULES_FINDING,
            finding_details=(
                f"{len(problems)} of {len(REQUIRED_SAGEMAKER_CONFIG_RULES)} required "
                f"SageMaker managed Config rules are missing or narrowed in {where}: "
                f"{'; '.join(problems)}."
            ),
            resolution=(
                "Deploy sagemaker-endpoint-configuration-kms-key-configured with "
                "kmsKeyArns set to the approved keys, "
                "sagemaker-notebook-instance-kms-key-configured and "
                "sagemaker-notebook-no-direct-internet-access, unscoped by resource "
                "id or tag."
            ),
            reference=REQUIRED_CONFIG_RULES_REFERENCE,
            severity="Medium",
            status="Failed",
            region=region,
        )
    return create_finding(
        check_id="SM-32",
        finding_name=REQUIRED_CONFIG_RULES_FINDING,
        finding_details=(
            f"All {len(REQUIRED_SAGEMAKER_CONFIG_RULES)} required SageMaker managed "
            f"Config rules are active in {where}: {'; '.join(passing)}. They are "
            "periodic, and Config records no training, processing or transform "
            "job, so those jobs depend on the preventive controls."
        ),
        resolution="No action required",
        reference=REQUIRED_CONFIG_RULES_REFERENCE,
        severity="Medium",
        status="Passed",
        region=region,
    )


def _conformance_pack_finding(
    config_client: Any, rules: List[Dict[str, Any]], region: str
) -> Dict[str, Any]:
    """Pass only when an organization conformance pack carries all three rules."""
    identifier_by_rule = {
        rule.get("ConfigRuleName"): (rule.get("Source") or {}).get("SourceIdentifier")
        for rule in rules
        if (rule.get("Source") or {}).get("Owner") == "AWS"
    }
    try:
        packs = []
        for page in config_client.get_paginator(
            "describe_conformance_packs"
        ).paginate():
            packs.extend(page.get("ConformancePackDetails", []))
    except Exception as error:
        return _unread_resources_finding(
            "SM-32",
            CONFORMANCE_PACK_FINDING,
            [f"config:DescribeConformancePacks ({get_assessment_error_label(error)})"],
            "no conformance pack was read.",
            CONFORMANCE_PACK_REFERENCE,
            region,
        )
    unread = []
    described = []
    for pack in packs:
        name = pack.get("ConformancePackName")
        rule_names = set()
        try:
            for page in config_client.get_paginator(
                "describe_conformance_pack_compliance"
            ).paginate(ConformancePackName=name):
                for entry in page.get("ConformancePackRuleComplianceList", []):
                    rule_names.add(entry.get("ConfigRuleName"))
        except Exception as error:
            unread.append(
                f"config:DescribeConformancePackCompliance {name} "
                f"({get_assessment_error_label(error)})"
            )
            continue
        carried = {identifier_by_rule.get(rule_name) for rule_name in rule_names}
        missing = [
            item for item in REQUIRED_SAGEMAKER_CONFIG_RULES if item not in carried
        ]
        organization = pack.get("CreatedBy") == ORGANIZATION_CONFORMANCE_PACK_CREATOR
        if organization and not missing:
            return create_finding(
                check_id="SM-32",
                finding_name=CONFORMANCE_PACK_FINDING,
                finding_details=(
                    f"Organization conformance pack '{name}' in "
                    f"{region or 'this region'} deploys all "
                    f"{len(REQUIRED_SAGEMAKER_CONFIG_RULES)} required SageMaker "
                    "managed rules."
                ),
                resolution="No action required",
                reference=CONFORMANCE_PACK_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        described.append(
            f"'{name}' ("
            + ("organization" if organization else "this account only")
            + (f", lacks {', '.join(missing)}" if missing else "")
            + ")"
        )
    read_text = (
        f"{len(described)} pack(s) read, none an organization pack carrying all "
        f"{len(REQUIRED_SAGEMAKER_CONFIG_RULES)} required rules: "
        f"{'; '.join(described[:5])}."
        if described
        else "no conformance pack is deployed."
    )
    if unread:
        return _unread_resources_finding(
            "SM-32",
            CONFORMANCE_PACK_FINDING,
            unread,
            read_text,
            CONFORMANCE_PACK_REFERENCE,
            region,
        )
    return create_finding(
        check_id="SM-32",
        finding_name=CONFORMANCE_PACK_FINDING,
        finding_details=(
            f"No organization conformance pack deploys the required SageMaker "
            f"managed rules in {region or 'this region'}: {read_text}"
        ),
        resolution=(
            "Deploy the Security and Governance Best Practices for Amazon SageMaker "
            "AI conformance pack as an organization conformance pack."
        ),
        reference=CONFORMANCE_PACK_REFERENCE,
        severity="Medium",
        status="Failed",
        region=region,
    )


def check_sagemaker_config_compliance_evaluation(region: str = "") -> Dict[str, Any]:
    """
    SM-32: Verify SageMaker configuration state is continuously evaluated and
    non-compliant resources are reported (AIR-SGM-GOV-10).

    Two independent legs: an AWS Config recorder covering SageMaker resource
    types, and at least one active Config rule evaluating SageMaker with its
    current compliance result. A recorder without rules evaluates nothing, and a
    rule without a recorder cannot see configuration changes, so neither verdict
    implies the other.

    Two more legs read the three managed rules AIR-SGM-GOV-10 names and whether
    an organization conformance pack deploys them. A rule with no current
    evaluation withholds Passed.
    """
    logger.debug("Starting check for SageMaker AWS Config coverage")
    findings = {"csv_data": []}
    try:
        config_client = boto3.client("config", config=boto3_config, region_name=region)

        # DescribeConfigurationRecorders has no continuation field in the
        # botocore model, so there is no paginator to use. Called without
        # arguments it returns only the customer-managed recorder; a recorder
        # created for another service is reachable only by naming that service
        # principal, which this check does not guess at.
        recorders = config_client.describe_configuration_recorders().get(
            "ConfigurationRecorders", []
        )

        if not recorders:
            findings["csv_data"].append(
                _no_customer_recorder_finding(config_client, region)
            )
        else:
            findings["csv_data"].extend(
                _recorder_findings(config_client, recorders, region)
            )

        all_rules = []
        rule_paginator = config_client.get_paginator("describe_config_rules")
        for page in rule_paginator.paginate():
            all_rules.extend(page.get("ConfigRules", []))
        sagemaker_rules = [rule for rule in all_rules if _rule_targets_sagemaker(rule)]
        findings["csv_data"].append(_required_config_rules_finding(all_rules, region))
        findings["csv_data"].append(
            _conformance_pack_finding(config_client, all_rules, region)
        )

        active_rules = [
            rule for rule in sagemaker_rules if rule.get("ConfigRuleState") == "ACTIVE"
        ]

        if not active_rules:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-32",
                    finding_name=CONFIG_RULE_COMPLIANCE_FINDING,
                    finding_details=(
                        f"No ACTIVE AWS Config rule in {region or 'this region'} "
                        "evaluates SageMaker: none of the "
                        f"{len(sagemaker_rules)} SageMaker-related rule(s) found is "
                        "in the ACTIVE state, so no SageMaker resource is reported "
                        "as compliant or non-compliant."
                    ),
                    resolution=CONFIG_RULE_RESOLUTION,
                    reference=CONFIG_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )
            return findings

        # DescribeConfigRules sets CreatedBy only on a service-linked rule. The
        # owning service holds its compliance results: Config returns
        # AccessDeniedException to every caller, so these rules can neither
        # earn a Passed nor be blamed on this assessment's permissions.
        service_linked = [rule for rule in active_rules if rule.get("CreatedBy")]
        readable_rules = [rule for rule in active_rules if not rule.get("CreatedBy")]
        if service_linked:
            owners = ", ".join(sorted({rule["CreatedBy"] for rule in service_linked}))
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-32",
                    finding_name=CONFIG_RULE_COMPLIANCE_FINDING,
                    finding_details=(
                        f"{len(service_linked)} ACTIVE SageMaker Config rule(s) "
                        f"in {region or 'this region'} are service-linked rules "
                        f"owned by {owners}. AWS Config does not return their "
                        "compliance results to any caller, so this check cannot "
                        "read them; the owning service reports them, for example "
                        "as Security Hub control findings."
                    ),
                    resolution=(
                        "Review these rules' results in the owning service, or "
                        "add a customer-managed Config rule for SageMaker so the "
                        "result can be read here."
                    ),
                    reference=CONFIG_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            if not readable_rules:
                return findings

        rule_names = [
            rule.get("ConfigRuleName")
            for rule in readable_rules
            if rule.get("ConfigRuleName")
        ]
        compliance_by_rule = {}
        compliance_error = None
        try:
            compliance_paginator = config_client.get_paginator(
                "describe_compliance_by_config_rule"
            )
            # DescribeComplianceByConfigRule accepts at most 25 rule names.
            for index in range(0, len(rule_names), 25):
                batch = rule_names[index : index + 25]
                for page in compliance_paginator.paginate(ConfigRuleNames=batch):
                    for entry in page.get("ComplianceByConfigRules", []):
                        name = entry.get("ConfigRuleName")
                        compliance = entry.get("Compliance") or {}
                        if name:
                            compliance_by_rule[name] = compliance
        except Exception as error:
            compliance_error = get_assessment_error_label(error)

        non_compliant = {
            name: compliance
            for name, compliance in compliance_by_rule.items()
            if compliance.get("ComplianceType") == "NON_COMPLIANT"
        }

        if non_compliant:
            for name, compliance in sorted(non_compliant.items())[:20]:
                capped = (compliance.get("ComplianceContributorCount") or {}).get(
                    "CappedCount"
                )
                counted = (
                    f"{capped} non-compliant resource(s)"
                    if capped is not None
                    else "a non-compliant resource"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-32",
                        finding_name=CONFIG_RULE_COMPLIANCE_FINDING,
                        finding_details=(
                            f"AWS Config rule '{name}' reports {counted} for "
                            "SageMaker. The rule is evaluating, and the resources "
                            "it flagged are outstanding."
                        ),
                        resolution=(
                            "Remediate the resources the rule flagged, then "
                            "re-evaluate the rule."
                        ),
                        reference=CONFIG_REFERENCE,
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

        compliant_names = sorted(
            name
            for name, compliance in compliance_by_rule.items()
            if compliance.get("ComplianceType") == "COMPLIANT"
        )
        # INSUFFICIENT_DATA, or no entry at all, means Config holds no current
        # evaluation for the rule, so it has flagged nothing either way.
        unevaluated = (
            []
            if compliance_error
            else sorted(
                name
                for name in rule_names
                if (compliance_by_rule.get(name) or {}).get("ComplianceType")
                not in ("COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE")
            )
        )
        if not non_compliant and not compliance_error and not unevaluated:
            described = ", ".join((compliant_names or rule_names)[:5])
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-32",
                    finding_name=CONFIG_RULE_COMPLIANCE_FINDING,
                    finding_details=(
                        f"{len(readable_rules)} ACTIVE AWS Config rule(s) evaluate "
                        f"SageMaker in {region or 'this region'} and report no "
                        f"non-compliant resource: {described}. AWS Config has no "
                        "resource type for a training, processing or transform "
                        "job, so no Config rule evaluates a job and this row "
                        "makes no claim about jobs."
                    ),
                    resolution="No action required",
                    reference=CONFIG_REFERENCE,
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        if unevaluated:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-32",
                    finding_name=CONFIG_RULE_COMPLIANCE_FINDING,
                    finding_details=(
                        f"{len(unevaluated)} of {len(readable_rules)} ACTIVE "
                        "SageMaker Config rule(s) have no current evaluation "
                        "(INSUFFICIENT_DATA or no compliance entry), so they have "
                        f"not assessed any resource: {', '.join(unevaluated[:10])}."
                    ),
                    resolution=(
                        "Check each rule's evaluation status with "
                        "DescribeConfigRuleEvaluationStatus, fix the failing "
                        "invocation or recorder, and re-evaluate the rule."
                    ),
                    reference=CONFIG_REFERENCE,
                    severity="Medium",
                    status="N/A",
                    region=region,
                )
            )

        if compliance_error:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-32",
                    finding_name=CONFIG_RULE_COMPLIANCE_FINDING,
                    finding_details=(
                        f"{len(readable_rules)} ACTIVE SageMaker Config rule(s) were "
                        "found, but their compliance results could not be read. "
                        f"Assessment error: {compliance_error}."
                    ),
                    resolution=(
                        "Grant config:DescribeComplianceByConfigRule and retry."
                    ),
                    reference=CONFIG_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as error:
        logger.error(
            f"Error in check_sagemaker_config_compliance_evaluation: {str(error)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-32",
                    finding_name=CONFIG_RECORDING_FINDING,
                    finding_details=build_could_not_assess_detail(error, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference=CONFIG_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


TRAINING_NETWORK_BOUNDARY_FINDING = "Training Job Network Boundary"
TRAINING_SUBNET_EXPOSURE_FINDING = "SageMaker Training Job Subnet Internet Exposure"
TRAINING_NETWORK_BOUNDARY_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/train-vpc.html"
)
TRAINING_NETWORK_BOUNDARY_RESOLUTION = (
    "Create training jobs with VpcConfig naming private subnets and security "
    "groups, and set EnableNetworkIsolation true unless the job has to reach an "
    "approved external source. Without VpcConfig the training container runs in "
    "a SageMaker-managed network with outbound internet access, so nothing stops "
    "a compromised training script from exfiltrating the training data."
)

TRAINING_NETWORK_ISOLATION_FINDING = "Training Job Network Isolation"
TRAINING_VPC_ENDPOINTS_FINDING = "Training Job VPC Endpoint Coverage"
# The services a VPC-attached training job reaches, per AIR-SGM-TRN-01: S3,
# CloudWatch Logs, the SageMaker API and ECR (API and image layers).
TRAINING_REQUIRED_ENDPOINT_SERVICES = (
    "s3",
    "logs",
    "sagemaker.api",
    "ecr.api",
    "ecr.dkr",
)


S3_ENDPOINT_PROBE_OBJECT = "arn:aws:s3:::zz-probe-bucket-0/zz-probe"
S3_ENDPOINT_DATA_ACTIONS = ("s3:getobject", "s3:putobject")
PRINCIPAL_NARROWING_KEYS = ("aws:principalarn",)


def _endpoint_policy_principal_is_anyone(statement: Dict[str, Any]) -> bool:
    """
    Return whether an endpoint policy statement admits any principal.

    A Principal element narrows only when every value names a role or user
    without a wildcard; an account id or :root admits every identity in the
    account. A positive aws:PrincipalArn condition narrows on the same terms.
    """
    principal = statement.get("Principal", "*")
    values = (
        _policy_values(principal.get("AWS"))
        if isinstance(principal, dict)
        else _policy_values(principal)
    )
    if values and all(
        re.match(r"^arn:aws[a-z-]*:iam::\d{12}:(role|user)/", v)
        and "*" not in v
        and "?" not in v
        for v in values
    ):
        return False
    for operator, key, condition_values in _condition_entries(statement):
        if key not in PRINCIPAL_NARROWING_KEYS or not condition_values:
            continue
        prefix, base, if_exists = _condition_operator_parts(operator)
        if if_exists or "not" in base or prefix or base == "null":
            continue
        if any("*" in v or "?" in v for v in condition_values):
            continue
        return False
    return True


def _s3_bucket_pattern_is_wildcard(pattern: str) -> bool:
    """Return whether the bucket segment of an S3 ARN pattern holds a wildcard."""
    if not pattern.startswith("arn:"):
        return True
    bucket = pattern.split(":::", 1)[-1].split("/", 1)[0]
    return "*" in bucket or "?" in bucket


def _broad_s3_endpoint_statement(policy: Dict[str, Any]) -> Optional[str]:
    """
    Return a description of the first Allow that lets a principal read or write
    objects in every bucket, which is what the default full-access endpoint
    policy does, or that lets any principal do so on a bucket pattern with a
    wildcard, which reaches buckets outside the workload. A named principal does
    not excuse every bucket: the endpoint is then no bucket boundary at all.
    Deny statements are not evaluated.
    """
    for statement in _sm_policy_statements(policy):
        actions = [
            a
            for a in S3_ENDPOINT_DATA_ACTIONS
            if _statement_allows_action(statement, a)
        ]
        if not actions:
            continue
        if "NotResource" in statement:
            every_bucket = not any(
                _iam_action_matches(p, S3_ENDPOINT_PROBE_OBJECT)
                for p in _policy_values(statement.get("NotResource"))
            )
            wildcard_buckets = ["NotResource"]
        else:
            resources = _policy_values(statement.get("Resource"))
            every_bucket = any(
                fnmatch.fnmatchcase(S3_ENDPOINT_PROBE_OBJECT, p) for p in resources
            )
            wildcard_buckets = [
                p for p in resources if _s3_bucket_pattern_is_wildcard(p)
            ]
        anyone = _endpoint_policy_principal_is_anyone(statement)
        sid = statement.get("Sid") or "unnamed"
        if every_bucket:
            return f"statement '{sid}' allows {', '.join(actions)} on every bucket" + (
                " to any principal" if anyone else ""
            )
        if anyone and wildcard_buckets:
            return (
                f"statement '{sid}' allows {', '.join(actions)} to any principal "
                f"on bucket pattern(s) with a wildcard: {', '.join(wildcard_buckets)}"
            )
    return None


def _training_vpc_endpoint_findings(
    jobs_in_vpc: List[Dict[str, Any]],
    region: str,
    check_id: str = "SM-33",
    finding_name: str = TRAINING_VPC_ENDPOINTS_FINDING,
    services: tuple = TRAINING_REQUIRED_ENDPOINT_SERVICES,
    subject: str = "training job",
    resolution: str = (
        "Create the missing VPC endpoints: a gateway endpoint for "
        "S3 and interface endpoints with private DNS for "
        "CloudWatch Logs, the SageMaker API, ecr.api and ecr.dkr."
    ),
    judge_s3_policy: bool = False,
) -> List[Dict[str, Any]]:
    """
    AIR-SGM-TRN-01: every VPC a training job ran in needs an available endpoint
    for each service in TRAINING_REQUIRED_ENDPOINT_SERVICES. An interface
    endpoint counts only with private DNS on, since the job resolves the
    service's default hostname; S3 counts as a gateway or interface endpoint.
    AIR-SGM-EP-08 calls it for transform job models with S3 only, and with
    judge_s3_policy each S3 endpoint's policy must not grant object reads and
    writes on every bucket to any principal.
    """
    subnets = sorted({s for job in jobs_in_vpc for s in job["subnets"] if s})
    if not subnets:
        return []
    prefix = f"com.amazonaws.{region}."
    subnet_vpcs = {}
    subnet_azs = {}
    subnet_tables = {}
    try:
        ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)
        subnet_paginator = ec2_client.get_paginator("describe_subnets")

        def read_subnets(subnet_ids: List[str], record_vpc: bool) -> None:
            for chunk in _chunked(subnet_ids, SUBNET_LOOKUP_BATCH_SIZE):
                for page in subnet_paginator.paginate(
                    Filters=[{"Name": "subnet-id", "Values": chunk}]
                ):
                    for subnet in page.get("Subnets", []):
                        subnet_id = subnet.get("SubnetId")
                        if subnet_id not in subnet_ids:
                            continue
                        if subnet.get("AvailabilityZone"):
                            subnet_azs[subnet_id] = subnet["AvailabilityZone"]
                        if record_vpc and subnet.get("VpcId"):
                            subnet_vpcs[subnet_id] = subnet["VpcId"]

        read_subnets(subnets, True)
        present = {vpc_id: set() for vpc_id in subnet_vpcs.values()}
        s3_endpoints = {vpc_id: [] for vpc_id in present}
        service_endpoints = {vpc_id: {} for vpc_id in present}
        vpce_paginator = ec2_client.get_paginator("describe_vpc_endpoints")
        for chunk in _chunked(sorted(present), SUBNET_LOOKUP_BATCH_SIZE):
            for page in vpce_paginator.paginate(
                Filters=[{"Name": "vpc-id", "Values": chunk}]
            ):
                for vpce in page.get("VpcEndpoints", []):
                    service = str(vpce.get("ServiceName", ""))
                    if (
                        vpce.get("VpcId") not in present
                        or str(vpce.get("State", "")).lower() != "available"
                        or not service.startswith(prefix)
                    ):
                        continue
                    short = service[len(prefix) :]
                    if (
                        vpce.get("VpcEndpointType") == "Interface"
                        and vpce.get("PrivateDnsEnabled") is not True
                        and short != "s3"
                    ):
                        continue
                    present[vpce["VpcId"]].add(short)
                    service_endpoints[vpce["VpcId"]].setdefault(short, []).append(vpce)
                    if short == "s3":
                        s3_endpoints[vpce["VpcId"]].append(vpce)
        # AIR-SGM-TRN-01: a gateway endpoint serves only the route tables it is
        # associated with, and an interface endpoint only the Availability
        # Zones it has a network interface in.
        explicit_tables, main_tables = {}, {}
        route_paginator = ec2_client.get_paginator("describe_route_tables")
        for chunk in _chunked(sorted(present), SUBNET_LOOKUP_BATCH_SIZE):
            for page in route_paginator.paginate(
                Filters=[{"Name": "vpc-id", "Values": chunk}]
            ):
                for table in page.get("RouteTables", []):
                    for association in table.get("Associations", []):
                        if association.get("SubnetId"):
                            explicit_tables[association["SubnetId"]] = table.get(
                                "RouteTableId"
                            )
                        elif association.get("Main") is True and table.get("VpcId"):
                            main_tables[table["VpcId"]] = table.get("RouteTableId")
        for subnet_id, vpc_id in subnet_vpcs.items():
            table_id = explicit_tables.get(subnet_id) or main_tables.get(vpc_id)
            if table_id:
                subnet_tables[subnet_id] = table_id
        endpoint_subnets = sorted(
            {
                subnet_id
                for by_service in service_endpoints.values()
                for vpces in by_service.values()
                for vpce in vpces
                if vpce.get("VpcEndpointType") != "Gateway"
                for subnet_id in vpce.get("SubnetIds") or []
                if subnet_id not in subnet_azs
            }
        )
        read_subnets(endpoint_subnets, False)
    except Exception as error:
        logger.warning(f"Error reading training VPC endpoints: {str(error)}")
        return [
            create_finding(
                check_id=check_id,
                finding_name=f"{finding_name} Incomplete",
                finding_details=(
                    f"The VPC endpoints of the {len(jobs_in_vpc)} VPC-attached "
                    f"{subject}(s) were not read (ec2:DescribeSubnets, "
                    "ec2:DescribeVpcEndpoints, ec2:DescribeRouteTables: "
                    f"{get_assessment_error_label(error)})."
                ),
                resolution=COULD_NOT_ASSESS_RESOLUTION,
                reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]

    emitted = []
    complete = []
    unread = []
    for vpc_id in sorted(present):
        missing = [service for service in services if service not in present[vpc_id]]
        jobs = sorted(
            {
                job["name"]
                for job in jobs_in_vpc
                if any(subnet_vpcs.get(s) == vpc_id for s in job["subnets"])
            }
        )
        vpc_subnets = [s for s in subnets if subnet_vpcs.get(s) == vpc_id]
        uncovered = []
        reach_unread = []
        for service in services:
            vpces = service_endpoints[vpc_id].get(service) or []
            if not vpces:
                continue
            tables = {
                table_id
                for vpce in vpces
                if vpce.get("VpcEndpointType") == "Gateway"
                for table_id in vpce.get("RouteTableIds") or []
            }
            interface_subnets = [
                subnet_id
                for vpce in vpces
                if vpce.get("VpcEndpointType") != "Gateway"
                for subnet_id in vpce.get("SubnetIds") or []
            ]
            zones = {subnet_azs[s] for s in interface_subnets if s in subnet_azs}
            zones_unread = [s for s in interface_subnets if s not in subnet_azs]
            gaps = []
            for subnet_id in vpc_subnets:
                if subnet_tables.get(subnet_id) in tables or (
                    subnet_azs.get(subnet_id) in zones
                ):
                    continue
                if (
                    subnet_id not in subnet_tables
                    or subnet_id not in subnet_azs
                    or zones_unread
                ):
                    reach_unread.append(
                        f"whether the {prefix + service} endpoint reaches subnet "
                        f"{subnet_id} in {vpc_id} (its route table, its "
                        "Availability Zone or the endpoint's subnets were not read)"
                    )
                    continue
                gaps.append(
                    f"{subnet_id} (route table {subnet_tables[subnet_id]}, "
                    f"{subnet_azs[subnet_id]})"
                )
            if gaps:
                uncovered.append(
                    f"the {prefix + service} endpoint(s) "
                    f"{', '.join(str(v.get('VpcEndpointId')) for v in vpces)} serve "
                    f"neither the route table nor the Availability Zone of subnet(s) "
                    f"{', '.join(gaps[:5])}"
                )
        broad = []
        policy_unread = []
        if judge_s3_policy and not missing:
            for vpce in s3_endpoints[vpc_id]:
                document = vpce.get("PolicyDocument")
                try:
                    policy = (
                        json.loads(document) if isinstance(document, str) else document
                    )
                except ValueError:
                    policy = None
                if not isinstance(policy, dict):
                    policy_unread.append(
                        f"policy of S3 endpoint {vpce.get('VpcEndpointId')} in "
                        f"{vpc_id} (not returned or not parsed)"
                    )
                    continue
                statement = _broad_s3_endpoint_statement(policy)
                if statement:
                    broad.append(f"{vpce.get('VpcEndpointId')} ({statement})")
        if broad:
            emitted.append(
                create_finding(
                    check_id=check_id,
                    finding_name=finding_name,
                    finding_details=(
                        f"VPC {vpc_id}, used by {subject}(s) "
                        f"{', '.join(jobs[:5])}, reaches S3 through endpoint(s) "
                        f"whose policy is not scoped: {'; '.join(broad)}. Deny "
                        "statements were not evaluated, so a Deny could narrow it."
                    ),
                    resolution=(
                        "Replace the S3 endpoint policy with one that allows object "
                        "reads and writes only on the job's input and output "
                        "buckets, or only to the job's execution role."
                    ),
                    reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )
        elif uncovered:
            emitted.append(
                create_finding(
                    check_id=check_id,
                    finding_name=finding_name,
                    finding_details=(
                        f"VPC {vpc_id}, used by {subject}(s) "
                        f"{', '.join(jobs[:5])}: {'; '.join(uncovered)}. A gateway "
                        "endpoint carries traffic only for the route tables it is "
                        "associated with, and an interface endpoint has a network "
                        "interface only in the Availability Zones of its subnets."
                        + (
                            f" Also missing: {', '.join(prefix + m for m in missing)}."
                            if missing
                            else ""
                        )
                    ),
                    resolution=(
                        "Associate the gateway endpoint with the route table of "
                        "every job subnet, and add a subnet in each job subnet's "
                        "Availability Zone to the interface endpoint."
                    ),
                    reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )
        elif policy_unread or reach_unread:
            unread.extend(policy_unread + reach_unread)
        elif missing:
            emitted.append(
                create_finding(
                    check_id=check_id,
                    finding_name=finding_name,
                    finding_details=(
                        f"VPC {vpc_id}, used by {subject}(s) "
                        f"{', '.join(jobs[:5])}, has no available endpoint (with "
                        "private DNS for interface endpoints) for "
                        f"{', '.join(prefix + m for m in missing)}, so that "
                        "traffic leaves the VPC or fails."
                    ),
                    resolution=resolution,
                    reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )
        else:
            complete.append(vpc_id)
    unresolved = [s for s in subnets if s not in subnet_vpcs]
    read_details = (
        f"{len(complete)} VPC(s) used by {subject}s have an endpoint for every "
        "required service that serves each job subnet, through its route table "
        "for a gateway endpoint or its Availability Zone for an interface "
        f"endpoint: {', '.join(complete) or 'none'}."
    )
    if judge_s3_policy:
        read_details += (
            " Their S3 endpoint policies grant object reads and writes only on "
            "buckets named without a wildcard, or only to named roles or users on "
            "bucket patterns short of every bucket. Deny statements were not "
            "evaluated; whether the buckets and principals they name are the "
            "job's own is a workload decision this check does not judge."
        )
    unread.extend(f"subnet {s} (not found by ec2:DescribeSubnets)" for s in unresolved)
    if unread:
        emitted.append(
            _unread_resources_finding(
                check_id,
                finding_name,
                unread,
                read_details,
                TRAINING_NETWORK_BOUNDARY_REFERENCE,
                region,
            )
        )
    elif complete and not emitted:
        emitted.append(
            create_finding(
                check_id=check_id,
                finding_name=finding_name,
                finding_details=read_details,
                resolution="No action required",
                reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return emitted


PROCESSING_NETWORK_BOUNDARY_FINDING = "Processing Job Network Boundary"
PROCESSING_SUBNET_EXPOSURE_FINDING = "SageMaker Processing Job Subnet Internet Exposure"
PROCESSING_NETWORK_BOUNDARY_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_NetworkConfig.html"
)
PROCESSING_NETWORK_BOUNDARY_RESOLUTION = (
    "Create processing jobs with NetworkConfig.VpcConfig naming private subnets "
    "and security groups, and set NetworkConfig.EnableNetworkIsolation true "
    "unless the job has to reach an approved external source."
)


def _processing_job_network_findings(
    sagemaker_client: Any, region: str
) -> Tuple[List[Dict[str, Any]], int]:
    """SM-33 processing-job leg of AIR-FND-NET-01.

    Returns the rows and the number of processing jobs listed. Every job is
    listed and described. A processing job reports its network placement under
    NetworkConfig, not at the top level as a training job does.
    """
    rows: List[Dict[str, Any]] = []
    in_vpc: List[Dict[str, Any]] = []
    without_vpc: List[Dict[str, Any]] = []
    describe_errors: List[Dict[str, str]] = []
    jobs_read = 0

    try:
        paginator = sagemaker_client.get_paginator("list_processing_jobs")
        for page in paginator.paginate():
            for summary in page.get("ProcessingJobSummaries", []):
                job_name = summary.get("ProcessingJobName")
                if not job_name:
                    continue
                jobs_read += 1
                try:
                    detail = sagemaker_client.describe_processing_job(
                        ProcessingJobName=job_name
                    )
                except Exception as error:
                    describe_errors.append(
                        {"name": job_name, "label": get_assessment_error_label(error)}
                    )
                    continue
                network = detail.get("NetworkConfig")
                network = network if isinstance(network, dict) else {}
                vpc_config = network.get("VpcConfig")
                subnets = (
                    vpc_config.get("Subnets") if isinstance(vpc_config, dict) else None
                )
                isolated = network.get("EnableNetworkIsolation") is True
                if subnets:
                    in_vpc.append({"name": job_name, "subnets": list(subnets)})
                else:
                    without_vpc.append({"name": job_name, "isolated": isolated})
    except Exception as error:
        logger.warning(f"Could not list SageMaker processing jobs: {str(error)}")
        return [
            create_finding(
                check_id="SM-33",
                finding_name=PROCESSING_NETWORK_BOUNDARY_FINDING,
                finding_details=(
                    "SageMaker processing jobs could not be listed, so their "
                    "network placement was not read. Assessment error: "
                    f"{get_assessment_error_label(error)}."
                ),
                resolution="Grant sagemaker:ListProcessingJobs and retry.",
                reference=PROCESSING_NETWORK_BOUNDARY_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ], jobs_read

    for entry in without_vpc[:20]:
        isolation_note = (
            " Network isolation is on, which blocks the container's own egress "
            "but leaves it outside the customer VPC."
            if entry["isolated"]
            else " Network isolation is off as well."
        )
        rows.append(
            create_finding(
                check_id="SM-33",
                finding_name=PROCESSING_NETWORK_BOUNDARY_FINDING,
                finding_details=(
                    f"Processing job '{entry['name']}' ran with no "
                    "NetworkConfig.VpcConfig, so it ran in the SageMaker-managed "
                    f"network.{isolation_note}"
                ),
                resolution=PROCESSING_NETWORK_BOUNDARY_RESOLUTION,
                reference=PROCESSING_NETWORK_BOUNDARY_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if len(without_vpc) > 20:
        rows.append(
            create_finding(
                check_id="SM-33",
                finding_name=PROCESSING_NETWORK_BOUNDARY_FINDING,
                finding_details=(
                    f"{len(without_vpc)} of the {jobs_read} processing jobs ran "
                    "with no NetworkConfig.VpcConfig (the first 20 are reported "
                    "individually above)."
                ),
                resolution=PROCESSING_NETWORK_BOUNDARY_RESOLUTION,
                reference=PROCESSING_NETWORK_BOUNDARY_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if in_vpc:
        described = "; ".join(
            "{} in {}".format(entry["name"], ", ".join(entry["subnets"][:3]))
            for entry in in_vpc[:3]
        )
        rows.append(
            create_finding(
                check_id="SM-33",
                finding_name=PROCESSING_NETWORK_BOUNDARY_FINDING,
                finding_details=(
                    f"{len(in_vpc)} of the {jobs_read} processing jobs ran in "
                    f"customer subnets: {described}. Whether those subnets have "
                    "a route to an internet gateway is reported under "
                    f"'{PROCESSING_SUBNET_EXPOSURE_FINDING}'."
                ),
                resolution="No action required on the VPC attachment.",
                reference=PROCESSING_NETWORK_BOUNDARY_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    for entry in describe_errors[:5]:
        rows.append(
            create_finding(
                check_id="SM-33",
                finding_name=PROCESSING_NETWORK_BOUNDARY_FINDING,
                finding_details=(
                    f"Processing job '{entry['name']}' could not be assessed for "
                    f"network configuration. Assessment error: {entry['label']}."
                ),
                resolution="Grant sagemaker:DescribeProcessingJob and retry.",
                reference=PROCESSING_NETWORK_BOUNDARY_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    if len(describe_errors) > 5:
        rows.append(
            create_finding(
                check_id="SM-33",
                finding_name=PROCESSING_NETWORK_BOUNDARY_FINDING,
                finding_details=(
                    f"{len(describe_errors)} of the {jobs_read} processing jobs "
                    "could not be described (the first 5 are reported "
                    "individually above)."
                ),
                resolution="Grant sagemaker:DescribeProcessingJob and retry.",
                reference=PROCESSING_NETWORK_BOUNDARY_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    rows.extend(
        _subnet_exposure_findings(
            check_id="SM-33",
            finding_name=PROCESSING_SUBNET_EXPOSURE_FINDING,
            resources=[
                {
                    "name": f"Processing job '{entry['name']}'",
                    "subnets": entry["subnets"],
                }
                for entry in in_vpc
            ],
            region=region,
            reference=PROCESSING_NETWORK_BOUNDARY_REFERENCE,
            resolution=(
                "Run processing jobs with NetworkConfig.VpcConfig naming subnets "
                "whose route tables have no internet gateway route, or remove that "
                "route from the subnets' route tables."
            ),
            severity="Medium",
        )
    )
    return rows, jobs_read


def check_sagemaker_training_job_network_boundary(region: str = "") -> Dict[str, Any]:
    """
    SM-33: Verify training jobs run inside a customer VPC (AIR-SGM-TRN-01).

    SM-21 asserts this for AutoML jobs only. Network isolation and VpcConfig are
    reported separately because a job can be isolated with no VPC attachment, and
    an isolated job still has no private path to S3 or ECR without one. Every
    training job and every processing job is listed and described.
    """
    logger.debug("Starting check for SageMaker training job network boundary")
    findings = {"csv_data": []}
    try:
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_in_vpc = []
        jobs_without_vpc = []
        jobs_sampled = 0
        describe_errors = []

        paginator = sagemaker_client.get_paginator("list_training_jobs")
        # AIR-SGM-TRN-01 is a population claim, so every job is read.
        for page in paginator.paginate(SortBy="CreationTime", SortOrder="Descending"):
            for summary in page.get("TrainingJobSummaries", []):
                job_name = summary.get("TrainingJobName")
                if not job_name:
                    continue
                jobs_sampled += 1
                try:
                    detail = sagemaker_client.describe_training_job(
                        TrainingJobName=job_name
                    )
                except Exception as error:
                    describe_errors.append(
                        {
                            "name": job_name,
                            "label": get_assessment_error_label(error),
                        }
                    )
                    continue

                vpc_config = detail.get("VpcConfig")
                subnets = (
                    vpc_config.get("Subnets") if isinstance(vpc_config, dict) else None
                )
                isolated = detail.get("EnableNetworkIsolation") is True
                if subnets:
                    jobs_in_vpc.append(
                        {
                            "name": job_name,
                            "subnets": list(subnets),
                            "isolated": isolated,
                        }
                    )
                else:
                    jobs_without_vpc.append({"name": job_name, "isolated": isolated})

        processing_rows, processing_jobs = _processing_job_network_findings(
            sagemaker_client, region
        )

        if jobs_sampled == 0 and processing_jobs == 0 and not processing_rows:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-33",
                    finding_name=TRAINING_NETWORK_BOUNDARY_FINDING,
                    finding_details=(
                        "No SageMaker training or processing jobs found in "
                        f"{region or 'this region'}."
                    ),
                    resolution="No action required",
                    reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            return findings

        for entry in jobs_without_vpc[:20]:
            isolation_note = (
                " Network isolation is on, which blocks the container's own "
                "egress but leaves it outside the customer VPC."
                if entry["isolated"]
                else " Network isolation is off as well."
            )
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-33",
                    finding_name=TRAINING_NETWORK_BOUNDARY_FINDING,
                    finding_details=(
                        f"Training job '{entry['name']}' ran with no VpcConfig, so "
                        "it ran in the SageMaker-managed network."
                        f"{isolation_note}"
                    ),
                    resolution=TRAINING_NETWORK_BOUNDARY_RESOLUTION,
                    reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )

        if len(jobs_without_vpc) > 20:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-33",
                    finding_name=TRAINING_NETWORK_BOUNDARY_FINDING,
                    finding_details=(
                        f"{len(jobs_without_vpc)} of the {jobs_sampled} training "
                        "jobs ran with no VpcConfig (the first 20 are "
                        "reported individually above)."
                    ),
                    resolution=TRAINING_NETWORK_BOUNDARY_RESOLUTION,
                    reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )

        for entry in [job for job in jobs_in_vpc if not job["isolated"]][:20]:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-33",
                    finding_name=TRAINING_NETWORK_ISOLATION_FINDING,
                    finding_details=(
                        f"Training job '{entry['name']}' ran in customer subnets "
                        "with EnableNetworkIsolation off, so its container can "
                        "reach any destination its subnets route to. No API "
                        "records whether the job was an approved exception."
                    ),
                    resolution=(
                        "Set EnableNetworkIsolation=true on training jobs whose "
                        "algorithm does not need to call out, and require it with "
                        "the sagemaker:NetworkIsolation condition key."
                    ),
                    reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )

        described = "; ".join(
            "{} in {}".format(entry["name"], ", ".join(entry["subnets"][:3]))
            for entry in jobs_in_vpc[:3]
        )
        vpc_pass_details = (
            f"{len(jobs_in_vpc)} of the {jobs_sampled} training jobs ran in "
            f"customer subnets: {described}. "
            "Whether those subnets have a route to an internet gateway "
            f"is reported under '{TRAINING_SUBNET_EXPOSURE_FINDING}'."
        )
        if describe_errors:
            findings["csv_data"].append(
                _unread_resources_finding(
                    "SM-33",
                    TRAINING_NETWORK_BOUNDARY_FINDING,
                    [
                        f"training job '{entry['name']}' ({entry['label']})"
                        for entry in describe_errors
                    ],
                    vpc_pass_details,
                    TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    region,
                )
            )
        elif jobs_in_vpc:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-33",
                    finding_name=TRAINING_NETWORK_BOUNDARY_FINDING,
                    finding_details=(
                        f"{len(jobs_in_vpc)} of the {jobs_sampled} training jobs "
                        f"ran in customer subnets: {described}. "
                        "Whether those subnets have a route to an internet gateway "
                        f"is reported under '{TRAINING_SUBNET_EXPOSURE_FINDING}'. "
                        "Whether the job needed outbound access at all is a "
                        "workload decision the owner still has to confirm."
                    ),
                    resolution=(
                        "No action required on the VPC attachment. Review whether "
                        "the job needed outbound access at all."
                    ),
                    reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        findings["csv_data"].extend(
            _training_vpc_endpoint_findings(jobs_in_vpc, region)
        )

        # AIR-FND-NET-01: a job's VpcConfig subnets decide nothing about egress
        # until their route tables are read.
        findings["csv_data"].extend(
            _subnet_exposure_findings(
                check_id="SM-33",
                finding_name=TRAINING_SUBNET_EXPOSURE_FINDING,
                resources=[
                    {
                        "name": f"Training job '{entry['name']}'",
                        "subnets": entry["subnets"],
                    }
                    for entry in jobs_in_vpc
                ],
                region=region,
                reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                resolution=(
                    "Run training jobs with VpcConfig naming subnets whose route "
                    "tables have no internet gateway route, or remove that route "
                    "from the subnets' route tables."
                ),
                severity="Medium",
            )
        )
        findings["csv_data"].extend(processing_rows)

        return findings

    except Exception as error:
        logger.error(
            f"Error in check_sagemaker_training_job_network_boundary: {str(error)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-33",
                    finding_name=TRAINING_NETWORK_BOUNDARY_FINDING,
                    finding_details=build_could_not_assess_detail(error, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference=TRAINING_NETWORK_BOUNDARY_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


CREATION_GUARDRAIL_FINDING = "SageMaker Creation Guardrail"
CREATION_GUARDRAIL_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/security_iam_service-with-iam.html"
)

# The creation actions this control names, with the resource type each creates.
# A batch transform job takes its network posture from its model, so
# CreateModel carries the network keys and CreateTransformJob the KMS keys.
SAGEMAKER_GUARDED_CREATE_ACTIONS = (
    ("sagemaker:CreateTrainingJob", "training-job"),
    ("sagemaker:CreateEndpointConfig", "endpoint-config"),
    ("sagemaker:CreateNotebookInstance", "notebook-instance"),
    ("sagemaker:CreateModel", "model"),
    ("sagemaker:CreateTransformJob", "transform-job"),
)
# The creation actions that define sagemaker:VpcSubnets and
# sagemaker:VpcSecurityGroupIds. CreateTransformJob defines neither.
SAGEMAKER_NETWORK_CREATE_ACTIONS = (
    "sagemaker:CreateTrainingJob",
    "sagemaker:CreateEndpointConfig",
    "sagemaker:CreateNotebookInstance",
    "sagemaker:CreateModel",
)

# Each guardrail category as (action, key group) requirements. Every requirement
# must be enforced, and any one key of its group enforces it. Each key is listed
# as an ActionConditionKey of its action in the sagemaker service-reference JSON
# (read 2026-09-27). sagemaker:VolumeKmsKey and sagemaker:OutputKmsKey are listed
# service-wide but no action defines them, so a condition on either enforces
# nothing and neither is accepted.
SAGEMAKER_CREATION_GUARDRAILS = (
    (
        "encryption",
        (
            ("sagemaker:CreateTrainingJob", ("sagemaker:VolumeKmsKeyArn",)),
            ("sagemaker:CreateTrainingJob", ("sagemaker:OutputKmsKeyArn",)),
            (
                "sagemaker:CreateTrainingJob",
                ("sagemaker:InterContainerTrafficEncryption",),
            ),
            ("sagemaker:CreateEndpointConfig", ("sagemaker:VolumeKmsKeyArn",)),
            ("sagemaker:CreateNotebookInstance", ("sagemaker:VolumeKmsKeyArn",)),
            ("sagemaker:CreateTransformJob", ("sagemaker:VolumeKmsKeyArn",)),
            ("sagemaker:CreateTransformJob", ("sagemaker:OutputKmsKeyArn",)),
        ),
    ),
    (
        "approved network",
        tuple(
            (action, ("sagemaker:VpcSubnets", "sagemaker:VpcSecurityGroupIds"))
            for action in SAGEMAKER_NETWORK_CREATE_ACTIONS
        ),
    ),
    (
        "no direct internet access",
        (
            ("sagemaker:CreateTrainingJob", ("sagemaker:NetworkIsolation",)),
            ("sagemaker:CreateEndpointConfig", ("sagemaker:NetworkIsolation",)),
            ("sagemaker:CreateNotebookInstance", ("sagemaker:DirectInternetAccess",)),
            ("sagemaker:CreateModel", ("sagemaker:NetworkIsolation",)),
        ),
    ),
)

# Keys whose compliant request value is fixed. The other keys take the
# customer's approved KMS keys, subnets or security groups, so any value list is
# accepted for them.
CREATION_KEY_COMPLIANT_VALUES = {
    "sagemaker:intercontainertrafficencryption": "true",
    "sagemaker:networkisolation": "true",
    "sagemaker:directinternetaccess": "disabled",
    "sagemaker:rootaccess": "disabled",
}
CREATION_KEY_NONCOMPLIANT_VALUES = {
    "sagemaker:intercontainertrafficencryption": "false",
    "sagemaker:networkisolation": "false",
    "sagemaker:directinternetaccess": "enabled",
    "sagemaker:rootaccess": "enabled",
}
CREATION_PROBE_PARTITIONS = ("aws", "aws-cn", "aws-us-gov")
# AIR-SGM-EP-08: the batch transform path. A transform job takes its network
# posture from its model, so these two actions carry the whole guardrail.
BATCH_CREATION_GUARDRAIL_FINDING = "SageMaker Batch Transform Creation Guardrail"
BATCH_CREATION_GUARDRAIL_REFERENCE = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/batch-vpc.html"
)
SAGEMAKER_BATCH_CREATE_ACTIONS = (
    "sagemaker:CreateModel",
    "sagemaker:CreateTransformJob",
)
SAGEMAKER_BATCH_CREATION_GUARDRAILS = tuple(
    (
        category,
        tuple(r for r in requirements if r[0] in SAGEMAKER_BATCH_CREATE_ACTIONS),
    )
    for category, requirements in SAGEMAKER_CREATION_GUARDRAILS
)
# The ArrayOfString keys among them, per the sagemaker service-reference JSON.
MULTIVALUED_CREATION_KEYS = {"sagemaker:vpcsubnets", "sagemaker:vpcsecuritygroupids"}

NOTEBOOK_ACCESS_GUARDRAIL_FINDING = "SageMaker Notebook Access Guardrail"
NOTEBOOK_ACCESS_GUARDRAIL_REFERENCE = (
    "https://docs.aws.amazon.com/whitepapers/latest/"
    "sagemaker-studio-admin-best-practices/permissions-management.html"
)
# AIR-SGM-TRN-05: each key below is an ActionConditionKey of
# CreateNotebookInstance in the sagemaker service-reference JSON (read
# 2026-09-27). The two presigned-URL actions define no action keys, so the
# global aws:SourceIp and aws:SourceVpce keys restrict where they are called.
NOTEBOOK_ACCESS_GUARDRAILS = (
    ("sagemaker:CreateNotebookInstance", ("sagemaker:RootAccess",)),
    ("sagemaker:CreateNotebookInstance", ("sagemaker:DirectInternetAccess",)),
    (
        "sagemaker:CreateNotebookInstance",
        ("sagemaker:VpcSubnets", "sagemaker:VpcSecurityGroupIds"),
    ),
    ("sagemaker:CreateNotebookInstance", ("sagemaker:VolumeKmsKeyArn",)),
    (
        "sagemaker:CreatePresignedNotebookInstanceUrl",
        ("aws:SourceIp", "aws:SourceVpce"),
    ),
    ("sagemaker:CreatePresignedDomainUrl", ("aws:SourceIp", "aws:SourceVpce")),
)
GUARDED_ACTION_RESOURCE_TYPES = {
    **dict(SAGEMAKER_GUARDED_CREATE_ACTIONS),
    "sagemaker:CreatePresignedNotebookInstanceUrl": "notebook-instance",
    "sagemaker:CreatePresignedDomainUrl": "user-profile",
}
# A user profile ARN carries the domain id before the profile name.
GUARDED_RESOURCE_PROBE_PATHS = {"user-profile": "user-profile/d-zzprobe/zz-probe"}
MANAGEMENT_ACCOUNT_SCP_NOTE = (
    "Service control policies do not apply to the organization management "
    "account, so none guards SageMaker creation in this account."
)


def _sm_organization_policy_context() -> Dict[str, Any]:
    """
    Resolve the organization, this account and whether it is the management account.

    A member account can read policy documents and attachments only when it is a
    delegated administrator for Organizations policy management, so the reads are
    attempted and their failure is reported, instead of assuming either way.
    """
    context = {
        "state": "read",
        "detail": "",
        "resolution": "",
        "account": "",
        "management": False,
    }

    orgs_client = boto3.client("organizations", config=boto3_config)
    try:
        org_info = orgs_client.describe_organization()
        master_account_id = org_info["Organization"]["MasterAccountId"]
        context["account"] = boto3.client(
            "sts", config=boto3_config
        ).get_caller_identity()["Account"]
    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "")
        if error_code == "AWSOrganizationsNotInUseException":
            context["state"] = "none"
            context["detail"] = (
                "AWS Organizations is not in use for this account, so no service "
                "control policy can exist to enforce this control"
            )
            context["resolution"] = (
                "Enable AWS Organizations if an organization-wide preventive "
                "control is required."
            )
            return context
        if error_code in ACCESS_DENIED_ERROR_CODES:
            context["state"] = "unread"
            context["detail"] = (
                "the organization could not be read "
                f"({get_assessment_error_label(error)}), so service control "
                "policies were not enumerated"
            )
            context["resolution"] = (
                "Grant organizations:DescribeOrganization, "
                "organizations:ListPolicies and organizations:DescribePolicy to "
                "the assessment role."
            )
            return context
        raise

    context["management"] = context["account"] == master_account_id
    return context


def get_sagemaker_scp_inventory() -> Dict[str, Any]:
    """Read every service control policy document and its attachment targets once."""
    inventory = {"items": [], "errors": [], "list_error": None}
    orgs_client = boto3.client("organizations", config=boto3_config)

    try:
        policies = []
        paginator = orgs_client.get_paginator("list_policies")
        for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
            policies.extend(page.get("Policies", []))
    except Exception as error:
        inventory["list_error"] = get_assessment_error_label(error)
        return inventory

    for policy in policies:
        policy_id = policy.get("Id")
        if not policy_id:
            continue
        policy_name = policy.get("Name") or policy_id
        try:
            policy_detail = orgs_client.describe_policy(PolicyId=policy_id)
            content = (
                policy_detail.get("Policy", {}).get("Content")
                if isinstance(policy_detail, dict)
                else None
            )
        except Exception as error:
            inventory["errors"].append(f"policy '{policy_name}': {str(error)}")
            continue
        item = {"name": policy_name, "id": policy_id, "content": content}
        try:
            targets = []
            target_paginator = orgs_client.get_paginator("list_targets_for_policy")
            for page in target_paginator.paginate(PolicyId=policy_id):
                targets.extend(page.get("Targets", []))
            item["targets"] = targets
        except ClientError as error:
            item["targets_error"] = get_assessment_error_label(error)
        inventory["items"].append(item)

    return inventory


def _sm_account_policy_path(account_id: str) -> List[str]:
    """
    Return this account, every OU above it and the root, from ListParents.

    An SCP governs the account when it is attached to any of these.
    """
    orgs_client = boto3.client("organizations", config=boto3_config)
    path = [account_id]
    child = account_id
    # Organizations nests OUs at most five deep under the root.
    for _ in range(8):
        parents = []
        for page in orgs_client.get_paginator("list_parents").paginate(ChildId=child):
            parents.extend(page.get("Parents", []))
        if not parents or not parents[0].get("Id"):
            break
        path.append(parents[0]["Id"])
        if parents[0].get("Type") == "ROOT":
            break
        child = parents[0]["Id"]
    return path


def _condition_operator_parts(operator: str) -> tuple:
    """Split a condition operator into (set prefix, base operator, IfExists)."""
    name = str(operator).strip().lower()
    prefix = ""
    for candidate in ("forallvalues:", "foranyvalue:"):
        if name.startswith(candidate):
            prefix = candidate[:-1]
            name = name[len(candidate) :]
    if_exists = name.endswith("ifexists")
    if if_exists:
        name = name[: -len("ifexists")]
    return prefix, name, if_exists


def _condition_entries(statement: Dict[str, Any]) -> List[tuple]:
    """Return (operator, lowercased key, lowercased values) for each condition."""
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return []
    entries = []
    for operator, block in condition.items():
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            entries.append(
                (
                    str(operator),
                    str(key).lower(),
                    [str(item).lower() for item in _policy_values(value)],
                )
            )
    return entries


def _statement_names_action(statement: Dict[str, Any], action: str) -> bool:
    """Return whether a statement's Action or NotAction reaches action."""
    if "Action" in statement:
        return any(
            _iam_action_matches(p, action) for p in _policy_values(statement["Action"])
        )
    if "NotAction" in statement:
        return not any(
            _iam_action_matches(p, action)
            for p in _policy_values(statement["NotAction"])
        )
    return False


def _deny_covers_every_resource(statement: Dict[str, Any], resource_type: str) -> bool:
    """Return whether a Deny's Resource matches every resource of that type."""
    if "NotResource" in statement:
        return False
    for pattern in _policy_values(statement.get("Resource")):
        for partition in CREATION_PROBE_PARTITIONS:
            path = GUARDED_RESOURCE_PROBE_PATHS.get(
                resource_type, f"{resource_type}/zz-probe"
            )
            probe = f"arn:{partition}:sagemaker:zz-probe-1:000000000000:{path}"
            if _iam_action_matches(pattern, probe):
                return True
    return False


def _deny_guard_strength(statement: Dict[str, Any], keys: tuple) -> Optional[str]:
    """
    Classify how a Deny statement holds one key group.

    "enforced": it fires when the key is absent or holds a non-compliant value.
    "presence": it fires when the key is absent but admits a non-compliant
    value: a Null test, a negated Like or Arn operator on a wildcard value, a
    NotIpAddress on aws:SourceIp values that cover every address, or
    ForAllValues on a multivalued key, which admits a request that mixes an
    approved value with an unapproved one. "value": it fires only for one named value whose
    compliance this check does not judge. "absent-open": it fires for a
    non-compliant value but not when the request omits the key. A "presence"
    and an "absent-open" Deny together enforce the key. "conjunctive": the key
    shares the statement with other conditions, so the deny fires only when all
    of them hold. "undefined-operator": a negated operator on a multivalued
    key with no ForAllValues or ForAnyValue prefix, which IAM does not define,
    so it earns no credit. None: the key is not named.
    """
    entries = _condition_entries(statement)
    matched = [entry for entry in entries if entry[1] in keys]
    if not matched:
        return None
    if len(entries) > 1:
        return "conjunctive"
    operator, key, values = matched[0]
    prefix, base, if_exists = _condition_operator_parts(operator)
    if base == "null":
        return "presence" if "true" in values else "value"
    if "not" in base:
        if not prefix and key in MULTIVALUED_CREATION_KEYS:
            return "undefined-operator"
        # A negated operator is true for an absent key, except under
        # ForAnyValue, which is false over an empty set.
        if _like_values_unbounded(base, values) or _source_ip_values_unbounded(
            key, values
        ):
            return "value" if prefix == "foranyvalue" else "presence"
        if prefix == "foranyvalue":
            return "absent-open"
        if prefix == "forallvalues" and key in MULTIVALUED_CREATION_KEYS:
            return "presence"
        return "enforced"
    noncompliant = CREATION_KEY_NONCOMPLIANT_VALUES.get(key)
    if noncompliant is not None and noncompliant in values:
        if if_exists or prefix == "forallvalues":
            return "enforced"
        return "absent-open"
    return "value"


def _deny_pair_enforces(strengths: set) -> bool:
    """A Deny that fires on an absent key and one that fires on a
    non-compliant value together enforce the key."""
    return "enforced" in strengths or {"presence", "absent-open"} <= strengths


def _like_values_unbounded(base: str, values: List[str]) -> bool:
    """Return whether a Like or Arn operator's values hold a wildcard, which
    admits values beyond any approved list. ArnEquals and ArnNotEquals match
    wildcards exactly as ArnLike and ArnNotLike do."""
    return ("like" in base or base.startswith("arn")) and any(
        "*" in v or "?" in v for v in values
    )


def _source_ip_values_unbounded(key: str, values: List[str]) -> bool:
    """Return whether aws:SourceIp values together cover every IPv4 or every
    IPv6 address, as 0.0.0.0/0 or ::/0 do, so they approve no range."""
    if key != "aws:sourceip":
        return False
    networks = {4: [], 6: []}
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        networks[network.version].append(network)
    return any(
        [str(n) for n in ipaddress.collapse_addresses(found)]
        == [("0.0.0.0/0" if version == 4 else "::/0")]
        for version, found in networks.items()
        if found
    )


def _allow_enforces_key(statement: Dict[str, Any], keys: tuple) -> bool:
    """
    Return whether an Allow grants only requests that carry a compliant key.

    IfExists and negated operators match a request that omits the key, so
    neither enforces it. ForAllValues does too, unless the statement also holds
    a Null false test on the same key. A Null test, a Like or Arn operator
    on a wildcard value, and aws:SourceIp values that cover every address
    require only that the key is present. ForAnyValue on a multivalued key
    admits a request that mixes an approved value with an unapproved one, and
    IAM does not define a multivalued key under no set operator.
    """
    entries = _condition_entries(statement)
    required = {
        key
        for operator, key, values in entries
        if _condition_operator_parts(operator)[1] == "null" and values == ["false"]
    }
    for operator, key, values in entries:
        if key not in keys:
            continue
        prefix, base, if_exists = _condition_operator_parts(operator)
        if if_exists or "not" in base:
            continue
        if (
            base == "null"
            or _like_values_unbounded(base, values)
            or _source_ip_values_unbounded(key, values)
        ):
            continue
        if prefix == "forallvalues" and key not in required:
            continue
        if key in MULTIVALUED_CREATION_KEYS and prefix != "forallvalues":
            continue
        compliant = CREATION_KEY_COMPLIANT_VALUES.get(key)
        if compliant is None or (values and all(v == compliant for v in values)):
            return True
    return False


def _statements_leave_creation_open(
    allow_statements: List[Dict[str, Any]], action: str, keys: tuple
) -> bool:
    """Return whether an Allow reaches action with no condition enforcing keys."""
    return any(
        _statement_allows_action(statement, action)
        and not _allow_enforces_key(statement, keys)
        for statement in allow_statements
    )


def _denies_enforce(
    statements: List[Dict[str, Any]], action: str, resource_type: str, keys: tuple
) -> bool:
    return _deny_pair_enforces(
        {
            _deny_guard_strength(statement, keys)
            for statement in statements
            if str(statement.get("Effect", "")).upper() == "DENY"
            and _statement_names_action(statement, action)
            and _deny_covers_every_resource(statement, resource_type)
        }
    )


def _statements_condition_key(
    statements: List[Dict[str, Any]], action: str, keys: tuple
) -> bool:
    """Return whether an Allow or Deny reaching action has a condition on keys."""
    for statement in statements:
        effect = str(statement.get("Effect", "")).upper()
        if effect == "ALLOW" and not _statement_allows_action(statement, action):
            continue
        if effect == "DENY" and not _statement_names_action(statement, action):
            continue
        if any(key in keys for _, key, _ in _condition_entries(statement)):
            return True
    return False


def _open_principals_text(identity: Dict[str, Any]) -> str:
    """Name the open principals, split by whether any condition names the key."""
    groups = []
    for principals, verb in (
        (
            [p for p in identity["principals"] if p not in identity["conditioned"]],
            "can call it with no condition on that key",
        ),
        (
            identity["conditioned"],
            "can call it under a condition on that key that does not enforce it",
        ),
    ):
        if not principals:
            continue
        shown = ", ".join(principals[:5])
        if len(principals) > 5:
            shown += f" and {len(principals) - 5} more"
        groups.append(f"{shown} {verb}")
    return ", and ".join(groups)


def _creation_identity_leg(
    permission_cache: Optional[Dict[str, Any]], action: str, keys: tuple
) -> Dict[str, Any]:
    """
    Report which cached principals can call action without the key enforced.

    A permissions boundary is an intersection: a principal is open only when
    both its identity policies and its boundary allow the call without the key.
    """
    if permission_cache is None:
        return {"state": "unread", "principals": [], "v1": False}
    resource_type = GUARDED_ACTION_RESOURCE_TYPES[action]
    open_principals = []
    conditioned = []
    for identity_type, cache_key in (
        ("Role", "role_permissions"),
        ("User", "user_permissions"),
    ):
        for name, permissions in (permission_cache.get(cache_key) or {}).items():
            statements = []
            for policy in [
                *(permissions.get("attached_policies") or []),
                *(permissions.get("inline_policies") or []),
                *(permissions.get("group_policies") or []),
            ]:
                statements.extend(_sm_policy_statements(policy.get("document")))
            boundary = permissions.get("permissions_boundary")
            boundary_statements = (
                _sm_policy_statements(boundary) if boundary is not None else []
            )
            if _denies_enforce(
                statements + boundary_statements, action, resource_type, keys
            ):
                continue
            if not _statements_leave_creation_open(statements, action, keys):
                continue
            if boundary is not None and not _statements_leave_creation_open(
                boundary_statements, action, keys
            ):
                continue
            # An unread boundary may close the call; the principal is already
            # named among the cache's unread principals.
            if boundary is None and (
                identity_type.lower(),
                name,
            ) in _boundary_unread(permission_cache):
                continue
            open_principals.append(f"{identity_type} '{name}'")
            if _statements_condition_key(
                statements + boundary_statements, action, keys
            ):
                conditioned.append(f"{identity_type} '{name}'")
    unread = _principal_read_errors(permission_cache)
    if open_principals:
        return {
            "state": "open",
            "principals": open_principals,
            "conditioned": conditioned,
            "v1": unread is None,
        }
    if unread:
        return {"state": "incomplete", "principals": unread, "v1": False}
    return {"state": "guarded", "principals": [], "v1": unread is None}


def _creation_scp_leg(scp: Dict[str, Any], action: str, keys: tuple) -> Dict[str, Any]:
    """
    Report whether an SCP governing this account enforces keys on action.

    Returns a state of "enforced", "unattached", "value", "presence",
    "absent-open", "conjunctive", "undefined-operator", "attachment-unread",
    "missing" or the
    leg-wide state ("none", "unread", "exempt"), with the policy names behind
    it. An attached "presence" Deny and an attached "absent-open" Deny that
    both cover every resource are "enforced" together.
    """
    if scp["state"] != "read":
        return {"state": scp["state"], "policies": []}
    resource_type = GUARDED_ACTION_RESOURCE_TYPES[action]
    found = {}
    halves = {}
    for item in scp["items"]:
        for statement in _sm_policy_statements(item.get("content")):
            if str(statement.get("Effect", "")).upper() != "DENY":
                continue
            if not _statement_names_action(statement, action):
                continue
            strength = _deny_guard_strength(statement, keys)
            if strength is None:
                continue
            if strength in (
                "enforced",
                "undefined-operator",
            ) and not _deny_covers_every_resource(statement, resource_type):
                strength = "conjunctive"
            if "targets_error" in item:
                attachment = "attachment-unread"
            elif not {
                target.get("TargetId") for target in item.get("targets") or []
            } & set(scp["path"]):
                attachment = "unattached"
            else:
                attachment = "attached"
            if strength == "enforced" and attachment != "attached":
                strength = attachment
            elif strength in ("presence", "absent-open") and (
                _deny_covers_every_resource(statement, resource_type)
            ):
                halves.setdefault((strength, attachment), [])
                if item["name"] not in halves[(strength, attachment)]:
                    halves[(strength, attachment)].append(item["name"])
            found.setdefault(strength, [])
            if item["name"] not in found[strength]:
                found[strength].append(item["name"])
    # A presence Deny and a value Deny enforce together, and the pair is only
    # as attached as its least attached half.
    admitted = []
    pair_state = None
    for state in ("attached", "attachment-unread", "unattached"):
        admitted.append(state)
        pair = {
            strength: names
            for (strength, attachment), names in halves.items()
            if attachment in admitted
        }
        if "enforced" not in found and _deny_pair_enforces(set(pair)):
            names = [n for names in pair.values() for n in names]
            if state == "attached":
                found["enforced"] = list(dict.fromkeys(names))
            else:
                pair_state = {"state": state, "policies": list(dict.fromkeys(names))}
            break
    if "enforced" not in found and scp.get("unread_policies"):
        return {"state": "documents-unread", "policies": scp["unread_policies"]}
    if "enforced" not in found and pair_state:
        return pair_state
    for state in (
        "enforced",
        "attachment-unread",
        "conjunctive",
        "undefined-operator",
        "value",
        "presence",
        "absent-open",
        "unattached",
    ):
        if state in found:
            return {"state": state, "policies": found[state]}
    return {"state": "missing", "policies": []}


def _creation_requirement_label(action: str, keys: tuple) -> str:
    return f"{action.split(':', 1)[1]} on {' or '.join(keys)}"


def _creation_scp_reason(scp_leg: Dict[str, Any], scp: Dict[str, Any]) -> str:
    names = ", ".join(f"'{name}'" for name in scp_leg["policies"][:3])
    state = scp_leg["state"]
    if state in ("none", "unread", "exempt"):
        return scp["detail"]
    if state == "documents-unread":
        return (
            f"{len(scp_leg['policies'])} service control policy document(s) could "
            f"not be read ({'; '.join(scp_leg['policies'][:5])})"
        )
    if state == "attachment-unread":
        return f"the attachment of service control policy {names} could not be read"
    if state == "unattached":
        return (
            f"service control policy {names} enforces it but is not attached to "
            "this account, an OU above it or the root"
        )
    if state == "conjunctive":
        return (
            f"service control policy {names} names the key alongside other "
            "conditions or on named resources only, so it denies only when all of "
            "them hold"
        )
    if state == "undefined-operator":
        return (
            f"service control policy {names} denies with an operator IAM does not "
            "define for a multivalued key, so it earns no credit"
        )
    if state == "value":
        return (
            f"service control policy {names} denies one named value, so whether "
            "the guardrail holds depends on that value"
        )
    if state == "absent-open":
        return (
            f"service control policy {names} does not deny a request that omits the key"
        )
    if state == "presence":
        return (
            f"service control policy {names} denies only a request that omits "
            "the key, so it admits any value"
        )
    return "no service control policy Deny on this action names the key"


CREATION_GUARDRAIL_RESOLUTION = (
    "Deny the named create action in a service control policy "
    "attached above this account when the key is outside the approved "
    "values (ArnNotEquals or StringNotEquals, which also fire when the key "
    "is absent), or add an Allow condition naming the approved values to "
    "every policy that grants the action. A Null test alone admits any "
    "value. Use sagemaker:VolumeKmsKeyArn and "
    "sagemaker:OutputKmsKeyArn: the short key names are defined by no "
    "action and enforce nothing."
)


def _creation_category_finding(
    category: str,
    requirements: tuple,
    scp: Dict[str, Any],
    permission_cache: Optional[Dict[str, Any]],
    region: str,
    check_id: str = "SM-34",
    finding_name: str = CREATION_GUARDRAIL_FINDING,
    reference: str = CREATION_GUARDRAIL_REFERENCE,
    resolution: str = CREATION_GUARDRAIL_RESOLUTION,
    scope: str = "at SageMaker creation time",
    consequence: str = (
        "A non-compliant resource can be created and is only detected afterwards."
    ),
) -> Dict[str, Any]:
    met = []
    failed = []
    unresolved = []
    v1 = False
    used_identity = False
    for action, keys in requirements:
        label = _creation_requirement_label(action, keys)
        scp_leg = _creation_scp_leg(scp, action, tuple(k.lower() for k in keys))
        if scp_leg["state"] == "enforced":
            met.append(
                f"{label} by service control policy "
                f"{', '.join(repr(n) for n in scp_leg['policies'][:3])}"
            )
            continue
        identity = _creation_identity_leg(
            permission_cache, action, tuple(k.lower() for k in keys)
        )
        v1 = v1 or identity["v1"]
        scp_reason = _creation_scp_reason(scp_leg, scp)
        if identity["state"] == "guarded":
            # AIR-SGM-TRN-08: identity policies bind roles and users only. The
            # account root user is bound by no identity policy, so without an
            # attached SCP it can still make the call without the key.
            used_identity = True
            failed.append(
                f"{label}: {scp_reason}, and although the identity policies of "
                "every IAM role and user that can call it enforce it, the account "
                "root user is bound by no identity policy and can call it with no "
                "condition on that key"
            )
        elif identity["state"] == "open" and scp_leg["state"] in (
            "missing",
            "presence",
            "absent-open",
            "unattached",
            "none",
            "exempt",
        ):
            failed.append(
                f"{label}: {scp_reason}, and {_open_principals_text(identity)}"
            )
        elif identity["state"] == "open":
            unresolved.append(
                f"{label}: {scp_reason}, and {_open_principals_text(identity)}"
            )
        elif identity["state"] == "incomplete":
            unresolved.append(
                f"{label}: {scp_reason}, and the IAM cache recorded read errors for "
                f"{', '.join(identity['principals'][:10])}"
            )
        else:
            unresolved.append(
                f"{label}: {scp_reason}, and identity policies were not read "
                "because the IAM permissions cache was not available"
            )

    total = len(requirements)
    identity_notes = (
        f" {MANAGEMENT_ACCOUNT_SCP_NOTE}"
        if scp["state"] == "exempt"
        else f" {SCP_NOT_EVALUATED_NOTE}"
    )
    if v1:
        identity_notes += f" {UNRECORDED_PRINCIPAL_ERRORS_NOTE}"
    if failed:
        return create_finding(
            check_id=check_id,
            finding_name=finding_name,
            finding_details=(
                f"{len(failed)} of {total} {category} requirements are not "
                f"enforced {scope}: {'; '.join(failed[:3])}. "
                f"{consequence}{identity_notes}"
            ),
            resolution=resolution,
            reference=reference,
            severity="Medium",
            status="Failed",
            region=region,
        )
    if unresolved:
        return create_finding(
            check_id=check_id,
            finding_name=f"{finding_name} Incomplete",
            finding_details=(
                f"{len(unresolved)} of {total} {category} requirements could not be "
                f"established: {'; '.join(unresolved[:3])}. This check recognises "
                "a Deny that fires both when the key is absent and when it holds "
                "a non-compliant value (a negated operator naming the approved "
                "values, or an IfExists form naming the non-compliant value) as "
                f"the only condition of its statement.{identity_notes}"
            ),
            resolution=(
                "Restate the deny with a negated operator naming the approved "
                "values, which also fires when the key is absent, and resolve "
                "the unread reads named above."
            ),
            reference=reference,
            severity="Informational",
            status="N/A",
            region=region,
        )
    return create_finding(
        check_id=check_id,
        finding_name=finding_name,
        finding_details=(
            f"All {total} {category} requirements are enforced {scope} "
            f"for account {scp['account'] or 'unknown'}: "
            f"{'; '.join(met)}.{identity_notes if used_identity else ''}"
        ),
        resolution="No action required",
        reference=reference,
        severity="Medium",
        status="Passed",
        region=region,
    )


def _creation_scp_state(scp_inventory: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Resolve which service control policies govern this account, or why not."""
    scp = _sm_organization_policy_context()
    scp["items"] = []
    scp["path"] = []
    scp["unread_policies"] = []
    if scp["state"] == "read":
        inventory = (
            scp_inventory
            if scp_inventory is not None
            else get_sagemaker_scp_inventory()
        )
        if inventory.get("list_error"):
            scp["state"] = "unread"
            scp["detail"] = (
                "service control policies could not be listed from account "
                f"{scp['account']} ({inventory['list_error']}). A member account "
                "reads them only as a delegated administrator for "
                "Organizations policy management; otherwise run the "
                "assessment from the management account"
            )
            scp["resolution"] = (
                "Grant organizations:ListPolicies, organizations:DescribePolicy, "
                "organizations:ListTargetsForPolicy and organizations:ListParents "
                "to the assessment role."
            )
        elif scp["management"]:
            scp["state"] = "exempt"
            scp["detail"] = (
                f"this assessment ran in the management account "
                f"{scp['account']}, which service control policies do not govern"
            )
        else:
            scp["items"] = inventory.get("items", [])
            try:
                scp["path"] = _sm_account_policy_path(scp["account"])
            except ClientError as error:
                scp["state"] = "unread"
                scp["detail"] = (
                    "the account's path to the organization root could not be "
                    f"read with organizations:ListParents "
                    f"({get_assessment_error_label(error)}), so which service "
                    "control policies govern it is unknown"
                )
        scp["unread_policies"] = [
            entry.split(":")[0] for entry in inventory.get("errors", [])
        ]
    return scp


def check_sagemaker_creation_guardrails(
    region: str = "",
    scp_inventory: Dict[str, Any] = None,
    permission_cache: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    SM-34: Verify creation of unencrypted, internet-exposed or non-VPC SageMaker
    resources is denied at creation time (AIR-SGM-TRN-08).

    One verdict per guardrail category. Each (action, key) requirement is met by
    a Deny in a service control policy attached on this account's path to the
    root. A condition on the key in every identity policy that grants the action
    still fails, because the account root user is bound by no identity policy.
    """
    logger.debug("Starting check for SageMaker creation guardrails")
    return _creation_guardrail_findings(
        region,
        scp_inventory,
        permission_cache,
        SAGEMAKER_CREATION_GUARDRAILS,
        check_id="SM-34",
        finding_name=CREATION_GUARDRAIL_FINDING,
        reference=CREATION_GUARDRAIL_REFERENCE,
    )


def check_sagemaker_batch_creation_guardrails(
    region: str = "",
    scp_inventory: Dict[str, Any] = None,
    permission_cache: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    SM-42: Verify CreateModel and CreateTransformJob are held to the encryption,
    network and isolation guardrails at creation time (AIR-SGM-EP-08).

    The SM-34 legs, over the batch transform path only, so a training or
    notebook gap does not fail this verdict. Regional, so it shares a
    (account, region) key with the SM-18 transform job rows.
    """
    logger.debug("Starting check for SageMaker batch creation guardrails")
    return _creation_guardrail_findings(
        region,
        scp_inventory,
        permission_cache,
        SAGEMAKER_BATCH_CREATION_GUARDRAILS,
        check_id="SM-42",
        finding_name=BATCH_CREATION_GUARDRAIL_FINDING,
        reference=BATCH_CREATION_GUARDRAIL_REFERENCE,
        scope="on the SageMaker batch transform path",
        consequence=(
            "A transform job can run on a model outside the approved network or "
            "write results under an unapproved key, and is only detected "
            "afterwards."
        ),
    )


def _creation_guardrail_findings(
    region: str,
    scp_inventory: Optional[Dict[str, Any]],
    permission_cache: Optional[Dict[str, Any]],
    guardrails: tuple,
    check_id: str,
    finding_name: str,
    reference: str,
    **category_kwargs: Any,
) -> Dict[str, Any]:
    """One creation guardrail verdict per category of guardrails."""
    findings = {"csv_data": []}
    try:
        scp = _creation_scp_state(scp_inventory)

        if scp["state"] != "read" and permission_cache is None:
            findings["csv_data"].append(
                create_finding(
                    check_id=check_id,
                    finding_name=finding_name,
                    finding_details=(
                        "Creation guardrails for SageMaker were not assessed: "
                        f"{scp['detail']}. The IAM permissions cache was not "
                        "available, so identity-policy conditions were not read "
                        "either."
                    ),
                    resolution=scp["resolution"] or COULD_NOT_ASSESS_RESOLUTION,
                    reference=reference,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            return findings

        for category, requirements in guardrails:
            findings["csv_data"].append(
                _creation_category_finding(
                    category,
                    requirements,
                    scp,
                    permission_cache,
                    region,
                    check_id=check_id,
                    finding_name=finding_name,
                    reference=reference,
                    **category_kwargs,
                )
            )
        return findings

    except Exception as error:
        logger.error(
            f"Error in {check_id} creation guardrail check: {str(error)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id=check_id,
                    finding_name=finding_name,
                    finding_details=build_could_not_assess_detail(error, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference=reference,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


def check_sagemaker_notebook_access_guardrails(
    region: str = "",
    scp_inventory: Dict[str, Any] = None,
    permission_cache: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    SM-09: Verify notebook creation and presigned-URL access are held by IAM
    conditions (AIR-SGM-TRN-05).

    Each (action, key) requirement is met by a Deny in a service control policy
    attached on this account's path to the root. A condition on the key in every
    identity policy that grants the action still fails, because the account root
    user is bound by no identity policy.
    """
    logger.debug("Starting check for SageMaker notebook access guardrails")
    try:
        scp = _creation_scp_state(scp_inventory)
        if scp["state"] != "read" and permission_cache is None:
            return {
                "csv_data": [
                    create_finding(
                        check_id="SM-09",
                        finding_name=NOTEBOOK_ACCESS_GUARDRAIL_FINDING,
                        finding_details=(
                            "Notebook access guardrails were not assessed: "
                            f"{scp['detail']}. The IAM permissions cache was not "
                            "available, so identity-policy conditions were not "
                            "read either."
                        ),
                        resolution=scp["resolution"] or COULD_NOT_ASSESS_RESOLUTION,
                        reference=NOTEBOOK_ACCESS_GUARDRAIL_REFERENCE,
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                ]
            }
        return {
            "csv_data": [
                _creation_category_finding(
                    "notebook access",
                    NOTEBOOK_ACCESS_GUARDRAILS,
                    scp,
                    permission_cache,
                    region,
                    check_id="SM-09",
                    finding_name=NOTEBOOK_ACCESS_GUARDRAIL_FINDING,
                    reference=NOTEBOOK_ACCESS_GUARDRAIL_REFERENCE,
                    resolution=(
                        "Deny sagemaker:CreateNotebookInstance in a service control "
                        "policy attached above this account when RootAccess or "
                        "DirectInternetAccess is not Disabled, or VpcSubnets or "
                        "VolumeKmsKeyArn is absent, and deny "
                        "CreatePresignedNotebookInstanceUrl and "
                        "CreatePresignedDomainUrl outside the approved aws:SourceIp "
                        "range or aws:SourceVpce. An Allow condition on the key in "
                        "every policy that grants the action also holds it."
                    ),
                    scope="for SageMaker notebook and Studio access",
                    consequence=(
                        "A notebook can be created, or a notebook or Studio URL "
                        "issued, outside the production access bar."
                    ),
                )
            ]
        }
    except Exception as error:
        logger.error(
            f"Error in check_sagemaker_notebook_access_guardrails: {str(error)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-09",
                    finding_name=NOTEBOOK_ACCESS_GUARDRAIL_FINDING,
                    finding_details=build_could_not_assess_detail(error, region),
                    resolution=COULD_NOT_ASSESS_RESOLUTION,
                    reference=NOTEBOOK_ACCESS_GUARDRAIL_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        }


DELEGATED_ADMIN_FINDING = "Security Service Delegated Administrator"
DELEGATED_ADMIN_REFERENCE = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_delegated_admin.html"

# The security services whose administration SM-35 asserts. A fixed list: the
# report names it so a reader knows which services were and were not examined.
SECURITY_SERVICE_PRINCIPALS = (
    ("Amazon GuardDuty", "guardduty.amazonaws.com"),
    ("AWS Security Hub", "securityhub.amazonaws.com"),
    ("Amazon Inspector", "inspector2.amazonaws.com"),
    ("Amazon Macie", "macie.amazonaws.com"),
    ("AWS Config", "config.amazonaws.com"),
    ("AWS Config multi-account setup", "config-multiaccountsetup.amazonaws.com"),
    ("IAM Access Analyzer", "access-analyzer.amazonaws.com"),
    ("AWS CloudTrail", "cloudtrail.amazonaws.com"),
    ("Amazon Detective", "detective.amazonaws.com"),
    ("Amazon Security Lake", "securitylake.amazonaws.com"),
    ("AWS Firewall Manager", "fms.amazonaws.com"),
    ("AWS Audit Manager", "auditmanager.amazonaws.com"),
)
SECURITY_SERVICE_LIST_TEXT = ", ".join(name for name, _ in SECURITY_SERVICE_PRINCIPALS)
# Principal names no live ListAWSServiceAccessForOrganization read has returned,
# so an absent one may be a name the service does not use for trusted access.
UNCONFIRMED_TRUSTED_ACCESS_PRINCIPALS = frozenset(
    {
        "macie.amazonaws.com",
        "detective.amazonaws.com",
        "fms.amazonaws.com",
        "auditmanager.amazonaws.com",
    }
)
DELEGATED_ADMIN_CONSOLIDATION_FINDING = (
    "Security Service Delegated Administrator Consolidation"
)


def check_security_service_delegated_admin(region: str = "") -> Dict[str, Any]:
    """
    SM-35: Verify each security service is administered from a delegated
    administrator account that is not the organization management account
    (AIR-FND-ACC-09). One row per service.
    """
    logger.debug("Starting check for security service delegated administrators")
    findings = {"csv_data": []}
    scope_note = f"Services checked (fixed list): {SECURITY_SERVICE_LIST_TEXT}."

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-35",
            finding_name=DELEGATED_ADMIN_FINDING,
            finding_details=f"{details} {scope_note}",
            resolution=resolution,
            reference=DELEGATED_ADMIN_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    orgs_client = boto3.client("organizations", config=boto3_config)
    try:
        master_account_id = orgs_client.describe_organization()["Organization"][
            "MasterAccountId"
        ]
    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "")
        if error_code == "AWSOrganizationsNotInUseException":
            details = (
                "AWS Organizations is not in use for this account, so no "
                "security service can have a delegated administrator."
            )
            resolution = (
                "Create an organization with a dedicated security tooling "
                "account if AI workloads span more than one account."
            )
        else:
            details = build_could_not_assess_detail(error, region)
            resolution = COULD_NOT_ASSESS_RESOLUTION
        findings["csv_data"].append(_row(details, resolution, "Informational", "N/A"))
        return findings
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
        return findings

    enabled_principals = set()
    trusted_access_error = ""
    try:
        paginator = orgs_client.get_paginator(
            "list_aws_service_access_for_organization"
        )
        for page in paginator.paginate():
            enabled_principals.update(
                item.get("ServicePrincipal")
                for item in page.get("EnabledServicePrincipals", [])
            )
    except Exception as error:
        trusted_access_error = get_assessment_error_label(error)

    admins_by_service = {}
    unread_services = []
    for service_name, principal in SECURITY_SERVICE_PRINCIPALS:
        try:
            admins = []
            paginator = orgs_client.get_paginator("list_delegated_administrators")
            for page in paginator.paginate(ServicePrincipal=principal):
                admins.extend(page.get("DelegatedAdministrators", []))
        except ClientError as error:
            if error.response.get("Error", {}).get("Code", "") in (
                ACCESS_DENIED_ERROR_CODES
            ):
                details = (
                    f"Delegated administrators for {service_name} ({principal}) "
                    "could not be listed "
                    f"({get_assessment_error_label(error)}). The list is readable "
                    "only from the management account or a delegated "
                    "administrator account."
                )
            else:
                details = (
                    f"{service_name} ({principal}): "
                    f"{build_could_not_assess_detail(error, region)}"
                )
            findings["csv_data"].append(
                _row(details, COULD_NOT_ASSESS_RESOLUTION, "Informational", "N/A")
            )
            unread_services.append(service_name)
            continue
        except Exception as error:
            unread_services.append(service_name)
            findings["csv_data"].append(
                _row(
                    f"{service_name} ({principal}): "
                    f"{build_could_not_assess_detail(error, region)}",
                    COULD_NOT_ASSESS_RESOLUTION,
                    "Informational",
                    "N/A",
                )
            )
            continue

        active = [admin for admin in admins if admin.get("Status") == "ACTIVE"]
        dedicated = sorted(
            str(admin.get("Id"))
            for admin in active
            if admin.get("Id") and admin.get("Id") != master_account_id
        )
        admins_by_service[service_name] = dedicated
        administered = (
            f"{service_name} ({principal}) is administered from delegated "
            f"administrator account {', '.join(dedicated)}, which is not "
            "the organization management account."
        )
        if dedicated and trusted_access_error:
            findings["csv_data"].append(
                _row(
                    f"{administered} Whether trusted access is enabled for "
                    f"{principal} was not read "
                    "(organizations:ListAWSServiceAccessForOrganization: "
                    f"{trusted_access_error}).",
                    COULD_NOT_ASSESS_RESOLUTION,
                    "Informational",
                    "N/A",
                )
            )
        elif dedicated and principal not in enabled_principals:
            unconfirmed = (
                f" The trusted-access principal name {principal} is not confirmed "
                "by a live read, so the service may enable trusted access under "
                "another name."
                if principal in UNCONFIRMED_TRUSTED_ACCESS_PRINCIPALS
                else ""
            )
            findings["csv_data"].append(
                _row(
                    f"{administered} Trusted access for {principal} is not "
                    "enabled: the principal is absent from the organization's "
                    "enabled service principals "
                    f"(ListAWSServiceAccessForOrganization).{unconfirmed}",
                    f"Enable trusted access for {service_name} in AWS "
                    "Organizations so the delegated administrator can act "
                    "across member accounts.",
                    "High",
                    "Failed",
                )
            )
        elif dedicated:
            findings["csv_data"].append(
                _row(
                    f"{administered} Trusted access for {principal} is enabled.",
                    "No action required",
                    "High",
                    "Passed",
                )
            )
        elif active:
            findings["csv_data"].append(
                _row(
                    f"The only active delegated administrator for {service_name} "
                    f"({principal}) is the organization management account "
                    f"{master_account_id}.",
                    f"Register a dedicated security tooling account as the "
                    f"{service_name} delegated administrator and administer the "
                    "service from there.",
                    "High",
                    "Failed",
                )
            )
        else:
            findings["csv_data"].append(
                _row(
                    f"No active delegated administrator is registered for "
                    f"{service_name} ({principal}), so the service is "
                    "administered from the organization management account or "
                    "not administered organization-wide.",
                    f"Register a dedicated security tooling account as the "
                    f"{service_name} delegated administrator.",
                    "High",
                    "Failed",
                )
            )

    findings["csv_data"].append(
        _delegated_admin_consolidation_finding(
            admins_by_service, unread_services, region
        )
    )
    return findings


def _delegated_admin_consolidation_finding(
    admins_by_service: Dict[str, List[str]],
    unread_services: List[str],
    region: str,
) -> Dict[str, Any]:
    """
    Report whether every security service shares one non-management administrator.

    Administrator-member relationships do not carry across services, so two
    services administered from different accounts split the security view.
    """
    accounts = {}
    for service_name, dedicated in admins_by_service.items():
        for account_id in dedicated:
            accounts.setdefault(account_id, []).append(service_name)
    without = [name for name, dedicated in admins_by_service.items() if not dedicated]

    def _row(details, resolution, severity, status, name=None):
        return create_finding(
            check_id="SM-35",
            finding_name=name or DELEGATED_ADMIN_CONSOLIDATION_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=DELEGATED_ADMIN_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    if len(accounts) > 1:
        split = "; ".join(
            f"account {account_id}: {', '.join(services)}"
            for account_id, services in sorted(accounts.items())
        )
        return _row(
            f"The security services are administered from {len(accounts)} "
            f"different non-management accounts ({split}). Administrator-member "
            "relationships do not carry across services, so no single account "
            "holds the whole security view.",
            "Move every security service's delegated administrator to the one "
            "security tooling account.",
            "Medium",
            "Failed",
        )
    if without:
        return _row(
            f"Not every security service has a non-management delegated "
            f"administrator ({', '.join(without)}), so the services are not "
            "administered from one security tooling account.",
            "Register the same security tooling account as delegated administrator "
            "for each service named.",
            "Medium",
            "Failed",
        )
    if unread_services or not accounts:
        return _row(
            "Whether every security service shares one delegated administrator "
            "was not established: the administrators of "
            f"{', '.join(unread_services)} could not be listed.",
            COULD_NOT_ASSESS_RESOLUTION,
            "Informational",
            "N/A",
            name=f"{DELEGATED_ADMIN_CONSOLIDATION_FINDING} Incomplete",
        )
    (account_id,) = accounts
    return _row(
        f"All {len(admins_by_service)} security services checked "
        f"({SECURITY_SERVICE_LIST_TEXT}) are administered from the one "
        f"non-management account {account_id}. Whether that account is a "
        "dedicated security tooling account and not an AI workload account is "
        "not recorded by any Organizations API and was not assessed.",
        "No action required",
        "Medium",
        "Passed",
    )


REGIONAL_ADMIN_FINDING = "Security Service Regional Delegated Administrator"
REGIONAL_ADMIN_REFERENCE = (
    "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_organizations.html"
)


def _account_and_status(response, key, account_field, status_field):
    record = response.get(key) or {}
    return record.get(account_field), record.get(status_field)


def _regional_admin(
    get_administrator, read_self_admin, account_id: str
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(administrator, how it was read, unread reason) for one service.

    get_administrator returns (administrator id, relationship status), or
    (None, None). Only an Enabled relationship counts. A caller with no
    administrator is its own when read_self_admin succeeds, because only an
    administrator can read its organization configuration.
    """
    try:
        administrator, status = get_administrator()
    except Exception as error:
        return None, None, get_assessment_error_label(error)
    if administrator and str(status).lower() == "enabled":
        return administrator, "administers this account as a member", None
    if administrator:
        return (
            None,
            f"a member of {administrator} with relationship status {status}",
            None,
        )
    try:
        read_self_admin()
    except ClientError as error:
        if error.response.get("Error", {}).get("Code", "") in (
            ACCESS_DENIED_ERROR_CODES
        ):
            return None, None, get_assessment_error_label(error)
        return (
            None,
            f"not the administrator ({get_assessment_error_label(error)})",
            None,
        )
    except Exception as error:
        return None, None, get_assessment_error_label(error)
    return (
        account_id,
        "is this account, which reads the organization configuration",
        None,
    )


def check_regional_security_admin(
    region: str = "", detector_inventory: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    SM-35: Verify GuardDuty, Security Hub and Amazon Inspector are administered
    in this Region from one delegated administrator that is not the
    organization management account (AIR-FND-ACC-09).

    Each of these services designates its administrator per Region, so the
    organization-wide delegated administrator list does not show a Region
    where the service has none. The admin listing APIs answer only the
    management account; a member reads its own administrator instead.
    """
    findings = {"csv_data": []}

    def _row(details, resolution, severity, status, name=REGIONAL_ADMIN_FINDING):
        return create_finding(
            check_id="SM-35",
            finding_name=name,
            finding_details=details,
            resolution=resolution,
            reference=REGIONAL_ADMIN_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        account_id = boto3.client(
            "sts", config=boto3_config, region_name=region
        ).get_caller_identity()["Account"]
        master_account_id = boto3.client(
            "organizations", config=boto3_config
        ).describe_organization()["Organization"]["MasterAccountId"]
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
        return findings

    detector_inventory = detector_inventory or get_guardduty_detector_inventory(region)
    admins, problems, unread = {}, [], []
    guardduty = boto3.client("guardduty", config=boto3_config, region_name=region)
    detector_id = detector_inventory.get("detector_id")
    if detector_inventory.get("error") is not None:
        unread.append(
            "Amazon GuardDuty (guardduty:ListDetectors: "
            f"{get_assessment_error_label(detector_inventory['error'])})"
        )
    elif not detector_id:
        problems.append(
            "Amazon GuardDuty has no detector in this Region, so no administrator "
            "administers it here"
        )
    else:
        admins["Amazon GuardDuty"] = _regional_admin(
            lambda: _account_and_status(
                guardduty.get_administrator_account(DetectorId=detector_id),
                "Administrator",
                "AccountId",
                "RelationshipStatus",
            ),
            lambda: guardduty.describe_organization_configuration(
                DetectorId=detector_id
            ),
            account_id,
        )
    securityhub = boto3.client("securityhub", config=boto3_config, region_name=region)
    admins["AWS Security Hub"] = _regional_admin(
        lambda: _account_and_status(
            securityhub.get_administrator_account(),
            "Administrator",
            "AccountId",
            "MemberStatus",
        ),
        securityhub.describe_organization_configuration,
        account_id,
    )
    inspector = boto3.client("inspector2", config=boto3_config, region_name=region)

    def _inspector_admin():
        try:
            return _account_and_status(
                inspector.get_delegated_admin_account(),
                "delegatedAdmin",
                "accountId",
                "relationshipStatus",
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code", "") in (
                "ResourceNotFoundException",
                "ValidationException",
            ):
                return None, None
            raise

    def _inspector_self():
        # GetDelegatedAdminAccount answers the delegated administrator itself
        # with a ValidationException naming it as the invoking account.
        try:
            inspector.get_delegated_admin_account()
        except ClientError as error:
            message = str(error.response.get("Error", {}).get("Message", ""))
            if "Invoking account is the delegated admin" in message:
                return
            raise

    admins["Amazon Inspector"] = _regional_admin(
        _inspector_admin, _inspector_self, account_id
    )

    dedicated = {}
    for service, (administrator, how, reason) in admins.items():
        if reason:
            unread.append(f"{service} ({reason})")
        elif administrator is None:
            problems.append(
                f"{service} has no delegated administrator for this account in this "
                f"Region: this account is {how}"
            )
        elif administrator == master_account_id:
            problems.append(
                f"{service} is administered from the organization management "
                f"account {master_account_id}"
            )
        else:
            dedicated.setdefault(administrator, []).append(service)
    if len(dedicated) > 1:
        problems.append(
            "the services are administered from "
            f"{len(dedicated)} different accounts ("
            + "; ".join(
                f"account {account}: {', '.join(services)}"
                for account, services in sorted(dedicated.items())
            )
            + "), and administrator-member relationships do not carry across "
            "services"
        )

    if problems:
        findings["csv_data"].append(
            _row(
                f"In {region}, " + "; ".join(problems) + ".",
                "Designate the same dedicated security tooling account as the "
                "delegated administrator of GuardDuty, Security Hub and Amazon "
                "Inspector in every Region, and enroll this account as a member.",
                "High",
                "Failed",
            )
        )
    if unread:
        findings["csv_data"].append(
            _unread_resources_finding(
                "SM-35",
                REGIONAL_ADMIN_FINDING,
                unread,
                f"{sum(len(v) for v in dedicated.values())} service(s) were read "
                "with a non-management administrator.",
                REGIONAL_ADMIN_REFERENCE,
                region,
            )
        )
    if not problems and not unread:
        ((administrator, services),) = dedicated.items()
        findings["csv_data"].append(
            _row(
                f"In {region}, {', '.join(services)} are all administered from "
                f"account {administrator}, which is not the organization "
                "management account. Each Region is judged by its own run, so "
                "whether every Region names the same account is not compared here.",
                "No action required",
                "High",
                "Passed",
            )
        )
    return findings


AI_SECURITY_STANDARD_FINDING = "Security Hub AI Security Best Practices Standard"
AI_SECURITY_STANDARD_REFERENCE = "https://docs.aws.amazon.com/securityhub/latest/userguide/standards-ai-security.html"
AI_SECURITY_STANDARD_ARN_FRAGMENT = "standards/ai-security-best-practices/v/1.0.0"
AI_SECURITY_STANDARD_RESOLUTION = (
    "Enable the AWS Security Hub AI Security Best Practices v1.0.0 standard in "
    "this region so AI resource configuration is evaluated continuously."
)


CENTRAL_CONFIGURATION_FINDING = "Security Hub Central Configuration"
CENTRAL_CONFIGURATION_REFERENCE = (
    "https://docs.aws.amazon.com/securityhub/latest/userguide/"
    "central-configuration-intro.html"
)
SELF_MANAGED_CONFIGURATION_POLICY_ID = "SELF_MANAGED_SECURITY_HUB"


def _central_configuration_association_finding(region: str, row) -> Dict[str, Any]:
    """SM-36: read the configuration policy association of this account.

    GetConfigurationPolicyAssociation answers only for the Security Hub
    delegated administrator in the home Region, so any other caller reads N/A.
    Whether an associated policy enables the AI standard is in the policy
    itself, which only securityhub:GetConfigurationPolicy returns, and only to
    the delegated administrator, so a member account's ceiling is N/A.
    """
    try:
        account_id = boto3.client(
            "sts", config=boto3_config, region_name=region
        ).get_caller_identity()["Account"]
        client = boto3.client("securityhub", config=boto3_config, region_name=region)
        association = client.get_configuration_policy_association(
            Target={"AccountId": account_id}
        )
    except Exception as error:
        return row(
            "Security Hub central configuration is enabled for the organization "
            "(ConfigurationType CENTRAL, Status ENABLED), but the configuration "
            "policy associated with this account was not read: "
            "securityhub:GetConfigurationPolicyAssociation failed. It answers only "
            "for the Security Hub delegated administrator in the home Region. "
            + build_could_not_assess_detail(error, region),
            COULD_NOT_ASSESS_RESOLUTION,
            "Informational",
            "N/A",
            name=f"{CENTRAL_CONFIGURATION_FINDING} Incomplete",
        )
    policy_id = str(association.get("ConfigurationPolicyId") or "")
    status = str(association.get("AssociationStatus") or "")
    how = str(association.get("AssociationType") or "not returned").lower()
    if policy_id == SELF_MANAGED_CONFIGURATION_POLICY_ID:
        return row(
            f"Under central configuration, this account ({account_id}) is "
            f"associated ({how}) with self-managed behavior, so the account "
            "enables its own standards and no configuration policy enforces the "
            "AI Security Best Practices standard on it.",
            "From the Security Hub delegated administrator, associate this account "
            "with a configuration policy that enables the AI Security Best "
            "Practices standard.",
            "Medium",
            "Failed",
        )
    if status == "FAILED":
        return row(
            f"The association of configuration policy {policy_id or 'not returned'} "
            f"with this account ({account_id}) is in AssociationStatus FAILED, so "
            "the policy is not applied: "
            f"{association.get('AssociationStatusMessage') or 'no status message'}.",
            "Resolve the association failure from the Security Hub delegated "
            "administrator.",
            "Medium",
            "Failed",
        )
    return row(
        f"This account ({account_id}) is associated ({how}) with configuration "
        f"policy {policy_id or 'not returned'}, in AssociationStatus "
        f"{status or 'not returned'}, as securityhub:"
        "GetConfigurationPolicyAssociation reports. Whether that policy enables "
        "the AI Security Best Practices standard was not read: the configuration "
        "policy's enabled standards and controls are returned only by "
        "securityhub:GetConfigurationPolicy, which only the Security Hub delegated "
        "administrator can call, from its home Region.",
        f"From the Security Hub delegated administrator in its home Region, "
        f"confirm that configuration policy {policy_id or 'not returned'} lists "
        "the AI Security Best Practices standard among its enabled standards.",
        "Informational",
        "N/A",
        name=f"{CENTRAL_CONFIGURATION_FINDING} Incomplete",
    )


def _security_hub_central_configuration_finding(region: str) -> Dict[str, Any]:
    """SM-36: Security Hub standards are enforced org-wide only under CENTRAL."""

    def _row(details, resolution, severity, status, name=CENTRAL_CONFIGURATION_FINDING):
        return create_finding(
            check_id="SM-36",
            finding_name=name,
            finding_details=details,
            resolution=resolution,
            reference=CENTRAL_CONFIGURATION_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        client = boto3.client("securityhub", config=boto3_config, region_name=region)
        configuration = client.describe_organization_configuration().get(
            "OrganizationConfiguration", {}
        )
    except Exception as error:
        return _row(
            "Security Hub central configuration was not read: "
            "DescribeOrganizationConfiguration failed. It can be called from the "
            "Security Hub delegated administrator account, so a run in any other "
            "account cannot read it. " + build_could_not_assess_detail(error, region),
            COULD_NOT_ASSESS_RESOLUTION,
            "Informational",
            "N/A",
            name=f"{CENTRAL_CONFIGURATION_FINDING} Incomplete",
        )
    configuration_type = configuration.get("ConfigurationType")
    configuration_status = configuration.get("Status")
    if configuration_type == "CENTRAL" and configuration_status == "ENABLED":
        return _central_configuration_association_finding(region, _row)
    if configuration_type == "CENTRAL":
        return _row(
            "Security Hub central configuration was requested but is in Status "
            f"{configuration_status}, so no configuration policy is being applied.",
            "Resolve the central configuration StatusMessage from the Security Hub "
            "delegated administrator.",
            "Medium",
            "Failed",
        )
    return _row(
        f"Security Hub uses ConfigurationType {configuration_type or 'not returned'}, "
        "so each account and region enables its own standards and nothing "
        "enforces the AI Security Best Practices standard across the organization.",
        "From the Security Hub delegated administrator, turn on central "
        "configuration and associate a configuration policy that enables the AI "
        "Security Best Practices standard with every AI workload account.",
        "Medium",
        "Failed",
    )


def check_security_hub_ai_standard(region: str = "") -> Dict[str, Any]:
    """SM-36: Verify the Security Hub AI Security Best Practices standard is on."""
    logger.debug("Starting check for the Security Hub AI security standard")
    findings = {"csv_data": []}

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-36",
            finding_name=AI_SECURITY_STANDARD_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=AI_SECURITY_STANDARD_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        client = boto3.client("securityhub", config=boto3_config, region_name=region)
        subscriptions = []
        paginator = client.get_paginator("get_enabled_standards")
        for page in paginator.paginate():
            subscriptions.extend(page.get("StandardsSubscriptions", []))
    except ClientError as error:
        if error.response.get("Error", {}).get("Code", "") == "InvalidAccessException":
            findings["csv_data"].append(
                _row(
                    "Security Hub is not enabled in this region, so the AI "
                    "Security Best Practices standard is not evaluating any "
                    "resource.",
                    AI_SECURITY_STANDARD_RESOLUTION,
                    "High",
                    "Failed",
                )
            )
            return findings
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
        return findings
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
        return findings

    matching = [
        subscription
        for subscription in subscriptions
        if AI_SECURITY_STANDARD_ARN_FRAGMENT
        in str(subscription.get("StandardsArn", ""))
    ]
    active = [
        subscription
        for subscription in matching
        if subscription.get("StandardsStatus") in ("READY", "INCOMPLETE")
    ]
    if active:
        status = active[0].get("StandardsStatus")
        details = (
            f"The AI Security Best Practices v1.0.0 standard is enabled "
            f"(status {status})."
        )
        if status == "INCOMPLETE":
            details += (
                " Some of its controls could not be enabled; review the standard's "
                "StatusReason in Security Hub."
            )
        findings["csv_data"].append(
            _row(details, "No action required", "High", "Passed")
        )
    elif matching:
        findings["csv_data"].append(
            _row(
                "The AI Security Best Practices v1.0.0 standard subscription is in "
                f"status {matching[0].get('StandardsStatus')}, so its controls are "
                "not evaluating resources.",
                AI_SECURITY_STANDARD_RESOLUTION,
                "High",
                "Failed",
            )
        )
    else:
        findings["csv_data"].append(
            _row(
                f"Security Hub is enabled with {len(subscriptions)} standard(s), "
                "but not the AI Security Best Practices v1.0.0 standard.",
                AI_SECURITY_STANDARD_RESOLUTION,
                "High",
                "Failed",
            )
        )
    findings["csv_data"].append(_security_hub_central_configuration_finding(region))
    return findings


def _guardduty_feature(detail: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    for feature in detail.get("Features") or []:
        if feature.get("Name") == name:
            return feature
    return None


LAMBDA_NETWORK_LOGS_FINDING = "GuardDuty Lambda Protection"
LAMBDA_NETWORK_LOGS_REFERENCE = (
    "https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection.html"
)


def check_guardduty_lambda_network_logs(
    region: str = "", detector_inventory: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    SM-37: Verify GuardDuty Lambda Protection (LAMBDA_NETWORK_LOGS) is enabled,
    so anomalous network activity from AI workload functions is detected.
    """
    findings = {"csv_data": []}

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-37",
            finding_name=LAMBDA_NETWORK_LOGS_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=LAMBDA_NETWORK_LOGS_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        inventory = detector_inventory or get_guardduty_detector_inventory(region)
        if inventory.get("error"):
            raise inventory["error"]
        if not inventory.get("detector_id"):
            findings["csv_data"].append(
                _row(
                    "No GuardDuty detector found; Lambda Protection cannot be "
                    "assessed separately.",
                    "Enable GuardDuty first, then enable Lambda Protection.",
                    "Informational",
                    "N/A",
                )
            )
            return findings
        detail = inventory.get("detail") or {}
        feature = _guardduty_feature(detail, "LAMBDA_NETWORK_LOGS")
        if detail.get("Status") != "ENABLED":
            findings["csv_data"].append(
                _row(
                    "The GuardDuty detector is not enabled, so Lambda network "
                    "activity is not monitored.",
                    "Enable the GuardDuty detector and its Lambda Protection "
                    "feature in this region.",
                    "Medium",
                    "Failed",
                )
            )
        elif feature and feature.get("Status") == "ENABLED":
            findings["csv_data"].append(
                _row(
                    "GuardDuty Lambda Protection (LAMBDA_NETWORK_LOGS) is enabled, "
                    "so network activity from Lambda functions is monitored for "
                    "anomalous destinations.",
                    "No action required",
                    "Medium",
                    "Passed",
                )
            )
        else:
            state = feature.get("Status") if feature else "absent"
            findings["csv_data"].append(
                _row(
                    "GuardDuty is enabled, but the LAMBDA_NETWORK_LOGS feature is "
                    f"{state}, so network activity from Lambda functions is not "
                    "monitored.",
                    "Enable GuardDuty Lambda Protection for this region.",
                    "Medium",
                    "Failed",
                )
            )
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
    return findings


ENDPOINT_FLOW_LOG_ALERTING_FINDING = "SageMaker Endpoint Network Anomaly Alerting"
ENDPOINT_FLOW_LOG_ALERTING_REFERENCE = (
    "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-cwl.html"
)
ENDPOINT_FLOW_LOG_ALERTING_RESOLUTION = (
    "Publish VPC Flow Logs (traffic type ALL or ACCEPT) for every VPC or subnet "
    "an endpoint runs in to CloudWatch Logs, add a metric filter on that log "
    "group, and alarm on the metric with a static threshold or an anomaly "
    "detection band that has an alarm action."
)
ENDPOINT_FLOW_LOG_SCOPE_NOTE = (
    "GuardDuty foundational flow-log analysis covers EC2 network interfaces, not "
    "SageMaker endpoints, so the customer flow log is the only network telemetry "
    "for an endpoint, and AgentCore Runtime yields none either, so each runtime in "
    "VPC network mode is judged like an endpoint and one in PUBLIC mode fails. The "
    "state "
    "named for each alarm is its current StateValue, and its last entry into "
    "ALARM comes from the metric alarm's own StateUpdate history. An alarm with "
    "no action of its own is credited when an OR of ALARM() terms carries it to "
    "a composite alarm with an action, and that composite's own last entry into "
    "ALARM is read too, through cloudwatch:DescribeAlarmHistory with the "
    "CompositeAlarm type. Neither history result changes the status: an alarm that "
    "has never entered ALARM still passes, and a history read that fails is "
    "named in the row without holding back Passed. Whether a fired alarm was "
    "triaged is not recorded by any CloudWatch API. An alarm is credited only "
    "when it reads the dimension names and unit the filter publishes, and its "
    "static threshold is judged only when the filter publishes literal values. "
    "Pattern terms and field equalities are matched against the tokens of the "
    "default flow-log format, so a field only a custom log format carries is "
    "not recognized."
)
FLOW_LOG_ALERTING_TRAFFIC_TYPES = ("ALL", "ACCEPT")
FLOW_LOG_RECORD_TERM = re.compile(
    r"^(ACCEPT|REJECT|OK|NODATA|SKIPDATA|-|\d[\d.:]*|[0-9a-f]*:[0-9a-f:]*"
    r"|(eni|vpc|subnet|i)-[0-9a-f]+)$"
)
FLOW_LOG_FIELD_CONDITION = re.compile(r"^\s*[\w.-]*\s*(!=|>=|<=|=|>|<)\s*(.*?)\s*$")


def _bracketed_pattern_selects_flow_records(pattern: str) -> bool:
    """
    Whether a space-delimited pattern's field conditions can hold on a record.

    Only an equality to a literal no flow-log record carries rules a field out;
    a wildcard value, an OR (||) of conditions and every comparison other than
    = are taken to hold.
    """
    for field in pattern[1 : pattern.rfind("]")].split(","):
        if "||" in field:
            continue
        for condition in field.split("&&"):
            match = FLOW_LOG_FIELD_CONDITION.match(condition)
            if not match or match.group(1) != "=":
                continue
            value = match.group(2).strip('"')
            if "*" not in value and not FLOW_LOG_RECORD_TERM.match(value):
                return False
    return True


def _filter_pattern_selects_flow_records(metric_filter: Dict[str, Any]) -> bool:
    """
    Whether a metric filter's pattern can match a default flow-log record.

    Flow-log records are space-delimited text. An empty pattern matches every
    record and a bracketed pattern selects its fields; a JSON pattern matches
    only when the filter runs on transformed logs. A term pattern matches only
    when every required term, and at least one optional (?) term, is a token a
    flow-log record carries; exclusion (-) terms never stop a match.
    """
    pattern = (metric_filter.get("filterPattern") or "").strip()
    if not pattern:
        return True
    if pattern.startswith("["):
        return _bracketed_pattern_selects_flow_records(pattern)
    if pattern.startswith("{"):
        return bool(metric_filter.get("applyOnTransformedLogs"))
    required, optional = [], []
    for term in pattern.split():
        if term.startswith("-"):
            continue
        bucket = optional if term.startswith("?") else required
        bucket.append(term.lstrip("?").strip('"'))
    if not required and not optional:
        return True
    return all(FLOW_LOG_RECORD_TERM.match(t) for t in required) and (
        not optional or any(FLOW_LOG_RECORD_TERM.match(t) for t in optional)
    )


COMPOSITE_ALARM_TERM = re.compile(r'\bALARM\(\s*"?([^")]+?)"?\s*\)')


def _composite_rule_alarms(rule: str) -> List[str]:
    """
    The alarms whose ALARM state alone puts a composite alarm in ALARM.

    Only a rule that joins ALARM() terms with OR credits them. A rule holding
    AND, NOT, OK(), INSUFFICIENT_DATA(), TRUE or FALSE credits none, because a
    child in ALARM can leave that composite out of ALARM.
    """
    names = COMPOSITE_ALARM_TERM.findall(rule or "")
    rest = COMPOSITE_ALARM_TERM.sub(" ", rule or "").replace("(", " ").replace(")", " ")
    if not names or any(token != "OR" for token in rest.split()):
        return []
    return [name.strip() for name in names]


def _actioned_alarms(
    metric_alarms: List[Dict[str, Any]], composite_alarms: List[Dict[str, Any]]
) -> Dict[str, Optional[str]]:
    """
    Map each alarm whose ALARM state reaches an alarm action to the composite
    alarm that carries the action, or None when the alarm carries its own.
    """
    names = {}
    for alarm in metric_alarms + composite_alarms:
        names[alarm.get("AlarmName")] = alarm.get("AlarmName")
        if alarm.get("AlarmArn"):
            names[alarm["AlarmArn"]] = alarm.get("AlarmName")
    actioned = {
        alarm.get("AlarmName"): None
        for alarm in metric_alarms + composite_alarms
        if alarm.get("ActionsEnabled") and alarm.get("AlarmActions")
    }
    changed = True
    while changed:
        changed = False
        for composite in composite_alarms:
            parent = composite.get("AlarmName")
            if parent not in actioned:
                continue
            for reference in _composite_rule_alarms(composite.get("AlarmRule")):
                child = names.get(reference, reference)
                if child not in actioned:
                    actioned[child] = actioned[parent] or parent
                    changed = True
    return actioned


def _alarm_last_fired(
    cloudwatch_client, alarm_name: str, alarm_type: str = "MetricAlarm"
) -> str:
    """When an alarm last entered ALARM, from its StateUpdate history."""
    try:
        for page in cloudwatch_client.get_paginator("describe_alarm_history").paginate(
            AlarmName=alarm_name,
            AlarmTypes=[alarm_type],
            HistoryItemType="StateUpdate",
            ScanBy="TimestampDescending",
        ):
            for item in page.get("AlarmHistoryItems", []):
                if item.get("AlarmName") not in (None, alarm_name):
                    continue
                try:
                    data = json.loads(item.get("HistoryData") or "{}")
                except (TypeError, ValueError):
                    continue
                new_state = data.get("newState") if isinstance(data, dict) else None
                if isinstance(new_state, dict) and new_state.get("stateValue") == (
                    "ALARM"
                ):
                    timestamp = item.get("Timestamp")
                    if hasattr(timestamp, "isoformat"):
                        timestamp = timestamp.isoformat()
                    return f"last entered ALARM at {timestamp or 'an unreturned time'}"
    except Exception as error:
        return (
            "alarm history not read (cloudwatch:DescribeAlarmHistory: "
            f"{get_assessment_error_label(error)})"
        )
    return "no entry into ALARM in the alarm history CloudWatch returned"


def _alarm_metrics(alarm: Dict[str, Any]) -> List[tuple]:
    """
    Every (namespace, metric name) a metric alarm evaluates, with the series
    it reads: its dimension names, its unit, and, for a single-metric alarm,
    the statistic it compares with its threshold.
    """
    metrics = []
    if alarm.get("MetricName"):
        metrics.append(
            (
                (alarm.get("Namespace"), alarm.get("MetricName")),
                {
                    "dimensions": {
                        d.get("Name") for d in alarm.get("Dimensions") or []
                    },
                    "unit": alarm.get("Unit"),
                    "statistic": alarm.get("Statistic")
                    or alarm.get("ExtendedStatistic"),
                    "operator": alarm.get("ComparisonOperator"),
                    "threshold": alarm.get("Threshold"),
                },
            )
        )
    for query in alarm.get("Metrics") or []:
        metric_stat = query.get("MetricStat") or {}
        metric = metric_stat.get("Metric") or {}
        if metric.get("MetricName"):
            metrics.append(
                (
                    (metric.get("Namespace"), metric.get("MetricName")),
                    {
                        "dimensions": {
                            d.get("Name") for d in metric.get("Dimensions") or []
                        },
                        "unit": metric_stat.get("Unit"),
                    },
                )
            )
    return metrics


BOUNDED_ALARM_STATISTIC = re.compile(r"^(Maximum|Minimum|Average|p\d+(\.\d+)?)$")


def _alarm_cannot_fire(
    transformation: Dict[str, Any], series: Dict[str, Any]
) -> Optional[str]:
    """
    Why an alarm on a metric filter's metric can never enter ALARM, or None.

    The alarm reads nothing when its dimension names differ from those the
    filter publishes, or when it names a unit other than the filter's (None
    when the filter sets none). When the filter publishes only literal values,
    a static threshold that no statistic of those values can cross is never
    breached: no statistic of values at or above zero falls below zero, and a
    Maximum, Minimum, Average or percentile never exceeds the largest value.
    """
    published = set(transformation.get("dimensions") or {})
    if series["dimensions"] != published:
        return (
            f"it reads dimension(s) {', '.join(sorted(series['dimensions'])) or 'none'}"
            f" and the filter publishes {', '.join(sorted(published)) or 'none'}"
        )
    unit = transformation.get("unit") or "None"
    if series["unit"] and series["unit"] != unit:
        return f"it reads unit {series['unit']} and the filter publishes unit {unit}"
    operator, threshold = series.get("operator"), series.get("threshold")
    if threshold is None:
        return None
    values = [transformation.get("metricValue")]
    if transformation.get("defaultValue") is not None:
        values.append(transformation["defaultValue"])
    try:
        values = [float(value) for value in values]
    except (TypeError, ValueError):
        return None
    statistic = series.get("statistic") or ""
    bounded = BOUNDED_ALARM_STATISTIC.match(statistic) or (
        statistic == "Sum" and not any(values)
    )
    compare = f"{statistic or 'its statistic'} {operator} {threshold:g}"
    shown = ", ".join(f"{value:g}" for value in values)
    if min(values) >= 0 and (
        (operator == "LessThanThreshold" and threshold <= 0)
        or (operator == "LessThanOrEqualToThreshold" and threshold < 0)
    ):
        return f"it compares {compare} and the filter publishes only {shown}"
    if bounded and (
        (operator == "GreaterThanThreshold" and threshold >= max(values))
        or (operator == "GreaterThanOrEqualToThreshold" and threshold > max(values))
    ):
        return f"it compares {compare} and the filter publishes only {shown}"
    return None


def _agentcore_runtime_subnets(
    region: str,
) -> Tuple[Dict[str, List[str]], List[str]]:
    """The subnets of each AgentCore runtime; an empty list for PUBLIC mode."""
    try:
        client = boto3.client(
            "bedrock-agentcore-control", config=boto3_config, region_name=region
        )
        runtimes = []
        for page in client.get_paginator("list_agent_runtimes").paginate():
            runtimes.extend(page.get("agentRuntimes", []))
    except Exception as error:
        return {}, [
            f"bedrock-agentcore:ListAgentRuntimes ({get_assessment_error_label(error)})"
        ]
    subnets, unread = {}, []
    for runtime in runtimes:
        name = runtime.get("agentRuntimeName") or runtime.get("agentRuntimeId")
        try:
            detail = client.get_agent_runtime(agentRuntimeId=runtime["agentRuntimeId"])
        except Exception as error:
            unread.append(
                f"AgentCore runtime '{name}' "
                f"(bedrock-agentcore:GetAgentRuntime: {get_assessment_error_label(error)})"
            )
            continue
        network = detail.get("networkConfiguration") or {}
        subnets[name] = (
            sorted((network.get("networkModeConfig") or {}).get("subnets") or [])
            if network.get("networkMode") == "VPC"
            else []
        )
    return subnets, unread


def check_sagemaker_endpoint_flow_log_alerting(region: str = "") -> Dict[str, Any]:
    """
    SM-37: Verify every SageMaker endpoint's and AgentCore runtime's network
    carries alerting telemetry.

    An endpoint or runtime passes only when each subnet it runs in is covered by an ACTIVE
    VPC or subnet flow log that captures accepted traffic into CloudWatch Logs,
    and that log group has a metric filter whose pattern can match a flow-log
    record and whose metric an alarm with an action evaluates on the series the
    filter publishes, with a threshold the published values can cross.
    """
    findings = {"csv_data": []}

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-37",
            finding_name=ENDPOINT_FLOW_LOG_ALERTING_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=ENDPOINT_FLOW_LOG_ALERTING_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        inventory = _endpoint_hosting_inventory(sagemaker_client)
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
        return findings

    unread = list(inventory["unread"])
    endpoint_subnets = {}
    model_subnets = {}
    for endpoint in inventory["endpoints"]:
        subnets = set((endpoint["config"].get("VpcConfig") or {}).get("Subnets") or [])
        model_unread = False
        for model_name in endpoint["models"]:
            if model_name not in model_subnets:
                try:
                    model = sagemaker_client.describe_model(ModelName=model_name)
                    model_subnets[model_name] = list(
                        (model.get("VpcConfig") or {}).get("Subnets") or []
                    )
                except Exception as error:
                    model_subnets[model_name] = None
                    unread.append(
                        f"model '{model_name}' of endpoint '{endpoint['name']}' "
                        f"({get_assessment_error_label(error)})"
                    )
            if model_subnets[model_name] is None:
                model_unread = True
            else:
                subnets.update(model_subnets[model_name])
        if not model_unread:
            endpoint_subnets[f"endpoint '{endpoint['name']}'"] = sorted(subnets)
    runtime_subnets, runtime_unread = _agentcore_runtime_subnets(region)
    unread.extend(runtime_unread)
    for name, subnets in runtime_subnets.items():
        endpoint_subnets[f"AgentCore runtime '{name}'"] = subnets

    if not inventory["endpoints"] and not runtime_subnets and not unread:
        findings["csv_data"].append(
            _row(
                "No SageMaker endpoints or AgentCore runtimes were found in this "
                "region.",
                "No action required",
                "Informational",
                "N/A",
            )
        )
        return findings

    ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)
    all_subnets = sorted({s for subnets in endpoint_subnets.values() for s in subnets})
    subnet_vpc = {}
    subnet_error = None
    try:
        for batch in _chunked(all_subnets, SUBNET_LOOKUP_BATCH_SIZE):
            for page in ec2_client.get_paginator("describe_subnets").paginate(
                SubnetIds=batch
            ):
                for subnet in page.get("Subnets", []):
                    if subnet.get("SubnetId") in batch and subnet.get("VpcId"):
                        subnet_vpc[subnet["SubnetId"]] = subnet["VpcId"]
    except Exception as error:
        subnet_error = get_assessment_error_label(error)

    resource_ids = sorted(set(all_subnets) | set(subnet_vpc.values()))
    flow_logs = []
    flow_log_error = None
    try:
        for batch in _chunked(resource_ids, SUBNET_LOOKUP_BATCH_SIZE):
            for page in ec2_client.get_paginator("describe_flow_logs").paginate(
                Filter=[{"Name": "resource-id", "Values": batch}]
            ):
                flow_logs.extend(page.get("FlowLogs", []))
    except Exception as error:
        flow_log_error = get_assessment_error_label(error)

    alerting_logs = {}
    for flow_log in flow_logs:
        if (
            flow_log.get("ResourceId") in resource_ids
            and flow_log.get("FlowLogStatus") == "ACTIVE"
            and flow_log.get("LogDestinationType") == "cloud-watch-logs"
            and flow_log.get("TrafficType") in FLOW_LOG_ALERTING_TRAFFIC_TYPES
            and flow_log.get("LogGroupName")
        ):
            alerting_logs.setdefault(flow_log["ResourceId"], set()).add(
                flow_log["LogGroupName"]
            )

    logs_client = boto3.client("logs", config=boto3_config, region_name=region)
    group_metrics = {}
    group_errors = {}
    unmatched_filters = {}
    for group in sorted({g for groups in alerting_logs.values() for g in groups}):
        try:
            metrics = {}
            for page in logs_client.get_paginator("describe_metric_filters").paginate(
                logGroupName=group
            ):
                for metric_filter in page.get("metricFilters", []):
                    if metric_filter.get("logGroupName") not in (None, group):
                        continue
                    if not _filter_pattern_selects_flow_records(metric_filter):
                        unmatched_filters.setdefault(group, []).append(
                            f"'{metric_filter.get('filterName')}' "
                            f"({metric_filter.get('filterPattern')!r})"
                        )
                        continue
                    for transformation in (
                        metric_filter.get("metricTransformations") or []
                    ):
                        metrics.setdefault(
                            (
                                transformation.get("metricNamespace"),
                                transformation.get("metricName"),
                            ),
                            [],
                        ).append(transformation)
            group_metrics[group] = metrics
        except Exception as error:
            group_errors[group] = get_assessment_error_label(error)

    alarmed_metrics = {}
    alarm_error = None
    if any(group_metrics.values()):
        try:
            cloudwatch_client = boto3.client(
                "cloudwatch", config=boto3_config, region_name=region
            )
            metric_alarms = []
            composite_alarms = []
            for page in cloudwatch_client.get_paginator("describe_alarms").paginate(
                AlarmTypes=["MetricAlarm", "CompositeAlarm"]
            ):
                metric_alarms.extend(page.get("MetricAlarms", []))
                composite_alarms.extend(page.get("CompositeAlarms", []))
            actioned = _actioned_alarms(metric_alarms, composite_alarms)
            for alarm in metric_alarms:
                if alarm.get("AlarmName") not in actioned:
                    continue
                composite = actioned[alarm["AlarmName"]]
                label = f"alarm '{alarm['AlarmName']}' in state " + str(
                    alarm.get("StateValue") or "not returned"
                )
                if composite:
                    label += f", actioned through composite alarm '{composite}'"
                for metric, series in _alarm_metrics(alarm):
                    alarmed_metrics.setdefault(metric, []).append(
                        (label, alarm["AlarmName"], composite, series)
                    )
        except Exception as error:
            alarm_error = get_assessment_error_label(error)

    failed = []
    passed = []
    for name, subnets in endpoint_subnets.items():
        if not subnets:
            failed.append(
                f"{name} runs outside any customer VPC, so no flow log "
                "can capture its traffic"
            )
            continue
        if subnet_error and any(s not in subnet_vpc for s in subnets):
            unread.append(f"subnets of {name} (ec2:DescribeSubnets: {subnet_error})")
            continue
        if flow_log_error:
            unread.append(
                f"flow logs of {name} (ec2:DescribeFlowLogs: {flow_log_error})"
            )
            continue
        uncovered = []
        unalarmed = {}
        alarmed = []
        dead_alarms = []
        for subnet in subnets:
            covering = alerting_logs.get(subnet, set()) | alerting_logs.get(
                subnet_vpc.get(subnet), set()
            )
            if not covering:
                uncovered.append(subnet)
                continue
            hits = []
            dead = []
            for g in sorted(covering):
                for metric in sorted(group_metrics.get(g, {}), key=str):
                    for transformation in group_metrics[g][metric]:
                        for label, alarm, composite, series in alarmed_metrics.get(
                            metric, []
                        ):
                            reason = _alarm_cannot_fire(transformation, series)
                            if reason is None:
                                hits.append((g, label, alarm, composite))
                                continue
                            dead.append(
                                f"alarm '{alarm}' on {metric[0]}/{metric[1]} can "
                                f"never fire: {reason}"
                            )
            if hits:
                alarmed.append(hits[0])
            else:
                unalarmed[subnet] = covering
                dead_alarms.extend(d for d in dead if d not in dead_alarms)
        if uncovered:
            failed.append(
                f"{name}: no ACTIVE flow log capturing accepted traffic "
                f"into CloudWatch Logs covers {', '.join(uncovered)}"
            )
            continue
        groups = {g for covering in unalarmed.values() for g in covering}
        unread_groups = sorted(g for g in groups if g in group_errors)
        if not unalarmed:
            passed.append((name, sorted(set(alarmed))))
        elif unread_groups:
            unread.append(
                f"metric filters of {', '.join(unread_groups)} for {name} "
                f"(logs:DescribeMetricFilters: {group_errors[unread_groups[0]]})"
            )
        elif alarm_error:
            unread.append(
                f"alarms for {name} (cloudwatch:DescribeAlarms: {alarm_error})"
            )
        else:
            unmatched = [
                f"{g}: {', '.join(unmatched_filters[g])}"
                for g in sorted(groups)
                if g in unmatched_filters
            ]
            failed.append(
                f"{name}: flow log group(s) {', '.join(sorted(groups))} "
                f"covering {', '.join(sorted(unalarmed))} have no metric filter "
                "whose metric an alarm with an action evaluates"
                + (
                    " (filter(s) whose pattern matches no flow-log record: "
                    f"{'; '.join(unmatched)})"
                    if unmatched
                    else ""
                )
                + (f" ({'; '.join(dead_alarms)})" if dead_alarms else "")
            )

    history = {
        alarm: _alarm_last_fired(cloudwatch_client, alarm)
        for alarm in sorted({hit[2] for _, hits in passed for hit in hits})
    }
    composite_history = {
        composite: _alarm_last_fired(cloudwatch_client, composite, "CompositeAlarm")
        for composite in sorted(
            {hit[3] for _, hits in passed for hit in hits if hit[3]}
        )
    }
    passed = [
        f"{name} ("
        + "; ".join(
            f"log group {group}, {label}, {history[alarm]}"
            + (
                f", composite alarm '{composite}' {composite_history[composite]}"
                if composite
                else ""
            )
            for group, label, alarm, composite in hits
        )
        + ")"
        for name, hits in passed
    ]

    if failed:
        shown = "; ".join(failed[:10])
        if len(failed) > 10:
            shown += f"; and {len(failed) - 10} more"
        findings["csv_data"].append(
            _row(
                f"{len(failed)} endpoint(s) and AgentCore runtime(s) have no network "
                f"anomaly alerting: {shown}. " + ENDPOINT_FLOW_LOG_SCOPE_NOTE,
                ENDPOINT_FLOW_LOG_ALERTING_RESOLUTION,
                "Medium",
                "Failed",
            )
        )
    if unread:
        findings["csv_data"].append(
            _unread_resources_finding(
                "SM-37",
                ENDPOINT_FLOW_LOG_ALERTING_FINDING,
                unread,
                f"{len(passed)} endpoint(s) and AgentCore runtime(s) passed and "
                f"{len(failed)} failed. " + ENDPOINT_FLOW_LOG_SCOPE_NOTE,
                ENDPOINT_FLOW_LOG_ALERTING_REFERENCE,
                region,
            )
        )
    if not failed and not unread:
        findings["csv_data"].append(
            _row(
                f"All {len(passed)} endpoint(s) and AgentCore runtime(s) run in "
                "subnets covered by an ACTIVE "
                "flow log in CloudWatch Logs whose metric filter feeds an alarm with "
                f"an action: {'; '.join(passed[:10])}. " + ENDPOINT_FLOW_LOG_SCOPE_NOTE,
                "No action required",
                "Medium",
                "Passed",
            )
        )
    return findings


VPC_DNS_RESOLVER_FINDING = "VPC DNS Resolver Visible to GuardDuty"
VPC_DNS_RESOLVER_REFERENCE = (
    "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html"
)
# The Amazon DNS server answers at these addresses and at the VPC IPv4 base
# plus two, so a DHCP option set that names it by address still uses it.
AMAZON_DNS_SERVER_VALUES = ("AmazonProvidedDNS", "169.254.169.253", "fd00:ec2::253")


def check_vpc_dns_resolver_visibility(region: str = "") -> Dict[str, Any]:
    """
    SM-37: Verify every VPC resolves DNS through the Amazon DNS server.

    GuardDuty analyzes DNS query logs only for queries that reach the
    AWS-provided resolver, so a VPC whose DHCP option set names any other
    domain name server sends DNS that GuardDuty never sees.
    """
    findings = {"csv_data": []}
    unread = []
    vpcs = []
    try:
        ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)
        for page in ec2_client.get_paginator("describe_vpcs").paginate():
            vpcs.extend(page.get("Vpcs", []))
    except Exception as error:
        findings["csv_data"].append(
            _unread_resources_finding(
                "SM-37",
                VPC_DNS_RESOLVER_FINDING,
                [f"ec2:DescribeVpcs ({get_assessment_error_label(error)})"],
                "no VPC was read.",
                VPC_DNS_RESOLVER_REFERENCE,
                region,
            )
        )
        return findings
    option_ids = sorted(
        {
            v.get("DhcpOptionsId")
            for v in vpcs
            if v.get("DhcpOptionsId") not in (None, "default")
        }
    )
    servers = {}
    if option_ids:
        try:
            for page in ec2_client.get_paginator("describe_dhcp_options").paginate(
                DhcpOptionsIds=option_ids
            ):
                for options in page.get("DhcpOptions", []):
                    servers[options.get("DhcpOptionsId")] = [
                        str(value.get("Value"))
                        for entry in options.get("DhcpConfigurations") or []
                        if entry.get("Key") == "domain-name-servers"
                        for value in entry.get("Values") or []
                    ]
        except Exception as error:
            unread.append(
                f"ec2:DescribeDhcpOptions ({get_assessment_error_label(error)})"
            )
            servers = None

    problems, unjudged, passed = [], [], []
    for vpc in vpcs:
        vpc_id, option_id = vpc.get("VpcId"), vpc.get("DhcpOptionsId")
        if option_id in (None, "default"):
            passed.append(f"{vpc_id} (no DHCP option set)")
            continue
        if servers is None:
            continue
        if option_id not in servers:
            unread.append(f"DHCP option set {option_id} of {vpc_id}")
            continue
        if not servers[option_id]:
            unjudged.append(f"{vpc_id} ({option_id})")
            continue
        amazon = set(AMAZON_DNS_SERVER_VALUES)
        for block in vpc.get("CidrBlockAssociationSet") or [
            {"CidrBlock": vpc.get("CidrBlock")}
        ]:
            try:
                network = ipaddress.ip_network(block.get("CidrBlock"), strict=False)
            except (TypeError, ValueError):
                continue
            amazon.add(str(network.network_address + 2))
        other = [server for server in servers[option_id] if server not in amazon]
        if other:
            problems.append(
                f"VPC {vpc_id} uses DHCP option set {option_id}, whose domain name "
                f"servers include {', '.join(other[:4])}, which is not the Amazon "
                "DNS server. GuardDuty analyzes DNS query logs only for queries "
                "that reach the AWS-provided resolver, so DNS sent to these "
                "servers is not analyzed."
            )
        else:
            passed.append(f"{vpc_id} ({option_id})")

    findings["csv_data"].extend(
        _capped_problem_rows(
            "SM-37",
            VPC_DNS_RESOLVER_FINDING,
            problems,
            "Set domain-name-servers to AmazonProvidedDNS in the VPC's DHCP option "
            "set, and forward on-premises names through Route 53 Resolver "
            "outbound endpoints and rules in place of custom DNS servers.",
            VPC_DNS_RESOLVER_REFERENCE,
            "Medium",
            region,
            "VPCs with a DNS resolver GuardDuty does not see",
        )
    )
    if unjudged:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-37",
                finding_name=f"{VPC_DNS_RESOLVER_FINDING} Not Judged",
                finding_details=(
                    f"{len(unjudged)} VPC(s) use a DHCP option set that names no "
                    f"domain name servers: {', '.join(unjudged[:10])}. Which DNS "
                    "server their instances use is not stated by the option set, "
                    "so whether GuardDuty sees their DNS queries was not judged."
                ),
                resolution=(
                    "Set domain-name-servers to AmazonProvidedDNS in the DHCP "
                    "option set."
                ),
                reference=VPC_DNS_RESOLVER_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    if unread:
        findings["csv_data"].append(
            _unread_resources_finding(
                "SM-37",
                VPC_DNS_RESOLVER_FINDING,
                unread,
                f"{len(passed)} VPC(s) use the Amazon DNS server and "
                f"{len(problems)} do not.",
                VPC_DNS_RESOLVER_REFERENCE,
                region,
            )
        )
    elif not problems and not unjudged:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-37",
                finding_name=VPC_DNS_RESOLVER_FINDING,
                finding_details=(
                    f"All {len(passed)} VPC(s) resolve DNS through the Amazon DNS "
                    f"server: {', '.join(passed[:10])}. A VPC with no DHCP option "
                    "set gets the Amazon DNS server at 169.254.169.253 on Nitro "
                    "instances and no DNS server on Xen instances. Whether "
                    "GuardDuty is enabled is reported by SM-04."
                    if passed
                    else "No VPCs were found in this region."
                ),
                resolution="No action required",
                reference=VPC_DNS_RESOLVER_REFERENCE,
                severity="Medium" if passed else "Informational",
                status="Passed" if passed else "N/A",
                region=region,
            )
        )
    return findings


MODEL_ARTIFACT_INTEGRITY_FINDING = "SageMaker Model Artifact Integrity"
MODEL_ARTIFACT_INTEGRITY_REFERENCE = (
    "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html"
)
MODEL_ARTIFACT_INTEGRITY_RESOLUTION = (
    "Reference each serving image by digest (@sha256:) or by a tag in an Amazon "
    "ECR repository with immutable tags, and keep images signed where a managed "
    "signing rule covers the repository. Deploy model data through "
    "ModelDataSource with its S3 ETag or ManifestEtag recorded, or from a model "
    "package container that records ModelDataETag, in place of a bare "
    "ModelDataUrl or a hub model id read at startup, and encrypt the artifact "
    "bucket with SSE-KMS under a named key. An inference component whose "
    "container names an S3 ArtifactUrl has no ETag field to record one, so "
    "create the component from a model (ModelName) whose container loads its "
    "data through ModelDataSource with the ETag recorded."
)
SM43_PREFIX_OBJECT_CAP = 1000
MODEL_ARTIFACT_INTEGRITY_SCOPE_NOTE = (
    "A recorded ETag, ManifestEtag or ModelDataETag means an expected value is "
    "recorded; whether SageMaker or the container compared it to the object at "
    "load time is not returned by any API this check reads. Model data named "
    "as one S3 object (a ModelDataUrl, an S3Object source or a manifest) is read "
    "with HeadObject: its current ETag is compared to the recorded value and its "
    "own server-side encryption is judged. Each object under an S3Prefix source "
    "or a multi-model prefix is listed and read with HeadObject for its "
    "server-side encryption, up to "
    f"{SM43_PREFIX_OBJECT_CAP} objects per run. No SageMaker field records a "
    "SHA256 digest to compare. The execution role's s3:GetObject reach is judged "
    "per bucket from its Allow statements and permissions boundary, not against "
    "the artifact prefix; a Deny narrower than every resource, and SCPs, are not "
    "subtracted. Weights fetched by "
    "container startup code, and models loaded by workloads on ECS, EKS or EC2, "
    "are not read. Of each container's environment only the keys are read."
)
ECR_IMAGE_URI = re.compile(
    r"^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?/"
    r"([^:@]+)(?::([^@]+))?(?:@(sha256:[0-9a-fA-F]{64}))?$"
)


def _ecr_wildcard_match(pattern: str, value: str) -> bool:
    """An ECR filter match, where * matches any sequence of characters."""
    expression = ".*".join(re.escape(part) for part in (pattern or "").split("*"))
    return re.fullmatch(expression, value) is not None


def _ecr_tag_is_immutable(repository: Dict[str, Any], tag: str) -> Optional[bool]:
    """
    Whether a repository's tag mutability setting holds this tag fixed.

    An exclusion filter takes a tag out of the repository's setting, so an
    excluded tag is mutable in an IMMUTABLE_WITH_EXCLUSION repository and
    immutable in a MUTABLE_WITH_EXCLUSION one. None for any other value.
    """
    mutability = repository.get("imageTagMutability")
    excluded = any(
        f.get("filterType", "WILDCARD") == "WILDCARD"
        and _ecr_wildcard_match(f.get("filter") or "", tag)
        for f in repository.get("imageTagMutabilityExclusionFilters") or []
    )
    return {
        "IMMUTABLE": True,
        "MUTABLE": False,
        "IMMUTABLE_WITH_EXCLUSION": not excluded,
        "MUTABLE_WITH_EXCLUSION": excluded,
    }.get(mutability)


def _signing_rule_covers(rule: Dict[str, Any], repository_name: str) -> bool:
    """A signing rule with no repository filters signs every repository."""
    filters = rule.get("repositoryFilters") or []
    return not filters or any(
        f.get("filterType") == "WILDCARD_MATCH"
        and _ecr_wildcard_match(f.get("filter") or "", repository_name)
        for f in filters
    )


def _s3_object_reach_beyond(
    statements: List[Tuple[str, Dict[str, Any]]], buckets: set
) -> List[Tuple[str, str, bool]]:
    """
    Each Allow that grants s3:GetObject on an object outside ``buckets``, as
    (resource, "policy P statement S", conditioned). A wildcard or policy
    variable in the bucket segment reaches other buckets; a bucket ARN with no
    object path reaches no object.
    """
    reach = []
    for policy_name, statement in statements:
        if not _statement_allows_action(statement, "s3:GetObject"):
            continue
        where = (
            f"policy {policy_name} statement {statement.get('Sid') or 'without a Sid'}"
        )
        conditioned = bool(statement.get("Condition"))
        if "NotResource" in statement:
            excluded = ", ".join(_policy_values(statement["NotResource"])[:3])
            reach.append(
                (f"every resource but NotResource {excluded}", where, conditioned)
            )
            continue
        for resource in _policy_values(statement.get("Resource")):
            pattern = re.sub(r"\$\{[^}]*\}", "*", resource.strip()).lower()
            if not _globs_overlap(pattern, "arn:*:s3:::*/*"):
                continue
            bucket = pattern.split(":::", 1)[-1].split("/", 1)[0]
            if _s3_bucket_pattern_is_wildcard(pattern) or bucket not in buckets:
                reach.append((resource, where, conditioned))
    return reach


def check_sagemaker_model_artifact_integrity(
    region: str = "", permission_cache: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    SM-43: Verify every InService endpoint serves pinned images and model data
    with a recorded expected value, from an SSE-KMS artifact bucket.

    Each serving container is judged on four legs: its image is pinned by
    digest or by a tag its ECR repository holds immutable, and signed when a
    managed signing rule covers the repository; its S3 model data records an
    ETag, ManifestEtag or ModelDataETag, or comes from SageMaker hub content;
    it does not name an HF_MODEL_ID with no model data; and each artifact
    bucket defaults to SSE-KMS with a named customer managed key. Each object
    named or listed under a prefix is read with HeadObject, and each execution
    role's s3:GetObject grants must stay inside the artifact buckets. A denied
    read leaves that endpoint N/A, never Failed.
    """
    findings = {"csv_data": []}

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-43",
            finding_name=MODEL_ARTIFACT_INTEGRITY_FINDING,
            finding_details=f"{details} {MODEL_ARTIFACT_INTEGRITY_SCOPE_NOTE}",
            resolution=resolution,
            reference=MODEL_ARTIFACT_INTEGRITY_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        inventory = _endpoint_hosting_inventory(sagemaker_client)
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
        return findings

    endpoints = [e for e in inventory["endpoints"] if e["status"] == "InService"]
    unread = list(inventory["unread"])
    if not endpoints and not unread:
        findings["csv_data"].append(
            _row(
                "No InService SageMaker endpoints were found in this region.",
                "No action required",
                "Informational",
                "N/A",
            )
        )
        return findings

    ecr_clients = {}
    repositories = {}
    signing = {}
    buckets = {}
    models = {}
    packages = {}
    heads = {}
    listings = {}
    model_roles = {}
    role_reach = {}
    prefix_budget = [SM43_PREFIX_OBJECT_CAP]
    s3_client = boto3.client("s3", config=boto3_config, region_name=region)

    def _ecr(image_region):
        if image_region not in ecr_clients:
            ecr_clients[image_region] = boto3.client(
                "ecr", config=boto3_config, region_name=image_region
            )
        return ecr_clients[image_region]

    def _repository(image_region, registry, name):
        key = (image_region, registry, name)
        if key not in repositories:
            try:
                found = (
                    _ecr(image_region)
                    .describe_repositories(registryId=registry, repositoryNames=[name])
                    .get("repositories")
                    or []
                )
                repositories[key] = (
                    found[0]
                    if found
                    else "ecr:DescribeRepositories returned no repository"
                )
            except Exception as error:
                repositories[key] = (
                    f"ecr:DescribeRepositories: {get_assessment_error_label(error)}"
                )
        return repositories[key]

    def _signing_rules(image_region):
        if image_region not in signing:
            try:
                response = _ecr(image_region).get_signing_configuration()
                signing[image_region] = (
                    response.get("registryId"),
                    (response.get("signingConfiguration") or {}).get("rules") or [],
                )
            except Exception as error:
                label = get_assessment_error_label(error)
                signing[image_region] = (
                    (None, [])
                    if label == "SigningConfigurationNotFoundException"
                    else f"ecr:GetSigningConfiguration: {label}"
                )
        return signing[image_region]

    def _judge_image(label, image, resolved):
        problems, unreads = [], []
        match = ECR_IMAGE_URI.match(image)
        if not match:
            if "@sha256:" not in image:
                unreads.append(
                    f"{label} image is outside Amazon ECR, so its tag mutability "
                    "is not readable"
                )
            return problems, unreads
        registry, image_region, name, tag, digest = match.groups()
        tag = tag or "latest"
        if not digest:
            repository = _repository(image_region, registry, name)
            if isinstance(repository, str):
                unreads.append(
                    f"{label} image repository {name} in account {registry} was "
                    f"not read ({repository})"
                )
            else:
                immutable = _ecr_tag_is_immutable(repository, tag)
                mutability = repository.get("imageTagMutability")
                if immutable is None:
                    unreads.append(
                        f"{label} repository {name} returned imageTagMutability "
                        f"{mutability}, which this check does not interpret"
                    )
                elif not immutable:
                    problems.append(
                        f"{label} image is pinned by tag '{tag}' in repository "
                        f"{name}, whose imageTagMutability {mutability} lets "
                        "that tag move"
                    )
        rules = _signing_rules(image_region)
        if isinstance(rules, str):
            unreads.append(f"{label} image signing rules were not read ({rules})")
            return problems, unreads
        registry_id, rule_list = rules
        if registry_id != registry or not any(
            _signing_rule_covers(rule, name) for rule in rule_list
        ):
            return problems, unreads
        resolved_digest = (
            resolved.split("@", 1)[1] if resolved and "@sha256:" in resolved else None
        )
        image_id = (
            {"imageDigest": digest or resolved_digest}
            if digest or resolved_digest
            else {"imageTag": tag}
        )
        try:
            statuses = (
                _ecr(image_region)
                .describe_image_signing_status(
                    registryId=registry, repositoryName=name, imageId=image_id
                )
                .get("signingStatuses")
                or []
            )
        except Exception as error:
            unreads.append(
                f"{label} image signing status was not read "
                f"(ecr:DescribeImageSigningStatus: {get_assessment_error_label(error)})"
            )
            return problems, unreads
        states = {s.get("status") for s in statuses}
        if "COMPLETE" in states:
            return problems, unreads
        if "IN_PROGRESS" in states:
            unreads.append(f"{label} image signing is IN_PROGRESS")
        elif statuses:
            codes = sorted({str(s.get("failureCode")) for s in statuses})
            problems.append(
                f"{label} image failed managed signing ({', '.join(codes)})"
            )
        else:
            problems.append(
                f"{label} image has no managed signing status, though a signing "
                f"rule covers repository {name}"
            )
        return problems, unreads

    def _bucket_encryption(bucket):
        if bucket not in buckets:
            try:
                rules = (
                    s3_client.get_bucket_encryption(Bucket=bucket)
                    .get("ServerSideEncryptionConfiguration", {})
                    .get("Rules", [])
                )
                defaults = [
                    r.get("ApplyServerSideEncryptionByDefault") or {} for r in rules
                ]
                kms_defaults = [
                    d
                    for d in defaults
                    if d.get("SSEAlgorithm") in S3_ENCRYPTION_KMS_ALGORITHMS
                ]
                if not kms_defaults:
                    algorithms = sorted({str(d.get("SSEAlgorithm")) for d in defaults})
                    buckets[bucket] = (
                        "failed",
                        "default encryption is not SSE-KMS "
                        f"({', '.join(algorithms) or 'no default rule'})",
                    )
                elif not kms_defaults[0].get("KMSMasterKeyID"):
                    buckets[bucket] = (
                        "failed",
                        "default encryption is SSE-KMS with no KMSMasterKeyID, so "
                        "it uses the AWS managed key aws/s3",
                    )
                else:
                    key_id = str(kms_defaults[0]["KMSMasterKeyID"])
                    key = _kms_key_managers([key_id], region)[key_id]
                    if key["manager"] == "AWS":
                        buckets[bucket] = (
                            "failed",
                            f"default encryption key {key_id} is an AWS managed "
                            "key, not a customer managed key",
                        )
                    elif key["manager"] is None:
                        buckets[bucket] = (
                            "unread",
                            f"kms:DescribeKey on {key_id}: {key['error']}",
                        )
                    else:
                        buckets[bucket] = (None, None)
            except Exception as error:
                label = get_assessment_error_label(error)
                buckets[bucket] = (
                    ("failed", "the bucket has no default encryption configuration")
                    if label == "ServerSideEncryptionConfigurationNotFoundError"
                    else ("unread", f"s3:GetEncryptionConfiguration: {label}")
                )
        return buckets[bucket]

    def _head(uri):
        if uri not in heads:
            bucket, _, key = uri[len("s3://") :].partition("/")
            try:
                heads[uri] = s3_client.head_object(Bucket=bucket, Key=key)
            except Exception as error:
                heads[uri] = get_assessment_error_label(error)
        return heads[uri]

    def _judge_object(where, uri, recorded):
        """Compare one S3 object to its recorded ETag and judge its own SSE."""
        problems, unreads = [], []
        head = _head(uri)
        if isinstance(head, str):
            if head in ("404", "NoSuchKey", "NotFound"):
                problems.append(
                    f"{where} {uri} returned 404 to HeadObject, so no object holds "
                    f"the recorded {recorded or 'model data'}"
                )
            else:
                unreads.append(f"{where} {uri} was not read (s3:GetObject: {head})")
            return problems, unreads
        actual = str(head.get("ETag") or "").strip('"')
        if recorded and actual.lower() != str(recorded).strip('"').lower():
            problems.append(
                f"{where} {uri} now has ETag {actual or 'none'}, not the recorded "
                f"{recorded}, so the object changed after its expected value was "
                "recorded"
            )
        algorithm = head.get("ServerSideEncryption")
        if algorithm not in S3_ENCRYPTION_KMS_ALGORITHMS:
            problems.append(
                f"{where} object {uri} "
                + (
                    f"is encrypted with {algorithm}"
                    if algorithm
                    else "reports no server-side encryption"
                )
                + ", not SSE-KMS"
            )
            return problems, unreads
        key_id = str(head.get("SSEKMSKeyId") or "")
        key = _kms_key_managers([key_id], region).get(key_id) if key_id else None
        if not key or key["manager"] == "AWS":
            problems.append(
                f"{where} object {uri} is encrypted under "
                f"{key_id or 'no named key'}, an AWS managed key"
            )
        elif key["manager"] is None:
            unreads.append(
                f"{where} object {uri} key was not read "
                f"(kms:DescribeKey on {key_id}: {key['error']})"
            )
        return problems, unreads

    def _prefix_keys(uri):
        """The keys under a prefix up to the run's remaining HeadObject budget,
        with whether more were left, or the error label of a failed listing."""
        if uri not in listings:
            bucket, _, prefix = uri[len("s3://") :].partition("/")
            keys, more = [], False
            try:
                for page in s3_client.get_paginator("list_objects_v2").paginate(
                    Bucket=bucket, Prefix=prefix
                ):
                    for item in page.get("Contents") or []:
                        if len(keys) >= prefix_budget[0]:
                            more = True
                            break
                        keys.append(item["Key"])
                    if more:
                        break
                prefix_budget[0] -= len(keys)
                listings[uri] = (bucket, keys, more)
            except Exception as error:
                listings[uri] = get_assessment_error_label(error)
        return listings[uri]

    def _judge_prefix(where, uri):
        problems, unreads = [], []
        listing = _prefix_keys(uri)
        if isinstance(listing, str):
            unreads.append(
                f"{where} {uri} objects were not listed (s3:ListBucket: {listing})"
            )
            return problems, unreads
        bucket, keys, more = listing
        if not keys and not more:
            problems.append(
                f"{where} {uri} lists no objects, so no object holds the model data"
            )
        for key in keys:
            object_problems, object_unreads = _judge_object(
                where, f"s3://{bucket}/{key}", None
            )
            problems += object_problems
            unreads += object_unreads
        if more:
            unreads.append(
                f"{where} {uri} holds more objects than the "
                f"{SM43_PREFIX_OBJECT_CAP} this run reads with HeadObject, so the "
                f"objects after the first {len(keys)} listed were not read"
            )
        return problems, unreads

    def _judge_role(role_arn, buckets):
        """Whether one execution role's s3:GetObject grants reach objects
        outside the artifact buckets, as (problems, unreads)."""
        key = (role_arn, frozenset(buckets))
        if key in role_reach:
            return role_reach[key]
        name = _role_name_from_arn(role_arn)
        cached = (permission_cache or {}).get("role_permissions") or {}
        unread_principals = (
            _principal_read_errors(permission_cache) or [] if permission_cache else []
        )
        reason = None
        if permission_cache is None:
            reason = "the IAM permissions cache was not available"
        elif name not in cached:
            reason = "not in the IAM cache"
        elif any(
            p.lower().startswith(f"role '{name.lower()}' ")
            and p.lower() != f"role '{name.lower()}' (permissions_boundary)"
            for p in unread_principals
        ):
            reason = "IAM cache read error"
        if reason:
            role_reach[key] = (
                [],
                [f"execution role {role_arn} read scope was not judged ({reason})"],
            )
            return role_reach[key]
        permissions = cached[name]
        statements = [
            (policy.get("name") or "inline policy", statement)
            for policy in (permissions.get("attached_policies") or [])
            + (permissions.get("inline_policies") or [])
            for statement in _sm_policy_statements(policy.get("document"))
        ]
        reach = []
        if not any(
            _merged_account_wide_deny(statement, "s3:getobject")
            for _, statement in statements
        ):
            reach = _s3_object_reach_beyond(statements, buckets)
        boundary = permissions.get("permissions_boundary")
        if boundary is not None:
            boundary_statements = [
                ("boundary", statement) for statement in _sm_policy_statements(boundary)
            ]
            if any(
                _merged_account_wide_deny(statement, "s3:getobject")
                for _, statement in boundary_statements
            ) or not _s3_object_reach_beyond(boundary_statements, buckets):
                reach = []
        problems, unreads = [], []
        plain = [r for r in reach if not r[2]]
        listed = ", ".join(sorted(buckets))
        if plain:
            resource, where, _ = plain[0]
            if boundary is None and ("role", name) in _boundary_unread(
                permission_cache
            ):
                unreads.append(
                    f"execution role '{name}' is allowed s3:GetObject on {resource} "
                    f"by {where}, and its permissions boundary was not read"
                )
            else:
                problems.append(
                    f"execution role '{name}' is allowed s3:GetObject on {resource} "
                    f"by {where}, which reaches objects outside its artifact "
                    f"bucket(s) {listed}"
                )
        elif reach:
            resource, where, _ = reach[0]
            unreads.append(
                f"execution role '{name}' is allowed s3:GetObject on {resource} by "
                f"{where} under a Condition this check does not evaluate"
            )
        role_reach[key] = (problems, unreads)
        return role_reach[key]

    def _judge_data(label, unit, env_keys):
        problems, unreads, uris = [], [], []
        objects = []
        prefixes = []
        url = unit.get("ModelDataUrl")
        source = (unit.get("ModelDataSource") or {}).get("S3DataSource")
        if url:
            uris.append(url)
            if not unit.get("ModelDataETag"):
                problems.append(
                    f"{label} loads ModelDataUrl {url} with no expected value recorded"
                )
            if (
                _s3_uri_bucket(url)
                and not url.endswith("/")
                and unit.get("Mode") != "MultiModel"
            ):
                objects.append(
                    (f"{label} ModelDataUrl", url, unit.get("ModelDataETag"))
                )
            elif _s3_uri_bucket(url):
                prefixes.append((f"{label} ModelDataUrl", url))
        sources = [("ModelDataSource", source)] if source else []
        for extra in unit.get("AdditionalModelDataSources") or []:
            if extra.get("S3DataSource"):
                sources.append(
                    (
                        f"additional source {extra.get('ChannelName')}",
                        extra["S3DataSource"],
                    )
                )
        for name, s3_source in sources:
            if (s3_source.get("HubAccessConfig") or {}).get("HubContentArn"):
                continue
            uris.append(s3_source.get("S3Uri"))
            if not (s3_source.get("ETag") or s3_source.get("ManifestEtag")):
                problems.append(
                    f"{label} {name} {s3_source.get('S3Uri')} records no ETag or "
                    "ManifestEtag"
                )
            if s3_source.get("S3DataType") == "S3Object" and _s3_uri_bucket(
                s3_source.get("S3Uri")
            ):
                objects.append(
                    (f"{label} {name}", s3_source["S3Uri"], s3_source.get("ETag"))
                )
            elif s3_source.get("S3DataType") == "S3Prefix" and _s3_uri_bucket(
                s3_source.get("S3Uri")
            ):
                prefixes.append((f"{label} {name}", s3_source["S3Uri"]))
            if s3_source.get("ManifestEtag") and _s3_uri_bucket(
                s3_source.get("ManifestS3Uri")
            ):
                objects.append(
                    (
                        f"{label} {name} manifest",
                        s3_source["ManifestS3Uri"],
                        s3_source["ManifestEtag"],
                    )
                )
        if "HF_MODEL_ID" in env_keys and not url and not source:
            problems.append(
                f"{label} sets HF_MODEL_ID with no ModelDataUrl or ModelDataSource, "
                "so its weights come from a model hub at container startup with "
                "no recorded source"
            )
        for uri in uris:
            bucket = _s3_uri_bucket(uri)
            if not bucket:
                continue
            state, detail = _bucket_encryption(bucket)
            if state == "failed":
                problems.append(f"{label} artifact bucket {bucket}: {detail}")
            elif state == "unread":
                unreads.append(
                    f"{label} artifact bucket {bucket} encryption was not read "
                    f"({detail})"
                )
        for where, uri, recorded in objects:
            object_problems, object_unreads = _judge_object(where, uri, recorded)
            problems += object_problems
            unreads += object_unreads
        for where, uri in prefixes:
            prefix_problems, prefix_unreads = _judge_prefix(where, uri)
            problems += prefix_problems
            unreads += prefix_unreads
        buckets_read = {_s3_uri_bucket(uri) for uri in uris} - {None}
        return problems, unreads, buckets_read

    def _package_containers(package_name):
        if package_name not in packages:
            try:
                packages[package_name] = list(
                    (
                        sagemaker_client.describe_model_package(
                            ModelPackageName=package_name
                        ).get("InferenceSpecification")
                        or {}
                    ).get("Containers")
                    or []
                )
            except Exception as error:
                packages[package_name] = (
                    "sagemaker:DescribeModelPackage: "
                    f"{get_assessment_error_label(error)}"
                )
        return packages[package_name]

    def _model_units(model_name):
        """
        Each serving container of a model as (label, container, env keys), or
        a string naming a model package that was not read.
        """
        if model_name not in models:
            try:
                model = sagemaker_client.describe_model(ModelName=model_name)
            except Exception as error:
                models[model_name] = (
                    f"model '{model_name}' was not read "
                    f"({get_assessment_error_label(error)})"
                )
                return models[model_name]
            model_roles[model_name] = model.get("ExecutionRoleArn")
            containers = (
                [model["PrimaryContainer"]]
                if model.get("PrimaryContainer")
                else list(model.get("Containers") or [])
            )
            units = []
            for index, container in enumerate(containers, start=1):
                label = (
                    f"model '{model_name}' container "
                    f"{container.get('ContainerHostname') or index}"
                )
                env_keys = set(container.get("Environment") or {})
                package_name = container.get("ModelPackageName")
                if not package_name:
                    units.append((label, container, env_keys))
                    continue
                package = _package_containers(package_name)
                if isinstance(package, str):
                    units.append(
                        f"{label} model package {package_name} was not read ({package})"
                    )
                    continue
                for position, package_container in enumerate(package, start=1):
                    units.append(
                        (
                            f"{label} (model package {package_name} container "
                            f"{position})",
                            package_container,
                            env_keys | set(package_container.get("Environment") or {}),
                        )
                    )
            models[model_name] = units
        return models[model_name]

    def _component_units(endpoint):
        units, unreads = [], []
        for variant in endpoint["component_variants"]:
            action = "sagemaker:ListInferenceComponents"
            try:
                for page in sagemaker_client.get_paginator(
                    "list_inference_components"
                ).paginate(
                    EndpointNameEquals=endpoint["name"], VariantNameEquals=variant
                ):
                    for component in page.get("InferenceComponents", []):
                        if component.get("EndpointName") not in (
                            None,
                            endpoint["name"],
                        ) or component.get("InferenceComponentStatus") not in (
                            None,
                            "InService",
                        ):
                            continue
                        name = component.get("InferenceComponentName")
                        action = "sagemaker:DescribeInferenceComponent"
                        described = sagemaker_client.describe_inference_component(
                            InferenceComponentName=name
                        )
                        specs = described.get("Specifications") or [
                            described.get("Specification") or {}
                        ]
                        for spec in specs:
                            if spec.get("ModelName"):
                                units.append(("model", spec["ModelName"], None))
                                continue
                            container = spec.get("Container") or {}
                            deployed = container.get("DeployedImage") or {}
                            if not deployed.get("SpecifiedImage") and not container.get(
                                "ArtifactUrl"
                            ):
                                unreads.append(
                                    f"inference component '{name}' returned no model "
                                    "name, image or artifact URL to judge"
                                )
                                continue
                            units.append(
                                (
                                    "container",
                                    f"inference component '{name}' container",
                                    {
                                        "Image": deployed.get("SpecifiedImage"),
                                        "ResolvedImage": deployed.get("ResolvedImage"),
                                        "ModelDataUrl": container.get("ArtifactUrl"),
                                        "Environment": container.get("Environment"),
                                    },
                                )
                            )
            except Exception as error:
                unreads.append(
                    f"inference components of variant {variant} were not read "
                    f"({action}: {get_assessment_error_label(error)})"
                )
        return units, unreads

    failed = []
    compliant = []
    for endpoint in endpoints:
        problems, unreads = [], []
        work = [("model", name, None) for name in endpoint["models"]]
        component_work, component_unreads = _component_units(endpoint)
        work += component_work
        unreads += component_unreads
        judged = []
        for kind, name, container in work:
            if kind == "container":
                judged.append(
                    (
                        name,
                        container,
                        set(container.get("Environment") or {}),
                        container.get("ResolvedImage"),
                        endpoint["config"].get("ExecutionRoleArn"),
                    )
                )
                continue
            units = _model_units(name)
            if isinstance(units, str):
                unreads.append(units)
                continue
            for entry in units:
                if isinstance(entry, str):
                    unreads.append(entry)
                    continue
                label, unit, env_keys = entry
                judged.append(
                    (
                        label,
                        unit,
                        env_keys,
                        endpoint["deployed_images"].get(unit.get("Image")),
                        model_roles.get(name),
                    )
                )
        role_buckets = {}
        for label, unit, env_keys, resolved, role_arn in judged:
            if unit.get("Image"):
                image_problems, image_unreads = _judge_image(
                    label, unit["Image"], resolved
                )
                problems += image_problems
                unreads += image_unreads
            data_problems, data_unreads, data_buckets = _judge_data(
                label, unit, env_keys
            )
            problems += data_problems
            unreads += data_unreads
            if data_buckets and not role_arn:
                unreads.append(f"{label} returned no ExecutionRoleArn to judge")
            elif data_buckets:
                role_buckets.setdefault(role_arn, set()).update(data_buckets)
        for role_arn, artifact_buckets in role_buckets.items():
            role_problems, role_unreads = _judge_role(role_arn, artifact_buckets)
            problems += role_problems
            unreads += role_unreads
        problems = list(dict.fromkeys(problems))
        unread += [
            f"endpoint '{endpoint['name']}': {u}" for u in dict.fromkeys(unreads)
        ]
        if problems:
            failed.append((endpoint["name"], problems))
        elif not unreads:
            compliant.append(endpoint["name"])

    for name, problems in failed:
        findings["csv_data"].append(
            _row(
                f"Endpoint '{name}' serves model artifacts whose integrity is not "
                f"pinned or recorded: {'; '.join(problems)}.",
                MODEL_ARTIFACT_INTEGRITY_RESOLUTION,
                "Medium",
                "Failed",
            )
        )
    read_details = (
        f"{len(compliant)} InService endpoint(s) serve only pinned images and "
        f"model data with a recorded expected value from SSE-KMS buckets, through "
        f"an execution role whose s3:GetObject grants stay inside those buckets: "
        f"{', '.join(compliant[:10]) or 'none'}."
    )
    if unread:
        findings["csv_data"].append(
            _unread_resources_finding(
                "SM-43",
                MODEL_ARTIFACT_INTEGRITY_FINDING,
                unread,
                f"{read_details} {MODEL_ARTIFACT_INTEGRITY_SCOPE_NOTE}",
                MODEL_ARTIFACT_INTEGRITY_REFERENCE,
                region,
            )
        )
    elif compliant and not failed:
        findings["csv_data"].append(
            _row(read_details, "No action required", "Medium", "Passed")
        )
    return findings


RUNTIME_MONITORING_FINDING = "GuardDuty Runtime Monitoring"
RUNTIME_MONITORING_REFERENCE = (
    "https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html"
)
RUNTIME_MONITORING_AGENT_CONFIGS = (
    "EKS_ADDON_MANAGEMENT",
    "ECS_FARGATE_AGENT_MANAGEMENT",
    "EC2_AGENT_MANAGEMENT",
)


def check_guardduty_runtime_monitoring(
    region: str = "", detector_inventory: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    SM-38: Verify GuardDuty Runtime Monitoring (RUNTIME_MONITORING) is enabled
    for self-hosted agent workloads. The legacy EKS_RUNTIME_MONITORING feature
    covers EKS only and does not pass.
    """
    findings = {"csv_data": []}

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-38",
            finding_name=RUNTIME_MONITORING_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=RUNTIME_MONITORING_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    resolution = (
        "Enable the GuardDuty Runtime Monitoring feature and automated agent "
        "management for the EC2, ECS Fargate and EKS hosts that run agent "
        "workloads."
    )
    try:
        inventory = detector_inventory or get_guardduty_detector_inventory(region)
        if inventory.get("error"):
            raise inventory["error"]
        if not inventory.get("detector_id"):
            findings["csv_data"].append(
                _row(
                    "No GuardDuty detector found; Runtime Monitoring cannot be "
                    "assessed separately.",
                    "Enable GuardDuty first, then enable Runtime Monitoring.",
                    "Informational",
                    "N/A",
                )
            )
            return findings
        detail = inventory.get("detail") or {}
        runtime = _guardduty_feature(detail, "RUNTIME_MONITORING")
        legacy = _guardduty_feature(detail, "EKS_RUNTIME_MONITORING")
        if detail.get("Status") != "ENABLED":
            findings["csv_data"].append(
                _row(
                    "The GuardDuty detector is not enabled, so workload runtime "
                    "behavior is not monitored.",
                    resolution,
                    "High",
                    "Failed",
                )
            )
        elif runtime and runtime.get("Status") == "ENABLED":
            states = {
                config.get("Name"): config.get("Status")
                for config in runtime.get("AdditionalConfiguration") or []
            }
            agent_text = ", ".join(
                f"{name} {states.get(name, 'not reported')}"
                for name in RUNTIME_MONITORING_AGENT_CONFIGS
            )
            findings["csv_data"].append(
                _row(
                    "GuardDuty Runtime Monitoring (RUNTIME_MONITORING) is enabled. "
                    f"Automated agent management: {agent_text}. A host type with "
                    "agent management disabled is covered only where the "
                    "security agent was installed manually.",
                    "No action required",
                    "High",
                    "Passed",
                )
            )
        elif legacy and legacy.get("Status") == "ENABLED":
            findings["csv_data"].append(
                _row(
                    "Only the legacy EKS_RUNTIME_MONITORING feature is enabled, "
                    "which covers EKS only; agent workloads on EC2 and ECS "
                    "Fargate are not monitored at runtime.",
                    resolution,
                    "High",
                    "Failed",
                )
            )
        else:
            state = runtime.get("Status") if runtime else "absent"
            findings["csv_data"].append(
                _row(
                    "GuardDuty is enabled, but the RUNTIME_MONITORING feature is "
                    f"{state}, so process, file and network activity inside agent "
                    "workloads is not monitored.",
                    resolution,
                    "High",
                    "Failed",
                )
            )
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
    return findings


RUNTIME_COVERAGE_FINDING = "GuardDuty Runtime Monitoring Coverage"
RUNTIME_COVERAGE_REFERENCE = (
    "https://docs.aws.amazon.com/guardduty/latest/ug/"
    "runtime-monitoring-assessing-coverage.html"
)
LAMBDA_RUNTIME_TIER_FINDING = "Lambda Runtime Detection Tier"
LAMBDA_RUNTIME_TIER_REFERENCE = (
    "https://docs.aws.amazon.com/inspector/latest/user/scanning-lambda.html"
)
RUNTIME_UNSUPPORTED_NOTE = (
    "EKS on Fargate, EKS Hybrid Nodes and ECS Managed Instances are not "
    "supported by Runtime Monitoring and fall to task- and network-level telemetry"
)


def _runtime_coverage_findings(
    region: str, detector_id: str, runtime: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Every covered resource HEALTHY, and every EKS and ECS cluster covered."""
    unread = []
    try:
        client = boto3.client("guardduty", config=boto3_config, region_name=region)
        resources = []
        for page in client.get_paginator("list_coverage").paginate(
            DetectorId=detector_id
        ):
            resources.extend(page.get("Resources", []))
    except Exception as error:
        return [
            _unread_resources_finding(
                "SM-38",
                RUNTIME_COVERAGE_FINDING,
                [f"guardduty:ListCoverage ({get_assessment_error_label(error)})"],
                "no per-resource coverage was read.",
                RUNTIME_COVERAGE_REFERENCE,
                region,
            )
        ]

    eks_clusters = []
    fargate_profiles = {}
    try:
        eks_client = boto3.client("eks", config=boto3_config, region_name=region)
        for page in eks_client.get_paginator("list_clusters").paginate():
            eks_clusters.extend(page.get("clusters", []))
    except Exception as error:
        unread.append(f"eks:ListClusters ({get_assessment_error_label(error)})")
    # AIR-SLF-RT-04: Runtime Monitoring does not cover pods on Fargate, and a
    # cluster's node counts say nothing about them.
    for cluster in eks_clusters:
        try:
            for page in eks_client.get_paginator("list_fargate_profiles").paginate(
                clusterName=cluster
            ):
                fargate_profiles.setdefault(cluster, []).extend(
                    page.get("fargateProfileNames", [])
                )
        except Exception as error:
            unread.append(
                f"eks:ListFargateProfiles {cluster} "
                f"({get_assessment_error_label(error)})"
            )
    ecs_clusters = []
    try:
        ecs_client = boto3.client("ecs", config=boto3_config, region_name=region)
        for page in ecs_client.get_paginator("list_clusters").paginate():
            ecs_clusters.extend(
                str(arn).rsplit("/", 1)[-1] for arn in page.get("clusterArns", [])
            )
    except Exception as error:
        unread.append(f"ecs:ListClusters ({get_assessment_error_label(error)})")
    instances = []
    eks_nodes = 0
    windows = 0
    try:
        ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)
        for page in ec2_client.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tag_keys = [
                        tag.get("Key") or "" for tag in instance.get("Tags") or []
                    ]
                    if "eks:cluster-name" in tag_keys or any(
                        key.startswith("kubernetes.io/cluster/") for key in tag_keys
                    ):
                        eks_nodes += 1
                    elif instance.get("Platform") == "windows":
                        windows += 1
                    elif instance.get("InstanceId"):
                        instances.append(instance["InstanceId"])
    except Exception as error:
        unread.append(f"ec2:DescribeInstances ({get_assessment_error_label(error)})")
    excluded = (
        f"{eks_nodes} EKS node instance(s) are judged by their cluster's node count "
        f"and {windows} Windows instance(s) are not compared"
    )

    problems = []
    covered = {"EKS": set(), "ECS": set(), "EC2": set()}
    healthy = []
    for resource in resources:
        details = resource.get("ResourceDetails") or {}
        kind = details.get("ResourceType") or "resource"
        eks = details.get("EksClusterDetails") or {}
        ecs = details.get("EcsClusterDetails") or {}
        ec2 = details.get("Ec2InstanceDetails") or {}
        name = (
            eks.get("ClusterName")
            or ecs.get("ClusterName")
            or ec2.get("InstanceId")
            or resource.get("ResourceId")
        )
        if kind in covered and name:
            covered[kind].add(name)
        label = f"{kind} {name}"
        if resource.get("CoverageStatus") != "HEALTHY":
            issue = resource.get("Issue")
            problems.append(
                f"{label} is {resource.get('CoverageStatus') or 'without a status'}"
                + (f" ({str(issue)[:160]})" if issue else "")
            )
            continue
        if kind == "EKS":
            compatible = eks.get("CompatibleNodes")
            covered_nodes = eks.get("CoveredNodes")
            if not isinstance(compatible, int) or not isinstance(covered_nodes, int):
                unread.append(f"{label} reports no CompatibleNodes or CoveredNodes")
                continue
            if compatible == 0:
                problems.append(
                    f"{label} is HEALTHY with 0 compatible nodes, so no node "
                    "runs the GuardDuty agent"
                )
                continue
            if covered_nodes < compatible:
                problems.append(
                    f"{label} covers {covered_nodes} of {compatible} compatible nodes"
                )
                continue
        healthy.append(label)
    for cluster in eks_clusters:
        if cluster not in covered["EKS"]:
            problems.append(f"EKS cluster {cluster} has no Runtime Monitoring coverage")
        if fargate_profiles.get(cluster):
            problems.append(
                f"EKS cluster {cluster} has Fargate profile(s) "
                f"{', '.join(sorted(fargate_profiles[cluster])[:5])}, whose pods "
                "Runtime Monitoring does not cover"
            )
    for cluster in ecs_clusters:
        if cluster not in covered["ECS"]:
            problems.append(f"ECS cluster {cluster} has no Runtime Monitoring coverage")
    for instance_id in instances:
        if instance_id not in covered["EC2"]:
            problems.append(
                f"EC2 instance {instance_id} has no Runtime Monitoring coverage"
            )

    states = {
        config.get("Name"): config.get("Status")
        for config in runtime.get("AdditionalConfiguration") or []
    }
    unmanaged = [
        name
        for name in RUNTIME_MONITORING_AGENT_CONFIGS
        if states.get(name) != "ENABLED"
    ]
    rows = []
    if (
        not resources
        and not eks_clusters
        and not ecs_clusters
        and not instances
        and not unread
    ):
        if unmanaged:
            problems.append(
                "no host reports a Runtime Monitoring agent, and automated agent "
                f"management is not enabled for {', '.join(unmanaged)}"
            )
        else:
            rows.append(
                create_finding(
                    check_id="SM-38",
                    finding_name=RUNTIME_COVERAGE_FINDING,
                    finding_details=(
                        "Automated agent management is enabled for EKS, ECS Fargate "
                        "and EC2, no host is in coverage yet, and no running EC2 "
                        f"instance was found outside coverage ({excluded})."
                    ),
                    resolution="No action required",
                    reference=RUNTIME_COVERAGE_REFERENCE,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
    for problem in problems[:20]:
        rows.append(
            create_finding(
                check_id="SM-38",
                finding_name=RUNTIME_COVERAGE_FINDING,
                finding_details=(
                    f"Runtime Monitoring coverage: {problem}. {RUNTIME_UNSUPPORTED_NOTE}."
                ),
                resolution=(
                    "Enable automated agent management for the host type or install "
                    "the GuardDuty security agent, then resolve the coverage issue "
                    "GuardDuty reports until the resource is HEALTHY."
                ),
                reference=RUNTIME_COVERAGE_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )
    if len(problems) > 20:
        rows.append(
            create_finding(
                check_id="SM-38",
                finding_name=RUNTIME_COVERAGE_FINDING,
                finding_details=(
                    f"{len(problems)} Runtime Monitoring coverage gaps were found "
                    "(the first 20 are reported individually above)."
                ),
                resolution="Resolve each coverage gap until the resource is HEALTHY.",
                reference=RUNTIME_COVERAGE_REFERENCE,
                severity="High",
                status="Failed",
                region=region,
            )
        )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-38",
                RUNTIME_COVERAGE_FINDING,
                unread,
                f"{len(resources)} covered resource(s) were read.",
                RUNTIME_COVERAGE_REFERENCE,
                region,
            )
        )
    elif healthy and not problems:
        rows.append(
            create_finding(
                check_id="SM-38",
                finding_name=RUNTIME_COVERAGE_FINDING,
                finding_details=(
                    f"All {len(healthy)} resource(s) in Runtime Monitoring coverage "
                    "are HEALTHY, including every EKS cluster listed, each with "
                    "every compatible node covered and no Fargate profile, every "
                    "ECS cluster listed, and "
                    f"every running EC2 instance ({len(instances)}): "
                    f"{', '.join(healthy[:10])}. {excluded}."
                ),
                resolution="No action required",
                reference=RUNTIME_COVERAGE_REFERENCE,
                severity="High",
                status="Passed",
                region=region,
            )
        )
    return rows


EKS_AUDIT_LOGS_FINDING = "GuardDuty EKS Audit Log Monitoring"
EKS_AUDIT_LOGS_REFERENCE = (
    "https://docs.aws.amazon.com/guardduty/latest/ug/kubernetes-protection.html"
)


def _eks_audit_log_findings(
    region: str, detail: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Where EKS clusters exist, the detector must be ENABLED with its
    EKS_AUDIT_LOGS feature ENABLED. No cluster yields no row.
    """
    try:
        eks_client = boto3.client("eks", config=boto3_config, region_name=region)
        clusters = []
        for page in eks_client.get_paginator("list_clusters").paginate():
            clusters.extend(page.get("clusters", []))
    except Exception as error:
        return [
            _unread_resources_finding(
                "SM-38",
                EKS_AUDIT_LOGS_FINDING,
                [f"eks:ListClusters ({get_assessment_error_label(error)})"],
                "whether any EKS cluster needs audit log monitoring is unknown.",
                EKS_AUDIT_LOGS_REFERENCE,
                region,
            )
        ]
    if not clusters:
        return []
    shown = ", ".join(sorted(clusters)[:10])
    feature = _guardduty_feature(detail, "EKS_AUDIT_LOGS")
    state = feature.get("Status") if feature else "absent"
    if detail.get("Status") != "ENABLED":
        problem = "the GuardDuty detector is not enabled"
    elif state != "ENABLED":
        problem = f"the detector's EKS_AUDIT_LOGS feature is {state}"
    else:
        return [
            create_finding(
                check_id="SM-38",
                finding_name=EKS_AUDIT_LOGS_FINDING,
                finding_details=(
                    "GuardDuty EKS_AUDIT_LOGS is enabled on the detector for the "
                    f"{len(clusters)} EKS cluster(s) in this Region: {shown}."
                ),
                resolution="No action required",
                reference=EKS_AUDIT_LOGS_REFERENCE,
                severity="High",
                status="Passed",
                region=region,
            )
        ]
    return [
        create_finding(
            check_id="SM-38",
            finding_name=EKS_AUDIT_LOGS_FINDING,
            finding_details=(
                f"{len(clusters)} EKS cluster(s) run in this Region ({shown}), but "
                f"{problem}, so GuardDuty does not analyze their Kubernetes audit "
                "logs."
            ),
            resolution=(
                "Enable the GuardDuty detector and its EKS Protection "
                "(EKS_AUDIT_LOGS) feature."
            ),
            reference=EKS_AUDIT_LOGS_REFERENCE,
            severity="High",
            status="Failed",
            region=region,
        )
    ]


def _lambda_runtime_tier_findings(
    region: str, detail: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Lambda has no runtime agent, so the tier is GuardDuty Lambda Protection plus
    Inspector Lambda standard and code scanning, read per function.
    """
    problems = []
    unread = []
    lambda_logs = _guardduty_feature(detail, "LAMBDA_NETWORK_LOGS") if detail else None
    if detail.get("Status") != "ENABLED" or not (
        lambda_logs and lambda_logs.get("Status") == "ENABLED"
    ):
        problems.append(
            "GuardDuty Lambda Protection (LAMBDA_NETWORK_LOGS) is not enabled"
        )
    inspector = boto3.client("inspector2", config=boto3_config, region_name=region)
    try:
        accounts = inspector.batch_get_account_status().get("accounts") or []
        state = (accounts[0].get("resourceState") or {}) if accounts else {}
        for key, label in (("lambda", "standard"), ("lambdaCode", "code")):
            status = (state.get(key) or {}).get("status")
            if status != "ENABLED":
                problems.append(
                    f"Inspector Lambda {label} scanning is {status or 'not reported'}"
                )
    except Exception as error:
        unread.append(
            f"inspector2:BatchGetAccountStatus ({get_assessment_error_label(error)})"
        )
    scanned = {}
    try:
        for page in inspector.get_paginator("list_coverage").paginate(
            filterCriteria={
                "resourceType": [
                    {"comparison": "EQUALS", "value": "AWS_LAMBDA_FUNCTION"}
                ]
            }
        ):
            for resource in page.get("coveredResources", []):
                name = (
                    (resource.get("resourceMetadata") or {}).get("lambdaFunction") or {}
                ).get("functionName") or str(resource.get("resourceId"))
                scanned.setdefault(name, []).append(resource)
    except Exception as error:
        unread.append(f"inspector2:ListCoverage ({get_assessment_error_label(error)})")
        scanned = None
    functions = []
    try:
        lambda_client = boto3.client("lambda", config=boto3_config, region_name=region)
        for page in lambda_client.get_paginator("list_functions").paginate():
            functions.extend(page.get("Functions", []))
    except Exception as error:
        unread.append(f"lambda:ListFunctions ({get_assessment_error_label(error)})")
    if scanned is not None:
        for function in functions:
            name = function.get("FunctionName")
            entries = scanned.get(name) or scanned.get(function.get("FunctionArn"))
            if not entries:
                problems.append(
                    f"function {name} is not in Inspector coverage"
                    + (
                        " (a customer-managed KmsKeyArn removes Inspector scanning)"
                        if function.get("KMSKeyArn")
                        else ""
                    )
                )
                continue
            for entry in entries:
                status = entry.get("scanStatus") or {}
                if status.get("statusCode") != "ACTIVE":
                    problems.append(
                        f"function {name} {entry.get('scanType') or ''} scanning is "
                        f"{status.get('statusCode') or 'not reported'} "
                        f"({status.get('reason') or 'no reason'})".replace("  ", " ")
                    )
    rows = []
    for problem in problems[:20]:
        rows.append(
            create_finding(
                check_id="SM-38",
                finding_name=LAMBDA_RUNTIME_TIER_FINDING,
                finding_details=(
                    f"Lambda runtime tier: {problem}. Lambda has no runtime agent, "
                    "so this tier is the only managed detection for functions."
                ),
                resolution=(
                    "Enable GuardDuty Lambda Protection and Inspector Lambda standard "
                    "and code scanning, and keep each function eligible (no "
                    "InspectorExclusion tag, invoked or updated within 90 days, no "
                    "customer-managed KmsKeyArn unless the artifact is scanned in CI)."
                ),
                reference=LAMBDA_RUNTIME_TIER_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if len(problems) > 20:
        rows.append(
            create_finding(
                check_id="SM-38",
                finding_name=LAMBDA_RUNTIME_TIER_FINDING,
                finding_details=(
                    f"{len(problems)} Lambda runtime tier gaps were found (the first "
                    "20 are reported individually above)."
                ),
                resolution="Resolve each Lambda coverage gap.",
                reference=LAMBDA_RUNTIME_TIER_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-38",
                LAMBDA_RUNTIME_TIER_FINDING,
                unread,
                f"{len(functions)} function(s) were listed.",
                LAMBDA_RUNTIME_TIER_REFERENCE,
                region,
            )
        )
    elif not problems:
        rows.append(
            create_finding(
                check_id="SM-38",
                finding_name=LAMBDA_RUNTIME_TIER_FINDING,
                finding_details=(
                    "GuardDuty Lambda Protection and Inspector Lambda standard and "
                    f"code scanning are enabled, and all {len(functions)} function(s) "
                    "are ACTIVE in Inspector coverage."
                ),
                resolution="No action required",
                reference=LAMBDA_RUNTIME_TIER_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return rows


def check_guardduty_runtime_monitoring_coverage(
    region: str = "", detector_inventory: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    SM-38: Read Runtime Monitoring coverage per resource against the EKS and ECS
    cluster population, EKS audit log monitoring where EKS clusters exist, and
    the Lambda tier that stands in for a runtime agent.
    A detector with every agent-management option off and no manual agent
    fails here, where the feature flag alone reads as enabled.
    """
    findings = {"csv_data": []}
    try:
        inventory = detector_inventory or get_guardduty_detector_inventory(region)
        if inventory.get("error"):
            raise inventory["error"]
        detail = inventory.get("detail") or {}
        runtime = _guardduty_feature(detail, "RUNTIME_MONITORING")
        if (
            inventory.get("detector_id")
            and detail.get("Status") == "ENABLED"
            and runtime
            and runtime.get("Status") == "ENABLED"
        ):
            findings["csv_data"].extend(
                _runtime_coverage_findings(region, inventory["detector_id"], runtime)
            )
        findings["csv_data"].extend(_eks_audit_log_findings(region, detail))
        findings["csv_data"].extend(_lambda_runtime_tier_findings(region, detail))
    except Exception as error:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-38",
                finding_name=RUNTIME_COVERAGE_FINDING,
                finding_details=build_could_not_assess_detail(error, region),
                resolution=COULD_NOT_ASSESS_RESOLUTION,
                reference=RUNTIME_COVERAGE_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    return findings


EKS_NETWORK_POLICY_FINDING = "EKS VPC CNI Network Policy Enforcement"
EKS_NETWORK_POLICY_REFERENCE = (
    "https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.html"
)
EKS_NETWORK_POLICY_RESOLUTION = (
    "Set enableNetworkPolicy to true in the vpc-cni add-on configuration, then "
    "apply Kubernetes NetworkPolicy objects that limit each agent workload to "
    "the services it needs."
)


def _vpc_cni_network_policy_enabled(configuration_values: Any) -> bool:
    """
    Return whether a vpc-cni configurationValues string turns on network policy.

    EKS returns configurationValues as a JSON (or YAML) string, and the add-on
    schema types enableNetworkPolicy as the string "true", so both the string
    and a boolean true count.
    """
    if not isinstance(configuration_values, str) or not configuration_values.strip():
        return False
    value = None
    try:
        parsed = json.loads(configuration_values)
        if isinstance(parsed, dict):
            value = parsed.get("enableNetworkPolicy")
    except ValueError:
        match = re.search(
            r"^enableNetworkPolicy\s*:\s*[\"']?([A-Za-z]+)[\"']?\s*$",
            configuration_values,
            re.MULTILINE,
        )
        if match:
            value = match.group(1)
    return value is True or str(value).lower() == "true"


def check_eks_vpc_cni_network_policy(region: str = "") -> Dict[str, Any]:
    """
    SM-39: Verify EKS clusters that host self-hosted agent workloads enforce
    Kubernetes network policy through the managed vpc-cni add-on.
    """
    logger.debug("Starting check for EKS vpc-cni network policy")
    findings = {"csv_data": []}

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-39",
            finding_name=EKS_NETWORK_POLICY_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=EKS_NETWORK_POLICY_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        eks_client = boto3.client("eks", config=boto3_config, region_name=region)
        clusters = []
        for page in eks_client.get_paginator("list_clusters").paginate():
            clusters.extend(page.get("clusters", []))
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
        return findings

    if not clusters:
        findings["csv_data"].append(
            _row(
                "No EKS clusters found in this region.",
                "No action required",
                "Informational",
                "N/A",
            )
        )
        return findings

    enforced, not_enforced, self_managed, auto_mode, errors = [], [], [], [], []
    for cluster in clusters:
        try:
            detail = eks_client.describe_cluster(name=cluster).get("cluster", {})
            # Auto Mode sets network policy on the NodeClass and runs no managed
            # vpc-cni add-on, so it must not read as a self-managed CNI.
            if (detail.get("computeConfig") or {}).get("enabled") is True:
                auto_mode.append(cluster)
                continue
            addons = []
            paginator = eks_client.get_paginator("list_addons")
            for page in paginator.paginate(clusterName=cluster):
                addons.extend(page.get("addons", []))
            if "vpc-cni" not in addons:
                self_managed.append(cluster)
                continue
            addon = eks_client.describe_addon(
                clusterName=cluster, addonName="vpc-cni"
            ).get("addon", {})
            if _vpc_cni_network_policy_enabled(addon.get("configurationValues")):
                enforced.append(cluster)
            else:
                not_enforced.append(cluster)
        except Exception as error:
            errors.append((cluster, error))

    for cluster in not_enforced[:20]:
        findings["csv_data"].append(
            _row(
                f"EKS cluster '{cluster}' runs the managed vpc-cni add-on without "
                "enableNetworkPolicy set to true, so Kubernetes NetworkPolicy "
                "objects are not enforced between pods.",
                EKS_NETWORK_POLICY_RESOLUTION,
                "Medium",
                "Failed",
            )
        )
    if len(not_enforced) > 20:
        findings["csv_data"].append(
            _row(
                f"{len(not_enforced)} EKS clusters do not enforce network policy "
                "through vpc-cni (the first 20 are reported individually above).",
                EKS_NETWORK_POLICY_RESOLUTION,
                "Medium",
                "Failed",
            )
        )
    if enforced:
        findings["csv_data"].append(
            _row(
                f"{len(enforced)} EKS cluster(s): "
                f"{', '.join(sorted(enforced)[:5])}. Network-policy enforcement "
                "is enabled on the VPC CNI add-on; whether NetworkPolicy objects "
                "restrict pod traffic is a Kubernetes-API fact this scan cannot "
                "read.",
                "No action required",
                "Medium",
                "Passed",
            )
        )
    if self_managed:
        findings["csv_data"].append(
            _row(
                f"{len(self_managed)} EKS cluster(s) have no managed vpc-cni "
                f"add-on: {', '.join(sorted(self_managed)[:5])}. Network policy "
                "enforcement is not readable for a self-managed CNI.",
                "Confirm the cluster's CNI enforces Kubernetes NetworkPolicy, or "
                "migrate to the managed vpc-cni add-on.",
                "Informational",
                "N/A",
            )
        )
    if auto_mode:
        findings["csv_data"].append(
            _row(
                f"{len(auto_mode)} EKS cluster(s) run in EKS Auto Mode: "
                f"{', '.join(sorted(auto_mode)[:5])}. EKS Auto Mode sets network "
                "policy on the NodeClass, a Kubernetes object no AWS API returns.",
                "Confirm the cluster's NodeClass enables network policy and that "
                "NetworkPolicy objects restrict each agent workload.",
                "Informational",
                "N/A",
            )
        )
    for cluster, error in errors[:5]:
        findings["csv_data"].append(
            _row(
                f"EKS cluster '{cluster}': {build_could_not_assess_detail(error, region)}",
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
    return findings


EKS_POLICY_MODE_FINDING = "EKS Network Policy Default-Deny Mode"
EKS_POLICY_MODE_REFERENCE = (
    "https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html"
)
WORKLOAD_SEGMENTATION_FINDING = "Agent Workload Security Group Segmentation"
WORKLOAD_SEGMENTATION_REFERENCE = (
    "https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/"
    "security-network.html"
)
# AIR-SLF-RT-05 asks for security groups that reference each other in place of
# broad CIDR allowances and names no width. A CIDR of /16 (IPv6 /48) or wider
# fails; one wider than a /24 (IPv6 /64) but narrower than that is not judged.
BROAD_IPV4_PREFIX = 16
BROAD_IPV6_PREFIX = 48
UNJUDGED_IPV4_PREFIX = 23
UNJUDGED_IPV6_PREFIX = 63


def _vpc_cni_env_value(configuration_values: Any, key: str) -> Optional[str]:
    """Return one env entry of a vpc-cni configurationValues JSON or YAML string."""
    if not isinstance(configuration_values, str) or not configuration_values.strip():
        return None
    try:
        parsed = json.loads(configuration_values)
        env = parsed.get("env") if isinstance(parsed, dict) else None
        value = env.get(key) if isinstance(env, dict) else None
        return None if value is None else str(value)
    except ValueError:
        match = re.search(
            r"^env\s*:\s*\n((?:[ \t]+.*\n?)*)", configuration_values, re.MULTILINE
        )
        if not match:
            return None
        entry = re.search(
            rf"^[ \t]+{re.escape(key)}\s*:\s*[\"']?([^\"'\s]+)[\"']?\s*$",
            match.group(1),
            re.MULTILINE,
        )
        return entry.group(1) if entry else None


def _broad_rule_targets(
    permission: Dict[str, Any], prefix_lists: Dict[str, Optional[List[str]]]
) -> Tuple[List[str], List[str]]:
    """(broad, unjudged) CIDRs in one rule, split at the BROAD_ and UNJUDGED_ bounds.

    A customer-managed prefix list the rule names adds each of its entries,
    labelled with the list. An AWS-managed list (None) adds none.
    """
    cidrs = [
        (entry.get(field) or "", family, "")
        for key, field, family in (
            ("IpRanges", "CidrIp", "IPv4"),
            ("Ipv6Ranges", "CidrIpv6", "IPv6"),
        )
        for entry in permission.get(key) or []
    ]
    for entry in permission.get("PrefixListIds") or []:
        prefix_list_id = entry.get("PrefixListId")
        cidrs.extend(
            (cidr, "prefix list", f" in {prefix_list_id}")
            for cidr in prefix_lists.get(prefix_list_id) or []
        )
    broad, unjudged = [], []
    for cidr, family, where in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            broad.append((cidr or f"an unparsed {family} range") + where)
            continue
        if network.version == 4:
            broad_prefix, unjudged_prefix = BROAD_IPV4_PREFIX, UNJUDGED_IPV4_PREFIX
        else:
            broad_prefix, unjudged_prefix = BROAD_IPV6_PREFIX, UNJUDGED_IPV6_PREFIX
        if network.prefixlen <= broad_prefix:
            broad.append(cidr + where)
        elif network.prefixlen <= unjudged_prefix:
            unjudged.append(cidr + where)
    return broad, unjudged


def _prefix_list_cidrs(
    ec2_client: Any, users: Dict[str, List[str]]
) -> Tuple[Dict[str, Optional[List[str]]], List[str]]:
    """The entries of each customer-managed prefix list; None for AWS-managed.

    users maps each prefix list to the security groups whose rules name it.
    An AWS-managed list names one AWS service's published ranges, which are
    as wide as that service's address space, so its entries are not judged
    by width. A list whose owner or entries were not read is left out and
    named in the unread list.
    """
    if not users:
        return {}, []

    def where(prefix_list_id: str) -> str:
        return f"prefix list {prefix_list_id} in {', '.join(users[prefix_list_id][:3])}"

    owners = {}
    try:
        for page in ec2_client.get_paginator("describe_managed_prefix_lists").paginate(
            PrefixListIds=sorted(users)
        ):
            for prefix_list in page.get("PrefixLists", []):
                owners[prefix_list.get("PrefixListId")] = prefix_list.get("OwnerId")
    except Exception as error:
        label = get_assessment_error_label(error)
        return {}, [
            f"{where(prefix_list_id)} (ec2:DescribeManagedPrefixLists: {label})"
            for prefix_list_id in sorted(users)
        ]
    prefix_lists, unread = {}, []
    for prefix_list_id in sorted(users):
        if prefix_list_id not in owners:
            unread.append(
                f"{where(prefix_list_id)} (not returned by "
                "ec2:DescribeManagedPrefixLists)"
            )
            continue
        if owners[prefix_list_id] == "AWS":
            prefix_lists[prefix_list_id] = None
            continue
        try:
            entries = []
            for page in ec2_client.get_paginator(
                "get_managed_prefix_list_entries"
            ).paginate(PrefixListId=prefix_list_id):
                entries.extend(page.get("Entries", []))
        except Exception as error:
            unread.append(
                f"{where(prefix_list_id)} (ec2:GetManagedPrefixListEntries: "
                f"{get_assessment_error_label(error)})"
            )
            continue
        prefix_lists[prefix_list_id] = [
            str(entry.get("Cidr") or "") for entry in entries
        ]
    return prefix_lists, unread


def _rule_ports(permission: Dict[str, Any]) -> str:
    protocol = str(permission.get("IpProtocol"))
    if protocol == "-1":
        return "all traffic"
    low, high = permission.get("FromPort"), permission.get("ToPort")
    ports = str(low) if low == high else f"{low}-{high}"
    return f"{protocol} {ports}"


def _security_group_permissions(group: Dict[str, Any], check_ingress: bool):
    """(direction, preposition, permission) for each rule the check judges."""
    directions = [("egress", "IpPermissionsEgress", "to")]
    if check_ingress:
        directions.insert(0, ("ingress", "IpPermissions", "from"))
    for direction, key, preposition in directions:
        for permission in group.get(key) or []:
            yield direction, preposition, permission


def _security_group_problems(
    group: Dict[str, Any],
    check_ingress: bool,
    referenced: Dict[str, Any],
    unjudged: List[str],
    prefix_lists: Dict[str, Optional[List[str]]],
) -> List[str]:
    """Rule problems of one group; rules to an unjudged CIDR go to unjudged."""
    problems = []
    for direction, preposition, permission in _security_group_permissions(
        group, check_ingress
    ):
        rule = f"{group.get('GroupId')} allows {direction} {_rule_ports(permission)}"
        broad, between = _broad_rule_targets(permission, prefix_lists)
        if broad:
            problems.append(f"{rule} {preposition} {', '.join(broad[:3])}")
        if between:
            unjudged.append(f"{rule} {preposition} {', '.join(between[:3])}")
        for pair in permission.get("UserIdGroupPairs") or []:
            target = referenced.get(pair.get("GroupId")) or {}
            if target.get("GroupName") == "default":
                problems.append(
                    f"{rule} {preposition} {pair.get('GroupId')}, the default "
                    "security group of its VPC, which holds every resource "
                    "launched there without a security group of its own"
                )
    return problems


def _eks_policy_mode_findings(region: str) -> List[Dict[str, Any]]:
    """strict mode denies pod traffic until a NetworkPolicy allows it."""
    rows = []
    try:
        eks_client = boto3.client("eks", config=boto3_config, region_name=region)
        clusters = []
        for page in eks_client.get_paginator("list_clusters").paginate():
            clusters.extend(page.get("clusters", []))
    except Exception as error:
        return [
            _unread_resources_finding(
                "SM-39",
                EKS_POLICY_MODE_FINDING,
                [f"eks:ListClusters ({get_assessment_error_label(error)})"],
                "no cluster's enforcing mode was read.",
                EKS_POLICY_MODE_REFERENCE,
                region,
            )
        ]
    strict, unread = [], []
    for cluster in clusters:
        try:
            detail = eks_client.describe_cluster(name=cluster).get("cluster", {})
            if (detail.get("computeConfig") or {}).get("enabled") is True:
                continue
            addons = []
            for page in eks_client.get_paginator("list_addons").paginate(
                clusterName=cluster
            ):
                addons.extend(page.get("addons", []))
            if "vpc-cni" not in addons:
                continue
            values = (
                eks_client.describe_addon(clusterName=cluster, addonName="vpc-cni")
                .get("addon", {})
                .get("configurationValues")
            )
        except Exception as error:
            unread.append(f"{cluster} ({get_assessment_error_label(error)})")
            continue
        if not _vpc_cni_network_policy_enabled(values):
            continue
        mode = _vpc_cni_env_value(values, "NETWORK_POLICY_ENFORCING_MODE")
        pod_eni = _vpc_cni_env_value(values, "ENABLE_POD_ENI")
        pod_sg = (
            "security groups for pods are enabled"
            if str(pod_eni).lower() == "true"
            else "security groups for pods are not enabled"
        )
        if str(mode).lower() == "strict":
            strict.append(f"{cluster} ({pod_sg})")
            continue
        rows.append(
            create_finding(
                check_id="SM-39",
                finding_name=EKS_POLICY_MODE_FINDING,
                finding_details=(
                    f"EKS cluster '{cluster}' enforces network policy in "
                    f"{mode or 'standard (the default)'} mode, where a pod accepts "
                    "and sends all traffic until a NetworkPolicy selects it. No AWS "
                    "API returns the NetworkPolicy objects, so strict mode is the "
                    f"only readable default-deny. {pod_sg.capitalize()}."
                ),
                resolution=(
                    "Set env.NETWORK_POLICY_ENFORCING_MODE to strict in the vpc-cni "
                    "add-on configuration and author NetworkPolicy objects for each "
                    "agent workload's declared dependencies."
                ),
                reference=EKS_POLICY_MODE_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-39",
                EKS_POLICY_MODE_FINDING,
                unread,
                f"{len(strict)} cluster(s) were read in strict mode.",
                EKS_POLICY_MODE_REFERENCE,
                region,
            )
        )
    if strict:
        rows.append(
            create_finding(
                check_id="SM-39",
                finding_name=EKS_POLICY_MODE_FINDING,
                finding_details=(
                    f"{len(strict)} EKS cluster(s) enforce network policy in strict "
                    f"mode: {', '.join(sorted(strict)[:5])}. Pods are denied traffic "
                    "until a NetworkPolicy allows it; which policies exist is a "
                    "Kubernetes-API fact this scan cannot read."
                ),
                resolution="No action required",
                reference=EKS_POLICY_MODE_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return rows


def _ecs_services(region: str) -> Tuple[List[Tuple[str, Dict[str, Any]]], List[str]]:
    """Every ECS service in the region with its cluster name."""
    services, unread = [], []
    try:
        ecs_client = boto3.client("ecs", config=boto3_config, region_name=region)
        clusters = []
        for page in ecs_client.get_paginator("list_clusters").paginate():
            clusters.extend(page.get("clusterArns", []))
    except Exception as error:
        return [], [f"ecs:ListClusters ({get_assessment_error_label(error)})"]
    for cluster in clusters:
        cluster_name = str(cluster).rsplit("/", 1)[-1]
        try:
            arns = []
            for page in ecs_client.get_paginator("list_services").paginate(
                cluster=cluster
            ):
                arns.extend(page.get("serviceArns", []))
            for start in range(0, len(arns), 10):
                response = ecs_client.describe_services(
                    cluster=cluster, services=arns[start : start + 10]
                )
                for failure in response.get("failures") or []:
                    unread.append(
                        f"ECS service {failure.get('arn')} ({failure.get('reason')})"
                    )
                for service in response.get("services") or []:
                    services.append((cluster_name, service))
        except Exception as error:
            unread.append(
                f"ECS cluster {cluster_name} services "
                f"({get_assessment_error_label(error)})"
            )
    return services, unread


def _lambda_functions(region: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    try:
        lambda_client = boto3.client("lambda", config=boto3_config, region_name=region)
        functions = []
        for page in lambda_client.get_paginator("list_functions").paginate():
            functions.extend(page.get("Functions", []))
        return functions, []
    except Exception as error:
        return [], [f"lambda:ListFunctions ({get_assessment_error_label(error)})"]


def _ec2_instance_workloads(region: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Each Auto Scaling group, and each EC2 instance outside one, with its groups.

    Instances of one Auto Scaling group are replicas of one workload, so they
    share its security groups by design and count as one workload. Every
    network interface's groups are read, not only the primary interface's.
    """
    workloads: Dict[str, Dict[str, Any]] = {}
    try:
        ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)
        for page in ec2_client.get_paginator("describe_instances").paginate(
            Filters=[
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                }
            ]
        ):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tags = {
                        tag.get("Key"): tag.get("Value")
                        for tag in instance.get("Tags") or []
                    }
                    asg = tags.get("aws:autoscaling:groupName")
                    label = (
                        f"EC2 Auto Scaling group {asg}"
                        if asg
                        else f"EC2 instance {instance.get('InstanceId')}"
                    )
                    groups = workloads.setdefault(
                        label,
                        {"label": label, "groups": [], "awsvpc": True, "ingress": True},
                    )["groups"]
                    for group in [
                        *(instance.get("SecurityGroups") or []),
                        *(
                            group
                            for interface in instance.get("NetworkInterfaces") or []
                            for group in interface.get("Groups") or []
                        ),
                    ]:
                        if group.get("GroupId") and group["GroupId"] not in groups:
                            groups.append(group["GroupId"])
    except Exception as error:
        return [], [f"ec2:DescribeInstances ({get_assessment_error_label(error)})"]
    return list(workloads.values()), []


def _segmentation_workloads(region: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """ECS services, Lambda functions and EC2 workloads with their security groups."""
    workloads = []
    services, unread = _ecs_services(region)
    for cluster_name, service in services:
        awsvpc = (service.get("networkConfiguration") or {}).get(
            "awsvpcConfiguration"
        ) or {}
        workloads.append(
            {
                "label": (
                    f"ECS service {service.get('serviceName')} in {cluster_name}"
                ),
                "groups": awsvpc.get("securityGroups") or [],
                "awsvpc": bool(awsvpc),
                "ingress": True,
            }
        )
    functions, lambda_unread = _lambda_functions(region)
    unread.extend(lambda_unread)
    for function in functions:
        groups = (function.get("VpcConfig") or {}).get("SecurityGroupIds") or []
        workloads.append(
            {
                "label": f"Lambda function {function.get('FunctionName')}",
                "groups": groups,
                "awsvpc": bool(groups),
                "ingress": False,
            }
        )
    instances, instance_unread = _ec2_instance_workloads(region)
    unread.extend(instance_unread)
    workloads.extend(instances)
    return workloads, unread


def _workload_segmentation_findings(region: str) -> List[Dict[str, Any]]:
    workloads, unread = _segmentation_workloads(region)
    group_ids = sorted({g for w in workloads for g in w["groups"]})
    groups = {}
    try:
        ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)
        for start in range(0, len(group_ids), 100):
            response = ec2_client.describe_security_groups(
                GroupIds=group_ids[start : start + 100]
            )
            for group in response.get("SecurityGroups", []):
                groups[group.get("GroupId")] = group
    except Exception as error:
        unread.append(
            f"ec2:DescribeSecurityGroups ({get_assessment_error_label(error)})"
        )
        groups = None

    referenced = {}
    prefix_lists = {}
    if groups:
        pending = {}
        prefix_list_users = {}
        for group_id in group_ids:
            group = groups.get(group_id)
            if group is None:
                continue
            for _, _, permission in _security_group_permissions(group, True):
                for entry in permission.get("PrefixListIds") or []:
                    named_by = prefix_list_users.setdefault(
                        entry.get("PrefixListId") or "(no id)", []
                    )
                    if group_id not in named_by:
                        named_by.append(group_id)
                for pair in permission.get("UserIdGroupPairs") or []:
                    target = pair.get("GroupId")
                    if not target or target == group_id:
                        continue
                    if target in groups:
                        referenced[target] = groups[target]
                    elif pair.get("UserId") in (None, group.get("OwnerId")):
                        pending.setdefault(target, group_id)
                    else:
                        unread.append(
                            f"security group {target} referenced by {group_id} "
                            f"(owned by account {pair.get('UserId')})"
                        )
        targets = sorted(pending)
        try:
            for start in range(0, len(targets), 100):
                response = ec2_client.describe_security_groups(
                    GroupIds=targets[start : start + 100]
                )
                for group in response.get("SecurityGroups", []):
                    referenced[group.get("GroupId")] = group
        except Exception as error:
            unread.append(
                "ec2:DescribeSecurityGroups on referenced groups "
                f"({get_assessment_error_label(error)})"
            )
        else:
            unread.extend(
                f"security group {target} referenced by {pending[target]}"
                for target in targets
                if target not in referenced
            )
        prefix_lists, prefix_unread = _prefix_list_cidrs(ec2_client, prefix_list_users)
        unread.extend(prefix_unread)

    users = {}
    for workload in workloads:
        for group in workload["groups"]:
            users.setdefault(group, []).append(workload["label"])
    problems = []
    unjudged = []
    outside_vpc = []
    for workload in workloads:
        if not workload["awsvpc"]:
            if workload["ingress"]:
                problems.append(
                    f"{workload['label']} has no awsvpc network configuration, so "
                    "its tasks share the host network and no per-task security "
                    "group applies"
                )
            else:
                outside_vpc.append(workload["label"])
            continue
        found = []
        for group in workload["groups"]:
            shared = [u for u in users[group] if u != workload["label"]]
            if shared:
                found.append(
                    f"{group} is shared with {len(shared)} other workload(s) "
                    f"({', '.join(shared[:2])})"
                )
            if groups is not None:
                if group not in groups:
                    unread.append(f"security group {group}")
                    continue
                between = []
                found.extend(
                    _security_group_problems(
                        groups[group],
                        workload["ingress"],
                        referenced,
                        between,
                        prefix_lists,
                    )
                )
                unjudged.extend(f"{workload['label']}: {rule}" for rule in between)
        if found:
            problems.append(f"{workload['label']}: {'; '.join(found[:4])}")
    if outside_vpc:
        problems.append(
            f"{len(outside_vpc)} Lambda function(s) run outside a VPC, so no "
            f"security group bounds their egress: {', '.join(outside_vpc[:5])}"
        )

    rows = []
    for problem in problems[:20]:
        rows.append(
            create_finding(
                check_id="SM-39",
                finding_name=WORKLOAD_SEGMENTATION_FINDING,
                finding_details=(
                    f"{problem}. A workload reaches only its declared dependencies "
                    "when its own security group allows traffic to and from the "
                    "dependency's security group or prefix list, not the VPC "
                    f"default security group or a CIDR of /{BROAD_IPV4_PREFIX} "
                    f"(IPv6 /{BROAD_IPV6_PREFIX}) or wider, named directly or as "
                    "an entry of a customer-managed prefix list."
                ),
                resolution=(
                    "Give every agent service and function its own security group, "
                    "and replace CIDR rules with rules that reference the "
                    "dependency's security group, the AWS-managed prefix list of "
                    "the AWS service it calls, or a customer-managed prefix list "
                    "that holds only the dependency's ranges."
                ),
                reference=WORKLOAD_SEGMENTATION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if len(problems) > 20:
        rows.append(
            create_finding(
                check_id="SM-39",
                finding_name=WORKLOAD_SEGMENTATION_FINDING,
                finding_details=(
                    f"{len(problems)} workload segmentation gaps were found (the "
                    "first 20 are reported individually above)."
                ),
                resolution="Scope each workload's security group to its dependencies.",
                reference=WORKLOAD_SEGMENTATION_REFERENCE,
                severity="Medium",
                status="Failed",
                region=region,
            )
        )
    if unjudged:
        shown = "; ".join(unjudged[:10])
        if len(unjudged) > 10:
            shown += f"; and {len(unjudged) - 10} more"
        rows.append(
            create_finding(
                check_id="SM-39",
                finding_name=f"{WORKLOAD_SEGMENTATION_FINDING} CIDR Width Not Judged",
                finding_details=(
                    f"{len(unjudged)} rule(s) name a CIDR narrower than "
                    f"/{BROAD_IPV4_PREFIX} (IPv6 /{BROAD_IPV6_PREFIX}) and wider "
                    f"than /{UNJUDGED_IPV4_PREFIX + 1} "
                    f"(IPv6 /{UNJUDGED_IPV6_PREFIX + 1}): {shown}. AIR-SLF-RT-05 "
                    "asks for security groups that reference each other in place "
                    "of broad CIDR allowances and names no width, so this check "
                    f"fails /{BROAD_IPV4_PREFIX} (IPv6 /{BROAD_IPV6_PREFIX}) or "
                    f"wider, passes /{UNJUDGED_IPV4_PREFIX + 1} "
                    f"(IPv6 /{UNJUDGED_IPV6_PREFIX + 1}) or narrower, and does not "
                    "judge the ranges between."
                ),
                resolution=(
                    "Replace each CIDR named with a rule that references the "
                    "dependency's security group, or confirm the range holds only "
                    "the workload's declared dependencies."
                ),
                reference=WORKLOAD_SEGMENTATION_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-39",
                WORKLOAD_SEGMENTATION_FINDING,
                list(dict.fromkeys(unread)),
                f"{len(workloads)} ECS service(s), Lambda function(s) and EC2 "
                "instance(s) or Auto Scaling group(s) were read.",
                WORKLOAD_SEGMENTATION_REFERENCE,
                region,
            )
        )
    elif not problems and not unjudged:
        ec2_count = sum(1 for w in workloads if w["label"].startswith("EC2 "))
        rows.append(
            create_finding(
                check_id="SM-39",
                finding_name=WORKLOAD_SEGMENTATION_FINDING,
                finding_details=(
                    f"All {len(workloads) - ec2_count} ECS service(s) and Lambda "
                    f"function(s) and all {ec2_count} EC2 instance(s) or Auto Scaling "
                    "group(s) run "
                    "in their own security groups with no rule to or from the VPC "
                    "default security group or a CIDR wider than "
                    f"/{UNJUDGED_IPV4_PREFIX + 1} (IPv6 /{UNJUDGED_IPV6_PREFIX + 1}), "
                    "named directly or as an entry of a customer-managed prefix "
                    "list. A rule to an AWS-managed prefix list names one AWS "
                    "service's published ranges and is not judged by width. The "
                    "instances of one Auto Scaling group count as one workload; "
                    "every other instance counts as its own."
                    if workloads
                    else "No ECS services, Lambda functions or EC2 instances found "
                    "in this region."
                ),
                resolution="No action required",
                reference=WORKLOAD_SEGMENTATION_REFERENCE,
                severity="Medium" if workloads else "Informational",
                status="Passed" if workloads else "N/A",
                region=region,
            )
        )
    return rows


def check_workload_network_segmentation(region: str = "") -> Dict[str, Any]:
    """
    SM-39: Read the EKS network-policy enforcing mode and the security groups
    each ECS service, Lambda function and EC2 instance (one per Auto Scaling
    group) runs in, so a workload that can reach
    any destination does not pass on the vpc-cni flag alone.
    """
    findings = {"csv_data": []}
    findings["csv_data"].extend(_eks_policy_mode_findings(region))
    findings["csv_data"].extend(_workload_segmentation_findings(region))
    return findings


SECRET_ROTATION_FINDING = "Secrets Manager Automatic Rotation"
SECRET_ROTATION_REFERENCE = "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_schedule.html"
SECRET_ROTATION_RESOLUTION = (
    "Turn on automatic rotation with a rotation schedule for the secret, and "
    "investigate the rotation function if a scheduled rotation did not complete."
)

_CRON_MONTHS = {
    name: index
    for index, name in enumerate(
        ("JAN", "FEB", "MAR", "APR", "MAY", "JUN")
        + ("JUL", "AUG", "SEP", "OCT", "NOV", "DEC"),
        start=1,
    )
}
_CRON_WEEKDAYS = {
    name: index
    for index, name in enumerate(
        ("SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"), start=1
    )
}


def _cron_field_values(
    field: str, low: int, high: int, names: Dict[str, int]
) -> Optional[set]:
    """Expand one cron field of numbers, names, lists, ranges and steps."""
    values = set()
    for part in field.split(","):
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            if not step_text.isdigit() or int(step_text) < 1:
                return None
            step = int(step_text)
            part = part or "*"
        if part == "*":
            start, end = low, high
        elif "-" in part:
            start_text, end_text = part.split("-", 1)
            start = names.get(start_text.upper()) or _cron_int(start_text)
            end = names.get(end_text.upper()) or _cron_int(end_text)
            if start is None or end is None:
                return None
        else:
            start = names.get(part.upper()) or _cron_int(part)
            if start is None:
                return None
            end = high if step > 1 else start
        if not (low <= start <= high and low <= end <= high):
            return None
        values.update(range(start, end + 1, step))
    return values


def _cron_int(text: str) -> Optional[int]:
    return int(text) if text.isdigit() else None


def _cron_fire_days(expression: str, start: datetime, days: int) -> Optional[List]:
    """
    Return the dates a Secrets Manager cron() schedule fires on, or None when
    the expression uses a form this check does not interpret.
    """
    fields = expression.split()
    if len(fields) != 6 or fields[5] != "*":
        return None
    day_of_month, month_field, day_of_week = fields[2], fields[3], fields[4]
    months = _cron_field_values(month_field, 1, 12, _CRON_MONTHS)
    if months is None:
        return None

    dom_values, dom_last = None, False
    if day_of_month == "L":
        dom_last = True
    elif day_of_month not in ("?", "*"):
        dom_values = _cron_field_values(day_of_month, 1, 31, {})
        if dom_values is None:
            return None

    dow_values, dow_nth, dow_last = None, None, None
    if day_of_week not in ("?", "*"):
        nth = re.fullmatch(r"([A-Za-z]{3}|[1-7])#([1-5])", day_of_week)
        last = re.fullmatch(r"([A-Za-z]{3}|[1-7])L", day_of_week)
        if nth or last:
            token = (nth or last).group(1)
            weekday = _CRON_WEEKDAYS.get(token.upper()) or _cron_int(token)
            if weekday is None:
                return None
            if nth:
                dow_nth = (weekday, int(nth.group(2)))
            else:
                dow_last = weekday
        else:
            dow_values = _cron_field_values(day_of_week, 1, 7, _CRON_WEEKDAYS)
            if dow_values is None:
                return None

    fire_days = []
    for offset in range(days):
        day = (start + timedelta(days=offset)).date()
        if day.month not in months:
            continue
        cron_weekday = (day.isoweekday() % 7) + 1
        next_week_month = (day + timedelta(days=7)).month
        if dom_last and (day + timedelta(days=1)).month == day.month:
            continue
        if dom_values is not None and day.day not in dom_values:
            continue
        if dow_values is not None and cron_weekday not in dow_values:
            continue
        if dow_nth and (
            cron_weekday != dow_nth[0] or (day.day - 1) // 7 + 1 != dow_nth[1]
        ):
            continue
        if dow_last and (cron_weekday != dow_last or next_week_month == day.month):
            continue
        fire_days.append(day)
    return fire_days


def _rotation_interval_days(rotation_rules: Dict[str, Any]) -> Optional[float]:
    """
    Return the longest gap, in days, between two scheduled rotations, or None
    when the schedule cannot be interpreted.
    """
    expression = str(rotation_rules.get("ScheduleExpression") or "").strip()
    if expression:
        rate = re.fullmatch(r"rate\(\s*(\d+)\s+(hour|hours|day|days)\s*\)", expression)
        if rate:
            value = int(rate.group(1))
            return value / 24 if rate.group(2).startswith("hour") else float(value)
        cron = re.fullmatch(r"cron\((.+)\)", expression)
        if not cron:
            return None
        # Two years and a leap day covers every gap a yearly-bounded schedule
        # can produce, including a month-restricted one.
        fire_days = _cron_fire_days(
            cron.group(1), datetime(2024, 1, 1, tzinfo=timezone.utc), 800
        )
        if not fire_days or len(fire_days) < 2:
            return None
        return float(
            max(
                (later - earlier).days
                for earlier, later in zip(fire_days, fire_days[1:])
            )
        )
    days = rotation_rules.get("AutomaticallyAfterDays")
    if isinstance(days, int) and days > 0:
        return float(days)
    return None


# The default maxDaysSinceRotation of Security Hub control SecretsManager.4.
SECRET_ROTATION_MAX_DAYS = 90


def check_secrets_manager_rotation(region: str = "") -> Dict[str, Any]:
    """
    SM-40: Verify customer-managed secrets rotate automatically on a schedule of
    at most SECRET_ROTATION_MAX_DAYS and the last rotation happened within that
    schedule. Secrets owned by another AWS service (OwningService set) rotate
    under that service's control and are skipped.
    """
    logger.debug("Starting check for Secrets Manager rotation")
    findings = {"csv_data": []}

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-40",
            finding_name=SECRET_ROTATION_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=SECRET_ROTATION_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        client = boto3.client("secretsmanager", config=boto3_config, region_name=region)
        secrets = []
        for page in client.get_paginator("list_secrets").paginate():
            secrets.extend(page.get("SecretList", []))
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
        return findings

    in_scope = [secret for secret in secrets if not secret.get("OwningService")]
    skipped = len(secrets) - len(in_scope)
    skipped_note = (
        f" {skipped} secret(s) managed by another AWS service (OwningService set) "
        "were skipped."
        if skipped
        else ""
    )
    if not in_scope:
        findings["csv_data"].append(
            _row(
                "No customer-managed Secrets Manager secrets found in this region."
                + skipped_note,
                "No action required",
                "Informational",
                "N/A",
            )
        )
        return findings

    now = datetime.now(timezone.utc)
    failed, passed, uninterpretable = [], [], []
    for secret in in_scope:
        name = secret.get("Name") or secret.get("ARN") or "unnamed secret"
        if secret.get("RotationEnabled") is not True:
            failed.append(f"Secret '{name}' has no automatic rotation configured.")
            continue
        last_rotated = secret.get("LastRotatedDate")
        if not isinstance(last_rotated, datetime):
            failed.append(
                f"Secret '{name}' has automatic rotation turned on but has never "
                "rotated."
            )
            continue
        if last_rotated.tzinfo is None:
            last_rotated = last_rotated.replace(tzinfo=timezone.utc)
        interval = _rotation_interval_days(secret.get("RotationRules") or {})
        if interval is None:
            uninterpretable.append(name)
            continue
        if interval > SECRET_ROTATION_MAX_DAYS:
            failed.append(
                f"Secret '{name}' rotates on a schedule with a gap of up to "
                f"{interval:g} days, longer than {SECRET_ROTATION_MAX_DAYS} days, "
                "the default maximum of Security Hub control SecretsManager.4."
            )
            continue
        age_days = (now - last_rotated).total_seconds() / 86400
        if age_days > interval + 1:
            failed.append(
                f"Secret '{name}' last rotated {int(age_days)} days ago, beyond its "
                f"{interval:g}-day schedule plus one day, so a scheduled rotation "
                "did not complete."
            )
        else:
            passed.append(name)

    for detail in failed[:20]:
        findings["csv_data"].append(
            _row(detail, SECRET_ROTATION_RESOLUTION, "Medium", "Failed")
        )
    if len(failed) > 20:
        findings["csv_data"].append(
            _row(
                f"{len(failed)} secrets are not rotating on schedule (the first 20 "
                "are reported individually above).",
                SECRET_ROTATION_RESOLUTION,
                "Medium",
                "Failed",
            )
        )
    if passed:
        findings["csv_data"].append(
            _row(
                f"{len(passed)} secret(s) rotate automatically and last rotated "
                f"within their schedule: {', '.join(sorted(passed)[:5])}. Whether "
                "running agents pick up the rotated value is not read by this "
                "check." + skipped_note,
                "No action required",
                "Medium",
                "Passed",
            )
        )
    if uninterpretable:
        findings["csv_data"].append(
            _row(
                f"{len(uninterpretable)} secret(s) rotate on a schedule this check "
                f"does not interpret: {', '.join(sorted(uninterpretable)[:5])}. "
                "Whether their last rotation is on time was not assessed.",
                "Confirm in the Secrets Manager console that the last rotation "
                "date falls within the schedule.",
                "Informational",
                "N/A",
            )
        )
    return findings


SECRET_HISTORY_FINDING = "Secrets Manager Rotation History"
SECRET_HISTORY_REFERENCE = (
    "https://docs.aws.amazon.com/secretsmanager/latest/userguide/"
    "monitoring-cloudtrail.html"
)
SECRET_PROPAGATION_FINDING = "Rotated Secret Propagation"
SECRET_PROPAGATION_REFERENCE = (
    "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/"
    "secrets-envvar-secrets-manager.html"
)
PLAINTEXT_CREDENTIAL_FINDING = "Credential Held Outside Secrets Manager"
ROTATION_FAILURE_EVENTS = ("RotationFailed", "RotationAbandoned")
ROTATION_STALL_HOURS = 24
SECRETS_EXTENSION_LAYER = "AWS-Parameters-and-Secrets-Lambda-Extension"
# Anchored at the end so SECRET_NAME, TOKEN_ENDPOINT and PASSWORD_LENGTH,
# which name a reference or a setting, do not match.
_CREDENTIAL_NAME = re.compile(
    r"(PASSWORD|PASSWD|SECRET|SECRET_?KEY|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY"
    r"|CREDENTIALS?)$",
    re.IGNORECASE,
)


def _looks_like_plaintext_credential(name: str, value: Any) -> bool:
    """A credential-named variable whose value is not a reference to a store."""
    if not _CREDENTIAL_NAME.search(name):
        return False
    text = str(value or "").strip()
    return bool(text) and not text.startswith("arn:")


def _secret_arn_prefix(value_from: str) -> Optional[str]:
    """The secret ARN inside an ECS valueFrom, without a JSON key suffix."""
    parts = str(value_from).split(":")
    if len(parts) >= 7 and parts[2] == "secretsmanager" and parts[5] == "secret":
        return ":".join(parts[:7])
    return None


def _capped_problem_rows(
    check_id, name, problems, resolution, reference, severity, region, noun
):
    rows = [
        create_finding(
            check_id=check_id,
            finding_name=name,
            finding_details=problem,
            resolution=resolution,
            reference=reference,
            severity=severity,
            status="Failed",
            region=region,
        )
        for problem in problems[:20]
    ]
    if len(problems) > 20:
        rows.append(
            create_finding(
                check_id=check_id,
                finding_name=name,
                finding_details=(
                    f"{len(problems)} {noun} were found (the first 20 are reported "
                    "individually above)."
                ),
                resolution=resolution,
                reference=reference,
                severity=severity,
                status="Failed",
                region=region,
            )
        )
    return rows


def _rotation_events(region: str) -> Dict[str, List[Tuple[str, datetime]]]:
    """Secret ARN or name to (event name, time) for the last 90 days."""
    client = boto3.client("cloudtrail", config=boto3_config, region_name=region)
    events = {}
    for event_name in ("RotationStarted",) + ROTATION_FAILURE_EVENTS:
        for page in client.get_paginator("lookup_events").paginate(
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": event_name}
            ]
        ):
            for event in page.get("Events", []):
                try:
                    record = json.loads(event.get("CloudTrailEvent") or "{}")
                except ValueError:
                    record = {}
                secret = (record.get("additionalEventData") or {}).get("SecretId") or (
                    record.get("requestParameters") or {}
                ).get("secretId")
                when = event.get("EventTime")
                if secret and isinstance(when, datetime):
                    if when.tzinfo is None:
                        when = when.replace(tzinfo=timezone.utc)
                    events.setdefault(secret, []).append((event_name, when))
    return events


def _rotation_history_findings(
    region: str, secrets: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    rotating = [s for s in secrets if s.get("RotationEnabled") is True]
    if not rotating:
        return []
    try:
        events = _rotation_events(region)
    except Exception as error:
        return [
            _unread_resources_finding(
                "SM-40",
                SECRET_HISTORY_FINDING,
                [f"cloudtrail:LookupEvents ({get_assessment_error_label(error)})"],
                f"{len(rotating)} rotating secret(s) have no history read.",
                SECRET_HISTORY_REFERENCE,
                region,
            )
        ]
    now = datetime.now(timezone.utc)
    problems, in_progress, clean, started = [], [], [], 0
    for secret in rotating:
        name = secret.get("Name") or secret.get("ARN")
        history = events.get(secret.get("ARN"), []) + events.get(secret.get("Name"), [])
        last = secret.get("LastRotatedDate")
        if isinstance(last, datetime) and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        after = [
            (event, when)
            for event, when in history
            if not isinstance(last, datetime) or when > last
        ]
        failure = max(
            (w for e, w in after if e in ROTATION_FAILURE_EVENTS), default=None
        )
        start = max((w for e, w in after if e == "RotationStarted"), default=None)
        if any(e == "RotationStarted" for e, _ in history):
            started += 1
        if failure:
            problems.append(
                f"Secret '{name}' recorded a rotation failure at "
                f"{failure.isoformat()} and has not rotated since."
            )
        elif start and now - start > timedelta(hours=ROTATION_STALL_HOURS):
            problems.append(
                f"Secret '{name}' started a rotation at {start.isoformat()} that "
                "has not completed: LastRotatedDate is older than the start."
            )
        elif start:
            in_progress.append(f"secret {name} (rotation started {start.isoformat()})")
        else:
            clean.append(name)
    rows = _capped_problem_rows(
        "SM-40",
        SECRET_HISTORY_FINDING,
        problems,
        "Read the rotation function's logs, fix the failing step, and rotate the "
        "secret again.",
        SECRET_HISTORY_REFERENCE,
        "Medium",
        region,
        "secrets with a failed or stalled rotation",
    )
    if in_progress:
        rows.append(
            _unread_resources_finding(
                "SM-40",
                SECRET_HISTORY_FINDING,
                in_progress,
                "a rotation in progress has no outcome yet.",
                SECRET_HISTORY_REFERENCE,
                region,
            )
        )
    if clean and not problems and not in_progress:
        rows.append(
            create_finding(
                check_id="SM-40",
                finding_name=SECRET_HISTORY_FINDING,
                finding_details=(
                    f"None of the {len(clean)} rotating secret(s) recorded a "
                    "failed, abandoned or stalled rotation in the 90 days of "
                    f"CloudTrail event history; {started} recorded a "
                    "RotationStarted event in that window."
                ),
                resolution="No action required",
                reference=SECRET_HISTORY_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return rows


def _rotation_redeploy_rules(region: str) -> List[str]:
    """ENABLED default-bus rules on aws.secretsmanager that have a target."""
    client = boto3.client("events", config=boto3_config, region_name=region)
    rules = []
    for page in client.get_paginator("list_rules").paginate():
        for rule in page.get("Rules", []):
            if rule.get("State") != "ENABLED":
                continue
            try:
                pattern = json.loads(rule.get("EventPattern") or "{}")
            except ValueError:
                continue
            sources = pattern.get("source") if isinstance(pattern, dict) else None
            if isinstance(sources, str):
                sources = [sources]
            if not isinstance(sources, list) or "aws.secretsmanager" not in sources:
                continue
            names = (pattern.get("detail") or {}).get("eventName")
            if isinstance(names, list) and not any(
                str(n).startswith("Rotation") for n in names
            ):
                continue
            targets = []
            for target_page in client.get_paginator("list_targets_by_rule").paginate(
                Rule=rule.get("Name")
            ):
                targets.extend(target_page.get("Targets", []))
            if targets:
                rules.append(rule.get("Name"))
    return rules


def _sagemaker_model_environments(
    region: str,
) -> Tuple[List[Tuple[str, Dict[str, Any]]], int, List[str]]:
    """(where, Environment) of every container of every model, the model count, unread."""
    try:
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        names = []
        for page in sagemaker_client.get_paginator("list_models").paginate():
            names.extend(m.get("ModelName") for m in page.get("Models", []))
    except Exception as error:
        return [], 0, [f"sagemaker:ListModels ({get_assessment_error_label(error)})"]
    environments, unread = [], []
    for name in names:
        try:
            model = sagemaker_client.describe_model(ModelName=name)
        except Exception as error:
            unread.append(
                f"SageMaker model {name} ({get_assessment_error_label(error)})"
            )
            continue
        containers = (
            [model["PrimaryContainer"]] if model.get("PrimaryContainer") else []
        )
        containers.extend(model.get("Containers") or [])
        for index, container in enumerate(containers, start=1):
            environments.append(
                (
                    f"SageMaker model {name}, container {index}",
                    container.get("Environment") or {},
                )
            )
    return environments, len(names), unread


def _propagation_and_plaintext_findings(
    region: str, secrets: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    rotating = {
        s.get("ARN"): s.get("Name") for s in secrets if s.get("RotationEnabled") is True
    }
    # AIR-SLF-RT-06: ECS accepts a partial ARN, which omits the six-character
    # suffix Secrets Manager appends, so each secret is keyed both ways.
    known = {}
    for secret in secrets:
        arn = str(secret.get("ARN") or "")
        if not arn:
            continue
        known.setdefault(arn[:-7] if re.search(r"-[A-Za-z0-9]{6}$", arn) else arn, arn)
    for secret in secrets:
        if secret.get("ARN"):
            known[secret["ARN"]] = secret["ARN"]
    services, unread = _ecs_services(region)
    functions, lambda_unread = _lambda_functions(region)
    unread.extend(lambda_unread)
    injected, parameters, plaintext = [], [], []
    ecs_client = boto3.client("ecs", config=boto3_config, region_name=region)
    task_definitions = {}
    for cluster_name, service in services:
        if service.get("status") != "ACTIVE":
            continue
        arn = service.get("taskDefinition")
        label = f"ECS service {service.get('serviceName')} in {cluster_name}"
        if arn not in task_definitions:
            try:
                task_definitions[arn] = ecs_client.describe_task_definition(
                    taskDefinition=arn
                ).get("taskDefinition", {})
            except Exception as error:
                task_definitions[arn] = None
                unread.append(
                    f"task definition {arn} ({get_assessment_error_label(error)})"
                )
        definition = task_definitions[arn]
        if definition is None:
            continue
        for container in definition.get("containerDefinitions") or []:
            where = f"{label}, container {container.get('name')}"
            for entry in container.get("secrets") or []:
                value_from = str(entry.get("valueFrom") or "")
                secret_arn = _secret_arn_prefix(value_from)
                if secret_arn is not None and secret_arn not in known:
                    unread.append(
                        f"{where} injects secret {secret_arn}, which is not among "
                        f"the secrets listed in {region or 'this region'} (another "
                        "account's or Region's secret), so whether it rotates was "
                        "not read"
                    )
                    continue
                secret_arn = known.get(secret_arn)
                if secret_arn in rotating:
                    injected.append(
                        f"{where} injects rotating secret '{rotating[secret_arn]}'"
                    )
                elif secret_arn is None:
                    parameters.append(
                        f"{where} injects {entry.get('name')} from Parameter Store "
                        f"({value_from.rsplit(':', 1)[-1][:120]}), which has no "
                        "automatic rotation"
                    )
            for entry in container.get("environment") or []:
                if _looks_like_plaintext_credential(
                    str(entry.get("name")), entry.get("value")
                ):
                    plaintext.append(
                        f"{where} sets {entry.get('name')} as a plaintext environment "
                        "variable"
                    )
    extension_users = 0
    for function in functions:
        if any(
            SECRETS_EXTENSION_LAYER in str(layer.get("Arn"))
            for layer in function.get("Layers") or []
        ):
            extension_users += 1
        variables = (function.get("Environment") or {}).get("Variables") or {}
        for name, value in variables.items():
            if _looks_like_plaintext_credential(name, value):
                plaintext.append(
                    f"Lambda function {function.get('FunctionName')} sets {name} as a "
                    "plaintext environment variable"
                )
    model_environments, model_count, model_unread = _sagemaker_model_environments(
        region
    )
    unread.extend(model_unread)
    for where, variables in model_environments:
        for name, value in variables.items():
            if _looks_like_plaintext_credential(name, value):
                plaintext.append(
                    f"{where} sets {name} as a plaintext environment variable"
                )

    rows = []
    stale = []
    redeploy = None
    if injected:
        try:
            redeploy = _rotation_redeploy_rules(region)
        except Exception as error:
            redeploy = None
            unread.append(f"events:ListRules ({get_assessment_error_label(error)})")
        if redeploy == []:
            stale = [
                f"{entry}. ECS resolves the value at task start, and no ENABLED "
                "EventBridge rule on aws.secretsmanager rotation events has a "
                "target, so a rotation does not reach running tasks"
                for entry in injected
            ]
    rows.extend(
        _capped_problem_rows(
            "SM-40",
            SECRET_PROPAGATION_FINDING,
            [f"{p}." for p in stale + parameters],
            "Fetch the secret at runtime with secretsmanager:GetSecretValue under "
            "the task role, or route the rotation event to an update-service "
            "--force-new-deployment, and move Parameter Store credentials to a "
            "rotating Secrets Manager secret.",
            SECRET_PROPAGATION_REFERENCE,
            "Medium",
            region,
            "secret propagation gaps",
        )
    )
    rows.extend(
        _capped_problem_rows(
            "SM-40",
            PLAINTEXT_CREDENTIAL_FINDING,
            [
                f"{p}. A credential set in configuration is outside any rotation "
                "schedule (matched on the variable name; the value is not logged)."
                for p in plaintext
            ],
            "Store the credential in Secrets Manager with automatic rotation and "
            "read it at runtime or through the Parameters and Secrets extension.",
            SECRET_ROTATION_REFERENCE,
            "Medium",
            region,
            "plaintext credentials",
        )
    )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-40",
                SECRET_PROPAGATION_FINDING,
                list(dict.fromkeys(unread)),
                f"{len(services)} ECS service(s), {len(functions)} Lambda "
                f"function(s) and {model_count} SageMaker model(s) were read.",
                SECRET_PROPAGATION_REFERENCE,
                region,
            )
        )
    elif redeploy:
        shown = "; ".join(injected[:10])
        rows.append(
            create_finding(
                check_id="SM-40",
                finding_name=SECRET_PROPAGATION_FINDING,
                finding_details=(
                    f"{len(injected)} injection(s) of a rotating secret rely on "
                    f"ENABLED EventBridge rotation rule(s) {', '.join(redeploy[:10])} "
                    "with a target: "
                    f"{shown}. This check lists each target but does not read what "
                    "it runs, so whether a target redeploys the service after a "
                    "rotation was not assessed."
                ),
                resolution="Confirm that each rule's target forces a new "
                "deployment of the services that inject the secret, or fetch the "
                "secret from Secrets Manager at runtime.",
                reference=SECRET_PROPAGATION_REFERENCE,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    elif not stale and not parameters:
        rows.append(
            create_finding(
                check_id="SM-40",
                finding_name=SECRET_PROPAGATION_FINDING,
                finding_details=(
                    "No ECS task injects a rotating secret, and none injects from "
                    "Parameter Store. Lambda functions "
                    "are not graded: no API shows whether a function re-fetches per "
                    "invocation or caches at init; "
                    f"{extension_users} of {len(functions)} use the Parameters and "
                    "Secrets extension."
                ),
                resolution="No action required",
                reference=SECRET_PROPAGATION_REFERENCE,
                severity="Medium",
                status="Passed",
                region=region,
            )
        )
    return rows


def check_secret_rotation_history_and_propagation(region: str = "") -> Dict[str, Any]:
    """
    SM-40: Read rotation outcomes from CloudTrail and whether a rotated value
    reaches the ECS tasks that inject it, and find credentials held in plaintext
    ECS, Lambda and SageMaker model environment variables outside any rotation.
    """
    findings = {"csv_data": []}
    try:
        client = boto3.client("secretsmanager", config=boto3_config, region_name=region)
        secrets = []
        for page in client.get_paginator("list_secrets").paginate():
            secrets.extend(
                s for s in page.get("SecretList", []) if not s.get("OwningService")
            )
    except Exception as error:
        findings["csv_data"].append(
            _unread_resources_finding(
                "SM-40",
                SECRET_PROPAGATION_FINDING,
                [f"secretsmanager:ListSecrets ({get_assessment_error_label(error)})"],
                "no secret was read.",
                SECRET_PROPAGATION_REFERENCE,
                region,
            )
        )
        return findings
    findings["csv_data"].extend(_rotation_history_findings(region, secrets))
    findings["csv_data"].extend(_propagation_and_plaintext_findings(region, secrets))
    return findings


IOT_DEVICE_POLICY_FINDING = "AWS IoT Device-Scoped Policy"
IOT_DEVICE_POLICY_REFERENCE = (
    "https://docs.aws.amazon.com/iot/latest/developerguide/thing-policy-variables.html"
)
IOT_DEVICE_POLICY_RESOLUTION = (
    "Scope the Publish, Subscribe and Receive resources to topics that embed "
    "${iot:Connection.Thing.ThingName}, scope Connect to that thing's client ID, "
    "and add a Bool condition requiring iot:Connection.Thing.IsAttached to be "
    "true on Connect."
)
IOT_DEVICE_ACTIONS = ("iot:publish", "iot:subscribe", "iot:receive", "iot:connect")
IOT_THING_NAME_VARIABLE = "${iot:Connection.Thing.ThingName}"
IOT_UNIQUE_CERTIFICATE_FINDING = "AWS IoT Unique Device Certificate"
IOT_UNIQUE_CERTIFICATE_REFERENCE = (
    "https://docs.aws.amazon.com/iot/latest/developerguide/x509-client-certs.html"
)
IOT_AUDIT_FINDING = "AWS IoT Device Defender Audit"
IOT_AUDIT_REFERENCE = (
    "https://docs.aws.amazon.com/iot-device-defender/latest/devguide/"
    "device-defender-audit.html"
)
IOT_SHARED_CERTIFICATE_CHECK = "DEVICE_CERTIFICATE_SHARED_CHECK"
IOT_ROLE_ALIAS_FINDING = "AWS IoT Role Alias Device Scope"
IOT_ROLE_ALIAS_REFERENCE = (
    "https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html"
)
IOT_AUDIT_FINDING_WINDOW_DAYS = 31


def _iot_statement_actions(statement: Dict[str, Any]) -> List[str]:
    """Return the device actions an Allow statement reaches."""
    if "NotAction" in statement:
        excluded = [
            value.lower() for value in _policy_values(statement.get("NotAction"))
        ]
        return [
            action
            for action in IOT_DEVICE_ACTIONS
            if not any(fnmatch.fnmatchcase(action, pattern) for pattern in excluded)
        ]
    patterns = [value.lower() for value in _policy_values(statement.get("Action"))]
    return [
        action
        for action in IOT_DEVICE_ACTIONS
        if any(fnmatch.fnmatchcase(action, pattern) for pattern in patterns)
    ]


def _iot_resource_bounded_to_thing(resource: str) -> bool:
    """
    True when the thing-name variable fills a whole path segment.

    A resource without the variable reaches every device's topic, and a
    wildcard or other text right after it (topic/${ThingName}*) reaches the
    topics of every thing whose name starts with this one. Right before it
    (topic/*${ThingName}) it reaches every thing whose name ends with this one.
    """
    parts = resource.split(IOT_THING_NAME_VARIABLE)
    if len(parts) < 2:
        return False
    # A wildcard before the variable (topic/*/${ThingName}) matches across
    # path segments, so it reaches topics under other devices' names too.
    path = parts[0].split(":", 5)[-1] if parts[0].startswith("arn:") else parts[0]
    if "*" in path or "?" in path:
        return False
    return all(part.endswith("/") for part in parts[:-1]) and all(
        part == "" or part.startswith("/") for part in parts[1:]
    )


def _iot_broad_resource(statement: Dict[str, Any]) -> Optional[str]:
    if "NotResource" in statement:
        return "NotResource"
    for resource in _policy_values(statement.get("Resource")):
        if not _iot_resource_bounded_to_thing(str(resource)):
            return resource
    return None


def _iot_requires_attached_thing(statement: Dict[str, Any]) -> bool:
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict):
        return False
    for operator, condition_keys in condition.items():
        operator_name = str(operator).lower()
        if not isinstance(condition_keys, dict) or "not" in operator_name:
            continue
        if operator_name.endswith("null") or operator_name.endswith("ifexists"):
            continue
        for key, value in condition_keys.items():
            if str(key).lower() != "iot:connection.thing.isattached":
                continue
            if "true" in [str(item).lower() for item in _policy_values(value)]:
                return True
            if value is True:
                return True
    return False


def _iot_policy_problems(document: Any) -> List[str]:
    problems = []
    for statement in _sm_policy_statements(document):
        if str(statement.get("Effect", "")).upper() != "ALLOW":
            continue
        actions = _iot_statement_actions(statement)
        if not actions:
            continue
        resource = _iot_broad_resource(statement)
        if resource:
            problems.append(
                f"allows {', '.join(a.split(':')[1].capitalize() for a in actions)} on "
                f"'{resource}' without the thing-name policy variable bounding a "
                "path segment"
            )
        if "iot:connect" in actions and not _iot_requires_attached_thing(statement):
            problems.append(
                "allows Connect without requiring the certificate to be attached "
                "to a thing"
            )
    return problems


CREDENTIALS_IOT_VARIABLE = "${credentials-iot:"


def _credentials_iot_bounded(value: str) -> bool:
    """True when a value names a credentials-iot variable with no wildcard before it."""
    text = str(value).lower()
    if CREDENTIALS_IOT_VARIABLE not in text:
        return False
    before = text.split(CREDENTIALS_IOT_VARIABLE, 1)[0]
    if before.startswith("arn:"):
        before = before.split(":", 5)[-1]
    return "*" not in before and "?" not in before


def _credentials_iot_scoped(statement: Dict[str, Any]) -> bool:
    """
    AIR-PHY-EDG-01: an Allow is device-scoped when every Resource value is
    bounded by a credentials-iot variable, or a positive condition requires a
    value bounded by one. A Not operator, IfExists, Null or ForAllValues (true
    on an absent key) leaves the grant open to every device.
    """
    resources = _policy_values(statement.get("Resource"))
    if (
        "NotResource" not in statement
        and resources
        and all(_credentials_iot_bounded(r) for r in resources)
    ):
        return True
    for operator, _, values in _condition_entries(statement):
        prefix, base, if_exists = _condition_operator_parts(operator)
        if if_exists or "not" in base or base == "null" or prefix == "forallvalues":
            continue
        if values and all(_credentials_iot_bounded(v) for v in values):
            return True
    return False


def _iot_role_alias_findings(
    iot_client, region: str, permission_cache: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    SM-41: each credentials-provider role alias's IAM role scopes a device by a
    credentials-iot policy variable in at least one Allow statement.
    """
    try:
        aliases = []
        for page in iot_client.get_paginator("list_role_aliases").paginate():
            aliases.extend(page.get("roleAliases") or [])
    except Exception as error:
        return [
            _unread_resources_finding(
                "SM-41",
                IOT_ROLE_ALIAS_FINDING,
                [f"iot:ListRoleAliases ({get_assessment_error_label(error)})"],
                "no role alias was read.",
                IOT_ROLE_ALIAS_REFERENCE,
                region,
            )
        ]
    if not aliases:
        return []
    cached = (permission_cache or {}).get("role_permissions") or {}
    unread_principals = (
        set(_principal_read_errors(permission_cache) or [])
        if permission_cache
        else set()
    )
    scoped, unscoped, unread = [], [], []
    for alias in aliases:
        try:
            description = (
                iot_client.describe_role_alias(roleAlias=alias).get(
                    "roleAliasDescription"
                )
                or {}
            )
        except Exception as error:
            unread.append(f"role alias '{alias}' ({get_assessment_error_label(error)})")
            continue
        role_arn = description.get("roleArn")
        name = _role_name_from_arn(role_arn) if role_arn else None
        if not name:
            unread.append(f"role alias '{alias}' (no roleArn returned)")
        elif permission_cache is None:
            unread.append(
                f"role alias '{alias}' role {role_arn} (the IAM permissions cache "
                "was not available)"
            )
        elif name not in cached:
            unread.append(
                f"role alias '{alias}' role {role_arn} (not in the IAM cache)"
            )
        elif any(p.startswith(f"role '{name}' ") for p in unread_principals):
            unread.append(
                f"role alias '{alias}' role {role_arn} (IAM cache read error)"
            )
        else:
            allows = [
                statement
                for policy in (cached[name].get("attached_policies") or [])
                + (cached[name].get("inline_policies") or [])
                for statement in _sm_policy_statements(policy.get("document"))
                if str(statement.get("Effect", "")).upper() == "ALLOW"
            ]
            open_sids = [
                str(statement.get("Sid") or f"statement {index + 1}")
                for index, statement in enumerate(allows)
                if not _credentials_iot_scoped(statement)
            ]
            if allows and not open_sids:
                scoped.append(alias)
            else:
                unscoped.append((alias, name, open_sids))

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-41",
            finding_name=IOT_ROLE_ALIAS_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=IOT_ROLE_ALIAS_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    rows = []
    for alias, name, open_sids in unscoped[:20]:
        rows.append(
            _row(
                f"AWS IoT role alias '{alias}' hands devices credentials for role "
                f"'{name}', and "
                + (
                    f"its Allow statement(s) {', '.join(open_sids[:5])} are not "
                    "bounded by a credentials-iot policy variable in every "
                    "Resource or in a positive Condition"
                    if open_sids
                    else "that role has no Allow statement in the IAM cache"
                )
                + ", so every device that assumes the alias gets that AWS access.",
                "Scope the role's Resource or Condition to the calling device with "
                "${credentials-iot:ThingName}, ${credentials-iot:ThingTypeName} or "
                "${credentials-iot:AwsCertificateId}.",
                "High",
                "Failed",
            )
        )
    if len(unscoped) > 20:
        rows.append(
            _row(
                f"{len(unscoped)} role aliases hand out an unscoped role (the first "
                "20 are reported individually above).",
                "Scope each role to the calling device.",
                "High",
                "Failed",
            )
        )
    if unread:
        rows.append(
            _unread_resources_finding(
                "SM-41",
                IOT_ROLE_ALIAS_FINDING,
                unread,
                f"{len(scoped) + len(unscoped)} role alias(es) were judged.",
                IOT_ROLE_ALIAS_REFERENCE,
                region,
            )
        )
    elif scoped and not unscoped:
        rows.append(
            _row(
                f"Every Allow statement of the roles of all {len(scoped)} role "
                "alias(es) is bounded by a credentials-iot policy variable, in "
                "every Resource or in a positive Condition: "
                f"{', '.join(sorted(scoped)[:5])}.",
                "No action required",
                "High",
                "Passed",
            )
        )
    return rows


def check_iot_device_scoped_policies(
    region: str = "", permission_cache: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    SM-41: Verify attached AWS IoT policies scope each device to its own topics
    and client ID, require the certificate to be attached to a thing, and that
    each role alias's IAM role is scoped per device (AIR-PHY-EDG-01).
    """
    logger.debug("Starting check for AWS IoT device-scoped policies")
    findings = {"csv_data": []}

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-41",
            finding_name=IOT_DEVICE_POLICY_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=IOT_DEVICE_POLICY_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    try:
        iot_client = boto3.client("iot", config=boto3_config, region_name=region)
        policies = []
        for page in iot_client.get_paginator("list_policies").paginate():
            policies.extend(page.get("policies", []))
    except Exception as error:
        findings["csv_data"].append(
            _row(
                build_could_not_assess_detail(error, region),
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
        return findings

    failed, passed, errors = [], [], []
    certificates = set()
    thing_groups = set()
    for policy in policies:
        name = policy.get("policyName")
        if not name:
            continue
        try:
            targets = []
            paginator = iot_client.get_paginator("list_targets_for_policy")
            for page in paginator.paginate(policyName=name):
                targets.extend(page.get("targets") or [])
            if not targets:
                continue
            certificates.update(t for t in targets if ":cert/" in str(t))
            thing_groups.update(t for t in targets if ":thinggroup/" in str(t))
            document = iot_client.get_policy(policyName=name).get("policyDocument")
        except Exception as error:
            errors.append((name, error))
            continue
        problems = _iot_policy_problems(document)
        if problems:
            failed.append((name, problems))
        else:
            passed.append(name)

    role_alias_rows = _iot_role_alias_findings(iot_client, region, permission_cache)
    if not failed and not passed and not errors:
        findings["csv_data"].append(
            _row(
                f"None of the {len(policies)} AWS IoT policies in this region is "
                "attached to a certificate or other principal.",
                "No action required",
                "Informational",
                "N/A",
            )
        )
        findings["csv_data"].extend(role_alias_rows)
        return findings

    for name, problems in failed[:20]:
        findings["csv_data"].append(
            _row(
                f"Attached AWS IoT policy '{name}' {'; '.join(problems)}, so one "
                "compromised device credential reaches other devices' topics.",
                IOT_DEVICE_POLICY_RESOLUTION,
                "High",
                "Failed",
            )
        )
    if len(failed) > 20:
        findings["csv_data"].append(
            _row(
                f"{len(failed)} attached AWS IoT policies are not device-scoped "
                "(the first 20 are reported individually above).",
                IOT_DEVICE_POLICY_RESOLUTION,
                "High",
                "Failed",
            )
        )
    if passed:
        findings["csv_data"].append(
            _row(
                f"{len(passed)} attached AWS IoT policies scope device actions to "
                "the thing-name policy variable and require an attached thing: "
                f"{', '.join(sorted(passed)[:5])}. Whether each device holds a "
                "unique certificate is not read by this check.",
                "No action required",
                "High",
                "Passed",
            )
        )
    for name, error in errors[:5]:
        findings["csv_data"].append(
            _row(
                f"AWS IoT policy '{name}': {build_could_not_assess_detail(error, region)}",
                COULD_NOT_ASSESS_RESOLUTION,
                "Informational",
                "N/A",
            )
        )
    findings["csv_data"].extend(role_alias_rows)
    findings["csv_data"].append(
        _iot_unique_certificate_finding(
            iot_client, sorted(certificates), region, sorted(thing_groups)
        )
    )
    findings["csv_data"].append(_iot_audit_finding(iot_client, region))
    return findings


def _iot_unique_certificate_finding(
    iot_client, certificates: List[str], region: str, thing_groups: List[str]
) -> Dict[str, Any]:
    """
    SM-41: each certificate a device policy is attached to serves one thing.

    A policy attached to a thing group reaches the certificates of the things
    in the group and in its child groups, so each group's things are listed
    recursively and each thing's certificate principals are judged too.
    """

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-41",
            finding_name=IOT_UNIQUE_CERTIFICATE_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=IOT_UNIQUE_CERTIFICATE_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    if not certificates and not thing_groups:
        return _row(
            "No attached AWS IoT policy in this region is attached to a "
            "certificate, so there is no device certificate to assess.",
            "No action required",
            "Informational",
            "N/A",
        )
    shared, unread = [], []
    certificates = set(certificates)
    group_names = [g.rsplit("/", 1)[-1] for g in thing_groups]
    for group in group_names:
        try:
            things = []
            paginator = iot_client.get_paginator("list_things_in_thing_group")
            for page in paginator.paginate(thingGroupName=group, recursive=True):
                things.extend(page.get("things") or [])
        except Exception as error:
            unread.append(f"thing group {group} ({get_assessment_error_label(error)})")
            continue
        for thing in things:
            try:
                paginator = iot_client.get_paginator("list_thing_principals")
                for page in paginator.paginate(thingName=thing):
                    certificates.update(
                        p for p in page.get("principals") or [] if ":cert/" in str(p)
                    )
            except Exception as error:
                unread.append(
                    f"thing {thing} in thing group {group} "
                    f"({get_assessment_error_label(error)})"
                )
    certificates = sorted(certificates)
    listing_errors = len(unread)
    for certificate in certificates:
        certificate_id = certificate.rsplit("/", 1)[-1]
        try:
            things = []
            paginator = iot_client.get_paginator("list_principal_things")
            for page in paginator.paginate(principal=certificate):
                things.extend(page.get("things") or [])
        except Exception as error:
            unread.append(
                f"certificate {certificate_id} ({get_assessment_error_label(error)})"
            )
            continue
        if len(set(things)) > 1:
            shown = ", ".join(sorted(set(things))[:5])
            shared.append(
                f"certificate {certificate_id} is attached to {len(set(things))} "
                f"things ({shown})"
            )
    ceiling = (
        " Whether one certificate is installed on more than one physical device "
        "is not an API field; Device Defender's "
        f"{IOT_SHARED_CERTIFICATE_CHECK} infers it from concurrent connections "
        "and is reported in the audit row."
    )
    groups = ""
    if thing_groups:
        groups = (
            " The certificates include those of the things reached through "
            f"{len(thing_groups)} thing group(s) ({', '.join(group_names[:10])}) "
            "an attached policy is attached to, child groups included."
        )
    if shared:
        return _row(
            f"{len(shared)} of {len(certificates)} device certificate(s) are shared "
            f"across things: {'; '.join(shared[:10])}. Recovering that "
            "certificate from one device yields every thing it serves." + ceiling,
            "Issue each device its own certificate and attach each certificate to "
            "exactly one thing with AttachThingPrincipal.",
            "High",
            "Failed",
        )
    if unread:
        return _unread_resources_finding(
            "SM-41",
            IOT_UNIQUE_CERTIFICATE_FINDING,
            unread,
            f"{len(certificates) - (len(unread) - listing_errors)} certificate(s) "
            "read are each attached to at most one thing." + groups + ceiling,
            IOT_UNIQUE_CERTIFICATE_REFERENCE,
            region,
        )
    if not certificates:
        return _row(
            "No attached AWS IoT policy is attached to a certificate directly, "
            f"and the things of the {len(thing_groups)} thing group(s) "
            f"({', '.join(group_names[:10])}) an attached policy is attached to "
            "hold no certificate, so there is no device certificate to assess.",
            "No action required",
            "Informational",
            "N/A",
        )
    return _row(
        f"Each of the {len(certificates)} certificate(s) that an attached AWS IoT "
        "policy reaches is attached to at most one thing." + groups + ceiling,
        "No action required",
        "High",
        "Passed",
    )


def _iot_audit_finding(iot_client, region: str) -> Dict[str, Any]:
    """
    SM-41: Device Defender audit runs the shared-certificate check on a schedule,
    and the last window holds no unsuppressed finding.
    """

    def _row(details, resolution, severity, status):
        return create_finding(
            check_id="SM-41",
            finding_name=IOT_AUDIT_FINDING,
            finding_details=details,
            resolution=resolution,
            reference=IOT_AUDIT_REFERENCE,
            severity=severity,
            status=status,
            region=region,
        )

    problems, unread = [], []
    try:
        configuration = iot_client.describe_account_audit_configuration()
        check = (configuration.get("auditCheckConfigurations") or {}).get(
            IOT_SHARED_CERTIFICATE_CHECK
        ) or {}
        if check.get("enabled") is not True:
            problems.append(
                f"the {IOT_SHARED_CERTIFICATE_CHECK} audit check is not enabled"
            )
    except Exception as error:
        unread.append(
            "iot:DescribeAccountAuditConfiguration "
            f"({get_assessment_error_label(error)})"
        )

    covering = []
    try:
        scheduled = []
        for page in iot_client.get_paginator("list_scheduled_audits").paginate():
            scheduled.extend(page.get("scheduledAudits") or [])
        audits_unread = []
        for audit in scheduled:
            name = audit.get("scheduledAuditName")
            try:
                detail = iot_client.describe_scheduled_audit(scheduledAuditName=name)
            except Exception as error:
                audits_unread.append(
                    f"scheduled audit '{name}' ({get_assessment_error_label(error)})"
                )
                continue
            if IOT_SHARED_CERTIFICATE_CHECK in (detail.get("targetCheckNames") or []):
                covering.append(name)
        if not covering:
            unread.extend(audits_unread)
        if not covering and not audits_unread:
            problems.append(
                f"none of the {len(scheduled)} scheduled audit(s) runs "
                f"{IOT_SHARED_CERTIFICATE_CHECK}"
            )
    except Exception as error:
        unread.append(f"iot:ListScheduledAudits ({get_assessment_error_label(error)})")

    # AIR-PHY-EDG-01: a schedule proves nothing until one of its runs completes
    # the check. The latest completed run of a covering scheduled audit is the
    # one whose findings are judged; a monthly schedule runs inside the window.
    latest_task = None
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=IOT_AUDIT_FINDING_WINDOW_DAYS)
        task_ids = []
        for page in iot_client.get_paginator("list_audit_tasks").paginate(
            startTime=start,
            endTime=end,
            taskType="SCHEDULED_AUDIT_TASK",
            taskStatus="COMPLETED",
        ):
            task_ids.extend(
                task.get("taskId")
                for task in page.get("tasks") or []
                if task.get("taskId")
            )
        tasks_unread = []
        for task_id in task_ids:
            try:
                task = iot_client.describe_audit_task(taskId=task_id)
            except Exception as error:
                tasks_unread.append(
                    f"audit task {task_id} ({get_assessment_error_label(error)})"
                )
                continue
            run = (task.get("auditDetails") or {}).get(
                IOT_SHARED_CERTIFICATE_CHECK
            ) or {}
            started = task.get("taskStartTime")
            if (
                task.get("scheduledAuditName") in covering
                and str(run.get("checkRunStatus", "")).startswith("COMPLETED_")
                and isinstance(started, datetime)
                and (latest_task is None or started > latest_task[1])
            ):
                latest_task = (task_id, started)
        if latest_task is None:
            if tasks_unread:
                unread.extend(tasks_unread)
            elif covering:
                problems.append(
                    "no run of the scheduled audit(s) "
                    f"{', '.join(covering[:3])} completed the "
                    f"{IOT_SHARED_CERTIFICATE_CHECK} check in the last "
                    f"{IOT_AUDIT_FINDING_WINDOW_DAYS} days"
                )
    except Exception as error:
        unread.append(f"iot:ListAuditTasks ({get_assessment_error_label(error)})")

    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=IOT_AUDIT_FINDING_WINDOW_DAYS)
        open_findings = {}
        finding_scope = (
            {"taskId": latest_task[0]}
            if latest_task
            else {"startTime": start, "endTime": end}
        )
        for page in iot_client.get_paginator("list_audit_findings").paginate(
            listSuppressedFindings=False, **finding_scope
        ):
            for audit_finding in page.get("findings") or []:
                if audit_finding.get("isSuppressed"):
                    continue
                name = audit_finding.get("checkName") or "unnamed check"
                open_findings[name] = open_findings.get(name, 0) + 1
        if open_findings:
            counts = ", ".join(
                f"{name} ({count})" for name, count in sorted(open_findings.items())
            )
            problems.append(
                (
                    f"the latest completed audit run ({latest_task[0]}) holds "
                    if latest_task
                    else f"the last {IOT_AUDIT_FINDING_WINDOW_DAYS} days hold "
                )
                + f"{sum(open_findings.values())} unsuppressed audit finding(s): {counts}"
            )
    except Exception as error:
        unread.append(f"iot:ListAuditFindings ({get_assessment_error_label(error)})")

    if problems:
        details = "Device Defender audit does not show a clean, scheduled audit: "
        details += "; ".join(problems) + "."
        if unread:
            details += f" Not read: {'; '.join(unread)}."
        return _row(
            details,
            "Enable the Device Defender audit checks, including "
            f"{IOT_SHARED_CERTIFICATE_CHECK}, schedule an audit that runs them, "
            "and resolve or suppress each finding with a recorded reason.",
            "Medium",
            "Failed",
        )
    if unread:
        return _unread_resources_finding(
            "SM-41",
            IOT_AUDIT_FINDING,
            unread,
            "no audit problem was found in the parts that were read.",
            IOT_AUDIT_REFERENCE,
            region,
        )
    return _row(
        f"The {IOT_SHARED_CERTIFICATE_CHECK} audit check is enabled, a scheduled "
        f"audit runs it, its latest run ({latest_task[0]}, started "
        f"{latest_task[1].isoformat()}) completed the check, and that run holds no "
        "unsuppressed audit finding.",
        "No action required",
        "Medium",
        "Passed",
    )


def handle_aws_throttling(func, *args, **kwargs):
    """
    Handle AWS API throttling with exponential backoff
    """
    max_retries = 5
    base_delay = 1  # Start with 1 second delay

    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "Throttling":
                if attempt == max_retries - 1:
                    raise  # Re-raise if we're out of retries
                delay = (2**attempt) * base_delay + (random.random() * 0.1)
                logger.warning(f"Request throttled. Retrying in {delay:.2f} seconds...")
                time.sleep(delay)
            else:
                raise


def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    """
    Generate CSV report from all security check findings
    """
    logger.debug("Generating CSV report")
    csv_buffer = StringIO()
    fieldnames = [
        "Check_ID",
        "Finding",
        "Finding_Details",
        "Resolution",
        "Reference",
        "Severity",
        "Status",
        "Region",
        "Compliance_Frameworks",
    ]
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)

    writer.writeheader()
    for finding in findings:
        if finding["csv_data"]:
            for row in finding["csv_data"]:
                writer.writerow(row)

    return csv_buffer.getvalue()


def get_current_utc_date():
    return datetime.now(timezone.utc).strftime("%Y/%m/%d")


def write_to_s3(
    execution_id, csv_content: str, bucket_name: str, region: str = ""
) -> Dict[str, str]:
    """
    Write CSV reports to S3 bucket
    """
    logger.debug(f"Writing reports to S3 bucket: {bucket_name}")
    try:
        s3_client = boto3.client("s3", config=boto3_config)

        if region:
            csv_file_name = f"sagemaker_security_report_{execution_id}_{region}.csv"
        else:
            csv_file_name = f"sagemaker_security_report_{execution_id}.csv"
        s3_client.put_object(
            Bucket=bucket_name,
            Key=csv_file_name,
            Body=csv_content,
            ContentType="text/csv",
        )

        return {
            "csv_url": f"https://{bucket_name}.s3.amazonaws.com/{csv_file_name}",
        }
    except Exception as e:
        logger.error(f"Error writing to S3: {str(e)}", exc_info=True)
        raise


def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    logger.info("Starting SageMaker security assessment")
    all_findings = []

    try:
        # Extract target region from Step Functions Map state
        region = event.get("Region", os.environ.get("AWS_REGION", "us-east-1"))
        # IAM is global: only the primary region (Map index 0) runs IAM-only checks.
        is_primary_region = int(event.get("RegionIndex", 0)) == 0
        logger.info(f"Scanning region: {region} (primary={is_primary_region})")

        execution_id = event["Execution"]["Name"]

        # Initialize permission cache (shared/global IAM data)
        logger.info("Initializing IAM permission cache")
        permission_cache = get_permissions_cache(execution_id)

        if not _is_valid_permissions_cache(permission_cache):
            logger.error(
                "Permission cache unavailable - IAM permission caching may have failed"
            )
            permission_cache = None

        # Run global IAM-only checks once (on the primary region) so the same role
        # and stale-access violations are not reported once per scanned region.
        # These run before the regional availability gate so they are still emitted
        # even if SageMaker is not available in the primary region.
        if is_primary_region:
            logger.info("Running global SageMaker IAM permissions check (SM-02)")
            sagemaker_iam_findings = (
                _permission_cache_unavailable_result(GLOBAL_REGION_LABEL)
                if permission_cache is None
                else check_sagemaker_iam_permissions(
                    permission_cache, region=GLOBAL_REGION_LABEL
                )
            )
            all_findings.append(sagemaker_iam_findings)

            # Service control policies are organization-wide, so this preventive
            # control is assessed once and not once per scanned region.
            logger.info("Running SageMaker creation guardrail check (SM-34)")
            all_findings.append(
                check_sagemaker_creation_guardrails(
                    region=GLOBAL_REGION_LABEL, permission_cache=permission_cache
                )
            )

            logger.info("Running SageMaker notebook access guardrail check (SM-09)")
            all_findings.append(
                check_sagemaker_notebook_access_guardrails(
                    region=GLOBAL_REGION_LABEL, permission_cache=permission_cache
                )
            )

            # Delegated administration is an organization-level setting, so it is
            # assessed once and not once per scanned region.
            logger.info("Running security service delegated admin check (SM-35)")
            all_findings.append(
                check_security_service_delegated_admin(region=GLOBAL_REGION_LABEL)
            )

        # Verify SageMaker is available in this region
        try:
            test_client = boto3.client(
                "sagemaker", config=boto3_config, region_name=region
            )
            test_client.list_notebook_instances(MaxResults=1)
        except EndpointConnectionError:
            logger.info(f"SageMaker service not available in region {region}, skipping")
            all_findings.append(
                {
                    "check_name": "SageMaker Service Availability",
                    "status": "N/A",
                    "details": f"SageMaker is not available in region {region}",
                    "csv_data": [
                        create_finding(
                            check_id="SM-00",
                            finding_name="SageMaker Service Availability",
                            finding_details=f"Amazon SageMaker is not available in region {region}. No checks performed.",
                            resolution="No action required. SageMaker is not deployed in this region.",
                            reference="https://docs.aws.amazon.com/general/latest/gr/sagemaker.html",
                            severity="Informational",
                            status="N/A",
                            region=region,
                        )
                    ],
                }
            )
            csv_content = generate_csv_report(all_findings)
            bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
            s3_url = write_to_s3(execution_id, csv_content, bucket_name, region=region)
            return {
                "statusCode": 200,
                "body": {
                    "message": f"SageMaker not available in {region}",
                    "report_url": s3_url,
                },
            }
        except ClientError as e:
            # A region that exists but is not enabled for the account surfaces as
            # an auth/opt-in error rather than a connection failure. Treat it the
            # same as "not available" instead of running every check against it.
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in REGION_UNAVAILABLE_ERROR_CODES:
                logger.info(
                    f"SageMaker not accessible in region {region} ({error_code}), skipping"
                )
                all_findings.append(
                    {
                        "check_name": "SageMaker Service Availability",
                        "status": "N/A",
                        "details": f"SageMaker is not available in region {region}",
                        "csv_data": [
                            create_finding(
                                check_id="SM-00",
                                finding_name="SageMaker Service Availability",
                                finding_details=f"Amazon SageMaker is not available or not enabled in region {region} ({error_code}). No checks performed.",
                                resolution="No action required if the region is intentionally disabled. Otherwise enable the region for this account.",
                                reference="https://docs.aws.amazon.com/general/latest/gr/sagemaker.html",
                                severity="Informational",
                                status="N/A",
                                region=region,
                            )
                        ],
                    }
                )
                csv_content = generate_csv_report(all_findings)
                bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
                s3_url = write_to_s3(
                    execution_id, csv_content, bucket_name, region=region
                )
                return {
                    "statusCode": 200,
                    "body": {
                        "message": f"SageMaker not available in {region}",
                        "report_url": s3_url,
                    },
                }
            # Service is reachable but returned another API error (e.g. AccessDenied)
            # — proceed; individual checks handle their own errors.
            logger.info(
                f"SageMaker availability probe returned {error_code}; proceeding with checks"
            )

        logger.info("Running SageMaker internet access check")
        sagemaker_internet_access_findings = check_sagemaker_internet_access(
            region=region
        )
        all_findings.append(sagemaker_internet_access_findings)

        logger.info("Running SageMaker SSO configuration check")
        sagemaker_sso_findings = check_sagemaker_sso_configuration(region=region)
        all_findings.append(sagemaker_sso_findings)

        logger.info("Running SageMaker data protection check")
        sagemaker_data_protection_findings = check_sagemaker_data_protection(
            region=region
        )
        all_findings.append(sagemaker_data_protection_findings)

        guardduty_inventory = get_guardduty_detector_inventory(region)
        logger.info("Running GuardDuty SageMaker monitoring check")
        guardduty_findings = check_guardduty_enabled(
            region=region, detector_inventory=guardduty_inventory
        )
        all_findings.append(guardduty_findings)

        logger.info("Running regional security service administrator check (SM-35)")
        all_findings.append(
            check_regional_security_admin(
                region=region, detector_inventory=guardduty_inventory
            )
        )

        logger.info("Running GuardDuty AI Protection check (SM-26)")
        all_findings.append(
            check_guardduty_ai_protection(
                region=region, detector_inventory=guardduty_inventory
            )
        )

        logger.info("Running SageMaker MLOps features utilization check")
        mlops_findings = check_sagemaker_mlops_utilization(
            permission_cache, region=region
        )
        all_findings.append(mlops_findings)

        logger.info("Running SageMaker Clarify usage check")
        clarify_findings = check_sagemaker_clarify_usage(
            permission_cache, region=region
        )
        all_findings.append(clarify_findings)

        logger.info("Running SageMaker Model Monitor usage check")
        monitor_findings = check_sagemaker_model_monitor_usage(
            permission_cache, region=region
        )
        all_findings.append(monitor_findings)

        try:
            registry_client = boto3.client(
                "sagemaker", config=boto3_config, region_name=region
            )
            model_package_groups = list_model_package_group_summaries(registry_client)
        except Exception:
            model_package_groups = None

        logger.info("Running Model Registry usage check")
        registry_findings = check_model_registry_usage(
            permission_cache,
            region=region,
            model_package_groups=model_package_groups,
        )
        all_findings.append(registry_findings)

        logger.info("Running SageMaker notebook root access check")
        notebook_root_findings = check_sagemaker_notebook_root_access(
            region=region, permission_cache=permission_cache
        )
        all_findings.append(notebook_root_findings)

        logger.info("Running SageMaker notebook VPC deployment check")
        notebook_vpc_findings = check_sagemaker_notebook_vpc_deployment(region=region)
        all_findings.append(notebook_vpc_findings)

        logger.info("Running SageMaker model network isolation check")
        model_isolation_findings = check_sagemaker_model_network_isolation(
            region=region, permission_cache=permission_cache
        )
        all_findings.append(model_isolation_findings)

        logger.info("Running AI Lambda function network boundary check (SM-11)")
        all_findings.append(check_ai_lambda_network_boundary(region=region))

        logger.info("Running AI API method authorization check (SM-02)")
        all_findings.append(check_ai_api_method_authorization(region=region))

        logger.info("Running SageMaker endpoint instance count check")
        endpoint_instance_findings = check_sagemaker_endpoint_instance_count(
            region=region
        )
        all_findings.append(endpoint_instance_findings)

        logger.info("Running SageMaker monitoring network isolation check")
        monitoring_isolation_findings = check_sagemaker_monitoring_network_isolation(
            region=region
        )
        all_findings.append(monitoring_isolation_findings)

        logger.info("Running SageMaker model container repository check")
        model_repository_findings = check_sagemaker_model_container_repository(
            region=region
        )
        all_findings.append(model_repository_findings)

        logger.info("Running SageMaker Feature Store encryption check")
        feature_store_encryption_findings = check_sagemaker_feature_store_encryption(
            region=region
        )
        all_findings.append(feature_store_encryption_findings)

        logger.info("Running SageMaker data quality job encryption check")
        data_quality_encryption_findings = check_sagemaker_data_quality_encryption(
            region=region
        )
        all_findings.append(data_quality_encryption_findings)

        # Additional AWS Security Hub Controls
        logger.info("Running SageMaker processing job encryption check (SageMaker.10)")
        processing_job_encryption_findings = check_sagemaker_processing_job_encryption(
            region=region
        )
        all_findings.append(processing_job_encryption_findings)

        logger.info("Running SageMaker transform job encryption check (SageMaker.11)")
        transform_job_encryption_findings = check_sagemaker_transform_job_encryption(
            region=region
        )
        all_findings.append(transform_job_encryption_findings)

        logger.info("Running SageMaker batch creation guardrail check (SM-42)")
        all_findings.append(
            check_sagemaker_batch_creation_guardrails(
                region=region, permission_cache=permission_cache
            )
        )

        logger.info(
            "Running SageMaker hyperparameter tuning job encryption check (SageMaker.12)"
        )
        hyperparameter_tuning_encryption_findings = (
            check_sagemaker_hyperparameter_tuning_encryption(region=region)
        )
        all_findings.append(hyperparameter_tuning_encryption_findings)

        logger.info("Running SageMaker compilation job encryption check (SageMaker.13)")
        compilation_job_encryption_findings = (
            check_sagemaker_compilation_job_encryption(region=region)
        )
        all_findings.append(compilation_job_encryption_findings)

        logger.info(
            "Running SageMaker AutoML job network isolation check (SageMaker.15)"
        )
        automl_network_isolation_findings = check_sagemaker_automl_network_isolation(
            region=region
        )
        all_findings.append(automl_network_isolation_findings)

        # Model Governance Checks
        logger.info("Running model approval workflow check")
        model_approval_workflow_findings = check_model_approval_workflow(region=region)
        all_findings.append(model_approval_workflow_findings)

        logger.info("Running model drift detection check")
        model_drift_detection_findings = check_model_drift_detection(region=region)
        all_findings.append(model_drift_detection_findings)

        logger.info("Running A/B testing and shadow deployment check")
        ab_testing_findings = check_ab_testing_shadow_deployment(region=region)
        all_findings.append(ab_testing_findings)

        logger.info("Running ML lineage tracking check")
        ml_lineage_tracking_findings = check_ml_lineage_tracking(region=region)
        all_findings.append(ml_lineage_tracking_findings)

        hyperpod_inventory = get_hyperpod_cluster_inventory(region)
        logger.info("Running HyperPod EBS CMK encryption check (SM-27)")
        all_findings.append(
            check_hyperpod_ebs_cmk_encryption(
                region=region, cluster_inventory=hyperpod_inventory
            )
        )

        logger.info("Running HyperPod VPC configuration check (SM-28)")
        all_findings.append(
            check_hyperpod_vpc_configuration(
                region=region, cluster_inventory=hyperpod_inventory
            )
        )

        logger.info("Running model package group policy exposure check (SM-30)")
        all_findings.append(
            check_model_package_group_policy_exposure(
                region=region, model_package_groups=model_package_groups
            )
        )

        logger.info("Running SageMaker endpoint data capture check (SM-31)")
        all_findings.append(check_sagemaker_endpoint_data_capture(region=region))

        logger.info("Running SageMaker AWS Config coverage check (SM-32)")
        all_findings.append(check_sagemaker_config_compliance_evaluation(region=region))

        logger.info("Running SageMaker training job network boundary check (SM-33)")
        all_findings.append(
            check_sagemaker_training_job_network_boundary(region=region)
        )

        logger.info("Running Security Hub AI security standard check (SM-36)")
        all_findings.append(check_security_hub_ai_standard(region=region))

        logger.info("Running GuardDuty Lambda Protection check (SM-37)")
        all_findings.append(
            check_guardduty_lambda_network_logs(
                region=region, detector_inventory=guardduty_inventory
            )
        )

        logger.info("Running SageMaker endpoint flow log alerting check (SM-37)")
        all_findings.append(check_sagemaker_endpoint_flow_log_alerting(region=region))

        logger.info("Running VPC DNS resolver visibility check (SM-37)")
        all_findings.append(check_vpc_dns_resolver_visibility(region=region))

        logger.info("Running SageMaker model artifact integrity check (SM-43)")
        all_findings.append(
            check_sagemaker_model_artifact_integrity(
                region=region, permission_cache=permission_cache
            )
        )

        logger.info("Running GuardDuty Runtime Monitoring check (SM-38)")
        all_findings.append(
            check_guardduty_runtime_monitoring(
                region=region, detector_inventory=guardduty_inventory
            )
        )

        logger.info("Running GuardDuty Runtime Monitoring coverage check (SM-38)")
        all_findings.append(
            check_guardduty_runtime_monitoring_coverage(
                region=region, detector_inventory=guardduty_inventory
            )
        )

        logger.info("Running EKS vpc-cni network policy check (SM-39)")
        all_findings.append(check_eks_vpc_cni_network_policy(region=region))
        all_findings.append(check_workload_network_segmentation(region=region))

        logger.info("Running Secrets Manager rotation check (SM-40)")
        all_findings.append(check_secrets_manager_rotation(region=region))
        all_findings.append(
            check_secret_rotation_history_and_propagation(region=region)
        )

        logger.info("Running AWS IoT device-scoped policy check (SM-41)")
        all_findings.append(
            check_iot_device_scoped_policies(
                region=region, permission_cache=permission_cache
            )
        )

        logger.info("Running sagemaker.runtime VPC endpoint policy check (SM-02)")
        all_findings.append(check_sagemaker_runtime_endpoint_policy(region=region))

        # Generate and upload report
        logger.info("Generating reports")
        csv_content = generate_csv_report(all_findings)

        bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        if not bucket_name:
            raise ValueError(
                "AIML_ASSESSMENT_BUCKET_NAME environment variable is not set"
            )

        logger.info("Writing reports to S3")
        s3_url = write_to_s3(execution_id, csv_content, bucket_name, region=region)

        return {
            "statusCode": 200,
            "body": {
                "message": "Security checks completed successfully",
                "findings": all_findings,
                "report_url": s3_url,
            },
        }

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        raise
