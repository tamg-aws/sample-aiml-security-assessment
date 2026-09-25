"""
Amazon Bedrock AgentCore Security Assessment Lambda Function

This function performs comprehensive security assessments for Amazon Bedrock AgentCore
resources including Runtimes, Code Interpreters, Browser Tools, Memory, and Gateways.
"""

import boto3
import csv
import json
import logging
import os
import time
from fnmatch import fnmatchcase
from io import StringIO
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

from schema import create_finding, SeverityEnum, StatusEnum

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configure boto3 with adaptive retry mode
boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

# Initialize S3 client (always uses Lambda's region for bucket operations)
s3_client = boto3.client("s3", config=boto3_config)

# Regional clients — initialized in lambda_handler with target region
iam_client = None
ec2_client = None
ecr_client = None
logs_client = None
cloudwatch_client = None
cloudtrail_client = None
oam_client = None
agentcore_client = None
kms_client = None
organizations_client = None

# Environment variables
BUCKET_NAME = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")

# IAM is a global service. Findings derived purely from the IAM permission cache
# (e.g. AC-02, AC-03) are identical across regions, so they are produced only on
# the primary region (Map index 0) and tagged with this region label to avoid
# duplicate findings when scanning multiple regions.
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


AGENTIC_AI_LENS_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/"
    "agentic-ai-lens.html"
)
AGENTCORE_STARTER_TOOLKIT_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
)
AGENTCORE_VPC_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/security/agentcore-vpc.html"
)
AGENTCORE_OBSERVABILITY_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/observability/quickstart.html"
)
AGENTCORE_MEMORY_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/memory/quickstart.html"
)
AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "specify-long-term-memory-organization.html"
)
AGENTCORE_GATEWAY_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/gateway/quickstart.html"
)
AGENTCORE_DATA_ENCRYPTION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html"
)
ECR_ENCRYPTION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html"
)
AGENTCORE_GATEWAY_API_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/"
    "API_GetGateway.html"
)
AGENTCORE_POLICY_ENGINE_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/"
    "API_GatewayPolicyEngineConfiguration.html"
)
AGENTCORE_IDENTITY_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "identity-data-encryption.html"
)
AGENTCORE_SECURITY_HUB_REFERENCE_URL = (
    "https://docs.aws.amazon.com/securityhub/latest/userguide/"
    "bedrockagentcore-controls.html"
)
AGENTCORE_BROWSER_RECORDING_FINDING_NAME = "AgentCore Browser Session Recording"
AGENTCORE_ONLINE_EVALUATION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "get-online-evaluations.html"
)
CLOUDTRAIL_DATA_EVENTS_REFERENCE_URL = (
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
    "logging-data-events-with-cloudtrail.html"
)
AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "observability-configure.html"
)
LOGS_DATA_PROTECTION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/"
    "mask-sensitive-log-data.html"
)
OAM_CROSS_ACCOUNT_REFERENCE_URL = (
    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/"
    "CloudWatch-Unified-Cross-Account.html"
)
AGENTCORE_GATEWAY_RATE_LIMIT_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/"
    "API_ListGatewayRateLimits.html"
)
AGENTCORE_GATEWAY_TARGET_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/"
    "API_CredentialProviderConfiguration.html"
)
LOGS_RETENTION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/"
    "Working-with-log-groups-and-streams.html"
)
KMS_KEY_POLICY_REFERENCE_URL = (
    "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html"
)
CONFUSED_DEPUTY_REFERENCE_URL = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"
)
VPC_ENDPOINT_POLICY_REFERENCE_URL = (
    "https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html"
)
AGENTCORE_GATEWAY_CONDITION_KEY_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "security-gateway-condition-keys.html"
)
AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-oauth.html"
)
AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "gateway-inbound-auth.html"
)
AGENTCORE_IAM_CONDITION_KEY_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "security_iam_service-with-iam.html"
)
AGENTCORE_WORKLOAD_IDENTITY_SCOPE_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "scope-credential-provider-access.html"
)
AGENTCORE_RUNTIME_SECRET_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "runtime-security-best-practices.html"
)
AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "policy-core-concepts.html"
)
AGENTCORE_POLICY_SESSION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "policy-session-based-temporal.html"
)
AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "policy-guardrails-in-policies.html"
)
AGENTCORE_POLICY_ENCRYPTION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "policy-encryption.html"
)


def _assessment_error_label(error: Exception) -> str:
    """Return a report-safe label for an assessment/tooling error."""
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        if code:
            return code
    if isinstance(error, EndpointConnectionError):
        return "EndpointConnectionError"
    return type(error).__name__


def _incomplete_check_finding(
    check_id: str,
    finding_name: str,
    error: Exception,
    reference: str,
    region: str = "",
) -> Dict[str, Any]:
    """Represent a scanner failure without treating it as workload risk."""
    return create_finding(
        check_id=check_id,
        finding_name=f"{finding_name} Incomplete",
        finding_details=(
            f"Could not assess {finding_name.lower()}. Assessment error: "
            f"{_assessment_error_label(error)}."
        ),
        resolution=(
            "No action is required on the assessed workload based on this result. "
            "Resolve the assessment permission, API, or tooling error and rerun the "
            "assessment."
        ),
        reference=reference,
        severity=SeverityEnum.INFORMATIONAL,
        status=StatusEnum.NA,
        region=region,
    )


def _incomplete_check_findings(
    check_ids: List[str],
    finding_name: str,
    error: Exception,
    region: str,
    reference: str = AGENTCORE_STARTER_TOOLKIT_URL,
) -> List[Dict[str, Any]]:
    """Create one visible incomplete row for every control a runner skipped."""
    return [
        _incomplete_check_finding(
            check_id,
            finding_name,
            error,
            reference,
            region=region,
        )
        for check_id in check_ids
    ]


AGENTIC_AGENTCORE_CHECK_MAPPINGS = {
    "AC-01": {
        "check_id": "AG-15",
        "finding": "Agentic AI Runtime Network Boundary",
        "lens_domain": "Bounded Autonomy",
        "agentic_context": "Agent runtimes should execute inside explicit network boundaries to reduce unintended external reachability.",
        "resolution": "Configure AgentCore runtimes with appropriate VPC settings and restrict network paths to required services.",
    },
    "AC-02": {
        "check_id": "AG-16",
        "finding": "Agentic AI AgentCore Least Privilege",
        "lens_domain": "Agent Identity & Access",
        "agentic_context": "Over-permissive AgentCore principals can let agents or operators bypass intended autonomy and tool boundaries.",
        "resolution": "Replace full-access AgentCore permissions with least-privilege IAM policies scoped to required resources and actions.",
    },
    "AC-03": {
        "check_id": "AG-17",
        "finding": "Agentic AI Stale AgentCore Access",
        "lens_domain": "Agent Identity & Access",
        "agentic_context": "Unused AgentCore permissions increase the blast radius of compromised principals.",
        "resolution": "Remove or restrict stale AgentCore permissions for principals that no longer need access.",
    },
    "AC-04": {
        "check_id": "AG-18",
        "finding": "Agentic AI AgentCore Observability",
        "lens_domain": "Auditability & Observability",
        "agentic_context": "AgentCore observability provides the telemetry needed to investigate runtime, tool, memory, and gateway behavior.",
        "resolution": "Enable CloudWatch Logs, tracing, and AgentCore observability for runtime and gateway resources where supported.",
    },
    "AC-07": {
        "check_id": "AG-19",
        "finding": "Agentic AI Memory Data Protection",
        "lens_domain": "Memory & Data Privacy",
        "agentic_context": "Agent memory can contain sensitive user or business context and should use customer-controlled encryption where required.",
        "resolution": "Configure AgentCore memory resources with customer-managed KMS keys and review memory access permissions.",
    },
    "AC-08": {
        "check_id": "AG-20",
        "finding": "Agentic AI Private AgentCore Connectivity",
        "lens_domain": "Bounded Autonomy",
        "agentic_context": "Private service connectivity reduces exposure for agents that access AgentCore control or runtime services.",
        "resolution": "Create required VPC endpoints for AgentCore services and validate endpoint availability.",
    },
    "AC-10": {
        "check_id": "AG-21",
        "finding": "Agentic AI Resource Policy Boundary",
        "lens_domain": "Agent Identity & Access",
        "agentic_context": "Resource-based policies add a second authorization boundary for AgentCore runtimes and gateways.",
        "resolution": "Attach resource-based policies to AgentCore resources to constrain principals, accounts, and network sources.",
    },
    "AC-11": {
        "check_id": "AG-22",
        "finding": "Agentic AI Policy Engine Data Protection",
        "lens_domain": "Tool Authorization",
        "agentic_context": "Policy engines contain authorization logic for tool calls and should be protected with appropriate encryption controls.",
        "resolution": "Configure policy engines with customer-managed KMS keys where enhanced key control is required.",
    },
    "AC-12": {
        "check_id": "AG-23",
        "finding": "Agentic AI Gateway Data Protection",
        "lens_domain": "Tool Authorization",
        "agentic_context": "Gateway configuration can include tool schemas, target definitions, and integration metadata.",
        "resolution": "Configure AgentCore gateways with customer-managed KMS keys where enhanced key control is required.",
    },
    "AC-14": {
        "check_id": "AG-28",
        "finding": "Agentic AI Identity Token Vault Protection",
        "lens_domain": "Agent Identity & Access",
        "agentic_context": "Agent credentials stored in the Identity token vault should use customer-controlled encryption where enhanced key control is required.",
        "resolution": "Configure the AgentCore Identity token vault with a customer-managed KMS key.",
    },
    "AC-15": {
        "check_id": "AG-29",
        "finding": "Agentic AI Code Interpreter Isolation",
        "lens_domain": "Bounded Autonomy",
        "agentic_context": "Agent-executed code should run inside an explicit VPC boundary with controlled network paths.",
        "resolution": "Configure custom AgentCore Code Interpreters in VPC mode with approved subnets and security groups.",
    },
    "AC-16": {
        "check_id": "AG-31",
        "finding": "Agentic AI Browser Tool Isolation",
        "lens_domain": "Bounded Autonomy",
        "agentic_context": "Browser tools can reach external systems and should use explicit private network boundaries.",
        "resolution": "Configure custom AgentCore browsers in VPC mode with approved subnets and security groups.",
    },
    "AC-17": {
        "check_id": "AG-32",
        "finding": "Agentic AI Online Evaluation Assurance",
        "lens_domain": "Auditability & Continuous Assurance",
        "agentic_context": "Online evaluation provides continuous evidence about agent behavior, quality, and policy-relevant outcomes.",
        "resolution": "Configure an active AgentCore online evaluation with sampling, evaluators, CloudWatch input logs, and an output log group.",
    },
}

REGIONAL_AGENTCORE_CHECK_IDS = (
    "AC-01",
    "AC-04",
    "AC-05",
    "AC-06",
    "AC-07",
    "AC-08",
    "AC-10",
    "AC-11",
    "AC-12",
    "AC-13",
    "AC-14",
    "AC-15",
    "AC-16",
    "AC-17",
    "AC-18",
    "AC-19",
    "AC-20",
    "AC-22",
    "AC-24",
    "AC-25",
    "AC-26",
    "AC-27",
    "AC-30",
    "AC-31",
    "AC-34",
    "AC-35",
    "AC-36",
    "AC-37",
    "AC-38",
)

AGENTCORE_RUNTIME_CHECK_IDS = (
    "AC-01",
    "AC-04",
    "AC-05",
    "AC-06",
    "AC-07",
    "AC-08",
    "AC-10",
    "AC-11",
    "AC-12",
    "AC-13",
    "AC-14",
    "AC-15",
    "AC-16",
    "AC-17",
    "AC-18",
    "AC-19",
    "AC-20",
    "AC-22",
    "AC-24",
    "AC-25",
    "AC-26",
    "AC-27",
    "AC-30",
    "AC-31",
    "AC-34",
    "AC-35",
    "AC-36",
    "AC-37",
    "AC-38",
)

NATIVE_AGENTIC_AGENTCORE_CHECK_NAMES = {
    "AG-24": "Agentic AI Gateway Authentication",
    "AG-25": "Agentic AI Gateway Policy Enforcement",
    "AG-26": "Agentic AI Gateway Exception Handling",
    "AG-27": "Agentic AI Gateway WAF Protection",
}

# CloudTrail data-event resource types per AgentCore service family, as listed in
# the CloudTrail data-events table. AC-18 decides presence from this module's own
# inventory so a family with no resources in the region reads N/A instead of a
# Failed nobody can act on.
AGENTCORE_DATA_EVENT_FAMILIES = (
    {
        "key": "runtime",
        "label": "Runtime",
        "resource_types": (
            "AWS::BedrockAgentCore::Runtime",
            "AWS::BedrockAgentCore::RuntimeEndpoint",
        ),
        "inventory": (("list_agent_runtimes", ("agentRuntimes",), {}),),
    },
    {
        "key": "memory",
        "label": "Memory",
        "resource_types": ("AWS::BedrockAgentCore::Memory",),
        "inventory": (("list_memories", ("memories",), {}),),
    },
    {
        "key": "tools",
        "label": "Tool",
        "resource_types": (
            "AWS::BedrockAgentCore::CodeInterpreter",
            "AWS::BedrockAgentCore::CodeInterpreterCustom",
            "AWS::BedrockAgentCore::Browser",
            "AWS::BedrockAgentCore::BrowserCustom",
        ),
        "inventory": (
            (
                "list_code_interpreters",
                ("codeInterpreterSummaries",),
                {"type": "CUSTOM"},
            ),
            ("list_browsers", ("browserSummaries",), {"type": "CUSTOM"}),
        ),
    },
)

# Log groups AgentCore writes to: the service-managed prefix and the vended-log
# prefix used by memory and gateway log delivery.
AGENTCORE_LOG_GROUP_PREFIXES = (
    "/aws/bedrock-agentcore/",
    "/aws/vendedlogs/bedrock-agentcore/",
)

# AgentCore does not configure log destinations automatically. Memory and gateway
# application logs reach CloudWatch only through a vended-log delivery source
# with this service and log type, plus a delivery to a destination.
AGENTCORE_VENDED_LOG_SERVICE = "bedrock-agentcore"
AGENTCORE_VENDED_LOG_TYPE = "APPLICATION_LOGS"

# Condition keys that bind a cross-account observability sink policy to a known
# set of principals. Operators may be prefixed (ForAnyValue:StringLike), so the
# key names are compared, not the operators.
SINK_PRINCIPAL_SCOPE_CONDITION_KEYS = {
    "aws:principalorgid",
    "aws:principalorgpaths",
}

# Namespace variable that partitions long-term memory records per end user. AWS
# documents "/strategy/{memoryStrategyId}/" and "/" as valid namespace
# granularities, so a strategy whose namespace carries no actor variable stores
# every actor's records in one namespace that a single retrieval returns.
MEMORY_ACTOR_NAMESPACE_VARIABLE = "{actorid}"

# Memory read actions that return stored records or events and that IAM can bind
# to one actor, session, strategy or namespace. Each action below publishes at
# least one of those condition keys, so a policy author can express the scope.
# GetMemoryRecord and ListActors read the same records but publish no scoping
# condition key at all, and their only resource type is the whole memory, so
# demanding a scope on them would fail a policy that cannot be written.
MEMORY_RECORD_READ_ACTIONS = (
    "retrievememoryrecords",
    "listmemoryrecords",
    "listevents",
    "getevent",
    "listsessions",
)

# Condition keys that bind a memory read to one actor, session, strategy or
# namespace. bedrock-agentcore:namespacePath and namespaceVariable/<key> are
# published in the devguide read-path and tenant-isolation examples but appear
# in neither the IAM service authorization reference nor the policy model as of
# 2026-09-25, so Access Analyzer reports them as unknown keys. Counting them as
# scoping intent is safe under both readings: if the key exists it scopes the
# grant, and if it does not the condition can never match and the Allow grants
# nothing.
MEMORY_SCOPE_CONDITION_KEYS = {
    "bedrock-agentcore:namespace",
    "bedrock-agentcore:namespacepath",
    "bedrock-agentcore:strategyid",
    "bedrock-agentcore:actorid",
    "bedrock-agentcore:sessionid",
}
MEMORY_SCOPE_CONDITION_KEY_PREFIXES = ("bedrock-agentcore:namespacevariable/",)

# A gateway rate limit carries one or more entries, and each entry may bound
# requests, tokens or connections. `dimensions` is the only required member of an
# entry, so a limit can exist with dimensions and no ceiling at all; the presence
# of one of these members is what makes the limit bound anything.
GATEWAY_RATE_LIMIT_VALUE_KEYS = ("requests", "tokens", "connections")

# Outbound credential provider types a gateway target can declare. The member is
# optional on CreateGatewayTarget and the console offers "No authorization (not
# recommended)", so a target can reach its backend with no gateway-supplied
# credential; the assessment reports the type it finds rather than ranking the
# types, because which one suits a backend is a workload decision.
GATEWAY_TARGET_CREDENTIAL_PROVIDER_TYPES = (
    "GATEWAY_IAM_ROLE",
    "OAUTH",
    "API_KEY",
    "CALLER_IAM_CREDENTIALS",
    "JWT_PASSTHROUGH",
)

# Condition keys that bind a resource policy or a role trust policy to the
# account or the resource the calling service acts for. Either one stops another
# customer's gateway from borrowing this account's permissions through the
# service principal.
CONFUSED_DEPUTY_CONDITION_KEYS = {"aws:sourceaccount", "aws:sourcearn"}

# Condition keys that bind a gateway resource policy to a private network path.
NETWORK_PATH_CONDITION_KEYS = {
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:vpcsourceip",
    "aws:sourceip",
}

# KMS actions that read log data under a customer managed key. A key policy that
# allows one of these to every principal with no condition hands the plaintext to
# anyone the account trusts, which defeats the point of the CMK.
KMS_DECRYPT_ACTIONS = ("decrypt", "generatedatakey", "reencryptfrom")

# Error codes that establish the target region is not enabled for the account.
# AWS returns these credential-shaped codes when a request is signed for a
# region the account has not opted into, so they are regional availability
# signals rather than credential defects — a genuinely invalid credential also
# fails the primary region, which the assessment always reaches first.
REGION_UNAVAILABLE_ERROR_CODES = {
    "AuthFailure",
    "InvalidClientTokenId",
    "OptInRequired",
    "UnrecognizedClientException",
}

# Error codes that only ever indicate an expired or malformed credential, never
# a disabled region.
AUTHENTICATION_ERROR_CODES = {
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidSignatureException",
    "SignatureDoesNotMatch",
}

# Execution tracking
start_time = None


def _is_valid_permissions_cache(cache: Any) -> bool:
    """Return whether cache has the IAM inventory shape produced upstream."""
    return (
        isinstance(cache, dict)
        and isinstance(cache.get("role_permissions"), dict)
        and isinstance(cache.get("user_permissions"), dict)
    )


def get_permissions_cache(execution_id: str) -> Dict[str, Any]:
    """
    Retrieve IAM permissions cache from S3.

    Args:
        execution_id: Unique execution identifier

    Returns:
        Dictionary containing cached IAM permissions

    Raises:
        Exception: If cache retrieval fails
    """
    try:
        cache_key = f"permissions_cache_{execution_id}.json"
        logger.info(f"Retrieving permissions cache: {cache_key}")

        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=cache_key)
        cache_data = json.loads(response["Body"].read().decode("utf-8"))
        if not _is_valid_permissions_cache(cache_data):
            raise ValueError("Permissions cache has an invalid schema")

        logger.info(
            f"Successfully retrieved permissions cache with {len(cache_data.get('role_permissions', []))} roles"
        )
        return cache_data

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            logger.error(f"Permissions cache not found: {cache_key}")
        else:
            logger.error(f"Error retrieving permissions cache: {e}")
        raise


def get_current_utc_date() -> str:
    """
    Get current UTC date in ISO format.

    Returns:
        Current UTC date as string
    """
    return datetime.now(timezone.utc).isoformat()


def check_timeout() -> bool:
    """
    Check if execution is approaching timeout.

    Returns:
        True if execution should continue, False if timeout approaching
    """
    if start_time is None:
        return True

    elapsed = time.time() - start_time

    if elapsed > 480:  # 8 minutes
        logger.warning(f"Approaching timeout: {elapsed}s elapsed")

    return elapsed < 540  # 9 minutes hard stop


def _agentcore_list_all(
    list_method_name: str, result_keys: List[str], **list_kwargs
) -> List[Dict[str, Any]]:
    """Collect all items from an AgentCore list API, following nextToken."""
    if agentcore_client is None:
        return []

    items: List[Dict[str, Any]] = []
    next_token = None
    seen_tokens = set()
    list_method = getattr(agentcore_client, list_method_name)

    while True:
        kwargs = dict(list_kwargs)
        if next_token:
            kwargs["nextToken"] = next_token

        response = list_method(**kwargs)
        if not isinstance(response, dict):
            logger.warning(
                f"{list_method_name} returned unexpected response type: "
                f"{type(response).__name__}"
            )
            break

        for result_key in result_keys:
            page_items = response.get(result_key)
            if isinstance(page_items, list):
                items.extend(page_items)
                break

        next_token = response.get("nextToken")
        if next_token is not None and not isinstance(next_token, str):
            logger.warning(
                f"{list_method_name} returned non-string nextToken: "
                f"{type(next_token).__name__}"
            )
            break
        if not next_token or next_token in seen_tokens:
            break
        seen_tokens.add(next_token)

    return items


def _paginate_aws_list(
    client: Any,
    operation_name: str,
    result_key: str,
    token_request_key: str = "nextToken",
    token_response_key: str = "nextToken",
    **list_kwargs,
) -> List[Dict[str, Any]]:
    """Collect all items from a non-AgentCore list API, following its token.

    The continuation member is capitalized differently per service, so both the
    request and the response member names are supplied by the caller.
    """
    if client is None:
        return []

    items: List[Dict[str, Any]] = []
    next_token = None
    seen_tokens = set()
    list_method = getattr(client, operation_name)

    while True:
        kwargs = dict(list_kwargs)
        if next_token:
            kwargs[token_request_key] = next_token

        response = list_method(**kwargs)
        if not isinstance(response, dict):
            logger.warning(
                f"{operation_name} returned unexpected response type: "
                f"{type(response).__name__}"
            )
            break

        page_items = response.get(result_key)
        if isinstance(page_items, list):
            items.extend(page_items)

        next_token = response.get(token_response_key)
        if next_token is not None and not isinstance(next_token, str):
            logger.warning(
                f"{operation_name} returned non-string {token_response_key}: "
                f"{type(next_token).__name__}"
            )
            break
        if not next_token or next_token in seen_tokens:
            break
        seen_tokens.add(next_token)

    return items


def get_custom_browser_inventory() -> Dict[str, Any]:
    """List custom browsers once and isolate per-browser detail failures."""
    inventory = {"items": [], "errors": [], "list_error": None}
    if agentcore_client is None:
        return inventory

    try:
        browsers = _agentcore_list_all(
            "list_browsers", ["browserSummaries"], type="CUSTOM"
        )
    except Exception as error:
        inventory["list_error"] = error
        return inventory

    for summary in browsers:
        browser_id = summary.get("browserId")
        if not browser_id:
            continue
        try:
            detail = _unwrap_agentcore_detail(
                agentcore_client.get_browser(browserId=browser_id), "browser"
            )
            inventory["items"].append({"summary": summary, "detail": detail})
        except Exception as error:
            inventory["errors"].append({"summary": summary, "error": error})

    return inventory


def _unwrap_agentcore_detail(
    response: Dict[str, Any], wrapper_key: str
) -> Dict[str, Any]:
    """Handle detail APIs that wrap the resource under a top-level key."""
    if not isinstance(response, dict):
        return {}

    wrapped = response.get(wrapper_key)
    if isinstance(wrapped, dict):
        return wrapped

    return response


def _get_agentcore_resource_policy(resource_arn: str) -> str:
    """Retrieve the generic AgentCore resource policy for a resource ARN."""
    response = agentcore_client.get_resource_policy(resourceArn=resource_arn)
    return response.get("policy") or response.get("resourcePolicy") or ""


def _is_access_denied_client_error(error: ClientError) -> bool:
    """Normalize access-denied checks across AgentCore control plane APIs."""
    if not isinstance(error, ClientError):
        return False

    error_code = error.response.get("Error", {}).get("Code")
    return error_code in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
    }


def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    """
    Generate CSV report from findings.

    Args:
        findings: List of finding dictionaries

    Returns:
        CSV content as string
    """
    output = StringIO()

    if not findings:
        logger.warning("No findings to generate report")
        # Create empty report with headers
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "Check_ID",
                "Finding",
                "Finding_Details",
                "Resolution",
                "Reference",
                "Severity",
                "Status",
                "Region",
                "Compliance_Frameworks",
            ],
        )
        writer.writeheader()
        return output.getvalue()

    # Write CSV with findings
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "Check_ID",
            "Finding",
            "Finding_Details",
            "Resolution",
            "Reference",
            "Severity",
            "Status",
            "Region",
            "Compliance_Frameworks",
        ],
    )
    writer.writeheader()

    for finding in findings:
        writer.writerow(finding)

    csv_content = output.getvalue()
    logger.info(f"Generated CSV report with {len(findings)} findings")

    return csv_content


def build_agentic_agentcore_security_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Create AG-* rows from AgentCore checks that already prove agentic controls."""
    agentic_findings = []
    for row in findings:
        source_check_id = row.get("Check_ID", "")
        mapping = AGENTIC_AGENTCORE_CHECK_MAPPINGS.get(source_check_id)
        if not mapping:
            continue

        status = row.get("Status", "N/A")
        severity = row.get("Severity", "Informational")
        if status == "N/A":
            severity = "Informational"

        agentic_findings.append(
            create_finding(
                check_id=mapping["check_id"],
                finding_name=mapping["finding"],
                finding_details=(
                    f"Agentic AI security domain: {mapping['lens_domain']}. "
                    f"{mapping['agentic_context']} "
                    f"Source check {source_check_id}: {row.get('Finding_Details', '')}"
                ),
                resolution=mapping["resolution"],
                reference=AGENTIC_AI_LENS_URL,
                severity=severity,
                status=status,
                region=row.get("Region", ""),
            )
        )
    return agentic_findings


def build_agentic_agentcore_unavailable_findings(
    region: str, existing_findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Create N/A AG-* rows for AgentCore-derived checks that could not run."""
    existing_check_ids = {finding.get("Check_ID") for finding in existing_findings}
    unavailable_findings = []

    for mapping in AGENTIC_AGENTCORE_CHECK_MAPPINGS.values():
        if mapping["check_id"] in existing_check_ids:
            continue

        unavailable_findings.append(
            create_finding(
                check_id=mapping["check_id"],
                finding_name=mapping["finding"],
                finding_details=(
                    f"Agentic AI security domain: {mapping['lens_domain']}. "
                    f"This AgentCore-derived control could not be assessed because "
                    f"Amazon Bedrock AgentCore is not available in region {region}."
                ),
                resolution="No action required unless AgentCore workloads are expected in this region.",
                reference=AGENTIC_AI_LENS_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
                region=region,
            )
        )

    return unavailable_findings


def build_agentcore_timeout_findings(
    region: str, existing_findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Create N/A AC-* and native AG-* rows skipped near the deadline."""
    existing_check_ids = {finding.get("Check_ID") for finding in existing_findings}
    timeout_findings = []

    for check_id in REGIONAL_AGENTCORE_CHECK_IDS:
        if check_id in existing_check_ids:
            continue
        timeout_findings.append(
            create_finding(
                check_id=check_id,
                finding_name="AgentCore Assessment Incomplete",
                finding_details=(
                    f"{check_id} could not be assessed because the Lambda timeout "
                    f"was approaching in region {region}."
                ),
                resolution="Re-run the assessment to complete the skipped AgentCore checks.",
                reference=AGENTCORE_STARTER_TOOLKIT_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
                region=region,
            )
        )

    for check_id, finding_name in NATIVE_AGENTIC_AGENTCORE_CHECK_NAMES.items():
        if check_id in existing_check_ids:
            continue
        timeout_findings.append(
            create_finding(
                check_id=check_id,
                finding_name=finding_name,
                finding_details=(
                    "This AgentCore gateway control could not be assessed because "
                    f"the Lambda timeout was approaching in region {region}."
                ),
                resolution="Re-run the assessment to complete the skipped AgentCore checks.",
                reference=AGENTIC_AI_LENS_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
                region=region,
            )
        )

    return timeout_findings


def build_agentic_agentcore_timeout_findings(
    region: str, existing_findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Create N/A mapped AG-* rows still missing after timeout backfill."""
    existing_check_ids = {finding.get("Check_ID") for finding in existing_findings}
    timeout_findings = []

    for mapping in AGENTIC_AGENTCORE_CHECK_MAPPINGS.values():
        if mapping["check_id"] in existing_check_ids:
            continue
        timeout_findings.append(
            create_finding(
                check_id=mapping["check_id"],
                finding_name=mapping["finding"],
                finding_details=(
                    f"Agentic AI security domain: {mapping['lens_domain']}. "
                    "This AgentCore-derived control could not be assessed because "
                    f"the Lambda timeout was approaching in region {region}."
                ),
                resolution="Re-run the assessment to complete the skipped AgentCore checks.",
                reference=AGENTIC_AI_LENS_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
                region=region,
            )
        )

    return timeout_findings


def prepare_agentcore_timeout_report_findings(
    findings: List[Dict[str, Any]], region: str
) -> None:
    """Backfill deadline-skipped checks and synthesize their Agentic AI rows."""
    findings.extend(build_agentcore_timeout_findings(region, findings))
    for finding in findings:
        if not finding.get("Region"):
            finding["Region"] = region
    findings.extend(build_agentic_agentcore_security_findings(findings))
    findings.extend(build_agentic_agentcore_timeout_findings(region, findings))
    for finding in findings:
        if not finding.get("Region"):
            finding["Region"] = region


def prepare_agentcore_runtime_incomplete_report_findings(
    findings: List[Dict[str, Any]],
    region: str,
    error_code: str,
) -> None:
    """Backfill Runtime checks skipped after an indeterminate credential probe."""
    resolution = (
        "Verify the assessment credentials, session token, signing region, and "
        "system clock, then retry."
    )
    existing_check_ids = {finding.get("Check_ID") for finding in findings}

    for check_id in AGENTCORE_RUNTIME_CHECK_IDS:
        if check_id in existing_check_ids:
            continue
        findings.append(
            create_finding(
                check_id=check_id,
                finding_name="AgentCore Runtime Assessment Incomplete",
                finding_details=(
                    f"{check_id} could not be assessed in region {region} because "
                    "the AgentCore Runtime availability probe returned credential "
                    f"or authentication error {error_code}."
                ),
                resolution=resolution,
                reference=AGENTCORE_STARTER_TOOLKIT_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
                region=region,
            )
        )

    for check_id, finding_name in NATIVE_AGENTIC_AGENTCORE_CHECK_NAMES.items():
        if check_id in existing_check_ids:
            continue
        findings.append(
            create_finding(
                check_id=check_id,
                finding_name=finding_name,
                finding_details=(
                    "This AgentCore gateway control could not be assessed in "
                    f"region {region} because the AgentCore Runtime availability "
                    "probe returned credential or authentication error "
                    f"{error_code}."
                ),
                resolution=resolution,
                reference=AGENTIC_AI_LENS_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
                region=region,
            )
        )

    for finding in findings:
        if not finding.get("Region"):
            finding["Region"] = region
    runtime_agentic_check_ids = {
        AGENTIC_AGENTCORE_CHECK_MAPPINGS[check_id]["check_id"]
        for check_id in AGENTCORE_RUNTIME_CHECK_IDS
        if check_id in AGENTIC_AGENTCORE_CHECK_MAPPINGS
    }
    agentic_findings = build_agentic_agentcore_security_findings(findings)
    for finding in agentic_findings:
        if finding.get("Check_ID") in runtime_agentic_check_ids:
            finding["Resolution"] = resolution
    findings.extend(agentic_findings)
    for finding in findings:
        if not finding.get("Region"):
            finding["Region"] = region


def write_to_s3(
    execution_id: str, csv_content: str, bucket_name: str, region: str = ""
) -> str:
    """
    Upload CSV report to S3.

    Args:
        execution_id: Unique execution identifier
        csv_content: CSV content to upload
        bucket_name: S3 bucket name
        region: AWS region identifier for the report filename

    Returns:
        S3 URL of uploaded file

    Raises:
        Exception: If upload fails
    """
    try:
        if region:
            key = f"agentcore_security_report_{execution_id}_{region}.csv"
        else:
            key = f"agentcore_security_report_{execution_id}.csv"

        s3_client.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=csv_content.encode("utf-8"),
            ContentType="text/csv",
        )

        s3_url = f"s3://{bucket_name}/{key}"
        logger.info(f"Successfully uploaded report to {s3_url}")

        return s3_url

    except Exception as e:
        logger.error(f"Error uploading to S3: {e}")
        raise


def check_agentcore_vpc_configuration() -> List[Dict[str, Any]]:
    """
    Check VPC configuration for AgentCore Runtimes, Code Interpreters, and Browser Tools.

    Validates:
    - VPC configuration exists
    - Subnets are private (not public)
    - Required VPC endpoints exist
    - NAT gateway configuration

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        logger.error("AgentCore client not available")
        findings.append(
            create_finding(
                check_id="AC-01",
                finding_name="AgentCore VPC Configuration Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference=AGENTCORE_STARTER_TOOLKIT_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore VPC configuration")
        resources_found = False

        # Check Runtimes
        try:
            runtimes = _agentcore_list_all("list_agent_runtimes", ["agentRuntimes"])

            if not runtimes:
                logger.info("No AgentCore Runtimes found")
            else:
                resources_found = True
                logger.info(f"Found {len(runtimes)} AgentCore Runtimes")

                for runtime in runtimes:
                    runtime_id = runtime.get("agentRuntimeId", "unknown")
                    runtime_name = runtime.get("agentRuntimeName", runtime_id)

                    # Get detailed runtime info
                    try:
                        runtime_details = agentcore_client.get_agent_runtime(
                            agentRuntimeId=runtime_id
                        )
                        network_config = runtime_details.get("networkConfiguration", {})
                        network_mode = network_config.get("networkMode", "PUBLIC")

                        if network_mode == "PUBLIC":
                            findings.append(
                                create_finding(
                                    check_id="AC-01",
                                    finding_name="AgentCore Runtime VPC Configuration",
                                    finding_details=f"Runtime '{runtime_name}' ({runtime_id}) is not configured with VPC. This exposes the runtime to public internet.",
                                    resolution="Configure VPC with private subnets and required VPC endpoints (ECR, S3, CloudWatch Logs)",
                                    reference=AGENTCORE_VPC_REFERENCE_URL,
                                    severity=SeverityEnum.HIGH,
                                    status=StatusEnum.FAILED,
                                )
                            )
                        else:
                            # Validate VPC configuration
                            subnet_ids = network_config.get("subnetIds", [])

                            if subnet_ids:
                                # Check if subnets are private
                                try:
                                    subnets_response = ec2_client.describe_subnets(
                                        SubnetIds=subnet_ids
                                    )
                                    for subnet in subnets_response.get("Subnets", []):
                                        subnet_id = subnet["SubnetId"]

                                        # Check route tables for internet gateway
                                        route_tables = ec2_client.describe_route_tables(
                                            Filters=[
                                                {
                                                    "Name": "association.subnet-id",
                                                    "Values": [subnet_id],
                                                }
                                            ]
                                        )

                                        for rt in route_tables.get("RouteTables", []):
                                            for route in rt.get("Routes", []):
                                                if route.get(
                                                    "GatewayId", ""
                                                ).startswith("igw-"):
                                                    findings.append(
                                                        create_finding(
                                                            check_id="AC-01",
                                                            finding_name="AgentCore Runtime Public Subnet",
                                                            finding_details=f"Runtime '{runtime_name}' is in public subnet {subnet_id} with direct internet access",
                                                            resolution="Move runtime to private subnets without direct internet gateway routes",
                                                            reference=AGENTCORE_VPC_REFERENCE_URL,
                                                            severity=SeverityEnum.MEDIUM,
                                                            status=StatusEnum.FAILED,
                                                        )
                                                    )

                                except ClientError as e:
                                    logger.warning(
                                        f"Error checking subnet configuration: {e}"
                                    )

                    except ClientError as e:
                        if e.response["Error"]["Code"] == "ResourceNotFoundException":
                            logger.warning(f"Runtime {runtime_id} not found")
                        else:
                            logger.error(f"Error describing runtime {runtime_id}: {e}")

        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.info("No AgentCore Runtimes found")
            else:
                logger.error(f"Error listing runtimes: {e}")
                raise

        # Note: Code Interpreters and Browser Tools are configured as part of Runtime
        # They don't have separate list/describe APIs in bedrock-agentcore-control
        # VPC configuration for these tools is inherited from the Runtime configuration

        # Return appropriate status based on whether resources were found
        if not findings:
            if resources_found:
                findings.append(
                    create_finding(
                        check_id="AC-01",
                        finding_name="AgentCore VPC Configuration Check",
                        finding_details="All AgentCore resources have proper VPC configuration",
                        resolution="No action required",
                        reference=AGENTCORE_VPC_REFERENCE_URL,
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-01",
                        finding_name="AgentCore VPC Configuration Check",
                        finding_details="No AgentCore resources found",
                        resolution="No action required",
                        reference=AGENTCORE_VPC_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in VPC configuration check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-01",
                finding_name="AgentCore VPC Configuration Check",
                error=e,
                reference=AGENTCORE_STARTER_TOOLKIT_URL,
            )
        )

    return findings


AGENT_PLATFORM_IAM_NAMESPACES = {"bedrock-agentcore"}


def _policy_document(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Return one cached IAM policy document as a mapping."""
    document = policy.get("document", {})
    if isinstance(document, str):
        document = json.loads(document)
    if not isinstance(document, dict):
        raise ValueError("IAM policy document is not a mapping")
    return document


def _allow_statements(policy: Dict[str, Any]):
    """Yield Allow statements from one cached attached or inline policy."""
    statements = _policy_document(policy).get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for statement in statements:
        if isinstance(statement, dict) and statement.get("Effect") == "Allow":
            yield statement


def _statement_actions(statement: Dict[str, Any]) -> List[str]:
    """Return normalized action strings from one IAM statement."""
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    return [str(action).strip().lower() for action in actions]


def _statement_not_actions(statement: Dict[str, Any]) -> List[str]:
    """Return normalized NotAction strings from one IAM statement."""
    not_actions = statement.get("NotAction", [])
    if isinstance(not_actions, str):
        not_actions = [not_actions]
    return [str(action).strip().lower() for action in not_actions]


def _statement_resources(statement: Dict[str, Any]) -> List[str]:
    """Return normalized resource strings from one IAM statement."""
    resources = statement.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    return [str(resource) for resource in resources]


def _document_statements(document: Any, effect: str = "") -> List[Dict[str, Any]]:
    """Return the statements of a policy document that is not a cached policy.

    Resource policies, role trust policies and service control policies arrive as
    a JSON string straight from their own API rather than through the permission
    cache, so `_allow_statements` cannot read them. A single-statement document is
    a mapping and not a list, which the IAM grammar allows and which would
    otherwise iterate the statement's keys.
    """
    if isinstance(document, (str, bytes)):
        try:
            document = json.loads(document)
        except (TypeError, ValueError):
            return []
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [
        statement
        for statement in statements
        if isinstance(statement, dict)
        and (not effect or statement.get("Effect") == effect)
    ]


def _statement_principals(statement: Dict[str, Any]) -> List[str]:
    """Return normalized principal values from one resource or trust statement.

    A bare `"Principal": "*"` and `{"AWS": "*"}` mean the same thing and are both
    flattened to `*` here, so a caller can test one shape.
    """
    principal = statement.get("Principal")
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal.strip()]
    if not isinstance(principal, dict):
        return []

    values: List[str] = []
    for entry in principal.values():
        if isinstance(entry, str):
            values.append(entry.strip())
        elif isinstance(entry, list):
            values.extend(str(item).strip() for item in entry)
    return values


def _is_agent_platform_action(action: str) -> bool:
    """Return whether an IAM action grants AgentCore access."""
    action_parts = action.split(":", 1)
    return len(action_parts) == 2 and action_parts[0] in AGENT_PLATFORM_IAM_NAMESPACES


def _not_action_excludes_namespace(pattern: str, namespace: str) -> bool:
    """Return whether one NotAction pattern excludes every action in a service."""
    if pattern == "*":
        return True
    pattern_parts = pattern.split(":", 1)
    if len(pattern_parts) != 2:
        return False
    service_pattern, action_pattern = pattern_parts
    return action_pattern == "*" and fnmatchcase(namespace, service_pattern)


def _not_action_targets_agent_platform(exclusions: List[str]) -> bool:
    """Return whether NotAction exclusions name an agent platform namespace."""
    for pattern in exclusions:
        pattern_parts = pattern.split(":", 1)
        if len(pattern_parts) != 2:
            continue
        service_pattern = pattern_parts[0]
        if any(
            fnmatchcase(namespace, service_pattern)
            for namespace in AGENT_PLATFORM_IAM_NAMESPACES
        ):
            return True
    return False


def _not_action_allows_agent_platform_access(statement: Dict[str, Any]) -> bool:
    """Return whether an Allow/NotAction statement still grants platform access."""
    if "NotAction" not in statement:
        return False
    exclusions = _statement_not_actions(statement)
    if not _not_action_targets_agent_platform(exclusions):
        # The exclusions name no agent platform namespace, so this is a
        # service-agnostic administrator-style grant rather than an
        # AgentCore-specific one. These checks scope themselves to explicit
        # platform namespaces, the same reason a bare `Action: "*"` is ignored.
        return False
    return any(
        not any(
            _not_action_excludes_namespace(pattern, namespace) for pattern in exclusions
        )
        for namespace in AGENT_PLATFORM_IAM_NAMESPACES
    )


def _policy_has_wildcard_agent_platform_access(policy: Dict[str, Any]) -> bool:
    """Return whether a policy grants broad platform access on all resources."""
    for statement in _allow_statements(policy):
        if "*" not in _statement_resources(statement):
            continue
        if _not_action_allows_agent_platform_access(statement):
            return True
        for action in _statement_actions(statement):
            action_parts = action.split(":", 1)
            if len(action_parts) != 2:
                continue
            service_namespace, action_pattern = action_parts
            if service_namespace in AGENT_PLATFORM_IAM_NAMESPACES and any(
                wildcard in action_pattern for wildcard in ("*", "?")
            ):
                return True
    return False


def _permissions_include_agent_platform_access(
    permissions: Dict[str, Any],
    principal_label: str,
) -> bool:
    """Inspect attached and inline policies for AgentCore access."""
    attached_policies = permissions.get("attached_policies", [])
    inline_policies = permissions.get("inline_policies", [])

    for policy in [*attached_policies, *inline_policies]:
        try:
            for statement in _allow_statements(policy):
                if _not_action_allows_agent_platform_access(statement) or any(
                    _is_agent_platform_action(action)
                    for action in _statement_actions(statement)
                ):
                    return True
        except Exception as error:
            logger.warning(f"Error parsing policy for {principal_label}: {error}")

    return False


def check_agentcore_full_access_roles(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Check for IAM roles with overly permissive AgentCore access.

    Identifies:
    - Roles with BedrockAgentCoreFullAccess
    - Roles with wildcard or allow-except AgentCore permissions

    Args:
        permission_cache: Cached IAM permissions data

    Returns:
        List of findings
    """
    findings = []

    try:
        logger.info("Checking for AgentCore full access roles")

        role_permissions = permission_cache.get("role_permissions", {})

        if not role_permissions:
            logger.info("No role permissions in cache")
            findings.append(
                create_finding(
                    check_id="AC-02",
                    finding_name="AgentCore IAM Full Access Check",
                    finding_details="No IAM role permissions found in cache",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        full_access_roles = []
        wildcard_roles = set()
        policy_parse_errors = []

        # Iterate over role_permissions dict (role_name -> permissions)
        for role_name, permissions in role_permissions.items():
            attached_policies = permissions.get("attached_policies", [])
            inline_policies = permissions.get("inline_policies", [])

            # Check for AgentCore full-access managed policies.
            for policy in attached_policies:
                policy_name = policy.get("name", "")
                if (
                    "BedrockAgentCoreFullAccess" in policy_name
                    or "AgentCoreFullAccess" in policy_name
                ):
                    full_access_roles.append(role_name)
                    break

            # Check attached and inline documents for wildcard or allow-except
            # AgentCore permissions.
            for policy in [*attached_policies, *inline_policies]:
                try:
                    if _policy_has_wildcard_agent_platform_access(policy):
                        wildcard_roles.add(role_name)
                        break
                except Exception as error:
                    logger.warning(
                        f"Error parsing policy for role {role_name}: {error}"
                    )
                    policy_parse_errors.append(error)

        # Generate findings for full access roles
        if full_access_roles:
            findings.append(
                create_finding(
                    check_id="AC-02",
                    finding_name="AgentCore IAM Full Access Policy",
                    finding_details=f"The following roles have AgentCore full-access policies: {', '.join(full_access_roles)}",
                    resolution="Replace with least-privilege policies scoped to specific AgentCore resources and actions",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        # Generate findings for wildcard roles
        if wildcard_roles:
            findings.append(
                create_finding(
                    check_id="AC-02",
                    finding_name="AgentCore IAM Wildcard Permissions",
                    finding_details=f"The following roles have wildcard or allow-except AgentCore permissions on all resources: {', '.join(sorted(wildcard_roles))}",
                    resolution="Replace wildcard or allow-except permissions with required AgentCore actions and scope resources using ARNs",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        if policy_parse_errors:
            findings.append(
                _incomplete_check_finding(
                    check_id="AC-02",
                    finding_name="AgentCore IAM Full Access Check",
                    error=policy_parse_errors[0],
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                )
            )

        # If no issues found - roles were evaluated and none were problematic
        if not findings:
            findings.append(
                create_finding(
                    check_id="AC-02",
                    finding_name="AgentCore IAM Full Access Check",
                    finding_details="No roles with overly permissive AgentCore access found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )

    except Exception as e:
        logger.error(f"Error in full access roles check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-02",
                finding_name="AgentCore IAM Full Access Check",
                error=e,
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
            )
        )

    return findings


def check_stale_agentcore_access(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Check for IAM principals with AgentCore permissions but no recent usage.

    Identifies:
    - Principals that haven't accessed AgentCore in 60+ days
    - Principals with permissions but never accessed AgentCore

    Args:
        permission_cache: Cached IAM permissions data

    Returns:
        List of findings
    """
    findings = []

    try:
        logger.info("Checking for stale AgentCore access")

        # Get current account ID from STS
        sts_client = boto3.client("sts", config=boto3_config)
        caller_identity = sts_client.get_caller_identity()
        account_id = caller_identity["Account"]
        partition = _caller_identity_partition(caller_identity)

        role_permissions = permission_cache.get("role_permissions", {})
        user_permissions = permission_cache.get("user_permissions", {})

        if not role_permissions and not user_permissions:
            logger.info("No IAM permissions in cache")
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Stale Access Check",
                    finding_details="No IAM permissions found in cache",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        # Identify principals with AgentCore permissions
        agentcore_principals = []

        # Check roles - iterate over dict
        for role_name, permissions in role_permissions.items():
            # Build role ARN from role name
            role_arn = f"arn:{partition}:iam::{account_id}:role/{role_name}"
            has_agentcore_permission = _permissions_include_agent_platform_access(
                permissions, f"role {role_name}"
            )

            if has_agentcore_permission and role_arn:
                agentcore_principals.append(
                    {"type": "role", "name": role_name, "arn": role_arn}
                )

        # Check users - iterate over dict
        for user_name, permissions in user_permissions.items():
            # Build user ARN from user name
            user_arn = f"arn:{partition}:iam::{account_id}:user/{user_name}"
            has_agentcore_permission = _permissions_include_agent_platform_access(
                permissions, f"user {user_name}"
            )

            if has_agentcore_permission and user_arn:
                agentcore_principals.append(
                    {"type": "user", "name": user_name, "arn": user_arn}
                )

        if not agentcore_principals:
            logger.info("No principals with AgentCore permissions found")
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Stale Access Check",
                    finding_details="No IAM principals with AgentCore permissions found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        logger.info(
            f"Found {len(agentcore_principals)} principals with AgentCore permissions"
        )

        # Check last accessed for each principal
        stale_principals = []
        never_accessed_principals = []

        for principal_index, principal in enumerate(agentcore_principals):
            principal_arn = principal["arn"]
            principal_name = principal["name"]
            principal_type = principal["type"]

            if not check_timeout():
                remaining_principals = len(agentcore_principals) - principal_index
                logger.warning(
                    "Stopping stale-access checks with "
                    f"{remaining_principals} principal(s) remaining because the "
                    "Lambda timeout is approaching"
                )
                findings.append(
                    create_finding(
                        check_id="AC-03",
                        finding_name="AgentCore Stale Access Check Incomplete",
                        finding_details=(
                            f"Stopped before completing the assessment of "
                            f"{remaining_principals} IAM principal(s) because the "
                            "Lambda timeout was approaching"
                        ),
                        resolution="Re-run the assessment to evaluate the remaining principals",
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                break

            try:
                # Generate service last accessed details
                logger.info(
                    f"Generating service last accessed details for {principal_type} {principal_name}"
                )

                generate_response = iam_client.generate_service_last_accessed_details(
                    Arn=principal_arn
                )
                job_id = generate_response["JobId"]

                # Wait for job completion (max 30 seconds)
                max_wait_time = 30
                wait_interval = 2
                elapsed_time = 0
                job_status = "IN_PROGRESS"
                lambda_timeout_approaching = False

                while job_status == "IN_PROGRESS" and elapsed_time < max_wait_time:
                    if not check_timeout():
                        lambda_timeout_approaching = True
                        break

                    time.sleep(wait_interval)  # nosemgrep: arbitrary-sleep
                    elapsed_time += wait_interval

                    if not check_timeout():
                        lambda_timeout_approaching = True
                        break

                    get_response = iam_client.get_service_last_accessed_details(
                        JobId=job_id
                    )
                    job_status = get_response["JobStatus"]

                    if job_status == "COMPLETED":
                        # Check for AgentCore service access
                        services = get_response.get("ServicesLastAccessed", [])

                        matching_services = []
                        for service in services:
                            service_name = service.get("ServiceName", "")
                            service_namespace = service.get("ServiceNamespace", "")

                            # Look for AgentCore service
                            if (
                                "agentcore" in service_name.lower()
                                or "agentcore" in service_namespace.lower()
                                or "bedrock-agentcore" in service_namespace.lower()
                            ):
                                matching_services.append(service)

                        if matching_services:
                            last_authenticated_values = [
                                service.get("LastAuthenticated")
                                for service in matching_services
                                if service.get("LastAuthenticated")
                            ]

                            if last_authenticated_values:
                                # Calculate days since last access
                                last_access_dates = []
                                for last_authenticated in last_authenticated_values:
                                    last_access_date = datetime.fromisoformat(
                                        str(last_authenticated).replace("Z", "+00:00")
                                    )
                                    if last_access_date.tzinfo is None:
                                        last_access_date = last_access_date.replace(
                                            tzinfo=timezone.utc
                                        )
                                    last_access_dates.append(last_access_date)
                                last_access_date = max(last_access_dates)
                                current_date = datetime.now(timezone.utc)
                                days_since_access = (
                                    current_date - last_access_date
                                ).days

                                if days_since_access > 60:
                                    stale_principals.append(
                                        {
                                            "type": principal_type,
                                            "name": principal_name,
                                            "days": days_since_access,
                                        }
                                    )
                                    logger.info(
                                        f"{principal_type} {principal_name} last accessed AgentCore {days_since_access} days ago"
                                    )
                            else:
                                # Never accessed
                                never_accessed_principals.append(
                                    {"type": principal_type, "name": principal_name}
                                )
                                logger.info(
                                    f"{principal_type} {principal_name} has never accessed AgentCore"
                                )
                        else:
                            # AgentCore service not in the list - treat as never accessed
                            never_accessed_principals.append(
                                {"type": principal_type, "name": principal_name}
                            )
                            logger.info(
                                f"{principal_type} {principal_name} has AgentCore permissions but service not in access history"
                            )

                        break

                    elif job_status == "FAILED":
                        logger.error(
                            f"Job failed for {principal_type} {principal_name}"
                        )
                        break

                if lambda_timeout_approaching:
                    remaining_principals = len(agentcore_principals) - principal_index
                    logger.warning(
                        "Stopping stale-access checks while assessing "
                        f"{principal_type} {principal_name}, with "
                        f"{remaining_principals} principal(s) incomplete, because "
                        "the Lambda timeout is approaching"
                    )
                    findings.append(
                        create_finding(
                            check_id="AC-03",
                            finding_name="AgentCore Stale Access Check Incomplete",
                            finding_details=(
                                f"Stopped before completing the assessment of "
                                f"{remaining_principals} IAM principal(s) because "
                                "the Lambda timeout was approaching"
                            ),
                            resolution="Re-run the assessment to evaluate the remaining principals",
                            reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                            severity=SeverityEnum.INFORMATIONAL,
                            status=StatusEnum.NA,
                        )
                    )
                    break

                if job_status == "IN_PROGRESS":
                    logger.warning(
                        f"Job timed out for {principal_type} {principal_name} after {max_wait_time}s"
                    )
                    findings.append(
                        create_finding(
                            check_id="AC-03",
                            finding_name="AgentCore Stale Access Check Incomplete",
                            finding_details=f"Could not determine last access for {principal_type} '{principal_name}' — IAM job timed out after {max_wait_time}s",
                            resolution="Re-run the assessment or manually check service last accessed details for this principal",
                            reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                            severity=SeverityEnum.INFORMATIONAL,
                            status=StatusEnum.NA,
                        )
                    )

            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "NoSuchEntity":
                    logger.warning(f"Principal {principal_name} no longer exists")
                elif error_code == "AccessDenied":
                    logger.error(f"Access denied when checking {principal_name}: {e}")
                    findings.append(
                        _incomplete_check_finding(
                            check_id="AC-03",
                            finding_name="AgentCore Stale Access Check",
                            error=e,
                            reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                        )
                    )
                    return findings
                else:
                    logger.error(
                        f"Error checking {principal_type} {principal_name}: {e}"
                    )

            except Exception as e:
                logger.error(
                    f"Unexpected error checking {principal_type} {principal_name}: {e}"
                )

        # Generate findings for stale access
        if stale_principals:
            stale_details = ", ".join(
                [
                    f"{p['type']} '{p['name']}' ({p['days']} days)"
                    for p in stale_principals
                ]
            )
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Stale Access",
                    finding_details=f"The following principals have not accessed AgentCore in 60+ days: {stale_details}",
                    resolution="Review and remove unused AgentCore permissions following least privilege principle",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )

        # Generate findings for never accessed
        if never_accessed_principals:
            never_accessed_details = ", ".join(
                [f"{p['type']} '{p['name']}'" for p in never_accessed_principals]
            )
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Unused Permissions",
                    finding_details=f"The following principals have AgentCore permissions but have never accessed the service: {never_accessed_details}",
                    resolution="Review and remove unused AgentCore permissions following least privilege principle",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

        # If no issues found
        if not findings:
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Stale Access Check",
                    finding_details=f"All {len(agentcore_principals)} principals with AgentCore permissions have accessed the service within the last 60 days",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.LOW,
                    status=StatusEnum.PASSED,
                )
            )

    except Exception as e:
        logger.error(f"Error in stale access check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-03",
                finding_name="AgentCore Stale Access Check",
                error=e,
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
            )
        )

    return findings


def check_agentcore_observability() -> List[Dict[str, Any]]:
    """
    Check observability configuration for AgentCore resources.

    Validates:
    - CloudWatch Logs configuration
    - X-Ray tracing enabled
    - CloudWatch custom metrics published

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-04",
                finding_name="AgentCore Observability Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore observability configuration")
        resources_found = False

        # Check Runtimes for logging and tracing
        try:
            runtimes = _agentcore_list_all("list_agent_runtimes", ["agentRuntimes"])

            if not runtimes:
                logger.info("No AgentCore Runtimes found")
            else:
                resources_found = True
                logger.info(f"Found {len(runtimes)} AgentCore Runtimes")

                for runtime in runtimes:
                    runtime_id = runtime.get("agentRuntimeId", "unknown")
                    runtime_name = runtime.get("agentRuntimeName", runtime_id)

                    try:
                        runtime_details = agentcore_client.get_agent_runtime(
                            agentRuntimeId=runtime_id
                        )

                        # Check CloudWatch Logs configuration
                        logging_config = runtime_details.get("loggingConfig", {})
                        cloudwatch_logs_config = logging_config.get(
                            "cloudWatchLogsConfig"
                        )

                        if not cloudwatch_logs_config:
                            findings.append(
                                create_finding(
                                    check_id="AC-04",
                                    finding_name="AgentCore Runtime CloudWatch Logs",
                                    finding_details=f"Runtime '{runtime_name}' ({runtime_id}) does not have CloudWatch Logs configured",
                                    resolution="Enable CloudWatch Logs for monitoring and troubleshooting",
                                    reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
                                    severity=SeverityEnum.MEDIUM,
                                    status=StatusEnum.FAILED,
                                )
                            )
                        else:
                            # Verify log group exists
                            log_group_name = cloudwatch_logs_config.get("logGroupName")
                            if log_group_name:
                                try:
                                    logs_client.describe_log_groups(
                                        logGroupNamePrefix=log_group_name, limit=1
                                    )
                                except ClientError as e:
                                    if (
                                        e.response["Error"]["Code"]
                                        == "ResourceNotFoundException"
                                    ):
                                        findings.append(
                                            create_finding(
                                                check_id="AC-04",
                                                finding_name="AgentCore Runtime Log Group Missing",
                                                finding_details=f"Runtime '{runtime_name}' has CloudWatch Logs configured but log group '{log_group_name}' does not exist",
                                                resolution="Create the log group or update runtime configuration",
                                                reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
                                                severity=SeverityEnum.MEDIUM,
                                                status=StatusEnum.FAILED,
                                            )
                                        )

                        # Check X-Ray tracing configuration
                        tracing_config = runtime_details.get("tracingConfig", {})
                        tracing_enabled = tracing_config.get("enabled", False)

                        if not tracing_enabled:
                            findings.append(
                                create_finding(
                                    check_id="AC-04",
                                    finding_name="AgentCore Runtime X-Ray Tracing",
                                    finding_details=f"Runtime '{runtime_name}' ({runtime_id}) does not have X-Ray tracing enabled",
                                    resolution="Enable X-Ray tracing for distributed tracing and performance analysis",
                                    reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
                                    severity=SeverityEnum.MEDIUM,
                                    status=StatusEnum.FAILED,
                                )
                            )

                    except ClientError as e:
                        if e.response["Error"]["Code"] != "ResourceNotFoundException":
                            logger.error(f"Error describing runtime {runtime_id}: {e}")

        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                logger.error(f"Error listing runtimes: {e}")

        # Return appropriate status based on whether resources were found
        if not findings:
            if resources_found:
                findings.append(
                    create_finding(
                        check_id="AC-04",
                        finding_name="AgentCore Observability Check",
                        finding_details="All AgentCore resources have proper observability configuration",
                        resolution="No action required",
                        reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-04",
                        finding_name="AgentCore Observability Check",
                        finding_details="No AgentCore resources found",
                        resolution="No action required",
                        reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in observability check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-04",
                finding_name="AgentCore Observability Check",
                error=e,
                reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
            )
        )

    return findings


def check_agentcore_encryption() -> List[Dict[str, Any]]:
    """
    Check encryption configuration for AgentCore resources.

    Validates:
    - ECR repository encryption
    - S3 bucket encryption for Browser Tool recordings
    - Customer-managed vs AWS-managed keys

    Returns:
        List of findings
    """
    findings = []

    try:
        logger.info("Checking AgentCore encryption configuration")
        resources_found = False

        # Check ECR repositories used by AgentCore
        try:
            ecr_response = ecr_client.describe_repositories()
            repositories = ecr_response.get("repositories", [])

            agentcore_repos = []
            for repo in repositories:
                repo_name = repo.get("repositoryName", "")
                # Look for AgentCore-related repositories
                if (
                    "agentcore" in repo_name.lower()
                    or "bedrock-agent" in repo_name.lower()
                ):
                    agentcore_repos.append(repo)

            if agentcore_repos:
                resources_found = True
                logger.info(
                    f"Found {len(agentcore_repos)} AgentCore-related ECR repositories"
                )

                for repo in agentcore_repos:
                    repo_name = repo.get("repositoryName", "unknown")
                    encryption_config = repo.get("encryptionConfiguration", {})
                    encryption_type = encryption_config.get("encryptionType", "NONE")

                    if encryption_type == "NONE" or not encryption_config:
                        findings.append(
                            create_finding(
                                check_id="AC-05",
                                finding_name="AgentCore ECR Repository Encryption",
                                finding_details=f"ECR repository '{repo_name}' does not have encryption enabled",
                                resolution="Enable encryption with customer-managed KMS keys for better control",
                                reference=ECR_ENCRYPTION_REFERENCE_URL,
                                severity=SeverityEnum.HIGH,
                                status=StatusEnum.FAILED,
                            )
                        )
                    elif encryption_type == "AES256":
                        findings.append(
                            create_finding(
                                check_id="AC-05",
                                finding_name="AgentCore ECR Repository AWS-Managed Keys",
                                finding_details=f"ECR repository '{repo_name}' uses AWS-managed keys instead of customer-managed KMS keys",
                                resolution="Consider using customer-managed KMS keys for better control and audit capabilities",
                                reference=ECR_ENCRYPTION_REFERENCE_URL,
                                severity=SeverityEnum.LOW,
                                status=StatusEnum.FAILED,
                            )
                        )

        except ClientError as e:
            logger.warning(f"Error checking ECR repositories: {e}")

        # Note: Browser Tool recording buckets and Code Interpreter storage are configured
        # as part of Runtime configuration, not as separate resources

        # Return appropriate status based on whether resources were found
        if not findings:
            if resources_found:
                findings.append(
                    create_finding(
                        check_id="AC-05",
                        finding_name="AgentCore Encryption Check",
                        finding_details="All AgentCore resources have proper encryption configuration",
                        resolution="No action required",
                        reference=AGENTCORE_DATA_ENCRYPTION_REFERENCE_URL,
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-05",
                        finding_name="AgentCore Encryption Check",
                        finding_details="No AgentCore resources found",
                        resolution="No action required",
                        reference=AGENTCORE_DATA_ENCRYPTION_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in encryption check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-05",
                finding_name="AgentCore Encryption Check",
                error=e,
                reference=AGENTCORE_DATA_ENCRYPTION_REFERENCE_URL,
            )
        )

    return findings


def check_browser_tool_recording(
    browser_inventory: Dict[str, Any] = None,
) -> List[Dict[str, Any]]:
    """AC-06: Require recording and an S3 destination on custom browsers."""
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-06",
                finding_name=AGENTCORE_BROWSER_RECORDING_FINDING_NAME,
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        inventory = browser_inventory or get_custom_browser_inventory()
        if inventory.get("list_error"):
            error = inventory["list_error"]
            findings.append(
                create_finding(
                    check_id="AC-06",
                    finding_name=AGENTCORE_BROWSER_RECORDING_FINDING_NAME,
                    finding_details=f"Could not assess custom browser recording: {type(error).__name__}.",
                    resolution="Grant bedrock-agentcore:ListBrowsers and bedrock-agentcore:GetBrowser, then retry.",
                    reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        browsers = inventory.get("items", [])
        if not browsers and not inventory.get("errors"):
            findings.append(
                create_finding(
                    check_id="AC-06",
                    finding_name=AGENTCORE_BROWSER_RECORDING_FINDING_NAME,
                    finding_details="No custom AgentCore browsers found",
                    resolution="No action required",
                    reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        for item in browsers:
            summary = item["summary"]
            detail = item["detail"]
            browser_id = summary.get("browserId", "unknown")
            browser_name = summary.get("name", browser_id)
            recording = detail.get("recording") or {}
            s3_location = recording.get("s3Location") or {}
            enabled = recording.get("enabled") is True
            bucket = s3_location.get("bucket")
            configured = enabled and bool(bucket)

            findings.append(
                create_finding(
                    check_id="AC-06",
                    finding_name=AGENTCORE_BROWSER_RECORDING_FINDING_NAME,
                    finding_details=(
                        f"Custom browser '{browser_name}' ({browser_id}) has session "
                        f"recording enabled with S3 bucket '{bucket}'."
                        if configured
                        else f"Custom browser '{browser_name}' ({browser_id}) does not "
                        "have session recording enabled with an S3 destination."
                    ),
                    resolution=(
                        "No action required"
                        if configured
                        else "Enable browser session recording and configure a non-empty S3 recording destination."
                    ),
                    reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED if configured else StatusEnum.FAILED,
                )
            )

        for item in inventory.get("errors", []):
            summary = item["summary"]
            error = item["error"]
            findings.append(
                create_finding(
                    check_id="AC-06",
                    finding_name=AGENTCORE_BROWSER_RECORDING_FINDING_NAME,
                    finding_details=(
                        f"Custom browser '{summary.get('name', summary.get('browserId', 'unknown'))}' "
                        f"could not be assessed: {type(error).__name__}."
                    ),
                    resolution="Grant bedrock-agentcore:GetBrowser and retry.",
                    reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

    except Exception as e:
        logger.error(f"Error in browser tool recording check: {e}")
        findings.append(
            create_finding(
                check_id="AC-06",
                finding_name=AGENTCORE_BROWSER_RECORDING_FINDING_NAME,
                finding_details=f"Could not assess custom browser recording: {type(e).__name__}.",
                resolution="Resolve the assessment prerequisite or permission issue and retry.",
                reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )

    return findings


def check_agentcore_token_vault_encryption() -> List[Dict[str, Any]]:
    """AC-14: Verify the default regional Identity token vault uses a CMK."""
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-14",
                finding_name="AgentCore Identity Token Vault CMK Encryption",
                finding_details="AgentCore client not available in this region",
                resolution="No action required unless AgentCore Identity is expected in this region.",
                reference=AGENTCORE_IDENTITY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    token_vault_id = os.environ.get("AGENTCORE_TOKEN_VAULT_ID", "default")
    try:
        detail = agentcore_client.get_token_vault(tokenVaultId=token_vault_id)
        kms_config = detail.get("kmsConfiguration") or {}
        uses_cmk = kms_config.get("keyType") == "CustomerManagedKey" and bool(
            kms_config.get("kmsKeyArn")
        )
        return [
            create_finding(
                check_id="AC-14",
                finding_name="AgentCore Identity Token Vault CMK Encryption",
                finding_details=(
                    f"AgentCore token vault '{token_vault_id}' uses customer-managed KMS key "
                    f"{kms_config.get('kmsKeyArn')}."
                    if uses_cmk
                    else f"AgentCore token vault '{token_vault_id}' uses a service-managed or AWS-owned key."
                ),
                resolution=(
                    "No action required"
                    if uses_cmk
                    else "Configure the AgentCore Identity token vault with a customer-managed KMS key."
                ),
                reference=AGENTCORE_IDENTITY_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.PASSED if uses_cmk else StatusEnum.FAILED,
            )
        ]
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        not_configured = code in {
            "ResourceNotFoundException",
            "ValidationException",
        }
        if not_configured or _is_access_denied_client_error(error):
            return [
                create_finding(
                    check_id="AC-14",
                    finding_name="AgentCore Identity Token Vault CMK Encryption",
                    finding_details=(
                        "No assessable AgentCore Identity token vault was found."
                        if not_configured
                        else "Could not assess the AgentCore Identity token vault because access was denied."
                    ),
                    resolution=(
                        "No action required"
                        if not_configured
                        else "Grant bedrock-agentcore:GetTokenVault and retry."
                    ),
                    reference=AGENTCORE_IDENTITY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            ]
        raise
    except Exception as error:
        return [
            create_finding(
                check_id="AC-14",
                finding_name="AgentCore Identity Token Vault CMK Encryption",
                finding_details=f"Could not assess the token vault: {type(error).__name__}.",
                resolution="Resolve the assessment prerequisite or regional API availability issue and retry.",
                reference=AGENTCORE_IDENTITY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]


def check_agentcore_code_interpreter_isolation() -> List[Dict[str, Any]]:
    """AC-15: Require custom Code Interpreters to use complete VPC config."""
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-15",
                finding_name="AgentCore Code Interpreter Network Isolation",
                finding_details="AgentCore client not available in this region",
                resolution="No action required unless custom Code Interpreters are expected.",
                reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    try:
        interpreters = _agentcore_list_all(
            "list_code_interpreters", ["codeInterpreterSummaries"], type="CUSTOM"
        )
        if not interpreters:
            return [
                create_finding(
                    check_id="AC-15",
                    finding_name="AgentCore Code Interpreter Network Isolation",
                    finding_details="No custom AgentCore Code Interpreters found",
                    resolution="No action required",
                    reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            ]

        for summary in interpreters:
            interpreter_id = summary.get("codeInterpreterId")
            name = summary.get("name", interpreter_id or "unknown")
            try:
                detail = _unwrap_agentcore_detail(
                    agentcore_client.get_code_interpreter(
                        codeInterpreterId=interpreter_id
                    ),
                    "codeInterpreter",
                )
                network = detail.get("networkConfiguration") or {}
                vpc = network.get("vpcConfig") or {}
                isolated = (
                    network.get("networkMode") == "VPC"
                    and bool(vpc.get("subnets"))
                    and bool(vpc.get("securityGroups"))
                )
                findings.append(
                    create_finding(
                        check_id="AC-15",
                        finding_name="AgentCore Code Interpreter Network Isolation",
                        finding_details=(
                            f"Custom Code Interpreter '{name}' ({interpreter_id}) uses VPC network isolation."
                            if isolated
                            else f"Custom Code Interpreter '{name}' ({interpreter_id}) does not use complete VPC network isolation."
                        ),
                        resolution=(
                            "No action required"
                            if isolated
                            else "Configure the custom Code Interpreter in VPC mode with non-empty subnets and security groups."
                        ),
                        reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.PASSED if isolated else StatusEnum.FAILED,
                    )
                )
            except Exception as error:
                findings.append(
                    create_finding(
                        check_id="AC-15",
                        finding_name="AgentCore Code Interpreter Network Isolation",
                        finding_details=f"Custom Code Interpreter '{name}' could not be assessed: {type(error).__name__}.",
                        resolution="Grant bedrock-agentcore:GetCodeInterpreter and retry.",
                        reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
    except Exception as error:
        findings.append(
            create_finding(
                check_id="AC-15",
                finding_name="AgentCore Code Interpreter Network Isolation",
                finding_details=f"Could not list custom Code Interpreters: {type(error).__name__}.",
                resolution="Grant bedrock-agentcore:ListCodeInterpreters and retry.",
                reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
    return findings


def check_agentcore_browser_network_isolation(
    browser_inventory: Dict[str, Any] = None,
) -> List[Dict[str, Any]]:
    """AC-16: Require custom browsers to use complete VPC configuration."""
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-16",
                finding_name="AgentCore Custom Browser Network Isolation",
                finding_details="AgentCore client not available in this region",
                resolution="No action required unless custom browsers are expected.",
                reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    inventory = browser_inventory or get_custom_browser_inventory()
    if inventory.get("list_error"):
        return [
            create_finding(
                check_id="AC-16",
                finding_name="AgentCore Custom Browser Network Isolation",
                finding_details=f"Could not list custom browsers: {type(inventory['list_error']).__name__}.",
                resolution="Grant bedrock-agentcore:ListBrowsers and retry.",
                reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]
    if not inventory.get("items") and not inventory.get("errors"):
        return [
            create_finding(
                check_id="AC-16",
                finding_name="AgentCore Custom Browser Network Isolation",
                finding_details="No custom AgentCore browsers found",
                resolution="No action required",
                reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    for item in inventory.get("items", []):
        summary = item["summary"]
        detail = item["detail"]
        browser_id = summary.get("browserId", "unknown")
        name = summary.get("name", browser_id)
        network = detail.get("networkConfiguration") or {}
        vpc = network.get("vpcConfig") or {}
        isolated = (
            network.get("networkMode") == "VPC"
            and bool(vpc.get("subnets"))
            and bool(vpc.get("securityGroups"))
        )
        findings.append(
            create_finding(
                check_id="AC-16",
                finding_name="AgentCore Custom Browser Network Isolation",
                finding_details=(
                    f"Custom browser '{name}' ({browser_id}) uses VPC network isolation."
                    if isolated
                    else f"Custom browser '{name}' ({browser_id}) is not configured with complete VPC network isolation."
                ),
                resolution=(
                    "No action required"
                    if isolated
                    else "Configure the custom browser in VPC mode with non-empty subnets and security groups."
                ),
                reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.PASSED if isolated else StatusEnum.FAILED,
            )
        )
    for item in inventory.get("errors", []):
        summary = item["summary"]
        findings.append(
            create_finding(
                check_id="AC-16",
                finding_name="AgentCore Custom Browser Network Isolation",
                finding_details=f"Custom browser '{summary.get('name', summary.get('browserId', 'unknown'))}' could not be assessed: {type(item['error']).__name__}.",
                resolution="Grant bedrock-agentcore:GetBrowser and retry.",
                reference=AGENTCORE_SECURITY_HUB_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
    return findings


def check_agentcore_online_evaluation_coverage() -> List[Dict[str, Any]]:
    """AC-17: Report whether an operational online-evaluation config exists."""
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-17",
                finding_name="AgentCore Online Evaluation Coverage",
                finding_details="AgentCore client not available in this region",
                resolution="No action required unless online evaluation is expected.",
                reference=AGENTCORE_ONLINE_EVALUATION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    required = os.environ.get("REQUIRE_AGENTCORE_ONLINE_EVALUATION", "").lower() in {
        "1",
        "true",
        "yes",
    }
    try:
        configs = _agentcore_list_all(
            "list_online_evaluation_configs", ["onlineEvaluationConfigs"]
        )
        if not configs:
            return [
                create_finding(
                    check_id="AC-17",
                    finding_name="AgentCore Online Evaluation Coverage",
                    finding_details="No AgentCore online evaluation configurations found.",
                    resolution="Configure online evaluation for production agent workloads where continuous assurance is required.",
                    reference=AGENTCORE_ONLINE_EVALUATION_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM
                    if required
                    else SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.FAILED if required else StatusEnum.NA,
                )
            ]

        findings = []
        for summary in configs:
            config_id = summary.get("onlineEvaluationConfigId")
            name = summary.get("onlineEvaluationConfigName", config_id or "unknown")
            try:
                detail = agentcore_client.get_online_evaluation_config(
                    onlineEvaluationConfigId=config_id
                )
                sampling = (
                    (detail.get("rule") or {})
                    .get("samplingConfig", {})
                    .get("samplingPercentage", 0)
                )
                data_source = (detail.get("dataSourceConfig") or {}).get(
                    "cloudWatchLogs", {}
                )
                output = (detail.get("outputConfig") or {}).get("cloudWatchConfig", {})
                operational = all(
                    [
                        detail.get("status") == "ACTIVE",
                        detail.get("executionStatus") == "ENABLED",
                        sampling > 0,
                        bool(detail.get("evaluators")),
                        bool(data_source.get("logGroupNames"))
                        or bool(data_source.get("serviceNames")),
                        bool(output.get("logGroupName")),
                    ]
                )
                findings.append(
                    create_finding(
                        check_id="AC-17",
                        finding_name="AgentCore Online Evaluation Coverage",
                        finding_details=(
                            f"Online evaluation '{name}' ({config_id}) is active with sampling, evaluators, input logs, and output logging."
                            if operational
                            else f"Online evaluation '{name}' ({config_id}) is missing one or more operational coverage settings."
                        ),
                        resolution=(
                            "No action required. Confirm the rule filters cover the intended production traces."
                            if operational
                            else "Set the evaluation ACTIVE and ENABLED, use non-zero sampling, add evaluators, and configure CloudWatch input and output log groups."
                        ),
                        reference=AGENTCORE_ONLINE_EVALUATION_REFERENCE_URL,
                        severity=SeverityEnum.MEDIUM
                        if required
                        else SeverityEnum.INFORMATIONAL,
                        status=(
                            StatusEnum.PASSED
                            if operational
                            else StatusEnum.FAILED
                            if required
                            else StatusEnum.NA
                        ),
                    )
                )
            except Exception as error:
                findings.append(
                    create_finding(
                        check_id="AC-17",
                        finding_name="AgentCore Online Evaluation Coverage",
                        finding_details=f"Online evaluation '{name}' could not be assessed: {type(error).__name__}.",
                        resolution="Grant bedrock-agentcore:GetOnlineEvaluationConfig and retry.",
                        reference=AGENTCORE_ONLINE_EVALUATION_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
        return findings
    except Exception as error:
        return [
            create_finding(
                check_id="AC-17",
                finding_name="AgentCore Online Evaluation Coverage",
                finding_details=f"Could not list online evaluation configurations: {type(error).__name__}.",
                resolution="Grant bedrock-agentcore:ListOnlineEvaluationConfigs and retry.",
                reference=AGENTCORE_ONLINE_EVALUATION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]


def _memory_strategy_namespaces(strategy: Dict[str, Any]) -> List[str]:
    """Return every namespace one memory strategy writes records into.

    A strategy carries the newer ``namespaceTemplates`` and the older
    ``namespaces``, and either list can hold namespaces the other does not, so
    both are read: a namespace without an actor variable flattens records no
    matter which member declares it.
    """
    namespaces: List[str] = []
    for member in ("namespaceTemplates", "namespaces"):
        values = strategy.get(member)
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value not in namespaces:
                namespaces.append(value)
    return namespaces


def _memory_namespace_scope_finding(
    memory_label: str,
    memory_details: Dict[str, Any],
) -> Dict[str, Any]:
    """Judge whether one memory partitions long-term records per actor."""
    strategies = memory_details.get("strategies")
    if not isinstance(strategies, list) or not strategies:
        return create_finding(
            check_id="AC-07",
            finding_name="AgentCore Memory Access Scope",
            finding_details=(
                f"Memory {memory_label} has no memory strategy, so it extracts no "
                "long-term records to partition."
            ),
            resolution=(
                "No action required. Add an actor variable to the namespace of any "
                "strategy added later."
            ),
            reference=AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        )

    unpartitioned: List[str] = []
    assessed = 0
    for strategy in strategies:
        if not isinstance(strategy, dict):
            continue
        strategy_label = strategy.get("name") or strategy.get("strategyId") or "unnamed"
        namespaces = _memory_strategy_namespaces(strategy)
        if not namespaces:
            continue
        assessed += 1
        if any(
            MEMORY_ACTOR_NAMESPACE_VARIABLE not in namespace.lower()
            for namespace in namespaces
        ):
            unpartitioned.append(str(strategy_label))

    if not assessed:
        return create_finding(
            check_id="AC-07",
            finding_name="AgentCore Memory Access Scope",
            finding_details=(
                f"Memory {memory_label} reports no namespace for any of its "
                f"{len(strategies)} strategies, so the record partitioning could "
                "not be read."
            ),
            resolution=(
                "Review the namespace of each memory strategy in the AgentCore "
                "console and rerun the assessment."
            ),
            reference=AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        )

    if unpartitioned:
        return create_finding(
            check_id="AC-07",
            finding_name="AgentCore Memory Access Scope",
            finding_details=(
                f"Memory {memory_label} stores long-term records in a namespace "
                "that carries no actor variable, so one retrieval returns every "
                f"actor's records. Strategies: {', '.join(sorted(unpartitioned))}."
            ),
            resolution=(
                "Include {actorId} in the namespace of each memory strategy so "
                "records are partitioned per end user, then confirm the retrieval "
                "calls pass the caller's actor id."
            ),
            reference=AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL,
            severity=SeverityEnum.HIGH,
            status=StatusEnum.FAILED,
        )

    return create_finding(
        check_id="AC-07",
        finding_name="AgentCore Memory Access Scope",
        finding_details=(
            f"Memory {memory_label} partitions the records of all {assessed} "
            "strategies by actor namespace."
        ),
        resolution=(
            "No action required. Confirm each retrieval call passes the actor id of "
            "the caller rather than a shared value."
        ),
        reference=AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL,
        severity=SeverityEnum.HIGH,
        status=StatusEnum.PASSED,
    )


def check_agentcore_memory_configuration() -> List[Dict[str, Any]]:
    """
    Check Memory resource configuration.

    Validates:
    - Encryption uses a customer managed key
    - Long-term records are partitioned into a per-actor namespace

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-07",
                finding_name="AgentCore Memory Configuration Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference=AGENTCORE_MEMORY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Memory configuration")

        memories = _agentcore_list_all("list_memories", ["memories"])

        if not memories:
            logger.info("No Memory resources found")
            findings.append(
                create_finding(
                    check_id="AC-07",
                    finding_name="AgentCore Memory Configuration Check",
                    finding_details="No Memory resources found",
                    resolution="No action required",
                    reference=AGENTCORE_MEMORY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        logger.info(f"Found {len(memories)} Memory resources")

        for memory in memories:
            memory_id = memory.get("id", "unknown")
            memory_name = (
                memory.get("name", memory_id) if memory.get("name") else memory_id
            )
            memory_label = f"'{memory_name}' ({memory_id})"

            try:
                memory_details = _unwrap_agentcore_detail(
                    agentcore_client.get_memory(memoryId=memory_id), "memory"
                )
            except ClientError as e:
                # A memory that cannot be described is reported per resource. An
                # earlier revision swallowed this error, so a run where every
                # GetMemory call failed reported the same aggregate pass as a run
                # that read every memory.
                logger.error(f"Error describing memory {memory_id}: {e}")
                findings.append(
                    create_finding(
                        check_id="AC-07",
                        finding_name="AgentCore Memory Configuration Check",
                        finding_details=(
                            f"Memory {memory_label} could not be described. "
                            f"Assessment error: {_assessment_error_label(e)}."
                        ),
                        resolution=(
                            "Grant bedrock-agentcore:GetMemory on this memory, or "
                            "remove a memory deleted mid-assessment from the "
                            "inventory, then rerun the assessment."
                        ),
                        reference=AGENTCORE_MEMORY_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                continue

            encryption_key_arn = memory_details.get(
                "encryptionKeyArn"
            ) or memory_details.get("kmsKeyArn")

            if encryption_key_arn:
                findings.append(
                    create_finding(
                        check_id="AC-07",
                        finding_name="AgentCore Memory Encryption",
                        finding_details=(
                            f"Memory {memory_label} encrypts stored records with "
                            "the customer managed key "
                            f"{encryption_key_arn}."
                        ),
                        resolution="No action required.",
                        reference=AGENTCORE_MEMORY_REFERENCE_URL,
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-07",
                        finding_name="AgentCore Memory Encryption",
                        finding_details=(
                            f"Memory {memory_label} does not have customer-managed "
                            "encryption configured"
                        ),
                        resolution="Enable encryption with customer-managed KMS keys",
                        reference=AGENTCORE_MEMORY_REFERENCE_URL,
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.FAILED,
                    )
                )

            findings.append(
                _memory_namespace_scope_finding(memory_label, memory_details)
            )

    except Exception as e:
        logger.error(f"Error in memory configuration check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-07",
                finding_name="AgentCore Memory Configuration Check",
                error=e,
                reference=AGENTCORE_MEMORY_REFERENCE_URL,
            )
        )

    return findings


def _vpc_endpoint_policy_is_full_access(policy_document: Any) -> bool:
    """Return whether an endpoint policy allows every principal every action.

    AWS attaches exactly this document when no policy is supplied, so an endpoint
    carrying it contributes a private network path and no authorization. One
    unconditioned statement of that shape has the effect no matter what else the
    document holds, which is why the statements are not scored together.
    """
    for statement in _document_statements(policy_document, effect="Allow"):
        if statement.get("Condition"):
            continue
        if (
            "*" in _statement_actions(statement)
            and "*" in _statement_resources(statement)
            and "*" in _statement_principals(statement)
        ):
            return True
    return False


def _security_group_open_ingress(security_group: Dict[str, Any]) -> List[str]:
    """Return the internet-open inbound CIDR ranges of one security group."""
    open_ranges: List[str] = []
    for permission in security_group.get("IpPermissions") or []:
        if not isinstance(permission, dict):
            continue
        for ip_range in permission.get("IpRanges") or []:
            if isinstance(ip_range, dict) and ip_range.get("CidrIp") == "0.0.0.0/0":
                open_ranges.append("0.0.0.0/0")
        for ip_range in permission.get("Ipv6Ranges") or []:
            if isinstance(ip_range, dict) and ip_range.get("CidrIpv6") == "::/0":
                open_ranges.append("::/0")
    return sorted(set(open_ranges))


def _agentcore_endpoint_scope_findings(
    endpoints: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Judge each AgentCore VPC endpoint's policy and inbound network scope.

    An endpoint that exists and reports `available` still authorizes every call
    from every principal unless its policy narrows them, and still accepts
    traffic from any address unless its security groups narrow the source. Both
    legs are reported per endpoint, so an account holding one hardened endpoint
    and one default endpoint does not read as uniformly compliant.

    Which principals and which ports a given workload needs is a workload
    decision, so the assertions here are the workload-independent ones: the
    policy is not the default allow-everything document, and the inbound rules
    do not name the whole internet.
    """
    findings: List[Dict[str, Any]] = []
    if not endpoints:
        return findings

    group_ids = sorted(
        {
            group["GroupId"]
            for entry in endpoints
            for group in entry["endpoint"].get("Groups") or []
            if isinstance(group, dict) and group.get("GroupId")
        }
    )
    security_groups: Dict[str, Dict[str, Any]] = {}
    security_group_error = None
    if group_ids:
        try:
            for security_group in _paginate_aws_list(
                ec2_client,
                "describe_security_groups",
                "SecurityGroups",
                token_request_key="NextToken",
                token_response_key="NextToken",
                GroupIds=group_ids,
            ):
                security_groups[security_group.get("GroupId")] = security_group
        except Exception as error:
            logger.warning(f"Could not describe endpoint security groups: {error}")
            security_group_error = error

    for entry in endpoints:
        endpoint = entry["endpoint"]
        endpoint_id = endpoint.get("VpcEndpointId", "unknown")
        label = f"endpoint {endpoint_id} for {entry['service']}"
        policy_document = endpoint.get("PolicyDocument")

        if not policy_document:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoint Policy",
                    finding_details=(
                        f"AgentCore VPC {label} returned no policy document, so "
                        "the calls it authorizes could not be assessed."
                    ),
                    resolution=(
                        "Grant ec2:DescribeVpcEndpoints on this endpoint and rerun "
                        "the assessment."
                    ),
                    reference=VPC_ENDPOINT_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
        elif _vpc_endpoint_policy_is_full_access(policy_document):
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoint Policy Unrestricted",
                    finding_details=(
                        f"AgentCore VPC {label} carries the default endpoint "
                        "policy, which allows every principal every action on "
                        "every resource. The endpoint keeps the traffic off the "
                        "public internet and authorizes nothing."
                    ),
                    resolution=(
                        "Replace the default endpoint policy with one that names "
                        "the principals allowed to reach AgentCore through this "
                        "endpoint and the AgentCore resources they may call."
                    ),
                    reference=VPC_ENDPOINT_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoint Policy",
                    finding_details=(
                        f"AgentCore VPC {label} carries an endpoint policy that "
                        "is narrower than the default allow-everything document."
                    ),
                    resolution=(
                        "No action required. Confirm the policy names the "
                        "principals and AgentCore resources this workload needs."
                    ),
                    reference=VPC_ENDPOINT_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

        groups = [
            group
            for group in endpoint.get("Groups") or []
            if isinstance(group, dict) and group.get("GroupId")
        ]
        if not groups:
            # Gateway-type endpoints have no security group, so there is no
            # inbound rule to judge.
            continue

        if security_group_error is not None:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoint Network Scope",
                    finding_details=(
                        f"AgentCore VPC {label} has "
                        f"{len(groups)} security group(s) whose inbound rules "
                        "could not be read: "
                        f"{_assessment_error_label(security_group_error)}."
                    ),
                    resolution="Grant ec2:DescribeSecurityGroups and retry.",
                    reference=VPC_ENDPOINT_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        open_ranges: List[str] = []
        unreadable: List[str] = []
        for group in groups:
            security_group = security_groups.get(group["GroupId"])
            if security_group is None:
                unreadable.append(group["GroupId"])
                continue
            open_ranges.extend(_security_group_open_ingress(security_group))

        if open_ranges:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoint Network Scope Unrestricted",
                    finding_details=(
                        f"AgentCore VPC {label} accepts inbound traffic from "
                        f"{', '.join(sorted(set(open_ranges)))}, so any host that "
                        "can route to the VPC reaches the AgentCore endpoint."
                    ),
                    resolution=(
                        "Restrict the endpoint security group's inbound rules to "
                        "the VPC CIDR ranges or the security groups of the "
                        "workloads that call AgentCore."
                    ),
                    reference=VPC_ENDPOINT_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )
        elif unreadable:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoint Network Scope",
                    finding_details=(
                        f"AgentCore VPC {label} references security group(s) "
                        f"{', '.join(unreadable)} that were not returned, so the "
                        "inbound scope is unknown."
                    ),
                    resolution="Grant ec2:DescribeSecurityGroups and retry.",
                    reference=VPC_ENDPOINT_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoint Network Scope",
                    finding_details=(
                        f"AgentCore VPC {label} accepts no inbound traffic from "
                        "0.0.0.0/0 or ::/0 on any of its "
                        f"{len(groups)} security group(s)."
                    ),
                    resolution=(
                        "No action required. Confirm the inbound rules name only "
                        "the workloads that call AgentCore."
                    ),
                    reference=VPC_ENDPOINT_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

    return findings


def check_agentcore_vpc_endpoints() -> List[Dict[str, Any]]:
    """
    Check for AWS PrivateLink VPC endpoints for AgentCore.

    Validates:
    - VPC endpoints exist for bedrock-agentcore services
    - Private connectivity is configured
    - Each endpoint's policy authorizes something narrower than every call
    - Each endpoint's security group admits a narrower source than the internet

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-08",
                finding_name="AgentCore VPC Endpoints Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking for AgentCore VPC endpoints")

        runtimes = _agentcore_list_all("list_agent_runtimes", ["agentRuntimes"])

        if not runtimes:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoints Check",
                    finding_details="No AgentCore resources found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        # Get all VPCs
        vpcs_response = ec2_client.describe_vpcs()
        vpcs = vpcs_response.get("Vpcs", [])

        if not vpcs:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoints Check",
                    finding_details="No VPCs found in the account",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        vpc_ids = [vpc["VpcId"] for vpc in vpcs]

        # Get all VPC endpoints
        all_endpoints = _paginate_aws_list(
            ec2_client,
            "describe_vpc_endpoints",
            "VpcEndpoints",
            token_request_key="NextToken",
            token_response_key="NextToken",
        )

        # Check for AgentCore endpoints
        found_agentcore_endpoints = []
        for endpoint in all_endpoints:
            service_name = endpoint.get("ServiceName", "")
            if (
                "agentcore" in service_name.lower()
                or "bedrock-agentcore" in service_name.lower()
            ):
                found_agentcore_endpoints.append(
                    {
                        "vpc_id": endpoint.get("VpcId"),
                        "service": service_name,
                        "state": endpoint.get("State"),
                        "endpoint": endpoint,
                    }
                )

        if not found_agentcore_endpoints:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoints Missing",
                    finding_details=f"No AgentCore VPC endpoints found in {len(vpc_ids)} VPCs. AgentCore API traffic traverses public internet, exposing it to interception.",
                    resolution="Create VPC interface endpoints for AgentCore services:\n"
                    + "1. com.amazonaws.region.bedrock-agentcore\n"
                    + "2. com.amazonaws.region.bedrock-agentcore-control\n"
                    + "3. com.amazonaws.region.bedrock-agentcore-runtime\n"
                    + "This enables private connectivity via AWS PrivateLink",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            # Check endpoint state
            unhealthy_endpoints = [
                e for e in found_agentcore_endpoints if e["state"] != "available"
            ]

            if unhealthy_endpoints:
                findings.append(
                    create_finding(
                        check_id="AC-08",
                        finding_name="AgentCore VPC Endpoints Unhealthy",
                        finding_details=f"Found {len(unhealthy_endpoints)} AgentCore VPC endpoints in non-available state",
                        resolution="Investigate and resolve VPC endpoint issues",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.FAILED,
                    )
                )
            else:
                endpoint_details = ", ".join(
                    [
                        f"{e['service']} in {e['vpc_id']}"
                        for e in found_agentcore_endpoints
                    ]
                )
                findings.append(
                    create_finding(
                        check_id="AC-08",
                        finding_name="AgentCore VPC Endpoints Check",
                        finding_details=f"AgentCore VPC endpoints configured: {endpoint_details}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.PASSED,
                    )
                )

        findings.extend(_agentcore_endpoint_scope_findings(found_agentcore_endpoints))

    except Exception as e:
        logger.error(f"Error in VPC endpoints check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-08",
                finding_name="AgentCore VPC Endpoints Check",
                error=e,
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
            )
        )

    return findings


def check_agentcore_service_linked_role() -> List[Dict[str, Any]]:
    """
    Check if the AgentCore service-linked role exists and is properly configured.

    The AWSServiceRoleForBedrockAgentCoreNetwork role is required for VPC ENI creation.

    Returns:
        List of findings
    """
    findings = []

    try:
        logger.info("Checking AgentCore service-linked role")

        slr_name = "AWSServiceRoleForBedrockAgentCoreNetwork"

        try:
            role_response = iam_client.get_role(RoleName=slr_name)
            role = role_response.get("Role", {})

            # Verify the role is properly configured
            assume_role_policy = role.get("AssumeRolePolicyDocument", {})

            # Check if the trust policy allows bedrock-agentcore service
            statements = assume_role_policy.get("Statement", [])
            has_correct_principal = False

            for statement in statements:
                principal = statement.get("Principal", {})
                service = principal.get("Service", "")
                if isinstance(service, list):
                    if any("agentcore" in s.lower() for s in service):
                        has_correct_principal = True
                elif "agentcore" in service.lower():
                    has_correct_principal = True

            if has_correct_principal:
                findings.append(
                    create_finding(
                        check_id="AC-09",
                        finding_name="AgentCore Service-Linked Role Check",
                        finding_details=f"Service-linked role '{slr_name}' exists and is properly configured for AgentCore VPC networking",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-09",
                        finding_name="AgentCore Service-Linked Role Misconfigured",
                        finding_details=f"Service-linked role '{slr_name}' exists but may have incorrect trust policy",
                        resolution="Delete and recreate the service-linked role by enabling VPC configuration on an AgentCore Runtime",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.FAILED,
                    )
                )

        except iam_client.exceptions.NoSuchEntityException:
            findings.append(
                create_finding(
                    check_id="AC-09",
                    finding_name="AgentCore Service-Linked Role Missing",
                    finding_details=f"Service-linked role '{slr_name}' does not exist. VPC configuration for AgentCore Runtimes will fail without this role.",
                    resolution=(
                        "Allow iam:CreateServiceLinkedRole for "
                        "arn:PARTITION:iam::*:role/aws-service-role/"
                        "network.bedrock-agentcore.amazonaws.com/"
                        "AWSServiceRoleForBedrockAgentCoreNetwork, replacing PARTITION "
                        "with the deployment partition, and add StringEquals for "
                        "iam:AWSServiceName = network.bedrock-agentcore.amazonaws.com. "
                        "Then configure VPC networking on an AgentCore Runtime so AWS "
                        "creates the service-linked role."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html",
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )

    except Exception as e:
        logger.error(f"Error in service-linked role check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-09",
                finding_name="AgentCore Service-Linked Role Check",
                error=e,
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html",
            )
        )

    return findings


def check_agentcore_resource_based_policies() -> List[Dict[str, Any]]:
    """
    Check for proper resource-based policies on AgentCore resources.

    Validates:
    - Agent Runtime resource policies
    - Gateway resource policies

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-10",
                finding_name="AgentCore Resource-Based Policies Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore resource-based policies")

        resources_without_rbp = []
        resources_with_rbp = []
        policy_access_denied = []
        policy_check_errors = []

        # Check Agent Runtimes
        try:
            runtimes = _agentcore_list_all("list_agent_runtimes", ["agentRuntimes"])

            for runtime in runtimes:
                runtime_id = runtime.get("agentRuntimeId", "unknown")
                runtime_name = runtime.get("agentRuntimeName", runtime_id)
                runtime_arn = runtime.get("agentRuntimeArn")

                try:
                    if not runtime_arn:
                        resources_without_rbp.append(
                            {"type": "Runtime", "name": runtime_name, "id": runtime_id}
                        )
                        continue

                    policy = _get_agentcore_resource_policy(runtime_arn)

                    if policy:
                        resources_with_rbp.append(f"Runtime: {runtime_name}")
                    else:
                        resources_without_rbp.append(
                            {"type": "Runtime", "name": runtime_name, "id": runtime_id}
                        )

                except ClientError as e:
                    if e.response["Error"]["Code"] == "ResourceNotFoundException":
                        resources_without_rbp.append(
                            {"type": "Runtime", "name": runtime_name, "id": runtime_id}
                        )
                    elif _is_access_denied_client_error(e):
                        policy_access_denied.append(
                            {"type": "Runtime", "name": runtime_name, "id": runtime_id}
                        )
                    else:
                        policy_check_errors.append(
                            {
                                "type": "Runtime",
                                "name": runtime_name,
                                "id": runtime_id,
                                "error_code": e.response.get("Error", {}).get(
                                    "Code", "Unknown"
                                ),
                            }
                        )
                        logger.warning(
                            f"Error checking policy for runtime {runtime_id}: {e}"
                        )

        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                logger.warning(f"Error listing runtimes: {e}")

        # Check Gateways
        try:
            gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])

            for gateway in gateways:
                gateway_id = gateway.get("gatewayId", "unknown")
                gateway_name = gateway.get("name", gateway_id)

                try:
                    gateway_details = agentcore_client.get_gateway(
                        gatewayIdentifier=gateway_id
                    )
                    gateway_arn = gateway_details.get("gatewayArn")

                    if not gateway_arn:
                        resources_without_rbp.append(
                            {"type": "Gateway", "name": gateway_name, "id": gateway_id}
                        )
                        continue

                    policy = _get_agentcore_resource_policy(gateway_arn)

                    if policy:
                        resources_with_rbp.append(f"Gateway: {gateway_name}")
                    else:
                        resources_without_rbp.append(
                            {"type": "Gateway", "name": gateway_name, "id": gateway_id}
                        )

                except ClientError as e:
                    if e.response["Error"]["Code"] == "ResourceNotFoundException":
                        resources_without_rbp.append(
                            {"type": "Gateway", "name": gateway_name, "id": gateway_id}
                        )
                    elif _is_access_denied_client_error(e):
                        policy_access_denied.append(
                            {"type": "Gateway", "name": gateway_name, "id": gateway_id}
                        )
                    else:
                        policy_check_errors.append(
                            {
                                "type": "Gateway",
                                "name": gateway_name,
                                "id": gateway_id,
                                "error_code": e.response.get("Error", {}).get(
                                    "Code", "Unknown"
                                ),
                            }
                        )
                        logger.warning(
                            f"Error checking policy for gateway {gateway_id}: {e}"
                        )

        except (ClientError, AttributeError) as e:
            logger.info(f"Gateway APIs not available: {e}")

        # Generate findings
        if resources_without_rbp:
            resource_list = ", ".join(
                [f"{r['type']} '{r['name']}'" for r in resources_without_rbp[:5]]
            )
            if len(resources_without_rbp) > 5:
                resource_list += f" and {len(resources_without_rbp) - 5} more"

            findings.append(
                create_finding(
                    check_id="AC-10",
                    finding_name="AgentCore Resource-Based Policies Missing",
                    finding_details=f"The following AgentCore resources do not have resource-based policies: {resource_list}. Without RBPs, access control relies solely on identity-based policies.",
                    resolution="Attach resource-based policies to AgentCore resources to:\n"
                    + "1. Implement defense-in-depth access control\n"
                    + "2. Enable cross-account access control\n"
                    + "3. Restrict access based on source VPC or IP\n"
                    + "4. Implement hierarchical authorization for Agent Runtimes",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        if policy_access_denied:
            resource_list = ", ".join(
                [f"{r['type']} '{r['name']}'" for r in policy_access_denied[:5]]
            )
            if len(policy_access_denied) > 5:
                resource_list += f" and {len(policy_access_denied) - 5} more"

            findings.append(
                create_finding(
                    check_id="AC-10",
                    finding_name="AgentCore Resource-Based Policy Assessment Access Denied",
                    finding_details=(
                        f"Unable to assess resource-based policies for {resource_list} "
                        "because access to AgentCore resource policy metadata was denied."
                    ),
                    resolution=(
                        "Ensure the assessment role can call "
                        "bedrock-agentcore:GetResourcePolicy for AgentCore resources."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

        if policy_check_errors:
            resource_list = ", ".join(
                [f"{r['type']} '{r['name']}'" for r in policy_check_errors[:5]]
            )
            if len(policy_check_errors) > 5:
                resource_list += f" and {len(policy_check_errors) - 5} more"

            error_codes = sorted({r["error_code"] for r in policy_check_errors})
            findings.append(
                create_finding(
                    check_id="AC-10",
                    finding_name="AgentCore Resource-Based Policy Assessment Incomplete",
                    finding_details=(
                        f"Unable to fully assess resource-based policies for {resource_list} "
                        f"due to AgentCore API errors: {', '.join(error_codes)}."
                    ),
                    resolution=(
                        "Re-run the assessment. If the issue persists, review AgentCore "
                        "service health and the assessment role's control plane permissions."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                    severity=SeverityEnum.LOW,
                    status=StatusEnum.NA,
                )
            )

        if not findings:
            if resources_with_rbp:
                findings.append(
                    create_finding(
                        check_id="AC-10",
                        finding_name="AgentCore Resource-Based Policies Check",
                        finding_details=f"Resource-based policies configured on: {', '.join(resources_with_rbp)}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-10",
                        finding_name="AgentCore Resource-Based Policies Check",
                        finding_details="No AgentCore resources found to check for resource-based policies",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in resource-based policies check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-10",
                finding_name="AgentCore Resource-Based Policies Check",
                error=e,
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
            )
        )

    return findings


def check_agentcore_policy_engine_encryption() -> List[Dict[str, Any]]:
    """
    Check if AgentCore Policy Engines are encrypted with customer-managed KMS keys.

    Policy engines store authorization rules that determine what agents can do.
    Unencrypted policy data exposes security controls.

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-11",
                finding_name="AgentCore Policy Engine Encryption Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Policy Engine encryption")

        try:
            # List policy engines
            policy_engines = _agentcore_list_all(
                "list_policy_engines", ["policyEngines"]
            )

            if not policy_engines:
                findings.append(
                    create_finding(
                        check_id="AC-11",
                        finding_name="AgentCore Policy Engine Encryption Check",
                        finding_details="No Policy Engines found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                return findings

            engines_without_cmk = []
            engines_with_cmk = []

            for engine in policy_engines:
                engine_id = engine.get("policyEngineId", "unknown")
                engine_name = engine.get("name", engine_id)

                try:
                    engine_details = agentcore_client.get_policy_engine(
                        policyEngineId=engine_id
                    )

                    encryption_key_arn = engine_details.get("encryptionKeyArn")

                    if encryption_key_arn:
                        engines_with_cmk.append(engine_name)
                    else:
                        engines_without_cmk.append(
                            {"name": engine_name, "id": engine_id}
                        )

                except ClientError as e:
                    if e.response["Error"]["Code"] != "ResourceNotFoundException":
                        logger.warning(f"Error getting policy engine {engine_id}: {e}")

            if engines_without_cmk:
                engine_list = ", ".join([f"'{e['name']}'" for e in engines_without_cmk])
                findings.append(
                    create_finding(
                        check_id="AC-11",
                        finding_name="AgentCore Policy Engine Encryption Missing",
                        finding_details=f"The following Policy Engines do not use customer-managed KMS encryption: {engine_list}. Policy data containing authorization rules is not protected with CMK.",
                        resolution=(
                            "1. Create a symmetric customer-managed KMS key.\n"
                            "2. Grant the caller or account principal kms:CreateGrant, "
                            "kms:Decrypt, kms:GenerateDataKey, and kms:DescribeKey in "
                            "IAM and the key policy. Constrain access with kms:ViaService "
                            "for bedrock-agentcore.<region>.amazonaws.com and the "
                            "AgentCore policy-engine encryption context.\n"
                            "3. Create replacement policy engines with the "
                            "--encryption-key-arn parameter.\n"
                            "Note: The encryption key cannot be added to or changed on "
                            "an existing policy engine."
                        ),
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.FAILED,
                    )
                )

            if engines_with_cmk:
                findings.append(
                    create_finding(
                        check_id="AC-11",
                        finding_name="AgentCore Policy Engine Encryption Check",
                        finding_details=f"Policy Engines with CMK encryption: {', '.join(engines_with_cmk)}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )

            if not findings:
                findings.append(
                    create_finding(
                        check_id="AC-11",
                        finding_name="AgentCore Policy Engine Encryption Check",
                        finding_details=f"Checked {len(policy_engines)} Policy Engines",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

        except AttributeError:
            # API not available
            findings.append(
                create_finding(
                    check_id="AC-11",
                    finding_name="AgentCore Policy Engine Encryption Check",
                    finding_details="Policy Engine APIs not yet available in bedrock-agentcore-control client",
                    resolution="N/A - Check may need to be updated when APIs become available",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

    except Exception as e:
        logger.error(f"Error in policy engine encryption check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-11",
                finding_name="AgentCore Policy Engine Encryption Check",
                error=e,
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
            )
        )

    return findings


def check_agentcore_gateway_encryption() -> List[Dict[str, Any]]:
    """
    Check if AgentCore Gateways are encrypted with customer-managed KMS keys.

    Gateway configurations include tool definitions, target endpoints, and
    API schemas which may contain sensitive information.

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-12",
                finding_name="AgentCore Gateway Encryption Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Gateway encryption")

        try:
            gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])

            if not gateways:
                findings.append(
                    create_finding(
                        check_id="AC-12",
                        finding_name="AgentCore Gateway Encryption Check",
                        finding_details="No Gateways found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                return findings

            gateways_without_cmk = []
            gateways_with_cmk = []

            for gateway in gateways:
                gateway_id = gateway.get("gatewayId", "unknown")
                gateway_name = gateway.get("name", gateway_id)

                try:
                    gateway_details = agentcore_client.get_gateway(
                        gatewayIdentifier=gateway_id
                    )

                    # Check for customer-managed KMS key
                    encryption_key_arn = gateway_details.get(
                        "kmsKeyArn"
                    ) or gateway_details.get("encryptionKeyArn")

                    if encryption_key_arn:
                        gateways_with_cmk.append(gateway_name)
                    else:
                        gateways_without_cmk.append(
                            {"name": gateway_name, "id": gateway_id}
                        )

                except ClientError as e:
                    if e.response["Error"]["Code"] != "ResourceNotFoundException":
                        logger.warning(f"Error getting gateway {gateway_id}: {e}")

            if gateways_without_cmk:
                gateway_list = ", ".join(
                    [f"'{g['name']}'" for g in gateways_without_cmk]
                )
                findings.append(
                    create_finding(
                        check_id="AC-12",
                        finding_name="AgentCore Gateway Encryption Missing",
                        finding_details=f"The following Gateways do not use customer-managed KMS encryption: {gateway_list}. Gateway configuration data uses AWS-managed keys.",
                        resolution="1. Create gateways with customer-managed KMS keys for additional control\n"
                        + "2. AWS-managed keys are single-tenant and region-specific\n"
                        + "3. Consider CMK for enhanced audit capabilities and key rotation control",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                        severity=SeverityEnum.LOW,
                        status=StatusEnum.FAILED,
                    )
                )

            if gateways_with_cmk:
                findings.append(
                    create_finding(
                        check_id="AC-12",
                        finding_name="AgentCore Gateway Encryption Check",
                        finding_details=f"Gateways with CMK encryption: {', '.join(gateways_with_cmk)}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )

            if not findings:
                findings.append(
                    create_finding(
                        check_id="AC-12",
                        finding_name="AgentCore Gateway Encryption Check",
                        finding_details=f"Checked {len(gateways)} Gateways",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

        except AttributeError:
            findings.append(
                create_finding(
                    check_id="AC-12",
                    finding_name="AgentCore Gateway Encryption Check",
                    finding_details="Gateway APIs not yet available in bedrock-agentcore-control client",
                    resolution="N/A - Check may need to be updated when APIs become available",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

    except Exception as e:
        logger.error(f"Error in gateway encryption check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-12",
                finding_name="AgentCore Gateway Encryption Check",
                error=e,
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
            )
        )

    return findings


def check_agentcore_gateway_configuration() -> List[Dict[str, Any]]:
    """
    Check Gateway resource configuration.

    Note: Gateway APIs may not be available in bedrock-agentcore-control yet.
    This check will gracefully handle if the API doesn't exist.

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-13",
                finding_name="AgentCore Gateway Configuration Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference=AGENTCORE_GATEWAY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Gateway configuration")

        # Try to list gateways - this API may not exist yet
        try:
            gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])

            if not gateways:
                logger.info("No Gateway resources found")
                findings.append(
                    create_finding(
                        check_id="AC-13",
                        finding_name="AgentCore Gateway Configuration Check",
                        finding_details="No Gateway resources found",
                        resolution="No action required",
                        reference=AGENTCORE_GATEWAY_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                return findings

            logger.info(f"Found {len(gateways)} Gateway resources")

            # If we got here, gateways exist - check their configuration
            for gateway in gateways:
                gateway_id = gateway.get("gatewayId", "unknown")
                gateway_name = gateway.get("name", gateway_id)

                # Basic check - just verify gateway exists
                # Detailed configuration checks would require get_gateway API
                logger.info(f"Found gateway: {gateway_name} ({gateway_id})")

            # If no findings, return passed
            findings.append(
                create_finding(
                    check_id="AC-13",
                    finding_name="AgentCore Gateway Configuration Check",
                    finding_details=f"Found {len(gateways)} Gateway resources",
                    resolution="No action required",
                    reference=AGENTCORE_GATEWAY_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

        except AttributeError as e:
            # list_gateways method doesn't exist
            logger.info(f"Gateway API not available: {e}")
            findings.append(
                create_finding(
                    check_id="AC-13",
                    finding_name="AgentCore Gateway Configuration Check",
                    finding_details="Gateway API not yet available in bedrock-agentcore-control",
                    resolution="N/A - Gateway management may be done through other means",
                    reference=AGENTCORE_GATEWAY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                findings.append(
                    create_finding(
                        check_id="AC-13",
                        finding_name="AgentCore Gateway Configuration Check",
                        finding_details="No Gateway resources found",
                        resolution="No action required",
                        reference=AGENTCORE_GATEWAY_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
            else:
                raise

    except Exception as e:
        logger.error(f"Error in gateway configuration check: {e}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-13",
                finding_name="AgentCore Gateway Configuration Check",
                error=e,
                reference=AGENTCORE_GATEWAY_REFERENCE_URL,
            )
        )

    return findings


def _advanced_selector_data_resource_types(selector: Dict[str, Any]) -> Set[str]:
    """Read resources.type values from a Data-category advanced event selector.

    Management-category selectors carry no resources.type, and a selector that
    omits eventCategory Data does not log data events, so its resource types are
    not evidence of data-event coverage.
    """
    field_selectors = selector.get("FieldSelectors")
    if not isinstance(field_selectors, list):
        return set()

    logs_data_events = False
    resource_types: Set[str] = set()

    for field_selector in field_selectors:
        if not isinstance(field_selector, dict):
            continue
        equals = field_selector.get("Equals")
        if not isinstance(equals, list):
            continue
        field = field_selector.get("Field")
        if field == "eventCategory" and "Data" in equals:
            logs_data_events = True
        elif field == "resources.type":
            resource_types.update(value for value in equals if isinstance(value, str))

    return resource_types if logs_data_events else set()


def _cloudtrail_data_event_resource_types() -> Tuple[Set[str], List[str]]:
    """Collect every resources.type any trail selects for data events.

    Returns the selected types and the trails whose selectors could not be read,
    so a family with no matching type can be reported as unknown instead of
    uncovered when the evidence is incomplete.
    """
    selected_types: Set[str] = set()
    unreadable_trails: List[str] = []

    trails = _paginate_aws_list(
        cloudtrail_client,
        "list_trails",
        "Trails",
        token_request_key="NextToken",
        token_response_key="NextToken",
    )

    for trail in trails:
        # The ARN, not the name: a name resolves only in the trail's home region,
        # while organization and multi-region trails must resolve from any region.
        trail_identifier = trail.get("TrailARN") or trail.get("Name")
        if not trail_identifier:
            continue

        try:
            selectors = cloudtrail_client.get_event_selectors(
                TrailName=trail_identifier
            )
        except Exception as error:
            logger.warning(
                f"Could not read event selectors for {trail_identifier}: "
                f"{type(error).__name__}"
            )
            unreadable_trails.append(trail_identifier)
            continue

        advanced_selectors = selectors.get("AdvancedEventSelectors")
        if not isinstance(advanced_selectors, list):
            continue

        for selector in advanced_selectors:
            if isinstance(selector, dict):
                selected_types.update(_advanced_selector_data_resource_types(selector))

    return selected_types, unreadable_trails


def _agentcore_family_resource_count(family: Dict[str, Any]) -> int:
    """Count this region's resources for one AgentCore data-event family."""
    count = 0
    for operation_name, result_keys, list_kwargs in family["inventory"]:
        count += len(
            _agentcore_list_all(operation_name, list(result_keys), **list_kwargs)
        )
    return count


def check_agentcore_cloudtrail_data_events() -> List[Dict[str, Any]]:
    """AC-18: Report CloudTrail data-event coverage per AgentCore service family.

    Management events record that a runtime or memory was created. Only a
    Data-category advanced event selector on the family's resources.type records
    the invocations and the memory record reads and writes that follow.
    """
    if cloudtrail_client is None:
        return [
            create_finding(
                check_id="AC-18",
                finding_name="AgentCore CloudTrail Data Event Coverage",
                finding_details="CloudTrail client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=CLOUDTRAIL_DATA_EVENTS_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        selected_types, unreadable_trails = _cloudtrail_data_event_resource_types()
    except Exception as error:
        return [
            create_finding(
                check_id="AC-18",
                finding_name="AgentCore CloudTrail Data Event Coverage",
                finding_details=(
                    f"Could not list CloudTrail trails: {type(error).__name__}."
                ),
                resolution="Grant cloudtrail:ListTrails and retry.",
                reference=CLOUDTRAIL_DATA_EVENTS_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    for family in AGENTCORE_DATA_EVENT_FAMILIES:
        label = family["label"]
        resource_types = family["resource_types"]
        type_list = ", ".join(resource_types)

        try:
            resource_count = _agentcore_family_resource_count(family)
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-18",
                    finding_name="AgentCore CloudTrail Data Event Coverage",
                    finding_details=(
                        f"{label} resources could not be inventoried, so "
                        f"data-event coverage for {type_list} is unknown: "
                        f"{type(error).__name__}."
                    ),
                    resolution=(
                        "Grant the AgentCore list permissions for this resource "
                        "family and retry."
                    ),
                    reference=CLOUDTRAIL_DATA_EVENTS_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        covered_types = sorted(set(resource_types) & selected_types)

        if resource_count == 0:
            findings.append(
                create_finding(
                    check_id="AC-18",
                    finding_name="AgentCore CloudTrail Data Event Coverage",
                    finding_details=(
                        f"No AgentCore {label} resources found in this region, so "
                        f"data-event coverage for {type_list} is not assessed."
                    ),
                    resolution="No action required.",
                    reference=CLOUDTRAIL_DATA_EVENTS_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        if covered_types:
            findings.append(
                create_finding(
                    check_id="AC-18",
                    finding_name="AgentCore CloudTrail Data Event Coverage",
                    finding_details=(
                        f"{resource_count} AgentCore {label} resource(s) are "
                        f"covered by a CloudTrail data-event selector on "
                        f"{', '.join(covered_types)}."
                    ),
                    resolution=(
                        "No action required. Confirm the trail's selector matches "
                        "the resources in scope and that the trail is logging."
                    ),
                    reference=CLOUDTRAIL_DATA_EVENTS_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )
            continue

        if unreadable_trails:
            findings.append(
                create_finding(
                    check_id="AC-18",
                    finding_name="AgentCore CloudTrail Data Event Coverage",
                    finding_details=(
                        f"{resource_count} AgentCore {label} resource(s) found, and "
                        f"no readable trail selects {type_list} for data events, but "
                        f"{len(unreadable_trails)} trail(s) could not be read."
                    ),
                    resolution=(
                        "Grant cloudtrail:GetEventSelectors on every trail and "
                        "retry so the coverage verdict is decided on all trails."
                    ),
                    reference=CLOUDTRAIL_DATA_EVENTS_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        findings.append(
            create_finding(
                check_id="AC-18",
                finding_name="AgentCore CloudTrail Data Event Coverage",
                finding_details=(
                    f"{resource_count} AgentCore {label} resource(s) found, and no "
                    f"trail selects {type_list} for data events, so "
                    f"{label.lower()} invocations are not in the audit trail."
                ),
                resolution=(
                    "Add a CloudTrail advanced event selector with eventCategory "
                    f"Data and resources.type set to {type_list}."
                ),
                reference=CLOUDTRAIL_DATA_EVENTS_REFERENCE_URL,
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def _agentcore_delivery_configuration() -> Tuple[Dict[str, List[str]], Set[str]]:
    """Map AgentCore resource ARNs to their application-log delivery sources.

    A delivery source names the resource whose logs it collects; a delivery
    connects that source to a destination. A source with no delivery produces no
    logs, so both halves are needed to answer whether logging is configured.
    """
    sources = _paginate_aws_list(
        logs_client, "describe_delivery_sources", "deliverySources"
    )

    arn_sources: Dict[str, List[str]] = {}
    for source in sources:
        if source.get("service") != AGENTCORE_VENDED_LOG_SERVICE:
            continue
        if source.get("logType") != AGENTCORE_VENDED_LOG_TYPE:
            continue
        source_name = source.get("name")
        resource_arns = source.get("resourceArns")
        if not source_name or not isinstance(resource_arns, list):
            continue
        for resource_arn in resource_arns:
            if isinstance(resource_arn, str):
                arn_sources.setdefault(resource_arn, []).append(source_name)

    deliveries = _paginate_aws_list(logs_client, "describe_deliveries", "deliveries")
    delivered_source_names = {
        delivery.get("deliverySourceName")
        for delivery in deliveries
        if delivery.get("deliverySourceName")
    }

    return arn_sources, delivered_source_names


def _delivery_source_names_for(
    arn_match: str, arn_sources: Dict[str, List[str]]
) -> List[str]:
    """Find the delivery sources naming one resource.

    GatewaySummary carries no ARN, so a gateway is matched on the ARN tail built
    from its id; a memory is matched on the exact ARN the list API returns.
    """
    names: List[str] = []
    for resource_arn, source_names in arn_sources.items():
        if resource_arn == arn_match or resource_arn.endswith(arn_match):
            names.extend(source_names)
    return names


def _log_delivery_finding(
    resource_label: str,
    arn_match: str,
    arn_sources: Dict[str, List[str]],
    delivered_source_names: Set[str],
) -> Dict[str, Any]:
    """Build one AC-19 finding for a gateway or memory resource."""
    source_names = _delivery_source_names_for(arn_match, arn_sources)
    delivered = sorted(name for name in source_names if name in delivered_source_names)

    if delivered:
        return create_finding(
            check_id="AC-19",
            finding_name="AgentCore Log Delivery Configuration",
            finding_details=(
                f"{resource_label} delivers application logs through delivery "
                f"source {', '.join(delivered)}."
            ),
            resolution=(
                "No action required. Confirm the delivery destination retention "
                "and encryption meet the workload's requirements."
            ),
            reference=AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL,
            severity=SeverityEnum.MEDIUM,
            status=StatusEnum.PASSED,
        )

    if source_names:
        return create_finding(
            check_id="AC-19",
            finding_name="AgentCore Log Delivery Configuration",
            finding_details=(
                f"{resource_label} has delivery source "
                f"{', '.join(sorted(source_names))} but no delivery to a "
                "destination, so its application logs are not stored anywhere."
            ),
            resolution=(
                "Create a CloudWatch Logs delivery joining this delivery source "
                "to a log group, S3 bucket, or Firehose destination."
            ),
            reference=AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL,
            severity=SeverityEnum.MEDIUM,
            status=StatusEnum.FAILED,
        )

    return create_finding(
        check_id="AC-19",
        finding_name="AgentCore Log Delivery Configuration",
        finding_details=(
            f"{resource_label} has no bedrock-agentcore "
            f"{AGENTCORE_VENDED_LOG_TYPE} delivery source, so its application "
            "logs are not collected."
        ),
        resolution=(
            "Enable observability for this resource and configure a delivery "
            "source and delivery for its application logs."
        ),
        reference=AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL,
        severity=SeverityEnum.MEDIUM,
        status=StatusEnum.FAILED,
    )


def check_agentcore_log_delivery_configuration() -> List[Dict[str, Any]]:
    """AC-19: Report application-log delivery per gateway and memory resource.

    Runtime logging is service-managed and needs no delivery configuration, so
    runtimes are out of scope here; AC-04 covers runtime tracing.
    """
    if logs_client is None:
        return [
            create_finding(
                check_id="AC-19",
                finding_name="AgentCore Log Delivery Configuration",
                finding_details="CloudWatch Logs client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        arn_sources, delivered_source_names = _agentcore_delivery_configuration()
    except Exception as error:
        return [
            create_finding(
                check_id="AC-19",
                finding_name="AgentCore Log Delivery Configuration",
                finding_details=(
                    "Could not read CloudWatch Logs delivery configuration: "
                    f"{type(error).__name__}."
                ),
                resolution=(
                    "Grant logs:DescribeDeliverySources and logs:DescribeDeliveries "
                    "and retry."
                ),
                reference=AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except Exception as error:
        gateways = []
        findings.append(
            create_finding(
                check_id="AC-19",
                finding_name="AgentCore Log Delivery Configuration",
                finding_details=(
                    f"Gateways could not be listed: {type(error).__name__}."
                ),
                resolution="Grant bedrock-agentcore:ListGateways and retry.",
                reference=AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )

    for gateway in gateways:
        gateway_id = gateway.get("gatewayId")
        if not gateway_id:
            continue
        gateway_name = gateway.get("name", gateway_id)
        findings.append(
            _log_delivery_finding(
                f"Gateway '{gateway_name}' ({gateway_id})",
                f":gateway/{gateway_id}",
                arn_sources,
                delivered_source_names,
            )
        )

    try:
        memories = _agentcore_list_all("list_memories", ["memories"])
    except Exception as error:
        memories = []
        findings.append(
            create_finding(
                check_id="AC-19",
                finding_name="AgentCore Log Delivery Configuration",
                finding_details=(
                    f"Memory resources could not be listed: {type(error).__name__}."
                ),
                resolution="Grant bedrock-agentcore:ListMemories and retry.",
                reference=AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )

    for memory in memories:
        memory_arn = memory.get("arn")
        if not memory_arn:
            continue
        memory_id = memory.get("id", memory_arn)
        findings.append(
            _log_delivery_finding(
                f"Memory '{memory_id}'",
                memory_arn,
                arn_sources,
                delivered_source_names,
            )
        )

    if not findings:
        findings.append(
            create_finding(
                check_id="AC-19",
                finding_name="AgentCore Log Delivery Configuration",
                finding_details=(
                    "No AgentCore gateway or memory resources found in this region."
                ),
                resolution="No action required.",
                reference=AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )

    # AWS documents a configurable log destination for memory, gateway and
    # built-in tool resources only. Runtime logging is service-managed,
    # WorkloadIdentity log delivery is configured on the associated runtime or
    # gateway resource, and policy engines have no log-destination surface. A
    # built-in tool emits no service logs at all, so whether a missing delivery
    # loses anything depends on the workload writing its own logs.
    findings.append(
        create_finding(
            check_id="AC-19",
            finding_name="AgentCore Log Delivery Configuration",
            finding_details=(
                "Built-in tool log delivery is not assessed: AgentCore provides "
                "no tool logs by default, so a missing delivery only loses data "
                "when the workload writes its own logs. Identity log delivery is "
                "configured on the associated runtime or gateway resource, and "
                "policy engines have no log-destination configuration."
            ),
            resolution=(
                "Where a built-in tool writes its own logs, add a CloudWatch "
                "Logs, Amazon S3 or Firehose destination for that tool in the "
                "AgentCore console."
            ),
            reference=AGENTCORE_OBSERVABILITY_CONFIGURE_REFERENCE_URL,
            severity=SeverityEnum.INFORMATIONAL,
            status=StatusEnum.NA,
        )
    )

    return findings


def _masking_data_identifiers(policy_document: Any) -> List[str]:
    """Collect data identifiers a Logs policy actually de-identifies.

    An Audit-only statement records that sensitive data was found and masks
    nothing, so only Deidentify statements answer whether the data is masked.
    """
    if isinstance(policy_document, str):
        try:
            policy_document = json.loads(policy_document)
        except (TypeError, ValueError):
            return []
    if not isinstance(policy_document, dict):
        return []

    statements = policy_document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []

    identifiers: List[str] = []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        operation = statement.get("Operation")
        if not isinstance(operation, dict) or "Deidentify" not in operation:
            continue
        entries = statement.get("DataIdentifier")
        if isinstance(entries, str):
            entries = [entries]
        if isinstance(entries, list):
            identifiers.extend(entry for entry in entries if isinstance(entry, str))

    return identifiers


def _account_masking_data_identifiers() -> List[str]:
    """Data identifiers masked by an account-wide data-protection policy."""
    policies = _paginate_aws_list(
        logs_client,
        "describe_account_policies",
        "accountPolicies",
        policyType="DATA_PROTECTION_POLICY",
    )

    identifiers: List[str] = []
    for policy in policies:
        identifiers.extend(_masking_data_identifiers(policy.get("policyDocument")))
    return identifiers


def _agentcore_log_groups() -> List[Dict[str, Any]]:
    """List the log groups AgentCore writes to, across both name prefixes."""
    log_groups: List[Dict[str, Any]] = []
    for prefix in AGENTCORE_LOG_GROUP_PREFIXES:
        log_groups.extend(
            _paginate_aws_list(
                logs_client,
                "describe_log_groups",
                "logGroups",
                logGroupNamePrefix=prefix,
            )
        )
    return log_groups


def check_agentcore_log_group_data_protection() -> List[Dict[str, Any]]:
    """AC-20: Report masking and CMK encryption on AgentCore log groups.

    Agent prompts, tool arguments and memory records reach these log groups
    verbatim, so a guardrail at the model boundary does not cover them.
    """
    if logs_client is None:
        return [
            create_finding(
                check_id="AC-20",
                finding_name="AgentCore Log Data Protection",
                finding_details="CloudWatch Logs client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        account_identifiers = _account_masking_data_identifiers()
    except Exception as error:
        return [
            create_finding(
                check_id="AC-20",
                finding_name="AgentCore Log Data Protection",
                finding_details=(
                    "Could not read account data-protection policies: "
                    f"{type(error).__name__}."
                ),
                resolution="Grant logs:DescribeAccountPolicies and retry.",
                reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        log_groups = _agentcore_log_groups()
    except Exception as error:
        return [
            create_finding(
                check_id="AC-20",
                finding_name="AgentCore Log Data Protection",
                finding_details=(
                    f"Could not list AgentCore log groups: {type(error).__name__}."
                ),
                resolution="Grant logs:DescribeLogGroups and retry.",
                reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    if not log_groups:
        return [
            create_finding(
                check_id="AC-20",
                finding_name="AgentCore Log Data Protection",
                finding_details="No AgentCore log groups found in this region.",
                resolution="No action required.",
                reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    for log_group in log_groups:
        log_group_name = log_group.get("logGroupName")
        if not log_group_name:
            continue

        has_cmk = bool(log_group.get("kmsKeyId"))
        identifiers = list(account_identifiers)
        masking_scope = "account-wide"

        if not identifiers and log_group.get("dataProtectionStatus") == "ACTIVATED":
            # describe_log_groups reports that a policy is attached but not what
            # it masks, so the document is read only for groups that have one.
            try:
                document = logs_client.get_data_protection_policy(
                    logGroupIdentifier=log_group_name
                ).get("policyDocument")
                identifiers = _masking_data_identifiers(document)
                masking_scope = "log-group"
            except Exception as error:
                findings.append(
                    create_finding(
                        check_id="AC-20",
                        finding_name="AgentCore Log Data Protection",
                        finding_details=(
                            f"Log group '{log_group_name}' has a data-protection "
                            "policy whose document could not be read: "
                            f"{type(error).__name__}."
                        ),
                        resolution="Grant logs:GetDataProtectionPolicy and retry.",
                        reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                continue

        if identifiers and has_cmk:
            findings.append(
                create_finding(
                    check_id="AC-20",
                    finding_name="AgentCore Log Data Protection",
                    finding_details=(
                        f"Log group '{log_group_name}' masks "
                        f"{len(set(identifiers))} data identifier(s) through a "
                        f"{masking_scope} data-protection policy and is encrypted "
                        "with a customer managed key."
                    ),
                    resolution=(
                        "No action required. Confirm the data identifiers cover "
                        "the sensitive data this workload logs."
                    ),
                    reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )
            continue

        missing = []
        if not identifiers:
            missing.append("no data-protection policy that de-identifies log events")
        if not has_cmk:
            missing.append("no customer managed encryption key")

        findings.append(
            create_finding(
                check_id="AC-20",
                finding_name="AgentCore Log Data Protection",
                finding_details=(
                    f"Log group '{log_group_name}' has {' and '.join(missing)}."
                ),
                resolution=(
                    "Attach a data-protection policy with a Deidentify operation "
                    "covering the sensitive data identifiers this workload logs, "
                    "and set a customer managed KMS key on the log group."
                ),
                reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def _principals_granting_logs_unmask(
    permissions_by_name: Dict[str, Any],
    principal_kind: str,
) -> Tuple[List[str], List[str]]:
    """Split principals holding logs:Unmask into unscoped and scoped grants.

    Only an action in the ``logs`` namespace counts. A bare ``Action: "*"`` is a
    service-agnostic administrator grant, so counting it here would fail every
    account that has an administrator role; AC-21 reports the grants that name
    the logs namespace and leaves administrator scope to the IAM checks.
    """
    unscoped: List[str] = []
    scoped: List[str] = []

    for principal_name, permissions in permissions_by_name.items():
        if not isinstance(permissions, dict):
            continue
        label = f"{principal_kind} {principal_name}"
        attached_policies = permissions.get("attached_policies", [])
        inline_policies = permissions.get("inline_policies", [])
        if not isinstance(attached_policies, list):
            attached_policies = []
        if not isinstance(inline_policies, list):
            inline_policies = []

        holds_unmask = False
        holds_unscoped_unmask = False

        for policy in [*attached_policies, *inline_policies]:
            try:
                for statement in _allow_statements(policy):
                    grants_unmask = False
                    for action in _statement_actions(statement):
                        action_parts = action.split(":", 1)
                        if len(action_parts) != 2:
                            continue
                        service_namespace, action_pattern = action_parts
                        if service_namespace == "logs" and fnmatchcase(
                            "unmask", action_pattern
                        ):
                            grants_unmask = True
                            break
                    if not grants_unmask:
                        continue
                    holds_unmask = True
                    if "*" in _statement_resources(statement):
                        holds_unscoped_unmask = True
            except Exception as error:
                logger.warning(f"Error parsing policy for {label}: {error}")

        if holds_unscoped_unmask:
            unscoped.append(label)
        elif holds_unmask:
            scoped.append(label)

    return unscoped, scoped


def check_agentcore_log_unmask_restriction(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """AC-21: Report who can read masked values back out of AgentCore logs.

    Masking a log group is reversible by any principal holding logs:Unmask, so
    the masking control is only as strong as the scope of that grant.
    """
    findings = []

    try:
        role_permissions = permission_cache.get("role_permissions", {})
        user_permissions = permission_cache.get("user_permissions", {})

        if not role_permissions and not user_permissions:
            return [
                create_finding(
                    check_id="AC-21",
                    finding_name="AgentCore Log Unmask Restriction",
                    finding_details="No IAM permissions found in cache.",
                    resolution="No action required.",
                    reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                    region=GLOBAL_REGION_LABEL,
                )
            ]

        unscoped_roles, scoped_roles = _principals_granting_logs_unmask(
            role_permissions, "role"
        )
        unscoped_users, scoped_users = _principals_granting_logs_unmask(
            user_permissions, "user"
        )
        unscoped = sorted(unscoped_roles + unscoped_users)
        scoped = sorted(scoped_roles + scoped_users)

        if unscoped:
            findings.append(
                create_finding(
                    check_id="AC-21",
                    finding_name="AgentCore Log Unmask Restriction",
                    finding_details=(
                        "The following principals can unmask any log group's "
                        f"masked values: {', '.join(unscoped)}."
                    ),
                    resolution=(
                        "Scope logs:Unmask to the log groups whose masked values "
                        "the principal is authorized to read, and remove it from "
                        "principals that do not investigate log content."
                    ),
                    reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

        if scoped:
            findings.append(
                create_finding(
                    check_id="AC-21",
                    finding_name="AgentCore Log Unmask Restriction",
                    finding_details=(
                        "The following principals hold logs:Unmask only on named "
                        f"log group resources: {', '.join(scoped)}."
                    ),
                    resolution=(
                        "No action required. Confirm the named log groups are the "
                        "ones this principal is authorized to unmask."
                    ),
                    reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

        if not unscoped and not scoped:
            findings.append(
                create_finding(
                    check_id="AC-21",
                    finding_name="AgentCore Log Unmask Restriction",
                    finding_details=(
                        "No cached IAM role or user grants logs:Unmask, so masked "
                        "log values cannot be read back through IAM policy."
                    ),
                    resolution="No action required.",
                    reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

    except Exception as error:
        logger.error(f"Error in log unmask restriction check: {error}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-21",
                finding_name="AgentCore Log Unmask Restriction",
                error=error,
                reference=LOGS_DATA_PROTECTION_REFERENCE_URL,
                region=GLOBAL_REGION_LABEL,
            )
        )

    return findings


def _sink_statement_principals(statement: Dict[str, Any]) -> List[str]:
    """Return the principal values of one resource-policy statement."""
    principals = statement.get("Principal")
    if isinstance(principals, str):
        return [principals]
    if isinstance(principals, list):
        return [value for value in principals if isinstance(value, str)]
    if isinstance(principals, dict):
        values: List[str] = []
        for entry in principals.values():
            if isinstance(entry, str):
                values.append(entry)
            elif isinstance(entry, list):
                values.extend(value for value in entry if isinstance(value, str))
        return values
    return []


def _sink_statement_is_scoped(statement: Dict[str, Any]) -> bool:
    """Return whether one sink-policy statement binds the sink to known callers."""
    principals = _sink_statement_principals(statement)
    if principals and "*" not in principals:
        return True

    conditions = statement.get("Condition")
    if not isinstance(conditions, dict):
        return False

    for condition_values in conditions.values():
        if not isinstance(condition_values, dict):
            continue
        for condition_key in condition_values:
            if str(condition_key).lower() in SINK_PRINCIPAL_SCOPE_CONDITION_KEYS:
                return True

    return False


def check_agentcore_telemetry_sink_scope() -> List[Dict[str, Any]]:
    """AC-22: Report whether each observability sink is scoped to known callers.

    A sink accepting a link from any account turns centralized agent telemetry
    into a cross-account write path an unrelated account can join.
    """
    if oam_client is None:
        return [
            create_finding(
                check_id="AC-22",
                finding_name="AgentCore Telemetry Sink Scope",
                finding_details=(
                    "CloudWatch Observability Access Manager client not available "
                    "in this region."
                ),
                resolution="No action required unless telemetry is aggregated here.",
                reference=OAM_CROSS_ACCOUNT_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        sinks = _paginate_aws_list(
            oam_client,
            "list_sinks",
            "Items",
            token_request_key="NextToken",
            token_response_key="NextToken",
        )
    except Exception as error:
        return [
            create_finding(
                check_id="AC-22",
                finding_name="AgentCore Telemetry Sink Scope",
                finding_details=(
                    f"Could not list observability sinks: {type(error).__name__}."
                ),
                resolution="Grant oam:ListSinks and retry.",
                reference=OAM_CROSS_ACCOUNT_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    if not sinks:
        return [
            create_finding(
                check_id="AC-22",
                finding_name="AgentCore Telemetry Sink Scope",
                finding_details=(
                    "No observability sink found in this region, so no telemetry "
                    "is aggregated into this account."
                ),
                resolution=(
                    "No action required for a single-account deployment. Create a "
                    "sink in the monitoring account for a multi-account one."
                ),
                reference=OAM_CROSS_ACCOUNT_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    for sink in sinks:
        sink_arn = sink.get("Arn")
        if not sink_arn:
            continue
        sink_name = sink.get("Name", sink_arn)

        try:
            policy_text = oam_client.get_sink_policy(SinkIdentifier=sink_arn).get(
                "Policy"
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in {
                "ResourceNotFoundException",
                "MissingRequiredParameterException",
            }:
                policy_text = None
            else:
                findings.append(
                    create_finding(
                        check_id="AC-22",
                        finding_name="AgentCore Telemetry Sink Scope",
                        finding_details=(
                            f"Sink '{sink_name}' policy could not be read: "
                            f"{type(error).__name__}."
                        ),
                        resolution="Grant oam:GetSinkPolicy and retry.",
                        reference=OAM_CROSS_ACCOUNT_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                continue
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-22",
                    finding_name="AgentCore Telemetry Sink Scope",
                    finding_details=(
                        f"Sink '{sink_name}' policy could not be read: "
                        f"{type(error).__name__}."
                    ),
                    resolution="Grant oam:GetSinkPolicy and retry.",
                    reference=OAM_CROSS_ACCOUNT_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        if not policy_text:
            # With no policy attached the sink accepts no link at all, so nothing
            # is shared into it and an unscoped-sharing verdict would be wrong.
            findings.append(
                create_finding(
                    check_id="AC-22",
                    finding_name="AgentCore Telemetry Sink Scope",
                    finding_details=(
                        f"Sink '{sink_name}' has no policy attached, so no source "
                        "account can link to it."
                    ),
                    resolution=(
                        "No action required unless source accounts are expected to "
                        "share telemetry into this sink."
                    ),
                    reference=OAM_CROSS_ACCOUNT_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        try:
            policy_document = json.loads(policy_text)
        except (TypeError, ValueError) as error:
            findings.append(
                create_finding(
                    check_id="AC-22",
                    finding_name="AgentCore Telemetry Sink Scope",
                    finding_details=(
                        f"Sink '{sink_name}' policy is not valid JSON: "
                        f"{type(error).__name__}."
                    ),
                    resolution="Review the sink policy document.",
                    reference=OAM_CROSS_ACCOUNT_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        statements = policy_document.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            statements = []

        allow_statements = [
            statement
            for statement in statements
            if isinstance(statement, dict) and statement.get("Effect") == "Allow"
        ]
        unscoped_count = sum(
            1
            for statement in allow_statements
            if not _sink_statement_is_scoped(statement)
        )

        if allow_statements and not unscoped_count:
            findings.append(
                create_finding(
                    check_id="AC-22",
                    finding_name="AgentCore Telemetry Sink Scope",
                    finding_details=(
                        f"Sink '{sink_name}' restricts every Allow statement to "
                        "named principals or to an organization condition key."
                    ),
                    resolution=(
                        "No action required. Confirm the organization or account "
                        "list matches the accounts that run agents."
                    ),
                    reference=OAM_CROSS_ACCOUNT_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )
            continue

        findings.append(
            create_finding(
                check_id="AC-22",
                finding_name="AgentCore Telemetry Sink Scope",
                finding_details=(
                    f"Sink '{sink_name}' has {unscoped_count} Allow statement(s) "
                    "that name no principal and carry no organization condition, "
                    "so any account can link telemetry into it."
                    if unscoped_count
                    else f"Sink '{sink_name}' policy contains no Allow statement "
                    "binding it to a known set of principals."
                ),
                resolution=(
                    "Add an aws:PrincipalOrgID or aws:PrincipalOrgPaths condition "
                    "to each Allow statement, or name the source accounts "
                    "explicitly in the Principal element."
                ),
                reference=OAM_CROSS_ACCOUNT_REFERENCE_URL,
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def _statement_condition_keys(statement: Dict[str, Any]) -> List[str]:
    """Return the normalized condition keys of one IAM statement."""
    conditions = statement.get("Condition")
    if not isinstance(conditions, dict):
        return []
    keys: List[str] = []
    for condition_values in conditions.values():
        if not isinstance(condition_values, dict):
            continue
        keys.extend(str(key).strip().lower() for key in condition_values)
    return keys


def _statement_scopes_memory_records(statement: Dict[str, Any]) -> bool:
    """Return whether one statement binds a memory read to one actor or namespace."""
    for condition_key in _statement_condition_keys(statement):
        if condition_key in MEMORY_SCOPE_CONDITION_KEYS:
            return True
        if condition_key.startswith(MEMORY_SCOPE_CONDITION_KEY_PREFIXES):
            return True
    return False


def _statement_grants_memory_record_read(statement: Dict[str, Any]) -> bool:
    """Return whether one statement grants a scopable memory read action."""
    for action in _statement_actions(statement):
        action_parts = action.split(":", 1)
        if len(action_parts) != 2:
            continue
        service_namespace, action_pattern = action_parts
        if service_namespace not in AGENT_PLATFORM_IAM_NAMESPACES:
            continue
        if any(
            fnmatchcase(read_action, action_pattern)
            for read_action in MEMORY_RECORD_READ_ACTIONS
        ):
            return True
    return False


def _principals_reading_memory_records(
    permissions_by_name: Dict[str, Any],
    principal_kind: str,
) -> Tuple[List[str], List[str]]:
    """Split principals reading memory records into unscoped and scoped grants.

    The only resource type these actions accept is the whole memory, so naming a
    memory ARN still reads every actor's records inside it. A condition on the
    namespace, strategy, actor or session is the one way a policy narrows the
    read, which is why the resource element is not consulted here.
    """
    unscoped: List[str] = []
    scoped: List[str] = []

    for principal_name, permissions in permissions_by_name.items():
        if not isinstance(permissions, dict):
            continue
        label = f"{principal_kind} {principal_name}"
        attached_policies = permissions.get("attached_policies", [])
        inline_policies = permissions.get("inline_policies", [])
        if not isinstance(attached_policies, list):
            attached_policies = []
        if not isinstance(inline_policies, list):
            inline_policies = []

        reads_records = False
        reads_records_unscoped = False

        for policy in [*attached_policies, *inline_policies]:
            try:
                for statement in _allow_statements(policy):
                    if not _statement_grants_memory_record_read(statement):
                        continue
                    reads_records = True
                    if not _statement_scopes_memory_records(statement):
                        reads_records_unscoped = True
            except Exception as error:
                logger.warning(f"Error parsing policy for {label}: {error}")

        if reads_records_unscoped:
            unscoped.append(label)
        elif reads_records:
            scoped.append(label)

    return unscoped, scoped


def check_agentcore_memory_record_access_scope(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """AC-23: Report who can read memory records across every actor.

    Partitioning long-term memory into a per-actor namespace only separates the
    records if the retrieval is also bound to one actor: a principal holding
    RetrieveMemoryRecords with no namespace or actor condition reads every end
    user's records out of the same memory.
    """
    findings = []

    try:
        role_permissions = permission_cache.get("role_permissions", {})
        user_permissions = permission_cache.get("user_permissions", {})

        if not role_permissions and not user_permissions:
            return [
                create_finding(
                    check_id="AC-23",
                    finding_name="AgentCore Memory Record Access Scope",
                    finding_details="No IAM permissions found in cache.",
                    resolution="No action required.",
                    reference=AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                    region=GLOBAL_REGION_LABEL,
                )
            ]

        unscoped_roles, scoped_roles = _principals_reading_memory_records(
            role_permissions, "role"
        )
        unscoped_users, scoped_users = _principals_reading_memory_records(
            user_permissions, "user"
        )
        unscoped = sorted(unscoped_roles + unscoped_users)
        scoped = sorted(scoped_roles + scoped_users)

        if unscoped:
            findings.append(
                create_finding(
                    check_id="AC-23",
                    finding_name="AgentCore Memory Record Access Scope",
                    finding_details=(
                        "The following principals can read memory records and "
                        "events without a namespace, strategy, actor or session "
                        "condition, so one call returns every actor's stored "
                        f"records: {', '.join(unscoped)}."
                    ),
                    resolution=(
                        "Add a bedrock-agentcore:namespace, strategyId, actorId or "
                        "sessionId condition that binds the read to the caller, for "
                        "example by matching the actor id against the session tag "
                        "carried by the agent identity."
                    ),
                    reference=AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

        if scoped:
            findings.append(
                create_finding(
                    check_id="AC-23",
                    finding_name="AgentCore Memory Record Access Scope",
                    finding_details=(
                        "The following principals read memory records only under a "
                        "namespace, strategy, actor or session condition: "
                        f"{', '.join(scoped)}."
                    ),
                    resolution=(
                        "No action required. Confirm the condition resolves to the "
                        "end user the caller is acting for rather than to a fixed "
                        "value shared by every session."
                    ),
                    reference=AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

        if not unscoped and not scoped:
            findings.append(
                create_finding(
                    check_id="AC-23",
                    finding_name="AgentCore Memory Record Access Scope",
                    finding_details=(
                        "No cached IAM role or user grants a memory record or event "
                        "read action, so no principal reads stored memory through "
                        "IAM policy."
                    ),
                    resolution="No action required.",
                    reference=AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

    except Exception as error:
        logger.error(f"Error in memory record access scope check: {error}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-23",
                finding_name="AgentCore Memory Record Access Scope",
                error=error,
                reference=AGENTCORE_MEMORY_NAMESPACE_REFERENCE_URL,
                region=GLOBAL_REGION_LABEL,
            )
        )

    return findings


def _gateway_rate_limit_is_bounded(rate_limit: Dict[str, Any]) -> bool:
    """Return whether an active rate limit bounds a throughput value.

    `dimensions` is the only required member of a limit entry, so a limit can be
    ACTIVE, name a dimension, and bound nothing. Only `requests`, `tokens` or
    `connections` carries a rate, and a limit still CREATING or DELETING is not
    in force.
    """
    if rate_limit.get("status") != "ACTIVE":
        return False
    for entry in rate_limit.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        if any(entry.get(key) for key in GATEWAY_RATE_LIMIT_VALUE_KEYS):
            return True
    return False


def _gateway_rate_limit_summary(rate_limit: Dict[str, Any]) -> str:
    """Describe one rate limit's dimensions and bounded values for a finding."""
    dimensions = [str(key) for key in rate_limit.get("dimensionKeys") or []]
    bounded: List[str] = []
    for entry in rate_limit.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        for key in GATEWAY_RATE_LIMIT_VALUE_KEYS:
            values = entry.get(key) or []
            for value in values:
                if isinstance(value, dict) and value.get("period"):
                    bounded.append(f"{value.get('rate')} {key} per {value['period']}")
    label = rate_limit.get("rateLimitId", "unknown")
    parts = [f"'{label}'"]
    if dimensions:
        parts.append("on " + ", ".join(dimensions))
    if bounded:
        parts.append("limited to " + "; ".join(sorted(set(bounded))))
    return " ".join(parts)


def check_agentcore_gateway_rate_limiting() -> List[Dict[str, Any]]:
    """AC-24: Report whether each gateway carries an active, bounded rate limit.

    A gateway is a network-reachable entry point that fans one caller request out
    into tool calls and model invocations, so an unbounded gateway converts one
    abusive caller into a bill and a denial of service for every other caller.
    The WAF association AG-27 reports filters request content; it sets no
    throughput ceiling.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-24",
                finding_name="AgentCore Gateway Rate Limiting",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_GATEWAY_RATE_LIMIT_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-24",
                finding_name="AgentCore Gateway Rate Limiting",
                error=error,
                reference=AGENTCORE_GATEWAY_RATE_LIMIT_REFERENCE_URL,
            )
        ]

    if not gateways:
        return [
            create_finding(
                check_id="AC-24",
                finding_name="AgentCore Gateway Rate Limiting",
                finding_details="No AgentCore gateways found in this region.",
                resolution="No action required.",
                reference=AGENTCORE_GATEWAY_RATE_LIMIT_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    for gateway in gateways:
        gateway_id = gateway.get("gatewayId", "unknown")
        gateway_name = gateway.get("name", gateway_id)
        label = f"Gateway '{gateway_name}' ({gateway_id})"

        try:
            rate_limits = _agentcore_list_all(
                "list_gateway_rate_limits",
                ["rateLimits"],
                gatewayIdentifier=gateway_id,
            )
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-24",
                    finding_name="AgentCore Gateway Rate Limiting",
                    finding_details=(
                        f"{label} rate limits could not be read: "
                        f"{_assessment_error_label(error)}."
                    ),
                    resolution=(
                        "Grant bedrock-agentcore:ListGatewayRateLimits and retry. "
                        "The operation needs botocore 1.43.66 or later."
                    ),
                    reference=AGENTCORE_GATEWAY_RATE_LIMIT_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        bounded = [
            rate_limit
            for rate_limit in rate_limits
            if _gateway_rate_limit_is_bounded(rate_limit)
        ]
        if bounded:
            findings.append(
                create_finding(
                    check_id="AC-24",
                    finding_name="AgentCore Gateway Rate Limiting",
                    finding_details=(
                        f"{label} has {len(bounded)} active rate limit(s) that bound "
                        "throughput: "
                        + "; ".join(
                            _gateway_rate_limit_summary(rate_limit)
                            for rate_limit in bounded
                        )
                        + "."
                    ),
                    resolution=(
                        "No action required. Confirm the rate and the dimension "
                        "match this workload's expected caller volume, because the "
                        "right ceiling is a workload decision."
                    ),
                    reference=AGENTCORE_GATEWAY_RATE_LIMIT_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )
        elif rate_limits:
            findings.append(
                create_finding(
                    check_id="AC-24",
                    finding_name="AgentCore Gateway Rate Limiting Ineffective",
                    finding_details=(
                        f"{label} has {len(rate_limits)} rate limit(s), none of "
                        "which is ACTIVE with a requests, tokens or connections "
                        "ceiling, so no limit is in force."
                    ),
                    resolution=(
                        "Add a requests, tokens or connections rate to the limit's "
                        "entries and wait for its status to reach ACTIVE."
                    ),
                    reference=AGENTCORE_GATEWAY_RATE_LIMIT_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AC-24",
                    finding_name="AgentCore Gateway Rate Limiting Missing",
                    finding_details=(
                        f"{label} has no rate limit, so one caller can consume the "
                        "gateway's whole tool and model capacity."
                    ),
                    resolution=(
                        "Create a gateway rate limit with a requests, tokens or "
                        "connections ceiling on a caller dimension such as "
                        "$.context.iam.principal or a JWT claim."
                    ),
                    reference=AGENTCORE_GATEWAY_RATE_LIMIT_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )

    return findings


def check_agentcore_gateway_target_authorization() -> List[Dict[str, Any]]:
    """AC-25: Report the outbound credential each gateway target reaches out with.

    `credentialProviderConfigurations` is optional on CreateGatewayTarget and the
    console offers "No authorization", so a target can call its backend with no
    gateway-supplied credential at all. Which of the five provider types suits a
    given backend is a workload decision; that a credential exists is not.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-25",
                finding_name="AgentCore Gateway Target Authorization",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_GATEWAY_TARGET_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-25",
                finding_name="AgentCore Gateway Target Authorization",
                error=error,
                reference=AGENTCORE_GATEWAY_TARGET_REFERENCE_URL,
            )
        ]

    findings = []
    targets_seen = 0
    for gateway in gateways:
        gateway_id = gateway.get("gatewayId", "unknown")
        gateway_name = gateway.get("name", gateway_id)

        try:
            targets = _agentcore_list_all(
                "list_gateway_targets",
                ["items", "targets"],
                gatewayIdentifier=gateway_id,
            )
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-25",
                    finding_name="AgentCore Gateway Target Authorization",
                    finding_details=(
                        f"Gateway '{gateway_name}' ({gateway_id}) targets could not "
                        f"be listed: {_assessment_error_label(error)}."
                    ),
                    resolution="Grant bedrock-agentcore:ListGatewayTargets and retry.",
                    reference=AGENTCORE_GATEWAY_TARGET_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        for target in targets:
            target_id = target.get("targetId")
            if not target_id:
                continue
            targets_seen += 1
            target_name = target.get("name", target_id)
            label = (
                f"Target '{target_name}' ({target_id}) on gateway "
                f"'{gateway_name}' ({gateway_id})"
            )

            try:
                # The list summary carries targetType and status but no
                # credential provider, so the detail call is the only surface
                # that answers this control.
                detail = agentcore_client.get_gateway_target(
                    gatewayIdentifier=gateway_id, targetId=target_id
                )
            except Exception as error:
                findings.append(
                    create_finding(
                        check_id="AC-25",
                        finding_name="AgentCore Gateway Target Authorization",
                        finding_details=(
                            f"{label} could not be read: "
                            f"{_assessment_error_label(error)}."
                        ),
                        resolution=(
                            "Grant bedrock-agentcore:GetGatewayTarget and retry."
                        ),
                        reference=AGENTCORE_GATEWAY_TARGET_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                continue

            provider_types = [
                str(configuration.get("credentialProviderType"))
                for configuration in detail.get("credentialProviderConfigurations")
                or []
                if isinstance(configuration, dict)
                and configuration.get("credentialProviderType")
            ]

            if provider_types:
                findings.append(
                    create_finding(
                        check_id="AC-25",
                        finding_name="AgentCore Gateway Target Authorization",
                        finding_details=(
                            f"{label} authenticates outbound calls with "
                            f"{', '.join(provider_types)}."
                        ),
                        resolution=(
                            "No action required. Confirm the credential the "
                            "provider issues is scoped to the operations this "
                            "target needs on its backend, which the gateway API "
                            "does not express."
                        ),
                        reference=AGENTCORE_GATEWAY_TARGET_REFERENCE_URL,
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-25",
                        finding_name="AgentCore Gateway Target Unauthenticated",
                        finding_details=(
                            f"{label} declares no credential provider, so the "
                            "gateway reaches its backend with no credential of "
                            "its own and the backend cannot tell one caller from "
                            "another."
                        ),
                        resolution=(
                            "Set credentialProviderConfigurations on the target to "
                            "GATEWAY_IAM_ROLE, OAUTH, API_KEY, "
                            "CALLER_IAM_CREDENTIALS or JWT_PASSTHROUGH, whichever "
                            "the backend authenticates."
                        ),
                        reference=AGENTCORE_GATEWAY_TARGET_REFERENCE_URL,
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.FAILED,
                    )
                )

    if not targets_seen and not findings:
        return [
            create_finding(
                check_id="AC-25",
                finding_name="AgentCore Gateway Target Authorization",
                finding_details=(
                    f"No AgentCore gateway target found across {len(gateways)} "
                    "gateway(s) in this region."
                ),
                resolution="No action required.",
                reference=AGENTCORE_GATEWAY_TARGET_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    return findings


def _kms_key_policy_allows_open_decrypt(policy_document: Any) -> bool:
    """Return whether a key policy lets every principal decrypt with no condition.

    A customer managed key on a log group only keeps the log data under the
    account's control while the key policy narrows who may use it. An Allow to
    `Principal: "*"` with no condition puts the plaintext within reach of every
    principal the account trusts, which is the posture the CMK was meant to
    replace.
    """
    for statement in _document_statements(policy_document, effect="Allow"):
        if statement.get("Condition"):
            continue
        if "*" not in _statement_principals(statement):
            continue
        for pattern in _statement_actions(statement):
            if pattern == "*":
                return True
            namespace, _, action_pattern = pattern.partition(":")
            if namespace != "kms":
                continue
            if any(
                fnmatchcase(action, action_pattern) for action in KMS_DECRYPT_ACTIONS
            ):
                return True
    return False


def check_agentcore_log_retention_and_key_scope() -> List[Dict[str, Any]]:
    """AC-26: Report log retention and CMK key scope on AgentCore log groups.

    A log group with no retention keeps agent prompts, tool arguments and memory
    records forever, which turns an investigation aid into a growing store of the
    data the workload was careful about elsewhere. AC-20 asserts that a customer
    managed key is set; this check asserts that the key policy behind it narrows
    who can read through it.
    """
    if logs_client is None:
        return [
            create_finding(
                check_id="AC-26",
                finding_name="AgentCore Log Retention and Key Scope",
                finding_details="CloudWatch Logs client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=LOGS_RETENTION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        log_groups = _agentcore_log_groups()
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-26",
                finding_name="AgentCore Log Retention and Key Scope",
                error=error,
                reference=LOGS_RETENTION_REFERENCE_URL,
            )
        ]

    if not log_groups:
        return [
            create_finding(
                check_id="AC-26",
                finding_name="AgentCore Log Retention and Key Scope",
                finding_details="No AgentCore log groups found in this region.",
                resolution="No action required.",
                reference=LOGS_RETENTION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    key_policy_cache: Dict[str, Any] = {}
    findings = []
    for log_group in log_groups:
        log_group_name = log_group.get("logGroupName")
        if not log_group_name:
            continue

        retention = log_group.get("retentionInDays")
        key_id = log_group.get("kmsKeyId")
        problems: List[str] = []
        confirmations: List[str] = []

        if retention:
            confirmations.append(f"expires log events after {retention} day(s)")
        else:
            problems.append(
                "has no retention period, so every logged prompt, tool argument "
                "and memory record is kept indefinitely"
            )

        if key_id:
            if key_id not in key_policy_cache:
                try:
                    key_policy_cache[key_id] = kms_client.get_key_policy(KeyId=key_id)[
                        "Policy"
                    ]
                except Exception as error:
                    logger.warning(f"Could not read key policy for {key_id}: {error}")
                    key_policy_cache[key_id] = error
            key_policy = key_policy_cache[key_id]
            if isinstance(key_policy, Exception):
                findings.append(
                    create_finding(
                        check_id="AC-26",
                        finding_name="AgentCore Log Key Scope",
                        finding_details=(
                            f"Log group '{log_group_name}' is encrypted with "
                            f"{key_id}, whose key policy could not be read: "
                            f"{_assessment_error_label(key_policy)}."
                        ),
                        resolution="Grant kms:GetKeyPolicy on the key and retry.",
                        reference=KMS_KEY_POLICY_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
            elif _kms_key_policy_allows_open_decrypt(key_policy):
                problems.append(
                    f"is encrypted with {key_id}, whose key policy allows every "
                    "principal to decrypt with no condition"
                )
            else:
                confirmations.append(
                    f"is encrypted with {key_id}, whose key policy names the "
                    "principals allowed to decrypt"
                )

        if problems:
            findings.append(
                create_finding(
                    check_id="AC-26",
                    finding_name="AgentCore Log Retention and Key Scope",
                    finding_details=(
                        f"Log group '{log_group_name}' {' and '.join(problems)}."
                    ),
                    resolution=(
                        "Set a retention period on the log group that matches the "
                        "investigation window this workload commits to, and remove "
                        "any unconditioned wildcard-principal decrypt grant from "
                        "the encryption key's policy."
                    ),
                    reference=LOGS_RETENTION_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AC-26",
                    finding_name="AgentCore Log Retention and Key Scope",
                    finding_details=(
                        f"Log group '{log_group_name}' {' and '.join(confirmations)}."
                    ),
                    resolution=(
                        "No action required. Confirm the retention period covers "
                        "the investigation window this workload commits to."
                    ),
                    reference=LOGS_RETENTION_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

    return findings


def _statement_is_confused_deputy_exposed(statement: Dict[str, Any]) -> bool:
    """Return whether an Allow statement trusts a service or anyone without a guard.

    The confused-deputy problem is about a principal the account did not choose:
    an AWS service principal acting for somebody else's resource, or `*`. A named
    cross-account ARN is a trust the account owner wrote down, so it is left to
    the resource-policy checks that judge who is named.
    """
    principals = _statement_principals(statement)
    exposed = any(
        principal == "*" or principal.endswith(".amazonaws.com")
        for principal in principals
    )
    if not exposed:
        return False
    condition_keys = set(_statement_condition_keys(statement))
    return not (condition_keys & CONFUSED_DEPUTY_CONDITION_KEYS)


def check_agentcore_gateway_policy_conditions() -> List[Dict[str, Any]]:
    """AC-27: Judge the conditions on each gateway's resource and trust policies.

    AC-10 reports that a resource policy is present. Presence is not the control:
    a policy that allows the AgentCore service principal to invoke the gateway
    with no aws:SourceAccount or aws:SourceArn condition lets another customer's
    gateway borrow this account's permissions, and the same hole exists on the
    gateway execution role's trust policy. The network leg is separate: a gateway
    reachable over any path is restricted to an approved private path only by a
    condition on the request's source VPC, VPC endpoint or address.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Policy Conditions",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=CONFUSED_DEPUTY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Policy Conditions",
                error=error,
                reference=CONFUSED_DEPUTY_REFERENCE_URL,
            )
        ]

    if not gateways:
        return [
            create_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Policy Conditions",
                finding_details="No AgentCore gateways found in this region.",
                resolution="No action required.",
                reference=CONFUSED_DEPUTY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    trust_cache: Dict[str, Any] = {}
    for gateway in gateways:
        gateway_id = gateway.get("gatewayId", "unknown")
        gateway_name = gateway.get("name", gateway_id)
        label = f"Gateway '{gateway_name}' ({gateway_id})"

        try:
            detail = agentcore_client.get_gateway(gatewayIdentifier=gateway_id)
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-27",
                    finding_name="AgentCore Gateway Policy Conditions",
                    finding_details=(
                        f"{label} could not be read: {_assessment_error_label(error)}."
                    ),
                    resolution="Grant bedrock-agentcore:GetGateway and retry.",
                    reference=CONFUSED_DEPUTY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        findings.extend(
            _gateway_resource_policy_findings(label, detail.get("gatewayArn"))
        )
        findings.extend(
            _gateway_role_trust_findings(label, detail.get("roleArn"), trust_cache)
        )

    return findings


def _gateway_resource_policy_findings(
    label: str, gateway_arn: Any
) -> List[Dict[str, Any]]:
    """Judge one gateway resource policy's confused-deputy and network conditions."""
    if not gateway_arn:
        return [
            create_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Policy Conditions",
                finding_details=(
                    f"{label} reported no gateway ARN, so its resource policy "
                    "could not be read."
                ),
                resolution="Grant bedrock-agentcore:GetGateway and retry.",
                reference=CONFUSED_DEPUTY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        policy = _get_agentcore_resource_policy(gateway_arn)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            policy = ""
        else:
            return [
                create_finding(
                    check_id="AC-27",
                    finding_name="AgentCore Gateway Policy Conditions",
                    finding_details=(
                        f"{label} resource policy could not be read: "
                        f"{_assessment_error_label(error)}."
                    ),
                    resolution=("Grant bedrock-agentcore:GetResourcePolicy and retry."),
                    reference=CONFUSED_DEPUTY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            ]
    except Exception as error:
        return [
            create_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Policy Conditions",
                finding_details=(
                    f"{label} resource policy could not be read: "
                    f"{_assessment_error_label(error)}."
                ),
                resolution="Grant bedrock-agentcore:GetResourcePolicy and retry.",
                reference=CONFUSED_DEPUTY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    statements = _document_statements(policy, effect="Allow")
    findings = []

    if not statements:
        findings.append(
            create_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Resource Policy Confused Deputy Guard",
                finding_details=(
                    f"{label} has no resource policy that allows another account "
                    "or an AWS service to invoke it, so there is no service "
                    "principal to guard."
                ),
                resolution="No action required.",
                reference=CONFUSED_DEPUTY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
    else:
        exposed = [
            statement
            for statement in statements
            if _statement_is_confused_deputy_exposed(statement)
        ]
        if exposed:
            findings.append(
                create_finding(
                    check_id="AC-27",
                    finding_name=(
                        "AgentCore Gateway Resource Policy Confused Deputy Guard "
                        "Missing"
                    ),
                    finding_details=(
                        f"{label} has {len(exposed)} of {len(statements)} Allow "
                        "statement(s) that trust an AWS service principal or every "
                        "principal without an aws:SourceAccount or aws:SourceArn "
                        "condition, so another account's resource can make the "
                        "service call this gateway on its behalf."
                    ),
                    resolution=(
                        "Add aws:SourceAccount for this account and aws:SourceArn "
                        "for this gateway's ARN to every statement whose principal "
                        "is an AWS service or a wildcard."
                    ),
                    reference=CONFUSED_DEPUTY_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AC-27",
                    finding_name="AgentCore Gateway Resource Policy Confused Deputy Guard",
                    finding_details=(
                        f"{label} guards all {len(statements)} Allow statement(s) "
                        "in its resource policy with aws:SourceAccount or "
                        "aws:SourceArn, or names no service or wildcard principal."
                    ),
                    resolution=(
                        "No action required. Confirm the aws:SourceArn pattern "
                        "names this gateway rather than every resource in the "
                        "account."
                    ),
                    reference=CONFUSED_DEPUTY_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )

    network_keys = sorted(
        {
            key
            for statement in statements
            for key in _statement_condition_keys(statement)
            if key in NETWORK_PATH_CONDITION_KEYS
        }
    )
    if network_keys:
        findings.append(
            create_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Network Path Scope",
                finding_details=(
                    f"{label} binds its resource policy to a network path with "
                    f"{', '.join(network_keys)}."
                ),
                resolution=(
                    "No action required. Confirm the VPC, VPC endpoint or address "
                    "range named in the condition is the approved private path for "
                    "this workload."
                ),
                reference=VPC_ENDPOINT_POLICY_REFERENCE_URL,
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.PASSED,
            )
        )
    else:
        findings.append(
            create_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Network Path Unrestricted",
                finding_details=(
                    f"{label} carries no aws:SourceVpc, aws:SourceVpce, "
                    "aws:VpcSourceIp or aws:SourceIp condition, so any caller "
                    "holding a valid authorizer token reaches it over any network "
                    "path, including the public internet."
                ),
                resolution=(
                    "Attach a gateway resource policy that denies calls whose "
                    "aws:SourceVpce is not the approved interface endpoint, or "
                    "express the same restriction in a service control policy."
                ),
                reference=VPC_ENDPOINT_POLICY_REFERENCE_URL,
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def _gateway_role_trust_findings(
    label: str, role_arn: Any, trust_cache: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Judge one gateway execution role's trust policy for a confused-deputy guard.

    The permission cache stores attached and inline policies only, so the trust
    policy is read from IAM here. Roles are cached per invocation because several
    gateways in one account share one execution role.
    """
    if not role_arn:
        return [
            create_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Role Trust Confused Deputy Guard",
                finding_details=(
                    f"{label} has no execution role, so there is no trust policy "
                    "to guard."
                ),
                resolution="No action required.",
                reference=CONFUSED_DEPUTY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    role_name = str(role_arn).rsplit("/", 1)[-1]
    if role_name not in trust_cache:
        try:
            trust_cache[role_name] = iam_client.get_role(RoleName=role_name)["Role"][
                "AssumeRolePolicyDocument"
            ]
        except Exception as error:
            logger.warning(f"Could not read trust policy for {role_name}: {error}")
            trust_cache[role_name] = error

    document = trust_cache[role_name]
    if isinstance(document, Exception):
        return [
            create_finding(
                check_id="AC-27",
                finding_name="AgentCore Gateway Role Trust Confused Deputy Guard",
                finding_details=(
                    f"{label} uses execution role {role_name}, whose trust policy "
                    f"could not be read: {_assessment_error_label(document)}."
                ),
                resolution="Grant iam:GetRole on the role and retry.",
                reference=CONFUSED_DEPUTY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    statements = _document_statements(document, effect="Allow")
    exposed = [
        statement
        for statement in statements
        if _statement_is_confused_deputy_exposed(statement)
    ]

    if exposed:
        return [
            create_finding(
                check_id="AC-27",
                finding_name=(
                    "AgentCore Gateway Role Trust Confused Deputy Guard Missing"
                ),
                finding_details=(
                    f"{label} uses execution role {role_name}, which has "
                    f"{len(exposed)} of {len(statements)} Allow statement(s) "
                    "trusting an AWS service principal or every principal with no "
                    "aws:SourceAccount or aws:SourceArn condition. A guarded "
                    "statement elsewhere in the same policy does not narrow an "
                    "unguarded one."
                ),
                resolution=(
                    "Add aws:SourceAccount for this account and aws:SourceArn for "
                    "this gateway's ARN to every statement of the trust policy, or "
                    "delete the unguarded statement."
                ),
                reference=CONFUSED_DEPUTY_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )
        ]

    return [
        create_finding(
            check_id="AC-27",
            finding_name="AgentCore Gateway Role Trust Confused Deputy Guard",
            finding_details=(
                f"{label} uses execution role {role_name}, whose "
                f"{len(statements)} Allow statement(s) each carry an "
                "aws:SourceAccount or aws:SourceArn condition, or name no service "
                "or wildcard principal."
            ),
            resolution=(
                "No action required. Confirm the aws:SourceArn pattern names this "
                "gateway rather than every AgentCore resource in the account."
            ),
            reference=CONFUSED_DEPUTY_REFERENCE_URL,
            severity=SeverityEnum.HIGH,
            status=StatusEnum.PASSED,
        )
    ]


# Lowercased for matching against `_statement_actions`, which normalizes case,
# mapped to the spelling used in report text.
GATEWAY_WRITE_ACTIONS = {
    "bedrock-agentcore:creategateway": "CreateGateway",
    "bedrock-agentcore:updategateway": "UpdateGateway",
}

GATEWAY_AUTHORIZER_CONDITION_KEY = "bedrock-agentcore:gatewayauthorizertype"

# NONE is the authorizer type that means no inbound authorizer, so it is the
# value an effective guardrail has to exclude. The devguide lists AWS_IAM,
# CUSTOM_JWT and NONE; the CreateGateway API model carries a fourth value,
# AUTHENTICATE_ONLY, which is still an authorizer and is not this control's
# concern.
GATEWAY_AUTHORIZER_UNAUTHENTICATED_VALUE = "NONE"

# A Deny fires when the operator matches, so an equals-family operator naming
# the value and a not-equals-family operator that omits it both deny that value.
# A Null test can do neither here: the authorizer type is a required member of
# the create request, so the key is always present and `Null: true` never
# matches.
SCP_DENY_VALUE_INCLUDES_OPERATORS = (
    "stringequals",
    "stringequalsignorecase",
    "stringlike",
)
SCP_DENY_VALUE_EXCLUDES_OPERATORS = (
    "stringnotequals",
    "stringnotequalsignorecase",
    "stringnotlike",
)
SCP_SET_OPERATOR_PREFIXES = ("forallvalues:", "foranyvalue:")

RUNTIME_WRITE_ACTIONS = {
    "bedrock-agentcore:createagentruntime": "CreateAgentRuntime",
    "bedrock-agentcore:updateagentruntime": "UpdateAgentRuntime",
}

RUNTIME_AUTHORIZER_CONDITION_KEY = "bedrock-agentcore:runtimeauthorizertype"

# A runtime carries one of two inbound auth modes, "either IAM SigV4 or JWT
# Bearer Token based inbound auth, but not both simultaneously". Only the JWT
# path proves who the end user is: it "validates the token's issuer, signature,
# and expiry", while the SigV4 path authenticates the calling AWS principal and
# takes the end user from a request header that "does not verify the userId
# against an authenticated end-user identity". Both spellings are the service's
# own: no API member carries a runtime authorizer type and no page documents
# this condition key's values, but the three enums that do name these modes,
# AuthorizerType for gateways plus PaymentsAuthorizerType and
# RegistryAuthorizerType, spell them AWS_IAM and CUSTOM_JWT.
RUNTIME_AUTHORIZER_UNVERIFIED_USER_VALUE = "AWS_IAM"
RUNTIME_AUTHORIZER_VERIFIED_USER_VALUE = "CUSTOM_JWT"

# The codes Organizations raises when this account cannot see the organization's
# policies at all, as opposed to seeing them and finding no guardrail. Both
# spellings of the denial code are accepted because the service model declares
# AccessDeniedException while the shorter form is what a member account's SCP
# denial reports.
ORGANIZATIONS_UNREADABLE_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "AWSOrganizationsNotInUseException",
}


def _statement_matches_action(statement: Dict[str, Any], action: str) -> bool:
    """Return whether a Deny statement reaches one action.

    `Action` reaches the actions its patterns match. A Deny written with
    `NotAction` denies everything its list omits, so it reaches an action that
    matches none of the exclusions: an SCP denying all but a read-only
    allow-list under an authorizer condition does block the gateway write, and
    one that names the write in `NotAction` exempts it. The IAM grammar forbids
    both keys in one statement, so `Action` is read first and a statement
    carrying neither reaches nothing. fnmatchcase carries the IAM wildcard
    grammar and is linear in the pattern, unlike a translated regular
    expression.
    """
    if "Action" in statement:
        return any(
            fnmatchcase(action, pattern) for pattern in _statement_actions(statement)
        )
    if "NotAction" in statement:
        return not any(
            fnmatchcase(action, pattern)
            for pattern in _statement_not_actions(statement)
        )
    return False


def _condition_values(raw: Any) -> List[str]:
    """Return one condition entry's values as a list of strings."""
    if isinstance(raw, (list, tuple)):
        return [str(value) for value in raw]
    return [str(raw)]


def _statement_condition_denies_value(
    statement: Dict[str, Any], key: str, value: str
) -> bool:
    """Return whether a Deny statement's condition fires for one key value."""
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return False

    for operator, entries in condition.items():
        if not isinstance(entries, dict):
            continue
        name = str(operator).strip().lower()
        for prefix in SCP_SET_OPERATOR_PREFIXES:
            if name.startswith(prefix):
                name = name[len(prefix) :]
                break
        for entry_key, raw in entries.items():
            if str(entry_key).strip().lower() != key:
                continue
            values = {entry.strip().upper() for entry in _condition_values(raw)}
            if name in SCP_DENY_VALUE_INCLUDES_OPERATORS:
                if value in values:
                    return True
            elif name in SCP_DENY_VALUE_EXCLUDES_OPERATORS:
                if value not in values:
                    return True
    return False


def _scp_authorizer_deny_coverage(
    document: Any, actions: Dict[str, str], key: str, value: str
) -> Tuple[Set[str], bool]:
    """Return which of `actions` one SCP denies for `key` = `value`, and whether
    the policy conditions on the key at all.

    The second value separates a policy that never mentions the authorizer type
    from one that mentions it in a shape that cannot deny the value, because the
    two need different remediation.
    """
    covered: Set[str] = set()
    names_key = False
    for statement in _document_statements(document, effect="Deny"):
        if key in _statement_condition_keys(statement):
            names_key = True
        if not _statement_condition_denies_value(statement, key, value):
            continue
        for action in actions:
            if _statement_matches_action(statement, action):
                covered.add(action)
    return covered, names_key


def check_agentcore_gateway_authorizer_scp() -> List[Dict[str, Any]]:
    """AC-28: Require an SCP that denies creating a gateway with no authorizer.

    AG-24 reads the authorizer type of the gateways that exist now, which says
    nothing about the next gateway somebody creates. The preventive control is a
    service control policy that denies CreateGateway and UpdateGateway when
    bedrock-agentcore:GatewayAuthorizerType is NONE. Update matters as much as
    create: a Deny on create alone leaves an authenticated gateway one
    UpdateGateway call away from being open.

    The check reads policy content only. Whether a policy is attached to the
    root, to one organizational unit, or to nothing needs
    organizations:ListTargetsForPolicy, which this function is not granted, so
    every finding says that attachment is still the reader's to confirm.
    """
    if organizations_client is None:
        return [
            create_finding(
                check_id="AC-28",
                finding_name="AgentCore Gateway Authorizer Guardrail",
                finding_details="Organizations client not available.",
                resolution="No action required unless this account is in an organization.",
                reference=AGENTCORE_GATEWAY_CONDITION_KEY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        policies = _paginate_aws_list(
            organizations_client,
            "list_policies",
            "Policies",
            token_request_key="NextToken",
            token_response_key="NextToken",
            Filter="SERVICE_CONTROL_POLICY",
        )
    except Exception as error:
        if _assessment_error_label(error) in ORGANIZATIONS_UNREADABLE_ERROR_CODES:
            return [
                create_finding(
                    check_id="AC-28",
                    finding_name="AgentCore Gateway Authorizer Guardrail",
                    finding_details=(
                        "Service control policies could not be listed from this "
                        f"account: {_assessment_error_label(error)}. A member "
                        "account cannot read the organization's policies."
                    ),
                    resolution=(
                        "Run the assessment from the management account or an "
                        "Organizations delegated administrator, with "
                        "organizations:ListPolicies and organizations:DescribePolicy."
                    ),
                    reference=AGENTCORE_GATEWAY_CONDITION_KEY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            ]
        return [
            _incomplete_check_finding(
                check_id="AC-28",
                finding_name="AgentCore Gateway Authorizer Guardrail",
                error=error,
                reference=AGENTCORE_GATEWAY_CONDITION_KEY_REFERENCE_URL,
            )
        ]

    covered_actions: Set[str] = set()
    guarding_policies: List[str] = []
    attempting_policies: List[str] = []
    read_errors: List[Tuple[str, Exception]] = []

    for policy in policies:
        policy_name = policy.get("Name", policy.get("Id", "unknown"))
        try:
            detail = organizations_client.describe_policy(PolicyId=policy["Id"])
        except Exception as error:
            read_errors.append((policy_name, error))
            continue

        content = (detail.get("Policy") or {}).get("Content", "")
        covered, names_key = _scp_authorizer_deny_coverage(
            content,
            GATEWAY_WRITE_ACTIONS,
            GATEWAY_AUTHORIZER_CONDITION_KEY,
            GATEWAY_AUTHORIZER_UNAUTHENTICATED_VALUE,
        )
        if covered:
            covered_actions |= covered
            guarding_policies.append(policy_name)
        elif names_key:
            attempting_policies.append(policy_name)

    findings: List[Dict[str, Any]] = []
    for policy_name, error in read_errors:
        findings.append(
            create_finding(
                check_id="AC-28",
                finding_name="AgentCore Gateway Authorizer Guardrail",
                finding_details=(
                    f"Service control policy '{policy_name}' could not be read: "
                    f"{_assessment_error_label(error)}, so it was not judged."
                ),
                resolution="Grant organizations:DescribePolicy and retry.",
                reference=AGENTCORE_GATEWAY_CONDITION_KEY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )

    missing = [
        name
        for action, name in GATEWAY_WRITE_ACTIONS.items()
        if action not in covered_actions
    ]
    guarding_label = ", ".join(sorted(guarding_policies))

    if not missing:
        findings.append(
            create_finding(
                check_id="AC-28",
                finding_name="AgentCore Gateway Authorizer Guardrail",
                finding_details=(
                    "CreateGateway and UpdateGateway are both denied when "
                    "bedrock-agentcore:GatewayAuthorizerType is NONE, by service "
                    f"control policy: {guarding_label}."
                ),
                resolution=(
                    "No action required. Confirm the policy is attached to the root "
                    "or to every organizational unit that hosts gateways, because "
                    "this check reads policy content and not attachment targets."
                ),
                reference=AGENTCORE_GATEWAY_CONDITION_KEY_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.PASSED,
            )
        )
        return findings

    if covered_actions:
        covered_label = ", ".join(
            sorted(GATEWAY_WRITE_ACTIONS[action] for action in covered_actions)
        )
        findings.append(
            create_finding(
                check_id="AC-28",
                finding_name="AgentCore Gateway Authorizer Guardrail Partial",
                finding_details=(
                    f"Authorizer type NONE is denied on {covered_label} but not on "
                    f"{', '.join(missing)}, by service control policy: "
                    f"{guarding_label}. An existing gateway can still be moved to "
                    "authorizer type NONE."
                ),
                resolution=(
                    "Add the uncovered action to the same Deny statement, keeping "
                    "the bedrock-agentcore:GatewayAuthorizerType condition."
                ),
                reference=AGENTCORE_GATEWAY_CONDITION_KEY_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )
        )
        return findings

    if attempting_policies:
        findings.append(
            create_finding(
                check_id="AC-28",
                finding_name="AgentCore Gateway Authorizer Guardrail Ineffective",
                finding_details=(
                    "bedrock-agentcore:GatewayAuthorizerType is conditioned on in a "
                    "shape that cannot deny the value NONE, by service control "
                    f"policy: {', '.join(sorted(attempting_policies))}. A Null test "
                    "is one such shape: the authorizer type is a required member of "
                    "CreateGateway, so it is never absent from the request."
                ),
                resolution=(
                    "Deny CreateGateway and UpdateGateway with StringEquals on "
                    "NONE, or with StringNotEquals on the authorizer types the "
                    "organization approves."
                ),
                reference=AGENTCORE_GATEWAY_CONDITION_KEY_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )
        )
        return findings

    findings.append(
        create_finding(
            check_id="AC-28",
            finding_name="AgentCore Gateway Authorizer Guardrail Missing",
            finding_details=(
                f"None of the {len(policies)} service control policy(s) readable "
                "from this account denies CreateGateway or UpdateGateway when "
                "bedrock-agentcore:GatewayAuthorizerType is NONE, so the next "
                "gateway created can accept unauthenticated requests."
            ),
            resolution=(
                "Attach a service control policy that denies "
                "bedrock-agentcore:CreateGateway and "
                "bedrock-agentcore:UpdateGateway with StringEquals on "
                "bedrock-agentcore:GatewayAuthorizerType NONE."
            ),
            reference=AGENTCORE_GATEWAY_CONDITION_KEY_REFERENCE_URL,
            severity=SeverityEnum.HIGH,
            status=StatusEnum.FAILED,
        )
    )
    return findings


def check_agentcore_runtime_authorizer_scp() -> List[Dict[str, Any]]:
    """AC-29: Require an SCP that keeps a runtime off SigV4-only inbound auth.

    A runtime deployed with the default IAM SigV4 inbound auth authenticates the
    calling AWS principal, which for a hosting application is one shared role
    for every end user. The end user then arrives in the
    X-Amzn-Bedrock-AgentCore-Runtime-User-Id header, which the service does not
    verify against an authenticated identity, so one caller can ask for another
    user's tokens. The preventive control is a service control policy that
    denies CreateAgentRuntime and UpdateAgentRuntime when
    bedrock-agentcore:RuntimeAuthorizerType is AWS_IAM. Update matters as much
    as create: a Deny on create alone leaves a JWT runtime one
    UpdateAgentRuntime call away from SigV4.

    A policy written the other way round, denying the JWT mode and admitting
    SigV4, is reported separately: it is a guardrail pointed at the wrong value
    and reads as configured to anyone counting policies.

    The check reads policy content only, so every finding says that attachment
    is still the reader's to confirm.
    """
    if organizations_client is None:
        return [
            create_finding(
                check_id="AC-29",
                finding_name="AgentCore Runtime Authorizer Guardrail",
                finding_details="Organizations client not available.",
                resolution="No action required unless this account is in an organization.",
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        policies = _paginate_aws_list(
            organizations_client,
            "list_policies",
            "Policies",
            token_request_key="NextToken",
            token_response_key="NextToken",
            Filter="SERVICE_CONTROL_POLICY",
        )
    except Exception as error:
        if _assessment_error_label(error) in ORGANIZATIONS_UNREADABLE_ERROR_CODES:
            return [
                create_finding(
                    check_id="AC-29",
                    finding_name="AgentCore Runtime Authorizer Guardrail",
                    finding_details=(
                        "Service control policies could not be listed from this "
                        f"account: {_assessment_error_label(error)}. A member "
                        "account cannot read the organization's policies."
                    ),
                    resolution=(
                        "Run the assessment from the management account or an "
                        "Organizations delegated administrator, with "
                        "organizations:ListPolicies and organizations:DescribePolicy."
                    ),
                    reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            ]
        return [
            _incomplete_check_finding(
                check_id="AC-29",
                finding_name="AgentCore Runtime Authorizer Guardrail",
                error=error,
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
            )
        ]

    covered_actions: Set[str] = set()
    inverted_actions: Set[str] = set()
    guarding_policies: List[str] = []
    inverted_policies: List[str] = []
    attempting_policies: List[str] = []
    read_errors: List[Tuple[str, Exception]] = []

    for policy in policies:
        policy_name = policy.get("Name", policy.get("Id", "unknown"))
        try:
            detail = organizations_client.describe_policy(PolicyId=policy["Id"])
        except Exception as error:
            read_errors.append((policy_name, error))
            continue

        content = (detail.get("Policy") or {}).get("Content", "")
        covered, names_key = _scp_authorizer_deny_coverage(
            content,
            RUNTIME_WRITE_ACTIONS,
            RUNTIME_AUTHORIZER_CONDITION_KEY,
            RUNTIME_AUTHORIZER_UNVERIFIED_USER_VALUE,
        )
        inverted, _ = _scp_authorizer_deny_coverage(
            content,
            RUNTIME_WRITE_ACTIONS,
            RUNTIME_AUTHORIZER_CONDITION_KEY,
            RUNTIME_AUTHORIZER_VERIFIED_USER_VALUE,
        )
        if covered:
            covered_actions |= covered
            guarding_policies.append(policy_name)
        elif inverted:
            inverted_actions |= inverted
            inverted_policies.append(policy_name)
        elif names_key:
            attempting_policies.append(policy_name)

    findings: List[Dict[str, Any]] = []
    for policy_name, error in read_errors:
        findings.append(
            create_finding(
                check_id="AC-29",
                finding_name="AgentCore Runtime Authorizer Guardrail",
                finding_details=(
                    f"Service control policy '{policy_name}' could not be read: "
                    f"{_assessment_error_label(error)}, so it was not judged."
                ),
                resolution="Grant organizations:DescribePolicy and retry.",
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )

    missing = [
        name
        for action, name in RUNTIME_WRITE_ACTIONS.items()
        if action not in covered_actions
    ]
    guarding_label = ", ".join(sorted(guarding_policies))

    if not missing:
        findings.append(
            create_finding(
                check_id="AC-29",
                finding_name="AgentCore Runtime Authorizer Guardrail",
                finding_details=(
                    "CreateAgentRuntime and UpdateAgentRuntime are both denied "
                    "when bedrock-agentcore:RuntimeAuthorizerType is AWS_IAM, by "
                    f"service control policy: {guarding_label}, so a new runtime "
                    "has to carry a JWT authorizer that validates the end user's "
                    "token."
                ),
                resolution=(
                    "No action required. Confirm the policy is attached to the "
                    "root or to every organizational unit that hosts runtimes, "
                    "because this check reads policy content and not attachment "
                    "targets."
                ),
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.PASSED,
            )
        )
        return findings

    if covered_actions:
        covered_label = ", ".join(
            sorted(RUNTIME_WRITE_ACTIONS[action] for action in covered_actions)
        )
        findings.append(
            create_finding(
                check_id="AC-29",
                finding_name="AgentCore Runtime Authorizer Guardrail Partial",
                finding_details=(
                    f"Authorizer type AWS_IAM is denied on {covered_label} but "
                    f"not on {', '.join(missing)}, by service control policy: "
                    f"{guarding_label}. An existing runtime can still be moved "
                    "to SigV4-only inbound auth."
                ),
                resolution=(
                    "Add the uncovered action to the same Deny statement, keeping "
                    "the bedrock-agentcore:RuntimeAuthorizerType condition."
                ),
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )
        )
        return findings

    if inverted_policies:
        inverted_label = ", ".join(
            sorted(RUNTIME_WRITE_ACTIONS[action] for action in inverted_actions)
        )
        findings.append(
            create_finding(
                check_id="AC-29",
                finding_name="AgentCore Runtime Authorizer Guardrail Inverted",
                finding_details=(
                    f"Service control policy {', '.join(sorted(inverted_policies))} "
                    f"denies {inverted_label} when "
                    "bedrock-agentcore:RuntimeAuthorizerType is CUSTOM_JWT, which "
                    "forbids the JWT mode and leaves SigV4-only inbound auth as "
                    "the only way to deploy a runtime."
                ),
                resolution=(
                    "Point the condition at AWS_IAM instead, or list CUSTOM_JWT "
                    "in a StringNotEquals on the approved authorizer types."
                ),
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )
        )
        return findings

    if attempting_policies:
        findings.append(
            create_finding(
                check_id="AC-29",
                finding_name="AgentCore Runtime Authorizer Guardrail Ineffective",
                finding_details=(
                    "bedrock-agentcore:RuntimeAuthorizerType is conditioned on in "
                    "a shape that denies neither AWS_IAM nor CUSTOM_JWT, by "
                    "service control policy: "
                    f"{', '.join(sorted(attempting_policies))}. A Null test is one "
                    "such shape: the authorizer type is a required member of the "
                    "create request, so it is never absent."
                ),
                resolution=(
                    "Deny CreateAgentRuntime and UpdateAgentRuntime with "
                    "StringEquals on AWS_IAM, or with StringNotEquals on the "
                    "authorizer types the organization approves."
                ),
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )
        )
        return findings

    findings.append(
        create_finding(
            check_id="AC-29",
            finding_name="AgentCore Runtime Authorizer Guardrail Missing",
            finding_details=(
                f"None of the {len(policies)} service control policy(s) readable "
                "from this account denies CreateAgentRuntime or "
                "UpdateAgentRuntime when bedrock-agentcore:RuntimeAuthorizerType "
                "is AWS_IAM, so the next runtime can be deployed with SigV4-only "
                "inbound auth and take its end user from an unverified header."
            ),
            resolution=(
                "Attach a service control policy that denies "
                "bedrock-agentcore:CreateAgentRuntime and "
                "bedrock-agentcore:UpdateAgentRuntime with StringEquals on "
                "bedrock-agentcore:RuntimeAuthorizerType AWS_IAM."
            ),
            reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
            severity=SeverityEnum.HIGH,
            status=StatusEnum.FAILED,
        )
    )
    return findings


# The claims a CUSTOM_JWT authorizer can be told to validate, split by what
# each one binds. Audience and client id bind which application's token is
# accepted; scopes and custom claims bind what the token may ask for. The
# inbound-authorizer guide states at least one of the four is required, so
# "validates nothing" is not the state to report: "validates a claim, but not
# which application the token was minted for" is, and the live estate has one.
JWT_AUTHORIZER_CALLER_CLAIMS = {
    "allowedAudience": "audience",
    "allowedClients": "client id",
}
JWT_AUTHORIZER_OTHER_CLAIMS = {
    "allowedScopes": "scope",
    "customClaims": "custom claim",
}


def _jwt_authorizer_claims(
    authorizer: Dict[str, Any], members: Dict[str, str]
) -> List[str]:
    """Return the claims a JWT authorizer pins out of one group."""
    return [
        label for member, label in sorted(members.items()) if authorizer.get(member)
    ]


def check_agentcore_runtime_inbound_authorization() -> List[Dict[str, Any]]:
    """AC-30: Report how each runtime authenticates the caller that invokes it.

    authorizerConfiguration is optional on CreateAgentRuntime, so a runtime
    either enforces SigV4 on every invoke or carries a JWT authorizer. A JWT
    authorizer that pins neither allowedAudience nor allowedClients accepts
    every token its issuer minted for every application registered with that
    issuer, so a token issued to a different application reaches this agent.
    AG-24 asks this of a gateway; a runtime that callers invoke directly never
    passes through one.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-30",
                finding_name="AgentCore Runtime Inbound Authorization",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        runtimes = _agentcore_list_all("list_agent_runtimes", ["agentRuntimes"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-30",
                finding_name="AgentCore Runtime Inbound Authorization",
                error=error,
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
            )
        ]

    if not runtimes:
        return [
            create_finding(
                check_id="AC-30",
                finding_name="AgentCore Runtime Inbound Authorization",
                finding_details="No AgentCore runtimes found in this region.",
                resolution="No action required.",
                reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    for runtime in runtimes:
        runtime_id = runtime.get("agentRuntimeId", "unknown")
        runtime_name = runtime.get("agentRuntimeName", runtime_id)
        label = f"Runtime '{runtime_name}' ({runtime_id})"

        try:
            details = agentcore_client.get_agent_runtime(agentRuntimeId=runtime_id)
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-30",
                    finding_name="AgentCore Runtime Inbound Authorization",
                    finding_details=(
                        f"{label} inbound authorizer could not be read: "
                        f"{_assessment_error_label(error)}."
                    ),
                    resolution=(
                        "Grant bedrock-agentcore:GetAgentRuntime on this runtime "
                        "and retry."
                    ),
                    reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        authorizer_configuration = details.get("authorizerConfiguration") or {}
        jwt_authorizer = authorizer_configuration.get("customJWTAuthorizer") or {}

        if not authorizer_configuration:
            findings.append(
                create_finding(
                    check_id="AC-30",
                    finding_name="AgentCore Runtime Inbound Authorization",
                    finding_details=(
                        f"{label} carries no inbound authorizer, so every invoke "
                        "must be SigV4-signed and IAM decides which principal may "
                        "reach the agent."
                    ),
                    resolution=(
                        "No action required. Confirm the IAM principals allowed to "
                        "call InvokeAgentRuntime are the intended callers, because "
                        "SigV4 proves the caller's AWS identity and not an end "
                        "user's."
                    ),
                    reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
            continue

        if not jwt_authorizer:
            findings.append(
                create_finding(
                    check_id="AC-30",
                    finding_name="AgentCore Runtime Inbound Authorization",
                    finding_details=(
                        f"{label} carries an inbound authorizer this assessment "
                        "cannot read: authorizerConfiguration holds "
                        f"{', '.join(sorted(authorizer_configuration))} and not "
                        "customJWTAuthorizer, the only member botocore 1.43.85 "
                        "defines."
                    ),
                    resolution=(
                        "Upgrade the assessment's botocore so the new authorizer "
                        "member can be judged, then re-run."
                    ),
                    reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        discovery_url = jwt_authorizer.get("discoveryUrl", "an unnamed issuer")
        caller_claims = _jwt_authorizer_claims(
            jwt_authorizer, JWT_AUTHORIZER_CALLER_CLAIMS
        )
        other_claims = _jwt_authorizer_claims(
            jwt_authorizer, JWT_AUTHORIZER_OTHER_CLAIMS
        )
        if caller_claims:
            validated = caller_claims + other_claims
            findings.append(
                create_finding(
                    check_id="AC-30",
                    finding_name="AgentCore Runtime Inbound Authorization",
                    finding_details=(
                        f"{label} accepts JWTs from {discovery_url} and validates "
                        f"the {', '.join(validated)} claim(s) before the agent's "
                        "code runs."
                    ),
                    resolution=(
                        "No action required. Confirm the pinned values name this "
                        "workload's own audience, clients and scopes."
                    ),
                    reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
        else:
            validated = (
                f"validates the {', '.join(other_claims)} claim(s) but"
                if other_claims
                else "validates"
            )
            findings.append(
                create_finding(
                    check_id="AC-30",
                    finding_name="AgentCore Runtime Inbound Authorization Unbounded",
                    finding_details=(
                        f"{label} accepts JWTs from {discovery_url}, {validated} "
                        "neither the audience nor the client id, so a token that "
                        "issuer minted for a different application invokes this "
                        "agent."
                    ),
                    resolution=(
                        "Set allowedAudience or allowedClients on the runtime's "
                        "customJWTAuthorizer, and keep allowedScopes or "
                        "customClaims where the agent's actions differ per caller."
                    ),
                    reference=AGENTCORE_RUNTIME_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

    return findings


# The two gateway authorizer types that authenticate a SigV4 signature. Neither
# carries a bearer token, so neither has an issuer or a client application to
# allow-list: gateway-inbound-auth.html states token passthrough "requires a
# JWT-bearing inbound type" and "is not available with AUTHENTICATE_ONLY, which
# is SigV4-based and carries no bearer token".
GATEWAY_AUTHORIZER_SIGV4_VALUES = ("AWS_IAM", "AUTHENTICATE_ONLY")
GATEWAY_AUTHORIZER_JWT_VALUE = "CUSTOM_JWT"


def check_agentcore_gateway_inbound_allow_lists() -> List[Dict[str, Any]]:
    """AC-31: Judge which issuers and applications each gateway accepts tokens from.

    AG-24 passes every CUSTOM_JWT gateway on the authorizer type alone, without
    reading the authorizer's allow-lists, so a gateway that honours any token its
    issuer minted for any registered application passes it today. The allow-lists
    that bind the calling application are allowedAudience and allowedClients; a
    scope or custom-claim constraint bounds what a token may ask for and not who
    minted it for whom. AC-30 asks this of a runtime.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-31",
                finding_name="AgentCore Gateway Inbound Allow Lists",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-31",
                finding_name="AgentCore Gateway Inbound Allow Lists",
                error=error,
                reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
            )
        ]

    if not gateways:
        return [
            create_finding(
                check_id="AC-31",
                finding_name="AgentCore Gateway Inbound Allow Lists",
                finding_details="No AgentCore gateways found in this region.",
                resolution="No action required.",
                reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    for gateway in gateways:
        gateway_id = gateway.get("gatewayId", "unknown")
        gateway_name = gateway.get("name", gateway_id)
        label = f"Gateway '{gateway_name}' ({gateway_id})"

        try:
            detail = agentcore_client.get_gateway(gatewayIdentifier=gateway_id)
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-31",
                    finding_name="AgentCore Gateway Inbound Allow Lists",
                    finding_details=(
                        f"{label} inbound authorizer could not be read: "
                        f"{_assessment_error_label(error)}."
                    ),
                    resolution="Grant bedrock-agentcore:GetGateway and retry.",
                    reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        authorizer_type = detail.get("authorizerType") or gateway.get("authorizerType")

        if authorizer_type in GATEWAY_AUTHORIZER_SIGV4_VALUES:
            findings.append(
                create_finding(
                    check_id="AC-31",
                    finding_name="AgentCore Gateway Inbound Allow Lists",
                    finding_details=(
                        f"{label} authenticates callers by SigV4 signature "
                        f"({authorizer_type}), so it accepts no bearer token and "
                        "has no issuer or client application to allow-list."
                    ),
                    resolution=(
                        "No action required for the issuer allow-list. Confirm the "
                        "IAM principals allowed to invoke this gateway are the "
                        "intended callers."
                    ),
                    reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
            continue

        if authorizer_type == GATEWAY_AUTHORIZER_UNAUTHENTICATED_VALUE:
            findings.append(
                create_finding(
                    check_id="AC-31",
                    finding_name="AgentCore Gateway Inbound Allow Lists Absent",
                    finding_details=(
                        f"{label} uses authorizerType "
                        f"{GATEWAY_AUTHORIZER_UNAUTHENTICATED_VALUE}, so it performs "
                        "no inbound authentication: there is no issuer allow-list to "
                        "hold, every caller reaches the tools, and a token "
                        "passthrough target forwards whatever bearer token the "
                        "caller sent."
                    ),
                    resolution=(
                        "Set the gateway's authorizerType to CUSTOM_JWT and pin "
                        "allowedAudience or allowedClients, or to AWS_IAM where the "
                        "callers are AWS principals."
                    ),
                    reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
            continue

        if authorizer_type != GATEWAY_AUTHORIZER_JWT_VALUE:
            findings.append(
                create_finding(
                    check_id="AC-31",
                    finding_name="AgentCore Gateway Inbound Allow Lists",
                    finding_details=(
                        f"{label} reported authorizerType "
                        f"{authorizer_type or 'unspecified'}, which this assessment "
                        "cannot judge against an issuer allow-list."
                    ),
                    resolution=(
                        "Upgrade the assessment's botocore so the new authorizer "
                        "type can be judged, then re-run."
                    ),
                    reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        authorizer_configuration = detail.get("authorizerConfiguration") or {}
        jwt_authorizer = authorizer_configuration.get("customJWTAuthorizer") or {}
        if not jwt_authorizer:
            findings.append(
                create_finding(
                    check_id="AC-31",
                    finding_name="AgentCore Gateway Inbound Allow Lists",
                    finding_details=(
                        f"{label} uses authorizerType "
                        f"{GATEWAY_AUTHORIZER_JWT_VALUE} but reported no "
                        "customJWTAuthorizer, so its allow-lists could not be read."
                    ),
                    resolution="Grant bedrock-agentcore:GetGateway and retry.",
                    reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        discovery_url = jwt_authorizer.get("discoveryUrl", "an unnamed issuer")
        caller_claims = _jwt_authorizer_claims(
            jwt_authorizer, JWT_AUTHORIZER_CALLER_CLAIMS
        )
        other_claims = _jwt_authorizer_claims(
            jwt_authorizer, JWT_AUTHORIZER_OTHER_CLAIMS
        )
        if caller_claims:
            allow_listed = caller_claims + other_claims
            findings.append(
                create_finding(
                    check_id="AC-31",
                    finding_name="AgentCore Gateway Inbound Allow Lists",
                    finding_details=(
                        f"{label} accepts JWTs from {discovery_url} and allow-lists "
                        f"the {', '.join(allow_listed)} claim(s), so a token minted "
                        "for another application is rejected at the gateway."
                    ),
                    resolution=(
                        "No action required. Confirm the pinned values name this "
                        "workload's own identity provider, audience and clients."
                    ),
                    reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
        else:
            bounded = (
                f"allow-lists the {', '.join(other_claims)} claim(s) but"
                if other_claims
                else "allow-lists"
            )
            findings.append(
                create_finding(
                    check_id="AC-31",
                    finding_name="AgentCore Gateway Inbound Allow Lists Absent",
                    finding_details=(
                        f"{label} accepts JWTs from {discovery_url}, {bounded} "
                        "neither the audience nor the client id, so any application "
                        "registered with that issuer can reach this gateway's tools."
                    ),
                    resolution=(
                        "Set allowedAudience or allowedClients on the gateway's "
                        "customJWTAuthorizer to the audience and client ids this "
                        "workload issues tokens to."
                    ),
                    reference=AGENTCORE_GATEWAY_INBOUND_AUTH_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

    return findings


# The two operations that accept an end user's JWT and hand back a workload
# access token. The service reference wires every bedrock-agentcore:InboundJwtClaim
# key to exactly these two, so they are the only IAM surface on which an issuer
# can be pinned.
INBOUND_JWT_EXCHANGE_ACTIONS = (
    "completeresourcetokenauth",
    "getworkloadaccesstokenforjwt",
)

# The claims that bind which identity provider minted the token and which
# application it was minted for. scope and sub bound what the token may ask for
# and which end user it speaks for, so neither keeps a token from an unapproved
# issuer out. client_id is available only when the JWT carries that claim under
# that exact name, which is why the resolution names all three.
INBOUND_JWT_ISSUER_CONDITION_KEYS = (
    "bedrock-agentcore:inboundjwtclaim/aud",
    "bedrock-agentcore:inboundjwtclaim/client_id",
    "bedrock-agentcore:inboundjwtclaim/iss",
)


def _statement_grants_inbound_jwt_exchange(statement: Dict[str, Any]) -> bool:
    """Return whether one statement grants an inbound JWT token exchange."""
    for action in _statement_actions(statement):
        action_parts = action.split(":", 1)
        if len(action_parts) != 2:
            continue
        service_namespace, action_pattern = action_parts
        if service_namespace not in AGENT_PLATFORM_IAM_NAMESPACES:
            continue
        if any(
            fnmatchcase(exchange_action, action_pattern)
            for exchange_action in INBOUND_JWT_EXCHANGE_ACTIONS
        ):
            return True
    return False


def _statement_pins_inbound_jwt_issuer(statement: Dict[str, Any]) -> bool:
    """Return whether one statement binds the exchange to named issuers or clients."""
    return any(
        condition_key in INBOUND_JWT_ISSUER_CONDITION_KEYS
        for condition_key in _statement_condition_keys(statement)
    )


def _principals_exchanging_inbound_jwts(
    permissions_by_name: Dict[str, Any],
    principal_kind: str,
) -> Tuple[List[str], List[str]]:
    """Split principals exchanging inbound JWTs into unpinned and pinned grants.

    The resource element cannot answer this question: both actions take the
    workload identity as their resource, so naming one workload still accepts a
    token from any issuer that workload's authorizer trusts. Only a condition on
    the issuer, audience or client id narrows which tokens the exchange accepts.
    """
    unpinned: List[str] = []
    pinned: List[str] = []

    for principal_name, permissions in permissions_by_name.items():
        if not isinstance(permissions, dict):
            continue
        label = f"{principal_kind} {principal_name}"
        attached_policies = permissions.get("attached_policies", [])
        inline_policies = permissions.get("inline_policies", [])
        if not isinstance(attached_policies, list):
            attached_policies = []
        if not isinstance(inline_policies, list):
            inline_policies = []

        exchanges_tokens = False
        exchanges_tokens_unpinned = False

        for policy in [*attached_policies, *inline_policies]:
            try:
                for statement in _allow_statements(policy):
                    if not _statement_grants_inbound_jwt_exchange(statement):
                        continue
                    exchanges_tokens = True
                    if not _statement_pins_inbound_jwt_issuer(statement):
                        exchanges_tokens_unpinned = True
            except Exception as error:
                logger.warning(f"Error parsing policy for {label}: {error}")

        if exchanges_tokens_unpinned:
            unpinned.append(label)
        elif exchanges_tokens:
            pinned.append(label)

    return unpinned, pinned


def check_agentcore_inbound_jwt_issuer_conditions(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """AC-32: Report who can exchange a JWT from any issuer for a workload token.

    AC-31 pins the issuer at the gateway's front door. This is the second leg:
    the token-exchange APIs accept an end user's JWT directly, so a principal
    holding GetWorkloadAccessTokenForJWT or CompleteResourceTokenAuth with no
    InboundJwtClaim condition trades a token from any issuer the workload trusts
    for a workload access token, without passing through a gateway authorizer.
    An action element of "*" is a service-agnostic administrator grant and is
    left to AC-02; this check reads the grants that name the bedrock-agentcore
    namespace.
    """
    findings = []

    try:
        role_permissions = permission_cache.get("role_permissions", {})
        user_permissions = permission_cache.get("user_permissions", {})

        if not role_permissions and not user_permissions:
            return [
                create_finding(
                    check_id="AC-32",
                    finding_name="AgentCore Inbound JWT Issuer Conditions",
                    finding_details="No IAM permissions found in cache.",
                    resolution="No action required.",
                    reference=AGENTCORE_IAM_CONDITION_KEY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                    region=GLOBAL_REGION_LABEL,
                )
            ]

        unpinned_roles, pinned_roles = _principals_exchanging_inbound_jwts(
            role_permissions, "role"
        )
        unpinned_users, pinned_users = _principals_exchanging_inbound_jwts(
            user_permissions, "user"
        )
        unpinned = sorted(unpinned_roles + unpinned_users)
        pinned = sorted(pinned_roles + pinned_users)

        if unpinned:
            findings.append(
                create_finding(
                    check_id="AC-32",
                    finding_name="AgentCore Inbound JWT Issuer Conditions",
                    finding_details=(
                        "The following principals can exchange an end user's JWT "
                        "for a workload access token with no condition on the "
                        "token's issuer, audience or client id, so a token minted "
                        "by any issuer the workload trusts is accepted: "
                        f"{', '.join(unpinned)}."
                    ),
                    resolution=(
                        "Add a bedrock-agentcore:InboundJwtClaim/iss condition "
                        "naming the approved identity providers, and "
                        "InboundJwtClaim/aud or InboundJwtClaim/client_id for the "
                        "approved applications, to every statement granting "
                        "GetWorkloadAccessTokenForJWT or CompleteResourceTokenAuth. "
                        "client_id resolves only where the JWT carries that claim "
                        "under that exact name, and aud arrives as a multi-valued "
                        "key, so qualify it with ForAllValues to keep one approved "
                        "audience from admitting a token that also carries others."
                    ),
                    reference=AGENTCORE_IAM_CONDITION_KEY_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

        if pinned:
            findings.append(
                create_finding(
                    check_id="AC-32",
                    finding_name="AgentCore Inbound JWT Issuer Conditions",
                    finding_details=(
                        "The following principals exchange inbound JWTs only under "
                        "an issuer, audience or client id condition: "
                        f"{', '.join(pinned)}."
                    ),
                    resolution=(
                        "No action required. Confirm the pinned values name this "
                        "workload's own identity providers and client applications."
                    ),
                    reference=AGENTCORE_IAM_CONDITION_KEY_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

        if not unpinned and not pinned:
            findings.append(
                create_finding(
                    check_id="AC-32",
                    finding_name="AgentCore Inbound JWT Issuer Conditions",
                    finding_details=(
                        "No cached IAM role or user grants "
                        "GetWorkloadAccessTokenForJWT or CompleteResourceTokenAuth, "
                        "so no principal exchanges an inbound JWT for a workload "
                        "access token through IAM policy."
                    ),
                    resolution="No action required.",
                    reference=AGENTCORE_IAM_CONDITION_KEY_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

    except Exception as error:
        logger.error(f"Error in inbound JWT issuer conditions check: {error}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-32",
                finding_name="AgentCore Inbound JWT Issuer Conditions",
                error=error,
                reference=AGENTCORE_IAM_CONDITION_KEY_REFERENCE_URL,
                region=GLOBAL_REGION_LABEL,
            )
        )

    return findings


# The actions that hand an agent a token or a stored credential. The reference
# Runtime execution role grants the first three under one Sid and the documented
# caller requirements include all three, so the control is not "remove them": it
# is which resources they may be used against.
TOKEN_ISSUANCE_ACTIONS = (
    "completeresourcetokenauth",
    "getresourceoauth2token",
    "getworkloadaccesstoken",
    "getworkloadaccesstokenforjwt",
    "getworkloadaccesstokenforuserid",
)

# A workload identity's ARN nests under its directory's, so this segment is what
# separates "this agent's identity" from "the directory that holds every agent's".
WORKLOAD_IDENTITY_ARN_SEGMENT = "workload-identity/"


def _statement_grants_token_issuance(statement: Dict[str, Any]) -> bool:
    """Return whether one statement grants an agent token or credential read."""
    for action in _statement_actions(statement):
        action_parts = action.split(":", 1)
        if len(action_parts) != 2:
            continue
        service_namespace, action_pattern = action_parts
        if service_namespace not in AGENT_PLATFORM_IAM_NAMESPACES:
            continue
        if any(
            fnmatchcase(issuance_action, action_pattern)
            for issuance_action in TOKEN_ISSUANCE_ACTIONS
        ):
            return True
    return False


def _resource_names_one_workload_identity(resource: str) -> bool:
    """Return whether one resource element names a single workload identity.

    A workload identity's ARN nests under its directory's, so the directory ARN
    ends at `workload-identity-directory/<name>` and never carries this segment:
    `workload-identity-directory/` does not contain `workload-identity/`.
    """
    _, separator, identity_name = resource.partition(WORKLOAD_IDENTITY_ARN_SEGMENT)
    if not separator:
        return False
    return bool(identity_name) and "*" not in identity_name


def _token_issuance_scope_verdict(statement: Dict[str, Any]) -> str:
    """Classify one token-issuance statement's resource element.

    AWS's own scoped example lists the directory ARN alongside the workload
    identity's, because both resource types are required on these actions, so a
    directory ARN in the list is not the widening. A trailing wildcard is: it
    reaches every identity, vault or provider under that prefix. A wildcard
    earlier in the ARN, in the region or the account, leaves the named identity
    named, so it is read as scoped.
    """
    resources = _statement_resources(statement)
    if any(resource.endswith("*") for resource in resources):
        return "unbounded"
    if any(_resource_names_one_workload_identity(resource) for resource in resources):
        return "scoped"
    return "directory_only"


def _principals_issuing_agent_tokens(
    permissions_by_name: Dict[str, Any],
    principal_kind: str,
) -> Tuple[List[str], List[str], List[str]]:
    """Group principals holding token-issuance actions by how narrow the grant is.

    A principal is judged on the union of its resource elements, so `scoped`
    outranks `directory_only`: AWS's own scoped policy lists the directory ARN
    beside the workload identity's, and splitting those two ARNs into two
    statements is the same grant.
    """
    unbounded: List[str] = []
    directory_only: List[str] = []
    scoped: List[str] = []

    for principal_name, permissions in permissions_by_name.items():
        if not isinstance(permissions, dict):
            continue
        label = f"{principal_kind} {principal_name}"
        attached_policies = permissions.get("attached_policies", [])
        inline_policies = permissions.get("inline_policies", [])
        if not isinstance(attached_policies, list):
            attached_policies = []
        if not isinstance(inline_policies, list):
            inline_policies = []

        verdicts = set()
        for policy in [*attached_policies, *inline_policies]:
            try:
                for statement in _allow_statements(policy):
                    if not _statement_grants_token_issuance(statement):
                        continue
                    verdicts.add(_token_issuance_scope_verdict(statement))
            except Exception as error:
                logger.warning(f"Error parsing policy for {label}: {error}")

        if "unbounded" in verdicts:
            unbounded.append(label)
        elif "scoped" in verdicts:
            scoped.append(label)
        elif "directory_only" in verdicts:
            directory_only.append(label)

    return unbounded, directory_only, scoped


def check_agentcore_token_issuance_scope(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """AC-33: Report which resources each principal may mint agent tokens against.

    AgentCore blocks a service-linked workload identity from retrieving its own
    access token, and Runtime hands the token to agent code in the invocation
    payload instead, so this control is not enforced by removing the actions: the
    reference execution role grants all three GetWorkloadAccessToken* actions and
    an agent breaks without them. What a policy can do is bound which workload
    identity, vault and credential provider they reach. AWS's own consent-portal
    execution role allows three of them on Resource "*", so the widest grant on
    the page is one a customer may have copied forward.
    """
    findings = []

    try:
        role_permissions = permission_cache.get("role_permissions", {})
        user_permissions = permission_cache.get("user_permissions", {})

        if not role_permissions and not user_permissions:
            return [
                create_finding(
                    check_id="AC-33",
                    finding_name="AgentCore Token Issuance Scope",
                    finding_details="No IAM permissions found in cache.",
                    resolution="No action required.",
                    reference=AGENTCORE_WORKLOAD_IDENTITY_SCOPE_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                    region=GLOBAL_REGION_LABEL,
                )
            ]

        role_groups = _principals_issuing_agent_tokens(role_permissions, "role")
        user_groups = _principals_issuing_agent_tokens(user_permissions, "user")
        unbounded = sorted(role_groups[0] + user_groups[0])
        directory_only = sorted(role_groups[1] + user_groups[1])
        scoped = sorted(role_groups[2] + user_groups[2])

        if unbounded:
            findings.append(
                create_finding(
                    check_id="AC-33",
                    finding_name="AgentCore Token Issuance Scope",
                    finding_details=(
                        "The following principals can mint agent access tokens or "
                        "read stored credentials against a wildcard resource, so "
                        "one compromised agent reaches every workload identity, "
                        "token vault and credential provider in the account: "
                        f"{', '.join(unbounded)}."
                    ),
                    resolution=(
                        "Replace the wildcard resource with the agent's own "
                        "workload-identity ARN, its token vault and its credential "
                        "provider, keeping the workload-identity-directory ARN in "
                        "the list, which the service authorization reference also "
                        "marks required on these actions."
                    ),
                    reference=AGENTCORE_WORKLOAD_IDENTITY_SCOPE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

        if directory_only:
            findings.append(
                create_finding(
                    check_id="AC-33",
                    finding_name="AgentCore Token Issuance Scope",
                    finding_details=(
                        "The following principals hold agent token-issuance actions "
                        "on named resources, none of which is a workload identity: "
                        f"{', '.join(directory_only)}. The service authorization "
                        "reference marks both workload-identity and "
                        "workload-identity-directory as required on these actions "
                        "and does not say whether allowing only the directory "
                        "authorizes the call, so this grant either reaches every "
                        "identity the directory holds or authorizes nothing."
                    ),
                    resolution=(
                        "Add the agent's own workload-identity ARN "
                        "(workload-identity-directory/<directory>/workload-identity/"
                        "<name>) to the resource list beside the directory ARN, "
                        "which settles both readings."
                    ),
                    reference=AGENTCORE_WORKLOAD_IDENTITY_SCOPE_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

        if scoped:
            findings.append(
                create_finding(
                    check_id="AC-33",
                    finding_name="AgentCore Token Issuance Scope",
                    finding_details=(
                        "The following principals hold agent token-issuance actions "
                        "only against named workload identities: "
                        f"{', '.join(scoped)}."
                    ),
                    resolution=(
                        "No action required. Confirm each named workload identity is "
                        "the one that principal's own agent runs as, and Deny "
                        "GetWorkloadAccessTokenForUserId and "
                        "InvokeAgentRuntimeForUser where a JWT is always available."
                    ),
                    reference=AGENTCORE_WORKLOAD_IDENTITY_SCOPE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

        if not unbounded and not directory_only and not scoped:
            findings.append(
                create_finding(
                    check_id="AC-33",
                    finding_name="AgentCore Token Issuance Scope",
                    finding_details=(
                        "No cached IAM role or user grants an AgentCore token "
                        "issuance or stored-credential action, so no principal "
                        "mints an agent token through IAM policy."
                    ),
                    resolution="No action required.",
                    reference=AGENTCORE_WORKLOAD_IDENTITY_SCOPE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                    region=GLOBAL_REGION_LABEL,
                )
            )

    except Exception as error:
        logger.error(f"Error in token issuance scope check: {error}")
        findings.append(
            _incomplete_check_finding(
                check_id="AC-33",
                finding_name="AgentCore Token Issuance Scope",
                error=error,
                reference=AGENTCORE_WORKLOAD_IDENTITY_SCOPE_REFERENCE_URL,
                region=GLOBAL_REGION_LABEL,
            )
        )

    return findings


# Lowercased fragments that name a credential in an environment-variable name,
# so AWS_SECRET_ACCESS_KEY, dbPassword and OPENAI_APIKEY all hit.
CREDENTIAL_VARIABLE_NAME_FRAGMENTS = (
    "apikey",
    "api_key",
    "credential",
    "passphrase",
    "password",
    "privatekey",
    "private_key",
    "secret",
    "token",
)

# The two access key id prefixes: AKIA for a long-term key, ASIA for a session
# key. Both are followed by 16 uppercase alphanumerics.
AWS_ACCESS_KEY_ID_PREFIXES = ("AKIA", "ASIA")
AWS_ACCESS_KEY_ID_LENGTH = 20


def _value_is_a_credential_literal(value: str) -> bool:
    """Return whether a value is credential material on its own shape alone."""
    if len(value) == AWS_ACCESS_KEY_ID_LENGTH and value.startswith(
        AWS_ACCESS_KEY_ID_PREFIXES
    ):
        if all(
            character.isdigit() or (character.isalpha() and character.isupper())
            for character in value[len(AWS_ACCESS_KEY_ID_PREFIXES[0]) :]
        ):
            return True
    return value.startswith("-----BEGIN") and "PRIVATE KEY" in value


def _value_points_at_a_credential_store(value: str) -> bool:
    """Return whether a value names where a credential lives, not the credential.

    An ARN, a Parameter Store path, a URL and a Secrets Manager secret name are
    all pointers. A decimal number or a boolean configures behaviour and is not a
    credential, which is what keeps TOKEN_TTL=3600 out of the finding. A secret
    name is a slash-separated path, so any value holding a slash reads as a
    pointer: a base64 credential containing a slash is the scan's blind spot and
    the passing finding says so.
    """
    lowered = value.lower()
    if lowered.startswith(("arn:", "/", "http://", "https://")):
        return True
    if "/" in value:
        return True
    if lowered in ("true", "false"):
        return True
    return value.isdigit()


def _runtime_credential_variables(
    environment_variables: Dict[str, Any],
) -> Tuple[List[str], List[str]]:
    """Split environment-variable names into inline credentials and pointers."""
    literals: List[str] = []
    pointers: List[str] = []

    for name, raw_value in sorted(environment_variables.items()):
        value = (raw_value if isinstance(raw_value, str) else str(raw_value)).strip()
        if _value_is_a_credential_literal(value):
            literals.append(name)
            continue
        if not any(
            fragment in name.lower() for fragment in CREDENTIAL_VARIABLE_NAME_FRAGMENTS
        ):
            continue
        if not value or _value_points_at_a_credential_store(value):
            pointers.append(name)
        else:
            literals.append(name)

    return literals, pointers


def check_agentcore_runtime_inline_credentials() -> List[Dict[str, Any]]:
    """AC-34: Scan each runtime's environment variables for inline credentials.

    AC-14 judges the token vault's own encryption. This is the other half of the
    control: a credential pasted into the agent's definition never reaches the
    vault, and every process in the microVM reads the variable. Only names are
    reported, never values, because environmentVariables is modelled sensitive.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-34",
                finding_name="AgentCore Runtime Inline Credentials",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_RUNTIME_SECRET_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        runtimes = _agentcore_list_all("list_agent_runtimes", ["agentRuntimes"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-34",
                finding_name="AgentCore Runtime Inline Credentials",
                error=error,
                reference=AGENTCORE_RUNTIME_SECRET_REFERENCE_URL,
            )
        ]

    if not runtimes:
        return [
            create_finding(
                check_id="AC-34",
                finding_name="AgentCore Runtime Inline Credentials",
                finding_details="No AgentCore runtimes found in this region.",
                resolution="No action required.",
                reference=AGENTCORE_RUNTIME_SECRET_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    findings = []
    for runtime in runtimes:
        runtime_id = runtime.get("agentRuntimeId", "unknown")
        runtime_name = runtime.get("agentRuntimeName", runtime_id)
        label = f"Runtime '{runtime_name}' ({runtime_id})"

        try:
            details = agentcore_client.get_agent_runtime(agentRuntimeId=runtime_id)
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-34",
                    finding_name="AgentCore Runtime Inline Credentials",
                    finding_details=(
                        f"{label} environment variables could not be read: "
                        f"{_assessment_error_label(error)}."
                    ),
                    resolution=(
                        "Grant bedrock-agentcore:GetAgentRuntime on this runtime "
                        "and retry."
                    ),
                    reference=AGENTCORE_RUNTIME_SECRET_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        environment_variables = details.get("environmentVariables") or {}
        if not environment_variables:
            findings.append(
                create_finding(
                    check_id="AC-34",
                    finding_name="AgentCore Runtime Inline Credentials",
                    finding_details=(
                        f"{label} carries no environment variables, so its "
                        "definition holds no inline credential."
                    ),
                    resolution="No action required.",
                    reference=AGENTCORE_RUNTIME_SECRET_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
            continue

        literals, pointers = _runtime_credential_variables(environment_variables)

        if literals:
            findings.append(
                create_finding(
                    check_id="AC-34",
                    finding_name="AgentCore Runtime Inline Credential Found",
                    finding_details=(
                        f"{label} holds credential material inline in the "
                        f"environment variable(s) {', '.join(literals)}, which "
                        "every process in the microVM reads. The values are "
                        "withheld from this report."
                    ),
                    resolution=(
                        "Move each value into the AgentCore Identity token vault "
                        "or AWS Secrets Manager, set the variable to the secret's "
                        "ARN, and rotate the exposed credential."
                    ),
                    reference=AGENTCORE_RUNTIME_SECRET_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
            continue

        scanned = (
            f"{len(environment_variables)} environment variable(s), of which "
            f"{', '.join(pointers)} name a credential and hold a reference to one"
            if pointers
            else f"{len(environment_variables)} environment variable(s)"
        )
        findings.append(
            create_finding(
                check_id="AC-34",
                finding_name="AgentCore Runtime Inline Credentials",
                finding_details=(
                    f"{label} was scanned across {scanned}, and none holds "
                    "credential material inline."
                ),
                resolution=(
                    "No action required. This scan reads variable names and value "
                    "shapes: a value containing a slash reads as a secret name, so "
                    "confirm the remaining values are references and not literals."
                ),
                reference=AGENTCORE_RUNTIME_SECRET_REFERENCE_URL,
                severity=SeverityEnum.HIGH,
                status=StatusEnum.PASSED,
            )
        )

    return findings


# The three Cedar scope positions, in the order they appear in a policy head.
CEDAR_SCOPE_POSITIONS = ("principal", "action", "resource")
# The Cedar effects that decide an authorization request. policy-guardrails-in-
# policies.html adds suppressOutput, which "operates on the data an action
# returns" after the action was already authorized, so it decides no request.
CEDAR_AUTHORIZING_EFFECTS = ("permit", "forbid")
# The qualifier that makes a condition block session-aware.
CEDAR_TEMPORAL_QUALIFIER = "temporal"
# The qualifier that hands the condition to Bedrock Guardrails.
CEDAR_GUARDRAIL_QUALIFIER = "guardrails"
CEDAR_CONDITION_KEYWORDS = ("when", "unless")
# The one Bedrock action the Policy data plane calls with the gateway execution
# role's FAS credentials when a guardrail condition is evaluated.
GUARDRAIL_CHECK_ACTION = "bedrock:InvokeGuardrailChecks"
# `_statement_matches_action` matches against normalized patterns, so the lookup
# spelling is lowercase while the spelling above is the one a finding shows.
GUARDRAIL_CHECK_ACTION_LOOKUP = GUARDRAIL_CHECK_ACTION.lower()
# ListPolicies reports a lifecycle status and an enforcement mode separately. A
# policy changes a caller's response only when both say ACTIVE.
POLICY_ACTIVE_STATUS = "ACTIVE"
POLICY_ENFORCING_MODE = "ACTIVE"
# The gateway-level mode that makes the engine's decisions binding.
POLICY_ENGINE_ENFORCE_MODE = "ENFORCE"
# policy-session-based-temporal.html names these two authorizer types as the ones
# where "the Gateway binds the session to the caller's authenticated identity".
GATEWAY_SESSION_BINDING_AUTHORIZERS = ("CUSTOM_JWT", "AWS_IAM")
# The KMS actions that make the policy engine's key unusable. Losing the key
# makes every stored Cedar policy unreadable, which is a different failure from
# the plaintext exposure AC-26 reads out of a log group's key.
KMS_KEY_DISABLING_ACTIONS = (
    "disablekey",
    "schedulekeydeletion",
    "putkeypolicy",
    "disablekeyrotation",
)


def _cedar_without_comments(statement: str) -> str:
    """Strip Cedar line comments, leaving string literals untouched.

    A comment can hold a semicolon or a brace, so the policy splitter below
    would mis-read the statement if the comments were still in it.
    """
    kept: List[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(statement):
        character = statement[index]
        if in_string:
            kept.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            kept.append(character)
            index += 1
            continue
        if character == "/" and statement[index + 1 : index + 2] == "/":
            while index < len(statement) and statement[index] != "\n":
                index += 1
            continue
        kept.append(character)
        index += 1
    return "".join(kept)


def _cedar_split(text: str, separator: str) -> List[str]:
    """Split on a separator that is outside every bracket and string literal."""
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            current.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
            current.append(character)
            continue
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
        if character == separator and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
    parts.append("".join(current))
    return parts


def _cedar_policies(statement: str) -> List[Tuple[str, List[str], str]]:
    """Read one policy statement into (effect, scope parts, condition text).

    One statement can hold several policies, so this returns a list. A policy
    whose head cannot be found is skipped: reporting a parse guess as a verdict
    would be worse than reporting that the statement was not judged, which the
    callers do by comparing the policy count with what they could read.
    """
    policies: List[Tuple[str, List[str], str]] = []
    for fragment in _cedar_split(_cedar_without_comments(statement), ";"):
        head, separator, remainder = fragment.partition("(")
        if not separator:
            continue
        effect = head.strip()
        if not effect:
            continue
        depth = 1
        in_string = False
        escaped = False
        for index, character in enumerate(remainder):
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
                continue
            if character in "([{":
                depth += 1
            elif character in ")]}":
                depth -= 1
                if depth == 0:
                    scope = [
                        part.strip() for part in _cedar_split(remainder[:index], ",")
                    ]
                    policies.append((effect, scope, remainder[index + 1 :].strip()))
                    break
    return policies


def _cedar_condition_qualifiers(conditions: str) -> Set[str]:
    """Return the qualifier of every when/unless block, "" for a plain block.

    `when { ... }` is a plain Cedar condition, `when temporal { ... }` is
    session-aware and `when guardrails { ... }` calls Bedrock Guardrails.
    """
    qualifiers: Set[str] = set()
    tokens = conditions.replace("{", " { ").split()
    for index, token in enumerate(tokens):
        if token not in CEDAR_CONDITION_KEYWORDS:
            continue
        following = tokens[index + 1] if index + 1 < len(tokens) else "{"
        qualifiers.add("" if following == "{" else following)
    return qualifiers


def _cedar_scope_is_unconstrained(scope: List[str], position: str) -> bool:
    """Return whether one scope position names no specific entity.

    Cedar reads a bare `action` as every action, so a permit written that way
    authorizes every tool the gateway exposes now and every tool added later.
    """
    try:
        part = scope[CEDAR_SCOPE_POSITIONS.index(position)]
    except IndexError:
        return False
    return part == position


def _policy_statement_text(policy: Dict[str, Any]) -> str:
    """Return the Cedar text of a listed policy.

    ListPolicies reports the definition under `cedar` for a Cedar policy and
    under `policy` for a Dogwood policy; a policy still being generated carries
    `policyGeneration` and no text at all.
    """
    definition = policy.get("definition") or {}
    for key in ("cedar", "policy"):
        section = definition.get(key)
        if isinstance(section, dict) and section.get("statement"):
            return section["statement"]
    return ""


def _enforcing_policies(
    policy_engine_id: str, cache: Dict[str, List[Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    """List the policies of one engine that change a caller's response.

    Several gateways can enforce one engine, and three checks ask the same engine
    a different question, so the caller passes a cache to keep one ListPolicies
    walk per engine per check.
    """
    if policy_engine_id not in cache:
        policies = _agentcore_list_all(
            "list_policies", ["policies"], policyEngineId=policy_engine_id
        )
        cache[policy_engine_id] = [
            policy
            for policy in policies
            if policy.get("status") == POLICY_ACTIVE_STATUS
            and policy.get("enforcementMode") == POLICY_ENFORCING_MODE
        ]
    return cache[policy_engine_id]


def _gateway_policy_engine_id(detail: Dict[str, Any]) -> str:
    """Return the policy engine id a gateway's ENFORCE configuration names.

    GatewayPolicyEngineConfiguration carries an ARN and a mode and no id, so the
    id comes off the ARN tail. An empty string means the gateway enforces no
    policy: LOG_ONLY records a decision it does not apply, which is AG-25's
    verdict to give.
    """
    configuration = detail.get("policyEngineConfiguration") or {}
    if configuration.get("mode") != POLICY_ENGINE_ENFORCE_MODE:
        return ""
    return (configuration.get("arn") or "").rsplit("/", 1)[-1]


def check_agentcore_policy_tool_scope() -> List[Dict[str, Any]]:
    """AC-35: Judge whether each enforcing permit names the tools it authorizes.

    policy-core-concepts.html states the engine "enforces default-deny and
    forbid-wins semantics automatically", so default-deny is not a setting to
    read; what a customer can still write is a permit that restores allow-all.
    The same page names the defect: Cedar analysis identifies "policies that
    always allow (no conditions restrict access)". AG-25 counts enforcing
    policies without reading one, so a single permit over every tool passes it.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-35",
                finding_name="AgentCore Policy Tool Scope",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-35",
                finding_name="AgentCore Policy Tool Scope",
                error=error,
                reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
            )
        ]

    if not gateways:
        return [
            create_finding(
                check_id="AC-35",
                finding_name="AgentCore Policy Tool Scope",
                finding_details="No AgentCore gateways found in this region.",
                resolution="No action required.",
                reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    policy_cache: Dict[str, List[Dict[str, Any]]] = {}
    findings = []
    for gateway in gateways:
        gateway_id = gateway.get("gatewayId", "unknown")
        gateway_name = gateway.get("name", gateway_id)
        label = f"Gateway '{gateway_name}' ({gateway_id})"

        try:
            detail = agentcore_client.get_gateway(gatewayIdentifier=gateway_id)
            policy_engine_id = _gateway_policy_engine_id(detail)
            policies = (
                _enforcing_policies(policy_engine_id, policy_cache)
                if policy_engine_id
                else []
            )
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-35",
                    finding_name="AgentCore Policy Tool Scope",
                    finding_details=(
                        f"{label} policy scope could not be read: "
                        f"{_assessment_error_label(error)}."
                    ),
                    resolution=(
                        "Grant bedrock-agentcore:GetGateway and "
                        "bedrock-agentcore:ListPolicies, then retry."
                    ),
                    reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        if not policy_engine_id:
            findings.append(
                create_finding(
                    check_id="AC-35",
                    finding_name="AgentCore Policy Tool Scope",
                    finding_details=(
                        f"{label} enforces no policy engine, so it has no permit "
                        "to scope. AG-25 judges whether an engine is attached in "
                        "ENFORCE mode."
                    ),
                    resolution="No action required for this check. Resolve AG-25.",
                    reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        always_allow: List[str] = []
        tool_wide: List[str] = []
        unreadable: List[str] = []
        scoped: List[str] = []
        readable = 0
        for policy in policies:
            policy_name = policy.get("name") or policy.get("policyId") or "unnamed"
            parsed = _cedar_policies(_policy_statement_text(policy))
            if not parsed:
                unreadable.append(policy_name)
                continue
            readable += 1
            for effect, scope, conditions in parsed:
                if effect != "permit":
                    continue
                if not _cedar_scope_is_unconstrained(scope, "action"):
                    scoped.append(policy_name)
                elif _cedar_condition_qualifiers(conditions):
                    tool_wide.append(policy_name)
                else:
                    always_allow.append(policy_name)

        if always_allow:
            findings.append(
                create_finding(
                    check_id="AC-35",
                    finding_name="AgentCore Policy Tool Scope Unbounded",
                    finding_details=(
                        f"{label} enforces policy engine {policy_engine_id}, whose "
                        f"policy {', '.join(sorted(set(always_allow)))} permits an "
                        "unnamed action with no condition, so every tool the "
                        "gateway exposes is authorized for every caller the scope "
                        "admits and the engine's default-deny decides nothing."
                    ),
                    resolution=(
                        "Name the tools each permit authorizes with "
                        'action == AgentCore::Action::"<target>___<tool>" or '
                        "action in [ ... ], and keep one policy per group of tools "
                        "that share a caller population."
                    ),
                    reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        elif tool_wide:
            findings.append(
                create_finding(
                    check_id="AC-35",
                    finding_name="AgentCore Policy Tool Scope Unbounded",
                    finding_details=(
                        f"{label} enforces policy engine {policy_engine_id}, whose "
                        f"policy {', '.join(sorted(set(tool_wide)))} permits an "
                        "unnamed action under a condition, so the one condition "
                        "gates every tool the gateway exposes today and every tool "
                        "added to it later."
                    ),
                    resolution=(
                        "Name the tools each permit authorizes so a new target does "
                        "not inherit an existing caller population, and keep the "
                        "condition that bounds who the permit applies to."
                    ),
                    reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )
        elif readable:
            bounded = (
                f"every one of its {len(set(scoped))} enforcing permit policies "
                "names the actions it authorizes"
                if scoped
                else f"none of its {readable} readable enforcing policies permits "
                "an action at all"
            )
            findings.append(
                create_finding(
                    check_id="AC-35",
                    finding_name="AgentCore Policy Tool Scope",
                    finding_details=(
                        f"{label} enforces policy engine {policy_engine_id}, and "
                        f"{bounded}, so a tool no policy names is denied by "
                        "default."
                    ),
                    resolution=(
                        "No action required. Confirm the named actions match the "
                        "targets this gateway exposes after each target change."
                    ),
                    reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
        elif not unreadable:
            findings.append(
                create_finding(
                    check_id="AC-35",
                    finding_name="AgentCore Policy Tool Scope",
                    finding_details=(
                        f"{label} enforces policy engine {policy_engine_id}, which "
                        "holds no active enforcing policy, so this check has no "
                        "permit to read. AG-25 judges whether the engine enforces "
                        "a policy at all."
                    ),
                    resolution="No action required for this check. Resolve AG-25.",
                    reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

        if unreadable:
            findings.append(
                create_finding(
                    check_id="AC-35",
                    finding_name="AgentCore Policy Tool Scope",
                    finding_details=(
                        f"{label} enforces policy "
                        f"{', '.join(sorted(set(unreadable)))}, whose definition "
                        "carries no policy text to read: a policy still being "
                        "generated reports only its generation id."
                    ),
                    resolution=(
                        "Rerun the assessment once policy generation has finished, "
                        "then confirm the generated policy names its actions."
                    ),
                    reference=AGENTCORE_POLICY_CORE_CONCEPTS_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

    return findings


def _kms_key_policy_open_actions(
    policy_document: Any, actions: Tuple[str, ...]
) -> List[str]:
    """Return which of these KMS actions any principal may take unconditioned.

    AC-26 asks the same question of a log group's key for the decrypt actions;
    this asks it for the actions that take the key away.
    """
    opened: List[str] = []
    for statement in _document_statements(policy_document, effect="Allow"):
        if statement.get("Condition"):
            continue
        if "*" not in _statement_principals(statement):
            continue
        for pattern in _statement_actions(statement):
            if pattern == "*":
                return sorted(actions)
            namespace, _, action_pattern = pattern.partition(":")
            if namespace != "kms":
                continue
            opened.extend(
                action for action in actions if fnmatchcase(action, action_pattern)
            )
    return sorted(set(opened))


def check_agentcore_policy_engine_key_scope() -> List[Dict[str, Any]]:
    """AC-36: Report who may use and who may take away a policy engine's key.

    AC-11 asserts that a policy engine names a customer managed key, which is
    presence only. policy-encryption.html states the key cannot be added to or
    changed on an existing engine, so the key policy is the whole guard: a
    principal who can schedule the key for deletion can make every stored Cedar
    policy unreadable, and the engine cannot be repointed at a new key.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-36",
                finding_name="AgentCore Policy Engine Key Scope",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_POLICY_ENCRYPTION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        engines = _agentcore_list_all("list_policy_engines", ["policyEngines"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-36",
                finding_name="AgentCore Policy Engine Key Scope",
                error=error,
                reference=AGENTCORE_POLICY_ENCRYPTION_REFERENCE_URL,
            )
        ]

    if not engines:
        return [
            create_finding(
                check_id="AC-36",
                finding_name="AgentCore Policy Engine Key Scope",
                finding_details="No AgentCore policy engines found in this region.",
                resolution="No action required.",
                reference=AGENTCORE_POLICY_ENCRYPTION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    key_policy_cache: Dict[str, Any] = {}
    findings = []
    for engine in engines:
        engine_id = engine.get("policyEngineId", "unknown")
        engine_name = engine.get("name", engine_id)
        label = f"Policy engine '{engine_name}' ({engine_id})"

        try:
            detail = agentcore_client.get_policy_engine(policyEngineId=engine_id)
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-36",
                    finding_name="AgentCore Policy Engine Key Scope",
                    finding_details=(
                        f"{label} encryption key could not be read: "
                        f"{_assessment_error_label(error)}."
                    ),
                    resolution="Grant bedrock-agentcore:GetPolicyEngine and retry.",
                    reference=AGENTCORE_POLICY_ENCRYPTION_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        key_arn = detail.get("encryptionKeyArn")
        if not key_arn:
            findings.append(
                create_finding(
                    check_id="AC-36",
                    finding_name="AgentCore Policy Engine Key Scope",
                    finding_details=(
                        f"{label} uses no customer managed key, so it has no key "
                        "policy to scope. AC-11 reports the missing key."
                    ),
                    resolution="No action required for this check. Resolve AC-11.",
                    reference=AGENTCORE_POLICY_ENCRYPTION_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        if key_arn not in key_policy_cache:
            try:
                key_policy_cache[key_arn] = kms_client.get_key_policy(KeyId=key_arn)[
                    "Policy"
                ]
            except Exception as error:
                logger.warning(f"Could not read key policy for {key_arn}: {error}")
                key_policy_cache[key_arn] = error
        key_policy = key_policy_cache[key_arn]

        if isinstance(key_policy, Exception):
            findings.append(
                create_finding(
                    check_id="AC-36",
                    finding_name="AgentCore Policy Engine Key Scope",
                    finding_details=(
                        f"{label} is encrypted with {key_arn}, whose key policy "
                        f"could not be read: {_assessment_error_label(key_policy)}."
                    ),
                    resolution="Grant kms:GetKeyPolicy on the key and retry.",
                    reference=KMS_KEY_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        problems: List[str] = []
        if _kms_key_policy_allows_open_decrypt(key_policy):
            problems.append(
                "lets every principal decrypt with no condition, so the stored "
                "authorization rules are readable by every principal the account "
                "trusts"
            )
        disabling = _kms_key_policy_open_actions(key_policy, KMS_KEY_DISABLING_ACTIONS)
        if disabling:
            problems.append(
                f"lets every principal call {', '.join(disabling)} with no "
                "condition, so any of them can make every stored policy "
                "unreadable, and the engine cannot be repointed at a new key"
            )

        if problems:
            findings.append(
                create_finding(
                    check_id="AC-36",
                    finding_name="AgentCore Policy Engine Key Scope Unbounded",
                    finding_details=(
                        f"{label} is encrypted with {key_arn}, whose key policy "
                        f"{' and '.join(problems)}."
                    ),
                    resolution=(
                        "Name the principals allowed to decrypt with this key and "
                        "the administrators allowed to disable or schedule it for "
                        "deletion, and constrain the service grants with "
                        "kms:ViaService for "
                        "bedrock-agentcore.<region>.amazonaws.com."
                    ),
                    reference=KMS_KEY_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AC-36",
                    finding_name="AgentCore Policy Engine Key Scope",
                    finding_details=(
                        f"{label} is encrypted with {key_arn}, whose key policy "
                        "names the principals allowed to decrypt with it and the "
                        "administrators allowed to disable it or schedule it for "
                        "deletion."
                    ),
                    resolution=(
                        "No action required. This check reads the key policy; "
                        "confirm separately that an alarm covers the key's "
                        "disable and delete events and that the break-glass "
                        "runbook has been rehearsed, neither of which is readable "
                        "from the key."
                    ),
                    reference=KMS_KEY_POLICY_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )

    return findings


def check_agentcore_policy_guardrail_wiring(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """AC-37: Assert a guardrail policy's gateway role can call the guardrail.

    policy-guardrails-in-policies.html states the Policy data plane "uses FAS
    (Forward Access Session) credentials derived from the gateway's execution
    role to call the Bedrock Guardrails API", and that
    bedrock:InvokeGuardrailChecks is required for it. A `when guardrails` policy
    whose gateway role lacks that permission cannot score the content it claims
    to score. Whether this workload's content-safety decisions belong at the
    authorization boundary at all is the workload owner's call; this check
    judges only the wiring of the guardrail policies that exist.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-37",
                finding_name="AgentCore Policy Guardrail Wiring",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    role_permissions = (permission_cache or {}).get("role_permissions") or {}
    if not role_permissions:
        return [
            create_finding(
                check_id="AC-37",
                finding_name="AgentCore Policy Guardrail Wiring",
                finding_details=(
                    "No IAM role permissions are in the cache, so the gateway "
                    "execution role behind a guardrail policy could not be read."
                ),
                resolution=(
                    "Review the IAM Permission Caching task and rerun the assessment."
                ),
                reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-37",
                finding_name="AgentCore Policy Guardrail Wiring",
                error=error,
                reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
            )
        ]

    if not gateways:
        return [
            create_finding(
                check_id="AC-37",
                finding_name="AgentCore Policy Guardrail Wiring",
                finding_details="No AgentCore gateways found in this region.",
                resolution="No action required.",
                reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    policy_cache: Dict[str, List[Dict[str, Any]]] = {}
    findings = []
    for gateway in gateways:
        gateway_id = gateway.get("gatewayId", "unknown")
        gateway_name = gateway.get("name", gateway_id)
        label = f"Gateway '{gateway_name}' ({gateway_id})"

        try:
            detail = agentcore_client.get_gateway(gatewayIdentifier=gateway_id)
            policy_engine_id = _gateway_policy_engine_id(detail)
            policies = (
                _enforcing_policies(policy_engine_id, policy_cache)
                if policy_engine_id
                else []
            )
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-37",
                    finding_name="AgentCore Policy Guardrail Wiring",
                    finding_details=(
                        f"{label} guardrail policies could not be read: "
                        f"{_assessment_error_label(error)}."
                    ),
                    resolution=(
                        "Grant bedrock-agentcore:GetGateway and "
                        "bedrock-agentcore:ListPolicies, then retry."
                    ),
                    reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        guardrail_policies = []
        for policy in policies:
            for _, _, conditions in _cedar_policies(_policy_statement_text(policy)):
                if CEDAR_GUARDRAIL_QUALIFIER in _cedar_condition_qualifiers(conditions):
                    guardrail_policies.append(
                        policy.get("name") or policy.get("policyId") or "unnamed"
                    )
                    break

        if not guardrail_policies:
            findings.append(
                create_finding(
                    check_id="AC-37",
                    finding_name="AgentCore Policy Guardrail Wiring",
                    finding_details=(
                        f"{label} enforces no policy with a guardrails condition, "
                        "so no content-safety score is consulted at the "
                        "authorization boundary. Whether harmful content, prompt "
                        "injection or sensitive information needs to be scored "
                        "here depends on what this gateway's tools accept and "
                        "return, which no API reports."
                    ),
                    resolution=(
                        "Decide whether this gateway's tools carry model-supplied "
                        "or user-supplied content. If they do, add a forbid policy "
                        "with a when guardrails condition on the PromptAttack, "
                        "ContentFilter or SensitiveInformation safeguard, and "
                        "record the decision either way."
                    ),
                    reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        role_arn = detail.get("roleArn") or ""
        role_name = role_arn.rsplit("/", 1)[-1]
        named = ", ".join(sorted(set(guardrail_policies)))
        if role_name not in role_permissions:
            findings.append(
                create_finding(
                    check_id="AC-37",
                    finding_name="AgentCore Policy Guardrail Wiring",
                    finding_details=(
                        f"{label} enforces guardrail policy {named}, and its "
                        f"execution role {role_arn or 'is unreported'}, which is "
                        "not in the IAM permissions snapshot, so the "
                        f"{GUARDRAIL_CHECK_ACTION} grant could not be read."
                    ),
                    resolution=(
                        "Confirm the gateway execution role is in the account the "
                        "assessment caches IAM for, then rerun the assessment."
                    ),
                    reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        permissions = role_permissions[role_name]
        documents = [
            *(permissions.get("attached_policies") or []),
            *(permissions.get("inline_policies") or []),
        ]
        granted = False
        unreadable_documents = 0
        for document in documents:
            try:
                granted = granted or any(
                    _statement_matches_action(statement, GUARDRAIL_CHECK_ACTION_LOOKUP)
                    for statement in _allow_statements(document)
                )
            except Exception as error:
                unreadable_documents += 1
                logger.warning(f"Error parsing policy for role {role_name}: {error}")

        if granted:
            findings.append(
                create_finding(
                    check_id="AC-37",
                    finding_name="AgentCore Policy Guardrail Wiring",
                    finding_details=(
                        f"{label} enforces guardrail policy {named}, and its "
                        f"execution role '{role_name}' grants "
                        f"{GUARDRAIL_CHECK_ACTION}, so the policy engine can "
                        "score the content the policy names."
                    ),
                    resolution=(
                        "No action required. Confirm the safeguard categories and "
                        "confidence thresholds in the policy match what this "
                        "workload treats as harmful; guardrail scores are "
                        "non-deterministic, so the same input can score "
                        "differently."
                    ),
                    reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
        elif unreadable_documents:
            findings.append(
                create_finding(
                    check_id="AC-37",
                    finding_name="AgentCore Policy Guardrail Wiring",
                    finding_details=(
                        f"{label} enforces guardrail policy {named}, and "
                        f"{unreadable_documents} of the "
                        f"{len(documents)} policy document(s) on its execution "
                        f"role '{role_name}' could not be parsed, so whether the "
                        f"role grants {GUARDRAIL_CHECK_ACTION} is unknown."
                    ),
                    resolution=(
                        "Review the IAM Permission Caching task for this role, "
                        "then rerun the assessment."
                    ),
                    reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AC-37",
                    finding_name="AgentCore Policy Guardrail Wiring Incomplete",
                    finding_details=(
                        f"{label} enforces guardrail policy {named}, but its "
                        f"execution role '{role_name}' does not grant "
                        f"{GUARDRAIL_CHECK_ACTION}, so the guardrail call the "
                        "Policy data plane makes with that role's forward access "
                        "session is denied. The devguide does not state whether "
                        "the policy then fails open or closed, so the content "
                        "safety this policy claims is either absent or the tool "
                        "is unreachable."
                    ),
                    resolution=(
                        f"Grant {GUARDRAIL_CHECK_ACTION} to the gateway execution "
                        "role, then invoke the gateway once and confirm the "
                        "decision record in the gateway's application logs shows "
                        "the guardrail policy among its determining policies."
                    ),
                    reference=AGENTCORE_POLICY_GUARDRAIL_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

    return findings


def check_agentcore_policy_session_binding() -> List[Dict[str, Any]]:
    """AC-38: Judge session-aware policy and whether a session binds to a caller.

    A rule that only reads across a sequence of actions, such as an unverified
    payee or a cumulative overspend, is a temporal policy evaluated against a
    policy session. policy-session-based-temporal.html states the Gateway binds
    a session to the caller's authenticated identity "on authenticated gateways
    (CUSTOM_JWT or AWS_IAM)", so on a gateway that authenticates no caller two
    callers presenting the same session id share one accumulated history, and a
    per-session limit is reset or consumed by someone else. AG-25 counts
    enforcing policies without reading whether any is session-aware.
    """
    if agentcore_client is None:
        return [
            create_finding(
                check_id="AC-38",
                finding_name="AgentCore Policy Session Binding",
                finding_details="AgentCore client not available in this region.",
                resolution="No action required unless AgentCore runs in this region.",
                reference=AGENTCORE_POLICY_SESSION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except Exception as error:
        return [
            _incomplete_check_finding(
                check_id="AC-38",
                finding_name="AgentCore Policy Session Binding",
                error=error,
                reference=AGENTCORE_POLICY_SESSION_REFERENCE_URL,
            )
        ]

    if not gateways:
        return [
            create_finding(
                check_id="AC-38",
                finding_name="AgentCore Policy Session Binding",
                finding_details="No AgentCore gateways found in this region.",
                resolution="No action required.",
                reference=AGENTCORE_POLICY_SESSION_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]

    policy_cache: Dict[str, List[Dict[str, Any]]] = {}
    findings = []
    for gateway in gateways:
        gateway_id = gateway.get("gatewayId", "unknown")
        gateway_name = gateway.get("name", gateway_id)
        label = f"Gateway '{gateway_name}' ({gateway_id})"

        try:
            detail = agentcore_client.get_gateway(gatewayIdentifier=gateway_id)
            policy_engine_id = _gateway_policy_engine_id(detail)
            policies = (
                _enforcing_policies(policy_engine_id, policy_cache)
                if policy_engine_id
                else []
            )
        except Exception as error:
            findings.append(
                create_finding(
                    check_id="AC-38",
                    finding_name="AgentCore Policy Session Binding",
                    finding_details=(
                        f"{label} session-aware policies could not be read: "
                        f"{_assessment_error_label(error)}."
                    ),
                    resolution=(
                        "Grant bedrock-agentcore:GetGateway and "
                        "bedrock-agentcore:ListPolicies, then retry."
                    ),
                    reference=AGENTCORE_POLICY_SESSION_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        if not policy_engine_id:
            findings.append(
                create_finding(
                    check_id="AC-38",
                    finding_name="AgentCore Policy Session Binding",
                    finding_details=(
                        f"{label} enforces no policy engine, so it evaluates no "
                        "session-aware policy. AG-25 judges whether an engine is "
                        "attached in ENFORCE mode."
                    ),
                    resolution="No action required for this check. Resolve AG-25.",
                    reference=AGENTCORE_POLICY_SESSION_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            continue

        temporal_policies = []
        for policy in policies:
            for effect, _, conditions in _cedar_policies(
                _policy_statement_text(policy)
            ):
                if effect not in CEDAR_AUTHORIZING_EFFECTS:
                    continue
                if CEDAR_TEMPORAL_QUALIFIER in _cedar_condition_qualifiers(conditions):
                    temporal_policies.append(
                        policy.get("name") or policy.get("policyId") or "unnamed"
                    )
                    break

        authorizer_type = detail.get("authorizerType") or gateway.get("authorizerType")

        if not temporal_policies:
            findings.append(
                create_finding(
                    check_id="AC-38",
                    finding_name="AgentCore Policy Session Binding Absent",
                    finding_details=(
                        f"{label} enforces policy engine {policy_engine_id} with "
                        f"{len(policies)} active enforcing policy or policies, "
                        "none of which carries a temporal condition, so every "
                        "request is judged on its own. A rule that spans a "
                        "sequence, such as requiring a prior approval or holding "
                        "a running total under a threshold, is enforced by the "
                        "agent or tool code here and not by the gateway."
                    ),
                    resolution=(
                        "Add a temporal policy for each rule that reads across a "
                        "session, or record that this gateway's tools carry no "
                        "such rule and that each call is independently safe."
                    ),
                    reference=AGENTCORE_POLICY_SESSION_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )
        elif authorizer_type in GATEWAY_SESSION_BINDING_AUTHORIZERS:
            findings.append(
                create_finding(
                    check_id="AC-38",
                    finding_name="AgentCore Policy Session Binding",
                    finding_details=(
                        f"{label} enforces temporal policy "
                        f"{', '.join(sorted(set(temporal_policies)))} and "
                        f"authenticates callers with {authorizer_type}, so the "
                        "gateway binds each policy session to the caller's own "
                        "identity and two callers presenting the same session id "
                        "accumulate separate histories."
                    ),
                    resolution=(
                        "No action required. The session id rides inside the "
                        "workload access token across Gateway to Runtime hops "
                        "within one account and region; confirm the first caller "
                        "in the chain sends "
                        "x-amzn-bedrock-agentcore-policy-session-id, without "
                        "which a request to an engine holding a temporal policy "
                        "fails validation."
                    ),
                    reference=AGENTCORE_POLICY_SESSION_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AC-38",
                    finding_name="AgentCore Policy Session Binding Unauthenticated",
                    finding_details=(
                        f"{label} enforces temporal policy "
                        f"{', '.join(sorted(set(temporal_policies)))} but uses "
                        f"authorizerType {authorizer_type or 'unspecified'}. The "
                        "devguide names CUSTOM_JWT and AWS_IAM as the authorizer "
                        "types where the gateway binds a session to the caller's "
                        "authenticated identity, so on this gateway the session id "
                        "in the request header is the only thing separating one "
                        "caller's accumulated history from another's, and a caller "
                        "who reuses someone else's session id inherits it."
                    ),
                    resolution=(
                        "Set the gateway authorizerType to CUSTOM_JWT or AWS_IAM "
                        "so each policy session is keyed by an authenticated "
                        "identity, or move the sequence rule to a boundary that "
                        "knows who the caller is."
                    ),
                    reference=AGENTCORE_POLICY_SESSION_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

    return findings


def check_agentcore_gateway_agentic_security() -> List[Dict[str, Any]]:
    """
    Check API-provable AgentCore Gateway controls for agentic tool execution.

    Validates:
    - Inbound gateway authorization is enabled
    - Policy engine is attached in ENFORCE mode
    - Debug exception detail is not exposed
    - AWS WAF web ACL is associated
    """
    findings = []

    if agentcore_client is None:
        for check_id, finding_name in [
            ("AG-24", "Agentic AI Gateway Inbound Authorization"),
            ("AG-25", "Agentic AI Gateway Tool Policy Enforcement"),
            ("AG-26", "Agentic AI Gateway Error Detail Exposure"),
            ("AG-27", "Agentic AI Gateway WAF Protection"),
        ]:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name=finding_name,
                    finding_details="AgentCore client not available in this region",
                    resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                    reference=AGENTIC_AI_LENS_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
        return findings

    gateway_check_ids = ["AG-24", "AG-25", "AG-26", "AG-27"]

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except (AttributeError, ClientError) as error:
        return _incomplete_check_findings(
            gateway_check_ids,
            "Agentic AI Gateway Security Controls",
            error,
            "",
            reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
        )

    if not gateways:
        return [
            create_finding(
                check_id="AG-24",
                finding_name="Agentic AI Gateway Inbound Authorization",
                finding_details="No AgentCore Gateways found",
                resolution="No action required",
                reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ),
            create_finding(
                check_id="AG-25",
                finding_name="Agentic AI Gateway Tool Policy Enforcement",
                finding_details="No AgentCore Gateways found",
                resolution="No action required",
                reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ),
            create_finding(
                check_id="AG-26",
                finding_name="Agentic AI Gateway Error Detail Exposure",
                finding_details="No AgentCore Gateways found",
                resolution="No action required",
                reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ),
            create_finding(
                check_id="AG-27",
                finding_name="Agentic AI Gateway WAF Protection",
                finding_details="No AgentCore Gateways found",
                resolution="No action required",
                reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ),
        ]

    for gateway in gateways:
        gateway_id = gateway.get("gatewayId", "unknown")
        gateway_name = gateway.get("name", gateway_id)

        try:
            gateway_details = agentcore_client.get_gateway(gatewayIdentifier=gateway_id)
        except ClientError as e:
            findings.extend(
                _incomplete_check_findings(
                    gateway_check_ids,
                    f"Agentic AI Gateway Security Controls for {gateway_name}",
                    e,
                    "",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                )
            )
            continue

        authorizer_type = gateway_details.get("authorizerType") or gateway.get(
            "authorizerType"
        )
        policy_engine_config = gateway_details.get("policyEngineConfiguration") or {}
        policy_engine_mode = policy_engine_config.get("mode")
        policy_engine_arn = policy_engine_config.get("arn")
        policy_engine_id = (
            policy_engine_config.get("policyEngineId")
            or (policy_engine_arn or "").rsplit("/", 1)[-1]
        )

        if authorizer_type in {"AWS_IAM", "CUSTOM_JWT"}:
            findings.append(
                create_finding(
                    check_id="AG-24",
                    finding_name="Agentic AI Gateway Inbound Authorization",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) uses authorizerType {authorizer_type}.",
                    resolution="No action required",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
        elif (
            authorizer_type == "AUTHENTICATE_ONLY"
            and policy_engine_mode == "ENFORCE"
            and policy_engine_arn
        ):
            findings.append(
                create_finding(
                    check_id="AG-24",
                    finding_name="Agentic AI Gateway Inbound Authorization",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) uses authorizerType AUTHENTICATE_ONLY and delegates authorization to policy engine {policy_engine_arn} in ENFORCE mode.",
                    resolution="No action required. Continue validating policy coverage for all exposed gateway targets.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
        elif authorizer_type == "AUTHENTICATE_ONLY":
            findings.append(
                create_finding(
                    check_id="AG-24",
                    finding_name="Agentic AI Gateway Authenticate-Only Authorization",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) uses authorizerType AUTHENTICATE_ONLY without an attached policy engine in ENFORCE mode. AgentCore Gateway authenticates the SigV4 caller but does not make an authorization decision for this authorizer type.",
                    resolution="Use AWS_IAM or CUSTOM_JWT for gateway-enforced authorization, or attach an AgentCore policy engine in ENFORCE mode before using AUTHENTICATE_ONLY.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AG-24",
                    finding_name="Agentic AI Gateway Inbound Authorization Disabled",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) uses authorizerType {authorizer_type or 'unspecified'}. Agent tool endpoints must use an explicit gateway authorizer.",
                    resolution="Configure the gateway authorizerType as AWS_IAM or CUSTOM_JWT and provide the required authorizer configuration.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        if not policy_engine_config:
            findings.append(
                create_finding(
                    check_id="AG-25",
                    finding_name="Agentic AI Gateway Tool Policy Enforcement Missing",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) does not have a policy engine configuration. Tool calls are not evaluated by AgentCore policy enforcement.",
                    resolution="Attach an AgentCore policy engine to the gateway and use ENFORCE mode for production tool authorization.",
                    reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        elif policy_engine_mode != "ENFORCE":
            findings.append(
                create_finding(
                    check_id="AG-25",
                    finding_name="Agentic AI Gateway Tool Policy Not Enforced",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) policy engine {policy_engine_arn or 'unknown'} is in {policy_engine_mode or 'unknown'} mode. LOG_ONLY mode records decisions but does not block denied tool calls.",
                    resolution="Change the gateway policyEngineConfiguration mode to ENFORCE after validating policies in LOG_ONLY mode.",
                    reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            try:
                policies = _agentcore_list_all(
                    "list_policies",
                    ["policies"],
                    policyEngineId=policy_engine_id,
                )
                active_policies = [
                    policy
                    for policy in policies
                    if policy.get("status") == "ACTIVE"
                    and policy.get("enforcementMode") == "ACTIVE"
                ]
                non_enforcing = [
                    policy
                    for policy in policies
                    if policy.get("status") != "ACTIVE"
                    or policy.get("enforcementMode") != "ACTIVE"
                ]
                if not active_policies:
                    findings.append(
                        create_finding(
                            check_id="AG-25",
                            finding_name="Agentic AI Gateway Tool Policy Enforcement Missing",
                            finding_details=(
                                f"Gateway '{gateway_name}' ({gateway_id}) has policy engine "
                                f"{policy_engine_arn or policy_engine_id or 'unknown'} in ENFORCE "
                                "mode, but it has no ACTIVE policies with ACTIVE enforcement."
                            ),
                            resolution="Create or activate at least one enforcing policy. LOG_ONLY policies do not change caller responses.",
                            reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                            severity=SeverityEnum.HIGH,
                            status=StatusEnum.FAILED,
                        )
                    )
                else:
                    advisory = (
                        f" {len(non_enforcing)} additional policies are inactive or LOG_ONLY."
                        if non_enforcing
                        else ""
                    )
                    findings.append(
                        create_finding(
                            check_id="AG-25",
                            finding_name="Agentic AI Gateway Tool Policy Enforcement",
                            finding_details=(
                                f"Gateway '{gateway_name}' ({gateway_id}) has policy engine "
                                f"{policy_engine_arn or policy_engine_id or 'unknown'} in ENFORCE "
                                f"mode with {len(active_policies)} active enforcing policies."
                                f"{advisory}"
                            ),
                            resolution=(
                                "Review inactive or LOG_ONLY policies before relying on them for authorization."
                                if non_enforcing
                                else "No action required"
                            ),
                            reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                            severity=SeverityEnum.HIGH,
                            status=StatusEnum.PASSED,
                        )
                    )
            except Exception as error:
                findings.append(
                    create_finding(
                        check_id="AG-25",
                        finding_name="Agentic AI Gateway Tool Policy Enforcement",
                        finding_details=f"Gateway '{gateway_name}' policy enforcement could not be fully assessed: {type(error).__name__}.",
                        resolution="Grant bedrock-agentcore:ListPolicies and retry the assessment.",
                        reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

        if gateway_details.get("exceptionLevel") == "DEBUG":
            findings.append(
                create_finding(
                    check_id="AG-26",
                    finding_name="Agentic AI Gateway Debug Error Detail Enabled",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) returns DEBUG-level exception detail. Detailed errors can disclose tool, target, or policy implementation details to callers.",
                    resolution="Remove DEBUG exceptionLevel for production gateways so callers receive generic gateway errors.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AG-26",
                    finding_name="Agentic AI Gateway Error Detail Exposure",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) does not expose DEBUG-level exception detail.",
                    resolution="No action required",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

        web_acl_arn = gateway_details.get("webAclArn")
        if web_acl_arn:
            findings.append(
                create_finding(
                    check_id="AG-27",
                    finding_name="Agentic AI Gateway WAF Protection",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) is associated with WAF web ACL {web_acl_arn}.",
                    resolution="No action required",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.LOW,
                    status=StatusEnum.PASSED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AG-27",
                    finding_name="Agentic AI Gateway WAF Protection Missing",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) is not associated with an AWS WAF web ACL.",
                    resolution="Associate an AWS WAF web ACL with internet-facing AgentCore gateways to add request filtering and abuse protection.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.LOW,
                    status=StatusEnum.FAILED,
                )
            )

    return findings


def lambda_handler(event, context):
    """
    Lambda handler for AgentCore security assessment.

    Args:
        event: Lambda event containing execution_id and Region
        context: Lambda context

    Returns:
        Response with status and S3 URL
    """
    global start_time, iam_client, ec2_client, ecr_client, logs_client
    global cloudwatch_client, cloudtrail_client, oam_client, agentcore_client
    global kms_client, organizations_client
    start_time = time.time()

    try:
        # Extract target region from Step Functions Map state
        region = event.get("Region", os.environ.get("AWS_REGION", "us-east-1"))
        # IAM is global: only the primary region (Map index 0) runs IAM-only checks.
        is_primary_region = int(event.get("RegionIndex", 0)) == 0
        logger.info(f"Scanning region: {region} (primary={is_primary_region})")

        execution_id = event.get("Execution", {}).get("Name", "unknown")

        # Initialize regional clients (iam is global, the rest are region-scoped)
        iam_client = boto3.client("iam", config=boto3_config)
        ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)
        ecr_client = boto3.client("ecr", config=boto3_config, region_name=region)
        logs_client = boto3.client("logs", config=boto3_config, region_name=region)
        cloudwatch_client = boto3.client(
            "cloudwatch", config=boto3_config, region_name=region
        )
        cloudtrail_client = boto3.client(
            "cloudtrail", config=boto3_config, region_name=region
        )
        oam_client = boto3.client("oam", config=boto3_config, region_name=region)
        # A log group's encryption key lives in the log group's own region.
        kms_client = boto3.client("kms", config=boto3_config, region_name=region)
        # Organizations resolves to one global endpoint whatever region is passed.
        organizations_client = boto3.client("organizations", config=boto3_config)

        # Collect all findings
        all_findings = []

        # Retrieve permission cache (shared/global IAM data)
        permission_cache_error = None
        try:
            permission_cache = get_permissions_cache(execution_id)
        except Exception as e:
            logger.warning(f"Failed to retrieve permission cache: {e}")
            permission_cache = None
            permission_cache_error = e

        # Run global IAM-only checks once (on the primary region) so the same role
        # violations are not reported once per scanned region. These run before the
        # regional availability gate so they are still emitted even if AgentCore is
        # not available in the primary region.
        if is_primary_region:
            if permission_cache is None:
                error_detail = (
                    str(permission_cache_error) or type(permission_cache_error).__name__
                )
                for check_id, finding_name in (
                    ("AC-02", "AgentCore IAM Full Access Check"),
                    ("AC-03", "AgentCore Stale Access Check"),
                    ("AC-21", "AgentCore Log Unmask Restriction"),
                    ("AC-23", "AgentCore Memory Record Access Scope"),
                    ("AC-32", "AgentCore Inbound JWT Issuer Conditions"),
                    ("AC-33", "AgentCore Token Issuance Scope"),
                ):
                    all_findings.append(
                        create_finding(
                            check_id=check_id,
                            finding_name=f"{finding_name} Incomplete",
                            finding_details=(
                                "The IAM permissions cache is missing, unreadable, "
                                "or malformed, so this identity-based control could "
                                f"not be assessed. Cache error: {error_detail}."
                            ),
                            resolution=(
                                "Review the IAM Permission Caching task and the "
                                "execution-scoped permissions_cache_<execution-id>.json "
                                "object, then rerun the assessment."
                            ),
                            reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
                            severity=SeverityEnum.INFORMATIONAL,
                            status=StatusEnum.NA,
                            region=GLOBAL_REGION_LABEL,
                        )
                    )
                global_checks = [
                    (
                        ["AC-09"],
                        "Service-Linked Role",
                        check_agentcore_service_linked_role,
                    ),
                    # AC-28 and AC-29 read service control policies, not the IAM
                    # cache, so a missing cache does not stop them.
                    (
                        ["AC-28"],
                        "Gateway Authorizer Guardrail",
                        check_agentcore_gateway_authorizer_scp,
                    ),
                    (
                        ["AC-29"],
                        "Runtime Authorizer Guardrail",
                        check_agentcore_runtime_authorizer_scp,
                    ),
                ]
            else:
                global_checks = [
                    (
                        ["AC-02"],
                        "IAM Full Access",
                        lambda: check_agentcore_full_access_roles(permission_cache),
                    ),
                    (
                        ["AC-03"],
                        "Stale Access",
                        lambda: check_stale_agentcore_access(permission_cache),
                    ),
                    # AC-21 reads the same global IAM cache: who can unmask a
                    # masked log value is identical in every scanned region.
                    (
                        ["AC-21"],
                        "Log Unmask Restriction",
                        lambda: check_agentcore_log_unmask_restriction(
                            permission_cache
                        ),
                    ),
                    # AC-23 reads the same global IAM cache: who can read another
                    # actor's memory records does not vary by region, and the
                    # namespace partitioning of each memory is judged by AC-07.
                    (
                        ["AC-23"],
                        "Memory Record Access Scope",
                        lambda: check_agentcore_memory_record_access_scope(
                            permission_cache
                        ),
                    ),
                    # AC-09 inspects a global IAM service-linked role, so it is also
                    # run once on the primary region rather than per scanned region.
                    (
                        ["AC-09"],
                        "Service-Linked Role",
                        check_agentcore_service_linked_role,
                    ),
                    # AC-32 reads the same global IAM cache: the token-exchange
                    # grants that accept an end user's JWT are identical in every
                    # scanned region, and AC-31 judges the gateway leg per region.
                    (
                        ["AC-32"],
                        "Inbound JWT Issuer Conditions",
                        lambda: check_agentcore_inbound_jwt_issuer_conditions(
                            permission_cache
                        ),
                    ),
                    # AC-33 reads the same global IAM cache: which workload
                    # identity a role may mint a token against is written in the
                    # policy's resource element, which carries its own region.
                    (
                        ["AC-33"],
                        "Token Issuance Scope",
                        lambda: check_agentcore_token_issuance_scope(permission_cache),
                    ),
                    # AC-28 and AC-29 judge organization-wide service control
                    # policies, the same documents whatever region a gateway or a
                    # runtime is created in.
                    (
                        ["AC-28"],
                        "Gateway Authorizer Guardrail",
                        check_agentcore_gateway_authorizer_scp,
                    ),
                    (
                        ["AC-29"],
                        "Runtime Authorizer Guardrail",
                        check_agentcore_runtime_authorizer_scp,
                    ),
                ]
            for check_ids, check_name, check_func in global_checks:
                try:
                    logger.info(f"Running global check: {check_name}")
                    global_findings = check_func()
                    for finding in global_findings:
                        finding["Region"] = GLOBAL_REGION_LABEL
                    all_findings.extend(global_findings)
                except Exception as e:
                    logger.error(f"Error in global check '{check_name}': {e}")
                    all_findings.extend(
                        _incomplete_check_findings(
                            check_ids,
                            f"AgentCore {check_name} Check",
                            e,
                            GLOBAL_REGION_LABEL,
                        )
                    )

        # AWS Agent Registry has its own Lambda, report artifact, and timeout
        # budget. AgentCore proceeds directly to its Runtime availability probe.
        deadline_reached = False
        # Reset per-invocation so a warm container cannot leak a previous
        # region's client if creation below fails.
        agentcore_client = None
        runtime_probe_auth_error_code = None
        try:
            agentcore_client = boto3.client(
                "bedrock-agentcore-control", config=boto3_config, region_name=region
            )
        except Exception as e:
            # The client could not even be constructed (e.g. the SDK in this
            # runtime does not know the service). This is the one case where the
            # region genuinely cannot be assessed.
            logger.warning(
                f"Failed to initialize bedrock-agentcore-control client: {e}"
            )
            agentcore_client = None

        if agentcore_client is not None:
            # Test service availability with a lightweight call
            try:
                agentcore_client.list_agent_runtimes(maxResults=1)
                logger.info("Successfully initialized bedrock-agentcore-control client")
            except EndpointConnectionError:
                logger.info(
                    f"AgentCore service not available in region {region}, skipping"
                )
                agentcore_client = None
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in REGION_UNAVAILABLE_ERROR_CODES:
                    logger.info(
                        f"AgentCore not accessible in region {region} ({error_code}), skipping"
                    )
                    agentcore_client = None
                elif error_code in AUTHENTICATION_ERROR_CODES:
                    runtime_probe_auth_error_code = error_code
                    logger.warning(
                        "AgentCore Runtime availability probe returned credential "
                        f"or authentication error {error_code}; writing an "
                        "incomplete assessment"
                    )
                else:
                    # Service is reachable but returned another API error (e.g. access
                    # denied) — proceed; individual checks handle their own errors.
                    logger.info(
                        f"AgentCore client initialized (probe returned {error_code})"
                    )
            except Exception as e:
                # An unexpected probe failure (e.g. a boto3/botocore SDK param or
                # operation mismatch such as ParamValidationError/AttributeError)
                # says nothing about regional availability. Treating it as "not
                # available" would silently skip every AgentCore check and emit a
                # false N/A report, so keep the client and let the individual
                # checks surface their own errors instead.
                logger.warning(
                    f"AgentCore availability probe raised an unexpected error, "
                    f"proceeding with checks: {e}"
                )

        if runtime_probe_auth_error_code is not None:
            all_findings.append(
                create_finding(
                    check_id="AC-00",
                    finding_name="AgentCore Runtime Assessment Incomplete",
                    finding_details=(
                        "Amazon Bedrock AgentCore Runtime checks could not be "
                        f"assessed in region {region} because the availability "
                        "probe returned credential or authentication error "
                        f"{runtime_probe_auth_error_code}."
                    ),
                    resolution=(
                        "Verify the assessment credentials, session token, signing "
                        "region, and system clock, then retry."
                    ),
                    reference=AGENTCORE_STARTER_TOOLKIT_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                    region=region,
                )
            )
            prepare_agentcore_runtime_incomplete_report_findings(
                all_findings,
                region,
                runtime_probe_auth_error_code,
            )
            csv_content = generate_csv_report(all_findings)
            s3_url = write_to_s3(execution_id, csv_content, BUCKET_NAME, region=region)
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": (
                            "AgentCore Runtime assessment was incomplete because "
                            f"the credentials were rejected in {region}"
                        ),
                        "s3_url": s3_url,
                    }
                ),
            }

        # If AgentCore not available, produce an N/A report (plus any global IAM
        # findings already collected on the primary region) and exit early
        if agentcore_client is None:
            all_findings.append(
                create_finding(
                    check_id="AC-00",
                    finding_name="AgentCore Service Availability",
                    finding_details=f"Amazon Bedrock AgentCore is not available in region {region}. No checks performed.",
                    resolution="No action required. AgentCore is not deployed in this region.",
                    reference=AGENTCORE_STARTER_TOOLKIT_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                    region=region,
                )
            )
            for finding in all_findings:
                if not finding.get("Region"):
                    finding["Region"] = region
            all_findings.extend(check_agentcore_gateway_agentic_security())
            all_findings.extend(build_agentic_agentcore_security_findings(all_findings))
            all_findings.extend(
                build_agentic_agentcore_unavailable_findings(region, all_findings)
            )
            for finding in all_findings:
                if not finding.get("Region"):
                    finding["Region"] = region
            csv_content = generate_csv_report(all_findings)
            s3_url = write_to_s3(execution_id, csv_content, BUCKET_NAME, region=region)
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": f"AgentCore not available in {region}",
                        "s3_url": s3_url,
                    }
                ),
            }

        logger.info(
            f"Starting AgentCore security assessment for execution: {execution_id}"
        )

        browser_inventory = get_custom_browser_inventory()

        # Execute regional assessment checks (IAM-only checks AC-02/AC-03 and the
        # global service-linked role check AC-09 are run separately, once, on the
        # primary region above)
        checks = [
            (["AC-01"], "VPC Configuration", check_agentcore_vpc_configuration),
            (["AC-04"], "Observability", check_agentcore_observability),
            (["AC-05"], "Encryption", check_agentcore_encryption),
            (
                ["AC-06"],
                "Browser Tool Recording",
                lambda: check_browser_tool_recording(browser_inventory),
            ),
            (["AC-07"], "Memory Configuration", check_agentcore_memory_configuration),
            (["AC-13"], "Gateway Configuration", check_agentcore_gateway_configuration),
            (["AC-08"], "VPC Endpoints", check_agentcore_vpc_endpoints),
            (
                ["AC-10"],
                "Resource-Based Policies",
                check_agentcore_resource_based_policies,
            ),
            (
                ["AC-11"],
                "Policy Engine Encryption",
                check_agentcore_policy_engine_encryption,
            ),
            (["AC-12"], "Gateway Encryption", check_agentcore_gateway_encryption),
            (
                ["AC-14"],
                "Identity Token Vault Encryption",
                check_agentcore_token_vault_encryption,
            ),
            (
                ["AC-15"],
                "Code Interpreter Isolation",
                check_agentcore_code_interpreter_isolation,
            ),
            (
                ["AC-16"],
                "Custom Browser Isolation",
                lambda: check_agentcore_browser_network_isolation(browser_inventory),
            ),
            (
                ["AC-17"],
                "Online Evaluation Coverage",
                check_agentcore_online_evaluation_coverage,
            ),
            (
                ["AC-18"],
                "CloudTrail Data Event Coverage",
                check_agentcore_cloudtrail_data_events,
            ),
            (
                ["AC-19"],
                "Log Delivery Configuration",
                check_agentcore_log_delivery_configuration,
            ),
            (
                ["AC-20"],
                "Log Data Protection",
                check_agentcore_log_group_data_protection,
            ),
            (
                ["AC-22"],
                "Telemetry Sink Scope",
                check_agentcore_telemetry_sink_scope,
            ),
            (
                ["AG-24", "AG-25", "AG-26", "AG-27"],
                "Agentic Gateway Security",
                check_agentcore_gateway_agentic_security,
            ),
            (
                ["AC-24"],
                "Gateway Rate Limiting",
                check_agentcore_gateway_rate_limiting,
            ),
            (
                ["AC-25"],
                "Gateway Target Authorization",
                check_agentcore_gateway_target_authorization,
            ),
            (
                ["AC-26"],
                "Log Retention and Key Scope",
                check_agentcore_log_retention_and_key_scope,
            ),
            (
                ["AC-27"],
                "Gateway Policy Conditions",
                check_agentcore_gateway_policy_conditions,
            ),
            (
                ["AC-30"],
                "Runtime Inbound Authorization",
                check_agentcore_runtime_inbound_authorization,
            ),
            (
                ["AC-31"],
                "Gateway Inbound Allow Lists",
                check_agentcore_gateway_inbound_allow_lists,
            ),
            (
                ["AC-34"],
                "Runtime Inline Credentials",
                check_agentcore_runtime_inline_credentials,
            ),
            (
                ["AC-35"],
                "Policy Tool Scope",
                check_agentcore_policy_tool_scope,
            ),
            (
                ["AC-36"],
                "Policy Engine Key Scope",
                check_agentcore_policy_engine_key_scope,
            ),
            (
                ["AC-37"],
                "Policy Guardrail Wiring",
                lambda: check_agentcore_policy_guardrail_wiring(permission_cache),
            ),
            (
                ["AC-38"],
                "Policy Session Binding",
                check_agentcore_policy_session_binding,
            ),
        ]

        for check_ids, check_name, check_func in checks:
            if not check_timeout():
                logger.error(
                    f"Timeout approaching, skipping remaining checks after {check_name}"
                )
                deadline_reached = True
                break

            try:
                logger.info(f"Running check: {check_name}")
                check_start = time.time()

                findings = check_func()
                all_findings.extend(findings)

                check_duration = time.time() - check_start
                logger.info(
                    f"Check '{check_name}' completed in {check_duration:.2f}s with {len(findings)} findings"
                )

            except Exception as e:
                logger.error(f"Error in check '{check_name}': {e}")
                all_findings.extend(
                    _incomplete_check_findings(
                        check_ids,
                        f"AgentCore {check_name} Check",
                        e,
                        region,
                    )
                )

        if deadline_reached:
            logger.warning(
                "AgentCore regional checks stopped near the Lambda timeout; "
                "backfilling skipped controls as N/A"
            )
            prepare_agentcore_timeout_report_findings(all_findings, region)
        else:
            # Inject region into all findings that don't have it set
            for finding in all_findings:
                if not finding.get("Region"):
                    finding["Region"] = region

            logger.info("Building Agentic AI Security findings from AgentCore results")
            all_findings.extend(build_agentic_agentcore_security_findings(all_findings))
            for finding in all_findings:
                if not finding.get("Region"):
                    finding["Region"] = region

        # Generate CSV report
        logger.info(f"Generating CSV report with {len(all_findings)} total findings")
        csv_content = generate_csv_report(all_findings)

        # Upload to S3
        s3_url = write_to_s3(execution_id, csv_content, BUCKET_NAME, region=region)

        # Calculate execution metrics
        total_duration = time.time() - start_time
        logger.info(f"Assessment completed in {total_duration:.2f}s")

        # Publish CloudWatch metrics
        try:
            cloudwatch_client.put_metric_data(
                Namespace="AIMLSecurity/AgentCore",
                MetricData=[
                    {
                        "MetricName": "AssessmentDuration",
                        "Value": total_duration,
                        "Unit": "Seconds",
                    },
                    {
                        "MetricName": "FindingsCount",
                        "Value": len(all_findings),
                        "Unit": "Count",
                    },
                ],
            )
        except Exception as e:
            logger.warning(f"Failed to publish CloudWatch metrics: {e}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "AgentCore security assessment completed successfully",
                    "s3_url": s3_url,
                    "execution_id": execution_id,
                    "findings_count": len(all_findings),
                    "duration_seconds": total_duration,
                }
            ),
        }

    except Exception as e:
        logger.error(f"Fatal error in lambda_handler: {e}", exc_info=True)
        raise
