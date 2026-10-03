#!/usr/bin/env python3
"""Generate the AISF parity work ledger from the verdict table.

The verdict table below is the single source of truth. It was derived by reading
both sides of every pair: the AISF control's assertion and the incumbent check's
actual comparison. See AISF-PARITY-PROPOSAL.md section 4.4 for the reasoning.

Run:  python3 aisf-parity/build_ledger.py
Emits aisf-parity/aisf-work-ledger.json and aisf-parity/AISF-WORK-LEDGER.md.

Neither output is hand-edited. Change ROWS, re-run, commit both.
"""

import json
import os
from datetime import date

# verdict values
COVERED = "covered"  # an incumbent already asserts this; nothing to write
TIGHTEN = "tighten"  # an incumbent asserts part of it
NEW = "new"  # no incumbent asserts any part of it
NOT_IMPL = "not_implementable"  # flagged machine_checkable but is not
UNASSESSED = "unassessed"  # in scope, dedup pass not yet run

# disposition values, for TIGHTEN rows only (proposal decision 2)
EXTEND = "extend"  # incumbent name is honest, assertion merely narrower
NEW_ID = "new_id"  # incumbent name claims more than it asserts

# tier values. The tier is decided by which of the two tables below a row sits
# in, never by SCOPE27, so check_ledger.py can compare the two and the comparison
# can fail.
AI_SUBJECT = "ai_subject"  # the assertion subject is an AI resource
FOUNDATION = "foundation"  # the account or runtime an AI workload sits on

# (control, verdict, disposition, module, incumbents, gap, extra_iam, phase)
AI_SUBJECT_ROWS = [
    # ---------------- BDR: 19 controls, bedrock_assessments ----------------
    ("AIR-BDR-GRD-01", COVERED, None, "bedrock_assessments", ["BR-10"], "", [], 3),
    (
        "AIR-BDR-GRD-03",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-26"],
        "BR-26 judges entity and regex actions on the input and output sides of each "
        "draft and deployed guardrail version. Each deployed version that passes those "
        "settings is then applied once with bedrock:ApplyGuardrail, source OUTPUT and "
        "outputScope INTERVENTIONS, to a fixed probe string built from AWS's documented "
        "example access key and secret key: both blocked or anonymized is Passed, either "
        "let through is Failed, and an ApplyGuardrail error is N/A. PASSWORD detection "
        "of the probe text and the custom regex patterns are stated, not judged",
        [],
        3,
    ),
    (
        "AIR-BDR-KB-03",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-20"],
        "BR-20 judges the vector store key of every knowledge base by DescribeKey. For "
        "an OpenSearch Serverless collection it also reads every data access policy "
        "(aoss:ListAccessPolicies, aoss:GetAccessPolicy) and fails an index rule "
        "reaching the knowledge base's index whose collection segment or principal is "
        "a wildcard, since OpenSearch Serverless does not check a caller's KMS "
        "permission; an unread policy is N/A. For S3 Vectors it judges the bucket "
        "policy. For an OpenSearch Service domain it fails an Allow admitting an "
        "unbounded principal unless fine-grained access control is on with anonymous "
        "authentication off, and for Neptune Analytics it fails a graph with "
        "publicConnectivity true; an absent field is N/A. For Aurora it fails a "
        "cluster with a PubliclyAccessible member instance (rds:DescribeDBInstances "
        "per DBClusterMembers entry), and an unread instance is N/A; database "
        "credentials themselves are not judged. A MANAGED store is judged on its key "
        "alone, and whether access matches the source data's is not compared",
        [],
        3,
    ),
    (
        "AIR-BDR-MDL-10",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-37"],
        "BR-37 reads bedrock:GetAccountDataRetention for the control plane, and the "
        "bedrock-mantle account mode plus every mantle project's data_retention mode "
        "over SigV4-signed HTTPS; the mantle account mode is judged on its own row "
        "even with no project listed, each project's effective mode is judged, and "
        "only none passes. Each model's allowed_modes are not read",
        [],
        3,
    ),
    ("AIR-BDR-GRD-02", COVERED, None, "bedrock_assessments", ["BR-34"], "", [], 3),
    ("AIR-BDR-GRD-04", COVERED, None, "bedrock_assessments", ["BR-32"], "", [], 3),
    ("AIR-BDR-GRD-09", COVERED, None, "bedrock_assessments", ["BR-27"], "", [], 3),
    ("AIR-BDR-GRD-10", COVERED, None, "bedrock_assessments", ["BR-41"], "", [], 3),
    (
        "AIR-BDR-KB-06",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-06"],
        "BR-06 credits retrieval traceability only when a trail or event data store "
        "records AWS::Bedrock::KnowledgeBase data events, read from multi-Region "
        "trails and from single-Region trails homed in the knowledge base's Region, "
        "invocation logging records "
        "text, and every S3 source bucket has versioning Enabled "
        "(s3:GetBucketVersioning); an unread data source or bucket is N/A. The "
        "RetrieveAndGenerate citations are not read, and sources outside S3 are not "
        "judged for versioning",
        [],
        3,
    ),
    (
        "AIR-BDR-MDL-07",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-06"],
        "BR-06 credits Bedrock management and data events from multi-region trails, "
        "from single-Region trails homed in the assessed Region, and from each ENABLED "
        "CloudTrail Lake event data store homed there or, with MultiRegionEnabled, "
        "in another assessed Region. A store homed in an unassessed Region is not "
        "read. Each store's advanced selectors are read with "
        "cloudtrail:GetEventDataStore and judged as a trail's. A management "
        "selector must admit both bedrock.amazonaws.com and bedrock-mantle.amazonaws.com, "
        "and a data-event row needs all six AWS::BedrockMantle:: resource types. "
        "An unread "
        "trail or store keeps a gap N/A. No record is traced end to end",
        [],
        3,
    ),
    (
        "AIR-BDR-MDL-02",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-04", "BR-12"],
        "",
        [],
        3,
    ),
    (
        "AIR-BDR-KB-01",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-46"],
        "BR-46 passes a knowledge base S3 source only when a recurring, full-depth "
        "Macie job scopes in its prefix, the latest ingestion did not start after "
        "the job's last run, and every source list was read. With Macie off, a "
        "source that no completed "
        "Comprehend PII detection job read fails, and a Comprehend-screened source "
        "is N/A. Whether classification is carried into per-document metadata needs "
        "s3:GetObject on the metadata sidecars, which the Bedrock role is not granted",
        [],
        3,
    ),
    ("AIR-BDR-MDL-01", COVERED, None, "bedrock_assessments", ["BR-42"], "", [], 3),
    ("AIR-BDR-MDL-03", COVERED, None, "bedrock_assessments", ["BR-43"], "", [], 3),
    ("AIR-BDR-MDL-04", COVERED, None, "bedrock_assessments", ["BR-44"], "", [], 3),
    ("AIR-BDR-MDL-09", COVERED, None, "bedrock_assessments", ["BR-45"], "", [], 3),
    (
        "AIR-BDR-KB-05",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-34"],
        "partial, ceiling reached. BR-34 reads every data source with GetDataSource "
        "for a POST_CHUNKING transformation Lambda, and every agent version and flow "
        "node that retrieves from the knowledge base, at DRAFT and at each "
        "alias-routed version, with ListAgentKnowledgeBases and the flow definition. "
        "It fails a knowledge base that ingests a source with no transformation step "
        "and is reached through any agent version or flow node, because managed "
        "retrieval cannot wrap retrieved chunks in guardContent tags, so an agent or "
        "flow guardrail's PROMPT_ATTACK filter does not evaluate them. It never passes "
        "one. An account-enforced configuration whose PROMPT_ATTACK input filter "
        "blocks at HIGH strength is credited only when it applies to every model and "
        "every message, without SELECTIVE guarding or inputTags HONOR. The ceiling: a "
        "transformation Lambda's logic is opaque, the bedrock-agent KnowledgeBase "
        "shape has no guardrail member, and guardrailConfiguration is a "
        "GenerationConfiguration request member of RetrieveAndGenerate, so no read "
        "can show that retrieved chunks are screened",
        [],
        3,
    ),
    (
        "AIR-BDR-KB-08",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-26"],
        "partial, ceiling reached. BR-26 fails a knowledge base that ingests a source "
        "with no POST_CHUNKING transformation step and no completed Comprehend "
        "ONLY_REDACTION job whose output location holds everything the source "
        "ingests, whose PiiEntityTypes names ALL, and that ended before the source's "
        "latest ingestion job started. An agent version or flow node guardrail is not "
        "credited as screening the retrieved chunks, because the agent guardrail guide "
        "describes it evaluating user messages and model responses only. Each object "
        "the source ingests is listed with s3:ListBucket, and one last modified after "
        "the job's EndTime fails the source; an unread or capped listing is N/A. It "
        "never passes one, because no API records that the job wrote each object. An account-enforced configuration is "
        "credited only when it applies to every model and every message, without "
        "SELECTIVE guarding or inputTags HONOR. comprehend:ListPiiEntitiesDetectionJobs has "
        "no resource type and is granted on *, and a failed read leaves an S3 "
        "source not judged. The ceiling: a transformation Lambda's logic and a Glue job's "
        "effect are not recorded, and guardrailConfiguration is a "
        "GenerationConfiguration request member of RetrieveAndGenerate, absent from "
        "the bedrock-agent KnowledgeBase shape",
        [],
        3,
    ),
    (
        "AIR-BDR-MDL-08",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-07"],
        "BR-07 holds the catalog leg (ListPrompts non-empty is its Passed row, zero prompts"
        " is Not Applicable) and now the production-version leg as well. For each prompt it"
        " calls ListPrompts(promptIdentifier=...) for the numbered versions, fails a prompt"
        " that has only its DRAFT, and reads GetPrompt(promptVersion=N) on every "
        "numbered version for customerEncryptionKeyArn, which PromptSummary does not carry, and "
        "judges that key by DescribeKey as customer managed and Enabled. For flows it reads "
        "the prompt node's resource.promptArn in the working draft and in every flow "
        "version an alias routes to (ListFlowAliases, GetFlowVersion), and fails a node that pins no version suffix,"
        " since an unversioned ARN resolves to the working draft, and a node that defines "
        "its prompt inline, which no version pins. The flow leg runs even with no prompt "
        "in the Region. A role or user allowed bedrock:UpdatePrompt, "
        "bedrock:CreatePromptVersion or bedrock:DeletePrompt on a Resource with a wildcard "
        "fails, and so does one that holds one of them beside bedrock:RenderPrompt. A version != DRAFT test "
        "on bare ListPrompts or on a GetPrompt with no promptVersion would have failed "
        "every prompt in every account, because both return the draft. Partial, ceiling "
        "reached: a prompt held in application code has no AWS record, and no AWS field "
        "names the role approved to release a version, so which of the scoped roles "
        "should release a version, beside the RenderPrompt roles, is not judged",
        [],
        4,
    ),
    # ---------------- SGM: 11 controls, sagemaker_assessments ----------------
    (
        "AIR-SGM-EP-08",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-18", "SM-42"],
        "",
        [],
        3,
    ),
    (
        "AIR-SGM-TRN-05",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-09", "SM-01", "SM-03"],
        "all three legs present",
        [],
        3,
    ),
    ("AIR-SGM-EP-01", COVERED, None, "sagemaker_assessments", ["SM-11"], "", [], 3),
    ("AIR-SGM-EP-02", COVERED, None, "sagemaker_assessments", ["SM-02"], "", [], 3),
    ("AIR-SGM-GOV-01", COVERED, None, "sagemaker_assessments", ["SM-22"], "", [], 3),
    ("AIR-SGM-TRN-02", COVERED, None, "sagemaker_assessments", ["SM-03"], "", [], 3),
    (
        "AIR-SGM-EP-06",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-23", "SM-31"],
        "SM-23 fails an InService endpoint with no Model Monitor schedule, or with "
        "no DataQuality or no ModelQuality schedule, and a schedule that is not "
        "Scheduled",
        [],
        3,
    ),
    ("AIR-SGM-GOV-10", COVERED, None, "sagemaker_assessments", ["SM-32"], "", [], 3),
    (
        "AIR-SGM-TRN-01",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-33", "SM-34"],
        "SM-34 is the approved-exception leg: its approved network and no direct "
        "internet access verdicts require sagemaker:CreateTrainingJob to be bound "
        "on sagemaker:VpcSubnets or sagemaker:VpcSecurityGroupIds and on "
        "sagemaker:NetworkIsolation, by a Deny in an attached service control "
        "policy or by a condition in every identity policy that grants the action",
        [],
        3,
    ),
    ("AIR-SGM-TRN-08", COVERED, None, "sagemaker_assessments", ["SM-34"], "", [], 3),
    (
        "AIR-SGM-EP-03",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-11", "SM-14"],
        "SM-11 judges EnableNetworkIsolation and VpcConfig on every model an endpoint "
        "serves and reads the endpoint config KmsKeyId of each instance-backed "
        "endpoint, and SM-14 requires RepositoryAccessMode Vpc on each model's image "
        "config. The one field not read is inter-container traffic encryption, "
        "because no endpoint API returns it: EnableInterContainerTrafficEncryption "
        "is a member of DescribeTrainingJob, DescribeProcessingJob and "
        "DescribeHyperParameterTuningJob, and of none of DescribeEndpointConfig, "
        "DescribeModel, DescribeEndpoint or DescribeInferenceComponent (botocore "
        "1.43.85). The AISF slug sagemaker_endpoint_intercontainer_encryption_enabled "
        "names that absent field and should be fixed in the AISF repo",
        [],
        3,
    ),
    # ---------------- ACR: 37 controls, agentcore_assessments ----------------
    (
        "AIR-ACR-GW-01",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-24"],
        "AG-24 passes authorizerType AWS_IAM, AUTHENTICATE_ONLY with a policy engine "
        "in ENFORCE, and CUSTOM_JWT only when the authorizer's values bound it: an "
        "allowedAudience or allowedClients list pins the application, and a list "
        "holding a blank or * value does not count. A CUSTOM_JWT gateway with no such "
        "list fails as Unbounded, one whose discoveryUrl is not https fails as Issuer "
        "Not HTTPS, and one that reports no customJWTAuthorizer is N/A",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-09",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-06"],
        "AC-06 judges every custom browser's recording destination as well as recording.enabled and "
        "a bucket name. The bucket, read with ExpectedBucketOwner set to the browser's account, must "
        "encrypt by default with a KMS key, deny every principal reads and writes of the recording "
        "prefix without TLS, and expire the prefix by lifecycle rule, including noncurrent versions "
        "when versioned. The execution role must be named and allowed to write the prefix by an "
        "identity or bucket policy and by its boundary, with no Deny refusing it. A Block Public "
        "Access setting the bucket leaves off fails unless the account sets it, read with "
        "s3:GetAccountPublicAccessBlock, and is N/A naming that action when the read is denied. "
        "A bucket policy Allow of s3:GetObject on a recording key to another account fails, as does "
        "one to * or NotPrincipal while RestrictPublicBuckets is off on bucket and account or while a "
        "fixed-value condition makes it non-public, unless aws:PrincipalAccount or aws:SourceAccount "
        "names the account or aws:PrincipalOrgID names its organization. While RestrictPublicBuckets "
        "is on, a public policy confines every grant to the account and AWS service principals, so "
        "none fails. Every row names the cached roles and users whose identity policies read the "
        "prefix. Statements naming a service principal and object ACLs are not judged for reads. "
        "SCPs, the bucket key policy and the role's use of that key are not evaluated, so a Passed "
        "write can still be refused. The AWS managed browser has no recording configuration and is "
        "outside the population",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-01",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-02"],
        "AC-02 reads roles, users and the group policies of each user, and counts a "
        'bare Action "*" and a NotAction that leaves AgentCore in. A wildcard action '
        'pattern, a bare "*" or a NotAction reaching any one of the six evaluator and '
        "online-evaluation-config writes grants all six and fails as Evaluation "
        "Administration Wildcard, because a principal that can delete an evaluation "
        "can stop the measurement of the agent it watches. A second leg fails when "
        "cached principals can author evaluators and none holds the evaluator reads "
        "without an author action, so no identity reviews an evaluator it cannot "
        "rewrite. A permissions boundary is intersected with the grants, and a "
        "principal the IAM cache could not read withholds Passed. SCPs are not "
        "evaluated per principal, so they can produce a false Failed and never a false "
        "Passed",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-10",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-33"],
        "AC-33 judges the resource element on the five token issuance actions per "
        "cached role and user: a resource ending in a wildcard, a wildcard in the "
        "region or account segment of the workload identity ARN, or a NotResource "
        "grant mints a token for every workload identity in the account, while a "
        "resource naming one identity bounds the grant to that agent. A bare Action "
        '"*" and group policies count, a grant the principal\'s own Deny or boundary '
        "removes does not, and a principal the IAM cache could not read is named in an "
        "N/A row that withholds Passed. A grant that names only the workload identity "
        "directory is reported separately at medium, because the service authorization "
        "reference marks both the directory and the identity required on these actions "
        "and never says whether the directory alone authorizes the call, so that grant "
        "either reaches every identity the directory holds or authorizes nothing. The "
        "role of each runtime with a custom JWT authorizer fails when it can still call "
        "GetWorkloadAccessTokenForUserId after its own Deny and boundary, and an uncached "
        "role or an unread runtime is N/A. Every cached role and user fails when an "
        "Allow of InvokeAgentRuntimeForUser or InvokeAgentRuntimeWithWebSocketStreamForUser "
        "reaches such a runtime or one of its endpoints and survives its own Deny and "
        "boundary; conditions on that Allow are not read",
        [],
        4,
    ),
    (
        "AIR-ACR-PAY-01",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-02"],
        "AC-02 fails any role or user, group policies included, whose Allow statements "
        "reach both an AgentCore payment session or instrument write and "
        "ProcessPayment with no account-wide Deny on the latter and no permissions "
        "boundary removing either. A payment session carries its own "
        "limits.maxSpendAmount, so that one principal sets the budget it then spends "
        "against, which is the single failure behind both legs the devguide draws: its "
        "ManagementRole denies ProcessPayment and its ProcessPaymentRole holds no "
        "session write. A Deny scoped to one payment manager or carrying a condition "
        "is read as no account-wide Deny, so a narrower Deny never excuses the "
        "collision. Two more legs read the payment manager: a principal that can "
        "create or update one fails when its iam:PassRole grant is wider than the "
        "retrieval role or does not pin iam:PassedToService, and each manager's "
        "retrieval role trust must name only bedrock-agentcore.amazonaws.com and pin "
        "aws:SourceArn to that manager. The trust leg reads N/A until "
        "bedrock-agentcore:ListPaymentManagers is granted",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-03",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-02", "AC-45", "AC-48"],
        "AC-45 reads the execution role of every code interpreter and browser in the "
        "account by value and fails a role whose Allow statements reach every resource "
        "or an unbounded one (arn:aws:s3:::*, table/*, a region or account wildcard), "
        "name a NotResource, carry a service-wide, bare or pattern action wildcard "
        "such as s3:Get*, or are written with NotAction. On the primary region a "
        "Global row names every principal that can run a command or open a shell in a "
        "runtime session through a grant that does not name "
        "bedrock-agentcore:InvokeAgentRuntimeCommandShell or "
        "InvokeAgentRuntimeCommand, or that reaches every runtime. AC-02 judges the "
        "same wildcards only over the bedrock-agentcore namespace, so a tool role "
        "granting s3:* on every bucket is a verdict it cannot reach. AC-48 reads the "
        "trust policy of every runtime, browser and code interpreter role, fails an "
        "AWS service principal with no aws:SourceAccount or aws:SourceArn condition "
        "and an account-root principal, and fails a role that more than one "
        "AgentCore resource names",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-05",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-17", "AC-39"],
        "AC-39 judges every online evaluation configuration that exists and names the "
        "setting that stops it running: a status other than ACTIVE, an executionStatus other "
        "than ENABLED, no sampling percentage above zero, no input log group or service, no "
        "output log group, or no evaluator attached. AC-17 judges every runtime whatever "
        "REQUIRE_AGENTCORE_ONLINE_EVALUATION is set to, and fails one that no running "
        "configuration reads by its log group and service name. The rule filters are counted "
        "and not judged, because which sessions an operator means to score has no API field",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-06",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-17", "AC-40"],
        "AC-40 classifies the evaluators each configuration attaches against the account's own "
        "catalogue, which marks a service-authored evaluator's category in its description, and "
        "fails a configuration that attaches no safety evaluator, attaches neither "
        "Builtin.ToolSelectionAccuracy nor Builtin.ToolParameterAccuracy, or has no CloudWatch "
        "alarm with actions on a metric in the namespace its scores are published to. "
        "Evaluators written in this account are named for the owner to classify, because "
        "their descriptions are prose no check can verify. The dimensions an alarm narrows on "
        "are not judged, because the dimension names the service emits are not API fields",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-03",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-10", "AC-27"],
        "AC-10 fails an Allow statement on a gateway or runtime resource policy that "
        "opens it to any principal without binding the caller's account or "
        "organization, and an unreadable gateway or runtime list is N/A. AC-27 judges "
        "whether the gateway's Allow statements and its execution role's trust policy "
        "carry aws:SourceAccount or aws:SourceArn naming the assessed account in every "
        "value, fails an unconditioned statement even when a guarded sibling sits "
        "beside it in the same document, and fails a gateway role that trusts a second "
        "principal. IfExists, ForAllValues and wildcard values do not count",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-13",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-08", "AC-10", "AC-47"],
        "AC-47 passes the network leg only on a resource policy Deny that refuses the "
        "invoke action to every principal outside a bounded aws:SourceVpc, "
        "aws:SourceVpce, aws:VpcSourceIp or aws:SourceIp value. An Allow condition "
        "alone, a positive or ForAnyValue operator, a wildcard endpoint, an address "
        "list covering every address (0.0.0.0/1 plus 128.0.0.0/1 included) and a Deny "
        "that ANDs in another key or names specific principals fail. The caller leg "
        "passes only on a Deny outside a bounded aws:PrincipalArn list, because an "
        "Allow does not stop a same-account caller, or on an allowedWorkloadConfiguration "
        "that admits a gateway whose target routes to the runtime and nothing else. A "
        "configuration admitting none of those gateways, another workload or a wildcard "
        "fails, and one with no gateway target routing to the runtime is N/A. AC-08 requires an available bedrock-agentcore endpoint "
        "when runtimes exist, fails an interface endpoint with private DNS off, and "
        "fails a security group set whose inbound ranges together cover the internet. "
        "AC-10 fails an Allow that opens the runtime to any principal without binding "
        "the caller's account or organization",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-08", "AC-27"],
        "AC-08 judges a region holding gateways and no runtime, and requires an available "
        "bedrock-agentcore.gateway endpoint when gateways exist, where any endpoint whose name "
        "carried agentcore counted. It judges each endpoint's policy against the default "
        "allow-everything document and fails a security group set whose inbound ranges "
        "together cover 0.0.0.0/0 or ::/0. AC-27 passes the gateway network leg only on a "
        "resource policy Deny outside a bounded aws:SourceVpc, aws:SourceVpce, "
        "aws:VpcSourceIp or aws:SourceIp value. Which VPC a gateway's callers run in has no "
        "API field, so an endpoint in any VPC of the region counts",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-05",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-27", "AC-24"],
        "AG-27 holds the WAF leg and reads the gateway's wafConfiguration failureMode "
        "beside the web ACL association: FAIL_OPEN fails, an unset value is N/A, and "
        "only FAIL_CLOSE passes. AC-24 requires an ACTIVE gateway rate limit carrying "
        "a requests, tokens or connections ceiling, because dimensions is the only "
        "required member of a limit entry and a limit can therefore name a dimension "
        "and bound nothing. A limit keyed on $.context.jwt.jti, iat, exp or nbf does "
        "not count, because each takes a new value with every token and a caller who "
        "mints a fresh token escapes the limit",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-05",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-14", "AC-34"],
        "AC-14 has the token vault CMK leg: the population is the configured vault plus every "
        "vault an OAuth2, API key or payment credential provider ARN names, and the vault key "
        "must be customer managed and Enabled by kms:DescribeKey. AC-34 adds the secret-scan "
        "leg over every definition that can carry a credential: GetAgentRuntime."
        "environmentVariables, the sensitive GetGatewayTarget fields (static query parameters, "
        "OAuth custom parameters, inline schema payloads) and the sensitive GetHarness fields "
        "(environment variables, remote MCP headers and URLs, OAuth custom parameters, the "
        "system prompt, model parameters). A value holding a slash reads as a secret name "
        "unless it is a base64 string of 40 or more characters. No API reads the rest: there "
        "is no ListTokenVaults, so a vault no provider names and that is not configured is not "
        "read, and the agent's code and container image are not readable through any "
        "AgentCore API. The vault key policy's trust is not graded, and the harness leg reads "
        "N/A until bedrock-agentcore:ListHarnesses is granted",
        [],
        4,
    ),
    (
        "AIR-ACR-MEM-01",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-07", "AC-23"],
        "AC-07 reads the key each memory names with kms:DescribeKey and passes only a "
        "key KMS reports as customer managed and Enabled: a memory with no key, a key "
        "that is not customer managed and a key that is disabled or pending deletion "
        "fail, and a key the assessment role cannot describe, which includes every key "
        "in another account, is N/A. AC-07 also requires an {actorId} variable in "
        "every namespace of every strategy, and fails a memory resource-based policy "
        "whose Allow statement trusts * or an AWS service with no account or "
        "organization condition, an unread policy being N/A. AC-23 judges each memory read by the key "
        "that action carries: namespace for record reads, actorId or sessionId for "
        "event reads. A strategyId condition alone, an IfExists, ForAllValues or "
        "negated operator and a wildcard-only value do not bound a read. A bare Action "
        '"*", a NotAction and group policies count, a grant the principal\'s own Deny '
        "or boundary removes does not, and a principal the IAM cache could not read is "
        "N/A",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-11", "AC-36"],
        "AC-11 asserts the engine names a customer managed key that DescribeKey reports "
        "as customer managed and Enabled, AC-36 asserts the key policy names who may "
        "decrypt with it and who may disable it or schedule it for deletion, scopes "
        "CreateGrant, Decrypt and GenerateDataKey by ViaService, grant constraint and "
        "source account as the policy encryption guide shows, and that the key carries "
        "the engine's management and evaluation grants; the key cannot be added to or "
        "changed on an existing engine, so the key policy is the whole guard. The "
        "disable/delete alarm and the break-glass runbook are not readable from the "
        "key, and AC-36's passing resolution says so",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-01",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-25", "AC-19", "AC-35"],
        "AG-25 asserts mode ENFORCE plus status/enforcementMode ACTIVE and reads the "
        "text of each enforcing policy: a permit over every action with no condition "
        "fails as Allows All, and an enforcing policy with no readable text is N/A. "
        "AC-19 asserts the gateway delivers APPLICATION_LOGS, which is where a policy "
        "decision record is written. AC-35 asserts no enforcing permit leaves the "
        "action position unconstrained, and reads the principal and resource of every "
        "permit over named tools: a bare principal that no condition reads fails as "
        "Caller Scope Unbounded, and a resource named by type alone or not at all "
        "fails as Gateway Scope Unbounded. A policy with no readable text, or a head "
        "without three scope positions, withholds the gateway's Passed. Default-deny "
        "and forbid-wins are engine behaviour and not a setting to read",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-07",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-25", "AC-38"],
        "AG-25 counts enforcing policies and reads their text. AC-38 asserts a "
        "temporal policy exists and that the gateway carrying it authenticates callers "
        "with CUSTOM_JWT or AWS_IAM, the two authorizer types the devguide names as "
        "binding a session to the caller's identity, and reads each event pattern of "
        "the temporal policy: one with no eventResource fails as Session Rule Resource "
        "Unscoped, and a temporal policy with no readable event pattern is N/A. The "
        "session-id propagation path is fail-closed by the service, since a request to "
        "an engine holding a temporal policy fails validation without the header. "
        "On a gateway holding a temporal policy, AC-38 reads the execution role's "
        "bedrock-agentcore:GetWorkloadAccessToken grant from the IAM cache on the "
        "gateway's workload identity and its directory, and fails a role with no "
        "surviving unconditioned grant, because the Gateway mints the token that "
        "carries the session identity with that role. SCPs are not read",
        [],
        4,
    ),
    (
        "AIR-ACR-REG-02",
        COVERED,
        None,
        "agent_registry_assessments",
        ["AR-03", "AR-09", "AR-10"],
        'AR-03 is named "Publication Approval Governance" and fails, by default, a '
        "registry whose approvalConfiguration.autoApprovalRules is non-empty; an omitted "
        "or empty list is manual review and passes. AR-09 asserts the separation "
        "leg: it fails any role or user whose attached, inline and group policies allow, "
        "by any Allow including a bare *, a *:* and a NotAction, both a record write "
        "(CreateRegistryRecord, UpdateRegistryRecord, SubmitRegistryRecordForApproval) and "
        "UpdateRegistryRecordStatus, the one operation that can set a record to APPROVED, "
        "in either the agent-registry namespace or the public-preview bedrock-agentcore "
        "spelling of it. A permissions boundary that does not allow an action removes it, "
        "as does a Deny with no condition on Resource *, and a principal whose policies "
        "could not be read blocks a Passed. AR-10 asserts the observation leg: an "
        "enabled rule on the default event bus that matches the aws.agent-registry "
        "Pending Approval, Approved and Rejected state-change events and has a Lambda, "
        "SNS, SQS or Step Functions target. A rule that matches only the aws.bedrock-agentcore preview source is "
        "reported apart, because that source stops routing on 30 October 2026. AWS delivers "
        "these events to the default bus, so a default-bus rule with an event-bus target "
        "and no review-pipeline target is followed one hop to a bus in the same account "
        "and Region and credited only if a rule there matches and has a review-pipeline "
        "target; a forward to another account or Region is reported N/A naming the bus",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-08",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-01", "AC-49"],
        "AC-01 unions the outbound ranges of every security group attached to a VPC "
        "runtime, code interpreter or browser and fails a resource whose groups "
        "together permit 0.0.0.0/0 or ::/0 egress, so 0.0.0.0/1 plus 128.0.0.0/1 fails "
        "as 0.0.0.0/0 does. A tool in PUBLIC network mode fails without a describe "
        "call, because the service grants it open internet egress by configuration, "
        "and a tool in SANDBOX fails at Medium, because no customer security group "
        "names what it reaches. A group the describe did not return and a denied "
        "ec2:DescribeSecurityGroups are both reported N/A on their own line, so an "
        "unread group is never counted as closed. A Global leg requires an attached "
        "SCP that denies CreateAgentRuntime, UpdateAgentRuntime, CreateCodeInterpreter "
        "and CreateBrowser with a Null true test on bedrock-agentcore:subnets or "
        "bedrock-agentcore:securityGroups, and a second that pins both keys with "
        "ForAnyValue:StringNotEquals to IDs without wildcards. AC-49 is the "
        "domain-filter leg: for each VPC hosting a runtime, browser or code "
        "interpreter it walks the Route 53 Resolver DNS Firewall rules in "
        "evaluation order and passes only when the first rule over * is a BLOCK "
        "that names no query type and the firewall config has FirewallFailOpen "
        "DISABLED",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-02",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-42"],
        "AC-42 reads iam:PassRole on every cached role and user, group policies "
        "included, against the execution roles the region's online evaluation "
        "configurations name, and judges the widest statement that reaches one of "
        "them: a Resource pattern wider than the role itself, a NotResource grant, "
        "which reaches every role it does not list, or a grant carrying no "
        "iam:PassedToService condition lets the holder run a role it could not assume "
        "by writing a configuration that names it. On the primary region a writer leg "
        "fails a principal able to create or update an online evaluation configuration "
        "whose PassRole grant does not name its roles or does not pin "
        "iam:PassedToService to bedrock-agentcore.amazonaws.com. A grant the "
        "principal's own Deny or boundary removes does not count, and a principal the "
        "IAM cache could not read is named in an N/A row that withholds Passed",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-03",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-43"],
        "AC-43 reads each evaluation execution role's own trust policy and fails every "
        "Allow statement trusting an AWS service principal, or every principal, unless "
        "an aws:SourceAccount or aws:SourceArn condition names the assessed account in "
        "every value: an IfExists or ForAllValues operator and a wildcard value do not "
        "count. The role can read the scored traces and invoke the judge model, so a "
        "service acting for another customer's configuration reaches both. AC-27 makes "
        "the same assertion on gateway execution roles and reaches no evaluation role, "
        "because it reads the roles gateways name",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-44"],
        "AC-44 reports whether each evaluation execution role's model-invocation grant "
        "names models at all: a Resource pattern ending in a bare wildcard, a wildcard "
        "in the service, account or resource type segment (arn:aws:bedrock:*::*), or a "
        "NotResource grant reaches every model the account can invoke, and the judge "
        "prompt carries the agent output being scored, so every model it reaches is "
        "one attacker-influenced text can be sent to. A region wildcard on a named "
        'model passes. A bare Action "*" counts, a grant the role\'s own Deny or '
        "boundary removes does not, and a role the IAM cache could not read is N/A. "
        "Which models a workload's judges may use is the workload owner's decision, so "
        "the check names the patterns it found and asserts only that they are bounded",
        [],
        4,
    ),
    (
        "AIR-ACR-EVAL-07",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-20", "AC-26", "AC-41"],
        "AC-41 anchors on the log group each configuration's outputConfig names and "
        "asserts a retention period, a customer managed key, and membership of the "
        "AgentCore log group prefixes, so a results group whose creator chose a name "
        "outside them is reported and not skipped. AC-41 reads that group's key policy "
        "itself: an Allow to a wildcard principal or a NotPrincipal fails unless a "
        "condition binds the caller's account, organization, principal ARN or source "
        "with a bounded value under a positive operator, kms:ViaService alone does not "
        "count, and a grant to the CloudWatch Logs service principal fails unless it "
        "binds the account or the kms:EncryptionContext:aws:logs:arn value. An "
        "unreadable key policy is N/A. A configuration writing to SOURCE_LOG_GROUP "
        "names no results group and is N/A, with AC-20 and AC-26 named as the checks "
        "that judge the input groups. Retention length is reported and not judged, "
        "because no API field states the workload's schedule. Tag values and the "
        "configuration's own description are free-form text AC-41 discloses without "
        "judging",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-02",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-28"],
        "AC-28 requires a service control policy that denies both CreateGateway and "
        "UpdateGateway when bedrock-agentcore:GatewayAuthorizerType is NONE, either by "
        "naming NONE in an equals-family condition or by omitting it from a "
        "not-equals-family one, so no approved-authorizer list has to be invented. "
        "IfExists operators read as their plain form. The policy counts only when it "
        "is attached to the assessed account, to an organizational unit above it or to "
        "the root, read with organizations:ListParents and "
        "organizations:ListTargetsForPolicy: a guard attached elsewhere fails as "
        "Unattached, the management account fails as Not Enforced because no SCP "
        "restricts it, and an unreadable parent chain or attachment list is N/A. The "
        "condition key carries a documentation drift: the AgentCore devguide wires "
        "GatewayAuthorizerType to CreateGateway and UpdateGateway and shows sibling "
        "gateway keys used this way in SCPs, while the machine-readable service "
        "reference and the service authorization reference page wire it to zero "
        "actions. The devguide wins for feature availability. Access Analyzer "
        "validate-policy accepts the key name but is no oracle for the wiring: it also "
        "accepts RuntimeAuthorizerType on CreateGateway, a pairing neither surface "
        "declares",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-08",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-25"],
        "AC-25 reads credentialProviderConfigurations per target through "
        "GetGatewayTarget, which is the only surface that carries it: the "
        "ListGatewayTargets summary omits the field. A Gateway Role Scope row per "
        "gateway reads the attached and inline policies of the gateway's roleArn from "
        "the IAM permission cache with the AC-45 rules, so a wildcard action, a "
        "Resource * or an unbounded ARN segment that no Deny or permissions boundary "
        "removes fails as Unscoped, and a role the cache records as unreadable, a role "
        "missing from the cache and a missing cache are N/A. SCPs are not evaluated "
        "per principal. The control's second leg, a Lambda target scoped to one "
        "function ARN, is not expressible because the target ARN members reject a "
        "wildcard",
        [],
        4,
    ),
    (
        "AIR-ACR-GW-10",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-18", "AC-19", "AC-20", "AC-26"],
        "AC-18 requires a CloudTrail data event selector for "
        "AWS::BedrockAgentCore::Gateway whenever the region holds a gateway, so "
        "each gateway call is recorded with its caller. AC-19 pairs each AgentCore delivery source with its delivery and AC-20 "
        "asserts masking plus a customer managed key. AC-26 adds an explicitly "
        "configured retentionInDays and reads each key policy by value: an Allow whose "
        "principal is a wildcard or a NotPrincipal fails unless a condition binds the "
        "caller's account, organization, principal ARN or source with a bounded value "
        "under a positive operator, and kms:ViaService alone, IfExists, ForAllValues "
        "and a wildcard account do not count. A grant to the CloudWatch Logs service "
        "principal fails unless it binds the account or the "
        "kms:EncryptionContext:aws:logs:arn value, because it serves log groups in any "
        "account. A Global leg requires an attached SCP denying logs:DeleteLogGroup, "
        "logs:PutRetentionPolicy, logs:PutLogGroupDeletionProtection and "
        "logs:DeleteSubscriptionFilter on the AgentCore log groups and aws/spans, and "
        "a regional leg fails a trail that records the Region with log file validation "
        "off",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-29"],
        "AC-29 requires a service control policy that denies both CreateAgentRuntime "
        "and UpdateAgentRuntime when bedrock-agentcore:RuntimeAuthorizerType is "
        "AWS_IAM, so a runtime cannot be created on, or moved back to, the SigV4 mode "
        "that authenticates the hosting application's shared role instead of the end "
        "user. IfExists operators read as their plain form. The policy counts only "
        "when it is attached to the assessed account, to an organizational unit above "
        "it or to the root, read with organizations:ListParents and "
        "organizations:ListTargetsForPolicy: a guard attached elsewhere fails as "
        "Unattached, the management account fails as Not Enforced because no SCP "
        "restricts it, and an unreadable parent chain or attachment list is N/A. A "
        "policy written the other way round, denying CUSTOM_JWT, is reported "
        "separately when it is attached, because it reads as configured to anyone "
        "counting policies. A gateway leg on AC-29 requires an attached SCP that "
        "denies CreateGateway and UpdateGateway unless "
        "bedrock-agentcore:GatewayAuthorizerType is CUSTOM_JWT, with one statement "
        "reaching every gateway firing on AWS_IAM, AUTHENTICATE_ONLY and NONE, "
        "because none of the three carries a validated end user and AC-28's Deny on "
        "NONE leaves the other two open, and on a type the key does not list, while "
        "not firing on CUSTOM_JWT. StringNotEquals CUSTOM_JWT passes; a deny-list of "
        "the three fails, because it does not deny a type the key does not "
        "enumerate. The Organizations grants are shared with "
        "GW-02's AC-28, so ID-04 costs no further permission",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-08",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-30", "AC-31"],
        "AC-30 reads GetAgentRuntime.authorizerConfiguration per runtime: an absent "
        "configuration means every invoke is SigV4-signed, and a customJWTAuthorizer "
        "that pins neither allowedAudience nor allowedClients accepts every token its "
        "issuer minted for every application registered there, so the claims are "
        "validated but not against this agent. A list holding a blank or * value names "
        "no single application and does not count, and a discoveryUrl that is not "
        "https fails as Issuer Not HTTPS whatever the lists hold. allowedScopes and "
        "customClaims are credited in the detail and cannot substitute, because a "
        "scope bounds what a token may ask for and not who it was minted for. AC-30 "
        "reads the version GetAgentRuntime returns by default and each other version "
        "an endpoint serves, on its own row. AC-31 asks the same of each gateway "
        "CUSTOM_JWT authorizer's allow-lists",
        [],
        4,
    ),
    (
        "AIR-ACR-ID-11",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-31", "AC-32"],
        "AC-31 reads each gateway JWT authorizer's allow-lists and fails a gateway "
        "that pins neither allowedAudience nor allowedClients, because it then honours "
        "any token its issuer minted for any application registered there; a list "
        "holding a blank or * value does not count, and a discoveryUrl that is not "
        "https fails. allowedScopes and customClaims bound what a token may ask for "
        "and not who minted it for whom, so they are credited but do not substitute. "
        "AC-32 covers the second door, where the token-exchange APIs take an end "
        "user's JWT without passing a gateway authorizer at all, and fails a cached "
        "principal holding GetWorkloadAccessTokenForJWT or CompleteResourceTokenAuth "
        "unless every InboundJwtClaim/iss value is a literal or a pattern narrower "
        'than *. A bare Action "*" and group policies count, a grant the principal\'s '
        "own Deny or boundary removes does not, and a principal the IAM cache could "
        "not read is N/A. The gateway's third, preventive layer, an SCP denying "
        "CreateGateway and UpdateGateway with StringNotEquals on "
        "bedrock-agentcore:DiscoveryUrl, is not judged",
        [],
        4,
    ),
    (
        "AIR-ACR-MEM-07",
        NOT_IMPL,
        None,
        None,
        [],
        "the only retention field AgentCore Memory exposes, eventExpiryDuration, is "
        "required on a standalone Memory and defaults to 30 days on harness-managed "
        "memory, and in both it bounds raw events only, a different thing from the one "
        "this control asks about. eventExpiryDuration is "
        "Required: Yes on CreateMemory, 3 to 365 days, and comes back on the Memory shape "
        "GetMemory returns, so a presence check over it passes for every memory that "
        "exists, which is worse than no check. It also bounds the wrong subject: the "
        "create page calls it event retention for raw events in short-term memory and "
        "applies it per event at write time, so updating it moves only later events, "
        "while what this control asks to bound is the long-term cross-session records "
        "extracted from those events, and neither CreateMemory nor Memory carries any "
        "retention field for those. Which value is short enough is the workload owner's "
        "judgment in any case, and this row will not invent a ceiling. What is readable "
        "is the namespace partitioning, already asserted under AIR-ACR-MEM-01 by AC-07 "
        "and AC-23 on {actorId}; session partitioning cannot join it, because AWS "
        "documents /summaries/{actorId}/{sessionId}/ for a summary strategy and "
        "/users/{actorId}/preferences/ for a user-preference strategy, so failing the "
        "absence of {sessionId} would fail a documented configuration. The log-retention "
        "clause is readable only as far as a period being set: AC-26 fails any log "
        "group under the AgentCore prefixes, /aws/vendedlogs/bedrock-agentcore/ "
        "included, that has no retentionInDays, and it is cited under other controls, "
        "not this one. Log retention bounds how long an operator can read what the "
        "agent logged, not what the agent can recall, so it cannot stand in for the "
        "bound this control asks about, and whether a period meets a compliance "
        "schedule is the workload owner's judgment. The Memory shape also carries "
        "namespaceKeys, whose entries can restrict a namespace key to allowedValues "
        "or a regexPattern. That narrows which namespaces records are written to, not "
        "how many records accumulate or how long they are kept, so it is not a limit "
        "either",
        [],
        None,
    ),
    (
        "AIR-ACR-MEM-12",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-18", "AC-19"],
        "AC-18 requires a CloudTrail advanced event selector that logs data events for "
        "AWS::BedrockAgentCore::Memory whenever the region holds a memory resource. A "
        "selector narrowed by readOnly, eventName, resources.ARN or any other field "
        "does not count, nor does a trail that is not logging or that neither spans "
        "all Regions nor is homed in the scanned one. An unreadable trail status is "
        "N/A. AC-19 requires each memory's APPLICATION_LOGS delivery, which carries "
        "the extraction and consolidation logs of long-term memory processing",
        [],
        4,
    ),
    (
        "AIR-ACR-OBS-02",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-18"],
        "AC-18 requires every data-event type in use, per resource family: runtimes "
        "need RuntimeEndpoint as well as Runtime, the AWS-managed code interpreter and "
        "browser need the unsuffixed types, and memory, gateways, identity (workload "
        "identities and credential providers) and policy engines are families of their "
        "own, so a trail that logs only the runtime types fails for the rest. A "
        "selector narrowed by readOnly, eventName, resources.ARN or any other field "
        "does not count, nor does a trail that is not logging or that neither spans "
        "all Regions nor is homed in the scanned one. An unreadable trail status is "
        "N/A",
        [],
        4,
    ),
    (
        "AIR-ACR-OBS-03",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-19"],
        "AC-19 requires a TRACES delivery wired to a destination for every runtime, "
        "gateway and memory, and an APPLICATION_LOGS delivery for every gateway and "
        "memory. A delivery source reporting INACTIVE does not count, and an "
        "unlistable runtime inventory is N/A. Runtime application logging is "
        "service-managed, WorkloadIdentity delivery is configured on the associated "
        "runtime or gateway resource, and policy engines have no log-destination "
        "surface, so those three legs need no separate assertion",
        [],
        4,
    ),
    (
        "AIR-ACR-OBS-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-20", "AC-21"],
        "AC-20 asserts a Deidentify data-protection policy and a customer managed key "
        "on the AgentCore log groups, and its Passed text says that AC-26 judges the "
        "key policy and that delivery destination log groups outside the AgentCore "
        "prefixes are not read. AC-21 fails a cached role or user that holds "
        'logs:Unmask on an unbounded log group resource. A bare Action "*", any '
        "pattern or NotAction that reaches the action and group policies count, a "
        "resource is unbounded when the group name is wildcard-only or a wider ARN "
        "segment is a wildcard, a grant the principal's own Deny or boundary removes "
        "does not count, and a policy that cannot be parsed or a principal the IAM "
        "cache could not read is N/A",
        [],
        4,
    ),
    (
        "AIR-ACR-OBS-06",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-22"],
        "AC-22 reads each Allow statement on an OAM sink policy by value. A statement "
        "naming principals passes only when no principal is a wildcard and no "
        "NotPrincipal is present; otherwise it needs aws:PrincipalOrgID or "
        "aws:PrincipalOrgPaths under StringEquals, StringEqualsIgnoreCase or "
        "StringLike with a value whose organization segment has no wildcard. A "
        "negated, IfExists or ForAllValues operator and a wildcard organization do not "
        "count",
        [],
        4,
    ),
    (
        "AIR-ACR-POL-06",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-37"],
        "AC-37 asserts the workload-independent half: a policy carrying a guardrails "
        "condition needs bedrock:InvokeGuardrailChecks on the gateway execution role, "
        "because the Policy data plane calls Bedrock Guardrails with that role's "
        "forward access session, and the grant counts after the role's own Deny and "
        "boundary, then fails when a service control policy attached to the account "
        "or an OU or root above it denies the action on Resource * with no condition, "
        "and withholds Passed for a conditioned Deny or an SCP it could not read. "
        "AC-37 reads each BedrockGuardrails call by value and fails a "
        "guardrail policy that no returned score (0, 0.2, 0.4, 0.6, 0.8, 1.0) can make "
        "act, or whose call names no category or data path. A suppressOutput policy in "
        "a plain when block counts, a threshold it cannot read is named in an N/A row, "
        "and a readable grant beside an unparseable policy does not pass. Whether this "
        "workload's content belongs at the authorization boundary at all, and which "
        "categories and reachable thresholds apply, is the workload owner's decision, "
        "which AC-37 reports and does not judge",
        [],
        4,
    ),
    (
        "AIR-ACR-RT-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-46"],
        "AC-46 fails a runtime that sets idleRuntimeSessionTimeout or maxLifetime at the "
        "service ceiling of 1209600 seconds, which lets one runaway session hold its "
        "resources for 14 days, that has no USAGE_LOGS delivery source of its own with a "
        "delivery to a destination, or that runs in a region where no alarm with actions "
        "reads ActiveSessionCount in AWS/Bedrock-AgentCore for Service AgentCore.Runtime. A "
        "runtime missing either lifecycle field, and a delivery or alarm inventory that could "
        "not be read, read N/A and never Passed. A runtime on a capacity provider names the "
        "instance types GetCapacityProvider reports, without judging their size, and an "
        "unread provider is N/A. AgentCore exposes no per-session memory or cost field to "
        "read, so usage is judged by whether it is recorded and alarmed. "
        "GetAgentRuntime reports the defaults of 900 and 28800 seconds for a runtime that "
        "sets neither field, so whether the owner chose the values is not readable, and every "
        "verdict says which values it found so the workload owner can judge whether the bound "
        "suits the task",
        [],
        4,
    ),
    # ------- FND, AI-resource subject: 11 controls -------
    (
        "AIR-FND-DAT-01",
        COVERED,
        None,
        [
            "bedrock_assessments",
            "sagemaker_assessments",
        ],
        ["BR-20", "BR-11", "BR-17", "SM-03"],
        "four checks cover the stores this control names: BR-20 the key of a managed "
        "store, an S3 Vectors store, and the OpenSearch Serverless, Aurora, OpenSearch "
        "domain and Neptune Analytics store each knowledge base names, and the Kendra "
        "index of a KENDRA knowledge base (kendra:DescribeIndex KmsKeyId; none named "
        "fails), each judged by "
        "DescribeKey as customer managed and Enabled, plus the default encryption of each "
        "data source bucket, which is where the ingested objects sit before any index "
        "exists, and each data source's transient data key; BR-11 the custom model's "
        "modelKmsKeyArn, else the customization job's outputModelKmsKeyArn, judged by "
        "DescribeKey, and the default encryption of every training, validation, "
        "invocation log source and output bucket the model names, and every such "
        "bucket a model customization job names, including a failed or stopped job "
        "that created no model; BR-17 the custom model's own modelKmsKeyArn, judged by DescribeKey; SM-03 the training output "
        "and volume keys. BR-11 used to read outputDataConfig.kmsKeyId, which the API never"
        " returns, so every custom model read as needing review until the documented field "
        "was read. FS-65 is not an incumbent: its finding is about S3 event notifications "
        "and says nothing about keys",
        [],
        5,
    ),
    (
        "AIR-FND-DAT-02",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-47"],
        "BR-47 reads the bucket policy of each S3 bucket on the Bedrock data path "
        "(knowledge base S3 sources, the invocation log S3 destination and its CloudWatch "
        "large-data bucket, the training, validation, output and distillation "
        "invocation-log source buckets of every customization job, batch inference "
        "input and output buckets, SageMaker training job buckets, AgentCore runtime "
        "code buckets and AgentCore browser recording buckets). It passes a "
        "bucket only when one Deny, conditioned by Bool or BoolIfExists on "
        "aws:SecureTransport false, reaches every principal, covers s3:*, and names both "
        "the bucket and its objects. A bucket with no policy fails, because S3 then "
        "accepts plaintext requests. For each Deny that falls short, the finding names the "
        "principals, resources or actions it misses, since a Deny scoped to some "
        "principals leaves the rest able to use HTTP. The aws:PrincipalIsAWSService "
        "false exception of the S3 example policy is credited, since the Deny still "
        "reaches every identity. The exact exclusion the recommendation prescribes for "
        "broken ingestion is credited too: a negated aws:PrincipalArn test with no "
        "set-operator prefix whose every value is an ARN with no wildcard or policy "
        "variable, or Bool aws:ViaAWSService false. The Passed text names each exempted "
        "ARN as keeping plaintext access, and a wildcard value, a set-operator prefix or "
        "another narrowing key still fails. Every data source and job is read "
        "with no cap, and a failed read withholds the Passed row, since an unread bucket "
        "may accept plaintext",
        [],
        5,
    ),
    (
        "AIR-FND-DAT-03",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-46"],
        "BR-46 judges the per-object leg by value on every AI source bucket: each "
        "knowledge base S3 source with its inclusion prefixes, and the training, "
        "validation and invocation-log source buckets of every customization job, "
        "the input bucket of every batch inference job, "
        "and the training data buckets of the newest 200 SageMaker training jobs. "
        "A failed or capped source read keeps every source off Passed. "
        "DescribeClassificationJob is read for each job that names the bucket or is its "
        "jobDetails.lastJobId, and a job clears the source only when it is SCHEDULED, "
        "RUNNING or IDLE, has run at least once with no ERROR, ran over existing "
        "objects, samples 100 percent, has data identifiers, and scopes in the source "
        "prefix. Automated discovery samples, so a MONITORED bucket with no such job "
        "fails. A source that an ingestion, customization or training job read "
        "before the Macie job was created fails, and one whose latest ingestion "
        "started after the job's last run is N/A. An exclude condition on extension, "
        "size, date or tag is N/A, and a failed read is N/A. The order of "
        "classification and ingestion per object needs object write times, which "
        "are not read. When Macie is off, completed Comprehend PII detection jobs "
        "(comprehend:ListPiiEntitiesDetectionJobs) are read: a source no job read "
        "in full fails, and a screened source is N/A, since a one-time job does not "
        "reach later objects. Real-time DetectPiiEntities calls are not read",
        [],
        5,
    ),
    (
        "AIR-FND-DAT-09",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-48"],
        "BR-48 reads both surfaces. DescribeEffectivePolicy on AISERVICES_OPT_OUT_POLICY "
        "answers what resolves for the account, and an absent effective policy fails "
        "because the account is then opted in. The effective document has the inheritance "
        "operators stripped, so an optOut default passes only when an opt-out policy "
        "attached to the root, an OU in the account's path or the account assigns "
        'optOut and sets ["@@none"] at services, services.default and '
        "services.default.opt_out_policy. A lock on the value alone lets a child add a "
        "service section that opts back in, so it fails, as does a locking policy "
        'that sets a child operator other than ["@@none"] on a section below its '
        "lock, and an unread path or policy is N/A. optOut and optIn are compared exactly, as the policy syntax spells "
        "them. The policy type does not govern Amazon Bedrock, and every row says it "
        "does not establish how Bedrock handles content",
        [],
        5,
    ),
    (
        "AIR-FND-DET-01",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-04", "BR-12"],
        "BR-04 reads loggingConfig for a destination, the log group's retention, the five "
        "modality flags (textDataDeliveryEnabled, imageDataDeliveryEnabled, "
        "embeddingDataDeliveryEnabled, videoDataDeliveryEnabled, audioDataDeliveryEnabled) "
        "and, for a CloudWatch destination, cloudWatchConfig.largeDataDeliveryS3Config, "
        "without which CloudWatch drops the largest payloads. Any modality flag set false "
        "fails, since that modality's prompts and completions go unlogged, and an absent "
        "flag is Not Applicable. An S3-only configuration is not failed on the "
        "large-payload field, which sits on CloudWatchConfig. BR-12 asserts a "
        "customer-managed key, judged by DescribeKey, on the S3 destination bucket, fails a "
        "bucket with no default encryption, and judges the CloudWatch Logs group the "
        "same way: a group with no kmsKeyId, or whose key is not an enabled customer "
        "managed key, fails. A key that cannot be described is Not Applicable",
        [],
        5,
    ),
    (
        "AIR-FND-DET-04",
        COVERED,
        None,
        ["bedrock_assessments", "sagemaker_assessments"],
        ["BR-34", "BR-41", "BR-49", "SM-26"],
        "three Bedrock checks, one per enforcement surface, and one detection check. "
        "BR-34 asserts a guardrail carries a "
        "PROMPT_ATTACK filter with inputEnabled true, inputAction BLOCK and inputStrength "
        "HIGH on the STANDARD content-filter tier, and fails a CLASSIC tier, which has no "
        "prompt-leakage detection. BR-34 also fails a Region whose model invocation "
        "logging is off or has textDataDeliveryEnabled not true, since the text output "
        "body is the record of a guardrail intervention, and reports an unread or absent "
        "flag as Not Applicable. SM-26 reads each GuardDuty detector's AI_PROTECTION "
        "feature, which raises the prompt-injection finding. BR-41 reads ListEnforcedGuardrailsConfiguration, including "
        "modelEnforcement.includedModels and excludedModels, where ALL with an empty "
        "excludedModels is every model and a non-empty excludedModels leaves holes, and "
        "selectiveContentGuarding, where SELECTIVE on either the system or the messages "
        "field leaves content the caller does not tag unguarded, and inputTags HONOR "
        "fails because the caller then picks what is evaluated. It reads each "
        "bedrock.guardrail_inference.<region> configuration of the effective "
        "Organizations Bedrock policy with the same model and content tests, credited "
        "only in its own Region, and credits a service control policy only when its "
        "Deny Resource covers every invoke resource type. "
        "BR-49 asserts the identity-policy fallback: each identity allowed to invoke a "
        "model is denied bedrock:InvokeModel and bedrock:InvokeModelWithResponseStream "
        "without an approved bedrock:GuardrailIdentifier. Those two actions authorize "
        "Converse and ConverseStream as well; the Converse operations have no IAM action of"
        " their own. Ceiling: whether an application runs ApplyGuardrail over retrieved "
        "and tool-returned content is runtime behaviour that no configuration API "
        "reports",
        [],
        5,
    ),
    (
        "AIR-FND-IAM-05",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-43", "AC-45", "AC-02", "AC-48"],
        "AC-45 scopes what a tool execution role may do and AC-02 flags wildcard or "
        "allow-except AgentCore grants on all resources across every cached role and "
        "user. AC-43 asserts the confused-deputy guard on evaluation roles. AC-48 "
        "reads the trust policy of every runtime, gateway, browser, code interpreter, "
        "memory, payment manager and harness execution role: it fails a service "
        "principal or * unless an aws:SourceAccount or aws:SourceArn condition names "
        "the assessed account in every value, fails an account-root or bare account-id "
        "principal unless its condition names the calling principal, and fails a role "
        "that more than one AgentCore resource names, since the shared role carries "
        "the union of what each needs. The sharing leg runs at the primary Region and "
        "compares the roles of every assessed Region, and an unread Region is N/A. "
        "The sharing Passed is withheld while any family "
        "could not be listed, so it reads N/A until "
        "bedrock-agentcore:ListPaymentManagers and bedrock-agentcore:ListHarnesses are "
        "granted. AC-27 also reads the gateway roles",
        [],
        5,
    ),
    (
        "AIR-FND-NET-01",
        COVERED,
        None,
        [
            "agentcore_assessments",
            "sagemaker_assessments",
            "bedrock_assessments",
        ],
        ["AC-01", "SM-10", "SM-11", "SM-28", "SM-33", "BR-39"],
        "spans three modules, because 'AI workloads run privately' has no single host. Six "
        "checks read the subnets a resource names and resolve each subnet's route table, "
        "the explicit association first and the VPC main table otherwise, and fail a route "
        "to an igw- gateway that is not a blackhole: AC-01 for the runtime, SM-10 for "
        "notebooks, SM-11 for models, SM-28 for HyperPod clusters, SM-33 for training jobs "
        "together with EnableNetworkIsolation, and BR-39 for marketplace model endpoints. "
        "An egress-only gateway, a NAT gateway and a peering connection do not make a "
        "subnet public. A route read that fails is reported Not Applicable and never passes. "
        "AC-01 also reads custom Code Interpreter and Browser subnets and fails a VPC "
        "runtime reporting requireServiceS3Endpoint true; SM-10 also reads every Studio "
        "domain's AppNetworkAccessType and SubnetIds; SM-33 also reads every processing "
        "job's NetworkConfig and every training job with no item cap; BR-39 resolves "
        "every subnet, and also fails every Bedrock model customization job and batch "
        "inference job whose vpcConfig is absent or names a subnet routed to an igw- "
        "gateway. Ceiling: Lambda GetFunctionConfiguration and ECS DescribeServices "
        "return no field that marks a function or service as AI inference, so general "
        "Lambda and ECS compute is not in the population",
        [],
        5,
    ),
    (
        "AIR-FND-NET-02",
        COVERED,
        None,
        [
            "agentcore_assessments",
            "bedrock_assessments",
        ],
        ["AC-08", "BR-02"],
        "AC-08 judges private DNS on interface endpoints, the endpoint policy, and whether "
        "the endpoint's security groups admit inbound traffic from 0.0.0.0/0 or ::/0, on "
        "the AgentCore interface endpoints and on the S3, DynamoDB and SageMaker endpoints "
        "in the same VPCs, so an endpoint left on the default full-access policy is "
        "reported. BR-02 reads "
        "private DNS and the endpoint policy on the Bedrock endpoints, where it used to "
        "report only that an endpoint existed. An endpoint policy counts as scoped only "
        "on exact principal or network values: a Deny needs one negated condition and "
        "Resource '*', and an Allow a positive test that is not IfExists. BR-02 also fails "
        "a Lambda function whose role is granted a Bedrock or AgentCore surface (the "
        "AgentCore data plane, control plane and Gateway each count) with no private-DNS "
        "endpoint for that surface in the function's VPC, and does the same for EC2 "
        "instances, ECS services (every cluster, awsvpc subnets, task definition role) "
        "and SageMaker notebook instances, failing a notebook with no subnet, and for "
        "each VPC-mode AgentCore runtime version, including the versions its endpoints "
        "serve. It does the same for ECS tasks started outside a service (task role "
        "override or task definition role, ENI subnet), for every model behind a "
        "SageMaker endpoint (production and shadow variants and inference "
        "components, with the model's execution role and VPC), and for EKS pod "
        "identity associations (the cluster's VPC and the association's role). BR-02 "
        "counts only endpoints in the available state. A workload granted a Bedrock or "
        "AgentCore surface must also have a private-DNS endpoint for each SageMaker API "
        "or runtime surface its role is granted, and a gateway or private-DNS endpoint "
        "for S3 and DynamoDB; a gateway endpoint is credited for its whole VPC, because "
        "subnet route tables are not compared with the endpoint's. Partial, "
        "ceiling reached for IAM roles for service accounts (IRSA): a pod that takes "
        "its role through IRSA is not read, because which service account a pod runs "
        "as, and the role annotation on it, are held by the Kubernetes API, which "
        "no AWS API returns",
        [],
        5,
    ),
    (
        "AIR-FND-NET-04",
        COVERED,
        None,
        "agentcore_assessments",
        ["AG-27", "AG-39"],
        "AG-27 asserts association: a gateway names a webAclArn. AG-39 reads the rule "
        "content behind it through wafv2:GetWebACL and fails an ACL with no rule, AWS "
        "managed rule group or default action that blocks, no SQL injection or cross-site "
        "scripting coverage, no rate-based rule, or an association body inspection limit "
        "left at the 16 KB default, since a tool call carries its arguments in the body. A "
        "customer rule group or a non-AWS managed rule group, whose rules AG-39 does not "
        "read, turns a missing filter into Not Applicable with the group named. Only a "
        "rule whose action is Block is credited. AWS managed groups are credited by name, "
        "and not for a filter whose providing rule is overridden to an action other than "
        "Block or excluded. A customer SQL injection statement is credited only at "
        "SensitivityLevel HIGH, and a customer SQL injection or cross-site scripting "
        "statement on the body only with OversizeHandling MATCH, or NO_MATCH beside a "
        "rule that blocks an oversized body. The statements inside an AWS managed group "
        "are not returned by GetWebACL, so their sensitivity and oversize handling are "
        "not read. A gateway whose wafConfiguration failureMode is FAIL_OPEN "
        "fails, because it allows a request when AWS WAF cannot be evaluated, and one "
        "that reports no failureMode is Not Applicable. The subject is AgentCore gateways",
        [],
        5,
    ),
    (
        "AIR-FND-NET-06",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-01", "AC-15", "AC-49"],
        "AC-01 fails a runtime or built-in tool whose security groups together allow "
        "egress to 0.0.0.0/0 or ::/0, unioning the ranges so 0.0.0.0/1 plus "
        "128.0.0.0/1 fails, fails a tool in PUBLIC or SANDBOX network mode, and "
        "requires attached SCPs that deny creating a runtime or tool outside a VPC or "
        "outside a pinned subnet and security group list. AC-15 requires each custom "
        "code interpreter to run in VPC mode with subnets and security groups. AC-49 "
        "asserts egress by destination "
        "name on each VPC that hosts an AgentCore runtime, browser or code interpreter: it "
        "walks the associated DNS Firewall rule groups in ascending association Priority "
        "and the enforcing rules in each in ascending Priority, as DNS Firewall evaluates "
        'them, and judges the first rule whose customer domain list holds "*", because the '
        "first match ends evaluation. It passes only when that rule is a BLOCK with no "
        "query type, which is the walled garden pattern Route 53 documents; an ALLOW or "
        'ALERT over "*" fails, and rules after the deciding rule are not reached. '
        'ListFirewallDomains returns that entry fully qualified as "*.", and '
        "AC-49 reads either spelling. Rule groups whose rules only BLOCK over an AWS managed "
        'list, over DNS threat protection, over a list without "*", or over "*" for one '
        "query type fail, because every name or query type those rules do not match is "
        "answered. A deciding BLOCK passes only when the VPC's DNS Firewall config has "
        "FirewallFailOpen DISABLED: ENABLED fails, because VPC Resolver answers every "
        "query while DNS Firewall is impaired, and any other value is Not Applicable with "
        "the value named. An IAM Deny on the bedrock-agentcore:subnets or :securityGroups keys "
        "does not substitute for this: the devguide lists those keys while the "
        "machine-readable IAM reference lists none for CreateGatewayTarget or "
        "UpdateGatewayTarget, so such a Deny can fail open",
        [],
        5,
    ),
]

# The 27 machine-checkable controls whose subject is the account, identity,
# network or runtime an AI workload sits on (FND, SLF, PHY). The user brought
# them into scope on 2026-09-27 so that the ledger covers every machine-checkable
# AISF control, and ruled that they are hosted in the existing modules. Each
# covered row names every check id whose shipped code asserts it.
FOUNDATION_ROWS = [
    # ---------------- covered: 26 controls ----------------
    (
        "AIR-FND-DAT-04",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-43"],
        "BR-43 passes only when an attached service control policy denies the "
        "Bedrock invocation actions with a condition on aws:RequestedRegion and a "
        "global inference profile cannot route around it, which is the enforcing "
        "half of a data-residency requirement. Which Regions are approved is the "
        "customer's decision, so BR-43 asserts that an enforcing Deny exists and "
        "reports the Region values it found, and never judges whether that list "
        "is the right one. The Deny must cover agent, flow, RetrieveAndGenerate and "
        "AgentCore runtime invocation too, an aws:PrincipalArn exemption with a "
        "wildcard role or user name is not credited, and an unread inference profile "
        "list makes the row N/A. The storage half is judged on the AI Service "
        "Region Control row: the Deny must also cover bedrock:CreateKnowledgeBase, "
        "bedrock:CreateModelCustomizationJob, bedrock-agentcore:CreateMemory, "
        "s3:CreateBucket, s3vectors:CreateVectorBucket, aoss:CreateCollection and "
        "the SageMaker endpoint, notebook, training, processing and transform "
        "creation actions",
        [],
        6,
    ),
    (
        "AIR-FND-IAM-01",
        COVERED,
        None,
        [
            "bedrock_assessments",
            "sagemaker_assessments",
        ],
        ["BR-42", "SM-02"],
        "BR-42 fails each cached role or user whose Bedrock invocation grant reaches "
        "every model instead of naming foundation-model or inference-profile ARNs. "
        "On the training data buckets of customization and SageMaker training jobs "
        "it fails an identity s3:GetObject grant that reaches the bucket through a "
        "wildcard, and reads each bucket policy with s3:GetBucketPolicy: an Allow "
        "of s3:GetObject to every principal with no condition fails, a conditioned "
        "one is named and not evaluated, and an unread policy withholds Passed. "
        "SM-02 fails each cached role or user whose sagemaker:InvokeEndpoint grant "
        "reaches every endpoint with no aws:ResourceTag condition that narrows "
        "it; a Like value made only of wildcards narrows nothing. Together they "
        "cover the model and the inference endpoint; which identities should hold "
        "those grants is a workload decision, so a grant that names its resources "
        "is not judged further",
        [],
        6,
    ),
    (
        "AIR-FND-NET-03",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-49"],
        "AC-49 asserts an egress allow-list by destination name on each VPC that "
        "hosts an AgentCore runtime, browser or code interpreter. It passes only "
        'when the first DNS Firewall rule that matches "*" is a BLOCK, which is '
        "the walled garden pattern: the domains allowed by earlier rules are the "
        "allow-list and every other name is refused. It fails an ALLOW or ALERT "
        'over "*", and a VPC whose DNS Firewall fails open. The same check covers '
        "AIR-FND-NET-06",
        [],
        6,
    ),
    (
        "AIR-SLF-RT-02",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-01"],
        "The population is the account's AgentCore runtimes, code interpreters and "
        "browsers, where AgentCore runs the customer's own agent container and tools. "
        "Agents hosted on ECS, EKS, Lambda or EC2 are outside it, because no API field "
        "marks a task, function or instance as agent code. AC-01 unions the outbound "
        "ranges of every security group on each resource and fails one whose groups "
        "together allow 0.0.0.0/0 or ::/0, fails a tool in PUBLIC or SANDBOX network "
        "mode, fails a runtime, custom code interpreter or custom browser subnet whose "
        "route table sends traffic to an internet gateway, and adds a Global leg "
        "requiring attached SCPs that deny creating a runtime or tool with no subnet or "
        "security group, or with one outside a pinned list",
        [],
        6,
    ),
    (
        "AIR-FND-ACC-02",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-43"],
        "BR-43 covers the Region half: it passes on an attached service control "
        "policy that denies the invocation actions on aws:RequestedRegion with "
        "global routing closed. Its model leg, published as 'Bedrock Approved "
        "Model Control', passes when an attached service control policy denies "
        "bedrock:InvokeModel and bedrock:InvokeModelWithResponseStream outside a "
        "named list of foundation-model or inference-profile ARNs, given as a "
        "NotResource or as a negated condition. Its Region leg covers agent, flow, "
        "RetrieveAndGenerate and AgentCore runtime invocation and credits no "
        "wildcard aws:PrincipalArn exemption. Converse and ConverseStream have "
        "no IAM action of their own and are authorized by those two, so the leg "
        "matches only them. A Deny written with NotAction is read as covering "
        "those actions, and arn:aws:bedrock:*::foundation-model/* counts as no "
        "list. The leg asserts that a model list exists and never which models "
        "are approved. Its AI Service Region Control row requires the same "
        "Region Deny over SageMaker endpoint, notebook, training, processing, "
        "transform and synchronous and asynchronous invocation, Bedrock knowledge "
        "base and customization job creation, AgentCore memory creation, and S3 "
        "bucket, S3 Vectors bucket and OpenSearch Serverless collection creation. "
        "No leg reads a Deny on unapproved AI services. Organization policies are "
        "readable only from the management account or a delegated administrator, "
        "so from any other member account the leg is Not Applicable",
        [],
        6,
    ),
    (
        "AIR-FND-DAT-08",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-04"],
        "BR-04 credits an enabled S3 lifecycle Expiration rule on the invocation "
        "log bucket only when its filter covers the log prefix. Expiration "
        "deletes current versions alone, so on a bucket whose GetBucketVersioning "
        "Status is Enabled or Suspended BR-04 also requires an enabled rule with "
        "NoncurrentVersionExpiration.NoncurrentDays over that prefix, and fails "
        "the bucket without one, because each expired object leaves a noncurrent "
        "version that is never deleted. A missing Status means the bucket was "
        "never versioned, and the Expiration rule alone decides it. An Object Lock "
        "default retention beside the rule fails, since Lifecycle does not delete a "
        "retained version. A replicated log bucket is N/A, because per-object "
        "ReplicationStatus needs s3:GetObject, which is not granted. Every page of "
        "ListMemories is read and each AgentCore memory's eventExpiryDuration is read "
        "with GetMemory: a read memory is Passed and its period in days is named as a "
        "service-enforced expiry, with no claim that deletion ran, and an unread list "
        "or memory is N/A naming the action. The field is required and bounded 1 to "
        "365 days, so a readable memory has no Failed outcome, and no retention "
        "threshold is assumed",
        [],
        6,
    ),
    (
        "AIR-FND-DET-09",
        COVERED,
        None,
        [
            "agentcore_assessments",
            "bedrock_assessments",
        ],
        ["AC-26", "BR-12"],
        "AC-26 reads deletionProtectionEnabled on each AgentCore runtime log group and "
        "on aws/spans, and BR-12 on the CloudWatch log group the Bedrock invocation "
        "logging configuration names, each from DescribeLogGroups by "
        "logGroupNamePrefix. Both fail a group where the value is false or absent, "
        "since CloudWatch Logs leaves deletion protection off by default and an "
        "administrator can otherwise delete the audit trail with the group. AC-26 also "
        "requires an attached SCP that denies logs:DeleteLogGroup, "
        "logs:PutRetentionPolicy, logs:PutLogGroupDeletionProtection and "
        "logs:DeleteSubscriptionFilter on those groups in every Region, exempting at "
        "most principals named by aws:PrincipalArn, and fails a trail that records the "
        "Region with log file validation off. An unreadable trail is N/A",
        [],
        6,
    ),
    (
        "AIR-FND-IAM-09",
        COVERED,
        None,
        [
            "bedrock_assessments",
            "sagemaker_assessments",
            "agentcore_assessments",
            "agent_registry_assessments",
        ],
        ["BR-01", "SM-02", "AC-02", "AR-01"],
        "BR-01, SM-02, AC-02 and AR-01 each read every attached, inline and "
        "group policy of every cached role and user, AWS managed included, and "
        "fail a wildcard Action pattern or a NotAction Allow that grants both a "
        "read and a write action on one resource type, as the service "
        'authorization reference classifies them. A bare "*", "*:*" and a '
        'partial pattern such as "bedrock:*Guardrail*" count. BR-01 reads the '
        "bedrock namespace, and the s3, dynamodb and s3vectors namespaces for an "
        "identity granted a Bedrock action. An action counts only after "
        "account-wide Denies and the permissions boundary. A condition applies "
        "to the read and the write alike, so ABAC does not separate them, and "
        "the Resource entries drop only the resource types they cannot name. A "
        "Passed is held as N/A while principal_errors names an unread "
        "principal. Service control policies are not evaluated per principal "
        "and can only make a row a false Failed. API Gateway method authorizers "
        "and Verified Permissions policy stores are not read: no field ties one "
        "to an AI workload",
        [],
        6,
    ),
    (
        "AIR-FND-DET-02",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-26", "SM-04", "SM-36"],
        "SM-04 ('GuardDuty Enabled') and SM-26 ('GuardDuty AI Protection') read "
        "the GuardDuty detector and its AI_PROTECTION feature, which is threat "
        "detection for the account. SM-26 fails a Region with no detector or a "
        "detector whose Status is not ENABLED. SM-36 covers the Security Hub AI security "
        "standard the control also asks for: it reads GetEnabledStandards in each "
        "Region and passes when a StandardsArn contains "
        "standards/ai-security-best-practices/v/1.0.0 with StandardsStatus READY "
        "or INCOMPLETE. It fails otherwise, and a Region where Security Hub is not "
        "enabled fails with that reason",
        [],
        6,
    ),
    (
        "AIR-FND-IAM-03",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-45", "BR-50"],
        "BR-45 ('Bedrock API Key Inventory') covers the Bedrock API keys, which "
        "are one kind of long-lived credential, and fails every active long-term "
        "key, one inside the lifetime cap at Medium. BR-50 covers the other, IAM user "
        "access keys: it reads ListAccessKeys for each cached IAM user whose "
        "attached, inline or group policies grant any bedrock:, sagemaker:, "
        "bedrock-agentcore: or bedrock-mantle: action, reads included, and whose permissions boundary "
        "allows one too, and for each cached user who can assume a cached role "
        "holding such an action: the role's trust policy, read with iam:GetRole, "
        "names the user, or trusts the account or every principal and the user's "
        "identity policies allow sts:AssumeRole on the role. An unread trust "
        "policy is N/A. It fails each Active key and reports its age from CreateDate. "
        "Inactive keys do not count. A separate BR-50 row reads iam:GetAccountSummary "
        "and fails when AccountAccessKeysPresent is 1, a root user access key",
        [],
        6,
    ),
    (
        "AIR-FND-NET-07",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-04", "SM-37"],
        "SM-04 ('GuardDuty Enabled') reads that a detector exists and is enabled, "
        "which does not say whether network behavior is analysed. SM-37 reads the "
        "detector's Features and passes when LAMBDA_NETWORK_LOGS is ENABLED, and "
        "fails otherwise. A Region with no detector is Not Applicable to SM-37, "
        "since SM-04 already fails it",
        [],
        6,
    ),
    (
        "AIR-SLF-CMP-01",
        COVERED,
        None,
        [
            "bedrock_assessments",
            "agentcore_assessments",
        ],
        ["BR-33", "AC-50"],
        "BR-33 ('Amazon Inspector Lambda Code Scanning Check') covers Lambda "
        "functions, zip and container image. Its population is every function that "
        "names Bedrock in its configuration or whose role the IAM cache shows "
        "granted a Bedrock or AgentCore action, and it fails a function encrypted "
        "with a customer managed key, which Inspector does not scan, or tagged "
        "InspectorExclusion=LambdaStandardScanning. Tags come back only to a "
        "caller allowed lambda:ListTags, which the Bedrock role holds; a "
        "function whose tags were still withheld is Not Applicable. It reads "
        "every inspector2:ListCoverage page and fails a zip function whose "
        "$LATEST PACKAGE or CODE record is missing or not ACTIVE, naming the "
        "reason. A container-image function fails when the image digest "
        "GetFunction resolves it to has no ACTIVE AWS_ECR_CONTAINER_IMAGE "
        "coverage record in its repository, and an image with no resolved "
        "digest or from another account is Not Applicable. It also names the enabled EventBridge rules that match Inspector "
        "findings without reading their targets. AC-50 covers AgentCore runtime "
        "images: it reads "
        "GetRegistryScanningConfiguration and passes when scanType is ENHANCED "
        "and a CONTINUOUS_SCAN rule has wildcard filters that match every ECR "
        "repository an AgentCore runtime's containerUri names, and every one "
        "whose name marks it as AgentCore or Bedrock agent code. SCAN_ON_PUSH "
        "alone fails, because a CVE published after the push is not reported. "
        "BASIC scanning fails, and a filter that misses a repository fails and "
        "names it. A runtime whose image could not be read, or comes from a "
        "registry in another account or region, is Not Applicable. No check "
        "reads a deploy gate that blocks on finding severity, because no AWS "
        "API records whether a pipeline stage fails on an Inspector finding",
        [],
        6,
    ),
    (
        "AIR-SLF-RT-04",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-04", "SM-38"],
        "SM-04 ('GuardDuty Enabled') reads that a detector is enabled, which does "
        "not monitor process, file or network activity inside a workload. SM-38 "
        "reads the detector's Features and passes when RUNTIME_MONITORING is "
        "ENABLED, reporting the ECS_FARGATE_AGENT_MANAGEMENT, "
        "EC2_AGENT_MANAGEMENT and EKS_ADDON_MANAGEMENT states without failing on "
        "them. EKS_RUNTIME_MONITORING alone fails, because it covers EKS only",
        [],
        6,
    ),
    (
        "AIR-FND-ACC-09",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-35"],
        "SM-35 reads the management account id from DescribeOrganization and "
        "calls ListDelegatedAdministrators for each of a fixed list of 12 service "
        "principals: GuardDuty, Security Hub, Inspector, Macie, Config "
        "(config.amazonaws.com), Config multi-account setup "
        "(config-multiaccountsetup.amazonaws.com), IAM Access Analyzer, "
        "CloudTrail, Detective, Security Lake, Firewall Manager and Audit "
        "Manager, which the finding states. One row per service passes "
        "when an ACTIVE delegated administrator is not the management account "
        "and ListAWSServiceAccessForOrganization lists the service principal as "
        "having trusted access. It fails when there is no such administrator, "
        "when it is the management account, or when trusted access for the "
        "principal is not enabled; an unread trusted-access list makes each "
        "administered service Not Applicable. A member account that cannot call "
        "the API is Not Applicable with the reason",
        [],
        6,
    ),
    (
        "AIR-FND-DAT-05",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-52"],
        "BR-52 reads GetObjectLockConfiguration on each bucket on the Bedrock data "
        "path: knowledge base sources, the invocation log bucket and its "
        "large-data bucket, the buckets of customization, batch inference and "
        "SageMaker training jobs, and AgentCore code and recording buckets. A "
        "bucket passes only when Object Lock is Enabled with "
        "a default retention in COMPLIANCE mode and a period in Days or Years. "
        "GOVERNANCE mode fails, because a principal holding "
        "s3:BypassGovernanceRetention can delete the objects, and so do no Object "
        "Lock configuration and a lock with no default retention. A bucket whose "
        "configuration the role cannot read, such as one in another account, is "
        "Not Applicable. A bucket without that lock can pass through AWS Backup: its "
        "newest completed recovery point must sit in a vault whose Vault Lock is in "
        "compliance mode past its LockDate grace period with a minimum retention, "
        "and a point created before the LockDate must itself be kept at least that "
        "long. Governance mode, a grace period and an unread recovery point list do "
        "not clear a bucket. The Bedrock role holds neither "
        "backup:ListRecoveryPointsByResource nor backup:DescribeRecoveryPoint, so "
        "a bucket without the Object Lock stays Failed and its row says whether a "
        "backup covers it is unknown, naming the action as not granted. That is a "
        "missing grant, not a ceiling: both APIs return the fields the check judges",
        [],
        6,
    ),
    (
        "AIR-FND-DAT-10",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-55"],
        "BR-55 reads the default key policy of each customer-managed KMS key. A "
        "key whose policy carries a kms:RecipientAttestation condition is declared "
        "enclave-bound, and every other key is Not Applicable. The condition keys "
        "come in two families, ImageSha384 and PCR<n> for Nitro Enclaves and "
        "NitroTPMPCR<n> for NitroTPM. Both are judged and each row names the "
        "family. An exact value on any of those keys pins the key. An "
        "enclave-bound key fails when no statement pins it, and when an Allow "
        "grants kms:Decrypt, kms:DeriveSharedSecret, kms:GenerateDataKey, "
        "kms:GenerateDataKeyPair or kms:ReEncryptFrom, which carries no "
        "attestation, with no attestation condition and no Deny covers "
        "it. A Deny to every principal counts when it covers all five operations "
        "and tests the attestation key with Null true or a negated operator. A "
        "positive operator, with or without IfExists, does not count. The default "
        "statement that grants the account root is such a bypass unless it "
        "carries an attestation pin or that Deny is present. A Null Deny alone "
        "refuses a missing attestation but admits any image, so a key with no "
        "exact pin still fails. A Nitro Enclave image pin alone fails too: every "
        "releasing statement needs an exact image value (ImageSha384, PCR0 or "
        "PCR8) and an exact deployment value (PCR3 or PCR4), each in itself or "
        "through a single-test Deny, because the image file is not secret, so a "
        "PCR3-only pin fails. A Deny narrowed by another condition key is not credited. Every "
        "grant is read, and a grant of the five operations fails the key unless a "
        "Deny covers it; unread grants are N/A. Which workloads must be "
        "enclave-bound is the customer's decision, and no API records it, so a key "
        "without the condition is never failed",
        [],
        6,
    ),
    (
        "AIR-FND-GOV-02",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-53"],
        "BR-53 passes the ARNs the module inventories from the Bedrock list APIs "
        "(agents, knowledge bases, flows, prompts, guardrails, custom and imported "
        "models, provisioned throughput, application inference profiles) to "
        "GetResources in batches of 100 and fails each resource with no owner tag "
        "whose value names someone. The key must be owner after any namespace, "
        "alone or with a closed list of qualifiers, so previous_owner is not "
        "credited, and a placeholder value such as TBD is not credited. Whether a "
        "value resolves to a person is not verified, and no API marks a resource "
        "as production. The Bedrock "
        "population is the inventory, never a ResourceTypeFilters sweep, because "
        "GetResources returns only resources that are or were tagged, so a sweep "
        "omits the resources that most need an owner. SageMaker and AgentCore "
        "resources are read through a ResourceTypeFilters sweep: each returned "
        "resource without an owner tag fails, and the sweep never passes. SageMaker "
        "endpoints, models, notebook instances, training jobs and domains, and agent "
        "runtimes, memories, gateways, custom browsers and custom code interpreters, "
        "listed by their SageMaker and AgentCore list APIs and absent from the "
        "sweep, fail as never tagged",
        [],
        6,
    ),
    (
        "AIR-FND-IAM-02",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-51"],
        "BR-51 reads each cached IAM user whose attached, inline or group "
        "policies grant a non-read bedrock:, sagemaker: or bedrock-agentcore: "
        "action, and fails a user that has a console password (GetLoginProfile "
        "succeeds) and no MFA device. NoSuchEntity means no console password. "
        "A Deny with Null true on aws:MultiFactorAuthPresent clears active access "
        "keys only, because a console session carries the key as false; only "
        "BoolIfExists false clears a console password. "
        "IAM Identity Center users are outside it: no sso-admin operation returns "
        "an instance's MFA settings, and the finding says so. BR-51 lists the "
        "Regions enabled for the account (account:ListRegions, ENABLED and "
        "ENABLED_BY_DEFAULT) and calls sso:ListInstances in each. When any "
        "Region returns an instance the Passed row is N/A, partial, ceiling "
        "reached. When a Region cannot be read, or the enabled Regions cannot be "
        "listed and only the primary scan Region is read, the row is N/A. It "
        "passes only when every enabled Region was read and none returns an "
        "instance, and no AI write role in the cache trusts a federated identity "
        "provider. A member account lists no organization instance, so an "
        "AWSReservedSSO_ or SAML role granted AI writes is named and keeps the row "
        "at N/A, because whether the provider required MFA is not read. That row "
        "names each permission set whose inline or AWS managed policies grant an "
        "AI write (sso:ListPermissionSets, sso:GetInlinePolicyForPermissionSet, "
        "sso:ListManagedPoliciesInPermissionSet, iam:GetPolicyVersion), and fails "
        "each one where no policy of the permission set carries a Deny keyed on "
        "one aws:PrincipalTag value over every AI service it grants. Each instance's "
        "attributes for access control are read with "
        "sso:DescribeInstanceAccessControlAttributeConfiguration, and each guarded "
        "permission set names the source its tag key is set from, or that the key is "
        "not a configured attribute and comes only from the identity provider's SAML "
        "assertion; whether that source reflects MFA is not judged. A permission "
        "set whose AWS managed policy is unread is N/A. Customer managed policy "
        "references resolve in each target account, so they are named and not "
        "read, and that permission set is not judged; the attributes for access "
        "control that set the tag are not read",
        [],
        6,
    ),
    (
        "AIR-FND-NET-08",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-51", "AG-39"],
        "AC-51 judges the web ACL on each AgentCore gateway for the AWS "
        "Anti-DDoS managed rule group. Front doors other than AgentCore gateways "
        "(API Gateway, ALB, CloudFront) are not identifiable as AI entry points by "
        "any API, so they are not judged. The gateway's web ACL comes from the "
        "lookup AG-27 and AG-39 already make, and the ACL passes when its rules "
        "include AWSManagedRulesAntiDDoSRuleSet with an override action other than "
        "Count. A passing finding names the Block and Challenge sensitivities the "
        "group runs with, API defaults filled in, and does not grade them, since "
        "the control asks for a deliberate choice and names no value. Shield "
        "Advanced enrollment is not judged, because shield:CreateProtection "
        "accepts no AgentCore gateway ARN. AG-39 is the request-rate leg: it fails "
        "a gateway web ACL with no rate-based rule whose action is Block",
        [],
        6,
    ),
    (
        "AIR-PHY-EDG-01",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-41"],
        "SM-41 reads each AWS IoT policy that is attached to a target and fails "
        "an Allow on iot:Publish, iot:Subscribe, iot:Receive or iot:Connect whose "
        "Resource ends in topic/*, topicfilter/*, client/* or is * without the "
        "${iot:Connection.Thing.ThingName} variable filling a whole path "
        "segment, since that policy grants every device the same reach, or a "
        "device the reach of every thing whose name starts or ends with its "
        "own. It also fails a Connect Allow with no "
        "iot:Connection.Thing.IsAttached condition. A policy attached to a "
        "thing group reaches the certificates of the group's things, child "
        "groups included, and each is judged like a certificate attached "
        "directly",
        [],
        6,
    ),
    (
        "AIR-SLF-RT-05",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-39"],
        "SM-39 reads the managed vpc-cni add-on of each EKS cluster and passes "
        "when its configurationValues sets enableNetworkPolicy to true. A pass "
        "means network-policy enforcement is available on the cluster, not that "
        "NetworkPolicy objects restrict pod traffic, which only the Kubernetes API "
        "returns. Absent or false fails. A cluster with no managed vpc-cni add-on "
        "is Not Applicable, because a self-managed CNI's configuration is not "
        "readable through the EKS API, and so is an EKS Auto Mode cluster, which "
        "sets network policy on its NodeClass and runs no managed vpc-cni add-on",
        [],
        6,
    ),
    (
        "AIR-SLF-RT-06",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-40"],
        "SM-40 lists Secrets Manager secrets, skipping those another service "
        "owns, and passes a secret when rotation is enabled and the last rotation "
        "falls within its schedule plus one day. It fails a secret with rotation "
        "off, one that has never rotated, and one whose schedule allows a gap "
        "longer than 90 days, the default of Security Hub control "
        "SecretsManager.4",
        [],
        6,
    ),
    (
        "AIR-SLF-RT-08",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-54"],
        "BR-54 reads the function URL's AuthType and CORS AllowOrigins and the "
        "resource policy of every Lambda function, alias and published version. "
        "It fails a function URL with AuthType NONE, and says the URL accepts no "
        "requests yet when the policy of the URL's own qualifier grants no public "
        "invoke. It fails a URL whose CORS origins hold a wildcard. It fails an "
        'Allow to Principal "*" on lambda:InvokeFunction* or lambda:* unless a '
        "positive, non-IfExists aws:SourceAccount, aws:PrincipalOrgID or "
        "aws:SourceArn test names one account, organization or source ARN in "
        "every value. lambda:FunctionUrlAuthType and lambda:InvokedViaFunctionUrl "
        "do not clear it, because they describe how the function is called. On "
        "the primary Region it judges the attached service control policies for a "
        "Deny on lambda:CreateFunctionUrlConfig and lambda:UpdateFunctionUrlConfig "
        "when lambda:FunctionUrlAuthType is NONE. Partial, ceiling reached: it "
        "reports configuration and does not claim the function is reachable, and "
        "a CloudFront or WAF front for a public URL is not read",
        [],
        6,
    ),
    (
        "AIR-SLF-AGT-05",
        COVERED,
        None,
        "bedrock_assessments",
        ["BR-57"],
        "BR-57 takes the agent roles to be the roles Bedrock agents run as, from "
        "GetAgent and from GetAgentVersion for every version an alias routes to, "
        "and the roles AgentCore runtimes run as, from GetAgentRuntime for the "
        "latest version and each endpoint's live and target version. A Bedrock "
        "collaborator, read with ListAgentCollaborators on every supervisor "
        "version and resolved through its alias routing, fails when it runs as "
        "its supervisor's own role, and two collaborators of one supervisor fail "
        "when they run as one role. Two agents fail when they run as one role, "
        "while versions of one agent may share it. From the primary Region, "
        "every assessed Region's agent roles are read and a role run by agents "
        "in two Regions fails; an unread Region withholds Passed. Every cached "
        "role's trust "
        "policy is read with iam:GetRole. An Allow on sts:AssumeRole is an edge from an agent role "
        "when it names that role, or names its account or * and the agent role's "
        "own identity policy allows sts:AssumeRole on the target, and a boundary "
        "that allows sts:AssumeRole nowhere removes it. An edge passes only on a "
        "positive string test of sts:SourceIdentity with no wildcard value, no "
        "IfExists form and no ForAllValues: prefix. An unread agent, runtime, "
        "collaborator alias, trust policy or cached principal reports N/A, never "
        "Passed. Partial, ceiling reached: no AWS API marks which ECS task or "
        "Lambda execution roles host an agent, GetAgentRuntime returns no field "
        "for a runtime session's token scope, and a role in another account that "
        "trusts an agent role is not read",
        [],
        6,
    ),
    (
        "AIR-SLF-CMP-08",
        COVERED,
        None,
        "sagemaker_assessments",
        ["SM-43"],
        "SM-43 judges every serving container of each InService endpoint, "
        "including model package containers and inference components. An image "
        "passes when it is pinned by an @sha256 digest, or by a tag its ECR "
        "repository holds immutable, and a mutable tag fails. When a managed "
        "signing rule read with ecr:GetSigningConfiguration covers the repository, "
        "a failed or absent DescribeImageSigningStatus result fails. Model data "
        "named by ModelDataUrl fails without a ModelDataETag, which only a model "
        "package container can record, so a plain model records its expected value "
        "through ModelDataSource.S3DataSource.ETag instead. An S3 ModelDataSource or "
        "additional model data source fails without an ETag or ManifestEtag unless it "
        "is SageMaker hub content. A container with an HF_MODEL_ID environment key and no model "
        "data fails. Each artifact bucket must default to aws:kms or aws:kms:dsse "
        "with a named key whose kms:DescribeKey KeyManager is CUSTOMER. An endpoint with an unread repository, signing status, "
        "model or bucket reports N/A, never Passed. Partial, ceiling reached: a "
        "recorded ETag says an expected value is recorded, and no AWS API returns "
        "whether SageMaker or the container compared it with the object at load "
        "time. Weights fetched by container startup code, and models loaded on "
        "ECS, EKS or EC2, are not read",
        [],
        6,
    ),
    (
        "AIR-FND-DET-10",
        COVERED,
        None,
        "agentcore_assessments",
        ["AC-53"],
        "AC-53 takes the agent pairs from Application Signals: ListMetrics on the "
        "ApplicationSignals namespace lists an Error, Fault and Latency metric per "
        "caller and callee, and a pair is judged when its Environment starts with "
        "bedrock-agentcore: and its RemoteService names another AgentCore runtime "
        "or gateway. A gateway's call to its policy engine is not a pair. Each "
        "pair fails without a metric alarm that reaches an action, on its own or "
        "through an acting composite alarm, whose ThresholdMetricId names an "
        "ANOMALY_DETECTION_BAND over one of those metrics, with the "
        "pair's Service and RemoteService, whatever other dimensions it carries. "
        "A pair whose RemoteService is UnknownRemoteService is N/A by name. An "
        "account with no agent pair reads N/A, never Passed. Partial, ceiling "
        "reached: "
        "runtimes not instrumented with Application Signals publish no pair, and "
        "no AWS API records workflow execution frequency, per-workflow metric "
        "definitions, or whether a new pair raises an alert",
        [],
        6,
    ),
    # ---------------- not_implementable: 1 control ----------------
    (
        "AIR-FND-GOV-12",
        NOT_IMPL,
        None,
        None,
        [],
        "The review queue and its backlog metrics are customer-built and "
        "customer-named, and no AWS API identifies which queue holds agent "
        "decisions awaiting review. Amazon Augmented AI (A2I), the AWS service for "
        "human review of model output, cannot carry the control either. A flow "
        "definition's HumanLoopConfig names a work team, a task count and time "
        "limits but has no priority field. ListHumanLoops and DescribeHumanLoop "
        "return a loop's status, flow definition and output location, so a backlog "
        "of InProgress loops can be counted, but they return no reviewer and no "
        "review-quality field. Nothing on a flow definition marks it as holding "
        "agent decisions.",
        [],
        None,
    ),
]

ROWS = AI_SUBJECT_ROWS + FOUNDATION_ROWS

TIERS = {
    **dict.fromkeys((row[0] for row in AI_SUBJECT_ROWS), AI_SUBJECT),
    **dict.fromkeys((row[0] for row in FOUNDATION_ROWS), FOUNDATION),
}

# The foundation population as the user's scope ruling states it, written out
# independently of FOUNDATION_ROWS. check_ledger.py requires the two to be the
# same set, and requires every machine-checkable control in the AISF
# classification ledger to be a row, so a foundation control dropped from the
# table, or filed in the AI-subject table, is a red and not a smaller total.
SCOPE27 = frozenset(
    {
        "AIR-FND-ACC-02",
        "AIR-FND-ACC-09",
        "AIR-FND-DAT-04",
        "AIR-FND-DAT-05",
        "AIR-FND-DAT-08",
        "AIR-FND-DAT-10",
        "AIR-FND-DET-02",
        "AIR-FND-DET-09",
        "AIR-FND-DET-10",
        "AIR-FND-GOV-02",
        "AIR-FND-GOV-12",
        "AIR-FND-IAM-01",
        "AIR-FND-IAM-02",
        "AIR-FND-IAM-03",
        "AIR-FND-IAM-09",
        "AIR-FND-NET-03",
        "AIR-FND-NET-07",
        "AIR-FND-NET-08",
        "AIR-PHY-EDG-01",
        "AIR-SLF-AGT-05",
        "AIR-SLF-CMP-01",
        "AIR-SLF-CMP-08",
        "AIR-SLF-RT-02",
        "AIR-SLF-RT-04",
        "AIR-SLF-RT-05",
        "AIR-SLF-RT-06",
        "AIR-SLF-RT-08",
    }
)

# Incumbent check_id -> its published finding name, extracted from the modules.
# A NEW_ID disposition is a claim about this name versus what the check asserts,
# so the name is recorded here rather than paraphrased.
INCUMBENT_NAMES = {
    "AC-48": "AgentCore Execution Role Trust",
    "AC-49": "AgentCore DNS Egress Control",
    "AC-50": "AgentCore ECR Enhanced Scanning",
    "AC-51": "AgentCore Gateway Anti-DDoS Protection",
    "AC-53": "AgentCore Inter-Agent Anomaly Alarms",
    "AG-39": "Agentic AI Gateway WAF Rule Coverage",
    "AR-10": "AWS Agent Registry Lifecycle Event Routing",
    "BR-47": "Bedrock Data Path Bucket TLS Enforcement",
    "BR-48": "AI Services Opt-Out Policy Enforcement",
    "BR-49": "Guardrail Invocation Deny Enforcement",
    "BR-50": "AI User Long-Term Access Key",
    "BR-51": "AI User Console MFA",
    "BR-52": "Bedrock Data Path Bucket Object Lock",
    "BR-53": "Bedrock Resource Owner Tag",
    "BR-54": "Lambda Function Public Invoke Configuration",
    "BR-55": "KMS Key Enclave Attestation Binding",
    "BR-57": "Agent Handoff Source Identity",
    # Five names: the Passed and N/A rows carry "AgentCore VPC Configuration
    # Check", and the Failed rows one of the other four, by resource and leg.
    "AC-01": (
        "AgentCore VPC Configuration Check",
        "AgentCore Runtime VPC Configuration",
        "AgentCore Runtime Public Subnet",
        "AgentCore Egress Unrestricted",
        "AgentCore Egress Filtering",
    ),
    "AC-02": "AgentCore IAM Full Access Check",
    "AC-04": "AgentCore Observability Check",
    "AC-06": "AgentCore Browser Session Recording",
    "AC-07": "AgentCore Memory Encryption",
    "AC-08": "AgentCore VPC Endpoints Check",
    "AC-10": "AgentCore Resource-Based Policies Check",
    "AC-11": "AgentCore Policy Engine Encryption Check",
    "AC-14": "AgentCore Identity Token Vault CMK Encryption",
    "AC-15": "AgentCore Code Interpreter Network Isolation",
    "AC-17": "AgentCore Online Evaluation Coverage",
    "AC-18": "AgentCore CloudTrail Data Event Coverage",
    "AC-19": "AgentCore Log Delivery Configuration",
    "AC-20": "AgentCore Log Data Protection",
    "AC-21": "AgentCore Log Unmask Restriction",
    "AC-22": "AgentCore Telemetry Sink Scope",
    "AC-23": "AgentCore Memory Record Access Scope",
    "AC-24": "AgentCore Gateway Rate Limiting",
    "AC-25": "AgentCore Gateway Target Authorization",
    "AC-26": (
        "AgentCore Log Retention and Key Scope",
        "AgentCore Span Log Deletion Protection",
    ),
    "AC-27": "AgentCore Gateway Policy Conditions",
    "AC-28": "AgentCore Gateway Authorizer Guardrail",
    "AC-29": "AgentCore Runtime Authorizer Guardrail",
    "AC-30": "AgentCore Runtime Inbound Authorization",
    "AC-31": "AgentCore Gateway Inbound Allow Lists",
    "AC-32": "AgentCore Inbound JWT Issuer Conditions",
    "AC-33": "AgentCore Token Issuance Scope",
    "AC-34": (
        "AgentCore Runtime Inline Credentials",
        "AgentCore Gateway Target Inline Credentials",
        "AgentCore Harness Inline Credentials",
    ),
    "AC-35": "AgentCore Policy Tool Scope",
    "AC-36": "AgentCore Policy Engine Key Scope",
    "AC-37": "AgentCore Policy Guardrail Wiring",
    "AC-38": "AgentCore Policy Session Binding",
    "AC-39": "AgentCore Online Evaluation Operation",
    "AC-40": "AgentCore Evaluation Safety Coverage",
    "AC-41": "AgentCore Evaluation Result Protection",
    "AC-42": "AgentCore Evaluation Pass Role Scope",
    "AC-43": "AgentCore Evaluation Role Trust",
    "AC-44": "AgentCore Evaluation Judge Model Scope",
    "AC-45": "AgentCore Tool Execution Role Scope",
    "AC-46": (
        "AgentCore Runtime Session Limits",
        "AgentCore Runtime Session Limit Unbounded",
        "AgentCore Runtime Session Usage Unmonitored",
    ),
    "AC-47": "AgentCore Runtime Invocation Path",
    "AG-24": "Agentic AI Gateway Inbound Authorization",
    "AG-25": "Agentic AI Gateway Tool Policy Enforcement",
    "AG-27": "Agentic AI Gateway WAF Protection",
    # The Passed and N/A rows carry the first name, and each Failed leg its own.
    "AR-01": (
        "AWS Agent Registry IAM Full Access Check",
        "AWS Agent Registry IAM Full Access Policy",
        "AWS Agent Registry IAM Wildcard Permissions",
    ),
    "AR-03": "AWS Agent Registry Publication Approval Governance",
    "AR-09": "AWS Agent Registry Approval Authority Separation",
    # Four names for one check, one per status branch: the Passed row, the Failed
    # row and each of the two N/A rows carry a different name. The subject is one
    # thing -- whether a Bedrock VPC endpoint is in use -- so no single CSV filter
    # returns this check's verdicts, and filtering on the Passed name reports a
    # clean estate for an account whose only row said "not used".
    # The second spelling is published only when the permission cache is
    # unavailable, by the handler and not by the check.
    "BR-01": (
        "AmazonBedrockFullAccess role check",
        "AmazonBedrockFullAccess Role Check",
        "Bedrock Wildcard Action Grant",
    ),
    "BR-02": (
        "Amazon Bedrock private connectivity",
        "Amazon Bedrock private connectivity not used",
        "Bedrock VPC Endpoint Check",
        "Bedrock Workload Private Connectivity",
    ),
    # The second name is published by the outer `except` alone, where every other
    # path publishes the first. An operator filtering the report on the name the
    # passing rows carry therefore sees no row at all for the runs that failed
    # with an exception, which is the direction that hides a broken check.
    "BR-04": (
        "Bedrock Model Invocation Logging Check",
        "Bedrock Logging Configuration Check",
        "Bedrock Invocation Log Retention",
        "AgentCore Memory Event Retention",
    ),
    "BR-06": "Bedrock CloudTrail Logging Check",
    # BR-07 publishes its Failed line under a different name than its Passed and
    # N/A lines, so both are recorded. Filtering the report CSV on either name
    # alone hides half of this check's verdicts.
    "BR-07": ("Bedrock Prompt Management Check", "Bedrock Prompt Variants Check"),
    "BR-10": "Bedrock Guardrail IAM Enforcement Check",
    # Same split as BR-07: the second name carries this check's Failed rows, one
    # per custom model found without a CMK, and the first carries everything else.
    "BR-11": (
        "Bedrock Custom Model Encryption Check",
        "Bedrock Custom Model Encryption Review",
        "Bedrock Customization Data Bucket Encryption",
    ),
    "BR-12": (
        "Bedrock Invocation Log Encryption",
        "Bedrock Invocation Log Group Encryption",
        "Bedrock Invocation Log Group Deletion Protection",
    ),
    "BR-15": "Cross-Account Guardrails Enforcement Check",
    "BR-17": "Custom Model Customer-Managed KMS Encryption Check",
    # The data source bucket and transient data key legs publish their own
    # names, and a knowledge base that could not be judged publishes Review.
    "BR-20": (
        "Knowledge Base Customer-Managed KMS Encryption Check",
        "Knowledge Base Customer-Managed KMS Encryption Review",
        "Knowledge Base Data Source Bucket Encryption",
        "Knowledge Base Data Source Transient Data Key",
    ),
    "BR-26": (
        "Guardrail Sensitive Information Filter Check",
        "Deployed Guardrail Sensitive Information Filter",
    ),
    "BR-27": (
        "Guardrail Contextual Grounding Check",
        "Deployed Guardrail Contextual Grounding",
    ),
    "BR-32": "Bedrock CloudWatch Alarm Check",
    "BR-33": "Amazon Inspector Lambda Code Scanning Check",
    "BR-34": (
        "Guardrail Prompt Attack Filter",
        "Deployed Guardrail Prompt Attack Filter",
    ),
    "BR-37": "Bedrock Account Data Retention",
    "BR-39": "Marketplace Model Endpoint VPC Configuration",
    "BR-41": "Central Guardrail Enforcement Policy Check",
    # The identity leg and the organization leg.
    "BR-42": (
        "Foundation Model Invocation Allow-List",
        "Bedrock Approved Model Control",
    ),
    # The Region leg, the model leg, the served-Region evidence, the SageMaker
    # and S3 Region leg, and the cross-account leg.
    "BR-43": (
        "Bedrock Region Invocation Control",
        "Bedrock Approved Model Control",
        "Bedrock Inference Region Evidence",
        "AI Service Region Control",
        "Bedrock Custom Model Cross-Account Access",
    ),
    "BR-44": "Marketplace Model Subscription Control",
    # An inventory line and a prevention line, by design.
    "BR-45": (
        "Bedrock API Key Inventory",
        "Bedrock API Key Age And Token Type Control",
    ),
    "BR-46": "Knowledge Base Source Data Classification",
    "FS-65": "KB Data Source Buckets Missing S3 Event Notifications",
    "SM-01": "SageMaker Internet Access Check",
    "SM-02": (
        "SageMaker IAM Permissions Check",
        "SageMaker Service-Wide Grant in Customer Policy",
    ),
    "SM-03": "SageMaker Data Protection Check",
    # One name per status branch: Passed, Failed, a disabled detector, and the
    # error path.
    "SM-04": (
        "GuardDuty Enabled",
        "GuardDuty Not Enabled",
        "GuardDuty Detector Disabled",
        "GuardDuty Check Error",
    ),
    "SM-09": "SageMaker Notebook Root Access Check",
    # Failed under the first name, Passed and both N/A rows under the second.
    "SM-10": (
        "SageMaker Notebook Not in VPC",
        "SageMaker Notebook VPC Deployment Check",
    ),
    "SM-11": "SageMaker Model Network Isolation Check",
    # Failed under the first name, Passed and N/A under the second.
    "SM-14": (
        "SageMaker Model Platform Repository Access",
        "SageMaker Model Repository Access Check",
    ),
    "SM-18": "SageMaker Transform Job Encryption Check",
    "SM-22": "Model Approval Workflow Check",
    # Failed under the first name, Passed and N/A under the second.
    "SM-23": ("Model Drift Detection Not Configured", "Model Drift Detection Check"),
    "SM-26": "GuardDuty AI Protection",
    "SM-28": "HyperPod VPC Configuration",
    "SM-31": "Endpoint Inference Data Capture",
    # Recording is the precondition, rule compliance is the assertion.
    "SM-32": ("SageMaker Configuration Recording", "SageMaker Config Rule Compliance"),
    "SM-33": "Training Job Network Boundary",
    "SM-34": "SageMaker Creation Guardrail",
    "SM-35": "Security Service Delegated Administrator",
    "SM-36": "Security Hub AI Security Best Practices Standard",
    "SM-37": "GuardDuty Lambda Protection",
    "SM-38": "GuardDuty Runtime Monitoring",
    "SM-39": "EKS VPC CNI Network Policy Enforcement",
    "SM-40": "Secrets Manager Automatic Rotation",
    "SM-41": "AWS IoT Device-Scoped Policy",
    "SM-42": "SageMaker Batch Transform Creation Guardrail",
    "SM-43": "SageMaker Model Artifact Integrity",
}


def published_names(check_id):
    """Every finding name one incumbent publishes, as a list.

    A value may be one string or a tuple of them, because several check ids
    publish more than one name -- usually the Failed rows under one name and
    everything else under another, and BR-02 a different name per status branch.
    No count is stated here on purpose: the last one drifted from three to seven
    the first time this map was extended, and nothing gates a number in a
    docstring. Raises on an unmapped id rather than returning nothing, so adding a
    check without recording its name stops the build here instead of shipping a
    row whose incumbent has no name.
    """
    try:
        entry = INCUMBENT_NAMES[check_id]
    except KeyError:
        raise KeyError(
            f"{check_id} is cited as an incumbent but has no INCUMBENT_NAMES "
            "entry. Add the finding name(s) the check actually publishes, as "
            "read from its create_finding calls."
        ) from None
    return [entry] if isinstance(entry, str) else list(entry)


AISF_REPO = os.path.expanduser(
    "~/WorkDocs/Builder/aws-ai-security-framework-assessment"
)
HERE = os.path.dirname(os.path.abspath(__file__))


def load_aisf():
    """Return {control_id: {q, ev, machine_checkable, workload_agnostic}}."""
    import glob

    import yaml

    ledger_path = os.path.join(AISF_REPO, "crosswalk", "classification-ledger.json")
    with open(ledger_path) as f:
        classification = json.load(f)["controls"]

    out = {}
    for path in glob.glob(
        os.path.join(AISF_REPO, "controls", "**", "*.yaml"), recursive=True
    ):
        with open(path) as f:
            doc = yaml.safe_load(f)

        def walk(node):
            if isinstance(node, dict):
                cid = node.get("id")
                if isinstance(cid, str) and cid.startswith("AIR-"):
                    flags = classification.get(cid, {})
                    out[cid] = {
                        "q": (node.get("q") or "").strip(),
                        "ev": (node.get("ev") or "").strip(),
                        "machine_checkable": bool(flags.get("machine_checkable")),
                        "workload_agnostic": bool(flags.get("workload_agnostic")),
                        "source": os.path.relpath(path, AISF_REPO),
                    }
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(doc)
    return out


def table_fields(row):
    """The ten ledger fields the verdict tables above decide, for one ROWS entry.

    Shared with gen_compliance_maps.rows_from_source(), which renders these same
    fields so that `--check` can compare the shipped json against this table.
    That comparison used to carry its own copy of this mapping, and a defect in
    build()'s copy was therefore invisible to it: neither copy was the other's
    oracle, so both could be read as agreeing while only one was right.

    Measured, which is why this function exists: the mutation battery's entry
    "the incumbent-name lookup reverts to its fail-open form" edits the
    incumbent_names comprehension below, and with two copies NO catcher went red
    -- check_ledger.py never re-runs build_ledger.py, so the shipped json it
    reads was still the good one, and gen_compliance_maps rendered its side from
    the unmutated copy. 21 of 22 caught. One function read by both makes the
    defect observable as a gate-15 drift.

    The other five fields a ledger row carries (`area`, `question`, `assert`,
    `workload_agnostic`, `source`) are not here: four are read from the sibling
    AISF repository and one is derived from the control id, so no verdict-table
    edit can change them.
    """
    control, verdict, disposition, module, incumbents, gap, extra_iam, phase = row
    return {
        "control": control,
        "verdict": verdict,
        "disposition": disposition,
        # a list: some controls have no single host module
        "target_modules": (
            []
            if module is None
            else [module]
            if isinstance(module, str)
            else list(module)
        ),
        "incumbents": incumbents,
        # Strict on purpose. The `if i in INCUMBENT_NAMES` guard this replaces
        # dropped any unmapped id silently, so 12 of 78 rows shipped an incumbent
        # id beside an empty name list -- every check phase 3 added, because the
        # map was never extended with them. A blank name list is also what gate 8
        # reads to decide whether a new_id row quotes its incumbent, so the
        # omission could only ever make that gate easier to pass.
        "incumbent_names": [name for i in incumbents for name in published_names(i)],
        "gap": gap,
        "extra_iam": extra_iam,
        "phase": phase,
        # which table the row sits in, so the json can be checked against SCOPE27
        "tier": TIERS[control],
    }


def build():
    aisf = load_aisf()
    rows = []
    for row in ROWS:
        control = row[0]
        meta = aisf.get(control)
        if meta is None:
            raise SystemExit(f"{control} is not a control in the AISF repo")
        if not meta["machine_checkable"]:
            raise SystemExit(f"{control} is not machine_checkable in the ledger")
        fields = table_fields(row)
        rows.append(
            {
                "control": control,
                "area": control.split("-")[1],
                "question": meta["q"],
                "assert": meta["ev"],
                "workload_agnostic": meta["workload_agnostic"],
                # Key order is preserved as it was when these nine were spelled
                # out here, so that regenerating produces the same json bytes and
                # a reader diffing the file sees only the rows that changed.
                **{k: v for k, v in fields.items() if k != "control"},
                "source": meta["source"],
            }
        )

    def count(**kw):
        return sum(1 for r in rows if all(r.get(k) == v for k, v in kw.items()))

    hosted = [r for r in rows if r["area"] in ("BDR", "SGM", "ACR")]
    fnd = [r for r in rows if r["area"] == "FND" and r["tier"] == AI_SUBJECT]
    foundation = [r for r in rows if r["tier"] == FOUNDATION]
    new_functions = (
        count(verdict=NEW)
        + count(verdict=TIGHTEN, disposition=NEW_ID)
        + count(verdict=UNASSESSED)
    )
    summary = {
        "hosted": len(hosted),
        "fnd_ai_subject": len(fnd),
        "foundation": len(foundation),
        "total": len(rows),
        "covered": count(verdict=COVERED),
        "tighten": count(verdict=TIGHTEN),
        "tighten_extend": count(verdict=TIGHTEN, disposition=EXTEND),
        "tighten_new_id": count(verdict=TIGHTEN, disposition=NEW_ID),
        "new": count(verdict=NEW),
        "not_implementable": count(verdict=NOT_IMPL),
        "unassessed": count(verdict=UNASSESSED),
        "new_check_functions": new_functions,
        "extensions": count(verdict=TIGHTEN, disposition=EXTEND),
        "extra_iam_actions": sorted({a for r in rows for a in r["extra_iam"]}),
    }

    doc = {
        "generated": date.today().isoformat(),
        "generator": "aisf-parity/build_ledger.py",
        "aisf_repo": AISF_REPO,
        "summary": summary,
        "rows": rows,
    }
    with open(os.path.join(HERE, "aisf-work-ledger.json"), "w") as f:
        json.dump(doc, f, indent=2, sort_keys=False)
        f.write("\n")
    write_markdown(doc)
    return doc


def render_markdown(doc):
    """Render the markdown view of a ledger doc. Pure: reads nothing, writes nothing.

    Separate from write_markdown so check_ledger.py's gate 10 can render the json
    and compare the result against the file on disk. That gate used to compare
    mtimes, which measures checkout order and not content: a clone writes every
    file within the same second, ordered by the git index, so the uppercase
    markdown name always lands before the lowercase json and the gate failed in
    every fresh clone while passing in the tree the ledger was generated in.
    """
    s = doc["summary"]
    out = []
    out.append("# AISF parity work ledger")
    out.append("")
    out.append(
        f"Generated {doc['generated']} by `{doc['generator']}`. Do not hand-edit: "
        "change `ROWS` in the generator and re-run."
    )
    out.append("")
    out.append(
        f"{s['total']} controls in scope: {s['hosted']} hosted (BDR, SGM, ACR) plus "
        f"{s['fnd_ai_subject']} FND controls whose assertion subject is an AI resource, "
        f"plus {s['foundation']} foundation controls (FND, PHY, SLF) over the account "
        "or runtime an AI workload sits on."
    )
    out.append("")
    out.append("| verdict | rows | meaning |")
    out.append("|---|---|---|")
    out.append(
        f"| covered | {s['covered']} | an incumbent already asserts this; nothing to write |"
    )
    out.append(
        f"| tighten / extend | {s['tighten_extend']} | incumbent name is honest, its "
        "assertion is narrower; extend it in place |"
    )
    out.append(
        f"| tighten / new_id | {s['tighten_new_id']} | incumbent name claims more than it "
        "asserts; allocate a new id beside it |"
    )
    out.append(f"| new | {s['new']} | no incumbent asserts any part of it |")
    out.append(
        f"| not_implementable | {s['not_implementable']} | flagged machine_checkable in the "
        "ledger but is not checkable from configuration |"
    )
    out.append(f"| unassessed | {s['unassessed']} | in scope, dedup pass not yet run |")
    out.append("")
    out.append(
        f"**{s['new_check_functions']} new check functions and {s['extensions']} extensions "
        "to existing checks.**"
    )
    out.append("")
    out.append("## New IAM actions required")
    out.append("")
    for action in s["extra_iam_actions"]:
        holders = [r["control"] for r in doc["rows"] if action in r["extra_iam"]]
        out.append(f"- `{action}` — {', '.join(holders)}")
    out.append("")
    for area in ("BDR", "SGM", "ACR", "FND", "PHY", "SLF"):
        rows = [r for r in doc["rows"] if r["area"] == area]
        if not rows:
            continue
        out.append(f"## {area} ({len(rows)} controls)")
        out.append("")
        out.append("| control | verdict | do | module | incumbent | gap |")
        out.append("|---|---|---|---|---|---|")
        order = {COVERED: 0, TIGHTEN: 1, NEW: 2, UNASSESSED: 3, NOT_IMPL: 4}
        for r in sorted(rows, key=lambda r: (order[r["verdict"]], r["control"])):
            inc = ", ".join(f"`{i}`" for i in r["incumbents"]) or "—"
            do = r["disposition"] or "—"
            mod = ", ".join(f"`{m}`" for m in r["target_modules"]) or "—"
            gap = r["gap"].replace("|", "\\|") or "—"
            wa = "" if r["workload_agnostic"] else " *(workload-specific)*"
            tier = " *(foundation)*" if r["tier"] == FOUNDATION else ""
            out.append(
                f"| `{r['control']}`{wa}{tier} | {r['verdict']} | {do} | {mod} | {inc} | {gap} |"
            )
        out.append("")
    return "\n".join(out)


def write_markdown(doc):
    with open(os.path.join(HERE, "AISF-WORK-LEDGER.md"), "w") as f:
        f.write(render_markdown(doc))


if __name__ == "__main__":
    result = build()
    print(json.dumps(result["summary"], indent=2))
