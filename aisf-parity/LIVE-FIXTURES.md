# Live fixtures for the AISF live-verifiability gate

`aisf-parity/probe_live.py` measures whether each shipped `AISF-` row actually
reaches both a Passed and a Failed verdict against a real account. Two rows could
not reach both from the account's standing resources, so two fixtures exist
purely to exercise the missing branch.

Account **ACCOUNT_ID**, region **us-east-1**. The id is redacted because this file
ships in a public fork; the profile in the commands below resolves it. Every resource
is named with the `aisflive` prefix and tagged
`purpose=aisf-live-verifiability-fixture` and `temporary=true`.

Do not use a tag query as the teardown inventory. Measured against the standing
fixtures, `resourcegroupstaggingapi get-resources --tag-filters
Key=purpose,Values=aisf-live-verifiability-fixture` returns two of them, the KMS key
and the knowledge base, and none of the vector bucket, the vector index, the gateway,
or the IAM roles. The lists below are the inventory.

The gate is not part of `gate_all.sh`. It needs AWS credentials, and it measures
an account rather than this tree, so a green battery says nothing about it. Run it
from `aisf-parity/`, which is where its repo-root derivation resolves:

```bash
AWS_PROFILE=delegated-admin .venv/bin/python aisf-parity/probe_live.py --region us-east-1
aisf-parity/probe_live.py --selftest    # 11 classifier cases, no credentials needed
```

## What each fixture unblocks

| Row | Incumbent | Branch it exercises | Without the fixture |
|---|---|---|---|
| AISF-01 | AG-24 | `elif authorizer_type == "AUTHENTICATE_ONLY"` → Failed (`agentcore_assessments/app.py:3617-3619`) | ONE_ONLY. All 15 standing gateways are `AWS_IAM` or `CUSTOM_JWT`, so only Passed fires. |
| AISF-05 | BR-20 | the S3 Vectors Passed path: `aws:kms` + `kmsKeyArn` **and** an attached bucket policy | ONE_ONLY. All 9 standing knowledge bases sit on `AES256` vector buckets with no bucket policy, so only Failed fires. |

Measured at `f65f948` with both fixtures in place: BOTH=4, ONE_ONLY=4, NONE=0,
VACUOUS=0, exit 0, over 19 legs. The four remaining ONE_ONLY rows are excused by
construction and not by a waiver. The last section says why for each one.

## AISF-01: an AUTHENTICATE_ONLY gateway

- `aisflive-gw-authonly` (`aisflive-gw-authonly-vmwcsepglu`), `authorizerType=AUTHENTICATE_ONLY`,
  no policy engine, no targets.
- `aisflive-gw-authonly-role`, trust for `bedrock-agentcore.amazonaws.com` with
  `aws:SourceAccount` and `aws:SourceArn` conditions. **No permissions policy** — a
  gateway with no targets needs none.

`AUTHENTICATE_ONLY` was chosen over `NONE` deliberately. Both reach a Failed
verdict, but `NONE` would provision an unauthenticated endpoint; `AUTHENTICATE_ONLY`
still authenticates the SigV4 caller and only declines to make the authorization
decision, which is what AG-24 flags.

**Cost: $0.** AgentCore Gateway bills per API invocation ($0.005 per 1,000),
Search API, and tool indexing ($0.02 per 100 tools per month). There is no
per-hour or per-gateway charge. This gateway has no tools indexed and receives no
invocations.

## AISF-05: a CMK-encrypted vector store with a bucket policy

BR-20's S3 Vectors branch has **two** legs and Passed needs both. A customer-managed
key with no bucket policy is a Failed, because half of "encrypted and
access-restricted" is not a pass. The CMK alone left the row at ONE_ONLY with all
ten knowledge bases Failed; the bucket policy is what moves it to BOTH.

- KMS CMK `alias/aisflive-vectors-cmk`. Its key policy is AWS's default
  (`Enable IAM User Permissions`, copied verbatim, never hand-authored) plus one
  appended statement allowing `indexing.s3vectors.amazonaws.com` to
  `Decrypt`/`GenerateDataKey`/`DescribeKey` under an `aws:SourceAccount`
  condition. `CreateIndex` fails with `AccessDeniedException` without it.
- Vector bucket `aisflive-vectors-cmk`, `sseType=aws:kms` with that key.
- Index `aisflive-index`, float32, dimension 1024, cosine. It reports the same
  `aws:kms` key, so the index-level override BR-20 cannot read is not masking a
  weaker key here.
- A vector bucket policy, one `Allow` statement, principal `aisflive-kb-cmk-role`
  and nothing else, six `s3vectors` actions, resources limited to that bucket and
  its indexes. No wildcard principal, action or resource: a bucket policy opened to
  `*` would satisfy the check's presence test while defeating the control it stands
  for.
- Knowledge base `aisflive-kb-cmk` (`BMUADJAEAQ`) on that bucket and index, with
  `amazon.titan-embed-text-v2:0`. **No data source attached and nothing synced**, so
  no embedding or ingestion charges.
- `aisflive-kb-cmk-role`, scoped to `bedrock:InvokeModel` on that one embedding
  model, the six `s3vectors` actions on that one bucket and index, and the three
  KMS actions on that one key under a `kms:ViaService` condition.

**Cost: about $1/month** for the CMK. Vector storage with zero vectors is
negligible. The CMK is the only recurring charge in either fixture.

## Teardown

The KMS key has a **7-day minimum** deletion window, so it outlives the other
resources. Run in this order:

```bash
export AWS_PROFILE=delegated-admin AWS_REGION=us-east-1

# AISF-01
aws bedrock-agentcore-control delete-gateway --gateway-identifier aisflive-gw-authonly-vmwcsepglu
aws iam delete-role --role-name aisflive-gw-authonly-role

# AISF-05
aws bedrock-agent delete-knowledge-base --knowledge-base-id BMUADJAEAQ
aws s3vectors delete-vector-bucket-policy --vector-bucket-name aisflive-vectors-cmk
aws s3vectors delete-index --vector-bucket-name aisflive-vectors-cmk --index-name aisflive-index
aws s3vectors delete-vector-bucket --vector-bucket-name aisflive-vectors-cmk
aws iam delete-role-policy --role-name aisflive-kb-cmk-role --policy-name aisflive-kb-cmk-access
aws iam delete-role --role-name aisflive-kb-cmk-role
aws kms delete-alias --alias-name alias/aisflive-vectors-cmk
aws kms schedule-key-deletion --key-id alias/aisflive-vectors-cmk --pending-window-in-days 7
```

Tearing these down returns AISF-01 and AISF-05 to ONE_ONLY, which fails the gate
for both. That is the intended behaviour: the gate reports what the account can
actually prove, so removing a fixture must remove the proof.

## What is NOT a fixture

The 36 `prowlerlive*` resources in this account belong to the Prowler check
pipeline and are not ours. Five of them bill hourly. Scan them, never modify them.

Four rows stay at ONE_ONLY by construction and are recorded rather than failed:

- **AISF-03 / AISF-07 / AISF-08** (`BR-10`, `SM-18`, `SM-09`+`SM-01`+`SM-03`) are
  `ELSE_GUARDED`: the only Passed emit sits in the `else` of the guard that emits
  the Failed findings, so one non-compliant resource suppresses Passed for the
  whole account. No fixture can fix this, and for transform jobs nothing can —
  SageMaker has no `DeleteTransformJob`, so `prowlerlive-xf-noenc` is permanent.
- **AISF-06** (`BR-37`) is `SINGLETON`: account-level data retention yields one
  verdict per region by construction.

`probe_live.py` computes these classifications from each check's own source on
every run, so none of them can go stale against an edited check. The excuse is
therefore re-earned every run, and an edit that makes Passed genuinely reachable
turns the excused row into a failing one without anyone updating this file.
