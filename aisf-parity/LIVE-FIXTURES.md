# Live fixtures for the AISF live-verifiability gate

`aisf-parity/probe_live.py` measures whether each shipped `AISF-` row actually
reaches both a Passed and a Failed verdict against a real account. Two rows could
not reach both from the account's standing resources, so two fixtures exist
purely to exercise the missing branch.

Account **ACCOUNT_ID**, region **us-east-1**. The id is redacted because this file
ships in a public fork; the profile in the commands below resolves it. Every resource
is named with the `aisflive` prefix. Four of the seven that can carry tags also carry
`purpose=aisf-live-verifiability-fixture` and `temporary=true`: the KMS key, the
knowledge base and both IAM roles. The gateway, the vector bucket and the vector index
carry no tags at all.

Neither tag is a teardown selector. Measured on 2026-09-25,
`resourcegroupstaggingapi get-resources --tag-filters
Key=purpose,Values=aisf-live-verifiability-fixture` returns six ARNs, and
`Key=temporary,Values=true` returns the identical six. The result is wrong in both
directions at once.

**Four of the six hits are not fixtures.** Only the KMS key and the knowledge base are.
The rest is the assessment pipeline: the CodeBuild project `AIMLSecurityCodeBuild`, its
start-build Lambda, the versioned assessment bucket
`aiml-security-aisf-parity-assessmentbucket-7za0aaaa3dfo`, and the
`aiml-security-aisf-parity` stack that owns all three, recorded under **Also standing**
below. They answer the filter because that `cloudformation deploy` passed these two
tags as stack tags and CloudFormation propagated them, so selecting on either tag
deletes the project the post-merge validation build runs on and a versioned bucket of
reports.

**Five of the seven taggable fixture resources are absent from the same result, for two
unrelated reasons.** The gateway
(`arn:aws:bedrock-agentcore:us-east-1:ACCOUNT_ID:gateway/aisflive-gw-authonly-vmwcsepglu`),
the vector bucket and the vector index carry no tags at all: `list-tags-for-resource`
returns `{}` for each, and both services expose `tag-resource`, so that is an omission
at creation and not a gap in the tagging API. Both IAM roles do carry the two tags and
the tagging API returns neither. A clean tag query therefore reads as an empty estate
while the AISF-01 gateway is `AUTHENTICATE_ONLY` and `READY`, so reach for the gateway
by the name above. Tagging the three untagged resources would close this direction and
leave the four false hits exactly as they are, so a tag is not the fix. The lists below
are the inventory.

The gate is not part of `gate_all.sh`. It needs AWS credentials, and it measures
an account rather than this tree, so a green battery says nothing about it. Run it
from `aisf-parity/`, which is where its repo-root derivation resolves:

```bash
AWS_PROFILE=delegated-admin .venv/bin/python aisf-parity/probe_live.py --region us-east-1
aisf-parity/probe_live.py --selftest    # 11 classifier cases, no credentials needed
```

## The second live leg: the tag column

`aisf-parity/probe_live_tags.py` is the live leg for phase 2's
`Compliance_Frameworks` column. It needs no fixture, because it reads the CSVs a
run already left in the assessment bucket, and it answers the one question the 41
offline tests structurally cannot.

Those tests build every finding from a check id they read out of the map under
test. The round trip proves the lookup and says nothing about whether the key is
an id a producer actually emits. `test_a_tag_names_a_check_its_own_module_emits`
narrows it to a substring search over `app.py`, which is weaker than it looks:
the `AG-` ids are split across three producers (bedrock emits `AG-01`-`AG-14` and
`AG-30`, agentcore `AG-15`-`AG-29` plus `AG-31`-`AG-32`, agent_registry
`AG-33`-`AG-38`), so the string is present in modules that do not emit it. A key
filed under the wrong module ships a permanently empty column for that check with
every offline test green.

```bash
AWS_PROFILE=delegated-admin .venv/bin/python aisf-parity/probe_live_tags.py \
    --bucket aiml-sec-ACCOUNT_ID-aimlassessmentbucket-gywyxnvqxpvx --region us-east-1
.venv/bin/python aisf-parity/probe_live_tags.py --selftest   # 12 cases, no credentials
```

Measured against execution `2654a727` in us-east-1, written 2026-09-25 12:51 UTC by
a CodeBuild run that resolved to commit `6ac8dca`: **13/13 assertions, 31/31 map keys confirmed against an
id the module really emitted, 0 unproven, 0 misplaced, 115 of 356 rows tagged as
the run wrote them, 0 producers disagreeing.** Qualifier forms on real rows: 33
bare, 101 `(partial)`, 11 joint, 28 pipe-joined multi-control, 0 unparseable. A key
the run did not emit is counted UNPROVEN and never as a pass, because an account
with no SageMaker notebook emits no `SM-09` and that is an evidence gap, not a
defect.

Two of the three sections read the same CSVs and catch different things, which is
why both exist:

- **as written** compares the `Compliance_Frameworks` value the run itself shipped
  against this tree's map. This is the only assertion in either probe that can see
  a deployed artifact built from source older than this tree.
- **replayed** rebuilds every row through the real `create_finding` and
  `generate_csv_report`. It compares the map against itself, so it would pass
  whatever the Lambda wrote; it covers the rendering path instead — the 9-column
  header and no row gained or lost.

A CSV predating the column **fails** the as-written section rather than skipping
it. A skip there would read as a pass for the one hop the offline suite cannot
reach.

The probe deliberately does **not** judge whether a qualifier is correct. It
compares each replayed row against the same map, so a wrong qualifier agrees with
itself; that is gate 14's job, which derives the expected qualifier from the
ledger row instead. The probe covers the plumbing: the key resolving to a real
emitted id, the 9-column header, no row gained or lost, and every row's tag
equalling the map's answer.

### Positive controls, and why they are not a gate

`31/31`, `0 misplaced` and `0 disagreeing` is a 100% result, which is also what a
probe that measures nothing prints. Every live assertion was therefore driven red
once against real CSVs:

| Injected | Result |
|---|---|
| `"BR-10"` added to agentcore's map | `PROBE FAIL`, 1 misplaced, naming agentcore |
| bedrock's `compliance_frameworks` default changed from `None` to `""` | `PROBE FAIL`, replayed tags 115 → 92, the 23 bedrock rows |
| one shipped `AC-02` tag blanked in a **copy** of agentcore's CSV, tree map untouched | `PROBE FAIL 12/13`, exit 1, as-written red for agentcore **only**, all four replays still green, tagged 115 → 114 |
| the column dropped from a **copy** of sagemaker's CSV | `PROBE FAIL 12/13`, exit 1, the "predates phase 2" branch, tagged 115 → 96 |

The first two edit the tree and were restored byte-identically. The last two edit a
copy of the CSVs instead, so the measured set is never mutated and there is no
restore to verify. They are the discriminating pair: the third shows the as-written
assertion fails where **every replay passes**, so it is not riding on the replay,
which is the whole reason it was added.

This stays a manual control rather than a `mutate.py` entry because it needs a
run's CSVs, and those carry account ids and resource ARNs, so they cannot be
committed as a fixture. `--selftest` covers the classifiers with synthetic input
(12 cases, no credentials); the table above is what proves the live wiring calls
them.

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

BR-20's S3 Vectors branch has **three** legs (bucket encryption, index encryption,
bucket policy) and Passed needs all three. A customer-managed
key with no bucket policy is a Failed, because half of "encrypted and
access-restricted" is not a pass. The CMK alone left the row at ONE_ONLY with all
ten knowledge bases Failed; the bucket policy is what moves it to BOTH.

- KMS CMK `alias/aisflive-vectors-cmk`. Its key policy is AWS's default
  (`Enable IAM User Permissions`, copied verbatim, never hand-authored) plus one
  appended statement allowing `indexing.s3vectors.amazonaws.com` to
  `Decrypt`/`GenerateDataKey`/`DescribeKey` under an `aws:SourceAccount`
  condition. `CreateIndex` fails with `AccessDeniedException` without it.
- Vector bucket `aisflive-vectors-cmk`, `sseType=aws:kms` with that key.
- Index `aisflive-index`, float32, dimension 1024, cosine. `GetIndex` returns the
  same `aws:kms` key, so the index leg agrees with the bucket leg on this fixture.
  Every index read live on 2026-09-25 echoed its bucket's configuration instead of
  omitting the field, so the fixture exercises the echoed shape and the unit suite
  carries the two shapes it cannot: an index with no `encryptionConfiguration` of
  its own, and an `AES256` index inside a CMK bucket.
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

## Also standing: the stack deployed to read the rows in a real report

The gate above measures the account. Reading the derived `AISF-` rows in a
generated HTML report needs the assessment itself deployed, and that deploy is not
a fixture: it leaves three stacks, three versioned buckets and a fixed-name IAM
role behind. It is recorded here because this file is the teardown inventory, and a
tag query reports it wrongly in both directions.
`deployment/aiml-security-single-account.yaml` sets no tags of its own, but the
`cloudformation deploy` that created the parent stack passed the two fixture tags on
the command line and CloudFormation propagated them, so the fixture filter answers
with the CodeBuild project, the start-build Lambda, the assessment bucket and the
stack itself. Both IAM roles in that same stack carry the identical tags and the
query returns neither, and no resource the inner `sam deploy` created answers either
tag.

Deployed twice, into the same three stacks:

| When | Branch | Build | Produced |
|---|---|---|---|
| 2026-09-24 21:23 UTC | `feature/aisf-report-section` | `AIMLSecurityCodeBuild:8fb19587` | `security_assessment_single_account_20260924_213330.html` |
| 2026-09-25 12:45 UTC | `feature/aisf-compliance-column` | `AIMLSecurityCodeBuild:a9a53ea5` | execution `2654a727`, the four 9-column CSVs the tag probe measures |

The second deploy passed `--source-version feature/aisf-compliance-column` to
`start-build` rather than changing the stack's `GitHubBranch` parameter:

```bash
aws codebuild start-build --project-name AIMLSecurityCodeBuild \
    --source-version feature/aisf-compliance-column
```

`buildspec.yml` never reads `GITHUB_BRANCH`; CodeBuild's own checkout decides what
is built, so the override needs no CloudFormation change and reverts by simply not
passing it again. The build reported `resolvedSourceVersion
6ac8dca1498efe559b04712be961cac3017e9dde`, which is what ties the CSVs above to a
commit instead of to a branch name that moves.

That distinction is load-bearing for the as-written assertion, which compares the
shipped column against whatever the tree says **now**. A run is reusable only while
the commits since it touch no map, `schema.py` or `app.py`:

```bash
git diff --name-only <resolvedSourceVersion> HEAD \
  | grep -E 'aisf_compliance_|/schema\.py|/app\.py'   # silence means reusable
```

A hit there means a redeploy, not a rerun of the probe: the failure would be real,
and it would name the deployed artifact rather than the map.

| Stack | Created by | Holds |
|---|---|---|
| `aiml-security-aisf-parity` | `aws cloudformation deploy` of `deployment/aiml-security-single-account.yaml` | CodeBuild project `AIMLSecurityCodeBuild`, IAM role `CodeBuildRole`, bucket `aiml-security-aisf-parity-assessmentbucket-7za0aaaa3dfo` |
| `aiml-sec-ACCOUNT_ID` | `sam deploy` inside the CodeBuild run (`buildspec.yml:318`) | the assessment Lambdas, the Step Functions state machine, bucket `aiml-sec-ACCOUNT_ID-aimlassessmentbucket-gywyxnvqxpvx` |
| `aws-sam-cli-managed-default` | the same `sam deploy`, first time SAM ran in this account and region | bucket `aws-sam-cli-managed-default-samclisourcebucket-mddfu3hfvyes` |

Two things that make this harder to remove than it looks.

**All three buckets have versioning Enabled**, and both assessment buckets carry
`DeletionPolicy` default `Delete`. `aws s3 rm --recursive` leaves every noncurrent
version and delete marker in place, the bucket stays non-empty, and the stack
delete then fails on `BucketNotEmpty` after it has already removed the other
resources. Empty the versions, not the objects.

**`CodeBuildRole` is a fixed name** at path `/service-role/`, so a second copy of
this template cannot be deployed into the same account while this stack exists.
Checked before deploying: no role of that name pre-existed, so nothing else in the
account owns it.

```bash
export AWS_PROFILE=delegated-admin AWS_REGION=us-east-1

# Save anything still wanted first: the HTML report and the four source CSVs
# live under the account-id prefix in the parent stack's bucket.
aws s3 sync s3://aiml-security-aisf-parity-assessmentbucket-7za0aaaa3dfo/ ./report-archive/

empty_versioned() {   # $1 = bucket. Versions AND delete markers, or the stack delete fails.
  local b="$1" q
  for q in Versions DeleteMarkers; do
    while :; do
      local payload
      payload=$(aws s3api list-object-versions --bucket "$b" --max-items 500 \
        --query "{Objects: ${q}[].{Key:Key,VersionId:VersionId}}" --output json)
      case "$payload" in *'"Objects": null'*|*'"Objects":null'*) break ;; esac
      aws s3api delete-objects --bucket "$b" --delete "$payload" >/dev/null
    done
  done
}

empty_versioned aiml-sec-ACCOUNT_ID-aimlassessmentbucket-gywyxnvqxpvx
aws cloudformation delete-stack --stack-name aiml-sec-ACCOUNT_ID
aws cloudformation wait stack-delete-complete --stack-name aiml-sec-ACCOUNT_ID

empty_versioned aiml-security-aisf-parity-assessmentbucket-7za0aaaa3dfo
aws cloudformation delete-stack --stack-name aiml-security-aisf-parity
aws cloudformation wait stack-delete-complete --stack-name aiml-security-aisf-parity

# Optional and account-wide. SAM recreates it on the next `sam deploy` in this
# region, so leaving it costs the storage of 12 packaged artifacts and nothing else.
# empty_versioned aws-sam-cli-managed-default-samclisourcebucket-mddfu3hfvyes
# aws cloudformation delete-stack --stack-name aws-sam-cli-managed-default
```

Removing these stacks does not change any gate. `probe_live.py` reads the account
through the checks' own source and never through a deployed assessment, so the
BOTH/ONE_ONLY figures above survive the teardown. The two fixtures in the sections
above are the ones that must stay for the gate to stay green.

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
