# Proposal: AWS AI Security Framework (AISF) parity in this repo

Status: proposal, nothing implemented.
Target repo: `tamg-aws/sample-aiml-security-assessment` (fork), branch `chore/aisf-parity-proposal`.
Measured against fork HEAD `7af13a8` (v2.0.0), level with `upstream/main`.
Source framework: `aws-ai-security-framework-assessment` (AISF), 218 controls.

## 1. Verified starting position

Every figure below was measured, not quoted.

| Fact | Value | How it was established |
|---|---|---|
| AISF controls | 218 | parsed `controls/**/*.yaml` on the `items` key |
| AISF machine-checkable | 105 | `crosswalk/classification-ledger.json`, `machine_checkable: true` |
| of those, workload-agnostic | 83 | `workload_agnostic: true` |
| of those, workload-specific | 22 | 83 + 22 = 105, reconciles |
| This repo's published checks | 208 | 214 distinct `^[A-Z]{2,3}-\d{2}$` ids minus 6 `XX-00` marker rows |
| Cross-check on 208 | agrees | `docs/SECURITY_CHECKS.md:7`, `README.md:9` |
| of the 208, independent probes | 164 | 34 AG and 10 OW rows re-project another check's verdict |
| of those, able to fire today | 163 | BR-14's only call site is commented out (section 4.5) |
| Test baseline | 1,846 passed, 0 failed, 0 skipped | three pytest sessions, Python 3.12.14, repo-local `.venv` |

The 208 figure is correct as published and should not be changed: every AG and OW row is a real report row a
reader sees. It is the wrong denominator for a dedup, though, because a re-projected row cannot duplicate an
AISF control independently of the check it re-projects. Section 4.4 dedups against 163.

Baseline command set, for reproduction:

```
tests/                                          955 passed
.../responsible_ai_grc_tests/                   875 passed
.../generate_consolidated_report/test_generate_report.py    16 passed
```

The baseline is green, so any later red is attributable to the port.

## 2. The request splits into two independent pieces

"Add AISF as a framework" and "incorporate all machine-verifiable checks" touch disjoint parts of
the codebase and can ship in either order.

Piece 1 is a tagging and reporting concern. Piece 2 is a check-authoring concern.
Treating them as one workstream is what would make this port expensive.

## 3. Piece 1: AISF as a framework

### 3.1 What constrains a framework name: nothing in the runtime

`responsible_ai_grc_assessments/schema.py:46-53` declares `Compliance_Frameworks` as a plain `str`
with `default=""`, no validator, no enum, no allow-list. The string `"AISF"` is accepted the moment
it appears in a map value. Every gate on framework naming is a test, not a schema rule.

### 3.2 The blocking fact: the column exists in 1 of 6 schemas

`Compliance_Frameworks` is declared only in `responsible_ai_grc_assessments/schema.py`. The Finding
models in `bedrock_assessments`, `sagemaker_assessments`, `agentcore_assessments`,
`agent_registry_assessments`, and `owasp_assessments` have no such field, and
`grep -c compliance_frameworks` returns **0** in all five of their `app.py` files.

`COMPLIANCE_MAP` (`responsible_ai_grc_assessments/app.py:408-489`) has 64 entries, one per FS
control, carrying 26 distinct free-text framework tokens. None is AISF.

Consequence: adding AISF to `COMPLIANCE_MAP` alone would tag only the 64 FinServ checks. It would
reach none of the 144 Bedrock, SageMaker, AgentCore, Agent Registry, or OWASP checks, which are
exactly the ones AISF overlaps. A framework tag that lands only on the FinServ subset is
misleading, because a reader would read absence of the tag as absence of AISF relevance.

### 3.3 Two candidate meanings, and which one to pick

**Option A, tag on existing rows.** Add `Compliance_Frameworks` to the five schemas that lack it,
then populate per-module maps. Cost: 5 schema edits, 5 map tables, and it rewrites the frozen
baseline in `responsible_ai_grc_tests/test_inventory_equivalence.py:604-696`, whose 66 tuples carry
the compliance string as their 5th element and are compared byte-for-byte at `:893`.

**Option B, AISF as its own report section.** `generate_consolidated_report/report_template.py:146-165`
defines `COMPLIANCE_STANDARDS`, the registration point for a compliance standard. It ships one live
entry (OWASP) and two commented-out future entries at `:163-164` that name the exact pattern:

```python
# Future: {"slug": "nist", "name": "NIST AI RMF", "prefix": "NR-", ...}
# Future: {"slug": "euaiact", "name": "EU AI Act", "prefix": "EU-", ...}
```

Eight keys are required, gated at `tests/test_report_template_owasp.py:255-272`. A working
monkeypatched proof that a second standard renders already exists at `:274-311`.

**Recommendation: B for the report surface, A scoped to the hosted checks only.** B is the
mechanism the repo was built for and has a passing proof. A is worth doing only for the checks that
actually map to AISF controls, which section 4 quantifies as 67.

### 3.4 Correction to a comment in the codebase

`report_template.py:140-145` states that appending an entry to `COMPLIANCE_STANDARDS` "is
sufficient, no loop-body edits required in the report layer or its callers." That holds for
rendering. It does not hold for artifact validation:
`generate_consolidated_report/app.py:84-95` hard-codes `per_region_categories`, and OWASP, the one
live precedent, needed an entry there (`:95`) plus an `enableOWASP` flag (`:90`). A new AISF module
would need the same. `docs/DEVELOPER_GUIDE.md:890-895` makes the same overclaim.

Three further sites enumerate artifact prefixes by hand and would need the new module:
`buildspec.yml:509-525`, and the report Lambda's S3 read policy which lists prefixes twice, at
`template.yaml:254-259` (`s3:ListBucket` condition) and `:265-270` (`s3:GetObject` resources),
mirrored in `template-multi-account.yaml`. Both are asserted by
`tests/test_sam_role_least_privilege.py:376-424`, which also bans the bucket-wildcard shortcut at
`:422`.

### 3.5 The id-encoding problem, and why it is not a blocker

AISF ids are four-segment (`AIR-BDR-MDL-01`). Every Finding schema validates `Check_ID` against
`^[A-Z]{2,3}-\d{2}$`, present in six copies plus a test constant at
`responsible_ai_grc_tests/test_legacy_contracts.py:123`. `AIR-BDR-MDL-01` is rejected by all of them.

This does not need a regex change. The AISF id belongs in the `Compliance_Frameworks` text, which is
unvalidated free text, while the repo-side check keeps its native `BR-`/`SM-`/`AC-` id. A row then
reads `AISF AIR-BDR-MDL-01`, and the crosswalk is data rather than schema.

For the checks with no existing host (section 4.2), a new 2-digit prefix is needed.
`tests/test_schema.py:114-125` proves a 3-letter prefix validates (`ACX-01` passes), so both `AI-`
and `AIR-` are schema-legal. **Recommend `AI-`**, for one measurable reason: OWASP's mapping parser
extracts a source id with `row["Finding_Details"].split("Source check ", 1)[1][:5]`
(`tests/test_owasp_checks.py:352`), a 5-character assumption. `AI-01` is 5 characters and `AIR-01`
is 6, so `AIR-` would be silently truncated to `AIR-0` if AISF rows ever feed OWASP mappings.
`AI-` is also unused: the live prefixes are AC, AG, AR, BR, FS, OW, SM.

Capacity check: the regex allows 2 digits, so 100 ids per prefix. 38 new checks fit in `AI-`. All
105 would not, which is the argument against giving AISF a single prefix for the whole framework.

## 4. Piece 2: the machine-verifiable checks

### 4.1 Where the 105 controls would live

Derived from `crosswalk/classification-ledger.json`, grouped by AISF area:

| AISF area | machine-checkable / total | agnostic | specific | Target module in this repo |
|---|---|---|---|---|
| ACR (AgentCore) | 37 / 70 | 32 | 5 | `agentcore_assessments` (+ `agent_registry_assessments`) |
| BDR (Bedrock) | 19 / 33 | 16 | 3 | `bedrock_assessments` |
| SGM (SageMaker) | 11 / 27 | 10 | 1 | `sagemaker_assessments` |
| FND (foundational) | 29 / 62 | 19 | 10 | none today |
| SLF (self-hosted) | 8 / 23 | 5 | 3 | none today |
| PHY (edge) | 1 / 3 | 1 | 0 | none today |
| **Total** | **105 / 218** | **83** | **22** | |

**67 controls host in an existing module. 38 have no host.**

Of the 105, 25 are already covered by an upstream Prowler check, 28 partially, 30 are new, and 22
are not applicable to Prowler. 56 of 105 carry a `candidate_check` slug in the ledger, which gives
an implementation to borrow rather than write.

### 4.2 The 38 with no host

FND breaks down as DAT 8, NET 7, DET 5, IAM 5, ACC 2, GOV 2. SLF as RT 5, CMP 2, AGT 1. PHY as EDG 1.

These are AI-workload-scoped versions of foundational controls (data protection, network isolation,
detection, identity). Whether an AI/ML security assessment tool should carry them is a scoping
decision for you, stated as an open question in section 7. They are the expensive 38: a new module
means a new Lambda, a new ASL branch, IAM in both SAM templates, the artifact plumbing in 3.4, and
a new prefix.

### 4.3 The workload-specific 22 are not automatically out of scope

AISF classifies a control `workload_specific` when it requires conformance to an approved list whose
contents only the workload owner knows (model ARNs, account ids, regions, FQDNs, KMS keys). A
scanner can catch a blanket allow but cannot confirm the list is right.

This repo already solves that with deploy-time parameters, and the pattern is fully wired and
tested. Eight slots exist today, but only two are allow-lists: `ApprovedExternalAccountIds` and
`ApprovedOrganizationIds`, both consumed by the single check SM-30. The other six carry no value
list. `RequireBedrockZeroDataRetention` (BR-37), `RequireMarketplaceEndpointCMK` (BR-40),
`RequireAgentCoreOnlineEvaluation` (AC-17), `RequireAgentRegistryManualApproval` (AR-03), and
`RequireAgentRegistryCMK` (AR-05) are booleans that flip a verdict; `AgentCoreTokenVaultId` (AC-14)
names one vault. So the mechanism is proven, but there is one precedent for the shape AISF needs, not
eight.

The chain for `ApprovedExternalAccountIds` runs: CFN parameter
(`template.yaml:87`, `template-multi-account.yaml:87`) to Lambda env var
`AIML_APPROVED_EXTERNAL_ACCOUNT_IDS` (`:491` / `:493`) to the read at
`sagemaker_assessments/app.py:4397-4403`, gated by
`tests/test_optional_policy_baseline_wiring.py`, which asserts both the exact `Fn::Ref` and sole
ownership of the variable (`:120`, `:122-124`).

Cost per new parameter is high and worth stating plainly: roughly 13 files, because the name is
renamed three times along the chain (CFN parameter, CodeBuild variable, Lambda env var) and the
`AIML_` prefix is applied inconsistently across the existing eight. `EXPECTED_ENV_OWNERS`
(`tests/test_optional_policy_baseline_wiring.py:14-47`) is an explicit dict, so a parameter that is
not registered there is not checked at all.

So the 22 are portable, at a price, and the price is a new parameter for almost every one of them.
Recommend selecting a subset by value rather than porting all of them; section 7 states this as a
decision.

Two of the 22 do not reduce to a parameter at all. `AIR-FND-IAM-09` needs a per-principal,
per-resource-type action matrix, which no flat list expresses; without it the check degrades to the
generic `service:*` wildcard test the repo already has. `AIR-SLF-CMP-08` needs an expected
model-weight digest, a build artifact held in no AWS API that changes per model version. Leave both
manual. The other 20 reduce to a list of strings, a small map, or an integer.

### 4.4 Dedup against what already ships

This is the section the earlier draft could not write. Verdicts below are per control, assigned by
reading both sides: the AISF assertion and the incumbent check's actual comparison.

| AISF area | controls | already covered | tightens an existing check | net new | flagged machine-checkable but is not |
|---|---|---|---|---|---|
| BDR | 19 | 4 | 7 | 5 | 3 |
| SGM | 11 | 2 | 4 | 4 | 1 |
| ACR | 37 | pending | pending | pending | pending |

**Bedrock, 19 controls, reconciles exactly.** Already covered: `GRD-01` by BR-10, `GRD-03` by BR-26,
`KB-03` by BR-20, `MDL-10` by BR-37 (same `GetAccountDataRetention` call). Tightenings: `GRD-02`
(BR-34 tests the BLOCK action, AISF tests `inputStrength` HIGH), `GRD-04` (BR-32 accepts any
`AWS/Bedrock` alarm, AISF wants the intervention metric filter), `GRD-09` (BR-27 tests presence,
AISF tests thresholds), `GRD-10` (BR-15 tests that an org policy exists, AISF tests it is non-DRAFT),
`KB-06` and `MDL-07` (BR-06 tests that a trail covers Bedrock, AISF wants named data-event resource
types), `MDL-02` (BR-04 plus BR-12 cover logging and destination encryption, AISF adds retention).
Net new: `KB-01` (Macie, no incumbent reads `macie2` in this module), `MDL-01`, `MDL-03`, `MDL-04`,
`MDL-09`.

**SageMaker, 11 controls, reconciles exactly.** Already covered: `EP-08` by SM-18, `TRN-05` by
SM-09 plus SM-01 plus SM-03 (all three legs). Tightenings: `EP-01` (SM-11 has the network-isolation
leg, not the `VpcConfig` leg), `EP-02`, `GOV-01` (SM-22 has approval status, not approver metadata),
`TRN-02` (SM-03 has the KMS legs, not inter-container encryption). Net new: `EP-06`
(`DataCaptureConfig`), `GOV-10` (Config recorder), `TRN-01` (training-job network isolation, which
SM-21 does only for AutoML), `TRN-08` (SCP).

**Three allow-list dimensions have no incumbent at all, verified by grep.** `aws:RequestedRegion`,
`aws:SourceVpc`, `aws:SourceVpce`, and `aws:PrincipalOrgID` each return **0** hits across all six
modules' `app.py`, against 3 hits for `GuardrailIdentifier` as a positive control, so the zeros are
the absence of the feature and not a broken pattern. No check asserts model-ARN scoping on
`bedrock:InvokeModel`, and none tests an FQDN egress list. That makes `BDR-MDL-01/03/04`,
`FND-ACC-02`, `FND-DAT-04`, `FND-NET-03`, and `SLF-RT-02` net-new detection rather than dedup risk.

**Where the incumbent is weaker than its name suggests.** Worth knowing before writing a check that
looks redundant:

- `FS-12`'s entire test is `"bedrock" in json.dumps(doc).lower()` over every SCP
  (`responsible_ai_grc_assessments/app.py:2016`). An SCP that *allows* all of Bedrock passes it. The
  allow-list language lives in the resolution string at `:2035`, not in any assertion. An AISF
  model-allowlist control does not duplicate it.
- `FS-07` tests exact membership in `["iam:*", "s3:*", "ec2:*", "lambda:*", "*"]` (`:1529`), so
  `iam:Put*` passes.
- 13 of the 64 FinServ checks assert nothing about the account (11 read nothing at all; `FS-24` and
  `FS-58` read an inventory slice and still emit an advisory).
- All 64 FinServ rows are stamped `Region="Global"` by `_stamp_unscoped_findings_global`, because the
  module runs once with region-less clients (`app.py:7949`). An AISF control needing per-region
  evidence is not covered by an FS row even when the subject matches.
- The CMK family (21 checks) asserts customer-managed against AWS-owned, never a specific approved
  key. `AC-10` and `BR-15` are presence-only.

**Two defects on the AISF side**, surfaced by this pass and worth fixing in the source repo:

1. `AIR-SGM-EP-03` carries the slug `sagemaker_endpoint_intercontainer_encryption_enabled`, but
   `EnableInterContainerTrafficEncryption` is absent from `DescribeEndpointConfig` and present only
   on `DescribeTrainingJob` (botocore 1.42.97 shape probe). The slug names a field the endpoint API
   does not have. Do not port it as written.
2. `AIR-FND-DET-09` is assertable: `deletionProtectionEnabled` *is* a `DescribeLogGroups` member, so
   `CONTRIBUTION-PROGRAM.md` section 8 is wrong to list it as mis-specified.

Three AISF controls are flagged `machine_checkable` in the ledger but are not checkable from
configuration: `AIR-BDR-KB-05` and `KB-08` depend on customer Lambda code, and `AIR-BDR-MDL-08`
needs a published-versus-DRAFT distinction `GetPrompt` does not return. With `AIR-SGM-EP-03` that is
4 of 105. The 105 figure is a ledger claim, not an implementability claim.

### 4.5 One published check cannot fire

`BR-14` is in the published 208 and has no live call site. Its sole invocation
(`bedrock_assessments/app.py:7983-7986`) is commented out; a repo-wide grep for
`check_stale_bedrock_access` returns only the definition at `:723`, an error-log string at `:896`,
and that commented call. This matters for the port in one specific way: an AISF stale-access control
has no working incumbent to dedup against, so it should be treated as net new even though a
same-named check exists.

## 5. Constraints, measured

### 5.1 What is not a constraint

IAM policy size. Measured free space against the project's own 9,000-character inline budget
(`tests/test_sam_role_least_privilege.py:28`), identical in both SAM templates:

| Function | Chars | Free | Approx. actions that fit |
|---|---|---|---|
| ResponsibleAIGRC | 5,319 | 3,681 | ~150 |
| Bedrock | 4,908 | 4,092 | ~167 |
| Sagemaker | 3,325 | 5,675 | ~232 |
| AgentCore | 3,005 | 5,995 | ~245 |

The multi-account member role measures 4,587 of a 5,500 budget, leaving 913 characters, which looks
alarming until you check what is on it: only `cloudformation`, `iam`, `lambda`, `s3`, and `states`.
It carries zero assessment APIs, and
`tests/test_deployment_role_least_privilege.py:38-51` enforces that. Adding checks does not grow it.

### 5.2 What is a constraint

**The Responsible AI GRC module is effectively frozen.** Its timeout is 900 s at
`template.yaml:786`, the Lambda maximum, with a comment saying so. Eleven hard-coded count
assertions pin it at 64/65/11: `test_provenance.py:85` and `:134`, `test_legacy_contracts.py:153`
and `:167`, `test_checks.py:3535` and `:3539`, `test_lambda_handler.py:86` and `:496`,
`test_inventory_equivalence.py:760`, `test_resilience.py:694` and `:758`, plus
`test_large_estate.py:315`. Adding one FS control touches all of them, and
`tests/test_responsible_ai_grc_presentation.py:264-288` additionally requires the literal
"64 automated checks" to equal `provenance.json`'s `control_count`, a deliberate tripwire per its
own docstring.

**Do not put AISF checks in the Responsible AI GRC module.** The count gates and the exhausted
timeout make it the worst host in the repo.

**Template divergence.** `template-multi-account.yaml:788` gives the same function 600 s, one third
less than single-account. Any timing headroom argument has to be made against 600 s.

**A timeout degrades silently.** The ASL `Catch` keeps the report generating, so exceeding the limit
yields a partial report rather than a failure.

**Failures present as N/A.** Per `AGENTS.md:112-121`, a check's outer `except` returns `N/A` plus
`Informational`, never `Failed`. A missing IAM grant is therefore indistinguishable from
"no resources found" (`AGENTS.md:94-99`). Every new check inherits this, so the IAM grant must be
added in the same change or the check silently reports nothing.

**Nine new IAM service prefixes for the unhosted 38.** `template.yaml` grants exactly 28 service
prefixes across 158 action entries, with no wildcard action anywhere and 37 statements scoped to
`Resource: "*"`. The 38 unhosted controls span 26 prefixes, of which 17 are already granted and
**9 are not**: `backup`, `cognito-idp`, `ecs`, `eks`, `elasticloadbalancing`, `iot`,
`network-firewall`, `route53resolver`, `secretsmanager`. Each needs a statement on the right role in
both SAM templates, since grants are per-function and not shared.

`kms` is the trap in that list, because it looks already granted. Only `kms:DescribeKey` is granted
(`template.yaml:409`, scoped to `key/*` in-account), so `AIR-FND-DAT-10`, which reads key policies,
needs a new action even though `kms` is in the union. `AIR-FND-DAT-01` resolving a key to
customer-managed is covered by the existing grant.

**Step Functions payload, unresolved.** Three handlers return the full findings list inline
(`bedrock_assessments/app.py:8286`, `sagemaker_assessments/app.py:5029`,
`responsible_ai_grc_assessments/app.py:8159`) and the invoking Task states carry no
`ResultSelector`. Nothing in the repo mentions the 256 KB state-payload quota, so there is no guard
and no test. The mechanism is verified; the breach point is not. Row count scales with estate size
times checks, so this needs a measurement before a large batch lands, not an assumption.

### 5.3 Gates that will not catch a mistake

Four fail-open patterns matter for a batch this size:

- `SEVERITY_REGISTER` (`responsible_ai_grc_tests/test_severity_register.py:27-40`) only checks rows
  whose finding name is already registered (`:106-116`). 100 new checks can register no severity and
  the suite stays green.
- OWASP mapping coverage is closed over a frozen 34-id snapshot
  (`tests/test_owasp_checks.py:291-336`). A batch of new checks gets zero mapping coverage,
  silently. Its `SOURCE_CHECK_ID_FILES` (`:41-46`) omits Agent Registry, and
  `_discover_source_check_ids` (`:49-52`) requires the `check_id=` keyword form, which is exactly
  how Agent Registry does not write its calls.
- The assessment-API deny-lists (`tests/test_deployment_role_least_privilege.py:38-51`, `:54-70`)
  are fixed 7- and 10-service lists. A check reading a service outside them, which most of the FND
  group would, is not covered by the invariant.
- CI is path-filtered (`.github/workflows/python-tests.yml:7-19`) and does not list
  `template.yaml`, `template-multi-account.yaml`, `statemachine/`, or `buildspec.yml`, yet five test
  files read exactly those. A template-only or buildspec-only PR does not run the tests that guard
  templates and buildspec, contradicting `CONTRIBUTING.md:88-96`.

The unknown-prefix path deserves one clarification. `consolidate_html_reports.py:197` ends its
routing chain with `else: service = "bedrock"`, silently attributing unknown rows to Bedrock, while
the single-account path (`generate_consolidated_report/app.py:231-232`) drops the file with a log
line instead. Same input, two different wrong answers. A prefix registered in
`COMPLIANCE_STANDARDS` is routed correctly before that fallback, because the lookup is keyed by
`prefix.upper().rstrip("-")` (`consolidate_html_reports.py:110-112`), so this bites only an
unregistered prefix. Registering `AI-` avoids it.

## 6. Proposed phasing and branches

Each phase is independently shippable and leaves the suite green.

| Phase | Branch | Content | Blast radius |
|---|---|---|---|
| 0 | `chore/aisf-parity-proposal` | this document, the crosswalk data, no code | none |
| 1 | `feature/aisf-report-section` | register `AI-` in `COMPLIANCE_STANDARDS`, wire `per_region_categories`, artifact prefixes, report IAM | report layer only |
| 2 | `feature/aisf-compliance-column` | add `Compliance_Frameworks` to the 5 schemas that lack it, plus per-module AISF maps for the 67 hosted controls | 5 schemas, rewrites the frozen baseline |
| 3 | `feature/aisf-checks-bedrock` | BDR 19 into `bedrock_assessments` | one module |
| 4 | `feature/aisf-checks-agentcore` | ACR 37 into `agentcore_assessments` / `agent_registry_assessments` | two modules |
| 5 | `feature/aisf-checks-sagemaker` | SGM 11 into `sagemaker_assessments` | one module |
| 6 | `feature/aisf-foundational-module` | the 38 unhosted, new Lambda, new ASL branch | new module, both templates, ASL |

Phase 1 should land a non-empty section on day one. `report_template.py:1317-1318` does
`if _total <= 0: continue`, so a registered standard emitting zero rows renders nothing at all: no
nav item, no card, no section. That is indistinguishable from a wiring bug, so phase 1 and the first
batch of rows should ship together.

Per-check obligations for phases 3 to 5, from the traced BR-37 example: the check function,
`create_finding(..., region=region)`, a dispatch site, IAM in **both** SAM templates, the matching
`_EXPECTED_ACTIONS` entry (set equality at `tests/test_sam_role_least_privilege.py:325-331`), at
least 4 tests per `docs/DEVELOPER_GUIDE.md:610-638`, and the doc count lockstep at `AGENTS.md:147`.
No ASL change is needed for a check inside an existing module.

One id-allocation trap. `docs/DEVELOPER_GUIDE.md:739` offers `AG-33` as an example of a new check id,
but `AG-33` is already taken: it is `AR-03`'s lens row (`agent_registry_assessments/app.py:93`). AG
ids run `AG-01` through `AG-38` with no gaps, so the next free one is `AG-39`. The line is an example
inside verification instructions and not an allocation register, so it is a stale example rather than
a wrong rule, but a contributor who copies it collides.

The count lockstep has 9 live "208" claims: `README.md:9,56,101,139,640`, `AGENTS.md:7`,
`docs/SECURITY_CHECKS.md:3` and `:7`, `docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md:218`. Six section
headings in `docs/SECURITY_CHECKS.md` carry their own counts and double as URL anchors
(`:119`, `:279`, `:507`, `:596`, `:659`, `:985`), so changing a count breaks inbound links.

## 7. Open decisions

These change the work materially and are yours to make.

1. **Scope of the 38 unhosted controls.** Port them (phase 6, a new module), or declare FND/SLF/PHY
   out of scope for this repo and ship 67 of 105. Shipping 67 is defensible and much cheaper; it
   should then be stated as 67, not as "all machine-verifiable checks."

   One fact sharpens this: **30 of the 38 call no Bedrock, SageMaker, or AgentCore API at all.** They
   read Organizations policy documents, IAM policy documents, S3, and CloudWatch. That is generic
   account posture, which is a reasonable thing for an AI/ML assessment tool to decline. It also
   means they do not need an AI host module, so if you do want them, they can go wherever the service
   already lives. The 8 that do touch an AI service are `FND-DAT-01/02/03`, `FND-DET-01/04`,
   `FND-IAM-05`, `FND-NET-01`, `FND-NET-06`. A middle option: port those 8, decline the other 30, and
   ship 75 of 105.
2. **Prefix.** `AI-` is recommended. Confirm, or pick another 2-character prefix.
3. **Whether to touch the frozen baseline** in phase 2. Tagging existing FS rows with AISF rewrites
   66 frozen tuples. The alternative is to tag only non-FS checks, leaving the FinServ module alone.
4. **The 22 workload-specific controls.** 20 of the 22 reduce to a flat list of strings, a small map,
   or an integer, so the existing deploy-time parameter pattern covers them. Only one incumbent check
   (SM-30) uses that pattern as an allow-list today, so this is 20 new parameters at roughly 13 files
   each, not a reuse. Recommend picking the subset by value, not porting all 20. `FND-IAM-09` and
   `SLF-CMP-08` should be declared manual per section 4.3.
5. **Whether to measure the Step Functions payload ceiling first.** Recommended before phase 4,
   which is the largest single batch at 37 checks.

## 8. What has not been verified

Stated so these are not read as settled:

- Whether any real estate crosses the Step Functions 256 KB state-payload quota. Mechanism
  confirmed, breach point not measured.
- The report Lambda's memory ceiling at scale. It is `MemorySize: 1024` with a 600 s timeout
  (`template.yaml:238-239`) and reads every CSV into memory. No test asserts its footprint, unlike
  the FinServ module.
- The ACR dedup, 37 of the 105. BDR and SGM are done per control in section 4.4 and reconcile
  exactly; ACR is still count-level. Until it lands, the total net-new figure is unknown, and the
  BDR and SGM pattern (9 of 30 net new) should not be extrapolated onto it.
- Assertion sufficiency of the API mapping. 42 of the API strings across the 83 workload-agnostic
  controls were derived from the control's classification basis rather than read from an artifact
  `check_api` field. Those name the right service and the APIs exist; whether each is sufficient to
  implement its control was not checked.
- Three API details behind specific controls: `bedrock:InvokeGuardrailChecks` as an IAM action name,
  `AWS::BedrockAgentCore::Memory` as a CloudTrail resource type (the AISF artifact itself says
  "confirm exact type string"), and the `bedrock ListInferenceProfiles` response shape.
- IAM grants were read in `template.yaml` only. `template-multi-account.yaml` was not diffed against
  it, so the grant set on the multi-account path needs separate confirmation before phase 6.
- Whether any real estate crosses the Step Functions 256 KB state-payload quota, repeated from above
  because it is the one unmeasured item that could force rework rather than just more work.
