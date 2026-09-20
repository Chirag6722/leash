# Leash — architecture notes

## Two shapes, one code path

| | `Brain=worker`, `PolicyStore=s3` (default, Free plan) | `Brain=bedrock`, `PolicyStore=avp` |
| --- | --- | --- |
| Where the model runs | an EC2 instance (`BrainOnEc2=true`, free-tier-eligible `m7i-flex.large`) running Ollama + `local_demo/cloud_worker.py` under the WorkerPolicy instance role, no keys; the same worker also runs on any machine for development | the agent Lambda on Bedrock |
| How alarms reach it | EventBridge -> SQS `leash-incidents` -> worker | EventBridge -> Lambda |
| How `/ask` reaches it | API -> SQS `leash-requests` -> worker; reply via `GET /reply` | API invokes the Lambda synchronously |
| Who evaluates Cedar | the authorizer Lambda, cedarpy, policies from the versioned S3 bucket | Amazon Verified Permissions |
| Who writes the audit row | the authorizer, **before** it answers | the tool, after acting |
| What the agent process can do | act on dev resources; cannot read policies, cannot write audit rows | same, plus IAM denies on every delete API |

The second column is stricter on one axis (IAM floor in Lambda), the first is stricter on
another (the audit cannot be skipped by the acting process). Both are real, both are tested, and
`src/agent` does not know which one it is running in.

## Flow, end to end

1. A CloudWatch alarm (`leash-disk-dev`, `leash-ecs-dev`) enters ALARM.
2. An EventBridge rule matches `source = aws.cloudwatch`, `detail-type = CloudWatch Alarm State
   Change`, `detail.state.value = ALARM`, `detail.alarmName` prefix `leash-`, and invokes the
   **Agent Lambda** asynchronously.
3. The handler extracts the alarm name and the metric dimensions (`InstanceId`, or `ClusterName`
   + `ServiceName`), mints an `incident_id`, and builds a short prompt for the Strands agent.
4. The agent calls read-only tools first (`get_instance_info`, `get_disk_usage`,
   `get_service_info`). These need no authorisation.
5. For any mutating tool (`clean_disk`, `restart_service`, `scale_group`, `terminate_instance`)
   the tool itself calls `common.authz.authorize()` **before** doing anything. The resource's
   `env` attribute is taken from the resource's tags; a missing tag is passed as `"unknown"`.
6. `authorize()` calls `verifiedpermissions:IsAuthorized` with principal `Leash::Agent::"leash"`,
   the action, the resource entity with its `env` attribute, and context (`desiredCapacity` for
   `scaleGroup`). Any exception -> `allowed=False` (fail closed). Verified Permissions returns
   opaque policy ids in `determiningPolicies`; the nested `cedar/template.yaml` outputs
   `PolicyIdMap` (logical name -> id) and the root template passes it as `POLICY_ID_MAP`, so the
   audit row and the reply say `ForbidProd`, not `SPEXAMPLE...`.
7. The tool performs the action only on ALLOW, then calls `common.audit.write_audit()` with the
   decision, the policy ids that determined it, and the result string. Denied calls are audited
   too — that is the point.
8. The agent ends with `notify()` (SNS) and a one-paragraph summary.
9. The **API Lambda** serves `GET /audit` (DynamoDB GSI query, newest first), `GET /policies`
   (ListPolicies + GetPolicy on the store, ids translated to names, so the dashboard shows the
   exact text being enforced) and `POST /ask` (synchronous invoke of the agent in chat mode) to
   the static S3 dashboard. The dashboard derives its "Alarm → fixed" figure from the rows: an
   incident id ends in the handler's start time, each row's `sk` is when the decision landed.

## The red team, and why the control arm is safe

`src/redteam/` runs each attack through two arms. The leashed arm is simply the agent in chat
mode: real tools, real Cedar, real AWS. The unleashed arm needs the model to be able to *succeed*,
so it runs against the in-memory fake AWS from `local_demo/fake_aws.py` with authorisation
switched off. Three things keep that switch from ever touching a real account:

1. `tools._sandbox_unleashed()` returns true only when `LEASH_SANDBOX_UNLEASHED=1` **and** the
   boto3 seam `aws_helpers.client` is the fake client factory. With real clients installed the
   flag is ignored (tested).
2. The runner installs the fake, runs the arm, then restores the real client and clears the flag
   in a `finally`.
3. The red-team Lambda's IAM role carries the same explicit `Deny` on every delete and terminate
   API as the agent's, so even a bug in 1 and 2 could not destroy anything.

Rows land in the audit table under `gsi1pk = REDTEAM`, one per attack, with what each arm did.
The leashed arm's denials are also ordinary audit rows (they are real decisions); the control
arm's tool calls are discarded, because "allowed by nothing" is not a decision.

## Defence in depth: Cedar vs IAM

| Layer | What it controls | Why it exists |
| --- | --- | --- |
| **Cedar (Verified Permissions)** | *Intent*: may the agent do action X to resource Y in state Z? Evaluated per tool call, with policy ids returned. | Fine-grained, readable, auditable. Can express "not above 4" and "only env=dev" in one line. Lives outside the model and the prompt, so prompt injection cannot change it. |
| **IAM (Lambda execution role)** | *Capability*: which AWS APIs the process can call at all. Explicit `Deny` on `ec2:TerminateInstances`, `ec2:DeleteVolume`, `ecs:DeleteService`, `ecs:DeleteCluster`, `autoscaling:DeleteAutoScalingGroup`, `dynamodb:DeleteTable`, `s3:DeleteBucket`, `rds:Delete*`; `ssm:SendCommand` only on instances with tag `env=dev`; `ecs:UpdateService` and `autoscaling:SetDesiredCapacity` only on the dev resources. | If a Cedar policy is mis-written, or someone bypasses `authorize()` in code, the destructive API still fails. IAM cannot express the scale cap or return a policy id, which is why it is the floor and not the leash. |
| **Code guard** | `terminate_instance` never calls `ec2.terminate_instances` even if authorisation somehow returned ALLOW. | Belt and braces for the one action that is irreversible. |

| **The floor** (`common/floor.py`) | *The policy set itself*: ten requests that must be DENY under every version (terminate, delete, anything on prod, scale to 10, untagged). Proved when a draft is proposed, again when it is approved, and by the authorizer before any new policy version is loaded. | The policies move (English rules, `set-cap.sh`), so something outside the store has to say how far. A set that breaks an invariant is never loaded: every request fails closed with `Floor:<name>` in the row until the store is fixed. Changing the floor is a code change and a deploy, not a click. |

The four layers fail independently. A demo can show layer 1 (Cedar denial with policy id) and
the floor (propose "allow terminate on dev" and watch the card refuse); layers 2 and 3 are there
so that a wrong demo never becomes a wrong outage.

Cedar semantics that matter: the evaluator is deny-by-default (no matching `permit` -> DENY), and
any matching `forbid` overrides every `permit`. `ForbidProd` and `ForbidDestructive` therefore win
regardless of what `PermitDevRemediation` says, and a resource with `env = "unknown"` matches no
permit at all.

## Data model

DynamoDB table (on-demand): `pk = incident_id`, `sk = ISO8601 UTC timestamp with microseconds`.
GSI `gsi1`: `gsi1pk = "ALL"`, `sk` — a single-partition index that gives "newest first" with one
`Query(ScanIndexForward=False)`. Item attributes: `action`, `resource_type`, `resource_id`,
`resource_env`, `decision` (`ALLOW`/`DENY`), `policy_ids` (list), `reason`, `result`,
`alarm_name`, `summary`.

## What is dev-only, and what would change for production

| Dev / hackathon choice | Production change |
| --- | --- |
| Single-partition GSI (`gsi1pk = "ALL"`). Fine for thousands of rows. | Shard the GSI key by day (`ALL#2026-09-18`) or move the trail to CloudWatch Logs / OpenSearch. |
| Public-read S3 website, HTTP API with CORS `*` and no auth. | CloudFront + OAC, Cognito or IAM auth on the API, CORS restricted to the dashboard origin. |
| `POST /ask` invokes the agent synchronously (30 s API timeout vs 300 s agent). | Async invoke + polling or WebSocket; or Step Functions for long incidents. |
| Bedrock `InvokeModel` on `*` (inference profiles need it). | Restrict to the specific model and inference-profile ARNs. |
| `ec2:Describe*`, `ecs:Describe*/List*`, `cloudwatch:GetMetric*` on `*`. | Resource-scoped where the API supports it; otherwise condition on tags. |
| Env attribute read from tags at call time, trusted as-is. | Tags enforced by SCP / tag policies so a resource cannot "become dev" by retagging. |
| One agent, one principal `Leash::Agent::"leash"`. | One principal per agent instance or per team, with Cedar policies per principal and a policy template per environment. |
| Prod instance is created running and stopped by a script. | Prod resources live in a different account; Leash gets no credentials there at all. |
| Audit rows written by the Lambda that also acts (AVP mode). | Done in the default shape: the authorizer Lambda writes the row before answering. For AVP mode, forward Verified Permissions' own CloudTrail events. |
| No retries / idempotency on incidents. | Idempotency key per alarm transition; cooldown per resource so a flapping alarm cannot cause repeated remediation. |
| Haiku-class model, short prompt, no memory between incidents. | Keep it small: the value is in the policies, not in the model. Add a runbook store if incident types multiply. |

## Repository map

```
template.yaml            root SAM stack (Lane C) — includes cedar/template.yaml as nested app "Authz"
cedar/                   Verified Permissions schema + the four policies + nested SAM template (Lane B)
src/common/authz.py      authorize(): the only path to Verified Permissions; LEASH_LOCAL_AUTHZ=1 -> cedarpy
src/common/audit.py      write_audit() / list_audit() (Lane B)
src/agent/               Strands agent + tools (Lane A)
src/authz_service/       the leash as a service: Cedar from S3, audit row first (Free-plan default)
local_demo/cloud_worker.py  the brain on any machine: SQS in, real AWS out, authorizer for every decision
src/api/handler.py       /health, /audit, /policies, /redteam, /ask, /reply (Lane D)
src/redteam/             attack catalogue + attacker model, two-arm runner, red-team Lambda handler
dashboard/index.html     static audit dashboard; config.js generated at deploy (Lane D)
scripts/                 deploy, break-disk, kill-task, inject-tag, stop-prod, ask, teardown (Lane C)
.github/workflows/ci.yml pytest + cfn-lint + sam validate on every push and pull request
tests/authz/             real Cedar evaluation of the four policies (cedarpy), file/template byte-identity
tests/agent, tests/api   tool and handler tests with fake boto3 clients; no AWS calls
docs/                    this file, WRITEUP.md, BLOG.md, SUBMISSION-CHECKLIST.md
```

### Known deviation: `template.yaml` is ~610 lines

The project guideline is ~300 lines per file. The root template is twice that because the
breakable demo infrastructure (two EC2 instances, the Fargate service, the Auto Scaling group and
both alarms) lives in it by design: one stack, one `sam deploy`, one `sam delete`, and the agent's
IAM statements reference those resources directly (`!Ref EcsService`, the ASG name). Splitting it
into a second nested application would add parameter plumbing for the AMI, VPC, subnet and key
name with no functional gain for a hackathon stack, so the size is accepted and noted here.
The Cedar side is already a nested application (`cedar/template.yaml`).
