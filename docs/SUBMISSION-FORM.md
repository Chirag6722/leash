# Submission form: the answers, ready to paste

The organisers' submission-day tips (20 Sept 2026): write detailed answers (idea, the problem
that made you build it, what it does), a 3-minute video on YouTube (record it first), a live demo
that needs no sign-up, be clear about which AWS services you used, how, and what feedback you
have, and say who worked on what. Everything below is written for those five points. Fill the two
links, check the team split, paste.

## Links

- Repository: https://github.com/thegoodengineers/leash
- Live demo (no sign-up, nothing to install): https://zjebhhtr9h.execute-api.us-east-1.amazonaws.com/
- Demo video (YouTube, unlisted): **[paste]**
- Blog (AWS Builder Center): **[paste]**
- Team: thegoodengineers (Abhijeet Sharma, Chirag Honnyal, Bhumika Gurav, Ayush V Upadhye)
- Track: Ship It

## Project description

**The idea.** An on-call ops agent that can fix your AWS at 3 AM but can never destroy anything,
because every action it takes is authorised by Cedar policies evaluated outside the model, before
it happens.

**The problem.** Every small team has the same story: a disk fills, a container dies, an alarm goes
red, and the fix is one command everyone already knows. Nobody runs it, because it is 3 AM. The
obvious answer is a bot. The reason nobody ships one is trust: credentials that can clean a disk
can usually also terminate the instance, and a language model with those credentials can be talked
into anything by whoever gets text in front of it, through a chat box, a log line, or a resource
tag. Capability was never the blocker. Trust was. So we built the trust part.

**What it does.** A CloudWatch alarm goes through EventBridge to an SQS queue. A Strands agent (the
brain) picks it up, diagnoses with read-only tools, then calls a mutating tool: clean the disk,
restart the service, scale the group. Inside every mutating tool, before anything touches AWS, the
tool asks the leash: a separate Lambda that holds four Cedar policies in a versioned S3 bucket,
evaluates them with the Cedar engine, and writes the audit row before it answers. Allowed, it acts
over Systems Manager, ECS or Auto Scaling and emails a summary. Denied, it does nothing, and the row
names the policy that refused. Cedar is deny-by-default and any forbid beats every permit, so the
model can be persuaded and it changes nothing.

We measured it rather than claimed it. A full dev disk was fixed in 5 min 48 s with nobody awake.
An attacker model wrote 54 attacks across eight tactics (fake AWS Support, fake emergencies, "the
policy was updated", role-play, base64, instructions hidden in logs and in the instance's own Name
tag), each run twice with the same model and tools: with the leash off in a sandbox, 42 destroyed
something; with the leash on, against real AWS, 0. Every zero is a Cedar decision you can read in
the audit trail.

Rules are written in English on the dashboard. The model drafts Cedar, the engine validates it, a
proof lists every request whose answer would flip, the last 200 real decisions are replayed under
the candidate ("this rule would have left seven disks full"), and only a person with the operator
token can publish. Under all of that is a floor: ten invariants that ship in code (never terminate,
never delete, nothing on prod, no scale cap of 10, nothing untagged). A policy set that breaks one is
never loaded; the agent switches off, it does not loosen. And the floor is formally verified: Cedar's
symbolic compiler and the cvc5 SMT solver prove, over every possible request the schema admits, that
the enforced policies allow nothing outside the floor. That proof runs in CI on every push, on every
rule the model drafts, and on the live policy store whenever it changes; the dashboard shows the
verdict. Loosen the cap to 20 and the solver hands back the exact request that escapes
(scaleGroup, desiredCapacity 17) in under a second. To our knowledge this is the first AI agent whose
action space is bounded by a formally verified policy floor.

All of it runs on the AWS Free plan, about eight cents an hour, with no access keys anywhere: the
model runs on an EC2 instance under a scoped IAM role.

**What you can do on the live page without an account:** read the audit trail and click any policy
id to see the rule that decided it; ask the agent to do something dangerous and watch the DENY row
land before the reply; propose a rule in English and see the proof, the replay and the SMT verdict;
read the red-team panel. Publishing a rule and launching a new attack run need the operator token
so a visitor cannot change the system for the next visitor; both are shown in the video.

## AWS services: which, how, and what we would tell AWS

| Service | How Leash uses it |
| --- | --- |
| **Strands Agents** (AWS open source) | The brain: tool-calling agent loop, same code on Bedrock or a local model |
| **Cedar** (AWS open source) via cedarpy and **cedar-policy-symcc** | The leash: four policies, deny-by-default, forbid beats permit; the symbolic compiler proves the floor over every request with cvc5 |
| **Lambda** | The authorizer (owns the policies and the audit trail, writes the row before answering), the HTTP API, the red-team runner, and the agent itself in Bedrock mode |
| **Amazon Verified Permissions** | Drop-in policy store for the authorizer with one template parameter (`PolicyStore=avp`) on accounts that have it |
| **Amazon Bedrock** | The brain with one parameter (`Brain=bedrock`, Claude Haiku 4.5); not in the Free plan, so the submission runs a local model instead |
| **EC2** | The brain host (m7i-flex.large, Ollama, systemd worker, self-updating from main, carries the SMT prover); the dev instance that gets broken; a stopped prod decoy that exists only to be denied |
| **Systems Manager** | Run Command for diagnosis and the disk clean, no SSH; SSM Parameter Store pins the AMI; SSM manages the brain host |
| **CloudWatch** | Disk and task-count alarms with metric math (`FILL(running, 0)` so a stopped task still alarms); agent metrics |
| **EventBridge** | Alarm state changes to the incident queue |
| **SQS** | Incident and request queues with dead-letter queues; the brain is a plain consumer, so it can run anywhere |
| **DynamoDB** | One table: audit rows (with the authorizer's own decision latency), heartbeats per brain, red-team rows, proposals, the latest SMT proof |
| **S3** | Versioned policy bucket (hot-reloaded by ETag; every version one `list-object-versions` away); the dashboard page |
| **API Gateway (HTTP API)** | The dashboard's API and the https origin for the page itself |
| **ECS on Fargate, Auto Scaling** | The dev service and group the agent is allowed to restart and scale, both with the cap enforced by Cedar |
| **SNS** | The email a human gets after every incident |
| **IAM** | The floor under the floor: explicit Deny on every delete and terminate API, Run Command only on `env=dev` instances |
| **CloudFormation / SAM** | One stack, one `sam deploy`, nested Cedar stack, change-set deploys |

**Feedback for AWS, from four days of building on the Free plan:**

- The Free plan is a good place to start, but the two services this project was designed around,
  Verified Permissions and Bedrock, both answer "needs a subscription" on it, and nothing on the
  plan's page says which services are excluded. We found out at deploy time. A list would have saved
  a day. (The split design it forced, a separate authorizer Lambda that owns the policies, ended up
  stricter than the original, so it was a good day.)
- CloudFront also cannot be created on a new account without an AWS Support verification, so an
  https dashboard needed a workaround: the HTTP API serves the page itself. Worth documenting next to
  the Free plan.
- Cedar's symbolic compiler (cedar-policy-symcc) is remarkable and almost unknown: an exact proof
  over every possible request in under a second. It deserves a Verified Permissions console button
  ("prove this policy set never allows X") and a first-class CLI; today it needs a Rust build and a
  pinned cvc5 1.3.1.
- Container Insights never reported the `RunningTaskCount` drop for a task that was killed and not
  replaced; we had to alarm on `FILL(running, 0)` metric math and break the service by setting the
  desired count to 0. The default metric should make a dead service visible.
- The free-tier-eligible EC2 list is generous (m7i-flex.large runs an 8B model with swap), but a
  CPU-only brain makes every agent turn slow; Bedrock on the Free plan, even rate-limited, would let
  Strands agents be demoed as they are meant to be.
- Strands is a pleasure: swapping Bedrock for a local Ollama model was one class, and the tool
  loop never got in the way of putting the authorisation check inside the tool.

## Who worked on what

From the commit history plus the parts that do not show up in git; edit before pasting.

- **Abhijeet Sharma**: AWS account, deployment and operations (SAM change-set deploys, the EC2
  brain, SSM); the authorizer-and-worker split for the Free plan; the floor and the SMT proof
  (`verify/`, CI, live prover on the brain); the red-team arena runner and both measured runs;
  proposals proofs (floor, SMT, replay against the record); docs, blog, demo script, video.
- **Chirag Honnyal**: the dashboard (editorial design, the verdict line, the 3D arena, the
  arrival animations, screenshots); the English-to-Cedar proposals module; agent prompt and
  performance work for CPU-only brains (prompt trimming, generation caps, summaries that name the
  policy); the org move and repository housekeeping. **[add anything else]**
- **Bhumika Gurav**: local in-memory AWS fixes (tag lookups), red-team runner cleanup, testing of
  the local demo. **[add: testing, blog review, video?]**
- **Ayush V Upadhye**: SQS dead-letter queues for both queues. **[add: testing, blog, video?]**

## AI tools used (disclosure the rules ask for)

Claude Code was used to scaffold and review code, as disclosed in the README. All architecture
decisions, the policy design, the measurements and the demo were made by the team; every generated
file was read and tested before it was kept.

## Before you press submit

1. Video uploaded to YouTube, unlisted or public, under three minutes, opens in a private window.
2. Live link opens in a private window and the header says "brain online".
3. Blog published on Builder Center; its URL and the video URL pasted above and into the README.
4. Team split checked by every teammate.
5. Form link: https://wemakedevs.org/aws/first-commit/submit
