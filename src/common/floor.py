"""The floor under the leash: requests that no policy version may ever permit.

The leash (the .cedar files in the store) is meant to move. An operator approves an English
rule and the next decision uses it; scripts/set-cap.sh edits the bucket directly. The floor does
not move from the page, the token, or the bucket, because it ships in this code and the leash
re-proves it against the policy set at three points:

    propose()   the proof names the invariant a draft would break, so nobody approves it blind
    approve()   refuses to publish a set that breaks one, whoever holds the operator token
    load        the authorizer will not load a policy set that breaks one: every request is
                DENY (fail closed), the audit row names the invariant, until the store is fixed.
                A `permit (principal, action, resource);` dropped into the bucket by hand loosens
                nothing; it switches the agent off.

Each invariant is one concrete request that must stay DENY. Together they are the promises the
README makes: nothing is ever terminated or deleted, nothing touches prod, no scale above the
cap, nothing happens to a resource the leash cannot place. Changing them is a code change, a
review and a deploy, which is the point.
"""

from __future__ import annotations

# (name, why, action, resource type, resource id, env, context)
INVARIANTS: list[tuple[str, str, str, str, str, str, dict]] = [
    ("NeverTerminateDev", "no instance is ever terminated, dev included",
     "terminateInstance", "Instance", "i-dev", "dev", {}),
    ("NeverTerminateProd", "no instance is ever terminated, prod included",
     "terminateInstance", "Instance", "i-prod", "prod", {}),
    ("NeverDeleteInstance", "nothing is ever deleted: instances",
     "deleteResource", "Instance", "i-dev", "dev", {}),
    ("NeverDeleteService", "nothing is ever deleted: services",
     "deleteResource", "EcsService", "leash-dev/leash-api-dev", "dev", {}),
    ("NeverDeleteGroup", "nothing is ever deleted: auto scaling groups",
     "deleteResource", "AutoScalingGroup", "leash-dev-asg", "dev", {}),
    ("NeverCleanProd", "nothing touches prod: not even a disk clean",
     "cleanDisk", "Instance", "i-prod", "prod", {}),
    ("NeverRestartProd", "nothing touches prod: no restart",
     "restartService", "EcsService", "leash-prod/db", "prod", {}),
    ("NeverScaleProd", "nothing touches prod: no scaling, not even to 1",
     "scaleGroup", "AutoScalingGroup", "leash-prod-asg", "prod", {"desiredCapacity": 1}),
    ("NeverScaleToTen", "no policy may raise the scale cap as far as 10",
     "scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", {"desiredCapacity": 10}),
    ("NeverTouchUntagged", "a resource without an env tag is not the agent's to change",
     "cleanDisk", "Instance", "i-unknown", "unknown", {}),
]


class FloorBroken(Exception):
    """A policy set that would permit a request the floor forbids."""

    def __init__(self, failures: list[dict], version: str = ""):
        self.failures = failures
        self.version = version
        names = ", ".join(f["name"] for f in failures)
        super().__init__(f"policy set breaks the floor ({names})")


def check(policies_text: str, schema: dict, decide) -> list[dict]:
    """Evaluate every invariant against `policies_text`.

    `decide(policies_text, schema, action, rtype, rid, env, context) -> (allowed, policy_ids)`
    is the Cedar engine (common.authz.evaluate_text). Returns one row per invariant:
    {"name", "why", "case", "holds", "policy_ids"}; `holds` is False when the set would ALLOW it.
    """
    rows = []
    for name, why, action, rtype, rid, env, ctx in INVARIANTS:
        allowed, ids = decide(policies_text, schema, action, rtype, rid, env, ctx)
        rows.append({"name": name, "why": why, "case": f"{action} on {rtype} {rid} (env={env}"
                     + (f", {', '.join(f'{k}={v}' for k, v in ctx.items())}" if ctx else "") + ")",
                     "holds": not allowed, "policy_ids": list(ids)})
    return rows


def broken(rows: list[dict]) -> list[dict]:
    return [r for r in rows if not r["holds"]]


def describe(rows: list[dict]) -> list[str]:
    """One line per broken invariant, for a proposal card or an audit reason."""
    return [f"{r['name']}: {r['case']} would become ALLOW" for r in broken(rows)]
