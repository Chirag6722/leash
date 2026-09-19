"""The leash as a service: a Lambda that owns the Cedar policies and the audit trail.

Why it exists: on the AWS Free plan Amazon Verified Permissions is not available, so this
function plays the same role with the same engine (cedarpy wraps the Cedar Rust crate that
Verified Permissions runs). The policies live in a versioned S3 bucket and are hot-reloaded;
every decision is written to the audit table *by this function, before it answers*, so the
process that asked (the agent, wherever it runs) can neither skip the audit nor see the policy
text. That is stricter than the Verified Permissions path, where the tool wrote its own row.

A policy set is proved against the floor (common.floor) before it is loaded; one that would
permit what the floor forbids is never enforced: every decision is DENY until the store is fixed.

Invoked with {"op": "authorize" | "list_policies" | "result" | "floor", ...}; see each handler.
"""

from __future__ import annotations

import json
import logging
import os
import time

log = logging.getLogger("leash.authz_service")
log.setLevel(logging.INFO)


def _authorize(event: dict) -> dict:
    from common import audit, authz

    action = str(event.get("action", ""))
    rtype = str(event.get("resource_type", ""))
    rid = str(event.get("resource_id", ""))
    env = str(event.get("resource_env", "unknown"))
    context = event.get("context") or None
    incident_id = str(event.get("incident_id") or "unset")
    alarm_name = str(event.get("alarm_name") or "")

    started = time.perf_counter()
    decision = authz.evaluate_local(action, rtype, rid, env, context or {})
    decision_ms = (time.perf_counter() - started) * 1000.0
    result = "pending" if decision.allowed else "skipped (denied)"
    if action == "scaleGroup" and context and "desiredCapacity" in context and not decision.allowed:
        result += f" desired={context['desiredCapacity']}"
    row = audit.write_audit(incident_id=incident_id, action=action, resource_type=rtype, resource_id=rid,
                            resource_env=env, decision=decision, result=result, alarm_name=alarm_name,
                            decision_ms=decision_ms)
    log.info("decision %s %s %s env=%s -> %s %s", incident_id, action, rid, env,
             "ALLOW" if decision.allowed else "DENY", decision.policy_ids)
    return {
        "allowed": decision.allowed,
        "policy_ids": decision.policy_ids,
        "reason": decision.reason,
        "errors": decision.errors,
        "audit_ref": {"pk": row["pk"], "sk": row["sk"]},
        "policy_version": authz.policy_version(),
        "decision_ms": round(decision_ms, 2),
    }


def _floor(event: dict) -> dict:
    """Every floor invariant against the policy set this function enforces."""
    from common import authz

    return authz.floor_report()


def _list_policies(event: dict) -> dict:
    from common import authz

    return {"items": authz.list_policies(), "policy_version": authz.policy_version()}


def _result(event: dict) -> dict:
    """The caller reports what happened after an ALLOW: fills in the row's result."""
    from common import audit

    ref = event.get("audit_ref") or {}
    audit.update_result(ref, str(event.get("result", ""))[:1500])
    return {"ok": True}


OPS = {"authorize": _authorize, "list_policies": _list_policies, "result": _result, "floor": _floor}


def handler(event, context):
    event = event or {}
    op = str(event.get("op", ""))
    fn = OPS.get(op)
    if fn is None:
        return {"error": f"unknown op {op!r}"}
    try:
        return fn(event)
    except Exception as exc:  # noqa: BLE001 - the caller fails closed on any error
        log.exception("authz service failed")
        return {"error": f"{type(exc).__name__}: {exc}", "allowed": False, "policy_ids": [],
                "reason": f"authz-error: {exc}"}
