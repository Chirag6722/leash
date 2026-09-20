"""Strands tools for the Leash agent.

Every mutating tool follows the same shape: authorize (Cedar via common.authz) -> act or skip
-> write_audit -> return a plain string. The string always says "DENIED by <policy ids>" when
Cedar said no, so the model cannot claim success for a denied action.

`common.authz` / `common.audit` are looked up as module attributes at call time so tests can
monkeypatch `common.authz.authorize` and `common.audit.write_audit`.
"""

import logging
import os

from strands import tool

from agent import aws_helpers as aws
from common import audit, authz

log = logging.getLogger("leash.tools")

# Per-invocation context set by the handler (tools are plain functions, so a module-level
# holder is the simplest way to thread incident_id / alarm_name through to the audit row).
_CTX = {"incident_id": "unset", "alarm_name": ""}

CLEAN_DISK_SCRIPT = [
    "set +e",
    "BEFORE=$(df --output=pcent / | tail -1 | tr -dc '0-9')",
    "echo \"before: $(df -h / | tail -1)\"",
    "rm -f /tmp/leash-fill* /var/tmp/leash-fill*",  # /tmp is tmpfs on AL2023; the demo fills /var/tmp
    "journalctl --vacuum-size=50M >/dev/null 2>&1 || true",
    "find /var/log -type f -name '*.gz' -delete 2>/dev/null || true",
    "sync",
    "AFTER=$(df --output=pcent / | tail -1 | tr -dc '0-9')",
    "echo \"after: $(df -h / | tail -1)\"",
    "echo \"disk_used_percent before=${BEFORE} after=${AFTER}\"",
]


def set_context(incident_id: str, alarm_name: str = "") -> None:
    """Called by the handler once per invocation before the agent runs."""
    _CTX["incident_id"] = incident_id
    _CTX["alarm_name"] = alarm_name
    authz.set_audit_context(incident_id, alarm_name)


AUDIT_FAILED = " (audit write FAILED)"


def _sandbox_unleashed() -> bool:
    """True only for the red-team control arm: LEASH_SANDBOX_UNLEASHED=1 AND the boto3 seam is
    the in-memory fake from local_demo/. With real clients installed the flag is ignored, so
    this can never switch authorisation off against a real account."""
    if os.environ.get("LEASH_SANDBOX_UNLEASHED") != "1":
        return False
    try:
        from local_demo import fake_aws
    except ImportError:
        return False
    return aws.client is fake_aws.fake_client


def _decide(action: str, rtype: str, rid: str, env: str, context: dict | None = None):
    """Cedar decides - except in the sandboxed control arm, where nothing is checked."""
    if _sandbox_unleashed():
        return authz.Decision(allowed=True, policy_ids=["UNLEASHED-SANDBOX"], reason="no authorisation (control arm)")
    return authz.authorize(action, rtype, rid, env, context)


def _audit(action: str, rtype: str, rid: str, env: str, decision, result: str, summary: str = "") -> bool:
    """Write the audit row; returns False (and logs) if it could not be written.

    When the authorizer service already wrote the row (decision.audit_ref), only the result is
    filled in - the decision itself was recorded before this process could act on it."""
    try:
        ref = getattr(decision, "audit_ref", None)
        if ref:
            audit.update_result(ref, result)
            return True
        audit.write_audit(
            incident_id=_CTX["incident_id"],
            action=action,
            resource_type=rtype,
            resource_id=rid,
            resource_env=env,
            decision=decision,
            result=result,
            alarm_name=_CTX["alarm_name"],
            summary=summary,
        )
    except Exception as exc:  # auditing must never mask the tool outcome
        log.error("audit write failed: %s", exc)
        return False
    return True


def _denied(action: str, rid: str, env: str, decision, audited: bool = True) -> str:
    ids = ", ".join(decision.policy_ids) or "no-matching-permit"
    text = f"DENIED by {ids}: {action} on {rid} (env={env}) was refused by Cedar. {decision.reason}".strip()
    return text if audited else text + AUDIT_FAILED


def _allowed(action: str, rid: str, decision, result: str, audited: bool) -> str:
    text = f"ALLOWED by {', '.join(decision.policy_ids)}: {action} on {rid} -> {result}"
    return text if audited else text + AUDIT_FAILED


# --- read-only tools -------------------------------------------------------


@tool
def get_instance_info(instance_id: str) -> str:
    """EC2 instance env tag, state and Name tag. Read-only.

    Args:
        instance_id: EC2 instance id
    """
    try:
        info = aws.describe_instance(instance_id)
    except Exception as exc:
        return f"error describing {instance_id}: {exc}"
    return f"instance {instance_id}: env={info['env']} state={info['state']} name={info['name'] or '-'}"


@tool
def get_disk_usage(instance_id: str) -> str:
    """Latest root-filesystem disk_used_percent of an instance. Read-only.

    Args:
        instance_id: EC2 instance id
    """
    try:
        point = aws.latest_metric("CWAgent", "disk_used_percent", {"InstanceId": instance_id})
    except Exception as exc:
        return f"error reading disk metric for {instance_id}: {exc}"
    if not point:
        return f"no recent disk_used_percent datapoint for {instance_id}"
    return f"disk_used_percent for {instance_id} = {point['value']:.1f}% at {point['timestamp']}"


@tool
def get_service_info(cluster: str, service: str) -> str:
    """ECS service running/desired task counts and env tag. Read-only.

    Args:
        cluster: ECS cluster name
        service: ECS service name
    """
    try:
        info = aws.describe_service(cluster, service)
    except Exception as exc:
        return f"error describing {cluster}/{service}: {exc}"
    return (
        f"service {cluster}/{service}: running={info['running']} desired={info['desired']} "
        f"status={info['status']} env={info['env']}"
    )


# --- mutating tools (authorize -> act -> audit) ----------------------------


@tool
def clean_disk(instance_id: str) -> str:
    """Free disk space on an instance over SSM (temp files, old logs). Cedar-checked.

    Args:
        instance_id: EC2 instance id
    """
    env = aws.instance_env(instance_id)
    decision = _decide("cleanDisk", "Instance", instance_id, env)
    if not decision.allowed:
        ok = _audit("cleanDisk", "Instance", instance_id, env, decision, "skipped (denied)")
        return _denied("cleanDisk", instance_id, env, decision, ok)
    try:
        run = aws.ssm_run(instance_id, CLEAN_DISK_SCRIPT, timeout_s=90)
        result = f"ssm {run['status']}: {run['stdout'].strip()[-600:]}"
        if run["stderr"].strip():
            result += f" | stderr: {run['stderr'].strip()[-200:]}"
    except Exception as exc:
        result = f"error: {exc}"
    ok = _audit("cleanDisk", "Instance", instance_id, env, decision, result)
    return _allowed("cleanDisk", instance_id, decision, result, ok)


@tool
def restart_service(cluster: str, service: str) -> str:
    """Bring an ECS service back: new deployment, desired count restored to 1 if 0. Cedar-checked.

    Args:
        cluster: ECS cluster name
        service: ECS service name
    """
    rid = f"{cluster}/{service}"
    env = aws.service_env(cluster, service)
    decision = _decide("restartService", "EcsService", rid, env)
    if not decision.allowed:
        ok = _audit("restartService", "EcsService", rid, env, decision, "skipped (denied)")
        return _denied("restartService", rid, env, decision, ok)
    try:
        # https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html
        kwargs = {"cluster": cluster, "service": service, "forceNewDeployment": True}
        try:
            if aws.describe_service(cluster, service)["desired"] == 0:
                kwargs["desiredCount"] = 1  # the service was left with no tasks at all
        except Exception:  # noqa: BLE001 - if we cannot read it, just force the deployment
            pass
        resp = aws.client("ecs").update_service(**kwargs)
        svc = resp.get("service", {})
        result = f"forceNewDeployment issued; desired={svc.get('desiredCount', '?')} status={svc.get('status', '?')}"
        if "desiredCount" in kwargs:
            result = "desired count was 0, set to 1; " + result
    except Exception as exc:
        result = f"error: {exc}"
    ok = _audit("restartService", "EcsService", rid, env, decision, result)
    return _allowed("restartService", rid, decision, result, ok)


@tool
def scale_group(asg_name: str, desired_capacity: int) -> str:
    """Set the desired capacity of an Auto Scaling group. Cedar-checked (including the cap).

    Args:
        asg_name: Auto Scaling group name
        desired_capacity: new desired instance count
    """
    env = aws.asg_env(asg_name)
    context = {"desiredCapacity": int(desired_capacity)}
    decision = _decide("scaleGroup", "AutoScalingGroup", asg_name, env, context)
    if not decision.allowed:
        ok = _audit("scaleGroup", "AutoScalingGroup", asg_name, env, decision, f"skipped (denied) desired={desired_capacity}")
        return _denied("scaleGroup", asg_name, env, decision, ok) + f" (requested desiredCapacity={desired_capacity})"
    try:
        aws.client("autoscaling").set_desired_capacity(
            AutoScalingGroupName=asg_name, DesiredCapacity=int(desired_capacity), HonorCooldown=False
        )
        result = f"desired capacity set to {desired_capacity}"
    except Exception as exc:
        result = f"error: {exc}"
    ok = _audit("scaleGroup", "AutoScalingGroup", asg_name, env, decision, result)
    return _allowed("scaleGroup", asg_name, decision, result, ok)


@tool
def terminate_instance(instance_id: str) -> str:
    """Terminate an EC2 instance. Cedar-checked; the decision is audited either way.

    Args:
        instance_id: EC2 instance id
    """
    env = aws.instance_env(instance_id)
    decision = _decide("terminateInstance", "Instance", instance_id, env)
    if not decision.allowed:
        ok = _audit("terminateInstance", "Instance", instance_id, env, decision, "skipped (denied)")
        return _denied("terminateInstance", instance_id, env, decision, ok)
    if _sandbox_unleashed():
        # Control arm only (fake EC2): show what an agent without the guard would have done.
        aws.client("ec2").terminate_instances(InstanceIds=[instance_id])
        result = "terminated (UNLEASHED SANDBOX - fake EC2, control arm)"
        ok = _audit("terminateInstance", "Instance", instance_id, env, decision, result)
        text = f"ALLOWED by UNLEASHED-SANDBOX: terminateInstance on {instance_id} -> {result}"
        return text if ok else text + AUDIT_FAILED
    # Defence in depth: never call ec2.terminate_instances from this code path, whatever Cedar said.
    result = "refused by hard-coded guard"
    ok = _audit("terminateInstance", "Instance", instance_id, env, decision, result)
    text = f"terminateInstance on {instance_id}: {result} (Leash never terminates instances)"
    return text if ok else text + AUDIT_FAILED


@tool
def notify(summary: str) -> str:
    """Publish a short incident summary to the alert SNS topic.

    Args:
        summary: one paragraph
    """
    topic = os.environ.get("ALERT_TOPIC_ARN", "")
    if not topic:
        return "notify skipped: ALERT_TOPIC_ARN not set"
    try:
        subject = f"[Leash] {_CTX['alarm_name'] or _CTX['incident_id']}"[:100]
        aws.client("sns").publish(TopicArn=topic, Subject=subject, Message=summary)
        return "notification published"
    except Exception as exc:
        return f"notify failed: {exc}"


ALL_TOOLS = [
    get_instance_info,
    get_disk_usage,
    get_service_info,
    clean_disk,
    restart_service,
    scale_group,
    terminate_instance,
    notify,
]
