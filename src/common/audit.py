"""Audit trail: one DynamoDB item per authorisation decision, newest-first listing for the dashboard.

Table (root template.yaml): pk = incident_id, sk = ISO8601 UTC timestamp with microseconds,
GSI "gsi1" on (gsi1pk = "ALL", sk) so a single Query returns everything newest first.
"""

import os
from datetime import datetime, timezone

_DDB = None  # cached boto3 client

GSI_NAME = "gsi1"
GSI_PK = "ALL"
GSI_PK_REDTEAM = "REDTEAM"  # red-team attack rows live in their own GSI partition
GSI_PK_REPLY = "REPLY"  # agent replies to queued human requests (worker mode)
REPLY_SK = "reply"
HEARTBEAT_KEY = ("heartbeat", "worker")  # the brain's liveness row (worker mode)


def _client():
    global _DDB
    if _DDB is None:
        import boto3

        _DDB = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    return _DDB


def _table() -> str:
    return os.environ["AUDIT_TABLE"]


def timestamp() -> str:
    """ISO8601 UTC with microseconds, e.g. 2026-09-18T03:12:07.123456Z (sorts lexically)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def write_audit(incident_id: str, action: str, resource_type: str, resource_id: str, resource_env: str,
                decision, result: str, alarm_name: str = "", summary: str = "",
                decision_ms: float | None = None) -> dict:
    """PutItem one decision row; returns the plain-dict item that was written. `decision_ms` is
    how long the Cedar evaluation itself took, when the caller measured it."""
    item = {
        "pk": incident_id,
        "sk": timestamp(),
        "gsi1pk": GSI_PK,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_env": resource_env,
        "decision": "ALLOW" if decision.allowed else "DENY",
        "policy_ids": list(decision.policy_ids),
        "reason": decision.reason,
        "result": result,
        "alarm_name": alarm_name,
        "summary": summary,
    }
    if decision_ms is not None:
        item["decision_ms"] = f"{decision_ms:.2f}"
    # Low-level client: attribute values are typed ({"S": ...}, {"L": [...]}).
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/put_item.html
    _client().put_item(TableName=_table(), Item=_serialize(item))
    return item


def list_audit(limit: int = 50) -> list[dict]:
    """Newest-first decisions via Query on gsi1 (gsi1pk = "ALL", ScanIndexForward=False)."""
    return _list_partition(GSI_PK, limit)


def list_redteam(limit: int = 200) -> list[dict]:
    """Newest-first red-team attack rows (gsi1pk = "REDTEAM")."""
    return _list_partition(GSI_PK_REDTEAM, limit)


def write_generic(pk: str, gsi1pk: str, attrs: dict) -> dict:
    """PutItem an arbitrary row (used by the red-team runner); sk is the timestamp as always."""
    item = {"pk": pk, "sk": timestamp(), "gsi1pk": gsi1pk, **attrs}
    _client().put_item(TableName=_table(), Item=_serialize(item))
    return item


def update_result(ref: dict, result: str) -> None:
    """Fill in the result of a row the authorizer service wrote ({"pk", "sk"})."""
    _client().update_item(
        TableName=_table(),
        Key={"pk": {"S": str(ref["pk"])}, "sk": {"S": str(ref["sk"])}},
        UpdateExpression="SET #r = :r",
        ExpressionAttributeNames={"#r": "result"},
        ExpressionAttributeValues={":r": {"S": result}},
    )


def write_reply(incident_id: str, reply: str) -> dict:
    """The agent's final text for a queued request; the dashboard polls GET /reply for it."""
    item = {"pk": incident_id, "sk": REPLY_SK, "gsi1pk": GSI_PK_REPLY, "reply": reply, "at": timestamp()}
    _client().put_item(TableName=_table(), Item=_serialize(item))
    return item


def get_reply(incident_id: str) -> dict | None:
    resp = _client().get_item(TableName=_table(), Key={"pk": {"S": incident_id}, "sk": {"S": REPLY_SK}})
    item = resp.get("Item")
    return _deserialize(item) if item else None


def write_heartbeat(model: str, host: str, busy: bool = False) -> dict:
    """One liveness row per brain (sk = its name), rewritten every few seconds, so several brains
    (an EC2 instance and a laptop, say) can share the queues and all be seen; `busy` says whether
    it is answering right now."""
    item = {"pk": HEARTBEAT_KEY[0], "sk": host or HEARTBEAT_KEY[1], "gsi1pk": "HEARTBEAT", "at": timestamp(),
            "model": model, "host": host, "busy": "true" if busy else "false"}
    _client().put_item(TableName=_table(), Item=_serialize(item))
    return item


def read_heartbeats() -> list[dict]:
    """Every brain that has ever written a heartbeat, newest first; the caller judges freshness."""
    resp = _client().query(
        TableName=_table(),
        KeyConditionExpression="pk = :hb",
        ExpressionAttributeValues={":hb": {"S": HEARTBEAT_KEY[0]}},
    )
    rows = [_deserialize(it) for it in resp.get("Items", [])]
    return sorted(rows, key=lambda r: r.get("at", ""), reverse=True)


def read_heartbeat() -> dict | None:
    rows = read_heartbeats()
    return rows[0] if rows else None


def _list_partition(gsi1pk: str, limit: int) -> list[dict]:
    resp = _client().query(
        TableName=_table(),
        IndexName=GSI_NAME,
        KeyConditionExpression="gsi1pk = :pk",
        ExpressionAttributeValues={":pk": {"S": gsi1pk}},
        ScanIndexForward=False,
        Limit=max(1, int(limit)),
    )
    return [_deserialize(it) for it in resp.get("Items", [])]


# --- DynamoDB typed-value helpers (kept explicit; only S and L-of-S are used) --------


def _serialize(item: dict) -> dict:
    out = {}
    for key, value in item.items():
        if isinstance(value, list):
            out[key] = {"L": [{"S": str(v)} for v in value]}
        else:
            out[key] = {"S": str(value)}
    return out


def _deserialize(item: dict) -> dict:
    out = {}
    for key, typed in item.items():
        if "S" in typed:
            out[key] = typed["S"]
        elif "L" in typed:
            out[key] = [v.get("S", "") for v in typed["L"]]
        elif "N" in typed:
            out[key] = typed["N"]
        else:
            out[key] = next(iter(typed.values()), None)
    return out
