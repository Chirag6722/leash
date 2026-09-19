"""The leash as a service: Cedar from files, audit row written before answering, result filled in."""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AUDIT_TABLE", "leash-audit-test")

import common.audit as audit  # noqa: E402
import common.authz as authz  # noqa: E402
from authz_service import handler as svc  # noqa: E402


class FakeDdb:
    def __init__(self):
        self.items = []

    def put_item(self, TableName, Item):
        self.items.append(Item)
        return {}

    def update_item(self, TableName, Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues):
        for it in self.items:
            if it["pk"] == Key["pk"] and it["sk"] == Key["sk"]:
                it["result"] = ExpressionAttributeValues[":r"]
                return {}
        raise KeyError("no row")


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setenv("LEASH_LOCAL_AUTHZ", "1")
    monkeypatch.delenv("LEASH_AUTHZ_FUNCTION", raising=False)
    monkeypatch.delenv("LEASH_CEDAR_S3_BUCKET", raising=False)
    monkeypatch.delenv("LEASH_CEDAR_DIR", raising=False)
    authz.reset_cache()
    ddb = FakeDdb()
    monkeypatch.setattr(audit, "_client", lambda: ddb)
    return ddb


def test_deny_is_written_before_the_answer(service):
    out = svc.handler({"op": "authorize", "action": "terminateInstance", "resource_type": "Instance",
                       "resource_id": "i-1", "resource_env": "dev", "incident_id": "inc-9", "alarm_name": ""}, None)
    assert out["allowed"] is False and out["policy_ids"] == ["ForbidDestructive"]
    assert len(service.items) == 1
    row = service.items[0]
    assert row["pk"]["S"] == "inc-9" and row["decision"]["S"] == "DENY" and row["result"]["S"] == "skipped (denied)"
    assert out["audit_ref"] == {"pk": "inc-9", "sk": row["sk"]["S"]}
    assert out["policy_version"].startswith("disk:")


def test_allow_writes_pending_row_then_result_fills_it(service):
    out = svc.handler({"op": "authorize", "action": "cleanDisk", "resource_type": "Instance",
                       "resource_id": "i-1", "resource_env": "dev", "incident_id": "inc-1"}, None)
    assert out["allowed"] is True and out["policy_ids"] == ["PermitDevRemediation"]
    assert service.items[0]["result"]["S"] == "pending"
    done = svc.handler({"op": "result", "audit_ref": out["audit_ref"], "result": "ssm Success: cleaned"}, None)
    assert done == {"ok": True}
    assert service.items[0]["result"]["S"] == "ssm Success: cleaned"


def test_scale_over_cap_records_requested_capacity(service):
    out = svc.handler({"op": "authorize", "action": "scaleGroup", "resource_type": "AutoScalingGroup",
                       "resource_id": "g", "resource_env": "dev", "context": {"desiredCapacity": 10},
                       "incident_id": "inc-2"}, None)
    assert out["allowed"] is False and out["policy_ids"] == ["ForbidScaleAboveCap"]
    assert service.items[0]["result"]["S"] == "skipped (denied) desired=10"


def test_list_policies_op(service):
    out = svc.handler({"op": "list_policies"}, None)
    assert [p["id"] for p in out["items"]] == list(authz.POLICY_NAMES)


def test_unknown_op_and_failures_fail_closed(service, monkeypatch):
    assert "error" in svc.handler({"op": "nope"}, None)
    monkeypatch.setattr(audit, "write_audit", lambda **kw: (_ for _ in ()).throw(RuntimeError("ddb down")))
    out = svc.handler({"op": "authorize", "action": "cleanDisk", "resource_type": "Instance",
                       "resource_id": "i-1", "resource_env": "dev"}, None)
    assert out["allowed"] is False and "ddb down" in out["error"]


# --- policies from S3 with hot reload ----------------------------------------------------


class FakeS3:
    def __init__(self, files: dict, etag_suffix="a"):
        self.files, self.etag_suffix, self.gets = files, etag_suffix, 0

    def list_objects_v2(self, Bucket, Prefix):
        return {"Contents": [{"Key": k, "ETag": f'"{abs(hash(v + self.etag_suffix)):x}"'} for k, v in self.files.items()]}

    def get_object(self, Bucket, Key):
        import io

        self.gets += 1
        return {"Body": io.BytesIO(self.files[Key].encode("utf-8"))}


def _cedar_files_on_disk() -> dict:
    base = ROOT / "cedar"
    files = {f"cedar/policies/{n}.cedar": (base / "policies" / f"{n}.cedar").read_text(encoding="utf-8")
             for n in authz.POLICY_NAMES}
    files["cedar/schema.json"] = (base / "schema.json").read_text(encoding="utf-8")
    return files


def test_s3_policies_evaluate_and_hot_reload(monkeypatch):
    import boto3

    monkeypatch.setenv("LEASH_LOCAL_AUTHZ", "1")
    monkeypatch.delenv("LEASH_AUTHZ_FUNCTION", raising=False)
    monkeypatch.setenv("LEASH_CEDAR_S3_BUCKET", "leash-policies")
    authz.reset_cache()
    fake = FakeS3(_cedar_files_on_disk())
    monkeypatch.setattr(boto3, "client", lambda *a, **k: fake)

    d = authz.authorize("cleanDisk", "Instance", "i-1", "prod")
    assert d.allowed is False and d.policy_ids == ["ForbidProd"]
    first_gets = fake.gets
    authz.authorize("cleanDisk", "Instance", "i-1", "prod")
    assert fake.gets == first_gets  # unchanged ETags: no re-download

    # Edit the cap in the bucket (what scripts/set-cap.sh does): the next decision sees it.
    assert authz.authorize("scaleGroup", "AutoScalingGroup", "g", "dev", {"desiredCapacity": 3}).allowed is True
    fake.files["cedar/policies/ForbidScaleAboveCap.cedar"] = (
        'forbid (principal, action == Leash::Action::"scaleGroup", resource) when { context.desiredCapacity > 2 };'
    )
    d2 = authz.authorize("scaleGroup", "AutoScalingGroup", "g", "dev", {"desiredCapacity": 3})
    assert d2.allowed is False and d2.policy_ids == ["ForbidScaleAboveCap"] and fake.gets > first_gets
    assert authz.policy_version().startswith("s3:")

    # Edit the bucket so prod is allowed for cleanDisk: that breaks the floor, so the set is never
    # loaded. Every request fails closed with the invariant's name, a dev clean included.
    fake.files["cedar/policies/ForbidProd.cedar"] = 'forbid (principal, action, resource) when { resource.env == "nope" };'
    fake.files["cedar/policies/PermitDevRemediation.cedar"] = (
        'permit (principal == Leash::Agent::"leash", action == Leash::Action::"cleanDisk", resource) '
        'when { resource.env == "prod" || resource.env == "dev" };'
    )
    gets_before = fake.gets
    d3 = authz.authorize("cleanDisk", "Instance", "i-1", "prod")
    assert d3.allowed is False and d3.policy_ids == ["Floor:NeverCleanProd"]
    assert "until the store is fixed" in d3.reason
    assert authz.authorize("cleanDisk", "Instance", "i-1", "dev").allowed is False  # fail closed for everything
    assert fake.gets == gets_before + 5  # the rejection is cached per version: no re-download per decision
    assert svc.handler({"op": "floor"}, None)["holds"] is False

    # Put the store right again and the leash is back, no restart.
    fake.files["cedar/policies/ForbidProd.cedar"] = 'forbid (principal, action, resource) when { resource.env == "prod" };'
    assert authz.authorize("cleanDisk", "Instance", "i-1", "dev").allowed is True
    assert svc.handler({"op": "floor"}, None)["holds"] is True
    authz.reset_cache()
