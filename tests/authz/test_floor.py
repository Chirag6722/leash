"""The floor: invariants no policy version may break, enforced when the set is loaded."""

import pytest

from common import authz, floor


@pytest.fixture
def scratch(tmp_path, monkeypatch):
    """A throwaway copy of cedar/ the authorizer reads from."""
    import shutil
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    dst = tmp_path / "cedar"
    shutil.copytree(root / "cedar", dst)
    monkeypatch.setenv("LEASH_LOCAL_AUTHZ", "1")
    monkeypatch.setenv("LEASH_CEDAR_DIR", str(dst))
    monkeypatch.delenv("LEASH_CEDAR_S3_BUCKET", raising=False)
    monkeypatch.delenv("LEASH_AUTHZ_FUNCTION", raising=False)
    authz.reset_cache()
    yield dst
    authz.reset_cache()


def test_the_shipped_policies_hold_every_invariant(scratch):
    report = authz.floor_report()
    assert report["holds"] is True and report["count"] == len(floor.INVARIANTS) == 10
    assert all(r["holds"] for r in report["invariants"])
    # each invariant is decided by a named forbid, or by deny-by-default (no permit matched)
    for r in report["invariants"]:
        assert all(pid.startswith("Forbid") for pid in r["policy_ids"]), r


def test_a_permit_all_dropped_into_the_store_switches_the_agent_off(scratch):
    """The forbids still beat a permit-all for terminate, delete and prod (Cedar: any matching
    forbid wins). But a permit-all also opens resources with no env tag, which no forbid covers,
    so the floor rejects the whole set: the agent is off, not loosened, until the file goes."""
    (scratch / "policies" / "Anything.cedar").write_text("permit (principal, action, resource);\n")
    authz.reset_cache()
    report = authz.floor_report()
    assert report["holds"] is False
    assert [r["name"] for r in report["invariants"] if not r["holds"]] == ["NeverTouchUntagged"]
    d = authz.authorize("cleanDisk", "Instance", "i-1", "dev")
    assert d.allowed is False and d.policy_ids == ["Floor:NeverTouchUntagged"]
    (scratch / "policies" / "Anything.cedar").unlink()
    authz.reset_cache()
    assert authz.authorize("cleanDisk", "Instance", "i-1", "dev").allowed is True


def test_removing_a_forbid_fails_closed_until_the_store_is_fixed(scratch):
    """Delete ForbidDestructive from the store, then add a permit for terminate: the set would
    permit what the floor forbids, so it is never loaded. Nothing is allowed, not even the dev
    clean that the shipped policies permit, and the row names the invariant."""
    (scratch / "policies" / "ForbidDestructive.cedar").unlink()
    (scratch / "policies" / "PermitTerminate.cedar").write_text(
        'permit (principal, action == Leash::Action::"terminateInstance", resource) when { resource.env == "dev" };\n')
    authz.reset_cache()
    d = authz.authorize("cleanDisk", "Instance", "i-1", "dev")
    assert d.allowed is False
    assert d.policy_ids == ["Floor:NeverTerminateDev"]
    assert "until the store is fixed" in d.reason
    assert d.errors == ["NeverTerminateDev: terminateInstance on Instance i-dev (env=dev) would become ALLOW"]
    assert authz.authorize("terminateInstance", "Instance", "i-1", "dev").allowed is False
    report = authz.floor_report()
    assert report["holds"] is False and [r["name"] for r in report["invariants"] if not r["holds"]] == ["NeverTerminateDev"]

    (scratch / "policies" / "PermitTerminate.cedar").unlink()
    authz.reset_cache()
    assert authz.authorize("cleanDisk", "Instance", "i-1", "dev").allowed is True
    assert authz.floor_report()["holds"] is True


def test_every_invariant_can_be_broken_by_some_policy(scratch):
    """The invariants are not tautologies: for each, a policy set exists that would permit its
    request, and the floor catches exactly that one."""
    files, _ = authz._policy_files()
    import json

    schema = json.loads(files["schema"])
    for name, _why, action, rtype, _rid, env, ctx in floor.INVARIANTS:
        text = (f'@id("Open")\npermit (principal, action == Leash::Action::"{action}", resource) '
                f'when {{ resource.env == "{env}" }};')
        rows = floor.check(text, schema, authz.evaluate_text)
        assert name in [r["name"] for r in floor.broken(rows)], name
