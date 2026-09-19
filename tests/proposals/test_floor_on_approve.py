"""A proposal that would break the floor is proved as such and can never be approved."""

import pytest

from common import authz, proposals

PERMIT_ALL = "permit (principal, action, resource);"


def test_a_model_draft_that_replaces_a_forbid_is_marked_and_refused(store):
    # "never touch prod" names the draft ForbidProd; a model that answers with a permit-all
    # therefore proposes to *replace* ForbidProd, and prod would open up.
    row = proposals.propose("never touch prod", drafter=lambda prompt: PERMIT_ALL)
    assert row["valid"] == "true" and row["source"] == "model" and row["replaces"] == "true"
    assert "NeverCleanProd: cleanDisk on Instance i-prod (env=prod) would become ALLOW" in row["breaks"]
    assert {b.split(":")[0] for b in row["breaks"]} == {"NeverCleanProd", "NeverRestartProd", "NeverScaleProd", "NeverTouchUntagged"}
    assert "clean the prod disk: DENY -> ALLOW" in row["changed"]  # the ordinary proof agrees

    with pytest.raises(ValueError, match="break the floor"):
        proposals.approve(row["pk"])
    assert authz.authorize("cleanDisk", "Instance", "i-1", "prod").allowed is False  # nothing was published
    assert (store / "policies" / "ForbidProd.cedar").read_text().strip().endswith('"prod" };')


def test_an_ordinary_rule_carries_an_empty_breaks_list_and_still_publishes(store):
    row = proposals.propose("the bot may never scale above 2")
    assert row["breaks"] == []
    out = proposals.approve(row["pk"])
    assert out["name"] == "ForbidScaleAboveCap"
    assert authz.authorize("scaleGroup", "AutoScalingGroup", "g", "dev", {"desiredCapacity": 3}).allowed is False


def test_the_floor_is_reproved_at_approval_not_trusted_from_the_card(store, monkeypatch):
    """Even if a stored card said 'breaks: []', approve proves again against the set in force."""
    row = proposals.propose("never touch prod", drafter=lambda prompt: PERMIT_ALL)
    monkeypatch.setattr(proposals, "list_proposals", lambda limit=20: [{**row, "breaks": []}])
    with pytest.raises(ValueError, match="break the floor"):
        proposals.approve(row["pk"])
