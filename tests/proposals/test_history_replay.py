"""A proposal is replayed against the real audit history: the card says how many past decisions
the rule would have flipped, and which."""

from common import audit, authz, proposals


def _row(pk, action, rtype, rid, env, allowed, ids, result=""):
    d = authz.Decision(allowed=allowed, policy_ids=ids, reason="")
    return audit.write_audit(incident_id=pk, action=action, resource_type=rtype, resource_id=rid,
                             resource_env=env, decision=d, result=result, alarm_name="leash-disk-dev" if allowed else "")


def test_a_rule_that_forbids_cleanup_would_have_left_the_disks_full(store):
    _row("alarm-20260919T031200Z", "cleanDisk", "Instance", "i-0667", "dev", True, ["PermitDevRemediation"], "ssm Success")
    _row("alarm-20260919T041200Z", "cleanDisk", "Instance", "i-0667", "dev", True, ["PermitDevRemediation"], "ssm Success")
    _row("chat-20260919T051200Z", "terminateInstance", "Instance", "i-0667", "dev", False, ["ForbidDestructive"])
    _row("chat-20260919T061200Z", "scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", False, ["ForbidScaleAboveCap"],
         "skipped (denied) desired=10")
    _row("chat-20260919T071200Z", "scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", True, ["PermitDevRemediation"],
         "set desired capacity")  # no capacity recorded: must be skipped, never guessed

    row = proposals.propose("the bot may never clean anything")
    assert row["name"] == "ForbidCleanDisk" and row["valid"] == "true"
    assert row["history_rows"] == "4" and row["history_skipped"] == "1"
    assert row["history_flipped"] == "2"
    assert all("cleanDisk on i-0667 (env=dev): ALLOW -> DENY" in f for f in row["history_flips"])
    assert {f.split(" · ")[0] for f in row["history_flips"]} == {"alarm-20260919T031200Z", "alarm-20260919T041200Z"}


def test_a_redundant_rule_flips_nothing(store):
    _row("chat-20260919T051200Z", "terminateInstance", "Instance", "i-0667", "dev", False, ["ForbidDestructive"])
    row = proposals.propose("never touch prod")
    assert row["history_rows"] == "1" and row["history_flipped"] == "0" and row["history_flips"] == []


def test_lowering_the_cap_flips_only_the_scale_decisions_it_would_have_caught(store):
    _row("chat-20260919T061200Z", "scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", False, ["ForbidScaleAboveCap"],
         "skipped (denied) desired=10")
    _row("chat-20260919T081200Z", "scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", False, [],
         "skipped (denied) desired=3")  # denied for another reason in history; would still be DENY at cap 2
    row = proposals.propose("the bot may never scale above 2")
    assert row["history_rows"] == "2"
    # desired=10 was DENY and stays DENY; desired=3 was recorded as DENY but under the current
    # policies is ALLOW (before) and under cap 2 is DENY (after): one flip, on the replayed decision
    assert row["history_flipped"] == "1" and "desired" not in row["history_flips"][0]
    assert row["history_flips"][0].startswith("chat-20260919T081200Z")
