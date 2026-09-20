"""verify/ through common.smtproof: silent when absent, exact when present."""

import os
import shutil
from pathlib import Path

import pytest

from common import authz, smtproof

ROOT = Path(__file__).resolve().parents[2]


def test_unavailable_without_binaries(monkeypatch, tmp_path):
    monkeypatch.setenv("LEASH_PROVE_BIN", str(tmp_path / "nope"))
    monkeypatch.setenv("CVC5", str(tmp_path / "nope-cvc5"))
    monkeypatch.setattr(smtproof, "_REPO", tmp_path)  # no verify/target here either
    assert smtproof.available() is False
    assert smtproof.prove_files({"schema": "{}"}) is None
    assert smtproof.flatten(None) == {}


def test_flatten_shapes_a_report_for_dynamodb():
    ok = {"holds": True, "environments": 7, "escapes": 0, "counterexamples": [], "ms": 812, "solver": "cvc5 1.3.1"}
    assert smtproof.flatten(ok) == {"smt_holds": "true", "smt_environments": "7", "smt_escapes": "0",
                                    "smt_counterexample": "", "smt_ms": "812", "smt_solver": "cvc5 1.3.1"}
    bad = {**ok, "holds": False, "escapes": 1, "counterexamples": ["scaleGroup desiredCapacity: 17"]}
    assert smtproof.flatten(bad, prefix="")["counterexample"] == "scaleGroup desiredCapacity: 17"
    assert smtproof.flatten({"error": "boom"}) == {"smt_error": "boom"}


@pytest.mark.skipif(not smtproof.available(), reason="needs verify/target/release/leash-prove and cvc5")
def test_the_real_prover_holds_for_the_shipped_set_and_catches_a_loosened_cap(monkeypatch):
    monkeypatch.setenv("LEASH_LOCAL_AUTHZ", "1")
    monkeypatch.delenv("LEASH_CEDAR_S3_BUCKET", raising=False)
    monkeypatch.delenv("LEASH_CEDAR_DIR", raising=False)
    authz.reset_cache()
    files, _ = authz._policy_files()
    r = smtproof.prove_files(files)
    assert r["holds"] is True and r["environments"] == 7 and r["escapes"] == 0
    loose = dict(files)
    loose["ForbidScaleAboveCap"] = files["ForbidScaleAboveCap"].replace("> 4", "> 20")
    r2 = smtproof.prove_files(loose)
    assert r2["holds"] is False and r2["escapes"] == 1
    assert "scaleGroup" in r2["counterexamples"][0] and "desiredCapacity" in r2["counterexamples"][0]
