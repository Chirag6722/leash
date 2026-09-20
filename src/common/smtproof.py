"""The floor, proved for every possible request: a thin wrapper around verify/ (leash-prove).

floor.py samples ten concrete requests with the Cedar evaluator. This module asks a stronger
question through Cedar's symbolic compiler (cedar-policy-symcc) and the cvc5 SMT solver: over
EVERY request the schema admits, is every request the enforced policies allow also allowed by
cedar/floor.cedar? The answer is exact. If not, the solver returns the escaping request.

It needs two binaries that a Lambda does not carry, so it is optional: `available()` is False
unless LEASH_PROVE_BIN (or verify/target/release/leash-prove next to this repo) and CVC5 (or a
cvc5 on PATH) exist. The brain host (EC2) has both, so proposals drafted there carry an SMT
verdict, and the worker re-proves the live policy set on a timer.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

SOLVER = "cvc5 1.3.1"
_REPO = Path(__file__).resolve().parents[2]


def _binary() -> str | None:
    cand = os.environ.get("LEASH_PROVE_BIN") or ""
    if cand and Path(cand).exists():
        return cand
    for name in ("leash-prove", "leash-prove.exe"):
        p = _REPO / "verify" / "target" / "release" / name
        if p.exists():
            return str(p)
    return None


def _cvc5() -> str | None:
    cand = os.environ.get("CVC5") or ""
    if cand and Path(cand).exists():
        return cand
    return shutil.which("cvc5")


def available() -> bool:
    return bool(_binary() and _cvc5())


def floor_text() -> str:
    return (_REPO / "cedar" / "floor.cedar").read_text(encoding="utf-8")


def prove_files(files: dict, timeout_s: int = 120) -> dict | None:
    """Prove the policy set in `files` ({name: cedar text, "schema": json text}).

    Returns None when the prover is not available. Otherwise:
      {"holds": bool, "environments": int, "escapes": int, "counterexamples": [str], "ms": int,
       "solver": "cvc5 1.3.1"}  or  {"error": str} when the prover itself failed.
    """
    binary, cvc5 = _binary(), _cvc5()
    if not binary or not cvc5:
        return None
    with tempfile.TemporaryDirectory(prefix="leash-prove-") as tmp:
        d = Path(tmp)
        (d / "policies").mkdir()
        (d / "schema.json").write_text(files["schema"], encoding="utf-8")
        (d / "floor.cedar").write_text(floor_text(), encoding="utf-8")
        for name, text in files.items():
            if name != "schema":
                (d / "policies" / f"{name}.cedar").write_text(text, encoding="utf-8")
        env = {**os.environ, "CVC5": cvc5}
        started = time.perf_counter()
        try:
            proc = subprocess.run([binary, str(d), "--json"], capture_output=True, text=True, timeout=timeout_s, env=env)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
        ms = int((time.perf_counter() - started) * 1000)
        if proc.returncode not in (0, 1) or not proc.stdout.strip():
            return {"error": (proc.stderr or "prover failed").strip()[-600:]}
        try:
            out = json.loads(proc.stdout)
        except ValueError:
            return {"error": "prover printed no JSON: " + proc.stderr.strip()[-300:]}
        cexs = [r.get("counterexample", "") for r in out.get("results", []) if not r.get("holds")]
        return {"holds": bool(out.get("holds")), "environments": int(out.get("environments", 0)),
                "escapes": int(out.get("escapes", 0)), "counterexamples": cexs, "ms": ms, "solver": SOLVER}


def flatten(report: dict | None, prefix: str = "smt_") -> dict:
    """The report as flat string attributes for a DynamoDB row (audit._serialize is strings only)."""
    if not report:
        return {}
    if "error" in report:
        return {prefix + "error": str(report["error"])[:600]}
    return {prefix + "holds": "true" if report["holds"] else "false",
            prefix + "environments": str(report["environments"]),
            prefix + "escapes": str(report["escapes"]),
            prefix + "counterexample": (report["counterexamples"] or [""])[0][:600],
            prefix + "ms": str(report["ms"]), prefix + "solver": report["solver"]}
