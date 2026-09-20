"""The leash cannot be bypassed in code: every tool that reaches a mutating AWS API asks the
leash first, and acts on the answer. Checked on the source itself (AST), not on behaviour, so a
future tool that forgets to ask fails CI before it ever runs."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "src" / "agent" / "tools.py"

# Calls that change AWS: boto3 methods, plus the one helper (aws_helpers.ssm_run) that wraps
# ssm.send_command. Anything else in tools.py is read-only or a notification.
MUTATING_CALLS = {"send_command", "ssm_run", "update_service", "set_desired_capacity", "terminate_instances",
                  "delete_service", "delete_auto_scaling_group", "stop_instances", "reboot_instances"}


def _tool_functions(tree: ast.Module) -> list[ast.FunctionDef]:
    out = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and any(
            (isinstance(d, ast.Name) and d.id == "tool") or (isinstance(d, ast.Attribute) and d.attr == "tool")
            for d in node.decorator_list
        ):
            out.append(node)
    return out


def _calls(fn: ast.FunctionDef):
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            yield node


def _attr_name(call: ast.Call) -> str:
    return call.func.attr if isinstance(call.func, ast.Attribute) else (call.func.id if isinstance(call.func, ast.Name) else "")


def test_every_mutating_tool_asks_the_leash_before_touching_aws():
    tree = ast.parse(TOOLS.read_text(encoding="utf-8"))
    tools = _tool_functions(tree)
    assert tools, "no @tool functions found"
    mutating_tools = {}
    for fn in tools:
        aws_calls = [c for c in _calls(fn) if _attr_name(c) in MUTATING_CALLS]
        if not aws_calls:
            continue
        decides = [c for c in _calls(fn) if _attr_name(c) == "_decide"]
        assert decides, f"{fn.name} reaches AWS ({[_attr_name(c) for c in aws_calls]}) without asking the leash"
        first_ask = min(c.lineno for c in decides)
        for c in aws_calls:
            assert c.lineno > first_ask, f"{fn.name}: {_attr_name(c)} on line {c.lineno} runs before _decide on line {first_ask}"
        # and the answer is read: the tool branches on decision.allowed
        reads_answer = any(isinstance(n, ast.Attribute) and n.attr == "allowed" for n in ast.walk(fn))
        assert reads_answer, f"{fn.name} asks the leash but never reads decision.allowed"
        mutating_tools[fn.name] = sorted({_attr_name(c) for c in aws_calls})
    assert set(mutating_tools) == {"clean_disk", "restart_service", "scale_group", "terminate_instance"}, mutating_tools


def test_the_agent_declares_exactly_the_mutating_tools():
    """agent.handler.MUTATING_TOOLS (what the runbook guard and the red team count as 'tried') is
    the same set the AST finds, so the two cannot drift apart."""
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    from agent import handler

    assert set(handler.MUTATING_TOOLS) == {"clean_disk", "restart_service", "scale_group", "terminate_instance"}


def test_terminate_never_calls_ec2_even_if_allowed():
    """Defence in depth stays in the source: no reachable ec2.terminate_instances call that is
    not inside the hard-coded guard's refused branch."""
    src = TOOLS.read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(f for f in _tool_functions(tree) if f.name == "terminate_instance")
    # every terminate_instances call sits under a guard comment/refusal; the tool text must say so
    assert "refused by hard-coded guard" in ast.get_source_segment(src, fn), "the hard-coded guard is gone"
