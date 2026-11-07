"""Self-heal test: broken code must be repaired and re-run to success.

Feeds the orchestrator a first-attempt code path that fails (simulated by
patching the analyst to emit bad code once), then verifies the repair loop
produces a passing run. Also unit-checks the LocalAnalyst repair rules.
Run:  .venv/bin/python tests/test_self_heal.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agent as agent_mod  # noqa: E402
from agent import Run, run_analysis  # noqa: E402
from llm import LocalAnalyst  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(BASE, ".venv", "bin", "python")
RUNS = os.path.join(BASE, "runs")


def test_repair_rules():
    a = LocalAnalyst()
    code_with_groupby = "df.groupby('region')['units'].sum()\n"
    assert a.repair("x", "ParserError: Error tokenizing data") is not None
    assert a.repair(code_with_groupby, "KeyError: 'nope'") is not None
    assert a.repair(code_with_groupby, "KeyError: 'nope'") != code_with_groupby
    assert a.repair("x", "Something totally unknown") is None
    print("repair rules OK")


def test_heal_loop():
    # Analyst that emits code with a deliberate bug on the first call, then
    # repairs by regenerating correct code — the same shape as the Vultr
    # path, which re-prompts the model with the traceback. This tests the
    # loop mechanics (fail -> repair -> rerun -> success); the deterministic
    # repair rules are unit-tested separately above.
    real = LocalAnalyst()
    calls = {"n": 0}
    orig_code = real.code
    schema = {"rows": 192, "columns": [
        {"name": "date", "dtype": "date"},
        {"name": "region", "dtype": "string"},
        {"name": "product", "dtype": "string"},
        {"name": "channel", "dtype": "string"},
        {"name": "units", "dtype": "number"},
        {"name": "revenue", "dtype": "number"},
    ]}
    good_code = orig_code(schema, "Summarize this dataset.")

    def buggy_code(s, task):
        calls["n"] += 1
        if calls["n"] == 1:
            # Deliberate bug: reference a column that does not exist.
            return good_code.replace("df['units']", "df['unitz']", 1)
        return good_code

    real.code = buggy_code
    real.repair = lambda code, tb: good_code
    agent_mod.get_analyst = lambda: (real, "local-fallback")

    with open(os.path.join(BASE, "sample_data.csv"), "rb") as f:
        csv_bytes = f.read()
    run = Run("test-heal", "Summarize this dataset.", "sample_data.csv",
              policy_mode="auto")
    try:
        run_analysis(run, csv_bytes, PY, RUNS, on_approval=lambda a, d: True)
    finally:
        agent_mod.get_analyst = __import__("llm").get_analyst

    assert run.status == "done", "status=%s" % run.status
    attempts = run.results["attempts"]
    assert len(attempts) == 2, attempts
    assert not attempts[0]["ok"] and attempts[1]["ok"], attempts
    print("heal loop OK: attempt 1 failed (%s), attempt 2 repaired and passed" % (
        attempts[0]["stderr"].strip().splitlines()[-1][:80]))


if __name__ == "__main__":
    test_repair_rules()
    test_heal_loop()
    print("SELF-HEAL OK")
