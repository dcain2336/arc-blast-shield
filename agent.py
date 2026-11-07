"""ARC Blast Shield — agent orchestrator.

Pipeline (every code execution happens inside sandbox.py's jail):
  1. inspect_schema — pandas reads the CSV in the jail, reports columns.
  2. plan — LLM (Vultr) or LocalAnalyst plans the analysis.
  3. generate code — LLM or LocalAnalyst writes pandas code.
  4. policy gate — static scan + approval policy; in interactive mode the
     run PAUSES here until a human approves the code execution in the UI.
  5. run in the jail; on failure, feed the traceback back for a repair
     (self-heal, up to 3 attempts), re-gating each attempt.
  6. collect artifacts (stats.json, chart PNGs) and summarize in plain English.
  7. containment probe — a separate jailed run that deliberately attempts
     unsafe actions (read /etc/passwd, open a socket, spawn a process,
     read the environment, write outside the jail). The jail must deny
     every one; the denials are the demo's containment moment.

The orchestrator never touches the network and never sees credentials: the
LLM client holds the Vultr key, the sandbox holds no key at all.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid

from llm import LocalAnalyst, VultrClient, get_analyst
from policy import ApprovalPolicy, Ledger
from sandbox import Sandbox

SCHEMA_CODE = """\
import json
import pandas as pd
df = pd.read_csv('data.csv')
cols = []
for c in df.columns:
    s = df[c]
    kind = 'number' if pd.api.types.is_numeric_dtype(s) else (
        'date' if pd.api.types.is_datetime64_any_dtype(s) else 'string')
    if kind == 'string':
        try:
            pd.to_datetime(s.dropna().head(20))
            kind = 'date'
        except Exception:
            pass
    cols.append({'name': str(c), 'dtype': kind,
                 'nulls': int(s.isna().sum()),
                 'sample': str(s.dropna().iloc[0]) if s.dropna().size else ''})
print(json.dumps({'rows': int(len(df)), 'columns': cols}))
"""

CONTAINMENT_PROBE_CODE = """\
# Deliberate unsafe actions. Every one must be denied by the jail.
# Each attempt is wrapped so the probe reports BLOCKED vs ALLOWED.
import os

def attempt(name, fn):
    try:
        fn()
        print("ALLOWED: %s  <-- CONTAINMENT FAILURE" % name)
    except PermissionError as e:
        print("BLOCKED: %s (%s)" % (name, e))
    except Exception as e:
        print("BLOCKED: %s (%s: %s)" % (name, type(e).__name__, e))

attempt("read /etc/passwd", lambda: open('/etc/passwd').read())
attempt("read /etc/shadow", lambda: open('/etc/shadow').read())
attempt("open network socket", lambda: __import__('socket').create_connection(('8.8.8.8', 53), timeout=3))
attempt("spawn a process", lambda: __import__('subprocess').run(['id'], capture_output=True))
attempt("run a shell command", lambda: os.system('id'))
attempt("read process environment", lambda: os.environ['VULTR_API_KEY'])
attempt("write outside the jail", lambda: open('/tmp/blastshield-evil.txt', 'w').write('pwned'))
attempt("import requests", lambda: __import__('requests'))
print("PROBE DONE — the sandbox absorbed every unsafe action above.")
"""


class Run:
    """One analysis run: state, event log, approval plumbing."""

    def __init__(self, run_id, task, filename, policy_mode="interactive"):
        self.id = run_id
        self.task = task
        self.filename = filename
        self.policy_mode = policy_mode
        self.status = "starting"          # starting|awaiting_approval|running|done|failed|denied
        self.events = []
        self.results = {}
        self.ledger = Ledger()
        self.policy = ApprovalPolicy(mode=policy_mode, ledger=self.ledger)
        self._approval_event = threading.Event()
        self._approval_decision = None
        self._lock = threading.Lock()

    def event(self, kind, text, data=None):
        with self._lock:
            entry = {"ts": time.strftime("%H:%M:%S"), "kind": kind,
                     "text": text, "data": data or {}}
            self.events.append(entry)
        return entry

    def wait_for_approval(self, action, detail, timeout=180):
        """Block until the UI answers an approval request. Returns bool."""
        self.status = "awaiting_approval"
        self.event("approval", "Waiting for human approval: %s" % action,
                   {"action": action, "detail": detail, "pending": True})
        self._approval_event.clear()
        self._approval_decision = None
        ok = self._approval_event.wait(timeout=timeout)
        if not ok:
            self.event("approval", "Approval timed out after %ds — DENIED by default" % timeout)
            return False
        decision = self._approval_decision
        self.event("approval", "Human decision on %s: %s" % (action, decision))
        return decision is True

    def answer_approval(self, approved):
        self._approval_decision = bool(approved)
        self._approval_event.set()

    def to_dict(self):
        return {
            "id": self.id, "task": self.task, "filename": self.filename,
            "status": self.status, "events": list(self.events),
            "results": self.results, "ledger": self.ledger.as_list(),
        }


def _extract_json(text):
    """Pull the first {...} JSON object out of model output."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object in model output")
    return json.loads(m.group(0))


def _extract_code(text):
    """Pull code out of a ```python fenced block, or use the raw text."""
    m = re.search(r"```(?:python)?\s*(.*?)```", text, re.S)
    if m:
        return m.group(1).strip() + "\n"
    return text.strip() + "\n"


def run_analysis(run, csv_bytes, python_exe, runs_root, on_approval=None):
    """Execute the full pipeline for a Run. Runs in the caller's thread
    (the server puts it on a worker thread). on_approval(action, detail)
    -> bool is used instead of run.wait_for_approval when supplied
    (tests pass an auto-approver)."""
    sandbox = Sandbox(python_exe=python_exe, runs_root=runs_root)
    analyst, mode = get_analyst()
    run.results["llm_mode"] = mode
    run.results["model"] = getattr(analyst, "model", LocalAnalyst.name)
    run.event("info", "Analyst: %s (model: %s)" % (mode, run.results["model"]))

    def approve(action, detail):
        if on_approval is not None:
            return on_approval(action, detail)
        return run.wait_for_approval(action, detail)

    try:
        # ---- 1. schema inspection (inside the jail) ----
        run.status = "running"
        run.policy.check("read_csv", run.filename)
        run.event("step", "Inspecting schema of %s inside the jail" % run.filename)
        res = sandbox.run(SCHEMA_CODE, input_files={"data.csv": csv_bytes})
        if not res.ok:
            run.event("error", "Schema inspection failed:\n" + res.stderr[-1500:])
            run.status = "failed"
            return run
        schema = _extract_json(res.stdout)
        run.results["schema"] = schema
        run.event("step", "Schema: %d rows, columns %s" % (
            schema["rows"], ", ".join(c["name"] for c in schema["columns"])))

        # ---- 2. plan ----
        if mode == "vultr":
            plan_text = analyst.chat(
                "You are a careful data-analysis planner. Reply with a JSON object "
                "only: {\"steps\": [\"...\", ...]}.",
                "Task: %s\nSchema: %s\nPlan the analysis in 4-6 steps." % (
                    run.task, json.dumps(schema)))
            plan = _extract_json(plan_text)
        else:
            plan = analyst.plan(schema, run.task)
        run.results["plan"] = plan
        run.event("step", "Plan (%d steps): %s" % (
            len(plan.get("steps", [])), "; ".join(plan.get("steps", []))))

        # ---- 3-5. generate code, gate it, run it, self-heal ----
        code = None
        attempts = []
        for attempt_no in range(1, 4):
            if attempt_no == 1:
                if mode == "vultr":
                    code_text = analyst.chat(
                        "You write pandas analysis code that runs in a sandbox. "
                        "Rules: read ONLY 'data.csv' from the working directory; "
                        "write ONLY files in the working directory (charts as PNG, "
                        "stats as stats.json); use only pandas, matplotlib, json, "
                        "numpy. Never use socket, subprocess, os.system, eval, "
                        "exec, open() with absolute paths, or environment variables. "
                        "Reply with a single ```python fenced block and nothing else.",
                        "Task: %s\nSchema: %s\nPlan: %s" % (
                            run.task, json.dumps(schema), json.dumps(plan)))
                    code = _extract_code(code_text)
                else:
                    code = analyst.code(schema, run.task)
            else:
                # self-heal: repair from the previous traceback
                tb = attempts[-1]["stderr"]
                run.event("step", "Self-heal attempt %d: repairing from traceback" % attempt_no)
                if mode == "vultr":
                    fix_text = analyst.chat(
                        "Fix this pandas code so it runs. Reply with a single "
                        "```python fenced block and nothing else.",
                        "Broken code:\n%s\n\nTraceback:\n%s" % (code, tb[-2000:]))
                    code = _extract_code(fix_text)
                else:
                    fixed = analyst.repair(code, tb)
                    if fixed is None:
                        run.event("error", "Local analyst has no repair for this failure; stopping")
                        run.status = "failed"
                        run.results["attempts"] = attempts
                        return run
                    code = fixed

            run.policy.check("write_code", "attempt %d (%d lines)" % (attempt_no, len(code.splitlines())))
            decision, hits = run.policy.scan_and_check_code(code)
            if decision["decision"] == "DENY":
                run.event("deny", "Policy refused the code: " + decision["reason"])
                run.status = "denied"
                return run
            # ASK: human tap in interactive mode; auto-allow in auto mode.
            if run.policy_mode == "interactive":
                run.event("step", "Code ready for review (%d lines) — awaiting approval" % len(code.splitlines()))
                run.results["code_pending"] = code
                if not approve("run_code", "Execute %d lines of agent-written pandas code in the jail" % len(code.splitlines())):
                    run.policy.ledger.record("run_code", "DENY", "human denied execution")
                    run.event("deny", "Human denied code execution")
                    run.status = "denied"
                    return run
                run.policy.ledger.record("run_code", "ALLOW", "human approved execution")
            else:
                run.policy.ledger.record("run_code", "ALLOW",
                                         "auto mode: static scan clean")
            run.results.pop("code_pending", None)

            run.event("step", "Running code in the jail (attempt %d)" % attempt_no)
            res = sandbox.run(code, input_files={"data.csv": csv_bytes})
            attempts.append({"attempt": attempt_no, "ok": res.ok,
                             "stdout": res.stdout, "stderr": res.stderr,
                             "denials": res.denials, "wall": round(res.wall_seconds, 2)})
            for d in res.denials:
                run.event("deny", "Jail denied at runtime: " + d)
            if res.ok:
                run.event("step", "Run succeeded in %.1fs: %s" % (
                    res.wall_seconds, res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""))
                break
            run.event("error", "Attempt %d failed (exit %d):\n%s" % (
                attempt_no, res.exit_code, res.stderr.strip().splitlines()[-1] if res.stderr.strip() else ""))
            if attempt_no == 3:
                run.event("error", "Self-heal exhausted after 3 attempts")
                run.status = "failed"
                run.results["attempts"] = attempts
                return run

        run.results["attempts"] = attempts
        run.results["code"] = code

        # ---- 6. collect artifacts + summarize ----
        artifacts = {}
        stats = {}
        # Re-run listing: the successful run's artifacts live in its jail dir.
        # The SandboxResult already captured them; recover from the last attempt
        # by re-running nothing — instead, artifacts were returned on `res`.
        # (We kept `res` from the successful attempt.)
        for name, data in res.artifacts.items():
            if name.endswith(".png"):
                artifacts[name] = data
            elif name == "stats.json":
                try:
                    stats = json.loads(data.decode())
                except Exception:
                    stats = {}
        run.results["stats"] = stats
        run.results["charts"] = sorted(artifacts.keys())
        run._artifacts = artifacts  # server serves these from memory
        run.policy.check("write_chart", "%d chart(s)" % len(artifacts))
        run.policy.check("write_summary", "plain-English summary")
        if mode == "vultr":
            summary = analyst.chat(
                "Summarize these analysis results in plain English in 3-5 sentences.",
                "Task: %s\nStats: %s" % (run.task, json.dumps(stats, default=str)[:3000]))
        else:
            summary = analyst.summarize(stats, run.task)
        run.results["summary"] = summary
        run.event("step", "Summary ready")

        # ---- 7. containment probe (the demo moment) ----
        run.event("step", "Running containment probe — unsafe actions vs the jail")
        probe = sandbox.run(CONTAINMENT_PROBE_CODE)
        probe_lines = [ln for ln in probe.stdout.splitlines() if ln.startswith(("BLOCKED", "ALLOWED", "PROBE"))]
        run.results["containment"] = {
            "lines": probe_lines,
            "denials": probe.denials,
            "all_blocked": all(ln.startswith("BLOCKED") for ln in probe_lines if ln.startswith(("BLOCKED", "ALLOWED"))),
        }
        run.event("contain", "Containment probe: %d/%d unsafe actions blocked" % (
            sum(1 for ln in probe_lines if ln.startswith("BLOCKED")),
            sum(1 for ln in probe_lines if ln.startswith(("BLOCKED", "ALLOWED")))))
        Sandbox.cleanup(probe.jail_dir)

        run.status = "done"
        run.event("done", "Analysis complete — %d chart(s), summary ready" % len(artifacts))
        return run
    except Exception as e:  # noqa: BLE001 — surface any orchestrator failure
        run.event("error", "Orchestrator error: %s: %s" % (type(e).__name__, e))
        run.status = "failed"
        return run


def new_run_id():
    return uuid.uuid4().hex[:12]
