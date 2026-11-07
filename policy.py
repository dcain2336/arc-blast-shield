"""ARC Blast Shield — approval policy.

Every agent action is gated by this policy BEFORE it executes. Decisions:
  ALLOW — safe by construction (read the uploaded CSV, write charts/summary
          inside the jail, run statically-clean code).
  DENY  — never allowed (any network use, any path outside the jail, package
          installs, process spawning, reading secrets/env).
  ASK   — needs a human tap: executing agent-written code. In interactive
          mode the run pauses until the user approves or denies in the UI;
          in auto mode ASK is treated as ALLOW only if the static scan is
          clean, otherwise DENY.

The policy is the gate; sandbox.py's audit hook is the wall behind it. A
bug or bypass in the policy cannot escape the jail — the hook still denies
the action at runtime. Every decision is written to the ledger so the demo
can show the full allow/deny trail.
"""

from __future__ import annotations

import re
import time

# Static scan: token patterns that must never appear in agent-written code.
# This is a gate, not the wall — the audit hook enforces the same rules at
# runtime even if a pattern slips past the scan.
BLOCKED_PATTERNS = [
    (r"\bimport\s+socket\b", "imports socket (network)"),
    (r"\bfrom\s+socket\b", "imports socket (network)"),
    (r"\bimport\s+subprocess\b", "imports subprocess (process spawn)"),
    (r"\bfrom\s+subprocess\b", "imports subprocess (process spawn)"),
    (r"\bimport\s+ctypes\b", "imports ctypes (escape hatch)"),
    (r"\bimport\s+requests\b", "imports requests (network)"),
    (r"\bimport\s+urllib\b", "imports urllib (network)"),
    (r"\bfrom\s+urllib\b", "imports urllib (network)"),
    (r"\bos\.system\s*\(", "os.system (process spawn)"),
    (r"\bos\.popen\s*\(", "os.popen (process spawn)"),
    (r"\bos\.exec\w*\s*\(", "os.exec* (process spawn)"),
    (r"\bos\.spawn\w*\s*\(", "os.spawn* (process spawn)"),
    (r"\bsubprocess\.", "subprocess use (process spawn)"),
    (r"\bsocket\.", "socket use (network)"),
    (r"\beval\s*\(", "eval (code injection)"),
    (r"\bexec\s*\(", "exec (code injection)"),
    (r"__import__\s*\(", "__import__ (import bypass)"),
    (r"\bcompile\s*\(", "compile (code injection)"),
    (r"\bglobals\s*\(\s*\)", "globals() (introspection escape)"),
    (r"\binput\s*\(", "input() (interactive read — no stdin in jail)"),
    (r"open\s*\(\s*['\"]/(?!tmp)", "open() of an absolute path outside the jail"),
    (r"/etc/passwd", "reads /etc/passwd"),
    (r"/etc/shadow", "reads /etc/shadow"),
    (r"environ", "reads process environment (secret hygiene)"),
    (r"VULTR_API_KEY|API_KEY|SECRET|TOKEN", "references credentials"),
    (r"\bpip\s+install\b", "package install"),
    (r"\bapt(-get)?\b", "package install"),
]

ALLOW_ACTIONS = {"read_csv", "inspect_schema", "write_code", "write_chart",
                 "write_summary", "read_jail_file"}
DENY_ACTIONS = {"network", "read_outside_jail", "write_outside_jail",
                "install_package", "spawn_process", "read_secrets",
                "read_env", "exfiltrate"}
ASK_ACTIONS = {"run_code"}


class Ledger:
    """Append-only record of every policy decision."""

    def __init__(self):
        self.entries = []

    def record(self, action, decision, reason, detail=""):
        entry = {
            "ts": time.strftime("%H:%M:%S"),
            "action": action,
            "decision": decision,
            "reason": reason,
            "detail": detail,
        }
        self.entries.append(entry)
        return entry

    def as_list(self):
        return list(self.entries)


def static_scan(code):
    """Return a list of (pattern, reason) hits in agent-written code."""
    hits = []
    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, code):
            hits.append((pattern, reason))
    return hits


class ApprovalPolicy:
    """Gate for agent actions. mode: 'interactive' (ASK pauses for a human
    tap) or 'auto' (ASK is allowed only when the static scan is clean)."""

    def __init__(self, mode="interactive", ledger=None):
        if mode not in ("interactive", "auto"):
            raise ValueError("mode must be 'interactive' or 'auto'")
        self.mode = mode
        self.ledger = ledger or Ledger()

    def check(self, action, detail=""):
        """Decide ALLOW / DENY / ASK for an action. ASK is returned as-is;
        the caller (agent/server) is responsible for pausing for approval."""
        if action in DENY_ACTIONS:
            return self.ledger.record(action, "DENY",
                                      "action is never allowed", detail)
        if action in ALLOW_ACTIONS:
            return self.ledger.record(action, "ALLOW",
                                      "safe by construction", detail)
        if action in ASK_ACTIONS:
            return self.ledger.record(action, "ASK",
                                      "human approval required before execution",
                                      detail)
        return self.ledger.record(action, "DENY", "unknown action", detail)

    def scan_and_check_code(self, code):
        """Static-scan code, then decide on running it.

        Returns (decision_entry, hits). A clean scan returns ASK (human tap
        in interactive mode; auto-allowed by the caller in auto mode). Any
        hit returns DENY.
        """
        hits = static_scan(code)
        if hits:
            reasons = "; ".join(reason for _, reason in hits)
            entry = self.ledger.record(
                "run_code", "DENY",
                "static scan refused the code: " + reasons)
            return entry, hits
        return self.ledger.record(
            "run_code", "ASK",
            "static scan clean — awaiting approval to execute"), []
