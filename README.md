# ARC Blast Shield — Vultr Agent Rush 2026

**Challenge:** "Blast Radius Zero: Safe Agent Execution on Vultr"
**Entry:** web-based agent, Pattern A (CSV Analyst). Upload a CSV → the agent
inspects the schema → writes pandas code → runs it in a jailed sandbox →
self-heals on errors → renders charts + a plain-English summary. Every tool
call is gated by an approval policy, and the sandbox absorbs anything unsafe.
**Deadline:** Nov 8, 2026, 5:00 PM EST (staged files; a Nov 3 note said 6:00 PM —
aim for 5:00).

## Run it locally

```sh
./run.sh            # venv python, serves http://127.0.0.1:8080
```

Requires the bundled `.venv` (pandas + matplotlib). To rebuild it:

```sh
python3 -m venv .venv
.venv/bin/pip install --no-cache-dir -r requirements.txt
```

## How it works

```
Browser UI ──> server.py (stdlib http.server, JSON API)
                  │
                  ├─> agent.py — orchestrator: schema → plan → code → gate → run → heal → summary
                  ├─> policy.py — approval gate (ALLOW / DENY / ASK) + append-only ledger
                  ├─> llm.py — Vultr Serverless Inference client (OpenAI-compatible)
                  │            + deterministic local-fallback analyst (no key configured)
                  └─> sandbox.py — the jail: throwaway dir + audit-hook child process
```

**The gate (policy.py).** Every action is decided before it executes:
`read_csv`/`write_chart`/`write_summary` → ALLOW; `network`,
`read/write_outside_jail`, `install_package`, `spawn_process`,
`read_secrets` → DENY; `run_code` → ASK. In interactive mode the run
pauses until a human approves the code in the UI (Approve/Deny buttons);
in auto mode ASK is allowed only when the static scan of the code is clean.
Every decision lands in the ledger, shown in the UI.

**The wall (sandbox.py).** Agent code runs in a child Python process with:
- `sys.addaudithook` denying opens outside the jail (except read-only
  stdlib/library roots, `/dev/null`, `/proc`, `/sys/fs/cgroup`), all socket
  use, subprocess/exec/spawn, and imports of networking/subprocess/ctypes
  modules **when the importing code is the agent itself** — library code
  importing the same modules lazily (pandas' plot backend, Pillow's PNG
  saver, numpy's ctypes use) is allowed, judged by which file is doing the
  importing. `ctypes` library loads/calls from agent code are denied too,
  including `ctypes` reached through `numpy.ctypeslib`.
- Resource limits (30 s CPU, 1 GiB memory, 10 MB files, 64 fds), wall-clock
  timeout, scrubbed environment — **no API key or credential is ever passed
  into the sandbox** (secret hygiene).
- The policy is the gate; the hook is the wall. A bug or bypass in the
  policy cannot escape the jail.

**The analyst (llm.py).** All LLM calls go through Vultr Serverless
Inference, base URL `https://api.vultrinference.com/v1`, model
`kimi-k2-instruct` by default (the model Vultr documents for tool calling).
Key from `VULTR_API_KEY` env, model from `VULTR_MODEL`. When no key is
configured, a deterministic local-fallback analyst generates the plan/code/
repair/summary from templates so the pipeline is verifiable end-to-end
offline — the UI and logs always label which analyst ran.

**Self-heal.** A failed run's traceback goes back to the analyst for a
repair (up to 3 attempts); each attempt is re-scanned and re-gated.

**Containment probe.** A separate jailed run deliberately attempts unsafe
actions (read `/etc/passwd` and `/etc/shadow`, open a socket, DNS lookup,
spawn a process, `os.system`, import requests/urllib/ctypes, reach ctypes
through numpy, reach a socket through a library attribute, write outside
the jail). Every one must be denied; the denials are the demo's containment
moment, and the agent notes the refusals and continues.

## Verified (Nov 6–7, 2026, local-fallback analyst)

| Test | Result |
|---|---|
| `tests/test_containment.py` | 12/12 attacks denied; legit pandas in jail OK; no key in sandbox env |
| `tests/test_self_heal.py` | attempt 1 KeyError → repaired → attempt 2 passed; repair rules OK |
| `tests/test_end_to_end.py` | 192-row CSV → schema, plan, 3 charts, stats, summary, containment 8/8 blocked |
| Server smoke test | health OK; upload OK; interactive run pauses at `awaiting_approval`; Approve → done with 3 real PNG charts; Deny → run `denied`; ledger shows ASK → ALLOW |

## Deploy on Vultr (for the real run)

1. **API key (Scott's step):** sign in at my.vultr.com with email/password +
   the trusted-device code emailed to ARC Gmail (Google SSO does not work;
   the saved vault login is stale — do not guess it). Then Serverless
   Inference → API Keys → create a key. Set `VULTR_API_KEY` on the instance.
   No card is linked and none is needed — the $200 participant credit covers it.
2. **Instance:** any Vultr cloud compute instance (2 GB RAM is plenty),
   Docker installed. `docker build -t blast-shield . && docker run -p 8080:8080
   -e VULTR_API_KEY=... blast-shield`. Or copy the repo and run `./run.sh`
   after installing `requirements.txt`.
3. **Verify on the instance:** `curl localhost:8080/api/health` must show
   `"llm_mode": "vultr"` and `"sandbox": true`, then run the test suite
   (`.venv/bin/python tests/test_end_to_end.py`).

## Files

- `server.py`, `agent.py`, `llm.py`, `policy.py`, `sandbox.py` — the app
- `static/` — single-page UI (upload, task, policy toggle, approval card,
  live log, charts, summary, containment log, ledger)
- `tests/` — containment, self-heal, end-to-end suites (see table above)
- `sample_data.csv` — 192-row monthly sales demo dataset
- `mpl-font-cache/` — prebuilt matplotlib font list, copied (hardlinked)
  into each jail so font setup never shells out to `fc-list`
- `Dockerfile`, `requirements.txt`, `run.sh`, `.gitignore`
- `../concept.md`, `../SUBMIT.md` — the staged entry concept and submit steps

## Submission checklist (before Nov 8, 5:00 PM EST)

- [x] Public GitHub repo: **https://github.com/dcain2336/arc-blast-shield**
      (created + pushed Nov 7, 2026 ~02:00 UTC; 2 commits; MIT license)
- [x] Demo video recorded: `demo-video/page@54b80b78fea5b1a34b988361004ecf1b.webm`
      (25 s, 1280x800, real app in a real browser via Playwright — upload,
      approval gate, charts, containment probe with all 8 BLOCKED lines).
      **Caveat:** recorded against the local-fallback analyst (no Vultr key
      yet) — the UI honestly shows "LLM: local-fallback". Re-record with
      `record_demo.py` once the Vultr key is live so the video shows Vultr
      mode; the script's pacing was already slowed for readability.
- [ ] Deploy on Vultr with `VULTR_API_KEY` set; confirm `llm_mode: vultr`
      — **BLOCKED on Scott's sign-in** (see step 1 above)
- [ ] Record the demo video per `DEMO_SCRIPT.md` — MUST include the
      containment moment (probe denials on screen, agent continuing safely)
- [ ] Upload demo to YouTube (ARC channel, unlisted) for the public link
- [ ] Submit repo + demo link on lablab.ai before the deadline
- [ ] If it wins: identity verification + tax forms are Scott's step

## Known limits

- Local verification used the local-fallback analyst (no Vultr key on file).
  The Vultr code path (`VultrClient.chat`) is written against the documented
  OpenAI-compatible endpoint but has not yet run against the live API — that
  needs the API key from step 1 above, then one live end-to-end run.
- The jail is process-level containment (audit hooks + rlimits), not a VM
  or gVisor — appropriate for the hackathon's threat model, and stated as
  such in the submission.
- No EOD content anywhere in the entry.
