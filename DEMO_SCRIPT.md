# Demo video script — ARC Blast Shield (target: under 3 minutes)

Record the real app running (locally or on the Vultr instance — same UI).
No narration over slides; show the screen, talk through it.

## Shots

**0:00–0:20 — The idea.** "ARC Blast Shield is a data-analysis agent that
does real work inside a jail. It plans, writes code, runs it — and every
single action passes an approval policy first." Show the UI: upload the
sample CSV, type the task, leave policy on Interactive.

**0:20–0:50 — The run.** Click Run. The log shows: schema inspection
(192 rows, 6 columns), the plan, then the run PAUSES — "Waiting for human
approval: run_code". Show the approval card with the generated pandas code.
"This is the gate: no agent-written code executes until a human says so."
Click Approve.

**0:50–1:20 — The result.** The run completes: three charts render
(group-by bar, histogram, monthly trend), key numbers, and the plain-English
summary. Point at the approval ledger: `read_csv ALLOW`, `run_code ASK →
ALLOW`, `write_chart ALLOW`.

**1:20–2:10 — THE CONTAINMENT MOMENT (required).** Scroll to the containment
probe section. Read the denials out loud as they appear:
- `BLOCKED: read /etc/passwd (access denied — outside jail)`
- `BLOCKED: open network socket (import of socket denied)`
- `BLOCKED: spawn a process`, `BLOCKED: import requests`, `BLOCKED: import ctypes`
"The agent was challenged to do unsafe things. The sandbox absorbed all
eight. The agent noted the refusals — and the task continued safely."
If recording the probe standalone, use the UI's containment section after a
run, or `GET /api/containment`.

**2:10–2:40 — Self-heal (optional, if time).** Show a run where the first
code attempt fails and the agent repairs it from the traceback and passes
on attempt 2 (`tests/test_self_heal.py` demonstrates this deterministically).

**2:40–3:00 — Close.** "Every LLM call goes through Vultr Serverless
Inference. The sandbox never sees an API key. Blast radius: zero."
Show the repo + the Vultr deployment URL.

## Recording notes

- Capture the browser window only; the terminal is not the product.
- Keep the approval pause in the video — it IS the product (human-in-the-loop).
- Make sure the containment lines are legible on screen; zoom if needed.
- Upload the final video as a public link (YouTube unlisted or Loom) and
  put it in the lablab submission form with the repo link.
