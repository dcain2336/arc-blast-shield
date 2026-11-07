"""ARC Blast Shield — web server (Python stdlib only, no dependencies).

Serves the single-page UI and the JSON API:

  GET  /                        -> UI
  GET  /static/<file>           -> UI assets
  GET  /api/health              -> {llm_mode, model, sandbox, policy}
  POST /api/upload              -> multipart CSV upload; returns run id + schema preview
  POST /api/run                 -> {run_id, task, policy_mode} starts analysis on a worker thread
  GET  /api/run/<id>            -> run status, events, results, ledger
  POST /api/approve             -> {run_id, approved} answers a pending approval
  GET  /api/artifact/<run>/<name> -> chart PNG from a finished run
  GET  /api/containment         -> runs the containment probe standalone

Run with:  ./run.sh   (uses the venv python; serves on :8080)
Env: VULTR_API_KEY (Vultr Serverless Inference key; when absent the
deterministic local-fallback analyst runs instead — the UI labels it),
VULTR_MODEL (default kimi-k2-instruct), PORT (default 8080).
"""

from __future__ import annotations

import cgi
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from agent import Run, new_run_id, run_analysis
from llm import get_analyst
from sandbox import Sandbox

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
RUNS_ROOT = os.path.join(BASE_DIR, "runs")
os.makedirs(RUNS_ROOT, exist_ok=True)

RUNS = {}          # run_id -> Run
RUNS_LOCK = threading.Lock()
CSV_STORE = {}     # run_id -> (filename, csv_bytes)


def _sandbox_ready():
    """Verify the jail boots: run a trivial snippet through it."""
    try:
        sb = Sandbox(python_exe=os.environ.get("BLASTSHIELD_PY", __import__("sys").executable),
                     runs_root=RUNS_ROOT)
        res = sb.run("print('sandbox-ok')")
        Sandbox.cleanup(res.jail_dir)
        return res.ok and "sandbox-ok" in res.stdout
    except Exception:
        return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- helpers ---------------------------------------------------------
    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype):
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode() or "{}")

    def log_message(self, fmt, *args):  # keep stdout clean
        pass

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path == "/":
            return self._send_file(os.path.join(STATIC_DIR, "index.html"), "text/html")
        if path.startswith("/static/"):
            name = path[len("/static/"):]
            full = os.path.join(STATIC_DIR, name)
            if not os.path.isfile(full) or ".." in name:
                return self.send_error(404)
            ctype = {"html": "text/html", "js": "text/javascript",
                     "css": "text/css"}.get(name.rsplit(".", 1)[-1], "application/octet-stream")
            return self._send_file(full, ctype)
        if path == "/api/health":
            _, mode = get_analyst()
            analyst, _ = get_analyst()
            return self._send_json({
                "llm_mode": mode,
                "model": getattr(analyst, "model", "local-fallback"),
                "sandbox": _sandbox_ready(),
                "vultr_base_url": "https://api.vultrinference.com/v1",
            })
        if path.startswith("/api/run/"):
            run_id = path[len("/api/run/"):]
            with RUNS_LOCK:
                run = RUNS.get(run_id)
            if not run:
                return self._send_json({"error": "unknown run"}, 404)
            return self._send_json(run.to_dict())
        if path.startswith("/api/artifact/"):
            parts = path[len("/api/artifact/"):].split("/", 1)
            if len(parts) != 2:
                return self.send_error(404)
            run_id, name = parts
            with RUNS_LOCK:
                run = RUNS.get(run_id)
            if not run or not hasattr(run, "_artifacts"):
                return self.send_error(404)
            data = run._artifacts.get(name)
            if data is None:
                return self.send_error(404)
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        if path == "/api/containment":
            from agent import CONTAINMENT_PROBE_CODE
            sb = Sandbox(python_exe=os.environ.get("BLASTSHIELD_PY", __import__("sys").executable),
                         runs_root=RUNS_ROOT)
            res = sb.run(CONTAINMENT_PROBE_CODE)
            out = {"stdout": res.stdout, "denials": res.denials,
                   "all_blocked": "ALLOWED" not in res.stdout}
            Sandbox.cleanup(res.jail_dir)
            return self._send_json(out)
        return self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path == "/api/upload":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                    environ={"REQUEST_METHOD": "POST",
                                             "CONTENT_TYPE": self.headers.get("Content-Type", "")})
            if "file" not in form:
                return self._send_json({"error": "no file field"}, 400)
            item = form["file"]
            data = item.file.read()
            filename = item.filename or "data.csv"
            if len(data) > 5 * 1024 * 1024:
                return self._send_json({"error": "file too large (5 MB max)"}, 400)
            run_id = new_run_id()
            CSV_STORE[run_id] = (filename, data)
            return self._send_json({"run_id": run_id, "filename": filename,
                                    "bytes": len(data)})
        if path == "/api/run":
            body = self._read_json()
            run_id = body.get("run_id")
            task = (body.get("task") or "Summarize this dataset and chart the key patterns.").strip()
            mode = body.get("policy_mode", "interactive")
            if run_id not in CSV_STORE:
                return self._send_json({"error": "unknown run_id — upload a CSV first"}, 400)
            filename, csv_bytes = CSV_STORE[run_id]
            run = Run(run_id, task, filename, policy_mode=mode)
            with RUNS_LOCK:
                RUNS[run_id] = run
            py = os.environ.get("BLASTSHIELD_PY", __import__("sys").executable)
            threading.Thread(target=run_analysis,
                             args=(run, csv_bytes, py, RUNS_ROOT),
                             kwargs={"on_approval": None}, daemon=True).start()
            return self._send_json({"started": True, "run_id": run_id})
        if path == "/api/approve":
            body = self._read_json()
            run_id = body.get("run_id")
            approved = bool(body.get("approved"))
            with RUNS_LOCK:
                run = RUNS.get(run_id)
            if not run:
                return self._send_json({"error": "unknown run"}, 404)
            if run.status != "awaiting_approval":
                return self._send_json({"error": "run is not awaiting approval"}, 400)
            run.answer_approval(approved)
            return self._send_json({"answered": True, "approved": approved})
        return self.send_error(404)


def main():
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("ARC Blast Shield listening on http://127.0.0.1:%d" % port)
    print("LLM mode: %s" % get_analyst()[1])
    server.serve_forever()


if __name__ == "__main__":
    main()
