"""ARC Blast Shield — jailed code runner.

Every line of agent-written code runs ONLY inside this jail. The jail is a
throwaway directory plus a child Python process with:

  * an audit hook that denies any filesystem access outside the jail (and
    outside read-only stdlib/library roots), any network use, any subprocess
    spawn, and imports of networking/subprocess modules from agent code —
    while allowing the same imports when a library triggers them lazily
    (pandas' plot backend, Pillow's PNG saver, numpy's ctypes use), judged
    by which file is doing the importing; ctypes library loads/calls from
    agent code are denied too;
  * resource limits (CPU, memory, file size, open files);
  * a scrubbed environment — no API keys or credentials are ever passed in
    (secret hygiene: the sandbox never sees VULTR_API_KEY or anything else);
  * a wall-clock timeout.

The audit hook is the wall. The approval policy (policy.py) is the gate in
front of it: code is statically scanned and policy-checked before it is ever
handed to the runner, but even if a check is bypassed, the hook still denies
the action at runtime.
"""

from __future__ import annotations

import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# The bootstrap: injected into the child process. It installs the audit hook
# and resource limits, then runs the agent code file given on the command line.
# ---------------------------------------------------------------------------

BOOTSTRAP = r'''
"""Jail bootstrap — runs inside the sandboxed child before agent code.

Installs sys.addaudithook to deny:
  * open() of any path outside the jail dir (except read-only access to the
    interpreter's own library roots and a tiny /dev + /proc allowlist)
  * all socket use (connect / DNS)
  * subprocess / os.system / exec / spawn / pty
  * imports of networking, subprocess, ctypes and similar modules
Denials are appended to denials.log inside the jail and raised as
PermissionError so the agent code (and the parent) can see exactly what
was refused.
"""
import os
import resource
import sys
import traceback

JAIL = os.environ["BLASTSHIELD_JAIL"]
ALLOWED_READ_ROOTS = [
    p for p in (sys.prefix, sys.base_prefix, sys.exec_prefix, "/usr/lib/python3.12",
               "/usr/local/lib/python3.12", "/usr/share/fonts", "/etc/fonts") if p
]
BLOCKED_MODULES = {
    "socket", "subprocess", "ctypes", "ctypeslib", "requests", "urllib", "urllib3",
    "http", "ftplib", "smtplib", "telnetlib", "paramiko", "pexpect",
    "pty", "multiprocessing", "asyncio", "ssl", "socketserver",
}

def _log_denial(what):
    try:
        with open(os.path.join(JAIL, "denials.log"), "a") as f:
            f.write(what + "\n")
    except Exception:
        pass

def _is_inside(path, root):
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:
        return False

def _importer_in_jail():
    """True when the code that triggered the current audit event lives in
    the jail (i.e. agent code), False when it lives in library code.
    Walks the stack from the top, skipping the audit machinery itself; the
    first real frame is the importer/caller. Fails closed (True) when the
    importer cannot be identified. This is what lets libraries lazily import
    what they need (pandas' plot backend -> importlib.metadata -> socket,
    Pillow -> subprocess, numpy -> ctypes) while agent code doing the same
    import is denied."""
    try:
        stack = traceback.extract_stack()
    except Exception:
        return True
    for frame in reversed(stack):
        fn = frame.filename or ""
        if "importlib" in fn or "<frozen" in fn or "jail_bootstrap.py" in fn:
            continue
        # ctypes' own __init__ wraps CDLL/dlsym calls: for ctypes.* events
        # the immediate caller is ctypes itself, so skip it to reach the
        # real caller (agent code or a library).
        if "/ctypes/" in fn:
            continue
        if fn.startswith("<"):
            continue
        return _is_inside(fn, JAIL)
    return True

def _blocked_import(name):
    parts = str(name).split(".")
    return any(p in BLOCKED_MODULES for p in parts) or "ctypes" in str(name)

def _hook(event, args):
    if event == "open":
        path = args[0]
        if isinstance(path, int):
            return  # already-open file descriptor
        path = os.fspath(path)
        mode = args[1] if len(args) > 1 else "r"
        writing = any(c in str(mode) for c in "wax+")
        ap = os.path.abspath(path)
        if _is_inside(ap, JAIL):
            return
        if ap in ("/dev/null", "/dev/urandom", "/dev/zero"):
            if writing and ap != "/dev/null":
                raise PermissionError("sandbox: write to %s denied" % ap)
            return
        if ap.startswith("/proc/") and not writing:
            return
        if ap.startswith("/sys/fs/cgroup/") and not writing:
            return  # threadpool/OpenBLAS reads cgroup limits; harmless telemetry
        for root in ALLOWED_READ_ROOTS:
            if _is_inside(ap, root) and not writing:
                return
        _log_denial("DENIED open %s mode=%s" % (ap, mode))
        raise PermissionError("sandbox: access to %s denied (outside jail)" % ap)
    if event in ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
                 "socket.gethostbyaddr"):
        _log_denial("DENIED network %s %r" % (event, args[:1]))
        raise PermissionError("sandbox: network access denied")
    if event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
                 "os.spawn", "os.spawnl", "os.spawnlp", "pty.spawn"):
        _log_denial("DENIED spawn %s" % event)
        raise PermissionError("sandbox: process spawn denied")
    if event == "import":
        name = args[0] if args else ""
        if _blocked_import(name) and _importer_in_jail():
            _log_denial("DENIED import %s" % name)
            raise PermissionError("sandbox: import of %s denied" % name)
    if event in ("ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function"):
        if _importer_in_jail():
            _log_denial("DENIED %s" % event)
            raise PermissionError("sandbox: ctypes use denied")

# Purge any blocked modules the interpreter itself pre-loaded, so agent
# code cannot reach them through a sys.modules cache hit (which fires no
# audit event). Libraries re-import them on demand through the hook, which
# allows library-triggered imports and denies jail-triggered ones.
for _m in [m for m in list(sys.modules) if m.split(".")[0] in BLOCKED_MODULES]:
    del sys.modules[_m]

sys.addaudithook(_hook)

# Resource limits: 30s CPU, 1 GiB address space (pandas + matplotlib
# reserve generously), 10 MiB files, 64 fds.
def _limits():
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    except Exception:
        pass

_limits()

if __name__ == "__main__":
    import runpy
    runpy.run_path(sys.argv[1], run_name="__main__")
'''


class SandboxResult:
    """Outcome of one jailed run."""

    def __init__(self, ok, stdout, stderr, exit_code, wall_seconds,
                 artifacts, denials, jail_dir):
        self.ok = ok
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.wall_seconds = wall_seconds
        self.artifacts = artifacts          # {name: bytes} for files the code left in the jail
        self.denials = denials              # list of denial lines from denials.log
        self.jail_dir = jail_dir            # kept for inspection; caller deletes when done


class Sandbox:
    """Runs untrusted agent code in a throwaway jail directory."""

    def __init__(self, python_exe=None, runs_root=None, timeout=60):
        self.python_exe = python_exe or sys.executable
        self.runs_root = runs_root or os.path.join(os.getcwd(), "runs")
        os.makedirs(self.runs_root, exist_ok=True)
        self.timeout = timeout

    def run(self, code, input_files=None, keep_jail=False):
        """Execute `code` (str) inside a fresh jail.

        input_files: {name: bytes} copied into the jail before the run
        (e.g. the uploaded CSV as data.csv). Returns SandboxResult.
        Artifacts are every file the code leaves in the jail other than the
        code itself, the bootstrap, and denials.log.
        """
        jail = tempfile.mkdtemp(prefix="jail-", dir=self.runs_root)
        try:
            # Seed the matplotlib font cache so font_manager does not call
            # fc-list (subprocess) on every run. The cache only contains
            # font paths; it is rebuilt automatically if stale.
            font_cache = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "mpl-font-cache")
            if os.path.isdir(font_cache):
                mpldir = os.path.join(jail, ".mpl")
                os.makedirs(mpldir, exist_ok=True)
                for name in os.listdir(font_cache):
                    src = os.path.join(font_cache, name)
                    dst = os.path.join(mpldir, name)
                    try:
                        os.link(src, dst)  # same inode, no extra disk
                    except OSError:
                        shutil.copyfile(src, dst)
            for name, data in (input_files or {}).items():
                dest = os.path.join(jail, name)
                os.makedirs(os.path.dirname(dest), exist_ok=True) if os.path.dirname(name) else None
                with open(dest, "wb") as f:
                    f.write(data)
            with open(os.path.join(jail, "agent_code.py"), "w") as f:
                f.write(code)
            with open(os.path.join(jail, "jail_bootstrap.py"), "w") as f:
                f.write(BOOTSTRAP)

            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": jail,
                "MPLCONFIGDIR": os.path.join(jail, ".mpl"),
                "BLASTSHIELD_JAIL": jail,
                "PYTHONDONTWRITEBYTECODE": "1",
                # Deliberately NO credentials of any kind in the sandbox env.
            }
            t0 = time.time()
            try:
                proc = subprocess.run(
                    [self.python_exe, "-I",
                     os.path.join(jail, "jail_bootstrap.py"),
                     os.path.join(jail, "agent_code.py")],
                    cwd=jail, env=env, capture_output=True, text=True,
                    timeout=self.timeout, start_new_session=True,
                )
                stdout, stderr, exit_code = proc.stdout, proc.stderr, proc.returncode
            except subprocess.TimeoutExpired as e:
                stdout = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
                stderr = (e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
                stderr += "\nsandbox: wall-clock timeout (%ds) — run killed" % self.timeout
                exit_code = 124
            wall = time.time() - t0

            artifacts = {}
            denials = []
            for name in sorted(os.listdir(jail)):
                path = os.path.join(jail, name)
                if not os.path.isfile(path):
                    continue
                if name in ("agent_code.py", "jail_bootstrap.py"):
                    continue
                if name == "denials.log":
                    with open(path, errors="replace") as f:
                        denials = [ln.strip() for ln in f if ln.strip()]
                    continue
                if name.startswith("."):
                    continue
                with open(path, "rb") as f:
                    artifacts[name] = f.read()

            ok = exit_code == 0
            if keep_jail:
                jail_dir = jail
            else:
                jail_dir = jail  # caller may inspect then delete via cleanup()
            return SandboxResult(ok, stdout, stderr, exit_code, wall,
                                 artifacts, denials, jail_dir)
        except Exception:
            shutil.rmtree(jail, ignore_errors=True)
            raise

    @staticmethod
    def cleanup(jail_dir):
        shutil.rmtree(jail_dir, ignore_errors=True)
