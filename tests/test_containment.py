"""Containment tests: every unsafe action must be denied by the jail.

Each probe asserts the denial happens (PermissionError at runtime, recorded
in denials.log) and that legitimate in-jail work still succeeds.
Run:  .venv/bin/python tests/test_containment.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbox import Sandbox  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(BASE, ".venv", "bin", "python")
RUNS = os.path.join(BASE, "runs")

CASES = [
    ("read /etc/passwd", "open('/etc/passwd').read()"),
    ("read /etc/shadow", "open('/etc/shadow').read()"),
    ("write outside jail", "open('/tmp/blastshield-evil.txt', 'w').write('x')"),
    ("open socket", "import socket; socket.create_connection(('8.8.8.8', 53), timeout=3)"),
    ("dns lookup", "import socket; socket.getaddrinfo('example.com', 80)"),
    ("subprocess", "import subprocess; subprocess.run(['id'], capture_output=True)"),
    ("os.system", "import os; os.system('id')"),
    ("import requests", "import requests"),
    ("import urllib", "import urllib.request; urllib.request.urlopen('https://example.com')"),
    ("import ctypes", "import ctypes"),
    ("ctypes via numpy", "import numpy as np; np.ctypeslib.ctypes.CDLL('libc.so.6')"),
    ("socket via library attr", "import matplotlib.backend_bases as b; b.socket.create_connection(('8.8.8.8', 53), timeout=3)"),
]


def main():
    sb = Sandbox(python_exe=PY, runs_root=RUNS)
    failures = []

    for name, snippet in CASES:
        code = "try:\n    %s\n    print('ALLOWED')\nexcept PermissionError as e:\n    print('BLOCKED: %%s' %% e)\n" % snippet
        res = sb.run(code)
        Sandbox.cleanup(res.jail_dir)
        blocked = ("BLOCKED" in res.stdout) or res.denials
        status = "BLOCKED" if blocked else "ALLOWED <-- FAILURE"
        print("%-22s %s" % (name, status))
        if not blocked:
            failures.append(name)

    # Legitimate work must still succeed inside the jail.
    good = sb.run(
        "import pandas as pd\n"
        "df = pd.DataFrame({'a': [1, 2, 3]})\n"
        "df.to_csv('out.csv', index=False)\n"
        "print('LEGIT-OK', df['a'].sum())\n",
        input_files={})
    Sandbox.cleanup(good.jail_dir)
    legit = good.ok and "LEGIT-OK 6" in good.stdout and "out.csv" in good.artifacts
    print("%-22s %s" % ("legit pandas in jail", "OK" if legit else "FAILED"))
    if not legit:
        failures.append("legit pandas in jail")
        print(good.stdout, good.stderr)

    # No secret may leak into the sandbox environment.
    import subprocess
    env_probe = sb.run("import os; print('KEY_PRESENT' if 'VULTR_API_KEY' in os.environ else 'KEY_ABSENT')")
    Sandbox.cleanup(env_probe.jail_dir)
    leak = "KEY_PRESENT" in env_probe.stdout
    print("%-22s %s" % ("no key in sandbox env", "FAILED — key leaked" if leak else "OK"))
    if leak:
        failures.append("secret leak")

    if failures:
        print("CONTAINMENT FAILURES: %s" % failures)
        return 1
    print("CONTAINMENT OK: all %d attacks denied, legit work unaffected" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
