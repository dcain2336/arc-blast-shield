"""End-to-end test: full pipeline with the local-fallback analyst.

Upload the sample CSV -> schema -> plan -> code -> policy gate (auto-approve)
-> jailed run -> charts + stats + summary -> containment probe.
Exits non-zero on any failure. Run:  .venv/bin/python tests/test_end_to_end.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import Run, run_analysis  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(BASE, ".venv", "bin", "python")
RUNS = os.path.join(BASE, "runs")


def main():
    with open(os.path.join(BASE, "sample_data.csv"), "rb") as f:
        csv_bytes = f.read()
    run = Run("test-e2e", "Summarize this dataset and chart the key patterns.",
              "sample_data.csv", policy_mode="auto")
    run_analysis(run, csv_bytes, PY, RUNS, on_approval=lambda a, d: True)

    assert run.status == "done", "run status=%s events=%s" % (
        run.status, json.dumps(run.events, indent=1))
    schema = run.results["schema"]
    assert schema["rows"] == 192, schema
    assert [c["name"] for c in schema["columns"]] == [
        "date", "region", "product", "channel", "units", "revenue"], schema
    assert run.results["charts"], "no charts produced"
    assert set(run.results["charts"]) >= {"chart_groupby.png", "chart_hist.png"}, run.results["charts"]
    stats = run.results["stats"]
    assert stats["rows"] == 192
    assert stats["group_by"], "group_by missing"
    assert run.results["summary"], "no summary"
    cont = run.results["containment"]
    assert cont["all_blocked"], cont
    assert len(run.results["attempts"]) == 1, run.results["attempts"]
    decisions = [e["decision"] for e in run.ledger.as_list()]
    assert "ALLOW" in decisions and "ASK" in decisions, run.ledger.as_list()
    print("E2E OK: rows=192 charts=%s summary=%r" % (
        run.results["charts"], run.results["summary"][:120]))
    print("containment: %s" % "; ".join(cont["lines"][:3]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
