"""ARC Blast Shield — LLM client.

All agent LLM calls go through Vultr Serverless Inference (OpenAI-compatible,
base URL https://api.vultrinference.com/v1). The key comes from the
environment (VULTR_API_KEY) and is NEVER passed into the sandbox.

When no key is configured, the deterministic LocalAnalyst answers instead.
It writes real pandas code from the schema and the task using templates, so
the full pipeline (inspect -> plan -> code -> run -> heal -> summary) can be
verified end-to-end offline. Every UI result and log line labels which
analyst produced it, so a local-fallback run can never be mistaken for a
Vultr-model run.
"""

from __future__ import annotations

import json
import os
import urllib.request

DEFAULT_BASE_URL = "https://api.vultrinference.com/v1"
# kimi-k2-instruct is the model Vultr documents for tool calling on
# Serverless Inference; keep it the default and let VULTR_MODEL override.
DEFAULT_MODEL = "kimi-k2-instruct"


class VultrClient:
    """Thin OpenAI-compatible chat client pointed at Vultr Serverless Inference."""

    def __init__(self, api_key=None, base_url=None, model=None, timeout=60):
        self.api_key = api_key or os.environ.get("VULTR_API_KEY", "")
        self.base_url = (base_url or os.environ.get(
            "VULTR_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        self.model = model or os.environ.get("VULTR_MODEL", DEFAULT_MODEL)
        self.timeout = timeout

    @property
    def configured(self):
        return bool(self.api_key)

    def chat(self, system, user, temperature=0.2, max_tokens=2000):
        """Return the model's reply text. Raises on HTTP/API errors."""
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }).encode()
        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.api_key,
                "User-Agent": "ARC-Blast-Shield/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode())
        return body["choices"][0]["message"]["content"]


class LocalAnalyst:
    """Deterministic offline analyst (no LLM, no network).

    Produces the same four artifacts the LLM path produces — a plan, pandas
    code, a repair for a failed run, and a plain-English summary — from the
    CSV schema and the task text. Used only when no Vultr key is configured,
    so the pipeline is verifiable end-to-end without credentials.
    """

    name = "local-fallback"

    def plan(self, schema, task):
        numeric = [c["name"] for c in schema["columns"] if c["dtype"] in ("number", "integer", "float")]
        cats = [c["name"] for c in schema["columns"] if c["dtype"] in ("string", "category")]
        steps = [
            "Load data.csv with pandas and report shape, dtypes, and missing values.",
            "Compute descriptive statistics for numeric columns: %s." % (
                ", ".join(numeric) or "none found"),
            "Group by the first categorical column (%s) and aggregate the first "
            "numeric column, if both exist." % (cats[0] if cats else "none"),
            "Draw two charts: a bar chart of the group-by totals and a histogram "
            "of the first numeric column.",
            "Write stats.json with the key numbers and a plain-English summary.",
        ]
        return {"task": task, "steps": steps, "numeric": numeric, "categorical": cats}

    def code(self, schema, task):
        """Generate pandas analysis code for the schema. The code only ever
        reads data.csv and writes files inside the jail (charts + stats.json).
        """
        numeric = [c["name"] for c in schema["columns"] if c["dtype"] in ("number", "integer", "float")]
        cats = [c["name"] for c in schema["columns"] if c["dtype"] in ("string", "category")]
        dates = [c["name"] for c in schema["columns"] if c["dtype"] == "date"]
        num = numeric[0] if numeric else None
        cat = cats[0] if cats else None
        lines = [
            "import json",
            "import pandas as pd",
            "import matplotlib",
            "matplotlib.use('Agg')",
            "import matplotlib.pyplot as plt",
            "",
            "df = pd.read_csv('data.csv')",
            "for c in df.columns:",
            "    if pd.api.types.is_string_dtype(df[c]):",
            "        try:",
            "            df[c] = pd.to_datetime(df[c])",
            "        except Exception:",
            "            pass",
            "stats = {}",
            "stats['rows'] = int(len(df))",
            "stats['columns'] = list(df.columns)",
            "stats['missing'] = {c: int(df[c].isna().sum()) for c in df.columns}",
            "desc = df.describe(include='all').to_dict()",
            "stats['describe'] = {k: {str(k2): (None if pd.isna(v2) else v2) for k2, v2 in v.items()} for k, v in desc.items()}",
        ]
        if num and cat:
            lines += [
                "grouped = df.groupby('%s')['%s'].agg(['sum', 'mean', 'count']).reset_index()" % (cat, num),
                "grouped = grouped.sort_values('sum', ascending=False)",
                "stats['group_by'] = grouped.to_dict(orient='records')",
                "plt.figure()",
                "plt.bar(grouped['%s'].astype(str), grouped['sum'])" % cat,
                "plt.title('Total %s by %s')" % (num, cat),
                "plt.xticks(rotation=30, ha='right')",
                "plt.tight_layout()",
                "plt.savefig('chart_groupby.png')",
                "plt.close()",
            ]
        if num:
            lines += [
                "plt.figure()",
                "df['%s'].hist(bins=12)" % num,
                "plt.title('Distribution of %s')" % num,
                "plt.tight_layout()",
                "plt.savefig('chart_hist.png')",
                "plt.close()",
                "stats['top_values'] = df.nlargest(5, '%s').to_dict(orient='records')" % num,
            ]
        if dates and num:
            lines += [
                "ts = df.groupby(df['%s'].dt.to_period('M'))['%s'].sum()" % (dates[0], num),
                "plt.figure()",
                "ts.plot(kind='line', marker='o')",
                "plt.title('%s over time')" % num,
                "plt.tight_layout()",
                "plt.savefig('chart_trend.png')",
                "plt.close()",
            ]
        lines += [
            "with open('stats.json', 'w') as f:",
            "    json.dump(stats, f, indent=2, default=str)",
            "print('ANALYSIS OK rows=%d charts written' % len(df))",
        ]
        return "\n".join(lines) + "\n"

    def repair(self, code, traceback_text):
        """Patch the most common failure modes deterministically. Returns
        repaired code, or None if the failure is not one we know how to fix.
        """
        if "KeyError" in traceback_text or "not in index" in traceback_text:
            fixed = code.replace("df.groupby(", "df.dropna().groupby(", 1)
            return fixed if fixed != code else None
        if "ParserError" in traceback_text or "Error tokenizing" in traceback_text:
            return code.replace("pd.read_csv('data.csv')",
                                "pd.read_csv('data.csv', on_bad_lines='skip')")
        if "ValueError: could not convert" in traceback_text:
            return code.replace("pd.to_datetime(df[c])",
                                "pd.to_datetime(df[c], errors='coerce')")
        return None

    def summarize(self, stats, task):
        rows = stats.get("rows", "?")
        cols = stats.get("columns", [])
        missing = stats.get("missing", {})
        total_missing = sum(missing.values())
        lines = [
            "Analyzed %s rows across %d columns (%s)." % (
                rows, len(cols), ", ".join(cols)),
            "Missing values: %d in total." % total_missing,
        ]
        group = stats.get("group_by") or []
        if group:
            top = group[0]
            keys = list(top.keys())
            lines.append(
                "Largest group: %s with total %s (mean %s, n=%s)." % (
                    top[keys[0]], top[keys[1]], top[keys[2]], top[keys[3]]))
        lines.append("Charts and full statistics are attached below.")
        return " ".join(lines)


def get_analyst():
    """Return (analyst, mode) where mode is 'vultr' or 'local-fallback'."""
    client = VultrClient()
    if client.configured:
        return client, "vultr"
    return LocalAnalyst(), "local-fallback"
