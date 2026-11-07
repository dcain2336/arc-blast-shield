"""Record the ARC Blast Shield demo video with Playwright.

Drives the real app in a real browser: upload the sample CSV, run in
interactive mode, approve the code execution at the approval gate, wait
for the analysis + charts + containment probe, then slowly scroll through
the results so the video shows each section.

Usage:
  1. Start the server first:  PORT=18081 ./run.sh
  2. .venv/bin/python record_demo.py
  3. Video lands in ./demo-video/*.webm (1280x800).

The video is the raw demo artifact: the parent uploads it (YouTube, ARC
channel, unlisted) and links it in the lablab submission.
"""
import os
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
URL = os.environ.get("BLASTSHIELD_URL", "http://127.0.0.1:18081")
OUT = os.path.join(BASE, "demo-video")
os.makedirs(OUT, exist_ok=True)

from playwright.sync_api import sync_playwright  # noqa: E402


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(
            viewport={"width": 1280, "height": 800},
            record_video_dir=OUT,
            record_video_size={"width": 1280, "height": 800},
        )
        page = ctx.new_page()
        page.goto(URL)
        page.wait_for_selector("#health")
        time.sleep(1.5)  # let the health line settle on screen

        # 1. Upload the sample CSV.
        page.set_input_files("#file", os.path.join(BASE, "sample_data.csv"))
        page.wait_for_selector("#fileinfo:not(:empty)")
        time.sleep(1.0)

        # 2. Run (interactive mode is the default: approval gate on).
        page.click("#run")
        # 3. Wait for the approval card, let the viewer read the code, approve.
        page.wait_for_selector("#approval-card:not([hidden])", timeout=60000)
        time.sleep(3.0)
        page.click("#approve")

        # 4. Wait for completion (status done via the API, or results visible).
        page.wait_for_selector("#results:not([hidden])", timeout=180000)
        time.sleep(1.0)

        # 5. Slow scroll-through for the video: log, results, containment.
        page.evaluate("document.querySelector('#results').scrollIntoView()")
        time.sleep(2.0)
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        time.sleep(2.5)
        page.evaluate("document.querySelector('#containment').scrollIntoView({block: 'center'})")
        time.sleep(2.5)
        page.evaluate("window.scrollTo(0, 0)")
        time.sleep(1.0)

        ctx.close()
        browser.close()

    videos = sorted(os.listdir(OUT))
    print("videos:", videos)
    for v in videos:
        path = os.path.join(OUT, v)
        print(v, os.path.getsize(path), "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
