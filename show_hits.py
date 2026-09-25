#!/usr/bin/env python3
"""Show the attacks that succeeded in a garak scan: prompt, response, and why it counted as a hit.

Usage:
  python show_hits.py                      # newest hitlog in garak's run directory
  python show_hits.py path/to/x.hitlog.jsonl
  python show_hits.py -p promptinject -n 5 # filter by probe substring, limit output
  python show_hits.py --html hits.html     # also write a browsable HTML page
  python show_hits.py --summary            # only a per-probe count table
"""
import argparse
import collections
import glob
import html
import json
import os
import sys

RUNS_DIR = os.path.expanduser("~/.local/share/garak/garak_runs")
RED, YEL, DIM, BOLD, END = "\033[91m", "\033[93m", "\033[2m", "\033[1m", "\033[0m"


def newest_hitlog():
    files = glob.glob(os.path.join(RUNS_DIR, "*.hitlog.jsonl"))
    if not files:
        sys.exit(f"No hitlog files in {RUNS_DIR}. A run with zero hits doesn't create one.")
    return max(files, key=os.path.getmtime)


def load(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def prompt_text(hit):
    parts = []
    for t in hit["prompt"].get("turns", []):
        content = t.get("content")
        text = content.get("text") if isinstance(content, dict) else content
        parts.append(f"[{t.get('role', '?')}] {text}")
    return "\n".join(parts)


def output_text(hit):
    out = hit.get("output")
    return (out.get("text") if isinstance(out, dict) else out) or ""


def mark(text, triggers, on, off):
    for trig in triggers or []:
        if trig:
            text = text.replace(trig, f"{on}{trig}{off}")
    return text


def print_hit(i, h):
    trig = h.get("triggers") or []
    print(f"{BOLD}{'=' * 78}{END}")
    print(f"{BOLD}HIT #{i}{END}  probe={h['probe']}  detector={h['detector']}  score={h['score']}")
    print(f"goal:     {h.get('goal')}")
    print(f"trigger:  {YEL}{trig}{END}  (text the detector looked for)")
    print(f"{DIM}--- PROMPT SENT TO MODEL {'-' * 50}{END}")
    print(mark(prompt_text(h), trig, YEL, END))
    print(f"{DIM}--- MODEL RESPONSE (this is the failure) {'-' * 35}{END}")
    print(mark(output_text(h), trig, RED, END))


def write_html(hits, path):
    esc = lambda s: html.escape(s)
    hl = lambda s, t: mark(esc(s), [esc(x) for x in t or []], "<mark>", "</mark>")
    rows = []
    for i, h in enumerate(hits, 1):
        t = h.get("triggers")
        rows.append(
            f"<details><summary>#{i} {esc(h['probe'])} / {esc(h['detector'])} "
            f"— trigger {esc(str(t))}</summary>"
            f"<h4>Prompt</h4><pre>{hl(prompt_text(h), t)}</pre>"
            f"<h4>Response</h4><pre>{hl(output_text(h), t)}</pre></details>"
        )
    with open(path, "w") as f:
        f.write(
            "<meta charset=utf-8><title>garak hits</title><style>"
            "body{font-family:sans-serif;max-width:1000px;margin:2em auto}"
            "pre{white-space:pre-wrap;background:#f4f4f4;padding:1em;border-radius:6px}"
            "mark{background:#ffd54f}summary{cursor:pointer;padding:.4em 0}</style>"
            f"<h1>{len(hits)} successful attacks</h1>" + "\n".join(rows)
        )
    print(f"wrote {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hitlog", nargs="?")
    ap.add_argument("-p", "--probe", help="only hits whose probe contains this text")
    ap.add_argument("-n", "--limit", type=int, default=10, help="max hits to print (default 10)")
    ap.add_argument("--html")
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()

    path = a.hitlog or newest_hitlog()
    hits = load(path)
    if a.probe:
        hits = [h for h in hits if a.probe in h["probe"]]
    print(f"{path}\n{len(hits)} hits\n")

    counts = collections.Counter((h["probe"], h["detector"]) for h in hits)
    for (probe, det), n in counts.most_common():
        print(f"{n:6d}  {probe}  ({det})")
    if a.summary:
        return
    print()
    for i, h in enumerate(hits[: a.limit], 1):
        print_hit(i, h)
    if len(hits) > a.limit:
        print(f"\n... {len(hits) - a.limit} more; raise -n or use --html")
    if a.html:
        write_html(hits, a.html)


if __name__ == "__main__":
    main()
