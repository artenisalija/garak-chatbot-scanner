# Garak installation notes

NVIDIA garak v0.17.0 was installed in `.venv/` inside this folder.

**There is no localhost link.** Garak is a command-line scanner and doesn't include a web UI or server, so nothing listens on a port.

## How it was installed

Python 3.14 (the system default) is too new for garak, so uv created a Python 3.12 virtual environment:

```bash
cd path/to/this/repo
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -U garak
```

To repeat the install on any machine, run `bash install_garak.sh` in this folder.

## How to use it

```bash
cd path/to/this/repo
source .venv/bin/activate
garak --list_probes                                   # see available attacks
garak --model_type openai --model_name gpt-4o-mini --probes promptinject   # example scan (needs OPENAI_API_KEY)
```

Scan results are written as reports (a `.report.html` summary and a `.jsonl` file) under `~/.local/share/garak/garak_runs/`. You can open the HTML file in a browser from there.

> Note added later: in v0.17 the `--probes` flag still works but is deprecated. The replacement is `--spec probes.<module>[.<Class>]`, for example `--spec probes.promptinject`.

If you want a browser interface, garak has no official one. Options: serve the report folder on a localhost port so you can open the HTML reports, or build a small local dashboard.
