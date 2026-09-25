# Garak Chatbot Scanner

An interactive terminal wizard that runs [NVIDIA garak](https://github.com/NVIDIA/garak) against a chatbot on your website and produces a full report, including every successful attack with the complete prompt and the chatbot's complete reply.

Garak is an LLM vulnerability scanner: it sends thousands of adversarial prompts (prompt injection, jailbreaks, data-leak attempts, encoding bypasses) and checks how the model responds. This repo adds:

- **`install_garak.sh`**: one-command installation into an isolated Python 3.12 environment.
- **`garak_wizard.py`**: a step-by-step wizard. You give it the chatbot's endpoint (copied from your browser's Network tab), it tests the connection, lets you pick attacks with explanations, runs the scan, and writes an HTML report plus an "attack evidence" page.
- **`my_target.py`**: adapters for chatbots whose endpoint you can't simply copy from the browser.
- **`show_hits.py`**: a terminal viewer for garak's hit logs.

> ## Authorized use only
> Only scan chatbots you own or have **written permission** to test. Scans send thousands of hostile requests: they can hit rate limits, cost money on the model behind the bot, and fill logs and analytics with junk. Prefer a staging copy over production. The wizard makes you confirm authorization before it sends anything. You are responsible for how you use this tool.

## Contents

- [Requirements](#requirements)
- [Install garak](#install-garak)
- [Use the wizard](#use-the-wizard)
- [Finding your chatbot's endpoint](#finding-your-chatbots-endpoint)
- [If you can't copy the endpoint from the browser](#if-you-cant-copy-the-endpoint-from-the-browser)
- [Choosing probes](#choosing-probes)
- [Reading the results](#reading-the-results)
- [Using garak directly](#using-garak-directly)
- [Limitations](#limitations)
- [Keeping secrets safe](#keeping-secrets-safe)
- [Repository layout](#repository-layout)
- [Credits](#credits)

## Requirements

- Linux or macOS with `bash` and `curl`. Developed and tested on Fedora Linux. Windows is untested (use WSL).
- Internet access for the install and for some probes that download datasets on first use.
- Python 3.12. You don't need to install it yourself: the installer gets it through [uv](https://docs.astral.sh/uv/). Garak doesn't support very new Python versions such as 3.14, which is why a dedicated environment is used.

## Install garak

```bash
git clone <this-repo-url>
cd <repo-folder>
bash install_garak.sh
```

The script:

1. Installs `uv` if it's missing (it runs uv's official installer, `curl -LsSf https://astral.sh/uv/install.sh | sh`. Read the script first if you prefer to install uv yourself).
2. Creates a Python 3.12 virtual environment in `.venv/`.
3. Installs or upgrades `garak` into it.
4. Verifies the install by printing the version and running a dry run that needs no API key (`PASS ok on 40/40` means it works).

It is safe to re-run. It reuses `.venv/` and just upgrades garak.

**Manual installation**, if you'd rather not use the script:

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -U garak
source .venv/bin/activate
garak --version
```

Garak is a command-line tool, not a server, so there is no web interface or localhost page to open.

## Use the wizard

```bash
python3 garak_wizard.py
```

You don't need to activate the virtual environment first. The script switches to it automatically. The wizard walks you through these steps:

| Step | What it asks | Notes |
|---|---|---|
| Confirmation | Type `yes` to confirm you're authorized to test the bot | Nothing is sent otherwise |
| 1. URL | The chatbot's Request URL, with instructions for finding it | You can instead paste a whole **Copy as cURL** command to fill steps 1–4 at once |
| 2. Method | HTTP method, normally POST | |
| 3. Headers | Cookie, Authorization, CSRF token, etc. | Typed hidden, never saved to the report |
| 4. Body | The request JSON and the unique message you typed while capturing | The wizard finds where the message goes and swaps in attack prompts |
| 5. Test | Sends one real message and shows the response | You pick the field holding the bot's reply. On 401/403 it offers to fix headers, body or URL. |
| 6. Probes | Which attacks to run | Groups, explanations, and presets. See [Choosing probes](#choosing-probes) |
| 7. Intensity | Attempts per prompt, parallel requests | Defaults are gentle (1 and 1) |
| 8. Estimate | Counts the requests before any are sent | Shows the number and approximate duration, then asks you to confirm |

Then it runs the scan with live garak output and writes the results.

## Finding your chatbot's endpoint

1. Open the page with the chatbot and press **F12** (or right-click → Inspect).
2. Open the **Network** tab and choose the **Fetch/XHR** filter.
3. Send a message in the chatbot. **Type something unique**, such as `ZEBRA-TEST-123`, so the wizard can find where your message sits in the request.
4. Click the new request in the list (often named `chat`, `message` or `completions`).
5. On the **Headers** tab, copy the **Request URL**, note the **Request Method**, and copy the **Request Headers** your site needs (usually `Cookie`, `Authorization` or a CSRF token).
6. On the **Payload** tab, click **view source** and copy the JSON.

Shortcut: right-click the request → **Copy → Copy as cURL (bash)** and paste it at the first prompt.

Session cookies and CSRF tokens expire. If a scan fails partway with 401/403, refresh them and run again.

## If you can't copy the endpoint from the browser

If your site blocks or hides its chat API from outsiders (bot guards, obfuscation), you don't need to defeat your own protection. Because you own the site, give the scanner a way in. [`my_target.py`](my_target.py) has three options:

1. **Test credential (recommended)**: make your staging server accept a secret token used only by garak, and keep the public guard on for everyone else.
   ```bash
   export TARGET_URL="https://staging.example.com/api/chat"
   export TARGET_TOKEN="your-garak-only-token"
   source .venv/bin/activate
   PYTHONPATH=. garak --target_type function.Single --target_name my_target#http_target \
       -g 1 --spec probes.promptinject.HijackHateHumans
   ```
   Edit `http_target` so the request body and reply field match your API.
2. **Call your backend directly**: wire `direct_target` to your chat function. No HTTP and no guard involved.
3. **Drive the real widget in a headless browser** with `browser_target` (needs Playwright). It's slower but tests the whole stack, including the guard. The CSS selectors are placeholders you must change.

## Choosing probes

A **probe** is one family of attack prompts. A **detector** judges each reply as safe or failed. The wizard lists 31 probes in six groups and explains each one (`info 3` for one, `info all` for everything):

| Group | What it tests | Probes |
|---|---|---|
| A. Prompt injection | Attacker text overrides your instructions | `promptinject`, `latentinjection`, `web_injection`, `goodside`, `suffix` |
| B. Jailbreaks and roleplay | Talking the model out of its rules | `dan`, `grandma`, `doctor`, `phrasing`, `sata`, `dra` |
| C. Encoding and obfuscation | Hiding the attack so filters miss it | `encoding`, `smuggling`, `badchars`, `glitch` |
| D. Data leakage | Revealing prompts, secrets, personal data | `sysprompt_extraction`, `leakreplay`, `apikey`, `divergence`, `propile` |
| E. Harmful or off-brand output | Content and policy failures | `malwaregen`, `ansiescape`, `exploitation`, `realtoxicityprompts`, `lmrc`, `donotanswer`, `continuation`, `topic` |
| F. Reliability | Wrong or made-up answers | `packagehallucination`, `snowball`, `misleading` |

Selection syntax at the prompt: numbers and ranges (`1,3,5-7`), names (`promptinject dan`), or a preset:

- `quick`: `promptinject` and `sysprompt_extraction`. The two most important first checks.
- `essentials`: a solid first audit of a customer-facing chatbot.
- `all`: every probe in the list. Slow, with many requests.

Not offered, because they need extra setup or don't apply to a text chatbot: probes that need a second "attacker" LLM (`tap`, `goat`, `atkgen`, `fitd`, `adaptive_attacks`, `agent_breaker`), audio and image probes, and garak's own test probes.

Start small. A full scan can send tens of thousands of requests.

## Reading the results

Each run is saved in `reports/<timestamp>/`, and the newest one is linked as `reports/latest`:

| File | What it contains |
|---|---|
| `report.html` | Summary: attack success rate and risk (PASS / LOW / MEDIUM / HIGH) per probe, what each failure means, how to defend, and a few examples |
| `evidence.html` | **Every** successful attack with the **full prompt sent** and the **full reply** from your chatbot. Search, filter by probe, and heuristic flags for replies that look like API keys, emails, system instructions or URLs. Untruncated. |
| `*.hitlog.jsonl` | Raw garak data: only the successful attacks |
| `*.report.jsonl` | Raw garak data: every attempt |
| `summary.json` | Per-probe numbers |

Reopen the latest reports at any time:

```bash
python3 garak_wizard.py --open-last
```

Tips for reading them:

- **Read the evidence, not just the percentages.** Detectors match patterns, so some hits are false positives (for example a bot that quotes the attack while refusing it).
- **Fix, then re-run the same probes with the same settings** and compare.
- The heuristic flags in `evidence.html` are pattern guesses and can be wrong.
- Any attempt with no usable reply is counted and warned about. Fix connectivity before trusting the numbers.

See [02_full_walkthrough.md](02_full_walkthrough.md) for how to turn findings into fixes (guardrails, input normalization, output filtering, and so on).

## Using garak directly

You can skip the wizard and use garak itself:

```bash
source .venv/bin/activate
garak --list_probes
garak --list_generators

# Example: scan a model hosted on Groq (key stays in your terminal, never in a file)
export GROQ_API_KEY="..."
garak --target_type groq                                   # lists available models
garak -t groq -n llama-3.1-8b-instant -g 1 --spec probes.promptinject.HijackHateHumans
```

Garak writes its own reports to `~/.local/share/garak/garak_runs/`. To print the successful attacks from a hit log in the terminal or as HTML:

```bash
python3 show_hits.py                        # newest hit log
python3 show_hits.py --summary              # hit count per probe
python3 show_hits.py -p promptinject -n 5   # filter by probe, show 5
python3 show_hits.py --html hits.html       # browsable page
```

Note: in garak 0.17 the `--probes` flag is deprecated in favor of `--spec probes.<module>[.<Class>]`.

## Limitations

- The wizard sends the attack prompt inside a **JSON body** (POST, PUT or PATCH). Other request styles need [`my_target.py`](my_target.py).
- **Streaming replies** (server-sent events, WebSockets) aren't supported by garak's REST generator. Turn streaming off on a staging copy or write an adapter that joins the stream.
- Each prompt is sent as a fresh request. Multi-turn attacks and conversation state aren't modeled.
- This tests **text attacks against the chat endpoint**. If your bot can take actions (orders, email, refunds), also test those by hand with a test account.
- If the server returns a 4xx error mid-scan (for example an expired cookie), garak stops.
- The request-count estimate is approximate. Probes that download data need internet access.
- Passing a scan is not proof of safety. It shows only that these attacks didn't work this time.

## Keeping secrets safe

- Header values (cookies, tokens) are typed hidden, held in a temporary file with owner-only permissions that is deleted when the run ends, and checked against the saved output. They are never written to reports.
- **`reports/` can contain sensitive data**: the chatbot's raw replies may include leaked system prompts, secrets or personal data. `.gitignore` excludes it, along with `.venv/` and garak's raw report files. Never commit or share those files publicly.
- Put API keys in environment variables (`export GROQ_API_KEY=...`), not in files in this repo.

## Repository layout

```
install_garak.sh         # installs garak into .venv (Python 3.12) and verifies it
garak_wizard.py          # the interactive scanner and report generator
my_target.py             # adapters for endpoints you can't copy from the browser
show_hits.py             # terminal / HTML viewer for garak hit logs
01_install_response.md   # notes on the garak installation
02_full_walkthrough.md   # learning guide: using garak to secure an AI model
.gitignore               # keeps .venv, reports and secrets out of git
```

## Credits

Built on [NVIDIA garak](https://github.com/NVIDIA/garak), an open-source LLM vulnerability scanner (Apache-2.0). This repository is an independent wrapper and is not affiliated with or endorsed by NVIDIA. The [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) is a good companion for understanding what the probes are testing.
