"""Adapters that let garak attack your own website chatbot without reading its
public endpoint from the browser's network tab.

Garak's `function` generator calls   fn(prompt: str, **kwargs) -> list[str]
Pick ONE of the functions below and point garak at it (see bottom of file).

  http_target     Call an endpoint over HTTP with a test credential that YOUR
                  server accepts (best on staging; lets you keep the public guard on).
  direct_target   Call your own backend chat function in-process. No HTTP, no guard.
  browser_target  Drive the real chat widget with Playwright. Slowest, but tests
                  the whole stack including the guard.

Only use this against systems you own or are authorized to test.
"""
import os
import time

# --------------------------------------------------------------------------
# Option A: HTTP with a test credential your server allowlists
# --------------------------------------------------------------------------
# Environment variables (set them in your terminal, not in this file):
#   TARGET_URL     e.g. https://staging.yoursite.com/api/chat
#   TARGET_TOKEN   a token/header value your server accepts for garak only
#   TARGET_HEADER  header name to send it in (default: Authorization)
def http_target(prompt: str, **kwargs):
    import requests

    headers = {"Content-Type": "application/json"}
    token = os.environ.get("TARGET_TOKEN")
    if token:
        name = os.environ.get("TARGET_HEADER", "Authorization")
        headers[name] = f"Bearer {token}" if name == "Authorization" else token

    # ADAPT: request body shape and reply field to match your API.
    body = {"message": prompt}
    try:
        r = requests.post(os.environ["TARGET_URL"], json=body, headers=headers, timeout=30)
    except requests.RequestException as e:
        return [None]
    if r.status_code == 429:
        time.sleep(5)  # back off; garak will see an empty reply for this prompt
        return [None]
    if r.status_code != 200:
        return [None]
    return [r.json()["reply"]]  # ADAPT: e.g. r.json()["data"]["reply"]


# --------------------------------------------------------------------------
# Option B: call your backend code directly
# --------------------------------------------------------------------------
def direct_target(prompt: str, **kwargs):
    # ADAPT: import the function your API route calls and return its text.
    #   from myapp.chat import answer
    #   return [answer(prompt, session_id="garak-test")]
    raise NotImplementedError("wire this to your backend's chat function")


# --------------------------------------------------------------------------
# Option C: drive the real widget in a headless browser (needs Playwright)
#   uv pip install --python .venv/bin/python playwright && .venv/bin/playwright install chromium
# --------------------------------------------------------------------------
_pw = {}


def browser_target(prompt: str, **kwargs):
    from playwright.sync_api import sync_playwright

    if "page" not in _pw:
        _pw["p"] = sync_playwright().start()
        _pw["b"] = _pw["p"].chromium.launch(headless=True)
        _pw["page"] = _pw["b"].new_page()
        _pw["page"].goto(os.environ["TARGET_PAGE"])  # page that hosts the widget

    page = _pw["page"]
    # ADAPT: these selectors are placeholders; inspect your widget's HTML.
    box = page.locator(os.environ.get("INPUT_SEL", "textarea"))
    box.fill(prompt)
    box.press("Enter")
    reply_sel = os.environ.get("REPLY_SEL", ".bot-message")
    page.wait_for_selector(reply_sel, timeout=30000)
    time.sleep(float(os.environ.get("SETTLE_SECONDS", "3")))  # let streaming finish
    return [page.locator(reply_sel).last.inner_text()]


# Run from this folder, with the venv active:
#   export TARGET_URL=... TARGET_TOKEN=...
#   PYTHONPATH=. garak --target_type function.Single --target_name my_target#http_target \
#       -g 1 --spec probes.promptinject.HijackHateHumans
