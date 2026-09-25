# Garak walkthrough: securing an AI model

> Note: v0.17 deprecates `--probes` / `-p` in favor of `--spec probes.<module>[.<Class>]`. The old flag still works, and both appear below.

## 1. What garak does

Garak is a scanner for LLMs, in the same role nmap or a vulnerability scanner plays for networks. It has three main parts:

| Component | Role | Example |
|---|---|---|
| **Generator** | The model under test | OpenAI, Anthropic, Hugging Face, a local model, a REST endpoint |
| **Probe** | Sends attack prompts | `promptinject`, `dan` (jailbreaks), `encoding`, `leakreplay` |
| **Detector** | Judges whether the reply was a failure | "Did the model follow the injected instruction?" |

Garak runs each probe against your model, and the detectors mark each response as pass or fail. It then writes a report.

Garak only **finds** weaknesses. Securing the model is the second half of the work, covered in step 7.

Only scan models and endpoints you own or are authorized to test.

## 2. Set up

```bash
cd path/to/this/repo
source .venv/bin/activate
```

Run this at the start of each session. Your prompt will show `(.venv)`.

## 3. Run a dry run with no API key

```bash
garak --model_type test.Blank --probes test.Test
```

This uses a fake model that returns empty output. It confirms garak works and shows you what the output looks like. Each probe prints a line like `PASS ok on 20/20`, or `FAIL ok on 15/20`, which means 5 attempts got through.

## 4. Explore what's available

```bash
garak --list_probes       # attack categories (about 40 modules in v0.17)
garak --list_detectors    # 140+ detectors
garak --list_generators   # supported model backends
```

Probe modules, grouped by what you're learning:

| Attack class | Probes |
|---|---|
| **Prompt injection** | `promptinject`, `latentinjection`, `web_injection`, `goodside` |
| **Jailbreaks** | `dan`, `grandma`, `tap`, `goat`, `fitd`, `suffix` |
| **Data leakage** | `leakreplay`, `sysprompt_extraction`, `apikey`, `divergence`, `propile` |
| **Encoding and smuggling bypasses** | `encoding`, `smuggling`, `badchars`, `glitch` |
| **Harmful output** | `malwaregen`, `realtoxicityprompts`, `lmrc`, `donotanswer` |
| **Hallucination and misinformation** | `packagehallucination`, `snowball`, `misleading` |
| **Agents and tools** | `agent_breaker`, `exploitation` |

A good learning order is `promptinject`, then `dan`, then `encoding`, then `leakreplay`. Each teaches a different failure mode.

## 5. Scan a real model

**Option A: a hosted API** (costs money per request):
```bash
export OPENAI_API_KEY="sk-..."
garak --model_type openai --model_name gpt-4o-mini --probes promptinject
```
The same pattern works for `anthropic`, `groq`, `cohere` and others. Set the matching `*_API_KEY` and change `--model_type`.

**Option B: a local model** (free, and good for learning):
- If you install Ollama and pull a model, run:
  ```bash
  garak --model_type ollama --model_name llama3.2 --probes promptinject
  ```
- Or use a small Hugging Face model. It downloads on first run and is slow on CPU:
  ```bash
  garak --model_type huggingface --model_name gpt2 --probes encoding
  ```

**Option C: your own app or chatbot** through a REST endpoint. This is the most realistic setup, because you test the whole system rather than the bare model:
```bash
garak --model_type rest -G rest_config.json --probes promptinject
```
The JSON file describes your URL, request template and response field. See garak's `rest` generator docs for the format. See also `my_target.py` in this folder for the case where you can't copy the endpoint from the browser.

Useful flags:
```bash
--probes dan,encoding             # several probes, comma-separated
--probes promptinject.HijackHateHumansMini   # one specific probe class
--generations 5                   # attempts per prompt (more is slower but more reliable)
--report_prefix mytest            # names the report files
--parallel_attempts 8             # speed things up
```

Start small. A full scan of every probe can run for hours and cost real money on paid APIs.

## 6. Read the results

Reports go to `~/.local/share/garak/garak_runs/`:
- `*.report.html` is the human-readable summary. Open it in a browser.
- `*.report.jsonl` is the full record of every prompt and response.
- `*.hitlog.jsonl` holds only the attempts that **succeeded**, meaning the model failed. **This is the file to study.** `show_hits.py` in this folder prints it readably.

Read the hitlog. The prompt and the model's reply show exactly *how* it failed, and that is where most of the learning is. Also note that detectors produce **false positives and false negatives**. Judge a "FAIL" by reading the reply before you trust it.

## 7. Turn findings into fixes

Scanning without fixing isn't securing. This is the loop:

1. **Baseline scan.** Pick 3 to 5 probes that matter for your use case and save the results.
2. **Read the hits.** Sort them into categories: injection, jailbreak, leakage, harmful output.
3. **Apply mitigations:**

   | Finding | Fix |
   |---|---|
   | Prompt injection succeeds | Separate trusted and untrusted input, filter or sanitize retrieved content, grant tools least privilege, require human confirmation for risky actions |
   | Jailbreaks succeed | Stronger system prompt, input and output guardrails (NeMo Guardrails, Llama Guard), a safer base model |
   | System prompt leaks | Never put secrets in the system prompt. Keep API keys and credentials out of the model's context entirely |
   | Encoding bypasses | Decode and normalize input before your safety filter sees it |
   | Package hallucination | Verify any suggested dependency against the real registry before installing |
   | Harmful or toxic output | Output moderation layer, rate limiting, logging |

4. **Re-scan with the same probes and settings.** Compare against the baseline to see whether the failure rate dropped.
5. **Repeat.** Models and attacks change, so this is continuous. Put it in CI to catch regressions.

Garak also supports `guardrails.NeMoGuardrails` as a generator. That lets you scan the model *with* your guardrails in front of it and measure how much they help.

## 8. A learning plan for this week

1. **Day 1:** Run the dry run, list the probes, and read the docs at `https://github.com/NVIDIA/garak`.
2. **Day 2:** Get a local model running with Ollama. Scan it with `promptinject` and read every hit.
3. **Day 3:** Run `dan` and `encoding`. Try to explain *why* each successful attack worked.
4. **Day 4:** Build a small chatbot with a system prompt containing a fake secret. Scan it with `sysprompt_extraction` and `leakreplay`.
5. **Day 5:** Add a mitigation, such as a system prompt rewrite or an output filter. Re-scan and compare the numbers.

To go further, read the OWASP Top 10 for LLM Applications. Garak's probes map roughly onto its categories, so it gives you a framework for what you're testing.
