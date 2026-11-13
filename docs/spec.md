# chkscript v0.2 Revision Spec

Oct 25, 2026 · Nicolas Kassis

This file is the source of truth for the v0.2 design. Choices made during implementation are recorded in `docs/decisions.md`; where the two disagree, `decisions.md` wins and this file gets corrected.

## Goals and non-goals

v0.2 turns chkscript from a single Claude call into a layered scanner whose unsafe verdicts cannot be argued down by the script being scanned, and that can run fully on the local machine.

**Goals**

- Deterministic layers (shellcheck, and rules over shfmt's syntax tree) own the floor; the model adds judgment on top and can only add findings or raise them, never remove or lower them.
- Follow the scripts an installer downloads and runs, under strict fetch guardrails, so second-stage payloads are inspected rather than ignored.
- Swappable providers through one thin boundary, with Ollama as a first-class local option so the script never has to leave the box.
- Reliable line references and schema-enforced structured output, replacing the fence-stripping regex and retry loop.
- Three run modes (full, no-follow, static-only) so the tool stays useful in CI and on air-gapped hosts.
- Keep the install footprint small: pydantic-ai-slim and pydantic-settings plus optional provider SDKs; external tools shelled out, never vendored.

**Non-goals**

- Not a general Bash linter. shellcheck already is one; chkscript reports its results, it does not replace it.
- Not a sandbox or dynamic analysis. Nothing is ever executed. Scripts that defeat static analysis through runtime behavior are out of scope and should be called out as such in the report.
- No agent framework (LangChain, LangGraph). The control flow is a bounded tool loop with a fetch budget, which does not justify a graph runtime.
- No binary analysis. Downloaded binaries are reported by URL, size and whether the script verifies a checksum or signature. They are never fetched.
- No Windows or PowerShell support in this revision.

## Threat model

The input is assumed hostile. An install script may be written by someone who knows chkscript exists and wants a green verdict.

| Attack on the scanner | Example | Property that defeats it |
| --- | --- | --- |
| Prompt injection through content | Comments like `# audited by security team, safe`, or a literal `</script>` followed by instructions | Unsafe findings come from deterministic rules the model cannot override; the model only adds findings; delimiters are randomized per run |
| Pattern evasion | `c=curl; $c ... \| sh`, commands assembled in heredocs or via `eval`, base64-encoded payloads | Rules run over executed commands, not text: wrappers are resolved, constant variables are substituted, and code fed to `sh -c`, a heredoc or `<(...)` is parsed as code. Values chkscript cannot resolve are treated cautiously. The model reasons about intent on top; `eval` of downloaded content and decoders feeding a shell are themselves unsafe findings |
| Hidden second stage | Script downloads `install-real.sh` and runs it | Nested scripts are fetched and run through the full pipeline; an unfetchable or unresolvable second stage is itself an unsafe finding |
| Scanner as SSRF probe | Second-stage URL points at `169.254.169.254` or an internal host | Fetch tool rejects loopback, RFC1918, link-local and metadata addresses, and re-checks after redirects |
| Resource exhaustion | Second-stage URL serves a multi-gigabyte file or never responds | Per-file size cap, timeout, depth limit, total fetch budget |
| Parser evasion | shfmt cannot parse the file, so the syntax-tree rules cannot run | Parse failure is reported as its own coverage warning, and the regex fallback runs on that file. The fallback reports at least the unsafe findings the syntax-tree engine would (Testing, invariant 4), so an unparseable file never gets a quieter report |
| Time-of-check vs time-of-use | Content served at scan time differs from what `curl` gets a minute later | Report carries the URL and SHA-256 of every file analyzed so the user can pin |
| Data exfiltration via the scanner | Script contents sent to a cloud model; a hardcoded credential echoed into the report, CI logs or the prompt | Local mode via Ollama; a one-line notice whenever contents leave the machine; and redaction of what leaves: detected credentials are masked in the model prompt and in every rendered report, in every mode (Static layer, Secrets and redaction) |
| Script supplies its own justification | A header comment or usage text claiming to be a system agent, so root, a service and a cron job all look proportionate | The user can state the purpose with `--expect`; without it the purpose is labeled `claimed` ("as the script describes itself"); reviewer-directed text is withheld from the model before it infers a purpose (NIM-152). Justification is descriptive and never changes a finding |

Justification and the footprint summary never touch severity. A model that judges a capability `needed` lowers nothing, and one that judges it `unexplained` raises nothing by doing so; a raise still goes through the capability-to-unsafe path with its own reason (Merge rules).

Two properties are non-negotiable and every later section is checked against them. First, no text inside a scanned script can lower the severity of a deterministic finding. Second, the scanner never executes anything it is analyzing, and never fetches anything it was not literally told about by a script already in hand.

Because nothing can lower the floor, the unsafe floor contains only patterns that are never legitimate in an installer. Behavior that is powerful but normal for an installer, such as running as root, installing a systemd unit or writing to `/usr/local`, is a `capability` finding: reported, exit 1, and open to the model raising it to unsafe with a reason. If a rule that fires on normal installer behavior sat in the floor, that installer would be unsafe permanently, with nothing able to correct it.

## Pipeline overview

```mermaid
flowchart TD
    entry["Entry script (file or stdin)"] --> pre["Preprocess<br/>number lines; extract URLs as allowlist"]
    pre --> static
    subgraph static["Static layer: deterministic"]
        sc["shellcheck<br/>lint findings, warning"]
        sf["shfmt --to-json<br/>syntax tree to command model"]
        rules["Python rules over commands<br/>capability: warning<br/>unsafe: the floor, model cannot lower"]
        rx["regex fallback<br/>shfmt missing or parse failure"]
        sf --> rules
    end
    sf -- "heredoc written to a file<br/>that is later run or installed" --> gen["Generated child file<br/>marked generated"]
    gen -- "scanned as its own file" --> pre
    static -- "findings passed as data" --> llm["LLM layer (pydantic-ai)<br/>intent, verification, obfuscation<br/>adds findings, may raise capability to unsafe<br/>never removes or downgrades"]
    llm -- requests --> fetch["fetch_script tool<br/>allowlist; https; no private hosts<br/>size, depth, budget, redirect caps"]
    fetch -- "fetched script re-enters" --> pre
    llm --> report["Report<br/>findings merged, max severity<br/>capability section, fetch tree with hashes, exit code"]
```

*A refused fetch is itself an unsafe finding.*

Every script, including each one fetched on the model's request and each generated child file, passes through preprocessing and the static layer before the model sees it; the model's findings are merged on top, and severity only ever goes up.

## Static layer

The static layer runs first, on every script including fetched and generated ones, and produces findings that the model cannot lower or remove.

**Preprocessing**

1. Decode as UTF-8 with replacement, normalize line endings, reject files over 500 KB.
2. Number every line (`   42 | curl ... `). This numbered form is what the model sees, so `line_reference` is an integer the model copies rather than estimates.
3. Extract URL candidates: every `https?://` literal, plus assignments that feed `curl`, `wget`, `fetch` or `git clone`. Record each with its line and whether it is literal or variable-built. This set is the fetch allowlist for the LLM layer.
4. Detect hardcoded secrets (`redact.py`) and build the masked numbered form, the only form a model is sent. See Secrets and redaction.

**Secrets and redaction**

A hardcoded credential is bad practice whatever chkscript does with it, and chkscript must not become the way it leaks. Detection is deliberately basic and misses are expected; verified-secret scanning is pre-commit's job, not chkscript's.

- *Detection.* Known formats: `sk-ant-`, `sk-proj-` and `sk-`, `ghp_`, `gho_`, `github_pat_`, `xoxb-` and `xoxp-`, `AKIA` key ids and, when one is present, their paired 40-character secrets, `-----BEGIN ... PRIVATE KEY-----` blocks, and JWTs. Plus one heuristic: a variable whose name contains `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `APIKEY` or `API_KEY` assigned a literal of 8 or more characters, excluding expansions, URLs, paths and `.env.example`-style placeholders (`your-key-here`, `changeme`). No entropy scanning.
- *Masking.* Each distinct value gets one stable placeholder, `[SECRET-<n>:<kind>]`, used for every occurrence, so the model can still follow a value from where it is defined to where it is sent. A multi-line value keeps its line count, so line numbers do not move.
- *Where it applies.* The static rules, shellcheck and the report's hashes see the original bytes; redaction changes nothing about static analysis or the floor. The model prompt is built from the masked form, for the entry script and every fetched or generated child file. Every text field of the report (summary, notes, finding descriptions and snippets) is masked before it is rendered to the terminal or JSON. Masking is always on, including `--static-only` and local models; there is no `--no-redact`.
- *Finding.* Each distinct value produces one `hardcoded-secret` finding (`source: chkscript`, `capability`, `warning`) naming its placeholder and lines, with a masked snippet and the remediation: move it to an env file or pass it through the environment. Values first seen on the same line share one finding. The model may raise it to `unsafe` with a reason, for example when the value is sent to a host unrelated to the project.
- *Notice.* When at least one fires, one stderr line, whatever the number of secrets: "This script contains what looks like a live credential (<kinds>). This report masks it, but the script file itself does not: do not commit, share or paste the script." Suppressed by `--quiet`; never on stdout or in JSON.

**shellcheck (lint)**

- Shelled out via `shellcheck -f json -`; absent on PATH means lint is skipped with a notice, not an error.
- Every shellcheck finding becomes `category: lint`, severity `warning`, with `source: shellcheck` and the SC code. No severity is promoted to `unsafe` from this layer.
- A small suppression list for codes that are noise on install scripts (to be tuned against the fixture set).

**Parser: shfmt**

- The static engine is `shfmt --to-json`, shelled out with the script on stdin. shfmt parses all 11 installers in the real-installer corpus (`tests/corpus/`).
- Its tree is the reason for the choice. Operators come out as strings (`|`, `<(`, `>>`, `<<`), so pipes, process substitution and redirects are matched on structure rather than text. Heredoc bodies are text attached to their redirect, never commands, so a heredoc printed to the user cannot fire a rule.
- shfmt is an external tool on PATH, like shellcheck, at a minimum version that supports `--to-json` (see Dependencies and packaging). A missing or older shfmt means the regex fallback runs, with a notice.

**Command model**

The syntax tree is turned into a list of executed commands. Rules are Python functions over that list, not YAML and not regexes over text.

- *Only real commands count.* Heredocs printed to stdout and text inside strings are data. A rule never fires on them.
- *Wrappers are resolved.* `sudo`, `env`, `command`, `exec`, `nohup` and `doas`, with their flags, are stripped to the command they run, and the command records that it runs as root where the wrapper implies it. So is any function whose body runs `"$@"`; in Homebrew's installer that finds `execute`, `execute_sudo` and `retry`.
- *Constants are substituted.* A variable or array whose every assignment is a literal resolves to that set of values: Homebrew's `CHMOD=("/bin/chmod")` resolves to `chmod`, and `c=curl; $c ... | sh` resolves to `curl ... | sh`. Any other value is unknown, and rules treat unknown values cautiously: an unknown command fed a download, or an unknown path given to `rm -rf`, is judged as the dangerous case.
- *Embedded code is parsed as code.* The heredoc fed to `sh` or `bash`, the literal in `bash -c '<literal>'`, and the commands inside `<(...)` and `$(...)` are parsed and added to the command list.
- *Generated scripts are scanned as their own files.* A heredoc written to a file that is later executed, installed, or made executable is scanned as a child file, marked `generated`, with findings attributed to it rather than to the parent. This covers k3s's killall and uninstall scripts: not install-time code, but code that runs later on the machine.
- *Downloads are tracked per output path.* Each `curl -o`, `wget -O` or redirect to a file records the URL and the path it wrote, so verification and execution are judged per file, and a finding lands on the line that downloads or runs that file.

**Finding categories**

Every finding carries a `category`, which decides its severity and where it appears in the report.

| Category | Meaning | Severity | Exit |
| --- | --- | --- | --- |
| `lint` | shellcheck output | `warning` | 1 |
| `capability` | Powerful but normal for an installer. Shown in its own report section, "what this script will do to your machine" | `warning` | 1 |
| `unsafe` | Never legitimate in an installer. This is the floor | `unsafe` | 2 |

The model may raise a `capability` finding to `unsafe`, with a reason. Nothing lowers any finding (LLM layer, merge rules).

**Classification**

| Category | Rules |
| --- | --- |
| unsafe | remote code chkscript could not inspect (`curl \| sh` and other interpreters, `bash <(curl ...)`, `sh -c "$(curl ...)"`, a downloaded script run unverified, `eval` of downloaded content); plain `http://` downloads; TLS verification disabled; decoded data fed to a shell; writes to sudoers, passwd, shadow or `ld.so.preload`; disabling SELinux, a firewall or a security service; `rm -rf` on an unguarded `"$VAR/..."` or an unquoted variable; world-writable files; setuid/setgid in a user-writable directory; and, when built, credential exfiltration, reverse shells, SSH key planting, package-trust bypass (`trusted=yes` and similar), PATH/LD_PRELOAD hijacking |
| capability | runs as root; installs a systemd unit, cron job, or shell rc or profile change; writes to system paths (`/usr/local`, `/opt`, `/usr/bin`); a downloaded binary whose integrity rests on TLS only; `eval` of the user's own environment; `rm -rf` on a quoted or guarded variable; setuid in a system path; adding a signed package repository, with its key's scope; adding a user to a root-equivalent group (`docker`, `lxd`, `libvirt`, `disk`); running a nested script that chkscript fetched and scanned (phase 4); a hardcoded credential (`hardcoded-secret`, `source: chkscript`, which some vendors embed legitimately in per-account installers) |

- `unverified-download` is a capability, not unsafe. A checksum fetched from the same server over the same connection adds little: whoever can swap the binary can swap the checksum. Real added trust comes from a signature checked against a key obtained elsewhere, or a checksum pinned in the script itself. The downgrades that matter, `http://` and TLS verification off, stay unsafe.
- `rm-rf-variable` is split. `rm -rf "$VAR/..."` with no guard that `VAR` is set, or `rm -rf` on an unquoted variable, is unsafe, because an empty or word-split value reaches `/` or an unintended path. `rm -rf` on a quoted or guarded variable (`"$TMP_DIR"`, `"${VAR:?}/..."`, a preceding `[ -n "$VAR" ]`) is a capability.
- Each rule carries a one-line rationale in its message, which is what the model and the user both see.
- Rule findings use `source: shfmt`, after the parser that produced the tree, as shellcheck findings use `source: shellcheck`.
- `root-equivalent-group` (capability) fires on `usermod -aG`, `gpasswd -a` or `adduser <user> <group>` adding to `docker`, `lxd`, `libvirt` or `disk`. Membership in any of them is root in practice. Adding to `sudo` or `wheel` is not this rule; it belongs to `rogue-account` (NIM-110), which is unsafe.
- `package-repo-added` (capability) records its key's scope: `scoped` when the repo is pinned to a `signed-by` keyring, `global` for `apt-key add` or a key written to `/etc/apt/trusted.gpg` or `/etc/apt/trusted.gpg.d/`. The message names the scope. A global key trusts that vendor for every package on the machine, but it is still a capability, consistent with NIM-97 leaving `apt-key add` out of the unsafe tier.

**Footprint groups**

Every capability rule declares exactly one footprint group. The groups are the vocabulary of the report's "What this script will do to your machine" section and of the footprint summary (Output and exit codes). A capability rule without a group fails a test, so no new rule can skip it. Lint and unsafe rules have no group.

| Group | Rules (current and planned) | Plain words when absent |
| --- | --- | --- |
| `root` | `runs-as-root` | (stated by the `NEEDS` line instead) |
| `persistence` | `persistence-append` (systemd unit, cron, shell rc or profile) | services, cron jobs, shell config |
| `system-write` | `system-path-write`, `setuid-system` | system file writes |
| `trust` | `package-repo-added`, `root-equivalent-group` | repos or group changes |
| `download` | `unverified-download` (TLS only), nested script fetched and scanned (phase 4) | (stated by the `NEEDS` line instead) |
| `other` | `eval-dynamic`, guarded `rm-rf-variable`, `reviewer-directed-text` (NIM-152), `hardcoded-secret` (NIM-151) | (never listed as absent) |

Trust grants are a group of their own because they are the least visible and the longest lived. Adding a user to `docker` gives them root for as long as the membership lasts, and a global apt key outlives the install. Neither is an attack, and neither looks alarming in the script.

A capability finding the model raised to unsafe keeps its group, so the footprint still counts it.

**Regex fallback and parse failures**

- A plain-regex implementation lives in `static/regex_rules.py`. It runs only when shfmt is absent from PATH or older than the minimum version, or on a file shfmt cannot parse. It is never a second opinion on a file shfmt parsed.
- A regex finding has `source: regex` and the same `rule_id`, `category` and message as the syntax-tree rule it stands in for.
- The fallback has no syntax tree, so it over-reports: it cannot tell a heredoc from a command, or a guarded `rm -rf` from an unguarded one. That is deliberate. On every corpus file it reports at least the unsafe findings the syntax-tree engine reports (Testing, invariant 4), so losing the parser never lowers the floor.
- A parse failure, crash or timeout produces its own `warning`, `source: chkscript`: "shfmt could not parse this file; static coverage reduced." This is deliberate, because a script that is unparseable on purpose should not get a quieter report.
- When shfmt is absent, the tool prints a one-line notice that only the regex rules ran, and still produces a report.

**Deduplication**

shellcheck, syntax-tree and regex findings on the same line and rule family are merged into one finding keyed on `(file, line, rule_id)`, keeping the highest severity and listing all sources.

## LLM layer

The model owns intent: what the script installs, from where, whether downloads are verified, and whether anything looks obfuscated or deceptive. It runs after the static layer and receives its findings as input.

**Boundary**

- One class, `LLMAnalyzer`, in `analyzer.py`, with a single method: `analyze(bundle: ScriptBundle, static: list[Finding], allowlist: set[str]) -> LLMResult`.
- Nothing outside `analyzer.py` imports `pydantic_ai`. Replacing the library later is a one-file change.

**Agent**

- Built on `pydantic-ai-slim` with the `anthropic` and `openai` extras. The agent's output type is `LLMResult`, a Pydantic model: `summary: str`, `findings: list[Finding]`, `notes: list[str]`, `fetched: list[FetchRecord]`, `purpose: str`, `assessments: list[CapabilityAssessment]`. `LLMResult` also carries `purpose_source: "user" | "claimed"`, which chkscript sets after the call and the model's output schema does not include (Justification, below).
- Output mode is `NativeOutput` (schema enforced during generation) where the provider supports it, falling back to `ToolOutput`. This replaces the fence-stripping regex and the parse-and-retry loop.
- `temperature=0` on every provider that accepts it, so the same script yields the same verdict.
- `max_tokens` sized from the input: findings for a 500 KB script will not fit in 4096 tokens, so the budget scales with line count and truncation is detected from the stop reason and reported as an error rather than a partial result.

**Prompt contract**

- System prompt states the role, the severity and category definitions, and that the model may add findings and may raise a `capability` finding to `unsafe` with a reason, but must not dispute, lower or omit any finding it was given.
- Script content is wrapped in a delimiter randomized per run (`<script-7f3a9c>` ... `</script-7f3a9c>`), with the line-numbered form, so a literal `</script>` inside the file does nothing.
- Static findings are passed as structured data, not prose, with their `source`, `rule_id` and `category`.
- The model is asked specifically for: what gets installed and where; every network destination and whether it is verified; whether the script fetches and runs further content; signs of obfuscation; and anything the static rules missed.
- The model states the script's purpose in one sentence, then assesses each capability finding it was given against that purpose: `needed`, `avoidable` or `unexplained`, with a one-line reason. An alternative must cite the line where the script supports it (an install-dir variable it honors, a flag it parses).
- When the user gave `--expect`, that text goes into the prompt outside the script delimiter, labeled as the user's statement of purpose, and the model judges against it rather than inferring one. Behavior the stated purpose does not account for (asked for a CLI, the script also installs a service and a cron job) is what `unexplained` is for, and is evidence a capability-to-unsafe raise may cite.
- The script text the model reads, for findings and for the purpose alike, is the masked form (NIM-151 secrets, NIM-152 reviewer-directed text), so text addressed to a reviewer can never become the stated purpose.

**Merge rules**

- Model findings are tagged `source: llm`.
- A model finding on the same line and rule family as a static finding is merged into it (its description is kept as explanation). A model finding with no static counterpart stands alone.
- Severity of the merged report is the maximum across all sources. The model's severity can raise a line, never lower it.
- The model may raise a `capability` finding to `unsafe`, and must give a reason (for example, the cron job it installs re-downloads and runs a script every hour). The merged finding becomes `category: unsafe`, severity `unsafe`, keeps its static `rule_id`, lists `llm` in `merged_from`, and carries the model's reason in its description. A raise with no reason is ignored.
- Nothing lowers anything. The model cannot move an `unsafe` finding to `capability`, a `capability` finding to `lint`, or drop a finding.
- If the model call fails, the static report is still emitted, with a `warning` from `chkscript` that the LLM layer did not run, and the exit code reflects static findings only.
- Assessments, `purpose` and `purpose_source` are outside the merge. They are never fed into it, into the floor check or into the exit code.

**Justification**

The verdict answers "is this hostile or broken?". Justification answers a separate question: "what will this do to my machine, and is that proportionate?". It is descriptive. It attaches to capability findings in the report and changes nothing about them.

`CapabilityAssessment`:

| Field | Type | Meaning |
| --- | --- | --- |
| `file` | str | File of the capability finding assessed |
| `line` | int or null | Its line |
| `rule_id` | str | Its rule |
| `verdict` | `needed` \| `avoidable` \| `unexplained` | Against the purpose |
| `reason` | str | One line |
| `alternative` | str or null | A way to do it with less, which the script supports |
| `alternative_line` | int or null | Where the script supports it |

Rules, enforced by chkscript after the call, not by the prompt:

- An assessment is keyed on `(file, line, rule_id)`. One whose key matches no capability finding in the merged report is dropped, as is a second assessment for the same key.
- `alternative` is kept only together with an `alternative_line` that is a line of the same file. Otherwise it is dropped and the verdict and reason stay. chkscript checks that the line exists, not that the model read it right; the user sees the cited line and can check it.
- A capability finding with no assessment is rendered without one. The report never invents a verdict.
- `purpose_source` is set by chkscript, not taken from the model: `user` when `--expect` was given, and then `purpose` is the user's text verbatim; otherwise `claimed`, and `purpose` is the model's sentence.
- In `--static-only`, or when the model call fails, there is no purpose and no assessment.

**Model-dependent degradation**

- A provider or model without tool support runs with the fetch tool withheld (equivalent to `--no-follow`), with a notice.
- Small local models are easier to inject than frontier ones. That is acceptable only because the floor is held by the static layer; this is the reason the static layer exists at all.

## Nested script fetching

The model decides which referenced scripts are worth reading. chkscript decides whether a fetch is permitted, performs it, and runs the result through the full pipeline before the model sees a line of it.

**The tool**

`fetch_script(url: str, reason: str) -> FetchResult` is the only tool the agent has. `reason` is recorded in the report so the user can see why each fetch happened. The tool returns either the numbered content plus that file's static findings, or a refusal with a code the model must report as a finding.

**Guardrails, enforced in the tool, not in the prompt**

| Rule | Value | On violation |
| --- | --- | --- |
| URL must appear in the allowlist | Literal URLs from any script already analyzed in this run; a variable-built URL is allowed only if its host is a literal in the script | Refused, `not_in_script` |
| Scheme | `https` only | Refused, `insecure_scheme`; plain `http` download is also an `unsafe` static finding |
| Destination | No loopback, RFC1918, link-local, `169.254.169.254`, `.local`, `.internal`; DNS resolved and checked before connect and again after every redirect | Refused, `private_destination` |
| Content type | `text/*` or `application/x-sh`; anything else gets a HEAD only and its size and type are recorded | Refused, `not_text`, with HEAD metadata |
| Size | 500 KB per file, read with a hard cap, not trusting `Content-Length` | Refused, `too_large` |
| Timeout | 10 s connect, 20 s total | Refused, `timeout` |
| Depth | 2 by default (`--depth`), max 4 | Refused, `depth_exceeded` |
| Budget | 5 fetches per run (`--max-fetches`) | Refused, `budget_exhausted` |
| Redirects | Max 3, each re-validated against every rule above | Refused, `redirect_rejected` |

**What a refusal means for the verdict**

Any refused fetch of something the script would execute produces an `unsafe` finding, `source: chkscript`, "executes remote content that could not be inspected". The attacker does not get a quieter report by making the second stage unreachable.

**Recursion**

A fetched file goes through preprocessing, shellcheck and the syntax-tree rules (or the regex fallback) before it is returned to the model, and its URLs are added to the allowlist for the next depth. Findings carry the file they came from. Binaries are never fetched; their URL, size and the presence or absence of checksum verification in the calling script are reported instead.

**Report**

The fetch tree is part of every report, whether or not findings exist: for each file, its URL, depth, parent, SHA-256, size and the reason the model gave. The entry script is the root with the hash of what was read from the file or stdin. This is the user's handle on time-of-check versus time-of-use.

## Providers and models

Model selection is one string in pydantic-ai's `provider:model` form, so no provider logic lives in chkscript beyond auto-detection and the leaves-the-box notice.

| Provider | Selector example | Install extra | Reaches | Structured output |
| --- | --- | --- | --- | --- |
| Anthropic | `anthropic:claude-sonnet-5-5` | `anthropic` | api.anthropic.com | Tool-based |
| Ollama (local) | `ollama:gpt-oss:20b` | `openai` | `OLLAMA_BASE_URL`, default `http://localhost:11434/v1` | Native JSON schema, enforced during generation (Ollama 0.5+) |
| OpenAI-compatible | `openai:<model>` with `OPENAI_BASE_URL` | `openai` | vLLM, llama.cpp server, OpenRouter, hosted providers | Varies; tool-based fallback |

**Default model**

Defaults live in `src/chkscript/config.py` and nowhere else, as provider aliases rather than dated snapshots (v0.1's `claude-sonnet-4-20250514` was retired and returned 404):

- Hosted: `anthropic:claude-sonnet-5-5`. Until phase 3 replaces the v0.1 analyzer, `config.py` stores the bare `claude-sonnet-5-5` because that analyzer passes the string straight to the Anthropic SDK; phase 3 switches it to the prefixed form so both defaults use `provider:model`.
- Local: `ollama:gpt-oss:20b`. The Ollama tag is `gpt-oss:20b`; pydantic-ai strips the `ollama:` prefix and passes the rest to Ollama. Chosen because it supports tool calling and structured output and fits in 16 GB of VRAM; provisional until the `--run-live` fixture suite confirms it holds on the injection fixtures.

Any model can be selected with `--model` or `CHKSCRIPT_MODEL`.

**Auto-detection, in order**

1. `--model` flag or `CHKSCRIPT_MODEL` if set.
2. `ANTHROPIC_API_KEY` present: Anthropic with the default alias.
3. Ollama answers on `localhost:11434`: the local default if it is installed, else the first installed model that reports tool support, else the first installed model in no-follow mode.
4. Otherwise: static-only, with a one-line notice naming the two ways to enable the LLM layer.

**Data-leaves-the-box notice**

Whenever the selected endpoint is not loopback, the terminal output starts with one line: `Script contents will be sent to <host> for analysis.` This covers Anthropic, any OpenAI-compatible host, and an `OLLAMA_BASE_URL` pointed at Ollama Cloud or another machine. It is printed once, to stderr, and suppressed by `--quiet`.

**Capability probing**

Before the first call, chkscript checks whether the chosen model supports tools (from the provider's model metadata where available, otherwise by attempting the call once with the tool attached and catching the provider's rejection). A model without tool support runs in no-follow mode with a notice.

## Run modes and CLI

Three modes cover the environments the tool runs in. The default is full analysis.

| Mode | Flag | Static layer | LLM layer | Fetches nested scripts | When |
| --- | --- | --- | --- | --- | --- |
| Full | (default) | Yes | Yes | Yes | Interactive use before running an installer |
| No-follow | `--no-follow` | Yes | Yes | No | Analysis only of what is in hand; also the automatic fallback for models without tool support |
| Static-only | `--static-only` | Yes | No | No | CI on every commit, air-gapped hosts, no model available |

**Invocation, unchanged from v0.1**

```
chkscript install.sh
curl -fsSL https://example.com/install.sh | chkscript
chkscript --json install.sh | jq '.findings[] | select(.severity == "unsafe")'
```

**Flags**

| Flag | Default | Purpose |
| --- | --- | --- |
| `FILE` | stdin | Script to analyze |
| `--model` | auto-detect | `provider:model` selector |
| `--no-follow` | off | Withhold the fetch tool |
| `--static-only` | off | Skip the LLM layer entirely |
| `--depth N` | 2 | Max nested fetch depth, capped at 4 |
| `--max-fetches N` | 5 | Total fetch budget per run |
| `--fail-on {warning,unsafe}` | `warning` | Lowest severity that produces a non-zero exit; `unsafe` makes warnings informational |
| `--expect TEXT` | none | What the user expects the script to do (`--expect "install the k3d CLI"`); capabilities are judged against it instead of the purpose the script claims. No effect in `--static-only` |
| `--json` | off | Machine-readable output |
| `-v`, `--verbose` | off | Show snippets for every finding and the full fetch tree |
| `--quiet` | off | Suppress notices on stderr |
| `--no-color` | auto | Disable ANSI colors (also honors `NO_COLOR`) |

`--api-key` is deliberately absent; secrets never go on the command line.

**Precedence**

Flags override `CHKSCRIPT_*` environment variables, which override provider environment variables, which override auto-detection.

## Configuration and secrets

chkscript invents no secret variables of its own. Provider secrets use the names the provider SDKs already read; chkscript adds a `CHKSCRIPT_` namespace only for selection and limits.

**Provider variables (read by the SDKs, unchanged)**

| Variable | Provider | Notes |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | Anthropic |  |
| `OPENAI_API_KEY`, `OPENAI_BASE_URL` | OpenAI-compatible | `OPENAI_BASE_URL` points the same SDK at vLLM, OpenRouter, etc. |
| `OLLAMA_BASE_URL` | Ollama | Default `http://localhost:11434/v1`; `OLLAMA_HOST` is also honored and converted |
| `OLLAMA_API_KEY` | Ollama Cloud | Only needed for a non-local Ollama endpoint |

**chkscript variables**

| Variable | Equivalent flag | Purpose |
| --- | --- | --- |
| `CHKSCRIPT_MODEL` | `--model` | `provider:model` selector |
| `CHKSCRIPT_DEPTH` | `--depth` | Nested fetch depth |
| `CHKSCRIPT_MAX_FETCHES` | `--max-fetches` | Fetch budget |
| `CHKSCRIPT_FAIL_ON` | `--fail-on` | Exit threshold |
| `CHKSCRIPT_NO_FOLLOW` | `--no-follow` | `1` to withhold the fetch tool |
| `CHKSCRIPT_EXPECT` | `--expect` | User-stated purpose for justification |

**`_FILE` suffix**

Any `*_API_KEY` above may instead be given as `*_API_KEY_FILE=/path`. chkscript reads the file, strips one trailing newline, and sets the variable in its own process before the SDK initializes. This matches the Docker secrets and systemd credentials convention.

**Rules**

- No key ever appears in output, including error messages, verbose mode and JSON. The existing "ANTHROPIC_API_KEY not set" message is the ceiling for detail.
- No secret is accepted on the command line.
- Nothing is read from config files in this revision; a `~/.config/chkscript/config.toml` for non-secret defaults is listed under open questions.

**Precedence table**

| Priority | Source | Example |
| --- | --- | --- |
| 1 | Command-line flag | `--model ollama:gpt-oss:20b` |
| 2 | `CHKSCRIPT_*` variable | `CHKSCRIPT_MODEL=ollama:gpt-oss:20b` |
| 3 | Provider variable presence | `ANTHROPIC_API_KEY` set implies Anthropic |
| 4 | Auto-detection | Ollama reachable on localhost |
| 5 | Static-only | Nothing above applies |

## Output and exit codes

The v0.1 exit code contract is kept so existing pipes keep working; the finding schema grows to say where each finding came from and which file it is in.

**Finding schema (JSON)**

```
{
  "severity": "unsafe" | "warning",
  "category": "unsafe" | "capability" | "lint",
  "source": "shellcheck" | "shfmt" | "regex" | "llm" | "chkscript",
  "rule_id": "SC2086" | "curl-pipe-sh" | "llm.unverified-download" | ...,
  "file": "<entry>" | "https://..." | "/usr/local/bin/k3s-killall.sh",
  "generated": false,
  "line": 42 | null,
  "description": "...",
  "snippet": "..." | null,
  "merged_from": ["shfmt", "llm"],
  "group": "root" | "persistence" | "system-write" | "trust" | "download" | "other" | null
}
```

`category` and `severity` always agree: `unsafe` is severity `unsafe`, `capability` and `lint` are severity `warning`. A model raise changes both together. `chkscript`'s coverage notices (shfmt parse failure, LLM layer did not run) are `category: lint`; its refused-fetch finding is `category: unsafe`. `generated` is true for findings in a generated child file, whose `file` is the path the heredoc was written to. `group` is the footprint group of a capability rule, kept after a model raise to unsafe, and null for every other finding.

Top level adds `fetch_tree`, `mode` (which of the three ran), `model` (selector actually used, or null), `static_tools` (which of shellcheck, shfmt, regex ran), `footprint`, `purpose` (string or null), `purpose_source` (`user`, `claimed` or null) and `assessments` (a list of `CapabilityAssessment`, empty without a model), and keeps `summary`, `findings`, `notes`, `max_severity`.

**Footprint summary**

The footprint is computed by chkscript from the merged findings and the downloads the command model recorded, never by the model, so `--static-only` shows it too. It covers every file in the run, since a generated child file that installs a service is still the machine's footprint.

```
"footprint": {
  "privilege": "user" | "root" | null,
  "persistence": true | false | null,
  "network_hosts": ["github.com", "(unresolved)"],
  "coverage": "full" | "reduced",
  "unresolved_at": [{"file": "<entry>", "line": 42}],
  "absent": ["persistence", "trust"] | null
}
```

- `privilege` is `root` when any `runs-as-root` finding exists. `persistence` is true when any `persistence` group finding exists.
- `network_hosts` are the distinct hosts of the URLs the script downloads from (per-path download tracking in the command model; under the regex fallback, the hosts of the preprocessing URL candidates that feed a download command). A download whose host is not a constant adds `(unresolved)`, so a variable-built URL cannot shrink the list.
- `coverage` is `reduced` when the regex fallback ran on any file in the run, or shfmt failed on one. `unresolved_at` lists every `eval-dynamic` finding and every unknown command fed a download.
- `absent` lists the groups among `persistence`, `system-write` and `trust` that have no finding. It is null unless `coverage` is `full` and `unresolved_at` is empty, because a statement that something is absent is a claim, and a quieter report must never be what an evasive script earns. Under the same condition, a `privilege` of `user` and a `persistence` of false become null: chkscript states a negative only when it can back it.

**Terminal output**

The default (non-verbose) report reads top to bottom as verdict, footprint, justification, concerns, record. Illustrative, for a CLI installer with one unsafe line:

```
chkscript · install.sh · full · anthropic:claude-sonnet-5-5 · shellcheck, shfmt

VERDICT   UNSAFE   1 unsafe · 4 lint (-v to show)
NEEDS     root · no persistent changes · downloads from 2 hosts

Purpose (as the script describes itself): installs the k3d CLI

What this script will do to your machine
  root          Runs commands as root (3 places)                   L142
                Needed: writes to a system bin directory
  system-write  Installs /usr/local/bin/k3d                        L142
                Avoidable: set K3D_INSTALL_DIR to a user directory  L23
  download      Downloads k3d verified only by TLS                 L88
  No other changes found: no services, cron jobs, shell config, repos or group changes

Concerns
  UNSAFE  L91  Downloaded content is piped into a shell
               curl -fsSL "$url" | sh

Analyzed
  <entry>  sha256 3f9a1c…  4.1 KB
```

- **Header line**: file, mode, model, static tools. The leaves-the-box notice stays on stderr.
- **`VERDICT`**: `SAFE`, `WARNING` or `UNSAFE` from `max_severity`, then counts by category. Lint is folded unless `-v`.
- **`NEEDS`**: the footprint in one line. `root` or `user`; `persistent changes` or `no persistent changes`; `downloads from N hosts` (with `(N unresolved)` when any are) or `no downloads`. Where the footprint field is null, the term reads `root not ruled out` or `persistence not ruled out`.
- **Purpose**: from `purpose`, labeled `(as the script describes itself)` when `purpose_source` is `claimed` and `(as you stated it)` when `user`. Absent without a model.
- **What this script will do to your machine**: capability findings as short plain lines, grouped by footprint group with the group as a label, each with its line (and its file, when it is not the entry script). Findings of one rule in one file collapse into one line with a count and the first line; `-v` expands them. Under each line, an optional second line renders its assessment: `Needed:`, `Avoidable:` or `Unexplained:`, then the alternative and its line when there is one, otherwise the reason. A collapsed line shows the most concerning verdict among its findings (`unexplained`, then `avoidable`, then `needed`). The formatter renders that second line from data; nothing about it is special-cased.
- **Absence line**, ending the section, one of: `No other changes found: no <plain words of each absent group>` (Footprint groups table; omitted when no group is absent); `Not checked: static coverage reduced` when `coverage` is `reduced`; `Other changes possible: the script runs code chkscript could not resolve (line N)` for the first entry in `unresolved_at`. When both of the last two apply, both lines are shown.
- **Concerns**: unsafe findings, each with its snippet, as before. A capability raised to unsafe appears here, with the model's reason.
- **Analyzed**: the fetch tree. URL, depth, SHA-256 (first 12 characters, full in JSON), size, and the model's stated reason. Always shown, since it is the record of what was actually analyzed.
- `--static-only`: no Purpose line and no assessment lines, and the capability section ends with one line, `Run with a model to get a justification for each.`
- Colors via ANSI only when stdout is a TTY, and off under `NO_COLOR` or `--no-color`.

**Exit codes**

| Code | Meaning | Note |
| --- | --- | --- |
| 0 | No finding at or above `--fail-on` | With `--fail-on unsafe`, a warnings-only run exits 0 |
| 1 | Highest finding is `warning` | Default threshold. Covers `capability` and `lint` findings alike |
| 2 | At least one `unsafe` finding | Includes refused fetches of executed content and capability findings the model raised to unsafe |
| 3 | Error: bad input, oversized script, config error, CLI usage error, provider failure with no static result | LLM failure with a static result is exit 1 or 2 from the static findings, plus a notice. argparse exits 2 on a usage error by default, which collides with "unsafe"; it must be mapped to 3 (NIM-74) |

`--fail-on unsafe` exists because shellcheck-grade warnings appear in nearly every real installer, and an exit code that fires on all of them is not a gate anyone keeps.

Capability findings exit 1, like lint, so the exit code contract is unchanged: `capability` is a new category, not a new severity. A script that only does powerful-but-normal things exits 1 by default and 0 under `--fail-on unsafe`.

## Dependencies and packaging

The install footprint is pydantic-ai-slim and pydantic-settings plus optional provider SDKs. External analyzers are shelled out, never vendored or pip-installed by chkscript.

| Dependency | Kind | Why | Alternative rejected |
| --- | --- | --- | --- |
| `pydantic-ai-slim` | Required | Structured output, tool loop, provider adapters in one boundary | Hand-rolled adapters (viable fallback if the library disappoints; the boundary makes it a one-file swap) |
| `pydantic-ai-slim[anthropic]` | Optional extra | Anthropic provider |  |
| `pydantic-settings` | Required | `CHKSCRIPT_*` parsing and validation in `config.py`; the global default for anything that reads env, and small since pydantic is already present | Hand-parsing `os.environ` |
| `pydantic-ai-slim[openai]` | Optional extra | Ollama and every OpenAI-compatible endpoint |  |
| `httpx` | Transitive | Used directly for the fetch tool so there is one HTTP client | `requests`, `urllib` |
| `shellcheck` | External, on PATH | Lint findings | Vendoring the binary |
| `shfmt` v3.14.0 or later | External, on PATH | Syntax tree (`--to-json`) for the capability and unsafe rules | `shfmt-py`: one maintainer's repackaging of the binary, a supply-chain trust a security tool should not take on. Semgrep: parses 5 of the 11 corpus installers, and its rules fire on heredoc text that never runs |
| LangChain / LangGraph | Not used |  | Control flow is a bounded tool loop, not a graph |
| LiteLLM-style all-in-one gateways | Not used |  | 168 MB tree, March 2026 trojanized-release incident |

**Install paths**

- `uv tool install chkscript[anthropic]` or `[openai]` or `[all]` once published to PyPI; `uv tool install git+https://github.com/nkassis/chkscript` until then.
- `pipx install` works the same way.
- The README states plainly that shellcheck and shfmt are recommended and how to install each on Debian, Arch and macOS, and from the upstream shfmt release binary (checksum verified) where the distribution package is older than v3.14.0 (the first release whose `--to-json` writes operators as strings).

**Python version**

`requires-python = ">=3.11"`, down from 3.13. Nothing in the codebase needs 3.12 or 3.13, pydantic-ai supports 3.10+, and a wider floor removes a reason for people not to install it.

**Layout**

```
src/chkscript/
  cli.py           argparse, mode selection, orchestration
  config.py        env and flag resolution, _FILE handling, precedence
  preprocess.py    numbering, URL extraction, size checks
  static/
    shellcheck.py
    shfmt.py         runs shfmt --to-json, version check, parse failures
    commands.py      syntax tree to command model: wrappers, constants, embedded code, generated files, downloads
    rules/           rules as Python functions over the command model; ids and messages in catalog.py
    engine.py        shfmt tree, command model, rules, findings
    regex_rules.py   fallback when shfmt is missing or a file will not parse
    merge.py
  fetch.py         fetch_script tool, allowlist, guardrails, fetch tree
  analyzer.py      LLMAnalyzer, the only pydantic-ai import
  models.py        Finding, FetchRecord, Report (Pydantic)
  formatter.py     terminal and JSON
```

Phase 2b (NIM-122) settled these module names. Semgrep's `semgrep.py` and `rules/*.yml` are removed.

## Conventions from claude-code-patterns

The revision adopts the `stacks/python` starter and the `security/` layer from nkassis/claude-code-patterns (main at `7e54024`), applied during the scaffold phase. The starter enforces each rule at four points (CLAUDE.md, a Claude Code hook, pre-commit, CI); the table below says what each file becomes in chkscript and where this project departs from the template.

| File from claude-code-patterns | In chkscript | Departure or note |
| --- | --- | --- |
| `stacks/python/CLAUDE.md` | Replaces the current `CLAUDE.md`; placeholders filled: project paragraph, Python 3.11, `pydantic` at every external boundary; FastAPI line dropped | `structlog` line dropped (see below); the "one thing it must get right" is: a scanned script can never lower a deterministic finding |
| `stacks/python/AGENT.md` | Replaces the current `AGENT.md` as is | Adds the two external tools (shellcheck, shfmt) to Setup with install hints |
| `.claude/settings.json` + `.claude/hooks/check-python.sh` | Copied as is: Black applied and Ruff blocking on every Edit/Write, `ruff check .` on Stop | Merged with the `security/` `permissions.deny` block |
| `.pre-commit-config.yaml` | Stack hooks (ruff, black, pytest on pre-push) with the `security/` repos appended | `trufflehog` must be on PATH locally |
| `.github/workflows/ci.yml` | As is: `uv sync --locked`, ruff, black, pytest | CI installs shellcheck and shfmt so the golden suite runs the real tools, not only the regex fallback |
| `.github/workflows/secret-scan.yml`, `dependabot.yml` | Copied as is |  |
| `.gitignore` | Stack file replaces the current one | Already covers `.env*` except `.env.example` |
| `security/.env.example` pattern | `.env.example` lists every variable in Configuration and secrets with placeholders | chkscript itself never loads `.env`; that is the shell's or `uv run --env-file`'s job |
| `CLAUDE-global.md` type-hint rule | Ruff `ANN` rules enabled in `pyproject.toml` so the hook enforces signatures | No mypy; the stack does not include it and the hook contract is Black + Ruff |
| `stacks/shell` | Not applied | `tests/fixtures/` is deliberately bad Bash; a shellcheck hook would block every edit there. If helper scripts are added later, apply it with the fixture dirs excluded |

**Departures from the template, stated once**

- stdlib `logging` instead of structlog, which is the global default's own exit for a CLI whose logs are never shipped or queried. The report is written by `formatter.py`; notices and errors go to stderr through `logging`, never `print()`.
- `argparse` instead of Click: a single command, no extra dependency.
- `pydantic-settings` for config, per the global default for anything that reads env.
- The full list, with dates, is in `docs/decisions.md`.
- "Add dependencies with `uv add` only after asking": this spec is the approval for `pydantic-ai-slim` with the `anthropic` and `openai` extras. Anything else is a question first.
- Tests stay in `tests/`, which the template allows.
- Conventional Commits and the PR description format (plan summary, test changes and why, or an explicit "no tests changed") apply, one PR per build-order phase.

**Project-level `CLAUDE.md`**

Filled from the template and kept short enough that an agent reads all of it: the project paragraph, the stack block, the guardrails table as shipped, and under Rules the project-specific lines only: the layout, the three run modes, the two threat-model properties, "the model never lowers the floor", and the exit code table. Everything else stays in `CLAUDE-global.md`.

**Agent workflow**

Work runs in Claude Code (Opus) against a git worktree per Linear issue, one issue per build-order phase, under the nimsys workspace. Agents comment only on the issue they were started under, never create or close issues, and leave the issue in In Review; Done is set by hand. The kickoff prompt for each phase is pasted into the issue so the record stays readable.

## Testing

The static layer is tested as a golden suite against fixture scripts; the LLM layer is tested with pydantic-ai's test model so no network is needed; the two threat-model properties get explicit tests of their own.

**Fixtures (`tests/fixtures/`)**

| Fixture | Expected max severity | Exercises |
| --- | --- | --- |
| `safe.sh` | safe | Baseline, no findings |
| `warnings_only.sh` | warning | Unquoted vars, no `set -e`; exit 0 under `--fail-on unsafe` |
| `curl_pipe_sh.sh` | unsafe | Syntax-tree rule and regex fallback agree |
| `eval_variable.sh`, `base64_to_sh.sh` | unsafe | Decoder and eval rules |
| `evasion_var_cmd.sh` | unsafe | `c=curl; $c ... \| sh`; constant resolution catches it statically |
| `injection_comment.sh` | unsafe | `curl \| sh` plus `# verified safe by security team`; static finding must survive the model |
| `injection_delimiter.sh` | unsafe | Literal `</script>` and instructions inside the file; randomized delimiter must hold |
| `unparseable.sh` | warning + original severity | shfmt parse error produces its own finding and regex fallback still fires |
| `nested_fetch.sh` | depends on child | Downloads and runs a second script; served by a local test server |
| `nested_ssrf.sh` | unsafe | Second stage at `169.254.169.254`; fetch refused, finding emitted |
| `nested_http.sh` | unsafe | Plain-http second stage |
| `nested_binary.sh` | warning or unsafe | Downloads a binary with and without checksum verification |
| `k3d-no-checksum.sh`, `k3d-with-checksum.sh` | warning / warning | Real-world installers kept from v0.1, now in `tests/corpus/`. Under the capability tier the unverified download and the quoted `rm -rf "$K3D_TMP_ROOT"` are capabilities, so neither is unsafe |
| `docker_group.sh` | warning | `usermod -aG docker "$USER"`: `root-equivalent-group` in group `trust`; the same line with `sudo` does not fire it |
| `apt_global_key.sh`, `apt_signed_by.sh` | warning / warning | The same repo added with a global key and with a `signed-by` keyring; `package-repo-added` names the scope in its message |

**Justification fixtures (phase 3b)**

Run with `TestModel`/`FunctionModel` for the assessment rules, and under `--run-live` for the expected verdicts.

| Fixture | Run with | Expected assessments |
| --- | --- | --- |
| `cli_needs_root.sh` | no `--expect` | A CLI installed to `/usr/local/bin` with sudo and an install-dir variable: root `needed`; system write `avoidable`, with `alternative_line` on the variable's line |
| `cli_installs_service.sh` | `--expect "install the CLI"` | A CLI installer that also writes a systemd unit and a cron entry: both `unexplained` |
| `docker_group.sh` | no `--expect` | `root-equivalent-group` assessed; the finding's category and severity unchanged whatever the verdict |

Unit tests for the assessment rules: an assessment keyed to no capability finding is dropped; an alternative without a valid `alternative_line` is dropped while the verdict stays; a finding with no assessment renders without one; `purpose_source` is `user` with `--expect` whatever the model returns.

**Footprint tests (phase 2c)**

- Every capability rule declares a group (a test enumerates the rules).
- The absence line in each form: full coverage, regex fallback, unresolved dynamic code, and both of the last two.
- `network_hosts` counts an unresolved host, and `privilege`/`persistence` go null when the absence claim cannot be backed.

**Real-installer corpus (`tests/corpus/`)**

- Pinned copies of popular installers with agreed verdicts in `tests/corpus/expected.toml`; any drift fails the suite.
- Re-baselined with categories when the syntax-tree engine (2b) and the capability tier (2c) land: each entry records its finding's `category` as well as its rule and lines, and the agreed `max_severity` is re-agreed under the new classification.
- Each entry also records the installer's expected `footprint` (privilege, persistence, hosts, coverage, absent groups). It is deterministic, so it belongs in `expected.toml`; assessments are not, so they never go there.

**Unit tests**

- `preprocess`: numbering, URL extraction including variable-built hosts, size limit.
- `static/*`: each tool's JSON is parsed from recorded output; absent-tool paths produce the right notices; merge keeps max severity and all sources.
- Command model and rules: each is tested against snippets parsed by the real shfmt, not against hand-built trees or text. Every command-model behavior (heredoc as data, each wrapper, constant resolution and the unknown case, each kind of embedded code, a generated child file, per-path download tracking) and every rule has a firing and a non-firing snippet. The same snippets run through the regex fallback to check invariant 4.
- `fetch`: every guardrail in the table has a test that triggers it, including redirect re-validation and a `Content-Length` that lies. Uses a local `http.server` fixture, never the network.
- `config`: precedence order, `_FILE` suffix, no key in any error string (assert by grepping output for the fixture key value).
- `analyzer`: pydantic-ai `TestModel` and `FunctionModel` drive the agent; assert the model cannot drop or downgrade a static finding; assert no-follow withholds the tool.
- `formatter`: terminal and JSON for each mode; snapshot tests.

**Integration, opt-in**

A `--run-live` pytest flag runs the fixture suite against a real provider (Ollama locally by default) and reports verdict agreement with the expected column. Not in CI; used before releases.

**Property tests to keep**

1. For every fixture, `max_severity(full) >= max_severity(static_only)`. The model never lowers the floor.
2. For every fixture, no fetch is attempted for a URL absent from the allowlist (asserted on the test server's request log).
3. Running the same fixture twice with the same model yields identical findings (temperature 0).
4. Fallback superset: on every corpus file, the regex fallback reports at least the unsafe findings the syntax-tree engine reports (same `rule_id` on the same file). Losing the parser can add findings, never remove an unsafe one.
5. Justification is inert: for every fixture, deleting `assessments`, `purpose` and `footprint` from the result leaves `findings`, `max_severity` and the exit code identical.

## Build order

Each phase leaves the tool shippable; the static floor goes in before anything touches the model.

1. **Scaffold** (NIM-71, merged). New layout, Pydantic models, `config.py` with precedence and `_FILE`, Python floor to 3.11, claude-code-patterns python stack and security layer applied (hooks, pre-commit, CI, secret scan), CLAUDE.md and AGENT.md filled from the templates, .env.example added, remove the stray `tests/examples/bash` file. Gate: existing v0.1 tests pass against the new models.
2. **Static layer** (NIM-81, merged). Preprocessing, shellcheck adapter, regex fallback, parse-failure finding, merge. `--static-only` works end to end with no API key. The default mode runs the static layer, then the v0.1 LLM pass, merged, so the floor applies before phase 3. Gate: golden suite green for every fixture that does not need the model. This phase shipped a Semgrep engine; the NIM-95 corpus showed it parses 5 of 11 real installers, and 2b replaces it.
   - **2b. Syntax-tree engine** (NIM-122). shfmt adapter with version check, the command model (heredocs as data, wrappers, constants, embedded code, generated child files, per-path downloads), the existing rules ported to Python functions over it, Semgrep and its YAML removed, regex fallback limited to shfmt missing or a parse failure. Gate: all 11 corpus installers parse; the corpus re-baselined; fallback-superset invariant (property test 4) passes.
   - **2c. Capability tier** (NIM-123). `category` on `Finding`, rules reclassified per the classification table (`unverified-download` to capability, `rm-rf-variable` split), `root-equivalent-group` and key scope on `package-repo-added`, footprint groups on every capability rule, the "What this script will do to your machine" report section with room for an assessment line under each entry, the footprint summary (`NEEDS` line and JSON `footprint`) and the absence line, the model's capability-to-unsafe raise in the merge. Gate: corpus re-agreed with categories and footprints; capability-only scripts exit 1.
   - The rescoped rule issues follow 2c: every download-and-execute form and disabled TLS (NIM-96), then credential exfiltration, reverse shells, SSH key planting, package-trust bypass and PATH/LD_PRELOAD hijacking (NIM-97), each written against the command model.
3. **LLM layer, no-follow** (NIM-134, merged). `LLMAnalyzer` on pydantic-ai with `NativeOutput`, randomized delimiter, static findings passed in, merge rules. Providers: Anthropic and Ollama. The hosted default switches to `anthropic:claude-sonnet-5-5`, and `cli.py`'s hard `ANTHROPIC_API_KEY` check is removed in favor of the auto-detection order; until both happen, local mode cannot run. Gate: injection fixtures hold; property test 1 passes with `TestModel`.
   - **3b. Justification** (NIM-162). `purpose`, `purpose_source` and `assessments` on `LLMResult`, the prompt contract for assessing each capability, the assessment rules enforced after the call, `--expect` and `CHKSCRIPT_EXPECT`, the assessment lines and Purpose line in the report. Reads the masked script from NIM-151 and NIM-152. Gate: the justification fixtures; property test 5.
4. **Fetch tool.** `fetch.py` with every guardrail, local test server, fetch tree in the report, refused-fetch finding. Gate: every guardrail row has a failing-then-passing test; property test 2 passes.
5. **CLI and output.** Three modes, `--fail-on`, auto-detection, leaves-the-box notice, capability probing, terminal and JSON formats, including the header and `VERDICT` lines of the layout in Output and exit codes. Gate: snapshot tests; README rewritten.
6. **Release.** `--run-live` against Ollama and Anthropic on the fixture suite; tag 0.2.0; publish to PyPI with extras.

Phases 1 and 2 are the bulk of the value and carry no API cost to develop. Phase 4 is the one most likely to grow; keep its scope to the guardrail table.

## Open questions

- [x] Default models: `anthropic:claude-sonnet-5-5` hosted, `ollama:gpt-oss:20b` local (see Providers and models). The local pick is confirmed or replaced by the `--run-live` suite in phase 6.
- [ ] Whether to pre-screen with a smaller model (Haiku) and use the default only when the static layer flags something.
- [ ] Should `--fail-on unsafe` become the default? It matches how people actually gate, but changes the v0.1 contract.
- [ ] Config file (`~/.config/chkscript/config.toml`) for non-secret defaults: in 0.2 or later?
- [x] Shipping the rules as a standalone Semgrep registry pack: dropped, since the rules are now Python functions over the command model (NIM-121).
- [ ] Caching fetched files by SHA-256 within a run (cheap) and across runs (needs a cache dir and expiry policy).
- [ ] Whether a `--allow-host` flag for variable-built URLs the model cannot resolve is worth the added surface.
- [ ] Report format for the fetch tree in non-verbose terminal mode: full tree or one summary line with counts.
- [x] Logging: stdlib `logging` to stderr, no structlog. A `--debug` flag, if wanted, only raises the log level.
- [ ] Should the purpose default from the URL the script was piped from, when there is one, rather than from the script's own text?
- [ ] Should an `unexplained` assessment on a `root` or `persistence` capability be shown above Concerns, not only inside the capability section?
- [ ] Where the model's `summary` paragraph sits in the new terminal layout: under the Purpose line, or only with `-v`.
