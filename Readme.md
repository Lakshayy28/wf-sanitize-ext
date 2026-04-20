# SafeChat — VS Code Copilot DLP Extension

A Data Loss Prevention layer for GitHub Copilot Chat. SafeChat intercepts every tool result in the `@safechat` agent loop, routes it through a **Gitleaks + Tree-Sitter two-pass pipeline**, and masks secrets before the LLM sees them.

Nothing sensitive leaves your machine.

---

## How It Works

SafeChat registers as a VS Code Chat Participant (`@safechat`). When Copilot invokes any native tool (file read, terminal, MCP, etc.), the extension intercepts the result and runs it through a routing pipeline:

```
Tool result → Extract file extension → Router
  ├─ Source code (.ts, .py, .go, …)        → BYPASS (zero-touch)
  ├─ Structured JSON/YAML/TOML             → Gitleaks + Tree-Sitter CST (parallel)
  ├─ XML / SVG / Plist                     → Gitleaks + Tree-Sitter CST (html grammar)
  ├─ ENV / Shell scripts                   → Gitleaks + Tree-Sitter CST (bash grammar)
  ├─ INI / CFG                             → Gitleaks + custom INI verifier
  ├─ JSONL / NDJSON                        → Gitleaks scan + per-line CST verification
  ├─ Flat / IaC (.sql, .tf, .npmrc, …)     → Gitleaks raw scan → mask
  └─ Terminal / MCP / unknown              → Content detection → heuristic scan → mask
```

### Two-Pass Verification (Structured Files)

1. **Pass 1 — Gitleaks** scans the **raw unmodified text** so every contextual rule (`password=`, `aws_secret_access_key=`, connection strings) fires correctly.
2. **Pass 2 — Tree-Sitter** parses the file into a Concrete Syntax Tree and verifies each finding falls inside a **value node** — not a key name, structural header, or YAML anchor.
3. Only **verified findings** are masked. False positives on key names are silently dropped.

Both passes run **in parallel** via `Promise.all`. Latency cost is `max(gitleaks, parse)` rather than the sum.

### Fail-Closed Design

- CST parse failure → all Gitleaks findings are kept (mask everything rather than miss anything).
- `ERROR` nodes in CST → treated as values (mask them; ambiguous parse = unsafe).
- Gitleaks crash → error is logged; text passes through unchanged rather than corrupt.
- Payload > 2 MB → rejected entirely before scanning (a safe placeholder is shown).
- Payload > 250 KB → full text is scanned and masked first, then the output is truncated.
- Gitleaks stdout > 50 MB → process killed via SIGKILL; findings rejected.

---

## Engine Stack

| Component | Role |
|---|---|
| **Gitleaks v8.30.1** | Secret detection via `--pipe` stdin. ~160 built-in rules + 26 custom `safechat-*` rules. |
| **web-tree-sitter (WASM)** | CST parsing for 5 grammars: JSON, YAML, TOML, HTML/XML, Bash/ENV. Verifies findings are in value positions. |
| **INI verifier** | Lightweight regex-based key/value splitter for `.ini` and `.cfg` (no WASM grammar needed). |
| **Router** | Extension-based routing with content-type detection fallback for untyped inputs. |
| **Heuristic Classifier** | Classifies terminal commands as `debug` (lenient) or `strict` mode for Gitleaks config selection. |

---

## Routing Rules

| Priority | Match | Pipeline |
|---|---|---|
| 0 | Tool error messages | Bypass |
| 1 | Source code (`.ts`, `.py`, `.go`, `.rs`, `.java`, 30+ types) | **Bypass** — zero-touch policy |
| 2 | Flat / IaC (`.properties`, `.pgpass`, `.netrc`, `.npmrc`, `.sql`, `.tf`, `.hcl`, `.ps1`) | Gitleaks raw scan → mask |
| 3 | Structured (`.json`, `.yaml`, `.toml`, `.xml`, `.svg`, `.plist`, `.env`, `.sh`, `.ini`, `.cfg`) | **Two-pass: Gitleaks + CST verification** |
| 4 | JSONL / NDJSON (`.jsonl`, `.ndjson`) | Gitleaks scan + per-line CST |
| 5 | Terminal / MCP / unknown | Content detection → auto-select pipeline |

### Grammar Coverage

| Grammar | File Types |
|---------|-----------|
| JSON | `.json`, `.jsonc`, `.json5` |
| YAML | `.yaml`, `.yml` |
| TOML | `.toml` |
| HTML (xml mode) | `.xml`, `.xsl`, `.xslt`, `.svg`, `.plist` |
| Bash (env mode) | `.env`, `.sh`, `.bash`, `.zsh`, `.fish` |
| INI (custom) | `.ini`, `.cfg` |

---

## Extensible Rules via `safechat-rules.toml`

Drop a `safechat-rules.toml` file in your workspace root to add org-specific detection rules. The extension **hot-reloads** it automatically — no restart needed.

```toml
title = "My Org Custom Rules"

[extend]
useDefault = true   # inherit all ~160 built-in Gitleaks rules

[[rules]]
id          = "myorg-service-token"
description = "Internal Service Token"
regex       = '''myorg_[0-9a-f]{32}'''
entropy     = 3.5
keywords    = ["myorg_"]

[[rules]]
id          = "myorg-db-password"
description = "Hardcoded DB password"
regex       = '''(?i)db_pass(?:word)?\s*=\s*['"]?([A-Za-z0-9!@#$%]{8,})'''
secretGroup = 1
entropy     = 3.0
```

See `configs/safechat-rules.sample.toml` for a fully documented template with examples for tokens, connection strings, private keys, and allowlist patterns.

---

## Write Guard

Before any write tool or shell command executes, SafeChat checks whether the input contains `[MASKED_BY_SAFECHAT]` tokens and emits a warning to prevent:
- Masked placeholders being written to files (corrupting configs)
- Masked values being passed to shell commands (executing garbled input)

---

## Audit Log

Every sanitization event is written to:
- **VS Code Output panel** (`SafeChat Audit` channel) — live monitoring
- **`.safechat/audit.log`** in the workspace root — permanent forensic record

Each entry records the file path, route used, number of secrets caught, and secret type IDs — without logging the actual secret values.

---

## Project Structure

```
src/
  extension.ts          — Entry point, chat participant, tool interception, write-guard
  router.ts             — 6-rule routing dispatch, pipelines, 2MB cap, scan-then-truncate
  gitleaksEngine.ts     — Binary spawner, findings parser, PEM region expander, masker
  treeSitterEngine.ts   — WASM grammar loader, CST walkers (JSON/YAML/TOML/HTML/Bash), INI/JSONL verifiers
  heuristic.ts          — Terminal command classifier (debug vs strict)
configs/
  strict.toml           — Production Gitleaks config (useDefault + 26 safechat-* rules)
  testing.toml          — Same config + lenient allowlists for test runner output
  safechat-rules.sample.toml — Template for user-supplied custom rules
server/
  darwin-arm64/gitleaks — Gitleaks v8.30.1 (macOS Apple Silicon)
  win-x64/gitleaks.exe  — Gitleaks v8.30.1 (Windows x64)
grammars/               — WASM grammars (copied from node_modules at compile time)
  tree-sitter.wasm
  tree-sitter-json.wasm
  tree-sitter-yaml.wasm
  tree-sitter-toml.wasm
  tree-sitter-html.wasm
  tree-sitter-bash.wasm
```

---

## Usage

Invoke within Copilot Chat using the `@safechat` participant:

```
@safechat read the database config
@safechat show me the kubernetes secrets manifest
@safechat run terraform plan and explain the output
@safechat what's in my .env file?
```

All native Copilot tools (file read, run terminal, MCP) work unimpeded. SafeChat intercepts results transparently. When data is masked, a shield notice appears in chat showing which route and grammar were used.

---

## Security Properties

- **No network calls.** Gitleaks runs as a local subprocess. Tree-Sitter runs as WASM in-process.
- **No disk writes.** Tool output is scanned entirely in memory via stdin pipe.
- **Temp files** are used only for the Gitleaks JSON report — written to `os.tmpdir()` and deleted immediately after reading.
- **Source code is never scanned.** Zero-touch bypass is hard-coded for `.ts`, `.py`, `.go`, and 30+ other source extensions.
- **`[MASKED_BY_SAFECHAT]`** is the only mutation SafeChat ever makes to tool output.

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full technical deep-dive.

---

## Installation

See [INSTALLATION.md](INSTALLATION.md) for step-by-step setup from a fresh clone.

---

## License

MIT
