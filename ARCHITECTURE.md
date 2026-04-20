# SafeChat — Architecture Reference

## Overview

SafeChat is a VS Code extension that acts as a transparent **Data Loss Prevention (DLP) proxy** for GitHub Copilot Chat. It intercepts every tool result inside the `@safechat` agent loop and routes it through a secret-detection pipeline before the content reaches the LLM.

```
User prompt ──► @safechat chat participant
                      │
                      ▼
              Copilot LLM (tool-calling loop)
                      │
            ┌─────────┴──────────┐
            │   Tool invocation  │  (file read, terminal, MCP, etc.)
            └─────────┬──────────┘
                      │  raw tool output
                      ▼
            ┌─────────────────────┐
            │  SafeChat Intercept │  extractFileExtension + toolContext
            └─────────┬───────────┘
                      │
                      ▼
            ┌─────────────────────┐
            │      Router         │  routeAndSanitize()
            │   (router.ts)       │  Rules 0 → 5 evaluated in order
            └─────────┬───────────┘
                      │ cleanText
                      ▼
              Copilot LLM  ◄── sanitized context (secrets replaced with [MASKED_BY_SAFECHAT])
```

---

## Component Map

```
src/
  extension.ts        — Chat participant, tool loop, write-guard, audit log
  router.ts           — Central routing controller (6-rule dispatch table)
  gitleaksEngine.ts   — Gitleaks binary spawner, masking engine
  treeSitterEngine.ts — WASM grammar loader, CST verification engine, INI/JSONL verifiers
  heuristic.ts        — Terminal command classifier (debug vs strict mode)
configs/
  strict.toml         — Gitleaks config: useDefault + 26 safechat-* rules (production)
  testing.toml        — Same + lenient allowlists for test runner output
  safechat-rules.sample.toml — Template for user-supplied custom rules
server/
  darwin-arm64/gitleaks  — Gitleaks v8.30.1 binary (macOS Apple Silicon)
  win-x64/gitleaks.exe   — Gitleaks v8.30.1 binary (Windows x64)
grammars/              — Copied at compile time from node_modules
  tree-sitter.wasm       — Web Tree-Sitter runtime
  tree-sitter-json.wasm  — JSON CST grammar
  tree-sitter-yaml.wasm  — YAML CST grammar
  tree-sitter-toml.wasm  — TOML CST grammar
  tree-sitter-html.wasm  — HTML/XML CST grammar
  tree-sitter-bash.wasm  — Bash/ENV CST grammar
```

---

## The Routing Table

`router.ts` evaluates six rules in order on every tool output. The first matching rule wins.

| Rule | Trigger | Pipeline |
|------|---------|---------|
| **0** | Text starts with `"Error invoking tool"` | **Bypass** — pass through untouched |
| **1** | File extension in `BYPASS_EXTENSIONS` (`.ts`, `.py`, `.go`, `.java`, `.rs`, 30+ total) | **Bypass** — zero-touch source code policy |
| **2** | Extension in `FLAT_EXTENSIONS` (`.properties`, `.pgpass`, `.netrc`, `.npmrc`, `.sql`, `.tf`, `.hcl`, `.ps1`) | **Gitleaks raw scan** → mask |
| **3** | Extension maps to a CST grammar (`json`, `yaml`, `toml`, `html`, `bash`, `ini`) | **Two-pass CST pipeline** (see below) |
| **4** | Extension is `.jsonl` or `.ndjson` | **JSONL pipeline** — per-line JSON CST |
| **5** | No extension / MCP / terminal | **Content-type detection** → CST or raw scan; heuristic config selection |

### Extension Sets (defaults, overridable via `safechat.yml`)

| Set | Extensions |
|-----|-----------|
| `BYPASS` | `.ts .tsx .js .jsx .mjs .cjs .py .java .kt .go .rs .c .cpp .cs .rb .php .swift .dart .lua .r .pl .vue .svelte .proto .graphql` and more |
| `CST_JSON` | `.json .jsonc .json5` |
| `CST_YAML` | `.yaml .yml` |
| `CST_TOML` | `.toml` |
| `CST_HTML` | `.xml .xsl .xslt .svg .plist` |
| `CST_BASH` | `.env .sh .bash .zsh .fish` (and `.env.local`, `.env.production` etc.) |
| `CST_INI` | `.ini .cfg` |
| `FLAT` | `.properties .pgpass .netrc .npmrc .ps1 .psm1 .sql .tf .hcl` |

---

## The Two-Pass CST Pipeline

This is the core innovation. It combines Gitleaks' **pattern breadth** with Tree-Sitter's **structural precision**.

```
              Full raw text
                   │
          ┌────────┴────────┐
          │                 │  ← Promise.all (parallel)
          ▼                 ▼
   Gitleaks scan       Tree-Sitter parse
   (strict.toml)       (WASM grammar)
          │                 │
          │ findings[]      │ CST tree
          └────────┬────────┘
                   │
                   ▼
          verifyFindings()
          For each finding:
            locate secret in text → char offset
            CST.descendantForIndex(start, end)
            walk up parent chain
            is this node a VALUE? → keep
            is this node a KEY?   → drop (false positive)
                   │
                   ▼
          verified findings[]
                   │
                   ▼
           applyMask()  → [MASKED_BY_SAFECHAT]
```

### Why scan first, verify second?

Gitleaks needs full context to fire its rules. A pattern like `aws_secret_access_key = AKIA...` requires seeing the key name AND value together. If Tree-Sitter parsed first and only extracted values, Gitleaks would lose context and miss findings.

Running both in parallel (via `Promise.all`) means the latency cost is `max(gitleaks_time, parse_time)` rather than the sum.

---

## CST Grammar Walkers

Each language walker implements the same contract: given a `SyntaxNode` at the secret's position, walk up the parent chain and return `true` (mask it) or `false` (drop it).

All walkers share two fail-closed rules applied first:
- `ERROR` node → `true` (mask — ambiguous parse, be safe)
- `comment` node → `true` (mask secrets inside comments)

### JSON Walker (`isJsonValuePosition`)

```
pair
 ├─ key   "password"     ← return false if secret is here
 └─ value "s3cr3t"       ← return true if secret is here

array → always true (array items are values)
```

### YAML Walker (`isYamlValuePosition`)

```
block_mapping_pair
 ├─ key:   "api_key"     ← return false
 └─ value: "sk_live_…"   ← return true

flow_pair — same structure
block_sequence / flow_sequence → always true
```

### TOML Walker (`isTomlValuePosition`)

TOML `pair` has no named fields — uses positional children:
```
pair
 ├─ namedChild(0) = key    "token"   ← return false
 └─ namedChild(1) = value  "ghp_…"   ← return true

table / table_array_element headers → return false (structural)
```

### XML/HTML Walker (`isXmlValuePosition`)

Uses `tree-sitter-html` grammar for both HTML and XML:
```
element
 ├─ start_tag
 │   ├─ tag_name    "config"          ← return false
 │   └─ attribute
 │       ├─ attribute_name  "id"      ← return false
 │       └─ attribute_value "sec_…"   ← return true
 └─ text  "sk_live_123"               ← return true

comment <!-- old key: … --> → return true
```

### Bash/ENV Walker (`isEnvValuePosition`)

Uses `tree-sitter-bash` grammar for `.env`, `.sh`, `.bash`, `.zsh`, `.fish`:
```
variable_assignment
 ├─ variable_name  "API_KEY"   ← return false
 └─ word / string  "sk_abc…"   ← return true

declaration_command (export VAR=VALUE) → walks into variable_assignment
```

### INI Custom Verifier (`verifyIniFindings`)

No `tree-sitter-ini` grammar exists on npm. SafeChat implements a lightweight regex-based verifier:
```
[section]              → structural, return false
key = value            → check if secret offset >= '=' position → true (value)
; comment              → return true (mask)
# comment              → return true (mask)
bare key without '='   → return false
```

---

## JSONL Pipeline

JSONL/NDJSON files (`.jsonl`, `.ndjson`) are treated specially — each line is an independent JSON object. A single multi-MB log file may contain thousands of lines.

```
Full JSONL text
      │
      ▼
Gitleaks scan (once, full text)
      │
      │ findings[], each with StartLine
      ▼
Group findings by StartLine
      │
For each line with findings:
  parse that single line as JSON
  verify findings using JSON walker
      │
      ▼
verified findings → applyMask()
```

This is more efficient than parsing the whole file as one document (which would be invalid JSON) and gives precise value-position verification per line.

---

## PEM / Certificate Multi-Line Masking

When Gitleaks detects a secret inside a PEM block (`-----BEGIN RSA PRIVATE KEY-----`, etc.), `applyMask` expands the masking region to cover the **entire block** — not just the detected snippet.

```
expandPemRegion(text, region):
  look behind up to 200 chars for -----BEGIN
  if found → extend region.start to -----BEGIN
  look forward for -----END
  if found → extend region.end to end of that line
```

This ensures a partial private key can never leak through as unmasked surrounding lines.

---

## Heuristic Terminal Classifier

Terminal output has no file extension. The heuristic in `heuristic.ts` selects between two Gitleaks configs:

| Mode | Config | Used when |
|------|--------|-----------|
| `debug` | `testing.toml` | Command matches test runner patterns |
| `strict` | `strict.toml` | Command matches data-exfiltration patterns, or default |

**Debug command patterns** (use lenient config): `jest`, `pytest`, `mocha`, `vitest`, `playwright`, `cypress`, `bun test`, `deno test`, `cargo test`, `go test`, `npm run test`, `rspec`, `phpunit`, `nyc`, `tap`, `ava`, and 10+ more.

**Strict command patterns** (use strict config): `cat`, `less`, `printenv`, `curl`, `wget`, `env`, `echo`, `grep`, `jq`, `yq`, `openssl`, `base64`, `xxd`, and more.

**Priority**: explicit debug match → explicit strict match → output pattern analysis → default `strict`.

---

## Fail-Closed Design

Every decision that could go wrong defaults to **masking more, not less**:

| Failure scenario | Behavior |
|-----------------|---------|
| Tree-Sitter parse fails | Keep all Gitleaks findings (mask everything) |
| `ERROR` node in CST | Treat as value → mask |
| Secret not found in text | Keep finding → mask |
| Gitleaks crashes | Log error, return text unchanged (do not corrupt) |
| Payload > 2 MB | Reject entirely with a safe placeholder message |
| Payload > 250 KB | Scan full text, mask, then truncate output |
| Gitleaks stdout > 50 MB | Kill process via SIGKILL, reject |
| Gitleaks timeout (10s) | Kill, reject findings |

The 2 MB hard cap (scan-then-truncate ordering) is critical: truncation happens **after** masking the full text, so secrets near the truncation boundary cannot escape.

---

## Extensible Rules via `safechat-rules.toml`

SafeChat ships with 26 custom rules in `strict.toml` covering AWS, Stripe, GitHub, Slack, database URIs, generic credentials, and more. Users can extend detection without modifying the extension.

**How it works:**
1. Drop a `safechat-rules.toml` file in the workspace root.
2. The extension hot-reloads it automatically via `vscode.workspace.createFileSystemWatcher`.
3. This file **replaces** the bundled `strict.toml` as the Gitleaks config for that workspace.

**File format:**

```toml
title = "My Org Custom Rules"

[extend]
# Inherit all ~160 default Gitleaks rules + built-in entropy filters
useDefault = true

[[rules]]
id          = "myorg-internal-token"
description = "MyOrg Internal Service Token"
regex       = '''myorg_[0-9a-f]{32}'''
entropy     = 3.5
keywords    = ["myorg_"]

[[rules]]
id          = "myorg-db-password"
description = "Hardcoded database password"
regex       = '''(?i)db_pass(?:word)?\s*=\s*['"]?([A-Za-z0-9!@#$%^&*]{8,})'''
secretGroup = 1
entropy     = 3.0

[[rules.allowlists]]
# Exclude test files from this rule
paths = ['''test''', '''spec''', '''fixture''']
```

**Key Gitleaks TOML concepts:**

| Field | Purpose |
|-------|---------|
| `regex` | Go RE2 regex. The full match (or `secretGroup`) is what gets redacted. |
| `secretGroup` | Capture group index to redact (0 = full match). Use to target the value, not surrounding context. |
| `entropy` | Shannon entropy floor. Filters placeholders like `"changeme"` or `"example"`. Recommended: `3.5`. |
| `keywords` | Fast pre-filter. Rule only runs if a keyword appears in the surrounding ~250 chars. Speeds up scanning significantly. |
| `[[rules.allowlists]]` | Per-rule exclusions by regex, path, or stopword. |
| `[[allowlists]]` | Global exclusions applied to all rules. |

**Testing.toml strategy:** The bundled `testing.toml` uses `[extend] path = "strict.toml"` plus generous allowlists for common test patterns (`ghp_test`, `AKIA_EXAMPLE`, etc.), so test output from `jest`/`pytest` doesn't get over-redacted.

---

## Audit Log

Every sanitization event writes a structured receipt to:
- **VS Code Output panel** (`SafeChat Audit` channel) — for live monitoring
- **`.safechat/audit.log`** in the workspace root — permanent forensic record

Receipt format:
```
======================================================
[AUDIT RECEIPT] 🛡️ FILE SANITIZED: /path/to/.env
[TIMESTAMP]     2026-04-20T10:15:33.412Z
[ROUTE]         cst:bash
[SECRETS SAVED] 3
[TYPES CAUGHT]  safechat-aws-access-key, safechat-github-token, safechat-generic-credential
[PAYLOAD SENT TO COPILOT]:

DB_HOST=localhost
DB_PASSWORD=[MASKED_BY_SAFECHAT]
...
======================================================
```

---

## Write Guard

Before any write tool or terminal command executes, SafeChat checks whether the tool input contains `[MASKED_BY_SAFECHAT]`. If so, a warning is emitted in chat to prevent:
- Masked placeholders being written to files (corrupting configs)
- Masked credentials being passed to shell commands (executing garbled input)

---

## Security Boundaries

- **No network calls.** Gitleaks runs as a local subprocess. Tree-Sitter runs as WASM in-process.
- **No file writes.** Tool output is scanned entirely in memory via stdin pipe.
- **Temp files** are used only for the Gitleaks JSON report (written to `os.tmpdir()`, deleted immediately after reading).
- **Source code bypass** is a hard zero-touch policy — no scanning, no logging, no modification of `.ts`, `.py`, `.go`, etc.
- **`[MASKED_BY_SAFECHAT]`** is the only mutation SafeChat ever makes to tool output.
