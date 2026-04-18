# SafeChat — VS Code Copilot DLP Extension

A Data Loss Prevention layer for GitHub Copilot Chat. SafeChat intercepts every tool result in the `@safechat` agent loop, routes it through a **Gitleaks + Tree-Sitter two-pass pipeline**, and masks secrets before the LLM sees them.

Nothing sensitive leaves your machine.

---

## How It Works

SafeChat registers as a VS Code Chat Participant (`@safechat`). When Copilot invokes any native tool (file read, terminal, MCP, etc.), the extension intercepts the result and runs it through a routing pipeline:

```
Tool result → Extract file extension → Router
  ├─ Source code (.ts, .py, .go, …)     → BYPASS (no scanning)
  ├─ Flat files (.env, .sh, .tf, .sql, …) → Gitleaks raw scan → mask
  ├─ Structured (.json, .yaml, .toml)   → Gitleaks scan → Tree-Sitter CST verification → mask
  ├─ XML (.xml, .svg, .plist, …)        → Gitleaks raw scan → mask
  └─ Terminal / MCP / unknown            → Content-type detection → heuristic scan → mask
```

### Two-Pass Verification (Structured Files)

1. **Pass 1 — Gitleaks** scans the **raw unmodified text** so every contextual rule (`password=`, `aws_secret_access_key=`, connection strings) fires correctly.
2. **Pass 2 — Tree-Sitter** parses the file into a Concrete Syntax Tree and verifies each finding falls inside a **value node** (not a key name or structural element like a YAML anchor or TOML section header).
3. Only **verified findings** are masked. False positives on key names are dropped.

This gives 100% of Gitleaks' pattern context + 100% of Tree-Sitter's structural precision.

### Fail-Closed Design

- CST parse failure → all Gitleaks findings are kept (mask everything).
- ERROR nodes in CST → treated as values (mask them).
- Gitleaks crash → error is logged, text passes through unchanged.
- Payload > 250KB → truncated at nearest newline before scanning.
- Gitleaks stdout > 50MB → process killed via SIGKILL.

---

## Engine Stack

| Component | Role |
|---|---|
| **Gitleaks v8** | Secret detection via `--pipe` stdin. ~160 built-in rules + 27 custom `safechat-*` rules. |
| **Tree-Sitter (WASM)** | CST parsing for JSON, YAML, TOML. Verifies findings are in value positions. |
| **Router** | Extension-based routing with content-type detection fallback for untyped inputs. |
| **Heuristic Classifier** | Classifies terminal commands as `debug` (relaxed) or `strict` mode for config selection. |

---

## Routing Rules

| Priority | Match | Pipeline |
|---|---|---|
| 0 | Tool error messages | Bypass |
| 1 | Source code (`.ts`, `.py`, `.go`, `.rs`, `.java`, …) | Bypass |
| 2 | Flat / IaC (`.env`, `.sh`, `.tf`, `.sql`, `.ini`, …) | Gitleaks raw scan |
| 3 | Structured (`.json`, `.yaml`, `.toml`) | Two-Pass: Gitleaks + CST verification |
| 4 | XML (`.xml`, `.svg`, `.plist`) | Gitleaks raw scan |
| 5 | Terminal / MCP / unknown | Content detection → heuristic scan |

---

## Write Guard

If a tool writes to disk or runs a shell command, SafeChat checks whether the input contains `[MASKED_BY_SAFECHAT]` tokens and emits a warning to prevent masked placeholders from corrupting files or being executed.

---

## Project Structure

```
src/
  extension.ts        — Entry point, chat participant, tool interception
  router.ts           — Central routing controller
  gitleaksEngine.ts   — Gitleaks binary spawner, findings parser, masking
  treeSitterEngine.ts — WASM grammar loader, CST verification engine
  heuristic.ts        — Terminal command classifier
configs/
  strict.toml         — Gitleaks config (useDefault + 27 custom rules)
  testing.toml        — Same + allowlists for test fixtures
server/
  darwin-arm64/       — macOS Gitleaks binary
  win-x64/            — Windows Gitleaks binary
grammars/
  tree-sitter.wasm    — Tree-Sitter runtime
  tree-sitter-json.wasm
  tree-sitter-yaml.wasm
```

---

## Usage

Invoke within Copilot Chat:

```
@safechat read the database config
@safechat check the kubernetes secrets
@safechat run terraform plan
```

All native Copilot tools work unimpeded. SafeChat intercepts results transparently. A shield icon appears in chat when data is masked, showing which route was used.

---

## License

MIT
