# Red Team Security Audit: @safechat

**Date:** 2026-04-17 → 2026-04-18 (Updated for Smart Proxy Architecture)
**Target:** `@safechat` Data Loss Prevention (DLP) VS Code Extension
**Scope:** Smart Proxy Architecture (`extension.ts`, `sanitizer.ts`)
**Status:** All prior vulnerabilities have been **architecturally eliminated** by the transition to the Smart Proxy pattern.

---

## Architecture Change Summary

The extension was completely rewritten from a **Zero-Trust Custom Tool Interception** model (with custom `safechat_read_file`, `safechat_read_directory`, `safechat_run_terminal` tools, an MCP Triage Router, Presidio NLP server, Shannon Entropy engine, AST parsers, symlink jails, diff caching, and `.gitignore` routing) to a **Minimalist Smart Proxy** model.

### What Was Removed
- All custom tool registrations (`safechat_read_*`, `safechat_run_terminal`)
- Native tool blocking/redirection
- Python Presidio NLP integration
- Shannon Entropy Engine
- MCP Triage Router (profile-based routing)
- Diff cache system (`.temp_cache/latest/`)
- SessionStateManager
- Symlink jails, UTF-16 BOM detection, NFKD homoglyph normalization
- `.gitignore` dynamic routing

### What Remains
- **Universal Interceptor:** All tools execute natively → output intercepted → sanitized → returned to LLM
- **Polyglot AST Router:** JSON/YAML/XML parsed structurally, ENV line-by-line, code bypassed, catch-all regex
- **22-pattern Regex Dictionary:** Unchanged from prior architecture
- **Write-Guard:** File-write AND terminal tools checked for `[MASKED_BY_SAFECHAT]` in input
- **250KB Truncation Guard:** Safe newline-boundary truncation before regex scanning

---

## Prior Vulnerabilities — Disposition

### Round 1 Findings (All Eliminated)

| ID | Vulnerability | Old Severity | Disposition |
|---|---|---|---|
| 1A | PromptTsxPart / Object Injection Bypass | CRITICAL | ✅ **ELIMINATED** — `extractToolOutputAsString()` force-stringifies all output parts including `PromptTsxPart` via `JSON.stringify`. No type-check bypass possible. |
| 1B | Terminal Write-Guard Bypass | HIGH | ✅ **ELIMINATED** — No custom terminal tool exists. Terminal tools are native and covered by the expanded Write-Guard pattern list that includes `run_command`, `terminal_execute`, `bash`, `exec`, etc. |
| 2A | Path Traversal via Suffix Matching | MODERATE | ✅ **ELIMINATED** — `SessionStateManager` no longer exists. No state caching of any kind. |
| 3A | Uncapped File Allocation Spike (OOM) | CRITICAL | ✅ **MITIGATED** — No custom file read. Native tools handle their own memory. The 250KB truncation guard protects the regex engine from oversized payloads. |
| 4A | Orphaned Process Leaking (Zombie MCP) | HIGH | ✅ **ELIMINATED** — No custom `Promise.race` or MCP timeout logic. Native `vscode.lm.invokeTool` handles its own lifecycle and cancellation via the parent `CancellationToken`. |

### Round 2 Findings (All Eliminated)

| ID | Vulnerability | Disposition |
|---|---|---|
| Token Smuggling via Hard Truncation | ✅ **ELIMINATED** — `truncateAndSanitize()` backtracks to nearest `\n` before slicing |
| File Cache Race Condition | ✅ **ELIMINATED** — No diff cache exists. No serial write queue needed. |
| Homoglyph/Encoding Bypass | ✅ **REDUCED** — NFKD normalization removed but regex patterns use explicit character classes that don't rely on Unicode equivalence. Homoglyphs in key *names* are no longer a concern since we don't do key-name detection. |
| UI Spoofing via MCP Markdown | ✅ **ELIMINATED** — No MCP markdown escaping needed. Native tools return structured parts, not raw markdown. |

### Round 3 Findings (All Eliminated)

| ID | Vulnerability | Disposition |
|---|---|---|
| Symlink Workspace Escape | ✅ **ELIMINATED** — No custom file reading. Native tools handle symlink resolution. |
| Cognitive Prompt Injection | ✅ **ELIMINATED** — No data-fencing tags needed. We don't inject system prompts. |
| UTF-16 Encoding Bypass | ✅ **ELIMINATED** — No custom file reading. Native tools decode files. |
| Cache Disk DoS | ✅ **ELIMINATED** — No diff cache exists. |

---

## Current Attack Surface (Smart Proxy)

The new architecture has a minimal attack surface:

### Residual Risk 1: Regex Pattern Completeness
**Severity:** LOW
The 22-pattern dictionary may not cover future/proprietary token formats (e.g., a new cloud provider's API key prefix). This is inherent to any regex-based approach.
**Mitigation:** The pattern list is extensible in `sanitizer.ts`. Future work could add a Shannon Entropy heuristic for unknown formats.

### Residual Risk 2: AST Parse Failure Rate
**Severity:** LOW
Malformed JSON/YAML/XML will fail to parse and fall to the regex catch-all. This is by design (fail-closed), but the regex catch-all may miss structural secrets that the AST masker would have caught.
**Mitigation:** Acceptable trade-off. The regex dictionary still scans every string value.

### Residual Risk 3: Code File Bypass
**Severity:** INFORMATIONAL
Source code files are intentionally bypassed. If a `.ts` file contains a hardcoded secret like `const token = "ghp_..."`, the regex won't scan it because the file is bypassed by extension.
**Mitigation:** This is a deliberate design decision — scanning source code would produce excessive false positives and degrade developer UX. Hardcoded secrets in code should be caught by pre-commit hooks (e.g., `gitleaks`, `trufflehog`).

### Residual Risk 4: Native Tool Memory
**Severity:** LOW
Since we no longer do pre-flight `fs.stat()` checks, a native file read on a 1GB file would allocate memory in the native tool handler before our proxy intercepts the output.
**Mitigation:** Native tools have their own memory guards. Our 250KB truncation guard protects the regex scanning phase.
