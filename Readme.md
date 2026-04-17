# Safe Copilot Context — VS Code Extension (`@safechat`)

An Enterprise Data Loss Prevention (DLP) extension for VS Code Copilot. SafeChat sits as an invisible Smart Proxy inside the Copilot agent loop — it lets the LLM use **all native tools unimpeded**, intercepts every tool result, routes structured data through format-aware AST parsers, and scrubs secrets before the LLM ever sees them.

Nothing sensitive leaves your machine.

---

## 🏗️ Architecture: The Smart Proxy

SafeChat operates on a **Polyglot AST Router** pattern. No custom tools are registered. No native tool is blocked. The proxy sits between the tool execution and the LLM context window.

### The Data Flow

```
LLM picks a tool → vscode.lm.invokeTool (native) → Force Stringify → Extract Extension
    → Smart Router:
        ├── .json  → JSON.parse → maskObjectValues() → JSON.stringify
        ├── .yaml  → yaml.parse → maskObjectValues() → yaml.stringify
        ├── .xml   → XMLParser  → maskObjectValues() → XMLBuilder
        ├── .env   → Line-by-line key=value parser → regexSanitize(value)
        ├── .ts/.py/.go/etc → BYPASS (code files are safe)
        └── .log/.txt/unknown → truncateAndSanitize(text) [250KB budget + regex]
    → Sanitized text returned to LLM context
```

### The Engine Stack

1. **Universal Object Masker (`maskObjectValues`):** Recursively walks any JS object tree. String leaves are piped through the regex dictionary. Keys are preserved untouched. Depth-limited to 64 levels to prevent stack overflow on adversarial inputs.

2. **Regex Dictionary (`regexSanitize`):** 22 enterprise patterns executed sequentially — AWS keys, GCP service accounts, RSA/PEM keys, JWTs, Slack/Stripe/GitHub tokens, credential URLs, SSN, credit cards, IBANs, and more.

3. **Truncation Guard (`truncateAndSanitize`):** 250KB byte budget. Slices at the nearest newline to avoid splitting tokens mid-credential. Appends `[TRUNCATED]` warning. Then runs the full regex dictionary.

### The Write-Guard

| Tool Type | Examples | Guard Behavior |
|---|---|---|
| **File Writes** | `apply_workspace_edit`, `edit_file`, `write_file`, `create_file` | If input contains `[MASKED_BY_SAFECHAT]`, emits ⚠️ Markdown warning to chat stream |
| **Terminal Execution** | `run_command`, `terminal_execute`, `bash`, `exec` | Same — prevents masked tokens from being written to disk or executed as shell commands |

---

## ✨ Features

- **Zero Custom Tools:** Copilot uses all native tools (file read, directory listing, terminal, search) with zero restrictions. No tool is blocked or replaced.
- **Polyglot AST Parsing:** JSON, YAML, XML, and ENV/INI files are structurally parsed, values are selectively masked, and files are reconstructed in their original format — preserving keys, structure, and comments.
- **Code File Bypass:** Source code files (`.ts`, `.js`, `.py`, `.java`, `.go`, `.rs`, `.cpp`, etc.) are passed through completely unscanned.
- **Fail-Closed Fallback:** Every AST parser is `try/catch` wrapped. Parse failures **never fail open** — they fall through to the truncation + regex catch-all.
- **250KB Memory Guard:** Raw regex scanning on payloads > 250KB is prevented by safe truncation at the nearest newline boundary.
- **Write-Guard Protection:** Both file-write and terminal tools are guarded against masked-token corruption.
- **Route Transparency:** Every sanitization surfaces its route (`ast:json`, `ast:yaml`, `line:env`, `regex:catch-all`, `bypass:code`) in the chat stream.

---

## 🚀 Installation & Setup

### 1. Install Extension
```bash
code --install-extension safe-copilot-context-0.0.1.vsix
```

### 2. VS Code Settings
No configuration required for basic operation. Optional:
```json
{
  "safechat.ignoreExtensions": [".myext", ".custom"]
}
```

---

## 🛡️ Usage: `@safechat`

Invoke SafeChat within Copilot by typing `@safechat`.

- **File Reads:** `@safechat analyze this file #file:secrets.yaml` — YAML is parsed structurally, values are masked, keys are preserved.
- **Agentic Actions:** `@safechat check the database config` — Copilot uses its native tools freely; SafeChat intercepts results transparently.
- **Terminal:** `@safechat run npm test` — Output is regex-scanned before reaching the LLM.

When data is scrubbed, you'll see a shield notification in the chat stream showing which sanitization route was used.

---

## Configuration

The extension code-level bypass list covers 40+ source code extensions. To add additional bypass extensions, use:

```json
{
  "safechat.ignoreExtensions": [".myext"]
}
```

See `ARCHITECTURE.md` for the complete routing logic and pattern dictionary.
