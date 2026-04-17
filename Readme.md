# Safe Copilot Context — VS Code Extension (`@safechat`)

An Enterprise Data Loss Prevention (DLP) extension for VS Code Copilot. SafeChat automatically detects and masks PII, credentials, and secrets in any file attached to context, and intercepts **all native and MCP tool calls** via a Zero-Trust Sanctuary before forwarding results to GitHub Copilot. 

Nothing sensitive leaves your machine.

---

## 🏗️ Architecture: Hybrid Edge & The Zero-Trust Sanctuary

SafeChat operates on a mandatory, multi-layered interception architecture ("The Sanitization Mesh").

### The Edge Processing Engine
The extension combines two local engines to achieve zero-latency masking and advanced NLP contextualization:
1. **TypeScript Edge Service (Tier 1 & Tier 2):** Scans payloads at >100MB/s. Powers the AST Config Guardians, Regex Dictionaries (22 active patterns), and the **Shannon Entropy Heuristic Engine** (detects unknown/future token structures).
2. **Python Presidio Instance (Tier 3):** An optional, local FastAPI instance that leverages `Spacy` (en_core_web_lg) to detect unstructured human PII (Names, Phone Numbers, SSNs, IBANs, etc.) contextually.

### Zero-Friction UX: The Tool Matrix Interceptor
The extension sits between the Copilot Agent Loop and VS Code's Language Model API. It intercepts background agent actions without disrupting the chat experience.

| Tool Category | Native VS Code Tool | SafeChat Action | Resulting Pathway |
|---|---|---|---|
| **File/Dir Read** | `vscode_readFile` | **Redirected** | Custom `safechat_read*` tools → 5MB Memory Gate & `.gitignore` routing |
| **Codebase Search** | `#codebase` | **Delegated** | LLM instructed to rely entirely on native sandboxed Search Tools |
| **Terminal / CLI** | `vscode_runCommand` | **Redirected & Warned** | Shell Integration Buffer (512KB) + Pre-execution Write-Guard |
| **Write Tools** | `vscode_applyEdit` | **Warn-and-Proceed** | Executes normally; Stream warning triggered if payload contains `[MASKED]` |
| **MCP & 3rd Party** | `jira`, `splunk` | **Universal Sandbox** | MCP Triage Router → 30s Zombie Killer Timeout → Profiling |

> **Universal Interceptor Guard:** The framework natively disables dangerous native search/read tools and funnels all unhandled tools into the **Universal MCP Sandbox** (`invokeTool` wrapper with 30s timeout execution guard).

---

## ✨ Features

- **The MCP Triage Router:** Dynamically routes high-volume Model Context Protocol (MCP) tool payloads via wildcard matching (`bypass`, `json-keys`, `regex-only`, `nlp-full`).
- **Zombie Process Defense:** The Universal Sandbox uses linked `CancellationTokenSources` to actively terminate uncooperative MCP processes rather than leaking them into the background.
- **Dynamic GitIgnore & Symlink Jails:** Directory traversals dynamically compile and merge `.gitignore` rules while actively halting `realpath` symlink escapes that target outer-OS environments (e.g., `~/.ssh`).
- **Cognitive Data-Fences:** All sanitized file payloads are structurally encased in LLM constraint tags (`[SAFECHAT_FILE_CONTEXT_BEGIN]`) to heavily mitigate string-based prompt injection/cognitive subversion.
- **Homoglyph & Encoding Armor:** Decodes `UTF-16` payloads seamlessly to catch encoded secrets and executes `NFKD` normalization to thwart Cyrillic lookalike key obfuscations.
- **OOM Protection & Cache DoS Guard:** Enforces strict 5MB chunk limits on reads, 50KB slicing on Regex arrays, and bounds `.temp_cache` with a 200-document FIFO eviction cycle and 24h Garbage Collection.
- **Terminal & Editor Write-Guards:** Secures interactive terminal commands and `WorkspaceEdit` actions. Pre-execution inspections stop "masked-token overwrites" before the user presses Enter or saves.
- **AST Guardian:** Key-value parsers for structured configs (`.json`, `.yaml`, `.env`, `.csv`, `.toml`). Recursively masks depth up to 30 keys.
- **Shannon Entropy Engine:** Mathematically detects unknown secret formats globally by calculating character randomness.

---

## 🚀 Installation & Setup

### 1. Install Extension
```bash
code --install-extension safe-copilot-context-0.0.1.vsix
```

### 2. Configure Presidio Server (Optional, NLP PII Detection)
The Tier 3 NLP engine requires a local Python FastAPI server. Regex and Entropy scanners (Tiers 1 & 2) will still function if this is skipped.

```bash
# Initialize and install
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi "uvicorn[standard]" presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_lg

# Run the server on port 8000
PYTHONPATH="$PWD" presidio_server/.venv/bin/uvicorn presidio_server.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. VS Code Settings
Add these to your `settings.json`:
```json
{
  "safechat.presidioApiUrl": "http://localhost:8000",
  "safechat.rulesFile": ".vscode/safechat-rules.yaml"
}
```

---

## 🛡️ Usage: `@safechat`

Invoke SafeChat within Copilot by typing `@safechat`. 

- **Static Context:** `@safechat analyze this file #file:secret.yaml`
- **Agentic Actions:** `@safechat check my splunk environment for login errors.` (The Universal Interceptor will securely launch the `splunk_query` MCP tool, process it through the MCP Server Triage Router at 50KB chunks, escape Markdown output, and enforce budget constraints).

### Verification & Diff Tools
Whenever a payload is modified by the sanitizer, SafeChat outputs a **View Masked Diff** module into the chat stream. Click it to view exactly what was blocked locally within `.vscode/.temp_cache/latest`. No hidden transformations.

---

## Configuration (`safechat-rules.yaml`)
Administrators fully customize the routing and entity operations in `.vscode/safechat-rules.yaml`. (Refer to the comments within the YAML for MCP wildcard deployment, Tier 2 JSON AST lists, and custom presidio regex injections).

See `ARCHITECTURE.md` for a complete breakdown of the mathematical operations and sequential routing of the extension.
