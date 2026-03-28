 # Safe Copilot Context — VS Code Extension

A security-focused VS Code Chat Participant (`@safechat`) that automatically detects and masks PII, credentials, and secrets in any file you attach or that any tool reads before the context is forwarded to GitHub Copilot. Nothing sensitive leaves your machine.

---

## How it works

```
You type: @safechat explain this config #file:config.yaml
                        │
            Graceful Degradation Router
            reads the file and classifies it
                        │
          ┌─────────────▼──────────────────┐
          │  Safety Gates (pre-flight)     │  Binary files (.pdf, .zip, .dll…)
          │  blocked / bypass / truncate   │  → blocked.  Source code (.ts,
          │                                │  .py…) → bypass (no scan).
          │                                │  Files > 1 MB or minified lines
          │                                │  > 10 k chars → regex-only.
          └─────────────┬──────────────────┘
                        │
          ┌─────────────▼──────────────────┐
          │  Tier 2 — Tree-sitter CST      │  Known structured formats parsed
          │  (JSON · YAML · ENV · Props)   │  to a Concrete Syntax Tree.
          │  + Content Sniffer for unknown │  Values under sensitive keys are
          │    extensions                  │  masked; others go to Presidio.
          └─────────────┬──────────────────┘
                        │
          ┌─────────────▼──────────────────┐
          │  Tier 2B — Universal KV Lexer  │  Proprietary config formats
          │  (=  :  ->  >>  delimiters)    │  (e.g. .mycompany_conf) — regex
          │                                │  KV parser masks sensitive keys.
          └─────────────┬──────────────────┘
                        │
          ┌─────────────▼──────────────────┐
          │  Tier 3 — Full DLP             │  Unstructured text gets the full
          │  Regex Dictionary (22 patterns)│  pipeline: known-pattern regex →
          │  Shannon Entropy Scanner (≥3.8)│  entropy-gated unknown secret
          │  Bare Token Detector (>4 bits) │  scanner → Presidio NLP for
          │  Presidio PII Engine (12 types)│  human PII.
          └─────────────┬──────────────────┘
                        │ clean text
                 Sent to Copilot LM
                        │
          Full agentic tool loop (≤15 rounds):
          search code, read files, run commands
          — ALL tool results pass the mesh too
                        │
             Copilot response streamed
             back to Chat panel
```

The original and masked versions of each sanitization event are cached locally under `.vscode/.temp_cache/latest/` so you can inspect exactly what was stripped using the built-in diff viewer.

---

## Features

- **`@safechat` Chat Participant** — invoke directly in the Copilot Chat panel; attach any file as context.
- **Sanitization Mesh** — a mandatory multi-layer checkpoint for ALL data entering the model's context window: attached files, tool reads, search results, and terminal output are all sanitized.
- **Graceful Degradation Pipeline** — 5-engine routing with automatic fall-through:
  - **Blocked** — binary files (40+ extensions: `.pdf`, `.zip`, `.dll`, `.png`, `.sqlite`, etc.) and NUL-byte content are rejected before any processing.
  - **Bypass (Tier 1)** — safe files (source code, docs, images) skip scanning entirely for zero overhead.
  - **Tree-sitter CST (Tier 2)** — JSON, YAML, ENV/dotenv, and Java Properties are parsed into a Concrete Syntax Tree using native WASM grammars. A **Content Sniffer** also detects unknown extensions that contain a known format (e.g. `.myconfig` that is actually JSON). Only values under sensitive keys are masked; all other values are sent to Presidio NLP.
  - **Universal KV Lexer (Tier 2B)** — proprietary and vendor-specific config files that use `=`, `:`, `->`, or `>>` as delimiters are parsed line-by-line; only lines whose key matches a secret keyword list are masked.
  - **Full DLP (Tier 3)** — unstructured text gets the complete pipeline: 22-pattern regex dictionary → Shannon Entropy scanner (≥ 3.8 threshold for unknown secrets) → bare high-entropy token detector → Presidio NLP for human PII (12 entity types). Mega-files (> 1 MB) and minified files (first line > 10 000 chars) use this engine but **skip** the Presidio NLP call to protect latency.
- **Shannon Entropy Engine** — mathematically detects unknown/future secret formats by measuring randomness. Replaces brittle pattern matching with `calculateShannonEntropy()` and context-anchored `applyEntropyMasking()`.
- **Safe file tools** — `safechat_read_file` and `safechat_read_directory` are registered as LM tools so the model can read workspace files and directories via a sanitized pipeline.
- **Native tool blocklist** — native file-read, directory-listing, and workspace-search tools are stripped from the model's tool menu and, if called anyway, are intercepted and rerouted through the safe alternatives.
- **Terminal-aware sanitization** — ANSI escape codes are stripped; CLI-specific patterns (curl headers, env var exports, JSON credential fields) are caught separately from general file patterns.
- **12 PII entity types** — names, emails, phone numbers, credit cards, SSNs, IBANs, bank accounts, crypto wallets, IP addresses, URLs, card CVV, and card expiry. Hallucination-prone entities (`US_DRIVER_LICENSE`, `US_ITIN`) are intentionally excluded.
- **4 anonymizer operations** — `replace`, `mask`, `redact`, or `hash` per entity type, configured in a single YAML file.
- **File type allowlist** — restrict scanning to only data/config file extensions (`.yaml`, `.json`, `.env`, etc.); non-matching files are forwarded as-is to Copilot without modification.
- **Full agentic behaviour** — passes all available VS Code tools to the LLM and runs an agentic tool-calling loop (up to 15 rounds): search code, read files, run commands — identical to native Copilot Agent mode.
- **Conversation continuity** — per-file state cache with `mtime`-based invalidation keeps all attached file context live across multiple turns in the same chat.
- **User-defined custom recognizers** — add your own regex patterns (employee IDs, ticket numbers, internal references) via the YAML config; no server restart needed.
- **Append-only diff cache** — every sanitization event during a session (both user-attached files and autonomous tool reads) is written to `.vscode/.temp_cache/latest/` with a deduplicated manifest.
- **Diff viewer** — every sanitization event produces a "View Masked Diff" button that opens a side-by-side comparison of original vs. sanitized content; multiple files are presented in a QuickPick selector.
- **Graceful fallback** — if the Presidio server is not running the regex+heuristic engine still catches secrets; a warning is shown in chat.
- **Fully local** — the Presidio server runs on your machine; no data is sent to any external service beyond Copilot itself.

---

## Requirements

| Requirement | Version |
|---|---|
| VS Code | 1.95.0 or later |
| GitHub Copilot Chat extension | Latest |
| Python | 3.9 or later (optional — for Presidio PII engine) |
| Node.js | 18 or later (development only) |

---

## Installation

### 1 — Install the VS Code extension

Install from the VSIX file:

```bash
code --install-extension safe-copilot-context-0.0.1.vsix
```

Or open VS Code → Extensions → `···` → **Install from VSIX…** and select the file.

### 2 — Set up the Python environment for the Presidio server (optional)

The Presidio server provides NLP-based human PII detection (names, emails, phone numbers, credit cards, SSNs, etc.). The extension works without it (Tier 2 AST parsing + Tier 3 regex/entropy engines still catch all secrets), but Presidio catches human PII that regex cannot (e.g. people's names).

```bash
# Create a virtual environment in the project folder
python3 -m venv .venv

# Activate it
source .venv/bin/activate          # macOS / Linux
.venv\Scripts\activate             # Windows

# Install dependencies
pip install fastapi "uvicorn[standard]" presidio-analyzer presidio-anonymizer spacy

# Download the spaCy NLP model (required by Presidio)
python -m spacy download en_core_web_lg
```

### 3 — Start the Presidio server

The server must be running if you want Tier 1 detection. Start it in a terminal:

```bash
cd /path/to/wf-sanitize-ext
.venv/bin/uvicorn presidio_server.main:app --host 0.0.0.0 --port 8000 --reload
```

You should see:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

Alternatively, use the built-in VS Code task: `Cmd+Shift+P` → **Tasks: Run Task** → **Start Presidio Server**.

Or press `F5` with the **"Extension + Presidio Server"** compound launch config selected in the Run & Debug panel — this starts both the server and the Extension Development Host in one step.

---

## VS Code Settings

Open settings (`Cmd+,`) and search for **Safe Copilot** or add these to your `settings.json`:

```json
{
  "safechat.presidioApiUrl": "http://localhost:8000",
  "safechat.rulesFile": ".vscode/safechat-rules.yaml"
}
```

| Setting | Default | Description |
|---|---|---|
| `safechat.presidioApiUrl` | `http://localhost:8000` | Base URL of the running Presidio server. Change this if you run the server on a different port or host. |
| `safechat.rulesFile` | `.vscode/safechat-rules.yaml` | Workspace-relative path to the YAML file that controls per-entity masking behaviour. |

---

## Using the Extension

### Basic usage

1. Open the Copilot Chat panel (`Ctrl+Alt+I` / `Cmd+Alt+I`).
2. Type `@safechat` followed by your question.
3. Attach a file using `#file:path/to/file` or drag-and-drop into the chat.
4. Press Enter — the extension sanitizes the file content before it reaches Copilot.

```
@safechat review this service config for issues #file:config/production.yaml
```

```
@safechat what does this function do? #file:src/payment-processor.ts
```

### Autonomous tool reads

When the model needs to explore the codebase, it calls `safechat_read_file` or `safechat_read_directory` — both of which sanitize data before returning it. You can also ask explicitly:

```
@safechat scan the scripts folder for any hardcoded credentials
```

The model will call `safechat_read_directory` with `directoryPath: "scripts"`. Any files containing secrets will be masked before the content is returned, and a **"View Masked Diff"** button will appear in the chat.

### What gets sanitized

| Category | Examples detected |
|---|---|
| **Names** | `John Smith`, `Alice Brown` |
| **Email addresses** | `user@company.com` |
| **Phone numbers** | `415-555-0198`, `(800) 555-0199` |
| **Credit card numbers** | `4532015112830366` |
| **Bank / account numbers** | `3530111333300000` |
| **SSNs** | `078-05-1120` |
| **IBAN codes** | `GB29NWBK60161331926819` |
| **IP addresses** | `192.168.1.254`, `10.0.0.1` |
| **Crypto wallets** | `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2` |
| **Card CVV / CVC** | `cvv: 123`, `cvc2: 4567` |
| **API keys / secrets** | `api_key = sk-abc123`, `password = s3cr3t`, `const apiKey = "..."` |
| **Bearer tokens** | `Authorization: Bearer eyJhb…` |
| **AWS access keys** | `AKIA[0-9A-Z]{16}` |
| **PEM private keys** | Full `BEGIN/END PRIVATE KEY` blocks |
| **GitHub / GitLab / npm tokens** | `ghp_…`, `npm_…`, `sk-…` prefix detection |
| **High-entropy bare tokens** | 20+ char strings with Shannon entropy > 4 bits |
| **Unknown secrets (entropy-gated)** | Any `key = value` where value has Shannon entropy ≥ 3.8 |
| **CLI secrets** | `--token value`, `export SECRET=...`, `curl -H "Authorization: ..."` |
| **ANSI terminal output** | Escape codes stripped before scanning |

### Example — config file with credentials

**Original file attached to `@safechat`:**
```yaml
database:
  host: prod-db.internal.company.com
  username: admin
  password: s3cr3tP@ssword!
owner_email: dev@company.com
owner_phone: "(800) 555-0199"
stripe_key: sk_live_abc123xyz
```

**What Copilot receives after sanitization:**
```yaml
database:
  host: <URL>
  username: admin
  password: [MASKED_BY_SAFECHAT]
owner_email: <EMAIL_ADDRESS>
owner_phone: <PHONE_NUMBER>
stripe_key: [MASKED_BY_SAFECHAT]
```

### Example — source file with hardcoded secrets

**Original:**
```typescript
const DB_URL = "postgres://admin:RootPass789@prod-db.aws.com:5432/payments";
const API_KEY = "sk-live-abcdef123456";
const OWNER = "Jane Doe <jane.doe@acme.org>";
```

**After sanitization:**
```typescript
const DB_URL = "postgres://admin:[MASKED_BY_SAFECHAT]@<URL>:5432/payments";
const API_KEY = "[MASKED_BY_SAFECHAT]";
const OWNER = "<PERSON>";
```

### Example — search result snippet (Tier 2b heuristic)

When the model calls a search tool and results contain code snippets, the heuristic scanner runs:

**Raw search result:**
```
[src/config.ts:12] const dbPassword = "SuperSecret123!"
[src/auth.ts:5]    ghp_ABCDEFGHIJKLMNOPQRSTabcdef1234567890
```

**After sanitization:**
```
[src/config.ts:12] const dbPassword = "[MASKED_BY_SAFECHAT]"
[src/auth.ts:5]    [MASKED_BY_SAFECHAT]
```

### Viewing what was masked

After each sanitization event a **"View Masked Diff"** button appears in the chat response. Clicking it opens VS Code's built-in diff editor:

- **Left pane** — original file content (as attached or read by the tool)
- **Right pane** — what was actually sent to Copilot

When multiple files were masked in one session, a QuickPick selector lets you choose which file to inspect. All diffs persist across reloads in `.vscode/.temp_cache/latest/` and new entries are appended without overwriting existing ones.

---

## Sanitization Pipeline Details

### Smart Router — 3-Tier Content Classification

The Smart Router (`router.ts`) inspects each file's extension and content to assign it to one of three tiers:

| Tier | Category | What happens | Example files |
|---|---|---|---|
| **1** | `bypass` | No scanning — passed through as-is | `.ts`, `.py`, `.go`, `.md`, `.html` |
| **2** | `ast` | AST-parsed; only sensitive key values are masked | `.json`, `.yaml`, `.env`, `.properties`, `.xml` |
| **3** | `full_dlp` | Full regex + entropy + Presidio pipeline | `.log`, `.txt`, `.csv`, `.sql`, unknown formats |

Files with unknown extensions are sniffed by a content heuristic (`guessUnknownFileType()`) that checks for JSON braces, YAML colons, XML tags, etc.

### Tier 2 — AST Guardian Pipeline

Structured files are parsed into a key-value tree. The AST walker:
1. Checks each key against `DYNAMIC_AST_KEYS` (20 secret-related keywords like `password`, `token`, `secret`, `api_key`, etc.)
2. If the key is sensitive → masks the value immediately with `[MASKED_BY_SAFECHAT]`
3. If the key is NOT sensitive → sends the value to Presidio NLP to check for human PII (names, emails, etc.)

Supported formats: JSON, YAML, ENV/dotenv, Java Properties, XML.

### Tier 3 — Full DLP Pipeline

| Stage | What it catches |
|---|---|
| **regexSanitize (Step 1)** | 22 high-confidence patterns: AWS keys, GitHub/GitLab/npm tokens, JWTs, Bearer headers, PEM blocks, database URLs, Stripe/Slack/Twilio keys, credential URLs, query param secrets |
| **applyEntropyMasking (Step 2)** | Context-anchored Shannon Entropy scanner — finds any `key=value` where the key contains a secret-related word and the value has entropy ≥ 3.8 (catches unknown/future token formats) |
| **Bare Token Detector (Step 3)** | Standalone high-entropy strings (20+ chars, entropy > 4, 3+ character classes) with known service prefixes (`ghp_`, `sk-`, `AKIA`, `eyJ`, etc.) |
| **Presidio NLP** | Human PII: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, IBAN_CODE, US_BANK_NUMBER, CRYPTO, IP_ADDRESS, URL, CARD_CVV, CARD_EXPIRY |

### Terminal & Search Modes

| Mode | Pipeline | Used for |
|---|---|---|
| `general` | Smart Router → Tier 1/2/3 | Attached files, tool reads |
| `terminal` | stripAnsiCodes → terminalSanitize → regexSanitize | Terminal / shell output |
| `search` | regexSanitize | Workspace search, grep results |

---

## Native Tool Interception (Sanitization Mesh)

The extension enforces a mandatory sanitization boundary around ALL tool invocations:

### Tool menu filtering (Step 6)
Before the agentic loop starts, native file-read, directory-listing, and workspace-search tools are stripped from the model's tool menu so the model cannot select them. Only `safechat_read_file` and `safechat_read_directory` are available for I/O.

Blocked categories:
- **File-read tools**: `readFile`, `read_file`, `vscode_readFile`, `mcp_*read*file`, and similar
- **Directory tools**: `list_dir`, `read_folder`, `listDirectory`, `mcp_*dir*`, and similar
- **Search tools**: `workspace_search`, `find_files`, `grep_search`, `vscode_*search*`, and similar

### Defense-in-depth redirect (Step 8)
If a native tool is nonetheless invoked (e.g. via a tool reference the user explicitly attached), the agentic loop intercepts it:

| Tool type | Action |
|---|---|
| Native file-read | Redirect to `safechat_read_file` — extracts the file path from the tool input and re-invokes via the safe tool |
| Native directory | Redirect to `safechat_read_directory` — extracts the directory path and re-invokes via the safe tool |
| Native search | Allow execution but force-sanitize the raw result through `sanitizePipeline('search')` |

### Automatic diff + UI feedback
When `safechat_read_file` or `safechat_read_directory` masks data during an autonomous tool call, they automatically:

1. Append the masked file pair to `.vscode/.temp_cache/latest/` (without deleting previously cached files)
2. Update the `sessionStateMap` so subsequent reads of the same file return the already-masked version
3. Render a shield notice and "View Masked Diff" button in the chat stream

---

## Sanitization Rules File

All user controls live in a single file: `.vscode/safechat-rules.yaml`. This file is read on **every prompt** — no server restart or VS Code reload is required.

The file has four independent sections — use any combination:

```yaml
# 1. Force custom extensions into the Tree-sitter AST engine (Tier 2)
ast_extensions:
  - .custom_env
  - .kube_vars

# 2. Force custom extensions into the Full DLP engine (Tier 3)
full_dlp_extensions:
  - .audit_log
  - .chat_transcript

# 3. Per-entity anonymizer operations
rules:
  AccountNumber: mask
  PhoneNumber: replace
  US_SSN: redact
  CREDIT_CARD: hash

# 4. User-defined regex recognizers for Presidio NLP (no restart needed)
custom_recognizers:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
    score: 0.9
    context:
      - employee
      - staff
```

---

### Section 1 — Force AST routing (`ast_extensions`)

Extensions listed here are forced through the **Tier 2 AST Guardian** (Tree-sitter parser or Universal KV Lexer, depending on content). Use this for internal proprietary config formats whose content the automatic Content Sniffer might not recognise.

Extensions not listed here are still automatically routed by the Content Sniffer — you only need to list extensions that require an explicit override.

### Section 2 — Force Full DLP routing (`full_dlp_extensions`)

Extensions listed here skip the AST/KV engines entirely and go straight to the **Tier 3 Full DLP** pipeline (regex + entropy + Presidio NLP). Use this for log files, audit dumps, and other unstructured text that may contain human PII not detectable by key-name matching.

---

### Section 3 — Anonymizer operations (`rules`)

Controls how each detected entity type is transformed:

| Operation | Output example | Notes |
|---|---|---|
| `replace` | `<PHONE_NUMBER>` | **Default.** Preserves entity type label for Copilot context. |
| `mask` | `************` | Replaces every character with `*`. |
| `redact` | *(empty string)* | Completely removes the text. |
| `hash` | `b7531e08…` | One-way SHA-256 digest. Repeatable — identical values produce identical hashes. |

```yaml
rules:
  PhoneNumber:   replace   # → <PHONE_NUMBER>
  AccountNumber: mask      # → ************
  US_SSN:        redact    # (removed entirely)
  CREDIT_CARD:   hash      # → sha256 digest
```

#### Supported entity aliases

| Friendly alias | Presidio entity type |
|---|---|
| `PhoneNumber`, `Phone` | `PHONE_NUMBER` |
| `AccountNumber`, `BankAccount` | `US_BANK_NUMBER` |
| `Email`, `EmailAddress` | `EMAIL_ADDRESS` |
| `CreditCard`, `CC` | `CREDIT_CARD` |
| `SSN`, `SocialSecurityNumber` | `US_SSN` |
| `IPAddress`, `IP` | `IP_ADDRESS` |
| `Person`, `Name` | `PERSON` |
| `IBAN`, `IBANCode` | `IBAN_CODE` |
| `Crypto`, `Bitcoin` | `CRYPTO` |
| `URL` | `URL` |
| `CardCVV`, `CVV` | `CARD_CVV` |
| `CardExpiry` | `CARD_EXPIRY` |

Any entity type **not listed** in `rules` defaults to `replace`.

---

### Section 3 — Custom recognizers (`custom_recognizers`)

Define your own regex-based recognizers without touching the server:

```yaml
custom_recognizers:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
    score: 0.9
    context:
      - employee
      - staff

  - name: INTERNAL_TICKET
    pattern: "JIRA-\\d{4,6}"
    score: 0.85

rules:
  EMPLOYEE_ID:     mask
  INTERNAL_TICKET: redact
```

---

## Registered LM Tools

Two Language Model Tools are registered with VS Code, making them available to the model in the tool menu:

### `safechat_read_file`
- **Input**: `{ filePath: string }` (absolute or workspace-relative)
- **Behaviour**: (1) checks SessionStateManager for a previously masked version on disk; (2) checks in-memory `fileStateCache`; (3) reads fresh from disk and applies `regexSanitize`; if data was masked, appends to diff cache and renders a UI button
- **Safety**: Never blocked by its own blocklist

### `safechat_read_directory`
- **Input**: `{ directoryPath: string, maxDepth?: number, maxFiles?: number }`
- **Defaults**: `maxDepth: 5` (hard cap: 10), `maxFiles: 50` (hard cap: 200)
- **Behaviour**: Recursively collects files (sorted: files first, then directories); checks cache tiers per file; fresh reads are passed through `regexSanitize`; tracks all masked files and appends them to the diff cache in one batch; renders a UI button with the masked file count
- **Skipped directories**: `node_modules`, `.git`, `.venv`, `__pycache__`, `.temp_cache`, `out`, `dist`, `build`, `.next`, `.nuxt`, `coverage`

---

## Presidio Server API Reference

The server runs at `http://localhost:8000` by default. It is a lean **Human PII & Financial Data engine** — all developer secrets, CI/CD tokens, and infrastructure configs are handled by the TypeScript extension.

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check (returns entity count) |
| `/sanitize` | POST | Analyze + anonymize in one call (used by the extension) |
| `/docs` | GET | Swagger UI (auto-generated) |
| `/redoc` | GET | ReDoc API reference (auto-generated) |

### Active Entities (12)

`PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `US_SSN`, `IBAN_CODE`, `US_BANK_NUMBER`, `CRYPTO`, `IP_ADDRESS`, `URL`, `CARD_CVV`, `CARD_EXPIRY`

> **Anti-hallucination:** `US_DRIVER_LICENSE` and `US_ITIN` are intentionally excluded — they cause false positives on source code patterns like `apiVersion: v1`.

### `POST /sanitize`

```bash
curl -X POST http://localhost:8000/sanitize \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "Account: 4532015112830366, SSN: 078-05-1120",
    "rules": { "CREDIT_CARD": "mask", "US_SSN": "redact" }
  }'
```
```json
{
  "sanitized_text": "Account: ****, SSN: ",
  "was_modified": true,
  "entities_found": [ ... ]
}
```

**Request body:**

| Field | Type | Default | Description |
|---|---|---|---|
| `text` | string | — | Text to process |
| `rules` | object | `{}` | Per-entity operation (`replace`/`mask`/`redact`/`hash`) |

---

## Project Structure

```
wf-sanitize-ext/
├── src/
│   ├── extension.ts          # Chat participant, safe tools, agentic loop, cache helpers
│   ├── sanitizer.ts          # Thin orchestrator — wires 5-engine graceful degradation pipeline
│   ├── router.ts             # Graceful Degradation Router — determineSanitizationRoute(), Content Sniffer
│   ├── treeSitterManager.ts  # WASM grammar loader — bash, json, properties, yaml (parallel init)
│   ├── regexSanitizer.ts     # Mega-Dictionary, Shannon Entropy Engine, terminal sanitizer
│   └── astSanitizer.ts       # CST Guardian (Tree-sitter) + Universal KV Lexer (Tier 2B)
├── wasm/
│   ├── tree-sitter.wasm      # Tree-sitter runtime (196 KB)
│   ├── tree-sitter-bash.wasm # ENV / dotenv grammar (1.4 MB)
│   ├── tree-sitter-json.wasm # JSON grammar (6 KB)
│   ├── tree-sitter-properties.wasm  # Java Properties / INI grammar (11 KB)
│   └── tree-sitter-yaml.wasm # YAML grammar (194 KB)
├── presidio_server/
│   ├── main.py               # FastAPI server (Human PII & Financial engine)
│   ├── profiles.py           # Active entity list (12 types, anti-hallucination)
│   ├── recognizers/
│   │   ├── __init__.py        # Exports CardCvvRecognizer, CardExpiryRecognizer
│   │   └── financial.py       # Card CVV + Card Expiry pattern recognizers
│   ├── requirements.txt      # Python dependencies
│   └── README.md             # Server-specific docs
├── .vscode/
│   ├── safechat-rules.yaml   # Per-entity anonymization rules (edit this)
│   ├── launch.json           # Debug configs incl. compound launch
│   ├── tasks.json            # Build + server tasks
│   └── .temp_cache/          # Auto-generated diff cache (gitignored)
│       └── latest/           # Most recent session's masked file pairs + manifest.json
├── out/                      # Compiled JS (generated)
├── package.json              # Extension manifest
└── tsconfig.json
```

---

## Development Setup

```bash
# Clone and install Node dependencies
git clone <repo-url>
cd wf-sanitize-ext
npm install

# Set up Python environment (optional — for Presidio Tier 1)
python3 -m venv .venv
source .venv/bin/activate
pip install -r presidio_server/requirements.txt
python -m spacy download en_core_web_lg

# Compile TypeScript
npm run compile

# Launch both extension host and Presidio server in one step
# Open Run & Debug → select "Extension + Presidio Server" → F5
```

### Available launch configs

| Config | Description |
|---|---|
| **Run Extension** | Launches VS Code Extension Development Host only |
| **Start Presidio Server** | Runs the FastAPI server with hot-reload via debugpy |
| **Extension + Presidio Server** | Compound — starts both with a single F5; stopping one stops both |

### NPM scripts

```bash
npm run compile   # one-off TypeScript compile
npm run watch     # compile on save
npm run lint      # ESLint
```

### Rebuilding and reinstalling

After making changes to any file in `src/`:

```bash
# Compile + repackage
npm run compile
npx @vscode/vsce package --allow-missing-repository

# Reinstall
code --install-extension safe-copilot-context-0.0.1.vsix
```

---

## Privacy & Security

- **All sanitization runs locally.** The Presidio server and the regex/heuristic engines all run on your machine.
- **Nothing is stored remotely.** Only the already-sanitized text is forwarded to Copilot. The original context never leaves your machine.
- **Diff cache is local.** `.vscode/.temp_cache/` is gitignored by default (a `*` gitignore is written automatically on first use).
- **Tool boundary enforcement.** Native file-read, directory, and search tools are blocked at two layers: the tool menu (before the loop starts) and the agentic loop redirect guard (defense-in-depth).
- **Anti-hallucination Presidio config.** `US_DRIVER_LICENSE` and `US_ITIN` are deliberately excluded from the entity list to prevent false positives on source code.
- **No telemetry.** The extension collects no usage data.

---

## Troubleshooting

**`@safechat` does not appear in Copilot Chat**
- Reload VS Code (`Cmd+Shift+P` → Reload Window) after installing the VSIX.
- Ensure GitHub Copilot Chat is installed and you are signed in.

**"Advanced PII detection unavailable" warning in chat**
- The Presidio server is not running. Tier 1 (NLP) is skipped but Tier 2 (regex) and Tier 2b (heuristics) still run.
- Start the server: `.venv/bin/uvicorn presidio_server.main:app --port 8000 --reload`
- Check `safechat.presidioApiUrl` in VS Code settings matches the port you are using.

**"No cached diff available yet" when clicking View Masked Diff**
- This occurs if no sanitizable content has been processed yet in this session.
- Attach a file with a detectable secret and send a prompt — the button will appear automatically.

**Server starts but extension cannot reach it**
- Confirm the URL in settings (`safechat.presidioApiUrl`) does not have a trailing slash.
- Test with: `curl http://localhost:8000/health`

**`spacy` model not found error on server start**
```bash
python -m spacy download en_core_web_lg
```

**VSIX install succeeds but extension is not active**
- Check VS Code version is 1.95.0 or later.
- Open the Extensions panel and confirm "Safe Copilot Context" is listed and enabled.

---

## License

MIT

