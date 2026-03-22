 # Safe Copilot Context — VS Code Extension

A security-focused VS Code Chat Participant (`@safechat`) that automatically detects and masks PII, credentials, and secrets in any file you attach before the context is forwarded to GitHub Copilot. Nothing sensitive leaves your machine.

---

## How it works

```
You type: @safechat explain this config #file:config.yaml
                        │
               Extension reads the file
                        │
          ┌─────────────▼──────────────────┐
          │   Tier 1 — Presidio HTTP API   │  NLP-based PII detection
          │   POST http://localhost:8000/  │  (names, emails, cards, SSNs…)
          └─────────────┬──────────────────┘
                        │ sanitized text
          ┌─────────────▼──────────────────┐
          │   Tier 2 — Regex engine        │  Catches secrets the NLP misses
          │   (api_key=, Bearer tokens,    │  (API keys, tokens, AWS keys…)
          │    AWS AKIA keys…)             │
          └─────────────┬──────────────────┘
                        │ clean text
                 Sent to Copilot LM
                        │
             Copilot response streamed
             back to Chat panel
```

The original and masked versions of each prompt are cached locally under `.vscode/.temp_cache/<timestamp>/` so you can inspect exactly what was stripped using the built-in diff viewer.

---

## Features

- **`@safechat` Chat Participant** — invoke directly in the Copilot Chat panel, attach any file as context.
- **Two-tier sanitization** — Microsoft Presidio (NLP) as the primary engine with regex as an always-on fallback.
- **17 PII entity types detected** — names, emails, phone numbers, credit cards, SSNs, IBANs, IP addresses, crypto wallets, passports, driving licences, and more.
- **Per-entity anonymization rules** — configure whether each entity type is `Mask`ed (→ `****`) or `Replace`d (→ `<EMAIL_ADDRESS>`) via a per-workspace YAML file.
- **Diff viewer** — every prompt with detected PII gets a "View Masked Diff" button that opens a side-by-side comparison of original vs. sanitized context.
- **Graceful fallback** — if the Presidio server is not running the regex engine still catches secrets; a warning is shown in chat.
- **Fully local** — the Presidio server runs on your machine; no data is sent to any external service beyond Copilot itself.
- **Configurable API URL** — point the extension at any host/port via a VS Code setting.

---

## Requirements

| Requirement | Version |
|---|---|
| VS Code | 1.90.0 or later |
| GitHub Copilot Chat extension | Latest |
| Python | 3.9 or later |
| Node.js | 18 or later (development only) |

---

## Installation

### 1 — Install the VS Code extension

Install from the VSIX file:

```bash
code --install-extension safe-copilot-context-0.0.1.vsix
```

Or open VS Code → Extensions → `···` → **Install from VSIX…** and select the file.

### 2 — Set up the Python environment for the Presidio server

The Presidio server runs as a local FastAPI service. One-time setup:

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

The server must be running whenever you use `@safechat`. Start it in a terminal:

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
| **Passports / Driving licences** | US formats |
| **API keys / secrets** | `api_key = sk-abc123`, `password = s3cr3t` |
| **Bearer tokens** | `Authorization: Bearer eyJhb…` |
| **AWS access keys** | `AKIA[0-9A-Z]{16}` |
| **URLs** | Detected and optionally masked |

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

### Viewing what was masked

After each sanitized prompt a **"View Masked Diff"** button appears in the chat response. Clicking it opens VS Code's built-in diff editor showing a side-by-side comparison:

- **Left pane** — original file content (as you attached it)
- **Right pane** — what was actually sent to Copilot

All diffs are stored in `.vscode/.temp_cache/<timestamp>/` and persist across reloads so you can review any past prompt.

---

## Sanitization Rules File

Create `.vscode/safechat-rules.yaml` in your workspace to control how each PII type is anonymized. This file is read on every prompt — no restart required.

```yaml
rules:
  AccountNumber: Mask      # → ****
  PhoneNumber: Replace     # → <PHONE_NUMBER>
  CREDIT_CARD: Mask        # → ****
  EMAIL_ADDRESS: Replace   # → <EMAIL_ADDRESS>
  PERSON: Replace          # → <PERSON>
  US_SSN: Mask             # → ****
  IP_ADDRESS: Replace      # → <IP_ADDRESS>
```

### Operations

| Operation | Output | When to use |
|---|---|---|
| `Replace` | `<PHONE_NUMBER>` | Preserves entity type context so Copilot understands what was there |
| `Mask` | `****` | Use when the entity type itself is sensitive (e.g. account numbers, SSNs) |

### Supported entity aliases

You can use either friendly names or the canonical Presidio types — both work:

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
| `Location` | `LOCATION` |
| `Date`, `DateTime` | `DATE_TIME` |
| `URL` | `URL` |
| `Passport` | `US_PASSPORT` |
| `DrivingLicense`, `DriversLicense` | `US_DRIVER_LICENSE` |
| `MedicalLicense` | `MEDICAL_LICENSE` |
| `NRP` | `NRP` |

Any entity type **not listed** in the rules file defaults to `Replace`.

---

## Presidio Server API Reference

The server runs at `http://localhost:8000` by default. Interactive docs are at `http://localhost:8000/docs`.

### `GET /health`
Liveness check.
```json
{ "status": "ok", "service": "safechat-presidio-server" }
```

### `POST /analyze`
Detect PII entities without modifying text. Useful for previewing what would be masked.

```bash
curl -X POST http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text": "Call Jane at 415-555-0198 or jane@example.com"}'
```
```json
{
  "entities_found": [
    { "entity_type": "PERSON",        "start": 5,  "end": 9,  "score": 0.85, "text_snippet": "Jane" },
    { "entity_type": "PHONE_NUMBER",  "start": 13, "end": 25, "score": 0.4,  "text_snippet": "415-555-0198" },
    { "entity_type": "EMAIL_ADDRESS", "start": 29, "end": 45, "score": 1.0,  "text_snippet": "jane@example.com" }
  ]
}
```

### `POST /anonymize`
Mask PII entities and return the anonymized text.

```bash
curl -X POST http://localhost:8000/anonymize \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "Call Jane at 415-555-0198 or jane@example.com",
    "rules": { "PHONE_NUMBER": "Mask", "EMAIL_ADDRESS": "Replace" }
  }'
```
```json
{
  "anonymized_text": "Call <PERSON> at **** or <EMAIL_ADDRESS>",
  "entities_found": [ ... ]
}
```

### `POST /sanitize`
Combined analyze + anonymize in one call. This is what the extension uses.

```bash
curl -X POST http://localhost:8000/sanitize \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "Account: 4532015112830366, contact: billing@acme.com",
    "rules": { "CREDIT_CARD": "Mask", "EMAIL_ADDRESS": "Replace" }
  }'
```
```json
{
  "sanitized_text": "Account: ****, contact: <EMAIL_ADDRESS>",
  "was_modified": true,
  "entities_found": [ ... ]
}
```

**Request fields:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `text` | string | ✅ | — | Text to process |
| `language` | string | | `"en"` | Language code |
| `entities` | string[] | | all 17 types | Limit detection to specific entity types |
| `replacement_format` | string | | `"<{entity_type}>"` | Template for Replace operation |
| `rules` | object | | `{}` | Per-entity `Mask`/`Replace` overrides |

---

## Project Structure

```
wf-sanitize-ext/
├── src/
│   ├── extension.ts          # Chat participant registration & handler
│   └── sanitizer.ts          # Two-tier sanitization engine + cache management
├── presidio_server/
│   ├── main.py               # FastAPI server (Presidio NLP engine)
│   ├── requirements.txt      # Python dependencies
│   └── README.md             # Server-specific docs
├── .vscode/
│   ├── safechat-rules.yaml   # Per-entity anonymization rules (edit this)
│   ├── launch.json           # Debug configs incl. compound launch
│   ├── tasks.json            # Build + server tasks
│   └── .temp_cache/          # Auto-generated diff cache (gitignored)
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

# Set up Python environment
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

### Packaging a VSIX

```bash
npm install -g @vscode/vsce
vsce package --allow-missing-repository
# → safe-copilot-context-0.0.1.vsix
```

---

## Privacy & Security

- **All sanitization runs locally.** The Presidio server and the regex engine both run on your machine.
- **Nothing is stored remotely.** Only the already-sanitized text is forwarded to Copilot. The original context never leaves your machine.
- **Diff cache is local.** `.vscode/.temp_cache/` is gitignored by default (a `*` gitignore is written automatically).
- **No telemetry.** The extension collects no usage data.

---

## Troubleshooting

**`@safechat` does not appear in Copilot Chat**
- Reload VS Code (`Cmd+Shift+P` → Reload Window) after installing the VSIX.
- Ensure GitHub Copilot Chat is installed and you are signed in.

**"Advanced PII detection unavailable" warning in chat**
- The Presidio server is not running. Start it:
  ```bash
  .venv/bin/uvicorn presidio_server.main:app --port 8000 --reload
  ```
- Check `safechat.presidioApiUrl` in VS Code settings matches the port you are using.
- Regex-only masking still runs as a fallback — secrets like API keys and tokens are still caught.

**Server starts but extension cannot reach it**
- Confirm the URL in settings (`safechat.presidioApiUrl`) does not have a trailing slash.
- Test with: `curl http://localhost:8000/health`

**`spacy` model not found error on server start**
```bash
python -m spacy download en_core_web_lg
```

**VSIX install succeeds but extension is not active**
- Check VS Code version is 1.90.0 or later.
- Open the Extensions panel and confirm "Safe Copilot Context" is listed and enabled.

---

## License

MIT

