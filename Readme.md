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
- **70+ PII entity types** — names, emails, phone numbers, credit cards, SSNs, IBANs, SWIFT codes, API keys, JWTs, AWS keys, database URLs, K8s secrets, CI/CD tokens, and more.
- **5 anonymizer operations** — `replace`, `mask`, `redact`, `hash`, or `encrypt` per entity type, configured in a single YAML file.
- **File type allowlist** — restrict scanning to only data/config file extensions (`.yaml`, `.json`, `.env`, etc.); code files are excluded by default when enabled.
- **File ignore list** — specify workspace-relative paths that are never read, sanitized, or forwarded.
- **Folder ignore list** — exclude entire directory trees (e.g. `secrets/`, `infra/tfvars`) in one entry.
- **User-defined custom recognizers** — add your own regex patterns (employee IDs, ticket numbers, internal references) via the YAML config; no server restart needed.
- **5 sanitization profiles** — `financial`, `developer`, `infrastructure`, `cicd`, `full` — load the right set of recognizers for your context.
- **Diff viewer** — every prompt with detected PII gets a "View Masked Diff" button that opens a side-by-side comparison of original vs. sanitized context.
- **Interactive documentation** — built-in web UI at `http://localhost:8000/docs/ui` lists every entity type, recognizer, and anonymizer operation with examples.
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

All user controls live in a single file: `.vscode/safechat-rules.yaml`. This file is read on **every prompt** — no server restart or VS Code reload is required.

> **Tip:** A fully-commented template with all entity types, examples, and hints is pre-installed at `.vscode/safechat-rules.yaml`. An interactive YAML generator is also available at `http://localhost:8000/docs/ui`.

The file has four independent sections — use any combination:

```yaml
# 1. Which file types to scan (absent = scan everything)
include_extensions:
  - .yaml
  - .json
  - .env

# 2. Specific files to never forward to Copilot
ignore_files:
  - .env.local
  - secrets/dev-creds.json

# 3. Entire folders to never forward to Copilot
ignore_folders:
  - secrets
  - infra/tfvars
  - config/local

# 3. Per-entity anonymizer operations
rules:
  AccountNumber: mask
  PhoneNumber: replace
  US_SSN: redact
  CREDIT_CARD: hash

# 4. User-defined regex recognizers (no restart needed)
custom_recognizers:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
    score: 0.9
    context:
      - employee
      - staff
```

---

### Section 1 — File extension allowlist (`include_extensions`)

When present, only files whose extension matches the list are scanned and sanitized. Files that do not match are **skipped** — an `ℹ️ Skipped` notice appears in chat. If the section is absent or empty, all attached files are scanned (the original behaviour).

This lets you exclude code files (`.ts`, `.py`, `.go`, `.java`) while still catching secrets in config and data files. A commented template with every supported extension is pre-installed in `.vscode/safechat-rules.yaml`. Key groups:

```yaml
include_extensions:
  # Universal config formats
  - .yaml         # Kubernetes, Helm, CI/CD, Spring Boot, GitLab CI
  - .yml
  - .json         # package.json, appsettings.json, tsconfig.json
  - .xml          # Maven pom.xml, web.config, Spring context
  - .toml         # Cargo.toml, pyproject.toml, Pipfile, Poetry
  - .ini          # php.ini, tox.ini, pytest.ini
  - .cfg          # setup.cfg, pip, flake8, mypy
  - .conf         # Nginx, HAProxy, Apache, Redis, sshd_config
  - .config       # NuGet.config, app.config, web.config (.NET)
  - .properties   # Java application.properties, gradle.properties

  # Secret & credential dotfiles
  - .env          # dotenv (.env, .env.production — matched by full basename)
  - .npmrc        # npm / yarn / pnpm registry auth tokens
  - .yarnrc       # Yarn 1.x credentials
  - .gemrc        # Ruby gem source credentials
  - .netrc        # machine-level FTP/HTTP/Git credential store
  - .pgpass       # PostgreSQL password file
  - .terraformrc  # Terraform CLI config (registry tokens)
  - .curlrc       # curl config (proxy creds, headers)

  # Certificates & keys
  - .pem          # PEM certificate or private key
  - .crt          # X.509 certificate
  - .cer          # Windows certificate
  - .key          # private key (RSA, EC, PKCS#8)
  - .pub          # SSH/GPG public key
  - .p12          # PKCS#12 keystore
  - .pfx          # Windows PKCS#12
  - .jks          # Java KeyStore
  - .p8           # Apple AuthKey (APNs, App Store Connect)
  - .ppk          # PuTTY private key

  # Infrastructure as Code
  - .tf           # Terraform source (provider creds, resource config)
  - .tfvars       # Terraform variable values (often secrets)
  - .tfstate      # Terraform state (contains all resource attributes!)
  - .hcl          # HashiCorp Configuration Language (Vault, Consul)

  # JVM / Java, Kotlin, Groovy
  - .gradle       # Groovy Gradle build (repo credentials)
  - .kts          # Kotlin Script / Gradle KTS

  # .NET — C#, VB, F#
  - .csproj       # C# project (NuGet source URLs with tokens)
  - .nuspec       # NuGet package specification
  - .props        # MSBuild property sheet
  - .targets      # MSBuild targets

  # Shell scripts (can contain hardcoded credentials)
  - .sh
  - .bash
  - .zsh
  - .ps1          # PowerShell
  - .psm1         # PowerShell module
  - .bat
  - .cmd

  # Data / reports
  - .csv          # CSV exports (PII — names, emails, accounts)
  - .tsv
  - .sql          # SQL scripts (connection strings, INSERTs with PII)
  - .txt
  - .log          # logs (credentials, stack traces, PII)
  - .jsonl        # JSON Lines / event streams

  # API & schema definitions
  - .graphql
  - .gql
  - .proto        # Protocol Buffers
  - .wsdl         # SOAP Web Service Description Language
```

Dotfiles with no secondary extension (`.env`, `.npmrc`, `.netrc`) are matched by their full basename. Files like `.env.local` have extension `.local` — add `- .local` to the list to include them.

---

### Section 2 — File ignore list (`ignore_files`)

Workspace-relative paths listed here are **never read, never sanitized, and never forwarded to Copilot**. A leading `./` is stripped automatically. Use forward slashes on all platforms.

```yaml
ignore_files:
  - .env.local
  - .env.test
  - config/local-override.yaml
  - secrets/dev-credentials.json
  - infra/terraform.tfvars
```

---

### Section 2b — Folder ignore list (`ignore_folders`)

Any file whose workspace-relative path falls inside one of these folders is skipped entirely — at any nesting depth. A leading `./` and trailing `/` are stripped automatically.

```yaml
ignore_folders:
  - secrets            # skips secrets/*, secrets/**/*
  - infra/tfvars       # skips infra/tfvars/**/*
  - config/local       # skips config/local/**/*
  - .private
```

Files skipped by either list show an `ℹ️ Skipped` notice in the chat with the file name and reason.

---

### Section 3 — Anonymizer operations (`rules`)

Controls how each detected entity type is transformed:

| Operation | Output example | Notes |
|---|---|---|
| `replace` | `<PHONE_NUMBER>` | **Default.** Preserves entity type label for Copilot context. |
| `mask` | `************` | Replaces every character with `*`. |
| `redact` | *(empty string)* | Completely removes the text — nothing remains. |
| `hash` | `b7531e08…` | One-way SHA-256 digest. Repeatable — identical values produce identical hashes. |
| `encrypt` | `dGhpcyBp…` | AES-CBC reversible encryption. Requires `SAFECHAT_ENCRYPT_KEY` env var (16, 24, or 32 chars). Falls back to `replace` if key is missing. |

Legacy capitalised values (`Mask`, `Replace`) still work for backwards compatibility.

```yaml
rules:
  PhoneNumber:   replace   # → <PHONE_NUMBER>
  AccountNumber: mask      # → ************
  US_SSN:        redact    # (removed entirely)
  CREDIT_CARD:   hash      # → sha256 digest
  AWS_SECRET_KEY: encrypt  # → AES-CBC ciphertext
```

#### Supported entity aliases

You can use either friendly names or the canonical Presidio types:

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

Any entity type **not listed** in `rules` defaults to `replace`. For the full catalogue of 70+ entity types across Financial, Developer, Infrastructure, and CI/CD profiles, see `http://localhost:8000/docs/ui` or `http://localhost:8000/docs/entities`.

---

### Section 4 — Custom recognizers (`custom_recognizers`)

Define your own regex-based recognizers without touching the server. Each recognizer is active for the duration of the request — no restart required.

```yaml
custom_recognizers:
  - name: EMPLOYEE_ID          # entity type label (uppercase)
    pattern: "EMP-\\d{6}"     # Python-compatible regex
    score: 0.9                 # confidence 0.0–1.0 (default: 0.85)
    context:                   # optional — nearby words boost confidence
      - employee
      - staff
      - badge

  - name: INTERNAL_TICKET
    pattern: "JIRA-\\d{4,6}"
    score: 0.85
    context:
      - ticket
      - issue

  - name: CUSTOMER_ACCOUNT
    pattern: "CUST-[A-Z]{2}\\d{8}"
    score: 0.9
```

Then add a matching entry in the `rules` section:

```yaml
rules:
  EMPLOYEE_ID:      mask
  INTERNAL_TICKET:  redact
  CUSTOMER_ACCOUNT: replace
```

---

## Presidio Server API Reference

The server runs at `http://localhost:8000` by default.

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check |
| `/profiles` | GET | List available sanitization profiles |
| `/docs/ui` | GET | Interactive documentation web page |
| `/docs/entities` | GET | JSON catalogue of all entity types and profiles |
| `/analyze` | POST | Detect PII — returns findings without masking |
| `/anonymize` | POST | Detect + anonymize — returns masked text |
| `/sanitize` | POST | Detect + anonymize in one call (used by the extension) |

### `GET /health`
```json
{ "status": "ok", "service": "safechat-presidio-server" }
```

### `GET /docs/ui`
A self-contained HTML documentation page listing all 70+ entity types grouped by profile, all recognizer patterns with examples, all 5 anonymizer operations with input/output examples, and an interactive YAML config generator. Open in a browser:
```
http://localhost:8000/docs/ui
```

### `GET /profiles`
```json
{
  "profiles": [
    { "name": "financial",      "entity_count": 22 },
    { "name": "developer",      "entity_count": 17 },
    { "name": "infrastructure", "entity_count": 13 },
    { "name": "cicd",           "entity_count": 20 },
    { "name": "full",           "entity_count": 70 }
  ]
}
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

### `POST /sanitize`
Combined analyze + anonymize in one call. This is what the extension uses.

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

**Full request body:**

| Field | Type | Default | Description |
|---|---|---|---|
| `text` | string | — | Text to process |
| `language` | string | `"en"` | Language code |
| `profile` | string | — | Named recognizer set: `financial`, `developer`, `infrastructure`, `cicd`, `full` |
| `entities` | string[] | all types | Limit detection to specific entity types |
| `replacement_format` | string | `"<{entity_type}>"` | Template for `replace` operation |
| `rules` | object | `{}` | Per-entity operation (`replace`/`mask`/`redact`/`hash`/`encrypt`) |
| `custom_recognizers` | array | `[]` | Per-request user-defined regex recognizers |

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

