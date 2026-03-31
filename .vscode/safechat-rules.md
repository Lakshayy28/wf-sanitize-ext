# safechat-rules.yaml — Reference Guide

This file is the single control panel for the `@safechat` VS Code extension. Every setting that affects _which files are scanned_, _which data is detected_, and _how detected data is masked_ lives here.

**Key behaviour:** The file is re-read on every `@safechat` prompt — no VS Code reload or server restart is ever needed after editing it.

---

## Table of Contents

1. [How it fits into the pipeline](#1-how-it-fits-into-the-pipeline)
2. [Section: `ast_extensions`](#2-section-ast_extensions)
3. [Section: `full_dlp_extensions`](#3-section-full_dlp_extensions)
4. [Section: `custom_paths`](#4-section-custom_paths)
5. [Section: `custom_secrets`](#5-section-custom_secrets)
6. [Section: `rules`](#6-section-rules)
7. [Section: `custom_recognizers`](#7-section-custom_recognizers)
8. [Entity alias reference](#8-entity-alias-reference)
9. [Complete annotated example](#9-complete-annotated-example)
10. [Common recipes](#10-common-recipes)

---

## 1. How it fits into the pipeline

```
User attaches file(s) to @safechat
            │
            ▼
  ┌─────────────────────┐
  │  Step 0: Binary       │  .pdf, .zip, .exe, .png…?
  │  Blocklist            │ ── yes ──► 🚫 Blocked — not forwarded to Copilot.
  └─────────────────────┘
       │ no
       ▼
  ┌─────────────────────┐
  │  Step 1: custom_paths │  Path matches a custom_paths rule?
  │  (highest priority)   │ ── AST ──►      Tier 2 AST (key-based masking)
  └─────────────────────┘ ── FULL_DLP ──►  Tier 3 Full DLP (NLP + regex)
       │ no match          ── IGNORE ──►   📄 Bypass (no scan)
       ▼
  ┌─────────────────────┐
  │  Step 2 & 3: Extension│  Extension in ast_extensions or full_dlp_extensions?
  │  Whitelist            │ ── ast ──►     Tier 2 AST (key-based masking)
  └─────────────────────┘ ── dlp ──►     Tier 3 Full DLP (NLP + regex)
       │ no match
       ▼
  ┌─────────────────────┐
  │  Step 4: Default Deny │  Extension NOT in any whitelist?
  │  (bypass)             │ ── yes ──► 📄 Forwarded as-is (no scan)
  └─────────────────────┘
```

**Architecture: Hybrid Edge (TypeScript extension + Python server)**

- The **TypeScript extension** handles: Regex dictionary (22 patterns), Shannon Entropy scanner, bare token detection, and all Tier 2 AST key-based masking.
- The **Python Presidio server** handles: NLP-based human PII detection (Tier 3, 12 entity types). The extension works without it — secrets are still caught by the regex/entropy engines.

**Built-in scanned extensions (always active, no config needed):**

| Tier | Extensions |
|---|---|
| **Tier 2 (AST)** | `.json` `.jsonc` `.jsonl` `.yaml` `.yml` `.env` `.properties` `.ini` `.conf` `.cfg` `.config` `.toml` `.npmrc` `.kubeconfig` `.csv` `.tsv` `.netrc` `.pgpass` `.gemrc` `.yarnrc` `.pem` `.key` `.cert` `.crt` `.pub` `.ppk` `.cer` `.asc` `.tf` `.hcl` `.terraformrc` `.tfstate` `.tfvars` `.csproj` `.props` `.targets` `.nuspec` `.xml` `.xsd` `.wsdl` `.secret` `.sh` `.bash` `.zsh` `.bat` `.cmd` `.ps1` `.psm1` `.dockerfile` `.gradle` `.kts` |
| **Tier 3 (DLP)** | `.txt` `.log` `.md` `.sql` `.graphql` `.gql` `.rtf` |

Add extra extensions below ONLY for proprietary/internal formats not already in the built-in lists.

---

## 2. Section: `ast_extensions`

Adds custom or proprietary file extensions to the **Tier 2 AST whitelist** so they are scanned by the pure-JS parsers (JSON, YAML, XML, ENV, Properties, TOML, HCL, CSV/TSV).

### When to use it

The built-in whitelist already covers standard config formats. Add entries here only for **proprietary or internal formats** not already in the built-in list.

### Built-in AST extensions (already scanned — do NOT re-add)

| Category | Extensions |
|---|---|
| Data interchange | `.json` `.jsonc` `.jsonl` `.yaml` `.yml` |
| Environment / Properties | `.env` `.properties` `.ini` `.conf` `.cfg` `.config` `.toml` `.npmrc` `.kubeconfig` |
| Tabular data | `.csv` `.tsv` |
| Auth / Package managers | `.netrc` `.pgpass` `.gemrc` `.yarnrc` |
| Keys / Certificates | `.pem` `.key` `.cert` `.crt` `.pub` `.ppk` `.cer` `.asc` |
| Infrastructure as Code | `.tf` `.hcl` `.terraformrc` `.tfstate` `.tfvars` |
| Build / Project (XML) | `.csproj` `.props` `.targets` `.nuspec` `.xml` `.xsd` `.wsdl` |
| Secrets files | `.secret` |
| Shell scripts | `.sh` `.bash` `.zsh` `.bat` `.cmd` `.ps1` `.psm1` |
| Docker / Build | `.dockerfile` `.gradle` `.kts` |

### Syntax

```yaml
ast_extensions:
  - .custom_env      # force through AST engine
  - .kube_vars       # helm/kubernetes local var files
  - .mycompany_conf  # vendor-specific config
```

Each entry must start with a `.`. Matching is **case-insensitive**.

### Dotfile handling

| File | Extension seen | Matches |
|---|---|---|
| `settings.custom_env` | `.custom_env` | `- .custom_env` ✅ |
| `.kube_vars` | `.kube_vars` (full basename) | `- .kube_vars` ✅ |
| `Makefile` | *(empty)* | never matched |

---

## 3. Section: `full_dlp_extensions`

Forces custom file extensions straight to the **Tier 3 Full DLP** pipeline (regex + Shannon Entropy + Presidio NLP), bypassing the AST engines entirely.

### When to use it

Use this for log files, audit dumps, chat transcripts, or any unstructured text export from internal tools. These files may contain human PII (names, emails, phone numbers) that the key-name-based AST engine would miss because the data isn't under a recognisable key.

### Built-in Full DLP extensions (already scanned — do NOT re-add)

`.txt` `.log` `.md` `.sql` `.graphql` `.gql` `.rtf`

### Syntax

```yaml
full_dlp_extensions:
  - .audit_log
  - .splunk_dump
  - .chat_transcript
```

---

## 4. Section: `custom_paths`

Overrides routing for **specific files or paths**. Custom path rules have the **highest priority** — they are evaluated before extension whitelists and override all automatic routing.

### When to use it

- Force a specific file to a different tier than its extension would suggest
- Scan a file that has no recognized extension
- Exclude a noisy generated file from scanning entirely

### Strategies

| Strategy | Effect |
|---|---|
| `AST` | Route to Tier 2 AST engine (key-based masking) |
| `FULL_DLP` | Route to Tier 3 Full DLP (NLP + regex + entropy) |
| `IGNORE` | Bypass entirely — never scanned |

### Syntax

```yaml
custom_paths:
  - path: "src/config/internal_settings.conf"
    strategy: AST

  - path: "docs/sensitive_architecture.md"
    strategy: FULL_DLP

  - path: "generated/api_schema.json"
    strategy: IGNORE
```

### Path matching

- Paths are matched against the **workspace-relative file path**
- Matching is **case-insensitive**
- **Suffix matching** is supported: `"settings.conf"` matches `"src/config/settings.conf"`
- Use forward slashes (`/`) — backslashes are normalized automatically

### Example — exclude generated files, force internal config

```yaml
custom_paths:
  # This generated JSON is noisy and never contains real secrets
  - path: "generated/openapi_spec.json"
    strategy: IGNORE

  # This proprietary binary config actually contains key=value text
  - path: "config/internal.dat"
    strategy: AST

  # This .py file contains hardcoded credentials in comments
  - path: "scripts/legacy_deploy.py"
    strategy: FULL_DLP
```

---

## 5. Section: `custom_secrets`

Defines custom internal developer secrets recognised by the **TypeScript engine** (not Presidio). Each entry does two things:

1. **Injects `ast_keys`** into the Tier 2 JSON/YAML/ENV parser so those keys are masked immediately at the AST level.
2. **Compiles a regex** from `value_prefix` + `value_charset` + `value_length` and adds it to the Tier 3 regex dictionary for unstructured text.

### Syntax

```yaml
custom_secrets:
  - name: "My Secret Name"        # human-readable label
    ast_keys: ["key1", "key2"]    # extra keys to mask in Tier 2
    value_prefix: "mytoken_"      # optional token prefix
    value_charset: "alphanumeric" # alphanumeric | hex | base64 | all
    value_length: "32"            # expected token length
```

### Example — internal API token

```yaml
custom_secrets:
  - name: "Acme Corp Production Token"
    ast_keys: ["acme_prod", "acme_token"]
    value_prefix: "acme_live_"
    value_charset: "alphanumeric"
    value_length: "32"
```

This compiles the regex `\b(acme_live_[A-Za-z0-9_\-]{32})\b` and adds it to the Tier 3 dictionary. Any occurrence of an `acme_live_` token anywhere in unstructured text is masked automatically.

---

## 6. Section: `rules`

Defines how each detected entity type is anonymized. Any entity type not listed defaults to `replace`.

### Syntax

```yaml
rules:
  EntityKeyOrAlias: operation
```

### The five operations

| Operation | What it produces | When to use |
|---|---|---|
| `replace` | `<PHONE_NUMBER>` | **Default.** Keeps the entity type label so Copilot understands the context |
| `mask` | `************` | Every character replaced with `*`. Good for account numbers, SSNs, CVV codes |
| `redact` | *(empty — text removed entirely)* | Nothing remains. Use when even the label is too much |
| `hash` | `b7531e08a7ea1d5b7bec…` | One-way SHA-256 digest. Identical values always produce the same hash |
| `encrypt` | `dGhpcyBpcyBh…` | AES-CBC reversible. Requires env var `SAFECHAT_ENCRYPT_KEY` (16, 24, or 32 chars). Falls back to `replace` if the key is missing |

### Examples

```yaml
rules:
  PhoneNumber:    replace   # 415-555-0198           → <PHONE_NUMBER>
  AccountNumber:  mask      # 3530111333300000       → ****************
  US_SSN:         redact    # 078-05-1120            → (removed)
  CREDIT_CARD:    hash      # 4532015112830366       → b7531e08…
  AWS_SECRET_KEY: encrypt   # AKIAIOSFODNN7EXAMPLE   → dGhpcyBp…
  EmailAddress:   replace   # alice@example.com      → <EMAIL_ADDRESS>
```

#### `hash` use-case — de-duplication without exposure

Because the same value always produces the same hash, you can ask Copilot questions like "how many times does this account number appear?" without ever revealing the number itself.

#### `encrypt` use-case — sharing with trusted parties

If you are sharing sanitized output with a colleague who has the same `SAFECHAT_ENCRYPT_KEY`, they can reverse the encryption locally. Set the key:

```bash
export SAFECHAT_ENCRYPT_KEY="my32characterlongsecretkey123456"
```

---

## 7. Section: `custom_recognizers`

Adds your own regex-based entity detectors without modifying the server. Each recognizer is active for the duration of the request — no restart required.

### Syntax

```yaml
custom_recognizers:
  - name: ENTITY_NAME           # required — uppercase label, used as entity type
    pattern: "regex_pattern"    # required — Python-compatible regex
    score: 0.85                 # optional — confidence 0.0–1.0 (default: 0.85)
    context:                    # optional — nearby words that boost score
      - keyword1
      - keyword2
```

Then add a matching entry in `rules`:

```yaml
rules:
  ENTITY_NAME: mask   # or replace, redact, hash, encrypt
```

### Example — employee ID

```yaml
custom_recognizers:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
    score: 0.9
    context:
      - employee
      - staff
      - badge

rules:
  EMPLOYEE_ID: mask
```

Input:
```
Assigned to employee EMP-004821 (badge scan required)
```
Output:
```
Assigned to employee **** (badge scan required)
```

### Example — internal Jira ticket

```yaml
custom_recognizers:
  - name: INTERNAL_TICKET
    pattern: "PROJ-\\d{4,6}"
    score: 0.85
    context:
      - ticket
      - issue
      - jira

rules:
  INTERNAL_TICKET: replace
```

Output: `See ticket <INTERNAL_TICKET> for background`

### Example — customer account number

```yaml
custom_recognizers:
  - name: CUSTOMER_ACCOUNT
    pattern: "CUST-[A-Z]{2}\\d{8}"
    score: 0.9

rules:
  CUSTOMER_ACCOUNT: redact
```

### Example — multiple recognizers

```yaml
custom_recognizers:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
    score: 0.9
    context:
      - employee
      - staff

  - name: BRANCH_CODE
    pattern: "BR-[A-Z]{3}-\\d{4}"
    score: 0.85
    context:
      - branch
      - location

  - name: POLICY_NUMBER
    pattern: "POL-\\d{10}"
    score: 0.9
    context:
      - policy
      - insurance

rules:
  EMPLOYEE_ID:    mask
  BRANCH_CODE:    replace
  POLICY_NUMBER:  hash
```

### Tips

- **Escape backslashes twice** in YAML strings: `\\d` not `\d`
- **`context` is optional but recommended** — it raises confidence for ambiguous patterns and reduces false positives
- **`score`** of `1.0` means always match; `0.0` means never match. Most patterns work well at `0.85`–`0.9`
- The `name` becomes both the entity type label in replacements and the key you reference in `rules`

---

## 8. Entity alias reference

You can use either the friendly alias or the canonical Presidio type — both are accepted, case-insensitively.

**Active entities (12 — detected by the running server):**

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

> **Anti-hallucination:** `US_DRIVER_LICENSE` and `US_ITIN` are intentionally **not active** — they cause false positives on source code patterns like `apiVersion: v1`. Other Presidio built-ins (`LOCATION`, `DATE_TIME`, `US_PASSPORT`, `MEDICAL_LICENSE`, `NRP`) are also inactive in the default profile to reduce noise.

For the Swagger UI and full entity catalogue, visit `http://localhost:8000/docs` when the server is running.

---

## 9. Complete annotated example

```yaml
# ── 1. Force proprietary extensions into Tier 2 AST engine ────────────────────
ast_extensions:
  - .custom_env
  - .kube_vars
  - .mycompany_conf

# ── 2. Force log/dump extensions into Tier 3 Full DLP ─────────────────────────
full_dlp_extensions:
  - .audit_log
  - .splunk_dump
  - .chat_transcript

# ── 3. Path-specific overrides (highest routing priority) ─────────────────────
custom_paths:
  - path: "generated/openapi_spec.json"
    strategy: IGNORE
  - path: "scripts/legacy_deploy.py"
    strategy: FULL_DLP

# ── 4. Internal developer token definitions ────────────────────────────────────
custom_secrets:
  - name: "App Usernames"
    ast_keys: ["username", "db_user", "login"]

  - name: "Acme Corp Production Token"
    ast_keys: ["acme_prod", "acme_token"]
    value_prefix: "acme_live_"
    value_charset: "alphanumeric"
    value_length: "32"

# ── 5. Per-entity anonymization operations ────────────────────────────────────
rules:
  # Presidio built-in
  PhoneNumber:    replace   # → <PHONE_NUMBER>
  AccountNumber:  mask      # → ****
  EmailAddress:   replace   # → <EMAIL_ADDRESS>
  CreditCard:     mask      # → ****
  SSN:            redact    # → (removed)
  IPAddress:      replace   # → <IP_ADDRESS>
  Person:         replace   # → <PERSON>

  # Custom recognizers defined below
  EMPLOYEE_ID:    mask
  BRANCH_CODE:    replace

# ── 6. User-defined Presidio NLP recognizers ──────────────────────────────────
custom_recognizers:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
    score: 0.9
    context:
      - employee
      - staff
      - badge

  - name: BRANCH_CODE
    pattern: "BR-[A-Z]{3}-\\d{4}"
    score: 0.85
    context:
      - branch
      - location
```

---

## 10. Common recipes

### No overrides needed (default behaviour)

For standard projects, leave `ast_extensions`, `full_dlp_extensions`, and `custom_paths` empty or absent. The built-in whitelist covers all common config formats (`.json`, `.yaml`, `.env`, `.properties`, `.xml`, `.toml`, etc.) and unstructured text (`.txt`, `.md`, `.log`, `.sql`). Any extension not in the whitelist is bypassed (default deny).

### Java / Spring Boot project — add proprietary formats

```yaml
ast_extensions:
  - .myapp_config       # custom app config with key=value pairs
  - .spring_local       # local Spring overrides

full_dlp_extensions:
  - .gc_log             # GC / application logs
```

### Node / TypeScript / React project — add internal token format

```yaml
custom_secrets:
  - name: "Internal Service Token"
    ast_keys: ["service_token", "svc_key"]
    value_prefix: "svc_"
    value_charset: "alphanumeric"
    value_length: "40"
```

### Infrastructure / DevOps — force Terraform state to Full DLP

```yaml
full_dlp_extensions:
  - .tfstate            # Terraform state files contain raw secrets in plain text
  - .tfstate.backup
```

### Mask everything aggressively

```yaml
rules:
  PhoneNumber:    mask
  AccountNumber:  mask
  EmailAddress:   mask
  CreditCard:     mask
  SSN:            redact
  IPAddress:      mask
  Person:         mask
  IBAN:           mask
  URL:            mask
  Date:           mask
```

### Use hash for repeatable anonymization

Useful when you want Copilot to identify _which_ occurrences are the same value without seeing the actual value:

```yaml
rules:
  AccountNumber:  hash
  CUSTOMER_ID:    hash   # custom recognizer

custom_recognizers:
  - name: CUSTOMER_ID
    pattern: "C-\\d{8}"
    score: 0.9
```

Two occurrences of `C-00482819` will both become the same hash — Copilot can reason about identity without exposure.
