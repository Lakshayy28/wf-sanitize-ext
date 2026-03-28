# safechat-rules.yaml — Reference Guide

This file is the single control panel for the `@safechat` VS Code extension. Every setting that affects _which files are scanned_, _which data is detected_, and _how detected data is masked_ lives here.

**Key behaviour:** The file is re-read on every `@safechat` prompt — no VS Code reload or server restart is ever needed after editing it.

---

## Table of Contents

1. [How it fits into the pipeline](#1-how-it-fits-into-the-pipeline)
2. [Section: `ast_extensions`](#2-section-ast_extensions)
3. [Section: `full_dlp_extensions`](#3-section-full_dlp_extensions)
4. [Section: `custom_secrets`](#4-section-custom_secrets)
5. [Section: `rules`](#5-section-rules)
6. [Section: `custom_recognizers`](#6-section-custom_recognizers)
7. [Entity alias reference](#7-entity-alias-reference)
8. [Complete annotated example](#8-complete-annotated-example)
9. [Common recipes](#9-common-recipes)

---

## 1. How it fits into the pipeline

```
User attaches file(s) to @safechat
            │
            ▼
  ┌─────────────────────┐
  │  Safety Gates         │  Binary file or NUL bytes found?
  │  (blocked / bypass)   │ ── yes ──► 🚫 Rejected — not forwarded to Copilot.
  └─────────────────────┘  Source code / doc file?
       │                    ── yes ──► 📄 Forwarded as-is (bypass, no scan).
       │
       ▼
  ┌─────────────────────┐
  │  Content Sniffer &    │  Known extension (.json/.yaml/.env…) or unknown
  │  ast_extensions list  │  extension whose content looks like a known format?
  └─────────────────────┘  ── yes ──► Tree-sitter CST parser (Tier 2).
       │                    Unknown extension with KV pairs?
       │                    ── yes ──► Universal KV Lexer (Tier 2B).
       │
       ▼
  ┌─────────────────────┐      ┌─────────────────────┐
  │  Full DLP pipeline    │      │  custom_recognizers +    │
  │  Regex → Entropy      │◄────│  rules applied via        │
  │  → Presidio NLP       │      │  Presidio API call        │
  └─────────────────────┘      └─────────────────────┘
            │
            ▼
     Sanitized text → Copilot
```

Files that are source code or documentation are **forwarded as-is** to Copilot. Config and data files are always scanned — there is no longer an extension allowlist that gates scanning; instead the routing engine automatically assigns the most appropriate engine.

---

## 2. Section: `ast_extensions`

Forces custom or proprietary file extensions through the **Tier 2 AST / Universal KV engine** instead of leaving the decision entirely to the automatic router.

### When to use it

The Content Sniffer already handles most cases automatically — unknown extensions are sniffed, and if the content looks like JSON/YAML/ENV/Properties the Tree-sitter parser is used; if it looks like a generic key-value format the Universal KV Lexer is used. Add an entry here only when the automatic routing doesn’t pick the right engine (e.g. a format the sniffer doesn’t recognise).

### Syntax

```yaml
ast_extensions:
  - .custom_env      # force through AST/KV engine
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

Forces custom file extensions straight to the **Tier 3 Full DLP** pipeline (regex + Shannon Entropy + Presidio NLP), bypassing the AST/KV engines entirely.

### When to use it

Use this for log files, audit dumps, chat transcripts, or any unstructured text export from internal tools. These files may contain human PII (names, emails, phone numbers) that the key-name-based AST engine would miss because the data isn’t under a recognisable key.

### Syntax

```yaml
full_dlp_extensions:
  - .audit_log
  - .splunk_dump
  - .chat_transcript
```

---

## 4. Section: `custom_secrets`

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

## 5. Section: `rules`

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

> Legacy capitalised values `Mask` and `Replace` still work for backwards compatibility.

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

## 6. Section: `custom_recognizers`

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

## 7. Entity alias reference

You can use either the friendly alias or the canonical Presidio type — both are accepted, case-insensitively.

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

For the full catalogue of 70+ entity types (financial, developer, infrastructure, CI/CD), visit `http://localhost:8000/docs/ui` or `http://localhost:8000/docs/entities`.

---

## 8. Complete annotated example

```yaml
# ── 1. Force proprietary extensions into Tier 2 AST/KV engine ─────────────────
ast_extensions:
  - .custom_env
  - .kube_vars
  - .mycompany_conf

# ── 2. Force log/dump extensions into Tier 3 Full DLP ─────────────────────────
full_dlp_extensions:
  - .audit_log
  - .splunk_dump
  - .chat_transcript

# ── 3. Internal developer token definitions ────────────────────────────────────
custom_secrets:
  - name: "App Usernames"
    ast_keys: ["username", "db_user", "login"]

  - name: "Acme Corp Production Token"
    ast_keys: ["acme_prod", "acme_token"]
    value_prefix: "acme_live_"
    value_charset: "alphanumeric"
    value_length: "32"

# ── 4. Per-entity anonymization operations ────────────────────────────────────
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

# ── 5. User-defined Presidio NLP recognizers ──────────────────────────────────
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

## 9. Common recipes

### No overrides needed (default behaviour)

For standard projects, leave `ast_extensions` and `full_dlp_extensions` empty or absent. The Content Sniffer automatically routes `.json`, `.yaml`, `.yml`, `.env`, `.properties` to Tree-sitter, unknown KV files to the Universal Lexer, and everything else to Full DLP.

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
