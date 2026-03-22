# safechat-rules.yaml — Reference Guide

This file is the single control panel for the `@safechat` VS Code extension. Every setting that affects _which files are scanned_, _which data is detected_, and _how detected data is masked_ lives here.

**Key behaviour:** The file is re-read on every `@safechat` prompt — no VS Code reload or server restart is ever needed after editing it.

---

## Table of Contents

1. [How it fits into the pipeline](#1-how-it-fits-into-the-pipeline)
2. [Section: `include_extensions`](#2-section-include_extensions)
3. [Section: `rules`](#3-section-rules)
4. [Section: `custom_recognizers`](#4-section-custom_recognizers)
5. [Entity alias reference](#5-entity-alias-reference)
6. [Complete annotated example](#6-complete-annotated-example)
7. [Common recipes](#7-common-recipes)

---

## 1. How it fits into the pipeline

```
User attaches file(s) to @safechat
            │
            ▼
  ┌─────────────────────┐
  │  include_extensions │
  │  present & non-     │ ── no match ──► 📄 Forwarded as-is to Copilot (no PII scan)
  │  empty?             │
  └─────────────────────┘
            │ match (or section absent = scan all)
            ▼
       Read file content
            │
            ▼
  ┌─────────────────────┐      ┌───────────────────────────┐
  │  Presidio NLP API   │      │  custom_recognizers       │
  │  (Tier 1)           │◄─────│  sent with every request  │
  └─────────────────────┘      └───────────────────────────┘
            │
         rules applied (replace / mask / redact / hash / encrypt)
            │
            ▼
  ┌─────────────────────┐
  │  Regex engine       │  catches any remaining secrets (api_key=, Bearer …)
  │  (Tier 2, always)   │
  └─────────────────────┘
            │
            ▼
     Sanitized text → Copilot
```

Files that do not match `include_extensions` are **forwarded as-is** to Copilot — they are not blocked, just not scanned for PII.

---

## 2. Section: `include_extensions`

Controls which file types are scanned for PII before forwarding to Copilot.

### Rules

| Condition | Behaviour |
|---|---|
| Section absent or empty | **All** attached files are scanned (default — backwards compatible) |
| Section present with entries | Files matching the list are sanitized; **all other files are forwarded as-is** (no scanning, no blocking) |

### Syntax

```yaml
include_extensions:
  - .yaml
  - .json
  - .env       # matched by full basename for dotfiles (see below)
```

Each entry must start with a `.`. Matching is **case-insensitive**.

### Dotfile handling

| File | Extension seen | Matches |
|---|---|---|
| `config.yaml` | `.yaml` | `- .yaml` ✅ |
| `.env` | `.env` (full basename) | `- .env` ✅ |
| `.env.local` | `.local` | `- .local` ✅ |
| `.env.production` | `.production` | `- .production` ✅ |
| `Makefile` | *(empty)* | never matched |

### Example — only scan config and secret files

```yaml
include_extensions:
  - .yaml
  - .yml
  - .json
  - .xml
  - .conf
  - .env
  - .properties
  - .pem
  - .crt
  - .cer
  - .pfx
  - .key
```

With this active, attaching a TypeScript file (`.ts`) forwards it **as-is** to Copilot (no PII scanning). Config/secret files like `.yaml` or `.env` are sanitized first.

---

## 3. Section: `rules`

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

## 4. Section: `custom_recognizers`

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

## 5. Entity alias reference

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

## 6. Complete annotated example

```yaml
# ── Only scan data/config files — skip all code files ─────────────────────────
include_extensions:
  - .yaml
  - .yml
  - .json
  - .xml
  - .conf
  - .env
  - .properties
  - .pem
  - .crt
  - .pfx
  - .key

# ── Per-entity anonymization operations ───────────────────────────────────────
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

# ── User-defined regex recognizers ────────────────────────────────────────────
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

## 7. Common recipes

### Scan everything (default behaviour)

Remove or comment out `include_extensions` entirely. All attached files are scanned.

### Java / Spring Boot project

```yaml
include_extensions:
  - .yaml
  - .yml
  - .xml
  - .properties
  - .env
  - .gradle
  - .kts
```

### Node / TypeScript / React project

```yaml
include_extensions:
  - .json
  - .yaml
  - .yml
  - .env
  - .local      # .env.local, .env.development.local
  - .conf
```

### .NET / C# project

```yaml
include_extensions:
  - .json        # appsettings.json
  - .xml         # web.config, packages.config
  - .config      # app.config
  - .env
  - .csproj      # may contain NuGet source URLs with tokens
```

### Infrastructure / DevOps

```yaml
include_extensions:
  - .yaml
  - .yml
  - .tf
  - .tfvars
  - .hcl
  - .env
  - .conf
  - .pem
  - .key
  - .crt
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
