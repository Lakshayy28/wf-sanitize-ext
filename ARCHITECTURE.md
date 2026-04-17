# SafeChat Smart Proxy — Architecture & Order of Operations

The SafeChat extension operates as an invisible "Smart Proxy" inside the VS Code Copilot agent loop. It registers zero custom tools. ALL native Copilot tools (file read, directory listing, terminal execution, codebase search) are available to the LLM without restriction.

The proxy intercepts tool **results** (not inputs), routes them through a format-aware sanitization pipeline, and hands clean text back to the LLM context window.

## The Polyglot AST Router

Every tool result flows through a single entry point: `smartSanitize(text, fileExtension?)`.

### Phase 1: Extension Extraction

Before sanitization, the interceptor examines the tool's input object for file path properties (`uri`, `filePath`, `path`, `file`, `fileName`, `resource`). If found, the file extension is extracted and passed to the router. If no extension is found (terminal output, search results, MCP tools), the text falls to the catch-all.

### Phase 2: Route Selection

```
smartSanitize(text, ext)
    │
    ├── Code Files (.ts, .js, .py, .java, .go, .rs, .cpp, etc.)
    │       → BYPASS — return raw text, no scanning
    │
    ├── JSON (.json, .jsonc, .json5)
    │       → JSON.parse → maskObjectValues() → JSON.stringify(…, null, 2)
    │
    ├── YAML (.yaml, .yml)
    │       → yaml.parse → maskObjectValues() → yaml.stringify()
    │
    ├── XML (.xml, .xsl, .xslt, .svg, .plist)
    │       → XMLParser → maskObjectValues() → XMLBuilder
    │
    ├── ENV/INI (.env, .ini, .cfg, .properties, .env.local, .env.production)
    │       → Line-by-line: split at first '=', regexSanitize(value), reassemble
    │
    └── Catch-All (.log, .txt, .md, .csv, terminal, search, undefined)
            → truncateAndSanitize(text) — 250KB budget + full regex dictionary
```

### Phase 3: The Universal Object Masker (`maskObjectValues`)

Used by JSON, YAML, and XML routes. Recursively walks the parsed JavaScript object:

| Input Type | Action |
|---|---|
| `string` | Piped through `regexSanitize()` — 22 pattern dictionary |
| `array` | Each element recursively processed |
| `object` | Keys preserved, values recursively processed |
| `number`, `boolean`, `null` | Returned as-is (no scanning) |

**Depth limit:** 64 levels. Beyond this, values are returned untouched to prevent stack overflow on adversarial nested inputs.

### Phase 4: Reconstruction

After masking, the object is reconstructed in its original format:
- **JSON** → `JSON.stringify(masked, null, 2)` — pretty-printed, 2-space indent.
- **YAML** → `yaml.stringify(masked, { indent: 2 })` — standard YAML output.
- **XML** → `XMLBuilder.build(masked)` — formatted XML with attributes preserved.
- **ENV** → Lines reassembled as `key=maskedValue` with original quoting style.

## Fail-Closed Guarantee

Every AST parser (JSON.parse, yaml.parse, XMLParser) is wrapped in `try/catch`. If parsing fails for any reason (malformed input, encoding issues, adversarial payloads), the text **falls through to `truncateAndSanitize()`** — never fails open.

```
Parse error → console.warn() → truncateAndSanitize(text) → regex scan
```

## The Regex Dictionary (22 Patterns)

| Category | Patterns |
|---|---|
| Cloud & CI/CD | AWS Access Key, GCP Service Account, Azure Shared Key, GitHub Token, GitLab Token, Jenkins Token, Harness Token, OpenShift Token, LambdaTest/SauceLabs |
| APIs & Comms | Slack Token, Stripe Key, SendGrid Key, NPM Token, Vault Token, SonarQube Token, Terraform Cloud Token, Bitbucket Token |
| Crypto Material | RSA/PEM Private Key, JWT Token |
| URLs | URL Query Parameter Secret, Credential URL (protocol://user:pass@host) |
| Credentials | Netrc Password, Pgpass Password |
| PII | US SSN, Credit Card Number, IBAN Code, IPv4 Address, Internal Hostname, MAC Address, Certificate Thumbprint, Email Address, Phone Number |

## The Write-Guard

The interceptor checks every tool call against a hardcoded list of write and terminal tool patterns **before execution**:

| Pattern Category | Tool Names Matched |
|---|---|
| File Writes | `apply_workspace_edit`, `edit_file`, `write_file`, `create_file`, `apply_edit`, `insert_edit`, `replace_string`, `apply_diff`, `save_file` |
| Terminal | `run_command`, `terminal_execute`, `run_in_terminal`, `exec`, `execute_command`, `bash` |

If the tool's stringified input contains `[MASKED_BY_SAFECHAT]`, a Markdown warning is emitted to the chat stream **before** the tool executes:

```
⚠️ SafeChat Write-Guard: Tool `edit_file` was invoked with input containing
[MASKED_BY_SAFECHAT]. This could corrupt files or execute masked credentials
in the terminal. Please review the operation carefully.
```

## The Truncation Guard

For non-AST routes (catch-all), payloads exceeding 250KB (250,000 bytes) are truncated:

1. Slice at the 250KB boundary.
2. Backtrack to the nearest newline (`lastIndexOf('\n')`) to avoid splitting credentials.
3. Append `[... TRUNCATED: payload exceeded 250KB budget ...]`.
4. Run the full regex dictionary on the truncated text.

## Dependencies

| Package | Purpose |
|---|---|
| `yaml` | YAML parsing and stringification |
| `fast-xml-parser` | XML parsing (XMLParser) and reconstruction (XMLBuilder) |
