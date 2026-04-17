# SafeChat Sanitization Architecture & Order of Operations

The SafeChat extension enforces a mandatory, zero-trust sanitization boundary between the user's workspace and the LLM (GitHub Copilot). It uses a hybrid edge architecture consisting of a local TypeScript Engine (Tier 1 & 2) and an optional Python Presidio NLP server (Tier 3).

## The Sanitize Pipeline Map

Every file, search result, terminal output, or MCP tool payload goes through the pipeline. The routing depends on the **Sanitize Mode** (`general`, `terminal`, `search`, or `mcp_profile`).

### Phase 1: Ingestion & Profiling

1. **Binary Blocklist (Step 0)**: Files like `.pdf`, `.zip`, `.dll` are immediately rejected.
2. **Path Overrides (Step 1)**: Matches `custom_paths` in `safechat-rules.yaml` for hardcoded routing (AST, FULL_DLP, or IGNORE).
3. **Encoding Normalizer (Step 2)**: Detects UTF-16LE/BE Byte Order Marks and decodes memory buffers to strict UTF-8 to prevent regex string bypass via encoding mojibake.
4. **MIME/Extension Profiling (Step 3)**: 
   - `ast_extensions`: Structured configs (JSON, YAML, ENV, etc.) route to **Tier 2**.
   - `full_dlp_extensions`: Unstructured text (TXT, LOG, MD) route to **Tier 3**.
5. **Default Deny (Step 4)**: Unlisted extensions bypass scanning completely to ensure zero-friction for safe code files.

### Phase 2: Execution Pathways

**Pathway A: Single File Reads (`safechat_read_file`)**
- Protected tightly by an `fs.stat()` pre-flight check. Any file larger than 5 MB is rejected immediately to prevent V8 heap crashes via string allocation.
- **Symlink Jail:** Pre-flight actively resolves `fs.realpathSync` to block symbolic links that bypass the workspace boundary into native OS directories (e.g., `~/.ssh`).
- **Prompt Injection Data-Fence:** Output is strictly encapsulated within `[SAFECHAT_FILE_CONTEXT_BEGIN]` block borders, signaling the LLM to treat the payload as data, not instructions, thwarting cognitive overrides in poisoned `README.md` files.
- Output is written to local cache (`.vscode/.temp_cache`) to prevent re-sanitization. The cache is continuously governed by a 200-document FIFO Eviction queue and a 24-hour TTL Garbage Collector to prevent disk exhaustion.

**Pathway B: Codebase Reads (`#codebase` / Workspace Search)**
- Delegated entirely to LLM native search tools (e.g. `vscode_search`). The Sandbox intercepts these tools natively, avoiding out-of-memory errors on large mono-repos.

**Pathway B.2: Directory Reads (`safechat_read_directory`)**
- Combines a hardcoded `SKIP_DIRS` baseline with dynamic `GitIgnoreParser` matching.
- Evaluates `vscode.FileType` bitmasks rigorously to deny nested symlink escapes.
- Compiles `.gitignore` rules from the workspace root and the target folder into executable Regex matchers.
- Recursively skips ignored state files and environments completely to save processing power.

**Pathway C: Terminal Execution (`safechat_run_terminal`)**
- Intercepts native shell execution via VS Code Shell Integration API.
- **Terminal Write-Guard**: Inspects raw commands for `[MASKED_BY_SAFECHAT]` and warns the developer BEFORE the terminal shell executes.
1. `stripAnsiCodes()` removes all CLI formatting and colors.
2. `regexSanitize()` runs (applies CLI-specific patterns).
3. Payload is limited by local buffer size (512KB max).

**Pathway D: GUI Write & Refactor Tools**
- Guarded by the **Warn-and-Proceed** matrix. Native write tools execute unmodified natively. However, if the payload contains `[MASKED]` tokens, a stream warning forces the developer to manually review the VS Code file diff.

**Pathway E: MCP Tool Interception (The Triage Router)**
- Intercepts any tool not recognized as native.
- Executes `vscode.lm.invokeTool` in an isolated Sandbox.
- **Zombie-Killer Timeout:** Wrapped in a precise 30s CancellationToken source. If the MCP server hangs, the token fires and terminates the background process instantly, preventing V8 orphans.
- Matches `mcp_routing.profiles` in `safechat-rules.yaml`:
   - `bypass`: Skipped.
   - `json-keys`: JSON AST parser (`Tier 2`), falls back to regex string if invalid.
   - `regex-only`: Split into 50KB chunks to prevent backtracking (`safeRegexSanitize`).
   - `nlp-full`: Full DLP (`Tier 3`).
- **Object Serialization Guard:** Safely stringifies complex `PromptTsxPart` objects to guarantee non-string data structures are scanned.
- **Markdown Escaping applied** to payload to prevent UI injection before yielding to LLM.
- **Budget Guard:** Truncates response to 64KB (~16K tokens) to prevent context window overflow.

### Phase 3: The Engine Stack (Order of Operations)

If a payload enters the `sanitizePipeline()`, it goes through these exact stages in order:

#### Stage 1. Tier 2: The AST Guardian (Structured Only)
*Applies to `json-keys` profile and structured config files.*
- Decodes format via pure-JS parsers (JSON, YAML, TOML, ENV, CSV, XML).
- Walks the Abstract Syntax Tree.
- **Homoglyph Normalization:** Performs `NFKD` Unicode normalization on all keys, stripping diacritics and collapsing Cyrillic/Greek homoglyphs to Latin bases to thwart visual evasion.
- Checks keys against 20+ heuristics (e.g., `*password*`, `*secret*`, `*api_key*`) and `custom_secrets.ast_keys`.
- Masks values of triggering keys. (Recursion depth limited to 30 to prevent Stack Overflow).
- Preserves structure. Emits sanitized object.

#### Stage 2. Tier 3A: Dictionary & Regular Expressions (Unstructured)
*Applies to unstructured text, terminal output, and search results.*
- **`regexSanitize(text)`**: Runs 22 optimized RegExp patterns sequentially.
- Matches AWS keys, Bearer tokens, GitHub auth, Database URLs, PEM Certs, etc.
- Masks occurrences in place.
- *If MCP Triage detects a payload > 50KB, it is batched sequentially into chunks before this stage to prevent Regex Catastrophic Backtracking.*

#### Stage 3. Tier 3B: Shannon Entropy Engine
*Applies if Tier 3A completes.*
- **Heuristic Detector**: Scans for `key=value` formats not matching known dictionaries.
- Example: `my_custom_token = "xdQ2..."`
- Analyzes the value's Shannon Entropy. If `entropy >= 3.8` and length > 16, it is considered a generic secret and masked.
- **Bare Token Detector**: Scans for standalone high-entropy strings (20+ chars, entropy > 4.0) that carry service prefixes (`ghp_`, `sk-`, `ey...`).

#### Stage 4. Tier 3C: Presidio NLP (Human Entity Data)
- **`sanitizeOnly()` → `callPresidioApi()`**: 
- Takes text (already scrubbed of hardcoded credentials by Tier 3A and 3B).
- Calls local Python `FastAPI` instance.
- Analyzes for 12 PII Entities (Names, Email, Phones, SSN, Credit Cards, IBAN).
- Uses `Spacy` (en_core_web_lg).
- Replaces entities according to `safechat-rules.yaml` operations (`mask`, `replace`, `redact`, `hash`).
- Errors gracefully fallback to Regex/Entropy-only and alert user in stream.
