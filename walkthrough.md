# MCP Triage Router — Implementation Walkthrough

## Summary

Implemented Zero-Trust interception for Model Context Protocol (MCP) tool payloads in the `@safechat` VS Code extension. The architecture routes MCP tool outputs through 4 sanitization profiles based on glob-matched tool names, with semantic line-batching to prevent credential splitting and timeout sandboxing to prevent V8 lockups.

## Files Changed

### Step 1: Configuration Layer

#### [safechat-rules.yaml](file:///Users/lakshaychandra/Documents/wf-sanitize-ext/.vscode/safechat-rules.yaml)
Added `mcp_routing` section (Section 7) with:
- `default_profile: "regex-only"` — safest default for unknown tools  
- `timeout_ms: 5000` — sandbox timeout
- `profiles` with 4 categories and wildcard patterns:
  - `bypass` → `*weather*`, `*calc*`, `*time*`, `*ping*`
  - `json-keys` → `*github*`, `*gitlab*`, `*bitbucket*`, `*azure_devops*`
  - `regex-only` → `*splunk*`, `*datadog*`, `*elastic*`, `*kibana*`, `*grafana*`
  - `nlp-full` → `*jira*`, `*confluence*`, `*slack*`, `*teams*`, `*salesforce*`

#### [router.ts](file:///Users/lakshaychandra/Documents/wf-sanitize-ext/src/router.ts)
- Added `McpRoutingProfile` type union and `McpRoutingConfig` interface
- Added `mcp_routing?: McpRoutingConfig` to `RulesConfig`
- Extended the YAML parser with `mcp_routing` section handling (including nested `profiles:` with sub-profile list parsing)
- `mcpRoutingFound` flag ensures the config is only returned when explicitly present

---

### Step 2: MCP Router & Smart Chunking

#### [sanitizer.ts](file:///Users/lakshaychandra/Documents/wf-sanitize-ext/src/sanitizer.ts)
Added 158 lines implementing the core MCP sanitization engine:

| Function | Purpose |
|---|---|
| `sanitizeMcpPayload()` | Exported entry point — routes by profile |
| `matchMcpProfile()` | Resolves tool name → profile via wildcard matching |
| `wildcardMatch()` | Glob pattern → regex matcher (case-insensitive) |
| `localRegexOnlySanitize()` | Async wrapper around `regexSanitize` for batch processing |
| `maskSensitiveJsonKeys()` | Recursive JSON key masking using `isSensitiveKey` |

**Routing profiles implemented:**
- **bypass** → immediate return, zero processing
- **json-keys** → `JSON.parse` → recursive `maskSensitiveJsonKeys` → `JSON.stringify` (fallback to regex-only on parse failure)  
- **nlp-full** → delegates to existing `sanitizePipeline(text, 'general')`
- **regex-only** → Semantic line-batching:
  1. `text.split('\n')` (never splits credentials)
  2. Contextual truncation: >5000 lines → first 2500 + last 2500 + `[... TRUNCATED ... LINES ...]` warning
  3. Concurrent batching: 500 lines/batch via `Promise.all`

---

### Step 3: Interception Sandbox

#### [extension.ts](file:///Users/lakshaychandra/Documents/wf-sanitize-ext/src/extension.ts)
Inserted MCP interception block in the agentic tool loop (after terminal tool handler, before generic fallback):

```
Tool call detected
  ↓
call.name.toLowerCase().includes('mcp')?
  ↓ yes
vscode.lm.invokeTool() → get raw result
  ↓
Read mcp_routing.timeout_ms from config
  ↓
For each text part:
  Promise.race([sanitizeMcpPayload(), timeout])
  ↓
  ✓ Success → replace with sanitized text, show 🛡️ notification
  ✗ Timeout/Error → block payload with safety error message
```

---

### Step 4: Mock MCP Server

#### [mock-mcp.js](file:///Users/lakshaychandra/Documents/wf-sanitize-ext/mock-mcp.js) [NEW]
Standalone Node.js script using `@modelcontextprotocol/sdk`:

| Tool | Profile Hit | Payload |
|---|---|---|
| `mcp_test_weather` | bypass | Simple 10-line weather text |
| `mcp_test_splunk` | regex-only | 10,500 lines with IPs, emails, AWS keys, SSNs, JWTs, credit cards |
| `mcp_test_github` | json-keys | Nested JSON with `developer_email`, `token`, `ssh_key`, `database_url` |

**Setup:** Add to VS Code `settings.json`:
```json
"chat.experimental.mcp.servers": {
  "safechat-mock-mcp": {
    "type": "stdio",
    "command": "node",
    "args": ["${workspaceFolder}/mock-mcp.js"]
  }
}
```

## Verification

- **`npm run compile`** — ✅ Zero TypeScript errors
- All re-exports from `sanitizer.ts` verified (types and functions)
- Mock MCP server uses CommonJS `require()` for compatibility with the project's module format
