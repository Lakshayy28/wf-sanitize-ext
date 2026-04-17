# Red Team Security Audit: @safechat

**Date:** 2026-04-17
**Target:** `@safechat` Data Loss Prevention (DLP) VS Code Extension
**Scope:** Core Zero-Trust Interception Architecture (`extension.ts`, `sanitizer.ts`)
**Objective:** Bypass sanitization, induce state poisoning, crash the Extension Host, and identify orphaned process leaks.

---

## 1. The Native Tool Bypass (The "Zero-Day" Threat)

### 🔴 VULNERABILITY 1A: PromptTsxPart / Object Injection Bypass
**Vector:** Universal Triage Sandbox (`extension.ts` lines 1338-1342)  
**Severity:** CRITICAL - Complete Sanitization Bypass

**Exploit Scenario:** 
The sandbox incorrectly assumes `invokeResult.content` parts always evaluate to primitive strings. 
```typescript
if (typeof val === 'string') {
   // runs regex, presidio, truncation
} else {
   sanitizedParts.push(part); // BYPASS
}
```
If an MCP tool (or native tool) returns a structured object, binary buffer, or `LanguageModelPromptTsxPart` (which contains TSX components), the `typeof` check fails and the raw, completely unsanitized payload is funneled directly into the LLM context.

**Patch (Force Stringification Guard):**
```typescript
for (const part of (invokeResult.content as any[])) {
  let val = part.value;
  if (val === undefined || val === null) {
    sanitizedParts.push(part);
    continue;
  }
  
  // Force stringification of complex objects to ensure scanning
  if (typeof val !== 'string') {
      try { val = JSON.stringify(val); } catch { val = String(val); }
  }
  
  // ... execute sanitization on `val` ...
```

### 🔴 VULNERABILITY 1B: Terminal Write-Guard Bypass (Indirect State Mutation)
**Vector:** Native Write-Guard vs Terminal Routing Precedence  
**Severity:** HIGH - Unintended File Overwrites

**Exploit Scenario:** 
The Write-Guard correctly catches explicit edit tools (`vscode_applyWorkspaceEdit`). However, `isTerminalTool` takes precedence via `else if` routing. If the LLM uses a terminal command to mutate state (`sed -i s/foo/bar/ secret.json` or `echo "[MASKED_BY_SAFECHAT]" > .env`), it routes into `safechat_run_terminal`. The terminal executes natively *before* sanitizing the stdout. **No Write-Guard warning is ever shown to the user.** The user gets a native input box, blindly hits enter, and overwrites their config with dummy tokens.

**Patch (Inject Warning into Terminal Pipeline):**
```typescript
// Inside SafeRunTerminalTool.invoke()
if (inputContainsMaskedTokens(options.input)) {
    this._stream?.markdown(`\n\n> ⚠️ **SafeChat Alert:** Terminal command contains masked placeholders. Executing this may overwrite real secrets.\n\n`);
}
```

---

## 2. State Poisoning & Cache Leaks

### 🔴 VULNERABILITY 2A: Path Traversal via Suffix Matching
**Vector:** `SessionStateManager` (`extension.ts` lines 1594-1599)  
**Severity:** MODERATE - State Confusion

**Exploit Scenario:** 
```typescript
if (state.relPath === filePath || filePath.endsWith(state.relPath))
```
If `state.relPath` is `config/secret.json`, and the LLM explicitly requests to read `/workspace/malicious-repo/config/secret.json`, the `.endsWith` check triggers positively. Copilot is served the sanitized contents of the *first* file instead of the actual contents of the *second* file.

**Patch (Strict Path Separator Enforcement):**
```typescript
if (state.relPath === filePath || filePath.endsWith('/' + state.relPath) || filePath.endsWith('\\' + state.relPath)) {
```

---

## 3. Resource Exhaustion (OOM & V8 Lockups)

### 🔴 VULNERABILITY 3A: Uncapped File Allocation Spike
**Vector:** `safechat_read_file`  (`extension.ts` lines 176-177)  
**Severity:** CRITICAL - Denial of Service (V8 Crash)

**Exploit Scenario:** 
While `#codebase` directory mapping was fixed, arbitrary *single file* reads lack defense. An LLM invokes `safechat_read_file` on `server-access.log` (1.2 GB). 
`vscode.workspace.fs.readFile(fileUri)` allocates a 1.2GB buffer. `Buffer.from().toString('utf-8')` duplicates it into a consecutive string allocation. V8 exceeds heap limits and completely crashes the VS Code Extension Host.

**Patch (Pre-flight Stat Check):**
```typescript
const stat = await vscode.workspace.fs.stat(fileUri);
const ABSOLUTE_MAX_BYTES = 5 * 1024 * 1024; // 5MB limit
if (stat.size > ABSOLUTE_MAX_BYTES) {
    return new vscode.LanguageModelToolResult([
        new vscode.LanguageModelTextPart(`Error: File too large to read securely (${stat.size} bytes). Max limit is 5MB.`)
    ]);
}
```

---

## 4. The Timeout & Error Handling Blackholes

### 🔴 VULNERABILITY 4A: Orphaned Process Leaking (Dangling Promises)
**Vector:** MCP Triage Sandbox `Promise.race` (`extension.ts` lines 1323)  
**Severity:** HIGH - CPU/Memory Exhaustion via Zombie Processes

**Exploit Scenario:** 
```typescript
const invokeResult = await Promise.race([
  vscode.lm.invokeTool(call.name, { ... }, token),
  new Promise<never>((_, reject) => setTimeout(...))
]);
```
Currently, `token` is the parent Chat Request token. If an MCP server hangs processing a Splunk query, the 30-second `Promise.race` correctly times out, unblocking the LLM loop. **However, `invokeTool` is never canceled locally.** The MCP Splunk query continues burning CPU in the background forever. If the LLM loops this action 10 times, you spawn 10 zombie processes grinding VS Code to a halt.

**Patch (Local CancellationTokenSource):**
```typescript
const localTokenSource = new vscode.CancellationTokenSource();
token.onCancellationRequested(() => localTokenSource.cancel());

const timer = setTimeout(() => {
    localTokenSource.cancel(); // 🔴 KILL THE UNDERLYING MCP PROCESS 
}, invokeTimeoutMs);

try {
    const invokeResult = await vscode.lm.invokeTool(call.name, { ... }, localTokenSource.token);
    clearTimeout(timer);
    // ...
```
