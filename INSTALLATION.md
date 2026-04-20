# SafeChat — Installation Guide

Step-by-step setup from a fresh clone, covering all dependencies including Gitleaks binaries, web-tree-sitter WASM grammars, and the VS Code extension itself.

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|------------|----------------|-------|
| **Node.js** | 18.x | LTS recommended. [nodejs.org](https://nodejs.org) |
| **npm** | 9.x | Ships with Node.js 18+ |
| **VS Code** | 1.95.0 | Required for Chat Participant API |
| **GitHub Copilot** | any | Must be active in VS Code |
| **Git** | any | For cloning the repo |
| **macOS / Windows** | — | Gitleaks binaries bundled for `darwin-arm64` and `win-x64`. Linux requires a manual binary step (see below). |

---

## 1. Clone the Repository

```bash
git clone https://github.com/safechat/wf-sanitize-ext.git
cd wf-sanitize-ext
```

---

## 2. Install Node Dependencies

```bash
npm install --legacy-peer-deps
```

The `--legacy-peer-deps` flag is required because `web-tree-sitter@0.24.7` has a peer dependency conflict with the version pinned for WASM grammar compatibility. Without this flag, npm will refuse to install.

This installs:
- `web-tree-sitter` — WASM runtime for Tree-Sitter CST parsing
- `tree-sitter-wasms` — Precompiled WASM grammars (JSON, YAML, TOML, HTML, Bash)
- `@tree-sitter-grammars/tree-sitter-yaml` — YAML grammar (pinned version)
- TypeScript and ESLint toolchain (dev dependencies)

---

## 3. Gitleaks Binary

### macOS (Apple Silicon — darwin-arm64) and Windows (x64)

No action needed. The extension ships with precompiled Gitleaks v8.30.1 binaries at:

```
server/
  darwin-arm64/gitleaks      (macOS Apple Silicon)
  win-x64/gitleaks.exe       (Windows x64)
```

These are committed to the repository. If git LFS or `.gitignore` is stripping them, verify the files exist and are executable:

```bash
# macOS
ls -lh server/darwin-arm64/gitleaks
chmod +x server/darwin-arm64/gitleaks
./server/darwin-arm64/gitleaks version    # should print: v8.30.1
```

### macOS (Intel — darwin-x64)

Download the correct binary from the [Gitleaks releases page](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1):

```bash
# Download and place
curl -L https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz \
  | tar -xz gitleaks
mkdir -p server/darwin-x64
mv gitleaks server/darwin-x64/gitleaks
chmod +x server/darwin-x64/gitleaks
```

### Linux (x64 or arm64)

```bash
# Linux x64
curl -L https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
  | tar -xz gitleaks
mkdir -p server/linux-x64
mv gitleaks server/linux-x64/gitleaks
chmod +x server/linux-x64/gitleaks

# Linux arm64
curl -L https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz \
  | tar -xz gitleaks
mkdir -p server/linux-arm64
mv gitleaks server/linux-arm64/gitleaks
chmod +x server/linux-arm64/gitleaks
```

`gitleaksEngine.ts` already includes platform detection for `linux-x64` and `linux-arm64` — it will find the binary automatically once placed in the correct directory.

---

## 4. Compile the Extension

```bash
npm run compile
```

This runs two steps in sequence:

1. **`copy-grammars`** — copies all WASM grammar files from `node_modules` into `grammars/`:
   - `tree-sitter.wasm` (runtime)
   - `tree-sitter-json.wasm`
   - `tree-sitter-yaml.wasm`
   - `tree-sitter-toml.wasm`
   - `tree-sitter-html.wasm`
   - `tree-sitter-bash.wasm`

2. **`tsc -p ./`** — compiles TypeScript source (`src/`) to JavaScript (`out/`).

Expected output:
```
> npm run copy-grammars && tsc -p ./
# (no errors)
```

Verify the grammars directory was populated:
```bash
ls -lh grammars/
# should show 6 .wasm files
```

---

## 5. Install the Extension in VS Code

### Option A: Install the pre-built VSIX

If a packaged `safe-copilot-context-0.0.1.vsix` file is provided:

```bash
code --install-extension safe-copilot-context-0.0.1.vsix
```

Or in VS Code: **Extensions** → **⋯ menu** → **Install from VSIX…** → select the file.

### Option B: Build the VSIX yourself

```bash
npx vsce package --no-dependencies
code --install-extension safe-copilot-context-0.0.1.vsix
```

### Option C: Run in Extension Development Host (for development)

Open the workspace in VS Code and press **F5** (or **Run → Start Debugging**). This opens a new VS Code window with the extension loaded from source. Any changes to `src/` require a recompile and reload (`Ctrl+R` / `Cmd+R` in the Extension Development Host window).

---

## 6. Verify Installation

Open a new VS Code window (or the Extension Development Host) and open the Chat panel:

```
Ctrl+Shift+I   (Windows/Linux)
Cmd+Shift+I    (macOS)
```

Type:

```
@safechat hello
```

The `@safechat` participant should respond. If it doesn't appear in autocomplete, the extension is not active — check the Extensions panel for error messages.

---

## 7. Basic Usage

```
@safechat read the database config
@safechat show me the kubernetes secrets manifest
@safechat run terraform plan and explain the output
@safechat what's in my .env file?
```

SafeChat intercepts all Copilot tool results transparently. When secrets are detected, they are replaced with `[MASKED_BY_SAFECHAT]` and a shield notice appears in chat showing the pipeline route and how many secrets were caught.

---

## 8. Optional: Custom Detection Rules

To add org-specific secret detection rules without modifying the extension:

1. Copy the sample rules file to your workspace root:
   ```bash
   cp configs/safechat-rules.sample.toml /path/to/your/project/safechat-rules.toml
   ```

2. Edit `safechat-rules.toml` to add your patterns.

3. Save the file — SafeChat hot-reloads it automatically. No restart needed.

See `configs/safechat-rules.sample.toml` for the full documented template, including examples for API tokens, database passwords, connection strings, and allowlist patterns.

---

## Troubleshooting

### `@safechat` not appearing in chat autocomplete

- Verify VS Code version ≥ 1.95.0 (`Help → About`)
- Verify GitHub Copilot extension is installed and active
- Check **Extensions** panel for "SafeChat" and look for any error badge
- In Extension Development Host: check the Debug Console for startup errors

### Gitleaks binary permission denied (macOS)

macOS Gatekeeper may quarantine downloaded binaries. Run:
```bash
xattr -d com.apple.quarantine server/darwin-arm64/gitleaks
chmod +x server/darwin-arm64/gitleaks
```

### Grammars not found / Tree-Sitter fails to load

Re-run the copy step:
```bash
npm run copy-grammars
```
Then verify all 6 files exist in `grammars/`.

### npm install fails with peer dependency errors

Always use `--legacy-peer-deps`:
```bash
npm install --legacy-peer-deps
```

### TypeScript compile errors after pulling changes

```bash
npm run compile
```
If errors persist, check the `out/` directory for stale artifacts:
```bash
rm -rf out/
npm run compile
```

### VSIX packaging fails with "secrets detected"

The `.vscodeignore` file excludes test fixtures. If you have added new fixture files containing intentional fake secrets, add their directory to `.vscodeignore` before packaging.

---

## File Layout After Setup

After a successful `npm install --legacy-peer-deps && npm run compile`, your workspace should contain:

```
grammars/
  tree-sitter.wasm          ← copied from node_modules
  tree-sitter-json.wasm     ← copied from node_modules
  tree-sitter-yaml.wasm     ← copied from node_modules
  tree-sitter-toml.wasm     ← copied from node_modules
  tree-sitter-html.wasm     ← copied from node_modules
  tree-sitter-bash.wasm     ← copied from node_modules
out/
  extension.js              ← compiled from src/
  gitleaksEngine.js
  router.js
  treeSitterEngine.js
  heuristic.js
server/
  darwin-arm64/gitleaks     ← committed binary (or manually placed)
  win-x64/gitleaks.exe      ← committed binary (or manually placed)
```
