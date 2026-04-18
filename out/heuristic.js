"use strict";
/**
 * heuristic.ts — Terminal & MCP Output Classification
 * ════════════════════════════════════════════════════
 * Determines which Gitleaks config to use based on the command context.
 * - Debug mode (testing.toml): test runners, build tools, stack traces
 * - Strict mode (strict.toml): data-exfiltrating commands like cat, printenv, curl
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.classifyTerminalMode = classifyTerminalMode;
exports.getConfigPath = getConfigPath;
const path = __importStar(require("path"));
// ────────────────────────────────────────────────────────────────────────────
// Pattern Sets
// ────────────────────────────────────────────────────────────────────────────
/** Commands that produce test/debug output — use lenient scanning */
const DEBUG_COMMAND_PATTERNS = /\b(?:npm\s+(?:test|run\s+test)|jest|pytest|mocha|vitest|make\b|cargo\s+test|go\s+test|dotnet\s+test|mvn\s+test|gradle\s+test|rspec|phpunit)\b/i;
/** Output patterns indicating test/debug context */
const DEBUG_OUTPUT_PATTERNS = /(?:^|\n)\s*(?:PASS|FAIL|ERROR|Tests?:\s|✓|✗|✘|✔|Traceback|at\s+\S+\s+\(|assert(?:ion)?(?:Error)?|expect\(|describe\(|it\(|test\(|Test Suite|Test Results|PASSED|FAILED|Error:|Stack trace:)/i;
/** Commands that can exfiltrate secrets — use strict scanning */
const STRICT_COMMAND_PATTERNS = /\b(?:cat|less|more|head|tail|printenv|curl|wget|env|set|echo|printf|type|Get-ChildItem|Get-Content|Select-String|Write-Output|dir|findstr|sort|grep|awk|sed|xxd|hexdump|strings|openssl|base64|jq|yq)\b/i;
// ────────────────────────────────────────────────────────────────────────────
// Classification
// ────────────────────────────────────────────────────────────────────────────
/**
 * Classify a terminal command + output into debug or strict mode.
 *
 * Priority:
 * 1. If command explicitly matches a debug runner → debug
 * 2. If command explicitly matches a strict command → strict
 * 3. If output looks like test output (stack traces, assertions) → debug
 * 4. Default → strict (fail-closed: maximum scanning)
 */
function classifyTerminalMode(command, output) {
    if (command) {
        if (DEBUG_COMMAND_PATTERNS.test(command)) {
            return 'debug';
        }
        if (STRICT_COMMAND_PATTERNS.test(command)) {
            return 'strict';
        }
    }
    if (output && DEBUG_OUTPUT_PATTERNS.test(output)) {
        return 'debug';
    }
    // Default: strict (fail-closed)
    return 'strict';
}
// ────────────────────────────────────────────────────────────────────────────
// Config Resolution
// ────────────────────────────────────────────────────────────────────────────
/**
 * Returns the path to the appropriate Gitleaks TOML config file.
 */
function getConfigPath(mode, extensionPath) {
    const configName = mode === 'debug' ? 'testing.toml' : 'strict.toml';
    return path.join(extensionPath, 'configs', configName);
}
//# sourceMappingURL=heuristic.js.map