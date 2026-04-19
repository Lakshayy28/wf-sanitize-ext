/**
 * heuristic.ts — Terminal & MCP Output Classification
 * ════════════════════════════════════════════════════
 * Determines which Gitleaks config to use based on the command context.
 * - Debug mode (testing.toml): test runners, build tools, stack traces
 * - Strict mode (strict.toml): data-exfiltrating commands like cat, printenv, curl
 */

import * as path from 'path';

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

export type TerminalMode = 'debug' | 'strict';

// ────────────────────────────────────────────────────────────────────────────
// Pattern Sets
// ────────────────────────────────────────────────────────────────────────────

/** Commands that produce test/debug output — use lenient scanning */
const DEBUG_COMMAND_PATTERNS = /\b(?:npm\s+(?:test|run\s+(?:test|spec|e2e|integration|coverage))|jest|pytest|mocha|vitest|make\b|cargo\s+test|go\s+test|dotnet\s+test|mvn\s+test|gradle\s+test|rspec|phpunit|bun\s+test|deno\s+test|playwright|cypress|nyc|c8|istanbul|tap|ava|jasmine|karma|qunit|prove|ctest|gtest)\b/i;

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
export function classifyTerminalMode(command?: string, output?: string): TerminalMode {
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
export function getConfigPath(mode: TerminalMode, extensionPath: string): string {
  const configName = mode === 'debug' ? 'testing.toml' : 'strict.toml';
  return path.join(extensionPath, 'configs', configName);
}
