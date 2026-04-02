/**
 * astSanitizer.ts — Lightweight Pure-JS AST Sanitizer
 * ════════════════════════════════════════════════════
 * Tier 2 engine for structured config files.
 * Uses domain-specific pure-JS parsers (zero WASM / native bindings):
 *
 *   JSON/JSONC   → jsonc-parser  (offset-based edits, preserves formatting)
 *   YAML         → yaml          (AST document walk, preserves comments)
 *   XML          → fast-xml-parser (DOM traversal)
 *   ENV/Props    → line-by-line regex (PROP_RE)
 *   CSV/TSV      → RFC-4180 parser (quote-aware cell splitting)
 *
 * Parses into AST, identifies sensitive KEYS, masks their VALUES.
 * Guarantees 100% structure retention and zero false positives on code identifiers.
 */

import { MASK, isSensitiveKey } from './regexSanitizer';
import { localPiiScan } from './piiSanitizer';
import * as jsoncParser from 'jsonc-parser';
import * as YAML from 'yaml';
import { XMLParser, XMLBuilder } from 'fast-xml-parser';

// ────────────────────────────────────────────────────────────────────────────
// AST Value Processor (100% synchronous — zero API calls)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Process a single AST key-value pair:
 *  1. FAST PATH  — key matches the dynamic secret list → instant MASK
 *  2. SAFE PATH  — structural keys (version, id, type…) → passthrough
 *  3. LOCAL PII  — regex-based PII scan on the isolated value (synchronous)
 */
function processAstValue(key: string, value: string): string {
  // 1. FAST PATH: Mask known tech secrets instantly
  if (isSensitiveKey(key)) {
    return MASK;
  }

  // 2. SAFE PATH: Skip scanning for structural keys to prevent false positives
  const IGNORE_KEYS = /^(version|id|lineage|serial|type|kind|namespace|replicas|image|ami)$/i;
  if (IGNORE_KEYS.test(key.trim())) {
    return value;
  }

  // 3. LOCAL PII: Synchronous regex scan for PII entities in the value
  if (typeof value === 'string' && value.length > 3) {
    return localPiiScan(value);
  }
  return value;
}

// ────────────────────────────────────────────────────────────────────────────
// JSON / JSONC / JSONL Parser — jsonc-parser (offset-based editing)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize JSON/JSONC/JSONL files using Microsoft's `jsonc-parser`.
 * Walks the AST via `visit()`, collects offset-based edits for sensitive
 * values, then applies them back-to-front so positions stay stable.
 * Handles comments, trailing commas, and preserves all original formatting.
 *
 * Returns null if the input is not valid JSON/JSONC (caller should fall back).
 */
export function sanitizeJson(
  text: string,
): { cleanText: string; wasModified: boolean } | null {
  // Quick validation — bail if jsonc-parser can't make sense of it
  const errors: jsoncParser.ParseError[] = [];
  jsoncParser.parse(text, errors);
  if (errors.length > 0 && errors.some(e => e.error === jsoncParser.ParseErrorCode.InvalidSymbol)) {
    return null;
  }

  let modified = false;
  type Edit = { offset: number; length: number; replacement: string };
  const edits: Edit[] = [];

  // Track the current property name and a stack of parent object keys
  // so that "value" nested under a sensitive key (e.g. db_password.value in
  // Terraform state) correctly inherits the parent's sensitivity.
  let currentKey: string | undefined;
  const keyStack: string[] = [];

  jsoncParser.visit(text, {
    onObjectBegin() {
      keyStack.push(currentKey ?? '');
      currentKey = undefined;
    },
    onObjectProperty(property: string) {
      currentKey = property;
    },
    onLiteralValue(value: unknown, offset: number, length: number) {
      if (currentKey === undefined) { return; }
      if (typeof value !== 'string' || value.length === 0) { currentKey = undefined; return; }

      // Parent-key inheritance: if this key is a generic "value" (or "default")
      // and the immediate parent object key is itself sensitive, promote the
      // effective key so the value is masked directly (e.g. tfstate pattern:
      //   "db_password": { "value": "Sup3rS3cr3t", "sensitive": true }).
      const parentKey = keyStack.length > 0 ? keyStack[keyStack.length - 1] : '';
      const INHERITED_VALUE_KEYS = new Set(['value', 'default', 'data']);
      const effectiveKey =
        INHERITED_VALUE_KEYS.has(currentKey) && parentKey && isSensitiveKey(parentKey)
          ? parentKey
          : currentKey;

      // We can only do sync checks in the visitor — collect all candidates
      // and process async operations after the walk
      edits.push({ offset, length, replacement: effectiveKey });
      currentKey = undefined;
    },
    onObjectEnd() {
      keyStack.pop();
      currentKey = undefined;
    },
  });

  // Process collected edits: run processAstValue for each candidate
  const resolvedEdits: Edit[] = [];
  for (const edit of edits) {
    const key = edit.replacement; // we stored the key temporarily
    const rawSlice = text.slice(edit.offset, edit.offset + edit.length);

    // Extract the actual string value (strip surrounding quotes)
    let originalValue: string;
    try {
      originalValue = JSON.parse(rawSlice);
    } catch {
      continue;
    }
    if (typeof originalValue !== 'string') { continue; }

    const cleaned = processAstValue(key, originalValue);
    if (cleaned !== originalValue) {
      modified = true;
      // Build the replacement including the JSON quotes
      const jsonEncoded = JSON.stringify(cleaned);
      resolvedEdits.push({ offset: edit.offset, length: edit.length, replacement: jsonEncoded });
    }
  }

  if (!modified) {
    return { cleanText: text, wasModified: false };
  }

  // Apply edits back-to-front to preserve offsets
  let result = text;
  for (let i = resolvedEdits.length - 1; i >= 0; i--) {
    const e = resolvedEdits[i];
    result = result.slice(0, e.offset) + e.replacement + result.slice(e.offset + e.length);
  }

  return { cleanText: result, wasModified: true };
}

// ────────────────────────────────────────────────────────────────────────────
// YAML Parser — `yaml` library (AST document walk)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize YAML using the `yaml` library's `parseDocument()`.
 * Walks the concrete syntax tree (CST-aware document model), which preserves:
 *   - comments, anchors, aliases, block scalars, flow collections
 *   - original quoting style and indentation
 *
 * Mutates scalar values in-place (the document model tracks positions),
 * then serializes back via `doc.toString()` which re-emits the source
 * with only the changed values differing.
 */
export function sanitizeYaml(
  text: string,
): { cleanText: string; wasModified: boolean } {
  let doc: YAML.Document;
  try {
    doc = YAML.parseDocument(text, { keepSourceTokens: true });
  } catch {
    // Not valid YAML — fall back to line-by-line regex
    return sanitizeYamlRegex(text);
  }

  // If the document has serious errors, use the regex fallback
  if (doc.errors.length > 0) {
    return sanitizeYamlRegex(text);
  }

  let modified = false;

  function walkNode(node: unknown, parentKey?: string): void {
    if (YAML.isMap(node)) {
      for (const item of node.items) {
        const keyStr = YAML.isScalar(item.key) ? String(item.key.value) : undefined;
        if (YAML.isScalar(item.value) && typeof item.value.value === 'string' && keyStr) {
          const original = item.value.value as string;
          if (original.length > 0) {
            // Parent-key inheritance: "value" / "default" / "data" nested under
            // a sensitive parent key inherits the parent's sensitivity category
            // (e.g. Terraform outputs: db_password.value, K8s secret data.password).
            const INHERITED_VALUE_KEYS = new Set(['value', 'default', 'data']);
            const effectiveKey =
              INHERITED_VALUE_KEYS.has(keyStr) && parentKey && isSensitiveKey(parentKey)
                ? parentKey
                : keyStr;
            const cleaned = processAstValue(effectiveKey, original);
            if (cleaned !== original) {
              modified = true;
              item.value.value = cleaned;
            }
          }
        } else if (YAML.isMap(item.value) || YAML.isSeq(item.value)) {
          walkNode(item.value, keyStr);
        }
      }
    } else if (YAML.isSeq(node)) {
      for (const item of node.items) {
        if (YAML.isMap(item) || YAML.isSeq(item)) {
          walkNode(item, parentKey);
        }
        // Scalar items in sequences: mask if parent key is sensitive
        if (YAML.isScalar(item) && typeof item.value === 'string' && parentKey) {
          const original = item.value as string;
          if (original.length > 0) {
            const cleaned = processAstValue(parentKey, original);
            if (cleaned !== original) {
              modified = true;
              item.value = cleaned;
            }
          }
        }
      }
    }
  }

  walkNode(doc.contents);

  if (!modified) {
    return { cleanText: text, wasModified: false };
  }

  return { cleanText: doc.toString(), wasModified: true };
}

/**
 * Regex fallback for YAML files that fail AST parsing.
 * Matches `key: value` patterns line-by-line.
 */
function sanitizeYamlRegex(
  text: string,
): { cleanText: string; wasModified: boolean } {
  let modified = false;
  const lines = text.split('\n');
  const result: string[] = [];

  const KV_RE = /^(\s*)([\w][\w.\-]*)\s*:\s*(.*)$/;

  for (const line of lines) {
    const match = line.match(KV_RE);
    if (match) {
      const [, indent, key, rawVal] = match;
      const trimmedVal = rawVal.trim();

      // Skip if value is empty, a block indicator, or a nested mapping
      if (!trimmedVal || trimmedVal === '|' || trimmedVal === '>' || trimmedVal === '|-' || trimmedVal === '>-') {
        result.push(line);
        continue;
      }
      // Skip list/object starters
      if (trimmedVal.startsWith('[') || trimmedVal.startsWith('{')) {
        result.push(line);
        continue;
      }

      // Extract trailing comment
      let comment = '';
      const commentMatch = rawVal.match(/(\s+#.*)$/);
      if (commentMatch) { comment = commentMatch[1]; }

      // Isolate value portion (strip trailing comment)
      const valStr = comment
        ? rawVal.slice(0, rawVal.length - comment.length).trim()
        : trimmedVal;

      // Unquote for processAstValue
      let unquotedVal = valStr;
      let quoteChar = '';
      if ((valStr.startsWith('"') && valStr.endsWith('"') && valStr.length > 1) ||
          (valStr.startsWith("'") && valStr.endsWith("'") && valStr.length > 1)) {
        quoteChar = valStr[0];
        unquotedVal = valStr.slice(1, -1);
      }

      const cleaned = processAstValue(key, unquotedVal);
      if (cleaned !== unquotedVal) {
        modified = true;
        if (quoteChar) {
          result.push(`${indent}${key}: ${quoteChar}${cleaned}${quoteChar}${comment}`);
        } else {
          result.push(`${indent}${key}: ${cleaned}${comment}`);
        }
      } else {
        result.push(line);
      }
    } else {
      result.push(line);
    }
  }

  return { cleanText: result.join('\n'), wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// ENV Parser (.env files) — Regex Engine
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize .env files by splitting into lines, matching KEY=VALUE patterns,
 * and masking values whose keys match the sensitive-key list.
 */
export function sanitizeEnv(rawText: string): { cleanText: string; wasModified: boolean } {
  let modified = false;
  const lines = rawText.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const match = line.match(/^(\s*[A-Za-z0-9_.-]+)(\s*[:=]\s*)(["']?)(.*?)(["']?)(\s*(?:#.*)?)$/);

    if (match) {
      const [, key, operator, quoteOpen, value, quoteClose, tail] = match;

      if (quoteOpen === quoteClose) {
        const maskedValue = processAstValue(key, value);

        if (maskedValue !== value) {
          modified = true;
          lines[i] = `${key}${operator}${quoteOpen}${maskedValue}${quoteClose}${tail}`;
        }
      }
    }
  }
  return { cleanText: lines.join('\n'), wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// Properties / INI Parser — Regex Engine
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize .properties / .ini files using regex line-by-line matching.
 */
export function sanitizeProperties(
  text: string,
): { cleanText: string; wasModified: boolean } {
  let modified = false;
  const lines = text.split('\n');
  const result: string[] = [];

  const PROP_RE = /^(\s*[A-Za-z0-9_.\-]+)(\s*[=:]\s*)(.*)$/;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';') || trimmed.startsWith('[')) {
      result.push(line);
      continue;
    }

    const match = line.match(PROP_RE);
    if (match) {
      const [, keyPart, sep, valuePart] = match;
      const keyName = keyPart.trim();
      const trimVal = valuePart.trim();

      // Skip structural characters (block openers/closers in Gradle, HCL, etc.)
      if (trimVal.length > 0 && !/^[{}\[\]()]$/.test(trimVal)) {
        const cleaned = processAstValue(keyName, trimVal);
        if (cleaned !== trimVal) {
          result.push(`${keyPart}${sep}${cleaned}`);
          modified = true;
        } else {
          result.push(line);
        }
      } else {
        result.push(line);
      }
    } else {
      result.push(line);
    }
  }

  return { cleanText: result.join('\n'), wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// XML Parser — fast-xml-parser (DOM traversal)
// ────────────────────────────────────────────────────────────────────────────

const xmlParserOptions = {
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  preserveOrder: true,
  commentPropName: '#comment',
  cdataPropName: '#cdata',
  trimValues: false,
  parseTagValue: false,
  parseAttributeValue: false,
};

const xmlBuilderOptions = {
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  preserveOrder: true,
  commentPropName: '#comment',
  cdataPropName: '#cdata',
  format: true,
  suppressEmptyNode: false,
  suppressBooleanAttributes: false,
};

/**
 * Sanitize XML using `fast-xml-parser` for proper DOM-level traversal.
 * Walks the parsed tree, masking:
 *   - Text content of elements whose tag name matches sensitive keys
 *   - Attribute values where the attribute name matches sensitive keys
 *   - Config-style: `name="password" value="secret"` patterns
 *
 * Falls back to the regex-based XML scanner if parsing fails.
 */
export function sanitizeXml(
  text: string,
): { cleanText: string; wasModified: boolean } {
  let parsed: unknown[];
  try {
    const parser = new XMLParser(xmlParserOptions);
    parsed = parser.parse(text);
  } catch {
    return sanitizeXmlRegex(text);
  }

  if (!Array.isArray(parsed) || parsed.length === 0) {
    return sanitizeXmlRegex(text);
  }

  let modified = false;

  function walkXmlNodes(nodes: unknown[]): void {
    for (const node of nodes) {
      if (typeof node !== 'object' || node === null) { continue; }
      const obj = node as Record<string, unknown>;

      for (const tagName of Object.keys(obj)) {
        if (tagName.startsWith('@_') || tagName === '#text' || tagName === '#comment' || tagName === '#cdata') {
          continue;
        }

        const children = obj[tagName] as unknown[];
        if (!Array.isArray(children)) { continue; }

        for (const child of children) {
          if (typeof child !== 'object' || child === null) { continue; }
          const childObj = child as Record<string, unknown>;

          // Process text node: <tagName>value</tagName>
          if (typeof childObj['#text'] === 'string' && childObj['#text'].trim().length > 0) {
            const original = childObj['#text'] as string;
            const cleaned = processAstValue(tagName, original.trim());
            if (cleaned !== original.trim()) {
              modified = true;
              childObj['#text'] = cleaned;
            }
          }

          // Process attributes: mask if attr name is sensitive
          const attrs = childObj[':@'] as Record<string, unknown> | undefined;
          if (attrs && typeof attrs === 'object') {
            // Config-style detection: name/key attr has sensitive value → mask "value" attr
            const nameAttr = (attrs['@_name'] ?? attrs['@_key'] ?? attrs['@_id']) as string | undefined;
            if (nameAttr && typeof nameAttr === 'string' && isSensitiveKey(nameAttr)) {
              if (typeof attrs['@_value'] === 'string' && attrs['@_value'].length > 0) {
                modified = true;
                attrs['@_value'] = MASK;
              }
            }

            // Individual sensitive attributes
            for (const [attrName, attrVal] of Object.entries(attrs)) {
              if (!attrName.startsWith('@_')) { continue; }
              const cleanAttrName = attrName.slice(2); // strip @_ prefix
              if (typeof attrVal === 'string' && attrVal.length > 0 && isSensitiveKey(cleanAttrName)) {
                const cleaned = processAstValue(cleanAttrName, attrVal);
                if (cleaned !== attrVal) {
                  modified = true;
                  attrs[attrName] = cleaned;
                }
              }
            }
          }

          // Recurse into nested tags
          for (const childTag of Object.keys(childObj)) {
            if (childTag === '#text' || childTag === '#comment' || childTag === '#cdata' || childTag === ':@') {
              continue;
            }
            if (Array.isArray(childObj[childTag])) {
              // Wrap into the structure walkXmlNodes expects
              walkXmlNodes([{ [childTag]: childObj[childTag] }]);
            }
          }
        }
      }
    }
  }

  walkXmlNodes(parsed);

  if (!modified) {
    return { cleanText: text, wasModified: modified };
  }

  try {
    const builder = new XMLBuilder(xmlBuilderOptions);
    const rebuilt = builder.build(parsed) as string;

    // Preserve XML declaration if original had one
    const declMatch = text.match(/^<\?xml[^?]*\?>\s*/);
    const builtDeclMatch = rebuilt.match(/^<\?xml[^?]*\?>\s*/);
    let cleanText = rebuilt;
    if (declMatch && !builtDeclMatch) {
      cleanText = declMatch[0] + rebuilt;
    }

    return { cleanText, wasModified: true };
  } catch {
    // If builder fails, fall back to regex approach
    return sanitizeXmlRegex(text);
  }
}

/**
 * Regex fallback for XML files that fail DOM parsing.
 */
function sanitizeXmlRegex(
  text: string,
): { cleanText: string; wasModified: boolean } {
  let modified = false;
  let cleanText = text;

  // Tag-based: <tagName>value</tagName>
  const tagRe = /(<([A-Za-z0-9_.\-:]+)[^>]*>)([^<]+)(<\/\2>)/g;
  type TagReplacement = { start: number; end: number; text: string };
  const replacements: TagReplacement[] = [];

  let tagMatch: RegExpExecArray | null;
  while ((tagMatch = tagRe.exec(cleanText)) !== null) {
    const [full, openTag, tagName, value, closeTag] = tagMatch;
    if (value.trim().length > 0) {
      const cleaned = processAstValue(tagName, value.trim());
      if (cleaned !== value.trim()) {
        modified = true;
        replacements.push({
          start: tagMatch.index,
          end: tagMatch.index + full.length,
          text: `${openTag}${cleaned}${closeTag}`,
        });
      }
    }
  }

  for (let i = replacements.length - 1; i >= 0; i--) {
    const r = replacements[i];
    cleanText = cleanText.slice(0, r.start) + r.text + cleanText.slice(r.end);
  }

  // Attribute-based: name="password" value="secret"
  cleanText = cleanText.replace(
    /(\b(?:name|key|id)\s*=\s*["'][^"']*(?:password|secret|token|key|auth|credential|cert|api)[^"']*["']\s+(?:value)\s*=\s*)(["'])([^"']*)\2/gi,
    (full, prefix, quote, value) => {
      if (value.trim().length > 0) {
        modified = true;
        return `${prefix}${quote}${MASK}${quote}`;
      }
      return full;
    }
  );

  return { cleanText, wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// TOML Parser — Reuses Properties Regex Engine
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize TOML files using the properties regex parser.
 * TOML's `key = value` syntax is compatible with the properties regex engine.
 */
export function sanitizeToml(
  rawText: string,
): { cleanText: string; wasModified: boolean } {
  return sanitizeProperties(rawText);
}

// ────────────────────────────────────────────────────────────────────────────
// HCL Parser — Reuses Properties Regex Engine
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize HCL files (.tf, .tfvars, .hcl) using the properties regex parser.
 * HCL's `key = value` syntax is compatible with the properties regex engine.
 * The structural character guard prevents `{` / `}` corruption.
 */
export function sanitizeHcl(
  rawText: string,
): { cleanText: string; wasModified: boolean } {
  return sanitizeProperties(rawText);
}

// ────────────────────────────────────────────────────────────────────────────
// CSV / TSV Parser — Header-based Column Sanitizer (RFC-4180 quote-aware)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize CSV/TSV files by treating the header row as column keys and each
 * data cell as a value. Runs every cell through processAstValue so that
 * columns like "password", "ssn", "api_key" get masked automatically and
 * other values go through local PII scanning.
 *
 * @param delimiter — explicit delimiter override. Auto-detected (tab/comma) if omitted.
 */
export function sanitizeTabular(
  rawText: string,
  delimiter?: string,
): { cleanText: string; wasModified: boolean } {
  const lines = rawText.split('\n');
  if (lines.length < 2) {
    // Need at least a header + one data row
    return { cleanText: rawText, wasModified: false };
  }

  // Detect delimiter: explicit param > tab-first > comma
  const sep = delimiter ?? (lines[0].includes('\t') ? '\t' : ',');

  // Parse header row (strip surrounding quotes)
  const headers = parseCsvRow(lines[0], sep);
  if (headers.length === 0) {
    return { cleanText: rawText, wasModified: false };
  }

  let modified = false;
  const resultLines: string[] = [lines[0]]; // keep header unchanged

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    // Preserve blank lines / trailing newline
    if (line.trim().length === 0) {
      resultLines.push(line);
      continue;
    }

    const cells = parseCsvRow(line, sep);
    const cleanedCells: string[] = [];

    for (let col = 0; col < cells.length; col++) {
      const header = col < headers.length ? headers[col] : `col_${col}`;
      const cell = cells[col];
      if (cell.trim().length > 0) {
        const cleaned = processAstValue(header, cell);
        if (cleaned !== cell) { modified = true; }
        cleanedCells.push(cleaned);
      } else {
        cleanedCells.push(cell);
      }
    }

    // Rebuild the line — quote cells that contain the delimiter or quotes
    resultLines.push(cleanedCells.map(c => csvQuote(c, sep)).join(sep));
  }

  return { cleanText: resultLines.join('\n'), wasModified: modified };
}

/** Parse a single CSV row respecting quoted fields. */
function parseCsvRow(row: string, delimiter: string): string[] {
  const cells: string[] = [];
  let i = 0;
  while (i <= row.length) {
    if (i === row.length) { cells.push(''); break; }
    if (row[i] === '"') {
      // Quoted field
      let j = i + 1;
      let value = '';
      while (j < row.length) {
        if (row[j] === '"') {
          if (j + 1 < row.length && row[j + 1] === '"') {
            value += '"';
            j += 2;
          } else {
            j++; // closing quote
            break;
          }
        } else {
          value += row[j];
          j++;
        }
      }
      cells.push(value);
      // Skip delimiter after closing quote
      if (j < row.length && row[j] === delimiter) { j++; }
      i = j;
    } else {
      // Unquoted field
      const end = row.indexOf(delimiter, i);
      if (end === -1) {
        cells.push(row.substring(i));
        break;
      }
      cells.push(row.substring(i, end));
      i = end + 1;
    }
  }
  return cells;
}

/** Quote a CSV cell if it contains the delimiter, quotes, or newlines. */
function csvQuote(cell: string, delimiter: string): string {
  if (cell.includes(delimiter) || cell.includes('"') || cell.includes('\n')) {
    return '"' + cell.replace(/"/g, '""') + '"';
  }
  return cell;
}

// ────────────────────────────────────────────────────────────────────────────
// Tier 2B: Universal Key-Value Lexer (proprietary config fallback)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Fallback sanitizer for proprietary structured files that use standard
 * assignment operators (=, :, ->, >>) but aren't a known grammar.
 *
 * Strategy: split each line into key + delimiter + rest-of-line,
 * check the key against isSensitiveKey(), and aggressively mask the
 * entire value portion if positive. This is intentionally conservative
 * because we can't reliably parse custom quoting or comment styles.
 */
export function sanitizeUniversalKeyValue(
  rawText: string,
): { cleanText: string; wasModified: boolean } {
  let modified = false;
  const lines = rawText.split('\n');

  // Matches: Key (Group 1), Delimiter (Group 2), Value+Comments (Group 3)
  // Supports delimiters: =, :, ->, >>
  const universalRegex = /^(\s*[A-Za-z0-9_.-]+)(\s*(?:[:=]|->|>>)\s*)(.*)$/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip blank lines and common comment prefixes
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';') ||
        trimmed.startsWith('//') || trimmed.startsWith('/*')) {
      continue;
    }

    const match = line.match(universalRegex);
    if (match) {
      const [, key, delimiter, restOfLine] = match;
      if (restOfLine.trim().length > 0 && isSensitiveKey(key.trim())) {
        modified = true;
        lines[i] = `${key}${delimiter}${MASK}`;
      }
    }
  }

  return { cleanText: lines.join('\n'), wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// Dispatcher
// ────────────────────────────────────────────────────────────────────────────

export type AstFormat = 'json' | 'jsonc' | 'jsonl' | 'yaml' | 'env' | 'properties' | 'xml' | 'toml' | 'hcl' | 'csv' | 'tsv';

/**
 * Route to the correct AST parser based on the detected format.
 * 100% synchronous — zero API calls. Uses key-heuristics + local PII regex.
 */
export function astSanitize(
  text: string,
  format: AstFormat,
): { cleanText: string; wasModified: boolean } {
  switch (format) {
    case 'json':
    case 'jsonc': {
      const result = sanitizeJson(text);
      // If JSON/JSONC parsing fails, fall back to YAML parser (handles key: value generically)
      return result ?? sanitizeYaml(text);
    }
    case 'jsonl': {
      // JSONL: each line is an independent JSON object
      return sanitizeJsonl(text);
    }
    case 'yaml':
      return sanitizeYaml(text);
    case 'env':
      return sanitizeEnv(text);
    case 'properties':
      return sanitizeProperties(text);
    case 'xml':
      return sanitizeXml(text);
    case 'toml':
      return sanitizeToml(text);
    case 'hcl':
      return sanitizeHcl(text);
    case 'csv':
      return sanitizeTabular(text, ',');
    case 'tsv':
      return sanitizeTabular(text, '\t');
    default:
      return { cleanText: text, wasModified: false };
  }
}

/**
 * Sanitize JSONL (newline-delimited JSON).
 * Each non-empty line is independently parsed and sanitized.
 */
function sanitizeJsonl(
  text: string,
): { cleanText: string; wasModified: boolean } {
  const lines = text.split('\n');
  let modified = false;
  const result: string[] = [];

  for (const line of lines) {
    if (line.trim().length === 0) {
      result.push(line);
      continue;
    }
    const lineResult = sanitizeJson(line);
    if (lineResult) {
      result.push(lineResult.cleanText);
      if (lineResult.wasModified) { modified = true; }
    } else {
      result.push(line); // unparseable line — keep as-is
    }
  }

  return { cleanText: result.join('\n'), wasModified: modified };
}
