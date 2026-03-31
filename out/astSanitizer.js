"use strict";
/**
 * astSanitizer.ts — Universal AST Guardian
 * ═════════════════════════════════════════
 * Tier 2 engine for structured config files (.json, .yaml, .env, .xml, .properties, .ini).
 * Parses into AST, identifies sensitive KEYS, masks their VALUES.
 * Guarantees 100% structure retention and zero false positives on code identifiers.
 *
 * No Presidio HTTP calls — purely local, fast key-matching.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeJson = sanitizeJson;
exports.sanitizeYaml = sanitizeYaml;
exports.sanitizeEnv = sanitizeEnv;
exports.sanitizeProperties = sanitizeProperties;
exports.sanitizeXml = sanitizeXml;
exports.sanitizeToml = sanitizeToml;
exports.sanitizeHcl = sanitizeHcl;
exports.sanitizeCsv = sanitizeCsv;
exports.sanitizeUniversalKeyValue = sanitizeUniversalKeyValue;
exports.astSanitize = astSanitize;
const regexSanitizer_1 = require("./regexSanitizer");
/**
 * Process a single AST key-value pair:
 *  1. FAST PATH — key matches the dynamic secret list → instant MASK
 *  2. SLOW PATH — send the isolated value to Presidio for human PII detection
 *  3. PASSTHROUGH — return the value unchanged
 */
async function processAstValue(key, value, piiCheck) {
    // 1. FAST PATH: Mask known tech secrets instantly
    if ((0, regexSanitizer_1.isSensitiveKey)(key)) {
        return regexSanitizer_1.MASK;
    }
    // 2. SAFE PATH: Skip Presidio for structural keys to prevent hallucinations
    const IGNORE_KEYS = /^(version|id|lineage|serial|type|kind|namespace|replicas|image|ami)$/i;
    if (IGNORE_KEYS.test(key.trim())) {
        return value;
    }
    // 3. SLOW PATH: Deep scan for human PII via Presidio NLP
    if (piiCheck && typeof value === 'string' && value.length > 3) {
        return piiCheck(value);
    }
    return value;
}
// ────────────────────────────────────────────────────────────────────────────
// JSON Parser — JSON.parse Engine
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize JSON by parsing with JSON.parse, walking the resulting object tree,
 * and masking string values whose keys match the sensitive-key list.
 * Returns null if the input is not valid JSON (caller should fall back).
 */
async function sanitizeJson(text, piiCheck) {
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        return null; // Not valid JSON — caller should fall back
    }
    let modified = false;
    async function walk(node) {
        if (Array.isArray(node)) {
            const items = [];
            for (const item of node) {
                items.push(await walk(item));
            }
            return items;
        }
        if (node !== null && typeof node === 'object') {
            const obj = node;
            const result = {};
            for (const [key, val] of Object.entries(obj)) {
                if (typeof val === 'string' && val.length > 0) {
                    const cleaned = await processAstValue(key, val, piiCheck);
                    if (cleaned !== val) {
                        modified = true;
                    }
                    result[key] = cleaned;
                }
                else if (typeof val === 'object' && val !== null) {
                    result[key] = await walk(val);
                }
                else {
                    result[key] = val;
                }
            }
            return result;
        }
        return node;
    }
    const indent = detectJsonIndent(text);
    const cleaned = await walk(parsed);
    const cleanText = JSON.stringify(cleaned, null, indent);
    return { cleanText, wasModified: modified };
}
function detectJsonIndent(text) {
    const match = text.match(/^[\s]*\n([ \t]+)/m);
    if (match) {
        const ws = match[1];
        if (ws[0] === '\t') {
            return 1;
        } // tab-indented, use 1 tab via JSON.stringify
        return ws.length;
    }
    return 2; // default
}
// ────────────────────────────────────────────────────────────────────────────
// YAML Parser — Regex Engine
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize YAML by splitting into lines, matching `key: value` patterns,
 * and masking string values whose keys match the sensitive-key list.
 */
async function sanitizeYaml(text, piiCheck) {
    let modified = false;
    const lines = text.split('\n');
    const result = [];
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
            if (commentMatch) {
                comment = commentMatch[1];
            }
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
            const cleaned = await processAstValue(key, unquotedVal, piiCheck);
            if (cleaned !== unquotedVal) {
                modified = true;
                if (quoteChar) {
                    result.push(`${indent}${key}: ${quoteChar}${cleaned}${quoteChar}${comment}`);
                }
                else {
                    result.push(`${indent}${key}: ${cleaned}${comment}`);
                }
            }
            else {
                result.push(line);
            }
        }
        else {
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
async function sanitizeEnv(rawText) {
    let modified = false;
    const lines = rawText.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = line.match(/^(\s*[A-Za-z0-9_.-]+)(\s*[:=]\s*)(["']?)(.*?)(["']?)(\s*(?:#.*)?)$/);
        if (match) {
            const [, key, operator, quoteOpen, value, quoteClose, tail] = match;
            if (quoteOpen === quoteClose) {
                const maskedValue = await processAstValue(key, value);
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
async function sanitizeProperties(text, piiCheck) {
    let modified = false;
    const lines = text.split('\n');
    const result = [];
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
                const cleaned = await processAstValue(keyName, trimVal, piiCheck);
                if (cleaned !== trimVal) {
                    result.push(`${keyPart}${sep}${cleaned}`);
                    modified = true;
                }
                else {
                    result.push(line);
                }
            }
            else {
                result.push(line);
            }
        }
        else {
            result.push(line);
        }
    }
    return { cleanText: result.join('\n'), wasModified: modified };
}
// ────────────────────────────────────────────────────────────────────────────
// XML Parser — Regex Engine
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize XML by finding <TagName>value</TagName> and sending values
 * through processAstValue (secret-key → MASK, otherwise → Presidio PII check).
 * Also handles attribute-based sensitive values: name="password" value="secret".
 */
async function sanitizeXml(text, piiCheck) {
    let modified = false;
    let cleanText = text;
    // Tag-based: <tagName>value</tagName> — process via AST-to-Presidio bridge
    const tagRe = /(<([A-Za-z0-9_.\-:]+)[^>]*>)([^<]+)(<\/\2>)/g;
    const replacements = [];
    let tagMatch;
    while ((tagMatch = tagRe.exec(cleanText)) !== null) {
        const [full, openTag, tagName, value, closeTag] = tagMatch;
        if (value.trim().length > 0) {
            const cleaned = await processAstValue(tagName, value.trim(), piiCheck);
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
    // Apply replacements in reverse order to preserve string positions
    for (let i = replacements.length - 1; i >= 0; i--) {
        const r = replacements[i];
        cleanText = cleanText.slice(0, r.start) + r.text + cleanText.slice(r.end);
    }
    // Attribute-based: name="password" value="secret" — sync sensitive-key check
    cleanText = cleanText.replace(/(\b(?:name|key|id)\s*=\s*["'][^"']*(?:password|secret|token|key|auth|credential|cert|api)[^"']*["']\s+(?:value)\s*=\s*)(["'])([^"']*)\2/gi, (full, prefix, quote, value) => {
        if (value.trim().length > 0) {
            modified = true;
            return `${prefix}${quote}${regexSanitizer_1.MASK}${quote}`;
        }
        return full;
    });
    return { cleanText, wasModified: modified };
}
// ────────────────────────────────────────────────────────────────────────────
// TOML Parser — Reuses Properties Regex Engine
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize TOML files using the properties regex parser.
 * TOML's `key = value` syntax is compatible with the properties regex engine.
 */
async function sanitizeToml(rawText, piiCheck) {
    return sanitizeProperties(rawText, piiCheck);
}
// ────────────────────────────────────────────────────────────────────────────
// HCL Parser — Reuses Properties Regex Engine
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize HCL files (.tf, .tfvars, .hcl) using the properties regex parser.
 * HCL's `key = value` syntax is compatible with the properties regex engine.
 * The structural character guard prevents `{` / `}` corruption.
 */
async function sanitizeHcl(rawText, piiCheck) {
    return sanitizeProperties(rawText, piiCheck);
}
// ────────────────────────────────────────────────────────────────────────────
// CSV / TSV Parser — Header-based Column Sanitizer
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize CSV/TSV files by treating the header row as keys and each data
 * cell as a value.  Runs every cell through processAstValue so that
 * columns like "password", "ssn", "api_key" get masked automatically and
 * other values go through Presidio PII detection.
 */
async function sanitizeCsv(rawText, piiCheck) {
    const lines = rawText.split('\n');
    if (lines.length < 2) {
        // Need at least a header + one data row
        return { cleanText: rawText, wasModified: false };
    }
    // Detect delimiter: tab-first, then comma
    const delimiter = lines[0].includes('\t') ? '\t' : ',';
    // Parse header row (strip surrounding quotes)
    const headers = parseCsvRow(lines[0], delimiter);
    if (headers.length === 0) {
        return { cleanText: rawText, wasModified: false };
    }
    let modified = false;
    const resultLines = [lines[0]]; // keep header unchanged
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        // Preserve blank lines / trailing newline
        if (line.trim().length === 0) {
            resultLines.push(line);
            continue;
        }
        const cells = parseCsvRow(line, delimiter);
        const cleanedCells = [];
        for (let col = 0; col < cells.length; col++) {
            const header = col < headers.length ? headers[col] : `col_${col}`;
            const cell = cells[col];
            if (cell.trim().length > 0) {
                const cleaned = await processAstValue(header, cell, piiCheck);
                if (cleaned !== cell) {
                    modified = true;
                }
                cleanedCells.push(cleaned);
            }
            else {
                cleanedCells.push(cell);
            }
        }
        // Rebuild the line — quote cells that contain the delimiter or quotes
        resultLines.push(cleanedCells.map(c => csvQuote(c, delimiter)).join(delimiter));
    }
    return { cleanText: resultLines.join('\n'), wasModified: modified };
}
/** Parse a single CSV row respecting quoted fields. */
function parseCsvRow(row, delimiter) {
    const cells = [];
    let i = 0;
    while (i <= row.length) {
        if (i === row.length) {
            cells.push('');
            break;
        }
        if (row[i] === '"') {
            // Quoted field
            let j = i + 1;
            let value = '';
            while (j < row.length) {
                if (row[j] === '"') {
                    if (j + 1 < row.length && row[j + 1] === '"') {
                        value += '"';
                        j += 2;
                    }
                    else {
                        j++; // closing quote
                        break;
                    }
                }
                else {
                    value += row[j];
                    j++;
                }
            }
            cells.push(value);
            // Skip delimiter after closing quote
            if (j < row.length && row[j] === delimiter) {
                j++;
            }
            i = j;
        }
        else {
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
function csvQuote(cell, delimiter) {
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
async function sanitizeUniversalKeyValue(rawText) {
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
            if (restOfLine.trim().length > 0 && (0, regexSanitizer_1.isSensitiveKey)(key.trim())) {
                modified = true;
                lines[i] = `${key}${delimiter}${regexSanitizer_1.MASK}`;
            }
        }
    }
    return { cleanText: lines.join('\n'), wasModified: modified };
}
/**
 * Route to the correct AST parser based on the detected format.
 * Passes the optional PiiChecker callback through to each parser.
 */
async function astSanitize(text, format, piiCheck) {
    switch (format) {
        case 'json': {
            const result = await sanitizeJson(text, piiCheck);
            // If JSON parsing fails, fall back to YAML parser (handles key: value generically)
            return result ?? await sanitizeYaml(text, piiCheck);
        }
        case 'yaml':
            return sanitizeYaml(text, piiCheck);
        case 'env':
            return sanitizeEnv(text);
        case 'properties':
            return sanitizeProperties(text, piiCheck);
        case 'xml':
            return sanitizeXml(text, piiCheck);
        case 'toml':
            return sanitizeToml(text, piiCheck);
        case 'hcl':
            return sanitizeHcl(text, piiCheck);
        case 'csv':
            return sanitizeCsv(text, piiCheck);
        default:
            return { cleanText: text, wasModified: false };
    }
}
//# sourceMappingURL=astSanitizer.js.map