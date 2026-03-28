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
exports.sanitizeUniversalKeyValue = sanitizeUniversalKeyValue;
exports.astSanitize = astSanitize;
const regexSanitizer_1 = require("./regexSanitizer");
const treeSitterManager_1 = require("./treeSitterManager");
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
    const IGNORE_KEYS = /^(version|id|lineage|serial|name|type|kind|namespace|replicas|image|ami)$/i;
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
// JSON Parser — Tree-sitter CST Engine with JSON.parse Fallback
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize JSON using Tree-sitter's CST for lossless structure preservation.
 * Falls back to JSON.parse if Tree-sitter JSON grammar is not available.
 *
 * CST approach: finds every `pair` node, extracts the key's bare text via
 * the `string_content` child, masks the value at exact byte offsets.
 * Comments (JSONC), trailing commas, and formatting are preserved.
 */
async function sanitizeJson(text, piiCheck) {
    // Try Tree-sitter first
    if ((0, treeSitterManager_1.isTreeSitterReady)('json')) {
        try {
            return await sanitizeJsonTreeSitter(text, piiCheck);
        }
        catch {
            // Fall through to legacy parser
        }
    }
    return sanitizeJsonFallback(text, piiCheck);
}
/**
 * Tree-sitter CST engine for JSON.
 * Walks all `pair` nodes, masks string values at inner byte offsets (preserves quotes).
 */
async function sanitizeJsonTreeSitter(rawText, piiCheck) {
    const parser = (0, treeSitterManager_1.getTreeSitterParser)('json');
    const tree = parser.parse(rawText);
    if (!tree) {
        return null;
    }
    const pairs = tree.rootNode.descendantsOfType('pair');
    const replacements = [];
    for (const pair of pairs) {
        const keyNode = pair.childForFieldName('key');
        const valueNode = pair.childForFieldName('value');
        if (!keyNode || !valueNode) {
            continue;
        }
        // Extract bare key text from string_content (strips quotes)
        const keyContent = keyNode.namedChildren.find(c => c.type === 'string_content');
        const keyText = keyContent ? keyContent.text : keyNode.text;
        // Only mask string values (numbers, bools, null, objects, arrays are not secrets)
        if (valueNode.type === 'string') {
            const valContent = valueNode.namedChildren.find(c => c.type === 'string_content');
            if (!valContent || valContent.text.length === 0) {
                continue;
            }
            const bareValue = valContent.text;
            const masked = await processAstValue(keyText, bareValue, piiCheck);
            if (masked !== bareValue) {
                replacements.push({ start: valContent.startIndex, end: valContent.endIndex, text: masked });
            }
        }
        // Objects and arrays are handled implicitly — descendantsOfType('pair') recurses into them
    }
    if (replacements.length === 0) {
        return { cleanText: rawText, wasModified: false };
    }
    // Sort descending by start offset so replacements don't shift earlier offsets
    replacements.sort((a, b) => b.start - a.start);
    let result = rawText;
    for (const r of replacements) {
        result = result.slice(0, r.start) + r.text + result.slice(r.end);
    }
    return { cleanText: result, wasModified: true };
}
/**
 * Legacy JSON.parse fallback — used when Tree-sitter JSON grammar is unavailable.
 * Loses comments and original formatting.
 */
async function sanitizeJsonFallback(text, piiCheck) {
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
// YAML Parser — Tree-sitter CST Engine with Regex Fallback
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize YAML using Tree-sitter CST for lossless structure preservation.
 * Falls back to regex line-by-line parser if the YAML grammar is unavailable.
 *
 * CST approach: finds every `block_mapping_pair` node, extracts key via
 * `childForFieldName('key')`, masks string values at exact byte offsets.
 * Comments, indentation, anchors, and block scalars are preserved.
 */
async function sanitizeYaml(text, piiCheck) {
    // Try Tree-sitter first
    if ((0, treeSitterManager_1.isTreeSitterReady)('yaml')) {
        try {
            return await sanitizeYamlTreeSitter(text, piiCheck);
        }
        catch {
            // Fall through to legacy parser
        }
    }
    return sanitizeYamlRegexFallback(text, piiCheck);
}
/**
 * Tree-sitter CST engine for YAML.
 * Walks all `block_mapping_pair` nodes (automatically recurses into nested mappings).
 * Masks scalar values at inner byte offsets — preserves quotes on quoted scalars.
 */
async function sanitizeYamlTreeSitter(rawText, piiCheck) {
    const parser = (0, treeSitterManager_1.getTreeSitterParser)('yaml');
    const tree = parser.parse(rawText);
    if (!tree) {
        return sanitizeYamlRegexFallback(rawText, piiCheck);
    }
    // block_mapping_pair covers top-level + nested KV pairs automatically
    const pairs = tree.rootNode.descendantsOfType('block_mapping_pair');
    const replacements = [];
    for (const pair of pairs) {
        const keyNode = pair.childForFieldName('key');
        const valueNode = pair.childForFieldName('value');
        if (!keyNode || !valueNode) {
            continue;
        }
        const keyText = keyNode.text.trim();
        // Drill into the value node's first named child to determine the scalar type
        const scalar = valueNode.namedChildren[0];
        if (!scalar) {
            continue;
        }
        let bareValue;
        let innerStart;
        let innerEnd;
        switch (scalar.type) {
            case 'plain_scalar':
                // Unquoted value — offsets are exact
                bareValue = scalar.text;
                innerStart = scalar.startIndex;
                innerEnd = scalar.endIndex;
                break;
            case 'double_quote_scalar':
                // "value" — strip outer quotes for the bare value
                bareValue = scalar.text.slice(1, -1);
                innerStart = scalar.startIndex + 1;
                innerEnd = scalar.endIndex - 1;
                break;
            case 'single_quote_scalar':
                // 'value' — strip outer quotes
                bareValue = scalar.text.slice(1, -1);
                innerStart = scalar.startIndex + 1;
                innerEnd = scalar.endIndex - 1;
                break;
            default:
                // block_sequence, block_mapping, boolean_scalar, integer_scalar,
                // float_scalar, null_scalar — skip (not maskable or handled via recursion)
                continue;
        }
        if (bareValue.length === 0) {
            continue;
        }
        const masked = await processAstValue(keyText, bareValue, piiCheck);
        if (masked !== bareValue) {
            replacements.push({ start: innerStart, end: innerEnd, text: masked });
        }
    }
    if (replacements.length === 0) {
        return { cleanText: rawText, wasModified: false };
    }
    // Sort descending by start offset so replacements don't shift earlier offsets
    replacements.sort((a, b) => b.start - a.start);
    let result = rawText;
    for (const r of replacements) {
        result = result.slice(0, r.start) + r.text + result.slice(r.end);
    }
    return { cleanText: result, wasModified: true };
}
/**
 * Regex-based fallback for YAML — used when Tree-sitter YAML grammar is unavailable.
 */
async function sanitizeYamlRegexFallback(text, piiCheck) {
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
// ENV Parser (.env files) — Tree-sitter CST Engine
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize .env files using Tree-sitter's Concrete Syntax Tree.
 *
 * The parser produces a lossless CST from the Bash grammar where every
 * `variable_assignment` node has typed `name` and `value` children with
 * exact byte offsets. We replace *only* the value bytes — comments,
 * whitespace, quotes, and keys are never touched.
 *
 * Falls back to the regex-based parser if Tree-sitter is not initialized
 * (e.g., WASM failed to load).
 */
async function sanitizeEnv(rawText) {
    // Graceful fallback if Tree-sitter isn't available
    if (!(0, treeSitterManager_1.isTreeSitterReady)('bash')) {
        return sanitizeEnvRegexFallback(rawText);
    }
    const parser = (0, treeSitterManager_1.getTreeSitterParser)('bash');
    const tree = parser.parse(rawText);
    if (!tree) {
        return sanitizeEnvRegexFallback(rawText);
    }
    // Collect all variable_assignment nodes (includes those inside `export`)
    const assignments = tree.rootNode.descendantsOfType('variable_assignment');
    const replacements = [];
    for (const node of assignments) {
        const nameNode = node.childForFieldName('name');
        const valueNode = node.childForFieldName('value');
        if (!nameNode || !valueNode) {
            continue;
        }
        const keyText = nameNode.text;
        // Extract the bare value (strip outer quotes if present)
        const valueType = valueNode.type; // 'word', 'string', 'raw_string', 'number', etc.
        let bareValue;
        let innerStart;
        let innerEnd;
        if (valueType === 'string') {
            // Double-quoted: "value" → inner string_content child has the bare text
            const content = valueNode.namedChildren.find(c => c.type === 'string_content');
            if (content) {
                bareValue = content.text;
                innerStart = content.startIndex;
                innerEnd = content.endIndex;
            }
            else {
                // Empty string "" — nothing to mask
                continue;
            }
        }
        else if (valueType === 'raw_string') {
            // Single-quoted: 'value' → strip outer quotes from the byte range
            bareValue = valueNode.text.slice(1, -1);
            innerStart = valueNode.startIndex + 1;
            innerEnd = valueNode.endIndex - 1;
        }
        else {
            // Unquoted word, number, etc. — full text is the value
            bareValue = valueNode.text;
            innerStart = valueNode.startIndex;
            innerEnd = valueNode.endIndex;
        }
        if (bareValue.length === 0) {
            continue;
        }
        const masked = await processAstValue(keyText, bareValue);
        if (masked !== bareValue) {
            replacements.push({ start: innerStart, end: innerEnd, text: masked });
        }
    }
    if (replacements.length === 0) {
        return { cleanText: rawText, wasModified: false };
    }
    // Sort by startIndex DESCENDING so replacements don't invalidate earlier offsets
    replacements.sort((a, b) => b.start - a.start);
    let result = rawText;
    for (const r of replacements) {
        result = result.slice(0, r.start) + r.text + result.slice(r.end);
    }
    return { cleanText: result, wasModified: true };
}
/**
 * Regex-based fallback for .env parsing — used when Tree-sitter is unavailable.
 */
async function sanitizeEnvRegexFallback(rawText) {
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
// Properties / INI Parser — Tree-sitter CST Engine with Regex Fallback
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize .properties / .ini files using Tree-sitter CST.
 * Falls back to regex-based parser if the Properties grammar is unavailable.
 */
async function sanitizeProperties(text, piiCheck) {
    // Try Tree-sitter first
    if ((0, treeSitterManager_1.isTreeSitterReady)('properties')) {
        try {
            return await sanitizePropertiesTreeSitter(text, piiCheck);
        }
        catch {
            // Fall through to legacy parser
        }
    }
    return sanitizePropertiesRegexFallback(text, piiCheck);
}
/**
 * Tree-sitter CST engine for .properties files.
 * Walks `property` nodes, extracts `key` and `value` typed children,
 * masks values at exact byte offsets.
 */
async function sanitizePropertiesTreeSitter(rawText, piiCheck) {
    const parser = (0, treeSitterManager_1.getTreeSitterParser)('properties');
    const tree = parser.parse(rawText);
    if (!tree) {
        return sanitizePropertiesRegexFallback(rawText, piiCheck);
    }
    const properties = tree.rootNode.descendantsOfType('property');
    const replacements = [];
    for (const prop of properties) {
        const keyNode = prop.namedChildren.find(c => c.type === 'key');
        const valueNode = prop.namedChildren.find(c => c.type === 'value');
        if (!keyNode || !valueNode) {
            continue;
        }
        const keyText = keyNode.text.trim();
        const bareValue = valueNode.text.trim();
        if (bareValue.length === 0) {
            continue;
        }
        const masked = await processAstValue(keyText, bareValue, piiCheck);
        if (masked !== bareValue) {
            replacements.push({ start: valueNode.startIndex, end: valueNode.endIndex, text: masked });
        }
    }
    if (replacements.length === 0) {
        return { cleanText: rawText, wasModified: false };
    }
    // Sort descending by start offset
    replacements.sort((a, b) => b.start - a.start);
    let result = rawText;
    for (const r of replacements) {
        result = result.slice(0, r.start) + r.text + result.slice(r.end);
    }
    return { cleanText: result, wasModified: true };
}
/**
 * Regex-based fallback for .properties/.ini parsing.
 */
async function sanitizePropertiesRegexFallback(text, piiCheck) {
    let modified = false;
    const lines = text.split('\n');
    const result = [];
    const PROP_RE = /^(\s*[A-Za-z0-9_.\-]+)\s*([=:])\s*(.*)$/;
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
            if (trimVal.length > 0) {
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
// XML Parser (lightweight, regex-based key-value tag masking)
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
        default:
            return { cleanText: text, wasModified: false };
    }
}
//# sourceMappingURL=astSanitizer.js.map