"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HIGH_CONFIDENCE_SECRETS = exports.MASK = void 0;
exports.regexSanitize = regexSanitize;
/**
 * Minimalist Pure Proxy Sanitizer
 */
exports.MASK = '[MASKED_BY_SAFECHAT]';
const MAX_BUDGET_BYTES = 250_000;
exports.HIGH_CONFIDENCE_SECRETS = [
    // ── Cloud & CI/CD ─────────────────────────────────────────────────────
    { name: 'AWS Access Key', regex: /\b(AKIA[0-9A-Z]{16})\b/g },
    { name: 'GCP Service Account', regex: /"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:\s*"(-----BEGIN PRIVATE KEY[\s\S]*?-----END PRIVATE KEY-----\\n)"/g },
    { name: 'Azure Shared Key', regex: /\bAccountKey=([A-Za-z0-9+/]{86}==)\b/g },
    { name: 'GitHub Token', regex: /\b(gh[pousr]_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})\b/g },
    { name: 'GitLab Token', regex: /\b(glpat-[A-Za-z0-9_\-]{20})\b/g },
    { name: 'Jenkins Token', regex: /\b(11[a-f0-9]{32})\b/g },
    { name: 'Harness Token', regex: /\b(?:pat|sat)\.[A-Za-z0-9_-]{20,}\.([A-Za-z0-9_-]{20,})\b/g },
    { name: 'OpenShift Token', regex: /\b(sha256~[A-Za-z0-9_\-]{43})\b/g },
    { name: 'LambdaTest/SauceLabs', regex: /(?:https?:\/\/)[a-zA-Z0-9_.-]+:([a-zA-Z0-9]{32,64})@hub\.(?:lambdatest|saucelabs)\.com/g },
    // ── APIs & Comms ──────────────────────────────────────────────────────
    { name: 'Slack Token', regex: /\b(xox[bpas]-[0-9A-Za-z\-]+)\b/g },
    { name: 'Stripe Key', regex: /\b([spr]k_(?:live|test)_[A-Za-z0-9]{24,})\b/g },
    { name: 'SendGrid Key', regex: /\b(SG\.[A-Za-z0-9\-_]{16,32}\.[A-Za-z0-9\-_]{32,64})\b/g },
    { name: 'NPM Token', regex: /\b(npm_[a-zA-Z0-9]{36})\b/g },
    { name: 'HashiCorp Vault Token', regex: /\b((?:hvs|hvb|hvr|s)\.[A-Za-z0-9_\-]{24,120})\b/g },
    { name: 'SonarQube Token', regex: /\b(sq[pua]_[A-Za-z0-9]{40})\b/g },
    { name: 'Terraform Cloud Token', regex: /\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67})\b/g },
    { name: 'Bitbucket Token', regex: /\b(ATBB[A-Za-z0-9]{28}|ATCTT[A-Za-z0-9]{171,})\b/g },
    // ── Cryptographic Material ────────────────────────────────────────────
    { name: 'RSA/PEM Private Key', regex: /(-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----)/g },
    { name: 'JWT Token', regex: /\b(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)\b/g },
    // ── Generic URLs ─────────────────────────────────────
    { name: 'URL Query Parameter Secret', regex: /(?:password|passwd|secret|token|api_?key|auth)=([^&\s"']+)/gi },
    { name: 'Credential URL', regex: /\b([a-zA-Z0-9+.-]+:\/\/)([^@\s]+)(@[a-zA-Z0-9.-]+(?::[\d]+)?(?:\/[^\s"']*)?)/gi, isUrlAuth: true },
    // ── Keyless Credential Files ──────────────────────────────────────────────
    { name: 'Netrc Password', regex: /(?:password|passwd)\s+([^\s]+)/gi },
    { name: 'Pgpass Password', regex: /^(?:[^:\r\n]+:){4}([^:\r\n]+)$/gm },
    // ── Standard PII Fallback ──────
    { name: 'US SSN', regex: /\b(\d{3}-\d{2}-\d{4})\b/g },
    { name: 'Credit Card Number', regex: /\b(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7})\b/g },
    { name: 'IBAN Code', regex: /\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b/g },
    { name: 'IPv4 Address', regex: /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g },
    { name: 'Internal Hostname', regex: /\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*\.(?:internal|local|private)\b/gi },
    { name: 'MAC Address', regex: /(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}/g },
    { name: 'Certificate Thumbprint', regex: /(?:[0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}/g },
    { name: 'Email Address', regex: /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g },
    { name: 'Phone Number Fallback', regex: /(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g },
];
function regexSanitize(text) {
    let wasModified = false;
    let current = text;
    if (Buffer.byteLength(current, 'utf-8') > MAX_BUDGET_BYTES) {
        const bytes = Buffer.from(current, 'utf-8');
        const safeSubsetStr = bytes.subarray(0, MAX_BUDGET_BYTES).toString('utf-8');
        const lastNewline = safeSubsetStr.lastIndexOf('\n');
        let safeCut = safeSubsetStr.length;
        if (lastNewline > 0) {
            safeCut = lastNewline;
        }
        current = safeSubsetStr.slice(0, safeCut) + `\n\n[... TRUNCATED: payload exceeded 250KB budget ...]`;
        wasModified = true;
    }
    for (const pattern of exports.HIGH_CONFIDENCE_SECRETS) {
        if (pattern.isUrlAuth) {
            if (current.match(pattern.regex)) {
                current = current.replace(pattern.regex, `$1${exports.MASK}$3`);
                wasModified = true;
            }
        }
        else {
            if (current.match(pattern.regex)) {
                current = current.replace(pattern.regex, (full, captured) => {
                    wasModified = true;
                    if (captured !== undefined) {
                        return full.replace(captured, exports.MASK);
                    }
                    return exports.MASK;
                });
            }
        }
    }
    return { cleanText: current, wasModified };
}
//# sourceMappingURL=sanitizer.js.map