/**
 * Comprehensive fixture test — runs ALL 49 original files through the 
 * correct pipeline (AST format from router + regex safety net) and 
 * checks for common sensitive data leaks.
 */
const { astSanitize } = require('../out/astSanitizer');
const { regexSanitize } = require('../out/regexSanitizer');
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, '../latest');

// Map file extensions to AST formats (mirrors router.ts AST_FORMAT_MAP)
const AST_FORMAT_MAP = {
  '.json': 'json', '.jsonc': 'jsonc', '.jsonl': 'jsonl', '.tfstate': 'json',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.env': 'env',
  '.properties': 'properties', '.ini': 'properties', '.cfg': 'properties',
  '.npmrc': 'properties', '.netrc': 'properties', '.pgpass': 'properties',
  '.gemrc': 'properties', '.yarnrc': 'properties',
  '.conf': 'properties', '.config': 'properties',
  '.secret': 'properties',
  '.toml': 'toml',
  '.xml': 'xml', '.csproj': 'xml', '.props': 'xml', '.targets': 'xml',
  '.nuspec': 'xml', '.xsd': 'xml', '.wsdl': 'xml',
  '.pem': 'env', '.key': 'env', '.cert': 'env', '.crt': 'env',
  '.pub': 'env', '.ppk': 'env', '.cer': 'env', '.asc': 'env',
  '.tf': 'hcl', '.tfvars': 'hcl', '.hcl': 'hcl', '.terraformrc': 'hcl',
  '.csv': 'csv', '.tsv': 'tsv',
  '.sh': 'env', '.bash': 'env', '.bat': 'env', '.cmd': 'env',
  '.ps1': 'env', '.psm1': 'env',
  '.gradle': 'properties', '.kts': 'properties',
  '.gql': 'env', '.graphql': 'env',
  '.sql': 'env', '.txt': undefined,
};

function getFormat(filename) {
  const ext = '.' + filename.split('.').pop();
  return AST_FORMAT_MAP[ext];
}

// Sensitive values to look for across ALL fixture files
const COMMON_LEAKS = [
  // Passwords & tokens
  { label: 'password Sup3rS3cr3t', val: 'Sup3rS3cr3t' },
  { label: 'password r3d1sPassw0rd', val: 'r3d1sPassw0rd' },
  { label: 'password mongoSecret', val: 'mongoSecret' },
  { label: 'GitHub token ghp_', val: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ' },
  { label: 'Vault token hvs.', val: 'hvs.CAESIABC' },
  { label: 'Stripe key sk_live', val: 'sk_live_' },
  { label: 'SendGrid SG.', val: 'SG.' },
  { label: 'AWS AKIA', val: 'AKIAIOSFODNN7EXAMPLE' },
  // Phones
  { label: 'phone +1-555-867-5309', val: '+1-555-867-5309' },
  { label: 'phone (415) 555-0192', val: '(415) 555-0192' },
  { label: 'phone +1-555-123-4567', val: '+1-555-123-4567' },
  // IPs
  { label: 'IP 10.240.0.15', val: '10.240.0.15' },
  { label: 'IP 192.168.1.100', val: '192.168.1.100' },
  { label: 'IP 10.240.0.25', val: '10.240.0.25' },
  { label: 'IP 10.240.0.20', val: '10.240.0.20' },
  { label: 'IP 10.240.0.30', val: '10.240.0.30' },
  // Internal hostnames
  { label: 'host db.prod.internal', val: 'db.prod.internal' },
  { label: 'host cache.prod.internal', val: 'cache.prod.internal' },
  { label: 'host payments-api.corp.internal', val: 'payments-api.corp.internal' },
  { label: 'host prod-db.corp.internal', val: 'prod-db.corp.internal' },
  { label: 'host payments-db-primary.prod.internal', val: 'payments-db-primary.prod.internal' },
  { label: 'host registry.corp.internal', val: 'registry.corp.internal' },
  { label: 'host consul.prod.internal', val: 'consul.prod.internal' },
  // Email
  { label: 'email devops@securecorp', val: 'devops@securecorp.com' },
  { label: 'email alice.johnson@securecorp', val: 'alice.johnson@securecorp.com' },
  { label: 'email john.smith@testcorp', val: 'john.smith@testcorp.com' },
  // MAC
  { label: 'MAC 00:1A:2B:3C:4D:5E', val: '00:1A:2B:3C:4D:5E' },
];

async function fullPipeline(text, format) {
  let current = text;
  let modified = false;

  // AST pass (if applicable)
  if (format) {
    try {
      const astResult = await astSanitize(current, format);
      current = astResult.cleanText;
      if (astResult.wasModified) modified = true;
    } catch (e) {
      // AST parse failure — skip to regex
    }
  }

  // Regex safety net (always runs for ast files; only pass for non-ast)
  const regResult = regexSanitize(current);
  current = regResult.cleanText;
  if (regResult.wasModified) modified = true;

  return { cleanText: current, wasModified: modified };
}

async function run() {
  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith('.original.txt'))
    .sort();

  const fileResults = [];

  for (const origFile of files) {
    const maskedFile = origFile.replace('.original.txt', '.masked.txt');
    const origText = fs.readFileSync(path.join(dir, origFile), 'utf8');
    
    // Extract the actual filename from the path-encoded name
    const parts = origFile.replace('.original.txt', '').split('_');
    const actualFilename = parts[parts.length - 1]; // e.g., "sample.sh", "sample.tfstate"
    
    // Find extension for format detection - handle compound extensions
    const nameAfterSamples = origFile.replace('.original.txt', '').split('file_samples_')[1];
    const actualFile = nameAfterSamples || actualFilename;
    let ext;
    // Handle cases like kubernetes_secret.yaml, sample_config.json
    const extMatch = actualFile.match(/\.([a-z0-9]+)$/i);
    ext = extMatch ? '.' + extMatch[1] : undefined;
    
    const format = ext ? AST_FORMAT_MAP[ext] : undefined;

    // Run through our pipeline
    const result = await fullPipeline(origText, format);

    // Check for leaks
    const leaks = [];
    for (const check of COMMON_LEAKS) {
      if (origText.includes(check.val) && result.cleanText.includes(check.val)) {
        leaks.push(check.label);
      }
    }

    const shortName = actualFile || origFile.substring(0, 40);
    fileResults.push({ shortName, ext, format, modified: result.wasModified, leaks });
  }

  // Print results
  console.log('\n=== COMPREHENSIVE FIXTURE MASKING AUDIT ===\n');
  
  let totalPass = 0, totalFail = 0;
  const allLeaks = new Map(); // leak label → count

  for (const r of fileResults) {
    if (r.leaks.length === 0) {
      totalPass++;
      console.log(`PASS | ${r.shortName} (${r.format || 'regex-only'})`);
    } else {
      totalFail++;
      console.log(`FAIL | ${r.shortName} (${r.format || 'regex-only'}) | LEAKED: ${r.leaks.join(', ')}`);
      for (const l of r.leaks) {
        allLeaks.set(l, (allLeaks.get(l) || 0) + 1);
      }
    }
  }

  console.log(`\n--- SUMMARY ---`);
  console.log(`Total: ${totalPass} PASS, ${totalFail} FAIL out of ${fileResults.length}`);
  
  if (allLeaks.size > 0) {
    console.log(`\n--- LEAK FREQUENCY ---`);
    const sorted = [...allLeaks.entries()].sort((a, b) => b[1] - a[1]);
    for (const [label, count] of sorted) {
      console.log(`  ${count}x | ${label}`);
    }
  }
}

run().catch(err => console.error('ERROR:', err));
