const { Parser, Language } = require('web-tree-sitter');

async function main() {
  await Parser.init();
  const parser = new Parser();

  // Load YAML grammar
  let yamlLang;
  try {
    yamlLang = await Language.load('./wasm/tree-sitter-yaml.wasm');
    console.log('✅ YAML WASM loaded successfully!');
  } catch (e) {
    console.log('❌ YAML WASM load failed:', e.message);
    return;
  }
  parser.setLanguage(yamlLang);

  // Test 1: Simple key-value pairs
  const yaml1 = `
name: John Doe
age: 30
password: s3cret123
database_url: "postgresql://user:pass@host/db"
debug: true
items:
  - one
  - two
nested:
  api_key: "abc-123-def"
  host: localhost
  port: 8080
# This is a comment
description: "A simple test"
`.trim();

  console.log('\n=== Test 1: YAML Key-Value Pairs ===');
  const tree1 = parser.parse(yaml1);
  console.log('Root type:', tree1.rootNode.type);
  console.log('Root children count:', tree1.rootNode.namedChildCount);

  // Print all node types at first level
  console.log('\n--- First level named children ---');
  for (const child of tree1.rootNode.namedChildren) {
    console.log(`  type: ${child.type}, text: "${child.text.substring(0, 60)}..."`);
  }

  // Look for block_mapping_pair nodes (these are key-value pairs in YAML)
  const allNodeTypes = new Set();
  function collectTypes(node) {
    allNodeTypes.add(node.type);
    for (let i = 0; i < node.namedChildCount; i++) {
      collectTypes(node.namedChild(i));
    }
  }
  collectTypes(tree1.rootNode);
  console.log('\n--- All node types in tree ---');
  console.log([...allNodeTypes].sort().join(', '));

  // Find key-value pair nodes
  const pairTypes = ['block_mapping_pair', 'flow_pair', 'pair'];
  for (const pairType of pairTypes) {
    const pairs = tree1.rootNode.descendantsOfType(pairType);
    if (pairs.length > 0) {
      console.log(`\n--- Found ${pairs.length} "${pairType}" nodes ---`);
      for (const pair of pairs) {
        console.log(`  pair text: "${pair.text.substring(0, 80)}"`);
        console.log(`    child count: ${pair.childCount}, named: ${pair.namedChildCount}`);

        // Try field names
        const keyField = pair.childForFieldName('key');
        const valueField = pair.childForFieldName('value');
        console.log(`    key (field): ${keyField ? `type="${keyField.type}" text="${keyField.text}"` : 'null'}`);
        console.log(`    value (field): ${valueField ? `type="${valueField.type}" text="${valueField.text.substring(0, 60)}"` : 'null'}`);

        // Try named children
        for (const c of pair.namedChildren) {
          console.log(`    namedChild: type="${c.type}" text="${c.text.substring(0, 60)}" startIndex=${c.startIndex} endIndex=${c.endIndex}`);
        }

        // For value nodes, check their children
        if (valueField) {
          console.log(`    value children:`);
          for (const vc of valueField.namedChildren) {
            console.log(`      type="${vc.type}" text="${vc.text.substring(0, 60)}" start=${vc.startIndex} end=${vc.endIndex}`);
          }
        }
      }
    }
  }

  // Test 2: Check specific value types and offsets
  console.log('\n\n=== Test 2: Value Offset Precision ===');
  const yaml2 = `password: s3cret123
api_key: "abc-123"
token: 'tok-456'`;

  const tree2 = parser.parse(yaml2);
  for (const pairType of [...pairTypes]) {
    const pairs = tree2.rootNode.descendantsOfType(pairType);
    if (pairs.length > 0) {
      console.log(`\nUsing "${pairType}" nodes:`);
      for (const pair of pairs) {
        const k = pair.childForFieldName('key');
        const v = pair.childForFieldName('value');
        if (k && v) {
          console.log(`  key="${k.text}" (type=${k.type})`);
          console.log(`  value="${v.text}" (type=${v.type}) startIndex=${v.startIndex} endIndex=${v.endIndex}`);

          // Check for inner content for quoted strings
          if (v.type === 'flow_node' || v.type === 'plain_scalar' || v.type === 'double_quote_scalar' || v.type === 'single_quote_scalar') {
            console.log(`    value namedChildren:`);
            for (const vc of v.namedChildren) {
              console.log(`      type="${vc.type}" text="${vc.text}" start=${vc.startIndex} end=${vc.endIndex}`);
            }
          }

          // For double/single quote, verify byte offsets exclude quotes
          const rawSlice = yaml2.slice(v.startIndex, v.endIndex);
          console.log(`    raw slice from offsets: "${rawSlice}"`);
        }
      }
    }
  }
}

main().catch(console.error);
