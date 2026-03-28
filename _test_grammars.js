const { Parser, Language } = require('web-tree-sitter');

(async () => {
  await Parser.init();

  // Test JSON
  console.log('=== JSON Grammar ===');
  const jsonLang = await Language.load('./wasm/tree-sitter-json.wasm');
  const jsonParser = new Parser();
  jsonParser.setLanguage(jsonLang);
  const jsonTree = jsonParser.parse('{"password":"secret123","host":"localhost","nested":{"api_key":"abc"}}');
  printTree(jsonTree.rootNode);

  console.log('\n--- JSON pair nodes ---');
  const pairs = jsonTree.rootNode.descendantsOfType('pair');
  for (const pair of pairs) {
    const keyNode = pair.childForFieldName('key');
    const valNode = pair.childForFieldName('value');
    console.log('Key:', keyNode ? keyNode.text : 'N/A',
                '| Value:', valNode ? valNode.text : 'N/A',
                '| Type:', valNode ? valNode.type : 'N/A',
                '| Start:', valNode ? valNode.startIndex : 'N/A',
                '| End:', valNode ? valNode.endIndex : 'N/A');
  }

  // Test Properties
  console.log('\n=== Properties Grammar ===');
  const propLang = await Language.load('./wasm/tree-sitter-properties.wasm');
  const propParser = new Parser();
  propParser.setLanguage(propLang);
  const propTree = propParser.parse('# Comment\ndb.password=secret123\ndb.host=localhost\napi_key : mykey');
  printTree(propTree.rootNode);

  console.log('\n--- Properties pair/property nodes ---');
  // Try different node type names
  for (const typeName of ['pair', 'property', 'assignment', 'entry']) {
    const nodes = propTree.rootNode.descendantsOfType(typeName);
    if (nodes.length > 0) {
      console.log('Found', nodes.length, typeName, 'nodes');
      for (const n of nodes) {
        const k = n.childForFieldName('key') || n.childForFieldName('name');
        const v = n.childForFieldName('value');
        console.log('  Key:', k ? k.text : 'N/A',
                    '| Value:', v ? v.text : 'N/A',
                    '| Start:', v ? v.startIndex : 'N/A',
                    '| End:', v ? v.endIndex : 'N/A');
      }
    }
  }
  // Also dump all named child types at root level
  console.log('\nAll root named child types:');
  for (let i = 0; i < propTree.rootNode.namedChildCount; i++) {
    const c = propTree.rootNode.namedChild(i);
    console.log('  ', c.type, '|', JSON.stringify(c.text.slice(0, 60)));
  }

  // Test YAML (may fail if WASM is corrupt)
  console.log('\n=== YAML Grammar ===');
  try {
    const yamlLang = await Language.load('./wasm/tree-sitter-yaml.wasm');
    const yamlParser = new Parser();
    yamlParser.setLanguage(yamlLang);
    const yamlTree = yamlParser.parse('password: secret123\nhost: localhost\nnested:\n  api_key: mykey');
    printTree(yamlTree.rootNode);

    console.log('\n--- YAML mapping_pair / block_mapping_pair nodes ---');
    for (const typeName of ['block_mapping_pair', 'mapping_pair', 'pair']) {
      const nodes = yamlTree.rootNode.descendantsOfType(typeName);
      if (nodes.length > 0) {
        console.log('Found', nodes.length, typeName, 'nodes');
        for (const n of nodes) {
          const k = n.childForFieldName('key');
          const v = n.childForFieldName('value');
          console.log('  Key:', k ? k.text : 'N/A',
                      '| Value:', v ? v.text : 'N/A',  
                      '| Type:', v ? v.type : 'N/A',
                      '| Start:', v ? v.startIndex : 'N/A',
                      '| End:', v ? v.endIndex : 'N/A');
        }
      }
    }
  } catch (err) {
    console.log('YAML WASM failed:', err.message);
  }
})();

function printTree(node, depth) {
  depth = depth || 0;
  var indent = '  '.repeat(depth);
  var text = node.text.length > 60 ? node.text.slice(0, 60) + '...' : node.text;
  console.log(indent + node.type + ' [' + node.startIndex + '-' + node.endIndex + '] ' + JSON.stringify(text));
  for (var i = 0; i < node.childCount; i++) {
    printTree(node.child(i), depth + 1);
  }
}
