const { Parser, Language } = require('web-tree-sitter');
(async () => {
  await Parser.init();
  const Lang = await Language.load('./wasm/tree-sitter-bash.wasm');
  const p = new Parser();
  p.setLanguage(Lang);
  
  const testEnv = [
    '# Database Config',
    'DB_HOST=localhost',
    'DB_PASSWORD="super_secret_123"',
    "export API_KEY='ghp_abcdef1234567890abcdef1234567890ab'",
    'PORT=5432',
    'EMPTY_VAR=',
    'MULTI_WORD="hello world"  # inline comment',
  ].join('\n');
  
  const tree = p.parse(testEnv);
  
  function printTree(node, depth) {
    depth = depth || 0;
    var indent = '  '.repeat(depth);
    var text = node.text.length > 60 ? node.text.slice(0, 60) + '...' : node.text;
    console.log(indent + node.type + ' [' + node.startIndex + '-' + node.endIndex + '] ' + JSON.stringify(text));
    for (var i = 0; i < node.childCount; i++) {
      printTree(node.child(i), depth + 1);
    }
  }
  printTree(tree.rootNode);
  
  // Also test descendantsOfType
  console.log('\n--- variable_assignment nodes ---');
  var assignments = tree.rootNode.descendantsOfType('variable_assignment');
  assignments.forEach(function(a) {
    var nameNode = a.childForFieldName('name');
    var valueNode = a.childForFieldName('value');
    console.log('Key:', nameNode ? nameNode.text : 'N/A',
                '| Value:', valueNode ? valueNode.text : 'N/A',
                '| Value startIndex:', valueNode ? valueNode.startIndex : 'N/A',
                '| Value endIndex:', valueNode ? valueNode.endIndex : 'N/A');
  });
})();
