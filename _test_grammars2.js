const { Parser, Language } = require('web-tree-sitter');

(async () => {
  await Parser.init();

  // Test JSON with different value types
  console.log('=== JSON Grammar ===');
  const jsonLang = await Language.load('./wasm/tree-sitter-json.wasm');
  const jsonParser = new Parser();
  jsonParser.setLanguage(jsonLang);
  
  var jsonText = '{\n  "password": "secret123",\n  "count": 42,\n  "active": true,\n  "data": null,\n  "nested": {\n    "api_key": "abc"\n  }\n}';
  var jsonTree = jsonParser.parse(jsonText);
  
  var pairs = jsonTree.rootNode.descendantsOfType('pair');
  for (var pair of pairs) {
    var k = pair.childForFieldName('key');
    var v = pair.childForFieldName('value');
    var keyBare = '';
    if (k && k.type === 'string') {
      var kcontent = k.namedChildren.find(function(c) { return c.type === 'string_content'; });
      keyBare = kcontent ? kcontent.text : '';
    }
    var valInfo = '';
    if (v && v.type === 'string') {
      var vcontent = v.namedChildren.find(function(c) { return c.type === 'string_content'; });
      valInfo = vcontent ? 'bare=' + vcontent.text + ' innerStart=' + vcontent.startIndex + ' innerEnd=' + vcontent.endIndex : 'empty_string';
    }
    console.log('Key:', keyBare, '| valType:', v ? v.type : 'N/A', '| fullStart:', v ? v.startIndex : 'N/A', '| fullEnd:', v ? v.endIndex : 'N/A', '|', valInfo);
  }

  // Test Properties
  console.log('\n=== Properties Grammar ===');
  const propLang = await Language.load('./wasm/tree-sitter-properties.wasm');
  const propParser = new Parser();
  propParser.setLanguage(propLang);
  
  var propText = '# Comment\ndb.password=secret123\ndb.host = localhost\napi_key : mykey';
  var propTree = propParser.parse(propText);

  var props = propTree.rootNode.descendantsOfType('property');
  for (var prop of props) {
    var keyNode = prop.namedChildren.find(function(c) { return c.type === 'key'; });
    var valNode = prop.namedChildren.find(function(c) { return c.type === 'value'; });
    console.log('Key:', keyNode ? keyNode.text : 'N/A',
                '| Value:', valNode ? valNode.text : 'N/A',
                '| Start:', valNode ? valNode.startIndex : 'N/A',
                '| End:', valNode ? valNode.endIndex : 'N/A');
  }

  // Test YAML
  console.log('\n=== YAML Grammar ===');
  try {
    const yamlLang = await Language.load('./wasm/tree-sitter-yaml.wasm');
    const yamlParser = new Parser();
    yamlParser.setLanguage(yamlLang);
    var yamlText = 'password: secret123\nhost: localhost';
    var yamlTree = yamlParser.parse(yamlText);
    console.log('YAML parsing succeeded');
    printTree(yamlTree.rootNode);
  } catch(err) {
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
