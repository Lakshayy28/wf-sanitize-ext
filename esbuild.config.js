/**
 * esbuild.config.js — Bundles the extension + all npm dependencies into a
 * single out/extension.js so the VSIX is self-contained (no node_modules needed).
 *
 * Node built-ins and the 'vscode' host module are marked external because they
 * are provided by the VS Code runtime, not by npm.
 *
 * web-tree-sitter is bundled (its JS is inlined). The WASM files it needs are
 * already copied to grammars/ and loaded at runtime via locateFile().
 */

const esbuild = require('esbuild');

const isProduction = process.argv.includes('--production');
const isWatch      = process.argv.includes('--watch');

/** @type {import('esbuild').BuildOptions} */
const buildOptions = {
  entryPoints: ['./src/extension.ts'],
  bundle:      true,
  outfile:     './out/extension.js',
  external: [
    // VS Code host API — never bundle
    'vscode',
    // Node.js built-ins — always available in the extension host
    'fs', 'path', 'os', 'child_process', 'crypto', 'util', 'stream',
    'events', 'assert', 'buffer', 'url', 'http', 'https', 'net', 'tls',
    'zlib', 'readline', 'worker_threads',
  ],
  platform:    'node',
  format:      'cjs',
  target:      'node18',
  sourcemap:   !isProduction,
  minify:      isProduction,
  // Silence the "require is not statically analyzable" warning from web-tree-sitter
  logOverride: { 'ignored-bare-import': 'silent' },
};

if (isWatch) {
  esbuild.context(buildOptions).then(ctx => {
    ctx.watch();
    console.log('[esbuild] Watching for changes…');
  });
} else {
  esbuild.build(buildOptions).then(() => {
    console.log(`[esbuild] Build complete (${isProduction ? 'production' : 'development'})`);
  }).catch(err => {
    console.error(err);
    process.exit(1);
  });
}
