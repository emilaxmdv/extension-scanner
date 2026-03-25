import { build } from 'esbuild';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

const isWatch = process.argv.includes('--watch');

const config = {
  entryPoints: [resolve(root, 'scan-engine/src/index.js')],
  bundle: true,
  format: 'iife',
  globalName: 'ScanEngine',
  outfile: resolve(root, 'extension/lib/scan-engine.bundle.js'),
  minify: false,
  sourcemap: true,
  target: ['chrome100'],
  banner: {
    js: '/* MalXtension — Scan Engine v3.0.0 | Bundled for browser */\n'
  },
  footer: {
    js: '\nif(typeof window!=="undefined"){window.ScanEngine=ScanEngine;}'
  }
};

if (isWatch) {
  const ctx = await build({ ...config, logLevel: 'info' });
  console.log('Watching for changes...');
} else {
  await build(config);
  console.log('✓ Scan Engine bundled → extension/lib/scan-engine.bundle.js');
}
