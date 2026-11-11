/// <reference types="vitest/config" />
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

/**
 * Production Content Security Policy. Injected only into the built index.html because the
 * Vite dev server relies on inline scripts for hot module replacement.
 *
 * connect-src allows raw.githubusercontent.com solely for the analyst-initiated
 * "Check for ATT&CK update" action in Settings. No incident data is ever sent there.
 */
const CSP = [
  "default-src 'self'",
  "worker-src 'self'",
  "manifest-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' https://raw.githubusercontent.com",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
  // frame-ancestors is ignored in <meta>; send it (and X-Content-Type-Options etc.) as HTTP headers - see docs/PRODUCTION.md.
].join('; ');

function cspPlugin(): Plugin {
  return {
    name: 'soc-navigator-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<meta charset="UTF-8" />',
        `<meta charset="UTF-8" />\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`,
      );
    },
  };
}

/**
 * Writes dist/sw.js from pwa/sw.template.js with the list of built files and a content revision,
 * so every release installs a fresh cache and removes the previous one.
 */
function serviceWorkerPlugin(): Plugin {
  let outDir = 'dist';
  return {
    name: 'soc-navigator-service-worker',
    apply: 'build',
    configResolved(config) {
      outDir = config.build.outDir;
    },
    closeBundle() {
      const files: string[] = [];
      const walk = (dir: string) => {
        for (const name of readdirSync(dir)) {
          const full = join(dir, name);
          if (statSync(full).isDirectory()) walk(full);
          else if (name !== 'sw.js') files.push(relative(outDir, full).split('\\').join('/'));
        }
      };
      walk(outDir);
      files.sort();
      const hash = createHash('sha256');
      for (const f of files) hash.update(f).update(readFileSync(join(outDir, f)));
      const sw = readFileSync('pwa/sw.template.js', 'utf8')
        .replace('__REVISION__', hash.digest('hex').slice(0, 16))
        .replace('__PRECACHE__', JSON.stringify(['./', ...files]));
      writeFileSync(join(outDir, 'sw.js'), sw);
    },
  };
}

export default defineConfig({
  // Relative base so the build works from any sub-path (e.g. GitHub Pages project sites).
  base: './',
  plugins: [react(), tailwindcss(), cspPlugin(), serviceWorkerPlugin()],
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      onwarn(warning, warn) {
        // Third-party packages ship comment annotations Rollup cannot place; harmless noise.
        if (warning.code === 'INVALID_ANNOTATION' && warning.id?.includes('node_modules')) return;
        warn(warning);
      },
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return id.includes('/src/data/playbooks/') ? 'playbooks' : undefined;
          if (/recharts|d3-|victory|decimal\.js|es-toolkit|immer|reselect|redux/.test(id)) return 'charts';
          if (/react|scheduler/.test(id)) return 'react';
          return 'vendor';
        },
      },
    },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
  },
});
