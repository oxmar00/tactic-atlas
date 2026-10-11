/// <reference types="vitest/config" />
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

export default defineConfig({
  // Relative base so the build works from any sub-path (e.g. GitHub Pages project sites).
  base: './',
  plugins: [react(), tailwindcss(), cspPlugin()],
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
