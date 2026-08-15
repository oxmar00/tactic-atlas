import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = new URL("../", import.meta.url);
const read = path => readFile(new URL(path, root), "utf8");

function normalizeNewlines(value) {
  return String(value).replace(/\r\n?/g, "\n");
}

function replaceExactlyOnce(source, pattern, replacement, label) {
  const flags = [...new Set(`${pattern.flags}g`.split(""))].join("");
  const matcher = new RegExp(pattern.source, flags);
  const matches = [...source.matchAll(matcher)];
  if (matches.length !== 1) {
    throw new Error(`Expected exactly one ${label} anchor, found ${matches.length}.`);
  }
  return source.replace(pattern, replacement);
}

function escapeInlineScript(value) {
  return value.replace(/<\/script/gi, "<\\/script");
}

function safeJsonForHtml(value) {
  const parsed = JSON.parse(value);
  return JSON.stringify(parsed)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

export function sha256Csp(value) {
  return `sha256-${createHash("sha256").update(value, "utf8").digest("base64")}`;
}

export function renderStandalone({ html, css, core, app, data }) {
  let output = normalizeNewlines(html);
  const styleText = normalizeNewlines(css).trimEnd();
  if (/<\/style/i.test(styleText)) throw new Error("Stylesheet contains an unsafe </style sequence.");

  const coreText = escapeInlineScript(normalizeNewlines(core).trimEnd());
  const appText = escapeInlineScript(normalizeNewlines(app).trimEnd());
  const coreScript = `globalThis.__ATTACK_PLAYBOOK_STANDALONE__ = true;\n${coreText}`;
  const embeddedData = safeJsonForHtml(normalizeNewlines(data));

  try { new Function(coreScript); } catch (error) { throw new Error(`Core script syntax error: ${error.message}`); }
  try { new Function(appText); } catch (error) { throw new Error(`Application script syntax error: ${error.message}`); }

  const policy = [
    "default-src 'none'",
    `script-src '${sha256Csp(coreScript)}' '${sha256Csp(embeddedData)}' '${sha256Csp(appText)}'`,
    "style-src 'unsafe-inline'",
    `style-src-elem '${sha256Csp(styleText)}'`,
    "style-src-attr 'unsafe-inline'",
    "img-src data:",
    "connect-src 'none'",
    "font-src 'none'",
    "manifest-src 'none'",
    "worker-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'"
  ].join("; ");

  output = replaceExactlyOnce(
    output,
    /\s*<link\b(?=[^>]*\brel=["']manifest["'])[^>]*>\s*/i,
    "\n",
    "manifest link"
  );
  output = replaceExactlyOnce(
    output,
    /<link\b(?=[^>]*\bhref=["']assets\/style\.css["'])[^>]*>/i,
    `<style>${styleText}</style>`,
    "stylesheet"
  );
  output = replaceExactlyOnce(
    output,
    /<script\b(?=[^>]*\bsrc=["']assets\/core\.js["'])[^>]*>\s*<\/script>/i,
    `<script>${coreScript}</script>`,
    "core script"
  );
  output = replaceExactlyOnce(
    output,
    /<script\b(?=[^>]*\bsrc=["']assets\/app\.js["'])[^>]*>\s*<\/script>/i,
    `<script id="playbook-data" type="application/json">${embeddedData}</script>\n<script>${appText}</script>`,
    "application script"
  );
  output = replaceExactlyOnce(
    output,
    /<meta\b(?=[^>]*http-equiv=["']Content-Security-Policy["'])[^>]*>/i,
    `<meta http-equiv="Content-Security-Policy" content="${policy}">`,
    "Content Security Policy"
  );

  const brandPattern = /<a\b(?=[^>]*\bclass=["'][^"']*\bbrand\b[^"']*["'])(?=[^>]*\bhref=["']\.\/["'])[^>]*>/i;
  if (brandPattern.test(output)) {
    output = output.replace(brandPattern, match => match.replace(/\bhref=["']\.\/["']/i, 'href="#content"'));
  }
  const documentationPattern = /<a\b(?=[^>]*\bhref=["']README\.md["'])[^>]*>[\s\S]*?<\/a>/i;
  if (documentationPattern.test(output)) output = output.replace(documentationPattern, "<span>Documentation</span>");
  output = output.replace(
    /<noscript>[\s\S]*?<\/noscript>/i,
    '<noscript><div class="noscript">JavaScript is required to browse the embedded playbook library.</div></noscript>'
  );

  if (/\b(?:src|href)=["'](?:assets\/|data\/|manifest\.webmanifest|README\.md|service-worker\.js)/i.test(output)) {
    throw new Error("Standalone output still contains a required local-runtime reference.");
  }
  if (!output.includes("__ATTACK_PLAYBOOK_STANDALONE__ = true")) {
    throw new Error("Standalone service-worker guard is missing.");
  }

  return `${output.trimEnd()}\n`;
}

export async function buildStandalone({ check = false } = {}) {
  const [html, css, core, app, data] = await Promise.all([
    read("index.html"),
    read("assets/style.css"),
    read("assets/core.js"),
    read("assets/app.js"),
    read("data/playbooks.json")
  ]);
  const standalone = renderStandalone({ html, css, core, app, data });
  const target = new URL("standalone.html", root);

  if (check) {
    let current = "";
    try { current = await read("standalone.html"); } catch { /* reported as drift below */ }
    if (current !== standalone) {
      throw new Error("standalone.html is stale. Run `npm run build` and commit the result.");
    }
    console.log(`Verified standalone.html (${Buffer.byteLength(standalone).toLocaleString()} bytes).`);
    return standalone;
  }

  await writeFile(target, standalone, "utf8");
  console.log(`Built standalone.html (${Buffer.byteLength(standalone).toLocaleString()} bytes).`);
  return standalone;
}

const isMain = process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (isMain) {
  buildStandalone({ check: process.argv.includes("--check") }).catch(error => {
    console.error(`Standalone build failed: ${error.message}`);
    process.exitCode = 1;
  });
}
