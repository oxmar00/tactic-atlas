import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = new URL("../", import.meta.url);
const read = path => readFile(new URL(path, root), "utf8");

export const RUNTIME_REVISION_PATHS = Object.freeze([
  "index.html",
  "manifest.webmanifest",
  "service-worker.js",
  "assets/style.css",
  "assets/core.js",
  "assets/app.js",
  "assets/icon.svg",
  "data/playbooks.json",
  "data/playbooks.schema.json",
  "data/event-catalog.json",
  "data/attack-analytics.json"
]);

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

function attributeValue(tag, name) {
  const attribute = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'<>]+))`, "i").exec(tag);
  return attribute ? (attribute[1] ?? attribute[2] ?? attribute[3] ?? "").trim() : null;
}

function assertKnownIndexAssets(html) {
  const knownScripts = new Set(["assets/core.js", "assets/app.js"]);
  for (const match of html.matchAll(/<script\b[^>]*>/gi)) {
    const source = attributeValue(match[0], "src");
    if (!source || !knownScripts.has(source.toLowerCase())) {
      throw new Error(`Unexpected script element in index shell${source ? `: ${source}` : "."}`);
    }
  }
  if (/<style\b/i.test(html)) {
    throw new Error("Unexpected inline style element in index shell.");
  }
  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    const relation = attributeValue(match[0], "rel");
    if (!relation?.toLowerCase().split(/\s+/).includes("stylesheet")) continue;
    const href = attributeValue(match[0], "href");
    if (href?.toLowerCase() !== "assets/style.css") {
      throw new Error(`Unexpected stylesheet element in index shell${href ? `: ${href}` : "."}`);
    }
  }
}

function assertCspCompleteness(html, scriptHashes, styleHashes) {
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  const styles = [...html.matchAll(/<style\b([^>]*)>([\s\S]*?)<\/style\s*>/gi)];
  if (scripts.length !== scriptHashes.length || styles.length !== styleHashes.length) {
    throw new Error("Standalone output contains an unexpected script or style element.");
  }
  const actualScriptHashes = scripts.map(match => {
    if (attributeValue(match[1], "src")) throw new Error("Standalone output contains an external script element.");
    return sha256Csp(match[2]);
  });
  const actualStyleHashes = styles.map(match => sha256Csp(match[2]));
  if (!scriptHashes.every(hash => actualScriptHashes.includes(hash)) || !styleHashes.every(hash => actualStyleHashes.includes(hash))) {
    throw new Error("Standalone Content Security Policy does not cover every script and style element.");
  }
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

export function computeRuntimeRevision(files) {
  const hash = createHash("sha256");
  RUNTIME_REVISION_PATHS.forEach(path => {
    if (typeof files?.[path] !== "string") throw new Error(`Cannot calculate runtime revision without ${path}.`);
    hash.update(`${path}\0`, "utf8");
    hash.update(normalizeNewlines(files[path]), "utf8");
    hash.update("\0", "utf8");
  });
  return `sha256-${hash.digest("hex")}`;
}

export function renderStandalone({ html, css, core, app, data, eventCatalog = "{}", attackAnalytics = "{}" }) {
  let output = normalizeNewlines(html);
  assertKnownIndexAssets(output);
  const styleText = normalizeNewlines(css).trimEnd();
  if (/<\/style/i.test(styleText)) throw new Error("Stylesheet contains an unsafe </style sequence.");

  const coreText = escapeInlineScript(normalizeNewlines(core).trimEnd());
  const appText = escapeInlineScript(normalizeNewlines(app).trimEnd());
  const coreScript = `globalThis.__ATTACK_PLAYBOOK_STANDALONE__ = true;\n${coreText}`;
  const embeddedData = safeJsonForHtml(normalizeNewlines(data));
  const embeddedEventCatalog = safeJsonForHtml(normalizeNewlines(eventCatalog));
  const embeddedAttackAnalytics = safeJsonForHtml(normalizeNewlines(attackAnalytics));

  try { new Function(coreScript); } catch (error) { throw new Error(`Core script syntax error: ${error.message}`); }
  try { new Function(appText); } catch (error) { throw new Error(`Application script syntax error: ${error.message}`); }

  const scriptHashes = [coreScript, embeddedData, embeddedEventCatalog, embeddedAttackAnalytics, appText].map(sha256Csp);
  const styleHashes = [sha256Csp(styleText)];
  const policy = [
    "default-src 'none'",
    `script-src ${scriptHashes.map(hash => `'${hash}'`).join(" ")}`,
    "style-src 'unsafe-inline'",
    `style-src-elem '${styleHashes[0]}'`,
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
    `<script id="playbook-data" type="application/json">${embeddedData}</script>\n<script id="event-catalog-data" type="application/json">${embeddedEventCatalog}</script>\n<script id="attack-analytics-data" type="application/json">${embeddedAttackAnalytics}</script>\n<script>${appText}</script>`,
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

  const markupOnly = output
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "");
  const unresolvedMarkupUrl = [...markupOnly.matchAll(/<[a-z][^>]*>/gi)]
    .flatMap(match => [attributeValue(match[0], "src"), attributeValue(match[0], "href")])
    .filter(value => value != null)
    .find(value => value && !/^(?:data:|#)/i.test(value));
  if (unresolvedMarkupUrl) {
    throw new Error("Standalone output still contains a required local-runtime reference.");
  }
  const unresolvedStyleUrl = [...styleText.matchAll(/url\(\s*(["']?)([^"')]+)\1\s*\)/gi)]
    .map(match => match[2].trim())
    .find(value => value && !/^(?:data:|#)/i.test(value));
  if (unresolvedStyleUrl) {
    throw new Error("Standalone output still contains a local-runtime stylesheet reference.");
  }
  if (!output.includes("__ATTACK_PLAYBOOK_STANDALONE__ = true")) {
    throw new Error("Standalone service-worker guard is missing.");
  }
  assertCspCompleteness(output, scriptHashes, styleHashes);

  return `${output.trimEnd()}\n`;
}

export async function buildStandalone({ check = false } = {}) {
  const entries = await Promise.all(RUNTIME_REVISION_PATHS.map(async path => [path, await read(path)]));
  const files = Object.fromEntries(entries);
  const html = files["index.html"];
  const css = files["assets/style.css"];
  const core = files["assets/core.js"];
  const app = files["assets/app.js"];
  const data = files["data/playbooks.json"];
  const eventCatalog = files["data/event-catalog.json"];
  const attackAnalytics = files["data/attack-analytics.json"];
  const standalone = renderStandalone({ html, css, core, app, data, eventCatalog, attackAnalytics });
  const revision = `${JSON.stringify({ revision: computeRuntimeRevision(files) }, null, 2)}\n`;
  const target = new URL("standalone.html", root);
  const revisionTarget = new URL("data/revision.json", root);

  if (check) {
    let current = "";
    try { current = await read("standalone.html"); } catch { /* reported as drift below */ }
    if (current !== standalone) {
      throw new Error("standalone.html is stale. Run `npm run build` and commit the result.");
    }
    let currentRevision = "";
    try { currentRevision = await read("data/revision.json"); } catch { /* reported as drift below */ }
    if (currentRevision !== revision) {
      throw new Error("data/revision.json is stale. Run `npm run build` and commit the result.");
    }
    console.log(`Verified standalone.html (${Buffer.byteLength(standalone).toLocaleString()} bytes).`);
    return standalone;
  }

  await Promise.all([
    writeFile(target, standalone, "utf8"),
    writeFile(revisionTarget, revision, "utf8")
  ]);
  console.log(`Built standalone.html (${Buffer.byteLength(standalone).toLocaleString()} bytes) and data/revision.json.`);
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
