import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";

import "../assets/core.js";
import { renderStandalone, sha256Csp } from "../scripts/build-standalone.mjs";
import { auditDataset } from "../scripts/audit-content.mjs";
import { TACTICS, validateDataset } from "../scripts/validate.mjs";

const Core = globalThis.PlaybookCore;

function responseWorkflow() {
  return {
    triage: ["Validate the alert and preserve raw evidence before changing state."],
    investigation: ["Build a UTC timeline and inspect identity, endpoint, and network evidence."],
    scoping: ["Identify affected users, hosts, sessions, resources, and earliest activity."],
    containment: { immediate: ["Use an approved reversible containment action."], rollback: ["Verify and reverse if impact exceeds the approved boundary."] },
    eradication: ["Remove persistence and close the verified access path."],
    recovery: ["Restore from a trusted state and verify security telemetry."],
    post_incident: ["Record root cause, gaps, lessons, and accountable follow-up actions."],
    escalation: ["Escalate confirmed high-impact activity to incident command."],
    decision_tree: ["If compromise is confirmed, contain; otherwise preserve and gather bounded evidence."],
    closure_criteria: ["Close only after scope, containment, eradication, recovery, and residual risk are documented."]
  };
}

function contractPlaybook(overrides = {}) {
  return {
    schema_version: "4.0.0",
    id: "T1059",
    name: "Command and Scripting Interpreter",
    kind: "technique",
    description: "Detect suspicious command and scripting interpreter behavior with process, identity, and session context.",
    tactics: ["Execution"],
    tactic_mappings: [{ tactic: "Execution", technique_id: "T1059", status: "verified" }],
    techniques: [{ id: "T1059", name: "Command and Scripting Interpreter" }],
    subtechniques: [{ id: "T1059.001", name: "PowerShell" }],
    platforms: ["Windows", "Linux", "macOS"],
    data_source_summary: "Required endpoint process telemetry is correlated with identity, script, and network evidence.",
    telemetry_requirements: [{
      id: "endpoint-process",
      category: "Endpoint",
      tier: "required",
      priority: "required",
      event_types: [{ name: "process_start", purpose: "Execution lineage" }],
      event_ids: [{ product: "Windows Security", id: "4688" }],
      raw_fields: ["event_time", "host", "user", "process_id", "command_line"],
      normalized_fields: [{ field: "process.command_line", mapping: "ECS" }],
      correlation_fields: [{ field: "process.entity_id", purpose: "Process lineage" }],
      retention: { hot_days: 30, archive_days: 365 },
      latency: { target: "5 minutes" }
    }],
    detection: {
      objective: "Identify unexpected interpreter execution that is inconsistent with the initiating identity, asset, and parent process.",
      hypothesis: "An adversary using a command interpreter will create process and script telemetry that differs from approved administration.",
      strategy: { summary: "Correlate command execution with parent, identity, prevalence, and follow-on activity." },
      strategies: [{ id: "behavior", logic: "Match risky command behavior and corroborate with entity context." }],
      maturity_levels: [{ level: 1, description: "High-recall process match" }, { level: 2, description: "Contextual correlation" }]
    },
    queries: [{
      id: "vendor-neutral-1",
      name: "Suspicious interpreter behavior",
      platform: "Vendor-neutral",
      language: "pseudocode",
      query: "MATCH process_start WHERE interpreter = true AND command_risk >= threshold GROUP BY host, user",
      adaptation_required: true
    }],
    validation: {
      status: "validated",
      safe_method: "Use an approved benign interpreter command on a non-production host.",
      expected_output: "One enriched alert with host, user, process lineage, and raw-event references.",
      negative_test: "Run a documented management task and verify its bounded exception."
    },
    response: responseWorkflow(),
    lifecycle: {
      owner: { team: "Detection Engineering", role: "Rule owner" },
      review_frequency: "Quarterly and after material telemetry changes",
      version: "4.0.0",
      last_reviewed: "2026-07-12",
      status: "production"
    },
    tags: ["execution", "interpreter", "process"],
    severity: "high",
    confidence: "high",
    maturity: 3,
    status: "production",
    quality_score: 92,
    quality_breakdown: { telemetry: 94, detection: 92, response: 90 },
    coverage: { telemetry: true, queries: true, validation: true, response: true },
    content_sections: [{ id: "overview", title: "Overview", blocks: [{ type: "text", text: "Technique-specific analyst guidance." }] }],
    search_terms: ["T1059", "command interpreter", "PowerShell", "4688"],
    url: "https://attack.mitre.org/techniques/T1059/",
    ...overrides
  };
}

function contractDataset(playbooks = [contractPlaybook()]) {
  const counts = { total: playbooks.length, technique: 0, operational: 0, platform: 0 };
  playbooks.forEach(playbook => { counts[playbook.kind]++; });
  return {
    meta: {
      schema_version: "4.0.0",
      content_version: "4.0.0",
      generated: "2026-07-12",
      tactic_order: [...TACTICS],
      counts
    },
    playbooks
  };
}

test("core exposes the stable dependency-free API and current tactic contract", () => {
  assert.ok(Core, "assets/core.js must expose globalThis.PlaybookCore");
  for (const name of [
    "normalizeText", "tokenizeQuery", "normalizeDataset", "buildSearchIndex", "rankPlaybook",
    "filterAndSortPlaybooks", "encodeUrlState", "decodeUrlState", "serializePlaybookMarkdown",
    "serializePlaybooksJson", "serializeCoverageCsv", "escapeCsvCell", "safeFilename",
    "qualitySummary", "coverageSummary"
  ]) assert.equal(typeof Core[name], "function", `${name} must remain exported`);
  assert.deepEqual([...Core.TACTICS], [...TACTICS]);
});

test("normalization, tokenization, URL safety, and hash decoding reject unsafe input", () => {
  assert.equal(Core.normalizeText("  Cr\u00e8me\u2014PowerShell  "), "creme-powershell");
  assert.deepEqual(Core.tokenizeQuery('"PowerShell encoded" T1059 T1059'), ["powershell encoded", "t1059"]);
  assert.equal(Core.safeHttpUrl("javascript:alert(1)"), null);
  assert.equal(Core.safeHttpUrl("data:text/html,unsafe"), null);
  assert.equal(Core.safeHttpUrl("https://attack.mitre.org/techniques/T1059/")?.startsWith("https://"), true);
  assert.equal(Core.safeDecodeHash("#T1059"), "T1059");
  assert.equal(Core.safeDecodeHash("#%E0%A4%A"), null);
  assert.equal(Core.safeDecodeHash("#../../escape"), null);
});

test("dataset normalization rejects versions and duplicate IDs", () => {
  assert.throws(() => Core.normalizeDataset({ meta: { schema_version: "3.0.0", content_version: "3.0.0" }, playbooks: [] }), /v4\.0\.0 is required/);
  const duplicate = contractDataset([contractPlaybook(), contractPlaybook()]);
  assert.throws(() => Core.normalizeDataset(duplicate), /Duplicate playbook ID/);
  const normalized = Core.normalizeDataset(contractDataset());
  assert.equal(normalized.playbooks[0].id, "T1059");
  assert.equal(Object.hasOwn(normalized.playbooks[0], "html"), false);
});

test("search ranking, fuzzy matching, filters, and sorting are deterministic", () => {
  const second = contractPlaybook({
    id: "T1110",
    name: "Brute Force",
    description: "Detect repeated authentication attempts and password guessing with identity, device, and source context.",
    techniques: [{ id: "T1110", name: "Brute Force" }],
    subtechniques: [],
    platforms: ["Identity"],
    severity: "critical",
    quality_score: 88,
    search_terms: ["T1110", "brute force", "authentication"],
    url: "https://attack.mitre.org/techniques/T1110/"
  });
  const playbooks = Core.normalizeDataset(contractDataset([contractPlaybook(), second])).playbooks;
  const index = Core.buildSearchIndex(playbooks);
  assert.ok(Core.rankPlaybook(playbooks[0], "T1059", index) > Core.rankPlaybook(playbooks[0], "PowerShell", index));
  assert.deepEqual(Core.filterAndSortPlaybooks(playbooks, { query: "powershel" }, index).map(item => item.id), ["T1059"]);
  assert.deepEqual(Core.filterAndSortPlaybooks(playbooks, { platform: "Identity" }, index).map(item => item.id), ["T1110"]);
  assert.deepEqual(Core.filterAndSortPlaybooks(playbooks, { sort: "severity" }, index).map(item => item.id), ["T1110", "T1059"]);
});

test("URL state round-trips bounded filters and an encoded playbook ID", () => {
  const encoded = Core.encodeUrlState({
    query: "PowerShell encoded",
    view: "table",
    kind: "technique",
    platform: "Windows",
    tactics: ["Execution", "Defense Impairment"],
    favoritesOnly: true,
    openId: "T1059.001"
  }, "/console/");
  const url = new URL(encoded, "https://example.test");
  const state = Core.decodeUrlState(url.search, url.hash);
  assert.equal(state.query, "PowerShell encoded");
  assert.equal(state.view, "table");
  assert.equal(state.platform, "Windows");
  assert.deepEqual(state.tactics, ["Execution", "Defense Impairment"]);
  assert.equal(state.favoritesOnly, true);
  assert.equal(state.openId, "T1059.001");
});

test("exports prevent spreadsheet formulas and omit legacy HTML", () => {
  const playbook = Core.normalizeDataset(contractDataset()).playbooks[0];
  assert.equal(Core.escapeCsvCell("=2+3"), "'=2+3");
  assert.equal(Core.escapeCsvCell(" @SUM(A1:A2)"), "' @SUM(A1:A2)");
  assert.match(Core.serializePlaybookMarkdown(playbook), /^# T1059:/);
  assert.match(Core.serializeCoverageCsv([{ ...playbook, name: "=cmd|' /C calc" }]), /'=cmd/);
  assert.equal(Core.serializePlaybooksJson([{ ...playbook, html: "<script>unsafe</script>" }]).includes("<script>"), false);
  assert.equal(Core.safeFilename("../../Command & Script", "MD"), "command-script.md");
});

test("strict schema validation accumulates errors without crashing", () => {
  assert.doesNotThrow(() => validateDataset(null));
  assert.ok(validateDataset(null).errors.length > 0);
  assert.deepEqual(validateDataset(contractDataset()).errors, []);

  const mismatch = contractPlaybook();
  mismatch.telemetry_requirements[0].priority = "optional";
  assert.ok(validateDataset(contractDataset([mismatch])).errors.some(error => error.includes("tier and priority")));

  const legacy = contractPlaybook({
    tactics: ["Defense Evasion"],
    tactic_mappings: [{ tactic: "Defense Evasion", technique_id: "T1059", legacy: true, provenance: { status: "unverified" } }],
    status: "deprecated",
    lifecycle: { ...contractPlaybook().lifecycle, status: "deprecated" }
  });
  assert.equal(validateDataset(contractDataset([legacy])).errors.some(error => error.includes("unknown tactic")), false);
});

test("standalone rendering verifies anchors, hashes inline assets, and removes local runtime links", () => {
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'self'">
<link rel="manifest" href="manifest.webmanifest"><link rel="stylesheet" href="assets/style.css"></head>
<body><noscript><a href="data/playbooks.json">data</a></noscript><a class="brand home" href="./">Home</a>
<a href="README.md">Documentation</a><script src="assets/core.js" defer></script><script src="assets/app.js" defer></script></body></html>`;
  const data = JSON.stringify(contractDataset());
  const output = renderStandalone({
    html,
    css: ".app { color: #fff; }",
    core: '"use strict"; globalThis.CORE_MARK = true;',
    app: '"use strict"; globalThis.APP_MARK = true;',
    data
  });
  assert.ok(output.indexOf("CORE_MARK") < output.indexOf("playbook-data"));
  assert.ok(output.indexOf("playbook-data") < output.indexOf("APP_MARK"));
  const embedded = output.match(/<script id="playbook-data" type="application\/json">([\s\S]*?)<\/script>/)?.[1];
  assert.ok(embedded);
  assert.ok(output.includes(sha256Csp(embedded)));
  assert.equal(/(?:src|href)="(?:assets\/|data\/|README\.md|manifest\.webmanifest)/.test(output), false);
  assert.match(output, /__ATTACK_PLAYBOOK_STANDALONE__ = true/);
  assert.throws(() => renderStandalone({ html: html.replace(/<script src="assets\/core\.js" defer><\/script>/, ""), css: "x{}", core: "", app: "", data }), /core script anchor/);
});

test("service worker caches only the scoped shell and uses navigation-only offline fallback", async () => {
  const handlers = {};
  const stores = new Map();
  const keyOf = key => typeof key === "string" ? key : key.url;
  const caches = {
    async open(name) {
      if (!stores.has(name)) stores.set(name, new Map());
      const store = stores.get(name);
      return {
        async put(key, response) { store.set(keyOf(key), response.clone()); },
        async match(key) { return store.get(keyOf(key))?.clone(); }
      };
    },
    async keys() { return [...stores.keys()]; },
    async delete(name) { return stores.delete(name); }
  };
  let networkOnline = true;
  let skipWaitingCalls = 0;
  const fetch = async request => {
    if (!networkOnline) throw new Error("offline");
    const url = keyOf(request);
    return new Response(`network:${url}`, { status: 200, headers: { "Content-Type": url.endsWith(".json") ? "application/json" : "text/plain" } });
  };
  const self = {
    registration: { scope: "https://example.test/console/" },
    clients: {
      async claim() {},
      async matchAll() { return []; }
    },
    addEventListener(type, handler) { handlers[type] = handler; },
    skipWaiting() { skipWaitingCalls++; }
  };
  const source = await readFile(new URL("../service-worker.js", import.meta.url), "utf8");
  runInNewContext(source, { self, caches, fetch, URL, Request, Response, Set, Promise, Error, JSON });

  let pending;
  handlers.install({ waitUntil(promise) { pending = promise; } });
  await pending;
  const shellName = [...stores.keys()].find(name => name.endsWith("-shell"));
  assert.ok(shellName);
  const shell = stores.get(shellName);
  assert.equal(shell.size, 6);
  assert.equal(shell.has("https://example.test/console/index.html"), true);
  assert.equal([...shell.keys()].some(url => url.includes("playbooks.json")), false);
  const dataName = [...stores.keys()].find(name => name.endsWith("-data"));
  assert.equal(stores.get(dataName)?.has("https://example.test/console/data/playbooks.json"), true);

  stores.set("attack-playbook-console-v3-shell", new Map());
  stores.set("unrelated-cache", new Map());
  handlers.activate({ waitUntil(promise) { pending = promise; } });
  await pending;
  assert.equal(stores.has("attack-playbook-console-v3-shell"), false);
  assert.equal(stores.has("unrelated-cache"), true);

  handlers.message({ data: { type: "SKIP_WAITING" } });
  assert.equal(skipWaitingCalls, 1);

  networkOnline = false;
  let responsePromise;
  handlers.fetch({
    request: { method: "GET", mode: "navigate", url: "https://example.test/console/?q=T1059" },
    respondWith(promise) { responsePromise = promise; }
  });
  const navigation = await responsePromise;
  assert.match(await navigation.text(), /index\.html/);

  shell.delete("https://example.test/console/assets/app.js");
  responsePromise = null;
  handlers.fetch({
    request: { method: "GET", mode: "same-origin", url: "https://example.test/console/assets/app.js" },
    respondWith(promise) { responsePromise = promise; }
  });
  const failedAsset = await responsePromise;
  assert.equal(failedAsset.status, 503);
  assert.doesNotMatch(await failedAsset.text(), /index\.html/);

  responsePromise = null;
  handlers.fetch({
    request: { method: "GET", mode: "same-origin", url: "https://example.test/console/not-cached.js" },
    respondWith(promise) { responsePromise = promise; }
  });
  assert.equal(responsePromise, null, "unexpected same-origin requests must not be intercepted or cached");
});

test("content audit reports complete quality metrics for a valid contract fixture", () => {
  const { report, blockers } = auditDataset(contractDataset(), Date.parse("2026-07-12T00:00:00Z"));
  assert.equal(report.total_playbooks, 1);
  assert.equal(report.telemetry_mappings, 1);
  assert.equal(report.queries, 1);
  assert.equal(report.response_workflows_complete, 1);
  assert.deepEqual(blockers, []);
});
