import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";

import "../assets/core.js";
import { computeRuntimeRevision, renderStandalone, RUNTIME_REVISION_PATHS, sha256Csp } from "../scripts/build-standalone.mjs";
import { auditDataset } from "../scripts/audit-content.mjs";
import { applyThreatGroups } from "../scripts/add-threat-groups.mjs";
import { buildAttackAnalytics as buildAnalyticsArtifact, parseEventCodes as parseAnalyticsEventCodes } from "../scripts/build-attack-analytics.mjs";
import { applyTelemetryEnrichment, parseEventCodes as parseEnrichmentEventCodes } from "../scripts/enhance-telemetry.mjs";
import {
  TACTICS, validateAgainstSchema, validateAttackAnalytics, validateDataset, validateEventCatalog
} from "../scripts/validate.mjs";

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
    threat_groups: ["G0007"],
    platforms: ["Windows", "Linux", "macOS"],
    data_sources: ["endpoint-process"],
    data_source_summary: "required: Endpoint process telemetry",
    telemetry_requirements: [{
      id: "endpoint-process",
      source_name: "Endpoint process telemetry",
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
    coverage: {
      telemetry: true, queries: true, validation: true, response: true,
      required_telemetry: 1, recommended_telemetry: 0, optional_telemetry: 0, compensating_telemetry: 0
    },
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
      counts,
      attack: { domain: "enterprise-attack", version: "19.1" },
      quality_model: { version: "1.0.0" }
    },
    groups: [{ id: "G0007", name: "APT28", aliases: ["Fancy Bear", "Sofacy"], url: "https://attack.mitre.org/groups/G0007/" }],
    playbooks
  };
}

test("core exposes the stable dependency-free API and current tactic contract", () => {
  assert.ok(Core, "assets/core.js must expose globalThis.PlaybookCore");
  for (const name of [
    "normalizeText", "tokenizeQuery", "normalizeDataset", "buildSearchIndex", "rankPlaybook",
    "filterAndSortPlaybooks", "encodeUrlState", "decodeUrlState", "serializePlaybookMarkdown",
    "serializePlaybooksJson", "serializeCoverageCsv", "escapeCsvCell", "safeFilename",
    "qualitySummary", "coverageSummary", "wrapText", "buildFlowchart", "refreshServiceWorkerRevision",
    "waitForServiceWorkerRevision"
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
  const exported = JSON.parse(Core.serializePlaybooksJson([{ ...playbook, html: "<script>unsafe</script>" }], contractDataset().meta, contractDataset().groups));
  assert.equal(JSON.stringify(exported).includes("<script>"), false);
  assert.equal(exported.groups[0].id, "G0007");
  assert.deepEqual(exported.meta.counts, { total: 1, technique: 1, operational: 0, platform: 0 });
  assert.deepEqual(validateDataset(exported).errors, []);
  assert.equal(Core.safeFilename("../../Command & Script", "MD"), "command-script.md");
});

test("strict schema validation applies the declared contract and accumulates malformed-value errors", async () => {
  assert.doesNotThrow(() => validateDataset(null));
  assert.ok(validateDataset(null).errors.length > 0);
  assert.deepEqual(validateDataset(contractDataset()).errors, []);

  const mismatch = contractPlaybook();
  mismatch.telemetry_requirements[0].priority = "optional";
  assert.ok(validateDataset(contractDataset([mismatch])).errors.some(error => error.includes("tier and priority")));

  const staleTelemetry = contractPlaybook({ data_sources: [], data_source_summary: "required: Stale source summary" });
  staleTelemetry.coverage.required_telemetry = 0;
  const staleErrors = validateDataset(contractDataset([staleTelemetry])).errors;
  assert.ok(staleErrors.some(error => error.includes("exactly mirror")));
  assert.ok(staleErrors.some(error => error.includes("summarize the reconciled")));
  assert.ok(staleErrors.some(error => error.includes("required_telemetry")));

  const staleGroupSummary = contractDataset();
  staleGroupSummary.meta.threat_groups_summary = {
    total_groups: 0,
    playbooks_with_groups: 0,
    total_playbook_group_mappings: 0,
    attack_version: "19.1"
  };
  const staleGroupErrors = validateDataset(staleGroupSummary).errors;
  for (const field of ["total_groups", "playbooks_with_groups", "total_playbook_group_mappings"]) {
    assert.ok(staleGroupErrors.some(error => error.includes(`threat_groups_summary.${field}`)));
  }

  const legacy = contractPlaybook({
    tactics: ["Defense Evasion"],
    tactic_mappings: [{ tactic: "Defense Evasion", technique_id: "T1059", legacy: true, provenance: { status: "unverified" } }],
    status: "deprecated",
    lifecycle: { ...contractPlaybook().lifecycle, status: "deprecated" }
  });
  assert.equal(validateDataset(contractDataset([legacy])).errors.some(error => error.includes("unknown tactic")), false);

  const malformed = contractDataset();
  malformed.playbooks[0].telemetry_requirements[0].event_ids = {};
  malformed.playbooks[0].telemetry_requirements[0].attack_analytics = 42;
  malformed.playbooks[0].search_terms = ["T1059", {}, "PowerShell"];
  malformed.playbooks[0].content_sections[0].blocks.push(null);
  assert.doesNotThrow(() => validateDataset(malformed));
  assert.ok(validateDataset(malformed).errors.some(error => error.includes("event_ids")));
  assert.ok(validateDataset(malformed).errors.some(error => error.includes("attack_analytics")));
  assert.ok(validateDataset(malformed).errors.some(error => error.includes("content block")));

  const versionMismatch = contractDataset();
  versionMismatch.playbooks[0].telemetry_requirements[0].event_ids[0].provenance = "attack-v18.0-verified";
  versionMismatch.playbooks[0].telemetry_requirements[0].attack_enrichment = { generated: true, attack_version: "18.0" };
  const versionErrors = validateDataset(versionMismatch).errors;
  assert.ok(versionErrors.some(error => error.includes("provenance") && error.includes("19.1")));
  assert.ok(versionErrors.some(error => error.includes("attack_enrichment") && error.includes("19.1")));

  const schema = JSON.parse(await readFile(new URL("../data/playbooks.schema.json", import.meta.url), "utf8"));
  const schemaViolation = contractDataset();
  delete schemaViolation.meta.attack;
  delete schemaViolation.meta.quality_model;
  delete schemaViolation.meta.generated;
  schemaViolation.meta.last_updated = "2026-07-12";
  schemaViolation.playbooks[0].maturity = "advanced";
  const schemaResult = validateAgainstSchema(schemaViolation, schema);
  assert.equal(schemaResult.valid, false);
  assert.ok(schemaResult.errors.some(error => error.includes("attack")));
  assert.ok(schemaResult.errors.some(error => error.includes("quality_model")));
  assert.ok(schemaResult.errors.some(error => error.includes("generated")));
  assert.ok(schemaResult.errors.some(error => error.includes("maturity")));
});

test("supplemental data validators reject corrupt catalogs and analytics without throwing", () => {
  const catalog = {
    schema_version: "1.0.0", description: "Curated vendor event definitions for investigations.",
    provenance: { vendor: "Vendor documentation" },
    events: [{ event_id: "4688", log_source: "Windows Security", name: "Process Creation", source: "vendor", use_for: ["Execution"], fields: ["CommandLine"], investigation: ["Inspect lineage"] }]
  };
  assert.deepEqual(validateEventCatalog(catalog), []);
  assert.ok(validateEventCatalog({ ...catalog, events: 42 }).length > 0);

  const analytics = {
    schema_version: "1.0.0", attack_version: "19.1", generated_from: "Official ATT&CK Enterprise STIX", source_url: "https://github.com/mitre-attack/attack-stix-data",
    counts: { techniques: 1, with_telemetry: 1, log_source_refs: 1, event_id_refs: 2, platform_mismatched_refs: 0 },
    techniques: { T1059: { id: "T1059", name: "Command Interpreter", is_subtechnique: false, parent: null, tactics: ["execution"], platforms: ["Windows"], telemetry: [{ log_source: "WinEventLog:Security", channel: "EventCode=4688, 4689", event_ids: ["4688", "4689"], platform_mismatch: false, platforms: ["Windows"], analytic: "AN0001", strategy: "DET0001", strategy_name: "Interpreter detection", strategy_url: "https://attack.mitre.org/detectionstrategies/DET0001" }], tuning: [], pivots: [] } }
  };
  assert.deepEqual(validateAttackAnalytics(analytics), []);
  assert.ok(validateAttackAnalytics(analytics, "20.0").some(error => error.includes("playbook dataset")));
  analytics.counts.event_id_refs = 1;
  assert.ok(validateAttackAnalytics(analytics).some(error => error.includes("event_id_refs")));
  analytics.counts.event_id_refs = 2;
  analytics.techniques.T1059.telemetry[0].event_ids = ["9999", "8888"];
  assert.ok(validateAttackAnalytics(analytics).some(error => error.includes("exactly match every EventCode")));
});

test("ATT&CK tooling requires versioned, non-empty evidence and preserves every channel reference", () => {
  assert.deepEqual(parseAnalyticsEventCodes("EventCode=4103, 4104, 4105, 4106"), ["4103", "4104", "4105", "4106"]);
  assert.deepEqual(parseEnrichmentEventCodes("EventID=22, 5858, 5860"), ["22", "5858", "5860"]);
  assert.throws(() => buildAnalyticsArtifact({ objects: [] }), /release version is required/);
  assert.equal(buildAnalyticsArtifact({ objects: [] }, "20.0").attack_version, "20.0");

  const emptyTarget = contractDataset();
  const before = JSON.stringify(emptyTarget);
  assert.throws(() => applyTelemetryEnrichment(emptyTarget, {
    schema_version: "1.0.0", attack_version: "19.1", techniques: {}
  }, { generatedDate: "2026-09-05" }), /no usable detection-strategy/);
  assert.equal(JSON.stringify(emptyTarget), before, "failed evidence preflight must not mutate the dataset");

  const source = {
    ...contractPlaybook().telemetry_requirements[0],
    id: "windows-security",
    source_name: "Windows Security",
    event_ids: []
  };
  const target = contractDataset([contractPlaybook({
    telemetry_requirements: [source],
    data_sources: ["windows-security"],
    data_source_summary: "required: Windows Security"
  })]);
  const artifact = {
    schema_version: "1.0.0", attack_version: "19.1", techniques: {
      T1059: { telemetry: [
        { log_source: "WinEventLog:Security", channel: "EventCode=4103, 4104, 4105, 4106", event_ids: ["4103", "4104", "4105", "4106"], analytic: "AN0001", strategy: "DET0001", strategy_name: "Primary", strategy_url: "https://attack.mitre.org/detectionstrategies/DET0001" },
        { log_source: "WinEventLog:Security", channel: "EventCode=22", event_ids: ["22"], analytic: "AN0001", strategy: "DET0001", strategy_name: "Primary", strategy_url: "https://attack.mitre.org/detectionstrategies/DET0001" }
      ] }
    }
  };
  assert.throws(() => applyTelemetryEnrichment(structuredClone(target), { ...artifact, attack_version: "20.0" }, { generatedDate: "2026-09-05" }), /does not match dataset/);
  const summary = applyTelemetryEnrichment(target, artifact, { generatedDate: "2026-09-05" });
  assert.equal(summary.eventIdsAdded, 5);
  assert.deepEqual(target.playbooks[0].telemetry_requirements[0].event_ids.map(item => item.id).sort(), ["22", "4103", "4104", "4105", "4106"].sort());
  assert.equal(target.playbooks[0].telemetry_requirements[0].attack_analytics.length, 2);
  assert.deepEqual(target.playbooks[0].data_sources, ["windows-security"]);
  assert.equal(target.playbooks[0].coverage.required_telemetry, 1);

  const grouped = contractDataset();
  assert.throws(() => applyThreatGroups(grouped, [], new Map()), /no live direct group-to-technique/);
  const replacementGroups = [{ id: "G0008", name: "Replacement", aliases: [], url: "https://attack.mitre.org/groups/G0008/" }];
  const replacementMap = new Map([["T1059", new Set(["G0008"])]]);
  assert.throws(() => applyThreatGroups(structuredClone(grouped), replacementGroups, replacementMap), /remove 1 existing group mapping/);
  const replaced = structuredClone(grouped);
  replaced.groups.push({ id: "G1040", name: "Play", aliases: [], url: "https://attack.mitre.org/groups/G1040/" });
  replaced.playbooks[0].search_terms.push("G0007", "APT28", "Fancy Bear", "Play");
  applyThreatGroups(replaced, replacementGroups, replacementMap, { allowRemovals: true, attackVersion: "19.1" });
  assert.deepEqual(replaced.playbooks[0].threat_groups, ["G0008"]);
  assert.equal(replaced.playbooks[0].search_terms.includes("APT28"), false);
  assert.equal(replaced.playbooks[0].search_terms.includes("Fancy Bear"), false);
  assert.equal(replaced.playbooks[0].search_terms.includes("Play"), true, "terms from unrelated group records must be preserved");
});

test("standalone rendering verifies anchors, hashes inline assets, and removes local runtime links", () => {
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'self'">
<link rel="manifest" href="manifest.webmanifest"><link rel="stylesheet" href="assets/style.css"></head>
  <body><noscript><a href="data/playbooks.json">data</a></noscript><a class="brand home" href="./">Home</a>
<a href="README.md">Documentation</a><script src="assets/core.js" defer></script><script src="assets/app.js" defer></script></body></html>`;
  const data = JSON.stringify(contractDataset());
  const standaloneInput = {
    html,
    css: ".app { color: #fff; }",
    core: '"use strict"; globalThis.CORE_MARK = true;',
    app: '"use strict"; globalThis.APP_MARK = true;',
    data,
    eventCatalog: JSON.stringify({ schema_version: "1.0.0", events: [] }),
    attackAnalytics: JSON.stringify({ schema_version: "1.0.0", techniques: {} })
  };
  const output = renderStandalone(standaloneInput);
  assert.ok(output.indexOf("CORE_MARK") < output.indexOf("playbook-data"));
  assert.ok(output.indexOf("playbook-data") < output.indexOf("APP_MARK"));
  const embedded = output.match(/<script id="playbook-data" type="application\/json">([\s\S]*?)<\/script>/)?.[1];
  assert.ok(embedded);
  assert.ok(output.includes(sha256Csp(embedded)));
  assert.match(output, /id="event-catalog-data"/);
  assert.match(output, /id="attack-analytics-data"/);
  assert.equal(/(?:src|href)="(?:assets\/|data\/|README\.md|manifest\.webmanifest)/.test(output), false);
  assert.match(output, /__ATTACK_PLAYBOOK_STANDALONE__ = true/);
  assert.throws(() => renderStandalone({ html: html.replace(/<script src="assets\/core\.js" defer><\/script>/, ""), css: "x{}", core: "", app: "", data }), /core script anchor/);
  assert.throws(() => renderStandalone({ html, css: '.app{background:url("assets/background.svg")}', core: '"use strict";', app: '"use strict";', data }), /stylesheet reference/);
  assert.throws(() => renderStandalone({ html: html.replace("</body>", '<img src="./assets/unresolved.svg"></body>'), css: "x{}", core: '"use strict";', app: '"use strict";', data }), /local-runtime reference/);
  assert.throws(() => renderStandalone({ ...standaloneInput, html: html.replace("</body>", "<img src=assets/unresolved.svg></body>") }), /local-runtime reference/);
  assert.throws(
    () => renderStandalone({ ...standaloneInput, html: html.replace("</body>", '<script src="assets/extra.js"></script></body>') }),
    /unexpected script element/i
  );
  assert.throws(
    () => renderStandalone({ ...standaloneInput, html: html.replace("</body>", "<script>globalThis.EXTRA = true;</script></body>") }),
    /unexpected script element/i
  );
  assert.throws(
    () => renderStandalone({ ...standaloneInput, html: html.replace("</head>", "<style>.extra { color: red; }</style></head>") }),
    /unexpected inline style element/i
  );
  assert.throws(
    () => renderStandalone({ ...standaloneInput, html: html.replace("</head>", '<link rel="stylesheet" href="assets/extra.css"></head>') }),
    /unexpected stylesheet element/i
  );
});

test("runtime revisions are deterministic, path-delimited, and sensitive to every deployed source", () => {
  const files = Object.fromEntries(RUNTIME_REVISION_PATHS.map(path => [path, `content:${path}`]));
  const revision = computeRuntimeRevision(files);
  assert.match(revision, /^sha256-[a-f0-9]{64}$/);
  assert.equal(computeRuntimeRevision({ ...files }), revision);
  const changed = { ...files, "assets/style.css": `${files["assets/style.css"]}\nchange` };
  assert.notEqual(computeRuntimeRevision(changed), revision);
  assert.throws(() => computeRuntimeRevision({}), /without index\.html/);
});

test("service worker isolates scoped caches and uses navigation-only offline fallback", async () => {
  const handlers = {};
  const stores = new Map();
  let rejectCacheWrites = false;
  const keyOf = key => typeof key === "string" ? key : key.url;
  const caches = {
    async open(name) {
      if (!stores.has(name)) stores.set(name, new Map());
      const store = stores.get(name);
      return {
        async put(key, response) {
          if (rejectCacheWrites) throw new Error("cache quota exceeded");
          store.set(keyOf(key), response.clone());
        },
        async match(key) { return store.get(keyOf(key))?.clone(); },
        async keys() { return [...store.keys()].map(url => new Request(url)); },
        async delete(key) { return store.delete(keyOf(key)); }
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
    location: { href: "https://example.test/console/service-worker.js?rev=sha256-test-release" },
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
  assert.match(shellName, /^tactic-atlas-scope-%2Fconsole%2F-/);
  const shell = stores.get(shellName);
  assert.equal(shell.size, 6);
  assert.equal(shell.has("https://example.test/console/index.html"), true);
  assert.equal([...shell.keys()].some(url => url.includes("playbooks.json")), false);
  const dataName = [...stores.keys()].find(name => name.endsWith("-data"));
  assert.equal(stores.get(dataName)?.has("https://example.test/console/data/playbooks.json"), true);
  assert.equal(stores.get(dataName)?.has("https://example.test/console/data/event-catalog.json"), true);
  assert.equal(stores.get(dataName)?.has("https://example.test/console/data/attack-analytics.json"), true);
  assert.equal(stores.get(dataName)?.has("https://example.test/console/data/revision.json"), true);

  const sharedLegacy = "tactic-atlas-sha256-old-release-shell";
  const currentOnlyLegacy = "attack-playbook-console-v3-data";
  const otherScope = "tactic-atlas-scope-%2Fother-copy%2F-sha256-other-release-shell";
  stores.set(sharedLegacy, new Map([
    ["https://example.test/console/index.html", new Response("old current shell")],
    ["https://example.test/other-copy/index.html", new Response("old sibling shell")]
  ]));
  stores.set(currentOnlyLegacy, new Map([
    ["https://example.test/console/data/playbooks.json", new Response("old current data")]
  ]));
  stores.set(otherScope, new Map());
  stores.set("unrelated-cache", new Map());
  handlers.activate({ waitUntil(promise) { pending = promise; } });
  await pending;
  assert.equal(stores.get(sharedLegacy)?.has("https://example.test/console/index.html"), false, "activation must remove its own entries from a shared legacy cache");
  assert.equal(stores.get(sharedLegacy)?.has("https://example.test/other-copy/index.html"), true, "activation must preserve sibling entries in a shared legacy cache");
  assert.equal(stores.has(currentOnlyLegacy), false, "an emptied current-scope legacy cache must be removed");
  assert.equal(stores.has(otherScope), true, "activation must preserve another app copy's scoped caches");
  assert.equal(stores.has("unrelated-cache"), true);

  handlers.message({ data: { type: "SKIP_WAITING" } });
  assert.equal(skipWaitingCalls, 1);

  rejectCacheWrites = true;
  let responsePromise;
  handlers.fetch({
    request: { method: "GET", mode: "same-origin", url: "https://example.test/console/data/event-catalog.json" },
    waitUntil() {},
    respondWith(promise) { responsePromise = promise; }
  });
  const uncachedSuccess = await responsePromise;
  assert.equal(uncachedSuccess.status, 200, "a cache write failure must not replace a successful network response");
  assert.match(await uncachedSuccess.text(), /event-catalog\.json/);
  rejectCacheWrites = false;

  networkOnline = false;
  responsePromise = null;
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

test("long-lived pages retry a changed service-worker revision after transient registration failure", async () => {
  const app = await readFile(new URL("../assets/app.js", import.meta.url), "utf8");
  assert.doesNotMatch(app, /if \(!state\.runtimeRevision\) return/);
  assert.match(app, /setInterval\(\(\) => synchronizeRevision\(\),[\s\S]*?await synchronizeRevision\(/);
  assert.match(app, /observeWorker\(registration\.installing\)[\s\S]*?updatefound/);
  assert.match(app, /new URL\(`service-worker\.js\?rev=\$\{encodeURIComponent\(revision\)\}`,[\s\S]*?register\(workerUrl\)/);

  const newRevision = `sha256-${"b".repeat(64)}`;
  let attempts = 0;
  const options = {
    currentRevision: null,
    loadRevision: async () => newRevision,
    registerRevision: async revision => {
      attempts++;
      assert.equal(revision, newRevision);
      if (attempts === 1) throw new Error("temporary registration failure");
    },
    updateRegistration: async () => assert.fail("the old registration must not be updated after a revision change")
  };
  await assert.rejects(Core.refreshServiceWorkerRevision(options), /temporary registration failure/);
  assert.equal(options.currentRevision, null, "an initial failed registration must not commit the new revision");
  assert.equal(await Core.refreshServiceWorkerRevision(options), newRevision);
  assert.equal(attempts, 2, "the changed worker URL must be retried on the next poll");
});

test("service-worker revision waits resolve installed candidates and reject redundant ones", async () => {
  const eventTarget = () => {
    const listeners = new Map();
    return {
      addEventListener(type, listener) { listeners.set(type, listener); },
      removeEventListener(type, listener) { if (listeners.get(type) === listener) listeners.delete(type); },
      dispatch(type) { listeners.get(type)?.(); }
    };
  };
  const scriptURL = "https://example.test/service-worker.js?rev=sha256-current";
  const registration = { ...eventTarget(), installing: null, waiting: null, active: null };
  const installing = { ...eventTarget(), scriptURL, state: "installing" };
  registration.installing = installing;
  const installed = Core.waitForServiceWorkerRevision(registration, scriptURL, 100);
  installing.state = "installed";
  installing.dispatch("statechange");
  assert.equal(await installed, installing);

  const redundant = { ...eventTarget(), scriptURL, state: "redundant" };
  registration.installing = redundant;
  await assert.rejects(
    Core.waitForServiceWorkerRevision(registration, scriptURL, 100),
    /became redundant before installation/
  );
});

test("workflow stages are stable and legacy section titles route to the right stage", () => {
  assert.deepEqual(Core.STAGES.map(stage => stage.id), ["overview", "detect", "hunt", "validate", "respond", "reference"]);
  Core.STAGES.forEach(stage => {
    assert.ok(stage.label && stage.hint, `${stage.id} needs a label and hint`);
  });
  // Legacy v3 content_sections are matched by title, so these mappings must not drift.
  const expected = {
    "Technique Mapping": "overview",
    "Log Source Mapping": "detect",
    "Detection Logic": "detect",
    "Incident Response Playbook": "respond",
    "Automation Opportunities": "respond",
    "IR Playbook": "respond"
  };
  Object.entries(expected).forEach(([title, stage]) => {
    assert.equal(Core.stageForSection({ title }), stage, `"${title}" must route to ${stage}`);
  });
  // Anything unrecognised must land somewhere real rather than vanishing.
  const ids = new Set(Core.STAGES.map(stage => stage.id));
  assert.ok(ids.has(Core.stageForSection({ title: "Something entirely new" })));
  assert.ok(ids.has(Core.stageForSection({})));
});

test("analyst brief and hunt workflow surface data without inventing it", () => {
  const playbook = Core.normalizeDataset(contractDataset()).playbooks[0];
  const brief = Core.playbookBrief(playbook);
  assert.equal(brief.telemetryCount, 1);
  assert.equal(brief.queryCount, 1);
  assert.equal(brief.requiredCount, 1, "the fixture declares one required source");
  assert.deepEqual(brief.requiredSources, ["Endpoint process telemetry"]);
  assert.ok(brief.firstMoves.length >= 1 && brief.firstMoves[0].length > 0);
  assert.equal(brief.validationStatus, "validated");

  const hunt = Core.huntWorkflow(playbook);
  assert.match(hunt.hypothesis, /adversary using a command interpreter/i);
  assert.equal(hunt.pivots.length, 1);
  assert.equal(hunt.pivots[0].title, "Build a UTC timeline and inspect identity, endpoint, and network evidence.");

  // An empty record must degrade to empty structures, never throw or fabricate.
  const blank = Core.playbookBrief({});
  assert.equal(blank.telemetryCount, 0);
  assert.deepEqual(blank.firstMoves, []);
  assert.deepEqual(Core.huntWorkflow({}).pivots, []);
});

test("brief, hunt, Markdown, and numeric search preserve exact structured evidence", () => {
  const enriched = contractPlaybook({
    telemetry_requirements: [{
      ...contractPlaybook().telemetry_requirements[0],
      event_ids: [
        { provider: "Windows Security", id: "4688", provenance: "attack-v19.1-verified" },
        { provider: "Legacy", id: "4104", provenance: "legacy-authored-unverified" }
      ]
    }],
    detection: {
      ...contractPlaybook().detection,
      strategies: [{ id: "behavior", logic: "Correlate the exact process lineage." }],
      false_positives: [{ cause: "Approved administration.", distinguishing_evidence: "A linked change ticket and expected parent process." }]
    },
    content_sections: [{ id: "overview", title: "Overview", blocks: [null, { type: "text", text: "Legacy analyst rationale." }] }]
  });
  const normalized = Core.normalizeDataset(contractDataset([enriched])).playbooks[0];
  assert.equal(Core.playbookBrief(normalized).verifiedEventIds, 1);
  const hunt = Core.huntWorkflow(normalized);
  assert.match(hunt.falsePositives[0], /Approved administration/);
  assert.match(hunt.falsePositives[0], /linked change ticket/);
  assert.match(hunt.leads[0].signals[0], /exact process lineage/);
  const markdown = Core.serializePlaybookMarkdown(normalized);
  assert.match(markdown, /Legacy analyst rationale/);
  assert.match(markdown, /## Telemetry requirements/);

  const hashOnly = contractPlaybook({
    id: "T1110", name: "Hash-only digits", techniques: [{ id: "T1110", name: "Brute Force" }],
    subtechniques: [], threat_groups: [], search_terms: ["T1110", "hash", "abc4778def"],
    telemetry_requirements: [{ ...contractPlaybook().telemetry_requirements[0], event_ids: [] }],
    description: "Detect a synthetic hash value that contains digits but does not cite the corresponding event identifier.",
    url: "https://attack.mitre.org/techniques/T1110/"
  });
  const searchable = Core.normalizeDataset(contractDataset([enriched, hashOnly])).playbooks;
  const index = Core.buildSearchIndex(searchable);
  assert.deepEqual(Core.filterAndSortPlaybooks(searchable, { query: "4688" }, index).map(item => item.id), ["T1059"]);
  assert.deepEqual(Core.filterAndSortPlaybooks(searchable, { query: "4778" }, index), []);
  assert.equal(Core.playbookBrief({}).validationStatus, "missing");
});

test("wrapText breaks on words, bounds line count, and marks truncation", () => {
  assert.deepEqual(Core.wrapText("alpha beta gamma", 11), ["alpha beta", "gamma"]);
  assert.deepEqual(Core.wrapText("   spaced\n\nout   text ", 40), ["spaced out text"]);
  assert.deepEqual(Core.wrapText("", 20), []);
  const bounded = Core.wrapText("one two three four five six seven eight nine ten", 9, 2);
  assert.equal(bounded.length, 2);
  assert.ok(bounded.at(-1).endsWith("…"), "a truncated wrap must be marked with an ellipsis");
  const [longWord] = Core.wrapText("supercalifragilistic", 10, 1);
  assert.equal(longWord.length, 10, "an unbreakable word is clipped to the line budget");
});

test("flowchart layout is deterministic, bounded, and free of overlapping nodes", () => {
  const playbook = Core.normalizeDataset(contractDataset([contractPlaybook({
    response: {
      ...responseWorkflow(),
      decision_tree: [
        { condition: "Does evidence confirm the technique?", if_true: "Scope all linked entities.", if_false: "Document the benign evidence." },
        { condition: "Is activity ongoing or destructive?", if_true: "Use approved immediate containment.", if_false: "Run a bounded investigation first." },
        { condition: "Is evidence isolated to one entity?", if_true: "Continue standard handling.", if_false: "Treat as a campaign." },
        { condition: "Can integrity be proven after remediation?", if_true: "Recover with monitoring.", if_false: "Rebuild from a verified source." }
      ]
    }
  })])).playbooks[0];

  const model = Core.buildFlowchart(playbook);
  assert.deepEqual(model, Core.buildFlowchart(playbook), "layout must be deterministic");
  assert.ok(model.width > 0 && model.height > 0);
  assert.match(model.summary, /^Incident response flow for T1059/);

  const kinds = model.nodes.reduce((all, node) => ({ ...all, [node.kind]: (all[node.kind] || 0) + 1 }), {});
  assert.equal(kinds.decision, 4, "one gate per decision-tree entry");
  assert.equal(kinds.branch, 4, "every gate exposes its 'no' outcome");
  assert.equal(kinds.phase, 6);
  assert.equal(kinds.start, 1);
  assert.equal(kinds.end, 1);

  model.nodes.forEach(node => {
    assert.ok(node.x >= 0 && node.y >= 0 && node.x + node.w <= model.width && node.y + node.h <= model.height, `${node.id} must stay on canvas`);
    const padding = node.kind === "decision" ? model.metrics.decisionPadding : model.metrics.padding;
    const used = node.lines.reduce((total, line) => total + (line.kind === "title" ? model.metrics.titleHeight : model.metrics.lineHeight), 0);
    assert.ok(padding * 2 + used <= node.h + 0.01, `${node.id} must be tall enough for its text`);
  });

  const overlaps = model.nodes.flatMap((a, index) => model.nodes.slice(index + 1)
    .filter(b => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h)
    .map(b => `${a.id}/${b.id}`));
  assert.deepEqual(overlaps, [], "nodes must not overlap");

  const ids = new Set(model.nodes.map(node => node.id));
  model.edges.forEach(edge => {
    assert.ok(ids.has(edge.from) && ids.has(edge.to), `edge ${edge.from}->${edge.to} must reference real nodes`);
  });
  assert.equal(model.edges.filter(edge => edge.label === "yes").length, 4);
  assert.equal(model.edges.filter(edge => edge.label === "no").length, 4);
});

test("flowchart degrades safely when a playbook has no structured decision tree", () => {
  const playbook = Core.normalizeDataset(contractDataset()).playbooks[0];
  const model = Core.buildFlowchart(playbook);
  assert.equal(model.nodes.filter(node => node.kind === "decision").length, 0);
  assert.ok(model.nodes.some(node => node.kind === "start") && model.nodes.some(node => node.kind === "end"));
  assert.equal(Core.buildFlowchart({}).nodes.length > 0, true, "an empty record must still produce a start and end");
});

test("content audit reports complete quality metrics for a valid contract fixture", () => {
  const { report, blockers } = auditDataset(contractDataset(), Date.parse("2026-07-12T00:00:00Z"));
  assert.equal(report.total_playbooks, 1);
  assert.equal(report.telemetry_mappings, 1);
  assert.equal(report.queries, 1);
  assert.equal(report.response_workflows_complete, 1);
  assert.deepEqual(blockers, []);
});
