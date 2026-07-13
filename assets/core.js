// TacticAtlas v4 — dependency-free, DOM-free application core.
(() => {
  "use strict";

  const TACTICS = Object.freeze([
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact"
  ]);
  const FILTER_KEYS = Object.freeze([
    "kind", "technique", "platform", "source", "severity", "maturity", "status"
  ]);
  const VIEWS = new Set(["matrix", "list", "table", "dashboard"]);
  const SORTS = new Set(["relevance", "id", "name", "quality", "severity"]);
  const KINDS = new Set(["all", "technique", "operational", "platform"]);
  const SEVERITY_ORDER = Object.freeze({ critical: 5, high: 4, medium: 3, low: 2, informational: 1, unknown: 0 });
  const MAX_QUERY_LENGTH = 240;
  const MAX_FILTER_LENGTH = 160;

  function text(value, fallback = "") {
    return typeof value === "string" ? value.trim() : value == null ? fallback : String(value).trim();
  }

  function number(value, fallback = 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function list(value, limit = 500) {
    if (!Array.isArray(value)) return [];
    const seen = new Set();
    const values = [];
    value.slice(0, limit).forEach(item => {
      const normalized = text(item);
      if (normalized && !seen.has(normalized)) {
        seen.add(normalized);
        values.push(normalized);
      }
    });
    return values;
  }

  function plain(value, depth = 0) {
    if (depth > 10 || value == null) return value == null ? null : text(value);
    if (["string", "number", "boolean"].includes(typeof value)) return value;
    if (Array.isArray(value)) return value.slice(0, 1000).map(item => plain(item, depth + 1));
    if (typeof value !== "object") return text(value);
    const output = {};
    Object.keys(value).slice(0, 500).forEach(key => {
      if (["__proto__", "prototype", "constructor", "html"].includes(key)) return;
      output[key] = plain(value[key], depth + 1);
    });
    return output;
  }

  function normalizeText(value) {
    return text(value)
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[\u2018\u2019]/g, "'")
      .replace(/[\u2013\u2014]/g, "-")
      .toLowerCase()
      .replace(/[^a-z0-9._:/\\@+\-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function tokenizeQuery(value) {
    const query = text(value).slice(0, MAX_QUERY_LENGTH);
    const tokens = [];
    const pattern = /"([^"]+)"|(\S+)/g;
    let match;
    while ((match = pattern.exec(query)) && tokens.length < 16) {
      const token = normalizeText(match[1] || match[2]);
      if (token && !tokens.includes(token)) tokens.push(token);
    }
    return tokens;
  }

  function slugify(value) {
    return normalizeText(value).replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "item";
  }

  function safeHttpUrl(value) {
    const raw = text(value);
    if (!raw || raw.length > 2048) return null;
    try {
      const url = new URL(raw);
      return url.protocol === "https:" ? url.href : null;
    } catch {
      return null;
    }
  }

  function safeDecodeHash(value) {
    const raw = text(value).replace(/^#/, "");
    if (!raw || raw.length > 256) return null;
    try {
      const decoded = decodeURIComponent(raw);
      return /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(decoded) ? decoded : null;
    } catch {
      return null;
    }
  }

  function normalizeNamedItems(value) {
    if (!Array.isArray(value)) return [];
    return value.slice(0, 500).map(item => {
      if (typeof item === "string") return { id: text(item), name: text(item) };
      return { ...(plain(item) || {}), id: text(item?.id), name: text(item?.name || item?.id) };
    }).filter(item => item.id || item.name);
  }

  function normalizeTelemetry(value) {
    if (!Array.isArray(value)) return [];
    const arrayFields = [
      "event_types", "event_ids", "raw_fields", "normalized_fields", "mappings", "correlation_fields",
      "prerequisites", "audit_policy", "blind_spots", "data_quality", "time_sync", "normalization",
      "health", "example_products", "detection_relevance", "investigation_relevance", "evidence_value"
    ];
    return value.slice(0, 500).map((source, index) => {
      const item = {
        ...(plain(source) || {}),
        id: text(source?.id || `source-${index + 1}`),
        priority: text(source?.priority || source?.tier || "recommended").toLowerCase(),
        tier: text(source?.tier || source?.priority || "recommended").toLowerCase(),
        category: text(source?.category || "Other"),
        retention: plain(source?.retention),
        latency: plain(source?.latency)
      };
      arrayFields.forEach(key => {
        const field = source?.[key];
        item[key] = Array.isArray(field) ? field.slice(0, 1000).map(entry => plain(entry)) : field == null || field === "" ? [] : [plain(field)];
      });
      return item;
    });
  }

  function normalizeQueries(value) {
    if (!Array.isArray(value)) return [];
    return value.slice(0, 500).map((query, index) => ({
      ...(plain(query) || {}),
      id: text(query?.id || `query-${index + 1}`),
      name: text(query?.name || query?.title || `Query ${index + 1}`),
      platform: text(query?.platform || query?.product || "Vendor-neutral"),
      language: text(query?.language || query?.type || "text"),
      query: text(query?.query || query?.code || query?.text),
      description: text(query?.description),
      adaptation_required: plain(query?.adaptation_required),
      adaptation_notes: plain(query?.adaptation_notes || query?.notes) || [],
      prerequisites: plain(query?.prerequisites) || [],
      fields: plain(query?.fields || query?.required_fields) || [],
      required_fields: plain(query?.required_fields || query?.fields) || [],
      telemetry_ids: list(query?.telemetry_ids),
      limitations: plain(query?.limitations) || [],
      assumptions: plain(query?.assumptions) || []
    })).filter(query => query.query || query.description);
  }

  function normalizeReferences(value) {
    if (!Array.isArray(value)) return [];
    return value.slice(0, 500).map(reference => {
      if (typeof reference === "string") {
        const url = safeHttpUrl(reference);
        return url ? { title: url, url } : { title: text(reference), url: null };
      }
      return {
        ...(plain(reference) || {}),
        title: text(reference?.title || reference?.name || reference?.url || "Reference"),
        url: safeHttpUrl(reference?.url)
      };
    });
  }

  function normalizePlaybook(source, index) {
    const item = plain(source) || {};
    const id = text(item.id);
    const name = text(item.name);
    if (!id || !name) throw new Error(`Playbook ${index + 1} is missing a valid id or name.`);
    const quality = Math.max(0, Math.min(100, number(item.quality_score, 0)));
    return {
      ...item,
      schema_version: text(item.schema_version || "4.0.0"),
      id,
      name,
      kind: ["technique", "operational", "platform"].includes(item.kind) ? item.kind : "technique",
      description: text(item.description),
      tactics: list(item.tactics),
      tactic_mappings: Array.isArray(item.tactic_mappings) ? item.tactic_mappings.slice(0, 100).map(mapping => plain(mapping)) : [],
      techniques: normalizeNamedItems(item.techniques),
      subtechniques: normalizeNamedItems(item.subtechniques),
      platforms: list(item.platforms),
      data_sources: plain(item.data_sources) || [],
      data_source_summary: text(item.data_source_summary),
      telemetry_requirements: normalizeTelemetry(item.telemetry_requirements),
      detection: plain(item.detection) || {},
      queries: normalizeQueries(item.queries),
      validation: plain(item.validation) || {},
      response: plain(item.response) || {},
      lifecycle: plain(item.lifecycle) || {},
      references: normalizeReferences(item.references),
      known_gaps: plain(item.known_gaps) || [],
      tags: list(item.tags),
      severity: text(item.severity || "unknown").toLowerCase(),
      confidence: text(item.confidence || "unknown").toLowerCase(),
      maturity: text(item.maturity || "unknown"),
      status: text(item.status || "unknown").toLowerCase(),
      quality_score: quality,
      quality_breakdown: plain(item.quality_breakdown) || {},
      coverage: plain(item.coverage) || {},
      content_sections: Array.isArray(item.content_sections) ? item.content_sections.slice(0, 100).map(section => plain(section)) : [],
      search_terms: list(item.search_terms, 2000),
      url: safeHttpUrl(item.url)
    };
  }

  function normalizeDataset(value) {
    if (!value || typeof value !== "object" || !Array.isArray(value.playbooks)) {
      throw new Error("The playbook dataset has an invalid structure.");
    }
    const meta = plain(value.meta) || {};
    const schemaVersion = text(meta.schema_version);
    const contentVersion = text(meta.content_version);
    if (schemaVersion !== "4.0.0" || contentVersion !== "4.0.0") {
      throw new Error(`Unsupported dataset version ${schemaVersion || "unknown"}/${contentVersion || "unknown"}; v4.0.0 is required.`);
    }
    const seen = new Set();
    const playbooks = value.playbooks.map(normalizePlaybook);
    playbooks.forEach(playbook => {
      if (seen.has(playbook.id)) throw new Error(`Duplicate playbook ID: ${playbook.id}`);
      seen.add(playbook.id);
    });
    return {
      meta: {
        ...meta,
        schema_version: schemaVersion,
        content_version: contentVersion,
        generated: text(meta.generated || meta.last_updated),
        tactic_order: list(meta.tactic_order).length ? list(meta.tactic_order) : [...TACTICS]
      },
      playbooks
    };
  }

  function flattenStrings(value, output = [], depth = 0) {
    if (depth > 9 || value == null) return output;
    if (["string", "number", "boolean"].includes(typeof value)) {
      output.push(String(value));
    } else if (Array.isArray(value)) {
      value.forEach(item => flattenStrings(item, output, depth + 1));
    } else if (typeof value === "object") {
      Object.keys(value).forEach(key => {
        if (!key.startsWith("_") && key !== "content_sections") flattenStrings(value[key], output, depth + 1);
      });
      if (Array.isArray(value.content_sections)) flattenStrings(value.content_sections, output, depth + 1);
    }
    return output;
  }

  function buildSearchIndex(playbooks) {
    const index = new Map();
    playbooks.forEach(playbook => {
      const name = normalizeText(playbook.name);
      const id = normalizeText(playbook.id);
      const tactics = normalizeText(playbook.tactics.join(" "));
      const platforms = normalizeText(playbook.platforms.join(" "));
      const sources = normalizeText(playbook.telemetry_requirements.flatMap(source => [source.id, source.category, ...flattenStrings(source.example_products)]).join(" "));
      const haystack = normalizeText(flattenStrings(playbook).join(" "));
      index.set(playbook.id, {
        id, name, tactics, platforms, sources, haystack,
        words: [...new Set(haystack.split(" ").filter(word => word.length > 1))]
      });
    });
    return index;
  }

  function editDistanceWithin(a, b, limit) {
    if (Math.abs(a.length - b.length) > limit) return false;
    let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
    for (let i = 1; i <= a.length; i++) {
      const current = [i];
      let rowMin = current[0];
      for (let j = 1; j <= b.length; j++) {
        const value = Math.min(
          current[j - 1] + 1,
          previous[j] + 1,
          previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
        );
        current[j] = value;
        rowMin = Math.min(rowMin, value);
      }
      if (rowMin > limit) return false;
      previous = current;
    }
    return previous[b.length] <= limit;
  }

  function fuzzyWordMatch(words, token) {
    if (token.length < 4 || token.includes(" ")) return false;
    const limit = token.length >= 8 ? 2 : 1;
    return words.some(word => word.startsWith(token) || (word.length >= 4 && editDistanceWithin(word, token, limit)));
  }

  function rankPlaybook(playbook, queryOrTokens, searchIndex) {
    const tokens = Array.isArray(queryOrTokens) ? queryOrTokens : tokenizeQuery(queryOrTokens);
    if (!tokens.length) return 0;
    const entry = searchIndex instanceof Map ? searchIndex.get(playbook.id) : searchIndex;
    if (!entry) return -1;
    let score = 0;
    for (const token of tokens) {
      const inHaystack = entry.haystack.includes(token);
      if (!inHaystack && !fuzzyWordMatch(entry.words, token)) return -1;
      if (entry.id === token) score += 160;
      else if (entry.id.startsWith(token)) score += 110;
      if (entry.name === token) score += 100;
      else if (entry.name.startsWith(token)) score += 55;
      else if (entry.name.includes(token)) score += 38;
      if (entry.tactics.includes(token)) score += 18;
      if (entry.platforms.includes(token)) score += 16;
      if (entry.sources.includes(token)) score += 14;
      score += inHaystack ? 8 : 3;
    }
    return score;
  }

  function selectedValues(value) {
    if (value instanceof Set) return [...value];
    if (Array.isArray(value)) return value;
    return value && value !== "all" ? [value] : [];
  }

  function matchesFilter(playbook, state) {
    const kind = text(state.kind || state.filters?.kind || "all");
    if (kind !== "all" && playbook.kind !== kind) return false;
    if (state.favoritesOnly && !selectedValues(state.favoriteIds).includes(playbook.id)) return false;
    if (state.recentOnly && !selectedValues(state.recentIds).includes(playbook.id)) return false;

    const tactics = selectedValues(state.tactics || state.filters?.tactics);
    if (tactics.length && !playbook.tactics.some(tactic => tactics.includes(tactic))) return false;

    const technique = text(state.technique || state.filters?.technique || "all");
    if (technique !== "all") {
      const values = [playbook.id, ...playbook.techniques.flatMap(item => [item.id, item.name]), ...playbook.subtechniques.flatMap(item => [item.id, item.name])];
      if (!values.includes(technique)) return false;
    }

    const platform = text(state.platform || state.filters?.platform || "all");
    if (platform !== "all" && !playbook.platforms.includes(platform)) return false;

    const source = text(state.source || state.filters?.source || "all");
    if (source !== "all" && !playbook.telemetry_requirements.some(item => item.category === source || item.id === source)) return false;

    for (const key of ["severity", "maturity", "status"]) {
      const expected = text(state[key] || state.filters?.[key] || "all").toLowerCase();
      if (expected !== "all" && text(playbook[key]).toLowerCase() !== expected) return false;
    }
    return true;
  }

  function numericId(value) {
    const match = text(value).match(/\d+/);
    return match ? Number(match[0]) : Number.MAX_SAFE_INTEGER;
  }

  function filterAndSortPlaybooks(playbooks, state = {}, searchIndex = new Map()) {
    const tokens = tokenizeQuery(state.query);
    const scores = new Map();
    const filtered = playbooks.filter(playbook => {
      if (!matchesFilter(playbook, state)) return false;
      const score = rankPlaybook(playbook, tokens, searchIndex);
      scores.set(playbook.id, score);
      return score >= 0;
    });
    const sort = SORTS.has(state.sort) ? state.sort : tokens.length ? "relevance" : "id";
    return filtered.sort((a, b) => {
      if (sort === "relevance") return (scores.get(b.id) || 0) - (scores.get(a.id) || 0) || numericId(a.id) - numericId(b.id) || a.id.localeCompare(b.id);
      if (sort === "name") return a.name.localeCompare(b.name);
      if (sort === "quality") return b.quality_score - a.quality_score || a.name.localeCompare(b.name);
      if (sort === "severity") return (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0) || b.quality_score - a.quality_score;
      return numericId(a.id) - numericId(b.id) || a.id.localeCompare(b.id);
    });
  }

  function limitedParam(params, name, allowed) {
    const value = text(params.get(name)).slice(0, MAX_FILTER_LENGTH);
    return !value || (allowed && !allowed.has(value)) ? "all" : value;
  }

  function decodeUrlState(search = "", hash = "") {
    const params = new URLSearchParams(text(search).replace(/^\?/, ""));
    const view = limitedParam(params, "view", VIEWS);
    const sort = limitedParam(params, "sort", SORTS);
    const state = {
      query: text(params.get("q")).slice(0, MAX_QUERY_LENGTH),
      view: view === "all" ? "matrix" : view,
      sort: sort === "all" ? "id" : sort,
      kind: limitedParam(params, "kind", KINDS),
      technique: limitedParam(params, "technique"),
      platform: limitedParam(params, "platform"),
      source: limitedParam(params, "source"),
      severity: limitedParam(params, "severity"),
      maturity: limitedParam(params, "maturity"),
      status: limitedParam(params, "status"),
      tactics: params.getAll("tactic").flatMap(value => value.split(",")).map(value => text(value).slice(0, MAX_FILTER_LENGTH)).filter(Boolean).slice(0, 20),
      favoritesOnly: params.get("saved") === "1",
      recentOnly: params.get("recent") === "1",
      openId: safeDecodeHash(hash)
    };
    return state;
  }

  function encodeUrlState(state = {}, pathname = "") {
    const params = new URLSearchParams();
    const set = (name, value, defaultValue = "all") => {
      const normalized = text(value);
      if (normalized && normalized !== defaultValue) params.set(name, normalized.slice(0, MAX_FILTER_LENGTH));
    };
    if (state.query) params.set("q", text(state.query).slice(0, MAX_QUERY_LENGTH));
    set("view", state.view, "matrix");
    set("sort", state.sort, "id");
    set("kind", state.kind);
    set("technique", state.technique);
    set("platform", state.platform);
    set("source", state.source);
    set("severity", state.severity);
    set("maturity", state.maturity);
    set("status", state.status);
    selectedValues(state.tactics).slice(0, 20).forEach(tactic => params.append("tactic", text(tactic).slice(0, MAX_FILTER_LENGTH)));
    if (state.favoritesOnly) params.set("saved", "1");
    if (state.recentOnly) params.set("recent", "1");
    const query = params.toString();
    const hashId = safeDecodeHash(state.openId || "");
    return `${pathname || ""}${query ? `?${query}` : ""}${hashId ? `#${encodeURIComponent(hashId)}` : ""}`;
  }

  function markdownValue(value, depth = 0) {
    if (value == null || value === "") return "";
    if (["string", "number", "boolean"].includes(typeof value)) return String(value);
    if (Array.isArray(value)) return value.map(item => `${"  ".repeat(depth)}- ${markdownValue(item, depth + 1)}`).join("\n");
    return Object.entries(value).map(([key, item]) => `- **${key.replaceAll("_", " ")}**: ${markdownValue(item, depth + 1)}`).join("\n");
  }

  function markdownBlock(block) {
    if (typeof block === "string") return block;
    const type = text(block?.type).toLowerCase();
    if (["code", "query"].includes(type)) return `\`\`\`${text(block.language)}\n${text(block.code || block.query || block.text)}\n\`\`\``;
    if (["list", "steps"].includes(type)) {
      const ordered = block.ordered || type === "steps";
      return (Array.isArray(block.items) ? block.items : []).map((item, index) => `${ordered ? `${index + 1}.` : "-"} ${markdownValue(item)}`).join("\n");
    }
    if (type === "table" && Array.isArray(block.rows)) {
      const columns = Array.isArray(block.columns) ? block.columns.map(column => ({ key: text(column?.key), label: text(column?.label || column?.key) })) : (block.headers || []).map(header => ({ key: text(header), label: text(header) }));
      const labels = columns.map(column => column.label);
      return `| ${labels.join(" | ")} |\n| ${labels.map(() => "---").join(" | ")} |\n${block.rows.map(row => `| ${(Array.isArray(row) ? row : columns.map(column => row?.[column.key])).map(markdownValue).join(" | ")} |`).join("\n")}`;
    }
    if (type === "key_value") return (block.items || []).map(item => `- **${text(item?.label)}:** ${markdownValue(item?.value)}`).join("\n");
    if (type === "callout") return `${block.title ? `**${text(block.title)}**\n\n` : ""}${text(block.text)}`;
    return markdownValue(block.text || block.value || block.items || block.entries || block);
  }

  function serializePlaybookMarkdown(playbook) {
    const lines = [
      `# ${playbook.id}: ${playbook.name}`,
      "",
      playbook.description,
      "",
      `- **Kind:** ${playbook.kind}`,
      `- **Tactics:** ${playbook.tactics.join(", ") || "Not specified"}`,
      `- **Platforms:** ${playbook.platforms.join(", ") || "Not specified"}`,
      `- **Severity:** ${playbook.severity}`,
      `- **Confidence:** ${playbook.confidence}`,
      `- **Maturity:** ${playbook.maturity}`,
      `- **Status:** ${playbook.status}`,
      `- **Quality score:** ${playbook.quality_score}/100`,
      ""
    ];
    if (playbook.content_sections.length) {
      playbook.content_sections.forEach(section => {
        lines.push(`## ${text(section.title || section.id)}`, "");
        (Array.isArray(section.blocks) ? section.blocks : []).forEach(block => lines.push(markdownBlock(block), ""));
      });
    } else {
      lines.push("## Telemetry requirements", "", markdownValue(playbook.telemetry_requirements), "");
      lines.push("## Detection", "", markdownValue(playbook.detection), "");
      lines.push("## Queries", "", markdownValue(playbook.queries), "");
      lines.push("## Validation", "", markdownValue(playbook.validation), "");
      lines.push("## Incident response", "", markdownValue(playbook.response), "");
      lines.push("## Lifecycle", "", markdownValue(playbook.lifecycle), "");
    }
    return lines.filter((line, index, all) => line !== "" || all[index - 1] !== "").join("\n").trim() + "\n";
  }

  function exportRecord(playbook) {
    return plain(playbook);
  }

  function serializePlaybooksJson(playbooks, meta = {}) {
    return JSON.stringify({ meta: plain(meta), playbooks: playbooks.map(exportRecord) }, null, 2) + "\n";
  }

  function formulaSafe(value) {
    const string = value == null ? "" : String(value);
    return /^[\t\r ]*[=+\-@]/.test(string) ? `'${string}` : string;
  }

  function escapeCsvCell(value) {
    const safe = formulaSafe(Array.isArray(value) ? value.join("; ") : value);
    return /[",\r\n]/.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
  }

  function validationStatus(playbook) {
    return text(playbook.validation?.status || playbook.coverage?.validation_status || (playbook.validation && Object.keys(playbook.validation).length ? "documented" : "missing"));
  }

  function serializeCoverageCsv(playbooks) {
    const headers = [
      "id", "name", "kind", "tactics", "platforms", "data_sources", "severity", "confidence", "maturity",
      "status", "quality_score", "telemetry_requirements", "queries", "validation_status", "last_reviewed"
    ];
    const rows = playbooks.map(playbook => [
      playbook.id, playbook.name, playbook.kind, playbook.tactics, playbook.platforms,
      playbook.telemetry_requirements.map(source => source.category), playbook.severity, playbook.confidence,
      playbook.maturity, playbook.status, playbook.quality_score, playbook.telemetry_requirements.length,
      playbook.queries.length, validationStatus(playbook), playbook.lifecycle?.last_reviewed || playbook.lifecycle?.last_validation_date || ""
    ]);
    return [headers, ...rows].map(row => row.map(escapeCsvCell).join(",")).join("\r\n") + "\r\n";
  }

  function safeFilename(value, extension = "") {
    const base = slugify(text(value).slice(0, 120)).slice(0, 80) || "playbooks";
    const ext = text(extension).replace(/[^a-z0-9]/gi, "").toLowerCase();
    return `${base}${ext ? `.${ext}` : ""}`;
  }

  function increment(map, key) {
    const label = text(key || "Unknown");
    map[label] = (map[label] || 0) + 1;
  }

  function daysSince(value, now = Date.now()) {
    const time = Date.parse(text(value));
    return Number.isFinite(time) ? Math.floor((now - time) / 86400000) : null;
  }

  function responseComplete(playbook) {
    const required = ["triage", "investigation", "scoping", "containment", "eradication", "recovery", "post_incident", "escalation", "decision_tree", "closure_criteria"];
    return required.every(key => {
      const value = playbook.response?.[key];
      return Array.isArray(value) ? value.length > 0 : value && (typeof value !== "object" || Object.keys(value).length > 0);
    });
  }

  function qualitySummary(playbooks) {
    const total = playbooks.length;
    const sum = playbooks.reduce((value, playbook) => value + playbook.quality_score, 0);
    return {
      total,
      average: total ? Math.round((sum / total) * 10) / 10 : 0,
      excellent: playbooks.filter(playbook => playbook.quality_score >= 90).length,
      good: playbooks.filter(playbook => playbook.quality_score >= 75 && playbook.quality_score < 90).length,
      needsWork: playbooks.filter(playbook => playbook.quality_score < 75).length
    };
  }

  function coverageSummary(playbooks, now = Date.now()) {
    const output = {
      total: playbooks.length,
      withTelemetry: 0,
      withQueries: 0,
      withValidation: 0,
      responseComplete: 0,
      stale: 0,
      highRiskGaps: 0,
      byTactic: {},
      byPlatform: {},
      bySource: {},
      bySeverity: {},
      byMaturity: {},
      byStatus: {},
      byValidation: {}
    };
    playbooks.forEach(playbook => {
      const telemetry = playbook.telemetry_requirements.length > 0;
      const queries = playbook.queries.length > 0;
      const validated = validationStatus(playbook) !== "missing";
      const complete = responseComplete(playbook);
      const age = daysSince(playbook.lifecycle?.last_reviewed || playbook.lifecycle?.last_validation_date, now);
      if (telemetry) output.withTelemetry++;
      if (queries) output.withQueries++;
      if (validated) output.withValidation++;
      if (complete) output.responseComplete++;
      if (age == null || age > 365) output.stale++;
      if (["critical", "high"].includes(playbook.severity) && (!telemetry || !queries || !validated || playbook.quality_score < 75)) output.highRiskGaps++;
      playbook.tactics.forEach(value => increment(output.byTactic, value));
      playbook.platforms.forEach(value => increment(output.byPlatform, value));
      [...new Set(playbook.telemetry_requirements.map(source => source.category))].forEach(value => increment(output.bySource, value));
      increment(output.bySeverity, playbook.severity);
      increment(output.byMaturity, playbook.maturity);
      increment(output.byStatus, playbook.status);
      increment(output.byValidation, validationStatus(playbook));
    });
    return output;
  }

  globalThis.PlaybookCore = Object.freeze({
    TACTICS,
    FILTER_KEYS,
    normalizeText,
    tokenizeQuery,
    slugify,
    safeHttpUrl,
    safeDecodeHash,
    normalizeDataset,
    buildSearchIndex,
    rankPlaybook,
    filterAndSortPlaybooks,
    encodeUrlState,
    decodeUrlState,
    serializePlaybookMarkdown,
    serializePlaybooksJson,
    serializeCoverageCsv,
    escapeCsvCell,
    safeFilename,
    qualitySummary,
    coverageSummary
  });
})();
