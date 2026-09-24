// TacticAtlas v4 — dependency-free, DOM-free application core.
(() => {
  "use strict";

  const TACTICS = Object.freeze([
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact"
  ]);
  const FILTER_KEYS = Object.freeze([
    "kind", "technique", "platform", "source", "severity", "maturity", "status", "group"
  ]);
  const VIEWS = new Set(["matrix", "list", "table", "dashboard"]);
  const SORTS = new Set(["relevance", "id", "name", "quality", "severity"]);
  const KINDS = new Set(["all", "technique", "operational", "platform"]);
  const SEVERITY_ORDER = Object.freeze({ critical: 5, high: 4, medium: 3, low: 2, informational: 1, unknown: 0 });
  const MAX_QUERY_LENGTH = 240;
  const MAX_FILTER_LENGTH = 160;
  // Anchored on both ends: "legacy-authored-unverified" also ends in "verified".
  const ATTACK_VERIFIED = /^attack-v\d+(?:\.\d+)*-verified$/i;

  function text(value, fallback = "") {
    return typeof value === "string" ? value.trim() : value == null ? fallback : String(value).trim();
  }

  function isAttackVerified(provenance) {
    return ATTACK_VERIFIED.test(text(provenance));
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
      threat_groups: list(item.threat_groups),
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
      maturity: Math.max(1, Math.min(4, Math.trunc(number(item.maturity, 1)))),
      status: text(item.status || "unknown").toLowerCase(),
      quality_score: quality,
      quality_breakdown: plain(item.quality_breakdown) || {},
      coverage: plain(item.coverage) || {},
      content_sections: Array.isArray(item.content_sections) ? item.content_sections.slice(0, 100).map(section => plain(section)) : [],
      search_terms: list(item.search_terms, 2000),
      url: safeHttpUrl(item.url)
    };
  }

  function normalizeGroups(value) {
    if (!Array.isArray(value)) return [];
    const seen = new Set();
    return value.slice(0, 2000).map(item => {
      const group = plain(item) || {};
      return {
        id: text(group.id),
        name: text(group.name || group.id),
        aliases: list(group.aliases, 100),
        url: safeHttpUrl(group.url)
      };
    }).filter(group => group.id && group.name && !seen.has(group.id) && seen.add(group.id));
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
      groups: normalizeGroups(value.groups),
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

  function buildSearchIndex(playbooks, groups = []) {
    const groupsById = new Map(groups.map(group => [group.id, group]));
    const index = new Map();
    playbooks.forEach(playbook => {
      const name = normalizeText(playbook.name);
      const id = normalizeText(playbook.id);
      const tactics = normalizeText(playbook.tactics.join(" "));
      const platforms = normalizeText(playbook.platforms.join(" "));
      const sources = normalizeText(playbook.telemetry_requirements.flatMap(source => [source.id, source.category, ...flattenStrings(source.example_products)]).join(" "));
      const groupText = playbook.threat_groups.flatMap(groupId => {
        const group = groupsById.get(groupId);
        return group ? [group.id, group.name, ...group.aliases] : [groupId];
      }).join(" ");
      const threatGroups = normalizeText(groupText);
      const haystack = normalizeText(`${flattenStrings(playbook).join(" ")} ${groupText}`);
      const haystackWords = haystack.split(" ").filter(Boolean);
      index.set(playbook.id, {
        id, name, tactics, platforms, sources, threatGroups, haystack,
        words: [...new Set(haystackWords.filter(word => word.length > 1))],
        numericTokens: [...new Set(haystackWords.filter(word => /^\d+$/.test(word)))]
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
    // Numeric tokens are event IDs, ports, and ticket codes. Edit-distance matching makes
    // 4104 collide with 4103/4105/4106, so identifiers match exactly or not at all.
    if (/^\d+$/.test(token)) return false;
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
      // Numbers are identifiers in this interface (event IDs, ports, case IDs, and so on).
      // Treating them as arbitrary substrings makes a query such as "4778" match an unrelated
      // SHA-256 value that merely contains those digits. Normal words intentionally retain the
      // forgiving substring behaviour used by the type-ahead search.
      const inHaystack = /^\d+$/.test(token)
        ? (entry.numericTokens || entry.words).includes(token)
        : entry.haystack.includes(token);
      if (!inHaystack && !fuzzyWordMatch(entry.words, token)) return -1;
      if (entry.id === token) score += 160;
      else if (entry.id.startsWith(token)) score += 110;
      if (entry.name === token) score += 100;
      else if (entry.name.startsWith(token)) score += 55;
      else if (entry.name.includes(token)) score += 38;
      if (entry.tactics.includes(token)) score += 18;
      if (entry.platforms.includes(token)) score += 16;
      if (entry.sources.includes(token)) score += 14;
      if (entry.threatGroups.includes(token)) score += 14;
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

    const group = text(state.group || state.filters?.group || "all");
    if (group !== "all" && !playbook.threat_groups.includes(group)) return false;

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

  const ALERT_STOP_WORDS = new Set([
    "alert", "event", "from", "have", "into", "with", "that", "this", "were", "when", "where",
    "host", "user", "process", "source", "destination", "detected", "activity", "security", "technique", "execution"
  ]);

  function eventIdentifiers(playbook) {
    return (Array.isArray(playbook?.telemetry_requirements) ? playbook.telemetry_requirements : [])
      .flatMap(source => (Array.isArray(source?.event_ids) ? source.event_ids : []))
      .map(reference => ({
        id: text(typeof reference === "string" ? reference : reference?.id),
        provenance: text(typeof reference === "object" ? reference?.provenance : ""),
        provider: text(typeof reference === "object" ? reference?.provider || reference?.product : "")
      }))
      .filter(reference => reference.id);
  }

  function confidenceProfile(playbook, now = Date.now()) {
    const mappings = Array.isArray(playbook?.tactic_mappings) ? playbook.tactic_mappings : [];
    const mappingVerified = mappings.filter(mapping => mapping?.verified === true
      || text(mapping?.status).toLowerCase() === "verified"
      || isAttackVerified(mapping?.provenance)).length;
    const identifiers = eventIdentifiers(playbook);
    const eventVerified = identifiers.filter(reference => isAttackVerified(reference.provenance)).length;
    const queries = Array.isArray(playbook?.queries) ? playbook.queries : [];
    const adaptationRequired = queries.filter(query => query?.adaptation_required !== false).length;
    const lastReviewed = text(playbook?.lifecycle?.last_reviewed || playbook?.lifecycle?.last_validation_date);
    return {
      completeness: Math.max(0, Math.min(100, number(playbook?.quality_score, 0))),
      mappings: { verified: mappingVerified, total: mappings.length },
      eventIds: { verified: eventVerified, total: identifiers.length },
      queries: { adaptationRequired, total: queries.length },
      validationStatus: validationStatus(playbook),
      lastReviewed,
      reviewAgeDays: daysSince(lastReviewed, now),
      knownGapCount: Array.isArray(playbook?.known_gaps) ? playbook.known_gaps.length : 0
    };
  }

  function environmentFit(playbook, selectedSources = []) {
    const selected = new Set(list(selectedSources, 100).map(normalizeText));
    const telemetry = Array.isArray(playbook?.telemetry_requirements) ? playbook.telemetry_requirements : [];
    const required = telemetry.filter(source => text(source?.tier || source?.priority).toLowerCase() === "required");
    const matches = source => [source?.id, source?.category, source?.source_name, source?.source_heading]
      .map(normalizeText).some(value => value && selected.has(value));
    const available = telemetry.filter(matches);
    const requiredAvailable = required.filter(matches);
    return {
      configured: selected.size > 0,
      available: available.length,
      total: telemetry.length,
      requiredAvailable: requiredAvailable.length,
      requiredTotal: required.length,
      missingRequired: required.filter(source => !matches(source)).map(source => text(source?.source_name || source?.id)).filter(Boolean)
    };
  }

  function investigationSuggestions(playbooks, alertText, selectedSources = [], searchIndex = new Map(), limit = 8) {
    const normalizedAlert = normalizeText(text(alertText).slice(0, 12000));
    if (!normalizedAlert) return [];
    const tokens = tokenizeQuery(normalizedAlert)
      .flatMap(token => token.split(" "))
      .filter(token => token.length >= 3 && !ALERT_STOP_WORDS.has(token))
      .slice(0, 80);
    const tokenSet = new Set(tokens);
    const alertIds = new Set((normalizedAlert.match(/\bt\d{4}(?:\.\d{3})?\b/g) || []).map(value => value.toUpperCase()));
    const alertNumbers = new Set((normalizedAlert.match(/\b\d{3,6}\b/g) || []));

    const candidates = (Array.isArray(playbooks) ? playbooks : []).map(playbook => {
      let score = 0;
      const basis = [];
      const techniqueIds = [playbook.id, ...playbook.techniques.map(item => item.id), ...playbook.subtechniques.map(item => item.id)]
        .map(value => text(value).toUpperCase()).filter(Boolean);
      const matchedTechnique = techniqueIds.find(id => alertIds.has(id));
      if (matchedTechnique) { score += matchedTechnique === playbook.id.toUpperCase() ? 240 : 190; basis.push(`Technique ${matchedTechnique}`); }

      const identifiers = eventIdentifiers(playbook);
      const matchedEvents = [...new Set(identifiers.filter(reference => alertNumbers.has(reference.id)).map(reference => reference.id))].slice(0, 3);
      if (matchedEvents.length) { score += 70 + (matchedEvents.length - 1) * 20; basis.push(`Event ${matchedEvents.join(", ")}`); }

      const namedTechniques = [...playbook.techniques, ...playbook.subtechniques]
        .map(item => normalizeText(item.name)).filter(value => value.length >= 4);
      const matchedTechniqueName = namedTechniques.find(value => normalizedAlert.includes(value));
      if (matchedTechniqueName && matchedTechniqueName !== normalizeText(playbook.name)) {
        score += 140;
        basis.push(`Technique name: ${matchedTechniqueName}`);
      }

      const nameTokens = normalizeText(playbook.name).split(" ").filter(token => token.length >= 4 && !ALERT_STOP_WORDS.has(token));
      const matchedNameTokens = nameTokens.filter(token => tokenSet.has(token));
      if (normalizedAlert.includes(normalizeText(playbook.name)) && normalizeText(playbook.name).length >= 5) {
        score += 120;
        basis.push(`Playbook name: ${playbook.name}`);
      } else if (matchedNameTokens.length >= 2) {
        score += matchedNameTokens.length * 32;
        basis.push(`Name match: ${matchedNameTokens.slice(0, 3).join(", ")}`);
      }

      const matchedSignals = [...new Set((Array.isArray(playbook.search_terms) ? playbook.search_terms : [])
        .map(normalizeText)
        .filter(signal => signal.length >= 4 && !/^t\d{4}(?:\.\d{3})?$/.test(signal) && !/^\d+$/.test(signal)
          && !ALERT_STOP_WORDS.has(signal) && normalizedAlert.includes(signal)))].slice(0, 4);
      if (matchedSignals.length) {
        score += Math.min(80, matchedSignals.length * 20);
        basis.push(`Signal match: ${matchedSignals.slice(0, 3).join(", ")}`);
      }

      const fit = environmentFit(playbook, selectedSources);
      if (fit.configured && fit.requiredTotal && fit.requiredAvailable === fit.requiredTotal) score += 20;
      return { id: playbook.id, score, basis, environment: fit };
    }).filter(result => result.score >= 45 && result.basis.length)
      .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
    const relativeFloor = (candidates[0]?.score || 0) * .58;
    return candidates.filter(result => result.score >= Math.max(45, relativeFloor))
      .slice(0, Math.max(1, Math.min(20, number(limit, 8))));
  }

  function investigationTasks(playbooks) {
    const tasks = [];
    const seen = new Set();
    const add = (playbook, type, value) => {
      const label = text(typeof value === "string" ? value : value?.action || value?.title || value?.name);
      if (!label) return;
      const key = `${playbook.id}:${type}:${slugify(label).slice(0, 80)}`;
      if (seen.has(key)) return;
      seen.add(key);
      tasks.push({ id: key, playbookId: playbook.id, type, label });
    };
    (Array.isArray(playbooks) ? playbooks : []).forEach(playbook => {
      (Array.isArray(playbook?.response?.triage) ? playbook.response.triage : []).slice(0, 3)
        .forEach(item => add(playbook, "triage", item));
      (Array.isArray(playbook?.telemetry_requirements) ? playbook.telemetry_requirements : [])
        .filter(source => text(source?.tier || source?.priority).toLowerCase() === "required")
        .slice(0, 3)
        .forEach(source => add(playbook, "evidence", `Confirm ${text(source?.source_name || source?.id)} is available and healthy.`));
    });
    return tasks.slice(0, 80);
  }

  function investigationGraph(investigation, playbooks = []) {
    const rootId = text(investigation?.id || "investigation");
    const nodes = [{ id: rootId, label: text(investigation?.title || "Alert"), type: "alert" }];
    const edges = [];
    const entities = investigation?.entities && typeof investigation.entities === "object" ? investigation.entities : {};
    Object.entries(entities).slice(0, 20).forEach(([kind, value]) => {
      const label = text(value).slice(0, 160);
      if (!label) return;
      const id = `entity:${slugify(kind)}:${slugify(label).slice(0, 60)}`;
      nodes.push({ id, label, type: "entity", kind: text(kind) });
      edges.push({ from: rootId, to: id, label: text(kind) });
    });
    (Array.isArray(playbooks) ? playbooks : []).slice(0, 20).forEach(playbook => {
      const id = `playbook:${playbook.id}`;
      nodes.push({ id, label: `${playbook.id} ${playbook.name}`, type: "playbook" });
      edges.push({ from: rootId, to: id, label: "suspected" });
    });
    return { nodes, edges };
  }

  function serializeInvestigationMarkdown(investigation, playbooks = [], tasks = []) {
    const title = text(investigation?.title || "Security investigation");
    const lines = [
      `# ${title}`,
      "",
      `- **Case ID:** ${text(investigation?.id || "Local case")}`,
      `- **Status:** ${text(investigation?.status || "active")}`,
      `- **Created:** ${text(investigation?.createdAt || "Not recorded")}`,
      `- **Updated:** ${text(investigation?.updatedAt || "Not recorded")}`,
      "",
      "## Alert",
      "",
      text(investigation?.alert || "No alert text recorded."),
      "",
      "## Entities",
      ""
    ];
    const entities = investigation?.entities && typeof investigation.entities === "object" ? investigation.entities : {};
    const entityRows = Object.entries(entities).filter(([, value]) => text(value));
    lines.push(...(entityRows.length ? entityRows.map(([key, value]) => `- **${text(key)}:** ${text(value)}`) : ["No entities recorded."]));
    lines.push("", "## Selected Playbooks", "");
    lines.push(...(playbooks.length ? playbooks.map(playbook => {
      const confidence = confidenceProfile(playbook);
      return `- **${playbook.id}: ${playbook.name}** - completeness ${confidence.completeness}/100; ${confidence.eventIds.verified}/${confidence.eventIds.total} ATT&CK-verified event IDs; validation ${confidence.validationStatus}`;
    }) : ["No playbooks selected."]));
    lines.push("", "## Checklist", "");
    const completed = investigation?.completed && typeof investigation.completed === "object" ? investigation.completed : {};
    lines.push(...(tasks.length ? tasks.map(task => `- [${completed[task.id] ? "x" : " "}] ${task.label} (${task.playbookId})`) : ["No checklist items generated."]));
    lines.push("", "## Analyst Notes", "", text(investigation?.notes || "No notes recorded."), "", "## Limitations", "", "Suggestions are based on text and identifier matches. They are not incident verdicts. Query validation records are local to this browser.", "");
    return lines.join("\n");
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
      group: limitedParam(params, "group"),
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
    set("group", state.group);
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
    if (block == null) return "";
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
    if (type === "key_value") return (Array.isArray(block.items) ? block.items : []).map(item => `- **${text(item?.label)}:** ${markdownValue(item?.value)}`).join("\n");
    if (type === "callout") return `${block.title ? `**${text(block.title)}**\n\n` : ""}${text(block.text)}`;
    return markdownValue(block.text || block.value || block.items || block.entries || block);
  }

  function serializePlaybookMarkdown(playbook) {
    const tactics = Array.isArray(playbook?.tactics) ? playbook.tactics : [];
    const platforms = Array.isArray(playbook?.platforms) ? playbook.platforms : [];
    const threatGroups = Array.isArray(playbook?.threat_groups) ? playbook.threat_groups : [];
    const lines = [
      `# ${text(playbook?.id)}: ${text(playbook?.name)}`,
      "",
      text(playbook?.description),
      "",
      `- **Kind:** ${text(playbook?.kind)}`,
      `- **Tactics:** ${tactics.join(", ") || "Not specified"}`,
      `- **Platforms:** ${platforms.join(", ") || "Not specified"}`,
      `- **Threat groups:** ${threatGroups.join(", ") || "None recorded"}`,
      `- **Severity:** ${text(playbook?.severity)}`,
      `- **Confidence:** ${text(playbook?.confidence)}`,
      `- **Maturity:** ${text(playbook?.maturity)}`,
      `- **Status:** ${text(playbook?.status)}`,
      `- **Quality score:** ${number(playbook?.quality_score, 0)}/100`,
      ""
    ];
    const contentSections = Array.isArray(playbook?.content_sections) ? playbook.content_sections : [];
    if (contentSections.length) {
      contentSections.forEach(section => {
        if (!section || typeof section !== "object") return;
        lines.push(`## ${text(section.title || section.id)}`, "");
        (Array.isArray(section?.blocks) ? section.blocks : []).forEach(block => {
          const rendered = markdownBlock(block);
          if (rendered) lines.push(rendered, "");
        });
      });
    }
    // Legacy prose remains useful context, but it is not a substitute for the canonical v4
    // structures. Always export both so enriched telemetry and operational guidance cannot
    // silently disappear simply because content_sections is populated.
    lines.push("## Telemetry requirements", "", markdownValue(playbook?.telemetry_requirements || []), "");
    lines.push("## Detection", "", markdownValue(playbook?.detection || {}), "");
    lines.push("## Queries", "", markdownValue(playbook?.queries || []), "");
    lines.push("## Validation", "", markdownValue(playbook?.validation || {}), "");
    lines.push("## Incident response", "", markdownValue(playbook?.response || {}), "");
    lines.push("## Lifecycle", "", markdownValue(playbook?.lifecycle || {}), "");
    return lines.filter((line, index, all) => line !== "" || all[index - 1] !== "").join("\n").trim() + "\n";
  }

  function exportRecord(playbook) {
    return plain(playbook);
  }

  function exportCounts(playbooks) {
    const counts = { total: playbooks.length, technique: 0, operational: 0, platform: 0 };
    playbooks.forEach(playbook => {
      if (Object.hasOwn(counts, playbook?.kind)) counts[playbook.kind]++;
    });
    return counts;
  }

  function exportGroupDirectory(playbooks, groups) {
    const directory = new Map(normalizeGroups(groups).map(group => [group.id, group]));
    const referenced = [];
    const seen = new Set();
    playbooks.forEach(playbook => {
      (Array.isArray(playbook?.threat_groups) ? playbook.threat_groups : []).forEach(groupId => {
        const id = text(groupId);
        if (id && !seen.has(id)) {
          seen.add(id);
          referenced.push(id);
        }
      });
    });
    return referenced.map(id => directory.get(id) || {
      id,
      name: id,
      aliases: [],
      url: `https://attack.mitre.org/groups/${encodeURIComponent(id)}/`
    });
  }

  function exportQualitySummary(playbooks) {
    const scores = playbooks.map(playbook => number(playbook?.quality_score, 0));
    const validation = {};
    const readiness = {};
    playbooks.forEach(playbook => {
      increment(validation, validationStatus(playbook));
      increment(readiness, playbook?.coverage?.telemetry_readiness || (playbook?.telemetry_requirements?.length ? "documented" : "missing"));
    });
    return {
      average: scores.length ? Math.round((scores.reduce((sum, score) => sum + score, 0) / scores.length) * 10) / 10 : 0,
      minimum: scores.length ? Math.min(...scores) : 0,
      maximum: scores.length ? Math.max(...scores) : 0,
      validation_status: validation,
      telemetry_readiness: readiness
    };
  }

  // Supported forms are (playbooks, meta, groups), (playbooks, { meta, groups }), and the
  // historical (playbooks, meta). The historical form receives safe ATT&CK group stubs for any
  // referenced IDs so its root remains self-contained; callers should pass the real directory
  // when names and aliases are available.
  function serializePlaybooksJson(playbooks, metaOrOptions = {}, groups = []) {
    const records = (Array.isArray(playbooks) ? playbooks : []).map(exportRecord);
    const wrapped = metaOrOptions && typeof metaOrOptions === "object"
      && metaOrOptions.meta && typeof metaOrOptions.meta === "object";
    const sourceMeta = plain(wrapped ? metaOrOptions.meta : metaOrOptions) || {};
    const sourceGroups = wrapped ? metaOrOptions.groups : groups;
    const exportedGroups = exportGroupDirectory(records, sourceGroups);
    const counts = exportCounts(records);
    const generated = /^\d{4}-\d{2}-\d{2}$/.test(text(sourceMeta.generated || sourceMeta.last_updated))
      ? text(sourceMeta.generated || sourceMeta.last_updated)
      : new Date().toISOString().slice(0, 10);
    const attack = plain(sourceMeta.attack);
    const inferredAttackVersion = records.flatMap(playbook => playbook?.telemetry_requirements || [])
      .flatMap(source => source?.event_ids || [])
      .map(eventId => text(eventId?.provenance).match(/^attack-v([\d.]+)-verified$/i)?.[1])
      .find(Boolean);
    const attackVersion = text(attack?.version || inferredAttackVersion || "0.0");
    const qualityModel = plain(sourceMeta.quality_model);
    const metadata = {
      ...sourceMeta,
      schema_version: text(sourceMeta.schema_version || records[0]?.schema_version || "4.0.0"),
      content_version: text(sourceMeta.content_version || "4.0.0"),
      generated,
      counts,
      tactic_order: list(sourceMeta.tactic_order).length ? list(sourceMeta.tactic_order) : [...TACTICS],
      attack: { domain: "unspecified", ...(attack && Object.keys(attack).length ? attack : {}), version: attackVersion },
      quality_model: qualityModel && Object.keys(qualityModel).length ? qualityModel : { version: "unspecified" },
      quality_summary: exportQualitySummary(records),
      threat_groups_summary: {
        ...(plain(sourceMeta.threat_groups_summary) || {}),
        total_groups: exportedGroups.length,
        playbooks_with_groups: records.filter(playbook => Array.isArray(playbook?.threat_groups) && playbook.threat_groups.length).length,
        total_playbook_group_mappings: records.reduce((total, playbook) => total + (Array.isArray(playbook?.threat_groups) ? playbook.threat_groups.length : 0), 0),
        attack_version: attackVersion
      }
    };
    // These enrichment counters describe the source corpus and cannot be inferred honestly for
    // an arbitrary subset export. Omitting them is preferable to publishing stale full-corpus
    // counts alongside a one-playbook download.
    delete metadata.telemetry_enrichment_summary;
    return JSON.stringify({ meta: metadata, groups: exportedGroups, playbooks: records }, null, 2) + "\n";
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
      "id", "name", "kind", "tactics", "platforms", "data_sources", "threat_groups", "severity", "confidence", "maturity",
      "status", "quality_score", "telemetry_requirements", "queries", "validation_status", "last_reviewed"
    ];
    const rows = playbooks.map(playbook => [
      playbook.id, playbook.name, playbook.kind, playbook.tactics, playbook.platforms,
      playbook.telemetry_requirements.map(source => source.category), playbook.threat_groups, playbook.severity, playbook.confidence,
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

  // The reader is organised around the analyst workflow rather than the data model, so every
  // section — legacy prose and structured record alike — is assigned to exactly one stage.
  const STAGES = Object.freeze([
    { id: "overview", label: "Overview", hint: "What this is and why it matters" },
    { id: "detect", label: "Detect", hint: "Telemetry, detection logic, and queries" },
    { id: "hunt", label: "Hunt", hint: "Hypothesis, pivots, and scoping" },
    { id: "validate", label: "Validate", hint: "Prove the detection actually fires" },
    { id: "respond", label: "Respond", hint: "Contain, eradicate, recover" },
    { id: "reference", label: "Reference", hint: "Lifecycle, quality, and known gaps" }
  ]);

  // Legacy v3 section titles are matched by keyword because their casing drifted across records.
  const STAGE_RULES = Object.freeze([
    [/^(overview|technique mapping)/i, "overview"],
    [/^(log source|structured telemetry|detection engineering|detection logic|query examples)/i, "detect"],
    [/^(hunt)/i, "hunt"],
    [/^(safe validation|validation)/i, "validate"],
    [/^(incident response|ir playbook|operational incident|automation)/i, "respond"],
    [/^(lifecycle)/i, "reference"]
  ]);

  function stageForSection(section) {
    const label = text(section?.title || section?.id);
    const match = STAGE_RULES.find(([pattern]) => pattern.test(label));
    return match ? match[1] : "reference";
  }

  function briefSteps(items, limit = 3) {
    return (Array.isArray(items) ? items : []).slice(0, limit)
      .map(item => text(typeof item === "string" ? item : item?.action || item?.title))
      .filter(Boolean);
  }

  // The 30-second answer an analyst needs before reading anything else.
  function playbookBrief(playbook) {
    const telemetry = Array.isArray(playbook?.telemetry_requirements) ? playbook.telemetry_requirements : [];
    const required = telemetry.filter(source => text(source?.tier).toLowerCase() === "required");
    const verified = telemetry.reduce((total, source) => total
      + (Array.isArray(source?.event_ids) ? source.event_ids.filter(id => isAttackVerified(id?.provenance)).length : 0), 0);
    return {
      hypothesis: text(playbook?.detection?.hypothesis),
      objective: text(playbook?.detection?.objective),
      firstMoves: briefSteps(playbook?.response?.triage),
      requiredSources: (required.length ? required : telemetry.slice(0, 3))
        .map(source => text(source?.source_name || source?.category || source?.id)).filter(Boolean),
      requiredCount: required.length,
      telemetryCount: telemetry.length,
      queryCount: Array.isArray(playbook?.queries) ? playbook.queries.length : 0,
      verifiedEventIds: verified,
      validationStatus: validationStatus(playbook),
      groupCount: Array.isArray(playbook?.threat_groups) ? playbook.threat_groups.length : 0
    };
  }

  function falsePositiveGuidance(value, limit = 8) {
    if (!Array.isArray(value)) return [];
    return value.slice(0, limit).map(item => {
      if (typeof item === "string") return text(item);
      if (!item || typeof item !== "object") return text(item);
      const cause = text(item.cause || item.title || item.name || item.id);
      const evidence = text(item.distinguishing_evidence || item.evidence || item.guidance || item.rationale);
      if (cause && evidence) return `${cause} Distinguishing evidence: ${evidence}`;
      return cause || evidence || flattenStrings(item).map(text).filter(Boolean).join(" ");
    }).filter(Boolean);
  }

  // Hunt is assembled from fields that exist but were previously buried inside nested records.
  function huntWorkflow(playbook) {
    const detection = playbook?.detection || {};
    const response = playbook?.response || {};
    const strategies = (Array.isArray(detection.strategies) ? detection.strategies : [])
      .map(strategy => {
        if (typeof strategy === "string") return { id: "", title: text(strategy), logic: "", signals: [] };
        const id = text(strategy?.id);
        const logic = text(strategy?.logic || strategy?.summary || strategy?.description);
        const title = text(strategy?.title || strategy?.name || id || logic);
        const signals = list([
          ...(logic ? [logic] : []),
          ...(Array.isArray(strategy?.primary_signals) ? strategy.primary_signals : [])
        ], 6);
        return { id, title, logic, signals };
      })
      .filter(strategy => strategy.title || strategy.signals.length);
    return {
      hypothesis: text(detection.hypothesis),
      objective: text(detection.objective),
      leads: strategies,
      // Response steps are objects in the v4 dataset but plain strings in older records and
      // fixtures, so both shapes must resolve rather than being silently dropped.
      pivots: (Array.isArray(response.investigation) ? response.investigation : [])
        .map(step => ({ title: flowLabel(step), rationale: text(step?.rationale) }))
        .filter(step => step.title),
      scoping: (Array.isArray(response.scoping) ? response.scoping : [])
        .map(flowLabel).filter(Boolean),
      falsePositives: falsePositiveGuidance(detection.false_positives, 8)
    };
  }

  // Deterministic geometry for the per-playbook incident-response flowchart. Every record carries
  // the same response shape, so one fixed spine (with a right-hand column for "no" branches)
  // lays out correctly for the whole library without a graph-layout dependency.
  const FLOW = Object.freeze({
    marginX: 20, marginY: 20,
    spineWidth: 344, branchWidth: 264, columnGap: 40,
    nodeGap: 30, padding: 12, lineHeight: 15, titleHeight: 18,
    decisionPadding: 38, minHeight: 46,
    titleChars: 40, itemChars: 52, decisionChars: 28, branchChars: 34
  });

  function wrapText(value, maxChars = 46, maxLines = 6) {
    const normalized = text(value).replace(/\s+/g, " ").trim();
    if (!normalized || maxChars < 4 || maxLines < 1) return [];
    const words = normalized.split(" ");
    const lines = [];
    let current = "";
    let truncated = false;
    for (let index = 0; index < words.length; index += 1) {
      const raw = words[index];
      const word = raw.length > maxChars ? `${raw.slice(0, maxChars - 1)}…` : raw;
      const candidate = current ? `${current} ${word}` : word;
      if (candidate.length <= maxChars) {
        current = candidate;
        continue;
      }
      lines.push(current);
      if (lines.length >= maxLines) {
        current = "";
        truncated = true;
        break;
      }
      current = word;
    }
    if (current) lines.push(current);
    if (truncated && lines.length) {
      const last = lines[lines.length - 1];
      lines[lines.length - 1] = last.length < maxChars ? `${last}…` : `${last.slice(0, maxChars - 1)}…`;
    }
    return lines.slice(0, maxLines);
  }

  function flowLabel(item) {
    if (typeof item === "string") return text(item);
    if (!item || typeof item !== "object") return "";
    return text(item.title || item.action || item.criterion || item.criteria || item.destination || item.summary);
  }

  function flowSteps(value, limit) {
    const items = Array.isArray(value)
      ? value
      : value && typeof value === "object"
        ? Object.values(value).flatMap(entry => (Array.isArray(entry) ? entry : []))
        : [];
    return items.map(flowLabel).filter(Boolean).slice(0, limit);
  }

  function flowCount(value) {
    if (Array.isArray(value)) return value.length;
    if (value && typeof value === "object") {
      return Object.values(value).reduce((total, entry) => total + (Array.isArray(entry) ? entry.length : 0), 0);
    }
    return 0;
  }

  function flowLines(node) {
    return node.lines.reduce((total, line) => total + (line.kind === "title" ? FLOW.titleHeight : FLOW.lineHeight), 0);
  }

  // Telemetry is attached to the flow by tier, at the step where an analyst actually needs it:
  // required sources before any decision is made, recommended sources while scoping, and
  // optional/compensating sources as the concrete answer to "unresolved evidence".
  const TELEMETRY_STEPS = Object.freeze([
    {
      id: "first", node: "triage", marker: "①", label: "Check first", when: "Triage",
      tiers: ["required"], withEvents: true,
      empty: "No source is marked required. Confirm collection before relying on this flow."
    },
    {
      id: "correlate", node: "analysis", marker: "②", label: "Correlate with", when: "Investigate and scope",
      tiers: ["recommended"], withEvents: false,
      empty: "No recommended sources are recorded for this technique."
    },
    {
      id: "fallback", node: "evidence-gap", marker: "③", label: "Next sources", when: "If evidence is unresolved",
      tiers: ["optional", "compensating"], withEvents: false,
      empty: "No optional or compensating sources are recorded; extend collection before closing."
    }
  ]);

  // Only ATT&CK-verified identifiers are promoted into the flow. Legacy identifiers carried
  // over from the v3 content are counted but withheld: in this dataset every event reference
  // attached to a source that cannot emit it is a legacy one, so surfacing them as "check
  // first" actions would send analysts to the wrong log.
  function flowchartTelemetry(playbook, { resolveEvent } = {}) {
    const sources = (Array.isArray(playbook?.telemetry_requirements) ? playbook.telemetry_requirements : [])
      .filter(source => source && typeof source === "object");
    let verifiedTotal = 0;
    let unverifiedTotal = 0;
    const shaped = sources.map(source => {
      const seen = new Set();
      const events = [];
      let unverified = 0;
      (Array.isArray(source.event_ids) ? source.event_ids : []).forEach(raw => {
        const reference = raw && typeof raw === "object" ? raw : { id: raw };
        const id = text(reference.id ?? reference.event_id);
        if (!id) return;
        if (!isAttackVerified(reference.provenance)) {
          unverified += 1;
          return;
        }
        if (seen.has(id)) return;
        seen.add(id);
        const catalog = typeof resolveEvent === "function" ? resolveEvent(id, reference, source) : undefined;
        events.push({
          id,
          provider: text(reference.provider || catalog?.log_source),
          name: text(catalog?.name),
          fields: list(catalog?.fields, 12),
          conditional: text(catalog?.conditional)
        });
      });
      verifiedTotal += events.length;
      unverifiedTotal += unverified;
      // Linux, macOS, cloud and EDR sources rarely have numeric event IDs; ATT&CK cites them
      // by channel instead ("auditd:SYSCALL" / "execve"). Channels that declare EventCode are
      // already represented above as verified events, so only the rest are kept here.
      const channelSeen = new Set();
      const channels = (Array.isArray(source.attack_analytics) ? source.attack_analytics : [])
        .map(analytic => ({ logSource: text(analytic?.log_source), channel: text(analytic?.channel) }))
        .filter(entry => entry.logSource && entry.channel && !/Event(?:Code|ID)\s*=/i.test(entry.channel))
        .filter(entry => {
          const key = `${entry.logSource}\u0000${entry.channel}`.toLowerCase();
          if (channelSeen.has(key)) return false;
          channelSeen.add(key);
          return true;
        });
      return {
        id: text(source.id),
        name: text(source.source_name || source.source_heading || source.category || source.id),
        tier: text(source.tier || source.priority || "recommended").toLowerCase(),
        events,
        channels,
        unverified
      };
    });
    // Verified events first, then sources ATT&CK cites by channel, then everything else.
    const rank = (a, b) => b.events.length - a.events.length
      || Number(b.channels.length > 0) - Number(a.channels.length > 0)
      || a.name.localeCompare(b.name);
    return {
      steps: TELEMETRY_STEPS.map(({ tiers, ...step }) => ({
        ...step,
        sources: shaped.filter(source => tiers.includes(source.tier)).sort(rank)
      })),
      counts: { sources: shaped.length, verified: verifiedTotal, unverified: unverifiedTotal }
    };
  }

  function telemetryEventLabel(event) {
    return event.name ? `${event.id} ${event.name}` : event.id;
  }

  // wrapText clips any single token longer than a line. ATT&CK channels are full of those
  // (comma-joined API names, file paths, regexes), and clipping them would alter MITRE's text.
  // This splits an over-long token at its own separators — or hard-splits it if it has none —
  // so rejoining the lines reproduces the input exactly, with nothing dropped or inserted.
  function wrapExact(value, maxChars) {
    const pieces = [];
    text(value).replace(/\s+/g, " ").split(" ").filter(Boolean).forEach(word => {
      if (word.length <= maxChars) {
        pieces.push({ text: word, glued: false });
        return;
      }
      (word.match(/[^,/|;:=&]*[,/|;:=&]?/g) || []).filter(Boolean).forEach((part, partIndex) => {
        for (let start = 0; start < part.length; start += maxChars) {
          pieces.push({ text: part.slice(start, start + maxChars), glued: partIndex > 0 || start > 0 });
        }
      });
    });
    const lines = [];
    let current = "";
    pieces.forEach(piece => {
      const candidate = current ? `${current}${piece.glued ? "" : " "}${piece.text}` : piece.text;
      if (candidate.length <= maxChars) {
        current = candidate;
        return;
      }
      if (current) lines.push(current);
      current = piece.text;
    });
    if (current) lines.push(current);
    return lines;
  }

  // Compact enough to sit inside a flowchart card; the full per-event detail is rendered
  // beside the diagram rather than squeezed into SVG text. Counts are capped instead of text,
  // so every line wraps in full: a label is never silently truncated with an ellipsis.
  function telemetryFlowLines(step, maxChars, shownSources = 3) {
    const lines = [{ kind: "telemetry-head", text: `${step.marker} ${step.label}` }];
    if (!step.sources.length) {
      wrapExact(step.empty, maxChars).forEach(line => lines.push({ kind: "telemetry-more", text: line }));
      return lines;
    }
    const shown = step.sources.slice(0, shownSources);
    shown.forEach(source => {
      wrapExact(`• ${source.name}`, maxChars).forEach(line => lines.push({ kind: "telemetry", text: line }));
      // Indented lines lose 12px of width, so they wrap two characters earlier.
      const detail = value => wrapExact(value, maxChars - 2)
        .forEach(line => lines.push({ kind: "telemetry-event", text: line, indent: 12 }));
      if (step.withEvents && source.events.length) {
        const events = source.events.slice(0, 3).map(telemetryEventLabel).join(" · ");
        detail(`${events}${source.events.length > 3 ? ` +${source.events.length - 3}` : ""}`);
      } else if (step.withEvents && source.channels.length) {
        const [first] = source.channels;
        detail(`${first.logSource} · ${first.channel}${source.channels.length > 1 ? ` +${source.channels.length - 1}` : ""}`);
      }
    });
    if (step.sources.length > shown.length) {
      lines.push({ kind: "telemetry-more", text: `+${step.sources.length - shown.length} more in the telemetry map` });
    }
    return lines;
  }

  function telemetrySummary(plan) {
    const evidence = source => source.events.length
      ? ` [${source.events.map(event => event.id).join(", ")}]`
      : source.channels.length ? ` [${source.channels.map(entry => `${entry.logSource} ${entry.channel}`).join(", ")}]` : "";
    return plan.steps.map(step => `${step.label} (${step.when}): ${step.sources.length
      ? step.sources.map(source => source.name + evidence(source)).join("; ")
      : "none recorded"}.`).join(" ");
  }

  // Explicit workflow edges keep evidence gaps, failed actions, and accepted closure distinct.
  function buildOperationalFlowchart(playbook, options = {}) {
    const workflow = playbook.response.workflow;
    const telemetry = flowchartTelemetry(playbook, options);
    const telemetryByNode = new Map(telemetry.steps.map(step => [step.node, step]));
    const nodes = []; const edges = []; const margin = 24; const gap = 44;
    const spineWidth = 344, branchWidth = 290, branchX = 444, centerX = margin + spineWidth / 2;
    let y = margin;
    const rows = [...new Set(workflow.nodes.map(node => node.row))].sort((a, b) => a - b);
    rows.forEach(row => {
      const members = workflow.nodes.filter(node => node.row === row).map(source => {
        const decision = source.kind === "decision";
        const maxChars = decision ? 22 : source.column === "branch" ? 38 : 46;
        // Diamonds taper, so telemetry is only ever attached to rectangular cards.
        const step = decision ? undefined : telemetryByNode.get(source.id);
        const lines = [
          ...wrapText(source.title, decision ? 22 : source.column === "branch" ? 33 : 40, 100).map(text => ({ kind: "title", text })),
          ...(source.items || []).flatMap(item => wrapText(item, maxChars, 100).map(text => ({ kind: "item", text }))),
          ...(step ? telemetryFlowLines(step, maxChars) : [])
        ];
        const body = lines.reduce((sum, line) => sum + (line.kind === "title" ? FLOW.titleHeight : FLOW.lineHeight), 0);
        const padding = decision ? body / 2 + FLOW.decisionPadding : FLOW.padding;
        return { ...source, lines, padding, x: source.column === "branch" ? branchX : margin,
          w: source.column === "branch" ? branchWidth : spineWidth, h: Math.max(FLOW.minHeight, body + padding * 2) };
      });
      const height = Math.max(...members.map(node => node.h));
      members.forEach(node => { node.y = y + (height - node.h) / 2; nodes.push(node); });
      y += height + gap;
    });
    const byId = new Map(nodes.map(node => [node.id, node]));
    let lane = 0;
    workflow.edges.forEach(source => {
      const from = byId.get(source.from), to = byId.get(source.to);
      if (!from || !to) throw new Error("Workflow edge references a missing node");
      let points, labelPoint;
      if (source.kind === "branch") {
        points = [[from.x + from.w, from.y + from.h / 2], [to.x, to.y + to.h / 2]];
      } else if (source.kind === "return") {
        const x = branchX + branchWidth + 24 + lane++ * 18;
        const approachY = to.y - 16;
        points = [[from.x + from.w, from.y + from.h / 2], [x, from.y + from.h / 2], [x, approachY], [centerX, approachY], [centerX, to.y]];
        labelPoint = [from.x + from.w + 8, from.y + from.h / 2 - 6];
      } else {
        points = [[from.x + from.w / 2, from.y + from.h], [to.x + to.w / 2, to.y]];
      }
      edges.push({ ...source, points, labelPoint });
    });
    return { title: text(playbook.id) + " incident response flowchart",
      summary: "Incident response flow for " + text(playbook.id) + " " + text(playbook.name) + ". " + workflow.scope + " " + workflow.edges.map(edge => edge.from + " -- " + (edge.label || "next") + " --> " + edge.to).join(". ") + ". Telemetry: " + telemetrySummary(telemetry),
      width: branchX + branchWidth + 48 + lane * 18, height: y - gap + margin, centerX, nodes, edges, telemetry,
      metrics: { padding: FLOW.padding, lineHeight: FLOW.lineHeight, titleHeight: FLOW.titleHeight, decisionPadding: FLOW.decisionPadding }
    };
  }
  function buildFlowchart(playbook, options = {}) {
    if (playbook?.response?.workflow?.version === 1) return buildOperationalFlowchart(playbook, options);
    const telemetry = flowchartTelemetry(playbook, options);
    const telemetryByNode = new Map(telemetry.steps.map(step => [step.node, step]));
    const response = playbook?.response || {};
    const tree = (Array.isArray(response.decision_tree) ? response.decision_tree : []).filter(node => node && typeof node === "object");
    const centerX = FLOW.marginX + FLOW.spineWidth / 2;
    const branchX = FLOW.marginX + FLOW.spineWidth + FLOW.columnGap;
    const width = branchX + FLOW.branchWidth + FLOW.marginX;
    const nodes = [];
    const edges = [];
    let cursorY = FLOW.marginY;
    let previous = null;

    const addSpine = (id, kind, lines, { edgeLabel = "" } = {}) => {
      const node = { id, kind, lines, x: FLOW.marginX, w: FLOW.spineWidth, y: cursorY };
      const body = flowLines(node);
      node.h = kind === "decision"
        ? body + FLOW.decisionPadding * 2
        : Math.max(FLOW.minHeight, body + FLOW.padding * 2);
      nodes.push(node);
      if (previous) {
        edges.push({
          from: previous.id, to: node.id, kind: "main", label: edgeLabel,
          points: [[centerX, previous.y + previous.h], [centerX, node.y]]
        });
      }
      cursorY = node.y + node.h + FLOW.nodeGap;
      previous = node;
      return node;
    };

    const addBranch = (id, kind, source, lines, label) => {
      const node = { id, kind, lines, x: branchX, w: FLOW.branchWidth };
      node.h = Math.max(FLOW.minHeight, flowLines(node) + FLOW.padding * 2);
      node.y = source.y + source.h / 2 - node.h / 2;
      nodes.push(node);
      edges.push({
        from: source.id, to: node.id, kind: "branch", label,
        points: [[source.x + source.w, source.y + source.h / 2], [node.x, node.y + node.h / 2]]
      });
      return node;
    };

    addSpine("start", "start", [
      { kind: "title", text: `Alert: ${text(playbook?.id)}` },
      ...wrapText(playbook?.name, FLOW.itemChars, 2).map(line => ({ kind: "item", text: line }))
    ]);

    const stages = [
      { id: "triage", title: "Triage", source: response.triage },
      {
        id: "analysis", title: "Investigation and scoping",
        source: [...(Array.isArray(response.investigation) ? response.investigation : []), ...(Array.isArray(response.scoping) ? response.scoping : [])]
      },
      { id: "containment", title: "Containment", source: response.containment },
      { id: "eradication", title: "Eradication", source: response.eradication },
      { id: "recovery", title: "Recovery", source: response.recovery },
      { id: "post-incident", title: "Post-incident", source: response.post_incident }
    ];

    stages.forEach((stage, index) => {
      // Each decision gate precedes the phase its "yes" outcome leads into.
      const decision = index > 0 ? tree[index - 1] : null;
      let edgeLabel = "";
      const entryLines = [];
      if (decision) {
        const gate = addSpine(`decision-${index}`, "decision",
          wrapText(decision.condition, FLOW.decisionChars, 5).map(line => ({ kind: "title", text: line })));
        addBranch(`decision-${index}-no`, "branch", gate, [
          { kind: "title", text: "If no" },
          ...wrapText(decision.if_false, FLOW.branchChars, 4).map(line => ({ kind: "item", text: line }))
        ], "no");
        edgeLabel = "yes";
        wrapText(decision.if_true, FLOW.itemChars, 2).forEach(line => entryLines.push({ kind: "entry", text: line }));
      }

      const count = flowCount(stage.source);
      const steps = flowSteps(stage.source, 3);
      const telemetryStep = telemetryByNode.get(stage.id);
      const stageNode = addSpine(stage.id, "phase", [
        ...entryLines,
        { kind: "title", text: count ? `${stage.title} · ${count} step${count === 1 ? "" : "s"}` : stage.title },
        ...steps.flatMap(step => wrapText(`• ${step}`, FLOW.itemChars, 2).map(line => ({ kind: "item", text: line }))),
        ...(telemetryStep ? telemetryFlowLines(telemetryStep, FLOW.itemChars) : [])
      ], { edgeLabel });

      if (stage.id === "triage") {
        const escalation = (Array.isArray(response.escalation) ? response.escalation : [])[0];
        if (escalation) {
          addBranch("escalation", "escalation", stageNode, [
            { kind: "title", text: `Escalate: ${text(escalation.destination) || "incident command"}` },
            ...wrapText(escalation.criteria, FLOW.branchChars, 4).map(line => ({ kind: "item", text: line }))
          ], "when");
        }
      }
    });

    const closureCount = flowCount(response.closure_criteria);
    addSpine("closure", "end", [
      { kind: "title", text: "Close incident" },
      ...wrapText(
        closureCount ? `All ${closureCount} closure criteria met and evidenced` : "Closure criteria met and evidenced",
        FLOW.itemChars, 2
      ).map(line => ({ kind: "item", text: line }))
    ]);

    const height = cursorY - FLOW.nodeGap + FLOW.marginY;
    const summary = [
      `Incident response flow for ${text(playbook?.id)} ${text(playbook?.name)}.`,
      `Alert triage leads through ${tree.length} decision gate${tree.length === 1 ? "" : "s"}:`,
      ...tree.map((node, index) => `Gate ${index + 1}: ${text(node.condition)} If yes, ${text(node.if_true)} If no, ${text(node.if_false)}`),
      `Phases: ${stages.map(stage => stage.title).join(", ")}, then closure.`,
      `Telemetry: ${telemetrySummary(telemetry)}`
    ].join(" ");

    return {
      title: `${text(playbook?.id)} incident response flowchart`,
      summary, width, height, centerX, nodes, edges, telemetry,
      metrics: {
        padding: FLOW.padding, lineHeight: FLOW.lineHeight,
        titleHeight: FLOW.titleHeight, decisionPadding: FLOW.decisionPadding
      }
    };
  }

  function coverageSummary(playbooks, now = Date.now()) {
    const output = {
      total: playbooks.length,
      withTelemetry: 0,
      withQueries: 0,
      withValidation: 0,
      withThreatGroups: 0,
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
      if (playbook.threat_groups.length) output.withThreatGroups++;
      increment(output.bySeverity, playbook.severity);
      increment(output.byMaturity, playbook.maturity);
      increment(output.byStatus, playbook.status);
      increment(output.byValidation, validationStatus(playbook));
    });
    return output;
  }

  async function refreshServiceWorkerRevision({ currentRevision, loadRevision, registerRevision, updateRegistration }) {
    const nextRevision = await loadRevision();
    if (nextRevision && nextRevision !== currentRevision) {
      await registerRevision(nextRevision);
      return nextRevision;
    }
    await updateRegistration?.();
    return currentRevision;
  }

  function waitForServiceWorkerRevision(registration, scriptUrl, timeoutMs = null) {
    const target = String(scriptUrl);
    const matchingWorker = () => [registration.installing, registration.waiting, registration.active]
      .find(worker => worker?.scriptURL === target);
    const waitForReadyState = worker => new Promise((resolve, reject) => {
      let timer;
      const cleanup = () => {
        clearTimeout(timer);
        worker.removeEventListener?.("statechange", check);
      };
      const check = () => {
        if (["installed", "activated"].includes(worker.state)) {
          cleanup();
          resolve(worker);
        } else if (worker.state === "redundant") {
          cleanup();
          reject(new Error("The service-worker candidate became redundant before installation."));
        }
      };
      worker.addEventListener?.("statechange", check);
      if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
        timer = setTimeout(() => {
          cleanup();
          reject(new Error("Timed out waiting for the service-worker candidate to install."));
        }, timeoutMs);
      }
      check();
    });

    const existing = matchingWorker();
    if (existing) return waitForReadyState(existing);
    return new Promise((resolve, reject) => {
      let timer;
      const cleanup = () => {
        clearTimeout(timer);
        registration.removeEventListener?.("updatefound", check);
      };
      const check = () => {
        const worker = matchingWorker();
        if (!worker) return;
        cleanup();
        waitForReadyState(worker).then(resolve, reject);
      };
      registration.addEventListener?.("updatefound", check);
      if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
        timer = setTimeout(() => {
          cleanup();
          reject(new Error("The expected service-worker candidate was not created."));
        }, timeoutMs);
      }
      check();
    });
  }

  globalThis.PlaybookCore = Object.freeze({
    TACTICS,
    FILTER_KEYS,
    STAGES,
    stageForSection,
    playbookBrief,
    huntWorkflow,
    isAttackVerified,
    flowchartTelemetry,
    normalizeText,
    tokenizeQuery,
    wrapText,
    buildFlowchart,
    slugify,
    safeHttpUrl,
    safeDecodeHash,
    normalizeDataset,
    buildSearchIndex,
    rankPlaybook,
    filterAndSortPlaybooks,
    confidenceProfile,
    environmentFit,
    investigationSuggestions,
    investigationTasks,
    investigationGraph,
    serializeInvestigationMarkdown,
    encodeUrlState,
    decodeUrlState,
    serializePlaybookMarkdown,
    serializePlaybooksJson,
    serializeCoverageCsv,
    escapeCsvCell,
    safeFilename,
    qualitySummary,
    coverageSummary,
    refreshServiceWorkerRevision,
    waitForServiceWorkerRevision
  });
})();
