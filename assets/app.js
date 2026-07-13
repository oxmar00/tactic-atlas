// TacticAtlas v4 — structured, dependency-free browser client.
(() => {
  "use strict";

  const Core = globalThis.PlaybookCore;
  const STORE = "tactic-atlas:v4";
  const LEGACY_STORE = "attack-playbook-console:v4";
  const RECENT_LIMIT = 16;
  const VIEW_IDS = { matrix: "v-matrix", list: "v-list", table: "v-table", dashboard: "v-dashboard" };
  const FILTER_IDS = ["kind", "technique", "platform", "source", "severity", "maturity", "status", "sort"];
  const state = {
    data: null,
    playbooks: [],
    byId: new Map(),
    searchIndex: new Map(),
    filtered: [],
    view: "matrix",
    preferredView: "matrix",
    query: "",
    kind: "all",
    technique: "all",
    platform: "all",
    source: "all",
    severity: "all",
    maturity: "all",
    status: "all",
    sort: "id",
    tactics: new Set(),
    favorites: new Set(),
    recent: [],
    favoritesOnly: false,
    recentOnly: false,
    openId: null,
    renderFrame: 0,
    renderTimer: 0,
    searchTimer: 0,
    toastTimer: 0,
    theme: "dark",
    swRegistration: null,
    refreshing: false
  };

  const requiredIds = [
    "q", "kind", "technique", "platform", "source", "severity", "maturity", "status", "sort",
    "favorites", "recent", "v-matrix", "v-list", "v-table", "v-dashboard", "tac-all", "tacbar",
    "clear", "empty-clear", "result-count", "active-filter-chips", "loading", "matrix", "list", "table", "dashboard", "empty",
    "theme", "command-button", "data-version", "data-freshness", "foot-count",
    "foot-quality", "panel", "p-id", "p-kind", "p-score", "p-name", "p-description", "p-tags", "p-toc",
    "p-body", "p-save", "p-copy", "p-print", "p-export-md", "p-export-json", "p-close", "p-prev", "p-next",
    "p-position", "command-palette", "command-q", "command-results", "command-close", "toast", "offline-banner",
    "update-banner", "update-reload", "update-dismiss"
  ];
  const ui = {};
  const lazySections = new WeakMap();
  requiredIds.forEach(id => {
    const node = document.getElementById(id);
    if (!node) throw new Error(`Application shell is missing #${id}.`);
    ui[id] = node;
  });

  const make = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined && value !== null) node.textContent = String(value);
    return node;
  };
  const humanize = value => String(value || "").replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());
  const toneClass = value => `tone-${Core.slugify(value)}`;
  const severityClass = value => `severity-${Core.slugify(value || "unknown")}`;
  const nonEmpty = value => Array.isArray(value) ? value.length > 0 : value && (typeof value !== "object" || Object.keys(value).length > 0);

  start().catch(showLoadError);

  async function start() {
    if (!Core) throw new Error("PlaybookCore did not load.");
    restorePreferences();
    applyAppearance();
    bindStaticEvents();
    updateOnlineState();
    const embedded = document.getElementById("playbook-data");
    const raw = embedded ? JSON.parse(embedded.textContent) : await fetchData();
    state.data = Core.normalizeDataset(raw);
    state.playbooks = state.data.playbooks;
    state.byId = new Map(state.playbooks.map(playbook => [playbook.id, playbook]));
    state.searchIndex = Core.buildSearchIndex(state.playbooks);
    state.favorites = new Set([...state.favorites].filter(id => state.byId.has(id)).slice(0, 500));
    state.recent = state.recent.filter(id => state.byId.has(id)).slice(0, RECENT_LIMIT);
    initializeFacets();
    applyLocationState(true);
    renderDatasetMeta();
    ui.loading.remove();
    scheduleRender(false);
    if (state.openId) openPlaybook(state.openId, { historyMode: "none", focus: false, recordRecent: false });
    registerServiceWorker();
  }

  async function fetchData() {
    const response = await fetch("data/playbooks.json", { credentials: "same-origin", cache: "no-cache" });
    if (!response.ok) throw new Error(`Playbook data request failed (${response.status}).`);
    return response.json();
  }

  function bindStaticEvents() {
    ui.q.addEventListener("input", event => {
      clearTimeout(state.searchTimer);
      state.searchTimer = setTimeout(() => {
        state.query = event.target.value.slice(0, 240);
        if (state.query && state.sort === "id") state.sort = "relevance";
        if (!state.query && state.sort === "relevance") state.sort = "id";
        syncControls();
        scheduleRender();
      }, 90);
    });
    FILTER_IDS.forEach(key => ui[key].addEventListener("change", event => {
      state[key] = event.target.value;
      scheduleRender();
    }));
    Object.entries(VIEW_IDS).forEach(([view, id]) => ui[id].addEventListener("click", () => setView(view)));
    ui.favorites.addEventListener("click", () => { state.favoritesOnly = !state.favoritesOnly; scheduleRender(); });
    ui.recent.addEventListener("click", () => { state.recentOnly = !state.recentOnly; scheduleRender(); });
    ui["tac-all"].addEventListener("click", () => { state.tactics.clear(); scheduleRender(); });
    ui.tacbar.addEventListener("click", event => {
      const button = event.target.closest("[data-tactic]");
      if (!button) return;
      const tactic = button.dataset.tactic;
      state.tactics.has(tactic) ? state.tactics.delete(tactic) : state.tactics.add(tactic);
      scheduleRender();
    });
    ui.clear.addEventListener("click", clearFilters);
    ui["empty-clear"].addEventListener("click", clearFilters);
    document.addEventListener("click", handleContentClick);
    ui.theme.addEventListener("click", toggleTheme);
    ui["command-button"].addEventListener("click", openCommandPalette);
    ui["command-close"].addEventListener("click", closeCommandPalette);
    ui["command-q"].addEventListener("input", renderCommandResults);
    ui["command-q"].addEventListener("keydown", navigateCommandResults);
    ui["command-results"].addEventListener("click", handleCommandClick);
    ui.panel.addEventListener("cancel", event => { event.preventDefault(); requestClosePanel(); });
    ui.panel.addEventListener("click", event => { if (event.target === ui.panel) requestClosePanel(); });
    ui.panel.addEventListener("close", syncModalState);
    ui["p-close"].addEventListener("click", requestClosePanel);
    ui["p-save"].addEventListener("click", toggleOpenFavorite);
    ui["p-copy"].addEventListener("click", copyOpenLink);
    ui["p-print"].addEventListener("click", printOpenPlaybook);
    ui["p-export-md"].addEventListener("click", exportOpenMarkdown);
    ui["p-export-json"].addEventListener("click", exportOpenJson);
    ui["p-prev"].addEventListener("click", () => navigatePanel(-1));
    ui["p-next"].addEventListener("click", () => navigatePanel(1));
    ui["p-toc"].addEventListener("click", navigateTableOfContents);
    ui["update-reload"].addEventListener("click", activateUpdate);
    ui["update-dismiss"].addEventListener("click", () => { ui["update-banner"].hidden = true; });
    window.addEventListener("online", updateOnlineState);
    window.addEventListener("offline", updateOnlineState);
    window.addEventListener("popstate", () => applyLocationState(false));
    window.addEventListener("hashchange", () => applyLocationState(false));
    document.addEventListener("keydown", handleGlobalKeys);
  }

  function initializeFacets() {
    const techniqueMap = new Map();
    state.playbooks.forEach(playbook => {
      if (playbook.kind === "technique") techniqueMap.set(playbook.id, `${playbook.id} — ${playbook.name}`);
      [...playbook.techniques, ...playbook.subtechniques].forEach(item => {
        if (item.id) techniqueMap.set(item.id, `${item.id}${item.name && item.name !== item.id ? ` — ${item.name}` : ""}`);
      });
    });
    fillSelect(ui.technique, [...techniqueMap].sort((a, b) => a[0].localeCompare(b[0])), true);
    fillSelect(ui.platform, uniqueValues(state.playbooks.flatMap(playbook => playbook.platforms)));
    fillSelect(ui.source, uniqueValues(state.playbooks.flatMap(playbook => playbook.telemetry_requirements.map(source => source.category))));
    fillSelect(ui.severity, orderedValues(state.playbooks.map(playbook => playbook.severity), ["critical", "high", "medium", "low", "informational", "unknown"]));
    fillSelect(ui.maturity, uniqueValues(state.playbooks.map(playbook => playbook.maturity)));
    fillSelect(ui.status, uniqueValues(state.playbooks.map(playbook => playbook.status)));
    const fragment = document.createDocumentFragment();
    state.data.meta.tactic_order.forEach(tactic => {
      const button = make("button", `tactic-chip ${toneClass(tactic)}`, tactic);
      button.type = "button";
      button.dataset.tactic = tactic;
      button.setAttribute("aria-pressed", "false");
      fragment.append(button);
    });
    ui.tacbar.replaceChildren(fragment);
  }

  function uniqueValues(values) {
    return [...new Set(values.map(value => String(value || "").trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  }

  function orderedValues(values, order) {
    const unique = new Set(uniqueValues(values));
    return [...order.filter(value => unique.delete(value)), ...[...unique].sort()];
  }

  function fillSelect(select, values, pairs = false) {
    const first = select.options[0].cloneNode(true);
    const fragment = document.createDocumentFragment();
    fragment.append(first);
    values.forEach(value => {
      const [key, label] = pairs ? value : [value, humanize(value)];
      const option = make("option", null, label);
      option.value = key;
      fragment.append(option);
    });
    select.replaceChildren(fragment);
  }

  function applyLocationState(initial) {
    if (!state.data) return;
    const decoded = Core.decodeUrlState(location.search, location.hash);
    const params = new URLSearchParams(location.search);
    state.query = decoded.query;
    state.view = params.has("view") ? decoded.view : initial ? state.preferredView : decoded.view;
    state.sort = params.has("sort") ? decoded.sort : state.query ? "relevance" : "id";
    ["kind", "technique", "platform", "source", "severity", "maturity", "status"].forEach(key => { state[key] = decoded[key]; });
    state.tactics = new Set(decoded.tactics.filter(tactic => state.data.meta.tactic_order.includes(tactic)));
    state.favoritesOnly = decoded.favoritesOnly;
    state.recentOnly = decoded.recentOnly;
    const nextId = decoded.openId && state.byId.has(decoded.openId) ? decoded.openId : null;
    state.openId = nextId;
    syncControls();
    scheduleRender(false);
    if (nextId) openPlaybook(nextId, { historyMode: "none", focus: false, recordRecent: false });
    else closePanelDirect();
  }

  function urlState() {
    return {
      query: state.query,
      view: state.view,
      sort: state.sort,
      kind: state.kind,
      technique: state.technique,
      platform: state.platform,
      source: state.source,
      severity: state.severity,
      maturity: state.maturity,
      status: state.status,
      tactics: state.tactics,
      favoritesOnly: state.favoritesOnly,
      recentOnly: state.recentOnly,
      openId: state.openId
    };
  }

  function writeUrl(mode = "replace") {
    const url = Core.encodeUrlState(urlState(), location.pathname);
    const previous = history.state && typeof history.state === "object" ? history.state : {};
    const historyState = { ...previous, attackConsole: true, appDialog: Boolean(state.openId), playbookId: state.openId };
    history[`${mode}State`](historyState, "", url);
  }

  function scheduleRender(updateUrl = true) {
    cancelAnimationFrame(state.renderFrame);
    clearTimeout(state.renderTimer);
    let rendered = false;
    const run = () => {
      if (rendered) return;
      rendered = true;
      cancelAnimationFrame(state.renderFrame);
      clearTimeout(state.renderTimer);
      render(updateUrl);
    };
    state.renderFrame = requestAnimationFrame(run);
    state.renderTimer = setTimeout(run, 60);
  }

  function render(updateUrl = true) {
    if (!state.data) return;
    state.filtered = Core.filterAndSortPlaybooks(state.playbooks, {
      query: state.query,
      sort: state.sort,
      kind: state.kind,
      technique: state.technique,
      platform: state.platform,
      source: state.source,
      severity: state.severity,
      maturity: state.maturity,
      status: state.status,
      tactics: state.tactics,
      favoritesOnly: state.favoritesOnly,
      recentOnly: state.recentOnly,
      favoriteIds: state.favorites,
      recentIds: state.recent
    }, state.searchIndex);
    const renderers = { matrix: renderMatrix, list: renderList, table: renderTable, dashboard: renderDashboard };
    renderers[state.view]();
    ["matrix", "list", "table", "dashboard"].forEach(view => { ui[view].hidden = view !== state.view || state.filtered.length === 0; });
    ui.empty.hidden = state.filtered.length > 0;
    ui["result-count"].textContent = state.filtered.length === state.playbooks.length ? `${state.playbooks.length} playbooks` : `${state.filtered.length} of ${state.playbooks.length} playbooks`;
    ui.clear.hidden = !hasActiveFilters();
    renderActiveFilters();
    syncControls();
    syncPanelNavigation();
    if (updateUrl) writeUrl("replace");
  }

  function syncControls() {
    ui.q.value = state.query;
    FILTER_IDS.forEach(key => {
      if ([...ui[key].options].some(option => option.value === state[key])) ui[key].value = state[key];
      else { state[key] = key === "sort" ? "id" : "all"; ui[key].value = state[key]; }
    });
    Object.entries(VIEW_IDS).forEach(([view, id]) => ui[id].setAttribute("aria-pressed", String(state.view === view)));
    ui.favorites.setAttribute("aria-pressed", String(state.favoritesOnly));
    ui.favorites.firstElementChild.textContent = state.favoritesOnly ? "★" : "☆";
    ui.recent.setAttribute("aria-pressed", String(state.recentOnly));
    ui.tacbar.querySelectorAll("[data-tactic]").forEach(button => button.setAttribute("aria-pressed", String(state.tactics.has(button.dataset.tactic))));
  }

  function setView(view) {
    if (!VIEW_IDS[view]) return;
    state.view = view;
    state.preferredView = view;
    savePreferences();
    scheduleRender();
  }

  function hasActiveFilters() {
    return Boolean(state.query || state.kind !== "all" || state.technique !== "all" || state.platform !== "all" || state.source !== "all" || state.severity !== "all" || state.maturity !== "all" || state.status !== "all" || state.tactics.size || state.favoritesOnly || state.recentOnly);
  }

  function renderActiveFilters() {
    const filters = [];
    if (state.query) filters.push({ key: "query", label: `Search: ${state.query}` });
    ["kind", "technique", "platform", "source", "severity", "maturity", "status"].forEach(key => {
      if (state[key] === "all") return;
      const selected = ui[key].selectedOptions?.[0]?.textContent || humanize(state[key]);
      filters.push({ key, label: `${humanize(key)}: ${selected}` });
    });
    state.tactics.forEach(tactic => filters.push({ key: "tactic", value: tactic, label: tactic }));
    if (state.favoritesOnly) filters.push({ key: "favorites", label: "Saved" });
    if (state.recentOnly) filters.push({ key: "recent", label: "Recent" });

    const fragment = document.createDocumentFragment();
    filters.forEach(filter => {
      const button = make("button", "active-filter-chip");
      button.type = "button";
      button.dataset.clearFilter = filter.key;
      if (filter.value) button.dataset.clearValue = filter.value;
      button.setAttribute("aria-label", `Remove filter: ${filter.label}`);
      button.append(make("span", null, filter.label), make("span", "active-filter-remove", "×"));
      fragment.append(button);
    });
    ui["active-filter-chips"].replaceChildren(fragment);
  }

  function clearFilters() {
    state.query = "";
    state.sort = "id";
    ["kind", "technique", "platform", "source", "severity", "maturity", "status"].forEach(key => { state[key] = "all"; });
    state.tactics.clear();
    state.favoritesOnly = false;
    state.recentOnly = false;
    syncControls();
    scheduleRender();
    ui.q.focus();
  }

  function appendHighlighted(parent, value) {
    const source = String(value || "");
    const tokens = Core.tokenizeQuery(state.query).filter(token => !token.includes(" "));
    if (!tokens.length) { parent.textContent = source; return; }
    const lower = source.toLowerCase();
    const ranges = [];
    tokens.forEach(token => {
      const needle = token.toLowerCase();
      let at = 0;
      while ((at = lower.indexOf(needle, at)) >= 0 && ranges.length < 30) { ranges.push([at, at + needle.length]); at += needle.length; }
    });
    ranges.sort((a, b) => a[0] - b[0]);
    const merged = ranges.reduce((all, range) => {
      const last = all.at(-1);
      if (last && range[0] <= last[1]) last[1] = Math.max(last[1], range[1]); else all.push([...range]);
      return all;
    }, []);
    let cursor = 0;
    merged.forEach(([start, end]) => {
      if (start > cursor) parent.append(document.createTextNode(source.slice(cursor, start)));
      parent.append(make("mark", "highlight", source.slice(start, end)));
      cursor = end;
    });
    if (cursor < source.length) parent.append(document.createTextNode(source.slice(cursor)));
  }

  function playbookCard(playbook, tone) {
    const button = make("button", `playbook-card ${toneClass(tone)}`);
    button.type = "button";
    button.dataset.openId = playbook.id;
    button.addEventListener("click", event => { event.stopPropagation(); openPlaybook(playbook.id); });
    button.setAttribute("aria-label", `${playbook.id}: ${playbook.name}. ${playbook.severity} severity. Quality ${playbook.quality_score}. ${state.favorites.has(playbook.id) ? "Saved." : ""}`);
    const top = make("span", "card-top");
    top.append(make("span", "card-id", playbook.id));
    if (state.favorites.has(playbook.id)) top.append(make("span", "card-save", "★"));
    const name = make("span", "card-name");
    appendHighlighted(name, playbook.name);
    const meta = make("span", "card-meta");
    meta.append(make("span", `mini-badge ${severityClass(playbook.severity)}`, humanize(playbook.severity)), make("span", "mini-badge", `Q ${playbook.quality_score}`));
    button.append(top, name, meta);
    return button;
  }

  function renderMatrix() {
    const fragment = document.createDocumentFragment();
    const groups = [...state.data.meta.tactic_order, "Operational", "Platform"];
    groups.forEach(group => {
      const items = state.filtered.filter(playbook => group === "Operational" ? playbook.kind === "operational" : group === "Platform" ? playbook.kind === "platform" : playbook.kind === "technique" && playbook.tactics.includes(group));
      if (!items.length) return;
      const section = make("section", `tactic-column ${toneClass(group)}`);
      const heading = make("header", "column-header");
      const title = make("h2", null, group);
      title.id = `matrix-${Core.slugify(group)}`;
      heading.append(title, make("span", null, `${items.length} playbook${items.length === 1 ? "" : "s"}`));
      section.setAttribute("aria-labelledby", title.id);
      const cards = make("div", "column-cards");
      items.forEach(playbook => cards.append(playbookCard(playbook, group)));
      section.append(heading, cards);
      fragment.append(section);
    });
    ui.matrix.replaceChildren(fragment);
  }

  function renderList() {
    const grouped = new Map();
    state.filtered.forEach(playbook => {
      const group = playbook.kind === "technique" ? playbook.tactics.find(tactic => !state.tactics.size || state.tactics.has(tactic)) || playbook.tactics[0] || "Other" : humanize(playbook.kind);
      if (!grouped.has(group)) grouped.set(group, []);
      grouped.get(group).push(playbook);
    });
    const order = [...state.data.meta.tactic_order, "Operational", "Platform", "Other"];
    const fragment = document.createDocumentFragment();
    [...grouped].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0])).forEach(([group, items]) => {
      const section = make("section", `list-group ${toneClass(group)}`);
      const heading = make("h2", null, group);
      heading.append(make("span", null, String(items.length)));
      const rows = make("div", "list-rows");
      items.forEach(playbook => rows.append(playbookRow(playbook, group)));
      section.append(heading, rows);
      fragment.append(section);
    });
    ui.list.replaceChildren(fragment);
  }

  function playbookRow(playbook, group) {
    const button = make("button", `list-row ${toneClass(group)}`);
    button.type = "button";
    button.dataset.openId = playbook.id;
    button.addEventListener("click", event => { event.stopPropagation(); openPlaybook(playbook.id); });
    button.setAttribute("aria-label", `${playbook.id}: ${playbook.name}. ${playbook.severity} severity. Quality ${playbook.quality_score}.`);
    const copy = make("span", "row-copy");
    const name = make("span", "row-name");
    appendHighlighted(name, playbook.name);
    copy.append(name, make("span", "row-summary", playbook.description || playbook.data_source_summary || "Structured security playbook"));
    const metrics = make("span", "row-metrics");
    metrics.append(make("span", `mini-badge ${severityClass(playbook.severity)}`, humanize(playbook.severity)), make("span", "mini-badge", `Q ${playbook.quality_score}`));
    if (state.favorites.has(playbook.id)) metrics.append(make("span", "card-save", "★"));
    button.append(make("span", "row-id", playbook.id), copy, metrics);
    return button;
  }

  function handleContentClick(event) {
    const clear = event.target.closest("[data-clear-filter]");
    if (clear) {
      const key = clear.dataset.clearFilter;
      if (key === "query") state.query = "";
      else if (key === "tactic") state.tactics.delete(clear.dataset.clearValue);
      else if (key === "favorites") state.favoritesOnly = false;
      else if (key === "recent") state.recentOnly = false;
      else if (["kind", "technique", "platform", "source", "severity", "maturity", "status"].includes(key)) state[key] = "all";
      if (!state.query && state.sort === "relevance") state.sort = "id";
      scheduleRender();
      return;
    }
    const open = event.target.closest("[data-open-id]");
    if (open) { openPlaybook(open.dataset.openId); return; }
    const drill = event.target.closest("[data-filter-key]");
    if (!drill) return;
    const key = drill.dataset.filterKey;
    const value = drill.dataset.filterValue;
    if (key === "tactic") state.tactics = new Set([value]);
    else if (["platform", "source", "severity", "maturity", "status"].includes(key)) state[key] = value;
    state.view = "table";
    scheduleRender();
  }

  function renderTable() {
    const wrapper = make("div", "data-table-wrap");
    wrapper.tabIndex = 0;
    wrapper.setAttribute("role", "region");
    wrapper.setAttribute("aria-label", "Scrollable playbook coverage table");
    const table = make("table", "coverage-table");
    table.append(make("caption", null, `${state.filtered.length} playbooks. Activate a playbook name to open its structured detail.`));
    const headers = ["Playbook", "Tactics", "Platforms", "Severity", "Maturity", "Status", "Telemetry", "Quality"];
    const headRow = make("tr");
    headers.forEach(label => { const th = make("th", null, label); th.scope = "col"; headRow.append(th); });
    const thead = make("thead");
    thead.append(headRow);
    const tbody = make("tbody");
    state.filtered.forEach(playbook => {
      const row = make("tr");
      const identity = make("td");
      const open = make("button", "table-open", `${playbook.id}: ${playbook.name}`);
      open.type = "button";
      open.dataset.openId = playbook.id;
      open.addEventListener("click", event => { event.stopPropagation(); openPlaybook(playbook.id); });
      identity.append(open, make("span", "table-sub", playbook.description));
      row.append(identity, tagCell(playbook.tactics), tagCell(playbook.platforms));
      row.append(make("td", severityClass(playbook.severity), humanize(playbook.severity)));
      row.append(make("td", null, humanize(playbook.maturity)), make("td", null, humanize(playbook.status)));
      row.append(make("td", null, `${playbook.telemetry_requirements.length} source${playbook.telemetry_requirements.length === 1 ? "" : "s"}`));
      const quality = make("td", "quality-cell");
      const meter = make("meter");
      meter.min = 0;
      meter.max = 100;
      meter.value = playbook.quality_score;
      meter.textContent = `${playbook.quality_score} of 100`;
      quality.append(meter, make("span", null, String(playbook.quality_score)));
      row.append(quality);
      tbody.append(row);
    });
    table.append(thead, tbody);
    wrapper.append(table);
    ui.table.replaceChildren(wrapper);
  }

  function tagCell(values) {
    const cell = make("td");
    const tags = make("div", "tag-list");
    (values.length ? values : ["Not specified"]).slice(0, 5).forEach(value => tags.append(make("span", "pill", value)));
    if (values.length > 5) tags.append(make("span", "pill", `+${values.length - 5}`));
    cell.append(tags);
    return cell;
  }

  function renderDashboard() {
    const coverage = Core.coverageSummary(state.filtered);
    const quality = Core.qualitySummary(state.filtered);
    const total = Math.max(coverage.total, 1);
    const fragment = document.createDocumentFragment();
    const intro = make("div", "dashboard-intro");
    const introCopy = make("div");
    introCopy.append(make("h2", null, "Coverage and content readiness"), make("p", null, "Metrics are computed from the currently filtered v4 records. Quality scores summarize documented content controls; they do not replace analyst review."));
    const scope = make("div", "dashboard-scope");
    scope.append(make("strong", null, `${coverage.total}`), make("span", null, coverage.total === state.playbooks.length ? "playbooks in scope" : `of ${state.playbooks.length} in scope`));
    intro.append(introCopy, scope);
    fragment.append(intro);

    const metrics = make("div", "metric-grid");
    metrics.append(
      metricCard(quality.average, "Average quality", `${quality.excellent} playbooks score 90 or higher`, "quality"),
      metricCard(percent(coverage.withTelemetry, total), "Telemetry mapped", `${coverage.withTelemetry} of ${coverage.total}`, "telemetry"),
      metricCard(percent(coverage.withQueries, total), "Query coverage", `${coverage.withQueries} of ${coverage.total}`, "queries"),
      metricCard(percent(coverage.withValidation, total), "Validation documented", `${coverage.withValidation} of ${coverage.total}`, "validation"),
      metricCard(percent(coverage.responseComplete, total), "Response complete", `${coverage.responseComplete} of ${coverage.total}`, "response"),
      metricCard(coverage.highRiskGaps, "High-risk gaps", "High/Critical records missing a key readiness control", coverage.highRiskGaps ? "risk" : "clear")
    );
    fragment.append(metrics);

    const grid = make("div", "dashboard-grid");
    grid.append(
      chartPanel("Tactic coverage", "Unique playbooks mapped to each tactic.", coverage.byTactic, "tactic"),
      chartPanel("Data-source coverage", "Playbooks with each telemetry category.", coverage.bySource, "source"),
      chartPanel("Platform coverage", "Structured platform mappings.", coverage.byPlatform, "platform"),
      chartPanel("Detection maturity", "Declared playbook maturity levels.", coverage.byMaturity, "maturity"),
      chartPanel("Validation status", "Documented validation state for the current result set.", coverage.byValidation, null),
      highRiskGapPanel()
    );
    fragment.append(grid);
    ui.dashboard.replaceChildren(fragment);
  }

  function percent(value, total) {
    return `${Math.round((value / total) * 100)}%`;
  }

  function metricCard(value, label, note, tone = "neutral") {
    const card = make("div", "metric-card");
    card.dataset.tone = tone;
    card.append(make("span", "metric-value", value), make("span", "metric-label", label), make("span", "metric-note", note));
    return card;
  }

  function chartPanel(title, description, values, filterKey) {
    const panel = make("section", "chart-panel");
    panel.append(make("h3", null, title), make("p", null, description));
    const list = make("ul", "bar-list");
    const entries = Object.entries(values).sort((a, b) => b[1] - a[1]).slice(0, 20);
    const max = Math.max(1, ...entries.map(entry => entry[1]));
    entries.forEach(([label, count]) => {
      const item = make("li");
      const button = make("button");
      button.type = "button";
      if (filterKey) {
        button.dataset.filterKey = filterKey;
        button.dataset.filterValue = label;
        button.setAttribute("aria-label", `Filter by ${label}: ${count} playbooks`);
      } else {
        button.disabled = true;
        button.setAttribute("aria-label", `${label}: ${count} playbooks`);
      }
      const meter = make("meter");
      meter.min = 0;
      meter.max = max;
      meter.value = count;
      button.append(make("span", "bar-label", label), meter, make("span", "bar-count", String(count)));
      item.append(button);
      list.append(item);
    });
    if (!entries.length) list.append(make("li", "metric-note", "No structured values in the current result set."));
    panel.append(list);
    return panel;
  }

  function highRiskGapPanel() {
    const panel = make("section", "chart-panel");
    panel.append(make("h3", null, "High-risk coverage gaps"), make("p", null, "High/Critical playbooks lacking telemetry, queries, validation, or a quality score of 75."));
    const list = make("div", "gap-list");
    const gaps = state.filtered.filter(playbook => ["critical", "high"].includes(playbook.severity) && (!playbook.telemetry_requirements.length || !playbook.queries.length || !nonEmpty(playbook.validation) || playbook.quality_score < 75)).slice(0, 12);
    gaps.forEach(playbook => {
      const button = make("button", "gap-item");
      button.type = "button";
      button.dataset.openId = playbook.id;
      button.addEventListener("click", event => { event.stopPropagation(); openPlaybook(playbook.id); });
      button.append(make("span", "gap-id", playbook.id), make("span", "gap-name", playbook.name), make("span", severityClass(playbook.severity), humanize(playbook.severity)));
      list.append(button);
    });
    if (!gaps.length) list.append(make("p", "metric-note", "No high-risk gaps in the current result set."));
    panel.append(list);
    return panel;
  }

  function openPlaybook(id, options = {}) {
    const playbook = state.byId.get(id);
    if (!playbook) return;
    const wasOpen = ui.panel.open;
    state.openId = id;
    renderPanel(playbook);
    if (options.recordRecent !== false) rememberRecent(id);
    if (options.historyMode === "replace") writeUrl("replace");
    else if (options.historyMode !== "none") writeUrl("push");
    if (!wasOpen) {
      ui.panel.showModal();
      syncModalState();
      if (options.focus !== false) ui["p-close"].focus();
    }
  }

  function renderPanel(playbook) {
    ui["p-id"].textContent = playbook.id;
    ui["p-kind"].textContent = humanize(playbook.kind);
    ui["p-score"].textContent = `Quality ${playbook.quality_score}`;
    ui["p-name"].textContent = playbook.name;
    ui["p-description"].textContent = playbook.description || "Structured detection and incident-response playbook.";
    renderPanelTags(playbook);
    const body = document.createDocumentFragment();
    const toc = document.createDocumentFragment();
    const sections = sectionsFor(playbook).sort((a, b) => Number(a.order || 0) - Number(b.order || 0));
    sections.forEach((section, index) => {
      const id = `${Core.slugify(playbook.id)}-${Core.slugify(section.id || section.title || `section-${index + 1}`)}`;
      const details = make("details", "pb-section");
      details.id = id;
      const summary = make("summary", null, section.title || humanize(section.id) || `Section ${index + 1}`);
      summary.id = `${id}-summary`;
      const content = make("div", "section-content");
      const populate = () => {
        if (content.dataset.rendered === "true") return;
        (Array.isArray(section.blocks) ? section.blocks : []).forEach(block => renderBlock(content, block));
        content.dataset.rendered = "true";
      };
      lazySections.set(details, populate);
      details.addEventListener("toggle", () => { if (details.open) populate(); });
      if (index === 0) { details.open = true; populate(); }
      details.append(summary, content);
      body.append(details);
      const link = make("a", null, summary.textContent);
      link.href = `#${id}`;
      link.dataset.sectionId = id;
      toc.append(link);
    });
    ui["p-body"].replaceChildren(body);
    ui["p-toc"].replaceChildren(toc);
    ui["p-body"].scrollTop = 0;
    syncOpenFavorite();
    syncPanelNavigation();
  }

  function renderPanelTags(playbook) {
    const fragment = document.createDocumentFragment();
    [...playbook.tactics, ...playbook.platforms, humanize(playbook.severity), humanize(playbook.maturity), humanize(playbook.status)].filter(Boolean).forEach(value => fragment.append(make("span", null, value)));
    const urls = [];
    if (playbook.url) urls.push({ title: "ATT&CK reference ↗", url: playbook.url });
    playbook.references.forEach(reference => { if (reference.url) urls.push(reference); });
    urls.slice(0, 5).forEach(reference => {
      const link = make("a", null, reference.title || "Reference ↗");
      link.href = reference.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      fragment.append(link);
    });
    ui["p-tags"].replaceChildren(fragment);
  }

  function sectionsFor(playbook) {
    const sourceSections = playbook.content_sections.map((section, index) => ({ ...section, order: Number(section.order || index + 1) }));
    const structured = [
      { id: "overview", title: "Overview and ATT&CK mapping", order: 1, blocks: [{ type: "paragraph", text: playbook.description }, { type: "key_value", items: [
        { label: "Tactics", value: playbook.tactics }, { label: "Techniques", value: playbook.techniques }, { label: "Subtechniques", value: playbook.subtechniques }, { label: "Platforms", value: playbook.platforms }
      ] }] },
      { id: "structured-telemetry", title: "Structured telemetry requirements", order: 101, blocks: [{ type: "telemetry", items: playbook.telemetry_requirements }] },
      { id: "structured-detection", title: "Detection engineering specification", order: 102, blocks: [{ type: "structured", value: playbook.detection }] },
      { id: "structured-queries", title: "Query examples", order: 103, blocks: [{ type: "queries", items: playbook.queries }] },
      { id: "structured-validation", title: "Safe validation and regression", order: 104, blocks: [{ type: "structured", value: playbook.validation }] },
      { id: "structured-response", title: "Operational incident response", order: 105, blocks: [{ type: "structured", value: playbook.response }] },
      { id: "structured-lifecycle", title: "Lifecycle, quality, coverage, and known gaps", order: 106, blocks: [{ type: "structured", value: { lifecycle: playbook.lifecycle, quality_breakdown: playbook.quality_breakdown, coverage: playbook.coverage, known_gaps: playbook.known_gaps } }] }
    ];
    if (!sourceSections.length) return structured;
    return [...sourceSections, ...structured.slice(1)];
  }

  function renderBlock(parent, block) {
    if (typeof block === "string") { parent.append(make("p", null, block)); return; }
    const type = String(block?.type || "structured").toLowerCase();
    if (type === "paragraph") { parent.append(make("p", null, block.text)); return; }
    if (type === "heading") { parent.append(make("h4", null, block.text || block.title)); return; }
    if (type === "list" || type === "steps") { renderListBlock(parent, block, type === "steps"); return; }
    if (type === "key_value") { renderKeyValueBlock(parent, block.items || block.entries || []); return; }
    if (type === "table") { renderTableBlock(parent, block); return; }
    if (type === "code" || type === "query") { renderCodeBlock(parent, block); return; }
    if (type === "callout") { renderCallout(parent, block); return; }
    if (type === "telemetry") { renderTelemetry(parent, block.items || []); return; }
    if (type === "queries") { renderQueries(parent, block.items || []); return; }
    appendStructuredValue(parent, block.value ?? block.text ?? block);
  }

  function renderListBlock(parent, block, forceOrdered) {
    const list = make(forceOrdered || block.ordered ? "ol" : "ul");
    (Array.isArray(block.items) ? block.items : []).forEach(item => {
      const li = make("li");
      appendStructuredValue(li, item);
      list.append(li);
    });
    parent.append(list);
  }

  function renderKeyValueBlock(parent, items) {
    const dl = make("dl", "kv-list");
    (Array.isArray(items) ? items : []).forEach(item => {
      dl.append(make("dt", null, item?.label || humanize(item?.key)));
      const dd = make("dd");
      appendStructuredValue(dd, item?.value);
      dl.append(dd);
    });
    parent.append(dl);
  }

  function renderTableBlock(parent, block) {
    const columns = Array.isArray(block.columns) ? block.columns.map(column => ({ key: String(column?.key || ""), label: String(column?.label || column?.key || "") })) : (block.headers || []).map(header => ({ key: String(header), label: String(header) }));
    const wrapper = make("div", "content-table-wrap");
    wrapper.tabIndex = 0;
    wrapper.setAttribute("role", "region");
    wrapper.setAttribute("aria-label", block.caption || "Scrollable data table");
    const table = make("table", "content-table");
    if (block.caption) table.append(make("caption", null, block.caption));
    const thead = make("thead");
    const headRow = make("tr");
    columns.forEach(column => { const th = make("th", null, column.label); th.scope = "col"; headRow.append(th); });
    thead.append(headRow);
    const tbody = make("tbody");
    (Array.isArray(block.rows) ? block.rows : []).forEach(rowData => {
      const row = make("tr");
      const values = Array.isArray(rowData) ? rowData : columns.map(column => rowData?.[column.key]);
      values.forEach(value => { const cell = make("td"); appendStructuredValue(cell, value); row.append(cell); });
      tbody.append(row);
    });
    table.append(thead, tbody);
    wrapper.append(table);
    parent.append(wrapper);
  }

  function renderCodeBlock(parent, block) {
    const wrapper = make("div", "code-block");
    if (block.caption || block.language) wrapper.append(make("span", "code-label", block.caption || block.language));
    const pre = make("pre");
    pre.append(make("code", null, block.code || block.query || block.text || ""));
    wrapper.append(pre);
    parent.append(wrapper);
  }

  function renderCallout(parent, block) {
    const callout = make("aside", `block-callout ${["warning", "danger", "success"].includes(block.tone) ? block.tone : "info"}`);
    if (block.title) callout.append(make("strong", null, block.title));
    callout.append(make("p", null, block.text));
    parent.append(callout);
  }

  function appendStructuredValue(parent, value, depth = 0) {
    if (value == null || value === "") { parent.append(document.createTextNode("Not specified")); return; }
    if (depth > 7) { parent.append(document.createTextNode("Additional nested content omitted.")); return; }
    if (["string", "number", "boolean"].includes(typeof value)) { parent.append(document.createTextNode(String(value))); return; }
    if (Array.isArray(value)) {
      if (!value.length) { parent.append(document.createTextNode("Not specified")); return; }
      const list = make("ul");
      value.forEach(item => { const li = make("li"); appendStructuredValue(li, item, depth + 1); list.append(li); });
      parent.append(list);
      return;
    }
    const entries = Object.entries(value).filter(([, item]) => item !== null && item !== "" && (!Array.isArray(item) || item.length));
    if (!entries.length) { parent.append(document.createTextNode("Not specified")); return; }
    const dl = make("dl", "kv-list");
    entries.forEach(([key, item]) => {
      dl.append(make("dt", null, humanize(key)));
      const dd = make("dd");
      appendStructuredValue(dd, item, depth + 1);
      dl.append(dd);
    });
    parent.append(dl);
  }

  function renderTelemetry(parent, sources) {
    const grid = make("div", "telemetry-grid");
    sources.forEach(source => {
      const card = make("section", "telemetry-card");
      const heading = make("h4", null, source.category || source.id || "Telemetry source");
      heading.append(make("span", "source-priority", source.priority || source.tier || "recommended"));
      card.append(heading);
      const items = Object.entries(source).filter(([key, value]) => !["id", "category", "priority", "tier"].includes(key) && nonEmpty(value)).map(([key, value]) => ({ label: humanize(key), value }));
      renderKeyValueBlock(card, items);
      grid.append(card);
    });
    if (!sources.length) grid.append(make("p", "metric-note", "No structured telemetry requirement is available."));
    parent.append(grid);
  }

  function renderQueries(parent, queries) {
    const grid = make("div", "query-grid");
    queries.forEach(query => {
      const wrapper = make("section", "code-block");
      const title = make("div", "query-title");
      title.append(make("strong", null, query.name), make("span", "pill", query.platform), make("span", "pill", query.language));
      wrapper.append(title);
      if (query.description) wrapper.append(make("p", null, query.description));
      const pre = make("pre");
      pre.append(make("code", null, query.query));
      wrapper.append(pre);
      const extra = Object.entries(query).filter(([key, value]) => !["id", "name", "platform", "language", "query", "description"].includes(key) && nonEmpty(value)).map(([key, value]) => ({ label: humanize(key), value }));
      if (extra.length) renderKeyValueBlock(wrapper, extra);
      grid.append(wrapper);
    });
    if (!queries.length) grid.append(make("p", "metric-note", "No structured query example is available."));
    parent.append(grid);
  }

  function navigateTableOfContents(event) {
    const link = event.target.closest("[data-section-id]");
    if (!link) return;
    event.preventDefault();
    const section = document.getElementById(link.dataset.sectionId);
    if (!section) return;
    section.open = true;
    lazySections.get(section)?.();
    section.scrollIntoView({ behavior: "smooth", block: "start" });
    const summary = section.querySelector("summary");
    summary?.focus({ preventScroll: true });
  }

  function requestClosePanel() {
    if (!state.openId) return;
    if (history.state?.appDialog && location.hash) history.back();
    else {
      state.openId = null;
      closePanelDirect();
      writeUrl("replace");
    }
  }

  function closePanelDirect() {
    state.openId = null;
    if (ui.panel.open) ui.panel.close();
    ui["p-body"].replaceChildren();
    ui["p-toc"].replaceChildren();
    syncModalState();
  }

  function syncModalState() {
    document.body.classList.toggle("modal-open", ui.panel.open || ui["command-palette"].open);
  }

  function panelCandidates() {
    return state.filtered.some(playbook => playbook.id === state.openId) ? state.filtered : state.playbooks;
  }

  function syncPanelNavigation() {
    if (!state.openId) return;
    const candidates = panelCandidates();
    const index = candidates.findIndex(playbook => playbook.id === state.openId);
    ui["p-prev"].disabled = index <= 0;
    ui["p-next"].disabled = index < 0 || index >= candidates.length - 1;
    ui["p-position"].textContent = index >= 0 ? `${index + 1} / ${candidates.length}` : "";
  }

  function navigatePanel(direction) {
    const candidates = panelCandidates();
    const index = candidates.findIndex(playbook => playbook.id === state.openId);
    const next = candidates[index + direction];
    if (next) openPlaybook(next.id, { historyMode: "replace", focus: false });
  }

  function rememberRecent(id) {
    state.recent = [id, ...state.recent.filter(value => value !== id)].slice(0, RECENT_LIMIT);
    savePreferences();
    if (state.recentOnly) scheduleRender();
  }

  function syncOpenFavorite() {
    const saved = state.favorites.has(state.openId);
    ui["p-save"].setAttribute("aria-pressed", String(saved));
    ui["p-save"].firstElementChild.textContent = saved ? "★" : "☆";
    const accessible = ui["p-save"].querySelector(".sr-only");
    if (accessible) accessible.textContent = saved ? "Remove saved playbook" : "Save playbook";
  }

  function toggleOpenFavorite() {
    if (!state.openId) return;
    state.favorites.has(state.openId) ? state.favorites.delete(state.openId) : state.favorites.add(state.openId);
    syncOpenFavorite();
    savePreferences();
    scheduleRender();
    toast(state.favorites.has(state.openId) ? "Playbook saved" : "Playbook removed from saved items");
  }

  async function writeClipboard(value) {
    if (navigator.clipboard?.writeText && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return true;
    }
    const active = document.activeElement;
    const textarea = make("textarea", "clipboard-fallback");
    textarea.value = value;
    textarea.readOnly = true;
    textarea.setAttribute("aria-hidden", "true");
    document.body.append(textarea);
    textarea.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } finally {
      textarea.remove();
      if (active instanceof HTMLElement && active.isConnected) active.focus();
    }
    return copied;
  }

  async function copyOpenLink() {
    if (!state.openId) return;
    const relative = Core.encodeUrlState(urlState(), location.pathname);
    const url = new URL(relative, location.href).href;
    try {
      if (!await writeClipboard(url)) throw new Error("copy command was rejected");
      toast("Playbook link copied");
    } catch (error) {
      console.warn("Clipboard unavailable", error);
      toast("Copy failed; use the browser address bar");
    }
  }

  function printOpenPlaybook() {
    if (!state.openId) return;
    ui["p-body"].querySelectorAll("details").forEach(details => {
      details.open = true;
      lazySections.get(details)?.();
    });
    window.print();
  }

  function downloadText(filename, value, type) {
    const blob = new Blob([value], { type: `${type};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const link = make("a");
    link.href = url;
    link.download = filename;
    link.rel = "noopener";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function exportOpenMarkdown() {
    const playbook = state.byId.get(state.openId);
    if (!playbook) return;
    downloadText(Core.safeFilename(`${playbook.id}-${playbook.name}`, "md"), Core.serializePlaybookMarkdown(playbook), "text/markdown");
    toast("Markdown export created");
  }

  function exportOpenJson() {
    const playbook = state.byId.get(state.openId);
    if (!playbook) return;
    downloadText(Core.safeFilename(`${playbook.id}-${playbook.name}`, "json"), Core.serializePlaybooksJson([playbook], state.data.meta), "application/json");
    toast("JSON export created");
  }

  const COMMANDS = [
    { id: "view-dashboard", label: "Open coverage dashboard", keywords: "coverage quality metrics", run: () => setView("dashboard") },
    { id: "view-matrix", label: "Open ATT&CK matrix", keywords: "tactics techniques", run: () => setView("matrix") },
    { id: "view-table", label: "Open coverage table", keywords: "list grid", run: () => setView("table") },
    { id: "view-list", label: "Open compact list", keywords: "rows", run: () => setView("list") },
    { id: "clear", label: "Clear all search and filters", keywords: "reset", run: clearFilters },
    { id: "theme", label: "Toggle light or dark theme", keywords: "appearance", run: toggleTheme }
  ];

  function openCommandPalette() {
    if (ui.panel.open) {
      toast("Close the playbook before opening the command palette");
      return;
    }
    ui["command-q"].value = "";
    renderCommandResults();
    if (!ui["command-palette"].open) ui["command-palette"].showModal();
    syncModalState();
    ui["command-q"].focus();
  }

  function closeCommandPalette() {
    if (ui["command-palette"].open) ui["command-palette"].close();
    syncModalState();
  }

  function commandMatches(value, query) {
    const tokens = Core.tokenizeQuery(query);
    const haystack = Core.normalizeText(value);
    return tokens.every(token => haystack.includes(token));
  }

  function renderCommandResults() {
    const query = ui["command-q"].value;
    const fragment = document.createDocumentFragment();
    const commands = COMMANDS.filter(command => commandMatches(`${command.label} ${command.keywords}`, query)).slice(0, 6);
    commands.forEach((command, index) => {
      const button = make("button", "command-item");
      button.type = "button";
      button.dataset.commandId = command.id;
      button.tabIndex = index === 0 ? 0 : -1;
      button.append(make("span", null, command.label), make("kbd", null, "Command"));
      fragment.append(button);
    });
    const playbooks = Core.filterAndSortPlaybooks(state.playbooks, { query, sort: "relevance" }, state.searchIndex).slice(0, 12);
    playbooks.forEach(playbook => {
      const button = make("button", "command-item");
      button.type = "button";
      button.dataset.commandPlaybook = playbook.id;
      button.tabIndex = commands.length || fragment.childNodes.length ? -1 : 0;
      button.append(make("span", null, `${playbook.id}: ${playbook.name}`), make("kbd", null, "Playbook"));
      fragment.append(button);
    });
    if (!commands.length && !playbooks.length) fragment.append(make("p", "command-empty", "No matching command or playbook."));
    ui["command-results"].replaceChildren(fragment);
  }

  function handleCommandClick(event) {
    const item = event.target.closest("[data-command-id],[data-command-playbook]");
    if (!item) return;
    if (item.dataset.commandPlaybook) {
      const id = item.dataset.commandPlaybook;
      closeCommandPalette();
      openPlaybook(id);
      return;
    }
    const command = COMMANDS.find(candidate => candidate.id === item.dataset.commandId);
    closeCommandPalette();
    command?.run();
  }

  function navigateCommandResults(event) {
    if (!['ArrowDown', 'ArrowUp', 'Enter', 'Escape'].includes(event.key)) return;
    if (event.key === "Escape") { event.preventDefault(); closeCommandPalette(); return; }
    const items = [...ui["command-results"].querySelectorAll("button")];
    if (!items.length) return;
    const current = items.indexOf(document.activeElement);
    if (event.key === "Enter" && current >= 0) { event.preventDefault(); items[current].click(); return; }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const direction = event.key === "ArrowDown" ? 1 : -1;
      const next = current < 0 ? 0 : (current + direction + items.length) % items.length;
      items[next].focus();
    }
  }

  function isTypingTarget(target) {
    return target instanceof HTMLElement && (/^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName) || target.isContentEditable);
  }

  function handleGlobalKeys(event) {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openCommandPalette();
      return;
    }
    if (event.key === "/" && !isTypingTarget(event.target) && !ui.panel.open && !ui["command-palette"].open) {
      event.preventDefault();
      ui.q.focus();
    }
  }

  function restorePreferences() {
    try {
      const saved = JSON.parse(localStorage.getItem(STORE) || localStorage.getItem(LEGACY_STORE) || "{}");
      if (["matrix", "list", "table", "dashboard"].includes(saved.view)) state.preferredView = saved.view;
      if (["dark", "light"].includes(saved.theme)) state.theme = saved.theme;
      state.favorites = new Set(Array.isArray(saved.favorites) ? saved.favorites.filter(value => typeof value === "string").slice(0, 500) : []);
      state.recent = Array.isArray(saved.recent) ? saved.recent.filter(value => typeof value === "string").slice(0, RECENT_LIMIT) : [];
    } catch { /* Storage can be unavailable or contain invalid data; use bounded defaults. */ }
  }

  function savePreferences() {
    try {
      localStorage.setItem(STORE, JSON.stringify({
        view: state.preferredView,
        theme: state.theme,
        favorites: [...state.favorites].slice(0, 500),
        recent: state.recent.slice(0, RECENT_LIMIT)
      }));
    } catch { /* Private browsing or storage policy may block persistence. */ }
  }

  function applyAppearance() {
    document.documentElement.dataset.theme = state.theme;
    const light = state.theme === "light";
    ui.theme?.setAttribute("aria-label", light ? "Use dark theme" : "Use light theme");
    const themeColor = document.querySelector('meta[name="theme-color"]');
    if (themeColor) themeColor.content = light ? "#f4f6fa" : "#0b0f17";
  }

  function toggleTheme() {
    state.theme = state.theme === "light" ? "dark" : "light";
    applyAppearance();
    savePreferences();
    toast(`${humanize(state.theme)} theme enabled`);
  }

  function renderDatasetMeta() {
    const attackVersion = state.data.meta.attack?.version ? ` · ATT&CK ${state.data.meta.attack.version}` : "";
    ui["data-version"].textContent = `Content ${state.data.meta.content_version}${attackVersion}`;
    ui["data-freshness"].textContent = `Updated ${state.data.meta.generated || "unknown"}`;
    ui["foot-count"].textContent = String(state.playbooks.length);
    const quality = Core.qualitySummary(state.playbooks);
    ui["foot-quality"].textContent = `Average quality ${quality.average}/100`;
  }

  function updateOnlineState() {
    ui["offline-banner"].hidden = navigator.onLine;
  }

  function toast(message) {
    ui.toast.textContent = message;
    ui.toast.classList.add("show");
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => ui.toast.classList.remove("show"), 2600);
  }

  function showLoadError(error) {
    console.error("Playbook console failed to start", error);
    ui.loading?.remove();
    ui["result-count"].textContent = "Unable to load playbooks";
    ui.empty.hidden = false;
    const strong = ui.empty.querySelector("strong");
    const copy = ui.empty.querySelector("span");
    if (strong) strong.textContent = "The structured playbook library could not be loaded";
    if (copy) copy.textContent = "Verify the deployment files and serve the multi-file edition over HTTP, or open standalone.html.";
  }

  async function registerServiceWorker() {
    if (globalThis.__ATTACK_PLAYBOOK_STANDALONE__ || !("serviceWorker" in navigator) || !location.protocol.startsWith("http")) return;
    try {
      const registration = await navigator.serviceWorker.register("service-worker.js");
      state.swRegistration = registration;
      const showWaiting = () => { if (registration.waiting) ui["update-banner"].hidden = false; };
      showWaiting();
      registration.addEventListener("updatefound", () => {
        const worker = registration.installing;
        worker?.addEventListener("statechange", () => {
          if (worker.state === "installed" && navigator.serviceWorker.controller) ui["update-banner"].hidden = false;
        });
      });
      navigator.serviceWorker.addEventListener("controllerchange", () => {
        if (state.refreshing) location.reload();
      });
      navigator.serviceWorker.addEventListener("message", event => {
        if (event.data?.type === "PLAYBOOK_SW_ACTIVATED" && event.data.version !== state.data.meta.content_version) ui["update-banner"].hidden = false;
      });
      setInterval(() => registration.update().catch(() => {}), 60 * 60 * 1000);
    } catch (error) {
      console.warn("Offline support could not be registered", error);
      toast("Offline installation is unavailable in this context");
    }
  }

  function activateUpdate() {
    const waiting = state.swRegistration?.waiting;
    if (!waiting) { location.reload(); return; }
    state.refreshing = true;
    waiting.postMessage({ type: "SKIP_WAITING" });
  }

  ui["command-palette"].addEventListener("cancel", event => { event.preventDefault(); closeCommandPalette(); });
  ui["command-palette"].addEventListener("click", event => { if (event.target === ui["command-palette"]) closeCommandPalette(); });
})();
