"use strict";

const CACHE_PREFIX = "tactic-atlas-";
const SCOPED_CACHE_PREFIX = `${CACHE_PREFIX}scope-`;
const LEGACY_CACHE_PREFIXES = [CACHE_PREFIX, "attack-playbook-console-"];
const SCOPE_URL = new URL("./", self.registration.scope);
const SCRIPT_URL = new URL(self.location?.href || SCOPE_URL.href);
// CacheStorage is shared by every service-worker scope on an origin. Include the encoded
// scope path so separate TacticAtlas deployments cannot overwrite or delete each other's
// offline data.
const CACHE_SCOPE = encodeURIComponent(SCOPE_URL.pathname || "/");
const CACHE_NAMESPACE = `${SCOPED_CACHE_PREFIX}${CACHE_SCOPE}-`;
const CACHE_REVISION = (SCRIPT_URL.searchParams.get("rev") || "release-4.5.0").replace(/[^a-z0-9._-]/gi, "-").slice(0, 100);
const SHELL_CACHE = `${CACHE_NAMESPACE}${CACHE_REVISION}-shell`;
const DATA_CACHE = `${CACHE_NAMESPACE}${CACHE_REVISION}-data`;
const INDEX_URL = new URL("index.html", SCOPE_URL).href;
const DATA_URL = new URL("data/playbooks.json", SCOPE_URL).href;
const DATA_URLS = [
  "data/playbooks.json",
  "data/event-catalog.json",
  "data/attack-analytics.json",
  "data/revision.json"
].map(path => new URL(path, SCOPE_URL).href);
const DATA_SET = new Set(DATA_URLS);
const SHELL_URLS = [
  "index.html",
  "assets/style.css",
  "assets/core.js",
  "assets/app.js",
  "assets/icon.svg",
  "manifest.webmanifest"
].map(path => new URL(path, SCOPE_URL).href);
const SHELL_SET = new Set(SHELL_URLS);
const OWNED_URLS = new Set([...SHELL_URLS, ...DATA_URLS]);

function isSuccessful(response) {
  return Boolean(response?.ok && response.type !== "opaque");
}

async function fetchRequired(url) {
  const response = await fetch(new Request(url, { cache: "reload", credentials: "same-origin" }));
  if (!isSuccessful(response)) throw new Error(`Required application resource failed: ${url}`);
  return response;
}

async function putSuccessful(cacheName, key, response) {
  if (!isSuccessful(response)) return;
  // Clone before the first await. The response is also returned to the page and may start being
  // consumed while CacheStorage opens; cloning after that point can throw "body already used".
  const copy = response.clone();
  const cache = await caches.open(cacheName);
  await cache.put(key, copy);
}

async function cachedResponse(cacheName, key) {
  const cache = await caches.open(cacheName);
  return cache.match(key);
}

function isUnscopedLegacyCache(cacheName) {
  return !cacheName.startsWith(SCOPED_CACHE_PREFIX)
    && LEGACY_CACHE_PREFIXES.some(prefix => cacheName.startsWith(prefix));
}

async function removeOwnedLegacyEntries(cacheName) {
  const cache = await caches.open(cacheName);
  const requests = await cache.keys();
  const owned = requests.filter(request => OWNED_URLS.has(request.url));
  if (!owned.length) return;
  await Promise.all(owned.map(request => cache.delete(request)));
  if (!(await cache.keys()).length) await caches.delete(cacheName);
}

function offlineResponse(message, type = "text/plain") {
  return new Response(message, {
    status: 503,
    statusText: "Offline",
    headers: { "Content-Type": `${type}; charset=utf-8`, "Cache-Control": "no-store" }
  });
}

self.addEventListener("install", event => {
  event.waitUntil((async () => {
    const cache = await caches.open(SHELL_CACHE);
    for (const url of SHELL_URLS) {
      const response = await fetchRequired(url);
      await cache.put(url, response);
    }
    const dataCache = await caches.open(DATA_CACHE);
    for (const url of DATA_URLS) await dataCache.put(url, await fetchRequired(url));
  })());
});

self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    const current = new Set([SHELL_CACHE, DATA_CACHE]);
    const keys = await caches.keys();
    await Promise.all([
      ...keys
        .filter(key => key.startsWith(CACHE_NAMESPACE) && !current.has(key))
        .map(key => caches.delete(key)),
      ...keys.filter(isUnscopedLegacyCache).map(removeOwnedLegacyEntries)
    ]);
    await self.clients.claim();
    const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    clients.forEach(client => client.postMessage({ type: "PLAYBOOK_SW_ACTIVATED", revision: CACHE_REVISION }));
  })());
});

self.addEventListener("message", event => {
  if (event.data?.type === "SKIP_WAITING") {
    self.skipWaiting();
    return;
  }
  if (event.data?.type === "GET_VERSION") {
    event.source?.postMessage({ type: "PLAYBOOK_SW_VERSION", revision: CACHE_REVISION });
  }
});

function cacheNetworkResponse(event, networkResponse, cacheName, key) {
  const update = networkResponse
    .then(response => putSuccessful(cacheName, key, response))
    .catch(() => {});
  if (typeof event.waitUntil === "function") event.waitUntil(update);
}

async function handleNavigation(networkResponse) {
  try {
    const response = await networkResponse;
    if (isSuccessful(response)) return response;
    return (await cachedResponse(SHELL_CACHE, INDEX_URL)) || response;
  } catch {
    return (await cachedResponse(SHELL_CACHE, INDEX_URL)) || offlineResponse("The playbook console is unavailable offline.", "text/html");
  }
}

async function handleData(networkResponse, url) {
  try {
    const response = await networkResponse;
    if (isSuccessful(response)) return response;
    return (await cachedResponse(DATA_CACHE, url)) || response;
  } catch {
    return (await cachedResponse(DATA_CACHE, url)) || offlineResponse('{"error":"Application data is unavailable offline."}', "application/json");
  }
}

async function handleShell(networkResponse, url) {
  try {
    const response = await networkResponse;
    if (isSuccessful(response)) return response;
    return (await cachedResponse(SHELL_CACHE, url)) || response;
  } catch {
    return (await cachedResponse(SHELL_CACHE, url)) || offlineResponse("Application resource unavailable offline.");
  }
}

self.addEventListener("fetch", event => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== SCOPE_URL.origin) return;

  const isAppNavigation = request.mode === "navigate"
    && (url.pathname === SCOPE_URL.pathname || url.pathname === new URL("index.html", SCOPE_URL).pathname);

  if (isAppNavigation) {
    const networkResponse = fetch(request);
    cacheNetworkResponse(event, networkResponse, SHELL_CACHE, INDEX_URL);
    event.respondWith(handleNavigation(networkResponse));
  } else if (DATA_SET.has(url.href)) {
    const networkResponse = fetch(request);
    cacheNetworkResponse(event, networkResponse, DATA_CACHE, url.href);
    event.respondWith(handleData(networkResponse, url.href));
  } else if (SHELL_SET.has(url.href)) {
    const networkResponse = fetch(request);
    cacheNetworkResponse(event, networkResponse, SHELL_CACHE, url.href);
    event.respondWith(handleShell(networkResponse, url.href));
  }
});
