"use strict";

const APP_VERSION = "4.0.0";
const CACHE_PREFIX = "attack-playbook-console-";
const SHELL_CACHE = `${CACHE_PREFIX}${APP_VERSION}-shell`;
const DATA_CACHE = `${CACHE_PREFIX}${APP_VERSION}-data`;
const SCOPE_URL = new URL("./", self.registration.scope);
const INDEX_URL = new URL("index.html", SCOPE_URL).href;
const DATA_URL = new URL("data/playbooks.json", SCOPE_URL).href;
const SHELL_URLS = [
  "index.html",
  "assets/style.css",
  "assets/core.js",
  "assets/app.js",
  "assets/icon.svg",
  "manifest.webmanifest"
].map(path => new URL(path, SCOPE_URL).href);
const SHELL_SET = new Set(SHELL_URLS);

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
  const cache = await caches.open(cacheName);
  await cache.put(key, response.clone());
}

async function cachedResponse(cacheName, key) {
  const cache = await caches.open(cacheName);
  return cache.match(key);
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
    await dataCache.put(DATA_URL, await fetchRequired(DATA_URL));
  })());
});

self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    const current = new Set([SHELL_CACHE, DATA_CACHE]);
    const keys = await caches.keys();
    await Promise.all(keys
      .filter(key => key.startsWith(CACHE_PREFIX) && !current.has(key))
      .map(key => caches.delete(key)));
    await self.clients.claim();
    const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    clients.forEach(client => client.postMessage({ type: "PLAYBOOK_SW_ACTIVATED", version: APP_VERSION }));
  })());
});

self.addEventListener("message", event => {
  if (event.data?.type === "SKIP_WAITING") {
    self.skipWaiting();
    return;
  }
  if (event.data?.type === "GET_VERSION") {
    event.source?.postMessage({ type: "PLAYBOOK_SW_VERSION", version: APP_VERSION });
  }
});

async function handleNavigation(request) {
  try {
    const response = await fetch(request);
    if (isSuccessful(response)) {
      await putSuccessful(SHELL_CACHE, INDEX_URL, response);
      return response;
    }
    return (await cachedResponse(SHELL_CACHE, INDEX_URL)) || response;
  } catch {
    return (await cachedResponse(SHELL_CACHE, INDEX_URL)) || offlineResponse("The playbook console is unavailable offline.", "text/html");
  }
}

async function handleData(request) {
  try {
    const response = await fetch(request);
    if (isSuccessful(response)) {
      await putSuccessful(DATA_CACHE, DATA_URL, response);
      return response;
    }
    return (await cachedResponse(DATA_CACHE, DATA_URL)) || response;
  } catch {
    return (await cachedResponse(DATA_CACHE, DATA_URL)) || offlineResponse('{"error":"Playbook data is unavailable offline."}', "application/json");
  }
}

async function handleShell(request) {
  try {
    const response = await fetch(request);
    if (isSuccessful(response)) await putSuccessful(SHELL_CACHE, request.url, response);
    if (isSuccessful(response)) return response;
    return (await cachedResponse(SHELL_CACHE, request.url)) || response;
  } catch {
    return (await cachedResponse(SHELL_CACHE, request.url)) || offlineResponse("Application resource unavailable offline.");
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
    event.respondWith(handleNavigation(request));
  } else if (url.href === DATA_URL) {
    event.respondWith(handleData(request));
  } else if (SHELL_SET.has(url.href)) {
    event.respondWith(handleShell(request));
  }
});
