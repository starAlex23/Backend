// sw.js
const CACHE_NAME = "stempel-cache-v1";
const URLS_TO_CACHE = [
  "/",
  "/index.html",
  "/manifest.json"
  // Icons entfernt, da nicht mehr vorhanden
];

// Installieren & Dateien cachen
self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(URLS_TO_CACHE))
  );
  self.skipWaiting();
});

// Alte Caches aufräumen
self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(key => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      )
    )
  );
  self.clients.claim();
});

// Netzwerkabfragen abfangen
self.addEventListener("fetch", event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request).catch(() => {
        // Optional: Fallback-Seite anzeigen, falls offline
        // return caches.match('/offline.html');
      });
    })
  );
});

