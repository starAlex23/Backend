const CACHE_NAME = "stempel-cache-v2";
const URLS_TO_CACHE = [
  "/",
  "/index.html",
  "/manifest.json",
  "/offline.html"
];

// =====================
// Installieren
// =====================
self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(URLS_TO_CACHE))
  );
  self.skipWaiting(); // sofort aktivieren
});

// =====================
// Aktivieren (alte Caches löschen)
// =====================
self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(key => key !== CACHE_NAME && caches.delete(key))
      )
    )
  );
  self.clients.claim(); // sofort für alle Clients übernehmen
});

// =====================
// Fetch-Handler
// =====================
self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);

  // Nur eigene Requests abfangen
  if (url.origin === location.origin) {

    // HTML-Dokumente → network-first
    if (event.request.destination === "document") {
      event.respondWith(
        fetch(event.request)
          .then(resp => {
            const respClone = resp.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, respClone));
            return resp;
          })
          .catch(() => caches.match(event.request).then(cached => cached || caches.match('/offline.html')))
      );
      return;
    }

    // CSS, JS, Bilder → cache-first
    event.respondWith(
      caches.match(event.request).then(cached => {
        return cached || fetch(event.request).then(resp => {
          const respClone = resp.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, respClone));
          return resp;
        }).catch(() => {
          // Fallback für Bilder optional
          if (event.request.destination === "image") {
            return new Response("", {status: 404});
          }
        });
      })
    );

  } else {
    // externe Requests normal laden
    event.respondWith(fetch(event.request));
  }
});

// =====================
// Optional: Message zum SW-Update
// =====================
self.addEventListener("message", event => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
});


