// Offline application shell only. Never caches decrypted list contents or API requests.
const CACHE = 'shared-list-shell-v2';
const SHELL = [
  './', './index.html', './app.js', './model.js', './db.js', './i18n.js',
  './crypto.js', './style.css', './manifest.webmanifest', './icons/icon.svg',
  './icons/icon-192.png', './icons/icon-512.png',
];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(SHELL)));
  self.skipWaiting();
});
self.addEventListener('activate', event => {
  event.waitUntil(Promise.all([
    caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key)))),
    self.clients.claim(),
  ]));
});
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.includes('/api/')) return;
  event.respondWith((async () => {
    const cached = await caches.match(request, { ignoreSearch: true });
    if (cached) return cached;
    try { return await fetch(request); }
    catch { if (request.mode === 'navigate') return caches.match('./index.html'); throw Error('Offline asset unavailable'); }
  })());
});
