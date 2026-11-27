const C='qlkh-v48-bbe24ecdfa';const F=['/','/manifest.webmanifest','/icon-192.png','/icon-512.png','/icon-180.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(F)).catch(()=>{}).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{const r=e.request;const u=new URL(r.url);if(r.method!=='GET'||u.origin!==location.origin||u.pathname.startsWith('/api/')||u.pathname.startsWith('/cdn-cgi/'))return;
 if(r.mode==='navigate'){e.respondWith(fetch(r).then(x=>{if(x.ok&&x.type==='basic'){const y=x.clone();caches.open(C).then(c=>c.put('/',y))}return x}).catch(()=>caches.match('/')));return}
 e.respondWith(caches.match(r).then(x=>x||fetch(r)))});
