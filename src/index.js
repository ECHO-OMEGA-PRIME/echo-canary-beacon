// Echo Canary Beacon — Honeypot tracking pixel + canary link server
// Logs EVERYTHING about visitors: IP, device, headers, timing, fingerprint

const TRANSPARENT_GIF = new Uint8Array([
  0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
  0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21,
  0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
  0x01, 0x00, 0x3b
]);

// Fingerprint collection page served on canary link clicks
const FINGERPRINT_PAGE = `<!DOCTYPE html>
<html><head><title>Document Shared With You</title>
<style>body{font-family:Segoe UI,Arial;background:#1a1a2e;color:#eee;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#16213e;border-radius:12px;padding:40px;max-width:500px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h2{color:#0f3460}p{color:#999;line-height:1.6}.spinner{border:3px solid #333;border-top:3px solid #e94560;border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}</style></head>
<body><div class="card">
<div class="spinner"></div>
<h2>Loading Secure Document...</h2>
<p>Verifying your access permissions.<br>This may take a moment.</p>
</div>
<script>
(async()=>{
  const d={
    ts:new Date().toISOString(),
    ua:navigator.userAgent,
    lang:navigator.language,
    langs:JSON.stringify(navigator.languages),
    platform:navigator.platform,
    cores:navigator.hardwareConcurrency||0,
    memory:navigator.deviceMemory||0,
    maxTouch:navigator.maxTouchPoints||0,
    screen:screen.width+'x'+screen.height,
    screenAvail:screen.availWidth+'x'+screen.availHeight,
    colorDepth:screen.colorDepth,
    pixelRatio:window.devicePixelRatio,
    timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,
    tzOffset:new Date().getTimezoneOffset(),
    online:navigator.onLine,
    cookieEnabled:navigator.cookieEnabled,
    dnt:navigator.doNotTrack,
    webgl:'unknown',
    canvas:'unknown',
    battery:'unknown',
    connection:'unknown',
    plugins:navigator.plugins?navigator.plugins.length:0,
    referrer:document.referrer,
    url:window.location.href
  };
  // WebGL fingerprint
  try{
    const c=document.createElement('canvas');
    const gl=c.getContext('webgl')||c.getContext('experimental-webgl');
    if(gl){
      d.webgl=gl.getParameter(gl.RENDERER)+' | '+gl.getParameter(gl.VENDOR);
      const dbg=gl.getExtension('WEBGL_debug_renderer_info');
      if(dbg) d.webgl=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)+' | '+gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
    }
  }catch(e){}
  // Canvas fingerprint
  try{
    const c=document.createElement('canvas');c.width=200;c.height=50;
    const ctx=c.getContext('2d');
    ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillStyle='#f60';
    ctx.fillRect(0,0,200,50);ctx.fillStyle='#069';
    ctx.fillText('echo-canary-fp',2,15);
    d.canvas=c.toDataURL().slice(-32);
  }catch(e){}
  // Battery
  try{
    if(navigator.getBattery){
      const b=await navigator.getBattery();
      d.battery=Math.round(b.level*100)+'% '+(b.charging?'charging':'discharging');
    }
  }catch(e){}
  // Network
  try{
    if(navigator.connection){
      const c=navigator.connection;
      d.connection=c.effectiveType+' '+c.downlink+'Mbps rtt:'+c.rtt;
    }
  }catch(e){}
  // Send fingerprint to beacon
  const token=window.location.pathname.split('/').pop();
  await fetch('/fp/'+token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
  // Show "access denied" after collecting
  setTimeout(()=>{
    document.querySelector('.card').innerHTML='<h2 style="color:#e94560">Access Denied</h2><p>This document link has expired or you do not have permission to view it.<br><br>Contact the document owner for access.</p>';
  },3000);
})();
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const ua = request.headers.get('user-agent') || 'unknown';
    const country = request.headers.get('cf-ipcountry') || 'unknown';
    const ts = new Date().toISOString();

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '86400' } });
    }

    // Payload size limit (1MB)
    if ((request.method === 'POST' || request.method === 'PUT') && parseInt(request.headers.get('Content-Length') || '0') > 1_048_576) {
      return json({ error: 'Payload too large', max_bytes: 1048576 }, 413, request);
    }

    // Collect ALL headers
    const headers = {};
    for (const [k, v] of request.headers.entries()) {
      headers[k] = v;
    }

    // Health check
    if (path === '/health') {
      const hits = await env.HITS.get('total_hits');
      return json({ status: 'ok', service: 'echo-canary-beacon', version: '1.0.1', total_hits: parseInt(hits || '0'), ts }, 200, request);
    }

    // View all captured data (authenticated)
    if (path === '/captures') {
      const key = url.searchParams.get('key');
      if (key !== env.ADMIN_KEY) return json({ error: 'unauthorized' }, 403, request);
      const list = await env.HITS.list({ prefix: 'hit:' });
      const captures = [];
      for (const k of list.keys) {
        const val = await env.HITS.get(k.name, 'json');
        if (val) captures.push(val);
      }
      captures.sort((a, b) => b.ts?.localeCompare(a.ts));
      return json({ total: captures.length, captures }, 200, request);
    }

    // Fingerprint collection endpoint (POST from JS)
    if (path.startsWith('/fp/')) {
      const token = path.split('/').pop();
      let body = {};
      try { body = await request.json(); } catch(e) { log('warn', 'fp_parse_failed', { error: e.message }); }
      const record = {
        type: 'fingerprint',
        token,
        ip,
        country,
        ua,
        headers,
        fingerprint: body,
        ts
      };
      const hitKey = 'hit:fp:' + ts.replace(/[:.]/g, '-') + ':' + ip.replace(/\./g, '-');
      await env.HITS.put(hitKey, JSON.stringify(record), { expirationTtl: 86400 * 30 });
      await incrementCounter(env);
      log('warn', 'FINGERPRINT_CAPTURED', { ip, token, device: body.platform, screen: body.screen, tz: body.timezone });
      return json({ ok: true }, 200, request);
    }

    // Tracking pixel (embedded in email as <img>)
    if (path.startsWith('/px/')) {
      const token = path.split('/').pop();
      const record = {
        type: 'pixel_open',
        token,
        ip,
        country,
        ua,
        headers,
        ts
      };
      const hitKey = 'hit:px:' + ts.replace(/[:.]/g, '-') + ':' + ip.replace(/\./g, '-');
      await env.HITS.put(hitKey, JSON.stringify(record), { expirationTtl: 86400 * 30 });
      await incrementCounter(env);
      log('alert', 'EMAIL_OPENED_BY_INTRUDER', { ip, ua, country, token });
      return new Response(TRANSPARENT_GIF, {
        headers: {
          'Content-Type': 'image/gif',
          'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      });
    }

    // Canary link (clicked from email — serves fingerprint collection page)
    if (path.startsWith('/doc/')) {
      const token = path.split('/').pop();
      const record = {
        type: 'canary_click',
        token,
        ip,
        country,
        ua,
        headers,
        ts
      };
      const hitKey = 'hit:click:' + ts.replace(/[:.]/g, '-') + ':' + ip.replace(/\./g, '-');
      await env.HITS.put(hitKey, JSON.stringify(record), { expirationTtl: 86400 * 30 });
      await incrementCounter(env);
      log('critical', 'CANARY_LINK_CLICKED', { ip, ua, country, token });
      return new Response(FINGERPRINT_PAGE, {
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
      });
    }

    // Catch-all — log everything
    const record = {
      type: 'unknown_visit',
      path,
      ip,
      country,
      ua,
      headers,
      ts
    };
    const hitKey = 'hit:unk:' + ts.replace(/[:.]/g, '-');
    await env.HITS.put(hitKey, JSON.stringify(record), { expirationTtl: 86400 * 30 });
    return json({ error: 'not found', path }, 404, request);
  }
};

function log(level, message, data = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), worker: 'echo-canary-beacon', level, message, ...data }));
}

async function incrementCounter(env) {
  const current = parseInt(await env.HITS.get('total_hits') || '0');
  await env.HITS.put('total_hits', String(current + 1));
}

const ALLOWED_ORIGINS = ['https://echo-ept.com', 'https://echo-op.com', 'https://www.echo-ept.com', 'https://www.echo-op.com', 'http://localhost:3000', 'http://localhost:3001'];

function json(data, status = 200, request) {
  const origin = request?.headers?.get('Origin') || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': allowedOrigin }
  });
}
