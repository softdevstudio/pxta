// Test stand-in for the TikTok Pixel: same endpoint and fields, not TikTok's code.
(function () {
  var q = window.ttq || []; var code = ''; var user = {};
  function hex(buf) { return Array.from(new Uint8Array(buf)).map(function (x) { return x.toString(16).padStart(2, '0'); }).join(''); }
  async function send(event, props) {
    var u = { anonymous_id: 'ttp-fixture-123' };
    if (user.email) u.email = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(user.email.trim().toLowerCase())));
    var body = { event: event, pixel_code: code, timestamp: new Date().toISOString(), context: { page: { url: location.href, referrer: document.referrer }, user: u, library: { name: 'pixel.js', version: 'fixture' } }, properties: props || {} };
    fetch('https://analytics.tiktok.com/api/v2/pixel', { method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' }, keepalive: true, mode: 'no-cors' });
  }
  var ttq = { load: function (c) { code = c; }, page: function () { send('Pageview'); }, track: send, identify: function (o) { user = Object.assign(user, o); } };
  window.ttq = ttq;
  (q._q || q).forEach(function (a) { ttq[a[0]].apply(ttq, Array.prototype.slice.call(a, 1)); });
})();
