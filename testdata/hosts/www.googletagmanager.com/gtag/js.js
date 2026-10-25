// Test stand-in for gtag.js (Google Analytics 4): same endpoint and parameters, not Google's code.
(function () {
  var dl = window.dataLayer = window.dataLayer || [];
  var cfg = {}, consent = { ad_storage: 'granted', analytics_storage: 'granted' };
  var q = new URLSearchParams((document.currentScript && document.currentScript.src || '').split('?')[1] || '');
  function gcs() { return 'G1' + (consent.ad_storage === 'granted' ? '1' : '0') + (consent.analytics_storage === 'granted' ? '1' : '0'); }
  function base(tid) {
    var p = new URLSearchParams({ v: '2', tid: tid, gcs: gcs(), cid: '1111111111.2222222222', dl: location.href, dt: document.title, dr: document.referrer });
    if (cfg[tid].user_id) p.set('uid', cfg[tid].user_id);
    return p;
  }
  function send(en, params, beacon) {
    for (var tid in cfg) {
      var p = base(tid);
      if (en === 'page_view' && !params) { p.set('en', en); navigator.sendBeacon('https://region1.google-analytics.com/g/collect?' + p.toString()); continue; }
      var body = new URLSearchParams({ en: en });
      for (var k in params || {}) body.set('ep.' + k, String(params[k]));
      navigator.sendBeacon('https://region1.google-analytics.com/g/collect?' + p.toString(), '_ee=1\n' + body.toString());
    }
  }
  function handle(a) {
    var cmd = a[0], x = a[1], y = a[2];
    if (cmd === 'config') { cfg[x] = y || {}; if (!(y && y.send_page_view === false)) send('page_view'); }
    else if (cmd === 'event') send(x, y);
    else if (cmd === 'set' && x === 'user_id') { for (var t in cfg) cfg[t].user_id = y; }
  }
  // Consent commands first, as gtag.js holds hits until consent is known.
  dl.forEach(function (a) { if (a[0] === 'consent') Object.assign(consent, a[2] || {}); });
  dl.forEach(function (a) { if (a[0] !== 'consent') handle(a); });
  var push = dl.push.bind(dl);
  dl.push = function (a) { if (a[0] === 'consent') Object.assign(consent, a[2] || {}); else handle(a); return push(a); };
  if (!window.gtag) window.gtag = function () { dl.push(arguments); };
})();
