// Test stand-in for the Pinterest Tag: same endpoint and parameters, not Pinterest's code.
(function () {
  var q = (window.pintrk && window.pintrk.queue) || []; var tid = ''; var em = '';
  function hex(buf) { return Array.from(new Uint8Array(buf)).map(function (x) { return x.toString(16).padStart(2, '0'); }).join(''); }
  async function send(event, data) {
    var pd = {};
    if (em) pd.em = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(em.trim().toLowerCase())));
    var p = new URLSearchParams({ tid: tid, event: event, ad: JSON.stringify({ loc: location.href, ref: document.referrer }), pd: JSON.stringify(pd), ed: JSON.stringify(data || {}) });
    new Image().src = 'https://ct.pinterest.com/v3/?' + p.toString();
  }
  function pintrk(cmd, a, b) { if (cmd === 'load') { tid = a; em = (b && b.em) || ''; } else if (cmd === 'page') send('pagevisit'); else if (cmd === 'track') send(a, b); }
  window.pintrk = pintrk;
  q.forEach(function (args) { pintrk.apply(null, args); });
})();
