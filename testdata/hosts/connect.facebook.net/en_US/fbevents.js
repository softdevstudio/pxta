// Test stand-in for the Meta Pixel: same endpoint and parameters, not Meta's code.
(function () {
  var queue = (window.fbq && window.fbq.queue) || [];
  var pixels = {};
  function hex(buf) { return Array.from(new Uint8Array(buf)).map(function (x) { return x.toString(16).padStart(2, '0'); }).join(''); }
  function hash(s) { return crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s).trim().toLowerCase())).then(hex); }
  async function send(ev, data) {
    for (var id in pixels) {
      var p = new URLSearchParams({ id: id, ev: ev, dl: location.href, rl: document.referrer, if: String(window !== window.top), ts: String(Date.now()), v: '2.9.fixture' });
      var ud = pixels[id];
      for (var k in ud) p.set('ud[' + k + ']', await hash(ud[k]));
      for (var c in (data || {})) p.set('cd[' + c + ']', String(data[c]));
      new Image().src = 'https://www.facebook.com/tr/?' + p.toString();
    }
  }
  function fbq(cmd, a, b) {
    if (cmd === 'init') pixels[a] = Object.assign({}, b || {});
    else if (cmd === 'track' || cmd === 'trackCustom') send(a, b);
  }
  // Automatic advanced matching: read email fields when they change.
  document.addEventListener('change', function (e) {
    var el = e.target;
    if (el && el.tagName === 'INPUT' && (el.type === 'email' || /mail/i.test(el.name)) && el.value) {
      for (var id in pixels) pixels[id].em = el.value;
      send('SubscribedButtonClick', {});
    }
  }, true);
  window.fbq = fbq;
  queue.forEach(function (args) { fbq.apply(null, args); });
})();
