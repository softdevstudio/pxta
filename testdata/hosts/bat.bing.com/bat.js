// Test stand-in for the Microsoft UET tag: same endpoint and parameters, not Microsoft's code.
(function () {
  window.UET = function (o) { this.ti = o.ti; };
  window.UET.prototype.push = function (evt) {
    var p = new URLSearchParams({ ti: this.ti, evt: evt === 'pageLoad' ? 'pageLoad' : 'custom', p: location.href, tl: document.title, r: document.referrer, mid: 'fixture-mid' });
    new Image().src = 'https://bat.bing.com/action/0?' + p.toString();
  };
  if (window.__uetReady) window.__uetReady();
})();
