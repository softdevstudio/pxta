// Test stand-in for the X Pixel: same endpoint and parameters, not X's code.
(function () {
  var q = (window.twq && window.twq.queue) || []; var id = '';
  function twq(cmd, a) {
    if (cmd === 'config' || cmd === 'init') { id = a; return; }
    var p = new URLSearchParams({ txn_id: id, p_id: 'Twitter', tw_document_href: location.href, events: JSON.stringify([[a || 'pageview', null]]), tpx_cb: 'twttr.adsct' });
    new Image().src = 'https://analytics.twitter.com/i/adsct?' + p.toString();
  }
  window.twq = twq;
  q.forEach(function (args) { twq.apply(null, args); });
})();
