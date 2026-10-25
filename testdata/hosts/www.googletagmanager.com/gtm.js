// Test stand-in for a Google Tag Manager container that adds Google Analytics a second later.
(function () {
  setTimeout(function () {
    window.dataLayer = window.dataLayer || [];
    window.gtag = window.gtag || function () { window.dataLayer.push(arguments); };
    gtag('js', new Date()); gtag('config', 'G-FROMGTM');
    var s = document.createElement('script'); s.src = 'https://www.googletagmanager.com/gtag/js?id=G-FROMGTM'; document.head.appendChild(s);
  }, 1000);
})();
