package pxta

// The browser tests audit fixture sites served from testdata. A local HTTPS
// server answers for every host name, and Chrome is pointed at it with a
// host resolver rule, so the fixture pages load "connect.facebook.net" and
// send to "www.facebook.com/tr" without leaving the machine. The tracker and
// consent scripts under testdata are small stand-ins written for these
// tests: they send what the real tags send, to the same endpoints, and the
// consent banners use each platform's own button IDs and JavaScript API.
// They are not the vendors' code.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var collectHosts = []string{"facebook.com", "google-analytics.com", "analytics.tiktok.com", "px.ads.linkedin.com", "bat.bing.com",
	"ct.pinterest.com", "tr.snapchat.com", "analytics.twitter.com", "googleads.g.doubleclick.net", "collector.datasink.test",
	"beacon.exitmetrics.test", "events.workerstats.test"}

type fixture struct {
	srv  *httptest.Server
	port string
	mu   sync.Mutex
	hits []string
}

func (f *fixture) hit(s string) {
	f.mu.Lock()
	f.hits = append(f.hits, s)
	f.mu.Unlock()
}

// Hits returns every request the fixture server received.
func (f *fixture) Hits() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hits...)
}

func startFixtures(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{}
	root, _ := filepath.Abs("testdata/hosts")
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		f.hit(host + r.URL.RequestURI())
		w.Header().Set("Cache-Control", "no-store")
		if serveDynamic(w, r, host) {
			return
		}
		p := r.URL.Path
		if strings.HasSuffix(p, "/") {
			p += "index.html"
		}
		file := filepath.Join(root, host, filepath.FromSlash(p))
		if !strings.HasPrefix(file, root+string(filepath.Separator)) {
			http.NotFound(w, r)
			return
		}
		cands := []string{file}
		if filepath.Ext(file) == "" {
			cands = []string{file + ".html", file + ".js"}
		}
		for _, c := range cands {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				if strings.HasSuffix(c, ".js") {
					w.Header().Set("Content-Type", "application/javascript")
				}
				http.ServeFile(w, r, c)
				return
			}
		}
		for _, c := range collectHosts {
			if hostMatches(host, c) {
				if r.Method == "GET" {
					w.Header().Set("Content-Type", "image/gif")
					w.Write([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"))
				} else {
					w.WriteHeader(204)
				}
				return
			}
		}
		http.NotFound(w, r)
	}))
	f.srv.EnableHTTP2 = false
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	_, f.port, _ = net.SplitHostPort(f.srv.Listener.Addr().String())
	return f
}

// Args are the Chrome flags that send every host name to the fixture server.
func (f *fixture) Args() []string {
	return []string{"--host-resolver-rules=MAP * 127.0.0.1:" + f.port + ", EXCLUDE localhost", "--ignore-certificate-errors", "--no-proxy-server"}
}

// Client reaches the fixture server for robots.txt and sitemaps.
func (f *fixture) Client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", "127.0.0.1:"+f.port)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test fixtures only
	}}
}

// serveDynamic answers the generated fixtures: consent platform scripts,
// the consent test sites, and the large site for the crash test.
func serveDynamic(w http.ResponseWriter, r *http.Request, host string) bool {
	switch {
	case host == "cdn.cookielaw.org":
		js(w, cmpScript("onetrust", r.URL.Query().Get("delay")))
	case host == "consent.cookiebot.com":
		js(w, cmpScript("cookiebot", ""))
	case host == "sdk.privacy-center.org":
		js(w, cmpScript("didomi", ""))
	case host == "app.usercentrics.eu":
		js(w, cmpScript("usercentrics", ""))
	case host == "cmp.fixtures.test":
		js(w, cmpScript(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".js"), ""))
	case host == "consent-frame.test":
		page(w, `<!doctype html><html><body style="margin:0;font:14px sans-serif;background:#222;color:#fff;padding:12px">
<p>We and our partners use cookies to measure the site and show ads.</p>
<button onclick="parent.postMessage('rejected','*')">Reject all</button> <button onclick="parent.postMessage('accepted','*')">Accept all</button>
</body></html>`)
	case strings.HasPrefix(host, "cmp-") && strings.HasSuffix(host, ".test"):
		name := strings.TrimSuffix(strings.TrimPrefix(host, "cmp-"), ".test") // e.g. onetrust-good
		platform, mode, _ := strings.Cut(name, "-")
		page(w, consentSite(platform, mode, r.URL.Path))
	case host == "www.bigsite.test":
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/p/"))
		var links strings.Builder
		for i := 1; i <= 3; i++ {
			fmt.Fprintf(&links, `<a href="/p/%d">page %d</a> `, n*3+i, n*3+i)
		}
		page(w, fmt.Sprintf(`<!doctype html><html><head><title>Page %d</title>
<script>navigator.sendBeacon('https://region1.google-analytics.com/g/collect?v=2&tid=G-BIG&en=page_view&dl='+encodeURIComponent(location.href));</script>
</head><body><h1>Page %d</h1>%s</body></html>`, n, n, links.String()))
	default:
		return false
	}
	return true
}

func js(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(s))
}

func page(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(s))
}

var cmpScriptURL = map[string]string{
	"onetrust":     "https://cdn.cookielaw.org/scripttemplates/otSDKStub.js",
	"delayed":      "https://cdn.cookielaw.org/scripttemplates/otSDKStub.js?delay=2500",
	"cookiebot":    "https://consent.cookiebot.com/uc.js",
	"didomi":       "https://sdk.privacy-center.org/loader.js",
	"usercentrics": "https://app.usercentrics.eu/browser-ui/latest/loader.js",
	"generic":      "https://cmp.fixtures.test/generic.js",
	"iframe":       "https://cmp.fixtures.test/iframe.js",
}

// consentSite is a one-page site with a banner and Google Analytics. In
// "good" mode the tag waits for consent; in "bad" mode it is hard-coded.
func consentSite(platform, mode, path string) string {
	tag := `<script>window.__onAccept(function(){ gtag('consent','update',{ad_storage:'granted',analytics_storage:'granted'}); var s=document.createElement('script'); s.src='https://www.googletagmanager.com/gtag/js?id=G-FIXTURE'; document.head.appendChild(s); });</script>`
	if mode == "bad" {
		tag = `<script async src="https://www.googletagmanager.com/gtag/js?id=G-FIXTURE"></script>`
	}
	return `<!doctype html><html><head><meta charset="utf-8"><title>Consent fixture</title>
<script src="` + cmpScriptURL[platform] + `"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}
gtag('consent','default',{ad_storage:'denied',analytics_storage:'denied'});gtag('js',new Date());gtag('config','G-FIXTURE');</script>
` + tag + `</head><body><h1>Consent fixture ` + platform + `</h1><p>Page ` + path + `</p><a href="/about">About</a></body></html>`
}

// cmpScript builds a stand-in for a consent platform: the banner markup with
// the platform's button IDs, its JavaScript API, and a first-party cookie
// that remembers the choice.
func cmpScript(vendor, delay string) string {
	if delay == "" {
		delay = "0"
	}
	var ui, api string
	switch vendor {
	case "onetrust":
		ui = `root=el('div',{id:'onetrust-banner-sdk',style:BOX},'<p>We use cookies to improve your experience and for advertising.</p><button id="onetrust-reject-all-handler">Reject All</button> <button id="onetrust-accept-btn-handler">Accept All Cookies</button>');
document.body.appendChild(root);
root.querySelector('#onetrust-reject-all-handler').onclick=function(){choose('rejected')};
root.querySelector('#onetrust-accept-btn-handler').onclick=function(){choose('accepted')};`
		api = `window.OneTrust={RejectAll:function(){choose('rejected')},AllowAll:function(){choose('accepted')}};`
	case "cookiebot":
		ui = `root=el('div',{id:'CybotCookiebotDialog',style:BOX},'<p>This website uses cookies.</p><button id="CybotCookiebotDialogBodyButtonDecline">Deny</button> <button id="CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll">Allow all</button>');
document.body.appendChild(root);
root.querySelector('#CybotCookiebotDialogBodyButtonDecline').onclick=function(){choose('rejected')};
root.querySelector('#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll').onclick=function(){choose('accepted')};`
		api = `window.Cookiebot={submitCustomConsent:function(a,b,c){choose(a&&b&&c?'accepted':'rejected')}};`
	case "didomi":
		ui = `root=el('div',{id:'didomi-host'},'<div id="didomi-notice" style="'+BOX+'"><p>We and our partners store and access information on your device (cookies) for personalised ads.</p><button id="didomi-notice-disagree-button">Disagree and close</button> <button id="didomi-notice-agree-button">Agree and close</button></div>');
document.body.appendChild(root);
root.querySelector('#didomi-notice-disagree-button').onclick=function(){choose('rejected')};
root.querySelector('#didomi-notice-agree-button').onclick=function(){choose('accepted')};`
		api = `window.Didomi={setUserAgreeToAll:function(){choose('accepted')},setUserDisagreeToAll:function(){choose('rejected')}};`
	case "usercentrics":
		// A closed shadow root, as on many real sites: the buttons can't be
		// reached from outside, so PXTA has to use the platform's API.
		ui = `root=el('div',{id:'usercentrics-root'},'');
document.body.appendChild(root);
var sr=root.attachShadow({mode:'closed'});
sr.innerHTML='<div data-testid="uc-default-banner" style="'+BOX+'"><p>We use cookies and similar technologies.</p><button data-testid="uc-deny-all-button">Deny</button> <button data-testid="uc-accept-all-button">Accept All</button></div>';
sr.querySelector('[data-testid=uc-deny-all-button]').onclick=function(){choose('rejected')};
sr.querySelector('[data-testid=uc-accept-all-button]').onclick=function(){choose('accepted')};`
		api = `window.UC_UI={denyAllConsents:function(){choose('rejected');return Promise.resolve()},acceptAllConsents:function(){choose('accepted');return Promise.resolve()}};`
	case "generic":
		ui = `root=el('div',{className:'cookie-notice',style:BOX},'<p>This site uses cookies for analytics and advertising.</p><button class="btn-a">Reject all</button> <button class="btn-b">Accept all</button>');
document.body.appendChild(root);
root.querySelector('.btn-a').onclick=function(){choose('rejected')};
root.querySelector('.btn-b').onclick=function(){choose('accepted')};`
	case "iframe":
		ui = `root=el('iframe',{src:'https://consent-frame.test/banner',style:BOX+';height:120px;border:0'},'');
document.body.appendChild(root);
window.addEventListener('message',function(e){ if(e.data==='accepted'||e.data==='rejected') choose(e.data); });`
	}
	return `(function(){
var BOX='position:fixed;left:0;right:0;bottom:0;background:#fff;border-top:2px solid #333;padding:16px;z-index:99999;font:15px sans-serif';
var root;
function el(tag,props,html){var e=document.createElement(tag);for(var k in props){if(k==='style')e.style.cssText=props[k];else e[k]=props[k];}if(html)e.innerHTML=html;return e;}
function get(){var m=document.cookie.match(/(?:^|; )fx_consent=([^;]*)/);return m?m[1]:'';}
window.__consent=get();
var waiting=[];
window.__onAccept=function(fn){ if(window.__consent==='accepted') fn(); else waiting.push(fn); };
function choose(c){
  document.cookie='fx_consent='+c+'; path=/; max-age=31536000; SameSite=Lax; Secure';
  window.__consent=c;
  if(root){ if(root.tagName==='IFRAME') root.remove(); else root.style.display='none'; }
  if(c==='accepted'){ var w=waiting; waiting=[]; w.forEach(function(f){f()}); }
  document.dispatchEvent(new CustomEvent('fixture-consent',{detail:c}));
}
` + api + `
function show(){ ` + ui + ` }
if(!window.__consent){
  var go=function(){ if(` + delay + `) setTimeout(show,` + delay + `); else show(); };
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',go); else go();
}
})();`
}
