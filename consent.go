package pxta

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// The consent script runs in every frame. It finds a known consent platform
// by its own JavaScript object and markup, or a generic banner by the words
// on its buttons, looking inside open shadow roots too. With an action it
// rejects or accepts: a real click on the platform's own button first, the
// platform's JavaScript API second, a generic button last.
const consentJS = `(async (action) => {
  const visible = (el) => {
    if (!el || !el.isConnected) return false;
    const s = getComputedStyle(el);
    if (s.display === 'none' || s.visibility === 'hidden' || Number(s.opacity) === 0) return false;
    const b = el.getBoundingClientRect();
    return b.width > 0 && b.height > 0;
  };
  const all = (sel, root = document) => {
    const out = [];
    const walk = (r) => {
      try { r.querySelectorAll(sel).forEach((e) => out.push(e)); } catch (e) {}
      r.querySelectorAll('*').forEach((e) => { if (e.shadowRoot) walk(e.shadowRoot); });
    };
    walk(root);
    return out;
  };
  const first = (sel) => all(sel).find(visible) || null;
  const platforms = [
    { id: 'onetrust', root: '#onetrust-consent-sdk, #onetrust-banner-sdk', present: () => !!(window.OneTrust || window.Optanon || document.getElementById('onetrust-banner-sdk')),
      banner: '#onetrust-banner-sdk', reject: '#onetrust-reject-all-handler', accept: '#onetrust-accept-btn-handler',
      apiReject: () => (window.OneTrust || window.Optanon).RejectAll(), apiAccept: () => (window.OneTrust || window.Optanon).AllowAll(),
      hasApi: () => !!((window.OneTrust || window.Optanon) && (window.OneTrust || window.Optanon).RejectAll) },
    { id: 'cookiebot', root: '#CybotCookiebotDialog', present: () => !!(window.Cookiebot || window.CookieConsent && window.CookieConsent.submitCustomConsent || document.getElementById('CybotCookiebotDialog')),
      banner: '#CybotCookiebotDialog', reject: '#CybotCookiebotDialogBodyButtonDecline',
      accept: '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll, #CybotCookiebotDialogBodyButtonAccept',
      apiReject: () => (window.Cookiebot || window.CookieConsent).submitCustomConsent(false, false, false),
      apiAccept: () => (window.Cookiebot || window.CookieConsent).submitCustomConsent(true, true, true),
      hasApi: () => !!((window.Cookiebot || window.CookieConsent) && (window.Cookiebot || window.CookieConsent).submitCustomConsent) },
    { id: 'didomi', root: '#didomi-host', present: () => !!(window.Didomi || document.getElementById('didomi-host')),
      banner: '#didomi-notice, #didomi-host .didomi-popup-container', reject: '#didomi-notice-disagree-button', accept: '#didomi-notice-agree-button',
      apiReject: () => window.Didomi.setUserDisagreeToAll(), apiAccept: () => window.Didomi.setUserAgreeToAll(),
      hasApi: () => !!(window.Didomi && window.Didomi.setUserDisagreeToAll) },
    { id: 'usercentrics', root: '#usercentrics-root, #usercentrics-cmp-ui', present: () => !!(window.UC_UI || window.__ucCmp || document.getElementById('usercentrics-root') || document.getElementById('usercentrics-cmp-ui')),
      banner: '[data-testid="uc-default-banner"], #uc-center-container, #usercentrics-cmp-ui', reject: '[data-testid="uc-deny-all-button"], #deny', accept: '[data-testid="uc-accept-all-button"], #accept',
      apiReject: () => window.UC_UI ? window.UC_UI.denyAllConsents() : window.__ucCmp.denyAllConsents(),
      apiAccept: () => window.UC_UI ? window.UC_UI.acceptAllConsents() : window.__ucCmp.acceptAllConsents(),
      hasApi: () => !!((window.UC_UI && window.UC_UI.denyAllConsents) || (window.__ucCmp && window.__ucCmp.denyAllConsents)) },
  ];
  const rejectWords = ['reject all', 'reject', 'decline all', 'decline', 'deny all', 'deny', 'refuse all', 'refuse', 'disagree',
    'necessary only', 'only necessary', 'essential only', 'only essential', 'use necessary cookies only', 'continue without accepting',
    'alle ablehnen', 'ablehnen', 'tout refuser', 'refuser', 'continuer sans accepter', 'rechazar todo', 'rechazar', 'rifiuta tutto',
    'rifiuta', 'alles weigeren', 'weigeren', 'avvisa alla', 'odrzuć wszystkie', 'recusar', 'rejeitar'];
  const acceptWords = ['accept all', 'accept all cookies', 'accept', 'accept cookies', 'allow all', 'allow all cookies', 'allow', 'agree',
    'i agree', 'agree and close', 'got it', 'ok', 'alle akzeptieren', 'akzeptieren', 'zustimmen', 'tout accepter', 'accepter',
    "j'accepte", 'aceptar todo', 'aceptar', 'accetta tutto', 'accetta', 'alles accepteren', 'accepteren', 'acceptera alla',
    'zaakceptuj wszystkie', 'aceitar'];
  const clean = (t) => (t || '').replace(/\s+/g, ' ').trim().toLowerCase();
  const consentContext = (el) => {
    for (let n = el, i = 0; n && i < 8; n = n.parentElement || (n.getRootNode && n.getRootNode().host), i++) {
      const t = clean(n.innerText || n.textContent || '');
      const idc = clean((n.id || '') + ' ' + (typeof n.className === 'string' ? n.className : ''));
      if (/cookie|consent|privacy|gdpr|tracking|datenschutz|confidentialit|privacidad/.test(t + ' ' + idc)) return true;
    }
    return false;
  };
  const generic = (words) => {
    const els = all('button, a, [role="button"], input[type="button"], input[type="submit"]').filter(visible);
    for (const w of words) {
      const el = els.find((e) => clean(e.innerText || e.value || e.getAttribute('aria-label')) === w && consentContext(e));
      if (el) return el;
    }
    return null;
  };
  let found = null;
  for (const p of platforms) { try { if (p.present()) { found = p; break; } } catch (e) {} }
  const res = { platform: found ? found.id : '', visible: false, reject: false, accept: false, done: '', error: '' };
  // A banner inside a closed shadow root can't be looked into, but it still
  // covers part of the screen: ask what is drawn at a few points.
  const covers = (sel) => {
    const pts = [[0.5, 0.97], [0.5, 0.85], [0.5, 0.5], [0.5, 0.1], [0.1, 0.95], [0.9, 0.95]];
    for (const [x, y] of pts) {
      const e = document.elementFromPoint(innerWidth * x, innerHeight * y);
      if (e && e.closest && e.closest(sel)) return true;
    }
    return false;
  };
  if (found) {
    const b = first(found.banner);
    res.reject = !!first(found.reject);
    res.accept = !!first(found.accept);
    res.visible = !!b || res.reject || res.accept;
    if (!res.visible && found.root && covers(found.root)) {
      res.visible = true;
      try { res.reject = res.accept = found.hasApi(); } catch (e) {}
    }
  }
  const gReject = generic(rejectWords), gAccept = generic(acceptWords);
  if (!res.visible && (gReject || gAccept)) {
    if (!found) res.platform = 'generic';
    res.visible = true;
    res.reject = res.reject || !!gReject;
    res.accept = res.accept || !!gAccept;
  }
  if (!action || !res.visible) return res;
  try {
    const sel = found ? (action === 'reject' ? found.reject : found.accept) : '';
    const btn = sel ? first(sel) : null;
    if (btn) { btn.click(); res.done = 'clicked ' + sel.split(',')[0].trim(); return res; }
    if (found && found.hasApi()) { await (action === 'reject' ? found.apiReject() : found.apiAccept()); res.done = 'called the ' + found.id + ' JavaScript API'; return res; }
    const g = action === 'reject' ? gReject : gAccept;
    if (g) { g.click(); res.done = 'clicked the button “' + clean(g.innerText || g.value) + '”'; return res; }
    res.error = 'no ' + action + ' control found';
  } catch (e) { res.error = String(e && e.message || e); }
  return res;
})`

// BannerState is what the consent script found in one frame.
type BannerState struct {
	Platform string `json:"platform"`
	Visible  bool   `json:"visible"`
	Reject   bool   `json:"reject"`
	Accept   bool   `json:"accept"`
	Done     string `json:"done"`
	Error    string `json:"error"`
	Frame    string `json:"frame,omitempty"`
}

// detectBanner polls every frame of the tab until a consent banner shows or
// wait runs out. Banners often appear a second or two after load.
func (t *tab) detectBanner(ctx context.Context, wait time.Duration) BannerState {
	deadline := time.Now().Add(wait)
	var best BannerState
	for {
		for _, f := range t.rec.frames() {
			var st BannerState
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := t.b.eval(cctx, f, consentJS+"(null)", &st)
			cancel()
			if err != nil {
				continue
			}
			if f.session != t.session {
				st.Frame = "iframe"
			}
			if st.Visible {
				return st
			}
			if st.Platform != "" && best.Platform == "" {
				best = st
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return best
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// answerBanner rejects or accepts in whichever frame shows the banner, then
// checks the banner went away.
func (t *tab) answerBanner(ctx context.Context, action string, wait time.Duration) BannerState {
	deadline := time.Now().Add(wait)
	arg, _ := json.Marshal(action)
	for {
		for _, f := range t.rec.frames() {
			var st BannerState
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := t.b.eval(cctx, f, consentJS+"("+string(arg)+")", &st)
			cancel()
			if err != nil || !st.Visible {
				continue
			}
			if f.session != t.session {
				st.Frame = "iframe"
			}
			if st.Done == "" {
				return st
			}
			// Give the platform a moment, then make sure the banner is gone.
			time.Sleep(1200 * time.Millisecond)
			after := t.detectBanner(ctx, 0)
			if after.Visible {
				st.Error = "the banner was still showing after PXTA " + st.Done
				st.Done = ""
			}
			return st
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return BannerState{Error: "no consent banner showed"}
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// pageInfoJS collects links for the crawl, and email addresses visible on
// the page or typed into its fields, so their hashes can be recognised.
const pageInfoJS = `(() => {
  const emailRe = /[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24}/g;
  const links = Array.from(document.querySelectorAll('a[href]')).map((a) => a.href).slice(0, 2000);
  const text = (document.body && document.body.innerText || '').slice(0, 500000);
  const emails = new Set(text.match(emailRe) || []);
  document.querySelectorAll('input, textarea').forEach((i) => { (String(i.value || '').match(emailRe) || []).forEach((e) => emails.add(e)); });
  return { url: location.href, title: document.title, links, emails: Array.from(emails).slice(0, 50) };
})()`

// fillFormsJS types a marker address into email fields (and a name and phone
// into theirs) and fires the events tags listen for, without submitting.
// Tags that scrape form fields ("automatic advanced matching") then show
// what they would send.
const fillFormsJS = `((email) => {
  let n = 0;
  const fire = (el) => ['input', 'change', 'blur'].forEach((t) => el.dispatchEvent(new Event(t, { bubbles: true })));
  document.querySelectorAll('input').forEach((el) => {
    const t = (el.type || '').toLowerCase(), hint = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.autocomplete || '')).toLowerCase();
    if (el.disabled || el.readOnly || el.value) return;
    if (t === 'email' || /e-?mail/.test(hint)) { el.focus(); el.value = email; fire(el); n++; }
    else if (t === 'tel' || /phone|tel/.test(hint)) { el.value = '+1 555 0100 123'; fire(el); n++; }
    else if (/first.?name|given/.test(hint)) { el.value = 'Pat'; fire(el); n++; }
    else if (/last.?name|family|surname/.test(hint)) { el.value = 'Probe'; fire(el); n++; }
  });
  document.querySelectorAll('button, input[type=submit]').forEach((b) => b.dispatchEvent(new MouseEvent('mouseover', { bubbles: true })));
  return n;
})`

// PlatformName is how a consent platform's name is written.
func PlatformName(id string) string {
	switch id {
	case "onetrust":
		return "OneTrust"
	case "cookiebot":
		return "Cookiebot"
	case "didomi":
		return "Didomi"
	case "usercentrics":
		return "Usercentrics"
	case "generic":
		return "an unrecognised platform"
	}
	return id
}

// ProbeEmail is the address PXTA types into email fields.
const ProbeEmail = "pxta-probe@example.com"

func lowerTrim(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
